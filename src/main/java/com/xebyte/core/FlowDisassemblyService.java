package com.xebyte.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Bounded recursive-descent disassembly with a side-effect-free planning phase.
 */
@McpToolGroup(value = "disassembly", description = "Safe bounded instruction discovery")
public final class FlowDisassemblyService {

    static final int DEFAULT_MAX_INSTRUCTIONS = 4_096;
    static final int HARD_MAX_INSTRUCTIONS = 100_000;
    @FunctionalInterface
    interface PlanningEngine {
        FlowPlan plan(Program program, FlowRequest request);
    }

    @FunctionalInterface
    interface MutationEngine {
        CommitResult commit(
                Program program,
                FlowPlan plan,
                ListingClearCore.Plan clearPlan) throws Exception;
    }

    @FunctionalInterface
    interface StockDisassembler {
        AddressSet disassemble(
                Program program,
                AddressSetView starts,
                AddressSetView restriction,
                boolean followFlow) throws Exception;
    }

    @FunctionalInterface
    interface AnalysisQueue {
        AnalysisSubmission submit(Program program, AddressSetView created) throws Exception;
    }

    record FunctionChange(Address entry, String status, long bodySize) {
    }

    record CommitResult(AddressSet createdInstructions, List<FunctionChange> functionChanges) {

        CommitResult {
            createdInstructions = new AddressSet(createdInstructions);
            functionChanges = List.copyOf(functionChanges);
        }

        @Override
        public AddressSet createdInstructions() {
            return new AddressSet(createdInstructions);
        }
    }

    record AnalysisSubmission(boolean queued, String requestIdentity) {
    }

    record PreparedPlan(
            FlowRequest request,
            FlowPlan flow,
            ListingClearCore.Plan clear) {
    }

    record CommitAttempt(
            FlowRequest request,
            FlowPlan flow,
            CommitResult commit) {
    }

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final ListingClearCore clearCore;
    private final PlanningEngine planningEngine;
    private final StockDisassembler stockDisassembler;
    private final MutationEngine mutationEngine;
    private final AnalysisQueue analysisQueue;

    public FlowDisassemblyService(
            ProgramProvider programProvider,
            ThreadingStrategy threadingStrategy) {
        this(
            programProvider,
            threadingStrategy,
            FlowDisassemblyService::submitAnalysis);
    }

    FlowDisassemblyService(
            ProgramProvider programProvider,
            ThreadingStrategy threadingStrategy,
            AnalysisQueue analysisQueue) {
        if (programProvider == null || threadingStrategy == null) {
            throw new IllegalArgumentException(
                "programProvider and threadingStrategy are required");
        }
        if (analysisQueue == null) {
            throw new IllegalArgumentException("analysisQueue is required");
        }
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.clearCore = new ListingClearCore();
        this.planningEngine = this::plan;
        this.stockDisassembler = FlowDisassemblyService::disassembleStock;
        this.mutationEngine = this::commitPlan;
        this.analysisQueue = analysisQueue;
    }

    FlowDisassemblyService(
            ProgramProvider programProvider,
            ThreadingStrategy threadingStrategy,
            PlanningEngine planningEngine,
            MutationEngine mutationEngine,
            AnalysisQueue analysisQueue) {
        if (programProvider == null || threadingStrategy == null ||
            planningEngine == null || mutationEngine == null || analysisQueue == null) {
            throw new IllegalArgumentException("service collaborators are required");
        }
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.clearCore = new ListingClearCore();
        this.planningEngine = planningEngine;
        this.stockDisassembler = FlowDisassemblyService::disassembleStock;
        this.mutationEngine = mutationEngine;
        this.analysisQueue = analysisQueue;
    }

    FlowDisassemblyService(
            ProgramProvider programProvider,
            ThreadingStrategy threadingStrategy,
            PlanningEngine planningEngine,
            StockDisassembler stockDisassembler,
            AnalysisQueue analysisQueue) {
        if (programProvider == null || threadingStrategy == null ||
            planningEngine == null || stockDisassembler == null || analysisQueue == null) {
            throw new IllegalArgumentException("service collaborators are required");
        }
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.clearCore = new ListingClearCore();
        this.planningEngine = planningEngine;
        this.stockDisassembler = stockDisassembler;
        this.mutationEngine = this::commitPlan;
        this.analysisQueue = analysisQueue;
    }

    @McpTool(
        path = "/disassemble_flow",
        method = "POST",
        description = "Preview or commit bounded recursive-descent disassembly from explicit seeds",
        category = "disassembly",
        supportsDryRun = false)
    public Response disassembleFlow(
            @Param(
                value = "seeds",
                source = ParamSource.BODY,
                fieldsJson = true,
                description = "JSON array of address strings used as traversal seeds")
            String seedsJson,
            @Param(
                value = "restrict_start",
                source = ParamSource.BODY,
                paramType = "address",
                description = "Inclusive start of the traversal boundary")
            String restrictStart,
            @Param(
                value = "restrict_end",
                source = ParamSource.BODY,
                paramType = "address",
                description = "Inclusive end of the traversal boundary")
            String restrictEnd,
            @Param(value = "dry_run", source = ParamSource.BODY, defaultValue = "true")
            boolean dryRun,
            @Param(value = "follow_calls", source = ParamSource.BODY, defaultValue = "true")
            boolean followCalls,
            @Param(
                value = "preserve_defined_data",
                source = ParamSource.BODY,
                defaultValue = "true")
            boolean preserveDefinedData,
            @Param(
                value = "create_functions",
                source = ParamSource.BODY,
                defaultValue = "false")
            boolean createFunctions,
            @Param(
                value = "enable_analysis",
                source = ParamSource.BODY,
                defaultValue = "false")
            boolean enableAnalysis,
            @Param(
                value = "max_instructions",
                source = ParamSource.BODY,
                defaultValue = "4096")
            int maxInstructions,
            @Param(value = "program", source = ParamSource.QUERY, defaultValue = "")
            String programName) {
        ServiceUtils.ProgramOrError resolved =
            ServiceUtils.getProgramOrError(programProvider, programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Program program = resolved.program();

        try {
            if (dryRun) {
                PreparedPlan prepared = threadingStrategy.executeRead(() -> {
                    FlowRequest request = parseRequest(
                        program,
                        seedsJson,
                        restrictStart,
                        restrictEnd,
                        followCalls,
                        preserveDefinedData,
                        createFunctions,
                        enableAnalysis,
                        maxInstructions);
                    FlowPlan flow = planningEngine.plan(program, request);
                    return new PreparedPlan(
                        request, flow, prepareClearPlan(program, flow));
                });
                FlowRequest request = prepared.request();
                FlowPlan plan = prepared.flow();
                String status = plan.conflicts().isEmpty() ? "preview" : "blocked";
                return Response.ok(resultMap(
                    program,
                    request,
                    plan,
                    null,
                    dryRun,
                    false,
                    status,
                    "not_requested",
                    null,
                    null));
            }

            CommitAttempt attempt = threadingStrategy.executeWrite(
                program,
                "Bounded flow disassembly",
                () -> {
                    FlowRequest request = parseRequest(
                        program,
                        seedsJson,
                        restrictStart,
                        restrictEnd,
                        followCalls,
                        preserveDefinedData,
                        createFunctions,
                        enableAnalysis,
                        maxInstructions);
                    FlowPlan current = planningEngine.plan(program, request);
                    ListingClearCore.Plan clearPlan =
                        prepareClearPlan(program, current);
                    if (!current.conflicts().isEmpty()) {
                        return new CommitAttempt(request, current, null);
                    }
                    return new CommitAttempt(
                        request,
                        current,
                        mutationEngine.commit(program, current, clearPlan));
                });
            FlowRequest request = attempt.request();
            FlowPlan plan = attempt.flow();
            CommitResult committed = attempt.commit();
            if (committed == null) {
                return Response.ok(resultMap(
                    program,
                    request,
                    plan,
                    null,
                    false,
                    false,
                    "blocked",
                    "not_requested",
                    null,
                    null));
            }

            String analysisStatus = "not_requested";
            String analysisError = null;
            AnalysisSubmission submission = null;
            if (request.enableAnalysis() && !committed.createdInstructions().isEmpty()) {
                try {
                    submission =
                        analysisQueue.submit(program, committed.createdInstructions());
                    if (submission != null && submission.queued()) {
                        analysisStatus = "queued";
                    }
                    else {
                        analysisStatus = "queue_failed";
                        analysisError = "analysis scheduler did not accept the request";
                    }
                }
                catch (Exception e) {
                    analysisStatus = "queue_failed";
                    analysisError = describe(e);
                }
            }

            return Response.ok(resultMap(
                program,
                request,
                plan,
                committed,
                false,
                true,
                "committed",
                analysisStatus,
                submission,
                analysisError));
        }
        catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }
        catch (Exception e) {
            return Response.err("Flow disassembly failed: " + describe(e));
        }
    }

    FlowPlan plan(Program program, FlowRequest request) {
        FlowPlan plan =
            new FlowPlanner(new GhidraInstructionSource(program)).plan(request);
        return request.createFunctions() ? preflightFunctions(program, plan) : plan;
    }

    enum LocationKind {
        UNDEFINED,
        EXISTING_INSTRUCTION,
        DEFINED_DATA,
        MIDDLE_CODE_UNIT,
        UNINITIALIZED
    }

    enum EdgeKind {
        SEED,
        FALLTHROUGH,
        BRANCH,
        CALL
    }

    record DecodedInstruction(
            Address address,
            int length,
            String text,
            Address fallThrough,
            List<Address> flows,
            FlowType flowType) {

        DecodedInstruction {
            flows = normalizeAddresses(flows);
        }
    }

    record Location(
            LocationKind kind,
            Address address,
            Address unitStart,
            Address unitEnd,
            DecodedInstruction instruction) {

        static Location undefined(Address address) {
            return new Location(LocationKind.UNDEFINED, address, null, null, null);
        }

        static Location uninitialized(Address address) {
            return new Location(LocationKind.UNINITIALIZED, address, null, null, null);
        }

        static Location existing(DecodedInstruction instruction) {
            Address end = endOf(instruction);
            return new Location(
                LocationKind.EXISTING_INSTRUCTION,
                instruction.address(),
                instruction.address(),
                end,
                instruction);
        }

        static Location data(Address address, Address start, Address end) {
            return new Location(LocationKind.DEFINED_DATA, address, start, end, null);
        }

        static Location middle(Address address, Address start, Address end) {
            return new Location(LocationKind.MIDDLE_CODE_UNIT, address, start, end, null);
        }
    }

    interface InstructionSource {
        Location inspect(Address address);

        DecodedInstruction decode(Address address) throws Exception;

        List<Location> intersecting(Address start, Address end);

        default boolean initialized(Address start, Address end) {
            return true;
        }
    }

    record FlowRequest(
            List<Address> seeds,
            AddressSet restriction,
            boolean followCalls,
            boolean preserveDefinedData,
            boolean createFunctions,
            boolean enableAnalysis,
            int maxInstructions) {

        FlowRequest {
            seeds = List.copyOf(seeds);
            restriction = new AddressSet(restriction);
        }

        @Override
        public AddressSet restriction() {
            return new AddressSet(restriction);
        }
    }

    record QueueItem(Address address, Address origin, EdgeKind edgeKind) {
    }

    record InstructionRecord(
            Address address,
            int length,
            String text,
            boolean existing,
            Address fallThrough,
            List<Address> flows,
            FlowType flowType) {

        InstructionRecord {
            flows = normalizeAddresses(flows);
        }
    }

    record DataUnit(Address start, Address end) {
    }

    record Conflict(
            Address address,
            Address origin,
            EdgeKind edgeKind,
            String reason,
            Address unitStart,
            Address unitEnd) {
    }

    record StopReason(
            Address address,
            Address origin,
            EdgeKind edgeKind,
            String reason,
            String detail) {
    }

    record UnresolvedFlow(Address from, String flowType, String reason) {
    }

    record FunctionPlan(Address entry, AddressSet body, boolean existing) {

        FunctionPlan {
            body = new AddressSet(body);
        }

        @Override
        public AddressSet body() {
            return new AddressSet(body);
        }
    }

    record FlowPlan(
            List<Address> normalizedSeeds,
            AddressSet restriction,
            List<InstructionRecord> instructions,
            AddressSet plannedNewInstructions,
            AddressSet existingInstructions,
            List<Address> directCallTargets,
            List<Address> directBranchTargets,
            List<UnresolvedFlow> unresolvedFlows,
            List<Conflict> conflicts,
            List<StopReason> stopReasons,
            List<DataUnit> clearedData,
            List<FunctionPlan> functions,
            boolean instructionCapReached) {

        FlowPlan {
            normalizedSeeds = List.copyOf(normalizedSeeds);
            restriction = new AddressSet(restriction);
            instructions = List.copyOf(instructions);
            plannedNewInstructions = new AddressSet(plannedNewInstructions);
            existingInstructions = new AddressSet(existingInstructions);
            directCallTargets = List.copyOf(directCallTargets);
            directBranchTargets = List.copyOf(directBranchTargets);
            unresolvedFlows = List.copyOf(unresolvedFlows);
            conflicts = List.copyOf(conflicts);
            stopReasons = List.copyOf(stopReasons);
            clearedData = List.copyOf(clearedData);
            functions = List.copyOf(functions);
        }

        @Override
        public AddressSet restriction() {
            return new AddressSet(restriction);
        }

        @Override
        public AddressSet plannedNewInstructions() {
            return new AddressSet(plannedNewInstructions);
        }

        @Override
        public AddressSet existingInstructions() {
            return new AddressSet(existingInstructions);
        }
    }

    static final class FlowPlanner {

        private static final Comparator<Address> ADDRESS_ORDER = Address::compareTo;
        private static final Comparator<QueueItem> QUEUE_ORDER =
            Comparator.comparing(QueueItem::address, ADDRESS_ORDER)
                .thenComparing(QueueItem::origin,
                    Comparator.nullsFirst(ADDRESS_ORDER))
                .thenComparing(item -> item.edgeKind().ordinal());

        private final InstructionSource source;

        FlowPlanner(InstructionSource source) {
            if (source == null) {
                throw new IllegalArgumentException("instruction source is required");
            }
            this.source = source;
        }

        FlowPlan plan(FlowRequest request) {
            validate(request);
            List<Address> seeds = request.seeds().stream()
                .distinct()
                .sorted(ADDRESS_ORDER)
                .toList();
            PriorityQueue<QueueItem> queue = new PriorityQueue<>(QUEUE_ORDER);
            for (Address seed : seeds) {
                queue.add(new QueueItem(seed, null, EdgeKind.SEED));
            }

            Map<Address, InstructionRecord> instructions = new LinkedHashMap<>();
            Set<QueueItem> processed = new TreeSet<>(QUEUE_ORDER);
            Set<Address> callTargets = new TreeSet<>(ADDRESS_ORDER);
            Set<Address> branchTargets = new TreeSet<>(ADDRESS_ORDER);
            List<UnresolvedFlow> unresolved = new ArrayList<>();
            List<Conflict> conflicts = new ArrayList<>();
            List<StopReason> stops = new ArrayList<>();
            NavigableMap<Address, DataUnit> dataToClear =
                new TreeMap<>(ADDRESS_ORDER);
            AddressSet plannedBytes = new AddressSet();
            AddressSet existingBytes = new AddressSet();
            boolean capReached = false;

            while (!queue.isEmpty()) {
                QueueItem item = queue.remove();
                if (!processed.add(item)) {
                    continue;
                }
                if (instructions.containsKey(item.address())) {
                    validateDuplicateProvenance(
                        item, instructions, dataToClear, conflicts);
                    continue;
                }
                if (instructions.size() >= request.maxInstructions()) {
                    stops.add(stop(item, "instruction_cap",
                        "max_instructions=" + request.maxInstructions()));
                    capReached = true;
                    break;
                }
                if (!request.restriction().contains(item.address())) {
                    stops.add(stop(item, "restricted_boundary",
                        "address is outside the inclusive restriction"));
                    continue;
                }
                if (isMiddleOfPlannedInstruction(plannedBytes, instructions, item.address())) {
                    conflicts.add(conflict(item, "middle_of_planned_instruction", null, null));
                    continue;
                }

                Location location = source.inspect(item.address());
                if (location == null || location.kind() == LocationKind.UNINITIALIZED) {
                    stops.add(stop(item, "uninitialized_memory",
                        "address is not in initialized memory"));
                    continue;
                }
                if (location.kind() == LocationKind.MIDDLE_CODE_UNIT) {
                    conflicts.add(conflict(item, "middle_of_code_unit",
                        location.unitStart(), location.unitEnd()));
                    continue;
                }

                if (location.kind() == LocationKind.DEFINED_DATA) {
                    if (isScheduledData(location, dataToClear)) {
                        if (isVirtualContinuation(
                                location, item, instructions, dataToClear)) {
                            location = Location.undefined(item.address());
                        }
                        else {
                            conflicts.add(conflict(item, "middle_of_defined_data",
                                location.unitStart(), location.unitEnd()));
                            continue;
                        }
                    }
                    else if (!item.address().equals(location.unitStart())) {
                        conflicts.add(conflict(item, "middle_of_defined_data",
                            location.unitStart(), location.unitEnd()));
                        continue;
                    }
                    else if (request.preserveDefinedData()) {
                        conflicts.add(conflict(item, "defined_data",
                            location.unitStart(), location.unitEnd()));
                        continue;
                    }
                    else if (!request.restriction().contains(
                            location.unitStart(), location.unitEnd())) {
                        conflicts.add(conflict(item, "defined_data_crosses_restriction",
                            location.unitStart(), location.unitEnd()));
                        continue;
                    }
                }

                boolean existing = location.kind() == LocationKind.EXISTING_INSTRUCTION;
                DecodedInstruction decoded;
                try {
                    decoded = existing ? location.instruction() : source.decode(item.address());
                }
                catch (Exception e) {
                    stops.add(stop(item, "decode_failure", describe(e)));
                    continue;
                }
                if (decoded == null) {
                    stops.add(stop(item, "decode_failure", "decoder returned no instruction"));
                    continue;
                }
                if (!item.address().equals(decoded.address()) || decoded.length() <= 0) {
                    stops.add(stop(item, "decode_failure",
                        "decoder returned an invalid instruction record"));
                    continue;
                }

                Address end;
                try {
                    end = endOf(decoded);
                }
                catch (IllegalArgumentException e) {
                    stops.add(stop(item, "decode_failure", e.getMessage()));
                    continue;
                }
                if (!request.restriction().contains(decoded.address(), end)) {
                    stops.add(stop(item, "restricted_boundary",
                        "instruction crosses the inclusive restriction"));
                    continue;
                }
                if (!source.initialized(decoded.address(), end)) {
                    stops.add(stop(item, "uninitialized_memory",
                        "instruction crosses uninitialized memory"));
                    continue;
                }

                Map<Address, DataUnit> pendingData = new LinkedHashMap<>();
                if (!existing && !authorizeIntersectingUnits(
                        request,
                        item,
                        decoded.address(),
                        end,
                        dataToClear,
                        pendingData,
                        conflicts)) {
                    continue;
                }
                AddressSet decodedBytes = new AddressSet(decoded.address(), end);
                if (!existing && plannedBytes.intersects(decodedBytes)) {
                    conflicts.add(conflict(item, "overlapping_planned_instruction", null, null));
                    continue;
                }

                InstructionRecord record = new InstructionRecord(
                    decoded.address(),
                    decoded.length(),
                    decoded.text(),
                    existing,
                    decoded.fallThrough(),
                    decoded.flows(),
                    decoded.flowType());
                instructions.put(record.address(), record);
                if (existing) {
                    existingBytes.add(record.address(), end);
                }
                else {
                    plannedBytes.add(record.address(), end);
                }
                dataToClear.putAll(pendingData);

                enqueueFlows(
                    request,
                    record,
                    queue,
                    callTargets,
                    branchTargets,
                    unresolved,
                    stops);
            }

            List<InstructionRecord> sortedInstructions = instructions.values().stream()
                .sorted(Comparator.comparing(InstructionRecord::address, ADDRESS_ORDER))
                .toList();
            List<FunctionPlan> functionPlans = request.createFunctions()
                ? buildFunctionPlans(
                    request, seeds, sortedInstructions, callTargets, conflicts)
                : List.of();
            unresolved.sort(Comparator.comparing(UnresolvedFlow::from, ADDRESS_ORDER)
                .thenComparing(UnresolvedFlow::flowType));
            conflicts.sort(Comparator.comparing(Conflict::address, ADDRESS_ORDER)
                .thenComparing(conflict -> conflict.edgeKind().ordinal())
                .thenComparing(Conflict::reason));
            stops.sort(Comparator.comparing(StopReason::address, ADDRESS_ORDER)
                .thenComparing(stop -> stop.edgeKind().ordinal())
                .thenComparing(StopReason::reason));
            List<DataUnit> sortedData = dataToClear.values().stream()
                .sorted(Comparator.comparing(DataUnit::start, ADDRESS_ORDER))
                .toList();

            return new FlowPlan(
                seeds,
                request.restriction(),
                sortedInstructions,
                plannedBytes,
                existingBytes,
                List.copyOf(callTargets),
                List.copyOf(branchTargets),
                unresolved,
                conflicts,
                stops,
                sortedData,
                functionPlans,
                capReached);
        }

        private static List<FunctionPlan> buildFunctionPlans(
                FlowRequest request,
                List<Address> seeds,
                List<InstructionRecord> instructions,
                Set<Address> callTargets,
                List<Conflict> conflicts) {
            Map<Address, InstructionRecord> byAddress = new LinkedHashMap<>();
            for (InstructionRecord instruction : instructions) {
                byAddress.put(instruction.address(), instruction);
            }

            Set<Address> entries = new TreeSet<>(ADDRESS_ORDER);
            for (Address seed : seeds) {
                if (byAddress.containsKey(seed)) {
                    entries.add(seed);
                }
            }
            if (request.followCalls()) {
                for (Address target : callTargets) {
                    if (byAddress.containsKey(target)) {
                        entries.add(target);
                    }
                }
            }

            List<FunctionCandidate> candidates = new ArrayList<>();
            for (Address entry : entries) {
                AddressSet body = new AddressSet();
                PriorityQueue<Address> queue = new PriorityQueue<>(ADDRESS_ORDER);
                Set<Address> visited = new TreeSet<>(ADDRESS_ORDER);
                Set<Address> bodyInstructionStarts =
                    new TreeSet<>(ADDRESS_ORDER);
                queue.add(entry);
                while (!queue.isEmpty()) {
                    Address address = queue.remove();
                    if (!visited.add(address) ||
                        !address.equals(entry) && entries.contains(address)) {
                        continue;
                    }
                    InstructionRecord instruction = byAddress.get(address);
                    if (instruction == null) {
                        continue;
                    }
                    body.add(
                        instruction.address(),
                        instruction.address().add(instruction.length() - 1L));
                    bodyInstructionStarts.add(instruction.address());
                    for (Address successor : successors(instruction, request.followCalls())) {
                        if (byAddress.containsKey(successor)) {
                            queue.add(successor);
                        }
                    }
                }
                candidates.add(new FunctionCandidate(
                    new FunctionPlan(entry, body, false),
                    List.copyOf(bodyInstructionStarts)));
            }

            FunctionBodyOwnership ownership = new FunctionBodyOwnership();
            List<FunctionPlan> plans = new ArrayList<>();
            for (FunctionCandidate candidate : candidates) {
                FunctionPlan function = candidate.plan();
                for (Address prior : ownership.claim(
                        function.entry(), candidate.instructionStarts())) {
                    conflicts.add(new Conflict(
                        function.entry(),
                        prior,
                        EdgeKind.SEED,
                        "overlapping_function_bodies",
                        prior,
                        function.entry()));
                }
                plans.add(function);
            }
            return List.copyOf(plans);
        }

        record FunctionCandidate(
                FunctionPlan plan,
                List<Address> instructionStarts) {

            FunctionCandidate {
                instructionStarts = List.copyOf(instructionStarts);
            }
        }

        static final class FunctionBodyOwnership {
            private final Map<Address, List<Address>> ownersByInstruction =
                new TreeMap<>(ADDRESS_ORDER);
            private long claimOperations;

            List<Address> claim(
                    Address entry,
                    List<Address> instructionStarts) {
                Set<Address> overlaps = new TreeSet<>(ADDRESS_ORDER);
                for (Address instructionStart : instructionStarts) {
                    claimOperations++;
                    List<Address> owners = ownersByInstruction.computeIfAbsent(
                        instructionStart, ignored -> new ArrayList<>());
                    overlaps.addAll(owners);
                    owners.add(entry);
                }
                return List.copyOf(overlaps);
            }

            long claimOperations() {
                return claimOperations;
            }
        }

        private static List<Address> successors(
                InstructionRecord instruction,
                boolean followCalls) {
            Set<Address> successors = new TreeSet<>(ADDRESS_ORDER);
            if (instruction.fallThrough() != null) {
                successors.add(instruction.fallThrough());
            }
            FlowType flowType = instruction.flowType();
            if (flowType == null || !flowType.isComputed() &&
                (!flowType.isCall() || followCalls)) {
                successors.addAll(instruction.flows());
            }
            return List.copyOf(successors);
        }

        private boolean authorizeIntersectingUnits(
                FlowRequest request,
                QueueItem item,
                Address start,
                Address end,
                Map<Address, DataUnit> dataToClear,
                Map<Address, DataUnit> pendingData,
                List<Conflict> conflicts) {
            List<Location> intersecting = source.intersecting(start, end);
            if (intersecting == null) {
                return true;
            }
            for (Location unit : intersecting) {
                if (unit.kind() == LocationKind.EXISTING_INSTRUCTION ||
                    unit.kind() == LocationKind.MIDDLE_CODE_UNIT) {
                    conflicts.add(conflict(item, "instruction_overlaps_code_unit",
                        unit.unitStart(), unit.unitEnd()));
                    return false;
                }
                if (unit.kind() != LocationKind.DEFINED_DATA) {
                    continue;
                }
                if (isScheduledData(unit, dataToClear) ||
                    isScheduledData(unit, pendingData)) {
                    continue;
                }
                if (request.preserveDefinedData()) {
                    conflicts.add(conflict(item, "instruction_overlaps_defined_data",
                        unit.unitStart(), unit.unitEnd()));
                    return false;
                }
                if (unit.unitStart() == null || unit.unitEnd() == null ||
                    !request.restriction().contains(unit.unitStart(), unit.unitEnd())) {
                    conflicts.add(conflict(item, "defined_data_crosses_restriction",
                        unit.unitStart(), unit.unitEnd()));
                    return false;
                }
                if (start.compareTo(unit.unitStart()) > 0) {
                    conflicts.add(conflict(item, "partial_defined_data_overlap",
                        unit.unitStart(), unit.unitEnd()));
                    return false;
                }
                pendingData.putIfAbsent(
                    unit.unitStart(), new DataUnit(unit.unitStart(), unit.unitEnd()));
            }
            return true;
        }

        private static boolean isScheduledData(
                Location location,
                Map<Address, DataUnit> scheduled) {
            if (location.unitStart() == null || location.unitEnd() == null) {
                return false;
            }
            DataUnit unit = scheduled.get(location.unitStart());
            return unit != null && unit.end().equals(location.unitEnd());
        }

        private static void validateDuplicateProvenance(
                QueueItem item,
                Map<Address, InstructionRecord> instructions,
                NavigableMap<Address, DataUnit> scheduled,
                List<Conflict> conflicts) {
            DataUnit unit = scheduledDataContaining(item.address(), scheduled);
            if (unit == null || item.address().equals(unit.start())) {
                return;
            }
            Location location =
                Location.data(item.address(), unit.start(), unit.end());
            if (!isVirtualContinuation(location, item, instructions, scheduled)) {
                conflicts.add(conflict(
                    item, "middle_of_defined_data", unit.start(), unit.end()));
            }
        }

        static DataUnit scheduledDataContaining(
                Address address,
                NavigableMap<Address, DataUnit> scheduled) {
            Map.Entry<Address, DataUnit> floor = scheduled.floorEntry(address);
            if (floor != null && floor.getValue().end().compareTo(address) >= 0) {
                return floor.getValue();
            }
            return null;
        }

        private static boolean isVirtualContinuation(
                Location location,
                QueueItem item,
                Map<Address, InstructionRecord> instructions,
                Map<Address, DataUnit> scheduled) {
            if (!isScheduledData(location, scheduled) ||
                item.origin() == null ||
                item.edgeKind() == EdgeKind.SEED) {
                return false;
            }
            InstructionRecord origin = instructions.get(item.origin());
            if (origin == null || origin.existing()) {
                return false;
            }
            Address originEnd = origin.address().add(origin.length() - 1L);
            return origin.address().compareTo(location.unitEnd()) <= 0 &&
                originEnd.compareTo(location.unitStart()) >= 0;
        }

        private static void enqueueFlows(
                FlowRequest request,
                InstructionRecord record,
                PriorityQueue<QueueItem> queue,
                Set<Address> callTargets,
                Set<Address> branchTargets,
                List<UnresolvedFlow> unresolved,
                List<StopReason> stops) {
            FlowType flowType = record.flowType();
            boolean computed = flowType != null && flowType.isComputed();
            boolean call = flowType != null && flowType.isCall();

            if (computed) {
                unresolved.add(new UnresolvedFlow(
                    record.address(),
                    flowType.toString(),
                    "computed flow target is not guessed"));
            }
            else {
                for (Address target : record.flows()) {
                    if (target == null) {
                        unresolved.add(new UnresolvedFlow(
                            record.address(),
                            flowType != null ? flowType.toString() : "unknown",
                            "flow target is unresolved"));
                        continue;
                    }
                    if (call) {
                        callTargets.add(target);
                        if (request.followCalls()) {
                            queue.add(new QueueItem(target, record.address(), EdgeKind.CALL));
                        }
                    }
                    else {
                        branchTargets.add(target);
                        queue.add(new QueueItem(target, record.address(), EdgeKind.BRANCH));
                    }
                }
            }

            if (record.fallThrough() != null) {
                queue.add(new QueueItem(
                    record.fallThrough(), record.address(), EdgeKind.FALLTHROUGH));
            }
            else if (flowType != null && flowType.isTerminal()) {
                stops.add(new StopReason(
                    record.address(),
                    record.address(),
                    EdgeKind.FALLTHROUGH,
                    "terminal",
                    flowType.toString()));
            }
        }

        private static boolean isMiddleOfPlannedInstruction(
                AddressSetView planned,
                Map<Address, InstructionRecord> instructions,
                Address address) {
            return planned.contains(address) && !instructions.containsKey(address);
        }

        private static Conflict conflict(
                QueueItem item,
                String reason,
                Address unitStart,
                Address unitEnd) {
            return new Conflict(
                item.address(), item.origin(), item.edgeKind(), reason, unitStart, unitEnd);
        }

        private static StopReason stop(QueueItem item, String reason, String detail) {
            return new StopReason(
                item.address(), item.origin(), item.edgeKind(), reason, detail);
        }

        private static void validate(FlowRequest request) {
            if (request == null) {
                throw new IllegalArgumentException("request is required");
            }
            if (request.seeds().isEmpty()) {
                throw new IllegalArgumentException("seeds must contain at least one address");
            }
            if (request.restriction().isEmpty()) {
                throw new IllegalArgumentException("restriction must not be empty");
            }
            if (request.maxInstructions() < 1 ||
                request.maxInstructions() > HARD_MAX_INSTRUCTIONS) {
                throw new IllegalArgumentException(
                    "max_instructions must be between 1 and " + HARD_MAX_INSTRUCTIONS);
            }
        }
    }

    private FlowRequest parseRequest(
            Program program,
            String seedsJson,
            String restrictStartText,
            String restrictEndText,
            boolean followCalls,
            boolean preserveDefinedData,
            boolean createFunctions,
            boolean enableAnalysis,
            int maxInstructions) {
        if (maxInstructions < 1 || maxInstructions > HARD_MAX_INSTRUCTIONS) {
            throw new IllegalArgumentException(
                "max_instructions must be between 1 and " + HARD_MAX_INSTRUCTIONS);
        }
        Address restrictStart = parseRequiredAddress(
            program, restrictStartText, "restrict_start");
        Address restrictEnd =
            parseRequiredAddress(program, restrictEndText, "restrict_end");
        if (!restrictStart.getAddressSpace().equals(restrictEnd.getAddressSpace())) {
            throw new IllegalArgumentException(
                "restrict_start and restrict_end must be in the same address space");
        }
        if (restrictStart.compareTo(restrictEnd) > 0) {
            throw new IllegalArgumentException(
                "restrict_start must be less than or equal to restrict_end");
        }

        List<String> seedTexts = parseSeedTexts(seedsJson);
        AddressSet restriction = new AddressSet(restrictStart, restrictEnd);
        AddressSetView initialized =
            program.getMemory().getLoadedAndInitializedAddressSet();
        Set<Address> normalized = new TreeSet<>(Address::compareTo);
        for (String seedText : seedTexts) {
            Address seed = parseRequiredAddress(program, seedText, "seed");
            if (!seed.getAddressSpace().equals(restrictStart.getAddressSpace()) ||
                !restriction.contains(seed)) {
                throw new IllegalArgumentException(
                    "every seed must be inside restriction; outside seed: " + seed);
            }
            if (!initialized.contains(seed)) {
                throw new IllegalArgumentException(
                    "every seed must be in initialized memory; invalid seed: " + seed);
            }
            normalized.add(seed);
        }
        return new FlowRequest(
            List.copyOf(normalized),
            restriction,
            followCalls,
            preserveDefinedData,
            createFunctions,
            enableAnalysis,
            maxInstructions);
    }

    private static List<String> parseSeedTexts(String seedsJson) {
        if (seedsJson == null || seedsJson.isBlank()) {
            throw new IllegalArgumentException(
                "seeds must be a non-empty JSON array of address strings");
        }
        try {
            JsonElement parsed = JsonParser.parseString(seedsJson);
            if (!parsed.isJsonArray() || parsed.getAsJsonArray().isEmpty()) {
                throw new IllegalArgumentException(
                    "seeds must be a non-empty JSON array of address strings");
            }
            List<String> seeds = new ArrayList<>();
            for (JsonElement element : parsed.getAsJsonArray()) {
                if (!element.isJsonPrimitive() ||
                    !element.getAsJsonPrimitive().isString() ||
                    element.getAsString().isBlank()) {
                    throw new IllegalArgumentException(
                        "seeds must be a non-empty JSON array of address strings");
                }
                seeds.add(element.getAsString());
            }
            return List.copyOf(seeds);
        }
        catch (JsonParseException | IllegalStateException e) {
            throw new IllegalArgumentException(
                "seeds must be a non-empty JSON array of address strings", e);
        }
    }

    private static Address parseRequiredAddress(
            Program program,
            String text,
            String fieldName) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
        Address address = ServiceUtils.parseAddress(program, text);
        if (address == null) {
            throw new IllegalArgumentException(
                fieldName + ": " + ServiceUtils.getLastParseError());
        }
        return address;
    }

    private ListingClearCore.Plan prepareClearPlan(Program program, FlowPlan plan) {
        if (plan.clearedData().isEmpty()) {
            return null;
        }
        AddressSet selected = new AddressSet();
        for (DataUnit data : plan.clearedData()) {
            selected.add(data.start(), data.end());
        }
        ListingClearCore.Plan clearPlan = clearCore.plan(
            program,
            selected,
            new ListingClearCore.Selection(false, true, false),
            ListingClearCore.Preservation.defaults());
        if (!clearPlan.conflicts().isEmpty()) {
            throw new IllegalArgumentException(
                "data clear plan has conflicts: " +
                    String.join("; ", clearPlan.conflicts()));
        }
        if (!clearPlan.expanded().hasSameAddresses(selected)) {
            throw new IllegalArgumentException(
                "defined data changed while preparing the clear plan");
        }
        return clearPlan;
    }

    private static FlowPlan preflightFunctions(Program program, FlowPlan plan) {
        List<Conflict> conflicts = new ArrayList<>(plan.conflicts());
        List<FunctionPlan> functions = new ArrayList<>();
        FunctionManager manager = program.getFunctionManager();
        for (FunctionPlan requested : plan.functions()) {
            Function atEntry = manager.getFunctionAt(requested.entry());
            if (atEntry != null) {
                functions.add(new FunctionPlan(
                    requested.entry(), requested.body(), true));
                continue;
            }
            var overlapping = manager.getFunctionsOverlapping(requested.body());
            if (overlapping.hasNext()) {
                Function function = overlapping.next();
                conflicts.add(new Conflict(
                    requested.entry(),
                    function.getEntryPoint(),
                    EdgeKind.SEED,
                    "function_body_overlaps_existing_function",
                    function.getBody().getMinAddress(),
                    function.getBody().getMaxAddress()));
            }
            functions.add(requested);
        }
        conflicts.sort(Comparator.comparing(Conflict::address)
            .thenComparing(conflict -> conflict.edgeKind().ordinal())
            .thenComparing(Conflict::reason));
        return copyPlan(plan, conflicts, functions);
    }

    private static FlowPlan copyPlan(
            FlowPlan plan,
            List<Conflict> conflicts,
            List<FunctionPlan> functions) {
        return new FlowPlan(
            plan.normalizedSeeds(),
            plan.restriction(),
            plan.instructions(),
            plan.plannedNewInstructions(),
            plan.existingInstructions(),
            plan.directCallTargets(),
            plan.directBranchTargets(),
            plan.unresolvedFlows(),
            conflicts,
            plan.stopReasons(),
            plan.clearedData(),
            functions,
            plan.instructionCapReached());
    }

    private CommitResult commitPlan(
            Program program,
            FlowPlan plan,
            ListingClearCore.Plan clearPlan) throws Exception {
        if (!plan.conflicts().isEmpty()) {
            throw new IllegalStateException("cannot commit a flow plan with conflicts");
        }
        if (clearPlan != null) {
            clearCore.apply(program, clearPlan);
        }

        AddressSet expected = plan.plannedNewInstructions();
        AddressSet created = new AddressSet();
        if (!expected.isEmpty()) {
            AddressSet frontier = commitFrontier(plan);
            if (frontier.isEmpty()) {
                throw new IllegalStateException(
                    "planned instructions have no undefined commit frontier");
            }
            created = stockDisassembler.disassemble(
                program, frontier, expected, true);
            if (!created.hasSameAddresses(expected)) {
                throw new IllegalStateException(
                    "stock disassembler diverged from preview; expected " +
                        expected + ", created " + created);
            }
        }

        List<FunctionChange> changes = new ArrayList<>();
        FunctionManager functions = program.getFunctionManager();
        for (FunctionPlan functionPlan : plan.functions()) {
            if (functionPlan.existing()) {
                changes.add(new FunctionChange(
                    functionPlan.entry(),
                    "existing",
                    functionPlan.body().getNumAddresses()));
                continue;
            }
            Function createdFunction = functions.createFunction(
                null,
                functionPlan.entry(),
                functionPlan.body(),
                SourceType.DEFAULT);
            if (createdFunction == null) {
                throw new IllegalStateException(
                    "failed to create function at " + functionPlan.entry());
            }
            changes.add(new FunctionChange(
                functionPlan.entry(),
                "created",
                createdFunction.getBody().getNumAddresses()));
        }
        return new CommitResult(created, changes);
    }

    private static AddressSet commitFrontier(FlowPlan plan) {
        AddressSet expected = plan.plannedNewInstructions();
        AddressSet frontier = new AddressSet();
        for (Address seed : plan.normalizedSeeds()) {
            if (expected.contains(seed)) {
                frontier.add(seed);
            }
        }
        for (InstructionRecord instruction : plan.instructions()) {
            if (!instruction.existing()) {
                continue;
            }
            if (instruction.fallThrough() != null &&
                expected.contains(instruction.fallThrough())) {
                frontier.add(instruction.fallThrough());
            }
            for (Address target : instruction.flows()) {
                if (expected.contains(target)) {
                    frontier.add(target);
                }
            }
        }
        return frontier;
    }

    private static AddressSet disassembleStock(
            Program program,
            AddressSetView starts,
            AddressSetView restriction,
            boolean followFlow) {
        List<String> messages = new ArrayList<>();
        Disassembler disassembler = Disassembler.getDisassembler(
            program, false, false, false, TaskMonitor.DUMMY, messages::add);
        return disassembler.disassemble(starts, restriction, followFlow);
    }

    private static AnalysisSubmission submitAnalysis(
            Program program,
            AddressSetView created) {
        AutoAnalysisManager manager =
            AutoAnalysisManager.getAnalysisManager(program);
        manager.codeDefined(created);
        return new AnalysisSubmission(manager.startBackgroundAnalysis(), null);
    }

    private static Map<String, Object> resultMap(
            Program program,
            FlowRequest request,
            FlowPlan plan,
            CommitResult commit,
            boolean dryRun,
            boolean committed,
            String commitStatus,
            String analysisStatus,
            AnalysisSubmission submission,
            String analysisError) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("program", program.getName());
        result.put("seeds", addresses(plan.normalizedSeeds()));
        result.put("restriction", range(
            request.restriction().getMinAddress(),
            request.restriction().getMaxAddress()));
        result.put("dry_run", dryRun);
        result.put("follow_calls", request.followCalls());
        result.put("preserve_defined_data", request.preserveDefinedData());
        result.put("create_functions", request.createFunctions());
        result.put("enable_analysis", request.enableAnalysis());
        result.put("max_instructions", request.maxInstructions());
        result.put("candidate_instruction_ranges",
            ranges(plan.plannedNewInstructions()));
        result.put("created_instruction_ranges",
            commit == null ? List.of() : ranges(commit.createdInstructions()));
        result.put("existing_instruction_ranges",
            ranges(plan.existingInstructions()));
        result.put("instructions", instructionMaps(plan.instructions()));
        result.put("direct_call_targets", addresses(plan.directCallTargets()));
        result.put("direct_branch_targets", addresses(plan.directBranchTargets()));
        result.put("unresolved_flows", unresolvedMaps(plan.unresolvedFlows()));
        result.put("conflicts", conflictMaps(plan.conflicts()));
        result.put("stop_reasons", stopMaps(plan.stopReasons()));
        result.put("cleared_data", dataMaps(plan.clearedData()));
        result.put("function_changes",
            commit == null
                ? previewFunctionMaps(plan.functions())
                : functionChangeMaps(commit.functionChanges()));
        result.put("instruction_cap_reached", plan.instructionCapReached());
        result.put("commit_status", commitStatus);
        result.put("committed", committed);
        result.put("analysis_status", analysisStatus);
        if (submission != null && submission.queued()) {
            Map<String, Object> descriptor = new LinkedHashMap<>();
            descriptor.put("program", program.getName());
            descriptor.put("address_set", ranges(commit.createdInstructions()));
            descriptor.put("request_identity", submission.requestIdentity());
            result.put("analysis_request", descriptor);
        }
        if (analysisError != null) {
            result.put("analysis_error", analysisError);
        }
        return result;
    }

    private static List<String> addresses(List<Address> addresses) {
        return addresses.stream().map(Address::toString).toList();
    }

    private static List<Address> normalizeAddresses(List<Address> addresses) {
        if (addresses == null || addresses.isEmpty()) {
            return List.of();
        }
        Set<Address> normalized = new TreeSet<>(Address::compareTo);
        for (Address address : addresses) {
            if (address != null) {
                normalized.add(address);
            }
        }
        return List.copyOf(normalized);
    }

    private static List<Map<String, Object>> ranges(AddressSetView set) {
        List<Map<String, Object>> ranges = new ArrayList<>();
        for (AddressRange addressRange : set) {
            ranges.add(range(addressRange.getMinAddress(), addressRange.getMaxAddress()));
        }
        return ranges;
    }

    private static Map<String, Object> range(Address start, Address end) {
        return JsonHelper.mapOf("start", start.toString(), "end", end.toString());
    }

    private static List<Map<String, Object>> instructionMaps(
            List<InstructionRecord> instructions) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (InstructionRecord instruction : instructions) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("address", instruction.address().toString());
            map.put("length", instruction.length());
            map.put("text", instruction.text());
            map.put("status", instruction.existing() ? "existing" : "planned");
            map.put("fall_through",
                instruction.fallThrough() == null
                    ? null
                    : instruction.fallThrough().toString());
            map.put("flows", addresses(instruction.flows()));
            map.put("flow_type",
                instruction.flowType() == null
                    ? null
                    : instruction.flowType().toString());
            result.add(map);
        }
        return result;
    }

    private static List<Map<String, Object>> unresolvedMaps(
            List<UnresolvedFlow> unresolved) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (UnresolvedFlow flow : unresolved) {
            result.add(JsonHelper.mapOf(
                "from", flow.from().toString(),
                "flow_type", flow.flowType(),
                "reason", flow.reason()));
        }
        return result;
    }

    private static List<Map<String, Object>> conflictMaps(List<Conflict> conflicts) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Conflict conflict : conflicts) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("address", conflict.address().toString());
            map.put("origin",
                conflict.origin() == null ? null : conflict.origin().toString());
            map.put("edge", conflict.edgeKind().name().toLowerCase());
            map.put("reason", conflict.reason());
            map.put("unit_start",
                conflict.unitStart() == null ? null : conflict.unitStart().toString());
            map.put("unit_end",
                conflict.unitEnd() == null ? null : conflict.unitEnd().toString());
            result.add(map);
        }
        return result;
    }

    private static List<Map<String, Object>> stopMaps(List<StopReason> stops) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (StopReason stop : stops) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("address", stop.address().toString());
            map.put("origin", stop.origin() == null ? null : stop.origin().toString());
            map.put("edge", stop.edgeKind().name().toLowerCase());
            map.put("reason", stop.reason());
            map.put("detail", stop.detail());
            result.add(map);
        }
        return result;
    }

    private static List<Map<String, Object>> dataMaps(List<DataUnit> data) {
        return data.stream().map(unit -> range(unit.start(), unit.end())).toList();
    }

    private static List<Map<String, Object>> previewFunctionMaps(
            List<FunctionPlan> functions) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (FunctionPlan function : functions) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("entry", function.entry().toString());
            map.put("status", function.existing() ? "existing" : "planned");
            map.put("body", ranges(function.body()));
            result.add(map);
        }
        return result;
    }

    private static List<Map<String, Object>> functionChangeMaps(
            List<FunctionChange> changes) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (FunctionChange change : changes) {
            result.add(JsonHelper.mapOf(
                "entry", change.entry().toString(),
                "status", change.status(),
                "body_size", change.bodySize()));
        }
        return result;
    }

    private static final class GhidraInstructionSource implements InstructionSource {

        private final Program program;
        private final Listing listing;
        private final AddressSetView initialized;
        private final PseudoDisassembler pseudo;

        GhidraInstructionSource(Program program) {
            this.program = program;
            this.listing = program.getListing();
            this.initialized =
                program.getMemory().getLoadedAndInitializedAddressSet();
            this.pseudo = new PseudoDisassembler(program);
            this.pseudo.setRespectExecuteFlag(false);
        }

        @Override
        public Location inspect(Address address) {
            if (!initialized.contains(address)) {
                return Location.uninitialized(address);
            }
            Instruction instruction = listing.getInstructionContaining(address);
            if (instruction != null) {
                if (!instruction.getMinAddress().equals(address)) {
                    return Location.middle(
                        address,
                        instruction.getMinAddress(),
                        instruction.getMaxAddress());
                }
                return Location.existing(decodeInstruction(instruction));
            }
            Data data = listing.getDefinedDataContaining(address);
            if (data != null) {
                return Location.data(
                    address, data.getMinAddress(), data.getMaxAddress());
            }
            CodeUnit unit = listing.getCodeUnitContaining(address);
            if (unit != null && !unit.getMinAddress().equals(address)) {
                return Location.middle(
                    address, unit.getMinAddress(), unit.getMaxAddress());
            }
            return Location.undefined(address);
        }

        @Override
        public DecodedInstruction decode(Address address) throws Exception {
            Instruction instruction = pseudo.disassemble(address);
            return instruction == null ? null : decodeInstruction(instruction);
        }

        @Override
        public List<Location> intersecting(Address start, Address end) {
            Map<Address, Location> locations = new LinkedHashMap<>();
            AddressSet range = new AddressSet(start, end);
            addLocation(locations, listing.getCodeUnitContaining(start));
            CodeUnitIterator iterator = listing.getCodeUnits(range, true);
            while (iterator.hasNext()) {
                addLocation(locations, iterator.next());
            }
            addLocation(locations, listing.getCodeUnitContaining(end));
            return locations.values().stream()
                .sorted(Comparator.comparing(Location::unitStart))
                .toList();
        }

        @Override
        public boolean initialized(Address start, Address end) {
            return initialized.contains(start, end);
        }

        private static void addLocation(
                Map<Address, Location> locations,
                CodeUnit unit) {
            if (unit instanceof Instruction instruction) {
                locations.putIfAbsent(
                    instruction.getMinAddress(),
                    Location.existing(decodeInstruction(instruction)));
            }
            else if (unit instanceof Data data && data.isDefined()) {
                locations.putIfAbsent(
                    data.getMinAddress(),
                    Location.data(
                        data.getMinAddress(),
                        data.getMinAddress(),
                        data.getMaxAddress()));
            }
        }

        private static DecodedInstruction decodeInstruction(Instruction instruction) {
            String[] operands = new String[instruction.getNumOperands()];
            for (int i = 0; i < operands.length; i++) {
                operands[i] = instruction.getDefaultOperandRepresentation(i);
            }
            String text = instruction.getMnemonicString();
            if (operands.length > 0) {
                text += " " + String.join(", ", operands);
            }
            return new DecodedInstruction(
                instruction.getAddress(),
                instruction.getLength(),
                text,
                instruction.getFallThrough(),
                Arrays.asList(instruction.getFlows()),
                instruction.getFlowType());
        }
    }

    private static Address endOf(DecodedInstruction instruction) {
        try {
            return instruction.address().addNoWrap(instruction.length() - 1L);
        }
        catch (AddressOverflowException e) {
            throw new IllegalArgumentException(
                "instruction at " + instruction.address() + " exceeds its address space", e);
        }
    }

    private static String describe(Exception exception) {
        String message = exception.getMessage();
        return exception.getClass().getSimpleName() +
            (message == null || message.isBlank() ? "" : ": " + message);
    }
}
