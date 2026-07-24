package com.xebyte.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/** Transaction-neutral planning and application of manual control-flow facts. */
final class ControlFlowCore {
    static final int MAX_ENTRY_ACTIONS = 10_000;
    static final int MAX_REFERENCE_ACTIONS = 10_000;
    static final int MAX_DISPATCHES = 1_024;
    static final int MAX_OPERAND_BYTES = 1_024;
    static final long MAX_REFERENCE_CROSS_PRODUCT = 1_000_000;

    record EntryAction(Address address, String action) {
    }

    record EntryPointPlan(Program owner, List<EntryAction> actions) {
        EntryPointPlan {
            actions = List.copyOf(actions);
        }
    }

    record FlowOverridePlan(
            Program owner, Address address, FlowOverride previous,
            FlowOverride requested, String action) {
    }

    record ReferenceRequest(
            String from, String to, RefType type, int operandIndex,
            boolean primary) {
    }

    record ReferenceIdentity(
            Address from, Address to, RefType type, int operandIndex) {
    }

    record ReferenceAction(
            ReferenceIdentity identity, SourceType source,
            boolean previousPrimary, boolean resultingPrimary,
            String action, boolean nonUserRemoval) {
    }

    record ReferencePlan(
            Program owner, List<ReferenceAction> removals,
            List<ReferenceAction> additions) {
        ReferencePlan {
            removals = List.copyOf(removals);
            additions = List.copyOf(additions);
        }
    }

    record JumpTablePlan(
            Program owner, DataRegionCore.Plan dataPlan,
            DataRegionCore.RegionPlan region, List<Address> dispatches,
            List<Address> decodedTargets,
            List<ReferenceAction> references, String generatedComment) {
        JumpTablePlan {
            dispatches = List.copyOf(dispatches);
            decodedTargets = List.copyOf(decodedTargets);
            references = List.copyOf(references);
        }
    }

    record SelfModifiedPlan(
            Program owner, Address writer, int writerOperandIndex,
            Address target, List<Address> operandBytes,
            List<ReferenceAction> references,
            AddressCommentCore.Plan writerComment,
            AddressCommentCore.Plan targetComment) {
        SelfModifiedPlan {
            operandBytes = List.copyOf(operandBytes);
            references = List.copyOf(references);
        }
    }

    private record ReferenceSlot(
            Address from, Address to, int operandIndex) {
    }

    private record SourceOperand(Address from, int operandIndex) {
    }

    private final AddressCommentCore comments;
    private final DataRegionCore dataRegions;

    ControlFlowCore() {
        this(new AddressCommentCore(), new DataRegionCore());
    }

    ControlFlowCore(
            AddressCommentCore comments, DataRegionCore dataRegions) {
        this.comments = Objects.requireNonNull(comments);
        this.dataRegions = Objects.requireNonNull(dataRegions);
    }

    EntryPointPlan planEntryPoints(
            Program program, List<String> additions,
            List<String> removals) {
        Objects.requireNonNull(program, "program");
        List<String> add = additions == null ? List.of() : additions;
        List<String> remove = removals == null ? List.of() : removals;
        requireActionCount(
            add.size(), remove.size(), MAX_ENTRY_ACTIONS, "entry-point");
        if (add.isEmpty() && remove.isEmpty()) {
            throw new IllegalArgumentException(
                "at least one entry-point add or remove is required");
        }
        List<Address> resolvedAdd =
            resolveUnique(program, add, "add");
        List<Address> resolvedRemove =
            resolveUnique(program, remove, "remove");
        Set<Address> intersection = new LinkedHashSet<>(resolvedAdd);
        intersection.retainAll(resolvedRemove);
        if (!intersection.isEmpty()) {
            throw new IllegalArgumentException(
                "entry-point addresses cannot appear in both add and remove: "
                    + intersection);
        }

        List<EntryAction> actions = new ArrayList<>();
        for (Address address : resolvedRemove) {
            actions.add(new EntryAction(
                address,
                program.getSymbolTable().isExternalEntryPoint(address)
                    ? "remove" : "unchanged"));
        }
        for (Address address : resolvedAdd) {
            actions.add(new EntryAction(
                address,
                program.getSymbolTable().isExternalEntryPoint(address)
                    ? "unchanged" : "add"));
        }
        return new EntryPointPlan(program, actions);
    }

    void applyEntryPoints(Program program, EntryPointPlan plan) {
        requireOwner(program, plan.owner(), "entry-point");
        for (EntryAction action : plan.actions()) {
            boolean present =
                program.getSymbolTable().isExternalEntryPoint(
                    action.address());
            switch (action.action()) {
                case "add" -> {
                    if (present) {
                        throw changedSincePlan("entry point", action.address());
                    }
                    program.getSymbolTable().addExternalEntryPoint(
                        action.address());
                }
                case "remove" -> {
                    if (!present) {
                        throw changedSincePlan("entry point", action.address());
                    }
                    program.getSymbolTable().removeExternalEntryPoint(
                        action.address());
                }
                case "unchanged" -> {
                    // The plan already records the desired idempotent state.
                }
                default -> throw new IllegalStateException(
                    "unknown entry-point action: " + action.action());
            }
        }
    }

    FlowOverridePlan planFlowOverride(
            Program program, String addressText, FlowOverride requested) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(requested, "requested");
        Instruction instruction =
            requireInstruction(program, addressText, "address");
        FlowOverride previous = instruction.getFlowOverride();
        return new FlowOverridePlan(
            program, instruction.getAddress(), previous, requested,
            previous == requested ? "unchanged" : "set");
    }

    void applyFlowOverride(Program program, FlowOverridePlan plan) {
        requireOwner(program, plan.owner(), "flow-override");
        Instruction instruction =
            program.getListing().getInstructionAt(plan.address());
        if (instruction == null) {
            throw changedSincePlan("instruction", plan.address());
        }
        if (instruction.getFlowOverride() != plan.previous()) {
            throw changedSincePlan("flow override", plan.address());
        }
        if ("set".equals(plan.action())) {
            instruction.setFlowOverride(plan.requested());
        }
        if (instruction.getFlowOverride() != plan.requested()) {
            throw new IllegalStateException(
                "Ghidra rejected flow override " + plan.requested()
                    + " at " + plan.address());
        }
    }

    ReferencePlan planReferences(
            Program program, List<ReferenceRequest> additions,
            List<ReferenceRequest> removals,
            boolean allowNonUserRemoval) {
        Objects.requireNonNull(program, "program");
        List<ReferenceRequest> add =
            additions == null ? List.of() : additions;
        List<ReferenceRequest> remove =
            removals == null ? List.of() : removals;
        requireActionCount(
            add.size(), remove.size(), MAX_REFERENCE_ACTIONS, "reference");
        if (add.isEmpty() && remove.isEmpty()) {
            throw new IllegalArgumentException(
                "at least one reference add or remove is required");
        }

        List<ReferenceIdentity> resolvedRemove =
            resolveReferenceRequests(program, remove, "remove");
        List<ReferenceIdentity> resolvedAdd =
            resolveReferenceRequests(program, add, "add");
        requireUniqueIdentities(resolvedRemove, "remove");
        requireUniqueIdentities(resolvedAdd, "add");
        requireUniqueSlots(resolvedAdd, "add");
        Set<ReferenceIdentity> overlap =
            new LinkedHashSet<>(resolvedRemove);
        overlap.retainAll(resolvedAdd);
        if (!overlap.isEmpty()) {
            throw new IllegalArgumentException(
                "the same exact reference cannot appear in both add and "
                    + "remove: " + overlap);
        }

        ReferenceManager manager = program.getReferenceManager();
        List<ReferenceAction> removeActions = new ArrayList<>();
        Set<ReferenceSlot> removedSlots = new LinkedHashSet<>();
        for (ReferenceIdentity identity : resolvedRemove) {
            Reference existing = manager.getReference(
                identity.from(), identity.to(), identity.operandIndex());
            if (existing == null
                    || existing.getReferenceType() != identity.type()) {
                throw new IllegalArgumentException(
                    "no exact reference exists for removal: "
                        + describe(identity, existing));
            }
            boolean nonUser =
                existing.getSource() != SourceType.USER_DEFINED;
            if (nonUser && !allowNonUserRemoval) {
                throw new IllegalArgumentException(
                    "removing non-user reference requires "
                        + "allow_non_user_removal=true: "
                        + describe(identity, existing));
            }
            removeActions.add(new ReferenceAction(
                identity, existing.getSource(), existing.isPrimary(),
                false, "remove", nonUser));
            removedSlots.add(slot(identity));
        }

        List<ReferenceAction> addActions = new ArrayList<>();
        for (int i = 0; i < resolvedAdd.size(); i++) {
            ReferenceIdentity identity = resolvedAdd.get(i);
            boolean requestedPrimary = add.get(i).primary();
            Reference existing = removedSlots.contains(slot(identity))
                ? null
                : manager.getReference(
                    identity.from(), identity.to(),
                    identity.operandIndex());
            addActions.add(planReferenceAdd(
                identity, existing, requestedPrimary));
        }
        validatePrimaryTransitions(
            program, removeActions, addActions);
        return new ReferencePlan(program, removeActions, addActions);
    }

    void applyReferences(Program program, ReferencePlan plan) {
        requireOwner(program, plan.owner(), "reference");
        applyReferenceRemovals(program, plan.removals());
        applyReferenceAdditions(program, plan.additions());
    }

    JumpTablePlan planJumpTable(
            Program program, DataRegionCore.RegionRequest request,
            List<String> dispatchTexts, RefType referenceType,
            TaskMonitor monitor) throws Exception {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(request, "table");
        if (referenceType != RefType.COMPUTED_JUMP
                && referenceType != RefType.UNCONDITIONAL_JUMP) {
            throw new IllegalArgumentException(
                "jump-table reference type must be computed_jump or jump");
        }
        if (dispatchTexts == null || dispatchTexts.isEmpty()
                || dispatchTexts.size() > MAX_DISPATCHES) {
            throw new IllegalArgumentException(
                "dispatch_addresses must contain between 1 and "
                    + MAX_DISPATCHES + " items");
        }
        List<Address> dispatches = new ArrayList<>();
        Set<Address> seen = new LinkedHashSet<>();
        for (String text : dispatchTexts) {
            Instruction instruction =
                requireInstruction(program, text, "dispatch address");
            if (!seen.add(instruction.getAddress())) {
                throw new IllegalArgumentException(
                    "duplicate dispatch address: "
                        + instruction.getAddress());
            }
            dispatches.add(instruction.getAddress());
        }

        String generated =
            jumpTableComment(request, dispatches);
        DataRegionCore.RegionRequest normalized =
            withPlateComment(request, generated);
        DataRegionCore.Plan dataPlan =
            dataRegions.plan(program, List.of(normalized), monitor);
        DataRegionCore.RegionPlan region = dataPlan.regions().get(0);
        if (region.pointers().isEmpty()) {
            throw new IllegalArgumentException(
                "table must decode at least one two-byte pointer");
        }
        if (request instanceof DataRegionCore.ContiguousRequest
                && (region.pointerOptions() == null
                    || region.dataLength() != 2)) {
            throw new IllegalArgumentException(
                "contiguous jump table must be a two-byte pointer region");
        }

        Set<Address> uniqueTargets = new LinkedHashSet<>();
        for (DataRegionCore.PointerPlan pointer : region.pointers()) {
            if (pointer.valid() && pointer.target() != null) {
                uniqueTargets.add(referenceTarget(pointer.target()));
            }
        }
        long crossProduct =
            (long) dispatches.size() * uniqueTargets.size();
        if (crossProduct > MAX_REFERENCE_CROSS_PRODUCT) {
            throw new IllegalArgumentException(
                "jump-table reference cross product exceeds "
                    + MAX_REFERENCE_CROSS_PRODUCT);
        }
        List<ReferenceAction> references = new ArrayList<>();
        ReferenceManager manager = program.getReferenceManager();
        for (Address dispatch : dispatches) {
            for (Address target : uniqueTargets) {
                ReferenceIdentity identity = new ReferenceIdentity(
                    dispatch, target,
                    referenceType, Reference.MNEMONIC);
                references.add(planReferenceAdd(
                    identity,
                    manager.getReference(
                        dispatch, target, Reference.MNEMONIC),
                    false));
            }
        }
        return new JumpTablePlan(
            program, dataPlan, region, dispatches,
            List.copyOf(uniqueTargets), references, generated);
    }

    void applyJumpTable(
            Program program, JumpTablePlan plan, TaskMonitor monitor)
            throws Exception {
        requireOwner(program, plan.owner(), "jump-table");
        TaskMonitor taskMonitor =
            monitor == null ? TaskMonitor.DUMMY : monitor;
        dataRegions.apply(program, plan.dataPlan(), taskMonitor);
        for (Address dispatch : plan.dispatches()) {
            taskMonitor.checkCancelled();
            if (program.getListing().getInstructionAt(dispatch) == null) {
                throw new IllegalStateException(
                    "jump-table data application removed dispatch "
                        + "instruction at " + dispatch);
            }
        }
        applyReferenceAdditions(program, plan.references());
    }

    SelfModifiedPlan planSelfModified(
            Program program, String writerText, int writerOperandIndex,
            String targetText, List<String> byteTexts,
            String valueSource, String targetComment,
            boolean appendTargetComment) {
        Objects.requireNonNull(program, "program");
        Instruction writer =
            requireInstruction(program, writerText, "writer instruction");
        validateOperandIndex(
            writer, writerOperandIndex, "writer_operand_index");
        Instruction target =
            requireInstruction(program, targetText, "target instruction");
        if (byteTexts == null || byteTexts.isEmpty()
                || byteTexts.size() > MAX_OPERAND_BYTES) {
            throw new IllegalArgumentException(
                "operand_byte_addresses must contain between 1 and "
                    + MAX_OPERAND_BYTES + " items");
        }
        List<Address> bytes =
            resolveUnique(program, byteTexts, "operand_byte_addresses");
        for (Address address : bytes) {
            if (address.getAddressSpace()
                    != target.getAddress().getAddressSpace()
                    || address.compareTo(target.getMinAddress()) < 0
                    || address.compareTo(target.getMaxAddress()) > 0) {
                throw new IllegalArgumentException(
                    "operand byte " + address
                        + " is outside target instruction "
                        + target.getMinAddress() + "-"
                        + target.getMaxAddress());
            }
        }

        List<ReferenceAction> references = new ArrayList<>();
        ReferenceManager manager = program.getReferenceManager();
        for (Address address : bytes) {
            ReferenceIdentity identity = new ReferenceIdentity(
                writer.getAddress(), referenceTarget(address), RefType.WRITE,
                writerOperandIndex);
            references.add(planReferenceAdd(
                identity,
                manager.getReference(
                    writer.getAddress(), identity.to(),
                    writerOperandIndex),
                false));
        }
        String evidence =
            selfModifiedComment(target.getAddress(), bytes, valueSource);
        AddressCommentCore.Plan writerPlan = comments.plan(
            program,
            new AddressCommentCore.ResolvedAddress(
                program, writer.getAddress()),
            CommentType.PRE, evidence,
            AddressCommentCore.WriteMode.APPEND_IDEMPOTENT);

        AddressCommentCore.Plan targetPlan = null;
        String normalizedComment = blankToNull(targetComment);
        if (normalizedComment != null) {
            AddressCommentCore.ResolvedAddress resolved =
                new AddressCommentCore.ResolvedAddress(
                    program, target.getAddress());
            String previous = program.getListing().getComment(
                CommentType.PLATE, target.getAddress());
            if (previous != null
                    && !previous.equals(normalizedComment)
                    && !appendTargetComment) {
                throw new IllegalArgumentException(
                    "different plate comment already exists at "
                        + target.getAddress()
                        + "; set append_comment=true to preserve it");
            }
            targetPlan = comments.plan(
                program, resolved, CommentType.PLATE, normalizedComment,
                appendTargetComment
                    ? AddressCommentCore.WriteMode.APPEND_IDEMPOTENT
                    : AddressCommentCore.WriteMode.REPLACE);
        }
        return new SelfModifiedPlan(
            program, writer.getAddress(), writerOperandIndex,
            target.getAddress(), bytes, references,
            writerPlan, targetPlan);
    }

    void applySelfModified(Program program, SelfModifiedPlan plan) {
        requireOwner(program, plan.owner(), "self-modification");
        if (program.getListing().getInstructionAt(plan.writer()) == null
                || program.getListing().getInstructionAt(
                    plan.target()) == null) {
            throw new IllegalStateException(
                "writer or target instruction changed since planning");
        }
        applyReferenceAdditions(program, plan.references());
        comments.apply(program, plan.writerComment());
        if (plan.targetComment() != null) {
            comments.apply(program, plan.targetComment());
        }
    }

    private List<ReferenceIdentity> resolveReferenceRequests(
            Program program, List<ReferenceRequest> requests,
            String description) {
        List<ReferenceIdentity> result = new ArrayList<>();
        for (int i = 0; i < requests.size(); i++) {
            ReferenceRequest request = requests.get(i);
            Address from = resolve(
                program, request.from(),
                description + "[" + i + "].from");
            Address to = referenceTarget(resolve(
                program, request.to(),
                description + "[" + i + "].to"));
            validateOperandIndex(
                program.getListing().getInstructionAt(from),
                request.operandIndex(),
                description + "[" + i + "].operand_index");
            result.add(new ReferenceIdentity(
                from, to, request.type(), request.operandIndex()));
        }
        return List.copyOf(result);
    }

    private ReferenceAction planReferenceAdd(
            ReferenceIdentity identity, Reference existing,
            boolean primary) {
        if (existing == null) {
            return new ReferenceAction(
                identity, SourceType.USER_DEFINED,
                false, primary, "create", false);
        }
        if (existing.getReferenceType() != identity.type()
                || existing.getSource() != SourceType.USER_DEFINED) {
            throw new IllegalArgumentException(
                "incompatible reference already exists: "
                    + describe(identity, existing));
        }
        return new ReferenceAction(
            identity, existing.getSource(), existing.isPrimary(), primary,
            existing.isPrimary() == primary
                ? "unchanged" : "set_primary",
            false);
    }

    private static void applyReferenceRemovals(
            Program program, List<ReferenceAction> actions) {
        ReferenceManager manager = program.getReferenceManager();
        for (ReferenceAction action : actions) {
            ReferenceIdentity identity = action.identity();
            Reference existing = manager.getReference(
                identity.from(), identity.to(), identity.operandIndex());
            requireExactReference(existing, action, "remove");
            manager.delete(existing);
            if (manager.getReference(
                    identity.from(), identity.to(),
                    identity.operandIndex()) != null) {
                throw new IllegalStateException(
                    "Ghidra did not remove reference: " + identity);
            }
        }
    }

    private static void applyReferenceAdditions(
            Program program, List<ReferenceAction> actions) {
        ReferenceManager manager = program.getReferenceManager();
        for (ReferenceAction action : actions) {
            ReferenceIdentity identity = action.identity();
            Reference current = manager.getReference(
                identity.from(), identity.to(), identity.operandIndex());
            Reference resulting;
            switch (action.action()) {
                case "create" -> {
                    if (current != null) {
                        throw changedSincePlan("reference", identity);
                    }
                    resulting = manager.addMemoryReference(
                        identity.from(), identity.to(), identity.type(),
                        SourceType.USER_DEFINED, identity.operandIndex());
                }
                case "set_primary", "unchanged" -> {
                    requireExactReference(current, action, action.action());
                    resulting = current;
                }
                default -> throw new IllegalStateException(
                    "unknown reference add action: " + action.action());
            }
            manager.setPrimary(resulting, action.resultingPrimary());
            Reference verified = manager.getReference(
                identity.from(), identity.to(), identity.operandIndex());
            if (verified == null
                    || verified.getReferenceType() != identity.type()
                    || verified.getSource() != SourceType.USER_DEFINED
                    || verified.isPrimary() != action.resultingPrimary()) {
                throw new IllegalStateException(
                    "Ghidra did not apply exact reference state: "
                        + describe(identity, verified));
            }
        }
    }

    private static void requireExactReference(
            Reference existing, ReferenceAction action,
            String operation) {
        ReferenceIdentity identity = action.identity();
        if (existing == null
                || existing.getReferenceType() != identity.type()
                || existing.getSource() != action.source()
                || existing.isPrimary() != action.previousPrimary()) {
            throw new IllegalStateException(
                "reference changed before " + operation + ": "
                    + describe(identity, existing));
        }
    }

    private static void validatePrimaryTransitions(
            Program program, List<ReferenceAction> removals,
            List<ReferenceAction> additions) {
        Set<ReferenceIdentity> removed = new LinkedHashSet<>();
        removals.forEach(action -> removed.add(action.identity()));
        Map<SourceOperand, ReferenceIdentity> primary =
            new LinkedHashMap<>();
        Set<SourceOperand> initialized = new LinkedHashSet<>();
        ReferenceManager manager = program.getReferenceManager();

        for (ReferenceAction action : additions) {
            ReferenceIdentity identity = action.identity();
            SourceOperand key = new SourceOperand(
                identity.from(), identity.operandIndex());
            if (initialized.add(key)) {
                for (Reference reference
                        : manager.getReferencesFrom(identity.from())) {
                    if (reference.getOperandIndex()
                            != identity.operandIndex()
                            || !reference.isPrimary()) {
                        continue;
                    }
                    ReferenceIdentity existing =
                        new ReferenceIdentity(
                            reference.getFromAddress(),
                            reference.getToAddress(),
                            reference.getReferenceType(),
                            reference.getOperandIndex());
                    if (!removed.contains(existing)) {
                        primary.put(key, existing);
                    }
                    break;
                }
            }

            ReferenceIdentity current = primary.get(key);
            if (action.resultingPrimary()) {
                if (current != null && !current.equals(identity)) {
                    throw new IllegalArgumentException(
                        "setting primary would implicitly demote "
                            + current + "; add an earlier primary=false "
                            + "action for that user reference or remove it "
                            + "explicitly");
                }
                primary.put(key, identity);
            }
            else if (identity.equals(current)) {
                primary.remove(key);
            }
        }
    }

    private Instruction requireInstruction(
            Program program, String text, String description) {
        Address address = resolve(program, text, description);
        Instruction instruction =
            program.getListing().getInstructionAt(address);
        if (instruction == null) {
            throw new IllegalArgumentException(
                "no instruction starts at " + description + " " + address);
        }
        return instruction;
    }

    private Address resolve(
            Program program, String text, String description) {
        try {
            return comments.resolveAddress(program, text).address();
        }
        catch (IllegalArgumentException error) {
            throw new IllegalArgumentException(
                description + ": " + error.getMessage(), error);
        }
    }

    private List<Address> resolveUnique(
            Program program, List<String> texts, String description) {
        List<Address> result = new ArrayList<>();
        Set<Address> seen = new LinkedHashSet<>();
        for (int i = 0; i < texts.size(); i++) {
            Address address =
                resolve(program, texts.get(i), description + "[" + i + "]");
            if (!seen.add(address)) {
                throw new IllegalArgumentException(
                    "duplicate address in " + description + ": " + address);
            }
            result.add(address);
        }
        return List.copyOf(result);
    }

    private static void validateOperandIndex(
            Instruction instruction, int operandIndex, String description) {
        if (operandIndex < Reference.MNEMONIC) {
            throw new IllegalArgumentException(
                description + " must be -1 or an instruction operand");
        }
        if (operandIndex == Reference.MNEMONIC) {
            return;
        }
        if (instruction == null) {
            throw new IllegalArgumentException(
                description
                    + " requires from to be an instruction address");
        }
        if (operandIndex >= instruction.getNumOperands()) {
            throw new IllegalArgumentException(
                description + " " + operandIndex
                    + " is outside instruction operand range 0.."
                    + Math.max(-1, instruction.getNumOperands() - 1));
        }
    }

    private static void requireUniqueIdentities(
            List<ReferenceIdentity> identities, String description) {
        Set<ReferenceIdentity> seen = new LinkedHashSet<>();
        for (ReferenceIdentity identity : identities) {
            if (!seen.add(identity)) {
                throw new IllegalArgumentException(
                    "duplicate exact reference in " + description + ": "
                        + identity);
            }
        }
    }

    private static void requireUniqueSlots(
            List<ReferenceIdentity> identities, String description) {
        Set<ReferenceSlot> seen = new LinkedHashSet<>();
        for (ReferenceIdentity identity : identities) {
            if (!seen.add(slot(identity))) {
                throw new IllegalArgumentException(
                    "multiple reference types cannot be added at the same "
                        + "from/to/operand slot in " + description + ": "
                        + slot(identity));
            }
        }
    }

    private static void requireActionCount(
            int additions, int removals, int maximum,
            String description) {
        long total = (long) additions + removals;
        if (total > maximum) {
            throw new IllegalArgumentException(
                description + " batch exceeds " + maximum + " actions");
        }
    }

    private static ReferenceSlot slot(ReferenceIdentity identity) {
        return new ReferenceSlot(
            identity.from(), identity.to(), identity.operandIndex());
    }

    private static Address referenceTarget(Address address) {
        if (address.getAddressSpace() instanceof OverlayAddressSpace overlay) {
            return overlay.translateAddress(address);
        }
        return address;
    }

    private static String describe(
            ReferenceIdentity expected, Reference actual) {
        if (actual == null) {
            return expected + " (actual: absent)";
        }
        return expected + " (actual: type="
            + actual.getReferenceType() + ", source="
            + actual.getSource() + ", operand_index="
            + actual.getOperandIndex() + ", primary="
            + actual.isPrimary() + ")";
    }

    private static String jumpTableComment(
            DataRegionCore.RegionRequest request,
            List<Address> dispatches) {
        String layout;
        int count;
        if (request instanceof DataRegionCore.ContiguousRequest contiguous) {
            if (contiguous.pointers() == null) {
                throw new IllegalArgumentException(
                    "contiguous jump table requires pointer options");
            }
            layout = contiguous.pointers().layout();
            count = -1;
        }
        else {
            DataRegionCore.SplitPointerRequest split =
                (DataRegionCore.SplitPointerRequest) request;
            layout = split.layout();
            count = split.count();
        }
        StringBuilder text = new StringBuilder(
            "Manual jump table\nLayout: ").append(layout);
        if (count >= 0) {
            text.append("\nEntries: ").append(count);
        }
        text.append("\nDispatch instructions: ");
        for (int i = 0; i < dispatches.size(); i++) {
            if (i > 0) {
                text.append(", ");
            }
            text.append(dispatches.get(i));
        }
        return text.toString();
    }

    private static DataRegionCore.RegionRequest withPlateComment(
            DataRegionCore.RegionRequest request, String generated) {
        DataRegionCore.Metadata original = request.metadata();
        String caller = original == null
            ? null : blankToNull(original.plateComment());
        String combined = caller == null
            ? generated : caller + "\n\n" + generated;
        DataRegionCore.Metadata metadata = new DataRegionCore.Metadata(
            original == null ? null : original.name(),
            original == null ? null : original.namespace(),
            combined,
            original != null && original.clearConflicts());
        if (request instanceof DataRegionCore.ContiguousRequest contiguous) {
            return new DataRegionCore.ContiguousRequest(
                contiguous.start(), contiguous.end(),
                contiguous.typeName(), contiguous.stride(),
                contiguous.allowTrailingBytes(), contiguous.pointers(),
                metadata);
        }
        DataRegionCore.SplitPointerRequest split =
            (DataRegionCore.SplitPointerRequest) request;
        return new DataRegionCore.SplitPointerRequest(
            split.firstStart(), split.secondStart(), split.count(),
            split.layout(), split.pointers(), metadata);
    }

    private static String selfModifiedComment(
            Address target, List<Address> bytes, String valueSource) {
        StringBuilder text = new StringBuilder(
            "Self-modifying operand evidence\nTarget instruction: ")
                .append(target)
                .append("\nOperand bytes: ");
        for (int i = 0; i < bytes.size(); i++) {
            if (i > 0) {
                text.append(", ");
            }
            text.append(bytes.get(i));
        }
        String source = blankToNull(valueSource);
        if (source != null) {
            text.append("\nValue source: ").append(source);
        }
        return text.toString();
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static void requireOwner(
            Program expected, Program actual, String description) {
        if (expected != actual) {
            throw new IllegalArgumentException(
                description + " plan belongs to a different program");
        }
    }

    private static IllegalStateException changedSincePlan(
            String description, Object identity) {
        return new IllegalStateException(
            description + " changed since planning: " + identity);
    }
}
