package com.xebyte.core;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.data.FactoryDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.task.TaskMonitor;

/** Transaction-neutral planner and applier for atomic range data definitions. */
final class DataRegionCore {
    static final int MAX_REGIONS = 1024;
    static final long MAX_PLANNED_ELEMENTS = 1_000_000;

    record RangeMath(
            long elementCount,
            BigInteger trailingStart,
            BigInteger trailingEnd) {
        boolean hasTrailing() {
            return trailingStart != null;
        }
    }

    record Metadata(
            String name, String namespace, String plateComment,
            boolean clearConflicts) {
    }

    record PointerOptions(
            String layout, String targetSpace, BigInteger targetBase,
            boolean createReferences, boolean validateTargets,
            String targetLabelPrefix, String labelNamespace) {
    }

    sealed interface RegionRequest
            permits ContiguousRequest, SplitPointerRequest {
        Metadata metadata();
    }

    record ContiguousRequest(
            String start, String end, String typeName, BigInteger stride,
            boolean allowTrailingBytes, PointerOptions pointers,
            Metadata metadata) implements RegionRequest {
    }

    record SplitPointerRequest(
            String firstStart, String secondStart, int count, String layout,
            PointerOptions pointers, Metadata metadata)
            implements RegionRequest {
    }

    record PointerPlan(
            List<Address> sources, Address target, long decoded,
            boolean valid, String invalidReason, String labelName) {
        PointerPlan {
            sources = List.copyOf(sources);
        }
    }

    record DataAction(
            Address address, DataType dataType, int length, String action) {
    }

    record SymbolAction(
            Address address, String name, String namespace, String kind,
            String action, String reason, boolean primary) {
    }

    record ReferenceAction(
            Address from, Address to, String action, String reason) {
    }

    record NamespaceAction(String name, String action) {
    }

    record RegionPlan(
            RegionRequest request, String kind, Address placement,
            List<Address> elementAddresses,
            DataType dataType, int dataLength, BigInteger stride,
            Address trailingStart, Address trailingEnd,
            List<Address> splitFirst, List<Address> splitSecond,
            List<PointerPlan> pointers, PointerOptions pointerOptions,
            AddressCommentCore.Plan platePlan, Metadata metadata,
            List<DataAction> dataActions,
            List<SymbolAction> symbolActions,
            List<ReferenceAction> referenceActions) {
        RegionPlan {
            elementAddresses = List.copyOf(elementAddresses);
            splitFirst = List.copyOf(splitFirst);
            splitSecond = List.copyOf(splitSecond);
            pointers = List.copyOf(pointers);
            dataActions = List.copyOf(dataActions);
            symbolActions = List.copyOf(symbolActions);
            referenceActions = List.copyOf(referenceActions);
        }
    }

    record Plan(
            Program owner, List<RegionPlan> regions,
            ListingClearCore.Plan clearPlan,
            List<String> conflicts,
            List<NamespaceAction> namespaceActions) {
        Plan {
            regions = List.copyOf(regions);
            conflicts = List.copyOf(conflicts);
            namespaceActions = List.copyOf(namespaceActions);
        }
    }

    private final ListingClearCore listingClear;
    private final AddressCommentCore comments;

    DataRegionCore() {
        this(new ListingClearCore(), new AddressCommentCore());
    }

    DataRegionCore(
            ListingClearCore listingClear, AddressCommentCore comments) {
        this.listingClear = Objects.requireNonNull(listingClear);
        this.comments = Objects.requireNonNull(comments);
    }

    static RangeMath rangeMath(
            long start, long end, long dataLength, long stride,
            boolean allowTrailing) {
        return rangeMath(
            unsigned(start), unsigned(end),
            BigInteger.valueOf(dataLength),
            BigInteger.valueOf(stride),
            allowTrailing);
    }

    private static RangeMath rangeMath(
            BigInteger start, BigInteger end, BigInteger dataLength,
            BigInteger stride, boolean allowTrailing) {
        if (end.compareTo(start) < 0) {
            throw new IllegalArgumentException("end must not precede start");
        }
        if (dataLength.signum() <= 0) {
            throw new IllegalArgumentException(
                "datatype length must be positive");
        }
        if (stride.compareTo(dataLength) < 0) {
            throw new IllegalArgumentException(
                "stride must be at least datatype length");
        }
        BigInteger length = end.subtract(start).add(BigInteger.ONE);
        BigInteger countValue = length.compareTo(dataLength) < 0
            ? BigInteger.ZERO
            : length.subtract(dataLength).divide(stride)
                .add(BigInteger.ONE);
        final long count;
        try {
            count = countValue.longValueExact();
        }
        catch (ArithmeticException error) {
            throw new IllegalArgumentException(
                "element count exceeds supported range", error);
        }
        BigInteger usedEnd = count == 0
            ? null
            : start.add(
                stride.multiply(BigInteger.valueOf(count - 1)))
                .add(dataLength).subtract(BigInteger.ONE);
        boolean trailing = count == 0 || !usedEnd.equals(end);
        if (trailing && !allowTrailing) {
            throw new IllegalArgumentException(
                "region has trailing bytes; set allow_trailing_bytes=true");
        }
        return new RangeMath(
            count,
            trailing
                ? (count == 0 ? start : usedEnd.add(BigInteger.ONE))
                : null,
            trailing ? end : null);
    }

    static void validateSplitRanges(
            Address firstStart, Address secondStart, long count) {
        if (count <= 0) {
            throw new IllegalArgumentException("count must be positive");
        }
        Address firstEnd = splitSourceEnd(
            firstStart, count, "first");
        Address secondEnd = splitSourceEnd(
            secondStart, count, "second");
        if (firstStart.getAddressSpace() == secondStart.getAddressSpace()
                && firstStart.compareTo(secondEnd) <= 0
                && secondStart.compareTo(firstEnd) <= 0) {
            throw new IllegalArgumentException(
                "split pointer source ranges overlap");
        }
    }

    private static Address splitSourceEnd(
            Address start, long count, String description) {
        AddressSpace space = start.getAddressSpace();
        BigInteger endOffset = start.getOffsetAsBigInteger()
            .add(BigInteger.valueOf(count - 1));
        BigInteger min = space.getMinAddress().getOffsetAsBigInteger();
        BigInteger max = space.getMaxAddress().getOffsetAsBigInteger();
        if (endOffset.compareTo(min) < 0
                || endOffset.compareTo(max) > 0) {
            throw new IllegalArgumentException(
                description
                    + " split pointer source range exceeds address space "
                    + space.getName());
        }
        try {
            return space.getAddress(endOffset.longValue());
        }
        catch (RuntimeException error) {
            throw new IllegalArgumentException(
                description
                    + " split pointer source range exceeds address space "
                    + space.getName(),
                error);
        }
    }

    static long addPlannedElements(long current, long addition) {
        if (current < 0 || addition < 0
                || addition > MAX_PLANNED_ELEMENTS - current) {
            throw new IllegalArgumentException(
                "request exceeds the aggregate limit of "
                    + MAX_PLANNED_ELEMENTS + " planned elements");
        }
        return current + addition;
    }

    private static BigInteger unsigned(long value) {
        return value >= 0
            ? BigInteger.valueOf(value)
            : BigInteger.valueOf(value & Long.MAX_VALUE)
                .setBit(Long.SIZE - 1);
    }

    static long decodeWord(int first, int second, String layout) {
        return switch (layout) {
            case "little_endian_words", "split_low_high" ->
                (first & 0xffL) | ((second & 0xffL) << 8);
            case "big_endian_words", "split_high_low" ->
                ((first & 0xffL) << 8) | (second & 0xffL);
            default -> throw new IllegalArgumentException(
                "Unsupported pointer layout: " + layout);
        };
    }

    Plan plan(Program program, List<RegionRequest> requests) throws Exception {
        return plan(program, requests, TaskMonitor.DUMMY);
    }

    Plan plan(
            Program program, List<RegionRequest> requests,
            TaskMonitor monitor) throws Exception {
        Objects.requireNonNull(program, "program");
        if (requests == null || requests.isEmpty()) {
            throw new IllegalArgumentException("regions must not be empty");
        }
        if (requests.size() > MAX_REGIONS) {
            throw new IllegalArgumentException("too many regions");
        }
        List<RegionPlan> regions = new ArrayList<>();
        AddressSet requestedBytes = new AddressSet();
        AddressSet clearBytes = new AddressSet();
        boolean anyClear = false;
        long plannedElements = 0;
        TaskMonitor taskMonitor =
            monitor == null ? TaskMonitor.DUMMY : monitor;
        for (RegionRequest request : requests) {
            taskMonitor.checkCancelled();
            long remaining = MAX_PLANNED_ELEMENTS - plannedElements;
            RegionPlan region = request instanceof ContiguousRequest c
                ? planContiguous(program, c, remaining, taskMonitor)
                : planSplit(
                    program, (SplitPointerRequest) request,
                    remaining, taskMonitor);
            long logicalElements = "contiguous".equals(region.kind())
                ? region.elementAddresses().size()
                : region.splitFirst().size();
            plannedElements = addPlannedElements(
                plannedElements, logicalElements);
            for (Address address : definitionAddresses(region)) {
                Address end = address.addNoWrap(region.dataLength() - 1L);
                if (!program.getMemory().contains(address, end)) {
                    throw new IllegalArgumentException(
                        "complete data definition is not mapped: "
                            + address + "-" + end);
                }
                AddressSet one = new AddressSet(address, end);
                if (requestedBytes.intersects(one)) {
                    throw new IllegalArgumentException(
                        "requested data definitions overlap at " + address);
                }
                requestedBytes.add(one);
                if (hasNonEquivalentUnit(
                        program, address, region.dataType(),
                        region.dataLength())) {
                    if (!region.metadata().clearConflicts()) {
                        throw new IllegalArgumentException(
                            "code/data conflict at " + address);
                    }
                    clearBytes.add(one);
                    anyClear = true;
                }
            }
            regions.add(planActions(program, region));
        }
        ListingClearCore.Plan clearPlan = null;
        if (anyClear) {
            clearPlan = listingClear.plan(
                program, clearBytes,
                new ListingClearCore.Selection(true, true, true),
                ListingClearCore.Preservation.defaults());
            if (!clearPlan.conflicts().isEmpty()) {
                throw new IllegalArgumentException(
                    "cannot clear conflicts: " + clearPlan.conflicts());
            }
        }
        regions = normalizeAndValidateBatchActions(regions);
        List<String> conflicts = clearPlan == null
            ? List.of()
            : clearPlan.units().stream()
                .map(unit -> unit.kind().name().toLowerCase()
                    + ":" + unit.start() + "-" + unit.end())
                .toList();
        return new Plan(
            program, regions, clearPlan, conflicts,
            planNamespaces(program, regions));
    }

    void apply(Program program, Plan plan, TaskMonitor monitor)
            throws Exception {
        Objects.requireNonNull(program);
        Objects.requireNonNull(plan);
        if (plan.owner() != program) {
            throw new IllegalArgumentException(
                "data-region plan belongs to a different program");
        }
        TaskMonitor taskMonitor =
            monitor == null ? TaskMonitor.DUMMY : monitor;
        taskMonitor.checkCancelled();
        if (plan.clearPlan() != null) {
            listingClear.apply(program, plan.clearPlan(), taskMonitor);
        }
        for (NamespaceAction action : plan.namespaceActions()) {
            taskMonitor.checkCancelled();
            if ("create".equals(action.action())) {
                resolveNamespace(program, action.name(), true);
            }
        }
        for (RegionPlan region : plan.regions()) {
            taskMonitor.checkCancelled();
            for (DataAction action : region.dataActions()) {
                taskMonitor.checkCancelled();
                if ("create".equals(action.action())) {
                    program.getListing().createData(
                        action.address(), action.dataType());
                }
            }
            if (region.platePlan() != null) {
                taskMonitor.checkCancelled();
                comments.apply(program, region.platePlan());
            }
            applySymbols(
                program, region.symbolActions(), taskMonitor);
            applyReferences(
                program, region.referenceActions(), taskMonitor);
        }
    }

    private RegionPlan planContiguous(
            Program program, ContiguousRequest request,
            long remainingElements, TaskMonitor monitor) throws Exception {
        Address start = resolve(program, request.start());
        Address end = resolve(program, request.end());
        requireSameSpace(start, end);
        DataType type = resolveFixedType(program, request.typeName());
        int length = type.getLength();
        BigInteger stride = request.stride() == null
            ? BigInteger.valueOf(length) : request.stride();
        RangeMath math = rangeMath(
            start.getOffsetAsBigInteger(), end.getOffsetAsBigInteger(),
            BigInteger.valueOf(length), stride,
            request.allowTrailingBytes());
        if (math.elementCount() > remainingElements) {
            addPlannedElements(
                MAX_PLANNED_ELEMENTS - remainingElements,
                math.elementCount());
        }
        List<Address> elements = new ArrayList<>();
        for (long i = 0; i < math.elementCount(); i++) {
            if ((i & 0x3ff) == 0) {
                monitor.checkCancelled();
            }
            elements.add(start.addNoWrap(
                stride.multiply(BigInteger.valueOf(i))));
        }
        PointerOptions pointerOptions = request.pointers();
        if (pointerOptions != null && length != 2) {
            throw new IllegalArgumentException(
                "word pointer layouts require a two-byte datatype");
        }
        List<PointerPlan> pointers = pointerOptions == null
            ? List.of()
            : planContiguousPointers(
                program, elements, pointerOptions, monitor);
        return new RegionPlan(
            request, "contiguous", start, elements, type, length, stride,
            math.hasTrailing()
                ? start.getAddressSpace().getAddress(
                    math.trailingStart().longValue())
                : null,
            math.hasTrailing()
                ? start.getAddressSpace().getAddress(
                    math.trailingEnd().longValue())
                : null,
            List.of(), List.of(),
            pointers, pointerOptions,
            platePlan(program, start, request.metadata()),
            request.metadata(),
            dataActions(program, elements, type, length),
            List.of(), List.of());
    }

    private RegionPlan planSplit(
            Program program, SplitPointerRequest request,
            long remainingElements, TaskMonitor monitor) throws Exception {
        if (!"split_low_high".equals(request.layout())
                && !"split_high_low".equals(request.layout())) {
            throw new IllegalArgumentException(
                "layout must be split_low_high or split_high_low");
        }
        Address first = resolve(program, request.firstStart());
        Address second = resolve(program, request.secondStart());
        if (request.count() > remainingElements) {
            addPlannedElements(
                MAX_PLANNED_ELEMENTS - remainingElements,
                request.count());
        }
        validateSplitRanges(
            first, second, request.count());
        DataType byteType = resolveFixedType(program, "byte");
        if (byteType.getLength() != 1) {
            throw new IllegalArgumentException(
                "program byte datatype is not one byte");
        }
        List<Address> firstSources = new ArrayList<>();
        List<Address> secondSources = new ArrayList<>();
        for (int i = 0; i < request.count(); i++) {
            if ((i & 0x3ff) == 0) {
                monitor.checkCancelled();
            }
            firstSources.add(first.addNoWrap(i));
            secondSources.add(second.addNoWrap(i));
        }
        PointerOptions options = request.pointers();
        List<PointerPlan> pointers = planSplitPointers(
            program, firstSources, secondSources, request.layout(), options,
            monitor);
        DataType arrayType =
            new ArrayDataType(byteType, request.count(), 1);
        return new RegionPlan(
            request, "split_pointer_table", first, List.of(), arrayType,
            request.count(), BigInteger.ONE,
            null, null, firstSources, secondSources,
            pointers, options,
            platePlan(program, first, request.metadata()),
            request.metadata(),
            dataActions(
                program, List.of(first, second),
                arrayType, request.count()),
            List.of(), List.of());
    }

    private List<PointerPlan> planContiguousPointers(
            Program program, List<Address> elements,
            PointerOptions options, TaskMonitor monitor) throws Exception {
        if (!"little_endian_words".equals(options.layout())
                && !"big_endian_words".equals(options.layout())) {
            throw new IllegalArgumentException(
                "contiguous pointer layout must be little_endian_words "
                    + "or big_endian_words");
        }
        AddressSpace targetSpace =
            targetSpace(program, options.targetSpace());
        List<PointerPlan> result = new ArrayList<>();
        for (int i = 0; i < elements.size(); i++) {
            if ((i & 0x3ff) == 0) {
                monitor.checkCancelled();
            }
            Address source = elements.get(i);
            int first = program.getMemory().getByte(source) & 0xff;
            int second =
                program.getMemory().getByte(source.addNoWrap(1)) & 0xff;
            result.add(pointer(
                program, List.of(source),
                decodeWord(first, second, options.layout()),
                options, targetSpace));
        }
        return result;
    }

    private List<PointerPlan> planSplitPointers(
            Program program, List<Address> first,
            List<Address> second, String layout,
            PointerOptions options, TaskMonitor monitor) throws Exception {
        PointerOptions normalized = options == null
            ? new PointerOptions(
                layout, null, BigInteger.ZERO,
                false, false, null, null)
            : new PointerOptions(
                layout, options.targetSpace(), options.targetBase(),
                options.createReferences(), options.validateTargets(),
                options.targetLabelPrefix(), options.labelNamespace());
        AddressSpace targetSpace =
            targetSpace(program, normalized.targetSpace());
        List<PointerPlan> result = new ArrayList<>();
        for (int i = 0; i < first.size(); i++) {
            if ((i & 0x3ff) == 0) {
                monitor.checkCancelled();
            }
            int a = program.getMemory().getByte(first.get(i)) & 0xff;
            int b = program.getMemory().getByte(second.get(i)) & 0xff;
            result.add(pointer(
                program, List.of(first.get(i), second.get(i)),
                decodeWord(a, b, layout), normalized, targetSpace));
        }
        return result;
    }

    private PointerPlan pointer(
            Program program, List<Address> sources, long decoded,
            PointerOptions options, AddressSpace space) {
        Address target = null;
        String invalid = null;
        BigInteger offset = options.targetBase()
            .add(BigInteger.valueOf(decoded));
        try {
            BigInteger min =
                space.getMinAddress().getOffsetAsBigInteger();
            BigInteger max =
                space.getMaxAddress().getOffsetAsBigInteger();
            if (offset.compareTo(min) < 0 || offset.compareTo(max) > 0) {
                throw new ArithmeticException("target outside address space");
            }
            target = space.getAddress(offset.longValue());
            Memory memory = program.getMemory();
            if (!memory.contains(target)) {
                invalid = "unmapped_target";
            }
            else if (memory.getBlock(target) == null
                    || !memory.getBlock(target).isInitialized()) {
                invalid = "uninitialized_target";
            }
            else if (memory.getBlock(target).isExternalBlock()) {
                invalid = "external_target";
            }
            else if (target.isExternalAddress()) {
                invalid = "external_target";
            }
        }
        catch (RuntimeException error) {
            invalid = "overflowing_target";
        }
        if (invalid != null && options.validateTargets()) {
            throw new IllegalArgumentException(
                "invalid pointer target (" + invalid + ") from "
                    + sources.get(0));
        }
        String label = options.targetLabelPrefix() == null
            ? null
            : options.targetLabelPrefix()
                + leftPadHex(offset);
        return new PointerPlan(
            sources, target, decoded, invalid == null, invalid, label);
    }

    private static String leftPadHex(BigInteger value) {
        String hex = value.toString(16);
        return "0".repeat(Math.max(0, 4 - hex.length())) + hex;
    }

    private static AddressSpace targetSpace(
            Program program, String name) {
        AddressSpace space = name == null || name.isBlank()
            ? program.getAddressFactory().getDefaultAddressSpace()
            : program.getAddressFactory().getAddressSpace(name);
        if (space == null || space.getType() == AddressSpace.TYPE_EXTERNAL) {
            throw new IllegalArgumentException(
                "unknown or external target_space: " + name);
        }
        return space;
    }

    private static DataType resolveFixedType(
            Program program, String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("type_name is required");
        }
        DataType type = program.getDataTypeManager().getDataType(name);
        if (type == null && !name.startsWith("/")) {
            type = program.getDataTypeManager().getDataType("/" + name);
        }
        if (type == null) {
            List<DataType> matches = new ArrayList<>();
            program.getDataTypeManager().findDataTypes(name, matches);
            if (matches.size() == 1) {
                type = matches.get(0);
            }
            else if (matches.size() > 1) {
                throw new IllegalArgumentException(
                    "ambiguous datatype name: " + name);
            }
        }
        if (type == null) {
            throw new IllegalArgumentException(
                "datatype not found: " + name);
        }
        return requireFixedPlaceable(type, name);
    }

    static DataType requireFixedPlaceable(
            DataType type, String name) {
        DataType current = type;
        Set<DataType> visited =
            Collections.newSetFromMap(new IdentityHashMap<>());
        while (true) {
            if (current == null || !visited.add(current)
                    || current.getLength() <= 0
                    || Undefined.isUndefined(current)
                    || current instanceof Dynamic
                    || current instanceof FactoryDataType
                    || current instanceof BitFieldDataType) {
                throw new IllegalArgumentException(
                    "datatype must be fixed and placeable as top-level data: "
                        + name);
            }
            if (!(current instanceof TypeDef typeDef)) {
                return type;
            }
            current = typeDef.getDataType();
        }
    }

    private Address resolve(Program program, String text) {
        AddressCommentCore.ResolvedAddress resolved =
            comments.resolveAddress(program, text);
        return resolved.address();
    }

    private AddressCommentCore.Plan platePlan(
            Program program, Address address, Metadata metadata) {
        if (metadata == null || metadata.plateComment() == null) {
            return null;
        }
        AddressCommentCore.ResolvedAddress target =
            new AddressCommentCore.ResolvedAddress(program, address);
        AddressCommentCore.Plan plan = comments.plan(
            program, target, CommentType.PLATE,
            metadata.plateComment(), AddressCommentCore.WriteMode.REPLACE);
        if (plan.previous() != null
                && !plan.previous().equals(metadata.plateComment())) {
            throw new IllegalArgumentException(
                "different plate comment already exists at " + address);
        }
        return plan;
    }

    private static void requireSameSpace(Address first, Address second) {
        if (first.getAddressSpace() != second.getAddressSpace()) {
            throw new IllegalArgumentException(
                "region endpoints must use the same address space");
        }
    }

    private static List<Address> definitionAddresses(RegionPlan region) {
        if ("contiguous".equals(region.kind())) {
            return region.elementAddresses();
        }
        return List.of(
            region.splitFirst().get(0),
            region.splitSecond().get(0));
    }

    private static List<DataAction> dataActions(
            Program program, List<Address> addresses, DataType type,
            int length) throws Exception {
        List<DataAction> result = new ArrayList<>();
        for (Address address : addresses) {
            boolean unchanged =
                !hasNonEquivalentUnit(program, address, type, length)
                    && program.getListing().getDefinedDataAt(address) != null;
            result.add(new DataAction(
                address, type, length,
                unchanged ? "unchanged" : "create"));
        }
        return List.copyOf(result);
    }

    private static boolean hasNonEquivalentUnit(
            Program program, Address address, DataType type, int length)
            throws Exception {
        Address end = address.addNoWrap(length - 1L);
        Data exact = program.getListing().getDefinedDataAt(address);
        if (exact != null
                && exact.getMaxAddress().equals(end)
                && (exact.getDataType().isEquivalent(type)
                    || type.isEquivalent(exact.getDataType()))) {
            return false;
        }
        AddressSet requested = new AddressSet(address, end);
        if (program.getListing().getInstructionContaining(address) != null
                || program.getListing().getDefinedDataContaining(address)
                    != null
                || program.getListing().getInstructions(
                    requested, true).hasNext()
                || program.getListing().getDefinedData(
                    requested, true).hasNext()) {
            return true;
        }
        return false;
    }

    private RegionPlan planActions(
            Program program, RegionPlan region) {
        List<SymbolAction> symbols = new ArrayList<>();
        List<ReferenceAction> references = new ArrayList<>();
        Metadata metadata = region.metadata();
        if (metadata != null && metadata.name() != null) {
            symbols.add(planSymbol(
                program, region.placement(), metadata.name(),
                metadata.namespace(), "region", true));
        }
        PointerOptions options = region.pointerOptions();
        for (PointerPlan pointer : region.pointers()) {
            if (options != null && options.createReferences()) {
                for (Address source : pointer.sources()) {
                    if (!pointer.valid()) {
                        references.add(new ReferenceAction(
                            source, pointer.target(), "skipped",
                            "invalid_target"));
                    }
                    else {
                        references.add(new ReferenceAction(
                            source, pointer.target(),
                            exactReferenceExists(
                                program, source, pointer.target())
                                    ? "unchanged" : "create",
                            null));
                    }
                }
            }
            if (pointer.labelName() != null) {
                if (!pointer.valid()) {
                    symbols.add(new SymbolAction(
                        pointer.target(), pointer.labelName(),
                        options == null ? null : options.labelNamespace(),
                        "pointer_target", "skipped",
                        "invalid_target", false));
                }
                else {
                    symbols.add(planSymbol(
                        program, pointer.target(), pointer.labelName(),
                        options == null
                            ? null : options.labelNamespace(),
                        "pointer_target", false));
                }
            }
        }
        return copyWithActions(region, symbols, references);
    }

    private static SymbolAction planSymbol(
            Program program, Address address, String name,
            String namespaceName, String kind, boolean primary) {
        validateSymbolName(name, kind + " name");
        Namespace namespace =
            namespaceForPlanning(program, namespaceName);
        Symbol existing = namespace == null
            ? null
            : program.getSymbolTable().getSymbol(
                name, address, namespace);
        if (namespace != null) {
            for (Symbol symbol :
                    program.getSymbolTable().getSymbols(name, namespace)) {
                if (!symbol.getAddress().equals(address)) {
                    throw new IllegalArgumentException(
                        "symbol name exists at another address: "
                            + qualified(namespaceName, name));
                }
            }
        }
        if (primary) {
            Symbol current =
                program.getSymbolTable().getPrimarySymbol(address);
            if (current != null && !current.equals(existing)) {
                throw new IllegalArgumentException(
                    "different primary symbol already exists at "
                        + address);
            }
        }
        String action = existing == null
            ? "create"
            : primary && !existing.isPrimary()
                ? "set_primary" : "unchanged";
        return new SymbolAction(
            address, name, emptyToNull(namespaceName), kind,
            action, null, primary);
    }

    private static Namespace namespaceForPlanning(
            Program program, String name) {
        if (name == null) {
            return program.getGlobalNamespace();
        }
        if (name.isBlank()) {
            throw new IllegalArgumentException(
                "namespace must not be blank");
        }
        validateSymbolName(name, "namespace");
        Namespace namespace = resolveNamespace(program, name, false);
        if (namespace == null
                && !program.getSymbolTable()
                    .getSymbols(name, program.getGlobalNamespace())
                    .isEmpty()) {
            throw new IllegalArgumentException(
                "namespace name conflicts with an existing symbol: "
                    + name);
        }
        return namespace;
    }

    private static void validateSymbolName(
            String name, String description) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException(
                description + " must not be blank");
        }
        try {
            SymbolUtilities.validateName(name);
        }
        catch (Exception error) {
            throw new IllegalArgumentException(
                "invalid " + description + ": " + name, error);
        }
    }

    private static boolean exactReferenceExists(
            Program program, Address from, Address to) {
        for (Reference reference
                : program.getReferenceManager().getReferencesFrom(from)) {
            if (reference.getToAddress().equals(to)
                    && reference.getSource() == SourceType.USER_DEFINED
                    && reference.getReferenceType() == RefType.DATA
                    && reference.getOperandIndex() == Reference.MNEMONIC) {
                return true;
            }
        }
        return false;
    }

    private static List<RegionPlan> normalizeAndValidateBatchActions(
            List<RegionPlan> regions) {
        Map<String, Address> labels = new LinkedHashMap<>();
        Map<Address, String> primaries = new LinkedHashMap<>();
        Map<Address, String> comments = new LinkedHashMap<>();
        Map<String, SymbolAction> seenSymbols = new LinkedHashMap<>();
        List<RegionPlan> normalized = new ArrayList<>();
        for (RegionPlan region : regions) {
            AddressCommentCore.Plan platePlan = region.platePlan();
            List<SymbolAction> symbols = new ArrayList<>();
            for (SymbolAction action : region.symbolActions()) {
                if ("skipped".equals(action.action())) {
                    symbols.add(action);
                    continue;
                }
                String qualified =
                    qualified(action.namespace(), action.name());
                Address priorAddress =
                    labels.putIfAbsent(qualified, action.address());
                if (priorAddress != null
                        && !priorAddress.equals(action.address())) {
                    throw new IllegalArgumentException(
                        "requested label collision: " + qualified);
                }
                if (action.primary()) {
                    String prior =
                        primaries.putIfAbsent(action.address(), qualified);
                    if (prior != null && !prior.equals(qualified)) {
                        throw new IllegalArgumentException(
                            "different requested primary symbols at "
                                + action.address());
                    }
                }
                String key = qualified + "@" + action.address();
                SymbolAction prior = seenSymbols.putIfAbsent(key, action);
                if (prior != null) {
                    continue;
                }
                symbols.add(action);
            }
            if (region.metadata() != null
                    && region.metadata().plateComment() != null) {
                String previous = comments.putIfAbsent(
                    region.placement(),
                    region.metadata().plateComment());
                if (previous != null
                        && !previous.equals(
                            region.metadata().plateComment())) {
                    throw new IllegalArgumentException(
                            "different requested plate comments at "
                                + region.placement());
                }
                if (previous != null) {
                    platePlan = null;
                }
            }
            normalized.add(copyWithActions(
                region, symbols, region.referenceActions(), platePlan));
        }
        List<RegionPlan> result = List.copyOf(normalized);
        validateRequestedNamespaceCollisions(result);
        return result;
    }

    private static void validateRequestedNamespaceCollisions(
            List<RegionPlan> regions) {
        Set<String> requestedNamespaces = new LinkedHashSet<>();
        Set<String> requestedGlobalLabels = new LinkedHashSet<>();
        for (RegionPlan region : regions) {
            for (SymbolAction symbol : region.symbolActions()) {
                if ("skipped".equals(symbol.action())) {
                    continue;
                }
                if (symbol.namespace() == null) {
                    requestedGlobalLabels.add(symbol.name());
                }
                else {
                    requestedNamespaces.add(symbol.namespace());
                }
            }
        }
        for (String namespace : requestedNamespaces) {
            if (requestedGlobalLabels.contains(namespace)) {
                throw new IllegalArgumentException(
                    "requested namespace conflicts with requested global label: "
                        + namespace);
            }
        }
    }

    private static List<NamespaceAction> planNamespaces(
            Program program, List<RegionPlan> regions) {
        Map<String, NamespaceAction> actions = new LinkedHashMap<>();
        for (RegionPlan region : regions) {
            for (SymbolAction symbol : region.symbolActions()) {
                String name = symbol.namespace();
                if (name == null || "skipped".equals(symbol.action())) {
                    continue;
                }
                namespaceForPlanning(program, name);
                actions.putIfAbsent(
                    name,
                    new NamespaceAction(
                        name,
                        resolveNamespace(program, name, false) == null
                            ? "create" : "unchanged"));
            }
        }
        return List.copyOf(actions.values());
    }

    private static RegionPlan copyWithActions(
            RegionPlan region, List<SymbolAction> symbols,
            List<ReferenceAction> references) {
        return copyWithActions(
            region, symbols, references, region.platePlan());
    }

    private static RegionPlan copyWithActions(
            RegionPlan region, List<SymbolAction> symbols,
            List<ReferenceAction> references,
            AddressCommentCore.Plan platePlan) {
        return new RegionPlan(
            region.request(), region.kind(), region.placement(),
            region.elementAddresses(), region.dataType(),
            region.dataLength(), region.stride(),
            region.trailingStart(), region.trailingEnd(),
            region.splitFirst(), region.splitSecond(),
            region.pointers(), region.pointerOptions(),
            platePlan, region.metadata(),
            region.dataActions(), symbols, references);
    }

    private static void applySymbols(
            Program program, List<SymbolAction> actions,
            TaskMonitor monitor) throws Exception {
        for (SymbolAction action : actions) {
            monitor.checkCancelled();
            if ("skipped".equals(action.action())
                    || "unchanged".equals(action.action())) {
                continue;
            }
            Namespace namespace =
                resolveNamespace(program, action.namespace(), false);
            if (namespace == null) {
                throw new IllegalArgumentException(
                    "planned namespace is missing: " + action.namespace());
            }
            Symbol symbol = program.getSymbolTable().getSymbol(
                action.name(), action.address(), namespace);
            if ("create".equals(action.action())) {
                symbol = program.getSymbolTable().createLabel(
                    action.address(), action.name(), namespace,
                    SourceType.USER_DEFINED);
            }
            if (action.primary()) {
                symbol.setPrimary();
            }
        }
    }

    private static void applyReferences(
            Program program, List<ReferenceAction> actions,
            TaskMonitor monitor) throws Exception {
        for (ReferenceAction action : actions) {
            monitor.checkCancelled();
            if ("create".equals(action.action())) {
                program.getReferenceManager().addMemoryReference(
                    action.from(), action.to(), RefType.DATA,
                    SourceType.USER_DEFINED, Reference.MNEMONIC);
            }
        }
    }

    private static String qualified(String namespace, String name) {
        return namespace == null || namespace.isBlank()
            ? name : namespace + "::" + name;
    }

    private static String emptyToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private static Namespace resolveNamespace(
            Program program, String name, boolean create) {
        if (name == null || name.isBlank()) {
            return program.getGlobalNamespace();
        }
        Namespace namespace = program.getSymbolTable().getNamespace(
            name, program.getGlobalNamespace());
        if (namespace == null && create) {
            try {
                namespace = program.getSymbolTable().createNameSpace(
                    program.getGlobalNamespace(), name,
                    SourceType.USER_DEFINED);
            }
            catch (Exception error) {
                throw new IllegalArgumentException(
                    "invalid namespace: " + name, error);
            }
        }
        return namespace;
    }
}
