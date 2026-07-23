package com.xebyte.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.data.FactoryDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.CodeUnit;
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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Transaction-neutral planner and applier for atomic range data definitions. */
final class DataRegionCore {
    static final int MAX_REGIONS = 1024;

    record RangeMath(long elementCount, long trailingStart, long trailingEnd) {
        boolean hasTrailing() {
            return trailingStart >= 0;
        }
    }

    record Metadata(
            String name, String namespace, String plateComment,
            boolean clearConflicts) {
    }

    record PointerOptions(
            String layout, String targetSpace, long targetBase,
            boolean createReferences, boolean validateTargets,
            String targetLabelPrefix, String labelNamespace) {
    }

    sealed interface RegionRequest
            permits ContiguousRequest, SplitPointerRequest {
        Metadata metadata();
    }

    record ContiguousRequest(
            String start, String end, String typeName, Long stride,
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

    record RegionPlan(
            String kind, Address placement, List<Address> elementAddresses,
            DataType dataType, int dataLength, long stride,
            Address trailingStart, Address trailingEnd,
            List<Address> splitFirst, List<Address> splitSecond,
            List<Address> existingData,
            List<PointerPlan> pointers, PointerOptions pointerOptions,
            AddressCommentCore.Plan platePlan, Metadata metadata) {
        RegionPlan {
            elementAddresses = List.copyOf(elementAddresses);
            splitFirst = List.copyOf(splitFirst);
            splitSecond = List.copyOf(splitSecond);
            existingData = List.copyOf(existingData);
            pointers = List.copyOf(pointers);
        }
    }

    record Plan(
            Program owner, List<RegionPlan> regions,
            ListingClearCore.Plan clearPlan,
            List<String> conflicts) {
        Plan {
            regions = List.copyOf(regions);
            conflicts = List.copyOf(conflicts);
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
        if (Long.compareUnsigned(end, start) < 0) {
            throw new IllegalArgumentException("end must not precede start");
        }
        if (dataLength <= 0) {
            throw new IllegalArgumentException(
                "datatype length must be positive");
        }
        if (stride < dataLength) {
            throw new IllegalArgumentException(
                "stride must be at least datatype length");
        }
        long length;
        try {
            length = Math.addExact(Math.subtractExact(end, start), 1);
        }
        catch (ArithmeticException error) {
            throw new IllegalArgumentException("range length overflows", error);
        }
        long count = length < dataLength
            ? 0 : 1 + (length - dataLength) / stride;
        long usedEnd = count == 0 ? start - 1
            : Math.addExact(start,
                Math.addExact(Math.multiplyExact(count - 1, stride),
                    dataLength - 1));
        boolean trailing = count == 0 || usedEnd != end;
        if (trailing && !allowTrailing) {
            throw new IllegalArgumentException(
                "region has trailing bytes; set allow_trailing_bytes=true");
        }
        return new RangeMath(
            count, trailing ? (count == 0 ? start : usedEnd + 1) : -1,
            trailing ? end : -1);
    }

    static void validateSplitRanges(
            long firstStart, long secondStart, long count) {
        if (count <= 0) {
            throw new IllegalArgumentException("count must be positive");
        }
        long firstEnd = Math.addExact(firstStart, count - 1);
        long secondEnd = Math.addExact(secondStart, count - 1);
        if (firstStart <= secondEnd && secondStart <= firstEnd) {
            throw new IllegalArgumentException(
                "split pointer source ranges overlap");
        }
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
        for (RegionRequest request : requests) {
            RegionPlan region = request instanceof ContiguousRequest c
                ? planContiguous(program, c)
                : planSplit(program, (SplitPointerRequest) request);
            for (Address address : definitionAddresses(region)) {
                Address end = address.addNoWrap(region.dataLength() - 1L);
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
            validateMetadata(program, region);
            validatePointerLabels(program, region);
            regions.add(region);
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
        validateBatchLabelCollisions(regions);
        List<String> conflicts = clearPlan == null
            ? List.of()
            : clearPlan.units().stream()
                .map(unit -> unit.kind().name().toLowerCase()
                    + ":" + unit.start() + "-" + unit.end())
                .toList();
        return new Plan(program, regions, clearPlan, conflicts);
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
        if (plan.clearPlan() != null) {
            listingClear.apply(program, plan.clearPlan());
        }
        for (RegionPlan region : plan.regions()) {
            taskMonitor.checkCancelled();
            for (Address address : definitionAddresses(region)) {
                Data existing =
                    program.getListing().getDefinedDataAt(address);
                if (existing == null) {
                    program.getListing().createData(
                        address, region.dataType());
                }
            }
            applyMetadata(program, region);
            if (region.platePlan() != null) {
                comments.apply(program, region.platePlan());
            }
            applyPointers(program, region);
        }
    }

    private RegionPlan planContiguous(
            Program program, ContiguousRequest request) throws Exception {
        Address start = resolve(program, request.start());
        Address end = resolve(program, request.end());
        requireSameSpace(start, end);
        DataType type = resolveFixedType(program, request.typeName());
        int length = type.getLength();
        long stride =
            request.stride() == null ? length : request.stride();
        RangeMath math = rangeMath(
            start.getOffset(), end.getOffset(), length, stride,
            request.allowTrailingBytes());
        List<Address> elements = new ArrayList<>();
        for (long i = 0; i < math.elementCount(); i++) {
            elements.add(start.addNoWrap(Math.multiplyExact(i, stride)));
        }
        PointerOptions pointerOptions = request.pointers();
        if (pointerOptions != null && length != 2) {
            throw new IllegalArgumentException(
                "word pointer layouts require a two-byte datatype");
        }
        List<PointerPlan> pointers = pointerOptions == null
            ? List.of()
            : planContiguousPointers(program, elements, pointerOptions);
        return new RegionPlan(
            "contiguous", start, elements, type, length, stride,
            math.hasTrailing()
                ? start.getAddressSpace().getAddress(math.trailingStart())
                : null,
            math.hasTrailing()
                ? start.getAddressSpace().getAddress(math.trailingEnd())
                : null,
            List.of(), List.of(),
            existingData(program, elements, type, length),
            pointers, pointerOptions,
            platePlan(program, start, request.metadata()),
            request.metadata());
    }

    private RegionPlan planSplit(
            Program program, SplitPointerRequest request) throws Exception {
        if (!"split_low_high".equals(request.layout())
                && !"split_high_low".equals(request.layout())) {
            throw new IllegalArgumentException(
                "layout must be split_low_high or split_high_low");
        }
        Address first = resolve(program, request.firstStart());
        Address second = resolve(program, request.secondStart());
        requireSameSpace(first, second);
        validateSplitRanges(
            first.getOffset(), second.getOffset(), request.count());
        DataType byteType = resolveFixedType(program, "byte");
        if (byteType.getLength() != 1) {
            throw new IllegalArgumentException(
                "program byte datatype is not one byte");
        }
        List<Address> firstSources = new ArrayList<>();
        List<Address> secondSources = new ArrayList<>();
        for (int i = 0; i < request.count(); i++) {
            firstSources.add(first.addNoWrap(i));
            secondSources.add(second.addNoWrap(i));
        }
        PointerOptions options = request.pointers();
        List<PointerPlan> pointers = planSplitPointers(
            program, firstSources, secondSources, request.layout(), options);
        DataType arrayType =
            new ArrayDataType(byteType, request.count(), 1);
        return new RegionPlan(
            "split_pointer_table", first, List.of(), arrayType,
            request.count(), 1,
            null, null, firstSources, secondSources,
            existingData(program,
                List.of(first, second), arrayType, request.count()),
            pointers, options,
            platePlan(program, first, request.metadata()),
            request.metadata());
    }

    private List<PointerPlan> planContiguousPointers(
            Program program, List<Address> elements,
            PointerOptions options) throws Exception {
        if (!"little_endian_words".equals(options.layout())
                && !"big_endian_words".equals(options.layout())) {
            throw new IllegalArgumentException(
                "contiguous pointer layout must be little_endian_words "
                    + "or big_endian_words");
        }
        List<PointerPlan> result = new ArrayList<>();
        for (int i = 0; i < elements.size(); i++) {
            Address source = elements.get(i);
            int first = program.getMemory().getByte(source) & 0xff;
            int second =
                program.getMemory().getByte(source.addNoWrap(1)) & 0xff;
            result.add(pointer(
                program, List.of(source),
                decodeWord(first, second, options.layout()), options, i));
        }
        return result;
    }

    private List<PointerPlan> planSplitPointers(
            Program program, List<Address> first,
            List<Address> second, String layout,
            PointerOptions options) throws Exception {
        PointerOptions normalized = options == null
            ? new PointerOptions(
                layout, null, 0, false, false, null, null)
            : new PointerOptions(
                layout, options.targetSpace(), options.targetBase(),
                options.createReferences(), options.validateTargets(),
                options.targetLabelPrefix(), options.labelNamespace());
        List<PointerPlan> result = new ArrayList<>();
        for (int i = 0; i < first.size(); i++) {
            int a = program.getMemory().getByte(first.get(i)) & 0xff;
            int b = program.getMemory().getByte(second.get(i)) & 0xff;
            result.add(pointer(
                program, List.of(first.get(i), second.get(i)),
                decodeWord(a, b, layout), normalized, i));
        }
        return result;
    }

    private PointerPlan pointer(
            Program program, List<Address> sources, long decoded,
            PointerOptions options, int index) {
        Address target = null;
        String invalid = null;
        try {
            long offset = Math.addExact(decoded, options.targetBase());
            AddressSpace space = targetSpace(program, options.targetSpace());
            target = space.getAddress(offset);
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
            || options.targetLabelPrefix().isEmpty()
            || target == null
            ? null
            : options.targetLabelPrefix()
                + String.format("%04x", target.getOffset());
        return new PointerPlan(
            sources, target, decoded, invalid == null, invalid, label);
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
        if (type.getLength() <= 0 || Undefined.isUndefined(type)
                || type instanceof Dynamic
                || type instanceof FactoryDataType) {
            throw new IllegalArgumentException(
                "datatype must have a fixed positive length: " + name);
        }
        return type;
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

    private static List<Address> combine(
            List<Address> first, List<Address> second) {
        List<Address> result = new ArrayList<>(first);
        result.addAll(second);
        return result;
    }

    private static List<Address> existingData(
            Program program, List<Address> addresses, DataType type,
            int length) throws Exception {
        List<Address> result = new ArrayList<>();
        for (Address address : addresses) {
            if (!hasNonEquivalentUnit(program, address, type, length)
                    && program.getListing().getDefinedDataAt(address)
                        != null) {
                result.add(address);
            }
        }
        return result;
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

    private void validateMetadata(
            Program program, RegionPlan region) {
        Metadata metadata = region.metadata();
        if (metadata == null) {
            return;
        }
        SymbolTable table = program.getSymbolTable();
        Namespace namespace = resolveNamespace(
            program, metadata.namespace(), false);
        if (namespace == null) {
            throw new IllegalArgumentException(
                "namespace does not exist: " + metadata.namespace());
        }
        if (metadata.name() != null && !metadata.name().isBlank()) {
            Symbol byName =
                table.getSymbol(metadata.name(), region.placement(), namespace);
            Symbol primary = table.getPrimarySymbol(region.placement());
            if (primary != null
                    && (byName == null || !primary.equals(byName))) {
                throw new IllegalArgumentException(
                    "different primary symbol already exists at "
                        + region.placement());
            }
            for (Symbol symbol : table.getSymbols(
                    metadata.name(), namespace)) {
                if (!symbol.getAddress().equals(region.placement())) {
                    throw new IllegalArgumentException(
                        "symbol name exists at another address: "
                            + metadata.name());
                }
            }
        }
        if (metadata.plateComment() != null) {
            String previous = program.getListing().getComment(
                CommentType.PLATE, region.placement());
            if (previous != null
                    && !previous.equals(metadata.plateComment())) {
                throw new IllegalArgumentException(
                    "different plate comment already exists at "
                        + region.placement());
            }
        }
    }

    private static void validatePointerLabels(
            Program program, RegionPlan region) {
        PointerOptions options = region.pointerOptions();
        if (options == null || options.targetLabelPrefix() == null) {
            return;
        }
        Namespace namespace = resolveNamespace(
            program, options.labelNamespace(), false);
        if (namespace == null) {
            throw new IllegalArgumentException(
                "label namespace does not exist: "
                    + options.labelNamespace());
        }
        Map<String, Address> requested = new LinkedHashMap<>();
        for (PointerPlan pointer : region.pointers()) {
            if (!pointer.valid() || pointer.labelName() == null) {
                continue;
            }
            Address previous =
                requested.putIfAbsent(pointer.labelName(), pointer.target());
            if (previous != null && !previous.equals(pointer.target())) {
                throw new IllegalArgumentException(
                    "target label collision: " + pointer.labelName());
            }
            for (Symbol symbol : program.getSymbolTable().getSymbols(
                    pointer.labelName(), namespace)) {
                if (!symbol.getAddress().equals(pointer.target())) {
                    throw new IllegalArgumentException(
                        "target label exists at another address: "
                            + pointer.labelName());
                }
            }
        }
    }

    private static void validateBatchLabelCollisions(
            List<RegionPlan> regions) {
        Map<String, Address> labels = new LinkedHashMap<>();
        for (RegionPlan region : regions) {
            Metadata metadata = region.metadata();
            if (metadata != null && metadata.name() != null) {
                addBatchLabel(labels,
                    (metadata.namespace() == null ? "" : metadata.namespace())
                        + "::" + metadata.name(),
                    region.placement());
            }
            PointerOptions options = region.pointerOptions();
            for (PointerPlan pointer : region.pointers()) {
                if (!pointer.valid() || pointer.labelName() == null) {
                    continue;
                }
                addBatchLabel(labels,
                    (options == null || options.labelNamespace() == null
                        ? "" : options.labelNamespace())
                        + "::" + pointer.labelName(),
                    pointer.target());
            }
        }
    }

    private static void addBatchLabel(
            Map<String, Address> labels, String name, Address address) {
        Address previous = labels.putIfAbsent(name, address);
        if (previous != null && !previous.equals(address)) {
            throw new IllegalArgumentException(
                "requested label collision: " + name);
        }
    }

    private static void applyMetadata(
            Program program, RegionPlan region) throws Exception {
        Metadata metadata = region.metadata();
        if (metadata == null) {
            return;
        }
        if (metadata.name() != null && !metadata.name().isBlank()) {
            Namespace namespace = resolveNamespace(
                program, metadata.namespace(), false);
            if (namespace == null) {
                throw new IllegalArgumentException(
                    "namespace does not exist: " + metadata.namespace());
            }
            Symbol existing = program.getSymbolTable().getSymbol(
                metadata.name(), region.placement(), namespace);
            if (existing == null) {
                existing = program.getSymbolTable().createLabel(
                    region.placement(), metadata.name(), namespace,
                    SourceType.USER_DEFINED);
            }
            existing.setPrimary();
        }
    }

    private static void applyPointers(
            Program program, RegionPlan region) throws Exception {
        for (PointerPlan pointer : region.pointers()) {
            if (!pointer.valid()) {
                continue;
            }
            PointerOptions options = region.pointerOptions();
            if (options != null && options.createReferences()) {
              for (Address source : pointer.sources()) {
                boolean exists = false;
                for (Reference reference
                        : program.getReferenceManager()
                            .getReferencesFrom(source)) {
                    if (reference.getToAddress().equals(pointer.target())
                            && reference.getSource()
                                == SourceType.USER_DEFINED
                            && reference.getReferenceType()
                                == RefType.DATA) {
                        exists = true;
                        break;
                    }
                }
                if (!exists) {
                    program.getReferenceManager().addMemoryReference(
                        source, pointer.target(), RefType.DATA,
                        SourceType.USER_DEFINED, Reference.MNEMONIC);
                }
              }
            }
            if (pointer.labelName() != null) {
                Namespace namespace = resolveNamespace(
                    program,
                    options == null ? null : options.labelNamespace(),
                    false);
                if (namespace == null) {
                    throw new IllegalArgumentException(
                        "label namespace does not exist: "
                            + options.labelNamespace());
                }
                Symbol existing = program.getSymbolTable().getSymbol(
                    pointer.labelName(), pointer.target(), namespace);
                if (existing == null) {
                    program.getSymbolTable().createLabel(
                        pointer.target(), pointer.labelName(), namespace,
                        SourceType.USER_DEFINED);
                }
            }
        }
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
