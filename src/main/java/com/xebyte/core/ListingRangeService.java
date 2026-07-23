package com.xebyte.core;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.NavigableSet;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Function-independent, bounded reader for Ghidra's authoritative mixed listing.
 */
@McpToolGroup(value = "listing", description = "Mixed code, data, and undefined listing reads")
public final class ListingRangeService {

    private static final int MAX_UNITS_LIMIT = 10_000;
    private static final int MIN_MAX_BYTES = 256;
    private static final int MAX_BYTES_LIMIT = 1_048_576;
    private static final int MAX_INCOMING_LIMIT = 10_000;
    private static final int CURSOR_VERSION = 1;
    private static final String CURSOR_MAC_ALGORITHM = "HmacSHA256";
    private static final byte[] CURSOR_MAC_KEY = randomKey();
    private static final HexFormat HEX = HexFormat.of();
    private static final Gson OUTPUT_JSON = new GsonBuilder()
        .disableHtmlEscaping()
        .serializeNulls()
        .create();

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final DataMetadataReader dataMetadataReader;

    public ListingRangeService(
            ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this(programProvider, threadingStrategy, ListingRangeService::readDataMetadata);
    }

    ListingRangeService(
            ProgramProvider programProvider,
            ThreadingStrategy threadingStrategy,
            DataMetadataReader dataMetadataReader) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.dataMetadataReader = dataMetadataReader;
    }

    @McpTool(
        path = "/get_listing_range",
        description = "Read an authoritative mixed instruction/data/undefined listing range "
            + "without requiring or creating functions",
        category = "listing")
    public Response getListingRange(
            @Param(value = "start", paramType = "address",
                description = "Inclusive start address") String startText,
            @Param(value = "end", paramType = "address",
                description = "Inclusive end address") String endText,
            @Param(value = "max_units", defaultValue = "1000",
                description = "Maximum listing units (1..10000)") int maxUnits,
            @Param(value = "max_bytes", defaultValue = "65536",
                description = "Maximum initialized raw bytes (256..1048576)") int maxBytes,
            @Param(value = "max_incoming_refs_per_unit", defaultValue = "1000",
                description = "Maximum incoming references per unit (1..10000)")
                int maxIncomingRefsPerUnit,
            @Param(value = "cursor", defaultValue = "",
                description = "Opaque cursor from a previous page") String cursor,
            @Param(value = "program", defaultValue = "",
                description = "Target program name") String programName) {
        ServiceUtils.ProgramOrError resolved =
            ServiceUtils.getProgramOrError(programProvider, programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Response limitsError =
            validateLimits(maxUnits, maxBytes, maxIncomingRefsPerUnit);
        if (limitsError != null) {
            return limitsError;
        }

        try {
            Program program = resolved.program();
            return threadingStrategy.executeRead(() -> readAuthoritativeRange(
                program, startText, endText, maxUnits, maxBytes,
                maxIncomingRefsPerUnit, cursor, dataMetadataReader));
        }
        catch (Exception exception) {
            return Response.err("Error reading listing range: " + exception.getMessage());
        }
    }

    private static Response readAuthoritativeRange(
            Program program,
            String startText,
            String endText,
            int maxUnits,
            int maxBytes,
            int maxIncomingRefsPerUnit,
            String cursor,
            DataMetadataReader dataMetadataReader) throws Exception {
        // This snapshot intentionally precedes every model-dependent parse,
        // containment check, unit expansion, index build, and byte read.
        long modificationNumber = program.getModificationNumber();

        Address requestedStart = ServiceUtils.parseAddress(program, startText);
        if (requestedStart == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }
        Address requestedEnd = ServiceUtils.parseAddress(program, endText);
        if (requestedEnd == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }
        if (!requestedStart.getAddressSpace().equals(requestedEnd.getAddressSpace())) {
            return Response.err("Listing range must stay within one address space.");
        }
        if (requestedStart.compareTo(requestedEnd) > 0) {
            return Response.err("Listing range start must not be after end.");
        }

        Memory memory = program.getMemory();
        if (!memory.contains(requestedStart, requestedEnd)) {
            return Response.err("Every address in the requested listing range must be mapped.");
        }

        Listing listing = program.getListing();
        Address effectiveStart = expandStart(listing, requestedStart);
        Address effectiveEnd = expandEnd(listing, requestedEnd);
        if (!memory.contains(effectiveStart, effectiveEnd)) {
            return Response.err("Expanded listing-unit boundaries include unmapped addresses.");
        }

        String programId = programIdentity(program);
        Address pageStart = effectiveStart;
        if (cursor != null && !cursor.isBlank()) {
            CursorValidation validation = ListingCursorCodec.decodeAndValidate(
                cursor, program, programId, modificationNumber,
                requestedStart, requestedEnd, effectiveStart, effectiveEnd,
                maxUnits, maxBytes, maxIncomingRefsPerUnit);
            if (validation.error() != null) {
                return Response.err(validation.error());
            }
            pageStart = validation.nextAddress();
        }

        RangeIndex index = RangeIndex.build(program, effectiveStart, effectiveEnd);
        CodeUnit containingPageStart = index.codeUnitContaining(pageStart);
        if (containingPageStart != null
                && !containingPageStart.getMinAddress().equals(pageStart)) {
            return Response.err("Listing cursor is not at a unit boundary.");
        }

        Page page = readPage(
            program, index, programId, modificationNumber,
            requestedStart, requestedEnd, effectiveStart, effectiveEnd,
            pageStart, maxUnits, maxBytes, maxIncomingRefsPerUnit,
            dataMetadataReader);
        if (program.getModificationNumber() != modificationNumber) {
            return Response.err(
                "Program changed while reading listing range; retry from the first page.");
        }

        // JsonHelper omits null map values for legacy responses. This contract
        // requires explicit nulls for bytes and nullable instruction/data fields.
        return Response.text(OUTPUT_JSON.toJson(page.response()));
    }

    private static Response validateLimits(
            int maxUnits, int maxBytes, int maxIncomingRefsPerUnit) {
        if (maxUnits < 1 || maxUnits > MAX_UNITS_LIMIT) {
            return Response.err("max_units must be between 1 and 10000.");
        }
        if (maxBytes < MIN_MAX_BYTES || maxBytes > MAX_BYTES_LIMIT) {
            return Response.err("max_bytes must be between 256 and 1048576.");
        }
        if (maxIncomingRefsPerUnit < 1
                || maxIncomingRefsPerUnit > MAX_INCOMING_LIMIT) {
            return Response.err(
                "max_incoming_refs_per_unit must be between 1 and 10000.");
        }
        return null;
    }

    private static Address expandStart(Listing listing, Address requested) {
        CodeUnit containing = definedUnitContaining(listing, requested);
        return containing == null ? requested : containing.getMinAddress();
    }

    private static Address expandEnd(Listing listing, Address requested) {
        CodeUnit containing = definedUnitContaining(listing, requested);
        return containing == null ? requested : containing.getMaxAddress();
    }

    private static CodeUnit definedUnitContaining(Listing listing, Address address) {
        Instruction instruction = listing.getInstructionContaining(address);
        if (instruction != null) {
            return instruction;
        }
        return listing.getDefinedDataContaining(address);
    }

    private static Page readPage(
            Program program,
            RangeIndex index,
            String programId,
            long modificationNumber,
            Address requestedStart,
            Address requestedEnd,
            Address effectiveStart,
            Address effectiveEnd,
            Address pageStart,
            int maxUnits,
            int maxBytes,
            int maxIncomingRefsPerUnit,
            DataMetadataReader dataMetadataReader) throws Exception {
        List<Map<String, Object>> units = new ArrayList<>();
        int includedBytes = 0;
        Address current = pageStart;
        Address returnedEnd = null;

        while (current != null
                && current.compareTo(effectiveEnd) <= 0
                && units.size() < maxUnits) {
            CodeUnit existing = index.codeUnitAt(current);
            Address unitEnd;
            boolean initialized;
            int length;

            if (existing != null) {
                unitEnd = existing.getMaxAddress();
                length = existing.getLength();
                initialized = index.initialized(current, unitEnd);

                if (initialized && length > maxBytes && units.isEmpty()) {
                    units.add(renderUnit(
                        index, programId, modificationNumber, existing,
                        current, unitEnd, true, null, false, true,
                        maxIncomingRefsPerUnit, dataMetadataReader));
                    returnedEnd = unitEnd;
                    current = next(unitEnd);
                    break;
                }
                if (initialized && length > maxBytes - includedBytes) {
                    break;
                }
            }
            else {
                initialized = index.initialized(current);
                int remainingBudget = maxBytes - includedBytes;
                if (initialized && remainingBudget == 0) {
                    break;
                }
                int undefinedLimit = initialized ? remainingBudget : maxBytes;
                unitEnd = index.undefinedEnd(current, undefinedLimit);
                length = rangeLength(current, unitEnd);
            }

            byte[] bytes = null;
            boolean bytesComplete = false;
            if (initialized) {
                bytes = readBytes(index.memory(), current, length);
                bytesComplete = true;
                includedBytes += length;
            }

            units.add(renderUnit(
                index, programId, modificationNumber, existing,
                current, unitEnd, initialized, bytes, bytesComplete, false,
                maxIncomingRefsPerUnit, dataMetadataReader));
            returnedEnd = unitEnd;
            current = next(unitEnd);
        }

        if (returnedEnd == null) {
            throw new IllegalStateException(
                "The page budgets could not represent the next listing unit.");
        }
        boolean complete = returnedEnd.compareTo(effectiveEnd) >= 0;

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("program", program.getName());
        response.put("requested_range", range(requestedStart, requestedEnd));
        response.put("effective_range", range(effectiveStart, effectiveEnd));
        response.put("returned_range", range(pageStart, returnedEnd));
        response.put("complete", complete);
        if (!complete) {
            if (current == null) {
                throw new IllegalStateException(
                    "Address overflow before effective listing range ended.");
            }
            CursorPayload payload = new CursorPayload(
                CURSOR_VERSION, programId, modificationNumber,
                address(requestedStart), address(requestedEnd),
                address(effectiveStart), address(effectiveEnd),
                maxUnits, maxBytes, maxIncomingRefsPerUnit, address(current));
            response.put("next_cursor", ListingCursorCodec.encode(payload));
        }
        response.put("units", units);
        return new Page(response);
    }

    private static Map<String, Object> renderUnit(
            RangeIndex index,
            String programId,
            long modificationNumber,
            CodeUnit existing,
            Address start,
            Address end,
            boolean initialized,
            byte[] bytes,
            boolean bytesComplete,
            boolean oversized,
            int maxIncomingRefsPerUnit,
            DataMetadataReader dataMetadataReader) {
        String kind = existing instanceof Instruction ? "instruction"
            : existing instanceof Data ? "data" : "undefined";
        Map<String, Object> unit = new LinkedHashMap<>();
        unit.put("start", address(start));
        unit.put("end", address(end));
        unit.put("kind", kind);
        unit.put("initialized", initialized);
        unit.put("bytes", bytes == null ? null : HEX.formatHex(bytes));
        unit.put("bytes_complete", bytesComplete);
        if (oversized) {
            unit.put("bytes_request", Map.of(
                "address", address(start),
                "length", rangeLength(start, end),
                "tool", "inspect_memory_content"));
        }

        if (existing instanceof Instruction instruction) {
            unit.put("mnemonic", instruction.getMnemonicString());
            unit.put("operand_text", operandText(instruction));
            unit.put("flow_type", instruction.getFlowType() == null
                ? null : instruction.getFlowType().getName());
            unit.put("fall_through", instruction.getFallThrough() == null
                ? null : address(instruction.getFallThrough()));
            Address[] flows = instruction.getFlows();
            unit.put("flows", flows == null ? List.of()
                : Arrays.stream(flows).sorted().map(ListingRangeService::address).toList());
        }
        else if (existing instanceof Data data) {
            DataMetadata metadata = dataMetadataReader.read(data);
            unit.put("data_type", metadata.displayName());
            unit.put("data_type_path", metadata.pathName());
            unit.put("representation", data.getDefaultValueRepresentation());
        }

        unit.put("labels", index.labels(start, end).stream()
            .map(ListingRangeService::labelRecord)
            .toList());
        unit.put("comments", index.comments(start, end).stream()
            .map(ListingRangeService::commentRecord)
            .toList());

        List<Reference> outgoing = index.outgoing(start, end);
        unit.put("outgoing_references", outgoing.stream()
            .map(reference -> referenceRecord(
                programId, modificationNumber, reference))
            .toList());

        IncomingPage incoming =
            index.incoming(start, end, maxIncomingRefsPerUnit);
        unit.put("incoming_references", incoming.included().stream()
            .map(reference -> referenceRecord(
                programId, modificationNumber, reference))
            .toList());
        unit.put("incoming_references_complete", incoming.complete());
        if (!incoming.complete()) {
            unit.put("incoming_references_next_address",
                address(incoming.nextAddress()));
            unit.put("incoming_references_next_offset", incoming.nextOffset());
            unit.put("incoming_references_tool", "get_xrefs_to");
        }
        return unit;
    }

    private static String operandText(Instruction instruction) {
        List<String> operands = new ArrayList<>();
        for (int index = 0; index < instruction.getNumOperands(); index++) {
            String operand = instruction.getDefaultOperandRepresentation(index);
            operands.add(operand == null ? "" : operand);
        }
        return String.join(", ", operands);
    }

    private static Map<String, Object> labelRecord(LabelRecord label) {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("address", address(label.address()));
        record.put("name", label.name());
        record.put("namespace", label.namespace());
        record.put("source_type", label.sourceType());
        record.put("primary", label.primary());
        record.put("entry_point", label.entryPoint());
        return record;
    }

    private static Map<String, Object> commentRecord(CommentRecord comment) {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("address", address(comment.address()));
        record.put("type", comment.type().name().toLowerCase(java.util.Locale.ROOT));
        record.put("text", comment.text());
        return record;
    }

    private static Map<String, Object> referenceRecord(
            String programId, long modificationNumber, Reference reference) {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("id", referenceId(programId, modificationNumber, reference));
        record.put("source", address(reference.getFromAddress()));
        record.put("destination", address(reference.getToAddress()));
        record.put("type", reference.getReferenceType().getName());
        record.put("operand_index", reference.getOperandIndex());
        record.put("source_kind", ReferenceOrdering.sourceKind(reference.getSource()));
        return record;
    }

    private static String referenceId(
            String programId, long modificationNumber, Reference reference) {
        String identity = String.join("\u001f",
            programId,
            Long.toString(modificationNumber),
            address(reference.getFromAddress()),
            address(reference.getToAddress()),
            reference.getReferenceType().getName(),
            Integer.toString(reference.getOperandIndex()),
            ReferenceOrdering.sourceKind(reference.getSource()));
        return sha256(identity);
    }

    private static String sha256(String text) {
        try {
            return HEX.formatHex(
                MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static byte[] readBytes(Memory memory, Address start, int length)
            throws Exception {
        byte[] bytes = new byte[length];
        int read = memory.getBytes(start, bytes);
        if (read != length) {
            throw new IllegalStateException(
                "Could not read all initialized bytes at " + address(start)
                    + ": expected " + length + ", read " + read + ".");
        }
        return bytes;
    }

    private static int rangeLength(Address start, Address end) {
        long length = end.subtract(start) + 1;
        if (length < 1 || length > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Listing unit length is not representable.");
        }
        return (int) length;
    }

    private static Address next(Address address) {
        try {
            return address.next();
        }
        catch (RuntimeException exception) {
            return null;
        }
    }

    private static Address cappedEnd(Address start, int maxLength, Address absoluteEnd) {
        if (maxLength < 1) {
            throw new IllegalArgumentException("Listing unit length must be positive.");
        }
        try {
            Address candidate = start.addNoWrap((long) maxLength - 1);
            return candidate.compareTo(absoluteEnd) < 0 ? candidate : absoluteEnd;
        }
        catch (Exception exception) {
            return absoluteEnd;
        }
    }

    private static Map<String, Object> range(Address start, Address end) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("start", address(start));
        result.put("end", address(end));
        return result;
    }

    private static String address(Address address) {
        return address.toString();
    }

    private static String programIdentity(Program program) {
        return Long.toUnsignedString(program.getUniqueProgramID());
    }

    private static String namespace(Symbol symbol) {
        Namespace namespace = symbol.getParentNamespace();
        return namespace == null ? "" : namespace.getName(true);
    }

    private static DataMetadata readDataMetadata(Data data) {
        var dataType = data.getDataType();
        if (dataType == null) {
            return new DataMetadata(null, null);
        }
        return new DataMetadata(
            dataType.getDisplayName(),
            dataType.getPathName());
    }

    private static byte[] randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    private static byte[] cursorMac(byte[] payload) {
        try {
            Mac mac = Mac.getInstance(CURSOR_MAC_ALGORITHM);
            mac.init(new SecretKeySpec(CURSOR_MAC_KEY, CURSOR_MAC_ALGORITHM));
            return mac.doFinal(payload);
        }
        catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Cursor HMAC is unavailable.", exception);
        }
    }

    record CursorPayload(
        int version,
        String programId,
        long modificationNumber,
        String requestedStart,
        String requestedEnd,
        String effectiveStart,
        String effectiveEnd,
        int maxUnits,
        int maxBytes,
        int maxIncoming,
        String nextAddress) {
    }

    record CursorValidation(Address nextAddress, String error) {
    }

    record LabelRecord(
        Address address,
        String name,
        String namespace,
        String sourceType,
        boolean primary,
        boolean entryPoint) {
    }

    record CommentRecord(Address address, CommentType type, String text) {
    }

    record DataMetadata(String displayName, String pathName) {
    }

    @FunctionalInterface
    interface DataMetadataReader {
        DataMetadata read(Data data);
    }

    record IncomingPage(
        List<Reference> included,
        boolean complete,
        Address nextAddress,
        long nextOffset) {
    }

    record SelectedReferences(List<Reference> references, boolean truncated) {
    }

    record Page(Map<String, Object> response) {
    }

    static final class RangeIndex {
        private final Memory memory;
        private final Address effectiveEnd;
        private final AddressSetView initialized;
        private final NavigableMap<Address, CodeUnit> codeUnits;
        private final NavigableMap<Address, List<LabelRecord>> labels;
        private final NavigableMap<Address, List<CommentRecord>> comments;
        private final NavigableSet<Address> outgoingSources;
        private final NavigableSet<Address> incomingDestinations;
        private final NavigableSet<Address> boundaries;
        private final ReferenceManager references;

        private RangeIndex(
                Memory memory,
                Address effectiveEnd,
                AddressSetView initialized,
                NavigableMap<Address, CodeUnit> codeUnits,
                NavigableMap<Address, List<LabelRecord>> labels,
                NavigableMap<Address, List<CommentRecord>> comments,
                NavigableSet<Address> outgoingSources,
                NavigableSet<Address> incomingDestinations,
                NavigableSet<Address> boundaries,
                ReferenceManager references) {
            this.memory = memory;
            this.effectiveEnd = effectiveEnd;
            this.initialized = initialized;
            this.codeUnits = codeUnits;
            this.labels = labels;
            this.comments = comments;
            this.outgoingSources = outgoingSources;
            this.incomingDestinations = incomingDestinations;
            this.boundaries = boundaries;
            this.references = references;
        }

        static RangeIndex build(
                Program program, Address effectiveStart, Address effectiveEnd) {
            AddressSet range = new AddressSet(effectiveStart, effectiveEnd);
            Listing listing = program.getListing();
            Memory memory = program.getMemory();
            AddressSetView initialized = memory.getAllInitializedAddressSet();
            ReferenceManager referenceManager = program.getReferenceManager();
            NavigableMap<Address, CodeUnit> codeUnits = new TreeMap<>();
            NavigableMap<Address, List<LabelRecord>> labels = new TreeMap<>();
            NavigableMap<Address, List<CommentRecord>> comments = new TreeMap<>();
            NavigableSet<Address> outgoingSources = new TreeSet<>();
            NavigableSet<Address> incomingDestinations = new TreeSet<>();
            NavigableSet<Address> boundaries = new TreeSet<>();
            boundaries.add(effectiveStart);

            CodeUnitIterator codeIterator = listing.getCodeUnits(range, true);
            while (codeIterator != null && codeIterator.hasNext()) {
                CodeUnit unit = codeIterator.next();
                if (unit == null) {
                    continue;
                }
                codeUnits.put(unit.getMinAddress(), unit);
                boundaries.add(unit.getMinAddress());
                Address after = next(unit.getMaxAddress());
                if (within(after, effectiveStart, effectiveEnd)) {
                    boundaries.add(after);
                }
            }

            addAddresses(
                referenceManager.getReferenceSourceIterator(range, true),
                outgoingSources, boundaries);
            addAddresses(
                referenceManager.getReferenceDestinationIterator(range, true),
                incomingDestinations, boundaries);

            SymbolTable symbolTable = program.getSymbolTable();
            Set<String> labelKeys = new HashSet<>();
            SymbolIterator symbolIterator =
                symbolTable.getSymbolIterator(effectiveStart, true);
            while (symbolIterator != null && symbolIterator.hasNext()) {
                Symbol symbol = symbolIterator.next();
                if (symbol == null || symbol.getAddress() == null) {
                    continue;
                }
                Address at = symbol.getAddress();
                if (!at.getAddressSpace().equals(effectiveStart.getAddressSpace())
                        || at.compareTo(effectiveEnd) > 0) {
                    break;
                }
                if (at.compareTo(effectiveStart) < 0) {
                    continue;
                }
                addLabel(symbol, symbolTable, labels, boundaries, labelKeys);
            }
            // Address-based iteration omits global dynamic labels. Those labels
            // can only arise at reference destinations, already indexed above,
            // so supplement them without falling back to a per-byte scan.
            for (Address destination : incomingDestinations) {
                Symbol[] at = symbolTable.getSymbols(destination);
                if (at == null) {
                    continue;
                }
                for (Symbol symbol : at) {
                    addLabel(symbol, symbolTable, labels, boundaries, labelKeys);
                }
            }
            Comparator<LabelRecord> labelOrder = Comparator
                .comparing(LabelRecord::address)
                .thenComparing(LabelRecord::namespace)
                .thenComparing(LabelRecord::name)
                .thenComparing(LabelRecord::sourceType)
                .thenComparing(LabelRecord::primary);
            labels.values().forEach(values -> values.sort(labelOrder));

            AddressIterator commentAddresses =
                listing.getCommentAddressIterator(range, true);
            while (commentAddresses != null && commentAddresses.hasNext()) {
                Address at = commentAddresses.next();
                if (at == null) {
                    continue;
                }
                for (CommentType type : CommentType.values()) {
                    String text = listing.getComment(type, at);
                    if (text != null) {
                        comments.computeIfAbsent(at, ignored -> new ArrayList<>())
                            .add(new CommentRecord(at, type, text));
                    }
                }
                boundaries.add(at);
            }
            Comparator<CommentRecord> commentOrder = Comparator
                .comparing(CommentRecord::address)
                .thenComparing(comment -> comment.type().name())
                .thenComparing(CommentRecord::text);
            comments.values().forEach(values -> values.sort(commentOrder));

            addInitializationBoundaries(
                initialized, effectiveStart, effectiveEnd, boundaries);

            return new RangeIndex(
                memory, effectiveEnd, initialized,
                codeUnits, labels, comments, outgoingSources,
                incomingDestinations, boundaries, referenceManager);
        }

        Memory memory() {
            return memory;
        }

        CodeUnit codeUnitAt(Address address) {
            return codeUnits.get(address);
        }

        CodeUnit codeUnitContaining(Address address) {
            Map.Entry<Address, CodeUnit> floor = codeUnits.floorEntry(address);
            if (floor == null || floor.getValue().getMaxAddress().compareTo(address) < 0) {
                return null;
            }
            return floor.getValue();
        }

        boolean initialized(Address address) {
            return initialized.contains(address);
        }

        boolean initialized(Address start, Address end) {
            return initialized.contains(start, end);
        }

        Address undefinedEnd(Address start, int maxLength) {
            Address nextBoundary = boundaries.higher(start);
            Address boundaryEnd = nextBoundary == null
                ? effectiveEnd : nextBoundary.previous();
            return cappedEnd(start, maxLength, boundaryEnd);
        }

        List<LabelRecord> labels(Address start, Address end) {
            return flatten(labels.subMap(start, true, end, true));
        }

        List<CommentRecord> comments(Address start, Address end) {
            return flatten(comments.subMap(start, true, end, true));
        }

        List<Reference> outgoing(Address start, Address end) {
            List<Reference> result = new ArrayList<>();
            for (Address source : outgoingSources.subSet(start, true, end, true)) {
                Reference[] at = references.getReferencesFrom(source);
                if (at != null) {
                    result.addAll(Arrays.asList(at));
                }
            }
            result.sort(ReferenceOrdering.outgoing());
            return result;
        }

        IncomingPage incoming(Address start, Address end, int cap) {
            List<Reference> collected = new ArrayList<>(cap + 1);
            for (Address destination :
                    incomingDestinations.subSet(start, true, end, true)) {
                int remaining = cap + 1 - collected.size();
                if (remaining <= 0) {
                    break;
                }
                SelectedReferences selected = selectFirstReferences(
                    references.getReferencesTo(destination), remaining);
                collected.addAll(selected.references());
                if (selected.truncated() || collected.size() == cap + 1) {
                    break;
                }
            }
            collected.sort(ReferenceOrdering.incoming());
            if (collected.size() <= cap) {
                return new IncomingPage(List.copyOf(collected), true, null, 0);
            }
            List<Reference> included = List.copyOf(collected.subList(0, cap));
            Reference next = collected.get(cap);
            long offset = included.stream()
                .filter(reference ->
                    reference.getToAddress().equals(next.getToAddress()))
                .count();
            return new IncomingPage(
                included, false, next.getToAddress(), offset);
        }

        private static SelectedReferences selectFirstReferences(
                ReferenceIterator iterator, int limit) {
            Comparator<Reference> order = ReferenceOrdering.perDestination();
            PriorityQueue<Reference> selected =
                new PriorityQueue<>(limit, order.reversed());
            int count = 0;
            while (iterator != null && iterator.hasNext()) {
                Reference reference = iterator.next();
                count++;
                if (selected.size() < limit) {
                    selected.add(reference);
                }
                else if (order.compare(reference, selected.peek()) < 0) {
                    selected.poll();
                    selected.add(reference);
                }
            }
            List<Reference> ordered = new ArrayList<>(selected);
            ordered.sort(order);
            return new SelectedReferences(
                ordered, count > limit);
        }

        private static <T> List<T> flatten(
                NavigableMap<Address, List<T>> byAddress) {
            List<T> result = new ArrayList<>();
            byAddress.values().forEach(result::addAll);
            return result;
        }

        private static void addAddresses(
                AddressIterator iterator,
                NavigableSet<Address> addresses,
                NavigableSet<Address> boundaries) {
            while (iterator != null && iterator.hasNext()) {
                Address address = iterator.next();
                if (address != null) {
                    addresses.add(address);
                    boundaries.add(address);
                }
            }
        }

        private static void addLabel(
                Symbol symbol,
                SymbolTable symbolTable,
                NavigableMap<Address, List<LabelRecord>> labels,
                NavigableSet<Address> boundaries,
                Set<String> labelKeys) {
            if (symbol == null || symbol.getAddress() == null) {
                return;
            }
            Address at = symbol.getAddress();
            LabelRecord label = new LabelRecord(
                at, symbol.getName(), namespace(symbol),
                ReferenceOrdering.sourceKind(symbol.getSource()),
                symbol.isPrimary(), symbolTable.isExternalEntryPoint(at));
            String key = String.join("\u001f",
                address(label.address()), label.namespace(), label.name(),
                label.sourceType(), Boolean.toString(label.primary()),
                Boolean.toString(label.entryPoint()));
            if (labelKeys.add(key)) {
                labels.computeIfAbsent(at, ignored -> new ArrayList<>()).add(label);
                boundaries.add(at);
            }
        }

        private static void addInitializationBoundaries(
                AddressSetView initialized,
                Address effectiveStart,
                Address effectiveEnd,
                NavigableSet<Address> boundaries) {
            AddressRangeIterator ranges =
                initialized.getAddressRanges(effectiveStart, true);
            while (ranges != null && ranges.hasNext()) {
                AddressRange range = ranges.next();
                if (range.getMinAddress().compareTo(effectiveEnd) > 0) {
                    break;
                }
                if (range.getMaxAddress().compareTo(effectiveStart) < 0) {
                    continue;
                }
                Address first = range.getMinAddress().compareTo(effectiveStart) < 0
                    ? effectiveStart : range.getMinAddress();
                boundaries.add(first);
                Address after = next(range.getMaxAddress());
                if (within(after, effectiveStart, effectiveEnd)) {
                    boundaries.add(after);
                }
            }
        }

        private static boolean within(
                Address address, Address start, Address end) {
            return address != null
                && address.getAddressSpace().equals(start.getAddressSpace())
                && address.compareTo(start) >= 0
                && address.compareTo(end) <= 0;
        }
    }

    static final class ListingCursorCodec {
        private ListingCursorCodec() {
        }

        static String encode(CursorPayload payload) {
            Map<String, Object> values = new LinkedHashMap<>();
            values.put("version", payload.version());
            values.put("program_id", payload.programId());
            values.put("modification_number", payload.modificationNumber());
            values.put("requested_start", payload.requestedStart());
            values.put("requested_end", payload.requestedEnd());
            values.put("effective_start", payload.effectiveStart());
            values.put("effective_end", payload.effectiveEnd());
            values.put("max_units", payload.maxUnits());
            values.put("max_bytes", payload.maxBytes());
            values.put("max_incoming", payload.maxIncoming());
            values.put("next_address", payload.nextAddress());
            byte[] json =
                JsonHelper.toJson(values).getBytes(StandardCharsets.UTF_8);
            String encodedPayload =
                Base64.getUrlEncoder().withoutPadding().encodeToString(json);
            String encodedMac = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(cursorMac(json));
            return encodedPayload + "." + encodedMac;
        }

        static CursorValidation decodeAndValidate(
                String cursor,
                Program program,
                String programId,
                long modificationNumber,
                Address requestedStart,
                Address requestedEnd,
                Address effectiveStart,
                Address effectiveEnd,
                int maxUnits,
                int maxBytes,
                int maxIncoming) {
            String[] parts = cursor.split("\\.", -1);
            if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
                return new CursorValidation(null, "Listing cursor is malformed.");
            }

            final byte[] payload;
            final byte[] suppliedMac;
            try {
                payload = Base64.getUrlDecoder().decode(parts[0]);
                suppliedMac = Base64.getUrlDecoder().decode(parts[1]);
            }
            catch (IllegalArgumentException exception) {
                return new CursorValidation(null, "Listing cursor is malformed.");
            }
            if (!MessageDigest.isEqual(cursorMac(payload), suppliedMac)) {
                return new CursorValidation(
                    null, "Listing cursor integrity check failed.");
            }

            final JsonObject json;
            try {
                json = JsonParser.parseString(
                    new String(payload, StandardCharsets.UTF_8)).getAsJsonObject();
            }
            catch (Exception exception) {
                return new CursorValidation(null, "Listing cursor is malformed.");
            }
            try {
                if (json.get("version").getAsInt() != CURSOR_VERSION) {
                    return new CursorValidation(
                        null, "Listing cursor version is unsupported.");
                }
                if (!json.get("program_id").getAsString().equals(programId)) {
                    return new CursorValidation(
                        null, "Listing cursor belongs to a different program.");
                }
                if (json.get("modification_number").getAsLong()
                        != modificationNumber) {
                    return new CursorValidation(
                        null,
                        "Listing cursor is invalid because the program changed; "
                            + "retry from the first page.");
                }
                if (!same(json, "requested_start", requestedStart)
                        || !same(json, "requested_end", requestedEnd)
                        || !same(json, "effective_start", effectiveStart)
                        || !same(json, "effective_end", effectiveEnd)) {
                    return new CursorValidation(
                        null, "Listing cursor bounds do not match this request.");
                }
                if (json.get("max_units").getAsInt() != maxUnits
                        || json.get("max_bytes").getAsInt() != maxBytes
                        || json.get("max_incoming").getAsInt() != maxIncoming) {
                    return new CursorValidation(
                        null, "Listing cursor limits do not match this request.");
                }
                Address nextAddress = ServiceUtils.parseAddress(
                    program, json.get("next_address").getAsString());
                if (nextAddress == null
                        || !nextAddress.getAddressSpace()
                            .equals(effectiveStart.getAddressSpace())
                        || nextAddress.compareTo(effectiveStart) <= 0
                        || nextAddress.compareTo(effectiveEnd) > 0) {
                    return new CursorValidation(
                        null, "Listing cursor next address is invalid.");
                }
                return new CursorValidation(nextAddress, null);
            }
            catch (Exception exception) {
                return new CursorValidation(null, "Listing cursor is malformed.");
            }
        }

        private static boolean same(
                JsonObject json, String field, Address expected) {
            return json.get(field).getAsString().equals(address(expected));
        }
    }
}
