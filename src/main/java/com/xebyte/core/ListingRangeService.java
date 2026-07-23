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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
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

    public ListingRangeService(
            ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
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
                maxIncomingRefsPerUnit, cursor));
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
            String cursor) throws Exception {
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

        CodeUnit containingPageStart = definedUnitContaining(listing, pageStart);
        if (containingPageStart != null
                && !containingPageStart.getMinAddress().equals(pageStart)) {
            return Response.err("Listing cursor is not at a unit boundary.");
        }
        RangeIndex index = RangeIndex.build(program, pageStart, effectiveEnd);

        Page page = readPage(
            program, index, programId, modificationNumber,
            requestedStart, requestedEnd, effectiveStart, effectiveEnd,
            pageStart, maxUnits, maxBytes, maxIncomingRefsPerUnit);
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
            int maxIncomingRefsPerUnit) throws Exception {
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
            UnitMetadata metadata;

            if (existing != null) {
                unitEnd = existing.getMaxAddress();
                length = existing.getLength();
                initialized = index.initialized(current, unitEnd);

                if (initialized && length > maxBytes && units.isEmpty()) {
                    metadata = index.collectMetadata(
                        current, unitEnd, maxIncomingRefsPerUnit);
                    units.add(renderUnit(
                        metadata, programId, modificationNumber, existing,
                        current, unitEnd, true, null, false, true));
                    returnedEnd = unitEnd;
                    current = next(unitEnd);
                    break;
                }
                if (initialized && length > maxBytes - includedBytes) {
                    break;
                }
                metadata = index.collectMetadata(
                    current, unitEnd, maxIncomingRefsPerUnit);
            }
            else {
                initialized = index.initialized(current);
                int remainingBudget = maxBytes - includedBytes;
                if (initialized && remainingBudget == 0) {
                    break;
                }
                int undefinedLimit = initialized ? remainingBudget : maxBytes;
                // Consume only annotations at the current address before
                // looking ahead. The next peek from each ordered stream is
                // therefore the first boundary of the following unit.
                metadata = index.collectMetadata(
                    current, current, maxIncomingRefsPerUnit);
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
                metadata, programId, modificationNumber, existing,
                current, unitEnd, initialized, bytes, bytesComplete, false));
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
            UnitMetadata metadata,
            String programId,
            long modificationNumber,
            CodeUnit existing,
            Address start,
            Address end,
            boolean initialized,
            byte[] bytes,
            boolean bytesComplete,
            boolean oversized) {
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
            DataMetadata dataMetadata = readDataMetadata(data);
            unit.put("data_type", dataMetadata.displayName());
            unit.put("data_type_path", dataMetadata.pathName());
            unit.put("representation", data.getDefaultValueRepresentation());
        }

        unit.put("labels", metadata.labels().stream()
            .map(ListingRangeService::labelRecord)
            .toList());
        unit.put("comments", metadata.comments().stream()
            .map(ListingRangeService::commentRecord)
            .toList());

        unit.put("outgoing_references", metadata.outgoing().stream()
            .map(reference -> referenceRecord(
                programId, modificationNumber, reference))
            .toList());

        IncomingPage incoming = metadata.incoming();
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

    record IncomingPage(
        List<Reference> included,
        boolean complete,
        Address nextAddress,
        long nextOffset) {
    }

    record UnitMetadata(
        List<LabelRecord> labels,
        List<CommentRecord> comments,
        List<Reference> outgoing,
        IncomingPage incoming) {
    }

    record Page(Map<String, Object> response) {
    }

    static final class RangeIndex {
        private final Memory memory;
        private final Address effectiveStart;
        private final Address effectiveEnd;
        private final AddressSetView initialized;
        private final Listing listing;
        private final SymbolTable symbols;
        private final ReferenceManager references;
        private final Peekable<Instruction> instructions;
        private final Peekable<Data> data;
        private final Peekable<Symbol> labels;
        private final Peekable<Address> commentAddresses;
        private final Peekable<Address> outgoingSources;
        private final Peekable<Address> incomingDestinations;

        private RangeIndex(
                Memory memory,
                Address effectiveStart,
                Address effectiveEnd,
                AddressSetView initialized,
                Listing listing,
                SymbolTable symbols,
                ReferenceManager references,
                InstructionIterator instructions,
                DataIterator data,
                SymbolIterator labels,
                AddressIterator commentAddresses,
                AddressIterator outgoingSources,
                AddressIterator incomingDestinations) {
            this.memory = memory;
            this.effectiveStart = effectiveStart;
            this.effectiveEnd = effectiveEnd;
            this.initialized = initialized;
            this.listing = listing;
            this.symbols = symbols;
            this.references = references;
            this.instructions = new Peekable<>(instructions);
            this.data = new Peekable<>(data);
            this.labels = new Peekable<>(labels);
            this.commentAddresses = new Peekable<>(commentAddresses);
            this.outgoingSources = new Peekable<>(outgoingSources);
            this.incomingDestinations = new Peekable<>(incomingDestinations);
        }

        static RangeIndex build(
                Program program, Address effectiveStart, Address effectiveEnd) {
            AddressSet range = new AddressSet(effectiveStart, effectiveEnd);
            Listing listing = program.getListing();
            Memory memory = program.getMemory();
            return new RangeIndex(
                memory, effectiveStart, effectiveEnd,
                memory.getAllInitializedAddressSet(),
                listing, program.getSymbolTable(), program.getReferenceManager(),
                listing.getInstructions(range, true),
                listing.getDefinedData(range, true),
                program.getSymbolTable().getSymbolIterator(effectiveStart, true),
                listing.getCommentAddressIterator(range, true),
                program.getReferenceManager()
                    .getReferenceSourceIterator(range, true),
                program.getReferenceManager()
                    .getReferenceDestinationIterator(range, true));
        }

        Memory memory() {
            return memory;
        }

        CodeUnit codeUnitAt(Address address) {
            discardCodeBefore(address);
            Instruction instruction = instructions.peek();
            Data definedData = data.peek();
            Address instructionAddress = codeUnitAddress(instruction);
            Address dataAddress = codeUnitAddress(definedData);
            if (address.equals(instructionAddress)
                    && (dataAddress == null
                        || instructionAddress.compareTo(dataAddress) <= 0)) {
                return instructions.take();
            }
            if (address.equals(dataAddress)) {
                return data.take();
            }
            return null;
        }

        boolean initialized(Address address) {
            return initialized.contains(address);
        }

        boolean initialized(Address start, Address end) {
            return initialized.contains(start, end);
        }

        Address undefinedEnd(Address start, int maxLength) {
            Address nextBoundary = nextBoundary(start);
            Address boundaryEnd = nextBoundary == null
                ? effectiveEnd : nextBoundary.previous();
            return cappedEnd(start, maxLength, boundaryEnd);
        }

        UnitMetadata collectMetadata(Address start, Address end, int incomingCap) {
            List<LabelRecord> collectedLabels = new ArrayList<>();
            List<CommentRecord> collectedComments = new ArrayList<>();
            List<Reference> collectedOutgoing = new ArrayList<>();
            List<Reference> collectedIncoming =
                new ArrayList<>(incomingCap + 1);
            Set<String> labelKeys = new HashSet<>();

            while (atOrBefore(symbolAddress(labels.peek()), end)) {
                Symbol symbol = labels.take();
                if (atOrAfter(symbolAddress(symbol), start)) {
                    addLabel(symbol, collectedLabels, labelKeys);
                }
            }

            while (atOrBefore(commentAddresses.peek(), end)) {
                Address at = commentAddresses.take();
                if (!atOrAfter(at, start)) {
                    continue;
                }
                for (CommentType type : CommentType.values()) {
                    String text = listing.getComment(type, at);
                    if (text != null) {
                        collectedComments.add(new CommentRecord(at, type, text));
                    }
                }
            }

            while (atOrBefore(outgoingSources.peek(), end)) {
                Address source = outgoingSources.take();
                if (!atOrAfter(source, start)) {
                    continue;
                }
                Reference[] at = references.getReferencesFrom(source);
                if (at != null) {
                    collectedOutgoing.addAll(Arrays.asList(at));
                }
            }

            while (atOrBefore(incomingDestinations.peek(), end)) {
                Address destination = incomingDestinations.take();
                if (!atOrAfter(destination, start)) {
                    continue;
                }
                addSymbolsAt(destination, collectedLabels, labelKeys);
                int remaining = incomingCap + 1 - collectedIncoming.size();
                if (remaining > 0) {
                    collectedIncoming.addAll(ReferenceOrdering.takeStored(
                        references.getReferencesTo(destination), remaining));
                }
            }

            collectedLabels.sort(Comparator
                .comparing(LabelRecord::address)
                .thenComparing(LabelRecord::namespace)
                .thenComparing(LabelRecord::name)
                .thenComparing(LabelRecord::sourceType)
                .thenComparing(LabelRecord::primary));
            collectedComments.sort(Comparator
                .comparing(CommentRecord::address)
                .thenComparing(comment -> comment.type().name())
                .thenComparing(CommentRecord::text));
            collectedOutgoing.sort(ReferenceOrdering.outgoing());

            IncomingPage incoming;
            if (collectedIncoming.size() <= incomingCap) {
                incoming = new IncomingPage(
                    List.copyOf(collectedIncoming), true, null, 0);
            }
            else {
                List<Reference> included =
                    List.copyOf(collectedIncoming.subList(0, incomingCap));
                Reference nextReference = collectedIncoming.get(incomingCap);
                long offset = included.stream()
                    .filter(reference -> reference.getToAddress().equals(
                        nextReference.getToAddress()))
                    .count();
                incoming = new IncomingPage(
                    included, false, nextReference.getToAddress(), offset);
            }
            return new UnitMetadata(
                List.copyOf(collectedLabels),
                List.copyOf(collectedComments),
                List.copyOf(collectedOutgoing),
                incoming);
        }

        private void addSymbolsAt(
                Address destination,
                List<LabelRecord> collected,
                Set<String> labelKeys) {
            Symbol[] at = symbols.getSymbols(destination);
            if (at == null) {
                return;
            }
            for (Symbol symbol : at) {
                addLabel(symbol, collected, labelKeys);
            }
        }

        private void addLabel(
                Symbol symbol,
                List<LabelRecord> collected,
                Set<String> labelKeys) {
            if (symbol == null || symbol.getAddress() == null) {
                return;
            }
            Address at = symbol.getAddress();
            LabelRecord label = new LabelRecord(
                at, symbol.getName(), namespace(symbol),
                ReferenceOrdering.sourceKind(symbol.getSource()),
                symbol.isPrimary(), symbols.isExternalEntryPoint(at));
            String key = String.join("\u001f",
                address(label.address()), label.namespace(), label.name(),
                label.sourceType(), Boolean.toString(label.primary()),
                Boolean.toString(label.entryPoint()));
            if (labelKeys.add(key)) {
                collected.add(label);
            }
        }

        private Address nextBoundary(Address start) {
            Address boundary = null;
            boundary = earlierAfter(boundary, codeUnitAddress(instructions.peek()), start);
            boundary = earlierAfter(boundary, codeUnitAddress(data.peek()), start);
            boundary = earlierAfter(boundary, symbolAddress(labels.peek()), start);
            boundary = earlierAfter(boundary, commentAddresses.peek(), start);
            boundary = earlierAfter(boundary, outgoingSources.peek(), start);
            boundary = earlierAfter(boundary, incomingDestinations.peek(), start);
            boundary = earlierAfter(
                boundary, initializationBoundaryAfter(start), start);
            return boundary;
        }

        private Address initializationBoundaryAfter(Address start) {
            if (initialized.contains(start)) {
                AddressRange range = initialized.getRangeContaining(start);
                if (range == null) {
                    return null;
                }
                Address after = next(range.getMaxAddress());
                return within(after) ? after : null;
            }
            Address nextInitialized = initialized.findFirstAddressInCommon(
                new AddressSet(start, effectiveEnd));
            return within(nextInitialized) ? nextInitialized : null;
        }

        private void discardCodeBefore(Address address) {
            while (before(codeUnitAddress(instructions.peek()), address)) {
                instructions.take();
            }
            while (before(codeUnitAddress(data.peek()), address)) {
                data.take();
            }
        }

        private boolean within(Address address) {
            return address != null
                && address.getAddressSpace().equals(
                    effectiveStart.getAddressSpace())
                && address.compareTo(effectiveStart) >= 0
                && address.compareTo(effectiveEnd) <= 0;
        }

        private static Address codeUnitAddress(CodeUnit unit) {
            return unit == null ? null : unit.getMinAddress();
        }

        private Address symbolAddress(Symbol symbol) {
            if (symbol == null || !within(symbol.getAddress())) {
                return null;
            }
            return symbol.getAddress();
        }

        private static boolean before(Address candidate, Address address) {
            return candidate != null && candidate.compareTo(address) < 0;
        }

        private static boolean atOrBefore(Address candidate, Address address) {
            return candidate != null && candidate.compareTo(address) <= 0;
        }

        private static boolean atOrAfter(Address candidate, Address address) {
            return candidate != null && candidate.compareTo(address) >= 0;
        }

        private static Address earlierAfter(
                Address current, Address candidate, Address start) {
            if (candidate == null || candidate.compareTo(start) <= 0) {
                return current;
            }
            return current == null || candidate.compareTo(current) < 0
                ? candidate : current;
        }
    }

    static final class Peekable<T> {
        private final Iterator<T> iterator;
        private T next;
        private boolean loaded;

        Peekable(Iterator<T> iterator) {
            this.iterator = iterator;
        }

        T peek() {
            if (!loaded) {
                next = null;
                while (iterator != null && iterator.hasNext() && next == null) {
                    next = iterator.next();
                }
                loaded = true;
            }
            return next;
        }

        T take() {
            T value = peek();
            next = null;
            loaded = false;
            return value;
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
