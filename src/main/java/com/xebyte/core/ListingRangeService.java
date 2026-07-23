package com.xebyte.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
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
    private static final HexFormat HEX = HexFormat.of();
    private static final Gson OUTPUT_JSON = new GsonBuilder()
        .disableHtmlEscaping()
        .serializeNulls()
        .create();
    private static final Comparator<Reference> REFERENCE_ORDER =
        Comparator.comparing((Reference reference) -> reference.getFromAddress())
            .thenComparing(reference -> reference.getToAddress())
            .thenComparing(reference -> reference.getReferenceType().getName())
            .thenComparingInt(Reference::getOperandIndex)
            .thenComparing(reference -> sourceName(reference.getSource()));

    private final ProgramProvider programProvider;

    public ListingRangeService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    static Comparator<Reference> referenceOrder() {
        return REFERENCE_ORDER;
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
        ServiceUtils.ProgramOrError pe =
            ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) {
            return pe.error();
        }
        Program program = pe.program();

        Response limitsError =
            validateLimits(maxUnits, maxBytes, maxIncomingRefsPerUnit);
        if (limitsError != null) {
            return limitsError;
        }

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

        long modificationNumber = program.getModificationNumber();
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

        try {
            Page page = readPage(
                program, programId, modificationNumber,
                requestedStart, requestedEnd, effectiveStart, effectiveEnd,
                pageStart, maxUnits, maxBytes, maxIncomingRefsPerUnit);
            if (program.getModificationNumber() != modificationNumber) {
                return Response.err(
                    "Program changed while reading listing range; retry from the first page.");
            }
            // The listing contract requires explicit JSON nulls for unavailable
            // bytes and nullable instruction/data fields. JsonHelper deliberately
            // omits null map entries for legacy responses, so serialize this
            // endpoint's complete schema locally.
            return Response.text(OUTPUT_JSON.toJson(page.response()));
        }
        catch (Exception exception) {
            return Response.err("Error reading listing range: " + exception.getMessage());
        }
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
        Listing listing = program.getListing();
        Memory memory = program.getMemory();
        AddressSetView initializedSet = memory.getAllInitializedAddressSet();
        List<Map<String, Object>> units = new ArrayList<>();
        int includedBytes = 0;
        Address current = pageStart;
        Address returnedEnd = null;

        while (current != null
                && current.compareTo(effectiveEnd) <= 0
                && units.size() < maxUnits) {
            CodeUnit existing = definedUnitContaining(listing, current);
            Address unitStart = current;
            Address unitEnd;
            boolean initialized;
            int length;

            if (existing != null) {
                unitStart = existing.getMinAddress();
                unitEnd = existing.getMaxAddress();
                length = existing.getLength();
                initialized = initializedSet.contains(unitStart, unitEnd);

                if (initialized && length > maxBytes && units.isEmpty()) {
                    units.add(renderUnit(
                        program, programId, modificationNumber, existing,
                        unitStart, unitEnd, true, null, false, true,
                        maxIncomingRefsPerUnit));
                    returnedEnd = unitEnd;
                    current = next(unitEnd);
                    break;
                }
                if (initialized && length > maxBytes - includedBytes) {
                    break;
                }
            }
            else {
                initialized = initializedSet.contains(current);
                int remainingBudget = maxBytes - includedBytes;
                if (initialized && remainingBudget == 0) {
                    break;
                }
                int undefinedLimit =
                    initialized ? remainingBudget : Math.max(1, maxBytes);
                unitEnd = findUndefinedEnd(
                    program, initializedSet, current, effectiveEnd,
                    initialized, undefinedLimit);
                length = checkedLength(unitStart, unitEnd);
            }

            byte[] bytes = null;
            boolean bytesComplete = false;
            if (initialized) {
                bytes = readBytes(memory, unitStart, length);
                bytesComplete = bytes != null;
                if (bytesComplete) {
                    includedBytes += length;
                }
            }

            units.add(renderUnit(
                program, programId, modificationNumber, existing,
                unitStart, unitEnd, initialized, bytes, bytesComplete, false,
                maxIncomingRefsPerUnit));
            returnedEnd = unitEnd;
            current = next(unitEnd);
        }

        boolean complete = returnedEnd != null && returnedEnd.compareTo(effectiveEnd) >= 0;
        if (returnedEnd == null) {
            throw new IllegalStateException(
                "The page budgets could not represent the next listing unit.");
        }

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

    private static Address findUndefinedEnd(
            Program program,
            AddressSetView initializedSet,
            Address start,
            Address effectiveEnd,
            boolean initialized,
            int maxLength) {
        Address candidate = start;
        int length = 1;
        while (candidate.compareTo(effectiveEnd) < 0 && length < maxLength) {
            Address following = next(candidate);
            if (following == null
                    || definedUnitContaining(program.getListing(), following) != null
                    || hasAnnotationOrReference(program, following)
                    || initializedSet.contains(following) != initialized) {
                break;
            }
            candidate = following;
            length++;
        }
        return candidate;
    }

    private static boolean hasAnnotationOrReference(Program program, Address address) {
        SymbolTable symbols = program.getSymbolTable();
        if (symbols.hasSymbol(address)) {
            return true;
        }
        Listing listing = program.getListing();
        for (CommentType type : CommentType.values()) {
            if (listing.getComment(type, address) != null) {
                return true;
            }
        }
        ReferenceManager references = program.getReferenceManager();
        return references.hasReferencesFrom(address) || references.hasReferencesTo(address);
    }

    private static Map<String, Object> renderUnit(
            Program program,
            String programId,
            long modificationNumber,
            CodeUnit existing,
            Address start,
            Address end,
            boolean initialized,
            byte[] bytes,
            boolean bytesComplete,
            boolean oversized,
            int maxIncomingRefsPerUnit) {
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
                "length", checkedLength(start, end),
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
            unit.put("data_type", data.getDataType() == null
                ? null : data.getDataType().getDisplayName());
            unit.put("data_type_path", data.getDataType() == null
                ? null : data.getDataType().getPathName());
            unit.put("representation", data.getDefaultValueRepresentation());
        }

        List<Map<String, Object>> labels = labels(program, start, end);
        List<Map<String, Object>> comments = comments(program, start, end);
        List<Reference> outgoing = references(program, start, end, false);
        List<Reference> incoming = references(program, start, end, true);

        unit.put("labels", labels);
        unit.put("comments", comments);
        unit.put("outgoing_references", outgoing.stream()
            .map(reference -> referenceRecord(
                programId, modificationNumber, reference))
            .toList());

        boolean incomingComplete = incoming.size() <= maxIncomingRefsPerUnit;
        List<Reference> includedIncoming = incoming.stream()
            .limit(maxIncomingRefsPerUnit)
            .toList();
        unit.put("incoming_references", includedIncoming.stream()
            .map(reference -> referenceRecord(
                programId, modificationNumber, reference))
            .toList());
        unit.put("incoming_references_complete", incomingComplete);
        if (!incomingComplete) {
            Reference nextReference = incoming.get(maxIncomingRefsPerUnit);
            Address nextDestination = nextReference.getToAddress();
            long offset = includedIncoming.stream()
                .filter(reference ->
                    reference.getToAddress().equals(nextDestination))
                .count();
            unit.put("incoming_references_next_address", address(nextDestination));
            unit.put("incoming_references_next_offset", offset);
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

    private static List<Map<String, Object>> labels(
            Program program, Address start, Address end) {
        List<Symbol> symbols = new ArrayList<>();
        Address current = start;
        while (current != null && current.compareTo(end) <= 0) {
            Symbol[] at = program.getSymbolTable().getSymbols(current);
            if (at != null) {
                symbols.addAll(Arrays.asList(at));
            }
            current = next(current);
        }
        symbols.sort(Comparator
            .comparing((Symbol symbol) -> address(symbol.getAddress()))
            .thenComparing(ListingRangeService::namespace)
            .thenComparing(symbol -> symbol.getName())
            .thenComparing(symbol -> sourceName(symbol.getSource()))
            .thenComparing(symbol -> Boolean.valueOf(symbol.isPrimary())));
        return symbols.stream().map(symbol -> {
            Map<String, Object> record = new LinkedHashMap<>();
            record.put("address", address(symbol.getAddress()));
            record.put("name", symbol.getName());
            record.put("namespace", namespace(symbol));
            record.put("source_type", sourceName(symbol.getSource()));
            record.put("primary", symbol.isPrimary());
            record.put("entry_point",
                program.getSymbolTable().isExternalEntryPoint(symbol.getAddress()));
            return record;
        }).toList();
    }

    private static String namespace(Symbol symbol) {
        Namespace namespace = symbol.getParentNamespace();
        return namespace == null ? "" : namespace.getName(true);
    }

    private static List<Map<String, Object>> comments(
            Program program, Address start, Address end) {
        List<CommentRecord> comments = new ArrayList<>();
        Address current = start;
        while (current != null && current.compareTo(end) <= 0) {
            for (CommentType type : CommentType.values()) {
                String text = program.getListing().getComment(type, current);
                if (text != null) {
                    comments.add(new CommentRecord(current, type, text));
                }
            }
            current = next(current);
        }
        comments.sort(Comparator
            .comparing((CommentRecord comment) -> address(comment.address()))
            .thenComparing(comment -> comment.type().name())
            .thenComparing(CommentRecord::text));
        return comments.stream().map(comment -> {
            Map<String, Object> record = new LinkedHashMap<>();
            record.put("address", address(comment.address()));
            record.put("type", comment.type().name().toLowerCase(Locale.ROOT));
            record.put("text", comment.text());
            return record;
        }).toList();
    }

    private static List<Reference> references(
            Program program, Address start, Address end, boolean incoming) {
        List<Reference> result = new ArrayList<>();
        Address current = start;
        ReferenceManager manager = program.getReferenceManager();
        while (current != null && current.compareTo(end) <= 0) {
            if (incoming) {
                ReferenceIterator iterator = manager.getReferencesTo(current);
                if (iterator != null) {
                    while (iterator.hasNext()) {
                        result.add(iterator.next());
                    }
                }
            }
            else {
                Reference[] at = manager.getReferencesFrom(current);
                if (at != null) {
                    result.addAll(Arrays.asList(at));
                }
            }
            current = next(current);
        }
        result.sort(REFERENCE_ORDER);
        return result;
    }

    private static Map<String, Object> referenceRecord(
            String programId, long modificationNumber, Reference reference) {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("id", referenceId(programId, modificationNumber, reference));
        record.put("source", address(reference.getFromAddress()));
        record.put("destination", address(reference.getToAddress()));
        record.put("type", reference.getReferenceType().getName());
        record.put("operand_index", reference.getOperandIndex());
        record.put("source_kind", sourceName(reference.getSource()));
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
            sourceName(reference.getSource()));
        return sha256(identity);
    }

    private static String sourceName(SourceType source) {
        return source == null ? "" : source.name().toLowerCase(Locale.ROOT);
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

    private static int checkedLength(Address start, Address end) {
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

    record CommentRecord(Address address, CommentType type, String text) {
    }

    record Page(Map<String, Object> response) {
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
            return Base64.getUrlEncoder().withoutPadding().encodeToString(json);
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
            final JsonObject json;
            try {
                byte[] decoded = Base64.getUrlDecoder().decode(cursor);
                json = JsonParser.parseString(
                    new String(decoded, StandardCharsets.UTF_8)).getAsJsonObject();
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
                        || nextAddress.compareTo(effectiveStart) < 0
                        || nextAddress.compareTo(effectiveEnd) > 0) {
                    return new CursorValidation(
                        null, "Listing cursor next address is invalid.");
                }
                CodeUnit containing =
                    definedUnitContaining(program.getListing(), nextAddress);
                if (containing != null
                        && !containing.getMinAddress().equals(nextAddress)) {
                    return new CursorValidation(
                        null, "Listing cursor is not at a unit boundary.");
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
