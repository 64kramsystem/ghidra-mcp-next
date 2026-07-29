package com.xebyte.core;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

/**
 * Byte windows that numerically decode into a destination address range.
 *
 * <p>The sibling {@code get_references_into_range} reports what Ghidra's reference
 * database holds and says so. This endpoint answers the complementary question — which
 * bytes <em>encode</em> an in-range address, whether or not a reference was ever recorded
 * — and therefore carries false positives by construction. It claims exhaustive
 * <em>encodings</em>, a checkable fact about bytes; it does not claim exhaustive meaning.</p>
 *
 * <p>The scan itself runs on {@link MemorySearchCore}, shared with
 * {@code search_byte_patterns}, so both endpoints have the same block-boundary, chunking
 * and read-failure behaviour.</p>
 */
public final class AddressEncodingSearchService {

    private static final int MAX_LIMIT = 10_000;
    private static final int MIN_WIDTH = 1;
    private static final int MAX_WIDTH = 8;
    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public AddressEncodingSearchService(
            ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    @McpTool(path = "/search_address_encodings",
        description = "Find byte windows that numerically decode into an inclusive "
            + "DESTINATION address range — including untyped pointer tables, unresolved "
            + "operands and pointers sitting in undefined bytes, none of which appear in "
            + "get_references_into_range. Every offset is tested, unaligned included, and "
            + "overlapping windows are separate rows, so the result carries FALSE "
            + "POSITIVES by construction: `scope` says it is exhaustive over encodings, "
            + "not over meaning. Each row reports where the window sits "
            + "(inside_instruction, inside_data_unit or undefined) and any recorded "
            + "reference whose destination equals the decoded target in BOTH space and "
            + "offset — so on an overlaid program a RAM query and an overlay query over "
            + "the same offsets return different references. Paged with a continuation "
            + "address in `cursor`; a whole window must lie inside one initialized range in one "
            + "block, so a window straddling a block seam is not reported.")
    public Response searchAddressEncodings(
            @Param(value = "start",
                description = "Inclusive start of the destination range being looked for. "
                    + "Accepts 0x<hex> (default space) or <space>:<hex>.") String startText,
            @Param(value = "end",
                description = "Inclusive end of the destination range; same address space "
                    + "as `start`.") String endText,
            @Param(value = "width_bytes", defaultValue = "2",
                description = "Encoding width in bytes, 1..8. Destination bounds not "
                    + "representable in this width are rejected.") int widthBytes,
            @Param(value = "byte_order", defaultValue = "little",
                description = "'little' or 'big'.") String byteOrder,
            @Param(value = "source_start", defaultValue = "",
                description = "Restrict where the scan looks; requires `source_end`. Omit "
                    + "both to scan all initialized memory.") String sourceStartText,
            @Param(value = "source_end", defaultValue = "",
                description = "Inclusive end of the scanned source range.") String sourceEndText,
            @Param(value = "limit", defaultValue = "1000",
                description = "Maximum rows returned per page, 1..10000.") int limit,
            @Param(value = "cursor", defaultValue = "",
                description = "Continuation address from a previous page. "
                    + "`limit` may change between pages.") String cursor,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe =
            ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (limit < 1 || limit > MAX_LIMIT) {
            return Response.err("limit must be in 1.." + MAX_LIMIT + " (got " + limit + ")");
        }
        if (widthBytes < MIN_WIDTH || widthBytes > MAX_WIDTH) {
            return Response.err("width_bytes must be in " + MIN_WIDTH + ".." + MAX_WIDTH
                + " (got " + widthBytes + ")");
        }
        String order = byteOrder == null ? "" : byteOrder.trim().toLowerCase(Locale.ROOT);
        if (!"little".equals(order) && !"big".equals(order)) {
            return Response.err("byte_order must be 'little' or 'big' (got '"
                + byteOrder + "')");
        }

        // parseAddress reports through a ThreadLocal, so every address resolves here on
        // the calling thread rather than inside the threading strategy's hop.
        Address start = ServiceUtils.parseAddress(program, startText);
        if (start == null) return Response.err(ServiceUtils.getLastParseError());
        Address end = ServiceUtils.parseAddress(program, endText);
        if (end == null) return Response.err(ServiceUtils.getLastParseError());
        Response rangeError = validateRange(start, end, startText, endText, "destination");
        if (rangeError != null) return rangeError;

        boolean hasSourceStart = sourceStartText != null && !sourceStartText.isBlank();
        boolean hasSourceEnd = sourceEndText != null && !sourceEndText.isBlank();
        if (hasSourceStart != hasSourceEnd) {
            return Response.err(
                "source_start and source_end must be given together, or neither.");
        }
        Address sourceStart = null;
        Address sourceEnd = null;
        if (hasSourceStart) {
            sourceStart = ServiceUtils.parseAddress(program, sourceStartText);
            if (sourceStart == null) return Response.err(ServiceUtils.getLastParseError());
            sourceEnd = ServiceUtils.parseAddress(program, sourceEndText);
            if (sourceEnd == null) return Response.err(ServiceUtils.getLastParseError());
            Response sourceError = validateRange(
                sourceStart, sourceEnd, sourceStartText, sourceEndText, "source");
            if (sourceError != null) return sourceError;
        }

        // A bound the width cannot represent would produce an empty result that reads
        // as a clean sweep, so it is rejected instead.
        BigInteger widthCeiling = BigInteger.ONE.shiftLeft(8 * widthBytes);
        if (end.getOffsetAsBigInteger().compareTo(widthCeiling) >= 0) {
            return Response.err("destination end " + end.toString(true)
                + " is not representable in " + widthBytes + " byte(s); the largest "
                + "encodable offset is 0x" + widthCeiling.subtract(BigInteger.ONE)
                    .toString(16));
        }

        Query query = new Query(start, end, widthBytes, order, sourceStart, sourceEnd);
        final String cursorText = cursor == null ? "" : cursor.trim();
        try {
            return threadingStrategy.executeRead(
                () -> runSearch(program, query, limit, cursorText));
        } catch (Exception exception) {
            return Response.err(
                "Error searching address encodings: " + exception.getMessage());
        }
    }

    private static Response validateRange(
            Address start, Address end, String startText, String endText, String label) {
        if (!start.getAddressSpace().getName().equals(end.getAddressSpace().getName())) {
            return Response.err(label + " start and end must resolve in the same address "
                + "space; got '" + start.getAddressSpace().getName() + "' and '"
                + end.getAddressSpace().getName()
                + "'. A range spanning two spaces has no meaning.");
        }
        if (start.getOffsetAsBigInteger().compareTo(end.getOffsetAsBigInteger()) > 0) {
            return Response.err(label + " start must not be greater than end; got '"
                + startText + "' > '" + endText + "'");
        }
        return null;
    }

    private record Query(
        Address destinationStart,
        Address destinationEnd,
        int widthBytes,
        String byteOrder,
        Address sourceStart,
        Address sourceEnd) {
    }

    /** One retained match, before reference enrichment. */
    private record Hit(Address encodingAddress, BigInteger value) {
    }

    private static Response runSearch(
            Program program, Query query, int limit, String cursorText) {
        long modificationBefore = program.getModificationNumber();

        Address resumeAt = null;
        if (!cursorText.isEmpty()) {
            resumeAt = ServiceUtils.parseAddress(program, cursorText);
            if (resumeAt == null) {
                return Response.err("Invalid encoding cursor address: " + cursorText);
            }
        }

        List<MemorySearchCore.ScanRange> allRanges = MemorySearchCore.initializedRanges(
            program, query.sourceStart(), query.sourceEnd());
        // The scanned tail may be shorter than the scope, but source_scope must always
        // describe the scope itself, so the space list comes from the full range list.
        Set<String> spaceNames = new LinkedHashSet<>();
        for (MemorySearchCore.ScanRange range : allRanges) {
            spaceNames.add(range.start().getAddressSpace().getName());
        }
        List<MemorySearchCore.ScanRange> ranges =
            resumeAt == null ? allRanges : resumeFrom(allRanges, resumeAt);

        BigInteger low = query.destinationStart().getOffsetAsBigInteger();
        BigInteger high = query.destinationEnd().getOffsetAsBigInteger();
        int width = query.widthBytes();
        boolean littleEndian = "little".equals(query.byteOrder());
        // The matcher runs immediately before the visitor for an accepted window, so
        // handing the decoded value over in a one-slot holder avoids decoding twice.
        BigInteger[] decoded = new BigInteger[1];
        MemorySearchCore.WindowMatcher matcher = (buffer, offset) -> {
            BigInteger value = decode(buffer, offset, width, littleEndian);
            if (value.compareTo(low) < 0 || value.compareTo(high) > 0) {
                return false;
            }
            decoded[0] = value;
            return true;
        };

        List<Hit> hits = new ArrayList<>();
        Address[] lookahead = new Address[1];
        MemorySearchCore.ScanOutcome outcome = MemorySearchCore.scan(
            MemorySearchCore.memorySource(program.getMemory()), ranges, width,
            MemorySearchCore.DEFAULT_CHUNK_SIZE, matcher,
            address -> {
                if (hits.size() < limit) {
                    hits.add(new Hit(address, decoded[0]));
                    return true;
                }
                // The one extra match establishes has_more honestly, and is bound as
                // the resume point so that resuming returns it rather than losing it.
                lookahead[0] = address;
                return false;
            });
        if (outcome.failed()) {
            return Response.err(outcome.error());
        }

        List<Map<String, Object>> rows = new ArrayList<>(hits.size());
        for (Hit hit : hits) {
            rows.add(describe(program, query, hit));
        }
        // Checked again after enrichment: an edit landing between the scan and the
        // reference reads tears the page just as badly as one during the scan.
        if (program.getModificationNumber() != modificationBefore) {
            return Response.err("Program changed while searching address encodings; "
                + "retry from the first page.");
        }

        Map<String, Object> sourceScope = new LinkedHashMap<>();
        if (query.sourceStart() == null) {
            sourceScope.put("mode", "all_initialized_memory");
        } else {
            sourceScope.put("mode", "range");
            sourceScope.put("start", query.sourceStart().toString(true));
            sourceScope.put("end", query.sourceEnd().toString(true));
        }
        sourceScope.put("spaces", new ArrayList<>(spaceNames));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("destination_range", query.destinationStart().toString(true)
            + " - " + query.destinationEnd().toString(true));
        result.put("source_scope", sourceScope);
        result.put("width_bytes", width);
        result.put("byte_order", query.byteOrder());
        result.put("scope", "byte_encodings_of_destination_range");
        result.put("encodings", rows);
        result.put("returned", rows.size());
        result.put("limit", limit);
        result.put("cursor", lookahead[0] == null ? null
            : lookahead[0].toString(true));
        result.put("has_more", lookahead[0] != null);
        result.put("program_modification_number", modificationBefore);
        // Nulls are meaningful here: `cursor: null` is how a caller learns the
        // traversal is complete, so the response is serialized with nulls retained.
        return Response.text(JsonHelper.toJsonWithNulls(result));
    }

    /**
     * The tail of the traversal beginning inclusively at {@code resumeAt}.
     *
     * <p>Inclusive on purpose: the resume address is a match that was found but not
     * returned, so it is deliberately retested and becomes the first row of this page.
     * Trimming a range's start never drops a later candidate, since a window only ever
     * extends forward.</p>
     */
    private static List<MemorySearchCore.ScanRange> resumeFrom(
            List<MemorySearchCore.ScanRange> ranges, Address resumeAt) {
        String resumeSpace = resumeAt.getAddressSpace().getName();
        List<MemorySearchCore.ScanRange> tail = new ArrayList<>();
        for (MemorySearchCore.ScanRange range : ranges) {
            String space = range.start().getAddressSpace().getName();
            int spaceOrder = space.compareTo(resumeSpace);
            if (spaceOrder < 0) continue;
            if (spaceOrder > 0) {
                tail.add(range);
                continue;
            }
            if (range.end().compareTo(resumeAt) < 0) continue;
            if (range.start().compareTo(resumeAt) >= 0) {
                tail.add(range);
                continue;
            }
            tail.add(new MemorySearchCore.ScanRange(
                range.blockName(), resumeAt, range.end()));
        }
        return tail;
    }

    /** Unsigned decode, so no width is a special case. */
    private static BigInteger decode(
            byte[] buffer, int offset, int width, boolean littleEndian) {
        byte[] bytes = new byte[width];
        for (int index = 0; index < width; index++) {
            bytes[index] = buffer[offset + (littleEndian ? width - 1 - index : index)];
        }
        return new BigInteger(1, bytes);
    }

    /**
     * One row: where the window sits, what it decodes to, and the recorded references
     * that agree with it.
     */
    private static Map<String, Object> describe(
            Program program, Query query, Hit hit) {
        Listing listing = program.getListing();
        Address encodingAddress = hit.encodingAddress();
        AddressSpace destinationSpace = query.destinationStart().getAddressSpace();
        Address decodedTarget = destinationSpace.getAddress(hit.value().longValue());

        Map<String, Object> row = new LinkedHashMap<>();
        row.put("encoding_address", encodingAddress.toString(true));

        Instruction instruction = listing.getInstructionContaining(encodingAddress);
        Data data = instruction == null
            ? listing.getDefinedDataContaining(encodingAddress) : null;

        Address siteAddress;
        String site;
        CodeUnit renderedUnit = null;
        Map<String, Object> container = null;
        if (instruction != null) {
            // Deliberately not "instruction_operand": a window beginning inside an
            // instruction may start on the opcode or straddle a code-unit boundary,
            // and Ghidra's API does not portably map operand indices to byte spans.
            site = "inside_instruction";
            siteAddress = instruction.getMinAddress();
            renderedUnit = instruction;
        } else if (data != null) {
            site = "inside_data_unit";
            Address unitStart = data.getMinAddress();
            long offsetInUnit = encodingAddress.subtract(unitStart);
            Data primitive = offsetInUnit >= 0 && offsetInUnit <= Integer.MAX_VALUE
                ? data.getPrimitiveAt((int) offsetInUnit) : null;
            // References are read from the containing PRIMITIVE component's start —
            // a dispatch-table entry, not the whole array.
            siteAddress = primitive != null && primitive.getMinAddress() != null
                ? primitive.getMinAddress() : unitStart;
            renderedUnit = primitive != null ? primitive : data;
            Symbol containerSymbol = program.getSymbolTable().getPrimarySymbol(unitStart);
            container = new LinkedHashMap<>();
            container.put("address", unitStart.toString(true));
            container.put("name", containerSymbol == null ? null : containerSymbol.getName());
            container.put("offset", offsetInUnit);
        } else {
            // No containing unit, so the encoding address is its own site.
            site = "undefined";
            siteAddress = encodingAddress;
        }

        row.put("site_address", siteAddress.toString(true));
        row.put("site_space", siteAddress.getAddressSpace().getName());
        row.put("decoded_offset", hit.value().toString(16));
        row.put("decoded_target", decodedTarget.toString(true));
        row.put("site", site);
        if (renderedUnit != null) {
            row.put("site_rendering", renderedUnit.toString());
        }
        if (container != null) {
            row.put("container", container);
        }
        row.put("matching_references",
            matchingReferences(program, siteAddress, decodedTarget));
        return row;
    }

    /**
     * References recorded at {@code origin} whose destination equals {@code target} in
     * BOTH space and offset.
     *
     * <p>The space test is the whole point on an overlaid program: a window into
     * {@code SND_PLAYER::9700} must not inherit the reference recorded to
     * {@code RAM:9700}, and the equivalent RAM query must invert exactly that.</p>
     */
    private static List<Map<String, Object>> matchingReferences(
            Program program, Address origin, Address target) {
        Reference[] from = program.getReferenceManager().getReferencesFrom(origin);
        List<Reference> matching = new ArrayList<>();
        if (from != null) {
            for (Reference reference : from) {
                if (reference == null || reference.getToAddress() == null) continue;
                Address to = reference.getToAddress();
                if (!to.getAddressSpace().getName()
                        .equals(target.getAddressSpace().getName())) {
                    continue;
                }
                if (!to.getOffsetAsBigInteger().equals(target.getOffsetAsBigInteger())) {
                    continue;
                }
                matching.add(reference);
            }
        }
        matching.sort(Comparator
            .comparing((Reference reference) -> reference.getToAddress().toString(true))
            .thenComparing(reference -> reference.getReferenceType().getName())
            .thenComparingInt(Reference::getOperandIndex)
            .thenComparing(reference -> ReferenceOrdering.sourceKind(reference.getSource())));

        List<Map<String, Object>> rows = new ArrayList<>(matching.size());
        for (Reference reference : matching) {
            Map<String, Object> record = new LinkedHashMap<>();
            record.put("to", reference.getToAddress().toString(true));
            record.put("type", reference.getReferenceType().getName());
            record.put("source_kind", ReferenceOrdering.sourceKind(reference.getSource()));
            record.put("operand_index", reference.getOperandIndex());
            record.put("primary", reference.isPrimary());
            rows.add(record);
        }
        return rows;
    }

}
