package com.xebyte.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;

/**
 * How much of a program is still unexplained, and where.
 *
 * <p>{@code find_code_gaps} looks like the tool for this and is not: it reports ranges not
 * covered by any <em>function body</em>, so a project that deliberately creates no function
 * objects — labels, comments and data only, a recurring convention for 6502 snapshots —
 * has its entire image reported as a gap. This endpoint classifies every initialized byte
 * as instruction, data or undefined, and reports the undefined stretches with enough
 * context to go and look at them.</p>
 *
 * <p>Two namespaces, deliberately kept apart: {@code memory_coverage} holds exact byte
 * facts, and {@code annotation_backlog} holds convention-based audits (generic
 * {@code DAT_}/{@code LAB_} names, {@code TODO} markers). They are different kinds of
 * claim and must not read as one metric.</p>
 */
public final class CoverageService {

    private static final int MAX_LIMIT = 10_000;
    private static final int MAX_SAMPLES = 20;
    private static final int MARKER_TEXT_CAP = 200;
    private static final String MARKER_TEXT_SUFFIX = "…";
    private static final int STALE_COMMENT_EXCERPT_CODE_POINTS = 160;

    /**
     * Marker kinds in their fixed sort order. A label and a comment at one address must
     * never tie, so the order is part of the contract rather than an accident.
     */
    private static final List<String> MARKER_KIND_ORDER =
        List.of("label", "plate", "pre", "eol", "post", "repeatable");

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final DynamicNameResolver dynamicNameResolver;

    public CoverageService(
            ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this(programProvider, threadingStrategy, SymbolUtilities::parseDynamicName);
    }

    CoverageService(
            ProgramProvider programProvider,
            ThreadingStrategy threadingStrategy,
            DynamicNameResolver dynamicNameResolver) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.dynamicNameResolver = dynamicNameResolver;
    }

    @FunctionalInterface
    interface DynamicNameResolver {
        Address resolve(AddressFactory addressFactory, String name);
    }

    @McpTool(path = "/analyze_coverage",
        description = "Report how much of the program is still unexplained: every "
            + "initialized byte classified as instruction, data or undefined, per address "
            + "space, plus the undefined runs themselves with their neighbouring labels "
            + "and incoming reference counts. Unlike find_code_gaps this does not depend "
            + "on function objects, so it works on a labels-only program. An explicitly "
            + "applied undefined1..8 counts as UNDEFINED, not as data. A second namespace, "
            + "annotation_backlog, audits generic symbol names (DAT_, LAB_, ...) and "
            + "unknown markers (TODO labels and comments) — convention-based, and kept "
            + "apart from the byte facts on purpose. Statistics are always whole-program; "
            + "undefined_runs and unknown_markers page independently.")
    public Response analyzeCoverage(
            @Param(value = "min_run_length", defaultValue = "1",
                description = "Undefined runs shorter than this are excluded from the page "
                    + "but still counted, in below_min. Any positive value; one larger "
                    + "than the program simply matches nothing.") long minRunLength,
            @Param(value = "limit", defaultValue = "100",
                description = "Maximum undefined runs returned, 1..10000.") int limit,
            @Param(value = "offset", defaultValue = "0",
                description = "Page start within the ordered undefined runs.") int offset,
            @Param(value = "marker_limit", defaultValue = "100",
                description = "Maximum unknown markers returned, 1..10000.") int markerLimit,
            @Param(value = "marker_offset", defaultValue = "0",
                description = "Page start within the ordered unknown markers.")
                int markerOffset,
            @Param(value = "unknown_marker_prefix", defaultValue = "TODO",
                description = "Case-sensitive literal that marks an unresolved item in a "
                    + "label name or comment. Scanning for TODO is one project's "
                    + "convention, so it is a parameter.") String unknownMarkerPrefix,
            @Param(value = "generic_prefixes", defaultValue = "DAT_,SUB_,LAB_,FUN_,UNK_",
                description = "Comma-separated generated-name prefixes to tally.")
                String genericPrefixes,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe =
            ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (minRunLength < 1) {
            return Response.err("min_run_length must be positive (got " + minRunLength + ")");
        }
        if (limit < 1 || limit > MAX_LIMIT) {
            return Response.err("limit must be in 1.." + MAX_LIMIT + " (got " + limit + ")");
        }
        if (offset < 0) {
            return Response.err("offset must not be negative (got " + offset + ")");
        }
        if (markerLimit < 1 || markerLimit > MAX_LIMIT) {
            return Response.err(
                "marker_limit must be in 1.." + MAX_LIMIT + " (got " + markerLimit + ")");
        }
        if (markerOffset < 0) {
            return Response.err(
                "marker_offset must not be negative (got " + markerOffset + ")");
        }
        String markerPrefix =
            unknownMarkerPrefix == null ? "" : unknownMarkerPrefix.trim();
        if (markerPrefix.isEmpty()) {
            return Response.err("unknown_marker_prefix must not be empty: an empty prefix "
                + "matches every label and every comment, turning the backlog into a dump "
                + "of the whole program.");
        }
        List<String> prefixes = new ArrayList<>();
        for (String candidate : (genericPrefixes == null ? "" : genericPrefixes).split(",")) {
            String trimmed = candidate.trim();
            if (!trimmed.isEmpty()) prefixes.add(trimmed);
        }
        if (prefixes.isEmpty()) {
            return Response.err("generic_prefixes must name at least one prefix");
        }

        Request request = new Request(
            minRunLength, limit, offset, markerLimit, markerOffset, markerPrefix, prefixes);
        try {
            return threadingStrategy.executeRead(() -> collect(program, request));
        } catch (Exception exception) {
            return Response.err("Error analyzing coverage: " + exception.getMessage());
        }
    }

    private record Request(
        long minRunLength,
        int limit,
        int offset,
        int markerLimit,
        int markerOffset,
        String markerPrefix,
        List<String> genericPrefixes) {
    }

    @McpTool(path = "/audit_stale_comment_names",
        description = "Find Ghidra-generated address names left in listing comments after "
            + "their targets were given meaningful symbols. Scans every comment kind in "
            + "mapped memory and reports only resolvable names whose target has a "
            + "non-generated current symbol. Mentions of deleted labels are out of scope; "
            + "deliberate historical uses of old names require human review.")
    public Response auditStaleCommentNames(
            @Param(value = "limit", defaultValue = "100",
                description = "Maximum stale mentions returned, 1..10000.") int limit,
            @Param(value = "offset", defaultValue = "0",
                description = "Page start within the ordered stale mentions.") int offset,
            @Param(value = "program",
                description = "Target program name (omit to use the active program — always specify when multiple programs are open)",
                defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe =
            ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        if (limit < 1 || limit > MAX_LIMIT) {
            return Response.err("limit must be in 1.." + MAX_LIMIT + " (got " + limit + ")");
        }
        if (offset < 0) {
            return Response.err("offset must not be negative (got " + offset + ")");
        }
        try {
            return threadingStrategy.executeRead(
                () -> collectStaleCommentNames(pe.program(), limit, offset));
        } catch (Exception exception) {
            return Response.err(
                "Error auditing stale comment names: " + exception.getMessage());
        }
    }

    private record StaleCommentName(
        Address commentAddress,
        String commentKind,
        String staleName,
        Address targetAddress,
        String currentPrimaryName,
        List<String> currentNames,
        String commentExcerpt) {
    }

    private Response collectStaleCommentNames(
            Program program, int limit, int offset) {
        long modificationBefore = program.getModificationNumber();
        AddressSet mapped = new AddressSet();
        for (MemoryBlock block : orderedBlocks(program.getMemory())) {
            mapped.add(block.getStart(), block.getEnd());
        }

        Listing listing = program.getListing();
        SymbolTable symbolTable = program.getSymbolTable();
        List<StaleCommentName> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (CommentType type : CommentType.values()) {
            String kind = type.name().toLowerCase(Locale.ROOT);
            AddressIterator addresses =
                listing.getCommentAddressIterator(type, mapped, true);
            while (addresses != null && addresses.hasNext()) {
                Address commentAddress = addresses.next();
                if (commentAddress == null) continue;
                String text = listing.getComment(type, commentAddress);
                for (GeneratedSymbolNames.CommentNameMention mention
                        : GeneratedSymbolNames.findCommentNameMentions(text)) {
                    Address target = dynamicNameResolver.resolve(
                        program.getAddressFactory(), mention.name());
                    if (target == null) continue;
                    Symbol[] current = symbolTable.getSymbols(target);
                    boolean exactNameExists = false;
                    boolean meaningfulNameExists = false;
                    List<Symbol> currentNamed = new ArrayList<>();
                    for (Symbol symbol : current) {
                        if (symbol == null || symbol.getName() == null) continue;
                        currentNamed.add(symbol);
                        if (mention.name().equals(symbol.getName())) {
                            exactNameExists = true;
                        }
                        if (!GeneratedSymbolNames.isGenerated(symbol.getName())
                                && !GeneratedSymbolNames.isCommentAddressName(
                                    symbol.getName())) {
                            meaningfulNameExists = true;
                        }
                    }
                    if (exactNameExists || !meaningfulNameExists) continue;

                    Symbol primary = currentNamed.stream()
                        .filter(Symbol::isPrimary)
                        .findFirst()
                        .orElse(currentNamed.get(0));
                    List<String> names = new ArrayList<>();
                    names.add(primary.getName());
                    names.addAll(currentNamed.stream()
                        .map(Symbol::getName)
                        .filter(name -> !primary.getName().equals(name))
                        .distinct()
                        .sorted()
                        .toList());
                    String key = commentAddress.toString(true) + "\n"
                        + kind + "\n" + mention.name();
                    if (!seen.add(key)) continue;
                    findings.add(new StaleCommentName(
                        commentAddress, kind, mention.name(), target,
                        primary.getName(), names,
                        excerptAround(text, mention.start(), mention.end())));
                }
            }
        }

        findings.sort(Comparator
            .comparing((StaleCommentName finding) ->
                finding.commentAddress().getAddressSpace().getName())
            .thenComparing(finding ->
                finding.commentAddress().getOffsetAsBigInteger())
            .thenComparingInt(finding ->
                MARKER_KIND_ORDER.indexOf(finding.commentKind()))
            .thenComparing(StaleCommentName::staleName));

        int from = Math.min(offset, findings.size());
        int to = (int) Math.min((long) from + limit, findings.size());
        List<Map<String, Object>> items = new ArrayList<>();
        for (StaleCommentName finding : findings.subList(from, to)) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("comment_address", finding.commentAddress().toString(true));
            row.put("comment_kind", finding.commentKind());
            row.put("stale_name", finding.staleName());
            row.put("target_address", finding.targetAddress().toString(true));
            row.put("current_primary_name", finding.currentPrimaryName());
            row.put("current_names", finding.currentNames());
            row.put("comment_excerpt", finding.commentExcerpt());
            items.add(row);
        }

        if (program.getModificationNumber() != modificationBefore) {
            return Response.err("Program changed while auditing stale comment names; retry.");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("program", program.getName());
        result.put("program_modification_number", modificationBefore);
        result.put("items", items);
        result.put("all_count", (long) findings.size());
        result.put("offset", (long) offset);
        result.put("limit", (long) limit);
        result.put("returned", (long) items.size());
        result.put("has_more", (long) offset + items.size() < findings.size());
        return Response.text(JsonHelper.toJson(result));
    }

    /**
     * One undefined stretch, closed at a block or initialized-range boundary.
     *
     * <p>The containing block's bounds travel with the run: neighbour lookups must not
     * walk out of the block, and re-deriving it from the address later would be both
     * redundant and a second chance to get the boundary wrong.</p>
     */
    private record Run(
        String blockName, Address blockStart, Address blockEnd,
        Address start, Address end, long length) {
    }

    /** Per-space byte accounting. */
    private static final class SpaceTotals {
        private final String name;
        private final boolean overlay;
        private long blocks;
        private long total;
        private long instruction;
        private long data;
        private long undefined;

        SpaceTotals(String name, boolean overlay) {
            this.name = name;
            this.overlay = overlay;
        }
    }

    private static Response collect(Program program, Request request) {
        // Pinned before any model read; checked again at the end. The read spans
        // several passes, and a torn aggregate would mix two program states.
        long modificationBefore = program.getModificationNumber();

        Memory memory = program.getMemory();
        Listing listing = program.getListing();
        // Not MemoryBlock.isInitialized(): that is false for byte- and bit-mapped blocks
        // whose underlying bytes are initialized, and those bytes are real coverage.
        AddressSetView initialized = memory.getAllInitializedAddressSet();

        List<MemoryBlock> blocks = orderedBlocks(memory);
        Map<String, SpaceTotals> spaces = new LinkedHashMap<>();
        List<Map<String, Object>> uninitializedRanges = new ArrayList<>();
        List<Run> runs = new ArrayList<>();

        for (MemoryBlock block : blocks) {
            Address blockStart = block.getStart();
            Address blockEnd = block.getEnd();
            String spaceName = blockStart.getAddressSpace().getName();
            SpaceTotals totals = spaces.computeIfAbsent(spaceName, name ->
                new SpaceTotals(name, block.isOverlay()));
            totals.blocks++;

            AddressSet blockSet = new AddressSet(blockStart, blockEnd);
            AddressSet usable = blockSet.intersect(initialized);
            AddressSet holes = blockSet.subtract(usable);
            for (AddressRange hole : holes) {
                Map<String, Object> record = new LinkedHashMap<>();
                record.put("block", block.getName());
                record.put("start", hole.getMinAddress().toString(true));
                record.put("end", hole.getMaxAddress().toString(true));
                record.put("length", length(hole.getMinAddress(), hole.getMaxAddress()));
                uninitializedRanges.add(record);
            }

            // One pass per initialized run inside this block. Intersecting per block is
            // what keeps two abutting blocks' runs separate: their initialized extents
            // coalesce inside an AddressSet, and a merged run would cross the seam.
            for (AddressRange range : usable) {
                classifyRange(listing, block, range, totals, runs);
            }
        }

        List<Map<String, Object>> spaceRows = new ArrayList<>();
        for (SpaceTotals totals : spaces.values().stream()
                .sorted(Comparator.comparing(candidate -> candidate.name)).toList()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("space", totals.name);
            row.put("blocks", totals.blocks);
            row.put("total", totals.total);
            if (totals.overlay) {
                // Overlay spaces get their own row: on a banked or overlaid target a
                // blended percentage is meaningless.
                row.put("overlay", true);
            }
            row.put("instruction", totals.instruction);
            row.put("data", totals.data);
            row.put("undefined", totals.undefined);
            row.put("undefined_pct", totals.total == 0 ? 0.0
                : Math.round(totals.undefined * 10_000.0 / totals.total) / 100.0);
            spaceRows.add(row);
        }
        uninitializedRanges.sort(Comparator
            .comparing((Map<String, Object> record) -> spaceOf((String) record.get("start")))
            .thenComparing(record -> (String) record.get("start")));

        // Ordering is total because every collection here is paged or sampled:
        // length descending, then space name, then address.
        runs.sort(Comparator
            .comparingLong((Run run) -> run.length()).reversed()
            .thenComparing(run -> run.start().getAddressSpace().getName())
            .thenComparing(run -> run.start().getOffsetAsBigInteger()));

        long belowMinCount = 0;
        long belowMinBytes = 0;
        List<Run> eligible = new ArrayList<>();
        for (Run run : runs) {
            if (run.length() < request.minRunLength()) {
                belowMinCount++;
                belowMinBytes += run.length();
            } else {
                eligible.add(run);
            }
        }
        int runFrom = Math.min(request.offset(), eligible.size());
        int runTo = (int) Math.min((long) runFrom + request.limit(), eligible.size());
        List<Map<String, Object>> runRows = new ArrayList<>();
        for (Run run : eligible.subList(runFrom, runTo)) {
            runRows.add(describeRun(program, run));
        }

        Map<String, Object> belowMin = new LinkedHashMap<>();
        belowMin.put("count", belowMinCount);
        belowMin.put("bytes", belowMinBytes);
        Map<String, Object> runsEnvelope = new LinkedHashMap<>();
        runsEnvelope.put("items", runRows);
        runsEnvelope.put("all_count", (long) runs.size());
        runsEnvelope.put("eligible_count", (long) eligible.size());
        runsEnvelope.put("below_min", belowMin);
        runsEnvelope.put("offset", (long) request.offset());
        runsEnvelope.put("limit", (long) request.limit());
        runsEnvelope.put("returned", (long) runRows.size());
        runsEnvelope.put("has_more",
            (long) request.offset() + runRows.size() < eligible.size());

        Backlog backlog = collectBacklog(program, blocks, request);

        if (program.getModificationNumber() != modificationBefore) {
            return Response.err("Program changed while analyzing coverage; the numbers "
                + "would mix two program states. Retry.");
        }

        Map<String, Object> memoryCoverage = new LinkedHashMap<>();
        memoryCoverage.put("spaces", spaceRows);
        memoryCoverage.put("uninitialized_ranges", uninitializedRanges);
        memoryCoverage.put("undefined_runs", runsEnvelope);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("program", program.getName());
        result.put("program_modification_number", modificationBefore);
        result.put("memory_coverage", memoryCoverage);
        result.put("annotation_backlog", backlog.asMap());
        // Nulls are contractual here: preceding_label / following_label are explicitly
        // null at a block edge, and an omitted key would read as "not computed".
        return Response.text(JsonHelper.toJsonWithNulls(result));
    }

    /**
     * Classify one initialized range, accumulating byte counts and undefined runs.
     *
     * <p>Deliberately NOT {@code listing.getCodeUnits(...)}: Ghidra synthesizes one
     * default undefined unit per uncovered address, making that walk proportional to
     * every undefined byte in the program. The stored units come from
     * {@code getInstructions} and {@code getDefinedData}, and the gaps between them are
     * derived arithmetically — the pattern {@code ListingRangeService.RangeIndex} uses.</p>
     */
    private static void classifyRange(
            Listing listing,
            MemoryBlock block,
            AddressRange range,
            SpaceTotals totals,
            List<Run> runs) {
        Address rangeStart = range.getMinAddress();
        Address rangeEnd = range.getMaxAddress();
        totals.total += length(rangeStart, rangeEnd);

        AddressSet set = new AddressSet(rangeStart, rangeEnd);
        ListingRangeService.Peekable<Instruction> instructions =
            new ListingRangeService.Peekable<>(listing.getInstructions(set, true));
        ListingRangeService.Peekable<Data> definedData =
            new ListingRangeService.Peekable<>(listing.getDefinedData(set, true));

        Address cursor = rangeStart;
        Address runStart = null;
        Address runEnd = null;

        while (cursor != null && cursor.compareTo(rangeEnd) <= 0) {
            discardBefore(instructions, definedData, cursor);
            Instruction instruction = instructions.peek();
            Data data = definedData.peek();
            Address instructionAt = instruction == null ? null : instruction.getMinAddress();
            Address dataAt = data == null ? null : data.getMinAddress();
            Address nextUnitAt = earlier(instructionAt, dataAt);

            if (nextUnitAt != null && nextUnitAt.equals(cursor)) {
                boolean isInstruction = cursor.equals(instructionAt);
                Address unitEnd = isInstruction
                    ? instruction.getMaxAddress() : data.getMaxAddress();
                if (unitEnd.compareTo(rangeEnd) > 0) unitEnd = rangeEnd;
                long bytes = length(cursor, unitEnd);
                if (isInstruction) {
                    instructions.take();
                    totals.instruction += bytes;
                } else {
                    definedData.take();
                    DataType type = data.getDataType();
                    // Undefined.isUndefined, never Data.isDefined(): the latter returns
                    // true for an explicitly applied undefined1..8 and false only for
                    // DefaultDataType, so it would classify exactly the bytes this
                    // endpoint exists to surface as "data".
                    if (Undefined.isUndefined(type)) {
                        totals.undefined += bytes;
                        if (runStart == null) runStart = cursor;
                        runEnd = unitEnd;
                        cursor = next(unitEnd);
                        continue;
                    }
                    totals.data += bytes;
                }
                if (runStart != null) {
                    runs.add(run(block, runStart, runEnd));
                    runStart = null;
                    runEnd = null;
                }
                cursor = next(unitEnd);
                continue;
            }

            // A gap: every address up to the next stored unit, or to the range end.
            Address gapEnd = rangeEnd;
            if (nextUnitAt != null && nextUnitAt.compareTo(rangeEnd) <= 0) {
                gapEnd = nextUnitAt.previous();
            }
            totals.undefined += length(cursor, gapEnd);
            if (runStart == null) runStart = cursor;
            runEnd = gapEnd;
            cursor = next(gapEnd);
        }

        // The range end is both a block boundary and an initialized-range boundary, and
        // a run must close at either.
        if (runStart != null) {
            runs.add(run(block, runStart, runEnd));
        }
    }

    private static Run run(MemoryBlock block, Address start, Address end) {
        return new Run(block.getName(), block.getStart(), block.getEnd(),
            start, end, length(start, end));
    }

    private static void discardBefore(
            ListingRangeService.Peekable<Instruction> instructions,
            ListingRangeService.Peekable<Data> definedData,
            Address cursor) {
        while (instructions.peek() != null
                && instructions.peek().getMinAddress().compareTo(cursor) < 0) {
            instructions.take();
        }
        while (definedData.peek() != null
                && definedData.peek().getMinAddress().compareTo(cursor) < 0) {
            definedData.take();
        }
    }

    /** One run row: the run plus the context needed to decide what it is. */
    private static Map<String, Object> describeRun(Program program, Run run) {
        SymbolTable symbols = program.getSymbolTable();
        Address blockStart = run.blockStart();
        Address blockEnd = run.blockEnd();

        Map<String, Object> row = new LinkedHashMap<>();
        row.put("start", run.start().toString(true));
        row.put("end", run.end().toString(true));
        row.put("length", run.length());
        row.put("block", run.blockName());

        // Neighbours are bounded by the containing block: a label from unrelated memory
        // reads as containment, which this repository already learned the hard way on
        // get_references_into_range.
        Symbol preceding = null;
        if (blockStart != null && run.start().compareTo(blockStart) > 0) {
            preceding = first(symbols.getPrimarySymbolIterator(
                new AddressSet(blockStart, run.start().previous()), false));
        }
        Symbol following = null;
        if (blockEnd != null && run.end().compareTo(blockEnd) < 0) {
            following = first(symbols.getPrimarySymbolIterator(
                new AddressSet(run.end().next(), blockEnd), true));
        }
        row.put("preceding_label", preceding == null ? null
            : neighbour(preceding, run.start().subtract(preceding.getAddress())));
        row.put("following_label", following == null ? null
            : neighbour(following, following.getAddress().subtract(run.end())));

        // Inclusive of the first and last byte, so a label at either end is disclosed
        // rather than falling between "inside the run" and the outside neighbours.
        long inRunCount = 0;
        List<Map<String, Object>> samples = new ArrayList<>();
        SymbolIterator inRun = symbols.getPrimarySymbolIterator(
            new AddressSet(run.start(), run.end()), true);
        while (inRun != null && inRun.hasNext()) {
            Symbol symbol = inRun.next();
            if (symbol == null || symbol.getAddress() == null) continue;
            inRunCount++;
            if (samples.size() < MAX_SAMPLES) {
                Map<String, Object> sample = new LinkedHashMap<>();
                sample.put("address", symbol.getAddress().toString(true));
                sample.put("name", symbol.getName());
                samples.add(sample);
            }
        }
        Map<String, Object> inRunLabels = new LinkedHashMap<>();
        inRunLabels.put("count", inRunCount);
        inRunLabels.put("samples", samples);
        row.put("primary_labels_in_run", inRunLabels);

        ReferenceManager referenceManager = program.getReferenceManager();
        long incoming = 0;
        AddressIterator destinations = referenceManager.getReferenceDestinationIterator(
            new AddressSet(run.start(), run.end()), true);
        while (destinations != null && destinations.hasNext()) {
            Address destination = destinations.next();
            if (destination == null) continue;
            incoming += referenceManager.getReferenceCountTo(destination);
        }
        row.put("incoming_reference_count", incoming);
        return row;
    }

    private static Map<String, Object> neighbour(Symbol symbol, long distance) {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("address", symbol.getAddress().toString(true));
        record.put("name", symbol.getName());
        record.put("distance", distance);
        return record;
    }

    // ------------------------------------------------------------- backlog

    /** The convention-based half of the report. */
    private record Backlog(
        Map<String, Long> totals,
        Map<String, List<String>> samples,
        List<Map<String, Object>> markerItems,
        long markerAllCount,
        int markerOffset,
        int markerLimit) {

        Map<String, Object> asMap() {
            Map<String, Object> generic = new LinkedHashMap<>();
            generic.put("totals", totals);
            generic.put("samples", samples);
            Map<String, Object> markers = new LinkedHashMap<>();
            markers.put("items", markerItems);
            markers.put("all_count", markerAllCount);
            markers.put("offset", (long) markerOffset);
            markers.put("limit", (long) markerLimit);
            markers.put("returned", (long) markerItems.size());
            markers.put("has_more", (long) markerOffset + markerItems.size() < markerAllCount);
            Map<String, Object> backlog = new LinkedHashMap<>();
            backlog.put("generic_symbols", generic);
            backlog.put("unknown_markers", markers);
            return backlog;
        }
    }

    /** One marker row before ordering: a label or a comment carrying the prefix. */
    private record Marker(
        Address address, String kind, String text, String namespace, String name) {
    }

    private static Backlog collectBacklog(
            Program program, List<MemoryBlock> blocks, Request request) {
        Map<String, Long> totals = new LinkedHashMap<>();
        Map<String, List<String>> samples = new LinkedHashMap<>();
        for (String prefix : request.genericPrefixes()) {
            totals.put(prefix, 0L);
        }
        List<Marker> markers = new ArrayList<>();

        // One symbol pass serves both the generic tally and the marker labels.
        // Dynamic symbols are included: a DAT_ label Ghidra generated for a referenced
        // address is exactly the backlog this field is about, and it is what the
        // listing shows.
        SymbolIterator allSymbols = program.getSymbolTable().getAllSymbols(true);
        while (allSymbols != null && allSymbols.hasNext()) {
            Symbol symbol = allSymbols.next();
            if (symbol == null || symbol.getAddress() == null) continue;
            String name = symbol.getName();
            if (name == null) continue;
            for (String prefix : request.genericPrefixes()) {
                if (!name.startsWith(prefix)) continue;
                totals.merge(prefix, 1L, Long::sum);
                List<String> collected =
                    samples.computeIfAbsent(prefix, ignored -> new ArrayList<>());
                if (collected.size() < MAX_SAMPLES) {
                    collected.add(symbol.getAddress().toString(true));
                }
            }
            if (name.startsWith(request.markerPrefix())) {
                markers.add(new Marker(symbol.getAddress(), "label", name,
                    namespaceOf(symbol), name));
            }
        }
        for (List<String> collected : samples.values()) {
            collected.sort(Comparator
                .comparing(CoverageService::spaceOf)
                .thenComparing(Comparator.naturalOrder()));
        }

        AddressSet mapped = new AddressSet();
        for (MemoryBlock block : blocks) {
            mapped.add(block.getStart(), block.getEnd());
        }
        Listing listing = program.getListing();
        for (CommentType type : CommentType.values()) {
            String kind = type.name().toLowerCase(Locale.ROOT);
            AddressIterator addresses =
                listing.getCommentAddressIterator(type, mapped, true);
            while (addresses != null && addresses.hasNext()) {
                Address at = addresses.next();
                if (at == null) continue;
                String text = listing.getComment(type, at);
                if (text == null || !text.contains(request.markerPrefix())) continue;
                markers.add(new Marker(at, kind, truncate(text), "", ""));
            }
        }

        // A total order: space, address, kind, then — for two labels at one address —
        // namespace and name, with text last so nothing can tie.
        markers.sort(Comparator
            .comparing((Marker marker) -> marker.address().getAddressSpace().getName())
            .thenComparing(marker -> marker.address().getOffsetAsBigInteger())
            .thenComparingInt(marker -> MARKER_KIND_ORDER.indexOf(marker.kind()))
            .thenComparing(Marker::namespace)
            .thenComparing(Marker::name)
            .thenComparing(Marker::text));

        int from = Math.min(request.markerOffset(), markers.size());
        int to = (int) Math.min((long) from + request.markerLimit(), markers.size());
        List<Map<String, Object>> items = new ArrayList<>();
        for (Marker marker : markers.subList(from, to)) {
            Map<String, Object> record = new LinkedHashMap<>();
            record.put("address", marker.address().toString(true));
            record.put("kind", marker.kind());
            record.put("text", marker.text());
            items.add(record);
        }
        return new Backlog(new TreeMap<>(totals), samples, items,
            markers.size(), request.markerOffset(), request.markerLimit());
    }

    // ------------------------------------------------------------- utilities

    private static List<MemoryBlock> orderedBlocks(Memory memory) {
        List<MemoryBlock> blocks = new ArrayList<>();
        MemoryBlock[] all = memory.getBlocks();
        if (all == null) return blocks;
        for (MemoryBlock block : all) {
            if (block == null || block.getStart() == null || block.getEnd() == null) {
                continue;
            }
            blocks.add(block);
        }
        blocks.sort(Comparator
            .comparing((MemoryBlock block) -> block.getStart().getAddressSpace().getName())
            .thenComparing(block -> block.getStart().getOffsetAsBigInteger()));
        return blocks;
    }

    private static Symbol first(SymbolIterator iterator) {
        while (iterator != null && iterator.hasNext()) {
            Symbol symbol = iterator.next();
            if (symbol != null && symbol.getAddress() != null) return symbol;
        }
        return null;
    }

    private static String namespaceOf(Symbol symbol) {
        return symbol.getParentNamespace() == null
            ? "" : symbol.getParentNamespace().getName(true);
    }

    private static String truncate(String text) {
        if (text.length() <= MARKER_TEXT_CAP) return text;
        int prefixEnd = MARKER_TEXT_CAP - MARKER_TEXT_SUFFIX.length();
        if (prefixEnd > 0
                && Character.isHighSurrogate(text.charAt(prefixEnd - 1))
                && Character.isLowSurrogate(text.charAt(prefixEnd))) {
            prefixEnd--;
        }
        return text.substring(0, prefixEnd) + MARKER_TEXT_SUFFIX;
    }

    private static String excerptAround(String text, int mentionStart, int mentionEnd) {
        int totalCodePoints = text.codePointCount(0, text.length());
        if (totalCodePoints <= STALE_COMMENT_EXCERPT_CODE_POINTS) return text;

        int mentionStartCodePoint = text.codePointCount(0, mentionStart);
        int mentionEndCodePoint = text.codePointCount(0, mentionEnd);
        int mentionLength = mentionEndCodePoint - mentionStartCodePoint;
        int leftContext = Math.max(
            0, (STALE_COMMENT_EXCERPT_CODE_POINTS - mentionLength) / 2);
        int excerptStartCodePoint = Math.max(
            0, mentionStartCodePoint - leftContext);
        excerptStartCodePoint = Math.min(
            excerptStartCodePoint,
            totalCodePoints - STALE_COMMENT_EXCERPT_CODE_POINTS);
        int excerptEndCodePoint =
            excerptStartCodePoint + STALE_COMMENT_EXCERPT_CODE_POINTS;
        int excerptStart = text.offsetByCodePoints(0, excerptStartCodePoint);
        int excerptEnd = text.offsetByCodePoints(0, excerptEndCodePoint);
        return (excerptStartCodePoint > 0 ? MARKER_TEXT_SUFFIX : "")
            + text.substring(excerptStart, excerptEnd)
            + (excerptEndCodePoint < totalCodePoints ? MARKER_TEXT_SUFFIX : "");
    }

    /** The space name of a rendered {@code SPACE:offset} address. */
    private static String spaceOf(String rendered) {
        int colon = rendered.lastIndexOf(':');
        return colon < 0 ? "" : rendered.substring(0, colon);
    }

    private static long length(Address start, Address end) {
        return end.subtract(start) + 1;
    }

    private static Address next(Address address) {
        try {
            return address.next();
        } catch (RuntimeException exception) {
            return null;
        }
    }

    private static Address earlier(Address left, Address right) {
        if (left == null) return right;
        if (right == null) return left;
        return left.compareTo(right) <= 0 ? left : right;
    }
}
