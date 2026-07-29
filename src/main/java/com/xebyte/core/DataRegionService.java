package com.xebyte.core;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** Atomic range data typing and generic pointer-table materialization. */
@McpToolGroup(
    value = "data",
    description = "Define fixed data ranges and generic pointer tables")
public final class DataRegionService {
    private static final long MAX_SPLIT_PARTNER_WORK = 1_000_000;
    private static final int MAX_DISCOVERY_LIMIT = 1_000;
    static final String REGION_ITEM_SCHEMA =
        "{\"oneOf\":["
        + "{\"type\":\"object\",\"additionalProperties\":false,"
        + "\"properties\":{"
        + "\"kind\":{\"const\":\"contiguous\"},"
        + "\"start\":{\"type\":\"string\"},\"end\":{\"type\":\"string\"},"
        + "\"type_name\":{\"type\":\"string\"},"
        + "\"stride\":{\"type\":\"integer\",\"minimum\":1},"
        + "\"allow_trailing_bytes\":{\"type\":\"boolean\",\"default\":false},"
        + "\"clear_conflicts\":{\"type\":\"boolean\",\"default\":false},"
        + "\"name\":{\"type\":\"string\"},\"namespace\":{\"type\":\"string\"},"
        + "\"plate_comment\":{\"type\":\"string\"},"
        + "\"pointers\":{\"type\":\"object\",\"additionalProperties\":false,"
        + "\"properties\":{"
        + "\"layout\":{\"enum\":[\"little_endian_words\",\"big_endian_words\"]},"
        + "\"target_space\":{\"type\":\"string\"},"
        + "\"target_base\":{\"type\":\"integer\",\"minimum\":0,\"default\":0},"
        + "\"create_references\":{\"type\":\"boolean\",\"default\":false},"
        + "\"validate_targets\":{\"type\":\"boolean\",\"default\":false},"
        + "\"target_label_prefix\":{\"type\":\"string\"},"
        + "\"label_namespace\":{\"type\":\"string\"}},"
        + "\"required\":[\"layout\",\"target_space\"]}},"
        + "\"required\":[\"kind\",\"start\",\"end\",\"type_name\"]},"
        + "{\"type\":\"object\",\"additionalProperties\":false,"
        + "\"properties\":{"
        + "\"kind\":{\"const\":\"split_pointer_table\"},"
        + "\"first_start\":{\"type\":\"string\"},"
        + "\"second_start\":{\"type\":\"string\"},"
        + "\"count\":{\"type\":\"integer\",\"minimum\":1,"
        + "\"maximum\":1000000},"
        + "\"layout\":{\"enum\":[\"split_low_high\",\"split_high_low\"]},"
        + "\"target_space\":{\"type\":\"string\"},"
        + "\"target_base\":{\"type\":\"integer\",\"minimum\":0,\"default\":0},"
        + "\"create_references\":{\"type\":\"boolean\",\"default\":false},"
        + "\"validate_targets\":{\"type\":\"boolean\",\"default\":false},"
        + "\"target_label_prefix\":{\"type\":\"string\"},"
        + "\"label_namespace\":{\"type\":\"string\"},"
        + "\"clear_conflicts\":{\"type\":\"boolean\",\"default\":false},"
        + "\"name\":{\"type\":\"string\"},\"namespace\":{\"type\":\"string\"},"
        + "\"plate_comment\":{\"type\":\"string\"}},"
        + "\"required\":[\"kind\",\"first_start\",\"second_start\","
        + "\"count\",\"layout\",\"target_space\"]}]}";
    static final String REGIONS_SCHEMA =
        "{\"type\":\"array\",\"minItems\":1,\"maxItems\":1024,"
        + "\"items\":" + REGION_ITEM_SCHEMA + "}";

    private static final Set<String> CONTIGUOUS_FIELDS = Set.of(
        "kind", "start", "end", "type_name", "stride",
        "allow_trailing_bytes", "clear_conflicts", "name",
        "namespace", "plate_comment", "pointers");
    private static final Set<String> SPLIT_FIELDS = Set.of(
        "kind", "first_start", "second_start", "count", "layout",
        "target_space", "target_base", "create_references",
        "validate_targets", "target_label_prefix", "label_namespace",
        "clear_conflicts", "name", "namespace", "plate_comment");
    private static final Set<String> POINTER_FIELDS = Set.of(
        "layout", "target_space", "target_base", "create_references",
        "validate_targets", "target_label_prefix", "label_namespace");

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threading;
    private final DataRegionCore core;
    private final TaskMonitor monitor;

    public DataRegionService(
            ProgramProvider programProvider, ThreadingStrategy threading) {
        this(programProvider, threading, new DataRegionCore(),
            TaskMonitor.DUMMY);
    }

    DataRegionService(
            ProgramProvider programProvider, ThreadingStrategy threading,
            DataRegionCore core, TaskMonitor monitor) {
        this.programProvider = Objects.requireNonNull(programProvider);
        this.threading = Objects.requireNonNull(threading);
        this.core = Objects.requireNonNull(core);
        this.monitor = Objects.requireNonNull(monitor);
    }

    @McpTool(
        path = "/apply_data_regions",
        method = "POST",
        description =
            "Atomically define fixed data ranges and generic pointer tables",
        category = "data",
        supportsSyntheticDryRun = false)
    public Response applyDataRegions(
            @Param(
                value = "regions",
                source = ParamSource.BODY,
                schemaFragment = REGIONS_SCHEMA,
                description = "Native JSON array of 1..1024 flat region records; "
                    + "at most 1000000 logical elements across the request")
                Object regionsValue,
            @Param(
                value = "dry_run",
                source = ParamSource.BODY,
                defaultValue = "true",
                strictBoolean = true)
                boolean dryRun,
            @Param(
                value = "program",
                defaultValue = "",
                description = "Target program name")
                String programName) {
        try {
            List<DataRegionCore.RegionRequest> requests =
                parseRegions(regionsValue);
            Program program = requireProgram(programName);
            if (dryRun) {
                DataRegionCore.Plan plan = threading.executeRead(
                    () -> core.plan(program, requests, monitor));
                return Response.ok(renderPlan(plan, false));
            }
            return threading.executeWrite(
                program, "Apply data regions", () -> {
                    DataRegionCore.Plan plan =
                        core.plan(program, requests, monitor);
                    monitor.checkCancelled();
                    core.apply(program, plan, monitor);
                    return Response.ok(renderPlan(plan, true));
                });
        }
        catch (Exception error) {
            String message = error.getMessage() == null
                ? error.toString() : error.getMessage();
            return Response.err(
                "Failed to apply data regions: " + message);
        }
    }

    @McpTool(
        path = "/find_split_pointer_partners",
        description = "Search a bounded initialized byte range for the unknown half "
            + "of a known split 16-bit pointer table. Tests both low/high and high/low "
            + "layouts under a fixed work cap. Results are numeric hypotheses and carry "
            + "false positives by construction; each includes an apply_data_regions-ready "
            + "region proposal.",
        category = "data")
    public Response findSplitPointerPartners(
            @Param(value = "first_start", paramType = "address",
                description = "Qualified start of the known first byte array.")
                String firstStartText,
            @Param(value = "count",
                description = "Known pointer count, 1..65536.") int count,
            @Param(value = "partner_start", paramType = "address",
                description = "Qualified inclusive start of the partner search range.")
                String partnerStartText,
            @Param(value = "partner_end", paramType = "address",
                description = "Qualified inclusive end of the partner search range.")
                String partnerEndText,
            @Param(value = "target_start", paramType = "address",
                description = "Qualified inclusive decoded-target start.")
                String targetStartText,
            @Param(value = "target_end", paramType = "address",
                description = "Qualified inclusive decoded-target end.")
                String targetEndText,
            @Param(value = "limit", defaultValue = "100",
                description = "Maximum proposals returned, 1..1000.") int limit,
            @Param(value = "offset", defaultValue = "0",
                description = "Zero-based offset into ordered proposals.") int offset,
            @Param(value = "program", defaultValue = "",
                description = "Target program name.") String programName) {
        try {
            if (count < 1 || count > 65_536) {
                return Response.err("count must be in 1..65536 (got " + count + ")");
            }
            if (limit < 1 || limit > MAX_DISCOVERY_LIMIT) {
                return Response.err("limit must be in 1.." + MAX_DISCOVERY_LIMIT
                    + " (got " + limit + ")");
            }
            if (offset < 0) {
                return Response.err("offset must not be negative (got " + offset + ")");
            }
            for (String text : new String[] {
                    firstStartText, partnerStartText, partnerEndText,
                    targetStartText, targetEndText }) {
                if (text == null || !text.contains(":")) {
                    return Response.err("first, partner, and target addresses must use "
                        + "explicitly qualified <space>:<hex> forms");
                }
            }
            Program program = requireProgram(programName);
            Address firstStart = parseAddress(program, firstStartText);
            Address partnerStart = parseAddress(program, partnerStartText);
            Address partnerEnd = parseAddress(program, partnerEndText);
            Address targetStart = parseAddress(program, targetStartText);
            Address targetEnd = parseAddress(program, targetEndText);
            String partnerError = rangeError(
                partnerStart, partnerEnd, "partner");
            if (partnerError != null) return Response.err(partnerError);
            String targetError = rangeError(targetStart, targetEnd, "target");
            if (targetError != null) return Response.err(targetError);
            if (targetEnd.getOffsetAsBigInteger().bitLength() > 16) {
                return Response.err("target range exceeds the 16-bit pointer width");
            }
            Address firstEnd;
            try {
                firstEnd = firstStart.addNoWrap(count - 1L);
            }
            catch (Exception error) {
                return Response.err("known first half exceeds its address space");
            }
            BigInteger searchBytes = partnerEnd.getOffsetAsBigInteger()
                .subtract(partnerStart.getOffsetAsBigInteger()).add(BigInteger.ONE);
            BigInteger candidateCount = searchBytes
                .subtract(BigInteger.valueOf(count)).add(BigInteger.ONE);
            if (candidateCount.signum() <= 0) {
                return Response.err("partner search range must contain at least count bytes");
            }
            BigInteger work = candidateCount.multiply(BigInteger.valueOf(count))
                .multiply(BigInteger.TWO);
            if (work.compareTo(BigInteger.valueOf(MAX_SPLIT_PARTNER_WORK)) > 0) {
                return Response.err("split pointer partner search requires " + work
                    + " byte-pair decodes; fixed cap is " + MAX_SPLIT_PARTNER_WORK
                    + ". Narrow the partner range or reduce count.");
            }
            return threading.executeRead(() -> searchSplitPartners(
                program, firstStart, firstEnd, count, partnerStart, partnerEnd,
                targetStart, targetEnd, limit, offset));
        }
        catch (Exception error) {
            String message = error.getMessage() == null
                ? error.toString() : error.getMessage();
            return Response.err("Failed to find split pointer partners: " + message);
        }
    }

    private static Address parseAddress(Program program, String text) {
        Address address = ServiceUtils.parseAddress(program, text);
        if (address == null) {
            throw new IllegalArgumentException(ServiceUtils.getLastParseError());
        }
        return address;
    }

    private static String rangeError(Address start, Address end, String label) {
        if (!start.getAddressSpace().equals(end.getAddressSpace())) {
            return label + " start and end must use the same address space";
        }
        if (start.compareTo(end) > 0) {
            return label + " start must not be greater than end";
        }
        return null;
    }

    private record SplitPartnerProposal(
        Address secondStart, String layout, long minimumTarget,
        long maximumTarget, int uniqueTargetCount, List<String> targetSample) {
    }

    private static Response searchSplitPartners(
            Program program, Address firstStart, Address firstEnd, int count,
            Address partnerStart, Address partnerEnd,
            Address targetStart, Address targetEnd, int limit, int offset)
            throws Exception {
        long modificationBefore = program.getModificationNumber();
        var initialized = program.getMemory().getAllInitializedAddressSet();
        if (!initialized.contains(firstStart, firstEnd)) {
            return Response.err("known first half is not wholly initialized");
        }
        if (!initialized.contains(partnerStart, partnerEnd)) {
            return Response.err("partner search range is not wholly initialized");
        }
        if (!initialized.contains(targetStart, targetEnd)) {
            return Response.err("target range is not wholly initialized");
        }
        byte[] first = new byte[count];
        if (program.getMemory().getBytes(firstStart, first) != count) {
            return Response.err("could not read the complete known first half");
        }
        long candidates = partnerEnd.subtract(partnerStart) - count + 2;
        List<SplitPartnerProposal> page = new ArrayList<>(limit);
        long totalMatched = 0;
        byte[] second = new byte[count];
        for (long candidate = 0; candidate < candidates; candidate++) {
            Address secondStart = partnerStart.addNoWrap(candidate);
            Address secondEnd = secondStart.addNoWrap(count - 1L);
            if (rangesOverlap(firstStart, firstEnd, secondStart, secondEnd)) {
                continue;
            }
            if (program.getMemory().getBytes(secondStart, second) != count) {
                return Response.err("could not read partner candidate at "
                    + secondStart.toString(true));
            }
            for (String layout
                    : List.of("split_low_high", "split_high_low")) {
                SplitPartnerProposal proposal = splitProposal(
                    first, second, secondStart, layout,
                    targetStart, targetEnd);
                if (proposal == null) {
                    continue;
                }
                if (totalMatched >= offset && page.size() < limit) {
                    page.add(proposal);
                }
                totalMatched++;
            }
        }
        List<Map<String, Object>> rows = new ArrayList<>(page.size());
        for (SplitPartnerProposal proposal : page) {
            rows.add(renderSplitProposal(
                firstStart, count, targetStart, proposal));
        }
        if (program.getModificationNumber() != modificationBefore) {
            return Response.err("Program changed while searching split pointer partners; "
                + "retry the request.");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("scope", "numeric_split_pointer_partner_hypotheses");
        result.put("false_positives_possible", true);
        result.put("work_cap", MAX_SPLIT_PARTNER_WORK);
        result.put("proposals", rows);
        result.put("total_matched", totalMatched);
        result.put("returned", rows.size());
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("has_more", totalMatched > (long) offset + rows.size());
        result.put("program_modification_number", modificationBefore);
        return Response.ok(result);
    }

    private static boolean rangesOverlap(
            Address leftStart, Address leftEnd,
            Address rightStart, Address rightEnd) {
        return leftStart.getAddressSpace().equals(rightStart.getAddressSpace())
            && leftStart.compareTo(rightEnd) <= 0
            && rightStart.compareTo(leftEnd) <= 0;
    }

    private static SplitPartnerProposal splitProposal(
            byte[] first, byte[] second,
            Address secondStart, String layout,
            Address targetStart, Address targetEnd) {
        long minimum = Long.MAX_VALUE;
        long maximum = Long.MIN_VALUE;
        Set<Long> unique = new HashSet<>();
        List<String> sample = new ArrayList<>();
        for (int index = 0; index < first.length; index++) {
            long decoded = DataRegionCore.decodeWord(
                first[index] & 0xff, second[index] & 0xff, layout);
            if (decoded < targetStart.getOffset()
                    || decoded > targetEnd.getOffset()) {
                return null;
            }
            minimum = Math.min(minimum, decoded);
            maximum = Math.max(maximum, decoded);
            unique.add(decoded);
            if (sample.size() < 16) {
                sample.add(targetStart.getAddressSpace()
                    .getAddress(decoded).toString(true));
            }
        }
        return new SplitPartnerProposal(
            secondStart, layout, minimum, maximum,
            unique.size(), List.copyOf(sample));
    }

    private static Map<String, Object> renderSplitProposal(
            Address firstStart, int count, Address targetStart,
            SplitPartnerProposal proposal) {
        Map<String, Object> region = new LinkedHashMap<>();
        region.put("kind", "split_pointer_table");
        region.put("first_start", firstStart.toString(true));
        region.put("second_start", proposal.secondStart().toString(true));
        region.put("count", count);
        region.put("layout", proposal.layout());
        region.put("target_space", targetStart.getAddressSpace().getName());
        region.put("target_base", 0);
        region.put("create_references", false);
        region.put("validate_targets", true);
        region.put("clear_conflicts", false);

        Map<String, Object> row = new LinkedHashMap<>();
        row.put("first_start", firstStart.toString(true));
        row.put("second_start", proposal.secondStart().toString(true));
        row.put("count", count);
        row.put("layout", proposal.layout());
        row.put("target_min", targetStart.getAddressSpace()
            .getAddress(proposal.minimumTarget()).toString(true));
        row.put("target_max", targetStart.getAddressSpace()
            .getAddress(proposal.maximumTarget()).toString(true));
        row.put("unique_target_count", proposal.uniqueTargetCount());
        row.put("target_sample", proposal.targetSample());
        row.put("apply_data_regions", region);
        return row;
    }

    private Program requireProgram(String programName) {
        ServiceUtils.ProgramOrError resolution =
            ServiceUtils.getProgramOrError(programProvider, programName);
        if (resolution.hasError()) {
            throw new IllegalArgumentException(
                resolution.error().toJson());
        }
        return resolution.program();
    }

    static List<DataRegionCore.RegionRequest> parseRegions(Object value) {
        if (!(value instanceof List<?> raw)) {
            throw new IllegalArgumentException(
                "regions must be a native JSON array");
        }
        if (raw.isEmpty() || raw.size() > DataRegionCore.MAX_REGIONS) {
            throw new IllegalArgumentException(
                "regions must contain between 1 and 1024 items");
        }
        List<DataRegionCore.RegionRequest> requests = new ArrayList<>();
        for (int i = 0; i < raw.size(); i++) {
            Object item = raw.get(i);
            if (!(item instanceof Map<?, ?> untyped)) {
                throw new IllegalArgumentException(
                    "regions[" + i + "] must be an object");
            }
            Map<String, Object> map = stringMap(untyped, "regions[" + i + "]");
            String kind = requiredString(map, "kind");
            requests.add(switch (kind) {
                case "contiguous" -> parseContiguous(map);
                case "split_pointer_table" -> parseSplit(map);
                default -> throw new IllegalArgumentException(
                    "unknown region kind: " + kind);
            });
        }
        return List.copyOf(requests);
    }

    private static DataRegionCore.ContiguousRequest parseContiguous(
            Map<String, Object> map) {
        rejectUnknown(map, CONTIGUOUS_FIELDS);
        BigInteger stride = optionalExactBigInteger(map, "stride");
        if (stride != null && stride.signum() <= 0) {
            throw new IllegalArgumentException("stride must be positive");
        }
        DataRegionCore.PointerOptions pointers = null;
        Object nested = map.get("pointers");
        if (nested != null) {
            if (!(nested instanceof Map<?, ?> raw)) {
                throw new IllegalArgumentException(
                    "pointers must be an object");
            }
            Map<String, Object> pointerMap =
                stringMap(raw, "pointers");
            rejectUnknown(pointerMap, POINTER_FIELDS);
            pointers = pointerOptions(
                pointerMap, requiredString(pointerMap, "layout"));
        }
        return new DataRegionCore.ContiguousRequest(
            requiredString(map, "start"),
            requiredString(map, "end"),
            requiredString(map, "type_name"),
            stride,
            exactBoolean(map, "allow_trailing_bytes", false),
            pointers, metadata(map));
    }

    private static DataRegionCore.SplitPointerRequest parseSplit(
            Map<String, Object> map) {
        rejectUnknown(map, SPLIT_FIELDS);
        long countValue = requiredExactLong(map, "count");
        if (countValue <= 0
                || countValue > DataRegionCore.MAX_PLANNED_ELEMENTS) {
            throw new IllegalArgumentException(
                "count must be between 1 and "
                    + DataRegionCore.MAX_PLANNED_ELEMENTS);
        }
        int count = (int) countValue;
        String layout = requiredString(map, "layout");
        return new DataRegionCore.SplitPointerRequest(
            requiredString(map, "first_start"),
            requiredString(map, "second_start"),
            count, layout, pointerOptions(map, layout), metadata(map));
    }

    private static DataRegionCore.Metadata metadata(
            Map<String, Object> map) {
        return new DataRegionCore.Metadata(
            optionalString(map, "name"),
            optionalString(map, "namespace"),
            optionalString(map, "plate_comment"),
            exactBoolean(map, "clear_conflicts", false));
    }

    private static DataRegionCore.PointerOptions pointerOptions(
            Map<String, Object> map, String layout) {
        BigInteger base = optionalExactBigInteger(map, "target_base");
        if (base == null) {
            base = BigInteger.ZERO;
        }
        if (base.signum() < 0) {
            throw new IllegalArgumentException(
                "target_base must be non-negative");
        }
        return new DataRegionCore.PointerOptions(
            layout, requiredString(map, "target_space"),
            base,
            exactBoolean(map, "create_references", false),
            exactBoolean(map, "validate_targets", false),
            optionalString(map, "target_label_prefix"),
            optionalString(map, "label_namespace"));
    }

    static JsonObject renderPlan(
            DataRegionCore.Plan plan, boolean committed) {
        JsonObject result = new JsonObject();
        result.addProperty("committed", committed);
        JsonArray regions = new JsonArray();
        JsonArray createdData = new JsonArray();
        JsonArray references = new JsonArray();
        JsonArray symbols = new JsonArray();
        JsonArray comments = new JsonArray();
        for (DataRegionCore.RegionPlan region : plan.regions()) {
            regions.add(renderRegionPlan(region));
            for (DataRegionCore.DataAction action
                    : region.dataActions()) {
                JsonObject data = new JsonObject();
                data.addProperty(
                    "address", action.address().toString());
                data.addProperty(
                    "type_name", action.dataType().getPathName());
                data.addProperty("length", action.length());
                data.addProperty("action", action.action());
                createdData.add(data);
            }
            for (DataRegionCore.SymbolAction action
                    : region.symbolActions()) {
                JsonObject symbol = new JsonObject();
                addNullable(symbol, "address",
                    action.address() == null
                        ? null : action.address().toString());
                symbol.addProperty("name", action.name());
                addNullable(
                    symbol, "namespace", action.namespace());
                symbol.addProperty("kind", action.kind());
                symbol.addProperty("action", action.action());
                if (action.reason() != null) {
                    symbol.addProperty("reason", action.reason());
                }
                symbol.addProperty("primary", action.primary());
                symbols.add(symbol);
            }
            for (DataRegionCore.ReferenceAction action
                    : region.referenceActions()) {
                JsonObject reference = new JsonObject();
                reference.addProperty(
                    "from", action.from().toString());
                addNullable(
                    reference, "to",
                    action.to() == null
                        ? null : action.to().toString());
                reference.addProperty("type", "data");
                reference.addProperty("source", "user_defined");
                reference.addProperty(
                    "operand_index",
                    ghidra.program.model.symbol.Reference.MNEMONIC);
                reference.addProperty("action", action.action());
                if (action.reason() != null) {
                    reference.addProperty("reason", action.reason());
                }
                references.add(reference);
            }
            if (region.platePlan() != null) {
                JsonObject comment = new JsonObject();
                comment.addProperty(
                    "address", region.placement().toString());
                comment.addProperty("type", "plate");
                addNullable(
                    comment, "previous",
                    region.platePlan().previous());
                addNullable(
                    comment, "resulting",
                    region.platePlan().resulting());
                comment.addProperty(
                    "action",
                    region.platePlan().changed()
                        ? "create" : "unchanged");
                comments.add(comment);
            }
        }
        result.add("regions", regions);
        result.add("created_data", createdData);
        result.add("symbols", symbols);
        result.add("references", references);
        result.add("comments", comments);
        JsonArray namespaces = new JsonArray();
        for (DataRegionCore.NamespaceAction action
                : plan.namespaceActions()) {
            JsonObject namespace = new JsonObject();
            namespace.addProperty("name", action.name());
            namespace.addProperty("action", action.action());
            namespaces.add(namespace);
        }
        result.add("namespaces", namespaces);
        JsonArray conflicts = new JsonArray();
        plan.conflicts().forEach(conflicts::add);
        result.add("conflicts", conflicts);
        if (plan.clearPlan() == null) {
            result.add("clear_plan", JsonNull.INSTANCE);
        }
        else {
            JsonObject clear = new JsonObject();
            JsonArray units = new JsonArray();
            plan.clearPlan().units().forEach(unit -> {
                JsonObject entry = new JsonObject();
                entry.addProperty("start", unit.start().toString());
                entry.addProperty("end", unit.end().toString());
                entry.addProperty(
                    "kind", unit.kind().name().toLowerCase());
                units.add(entry);
            });
            clear.add("code_units", units);
            JsonArray functions = new JsonArray();
            plan.clearPlan().functions().forEach(function -> {
                JsonObject entry = new JsonObject();
                entry.addProperty(
                    "entry", function.entry().toString());
                entry.addProperty("name", function.name());
                entry.addProperty("action", "remove");
                functions.add(entry);
            });
            clear.add("functions", functions);
            JsonArray expanded = new JsonArray();
            plan.clearPlan().expanded().forEach(range -> {
                JsonObject entry = new JsonObject();
                entry.addProperty(
                    "start", range.getMinAddress().toString());
                entry.addProperty(
                    "end", range.getMaxAddress().toString());
                expanded.add(entry);
            });
            clear.add("expanded_ranges", expanded);
            JsonObject counts = new JsonObject();
            counts.addProperty(
                "instructions",
                plan.clearPlan().removalCounts().instructions());
            counts.addProperty(
                "data", plan.clearPlan().removalCounts().data());
            counts.addProperty(
                "functions",
                plan.clearPlan().removalCounts().functions());
            clear.add("removal_counts", counts);
            result.add("clear_plan", clear);
        }
        return result;
    }

    static JsonObject renderRegionPlan(
            DataRegionCore.RegionPlan region) {
        JsonObject item = new JsonObject();
        item.addProperty("kind", region.kind());
        item.addProperty("placement", region.placement().toString());
        DataRegionCore.Metadata metadata = region.metadata();
        addNullable(item, "name",
            metadata == null ? null : metadata.name());
        addNullable(item, "namespace",
            metadata == null ? null : metadata.namespace());
        addNullable(item, "plate_comment",
            metadata == null ? null : metadata.plateComment());
        item.addProperty(
            "clear_conflicts",
            metadata != null && metadata.clearConflicts());
        item.addProperty(
            "element_count",
            "contiguous".equals(region.kind())
                ? region.elementAddresses().size()
                : region.splitFirst().size());
        if (region.request()
                instanceof DataRegionCore.ContiguousRequest request) {
            item.addProperty(
                "start", region.placement().toString());
            item.addProperty(
                "end", contiguousEnd(region).toString());
            item.addProperty(
                "type_name", region.dataType().getPathName());
            item.addProperty("data_length", region.dataLength());
            item.addProperty("stride", region.stride());
            item.addProperty(
                "allow_trailing_bytes",
                request.allowTrailingBytes());
            item.add(
                "pointer_options",
                pointerOptionsJson(region.pointerOptions()));
        }
        else {
            DataRegionCore.SplitPointerRequest request =
                (DataRegionCore.SplitPointerRequest) region.request();
            item.addProperty(
                "first_start",
                region.splitFirst().get(0).toString());
            item.addProperty(
                "second_start",
                region.splitSecond().get(0).toString());
            item.addProperty("count", request.count());
            item.addProperty("layout", request.layout());
            addPointerOptionsFlat(
                item, region.pointerOptions());
        }
        JsonArray addresses = new JsonArray();
        if ("contiguous".equals(region.kind())) {
            region.elementAddresses().forEach(
                address -> addresses.add(address.toString()));
        }
        else {
            for (int i = 0; i < region.splitFirst().size(); i++) {
                JsonObject pair = new JsonObject();
                pair.addProperty(
                    "first", region.splitFirst().get(i).toString());
                pair.addProperty(
                    "second", region.splitSecond().get(i).toString());
                addresses.add(pair);
            }
        }
        item.add("element_addresses", addresses);
        if (region.trailingStart() == null) {
            item.add("trailing_range", JsonNull.INSTANCE);
        }
        else {
            JsonObject trailing = new JsonObject();
            trailing.addProperty(
                "start", region.trailingStart().toString());
            trailing.addProperty(
                "end", region.trailingEnd().toString());
            item.add("trailing_range", trailing);
        }
        JsonArray pointerResults = new JsonArray();
        for (DataRegionCore.PointerPlan pointer : region.pointers()) {
            JsonObject pointerJson = new JsonObject();
            JsonArray sources = new JsonArray();
            pointer.sources().forEach(
                address -> sources.add(address.toString()));
            pointerJson.add("sources", sources);
            pointerJson.addProperty("decoded", pointer.decoded());
            if (pointer.target() == null) {
                pointerJson.add("target", JsonNull.INSTANCE);
            }
            else {
                pointerJson.addProperty(
                    "target", pointer.target().toString());
            }
            pointerJson.addProperty("valid", pointer.valid());
            if (!pointer.valid()) {
                pointerJson.addProperty(
                    "skipped", "invalid_target");
                pointerJson.addProperty(
                    "invalid_reason", pointer.invalidReason());
            }
            pointerResults.add(pointerJson);
        }
        item.add("pointers", pointerResults);
        return item;
    }

    private static Address contiguousEnd(
            DataRegionCore.RegionPlan region) {
        if (region.trailingEnd() != null) {
            return region.trailingEnd();
        }
        if (region.elementAddresses().isEmpty()) {
            return region.placement();
        }
        Address last = region.elementAddresses()
            .get(region.elementAddresses().size() - 1);
        return last.add(region.dataLength() - 1L);
    }

    private static JsonObject pointerOptionsJson(
            DataRegionCore.PointerOptions options) {
        if (options == null) {
            return null;
        }
        JsonObject result = new JsonObject();
        addPointerOptionsFlat(result, options);
        return result;
    }

    private static void addPointerOptionsFlat(
            JsonObject target,
            DataRegionCore.PointerOptions options) {
        if (options == null) {
            return;
        }
        target.addProperty("layout", options.layout());
        addNullable(
            target, "target_space", options.targetSpace());
        target.addProperty("target_base", options.targetBase());
        target.addProperty(
            "create_references", options.createReferences());
        target.addProperty(
            "validate_targets", options.validateTargets());
        addNullable(
            target, "target_label_prefix",
            options.targetLabelPrefix());
        addNullable(
            target, "label_namespace",
            options.labelNamespace());
    }

    private static void addNullable(
            JsonObject target, String name, String value) {
        if (value == null) {
            target.add(name, JsonNull.INSTANCE);
        }
        else {
            target.addProperty(name, value);
        }
    }

    private static Map<String, Object> stringMap(
            Map<?, ?> source, String path) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IllegalArgumentException(
                    path + " keys must be strings");
            }
            result.put(key, entry.getValue());
        }
        return result;
    }

    private static void rejectUnknown(
            Map<String, Object> map, Set<String> allowed) {
        for (String key : map.keySet()) {
            if (!allowed.contains(key)) {
                throw new IllegalArgumentException(
                    "unknown field: " + key);
            }
        }
    }

    private static String requiredString(
            Map<String, Object> map, String key) {
        String value = optionalString(map, key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                key + " is required and must be a string");
        }
        return value;
    }

    private static String optionalString(
            Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String text)) {
            throw new IllegalArgumentException(
                key + " must be a string");
        }
        return text;
    }

    private static boolean exactBoolean(
            Map<String, Object> map, String key, boolean defaultValue) {
        Object value = map.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (!(value instanceof Boolean result)) {
            throw new IllegalArgumentException(
                key + " must be a JSON boolean");
        }
        return result;
    }

    private static long requiredExactLong(
            Map<String, Object> map, String key) {
        Long value = optionalExactLong(map, key);
        if (value == null) {
            throw new IllegalArgumentException(
                key + " is required and must be a JSON integer");
        }
        return value;
    }

    private static Long optionalExactLong(
            Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof Number number)) {
            throw new IllegalArgumentException(
                key + " must be a JSON integer");
        }
        try {
            return new BigDecimal(number.toString()).longValueExact();
        }
        catch (ArithmeticException | NumberFormatException error) {
            throw new IllegalArgumentException(
                key + " must be an exact 64-bit JSON integer", error);
        }
    }

    private static BigInteger optionalExactBigInteger(
            Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof Number number)) {
            throw new IllegalArgumentException(
                key + " must be a JSON integer");
        }
        try {
            return new BigDecimal(number.toString()).toBigIntegerExact();
        }
        catch (ArithmeticException | NumberFormatException error) {
            throw new IllegalArgumentException(
                key + " must be an exact JSON integer", error);
        }
    }
}
