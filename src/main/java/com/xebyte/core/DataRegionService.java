package com.xebyte.core;

import java.math.BigDecimal;
import java.util.ArrayList;
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
    static final String REGIONS_SCHEMA =
        "{\"type\":\"array\",\"minItems\":1,\"maxItems\":1024,"
        + "\"items\":{\"oneOf\":["
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
        + "\"count\":{\"type\":\"integer\",\"minimum\":1},"
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
        + "\"count\",\"layout\",\"target_space\"]}]}}";

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
                description = "Native JSON array of 1..1024 flat region records")
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
                    () -> core.plan(program, requests));
                return Response.ok(result(plan, false));
            }
            return threading.executeWrite(
                program, "Apply data regions", () -> {
                    DataRegionCore.Plan plan = core.plan(program, requests);
                    monitor.checkCancelled();
                    core.apply(program, plan, monitor);
                    return Response.ok(result(plan, true));
                });
        }
        catch (Exception error) {
            String message = error.getMessage() == null
                ? error.toString() : error.getMessage();
            return Response.err(
                "Failed to apply data regions: " + message);
        }
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
        Long stride = optionalExactLong(map, "stride");
        if (stride != null && stride <= 0) {
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
        int count = Math.toIntExact(requiredExactLong(map, "count"));
        if (count <= 0) {
            throw new IllegalArgumentException("count must be positive");
        }
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
        Long baseValue = optionalExactLong(map, "target_base");
        long base = baseValue == null ? 0 : baseValue;
        if (base < 0) {
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

    private static JsonObject result(
            DataRegionCore.Plan plan, boolean committed) {
        JsonObject result = new JsonObject();
        result.addProperty("committed", committed);
        JsonArray regions = new JsonArray();
        JsonArray createdData = new JsonArray();
        JsonArray references = new JsonArray();
        JsonArray symbols = new JsonArray();
        for (DataRegionCore.RegionPlan region : plan.regions()) {
            JsonObject item = new JsonObject();
            item.addProperty("kind", region.kind());
            item.addProperty("placement", region.placement().toString());
            item.addProperty(
                "element_count",
                "contiguous".equals(region.kind())
                    ? region.elementAddresses().size()
                    : region.splitFirst().size());
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
            regions.add(item);
            List<Address> definitions = new ArrayList<>(
                region.elementAddresses());
            if (!region.splitFirst().isEmpty()) {
                definitions.add(region.splitFirst().get(0));
                definitions.add(region.splitSecond().get(0));
            }
            for (Address address : definitions) {
                JsonObject data = new JsonObject();
                data.addProperty("address", address.toString());
                data.addProperty(
                    "type_name", region.dataType().getPathName());
                data.addProperty("length", region.dataLength());
                data.addProperty(
                    "action",
                    region.existingData().contains(address)
                        ? "unchanged" : "create");
                createdData.add(data);
            }
            if (region.metadata() != null
                    && region.metadata().name() != null) {
                JsonObject symbol = new JsonObject();
                symbol.addProperty("address", region.placement().toString());
                symbol.addProperty("name", region.metadata().name());
                symbol.addProperty(
                    "namespace", region.metadata().namespace());
                symbol.addProperty("kind", "region");
                symbols.add(symbol);
            }
            DataRegionCore.PointerOptions options =
                region.pointerOptions();
            for (DataRegionCore.PointerPlan pointer : region.pointers()) {
                if (!pointer.valid()) {
                    continue;
                }
                if (options != null && options.createReferences()) {
                    for (Address source : pointer.sources()) {
                        JsonObject reference = new JsonObject();
                        reference.addProperty(
                            "from", source.toString());
                        reference.addProperty(
                            "to", pointer.target().toString());
                        references.add(reference);
                    }
                }
                if (pointer.labelName() != null) {
                    JsonObject symbol = new JsonObject();
                    symbol.addProperty(
                        "address", pointer.target().toString());
                    symbol.addProperty("name", pointer.labelName());
                    symbol.addProperty(
                        "namespace",
                        options == null
                            ? null : options.labelNamespace());
                    symbol.addProperty("kind", "pointer_target");
                    symbols.add(symbol);
                }
            }
        }
        result.add("regions", regions);
        result.add("created_data", createdData);
        result.add("symbols", symbols);
        result.add("references", references);
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
            result.add("clear_plan", clear);
        }
        return result;
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
}
