package com.xebyte.core;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.util.task.TaskMonitor;

/** Manual function-free control-flow metadata and evidence. */
@McpToolGroup(
    value = "control_flow",
    description = "Record manual entry, flow, dispatch, and mutation facts")
public final class ControlFlowService {
    static final String ADDRESS_ARRAY_SCHEMA =
        "{\"type\":\"array\",\"maxItems\":10000,"
        + "\"items\":{\"type\":\"string\"}}";
    static final String DISPATCH_ARRAY_SCHEMA =
        "{\"type\":\"array\",\"minItems\":1,\"maxItems\":1024,"
        + "\"items\":{\"type\":\"string\"}}";
    static final String OPERAND_BYTES_SCHEMA =
        "{\"type\":\"array\",\"minItems\":1,\"maxItems\":1024,"
        + "\"items\":{\"type\":\"string\"}}";
    static final String REMOVE_REFERENCES_SCHEMA =
        "{\"type\":\"array\",\"maxItems\":10000,\"items\":{"
        + "\"type\":\"object\",\"additionalProperties\":false,"
        + "\"properties\":{\"from\":{\"type\":\"string\"},"
        + "\"to\":{\"type\":\"string\"},"
        + "\"type\":{\"enum\":[\"computed_call\",\"computed_jump\","
        + "\"call\",\"jump\",\"data\",\"write\"]},"
        + "\"operand_index\":{\"type\":\"integer\",\"minimum\":-1,"
        + "\"default\":-1}},"
        + "\"required\":[\"from\",\"to\",\"type\"]}}";
    static final String ADD_REFERENCES_SCHEMA =
        "{\"type\":\"array\",\"maxItems\":10000,\"items\":{"
        + "\"type\":\"object\",\"additionalProperties\":false,"
        + "\"properties\":{\"from\":{\"type\":\"string\"},"
        + "\"to\":{\"type\":\"string\"},"
        + "\"type\":{\"enum\":[\"computed_call\",\"computed_jump\","
        + "\"call\",\"jump\",\"data\",\"write\"]},"
        + "\"operand_index\":{\"type\":\"integer\",\"minimum\":-1,"
        + "\"default\":-1},"
        + "\"primary\":{\"type\":\"boolean\",\"default\":false}},"
        + "\"required\":[\"from\",\"to\",\"type\"]}}";

    private static final Set<String> REMOVE_REFERENCE_FIELDS =
        Set.of("from", "to", "type", "operand_index");
    private static final Set<String> ADD_REFERENCE_FIELDS =
        Set.of("from", "to", "type", "operand_index", "primary");

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threading;
    private final ControlFlowCore core;
    private final TaskMonitor monitor;

    public ControlFlowService(
            ProgramProvider programProvider, ThreadingStrategy threading) {
        this(programProvider, threading, new ControlFlowCore(),
            TaskMonitor.DUMMY);
    }

    ControlFlowService(
            ProgramProvider programProvider, ThreadingStrategy threading,
            ControlFlowCore core, TaskMonitor monitor) {
        this.programProvider = Objects.requireNonNull(programProvider);
        this.threading = Objects.requireNonNull(threading);
        this.core = Objects.requireNonNull(core);
        this.monitor = Objects.requireNonNull(monitor);
    }

    @McpTool(
        path = "/update_entry_points",
        method = "POST",
        description =
            "Preview or atomically add/remove external entry points "
                + "without creating functions; dry_run defaults to true",
        category = "control_flow",
        supportsSyntheticDryRun = false)
    public Response updateEntryPoints(
            @Param(
                value = "add",
                source = ParamSource.BODY,
                optional = true,
                schemaFragment = ADDRESS_ARRAY_SCHEMA,
                description = "Native JSON array of mapped addresses to add")
                Object addValue,
            @Param(
                value = "remove",
                source = ParamSource.BODY,
                optional = true,
                schemaFragment = ADDRESS_ARRAY_SCHEMA,
                description = "Native JSON array of mapped addresses to remove")
                Object removeValue,
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
            List<String> add = parseStringArray(
                addValue, "add", ControlFlowCore.MAX_ENTRY_ACTIONS, true);
            List<String> remove = parseStringArray(
                removeValue, "remove",
                ControlFlowCore.MAX_ENTRY_ACTIONS, true);
            Program program = requireProgram(programName);
            if (dryRun) {
                ControlFlowCore.EntryPointPlan plan =
                    threading.executeRead(() ->
                        core.planEntryPoints(program, add, remove));
                return Response.ok(entryResult(plan, false));
            }
            return threading.executeWrite(
                program, "Update external entry points", () -> {
                    ControlFlowCore.EntryPointPlan plan =
                        core.planEntryPoints(program, add, remove);
                    core.applyEntryPoints(program, plan);
                    return Response.ok(entryResult(plan, true));
                });
        }
        catch (Exception error) {
            return failure("update entry points", error);
        }
    }

    @McpTool(
        path = "/set_instruction_flow_override",
        method = "POST",
        description =
            "Preview or set an instruction flow override without "
                + "redisassembly or analysis; dry_run defaults to true",
        category = "control_flow",
        supportsSyntheticDryRun = false)
    public Response setInstructionFlowOverride(
            @Param(
                value = "address",
                source = ParamSource.BODY,
                paramType = "address")
                String address,
            @Param(
                value = "override",
                source = ParamSource.BODY,
                schemaFragment =
                    "{\"enum\":[\"NONE\",\"BRANCH\",\"CALL\","
                        + "\"CALL_RETURN\",\"RETURN\"]}")
                String override,
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
            FlowOverride requested = parseFlowOverride(override);
            Program program = requireProgram(programName);
            if (dryRun) {
                ControlFlowCore.FlowOverridePlan plan =
                    threading.executeRead(() ->
                        core.planFlowOverride(
                            program, address, requested));
                return Response.ok(flowResult(plan, false));
            }
            return threading.executeWrite(
                program, "Set instruction flow override", () -> {
                    ControlFlowCore.FlowOverridePlan plan =
                        core.planFlowOverride(
                            program, address, requested);
                    core.applyFlowOverride(program, plan);
                    return Response.ok(flowResult(plan, true));
                });
        }
        catch (Exception error) {
            return failure("set instruction flow override", error);
        }
    }

    @McpTool(
        path = "/batch_update_references",
        method = "POST",
        description =
            "Preview or atomically add/remove exact manual references; "
                + "dry_run defaults to true",
        category = "control_flow",
        supportsSyntheticDryRun = false)
    public Response batchUpdateReferences(
            @Param(
                value = "add",
                source = ParamSource.BODY,
                optional = true,
                schemaFragment = ADD_REFERENCES_SCHEMA)
                Object addValue,
            @Param(
                value = "remove",
                source = ParamSource.BODY,
                optional = true,
                schemaFragment = REMOVE_REFERENCES_SCHEMA)
                Object removeValue,
            @Param(
                value = "allow_non_user_removal",
                source = ParamSource.BODY,
                defaultValue = "false",
                strictBoolean = true)
                boolean allowNonUserRemoval,
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
            List<ControlFlowCore.ReferenceRequest> add =
                parseReferenceRequests(addValue, true, "add");
            List<ControlFlowCore.ReferenceRequest> remove =
                parseReferenceRequests(removeValue, false, "remove");
            Program program = requireProgram(programName);
            if (dryRun) {
                ControlFlowCore.ReferencePlan plan =
                    threading.executeRead(() -> core.planReferences(
                        program, add, remove, allowNonUserRemoval));
                return Response.ok(referenceResult(plan, false));
            }
            return threading.executeWrite(
                program, "Batch update references", () -> {
                    ControlFlowCore.ReferencePlan plan =
                        core.planReferences(
                            program, add, remove,
                            allowNonUserRemoval);
                    core.applyReferences(program, plan);
                    return Response.ok(referenceResult(plan, true));
                });
        }
        catch (Exception error) {
            return failure("batch update references", error);
        }
    }

    @McpTool(
        path = "/describe_jump_table",
        method = "POST",
        description =
            "Preview or atomically type a bounded explicit pointer table "
                + "and link dispatch instructions; dry_run defaults to true",
        category = "control_flow",
        supportsSyntheticDryRun = false)
    public Response describeJumpTable(
            @Param(
                value = "table",
                source = ParamSource.BODY,
                schemaFragment = DataRegionService.REGION_ITEM_SCHEMA,
                description = "Exactly one explicit Feature 7 pointer region")
                Object tableValue,
            @Param(
                value = "dispatch_addresses",
                source = ParamSource.BODY,
                schemaFragment = DISPATCH_ARRAY_SCHEMA)
                Object dispatchValue,
            @Param(
                value = "reference_type",
                source = ParamSource.BODY,
                schemaFragment =
                    "{\"enum\":[\"computed_jump\",\"jump\"]}")
                String referenceType,
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
            DataRegionCore.RegionRequest table =
                parseOneRegion(tableValue);
            List<String> dispatches = parseStringArray(
                dispatchValue, "dispatch_addresses",
                ControlFlowCore.MAX_DISPATCHES, false);
            RefType type = parseJumpReferenceType(referenceType);
            Program program = requireProgram(programName);
            if (dryRun) {
                ControlFlowCore.JumpTablePlan plan =
                    threading.executeRead(() -> core.planJumpTable(
                        program, table, dispatches, type, monitor));
                return Response.ok(jumpResult(plan, false));
            }
            return threading.executeWrite(
                program, "Describe jump table", () -> {
                    ControlFlowCore.JumpTablePlan plan =
                        core.planJumpTable(
                            program, table, dispatches, type, monitor);
                    monitor.checkCancelled();
                    core.applyJumpTable(program, plan, monitor);
                    return Response.ok(jumpResult(plan, true));
                });
        }
        catch (Exception error) {
            return failure("describe jump table", error);
        }
    }

    @McpTool(
        path = "/annotate_self_modified_operand",
        method = "POST",
        description =
            "Preview or atomically record writer-to-operand-byte evidence; "
                + "dry_run defaults to true",
        category = "control_flow",
        supportsSyntheticDryRun = false)
    public Response annotateSelfModifiedOperand(
            @Param(
                value = "writer_address",
                source = ParamSource.BODY,
                paramType = "address")
                String writerAddress,
            @Param(
                value = "writer_operand_index",
                source = ParamSource.BODY,
                defaultValue = "-1",
                strictInteger = true)
                int writerOperandIndex,
            @Param(
                value = "target_address",
                source = ParamSource.BODY,
                paramType = "address")
                String targetAddress,
            @Param(
                value = "operand_byte_addresses",
                source = ParamSource.BODY,
                schemaFragment = OPERAND_BYTES_SCHEMA)
                Object operandBytesValue,
            @Param(
                value = "value_source",
                source = ParamSource.BODY,
                defaultValue = "")
                String valueSource,
            @Param(
                value = "comment",
                source = ParamSource.BODY,
                defaultValue = "")
                String comment,
            @Param(
                value = "append_comment",
                source = ParamSource.BODY,
                defaultValue = "false",
                strictBoolean = true)
                boolean appendComment,
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
            List<String> bytes = parseStringArray(
                operandBytesValue, "operand_byte_addresses",
                ControlFlowCore.MAX_OPERAND_BYTES, false);
            Program program = requireProgram(programName);
            if (dryRun) {
                ControlFlowCore.SelfModifiedPlan plan =
                    threading.executeRead(() -> core.planSelfModified(
                        program, writerAddress, writerOperandIndex,
                        targetAddress, bytes, valueSource, comment,
                        appendComment));
                return Response.ok(selfModifiedResult(plan, false));
            }
            return threading.executeWrite(
                program, "Annotate self-modified operand", () -> {
                    ControlFlowCore.SelfModifiedPlan plan =
                        core.planSelfModified(
                            program, writerAddress, writerOperandIndex,
                            targetAddress, bytes, valueSource, comment,
                            appendComment);
                    core.applySelfModified(program, plan);
                    return Response.ok(selfModifiedResult(plan, true));
                });
        }
        catch (Exception error) {
            return failure("annotate self-modified operand", error);
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

    static List<String> parseStringArray(
            Object value, String name, int maximum, boolean optional) {
        if (value == null && optional) {
            return List.of();
        }
        if (!(value instanceof List<?> raw)) {
            throw new IllegalArgumentException(
                name + " must be a native JSON array");
        }
        if (raw.size() > maximum) {
            throw new IllegalArgumentException(
                name + " must contain at most " + maximum + " items");
        }
        if (!optional && raw.isEmpty()) {
            throw new IllegalArgumentException(
                name + " must not be empty");
        }
        List<String> result = new ArrayList<>();
        for (int i = 0; i < raw.size(); i++) {
            Object item = raw.get(i);
            if (!(item instanceof String text) || text.isBlank()) {
                throw new IllegalArgumentException(
                    name + "[" + i + "] must be a nonblank string");
            }
            result.add(text);
        }
        return List.copyOf(result);
    }

    static List<ControlFlowCore.ReferenceRequest> parseReferenceRequests(
            Object value, boolean additions, String name) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> raw)) {
            throw new IllegalArgumentException(
                name + " must be a native JSON array");
        }
        if (raw.size() > ControlFlowCore.MAX_REFERENCE_ACTIONS) {
            throw new IllegalArgumentException(
                name + " must contain at most "
                    + ControlFlowCore.MAX_REFERENCE_ACTIONS + " items");
        }
        List<ControlFlowCore.ReferenceRequest> result =
            new ArrayList<>();
        Set<String> fields = additions
            ? ADD_REFERENCE_FIELDS : REMOVE_REFERENCE_FIELDS;
        for (int i = 0; i < raw.size(); i++) {
            if (!(raw.get(i) instanceof Map<?, ?> untyped)) {
                throw new IllegalArgumentException(
                    name + "[" + i + "] must be an object");
            }
            Map<String, Object> map =
                stringMap(untyped, name + "[" + i + "]");
            Set<String> unknown = new LinkedHashSet<>(map.keySet());
            unknown.removeAll(fields);
            if (!unknown.isEmpty()) {
                throw new IllegalArgumentException(
                    name + "[" + i + "] has unknown fields: "
                        + unknown);
            }
            int operandIndex =
                exactInteger(map.get("operand_index"), -1,
                    name + "[" + i + "].operand_index");
            boolean primary = additions
                && exactBoolean(map.get("primary"), false,
                    name + "[" + i + "].primary");
            result.add(new ControlFlowCore.ReferenceRequest(
                requiredString(map, "from", name + "[" + i + "]"),
                requiredString(map, "to", name + "[" + i + "]"),
                parseReferenceType(requiredString(
                    map, "type", name + "[" + i + "]")),
                operandIndex, primary));
        }
        return List.copyOf(result);
    }

    private static DataRegionCore.RegionRequest parseOneRegion(
            Object value) {
        if (!(value instanceof Map<?, ?>)) {
            throw new IllegalArgumentException(
                "table must be one native JSON object");
        }
        return DataRegionService.parseRegions(List.of(value)).get(0);
    }

    private static FlowOverride parseFlowOverride(String value) {
        if (value == null) {
            throw new IllegalArgumentException("override is required");
        }
        try {
            return FlowOverride.valueOf(value);
        }
        catch (IllegalArgumentException error) {
            throw new IllegalArgumentException(
                "override must be NONE, BRANCH, CALL, CALL_RETURN, or "
                    + "RETURN",
                error);
        }
    }

    private static RefType parseReferenceType(String value) {
        return switch (value) {
            case "computed_call" -> RefType.COMPUTED_CALL;
            case "computed_jump" -> RefType.COMPUTED_JUMP;
            case "call" -> RefType.UNCONDITIONAL_CALL;
            case "jump" -> RefType.UNCONDITIONAL_JUMP;
            case "data" -> RefType.DATA;
            case "write" -> RefType.WRITE;
            default -> throw new IllegalArgumentException(
                "reference type must be computed_call, computed_jump, "
                    + "call, jump, data, or write");
        };
    }

    private static RefType parseJumpReferenceType(String value) {
        return switch (value) {
            case "computed_jump" -> RefType.COMPUTED_JUMP;
            case "jump" -> RefType.UNCONDITIONAL_JUMP;
            default -> throw new IllegalArgumentException(
                "reference_type must be computed_jump or jump");
        };
    }

    private static JsonObject entryResult(
            ControlFlowCore.EntryPointPlan plan, boolean committed) {
        JsonObject result = baseResult(committed);
        JsonArray actions = new JsonArray();
        for (ControlFlowCore.EntryAction action : plan.actions()) {
            JsonObject item = new JsonObject();
            item.addProperty("address", action.address().toString());
            item.addProperty("action", action.action());
            actions.add(item);
        }
        result.add("actions", actions);
        return result;
    }

    private static JsonObject flowResult(
            ControlFlowCore.FlowOverridePlan plan, boolean committed) {
        JsonObject result = baseResult(committed);
        result.addProperty("address", plan.address().toString());
        result.addProperty("previous_override", plan.previous().name());
        result.addProperty("requested_override", plan.requested().name());
        result.addProperty("resulting_override", plan.requested().name());
        result.addProperty("action", plan.action());
        return result;
    }

    private static JsonObject referenceResult(
            ControlFlowCore.ReferencePlan plan, boolean committed) {
        JsonObject result = baseResult(committed);
        result.add("remove", referenceActions(plan.removals()));
        result.add("add", referenceActions(plan.additions()));
        return result;
    }

    private static JsonObject jumpResult(
            ControlFlowCore.JumpTablePlan plan, boolean committed) {
        JsonObject result = baseResult(committed);
        result.add(
            "data_region",
            DataRegionService.renderPlan(plan.dataPlan(), committed));
        result.add(
            "table", DataRegionService.renderRegionPlan(plan.region()));
        JsonArray dispatches = new JsonArray();
        plan.dispatches().forEach(
            address -> dispatches.add(address.toString()));
        result.add("dispatch_addresses", dispatches);
        JsonArray targets = new JsonArray();
        plan.decodedTargets().forEach(
            address -> targets.add(address.toString()));
        result.add("decoded_targets", targets);
        result.add("references", referenceActions(plan.references()));
        result.addProperty(
            "generated_comment", plan.generatedComment());
        return result;
    }

    private static JsonObject selfModifiedResult(
            ControlFlowCore.SelfModifiedPlan plan, boolean committed) {
        JsonObject result = baseResult(committed);
        result.addProperty("writer_address", plan.writer().toString());
        result.addProperty(
            "writer_operand_index", plan.writerOperandIndex());
        result.addProperty("target_address", plan.target().toString());
        JsonArray bytes = new JsonArray();
        plan.operandBytes().forEach(
            address -> bytes.add(address.toString()));
        result.add("operand_byte_addresses", bytes);
        result.add("references", referenceActions(plan.references()));
        result.add("writer_comment", commentAction(plan.writerComment()));
        result.add(
            "target_comment",
            plan.targetComment() == null
                ? JsonNull.INSTANCE
                : commentAction(plan.targetComment()));
        return result;
    }

    private static JsonArray referenceActions(
            List<ControlFlowCore.ReferenceAction> actions) {
        JsonArray result = new JsonArray();
        for (ControlFlowCore.ReferenceAction action : actions) {
            ControlFlowCore.ReferenceIdentity identity =
                action.identity();
            JsonObject item = new JsonObject();
            item.addProperty("from", identity.from().toString());
            item.addProperty("to", identity.to().toString());
            item.addProperty("type", wireType(identity.type()));
            item.addProperty(
                "source", action.source().name().toLowerCase());
            item.addProperty(
                "operand_index", identity.operandIndex());
            item.addProperty(
                "previous_primary", action.previousPrimary());
            item.addProperty(
                "resulting_primary", action.resultingPrimary());
            item.addProperty("action", action.action());
            item.addProperty(
                "non_user_removal", action.nonUserRemoval());
            result.add(item);
        }
        return result;
    }

    private static JsonObject commentAction(
            AddressCommentCore.Plan plan) {
        JsonObject result = new JsonObject();
        result.addProperty("address", plan.address().toString());
        result.addProperty(
            "type", plan.type().name().toLowerCase());
        addNullable(result, "previous", plan.previous());
        addNullable(result, "resulting", plan.resulting());
        result.addProperty(
            "action", plan.changed() ? "set" : "unchanged");
        return result;
    }

    private static JsonObject baseResult(boolean committed) {
        JsonObject result = new JsonObject();
        result.addProperty("committed", committed);
        return result;
    }

    private static String wireType(RefType type) {
        if (type == RefType.COMPUTED_CALL) {
            return "computed_call";
        }
        if (type == RefType.COMPUTED_JUMP) {
            return "computed_jump";
        }
        if (type == RefType.UNCONDITIONAL_CALL) {
            return "call";
        }
        if (type == RefType.UNCONDITIONAL_JUMP) {
            return "jump";
        }
        if (type == RefType.DATA) {
            return "data";
        }
        if (type == RefType.WRITE) {
            return "write";
        }
        return type.getName().toLowerCase();
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

    private static String requiredString(
            Map<String, Object> map, String name, String path) {
        Object value = map.get(name);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException(
                path + "." + name + " must be a nonblank string");
        }
        return text;
    }

    private static int exactInteger(
            Object value, int defaultValue, String path) {
        if (value == null) {
            return defaultValue;
        }
        if (!(value instanceof Number)) {
            throw new IllegalArgumentException(
                path + " must be a JSON integer");
        }
        try {
            return new BigDecimal(String.valueOf(value)).intValueExact();
        }
        catch (NumberFormatException | ArithmeticException error) {
            throw new IllegalArgumentException(
                path + " must be an exact 32-bit JSON integer", error);
        }
    }

    private static boolean exactBoolean(
            Object value, boolean defaultValue, String path) {
        if (value == null) {
            return defaultValue;
        }
        if (!(value instanceof Boolean booleanValue)) {
            throw new IllegalArgumentException(
                path + " must be a JSON boolean");
        }
        return booleanValue;
    }

    private static void addNullable(
            JsonObject object, String name, String value) {
        if (value == null) {
            object.add(name, JsonNull.INSTANCE);
        }
        else {
            object.addProperty(name, value);
        }
    }

    private static Response failure(String operation, Exception error) {
        String message = error.getMessage() == null
            ? error.toString() : error.getMessage();
        return Response.err(
            "Failed to " + operation + ": " + message);
    }
}
