package com.xebyte.core;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonParser;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Service for comment operations: set/get/clear decompiler, disassembly, and plate comments.
 */
@McpToolGroup(value = "comment", description = "Set/get plate, decompiler, disassembly, repeatable comments")
public class CommentService {

    private static final Gson GSON = new Gson();

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final AddressCommentCore addressCommentCore;

    private record BatchCommentOutcome(
            int decompilerCount,
            int disassemblyCount,
            boolean plateSet,
            int overwrittenCount) {
    }

    public CommentService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.addressCommentCore = new AddressCommentCore();
    }

    // -----------------------------------------------------------------------
    // Comment Methods
    // -----------------------------------------------------------------------

    /**
     * Set a comment using the specified comment type.
     */
    public Response setCommentAtAddress(String addressStr, String comment, CommentType commentType, String transactionName, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }
        if (comment == null) {
            return Response.err("Comment text is required");
        }

        // Resolve address before entering SwingUtilities lambda
        Address addr = ServiceUtils.parseMutationAddress(program, addressStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return Response.err("Failed to execute on Swing thread: " + e.getMessage());
        }

        if (success.get()) {
            return Response.ok(JsonHelper.mapOf("status", "success", "message", "Set comment at " + addressStr));
        }
        return Response.err(errorMsg.get() != null ? errorMsg.get() : "Unknown failure");
    }

    public Response setCommentAtAddress(String addressStr, String comment, CommentType commentType, String transactionName) {
        return setCommentAtAddress(addressStr, comment, commentType, transactionName, null);
    }

    @McpTool(path = "/set_decompiler_comment", method = "POST", description = "Set decompiler PRE_COMMENT at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "comment")
    public Response setDecompilerComment(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "comment", source = ParamSource.BODY) String comment,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        return setCommentAtAddress(addressStr, comment, CommentType.PRE, "Set decompiler comment", programName);
    }

    public Response setDecompilerComment(String addressStr, String comment) {
        return setDecompilerComment(addressStr, comment, null);
    }

    @McpTool(path = "/set_disassembly_comment", method = "POST", description = "Set disassembly EOL_COMMENT at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "comment")
    public Response setDisassemblyComment(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "comment", source = ParamSource.BODY) String comment,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        return setCommentAtAddress(addressStr, comment, CommentType.EOL, "Set disassembly comment", programName);
    }

    public Response setDisassemblyComment(String addressStr, String comment) {
        return setDisassemblyComment(addressStr, comment, null);
    }

    @McpTool(path = "/set_repeatable_comment", method = "POST",
             description = "Set or clear a repeatable comment at any valid program address. "
                         + "On programs with multiple address spaces, qualify the address as "
                         + "<space>:<hex>.",
             category = "comment")
    public Response setRepeatableComment(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or "
                               + "<space>:<hex>; mutations reject ambiguous unqualified offsets.")
                    String addressStr,
            @Param(value = "comment", source = ParamSource.BODY,
                   description = "Replacement text; pass an empty string to clear the comment.")
                    String comment,
            @Param(value = "program", description = "Target program name", defaultValue = "")
                    String programName) {
        return setExactComment(
            addressStr,
            comment,
            CommentType.REPEATABLE,
            "Set Repeatable Comment",
            "Failed to set repeatable comment",
            programName);
    }

    /**
     * Get the plate (header) comment for a function.
     */
    @McpTool(path = "/get_plate_comment", description = "Get function header/plate comment. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "comment")
    public Response getPlateComment(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String address,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (address == null || address.isEmpty()) {
            return Response.err("address parameter is required");
        }

        Address addr = ServiceUtils.parseAddress(program, address);
        if (addr == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        if (func == null) {
            return Response.err("No function at address: " + address);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.putAll(ServiceUtils.addressToJson(func.getEntryPoint(), program));
        result.put("function_name", func.getName());
        result.put("comment", func.getComment());
        return Response.ok(result);
    }

    /**
     * Set a plate comment at an exact mapped program address.
     */
    @McpTool(path = "/get_comment",
             description = "Get every listing comment kind (plate/pre/eol/post/repeatable) at ANY address, including data addresses. Unlike get_plate_comment this does not require a function at the address. Also returns `comment`, the first non-empty kind, and a `has_comment` flag.",
             category = "comment")
    public Response getComment(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or "
                               + "<space>:<hex> (e.g. mem:1000, SND_PLAYER::9695). Works at data "
                               + "addresses, not just function entries.") String addressStr,
            @Param(value = "program", description = "Target program name (omit to use the active program)",
                   defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter is required");
        }
        Address address = ServiceUtils.parseAddress(program, addressStr);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        // One read for all five kinds: separate reads could interleave with a write and return
        // a torn snapshot, where `comment` names a kind whose sibling values came from a
        // different moment. Sibling single-read getters here predate the read lock.
        Map<String, Object> result = threadingStrategy.executeReadUnchecked(() -> {
            Listing listing = program.getListing();
            Map<String, Object> kinds = new LinkedHashMap<>(
                ServiceUtils.addressToJson(address, program));
            String first = null;
            // Explicit precedence: CommentType.values() is declaration order, which puts EOL
            // ahead of PLATE and made `comment` pick the wrong kind. Plate first, then
            // narrowing scope.
            for (CommentType type : List.of(CommentType.PLATE, CommentType.PRE, CommentType.EOL,
                                            CommentType.POST, CommentType.REPEATABLE)) {
                String text = listing.getComment(type, address);
                kinds.put(type.name().toLowerCase(Locale.ROOT), text);
                if (first == null && text != null && !text.isBlank()) {
                    first = text;
                }
            }
            kinds.put("comment", first);
            kinds.put("has_comment", first != null);
            return kinds;
        });
        return Response.ok(result);
    }

    @McpTool(path = "/set_plate_comment", method = "POST", description = "Set a plate comment at any valid program address.", category = "comment")
    public Response setPlateComment(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddress,
            @Param(value = "comment", source = ParamSource.BODY) String comment,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        return setExactComment(
            functionAddress,
            comment,
            CommentType.PLATE,
            "Set Plate Comment",
            "Failed to set plate comment",
            programName);
    }

    private Response setExactComment(
            String address,
            String comment,
            CommentType type,
            String transactionName,
            String failureMessage,
            String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (address == null || address.isEmpty()) {
            return Response.err("Address is required");
        }
        if (comment == null) {
            return Response.err("Comment is required");
        }

        try {
            AddressCommentCore.WriteMode mode =
                comment.isEmpty()
                    ? AddressCommentCore.WriteMode.REMOVE
                    : AddressCommentCore.WriteMode.REPLACE;
            AddressCommentCore.Plan plan =
                threadingStrategy.executeWrite(
                    program,
                    transactionName,
                    () -> {
                        AddressCommentCore.ResolvedAddress target =
                            addressCommentCore.resolveAddress(
                                program, address);
                        AddressCommentCore.Plan prepared =
                            addressCommentCore.plan(
                                program,
                                target,
                                type,
                                comment,
                                mode);
                        addressCommentCore.apply(program, prepared);
                        return prepared;
                    });

            JsonObject result = new JsonObject();
            ServiceUtils.addressToJson(plan.address(), program)
                .forEach((key, value) ->
                    result.addProperty(key, String.valueOf(value)));
            result.add(
                "previous",
                plan.previous() == null
                    ? JsonNull.INSTANCE
                    : new JsonPrimitive(plan.previous()));
            result.add(
                "resulting",
                plan.resulting() == null
                    ? JsonNull.INSTANCE
                    : new JsonPrimitive(plan.resulting()));
            result.addProperty("changed", plan.changed());
            return Response.ok(result);
        }
        catch (Exception e) {
            return Response.err(
                e.getMessage() != null
                    ? e.getMessage()
                    : failureMessage);
        }
    }

    public Response setPlateComment(String functionAddress, String comment) {
        return setPlateComment(functionAddress, comment, null);
    }

    /**
     * Decode one comment array strictly, recording every problem rather than dropping items.
     *
     * <p>This rejects items the writer below would otherwise skip in silence. An item missing
     * {@code comment}, carrying an unrecognised key, or naming an unresolvable address used to
     * leave the request reporting success with a zero count, so a caller who sent the wrong
     * shape -- {@code text} instead of {@code comment}, say -- believed the write had happened.
     *
     * <p>The shared converters must stay permissive -- they also back endpoint-schema parsing,
     * where non-string values are legitimate -- so strictness lives here, at the one endpoint
     * whose contract is {@code {address: string, comment: string}}.
     *
     * <p>Direct and stringified input are normalised to the same JsonArray before inspection.
     * Handling them separately is what let a stringified {@code [{...}, 42]} lose its malformed
     * element while the direct form rejected it.
     */
    static List<Map<String, String>> decodeCommentItems(String field, Object raw,
                                                        List<String> problems) {
        List<Map<String, String>> decoded = new ArrayList<>();
        if (raw == null) {
            return decoded;
        }

        JsonElement element;
        try {
            element = raw instanceof String text
                ? (text.isBlank() ? null : JsonParser.parseString(text))
                : GSON.toJsonTree(raw);
        }
        catch (RuntimeException e) {
            problems.add(field + " is not valid JSON: " + e.getMessage());
            return decoded;
        }
        if (element == null || element.isJsonNull()) {
            return decoded;
        }
        if (!element.isJsonArray()) {
            problems.add(field + " must be a JSON array of objects, got "
                + (element.isJsonObject() ? "an object" : "a scalar"));
            return decoded;
        }

        JsonArray array = element.getAsJsonArray();
        for (int i = 0; i < array.size(); i++) {
            JsonElement item = array.get(i);
            String where = field + "[" + i + "]";
            if (item == null || !item.isJsonObject()) {
                problems.add(where + " must be an object");
                continue;
            }
            Map<String, String> entry = new LinkedHashMap<>();
            for (Map.Entry<String, JsonElement> member : item.getAsJsonObject().entrySet()) {
                JsonElement value = member.getValue();
                if (value != null && !value.isJsonNull() && !value.isJsonPrimitive()) {
                    problems.add(where + "." + member.getKey() + " must be a string, got "
                        + (value.isJsonArray() ? "an array" : "an object"));
                    continue;
                }
                if (value != null && value.isJsonPrimitive() && !value.getAsJsonPrimitive().isString()) {
                    problems.add(where + "." + member.getKey() + " must be a string, got "
                        + value.getAsJsonPrimitive());
                    continue;
                }
                entry.put(member.getKey(),
                    value == null || value.isJsonNull() ? null : value.getAsString());
            }
            decoded.add(entry);
        }
        return decoded;
    }

    static List<String> commentItemShapeProblems(String field, List<Map<String, String>> items) {
        List<String> problems = new ArrayList<>();
        if (items == null) {
            return problems;
        }
        for (int i = 0; i < items.size(); i++) {
            Map<String, String> item = items.get(i);
            String where = field + "[" + i + "]";
            if (item == null) {
                problems.add(where + " is null");
                continue;
            }
            List<String> unknown = item.keySet().stream()
                    .filter(k -> !"address".equals(k) && !"comment".equals(k))
                    .sorted()
                    .toList();
            if (!unknown.isEmpty()) {
                problems.add(where + " has unrecognised key(s) " + unknown);
            }
            if (item.get("address") == null) {
                problems.add(where + " is missing \"address\"");
            }
            if (item.get("comment") == null) {
                problems.add(where + " is missing \"comment\"");
            }
        }
        return problems;
    }

    private static void validateCommentItems(String field, List<Map<String, String>> items,
                                             Program program, List<String> problems) {
        problems.addAll(commentItemShapeProblems(field, items));
        if (items == null) {
            return;
        }
        for (int i = 0; i < items.size(); i++) {
            Map<String, String> item = items.get(i);
            String addressStr = item == null ? null : item.get("address");
            if (addressStr != null && ServiceUtils.parseMutationAddress(program, addressStr) == null) {
                // parseMutationAddress rejects an unqualified address that is mapped in more
                // than one space, so the reason is carried through rather than flattened to
                // "could not be resolved" — the caller needs to know which spaces collide.
                String reason = ServiceUtils.getLastParseError();
                problems.add(field + "[" + i + "] address \"" + addressStr
                        + "\" could not be resolved"
                        + (reason == null || reason.isBlank() ? "" : ": " + reason));
            }
        }
    }

    /**
     * Advertised shape of the two comment arrays. The parameters are declared Object so the raw
     * value reaches decodeCommentItems unconverted; without this fragment the scanner would infer
     * "any" from that Object and the bridge would publish them as strings.
     */
    static final String COMMENT_ITEMS_SCHEMA =
            "{\"type\":\"array\",\"items\":{\"type\":\"object\","
            + "\"additionalProperties\":false,"
            + "\"properties\":{\"address\":{\"type\":\"string\"},"
            + "\"comment\":{\"type\":\"string\"}},"
            + "\"required\":[\"address\",\"comment\"]}}";

    /**
     * Batch set multiple comments (decompiler, disassembly, and plate) in a single operation.
     */
    @McpTool(path = "/batch_set_comments", method = "POST", description = "Set multiple comments in one operation. Each item in decompiler_comments/disassembly_comments must be {\"address\": \"0x...\", \"comment\": \"...\"}; unrecognised keys, missing keys and unresolvable addresses are rejected and the whole request writes nothing. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "comment")
    public Response batchSetComments(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddress,
            @Param(value = "decompiler_comments", source = ParamSource.BODY, defaultValue = "[]",
                   schemaFragment = COMMENT_ITEMS_SCHEMA,
                   description = "Native JSON array of {address, comment} objects.") Object decompilerCommentsRaw,
            @Param(value = "disassembly_comments", source = ParamSource.BODY, defaultValue = "[]",
                   schemaFragment = COMMENT_ITEMS_SCHEMA,
                   description = "Native JSON array of {address, comment} objects.") Object disassemblyCommentsRaw,
            @Param(value = "plate_comment", source = ParamSource.BODY, defaultValue = "null",
                   description = "Plate comment text. Omit to leave existing plate untouched. Pass empty string to explicitly clear.") String plateComment,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> itemProblems = new ArrayList<>();
        List<Map<String, String>> decompilerComments =
            decodeCommentItems("decompiler_comments", decompilerCommentsRaw, itemProblems);
        List<Map<String, String>> disassemblyComments =
            decodeCommentItems("disassembly_comments", disassemblyCommentsRaw, itemProblems);
        validateCommentItems("decompiler_comments", decompilerComments, program, itemProblems);
        validateCommentItems("disassembly_comments", disassemblyComments, program, itemProblems);
        if (!itemProblems.isEmpty()) {
            return Response.err("batch_set_comments wrote nothing: " + String.join("; ", itemProblems)
                    + ". Each item must be {\"address\": \"0x...\", \"comment\": \"...\"}.");
        }

        final BatchCommentOutcome outcome;
        try {
            outcome = threadingStrategy.executeWrite(
                program,
                "Batch Set Comments",
                () -> {
                    int decompilerCount = 0;
                    int disassemblyCount = 0;
                    int overwrittenCount = 0;
                    boolean plateSet = false;

                    AddressCommentCore.ResolvedAddress target = null;
                    if (functionAddress != null
                            && !functionAddress.isEmpty()) {
                        target = addressCommentCore.resolveAddress(
                            program, functionAddress);
                    }

                    // Set or clear the exact-address plate through the same
                    // planner/writer as set_plate_comment.
                    if (plateComment != null
                            && !plateComment.equals("null")
                            && target != null) {
                        AddressCommentCore.Plan platePlan =
                            addressCommentCore.plan(
                                program,
                                target,
                                CommentType.PLATE,
                                plateComment,
                                plateComment.isEmpty()
                                    ? AddressCommentCore.WriteMode.REMOVE
                                    : AddressCommentCore.WriteMode.REPLACE);
                        if (platePlan.previous() != null
                                && !platePlan.previous().isEmpty()) {
                            overwrittenCount++;
                        }
                        addressCommentCore.apply(program, platePlan);
                        plateSet = true;
                    }

                    Listing listing = program.getListing();
                    if (decompilerComments != null) {
                        for (Map<String, String> commentEntry : decompilerComments) {
                            String addrStr = commentEntry.get("address");
                            String cmt = commentEntry.get("comment");
                            if (addrStr != null && cmt != null) {
                                Address address = ServiceUtils.parseMutationAddress(program, addrStr);
                                if (address != null) {
                                    String existing = listing.getComment(CommentType.PRE, address);
                                    if (existing != null && !existing.isEmpty()) {
                                        overwrittenCount++;
                                    }
                                    listing.setComment(address, CommentType.PRE, cmt.isEmpty() ? null : cmt);
                                    decompilerCount++;
                                }
                            }
                        }
                    }

                    if (disassemblyComments != null) {
                        for (Map<String, String> commentEntry : disassemblyComments) {
                            String addrStr = commentEntry.get("address");
                            String cmt = commentEntry.get("comment");
                            if (addrStr != null && cmt != null) {
                                Address address = ServiceUtils.parseMutationAddress(program, addrStr);
                                if (address != null) {
                                    String existing = listing.getComment(CommentType.EOL, address);
                                    if (existing != null && !existing.isEmpty()) {
                                        overwrittenCount++;
                                    }
                                    listing.setComment(address, CommentType.EOL, cmt.isEmpty() ? null : cmt);
                                    disassemblyCount++;
                                }
                            }
                        }
                    }

                    return new BatchCommentOutcome(
                        decompilerCount,
                        disassemblyCount,
                        plateSet,
                        overwrittenCount);
                });
        }
        catch (Exception e) {
            return Response.err(
                e.getMessage() != null
                    ? e.getMessage()
                    : "Failed to set batch comments");
        }

        Map<String, Object> resultMap = new LinkedHashMap<>();
        resultMap.put("success", true);
        resultMap.put(
            "decompiler_comments_set",
            outcome.decompilerCount());
        resultMap.put(
            "disassembly_comments_set",
            outcome.disassemblyCount());
        resultMap.put("plate_comment_set", outcome.plateSet());
        resultMap.put(
            "plate_comment_cleared",
            outcome.plateSet()
                && plateComment != null
                && plateComment.isEmpty());
        resultMap.put(
            "comments_overwritten",
            outcome.overwrittenCount());
        return Response.ok(resultMap);
    }

    /** Convenience overload. Takes the arrays raw so callers cannot pre-convert past validation. */
    public Response batchSetComments(String functionAddress, Object decompilerComments,
                                     Object disassemblyComments, String plateComment) {
        return batchSetComments(functionAddress, decompilerComments, disassemblyComments, plateComment, null);
    }

    /**
     * Clear all comments (plate, PRE, EOL) within a function's address range.
     */
    @McpTool(path = "/clear_function_comments", method = "POST", description = "Clear all comments within a function. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "comment")
    public Response clearFunctionComments(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddress,
            @Param(value = "clear_plate", source = ParamSource.BODY, defaultValue = "true") boolean clearPlate,
            @Param(value = "clear_pre", source = ParamSource.BODY, defaultValue = "true") boolean clearPre,
            @Param(value = "clear_eol", source = ParamSource.BODY, defaultValue = "true") boolean clearEol,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionAddress == null || functionAddress.isEmpty()) {
            return Response.err("function_address parameter is required");
        }

        // Resolve address before entering SwingUtilities lambda
        Address resolvedAddr = ServiceUtils.parseMutationAddress(program, functionAddress);
        if (resolvedAddr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<String> errorMsg = new AtomicReference<>();
        final AtomicInteger preCleared = new AtomicInteger(0);
        final AtomicInteger eolCleared = new AtomicInteger(0);
        final AtomicBoolean plateCleared = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Clear Function Comments");
                try {
                    Function func = program.getFunctionManager().getFunctionAt(resolvedAddr);
                    if (func == null) {
                        errorMsg.set("No function at address: " + functionAddress);
                        return;
                    }

                    if (clearPlate && func.getComment() != null) {
                        func.setComment(null);
                        plateCleared.set(true);
                    }

                    Listing listing = program.getListing();
                    AddressSetView body = func.getBody();
                    InstructionIterator instrIter = listing.getInstructions(body, true);

                    while (instrIter.hasNext()) {
                        Instruction instr = instrIter.next();
                        Address instrAddr = instr.getAddress();

                        if (clearPre) {
                            String existing = listing.getComment(CommentType.PRE, instrAddr);
                            if (existing != null) {
                                listing.setComment(instrAddr, CommentType.PRE, null);
                                preCleared.incrementAndGet();
                            }
                        }

                        if (clearEol) {
                            String existing = listing.getComment(CommentType.EOL, instrAddr);
                            if (existing != null) {
                                listing.setComment(instrAddr, CommentType.EOL, null);
                                eolCleared.incrementAndGet();
                            }
                        }
                    }

                    success.set(true);
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                    Msg.error(this, "Error clearing function comments", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        if (!success.get()) {
            return Response.err(errorMsg.get() != null ? errorMsg.get() : "Unknown failure");
        }

        return Response.ok(JsonHelper.mapOf(
                "success", true,
                "plate_comment_cleared", plateCleared.get(),
                "pre_comments_cleared", preCleared.get(),
                "eol_comments_cleared", eolCleared.get()
        ));
    }

    public Response clearFunctionComments(String functionAddress, boolean clearPlate, boolean clearPre, boolean clearEol) {
        return clearFunctionComments(functionAddress, clearPlate, clearPre, clearEol, null);
    }
}
