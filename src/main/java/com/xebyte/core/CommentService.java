package com.xebyte.core;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Read and replace any exact-address listing comment. */
public final class CommentService {

    private static final String COMMENT_TYPE_SCHEMA =
        "{\"type\":\"string\",\"enum\":[\"plate\",\"pre\",\"eol\","
            + "\"post\",\"repeatable\"]}";

    private final ProgramProvider programs;
    private final ThreadingStrategy threading;
    private final AddressCommentCore comments = new AddressCommentCore();

    public CommentService(
            ProgramProvider programs, ThreadingStrategy threading) {
        this.programs = programs;
        this.threading = threading;
    }

    @McpTool(
        path = "/get_comment",
        description = "Get all five listing comment kinds at an exact address"
    )
    public Response getComment(
            @Param(value = "address")
                String addressText,
            @Param(
                value = "program",
                description = "Target program name",
                defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved =
            ServiceUtils.getProgramOrError(programs, programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Program program = resolved.program();
        Address address = ServiceUtils.parseAddress(program, addressText);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        return Response.ok(threading.executeReadUnchecked(() -> {
            Listing listing = program.getListing();
            Map<String, Object> result = new LinkedHashMap<>(
                ServiceUtils.addressToJson(address, program));
            String first = null;
            for (CommentType type : List.of(
                    CommentType.PLATE,
                    CommentType.PRE,
                    CommentType.EOL,
                    CommentType.POST,
                    CommentType.REPEATABLE)) {
                String value = listing.getComment(type, address);
                result.put(type.name().toLowerCase(Locale.ROOT), value);
                if (first == null && value != null && !value.isBlank()) {
                    first = value;
                }
            }
            result.put("comment", first);
            result.put("has_comment", first != null);
            return result;
        }));
    }

    @McpTool(
        path = "/set_comment",
        method = "POST",
        description = "Replace or clear one exact-address listing comment"
    )
    public Response setComment(
            @Param(
                value = "address",
                source = ParamSource.BODY)
                String addressText,
            @Param(
                value = "comment_type",
                source = ParamSource.BODY,
                schemaFragment = COMMENT_TYPE_SCHEMA)
                String commentType,
            @Param(value = "comment", source = ParamSource.BODY)
                String comment,
            @Param(
                value = "program",
                description = "Target program name",
                defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved =
            ServiceUtils.getProgramOrError(programs, programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        if (comment == null) {
            return Response.err("comment is required");
        }

        CommentType type;
        try {
            type = CommentType.valueOf(commentType.toUpperCase(Locale.ROOT));
        } catch (RuntimeException error) {
            return Response.err(
                "comment_type must be plate, pre, eol, post, or repeatable");
        }

        Program program = resolved.program();
        try {
            AddressCommentCore.Plan plan = threading.executeWrite(
                program,
                "Set comment",
                () -> {
                    AddressCommentCore.ResolvedAddress target =
                        comments.resolveAddress(program, addressText);
                    AddressCommentCore.Plan prepared = comments.plan(
                        program,
                        target,
                        type,
                        comment,
                        comment.isEmpty()
                            ? AddressCommentCore.WriteMode.REMOVE
                            : AddressCommentCore.WriteMode.REPLACE);
                    comments.apply(program, prepared);
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
        } catch (Exception error) {
            return Response.err(
                error.getMessage() == null
                    ? "failed to set comment"
                    : error.getMessage());
        }
    }
}
