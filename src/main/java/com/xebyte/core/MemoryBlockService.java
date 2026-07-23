package com.xebyte.core;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Objects;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * Canonical initialized, uninitialized, and overlay memory-block API.
 */
@McpToolGroup(
    value = "memory",
    description = "Create and transform initialized or overlay memory blocks")
public final class MemoryBlockService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threading;
    private final SecurityConfig security;
    private final MemoryBlockCore.FileReader fileReader;
    private final MemoryBlockCore core;
    private final TaskMonitor monitor;

    public MemoryBlockService(
            ProgramProvider programProvider,
            ThreadingStrategy threading) {
        this(
            programProvider,
            threading,
            SecurityConfig.getInstance(),
            MemoryBlockService::readFileRange);
    }

    MemoryBlockService(
            ProgramProvider programProvider,
            ThreadingStrategy threading,
            SecurityConfig security,
            MemoryBlockCore.FileReader fileReader) {
        this(
            programProvider,
            threading,
            security,
            fileReader,
            new MemoryBlockCore(),
            TaskMonitor.DUMMY);
    }

    MemoryBlockService(
            ProgramProvider programProvider,
            ThreadingStrategy threading,
            SecurityConfig security,
            MemoryBlockCore.FileReader fileReader,
            MemoryBlockCore core,
            TaskMonitor monitor) {
        this.programProvider =
            Objects.requireNonNull(programProvider, "programProvider");
        this.threading = Objects.requireNonNull(threading, "threading");
        this.security = Objects.requireNonNull(security, "security");
        this.fileReader = Objects.requireNonNull(fileReader, "fileReader");
        this.core = Objects.requireNonNull(core, "core");
        this.monitor = Objects.requireNonNull(monitor, "monitor");
    }

    @McpTool(
        path = "/create_memory_block",
        method = "POST",
        description =
            "Create an initialized or uninitialized ordinary or overlay memory block",
        category = "memory",
        supportsSyntheticDryRun = false)
    public Response createMemoryBlock(
            @Param(value = "name", source = ParamSource.BODY)
                String name,
            @Param(
                value = "start",
                source = ParamSource.BODY,
                paramType = "address")
                String start,
            @Param(
                value = "length",
                source = ParamSource.BODY,
                optional = true,
                strictInteger = true)
                Long length,
            @Param(
                value = "bytes",
                source = ParamSource.BODY,
                optional = true,
                nativeByteLimit = (int) MemoryBlockCore.MAX_SOURCE_BYTES)
                Object bytes,
            @Param(
                value = "file_path",
                source = ParamSource.BODY,
                optional = true)
                String filePath,
            @Param(
                value = "file_offset",
                source = ParamSource.BODY,
                defaultValue = "0",
                strictInteger = true,
                description = "Byte offset in file_path; defaults to zero")
                Long fileOffset,
            @Param(
                value = "source_length",
                source = ParamSource.BODY,
                optional = true,
                strictInteger = true)
                Long sourceLength,
            @Param(
                value = "overlay",
                source = ParamSource.BODY,
                defaultValue = "false",
                strictBoolean = true)
                boolean overlay,
            @Param(
                value = "fill",
                source = ParamSource.BODY,
                optional = true,
                strictInteger = true)
                Integer fill,
            @Param(
                value = "read",
                source = ParamSource.BODY,
                defaultValue = "true",
                strictBoolean = true)
                boolean read,
            @Param(
                value = "write",
                source = ParamSource.BODY,
                defaultValue = "false",
                strictBoolean = true)
                boolean write,
            @Param(
                value = "execute",
                source = ParamSource.BODY,
                defaultValue = "false",
                strictBoolean = true)
                boolean execute,
            @Param(
                value = "volatile",
                source = ParamSource.BODY,
                defaultValue = "false",
                strictBoolean = true)
                boolean volatileFlag,
            @Param(
                value = "comment",
                source = ParamSource.BODY,
                optional = true)
                String comment,
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
            Program program = requireProgram(programName);
            Path resolvedFile = null;
            if (filePath != null && !filePath.isBlank()) {
                resolvedFile = security.resolveWithinFileRoot(filePath);
                if (resolvedFile == null) {
                    return Response.err(
                        "file_path is outside GHIDRA_MCP_FILE_ROOT: "
                            + filePath);
                }
            }
            MemoryBlockCore.SourceData source =
                MemoryBlockCore.normalizeSource(
                    length,
                    normalizeOptionalBytes(bytes),
                    resolvedFile,
                    fileOffset,
                    sourceLength,
                    security.hasFileRoot()
                        ? security::readFileRangeWithinRoot
                        : fileReader);
            source = MemoryBlockCore.withFill(source, fill);
            MemoryBlockCore.CreateRequest request =
                new MemoryBlockCore.CreateRequest(
                    name,
                    start,
                    source,
                    overlay,
                    read,
                    write,
                    execute,
                    volatileFlag,
                    comment);
            if (dryRun) {
                MemoryBlockCore.CreatePlan plan =
                    threading.executeRead(
                        () -> core.planCreate(program, request));
                return Response.ok(
                    createResult(false, plan.predicted()));
            }
            return threading.executeWrite(
                program,
                "Create memory block",
                () -> {
                    MemoryBlockCore.CreatePlan plan =
                        core.planCreate(program, request);
                    monitor.checkCancelled();
                    MemoryBlock block =
                        core.applyCreate(program, plan, monitor);
                    return Response.ok(
                        createResult(
                            true,
                            MemoryBlockCore.descriptor(block)));
                });
        }
        catch (Exception error) {
            return error("create memory block", error);
        }
    }

    @McpTool(
        path = "/update_memory_block",
        method = "POST",
        description =
            "Atomically rename or update memory-block metadata",
        category = "memory",
        supportsSyntheticDryRun = false)
    public Response updateMemoryBlock(
            @Param(value = "name", source = ParamSource.BODY)
                String name,
            @Param(
                value = "new_name",
                source = ParamSource.BODY,
                optional = true)
                String newName,
            @Param(
                value = "read",
                source = ParamSource.BODY,
                optional = true,
                strictBoolean = true)
                Boolean read,
            @Param(
                value = "write",
                source = ParamSource.BODY,
                optional = true,
                strictBoolean = true)
                Boolean write,
            @Param(
                value = "execute",
                source = ParamSource.BODY,
                optional = true,
                strictBoolean = true)
                Boolean execute,
            @Param(
                value = "volatile",
                source = ParamSource.BODY,
                optional = true,
                strictBoolean = true)
                Boolean volatileFlag,
            @Param(
                value = "comment",
                source = ParamSource.BODY,
                optional = true)
                String comment,
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
            Program program = requireProgram(programName);
            MemoryBlockCore.UpdateRequest request =
                new MemoryBlockCore.UpdateRequest(
                    name,
                    normalizeOptional(newName),
                    read,
                    write,
                    execute,
                    volatileFlag,
                    comment);
            if (dryRun) {
                MemoryBlockCore.UpdatePlan plan =
                    threading.executeRead(
                        () -> core.planUpdate(program, request));
                return Response.ok(
                    transformResult(
                        false, plan.before(), plan.predicted()));
            }
            return threading.executeWrite(
                program,
                "Update memory block",
                () -> {
                    MemoryBlockCore.UpdatePlan plan =
                        core.planUpdate(program, request);
                    monitor.checkCancelled();
                    MemoryBlock block = core.applyUpdate(plan);
                    return Response.ok(
                        transformResult(
                            true,
                            plan.before(),
                            MemoryBlockCore.descriptor(block)));
                });
        }
        catch (Exception error) {
            return error("update memory block", error);
        }
    }

    @McpTool(
        path = "/split_memory_block",
        method = "POST",
        description =
            "Split a memory block while preserving bytes and metadata",
        category = "memory",
        supportsSyntheticDryRun = false)
    public Response splitMemoryBlock(
            @Param(value = "name", source = ParamSource.BODY)
                String name,
            @Param(
                value = "split_address",
                source = ParamSource.BODY,
                paramType = "address")
                String splitAddress,
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
            Program program = requireProgram(programName);
            if (dryRun) {
                MemoryBlockCore.SplitPlan plan =
                    threading.executeRead(
                        () -> core.planSplit(
                            program, name, splitAddress));
                return Response.ok(splitResult(
                    false,
                    plan.before(),
                    plan.prefix(),
                    plan.suffix()));
            }
            return threading.executeWrite(
                program,
                "Split memory block",
                () -> {
                    MemoryBlockCore.SplitPlan plan =
                        core.planSplit(
                            program, name, splitAddress);
                    monitor.checkCancelled();
                    MemoryBlockCore.SplitApplied applied =
                        core.applySplit(program, plan);
                    return Response.ok(splitResult(
                        true,
                        applied.before(),
                        applied.prefix(),
                        applied.suffix()));
                });
        }
        catch (Exception error) {
            return error("split memory block", error);
        }
    }

    @McpTool(
        path = "/move_memory_block",
        method = "POST",
        description =
            "Move a non-overlay memory block after complete overlap validation",
        category = "memory",
        supportsSyntheticDryRun = false)
    public Response moveMemoryBlock(
            @Param(value = "name", source = ParamSource.BODY)
                String name,
            @Param(
                value = "new_start",
                source = ParamSource.BODY,
                paramType = "address")
                String newStart,
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
            Program program = requireProgram(programName);
            if (dryRun) {
                MemoryBlockCore.MovePlan plan =
                    threading.executeRead(
                        () -> core.planMove(
                            program, name, newStart));
                return Response.ok(
                    transformResult(
                        false, plan.before(), plan.predicted()));
            }
            return threading.executeWrite(
                program,
                "Move memory block",
                () -> {
                    MemoryBlockCore.MovePlan plan =
                        core.planMove(program, name, newStart);
                    monitor.checkCancelled();
                    MemoryBlock block =
                        core.applyMove(program, plan, monitor);
                    return Response.ok(
                        transformResult(
                            true,
                            plan.before(),
                            MemoryBlockCore.descriptor(block)));
                });
        }
        catch (Exception error) {
            return error("move memory block", error);
        }
    }

    @McpTool(
        path = "/write_memory_bytes",
        method = "POST",
        description =
            "Atomically write bytes inside one initialized block; "
                + "overwrite_bytes reports at most 4096 coalesced differing "
                + "ranges, so split requests that exceed the limit",
        category = "memory",
        supportsSyntheticDryRun = false)
    public Response writeMemoryBytes(
            @Param(
                value = "start",
                source = ParamSource.BODY,
                paramType = "address")
                String start,
            @Param(
                value = "bytes",
                source = ParamSource.BODY,
                nativeByteLimit = (int) MemoryBlockCore.MAX_SOURCE_BYTES)
                Object bytes,
            @Param(
                value = "conflict_policy",
                source = ParamSource.BODY,
                defaultValue = "error",
                description =
                    "error rejects the first mismatch; overwrite_bytes permits "
                        + "at most 4096 coalesced differing ranges and requires "
                        + "splitting a request that exceeds the limit")
                String conflictPolicy,
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
            Program program = requireProgram(programName);
            byte[] decoded = MemoryBlockCore.decodeBytes(bytes);
            if (dryRun) {
                MemoryBlockCore.WritePlan plan =
                    threading.executeRead(
                        () -> core.planWrite(
                            program,
                            start,
                            decoded,
                            conflictPolicy));
                return Response.ok(writeResult(false, plan));
            }
            return threading.executeWrite(
                program,
                "Write memory bytes",
                () -> {
                    MemoryBlockCore.WritePlan plan =
                        core.planWrite(
                            program,
                            start,
                            decoded,
                            conflictPolicy);
                    monitor.checkCancelled();
                    core.applyWrite(plan);
                    return Response.ok(writeResult(true, plan));
                });
        }
        catch (Exception error) {
            return error("write memory bytes", error);
        }
    }

    static byte[] readFileRange(
            Path path, long offset, int length) throws IOException {
        if (!java.nio.file.Files.isRegularFile(path)
                || !java.nio.file.Files.isReadable(path)) {
            throw new IOException(
                "file_path must be a regular readable file: " + path);
        }
        byte[] result = new byte[length];
        try (FileChannel channel = FileChannel.open(
                path, StandardOpenOption.READ)) {
            long size = channel.size();
            if (offset > size || length > size - offset) {
                throw new IOException(
                    "file_offset plus source_length exceeds file size");
            }
            channel.position(offset);
            ByteBuffer buffer = ByteBuffer.wrap(result);
            while (buffer.hasRemaining()) {
                int count = channel.read(buffer);
                if (count < 0) {
                    break;
                }
            }
            if (buffer.hasRemaining()) {
                throw new IOException(
                    "file changed while reading; requested range no longer fits");
            }
            return result;
        }
    }

    private Program requireProgram(String programName) {
        ServiceUtils.ProgramOrError resolution =
            ServiceUtils.getProgramOrError(
                programProvider, programName);
        if (resolution.hasError()) {
            String message = resolution.error() instanceof Response.Err error
                ? error.message()
                : resolution.error().toJson();
            throw new IllegalArgumentException(message);
        }
        return resolution.program();
    }

    private static JsonObject createResult(
            boolean committed,
            MemoryBlockCore.BlockDescriptor after) {
        JsonObject result = new JsonObject();
        result.addProperty("committed", committed);
        result.add("before", JsonNull.INSTANCE);
        result.add("after", descriptorJson(after));
        result.addProperty("address_space", after.addressSpace());
        result.addProperty("changed", true);
        return result;
    }

    private static JsonObject transformResult(
            boolean committed,
            MemoryBlockCore.BlockDescriptor before,
            MemoryBlockCore.BlockDescriptor after) {
        JsonObject result = new JsonObject();
        result.addProperty("committed", committed);
        result.add("before", descriptorJson(before));
        result.add("after", descriptorJson(after));
        result.addProperty("address_space", after.addressSpace());
        result.addProperty("changed", !before.equals(after));
        return result;
    }

    private static JsonObject splitResult(
            boolean committed,
            MemoryBlockCore.BlockDescriptor before,
            MemoryBlockCore.BlockDescriptor prefix,
            MemoryBlockCore.BlockDescriptor suffix) {
        JsonObject result = new JsonObject();
        JsonObject after = new JsonObject();
        after.add("prefix", descriptorJson(prefix));
        after.add("suffix", descriptorJson(suffix));
        result.addProperty("committed", committed);
        result.add("before", descriptorJson(before));
        result.add("after", after);
        result.add("prefix", descriptorJson(prefix));
        result.add("suffix", descriptorJson(suffix));
        result.addProperty("address_space", prefix.addressSpace());
        result.addProperty("changed", true);
        return result;
    }

    private static JsonObject writeResult(
            boolean committed,
            MemoryBlockCore.WritePlan plan) {
        JsonObject result = new JsonObject();
        JsonObject descriptor = descriptorJson(plan.before());
        JsonArray ranges = new JsonArray();
        for (MemoryBlockCore.DifferingRange range
                : plan.differingRanges()) {
            JsonObject item = new JsonObject();
            item.addProperty("start", range.start());
            item.addProperty("end", range.end());
            item.addProperty("length", range.length());
            ranges.add(item);
        }
        result.addProperty("committed", committed);
        result.add("before", descriptor);
        result.add("after", descriptor.deepCopy());
        result.addProperty("address_space", plan.before().addressSpace());
        result.addProperty("changed", !plan.differingRanges().isEmpty());
        result.addProperty("sha256", plan.sha256());
        result.add("differing_ranges", ranges);
        result.addProperty("conflict_policy", plan.conflictPolicy());
        result.addProperty("length", plan.requested().length);
        return result;
    }

    static JsonObject descriptorJson(
            MemoryBlockCore.BlockDescriptor descriptor) {
        JsonObject json = new JsonObject();
        json.addProperty("name", descriptor.name());
        json.addProperty("start", descriptor.start());
        json.addProperty("end", descriptor.end());
        json.addProperty("length", descriptor.length());
        json.addProperty("address_space", descriptor.addressSpace());
        json.addProperty("overlay", descriptor.overlay());
        json.addProperty("initialized", descriptor.initialized());
        json.addProperty("source", descriptor.source());
        json.addProperty("read", descriptor.read());
        json.addProperty("write", descriptor.write());
        json.addProperty("execute", descriptor.execute());
        json.addProperty("permissions", descriptor.permissions());
        json.addProperty("volatile", descriptor.volatileFlag());
        json.addProperty("comment", descriptor.comment());
        return json;
    }

    static List<JsonObject> descriptorJson(
            List<MemoryBlockCore.BlockDescriptor> descriptors) {
        return descriptors.stream()
            .map(MemoryBlockService::descriptorJson)
            .toList();
    }

    private static Response error(String operation, Exception error) {
        Throwable useful = error;
        while (useful.getCause() != null
                && (useful.getMessage() == null
                    || useful.getMessage().isBlank())) {
            useful = useful.getCause();
        }
        String message = useful.getMessage();
        return Response.err(
            "Failed to " + operation + ": "
                + (message == null ? useful.toString() : message));
    }

    private static String normalizeOptional(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private static Object normalizeOptionalBytes(Object value) {
        if (value instanceof String text && text.isBlank()) {
            return null;
        }
        return value;
    }
}
