package com.xebyte.core;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;
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
    private final MemoryBlockLifecycleCore lifecycle;
    private final PatchBytesCore patchCore;
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
            new PatchBytesCore(),
            TaskMonitor.DUMMY);
    }

    MemoryBlockService(
            ProgramProvider programProvider,
            ThreadingStrategy threading,
            SecurityConfig security,
            MemoryBlockCore.FileReader fileReader,
            MemoryBlockCore core,
            TaskMonitor monitor) {
        this(
            programProvider,
            threading,
            security,
            fileReader,
            core,
            new MemoryBlockLifecycleCore(),
            new PatchBytesCore(),
            monitor);
    }

    MemoryBlockService(
            ProgramProvider programProvider,
            ThreadingStrategy threading,
            SecurityConfig security,
            MemoryBlockCore.FileReader fileReader,
            MemoryBlockCore core,
            MemoryBlockLifecycleCore lifecycle,
            TaskMonitor monitor) {
        this(
            programProvider,
            threading,
            security,
            fileReader,
            core,
            lifecycle,
            new PatchBytesCore(),
            monitor);
    }

    MemoryBlockService(
            ProgramProvider programProvider,
            ThreadingStrategy threading,
            SecurityConfig security,
            MemoryBlockCore.FileReader fileReader,
            MemoryBlockCore core,
            PatchBytesCore patchCore,
            TaskMonitor monitor) {
        this(
            programProvider,
            threading,
            security,
            fileReader,
            core,
            new MemoryBlockLifecycleCore(),
            patchCore,
            monitor);
    }

    MemoryBlockService(
            ProgramProvider programProvider,
            ThreadingStrategy threading,
            SecurityConfig security,
            MemoryBlockCore.FileReader fileReader,
            MemoryBlockCore core,
            MemoryBlockLifecycleCore lifecycle,
            PatchBytesCore patchCore,
            TaskMonitor monitor) {
        this.programProvider =
            Objects.requireNonNull(programProvider, "programProvider");
        this.threading = Objects.requireNonNull(threading, "threading");
        this.security = Objects.requireNonNull(security, "security");
        this.fileReader = Objects.requireNonNull(fileReader, "fileReader");
        this.core = Objects.requireNonNull(core, "core");
        this.lifecycle = Objects.requireNonNull(lifecycle, "lifecycle");
        this.patchCore =
            Objects.requireNonNull(patchCore, "patchCore");
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

    @McpTool(
        path = "/delete_memory_block",
        method = "POST",
        description =
            "Preview and atomically delete one exact memory block with "
                + "explicit inbound-reference handling",
        category = "memory",
        supportsSyntheticDryRun = false)
    public Response deleteMemoryBlock(
            @Param(value = "name", source = ParamSource.BODY)
                String name,
            @Param(
                value = "on_inbound_refs",
                source = ParamSource.BODY,
                defaultValue = "error",
                description =
                    "error rejects inbound references; clear deletes them; "
                        + "keep preserves them when the address space survives")
                String onInboundRefs,
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
                MemoryBlockLifecycleCore.DeletePlan plan =
                    threading.executeRead(() -> lifecycle.planDelete(
                        program, name, onInboundRefs, monitor));
                return Response.ok(deleteResult(false, plan));
            }
            return threading.executeWrite(
                program,
                "Delete memory block",
                () -> {
                    MemoryBlockLifecycleCore.DeletePlan plan =
                        lifecycle.planDelete(
                            program, name, onInboundRefs, monitor);
                    monitor.checkCancelled();
                    lifecycle.applyDelete(plan, monitor);
                    return Response.ok(deleteResult(true, plan));
                });
        }
        catch (Exception error) {
            return error("delete memory block", error);
        }
    }

    @McpTool(
        path = "/resize_memory_block",
        method = "POST",
        description =
            "Preview and atomically shrink or grow one exact memory block",
        category = "memory",
        supportsSyntheticDryRun = false)
    public Response resizeMemoryBlock(
            @Param(
                value = "name",
                source = ParamSource.BODY)
                String name,
            @Param(
                value = "new_end",
                source = ParamSource.BODY,
                optional = true,
                paramType = "address")
                String newEnd,
            @Param(
                value = "new_length",
                source = ParamSource.BODY,
                optional = true,
                strictInteger = true)
                Long newLength,
            @Param(
                value = "on_inbound_refs",
                source = ParamSource.BODY,
                defaultValue = "error",
                description =
                    "error rejects inbound references; clear deletes them; "
                        + "keep preserves them")
                String onInboundRefs,
            @Param(
                value = "fill",
                source = ParamSource.BODY,
                optional = true,
                strictInteger = true)
                Integer fill,
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
                strictInteger = true)
                Long fileOffset,
            @Param(
                value = "source_length",
                source = ParamSource.BODY,
                optional = true,
                strictInteger = true)
                Long sourceLength,
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
                MemoryBlockLifecycleCore.ResizePlan plan =
                    threading.executeRead(() -> lifecycle.planResize(
                        program,
                        name,
                        normalizeOptional(newEnd),
                        newLength,
                        onInboundRefs,
                        growSource(
                            fill, normalizeOptionalBytes(bytes), filePath,
                            fileOffset, sourceLength),
                        monitor));
                return Response.ok(resizeResult(false, plan));
            }
            return threading.executeWrite(
                program,
                "Resize memory block",
                () -> {
                    MemoryBlockLifecycleCore.ResizePlan plan =
                        lifecycle.planResize(
                            program,
                            name,
                            normalizeOptional(newEnd),
                            newLength,
                            onInboundRefs,
                            growSource(
                                fill, normalizeOptionalBytes(bytes), filePath,
                                fileOffset, sourceLength),
                            monitor);
                    monitor.checkCancelled();
                    MemoryBlockLifecycleCore.ResizePlan applied =
                        lifecycle.applyResize(plan, monitor);
                    return Response.ok(resizeResult(true, applied));
                });
        }
        catch (Exception error) {
            return error("resize memory block", error);
        }
    }

    @McpTool(
        path = "/patch_bytes",
        method = "POST",
        description =
            "Preview or atomically patch hexadecimal bytes in one initialized "
                + "ordinary or overlay block while preserving annotations",
        category = "memory",
        supportsSyntheticDryRun = false)
    public Response patchBytes(
            @Param(
                value = "address",
                source = ParamSource.BODY,
                paramType = "address")
                String address,
            @Param(
                value = "bytes",
                source = ParamSource.BODY,
                description =
                    "Nonempty hexadecimal bytes; whitespace and one leading "
                        + "0x are accepted; maximum 1048576 bytes")
                String bytes,
            @Param(
                value = "block",
                source = ParamSource.BODY,
                optional = true,
                description =
                    "Exact memory-block name; bare address offsets are "
                        + "interpreted in this block's address space")
                String block,
            @Param(
                value = "clear_code_units",
                source = ParamSource.BODY,
                defaultValue = "true",
                strictBoolean = true,
                description =
                    "Clear complete intersecting code/data units while "
                        + "preserving labels, comments, bookmarks, and "
                        + "user/imported outgoing references")
                boolean clearCodeUnits,
            @Param(
                value = "expected_current",
                source = ParamSource.BODY,
                optional = true,
                description =
                    "Optional hexadecimal compare-and-swap guard with the "
                        + "same decoded length as bytes")
                String expectedCurrent,
            @Param(
                value = "allow_readonly",
                source = ParamSource.BODY,
                defaultValue = "false",
                strictBoolean = true,
                description =
                    "Temporarily enable and then restore write permission")
                boolean allowReadonly,
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
            if (dryRun) {
                PatchBytesCore.Plan plan =
                    threading.executeRead(() -> {
                        Program selected =
                            requireProgram(programName);
                        return patchCore.plan(
                            selected,
                            patchRequest(
                                address, bytes, block,
                                clearCodeUnits, expectedCurrent,
                                allowReadonly),
                            monitor);
                    });
                return Response.ok(
                    patchResult(plan, true, false));
            }
            Program transactionProgram =
                requireProgram(programName);
            return threading.executeWrite(
                transactionProgram,
                "Patch program bytes",
                () -> {
                    Program selected =
                        requireProgram(programName);
                    if (selected != transactionProgram) {
                        throw new IllegalStateException(
                            "selected program changed before patch transaction");
                    }
                    PatchBytesCore.Plan plan = patchCore.plan(
                        selected,
                        patchRequest(
                            address, bytes, block,
                            clearCodeUnits, expectedCurrent,
                            allowReadonly),
                        monitor);
                    patchCore.apply(selected, plan, monitor);
                    return Response.ok(
                        patchResult(plan, false, true));
                });
        }
        catch (Exception error) {
            if (error.getMessage() != null
                    && error.getMessage().startsWith(
                        "expected_current mismatch at offset ")) {
                return Response.err(error.getMessage());
            }
            return error("patch bytes", error);
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

    private MemoryBlockLifecycleCore.GrowSource growSource(
            Integer fill,
            Object bytes,
            String filePath,
            Long fileOffset,
            Long sourceLength) {
        boolean hasFile = filePath != null && !filePath.isBlank();
        int count = (fill != null ? 1 : 0)
            + (bytes != null ? 1 : 0)
            + (hasFile ? 1 : 0);
        if (count == 0) {
            if ((fileOffset != null && fileOffset != 0)
                    || sourceLength != null) {
                throw new IllegalArgumentException(
                    "file_offset and source_length are valid only with "
                        + "file_path");
            }
            return null;
        }
        if (count != 1) {
            throw new IllegalArgumentException(
                "grow requires exactly one of fill, bytes, or file_path");
        }
        if (fill != null) {
            if ((fileOffset != null && fileOffset != 0)
                    || sourceLength != null) {
                throw new IllegalArgumentException(
                    "file_offset and source_length are valid only with "
                        + "file_path");
            }
            return MemoryBlockLifecycleCore.fillSource(fill);
        }
        if (bytes != null) {
            if ((fileOffset != null && fileOffset != 0)
                    || sourceLength != null) {
                throw new IllegalArgumentException(
                    "file_offset and source_length are valid only with "
                        + "file_path");
            }
            return MemoryBlockLifecycleCore.bytesSource(
                MemoryBlockCore.decodeBytes(bytes), "bytes");
        }
        if (fileOffset != null && fileOffset != 0) {
            throw new IllegalArgumentException(
                "resize file_offset must be zero");
        }
        if (sourceLength == null) {
            throw new IllegalArgumentException(
                "source_length is required with file_path");
        }
        Path resolved = security.resolveWithinFileRoot(filePath);
        if (resolved == null) {
            throw new IllegalArgumentException(
                "file_path is outside GHIDRA_MCP_FILE_ROOT: " + filePath);
        }
        byte[] selected = MemoryBlockCore.readFileSource(
            resolved,
            0,
            sourceLength,
            security.hasFileRoot()
                ? security::readFileRangeWithinRoot
                : fileReader);
        return MemoryBlockLifecycleCore.bytesSource(selected, "file");
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

    private static PatchBytesCore.Request patchRequest(
            String address,
            String bytes,
            String block,
            boolean clearCodeUnits,
            String expectedCurrent,
            boolean allowReadonly) {
        byte[] payload =
            PatchBytesCore.decodeHex(bytes, "bytes");
        byte[] expected = expectedCurrent == null
            ? null
            : PatchBytesCore.decodeHex(
                expectedCurrent, "expected_current");
        return new PatchBytesCore.Request(
            address,
            block,
            payload,
            expected,
            clearCodeUnits,
            allowReadonly);
    }

    static JsonObject patchResult(
            PatchBytesCore.Plan plan,
            boolean dryRun,
            boolean committed) {
        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("address", plan.start().toString());
        result.addProperty(
            "address_space",
            plan.start().getAddressSpace().getName());
        result.addProperty("length", plan.payload().length);
        result.addProperty("block", plan.block().getName());
        result.add(
            "cleared_code_units",
            codeUnitsJson(plan.clearPlan().units()));
        result.add(
            "removed_functions",
            functionsJson(plan.clearPlan().functions()));
        result.addProperty(
            "original_write", plan.originalWrite());
        result.addProperty(
            "temporary_write_enabled",
            plan.temporaryWriteEnabled());
        result.addProperty("dry_run", dryRun);
        result.addProperty("committed", committed);

        PatchBytesCore.PayloadSummary summary =
            PatchBytesCore.summarize(
                plan.previous(), plan.payload(), dryRun);
        addOptional(result, "previous", summary.previous());
        addOptional(result, "written", summary.written());
        addOptional(
            result, "previous_sha256",
            summary.previousSha256());
        addOptional(
            result, "written_sha256",
            summary.writtenSha256());
        addOptional(
            result, "previous_first",
            summary.previousFirst());
        addOptional(
            result, "previous_last",
            summary.previousLast());
        addOptional(
            result, "written_first",
            summary.writtenFirst());
        addOptional(
            result, "written_last",
            summary.writtenLast());
        return result;
    }

    private static JsonArray codeUnitsJson(
            List<ListingClearCore.CodeUnitSnapshot> units) {
        JsonArray result = new JsonArray();
        List<ListingClearCore.CodeUnitSnapshot> ordered =
            units.stream()
                .sorted(java.util.Comparator.comparing(
                    ListingClearCore.CodeUnitSnapshot::start)
                    .thenComparing(
                        ListingClearCore.CodeUnitSnapshot::end)
                    .thenComparing(
                        unit -> unit.kind().name()))
                .toList();
        for (ListingClearCore.CodeUnitSnapshot unit : ordered) {
            JsonObject item = new JsonObject();
            item.addProperty(
                "kind",
                unit.kind() == ListingClearCore.UnitKind.INSTRUCTION
                    ? "instruction" : "data");
            item.addProperty("start", unit.start().toString());
            item.addProperty("end", unit.end().toString());
            item.addProperty(
                "length",
                unit.end().subtract(unit.start()) + 1L);
            result.add(item);
        }
        return result;
    }

    private static JsonArray functionsJson(
            List<ListingClearCore.FunctionSnapshot> functions) {
        JsonArray result = new JsonArray();
        List<ListingClearCore.FunctionSnapshot> ordered =
            functions.stream()
                .sorted(java.util.Comparator.comparing(
                    ListingClearCore.FunctionSnapshot::entry)
                    .thenComparing(
                        ListingClearCore.FunctionSnapshot::name))
                .toList();
        for (ListingClearCore.FunctionSnapshot function : ordered) {
            JsonObject item = new JsonObject();
            item.addProperty("entry", function.entry().toString());
            item.addProperty("name", function.name());
            result.add(item);
        }
        return result;
    }

    private static void addOptional(
            JsonObject target, String name, String value) {
        if (value != null) {
            target.addProperty(name, value);
        }
    }

    private static JsonObject deleteResult(
            boolean committed,
            MemoryBlockLifecycleCore.DeletePlan plan) {
        JsonObject result = new JsonObject();
        result.addProperty("committed", committed);
        result.add("before", descriptorJson(plan.before()));
        result.add("after", JsonNull.INSTANCE);
        result.addProperty("changed", true);
        result.addProperty("on_inbound_refs", plan.policy().wireName());
        result.addProperty("overlay", plan.overlay());
        result.addProperty(
            "overlay_space_predicted",
            plan.overlay()
                ? plan.overlaySpaceRemoved() ? "removed" : "retained"
                : "not_applicable");
        if (committed) {
            result.addProperty(
                "overlay_space_observed",
                plan.overlay()
                    ? plan.overlaySpaceRemoved() ? "removed" : "retained"
                    : "not_applicable");
        }
        else {
            result.add("overlay_space_observed", JsonNull.INSTANCE);
        }
        addCollateral(result, plan.collateral());
        return result;
    }

    private static JsonObject resizeResult(
            boolean committed,
            MemoryBlockLifecycleCore.ResizePlan plan) {
        JsonObject result = new JsonObject();
        result.addProperty("committed", committed);
        result.addProperty(
            "operation", plan.kind().name().toLowerCase());
        result.addProperty("changed", true);
        result.addProperty("on_inbound_refs", plan.policy().wireName());
        result.add("before", descriptorJson(plan.before()));
        result.add("after", descriptorJson(plan.predicted()));
        if (plan.kind() == MemoryBlockLifecycleCore.ResizeKind.SHRINK) {
            JsonArray truncated = new JsonArray();
            JsonObject range = new JsonObject();
            addRange(range, plan.changedRange());
            addCollateral(range, plan.collateral());
            truncated.add(range);
            result.add("truncated_ranges", truncated);
            result.add("added_ranges", new JsonArray());
        }
        else {
            JsonArray added = new JsonArray();
            JsonObject range = new JsonObject();
            addRange(range, plan.changedRange());
            range.addProperty("source_kind", plan.growSource().kind());
            range.addProperty("length", plan.changedRange().length());
            range.addProperty(
                "sha256",
                MemoryBlockCore.sha256(plan.growSource().bytes()));
            added.add(range);
            result.add("added_ranges", added);
            result.add("truncated_ranges", new JsonArray());
        }
        return result;
    }

    private static void addCollateral(
            JsonObject result,
            MemoryBlockLifecycleCore.Collateral collateral) {
        result.add("counts", collateralCounts(collateral));
        JsonArray symbols = new JsonArray();
        for (MemoryBlockLifecycleCore.SymbolRecord record
                : collateral.symbols()) {
            JsonObject item = new JsonObject();
            item.addProperty("address", qualified(record.address()));
            item.addProperty("namespace_path", record.namespacePath());
            item.addProperty("name", record.name());
            item.addProperty("symbol_type", record.symbolType());
            item.addProperty("source_type", record.sourceType());
            item.addProperty("primary", record.primary());
            item.addProperty("dynamic", record.dynamic());
            item.addProperty("symbol_id", record.symbolId());
            symbols.add(item);
        }
        result.add("symbols", symbols);
        JsonArray instructions = new JsonArray();
        for (MemoryBlockLifecycleCore.InstructionRecord record
                : collateral.instructions()) {
            JsonObject item = new JsonObject();
            item.addProperty("start", qualified(record.start()));
            item.addProperty("end", qualified(record.end()));
            item.addProperty("mnemonic", record.mnemonic());
            item.addProperty("length", record.length());
            item.addProperty(
                "delay_slot_depth", record.delaySlotDepth());
            instructions.add(item);
        }
        result.add("instructions", instructions);
        JsonArray data = new JsonArray();
        for (MemoryBlockLifecycleCore.DataRecord record
                : collateral.definedData()) {
            JsonObject item = new JsonObject();
            item.addProperty("start", qualified(record.start()));
            item.addProperty("end", qualified(record.end()));
            item.addProperty("datatype_path", record.datatypePath());
            item.addProperty("length", record.length());
            data.add(item);
        }
        result.add("defined_data", data);
        JsonArray comments = new JsonArray();
        for (MemoryBlockLifecycleCore.CommentRecord record
                : collateral.comments()) {
            JsonObject item = new JsonObject();
            item.addProperty("address", qualified(record.address()));
            item.addProperty(
                "comment_type",
                record.type().name().toLowerCase());
            item.addProperty("text", record.text());
            comments.add(item);
        }
        result.add("comments", comments);
        JsonArray bookmarks = new JsonArray();
        for (MemoryBlockLifecycleCore.BookmarkRecord record
                : collateral.bookmarks()) {
            JsonObject item = new JsonObject();
            item.addProperty("address", qualified(record.address()));
            item.addProperty("type", record.type());
            item.addProperty("category", record.category());
            item.addProperty("comment", record.comment());
            item.addProperty("bookmark_id", record.id());
            bookmarks.add(item);
        }
        result.add("bookmarks", bookmarks);
        JsonArray references = new JsonArray();
        for (MemoryBlockLifecycleCore.ReferenceRecord record
                : collateral.inboundReferences()) {
            references.add(referenceJson(record));
        }
        result.add("inbound_references", references);
    }

    private static JsonObject collateralCounts(
            MemoryBlockLifecycleCore.Collateral collateral) {
        JsonObject counts = new JsonObject();
        counts.addProperty("symbols", collateral.symbols().size());
        counts.addProperty(
            "instructions", collateral.instructions().size());
        counts.addProperty(
            "defined_data", collateral.definedData().size());
        JsonObject commentCounts = new JsonObject();
        for (Map.Entry<ghidra.program.model.listing.CommentType, Integer> entry
                : collateral.commentCounts().entrySet()) {
            commentCounts.addProperty(
                entry.getKey().name().toLowerCase(), entry.getValue());
        }
        counts.add("comments", commentCounts);
        counts.addProperty("bookmarks", collateral.bookmarks().size());
        counts.addProperty(
            "inbound_references",
            collateral.inboundReferences().size());
        return counts;
    }

    private static JsonObject referenceJson(
            MemoryBlockLifecycleCore.ReferenceRecord record) {
        JsonObject item = new JsonObject();
        item.addProperty("source", qualified(record.source()));
        item.addProperty("target", qualified(record.target()));
        item.addProperty("reference_type", record.referenceType());
        item.addProperty("source_type", record.sourceType());
        item.addProperty("operand_index", record.operandIndex());
        item.addProperty("primary", record.primary());
        item.addProperty(
            "associated_symbol_id_before",
            record.associatedSymbolIdBefore());
        item.addProperty(
            "associated_symbol_id_after",
            record.associatedSymbolIdAfter());
        item.addProperty(
            "association_cleared", record.associationCleared());
        addNullable(item, "source_block", record.sourceBlock());
        item.addProperty(
            "source_address_space", record.sourceAddressSpace());
        addNullable(item, "target_block", record.targetBlock());
        item.addProperty(
            "target_address_space", record.targetAddressSpace());
        if (record.offsetBase() == null) {
            item.add("offset", JsonNull.INSTANCE);
        }
        else {
            JsonObject offset = new JsonObject();
            offset.addProperty(
                "base_address", qualified(record.offsetBase()));
            offset.addProperty(
                "signed_offset", record.signedOffset());
            item.add("offset", offset);
        }
        if (record.shift() == null) {
            item.add("shifted", JsonNull.INSTANCE);
        }
        else {
            JsonObject shifted = new JsonObject();
            shifted.addProperty(
                "base_value", record.shiftedBaseValue());
            shifted.addProperty("shift", record.shift());
            item.add("shifted", shifted);
        }
        item.addProperty("policy_action", record.policyAction());
        return item;
    }

    private static void addRange(
            JsonObject json, MemoryBlockLifecycleCore.Range range) {
        json.addProperty("start", qualified(range.start()));
        json.addProperty("end", qualified(range.end()));
        json.addProperty("length", range.length());
    }

    private static String qualified(
            ghidra.program.model.address.Address address) {
        return address.getAddressSpace().getName()
            + "::" + address.toString(false);
    }

    private static void addNullable(
            JsonObject json, String name, String value) {
        if (value == null) {
            json.add(name, JsonNull.INSTANCE);
        }
        else {
            json.addProperty(name, value);
        }
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
        json.addProperty("type", descriptor.type());
        json.addProperty("artificial", descriptor.artificial());
        json.addProperty("loaded", descriptor.loaded());
        json.addProperty("source_name", descriptor.sourceName());
        if (descriptor.overlayBaseSpace() == null) {
            json.add("overlay_base_space", JsonNull.INSTANCE);
        }
        else {
            json.addProperty(
                "overlay_base_space", descriptor.overlayBaseSpace());
        }
        JsonArray sourceInfos = new JsonArray();
        for (MemoryBlockCore.SourceInfoDescriptor info
                : descriptor.sourceInfos()) {
            JsonObject item = new JsonObject();
            item.addProperty("min_address", info.minAddress());
            item.addProperty("max_address", info.maxAddress());
            item.addProperty("length", info.length());
            item.addProperty("description", info.description());
            if (info.file() == null) {
                item.add("file", JsonNull.INSTANCE);
            }
            else {
                JsonObject file = new JsonObject();
                file.addProperty("filename", info.file().filename());
                file.addProperty(
                    "imported_file_offset",
                    info.file().importedFileOffset());
                file.addProperty("stored_size", info.file().storedSize());
                item.add("file", file);
            }
            item.addProperty("file_offset", info.fileOffset());
            if (info.mappedRange() == null) {
                item.add("mapped_range", JsonNull.INSTANCE);
            }
            else {
                JsonObject mapped = new JsonObject();
                mapped.addProperty("start", info.mappedRange().start());
                mapped.addProperty("end", info.mappedRange().end());
                item.add("mapped_range", mapped);
            }
            if (info.byteMappingScheme() == null) {
                item.add("byte_mapping_scheme", JsonNull.INSTANCE);
            }
            else {
                item.addProperty(
                    "byte_mapping_scheme", info.byteMappingScheme());
            }
            sourceInfos.add(item);
        }
        json.add("source_infos", sourceInfos);
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
