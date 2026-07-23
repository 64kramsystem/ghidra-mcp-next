package com.xebyte.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import java.io.File;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

import ghidra.app.util.exporter.AsciiExporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Native file export operations.
 *
 * <p>The service delegates listing formatting to Ghidra's {@link AsciiExporter}.
 * It only owns request validation and safe filesystem publication.
 */
@McpToolGroup(value = "export", description = "Native program export")
public final class ExportService {

    interface ExportRunner {
        boolean supportsAddressRestrictedExport();

        boolean export(File file, DomainObject object, AddressSetView selection,
                TaskMonitor monitor) throws ExporterException, IOException;

        String name();

        default String diagnostic() {
            return "";
        }
    }

    static final class AsciiExportRunner implements ExportRunner {
        private final ThreadLocal<String> lastDiagnostic =
            ThreadLocal.withInitial(() -> "");

        @Override
        public boolean supportsAddressRestrictedExport() {
            return new AsciiExporter().supportsAddressRestrictedExport();
        }

        @Override
        public boolean export(File file, DomainObject object, AddressSetView selection,
                TaskMonitor monitor) throws ExporterException, IOException {
            AsciiExporter exporter = new AsciiExporter();
            try {
                return exporter.export(file, object, selection, monitor);
            }
            finally {
                lastDiagnostic.set(exporter.getMessageLog() == null
                    ? ""
                    : exporter.getMessageLog().toString());
            }
        }

        @Override
        public String name() {
            return AsciiExporter.class.getName();
        }

        @Override
        public String diagnostic() {
            return lastDiagnostic.get();
        }
    }

    private final ProgramProvider programProvider;
    private final SecurityConfig security;
    private final ExportRunner runner;

    public ExportService(ProgramProvider programProvider) {
        this(programProvider, SecurityConfig.getInstance());
    }

    ExportService(ProgramProvider programProvider, SecurityConfig security) {
        this(programProvider, security, new AsciiExportRunner());
    }

    ExportService(ProgramProvider programProvider, SecurityConfig security,
            ExportRunner runner) {
        this.programProvider = programProvider;
        this.security = security;
        this.runner = runner;
    }

    @McpTool(path = "/export_ascii_listing", method = "POST",
        description = "Export Ghidra AsciiExporter listing text without running a script",
        category = "export")
    public Response exportAsciiListing(
            @Param(value = "output_path", source = ParamSource.BODY,
                description = "Destination filesystem path") String outputPath,
            @Param(value = "start", source = ParamSource.BODY, defaultValue = "",
                paramType = "address",
                description = "Inclusive start address; must be supplied with end") String start,
            @Param(value = "end", source = ParamSource.BODY, defaultValue = "",
                paramType = "address",
                description = "Inclusive end address; must be supplied with start") String end,
            @Param(value = "overwrite", source = ParamSource.BODY,
                defaultValue = "false",
                description = "Replace an existing destination after successful export")
                boolean overwrite,
            @Param(value = "program", defaultValue = "",
                description = "Target program name (omit to use the active program)")
                String programName) {
        return export(programName, outputPath, normalizeOptional(start),
            normalizeOptional(end), overwrite);
    }

    private Response export(String programName, String outputPath, String start,
            String end, boolean overwrite) {
        if (outputPath == null || outputPath.isBlank()) {
            return Response.err("output_path is required");
        }

        Program program = programProvider.resolveProgram(programName);
        if (program == null) {
            return Response.err(programName == null || programName.isBlank()
                ? "No program currently loaded"
                : "Program not found: " + programName);
        }

        boolean hasStart = start != null;
        boolean hasEnd = end != null;
        if (hasStart != hasEnd) {
            return Response.err("start and end must be supplied together");
        }

        AddressSetView selection;
        if (hasStart) {
            Address startAddress = ServiceUtils.parseAddress(program, start);
            if (startAddress == null) {
                return Response.err("Invalid start address: " + usefulParseError(start));
            }
            Address endAddress = ServiceUtils.parseAddress(program, end);
            if (endAddress == null) {
                return Response.err("Invalid end address: " + usefulParseError(end));
            }
            if (!startAddress.getAddressSpace().equals(endAddress.getAddressSpace())) {
                return Response.err("start and end must be in the same address space");
            }
            if (startAddress.compareTo(endAddress) > 0) {
                return Response.err("start must not be after end");
            }
            if (!runner.supportsAddressRestrictedExport()) {
                return Response.err(runner.name()
                    + " does not support address-restricted export");
            }
            selection = new AddressSet(startAddress, endAddress);
        }
        else {
            selection = program.getMemory();
        }

        Path destination = security.resolveWithinFileRoot(outputPath);
        if (destination == null) {
            return Response.err(
                "output_path is outside GHIDRA_MCP_FILE_ROOT: " + outputPath);
        }

        Path parent = destination.getParent();
        if (parent == null || !Files.exists(parent)) {
            return Response.err("destination parent directory does not exist: " + parent);
        }
        if (!Files.isDirectory(parent)) {
            return Response.err("destination parent is not a directory: " + parent);
        }
        if (Files.exists(destination) && !overwrite) {
            return Response.err("destination already exists; set overwrite=true to replace it: "
                + destination);
        }

        Path temporary = siblingTemporaryPath(destination);
        try {
            Files.createFile(temporary);
            boolean exported = runner.export(temporary.toFile(), program, selection,
                TaskMonitor.DUMMY);
            if (!exported) {
                return Response.err(exportFailureMessage(
                    runner.name() + " returned false", runner.diagnostic()));
            }

            // Re-check after the potentially long export so an unauthorized
            // concurrent creator is not silently replaced at publication time.
            if (!overwrite && Files.exists(destination)) {
                throw new FileAlreadyExistsException(destination.toString());
            }
            publish(temporary, destination, overwrite);
            return Response.ok(exportResult(
                program, destination, start, end, selection, runner.name()));
        }
        catch (FileAlreadyExistsException e) {
            return Response.err("destination already exists; set overwrite=true to replace it: "
                + destination);
        }
        catch (ExporterException | IOException | RuntimeException e) {
            String message = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err(exportFailureMessage(message, runner.diagnostic()));
        }
        finally {
            try {
                Files.deleteIfExists(temporary);
            }
            catch (IOException ignored) {
                // Best-effort cleanup; the destination is never reported as successful
                // unless publication itself completed.
            }
        }
    }

    private static String normalizeOptional(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private static String usefulParseError(String requested) {
        String detail = ServiceUtils.getLastParseError();
        return detail != null && !detail.isBlank() ? detail : requested;
    }

    private static Path siblingTemporaryPath(Path destination) {
        String name = destination.getFileName().toString();
        return destination.resolveSibling("." + name + ".tmp-" + UUID.randomUUID());
    }

    private static void publish(Path temporary, Path destination, boolean overwrite)
            throws IOException {
        try {
            if (overwrite) {
                Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            }
            else {
                Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE);
            }
        }
        catch (AtomicMoveNotSupportedException e) {
            if (overwrite) {
                Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING);
            }
            else {
                Files.move(temporary, destination);
            }
        }
    }

    private static JsonObject exportResult(Program program, Path destination,
            String requestedStart, String requestedEnd, AddressSetView selection,
            String exporterName) throws IOException {
        JsonObject result = new JsonObject();
        result.addProperty("program", program.getName());
        result.addProperty("output_path", destination.toString());
        if (requestedStart != null) {
            result.addProperty("start", requestedStart);
        }
        else {
            result.add("start", JsonNull.INSTANCE);
        }
        if (requestedEnd != null) {
            result.addProperty("end", requestedEnd);
        }
        else {
            result.add("end", JsonNull.INSTANCE);
        }
        result.add("ranges", ranges(selection));
        result.addProperty("bytes_written", Files.size(destination));
        result.addProperty("exporter", exporterName);
        return result;
    }

    private static JsonArray ranges(AddressSetView selection) {
        JsonArray result = new JsonArray();
        for (AddressRange range : selection) {
            JsonObject item = new JsonObject();
            item.addProperty("start", range.getMinAddress().toString());
            item.addProperty("end", range.getMaxAddress().toString());
            result.add(item);
        }
        return result;
    }

    private static String exportFailureMessage(String primary, String diagnostic) {
        if (diagnostic == null || diagnostic.isBlank()) {
            return primary;
        }
        return primary + ": " + diagnostic.strip();
    }
}
