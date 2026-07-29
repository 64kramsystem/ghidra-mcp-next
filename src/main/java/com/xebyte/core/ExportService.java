package com.xebyte.core;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

import ghidra.app.util.exporter.AsciiExporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.app.util.exporter.XmlExporter;
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
@McpToolGroup(value = "export", description = "Native program and project export")
public final class ExportService {

    private static final Gson OUTPUT_GSON = new Gson();
    private static final Object XML_EXPORT_LOCK = new Object();

    interface ExportRunner {
        boolean supportsAddressRestrictedExport();

        boolean export(File file, DomainObject object, AddressSetView selection,
                TaskMonitor monitor) throws ExporterException, IOException;

        String name();

        default String diagnostic() {
            return "";
        }

        /**
         * Extra result fields describing what this runner emitted.
         */
        default Map<String, Object> report() {
            return Map.of();
        }
    }

    @FunctionalInterface
    interface AtomicReplace {
        void move(Path source, Path target) throws IOException;
    }

    @FunctionalInterface
    interface TempUnlink {
        void deleteIfExists(Path path) throws IOException;
    }

    @FunctionalInterface
    interface ResultFactory {
        Response.Ok build(Program program, Path destination, String requestedStart,
                String requestedEnd, AddressSetView selection, long bytesWritten,
                String exporterName) throws IOException;
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

    /**
     * Exports Ghidra's complete, re-importable program XML rather than a database copy.
     *
     * <p>The native exporter's defaults include memory blocks and contents, instructions,
     * data, symbols, equates, comments, properties, bookmarks, trees, references, functions,
     * register values, relocations, entry points, and external libraries.</p>
     */
    static final class XmlExportRunner implements ExportRunner {
        private final ThreadLocal<String> lastDiagnostic =
            ThreadLocal.withInitial(() -> "");
        private final ThreadLocal<Map<String, Object>> lastReport =
            ThreadLocal.withInitial(Map::of);

        @Override
        public boolean supportsAddressRestrictedExport() {
            return false;
        }

        @Override
        public boolean export(File file, DomainObject object, AddressSetView selection,
                TaskMonitor monitor) throws ExporterException, IOException {
            lastDiagnostic.set("");
            lastReport.set(Map.of());
            Program program = (Program) object;
            XmlExporter exporter = new XmlExporter();
            long modificationNumber = program.getModificationNumber();
            try {
                boolean exported = exporter.export(file, object, selection, monitor);
                String diagnostic = exporter.getMessageLog() == null
                    ? ""
                    : exporter.getMessageLog().toString();
                lastDiagnostic.set(diagnostic);
                lastReport.set(diagnostic.isBlank()
                    ? Map.of()
                    : Map.of("message_log", diagnostic.strip()));
                if (program.getModificationNumber() != modificationNumber) {
                    lastDiagnostic.set("program changed during export; nothing was published");
                    return false;
                }
                return exported;
            }
            finally {
                if (lastDiagnostic.get().isEmpty() && exporter.getMessageLog() != null) {
                    lastDiagnostic.set(exporter.getMessageLog().toString());
                }
            }
        }

        @Override
        public String name() {
            return XmlExporter.class.getName();
        }

        @Override
        public String diagnostic() {
            return lastDiagnostic.get();
        }

        @Override
        public Map<String, Object> report() {
            return lastReport.get();
        }
    }

    /**
     * Writes a listing with no clip step and no ceilings, unlike {@link AsciiExporter}.
     * See {@link CompleteListingWriter} for what that exporter loses and why.
     */
    static final class CompleteListingRunner implements ExportRunner {
        private final int xrefWrapColumn;
        private final ThreadLocal<String> lastDiagnostic =
            ThreadLocal.withInitial(() -> "");
        private final ThreadLocal<Map<String, Object>> lastReport =
            ThreadLocal.withInitial(Map::of);

        CompleteListingRunner(int xrefWrapColumn) {
            this.xrefWrapColumn = xrefWrapColumn;
        }

        @Override
        public boolean supportsAddressRestrictedExport() {
            return true;
        }

        @Override
        public boolean export(File file, DomainObject object, AddressSetView selection,
                TaskMonitor monitor) throws IOException {
            if (!(object instanceof Program program)) {
                lastDiagnostic.set("unsupported domain object: " + object.getClass().getName());
                return false;
            }
            lastDiagnostic.set("");
            // Pinned before any model read, as ListingRangeService does for a paged read. The
            // walk takes no read lock, so an edit landing mid-walk would otherwise publish a
            // listing stitched from two states of the program, with every counter agreeing
            // because the records it never saw are also never counted.
            long modificationNumber = program.getModificationNumber();
            CompleteListingWriter writer =
                new CompleteListingWriter(program, xrefWrapColumn);
            try (PrintWriter out = new PrintWriter(
                    Files.newBufferedWriter(file.toPath()))) {
                writer.write(out, selection);
                out.flush();
                // PrintWriter swallows IOExceptions. Without this a failed write publishes a
                // truncated file while every completeness counter still agrees.
                if (out.checkError()) {
                    lastDiagnostic.set("writing " + file + " failed");
                    return false;
                }
            }
            catch (CompleteListingWriter.IncompleteListingException e) {
                lastDiagnostic.set(e.getMessage());
                return false;
            }
            // Read back what was actually written: the counters only prove a record reached a
            // renderer, so the comment bodies are checked against the file itself.
            String shortfall;
            try (java.util.stream.Stream<String> written = Files.lines(file.toPath())) {
                shortfall = writer.shortfall(written);
            }
            if (shortfall != null) {
                lastDiagnostic.set(shortfall);
                return false;
            }
            if (program.getModificationNumber() != modificationNumber) {
                lastDiagnostic.set("program changed during export; nothing was published");
                return false;
            }
            lastReport.set(writer.report());
            return true;
        }

        @Override
        public String name() {
            return CompleteListingWriter.class.getName();
        }

        @Override
        public String diagnostic() {
            return lastDiagnostic.get();
        }

        @Override
        public Map<String, Object> report() {
            return lastReport.get();
        }
    }

    private final ProgramProvider programProvider;
    private final SecurityConfig security;
    private final ExportRunner runner;
    private final ExportRunner xmlRunner;
    private final ResultFactory resultFactory;

    public ExportService(ProgramProvider programProvider) {
        this(programProvider, SecurityConfig.getInstance());
    }

    ExportService(ProgramProvider programProvider, SecurityConfig security) {
        this(programProvider, security, new AsciiExportRunner(), new XmlExportRunner(),
            ExportService::buildExportResult);
    }

    ExportService(ProgramProvider programProvider, SecurityConfig security,
            ExportRunner runner) {
        this(programProvider, security, runner, new XmlExportRunner(),
            ExportService::buildExportResult);
    }

    ExportService(ProgramProvider programProvider, SecurityConfig security,
            ExportRunner runner, ResultFactory resultFactory) {
        this(programProvider, security, runner, new XmlExportRunner(), resultFactory);
    }

    ExportService(ProgramProvider programProvider, SecurityConfig security,
            ExportRunner runner, ExportRunner xmlRunner, ResultFactory resultFactory) {
        this.programProvider = programProvider;
        this.security = security;
        this.runner = runner;
        this.xmlRunner = xmlRunner;
        this.resultFactory = resultFactory;
    }

    @McpTool(path = "/export_ascii_listing", method = "POST",
        description = "Export Ghidra AsciiExporter listing text without running a script",
        category = "export", supportsDryRun = false)
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
        return export(runner, programName, outputPath, normalizeOptional(start),
            normalizeOptional(end), overwrite);
    }

    @McpTool(path = "/export_full_listing", method = "POST",
        description = "Export a complete listing that drops nothing. Unlike "
            + "export_ascii_listing, which delegates to Ghidra's AsciiExporter, this clips no "
            + "field, emits every line of every comment rather than the first six, and emits "
            + "every cross-reference rather than the first twenty-one. Columns are minimum "
            + "widths, so long operands push the comment column right instead of being "
            + "shortened, and authored newlines in comments are never re-flowed. Structures and "
            + "arrays are traversed, so field names, component types and values appear indented "
            + "under their parent. The export fails without publishing if it cannot emit "
            + "everything it collected: comment bodies and references are checked against the "
            + "written file, and a program edit landing mid-export fails it too.",
        category = "export", supportsDryRun = false)
    public Response exportFullListing(
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
            @Param(value = "xref_wrap_column", source = ParamSource.BODY,
                defaultValue = "100",
                description = "Column at which the cross-reference list wraps (40..500). "
                    + "Wrapping never drops a reference")
                int xrefWrapColumn,
            @Param(value = "program", defaultValue = "",
                description = "Target program name (omit to use the active program)")
                String programName) {
        if (xrefWrapColumn < 40 || xrefWrapColumn > 500) {
            return Response.err("xref_wrap_column must be between 40 and 500");
        }
        return export(new CompleteListingRunner(xrefWrapColumn), programName, outputPath,
            normalizeOptional(start), normalizeOptional(end), overwrite);
    }

    @McpTool(path = "/export_program_xml", method = "POST",
        description = "Export native Ghidra program XML and its required memory-bytes "
            + "sidecar for logical re-import. The native XML format includes memory, "
            + "code/data, symbols, comments, references, entry points, register values, "
            + "relocations, properties, bookmarks, and trees, subject to Ghidra XML "
            + "format limitations.",
        category = "export", supportsDryRun = false)
    public Response exportProgramXml(
            @Param(value = "output_path", source = ParamSource.BODY,
                description = "Destination filesystem path") String outputPath,
            @Param(value = "overwrite", source = ParamSource.BODY,
                defaultValue = "false",
                description = "Replace both an existing lowercase-.xml destination and "
                    + "its same-stem .bytes sidecar after successful export")
                boolean overwrite,
            @Param(value = "program", defaultValue = "",
                description = "Target program name (omit to use the active program)")
                String programName) {
        return exportXmlPair(programName, outputPath, overwrite);
    }

    private Response exportXmlPair(String programName, String outputPath,
            boolean overwrite) {
        if (outputPath == null || outputPath.isBlank()) {
            return Response.err("output_path is required");
        }

        Program program = programProvider.resolveProgram(programName);
        if (program == null) {
            return Response.err(programName == null || programName.isBlank()
                ? "No program currently loaded"
                : "Program not found: " + programName);
        }

        Path destination = security.resolveWithinFileRoot(outputPath);
        if (destination == null) {
            return Response.err(
                "output_path is outside GHIDRA_MCP_FILE_ROOT: " + outputPath);
        }
        if (destination.getFileName() == null ||
                !destination.getFileName().toString().endsWith(".xml")) {
            return Response.err("resolved output_path must end with lowercase .xml");
        }
        Path parent = destination.getParent();
        if (parent == null || !Files.exists(parent)) {
            return Response.err("destination parent directory does not exist: " + parent);
        }
        if (!Files.isDirectory(parent)) {
            return Response.err("destination parent is not a directory: " + parent);
        }

        synchronized (XML_EXPORT_LOCK) {
            return exportXmlPairLocked(
                program, destination, xmlSidecar(destination), overwrite);
        }
    }

    private Response exportXmlPairLocked(Program program, Path destination,
            Path sidecar, boolean overwrite) {
        if (!overwrite && (Files.exists(destination) || Files.exists(sidecar))) {
            return Response.err("destination XML or bytes sidecar already exists; "
                + "set overwrite=true to replace both: " + destination);
        }

        Path temporaryDirectory =
            destination.getParent().resolve(".xml-export-" + UUID.randomUUID());
        Path temporaryXml = temporaryDirectory.resolve(destination.getFileName());
        Path temporaryBytes = xmlSidecar(temporaryXml);
        Path bytesBackup = temporaryDirectory.resolve(".previous.bytes");
        try {
            Files.createDirectory(temporaryDirectory);
            boolean exported = xmlRunner.export(
                temporaryXml.toFile(), program, program.getMemory(), TaskMonitor.DUMMY);
            if (!exported) {
                return Response.err(exportFailureMessage(
                    xmlRunner.name() + " returned false", xmlRunner.diagnostic()));
            }
            if (!Files.isRegularFile(temporaryXml) ||
                    !Files.isRegularFile(temporaryBytes)) {
                return Response.err("Ghidra XML export did not produce both .xml and "
                    + ".bytes files");
            }

            if (!hasXmlClosingTag(temporaryXml)) {
                return Response.err(
                    "Ghidra XML export is incomplete; closing </PROGRAM> is absent");
            }

            long xmlBytes = Files.size(temporaryXml);
            long memoryBytes = Files.size(temporaryBytes);
            Response.Ok result = resultFactory.build(program, destination, null, null,
                program.getMemory(), xmlBytes + memoryBytes, xmlRunner.name());
            if (result.data() instanceof JsonObject data) {
                data.addProperty("sidecar_path", sidecar.toString());
                data.addProperty("xml_bytes", xmlBytes);
                data.addProperty("memory_bytes", memoryBytes);
            }
            mergeReport(result, xmlRunner.report());

            publishXmlPair(temporaryXml, temporaryBytes, destination, sidecar,
                bytesBackup, overwrite, (source, target) ->
                    Files.move(source, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING));
            return result;
        }
        catch (FileAlreadyExistsException e) {
            return Response.err("destination XML or bytes sidecar already exists; "
                + "set overwrite=true to replace both: " + destination);
        }
        catch (ExporterException | IOException | RuntimeException e) {
            String message = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err(exportFailureMessage(message, xmlRunner.diagnostic()));
        }
        finally {
            deleteTreeBestEffort(temporaryDirectory);
        }
    }

    static void publishXmlPair(Path temporaryXml, Path temporaryBytes,
            Path destination, Path sidecar, Path bytesBackup, boolean overwrite,
            AtomicReplace atomicReplace) throws IOException {
        boolean hadPreviousBytes = false;
        if (overwrite && Files.exists(sidecar)) {
            Files.move(sidecar, bytesBackup, StandardCopyOption.ATOMIC_MOVE);
            hadPreviousBytes = true;
        }
        try {
            publish(temporaryBytes, sidecar, overwrite, atomicReplace);
            try {
                publish(temporaryXml, destination, overwrite, atomicReplace);
            }
            catch (IOException | RuntimeException e) {
                if (hadPreviousBytes) {
                    Files.move(bytesBackup, sidecar, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
                }
                else {
                    Files.deleteIfExists(sidecar);
                }
                throw e;
            }
        }
        catch (IOException | RuntimeException e) {
            if (hadPreviousBytes && Files.exists(bytesBackup) &&
                    !Files.exists(sidecar)) {
                Files.move(bytesBackup, sidecar, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            }
            throw e;
        }
    }

    private static boolean hasXmlClosingTag(Path xml) throws IOException {
        long size = Files.size(xml);
        int window = (int) Math.min(size, 256);
        ByteBuffer buffer = ByteBuffer.allocate(window);
        try (SeekableByteChannel channel = Files.newByteChannel(xml)) {
            channel.position(size - window);
            while (buffer.hasRemaining() && channel.read(buffer) >= 0) {
                // Read the bounded tail completely.
            }
        }
        String tail = new String(buffer.array(), 0, buffer.position(),
            StandardCharsets.UTF_8).stripTrailing();
        return tail.endsWith("</PROGRAM>");
    }

    private static void deleteTreeBestEffort(Path directory) {
        if (!Files.exists(directory)) {
            return;
        }
        try (var paths = Files.walk(directory)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                }
                catch (IOException ignored) {
                    // Continue removing the rest of a private export directory.
                }
            });
        }
        catch (IOException ignored) {
            // Best effort after a failed export or publication.
        }
    }

    private static Path xmlSidecar(Path xmlPath) {
        String name = xmlPath.getFileName().toString();
        return xmlPath.resolveSibling(
            name.substring(0, name.length() - ".xml".length()) + ".bytes");
    }

    private Response export(ExportRunner runner, String programName, String outputPath,
            String start, String end, boolean overwrite) {
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
            AddressSet boundedSelection = new AddressSet(startAddress, endAddress);
            if (!program.getMemory().contains(boundedSelection)) {
                return Response.err(
                    "bounded export range must be entirely contained in program memory");
            }
            if (!runner.supportsAddressRestrictedExport()) {
                return Response.err(runner.name()
                    + " does not support address-restricted export");
            }
            selection = boundedSelection;
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
        boolean published = false;
        try {
            Files.createFile(temporary);
            boolean exported = runner.export(temporary.toFile(), program, selection,
                TaskMonitor.DUMMY);
            if (!exported) {
                return Response.err(exportFailureMessage(
                    runner.name() + " returned false", runner.diagnostic()));
            }

            long bytesWritten = Files.size(temporary);
            Response.Ok result = resultFactory.build(program, destination, start, end,
                selection, bytesWritten, runner.name());
            mergeReport(result, runner.report());
            publish(temporary, destination, overwrite);
            published = true;
            return result;
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
            if (!published) {
                try {
                    Files.deleteIfExists(temporary);
                }
                catch (IOException ignored) {
                    // Best-effort cleanup after a failed export or publication.
                }
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

    static Path siblingTemporaryPath(Path destination) {
        String name = destination.getFileName().toString();
        return destination.resolveSibling("." + name + ".tmp-" + UUID.randomUUID());
    }

    static void publish(Path temporary, Path destination, boolean overwrite)
            throws IOException {
        publish(temporary, destination, overwrite, (source, target) ->
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING),
            path -> Files.deleteIfExists(path));
    }

    static void publish(Path temporary, Path destination, boolean overwrite,
            AtomicReplace atomicReplace) throws IOException {
        publish(temporary, destination, overwrite, atomicReplace,
            path -> Files.deleteIfExists(path));
    }

    static void publish(Path temporary, Path destination, boolean overwrite,
            AtomicReplace atomicReplace, TempUnlink tempUnlink) throws IOException {
        if (!overwrite) {
            try {
                // createLink is an atomic fail-if-present publication primitive:
                // the complete sibling temp becomes visible at destination only
                // when destination does not already exist.
                Files.createLink(destination, temporary);
            }
            catch (UnsupportedOperationException e) {
                throw new IOException(
                    "safe no-overwrite publication is not supported by this filesystem", e);
            }
            try {
                tempUnlink.deleteIfExists(temporary);
            }
            catch (IOException firstFailure) {
                try {
                    tempUnlink.deleteIfExists(temporary);
                }
                catch (IOException ignored) {
                    // Destination already names the complete file. Cleanup is
                    // best-effort and has now been attempted twice.
                }
            }
            return;
        }

        atomicReplace.move(temporary, destination);
    }

    static Response.Ok buildExportResult(Program program, Path destination,
            String requestedStart, String requestedEnd, AddressSetView selection,
            long bytesWritten, String exporterName) {
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
        result.addProperty("bytes_written", bytesWritten);
        result.addProperty("exporter", exporterName);
        return new Response.Ok(result);
    }

    /**
     * Adds a runner's own result fields to a built payload. Runners that delegate to a Ghidra
     * exporter report nothing, so their payload is untouched.
     */
    private static void mergeReport(Response.Ok result, Map<String, Object> report) {
        if (report.isEmpty() || !(result.data() instanceof JsonObject data)) {
            return;
        }
        for (Map.Entry<String, Object> entry : report.entrySet()) {
            data.add(entry.getKey(), OUTPUT_GSON.toJsonTree(entry.getValue()));
        }
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
