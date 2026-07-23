package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

public class ExportServiceTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private Program program;
    private ProgramProvider provider;
    private SecurityConfig security;
    private Memory memory;

    @Before
    public void setUp() throws Exception {
        GenericAddressSpace ram = new GenericAddressSpace(
            "ram", 32, 1, AddressSpace.TYPE_RAM);
        AddressFactory factory = new DefaultAddressFactory(
            new AddressSpace[] {ram}, ram);

        program = mock(Program.class);
        memory = mock(Memory.class);
        when(program.getName()).thenReturn("fixture");
        when(program.getAddressFactory()).thenReturn(factory);
        when(program.getMemory()).thenReturn(memory);
        var memoryRange = new ghidra.program.model.address.AddressSet(
            ram.getAddress(0x1000), ram.getAddress(0x103f));
        when(memory.iterator()).thenAnswer(invocation -> memoryRange.iterator());
        when(memory.contains(any(AddressSetView.class))).thenAnswer(invocation ->
            memoryRange.contains(invocation.getArgument(0, AddressSetView.class)));

        provider = mock(ProgramProvider.class);
        when(provider.resolveProgram("fixture")).thenReturn(program);

        security = mock(SecurityConfig.class);
        when(security.resolveWithinFileRoot(anyString())).thenAnswer(invocation ->
            new File(invocation.getArgument(0, String.class)).getCanonicalFile().toPath());
    }

    @Test
    public void boundedExportPublishesOnlyAfterExporterSuccess() throws Exception {
        Path outputDir = temporaryFolder.newFolder("bounded").toPath();
        Path destination = outputDir.resolve("listing.asm");
        RecordingExportRunner runner =
            new RecordingExportRunner("expected\n", true, Outcome.SUCCESS);

        Response response = service(runner).exportAsciiListing(
            destination.toString(), "ram:1000", "ram:1003", false, "fixture");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertEquals("expected\n", Files.readString(destination));
        assertEquals("00001000", runner.requestedSet().getMinAddress().toString());
        assertEquals("00001003", runner.requestedSet().getMaxAddress().toString());
        assertFalse("destination must not exist while exporter is writing",
            runner.destinationExistedDuringExport());
        assertTrue("exporter must write a unique sibling temporary file",
            runner.exportFile().getParentFile().equals(outputDir.toFile())
                && runner.exportFile().getName().startsWith(".listing.asm.tmp-"));
        assertNoTemporaryFiles(outputDir);

        Map<String, Object> result = result(response);
        assertEquals("fixture", result.get("program"));
        assertEquals(destination.toFile().getCanonicalPath(), result.get("output_path"));
        assertEquals("ram:1000", result.get("start"));
        assertEquals("ram:1003", result.get("end"));
        assertEquals((double) Files.size(destination), result.get("bytes_written"));
        assertEquals("test.ExportRunner", result.get("exporter"));
        assertEquals(List.of(Map.of(
            "start", "00001000",
            "end", "00001003")), result.get("ranges"));
    }

    @Test
    public void wholeProgramExportPassesProgramMemoryAndNullRequestedBounds() throws Exception {
        Path outputDir = temporaryFolder.newFolder("whole").toPath();
        Path destination = outputDir.resolve("listing.asm");
        RecordingExportRunner runner =
            new RecordingExportRunner("whole\n", true, Outcome.SUCCESS);

        Response response = service(runner).exportAsciiListing(
            destination.toString(), null, null, false, "fixture");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertSame(memory, runner.requestedSet());
        com.google.gson.JsonObject data =
            (com.google.gson.JsonObject) ((Response.Ok) response).data();
        assertTrue(data.get("start").isJsonNull());
        assertTrue(data.get("end").isJsonNull());
    }

    @Test
    public void failedOverwritePreservesExistingDestinationAndCleansTemporaryFile()
            throws Exception {
        Path outputDir = temporaryFolder.newFolder("failed-overwrite").toPath();
        Path destination = outputDir.resolve("listing.asm");
        Files.writeString(destination, "old\n");
        RecordingExportRunner runner =
            new RecordingExportRunner("partial\n", true, Outcome.FALSE);

        Response response = service(runner).exportAsciiListing(
            destination.toString(), null, null, true, "fixture");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains("exporter diagnostic"));
        assertEquals("old\n", Files.readString(destination));
        assertNoTemporaryFiles(outputDir);
    }

    @Test
    public void thrownExporterFailurePreservesDestinationAndReturnsDiagnostic()
            throws Exception {
        Path outputDir = temporaryFolder.newFolder("thrown-overwrite").toPath();
        Path destination = outputDir.resolve("listing.asm");
        Files.writeString(destination, "old\n");
        RecordingExportRunner runner =
            new RecordingExportRunner("partial\n", true, Outcome.THROW);

        Response response = service(runner).exportAsciiListing(
            destination.toString(), null, null, true, "fixture");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains("simulated exporter failure"));
        assertEquals("old\n", Files.readString(destination));
        assertNoTemporaryFiles(outputDir);
    }

    @Test
    public void overwriteSuccessAtomicallyReplacesExistingDestination() throws Exception {
        Path outputDir = temporaryFolder.newFolder("successful-overwrite").toPath();
        Path destination = outputDir.resolve("listing.asm");
        Files.writeString(destination, "old\n");
        RecordingExportRunner runner =
            new RecordingExportRunner("new\n", true, Outcome.SUCCESS);

        Response response = service(runner).exportAsciiListing(
            destination.toString(), null, null, true, "fixture");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertEquals("new\n", Files.readString(destination));
        assertTrue("old destination should remain visible until publication",
            runner.destinationExistedDuringExport());
        assertNoTemporaryFiles(outputDir);
    }

    @Test
    public void rejectsDestinationOutsideFileRootBeforeFilesystemAccess() throws Exception {
        Path outputDir = temporaryFolder.newFolder("outside").toPath();
        Path destination = outputDir.resolve("listing.asm");
        when(security.resolveWithinFileRoot(destination.toString())).thenReturn(null);
        RecordingExportRunner runner =
            new RecordingExportRunner("unused\n", true, Outcome.SUCCESS);

        Response response = service(runner).exportAsciiListing(
            destination.toString(), null, null, false, "fixture");

        assertErrorContains(response, "outside GHIDRA_MCP_FILE_ROOT");
        assertFalse(Files.exists(destination));
        assertFalse(runner.wasCalled());
    }

    @Test
    public void rejectsMissingParentAndParentThatIsNotDirectory() throws Exception {
        Path root = temporaryFolder.newFolder("parents").toPath();
        RecordingExportRunner missingRunner =
            new RecordingExportRunner("unused\n", true, Outcome.SUCCESS);
        Response missing = service(missingRunner).exportAsciiListing(
            root.resolve("missing/listing.asm").toString(),
            null, null, false, "fixture");
        assertErrorContains(missing, "parent directory does not exist");
        assertFalse(missingRunner.wasCalled());

        Path parentFile = Files.createFile(root.resolve("parent-file"));
        RecordingExportRunner fileRunner =
            new RecordingExportRunner("unused\n", true, Outcome.SUCCESS);
        Response notDirectory = service(fileRunner).exportAsciiListing(
            parentFile.resolve("listing.asm").toString(),
            null, null, false, "fixture");
        assertErrorContains(notDirectory, "parent is not a directory");
        assertFalse(fileRunner.wasCalled());
    }

    @Test
    public void rejectsExistingDestinationWithoutOverwriteBeforeExporterRuns()
            throws Exception {
        Path outputDir = temporaryFolder.newFolder("existing").toPath();
        Path destination = Files.writeString(outputDir.resolve("listing.asm"), "old\n");
        RecordingExportRunner runner =
            new RecordingExportRunner("new\n", true, Outcome.SUCCESS);

        Response response = service(runner).exportAsciiListing(
            destination.toString(), null, null, false, "fixture");

        assertErrorContains(response, "destination already exists");
        assertEquals("old\n", Files.readString(destination));
        assertFalse(runner.wasCalled());
    }

    @Test
    public void destinationCreatedDuringExportIsNotOverwrittenWithoutAuthorization()
            throws Exception {
        Path outputDir = temporaryFolder.newFolder("raced-destination").toPath();
        Path destination = outputDir.resolve("listing.asm");
        RecordingExportRunner runner =
            new RecordingExportRunner("exported\n", true, Outcome.SUCCESS);
        runner.createDestinationDuringExport("raced\n");

        Response response = service(runner).exportAsciiListing(
            destination.toString(), null, null, false, "fixture");

        assertErrorContains(response, "destination already exists");
        assertEquals("raced\n", Files.readString(destination));
        assertNoTemporaryFiles(outputDir);
    }

    @Test
    public void noOverwritePublicationPrimitiveIntrinsicallyPreservesExistingTarget()
            throws Exception {
        Path outputDir = temporaryFolder.newFolder("primitive-existing").toPath();
        Path temporary = Files.writeString(
            outputDir.resolve(".listing.asm.tmp-fixed"), "new\n");
        Path destination = Files.writeString(outputDir.resolve("listing.asm"), "old\n");

        try {
            ExportService.publish(temporary, destination, false);
            throw new AssertionError("publication unexpectedly replaced an existing target");
        }
        catch (FileAlreadyExistsException expected) {
            assertEquals(destination.toString(), expected.getFile());
        }

        assertEquals("old\n", Files.readString(destination));
        assertEquals("new\n", Files.readString(temporary));
    }

    @Test
    public void noOverwritePublicationLinksCompleteTempThenRemovesTemp() throws Exception {
        Path outputDir = temporaryFolder.newFolder("primitive-success").toPath();
        Path temporary = Files.writeString(
            outputDir.resolve(".listing.asm.tmp-fixed"), "complete\n");
        Path destination = outputDir.resolve("listing.asm");

        ExportService.publish(temporary, destination, false);

        assertEquals("complete\n", Files.readString(destination));
        assertFalse(Files.exists(temporary));
    }

    @Test
    public void overwritePublicationFailsSafelyWhenAtomicReplaceIsUnsupported()
            throws Exception {
        Path outputDir = temporaryFolder.newFolder("atomic-unsupported").toPath();
        Path temporary = Files.writeString(
            outputDir.resolve(".listing.asm.tmp-fixed"), "new\n");
        Path destination = Files.writeString(outputDir.resolve("listing.asm"), "old\n");
        ExportService.AtomicReplace unsupported = (source, target) -> {
            throw new AtomicMoveNotSupportedException(
                source.toString(), target.toString(), "test filesystem");
        };

        try {
            ExportService.publish(temporary, destination, true, unsupported);
            throw new AssertionError("non-atomic replacement unexpectedly succeeded");
        }
        catch (AtomicMoveNotSupportedException expected) {
            assertTrue(expected.getMessage().contains("test filesystem"));
        }

        assertEquals("old\n", Files.readString(destination));
        assertEquals("new\n", Files.readString(temporary));
    }

    @Test
    public void noOverwritePublicationRetriesTempUnlinkAfterFirstFailure()
            throws Exception {
        Path outputDir = temporaryFolder.newFolder("unlink-retry").toPath();
        Path temporary = Files.writeString(
            outputDir.resolve(".listing.asm.tmp-fixed"), "complete\n");
        Path destination = outputDir.resolve("listing.asm");
        AtomicInteger attempts = new AtomicInteger();
        ExportService.TempUnlink flakyUnlink = path -> {
            if (attempts.incrementAndGet() == 1) {
                throw new IOException("simulated first unlink failure");
            }
            Files.deleteIfExists(path);
        };

        ExportService.publish(temporary, destination, false,
            (source, target) -> {
                throw new AssertionError("atomic replace must not run");
            },
            flakyUnlink);

        assertEquals(2, attempts.get());
        assertEquals("complete\n", Files.readString(destination));
        assertFalse(Files.exists(temporary));
    }

    @Test
    public void metadataFailurePrecedesPublicationAndPreservesExistingDestination()
            throws Exception {
        Path outputDir = temporaryFolder.newFolder("metadata-failure").toPath();
        Path destination = Files.writeString(outputDir.resolve("listing.asm"), "old\n");
        RecordingExportRunner runner =
            new RecordingExportRunner("complete-new\n", true, Outcome.SUCCESS);
        ExportService.ResultFactory failingMetadata = (
                ignoredProgram, ignoredDestination, ignoredStart, ignoredEnd,
                ignoredSelection, ignoredBytes, ignoredExporter) -> {
                    throw new IOException("simulated metadata failure");
                };
        ExportService service =
            new ExportService(provider, security, runner, failingMetadata);

        Response response = service.exportAsciiListing(
            destination.toString(), null, null, true, "fixture");

        assertErrorContains(response, "simulated metadata failure");
        assertEquals("old\n", Files.readString(destination));
        assertNoTemporaryFiles(outputDir);
    }

    @Test
    public void rejectsFullyAndPartiallyUnmappedBoundsBeforeSecurityOrExporter()
            throws Exception {
        Path outputDir = temporaryFolder.newFolder("unmapped").toPath();
        Path destination = outputDir.resolve("listing.asm");

        RecordingExportRunner fullyUnmapped =
            new RecordingExportRunner("unused\n", true, Outcome.SUCCESS);
        Response fullResponse = service(fullyUnmapped).exportAsciiListing(
            destination.toString(), "2000", "2003", false, "fixture");
        assertErrorContains(fullResponse, "entirely contained in program memory");
        assertFalse(fullyUnmapped.wasCalled());

        RecordingExportRunner partiallyUnmapped =
            new RecordingExportRunner("unused\n", true, Outcome.SUCCESS);
        Response partialResponse = service(partiallyUnmapped).exportAsciiListing(
            destination.toString(), "103e", "1041", false, "fixture");
        assertErrorContains(partialResponse, "entirely contained in program memory");
        assertFalse(partiallyUnmapped.wasCalled());

        verify(security, never()).resolveWithinFileRoot(anyString());
    }

    @Test
    public void realSecurityConfigAcceptsCanonicalInsideRootAndRejectsExistingOutsidePath()
            throws Exception {
        Path fileRoot = temporaryFolder.newFolder("real-file-root").toPath();
        Path inside = Files.createDirectory(fileRoot.resolve("inside"));
        Path outside = temporaryFolder.newFolder("real-file-root-outside").toPath();
        Path outsideDestination = Files.writeString(
            outside.resolve("listing.asm"), "outside-old\n");
        SecurityConfig realSecurity = SecurityConfig.forFileRootTesting(fileRoot);

        RecordingExportRunner outsideRunner =
            new RecordingExportRunner("unused\n", true, Outcome.SUCCESS);
        ExportService outsideService =
            new ExportService(provider, realSecurity, outsideRunner);
        Response outsideResponse = outsideService.exportAsciiListing(
            outsideDestination.toString(), null, null, false, "fixture");
        assertErrorContains(outsideResponse, "outside GHIDRA_MCP_FILE_ROOT");
        assertEquals("outside-old\n", Files.readString(outsideDestination));
        assertFalse(outsideRunner.wasCalled());

        RecordingExportRunner insideRunner =
            new RecordingExportRunner("inside\n", true, Outcome.SUCCESS);
        ExportService insideService =
            new ExportService(provider, realSecurity, insideRunner);
        Path nonCanonicalInside = inside.resolve("..").resolve("inside/listing.asm");
        Response insideResponse = insideService.exportAsciiListing(
            nonCanonicalInside.toString(), null, null, false, "fixture");
        assertTrue(insideResponse.toJson(), insideResponse instanceof Response.Ok);
        Path canonicalDestination = inside.resolve("listing.asm").toRealPath();
        assertEquals("inside\n", Files.readString(canonicalDestination));
        assertEquals(canonicalDestination.toString(),
            result(insideResponse).get("output_path"));
    }

    @Test
    public void rejectsIncompleteInvalidAndUnsupportedBoundsBeforeExporterRuns()
            throws Exception {
        Path outputDir = temporaryFolder.newFolder("bounds").toPath();
        Path destination = outputDir.resolve("listing.asm");
        RecordingExportRunner runner =
            new RecordingExportRunner("unused\n", true, Outcome.SUCCESS);

        assertErrorContains(service(runner).exportAsciiListing(
            destination.toString(), "1000", null, false, "fixture"),
            "start and end must be supplied together");
        assertErrorContains(service(runner).exportAsciiListing(
            destination.toString(), "not-an-address", "1003", false, "fixture"),
            "Invalid start address");
        assertErrorContains(service(runner).exportAsciiListing(
            destination.toString(), "1003", "1000", false, "fixture"),
            "start must not be after end");
        assertFalse(runner.wasCalled());

        RecordingExportRunner unsupported =
            new RecordingExportRunner("unused\n", false, Outcome.SUCCESS);
        Response response = service(unsupported).exportAsciiListing(
            destination.toString(), "1000", "1003", false, "fixture");
        assertErrorContains(response, "does not support address-restricted export");
        assertFalse(unsupported.wasCalled());
    }

    @Test
    public void defaultRunnerIsNativeAsciiExporterAndSourceHasNoScriptPath()
            throws Exception {
        ExportService.AsciiExportRunner runner = new ExportService.AsciiExportRunner();
        assertEquals("ghidra.app.util.exporter.AsciiExporter", runner.name());

        String source = Files.readString(Path.of(
            "src/main/java/com/xebyte/core/ExportService.java"));
        assertTrue(source.contains("new AsciiExporter()"));
        assertFalse(source.contains("ProgramScriptService"));
        assertFalse(source.contains("GhidraScript"));
        assertFalse(source.contains("run_script_inline"));
    }

    @Test
    public void schemaDeclaresPostExportToolWithDocumentedParameterSources() {
        AnnotationScanner scanner = new AnnotationScanner(
            provider, service(new RecordingExportRunner("unused\n", true, Outcome.SUCCESS)));
        AnnotationScanner.ToolDescriptor tool = scanner.getDescriptors().stream()
            .filter(candidate -> candidate.path().equals("/export_ascii_listing"))
            .findFirst()
            .orElseThrow();

        assertEquals("POST", tool.method());
        assertEquals("export", tool.category());
        assertFalse(tool.supportsDryRun());
        assertEquals(List.of("output_path", "start", "end", "overwrite", "program"),
            tool.params().stream().map(AnnotationScanner.ParamDescriptor::name).toList());
        assertEquals(List.of("body", "body", "body", "body", "query"),
            tool.params().stream().map(AnnotationScanner.ParamDescriptor::source).toList());
        assertFalse(tool.params().get(0).optional());
        assertEquals("false", tool.params().get(3).defaultValue());
        assertTrue(tool.toJson(), tool.toJson().contains("\"supports_dry_run\": false"));
    }

    @Test
    public void scannerRejectsExplicitUnsupportedDryRunBeforeFilesystemExport()
            throws Exception {
        Path outputDir = temporaryFolder.newFolder("unsupported-dry-run").toPath();
        Path destination = outputDir.resolve("listing.asm");
        RecordingExportRunner runner =
            new RecordingExportRunner("must-not-write\n", true, Outcome.SUCCESS);
        AnnotationScanner scanner = new AnnotationScanner(provider, service(runner));
        EndpointDef endpoint = scanner.getEndpoints().stream()
            .filter(candidate -> candidate.path().equals("/export_ascii_listing"))
            .findFirst()
            .orElseThrow();

        Response response = endpoint.handler().handle(
            Map.of("program", "fixture", "dry_run", "true"),
            Map.of("output_path", destination.toString()));

        assertErrorContains(response, "does not support dry_run");
        assertFalse(runner.wasCalled());
        assertFalse(Files.exists(destination));
    }

    private ExportService service(ExportService.ExportRunner runner) {
        return new ExportService(provider, security, runner);
    }

    private static Map<String, Object> result(Response response) {
        return JsonHelper.parseJson(response.toJson());
    }

    private static void assertErrorContains(Response response, String text) {
        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains(text));
    }

    private static void assertNoTemporaryFiles(Path directory) throws IOException {
        try (var files = Files.list(directory)) {
            assertFalse(files.anyMatch(path ->
                path.getFileName().toString().contains(".tmp-")));
        }
    }

    private enum Outcome {
        SUCCESS,
        FALSE,
        THROW
    }

    private static final class RecordingExportRunner implements ExportService.ExportRunner {
        private final byte[] content;
        private final boolean supportsRanges;
        private final Outcome outcome;
        private File exportFile;
        private AddressSetView requestedSet;
        private boolean destinationExistedDuringExport;
        private String racedDestinationContent;

        RecordingExportRunner(String content, boolean supportsRanges, Outcome outcome) {
            this.content = content.getBytes(StandardCharsets.UTF_8);
            this.supportsRanges = supportsRanges;
            this.outcome = outcome;
        }

        @Override
        public boolean supportsAddressRestrictedExport() {
            return supportsRanges;
        }

        @Override
        public boolean export(File file, DomainObject object, AddressSetView selection,
                TaskMonitor monitor) throws IOException {
            exportFile = file;
            requestedSet = selection;
            String temporaryName = file.getName();
            String destinationName = temporaryName.substring(
                1, temporaryName.indexOf(".tmp-"));
            destinationExistedDuringExport =
                Files.exists(file.toPath().resolveSibling(destinationName));
            Files.write(file.toPath(), content);
            if (racedDestinationContent != null) {
                Files.writeString(file.toPath().resolveSibling(destinationName),
                    racedDestinationContent);
            }
            if (outcome == Outcome.THROW) {
                throw new IOException("simulated exporter failure");
            }
            return outcome == Outcome.SUCCESS;
        }

        @Override
        public String name() {
            return "test.ExportRunner";
        }

        @Override
        public String diagnostic() {
            return "exporter diagnostic";
        }

        File exportFile() {
            return exportFile;
        }

        AddressSetView requestedSet() {
            return requestedSet;
        }

        boolean destinationExistedDuringExport() {
            return destinationExistedDuringExport;
        }

        boolean wasCalled() {
            return exportFile != null;
        }

        void createDestinationDuringExport(String content) {
            racedDestinationContent = content;
        }
    }
}
