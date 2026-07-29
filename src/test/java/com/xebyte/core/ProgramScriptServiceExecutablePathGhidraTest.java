package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

/** ProgramBuilder-backed coverage for executable-path metadata mutation. */
public class ProgramScriptServiceExecutablePathGhidraTest {

    private static final String ORIGINAL = "/private/import/original.bin";

    private ProgramBuilder builder;
    private ProgramDB program;
    private HeadlessProgramProvider provider;
    private ProgramScriptService service;

    @BeforeClass
    public static void initializeGhidraOrSkip() throws Exception {
        String installDir = System.getProperty("ghidra.test.install.dir");
        assumeTrue(
            "ghidra.test.install.dir is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        // This can be the first live fixture; complete extension discovery here or
        // later analyzer-configuration fixtures inherit an empty analyzer catalog.
        System.setProperty(
            "class.searcher.search.all.jars", Boolean.TRUE.toString());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration =
                new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDir)),
                configuration);
        }
        ClassSearcher.search(TaskMonitor.DUMMY);
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder(
            "executable-path-6502",
            "6502:LE:16:default",
            "default",
            this);
        program = builder.getProgram();
        builder.withTransaction(() -> program.setExecutablePath(ORIGINAL));

        provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        service = new ProgramScriptService(
            provider, new DirectThreadingStrategy());
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void replacesMetadataAndReportsExactState() {
        JsonObject result = object(
            service.setExecutablePath("assets/game.bin", ""));

        assertEquals("assets/game.bin", program.getExecutablePath());
        assertTrue(result.get("success").getAsBoolean());
        assertEquals(program.getName(), result.get("program").getAsString());
        assertEquals(ORIGINAL, result.get("previous").getAsString());
        assertEquals("assets/game.bin", result.get("resulting").getAsString());
        assertTrue(result.get("changed").getAsBoolean());
        assertTrue(
            service.getMetadata("").toJson()
                .contains("Executable Path: assets/game.bin"));
    }

    @Test
    public void repeatedValueIsSuccessfulNoOp() {
        service.setExecutablePath("assets/game.bin", "");

        JsonObject repeated = object(
            service.setExecutablePath("assets/game.bin", ""));

        assertFalse(repeated.get("changed").getAsBoolean());
        assertEquals(
            "assets/game.bin", repeated.get("previous").getAsString());
        assertEquals(
            "assets/game.bin", repeated.get("resulting").getAsString());
    }

    @Test
    public void ghidraUnknownSentinelClearsStoredLocation() {
        JsonObject result = object(
            service.setExecutablePath("unknown", ""));

        assertEquals("unknown", program.getExecutablePath());
        assertEquals("unknown", result.get("resulting").getAsString());
        assertTrue(result.get("changed").getAsBoolean());
    }

    @Test
    public void nullEmptyAndOmittedValuesAreRejectedBeforeMutation()
            throws Exception {
        Response direct = service.setExecutablePath(null, "");
        assertTrue(direct.toJson(), direct instanceof Response.Err);
        assertTrue(direct.toJson(), direct.toJson().contains("required"));

        Response empty = service.setExecutablePath("", "");
        assertTrue(empty.toJson(), empty instanceof Response.Err);
        assertTrue(empty.toJson(), empty.toJson().contains("non-empty"));

        EndpointDef endpoint = endpoint();
        Response omitted = endpoint.handler().handle(Map.of(), Map.of());
        assertTrue(omitted.toJson(), omitted instanceof Response.Err);
        assertTrue(omitted.toJson(), omitted.toJson().contains("required"));
        assertEquals(ORIGINAL, program.getExecutablePath());
    }

    @Test
    public void schemaPublishesPostBodyAndProgramQuery() {
        AnnotationScanner.ToolDescriptor tool =
            new AnnotationScanner(provider, service).getDescriptors().stream()
                .filter(candidate ->
                    "/set_executable_path".equals(candidate.path()))
                .findFirst()
                .orElseThrow();

        assertEquals("POST", tool.method());
        assertTrue(tool.supportsDryRun());
        assertEquals(
            Map.of("executable_path", "body", "program", "query"),
            tool.params().stream().collect(Collectors.toMap(
                AnnotationScanner.ParamDescriptor::name,
                AnnotationScanner.ParamDescriptor::source)));
        Map<String, AnnotationScanner.ParamDescriptor> parameters =
            tool.params().stream().collect(Collectors.toMap(
                AnnotationScanner.ParamDescriptor::name,
                Function.identity()));
        assertFalse(parameters.get("executable_path").optional());
        assertTrue(parameters.get("program").optional());
    }

    @Test
    public void scannerDryRunRollsBackMetadata() throws Exception {
        Response preview = endpoint().handler().handle(
            Map.of("dry_run", "true"),
            Map.of("executable_path", "assets/preview.bin"));

        JsonObject result = object(preview);
        assertTrue(result.get("dry_run").getAsBoolean());
        assertEquals("assets/preview.bin",
            result.get("resulting").getAsString());
        assertEquals(ORIGINAL, program.getExecutablePath());
    }

    @Test
    public void missingNamedProgramUsesStandardErrorWithoutMutation() {
        Response response =
            service.setExecutablePath("assets/game.bin", "missing-program");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains("Program not found"));
        assertTrue(response.toJson(), response.toJson().contains("Available programs"));
        assertEquals(ORIGINAL, program.getExecutablePath());
    }

    private EndpointDef endpoint() {
        return new AnnotationScanner(provider, service).getEndpoints().stream()
            .filter(candidate ->
                "/set_executable_path".equals(candidate.path()))
            .findFirst()
            .orElseThrow();
    }

    private static JsonObject object(Response response) {
        assertNotNull(response);
        assertTrue(response.toJson(), !(response instanceof Response.Err));
        return JsonParser.parseString(response.toJson()).getAsJsonObject();
    }
}
