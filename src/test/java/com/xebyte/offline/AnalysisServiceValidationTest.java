package com.xebyte.offline;

import com.xebyte.core.AnalysisService;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.FunctionService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import junit.framework.TestCase;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Validation + graceful-degradation coverage for AnalysisService (the largest service in the
 * repo, ~5.2K LOC, previously no behavioral tests). Exercises the input-validation branches
 * that run before any program access, plus the no-program degradation path.
 */
public class AnalysisServiceValidationTest extends TestCase {

    private AnalysisService analysis;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        com.xebyte.core.ProgramProvider provider = ServiceFactory.stubProvider();
        analysis = new AnalysisService(provider, ts, new FunctionService(provider, ts));
    }

    // --- validate-first branches (run before the program lookup) ---

    public void testGetFieldAccessContextRejectsNegativeOffset() {
        Response r = analysis.getFieldAccessContext("0x401000", -1, 5);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Field offset must be between 0 and"));
    }

    public void testBatchAnalyzeCompletenessRejectsMissingAddresses() {
        Response r = analysis.batchAnalyzeCompleteness(null, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Missing required parameter: addresses"));
    }

    // --- graceful degradation past validation, with no program loaded ---

    public void testGetFieldAccessContextDegradesGracefullyWithValidArgs() {
        Response r = analysis.getFieldAccessContext("0x401000", 0, 5);
        assertNotNull(r);
        assertTrue("expected 'No program loaded', got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }

    public void testAnalyzerConfigurationToolsHaveExactCatalogSchemas() {
        Map<String, AnnotationScanner.ToolDescriptor> tools =
            new AnnotationScanner(
                ServiceFactory.stubProvider(), ServiceFactory.buildAllServices())
                .getDescriptors()
                .stream()
                .collect(Collectors.toMap(
                    AnnotationScanner.ToolDescriptor::path,
                    Function.identity()));

        AnnotationScanner.ToolDescriptor single = tools.get("/configure_analyzer");
        assertNotNull("single-analyzer configuration is not cataloged", single);
        assertEquals("POST", single.method());
        assertEquals(
            List.of("analyzer", "enabled", "program"),
            single.params().stream()
                .map(AnnotationScanner.ParamDescriptor::name)
                .toList());

        AnnotationScanner.ToolDescriptor discovery =
            tools.get("/get_analyzer_configuration");
        assertNotNull("analyzer configuration discovery is not cataloged", discovery);
        assertEquals("GET", discovery.method());
        assertEquals(
            List.of("program"),
            discovery.params().stream()
                .map(AnnotationScanner.ParamDescriptor::name)
                .toList());

        AnnotationScanner.ToolDescriptor batch = tools.get("/configure_analyzers");
        assertNotNull("batch analyzer configuration is not cataloged", batch);
        assertEquals("POST", batch.method());
        assertFalse("batch owns its explicit body dry_run flag", batch.supportsDryRun());
        assertEquals(
            List.of("changes", "dry_run", "program"),
            batch.params().stream()
                .map(AnnotationScanner.ParamDescriptor::name)
                .toList());
        assertEquals(
            List.of("body", "body", "query"),
            batch.params().stream()
                .map(AnnotationScanner.ParamDescriptor::source)
                .toList());
        assertEquals(
            "json",
            batch.params().get(0).type());
    }

    public void testAnnotatedConfigurationReplacesRawHeadlessRoute() throws Exception {
        String source = Files.readString(Path.of(
            "src/main/java/com/xebyte/headless/GhidraMCPHeadlessServer.java"));
        assertFalse(
            "raw /configure_analyzer registration duplicates the annotated route",
            source.contains("safeContext(\"/configure_analyzer\""));
    }
}
