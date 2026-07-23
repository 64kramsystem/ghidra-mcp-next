package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.junit.BeforeClass;
import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;

import ghidra.GhidraApplicationLayout;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

/**
 * Opt-in tests against real Ghidra analyzer options. These complement the pure
 * atomicity tests with the scheduler/Options synchronization boundary.
 */
public class AnalysisServiceConfigurationGhidraTest {

    @BeforeClass
    public static void initializeGhidraOrSkip() throws Exception {
        String installDir = System.getProperty("ghidra.test.install.dir");
        assumeTrue(
            "ghidra.test.install.dir is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        System.setProperty(
            "class.searcher.search.all.jars", Boolean.TRUE.toString());
        if (!Application.isInitialized()) {
            GhidraApplicationLayout layout =
                new GhidraApplicationLayout(new File(installDir));
            Application.initializeApplication(
                layout, new ApplicationConfiguration());
        }
        // ProgramBuilder tests do not start a PluginTool, which is normally
        // responsible for this extension-point scan in GUI/headless startup.
        ClassSearcher.search(TaskMonitor.DUMMY);
    }

    @Test
    public void discoveryUsesRealAnalyzersAndExcludesUnrelatedBooleanOptions()
            throws Exception {
        try (Fixture fixture = fixture("analyzer-discovery")) {
            AutoAnalysisManager manager =
                AutoAnalysisManager.getAnalysisManager(fixture.program);
            var options = fixture.program.getOptions(
                ghidra.program.model.listing.Program.ANALYSIS_PROPERTIES);
            options
                .registerOption(
                    "Synthetic Non Analyzer Boolean",
                    Boolean.TRUE,
                    null,
                    "not an analyzer");
            Set<String> optionNamesBefore =
                new TreeSet<>(options.getOptionNames());

            Response response =
                fixture.analysis.getAnalyzerConfiguration("");
            JsonObject json =
                JsonParser.parseString(response.toJson()).getAsJsonObject();

            assertEquals(fixture.program.getName(),
                json.get("program").getAsString());
            JsonArray analyzers = json.getAsJsonArray("analyzers");
            assertTrue(analyzers.size() > 0);
            assertFalse(response.toJson(),
                response.toJson().contains("Synthetic Non Analyzer Boolean"));
            boolean sawUnavailable = false;
            for (var element : analyzers) {
                JsonObject analyzer = element.getAsJsonObject();
                boolean available = analyzer.get("available").getAsBoolean();
                assertEquals(
                    available,
                    manager.getAnalyzer(
                        analyzer.get("analyzer").getAsString()) != null);
                sawUnavailable |= !available;
                assertTrue(analyzer.has("enabled"));
                assertTrue(analyzer.has("available"));
                assertTrue(analyzer.has("analysis_type"));
            }
            assertTrue("fixture should exercise unavailable metadata", sawUnavailable);
            assertEquals(
                "configuration inspection must not register options for unavailable analyzers",
                optionNamesBefore,
                new TreeSet<>(options.getOptionNames()));
        }
    }

    @Test
    public void labelsOnlyConfigurationAndDefaultFlowCreateNoFunctions()
            throws Exception {
        try (Fixture fixture = fixture("labels-only")) {
            fixture.builder.createMemory(".ram", "0x1000", 0x20);
            fixture.builder.setBytes(
                "0x1000", "20 08 10 ea 60 ea ea ea a9 01 60");
            List<Map<String, Object>> originals =
                currentEnabledChanges(
                    fixture.analysis.getAnalyzerConfiguration(""));
            List<Map<String, Object>> disableAll =
                disabledChanges(
                    fixture.analysis.getAnalyzerConfiguration(""));
            try {
                Response configured =
                    fixture.analysis.configureAnalyzers(
                        JsonHelper.toJson(disableAll), false, "");
                assertTrue(configured.toJson(),
                    configured.toJson().contains("\"committed\":true"));
                assertEquals(0,
                    fixture.program.getFunctionManager().getFunctionCount());

                FlowDisassemblyService flow =
                    new FlowDisassemblyService(
                        fixture.provider, fixture.threading);
                Response disassembled = flow.disassembleFlow(
                    "[\"0x1000\"]",
                    "0x1000",
                    "0x100a",
                    false,
                    true,
                    true,
                    false,
                    false,
                    100,
                    "");

                assertTrue(disassembled.toJson(),
                    disassembled instanceof Response.Ok);
                assertTrue(disassembled.toJson(),
                    disassembled.toJson().contains(
                        "\"analysis_status\":\"not_requested\""));
                assertEquals(0,
                    fixture.program.getFunctionManager().getFunctionCount());
                assertFalse(AutoAnalysisManager
                    .getAnalysisManager(fixture.program)
                    .isAnalyzing());
            }
            finally {
                fixture.analysis.configureAnalyzers(
                    JsonHelper.toJson(originals), false, "");
            }
        }
    }

    @Test
    public void analysisEnabledFlowReturnsScopedRequestSeparateFromMutation()
            throws Exception {
        try (Fixture fixture = fixture("explicit-analysis")) {
            fixture.builder.createMemory(".ram", "0x1000", 0x20);
            fixture.builder.setBytes("0x1000", "20 08 10 60 ea ea ea ea 60");
            Response enabled = fixture.analysis.configureAnalyzer(
                "Subroutine References", true, "");
            assertTrue(enabled.toJson(),
                enabled.toJson().contains("\"committed\":true"));

            AutoAnalysisManager manager =
                AutoAnalysisManager.getAnalysisManager(fixture.program);
            FlowDisassemblyService flow =
                new FlowDisassemblyService(fixture.provider, fixture.threading);

            Response response = flow.disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1008",
                false,
                true,
                true,
                false,
                true,
                100,
                "");

            assertTrue(response.toJson(), response instanceof Response.Ok);
            assertTrue(response.toJson(),
                response.toJson().contains("\"analysis_request\""));
            assertTrue(response.toJson(),
                response.toJson().contains("\"analysis_status\":\"queued\""));
            assertTrue(response.toJson(),
                response.toJson().contains("\"request_identity\":\"analysis-"));
            assertTrue(
                "direct disassembly must report no direct function mutation",
                response.toJson().contains("\"function_changes\":[]"));

            ProgramScriptService programService =
                new ProgramScriptService(fixture.provider, fixture.threading);
            long deadline = System.nanoTime() +
                java.util.concurrent.TimeUnit.SECONDS.toNanos(30);
            JsonObject status = null;
            do {
                Response polled =
                    programService.analysisStatus(fixture.program.getName());
                assertTrue(polled.toJson(), polled instanceof Response.Ok);
                status = JsonParser.parseString(
                    polled.toJson()).getAsJsonObject();
                if (!status.get("analyzing").getAsBoolean() &&
                    status.get("function_count").getAsInt() > 0) {
                    break;
                }
                Thread.sleep(5);
            }
            while (System.nanoTime() < deadline);

            assertNotNull(status);
            assertFalse(status.get("analyzing").getAsBoolean());
            assertTrue(
                "explicit Subroutine References analysis should create the JSR target function: " +
                    status,
                status.get("function_count").getAsInt() > 0);
            assertFalse(manager.isAnalyzing());
        }
    }

    private static List<Map<String, Object>> currentEnabledChanges(
            Response response) {
        return enabledChanges(response, false);
    }

    private static List<Map<String, Object>> disabledChanges(
            Response response) {
        return enabledChanges(response, true);
    }

    private static List<Map<String, Object>> enabledChanges(
            Response response, boolean forceDisabled) {
        JsonArray analyzers = JsonParser.parseString(response.toJson())
            .getAsJsonObject()
            .getAsJsonArray("analyzers");
        List<Map<String, Object>> changes = new ArrayList<>();
        for (var element : analyzers) {
            JsonObject analyzer = element.getAsJsonObject();
            if (analyzer.get("available").getAsBoolean()) {
                changes.add(Map.of(
                    "analyzer", analyzer.get("analyzer").getAsString(),
                    "enabled",
                    forceDisabled
                        ? false
                        : analyzer.get("enabled").getAsBoolean()));
            }
        }
        return changes;
    }

    private static Fixture fixture(String name) throws Exception {
        ProgramBuilder builder =
            new ProgramBuilder(name, "6502:LE:16:default", "default", name);
        ProgramDB program = builder.getProgram();
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        DirectThreadingStrategy threading = new DirectThreadingStrategy();
        AnalysisService analysis = new AnalysisService(
            provider,
            threading,
            new FunctionService(provider, threading));
        return new Fixture(builder, program, provider, threading, analysis);
    }

    private record Fixture(
            ProgramBuilder builder,
            ProgramDB program,
            HeadlessProgramProvider provider,
            DirectThreadingStrategy threading,
            AnalysisService analysis) implements AutoCloseable {
        @Override
        public void close() {
            builder.dispose();
        }
    }
}
