package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.GhidraApplicationLayout;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.protocol.ghidra.Handler;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.classfinder.ClassSearcher;

/** Real-project coverage for program opens when no CodeBrowser exists. */
public class ProgramOpenOwnershipGhidraTest {

    private ProjectData projectData;
    private Project project;
    private ToolManager toolManager;
    private MultiToolProgramProvider provider;
    private ProgramScriptService service;

    @BeforeClass
    public static void initializeGhidraOrSkip() throws Exception {
        String installDir = System.getProperty("ghidra.test.install.dir");
        assumeTrue("ghidra.test.install.dir is required",
            installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDir)), configuration);
        }
        Handler.registerHandler();
        ClassSearcher.search(TaskMonitor.DUMMY);
    }

    @Before
    public void setUp() throws Exception {
        Path directory = Files.createTempDirectory("mcp-open-program");
        projectData = new DefaultProjectData(
            new ProjectLocator(directory.toString(), "fixtureproject"), null, true);

        ProgramBuilder builder = new ProgramBuilder(
            "fixture", "6502:LE:16:default", "default", null);
        try {
            projectData.getRootFolder().createFile(
                "fixture", builder.getProgram(), TaskMonitor.DUMMY);
        } finally {
            builder.dispose();
        }

        project = mock(Project.class);
        toolManager = mock(ToolManager.class);
        PluginTool tool = mock(PluginTool.class);
        when(project.getProjectData()).thenReturn(projectData);
        when(project.getToolManager()).thenReturn(toolManager);
        when(toolManager.getRunningTools()).thenReturn(new PluginTool[0]);
        when(tool.getProject()).thenReturn(project);
        when(tool.getService(ProgramManager.class)).thenReturn(null);

        Map<String, PluginTool> tools = new ConcurrentHashMap<>();
        tools.put("front-end", tool);
        provider = new MultiToolProgramProvider(
            tools, new AtomicReference<>("front-end"));
        service = new ProgramScriptService(provider, new SwingThreadingStrategy());
    }

    @After
    public void tearDown() {
        if (provider != null) {
            provider.releaseOwnedPrograms();
        }
        if (projectData != null) {
            projectData.close();
        }
    }

    @Test
    public void openWithoutCodeBrowserIsRetainedListedAndClosed() throws Exception {
        JsonObject opened = json(service.openProgramFromProject("/fixture", false));

        assertEquals("mcp", opened.get("held_by").getAsString());
        assertTrue(opened.get("is_current").getAsBoolean());
        assertEquals("/fixture", opened.get("path").getAsString());
        Program program = provider.getProgram("/fixture");
        assertNotNull(program);
        assertTrue(provider.ownsProgram(program));
        assertEquals(program, provider.getCurrentProgram());
        assertEquals(1, provider.getAllOpenPrograms().length);
        JsonObject listed = json(service.listOpenPrograms());
        assertEquals("mcp", listed.getAsJsonArray("programs").get(0)
            .getAsJsonObject().get("held_by").getAsString());

        JsonObject again = json(service.openProgramFromProject("/fixture", false));
        assertEquals("mcp", again.get("held_by").getAsString());
        assertTrue(again.get("is_current").getAsBoolean());
        assertEquals(1, provider.getAllOpenPrograms().length);

        int transaction = program.startTransaction("unsaved close fixture");
        try {
            program.getOptions("MCP test").setString("changed", "yes");
        } finally {
            program.endTransaction(transaction, true);
        }
        JsonObject refused = json(service.closeProgram("/fixture"));
        assertTrue(refused.get("error").getAsString().contains("Save modified"));
        assertTrue(provider.ownsProgram(program));
        program.save("test", TaskMonitor.DUMMY);

        JsonObject closed = json(service.closeProgram("/fixture"));
        assertEquals(1, closed.get("closed_count").getAsInt());
        assertTrue(program.isClosed());
        assertFalse(provider.ownsProgram(program));
        assertEquals(0, provider.getAllOpenPrograms().length);

        verify(project, never()).getLocalToolChest();
        verify(toolManager, never()).getActiveWorkspace();
    }

    private static JsonObject json(Response response) {
        return JsonParser.parseString(response.toJson()).getAsJsonObject();
    }
}
