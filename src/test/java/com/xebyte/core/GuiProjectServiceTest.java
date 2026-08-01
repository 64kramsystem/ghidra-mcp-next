package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.MockedStatic;

import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;

public class GuiProjectServiceTest {

    @BeforeClass
    public static void registerGhidraUrlHandler() {
        String key = "java.protocol.handler.pkgs";
        String packages = System.getProperty(key, "");
        if (!packages.contains("ghidra.framework.protocol")) {
            System.setProperty(key, packages.isEmpty()
                ? "ghidra.framework.protocol"
                : packages + "|ghidra.framework.protocol");
        }
    }

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private SecurityConfig security;

    @Before
    public void setUp() throws Exception {
        security = mock(SecurityConfig.class);
        when(security.resolveWithinFileRoot(anyString())).thenAnswer(invocation ->
            new File(invocation.getArgument(0, String.class)).getCanonicalFile().toPath());
    }

    @After
    public void clearActiveProject() {
        AppInfo.setActiveProject(null);
    }

    @Test
    public void createRejectsMissingParent() throws Exception {
        Path missing = temporaryFolder.getRoot().toPath().resolve("missing");
        Map<String, Object> result = createWithNoTool(missing, "NewProject");

        assertError(result, "parent_not_found");
    }

    @Test
    public void createRefusesUnsavedDataBeforeReleasingRetainedPrograms() throws Exception {
        Path parent = newProjectsParent();
        ProjectManager manager = mock(ProjectManager.class);
        Project current = mock(Project.class);
        DomainFile changed = mock(DomainFile.class);
        AtomicReference<Boolean> released = new AtomicReference<>(false);
        when(manager.getActiveProject()).thenReturn(current);
        when(changed.isChanged()).thenReturn(true);
        when(changed.getPathname()).thenReturn("/changed");
        when(current.getOpenData()).thenReturn(List.of(changed));
        GuiProjectService service = new GuiProjectService(
            security, () -> manager,
            () -> activeProjectController(new AtomicReference<>(current)),
            () -> released.set(true));

        Map<String, Object> result = parse(service.createProject(
            parent.toString(), "NewProject"));

        assertError(result, "unsaved_changes");
        assertFalse(released.get());
        verify(current, never()).close();
        verify(manager, never()).createProject(any(), any(), eq(true));
    }

    @Test
    public void createRejectsParentThatIsNotDirectory() throws Exception {
        Path file = temporaryFolder.newFile("parent-file").toPath();
        Map<String, Object> result = createWithNoTool(file, "NewProject");

        assertError(result, "parent_not_directory");
    }

    @Test
    public void createUsesProjectLocatorNameValidation() throws Exception {
        Path parent = newProjectsParent();
        Map<String, Object> result = createWithNoTool(parent, "bad/name");

        assertError(result, "invalid_project_name");
    }

    @Test
    public void createRequiresEachDestinationPathWithinFileRoot() throws Exception {
        Path parent = newProjectsParent();
        ProjectLocator locator = new ProjectLocator(parent.toString(), "NewProject");
        List<String> deniedPaths = List.of(
            parent.toFile().getCanonicalPath(),
            locator.getMarkerFile().getCanonicalPath(),
            locator.getProjectDir().getCanonicalPath());

        for (String deniedPath : deniedPaths) {
            when(security.resolveWithinFileRoot(anyString())).thenAnswer(invocation -> {
                File value = new File(invocation.getArgument(0, String.class))
                    .getCanonicalFile();
                return value.getPath().equals(deniedPath) ? null : value.toPath();
            });

            Map<String, Object> result = createWithNoTool(parent, "NewProject");
            assertError(result, "path_not_allowed");
        }
    }

    @Test
    public void createRejectsExistingMarkerRegardlessOfType() throws Exception {
        Path parent = newProjectsParent();
        Files.createDirectory(parent.resolve("NewProject.gpr"));

        Map<String, Object> result = createWithNoTool(parent, "NewProject");

        assertError(result, "destination_exists");
    }

    @Test
    public void createRejectsExistingProjectDirectoryRegardlessOfType() throws Exception {
        Path parent = newProjectsParent();
        Files.createFile(parent.resolve("NewProject.rep"));

        Map<String, Object> result = createWithNoTool(parent, "NewProject");

        assertError(result, "destination_exists");
    }

    @Test
    public void createRejectsDanglingMarkerSymlink() throws Exception {
        Path parent = newProjectsParent();
        createDanglingSymlink(
            parent.resolve("NewProject.gpr"), parent.resolve("missing-marker-target"));

        Map<String, Object> result = createWithNoTool(parent, "NewProject");

        assertError(result, "destination_exists");
    }

    @Test
    public void createRejectsUnavailableProjectManager() throws Exception {
        Path parent = newProjectsParent();
        GuiProjectService service = new GuiProjectService(() -> null, security);

        Map<String, Object> result = parse(service.createProject(
            parent.toString(), "NewProject"));

        assertError(result, "project_manager_unavailable");
    }

    @Test
    public void createRunsLifecycleAsOneEdtTaskAndActivatesProject() throws Exception {
        Path parent = newProjectsParent();
        ProjectManager manager = mock(ProjectManager.class);
        Project previous = mock(Project.class);
        Project created = mock(Project.class);
        AtomicReference<Project> active = new AtomicReference<>(previous);
        AtomicReference<Project> toolProject = new AtomicReference<>(previous);
        List<String> events = new ArrayList<>();
        GuiProjectService.ActiveProjectController controller =
            new GuiProjectService.ActiveProjectController() {
                @Override
                public Project getActiveProject() {
                    return toolProject.get();
                }

                @Override
                public void setActiveProject(Project project) {
                    events.add("tool:" + (project == null ? "null" : "created") + ":"
                        + SwingUtilities.isEventDispatchThread());
                    toolProject.set(project);
                }

                @Override
                public void projectClosed(Project project) {
                    events.add("notify-closed:" + SwingUtilities.isEventDispatchThread());
                }
            };

        when(manager.getActiveProject()).thenAnswer(invocation -> active.get());
        doAnswer(invocation -> {
            events.add("save:" + SwingUtilities.isEventDispatchThread());
            return null;
        }).when(previous).save();
        doAnswer(invocation -> {
            events.add("close:" + SwingUtilities.isEventDispatchThread());
            active.set(null);
            AppInfo.setActiveProject(null);
            return null;
        }).when(previous).close();
        when(manager.createProject(any(ProjectLocator.class), isNull(), eq(true)))
            .thenAnswer(invocation -> {
                events.add("create:" + SwingUtilities.isEventDispatchThread());
                active.set(created);
                AppInfo.setActiveProject(created);
                return created;
            });
        when(created.getName()).thenReturn("NewProject");

        GuiProjectService service = new GuiProjectService(
            security, () -> manager, () -> controller);
        Map<String, Object> result = parse(service.createProject(
            parent.toString(), "NewProject"));

        assertEquals(List.of("save:true", "close:true", "notify-closed:true", "tool:null:true",
            "create:true", "tool:created:true"), events);
        assertEquals(Boolean.TRUE, result.get("success"));
        assertEquals("NewProject", result.get("project"));
        assertEquals(parent.resolve("NewProject").toString(), result.get("path"));
        assertEquals(Boolean.TRUE, result.get("active"));
        assertSame(created, AppInfo.getActiveProject());
        assertSame(created, controller.getActiveProject());
    }

    @Test
    public void createNormalizesGprSuffixInProjectAndDestination() throws Exception {
        Path parent = newProjectsParent();
        ProjectManager manager = mock(ProjectManager.class);
        Project created = mock(Project.class);
        when(manager.createProject(any(ProjectLocator.class), isNull(), eq(true)))
            .thenAnswer(invocation -> {
                AppInfo.setActiveProject(created);
                return created;
            });
        when(created.getName()).thenReturn("NewProject");
        AtomicReference<Project> toolProject = new AtomicReference<>();
        GuiProjectService service = new GuiProjectService(
            security, () -> manager,
            () -> activeProjectController(toolProject));

        Map<String, Object> result = parse(service.createProject(
            parent.toString(), "NewProject.gpr"));

        assertEquals(Boolean.TRUE, result.get("success"));
        assertEquals("NewProject", result.get("project"));
        assertEquals(parent.resolve("NewProject").toString(), result.get("path"));
    }

    @Test
    public void openRejectsInvalidOrIncompleteProjectBeforeTouchingActiveProject()
            throws Exception {
        ProjectManager manager = mock(ProjectManager.class);
        Project current = mock(Project.class);
        when(manager.getActiveProject()).thenReturn(current);
        GuiProjectService service = new GuiProjectService(security, () -> manager);

        assertError(parse(service.openProject("relative.gpr")), "invalid_request");
        Path wrongSuffix = temporaryFolder.newFile("not-a-project.txt").toPath();
        assertError(parse(service.openProject(wrongSuffix.toString())), "invalid_request");
        Path marker = temporaryFolder.newFile("MissingDirectory.gpr").toPath();
        assertError(parse(service.openProject(marker.toString())), "project_not_found");

        verify(current, never()).save();
        verify(current, never()).close();
        verify(manager, never()).openProject(any(ProjectLocator.class), eq(true), eq(false));
    }

    @Test
    public void openRejectsMarkerOutsideFileRoot() throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        when(security.resolveWithinFileRoot(marker.toString())).thenReturn(null);
        ProjectManager manager = mock(ProjectManager.class);
        GuiProjectService service = new GuiProjectService(security, () -> manager);

        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertError(result, "path_not_allowed");
        verify(manager, never()).getActiveProject();
        verify(manager, never()).openProject(any(ProjectLocator.class), eq(true), eq(false));
    }

    @Test
    public void openRejectsProjectDirectoryOutsideFileRoot() throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Path outside = temporaryFolder.newFolder("outside-project").toPath().toRealPath();
        Path projectDirectory = parent.resolve("NewProject.rep");
        try {
            Files.createSymbolicLink(projectDirectory, outside);
        } catch (UnsupportedOperationException | IOException e) {
            assumeNoException(e);
        }
        when(security.resolveWithinFileRoot(outside.toString())).thenReturn(null);
        ProjectManager manager = mock(ProjectManager.class);
        GuiProjectService service = new GuiProjectService(security, () -> manager);

        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertError(result, "path_not_allowed");
        verify(manager, never()).getActiveProject();
        verify(manager, never()).openProject(any(ProjectLocator.class), eq(true), eq(false));
    }

    @Test
    public void openReturnsAlreadyActiveWithoutReopening() throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectLocator locator = new ProjectLocator(parent.toString(), "NewProject");
        ProjectManager manager = mock(ProjectManager.class);
        Project current = mock(Project.class);
        when(manager.getActiveProject()).thenReturn(current);
        when(current.getProjectLocator()).thenReturn(locator);
        AtomicReference<Project> toolProject = new AtomicReference<>(current);
        GuiProjectService service = new GuiProjectService(
            security, () -> manager, () -> activeProjectController(toolProject));

        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertEquals(Boolean.TRUE, result.get("success"));
        assertEquals(Boolean.TRUE, result.get("already_active"));
        assertSame(current, toolProject.get());
        verify(current, never()).save();
        verify(current, never()).close();
        verify(manager, never()).openProject(any(ProjectLocator.class), eq(true), eq(false));
    }

    @Test
    public void openAbortsWithoutClosingWhenCurrentProjectHasUnsavedDomainData()
            throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectManager manager = mock(ProjectManager.class);
        Project current = mock(Project.class);
        DomainFile changed = mock(DomainFile.class);
        when(changed.isChanged()).thenReturn(true);
        when(current.getOpenData()).thenReturn(List.of(changed));
        when(manager.getActiveProject()).thenReturn(current);
        when(current.getProjectLocator()).thenReturn(
            new ProjectLocator(parent.toString(), "OldProject"));
        AtomicReference<Project> toolProject = new AtomicReference<>(current);
        AppInfo.setActiveProject(current);
        GuiProjectService service = new GuiProjectService(
            security, () -> manager, () -> activeProjectController(toolProject));

        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertError(result, "unsaved_changes");
        assertSame(current, AppInfo.getActiveProject());
        assertSame(current, toolProject.get());
        verify(current, never()).save();
        verify(current, never()).close();
        verify(manager, never()).openProject(any(ProjectLocator.class), eq(true), eq(false));
    }

    @Test
    public void openRefusesBusyProjectToolWithoutClosing() throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectManager manager = mock(ProjectManager.class);
        Project current = mock(Project.class);
        ToolManager toolManager = mock(ToolManager.class);
        PluginTool busyTool = pluginToolOrSkip();
        when(manager.getActiveProject()).thenReturn(current);
        when(current.getProjectLocator()).thenReturn(
            new ProjectLocator(parent.toString(), "OldProject"));
        when(current.getToolManager()).thenReturn(toolManager);
        when(toolManager.getRunningTools()).thenReturn(new PluginTool[] { busyTool });
        when(busyTool.isExecutingCommand()).thenReturn(true);
        when(busyTool.getName()).thenReturn("CodeBrowser");
        GuiProjectService service = new GuiProjectService(
            security, () -> manager, () -> activeProjectController(
                new AtomicReference<>(current)));

        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertError(result, "project_close_refused");
        verify(current, never()).saveSessionTools();
        verify(current, never()).close();
        verify(manager, never()).openProject(any(ProjectLocator.class), eq(true), eq(false));
    }

    @Test
    public void openRefusesAmbiguousChangedSessionToolsWithoutDialog() throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectManager manager = mock(ProjectManager.class);
        Project current = mock(Project.class);
        ToolManager toolManager = mock(ToolManager.class);
        PluginTool first = pluginToolOrSkip();
        PluginTool second = pluginToolOrSkip();
        when(manager.getActiveProject()).thenReturn(current);
        when(current.getProjectLocator()).thenReturn(
            new ProjectLocator(parent.toString(), "OldProject"));
        when(current.getToolManager()).thenReturn(toolManager);
        when(toolManager.getRunningTools()).thenReturn(
            new PluginTool[] { first, second });
        when(first.hasConfigChanged()).thenReturn(true);
        when(second.hasConfigChanged()).thenReturn(true);
        when(first.getName()).thenReturn("CodeBrowser");
        when(second.getName()).thenReturn("CodeBrowser(2)");
        when(first.getToolName()).thenReturn("CodeBrowser");
        when(second.getToolName()).thenReturn("CodeBrowser");
        GuiProjectService service = new GuiProjectService(
            security, () -> manager, () -> activeProjectController(
                new AtomicReference<>(current)));

        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertError(result, "project_close_refused");
        assertTrue(result.get("message").toString().contains("share a name"));
        verify(current, never()).saveSessionTools();
        verify(current, never()).close();
        verify(manager, never()).openProject(any(ProjectLocator.class), eq(true), eq(false));
    }

    @Test
    public void openRefusesToolThatCannotClose() throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectManager manager = mock(ProjectManager.class);
        Project current = mock(Project.class);
        ToolManager toolManager = mock(ToolManager.class);
        PluginTool tool = pluginToolOrSkip();
        when(manager.getActiveProject()).thenReturn(current);
        when(current.getProjectLocator()).thenReturn(
            new ProjectLocator(parent.toString(), "OldProject"));
        when(current.getToolManager()).thenReturn(toolManager);
        when(toolManager.getRunningTools()).thenReturn(new PluginTool[] { tool });
        when(tool.getName()).thenReturn("CodeBrowser");
        GuiProjectService service = new GuiProjectService(
            security, () -> manager, () -> activeProjectController(
                new AtomicReference<>(current)));

        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertError(result, "project_close_refused");
        assertTrue(result.get("message").toString().contains("refused"));
        verify(current, never()).saveSessionTools();
        verify(current, never()).close();
    }

    @Test
    public void openAbortsWhenSessionToolsCannotBeSaved() throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectManager manager = mock(ProjectManager.class);
        Project current = mock(Project.class);
        ToolManager toolManager = mock(ToolManager.class);
        when(manager.getActiveProject()).thenReturn(current);
        when(current.getProjectLocator()).thenReturn(
            new ProjectLocator(parent.toString(), "OldProject"));
        when(current.getToolManager()).thenReturn(toolManager);
        when(toolManager.getRunningTools()).thenReturn(new PluginTool[0]);
        when(current.saveSessionTools()).thenReturn(false);
        GuiProjectService service = new GuiProjectService(
            security, () -> manager, () -> activeProjectController(
                new AtomicReference<>(current)));

        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertError(result, "project_close_failed");
        assertTrue(result.get("message").toString().contains("session tools"));
        verify(current, never()).save();
        verify(current, never()).close();
    }

    @Test
    public void openSavesUnchangedProjectBeforeClosing() throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectManager manager = mock(ProjectManager.class);
        Project current = mock(Project.class);
        Project opened = mock(Project.class);
        AtomicReference<Project> managerProject = new AtomicReference<>(current);
        AtomicReference<Boolean> released = new AtomicReference<>(false);
        when(manager.getActiveProject()).thenAnswer(invocation -> managerProject.get());
        when(current.getProjectLocator()).thenReturn(
            new ProjectLocator(parent.toString(), "OldProject"));
        doAnswer(invocation -> {
            assertTrue(released.get());
            managerProject.set(null);
            return null;
        }).when(current).close();
        when(manager.openProject(any(ProjectLocator.class), eq(true), eq(false)))
            .thenAnswer(invocation -> {
                managerProject.set(opened);
                AppInfo.setActiveProject(opened);
                return opened;
            });
        when(opened.getName()).thenReturn("NewProject");
        GuiProjectService service = new GuiProjectService(
            security, () -> manager, () -> activeProjectController(
                new AtomicReference<>()), () -> released.set(true));

        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertEquals(Boolean.TRUE, result.get("success"));
        verify(current).save();
        verify(current).close();
        assertTrue(released.get());
    }

    @Test
    public void openClearsActiveHoldersWhenCloseNotificationFails() throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectManager manager = mock(ProjectManager.class);
        Project current = mock(Project.class);
        when(manager.getActiveProject()).thenReturn(current);
        when(current.getProjectLocator()).thenReturn(
            new ProjectLocator(parent.toString(), "OldProject"));
        when(current.saveSessionTools()).thenReturn(true);
        AtomicReference<Project> toolProject = new AtomicReference<>(current);
        AppInfo.setActiveProject(current);
        GuiProjectService.ActiveProjectController controller =
            new GuiProjectService.ActiveProjectController() {
                @Override
                public Project getActiveProject() {
                    return toolProject.get();
                }

                @Override
                public void setActiveProject(Project project) {
                    toolProject.set(project);
                }

                @Override
                public void projectClosed(Project project) {
                    throw new IllegalStateException("listener failed");
                }
            };
        GuiProjectService service = new GuiProjectService(
            security, () -> manager, () -> controller);

        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertError(result, "project_open_failed");
        verify(current).close();
        assertNull(AppInfo.getActiveProject());
        assertNull(toolProject.get());
        verify(manager, never()).openProject(any(ProjectLocator.class), eq(true), eq(false));
    }

    @Test
    public void openNormalizesHoldersWhenProjectMarksClosedBeforeThrowing()
            throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectManager manager = mock(ProjectManager.class);
        Project current = mock(Project.class);
        when(manager.getActiveProject()).thenReturn(current);
        when(current.getProjectLocator()).thenReturn(
            new ProjectLocator(parent.toString(), "OldProject"));
        when(current.isClosed()).thenReturn(true);
        doAnswer(invocation -> {
            AppInfo.setActiveProject(null);
            throw new IllegalStateException("dispose failed");
        }).when(current).close();
        AtomicReference<Project> toolProject = new AtomicReference<>(current);
        AtomicReference<Project> notified = new AtomicReference<>();
        AppInfo.setActiveProject(current);
        GuiProjectService.ActiveProjectController controller =
            new GuiProjectService.ActiveProjectController() {
                @Override
                public Project getActiveProject() {
                    return toolProject.get();
                }

                @Override
                public void setActiveProject(Project project) {
                    toolProject.set(project);
                }

                @Override
                public void projectClosed(Project project) {
                    notified.set(project);
                }
            };
        GuiProjectService service = new GuiProjectService(
            security, () -> manager, () -> controller);

        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertError(result, "project_open_failed");
        assertSame(current, notified.get());
        assertNull(AppInfo.getActiveProject());
        assertNull(toolProject.get());
        verify(manager, never()).openProject(any(ProjectLocator.class), eq(true), eq(false));
    }

    @Test
    public void openRunsLifecycleAsOneEdtTaskAndActivatesProject() throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectManager manager = mock(ProjectManager.class);
        Project previous = mock(Project.class);
        Project opened = mock(Project.class);
        AtomicReference<Project> managerProject = new AtomicReference<>(previous);
        AtomicReference<Project> toolProject = new AtomicReference<>(previous);
        List<String> events = new ArrayList<>();
        when(previous.getProjectLocator()).thenReturn(
            new ProjectLocator(parent.toString(), "OldProject"));
        when(previous.hasChanged()).thenReturn(true, false);
        GuiProjectService.ActiveProjectController controller =
            new GuiProjectService.ActiveProjectController() {
                @Override
                public Project getActiveProject() {
                    return toolProject.get();
                }

                @Override
                public void setActiveProject(Project project) {
                    events.add("tool:" + (project == null ? "null" : "opened") + ":"
                        + SwingUtilities.isEventDispatchThread());
                    toolProject.set(project);
                }

                @Override
                public void projectClosed(Project project) {
                    events.add("notify-closed:" + SwingUtilities.isEventDispatchThread());
                }
            };

        when(manager.getActiveProject()).thenAnswer(invocation -> managerProject.get());
        doAnswer(invocation -> {
            events.add("save:" + SwingUtilities.isEventDispatchThread());
            return null;
        }).when(previous).save();
        doAnswer(invocation -> {
            events.add("close:" + SwingUtilities.isEventDispatchThread());
            managerProject.set(null);
            AppInfo.setActiveProject(null);
            return null;
        }).when(previous).close();
        when(manager.openProject(any(ProjectLocator.class), eq(true), eq(false)))
            .thenAnswer(invocation -> {
                events.add("open:" + SwingUtilities.isEventDispatchThread());
                managerProject.set(opened);
                AppInfo.setActiveProject(opened);
                return opened;
            });
        when(opened.getName()).thenReturn("NewProject");

        GuiProjectService service = new GuiProjectService(
            security, () -> manager, () -> controller);
        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertEquals(List.of("save:true", "close:true", "notify-closed:true",
            "tool:null:true", "open:true", "tool:opened:true"), events);
        assertEquals(Boolean.TRUE, result.get("success"));
        assertEquals(Boolean.FALSE, result.get("already_active"));
        assertSame(opened, AppInfo.getActiveProject());
        assertSame(opened, controller.getActiveProject());
    }

    @Test
    public void openClosesHalfOpenedProjectWhenRestoreFails() throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectLocator locator = new ProjectLocator(parent.toString(), "NewProject");
        ProjectManager manager = mock(ProjectManager.class);
        Project partiallyOpened = mock(Project.class);
        AtomicReference<Project> managerProject = new AtomicReference<>();
        AtomicReference<Project> toolProject = new AtomicReference<>();
        when(manager.getActiveProject()).thenAnswer(invocation -> managerProject.get());
        when(manager.openProject(any(ProjectLocator.class), eq(true), eq(false)))
            .thenAnswer(invocation -> {
                managerProject.set(partiallyOpened);
                AppInfo.setActiveProject(partiallyOpened);
                throw new IOException("restore failed");
            });
        when(partiallyOpened.getProjectLocator()).thenReturn(locator);
        doAnswer(invocation -> {
            managerProject.set(null);
            AppInfo.setActiveProject(null);
            return null;
        }).when(partiallyOpened).close();

        GuiProjectService service = new GuiProjectService(
            security, () -> manager, () -> activeProjectController(toolProject));
        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertError(result, "project_open_failed");
        assertTrue(result.get("message").toString().contains("restore failed"));
        verify(partiallyOpened).close();
        assertNull(managerProject.get());
        assertNull(toolProject.get());
        assertNull(AppInfo.getActiveProject());
    }

    @Test
    public void openRetainsHalfOpenedProjectHoldersWhenCleanupCloseFails()
            throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectLocator locator = new ProjectLocator(parent.toString(), "NewProject");
        ProjectManager manager = mock(ProjectManager.class);
        Project partiallyOpened = mock(Project.class);
        AtomicReference<Project> managerProject = new AtomicReference<>();
        AtomicReference<Project> toolProject = new AtomicReference<>(partiallyOpened);
        when(manager.getActiveProject()).thenAnswer(invocation -> managerProject.get());
        when(manager.openProject(any(ProjectLocator.class), eq(true), eq(false)))
            .thenAnswer(invocation -> {
                managerProject.set(partiallyOpened);
                AppInfo.setActiveProject(partiallyOpened);
                throw new IOException("restore failed");
            });
        when(partiallyOpened.getProjectLocator()).thenReturn(locator);
        doAnswer(invocation -> {
            throw new IllegalStateException("close failed");
        }).when(partiallyOpened).close();

        GuiProjectService service = new GuiProjectService(
            security, () -> manager, () -> activeProjectController(toolProject));
        Map<String, Object> result = parse(service.openProject(marker.toString()));

        assertError(result, "project_open_failed");
        assertTrue(result.get("message").toString().contains("cleanup failed"));
        assertSame(partiallyOpened, managerProject.get());
        assertSame(partiallyOpened, toolProject.get());
        assertSame(partiallyOpened, AppInfo.getActiveProject());
    }

    @Test
    public void createRechecksDestinationOnEdtBeforeClosingCurrentProject() throws Exception {
        Path parent = newProjectsParent();
        Path marker = parent.resolve("NewProject.gpr");
        ProjectManager manager = mock(ProjectManager.class);

        GuiProjectService service = new GuiProjectService(security, () -> {
            try {
                Files.createFile(marker);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return manager;
        });
        Map<String, Object> result = parse(service.createProject(
            parent.toString(), "NewProject"));

        assertError(result, "destination_exists");
        verify(manager, never()).getActiveProject();
        verify(manager, never()).createProject(any(), any(), eq(true));
    }

    @Test
    public void createRechecksProjectDirectoryOnEdtBeforeClosingCurrentProject()
            throws Exception {
        Path parent = newProjectsParent();
        Path projectDir = parent.resolve("NewProject.rep");
        ProjectManager manager = mock(ProjectManager.class);

        GuiProjectService service = new GuiProjectService(security, () -> {
            createDanglingSymlink(projectDir, parent.resolve("missing-rep-target"));
            return manager;
        });
        Map<String, Object> result = parse(service.createProject(
            parent.toString(), "NewProject"));

        assertError(result, "destination_exists");
        verify(manager, never()).getActiveProject();
        verify(manager, never()).createProject(any(), any(), eq(true));
    }

    @Test
    public void createRechecksParentOnEdtBeforeClosingCurrentProject() throws Exception {
        Path parent = newProjectsParent();
        ProjectManager manager = mock(ProjectManager.class);

        GuiProjectService service = new GuiProjectService(security, () -> {
            try {
                Files.delete(parent);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return manager;
        });
        Map<String, Object> result = parse(service.createProject(
            parent.toString(), "NewProject"));

        assertError(result, "parent_not_found");
        verify(manager, never()).getActiveProject();
        verify(manager, never()).createProject(any(), any(), eq(true));
    }

    @Test
    public void createClosesReturnedProjectWhenActivationVerificationFails()
            throws Exception {
        Path parent = newProjectsParent();
        ProjectManager manager = mock(ProjectManager.class);
        Project created = mock(Project.class);
        when(manager.createProject(any(ProjectLocator.class), isNull(), eq(true)))
            .thenAnswer(invocation -> {
                assertTrue(SwingUtilities.isEventDispatchThread());
                return created;
            });
        when(created.getProjectLocator()).thenReturn(
            new ProjectLocator(parent.toString(), "NewProject"));
        doAnswer(invocation -> {
            assertTrue(SwingUtilities.isEventDispatchThread());
            return null;
        }).when(created).close();

        AtomicReference<Map<String, Object>> result = new AtomicReference<>();
        AtomicReference<Project> assigned = new AtomicReference<>();
        GuiProjectService.ActiveProjectController controller =
            new GuiProjectService.ActiveProjectController() {
                @Override
                public Project getActiveProject() {
                    return null;
                }

                @Override
                public void setActiveProject(Project project) {
                    assigned.set(project);
                }
            };
        SwingUtilities.invokeAndWait(() -> {
            try (MockedStatic<AppInfo> appInfo = mockStatic(AppInfo.class)) {
                appInfo.when(AppInfo::getActiveProject).thenReturn(null);
                GuiProjectService service = new GuiProjectService(
                    security, () -> manager, () -> controller);
                result.set(parse(service.createProject(parent.toString(), "NewProject")));
                appInfo.verify(() -> AppInfo.setActiveProject(created));
                appInfo.verify(() -> AppInfo.setActiveProject(null));
            }
        });

        assertError(result.get(), "project_creation_failed");
        assertEquals(Boolean.TRUE, result.get().get("created"));
        verify(created).close();
        assertNull(assigned.get());
    }

    @Test
    public void createFailureBeforeArtifactsLeavesNoActiveProjectAndDoesNotRollback()
            throws Exception {
        Path parent = newProjectsParent();
        ProjectManager manager = mock(ProjectManager.class);
        Project previous = mock(Project.class);
        AtomicReference<Project> active = new AtomicReference<>(previous);
        when(manager.getActiveProject()).thenAnswer(invocation -> active.get());
        doAnswer(invocation -> {
            active.set(null);
            AppInfo.setActiveProject(null);
            return null;
        }).when(previous).close();
        when(manager.createProject(any(ProjectLocator.class), isNull(), eq(true)))
            .thenThrow(new IOException("creation failed before artifacts"));
        AtomicReference<Project> toolProject = new AtomicReference<>(previous);
        GuiProjectService service = new GuiProjectService(
            security, () -> manager,
            () -> activeProjectController(toolProject));

        Map<String, Object> result = parse(service.createProject(
            parent.toString(), "NewProject"));

        assertError(result, "project_creation_failed");
        assertEquals(Boolean.FALSE, result.get("created"));
        assertEquals(parent.resolve("NewProject").toString(), result.get("path"));
        verify(previous).save();
        verify(previous).close();
        assertNull(AppInfo.getActiveProject());
        assertNull(toolProject.get());
        assertFalse(Files.exists(parent.resolve("NewProject.gpr")));
        assertFalse(Files.exists(parent.resolve("NewProject.rep")));
    }

    @Test
    public void createFailureClosesNewlyActiveProjectWithoutDeletingArtifacts() throws Exception {
        Path parent = newProjectsParent();
        Path marker = parent.resolve("NewProject.gpr");
        ProjectManager manager = mock(ProjectManager.class);
        Project previous = mock(Project.class);
        Project created = mock(Project.class);
        AtomicReference<Project> active = new AtomicReference<>(previous);

        when(manager.getActiveProject()).thenAnswer(invocation -> active.get());
        doAnswer(invocation -> {
            active.set(null);
            AppInfo.setActiveProject(null);
            return null;
        }).when(previous).close();
        when(manager.createProject(any(ProjectLocator.class), isNull(), eq(true)))
            .thenAnswer(invocation -> {
                assertTrue(SwingUtilities.isEventDispatchThread());
                Files.createFile(marker);
                active.set(created);
                AppInfo.setActiveProject(created);
                throw new IOException("creation failed after activation");
            });
        when(created.getProjectLocator()).thenAnswer(invocation ->
            new ProjectLocator(parent.toString(), "NewProject"));
        doAnswer(invocation -> {
            assertTrue(SwingUtilities.isEventDispatchThread());
            active.set(null);
            AppInfo.setActiveProject(null);
            return null;
        }).when(created).close();

        AtomicReference<Project> toolProject = new AtomicReference<>(previous);
        GuiProjectService service = new GuiProjectService(
            security, () -> manager,
            () -> activeProjectController(toolProject));
        Map<String, Object> result = parse(service.createProject(
            parent.toString(), "NewProject"));

        assertError(result, "project_creation_failed");
        assertEquals(Boolean.TRUE, result.get("created"));
        assertEquals(parent.resolve("NewProject").toString(), result.get("path"));
        verify(created).close();
        assertNull(AppInfo.getActiveProject());
        assertNull(toolProject.get());
        assertTrue(Files.exists(marker));
    }

    @Test
    public void udsCreateRouteParsesBodyAndSerializesServiceResponse() throws Exception {
        Path parent = newProjectsParent();
        ProjectManager manager = mock(ProjectManager.class);
        Project created = mock(Project.class);
        when(manager.createProject(any(ProjectLocator.class), isNull(), eq(true)))
            .thenAnswer(invocation -> {
                AppInfo.setActiveProject(created);
                return created;
            });
        when(created.getName()).thenReturn("NewProject");
        AtomicReference<Project> toolProject = new AtomicReference<>();
        GuiProjectService service = new GuiProjectService(
            security, () -> manager,
            () -> activeProjectController(toolProject));
        EndpointDef endpoint = new AnnotationScanner(service).getEndpoints().stream()
            .filter(candidate -> "/create_project".equals(candidate.path()))
            .findFirst()
            .orElseThrow();
        Response response = endpoint.handler().handle(Map.of(), Map.of(
            "parentDir", parent.toString(), "name", "NewProject"));
        Map<String, Object> result = JsonHelper.parseJson(response.toJson());

        assertEquals(Boolean.TRUE, result.get("success"));
        assertEquals("NewProject", result.get("project"));
        assertEquals(parent.resolve("NewProject").toString(), result.get("path"));
    }

    @Test
    public void udsOpenRouteRequiresPathAndSerializesServiceResponse() throws Exception {
        Path parent = newProjectsParent();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectLocator locator = new ProjectLocator(parent.toString(), "NewProject");
        ProjectManager manager = mock(ProjectManager.class);
        Project opened = mock(Project.class);
        AtomicReference<Project> managerProject = new AtomicReference<>();
        AtomicReference<Project> toolProject = new AtomicReference<>();
        when(manager.getActiveProject()).thenAnswer(invocation -> managerProject.get());
        when(manager.openProject(any(ProjectLocator.class), eq(true), eq(false)))
            .thenAnswer(invocation -> {
                managerProject.set(opened);
                AppInfo.setActiveProject(opened);
                return opened;
            });
        when(opened.getName()).thenReturn("NewProject");
        when(opened.getProjectLocator()).thenReturn(locator);
        GuiProjectService service = new GuiProjectService(
            security, () -> manager,
            () -> activeProjectController(toolProject));
        EndpointDef endpoint = new AnnotationScanner(service).getEndpoints().stream()
            .filter(candidate -> "/open_project".equals(candidate.path()))
            .findFirst()
            .orElseThrow();

        assertEquals("POST", endpoint.method());
        assertError(parse(endpoint.handler().handle(Map.of(), Map.of())),
            "invalid_request");
        Response response = endpoint.handler().handle(
            Map.of(), Map.of("path", marker.toString()));
        Map<String, Object> result = JsonHelper.parseJson(response.toJson());

        assertEquals(Boolean.TRUE, result.get("success"));
        assertEquals("NewProject", result.get("project"));
        assertEquals(marker.toString(), result.get("path"));
    }

    @Test
    public void bundledGhidraExposesFrontEndProjectListenerContract() throws Exception {
        try (InputStream classFile = getClass().getClassLoader().getResourceAsStream(
                "ghidra/framework/main/FrontEndTool.class")) {
            assertTrue("Bundled FrontEndTool.class must be on the test classpath",
                classFile != null);
            String constantPool = new String(classFile.readAllBytes(),
                StandardCharsets.ISO_8859_1);
            assertTrue("Ghidra FrontEndTool must declare getListeners",
                constantPool.contains("getListeners"));
            assertTrue("FrontEndTool.getListeners must retain its Iterable return type",
                constantPool.contains("()Ljava/lang/Iterable;"));
        }
    }

    /**
     * A canonical parent directory. The service resolves every destination path through
     * SecurityConfig, so on macOS an uncanonicalized TemporaryFolder path (/var/folders/...)
     * would not match the resolved form (/private/var/folders/...): assertions on the
     * returned path fail, and activation verification takes a different branch entirely.
     */
    private Path newProjectsParent() throws IOException {
        return temporaryFolder.newFolder("projects").toPath().toRealPath();
    }

    private Map<String, Object> createWithNoTool(Path parent, String name) {
        GuiProjectService service = new GuiProjectService(() -> null, security);
        return parse(service.createProject(parent.toString(), name));
    }

    private Map<String, Object> parse(Response response) {
        return JsonHelper.parseJson(response.toJson());
    }

    private PluginTool pluginToolOrSkip() {
        try {
            return mock(PluginTool.class);
        } catch (Throwable failure) {
            assumeNoException(failure);
            return null;
        }
    }

    private GuiProjectService.ActiveProjectController activeProjectController(
            AtomicReference<Project> project) {
        return new GuiProjectService.ActiveProjectController() {
            @Override
            public Project getActiveProject() {
                return project.get();
            }

            @Override
            public void setActiveProject(Project activeProject) {
                project.set(activeProject);
            }
        };
    }

    private void assertError(Map<String, Object> result, String category) {
        assertEquals(Boolean.FALSE, result.get("success"));
        assertEquals(result.toString(), category, result.get("category"));
        assertTrue(result.get("message") instanceof String);
        assertFalse(((String) result.get("message")).isBlank());
    }

    private void createDanglingSymlink(Path link, Path target) {
        try {
            Files.createSymbolicLink(link, target);
        } catch (IOException | UnsupportedOperationException e) {
            assumeNoException(e);
        }
    }

}
