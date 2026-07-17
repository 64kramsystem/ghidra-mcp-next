package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
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
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;

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
    public void createRejectsParentThatIsNotDirectory() throws Exception {
        Path file = temporaryFolder.newFile("parent-file").toPath();
        Map<String, Object> result = createWithNoTool(file, "NewProject");

        assertError(result, "parent_not_directory");
    }

    @Test
    public void createUsesProjectLocatorNameValidation() throws Exception {
        Path parent = temporaryFolder.newFolder("projects").toPath();
        Map<String, Object> result = createWithNoTool(parent, "bad/name");

        assertError(result, "invalid_project_name");
    }

    @Test
    public void createRequiresEachDestinationPathWithinFileRoot() throws Exception {
        Path parent = temporaryFolder.newFolder("projects").toPath();
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
        Path parent = temporaryFolder.newFolder("projects").toPath();
        Files.createDirectory(parent.resolve("NewProject.gpr"));

        Map<String, Object> result = createWithNoTool(parent, "NewProject");

        assertError(result, "destination_exists");
    }

    @Test
    public void createRejectsExistingProjectDirectoryRegardlessOfType() throws Exception {
        Path parent = temporaryFolder.newFolder("projects").toPath();
        Files.createFile(parent.resolve("NewProject.rep"));

        Map<String, Object> result = createWithNoTool(parent, "NewProject");

        assertError(result, "destination_exists");
    }

    @Test
    public void createRejectsDanglingMarkerSymlink() throws Exception {
        Path parent = temporaryFolder.newFolder("projects").toPath();
        createDanglingSymlink(
            parent.resolve("NewProject.gpr"), parent.resolve("missing-marker-target"));

        Map<String, Object> result = createWithNoTool(parent, "NewProject");

        assertError(result, "destination_exists");
    }

    @Test
    public void createRejectsUnavailableProjectManager() throws Exception {
        Path parent = temporaryFolder.newFolder("projects").toPath();
        GuiProjectService service = new GuiProjectService(() -> null, security);

        Map<String, Object> result = parse(service.createProject(
            parent.toString(), "NewProject"));

        assertError(result, "project_manager_unavailable");
    }

    @Test
    public void createRunsLifecycleAsOneEdtTaskAndActivatesProject() throws Exception {
        Path parent = temporaryFolder.newFolder("projects").toPath();
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
            () -> null, security, () -> manager, () -> controller);
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
        Path parent = temporaryFolder.newFolder("projects").toPath();
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
            () -> null, security, () -> manager,
            () -> activeProjectController(toolProject));

        Map<String, Object> result = parse(service.createProject(
            parent.toString(), "NewProject.gpr"));

        assertEquals(Boolean.TRUE, result.get("success"));
        assertEquals("NewProject", result.get("project"));
        assertEquals(parent.resolve("NewProject").toString(), result.get("path"));
    }

    @Test
    public void openRunsLifecycleThroughFrontEndControllerOnEdt() throws Exception {
        Path parent = temporaryFolder.newFolder("projects").toPath();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectManager manager = mock(ProjectManager.class);
        Project previous = mock(Project.class);
        Project opened = mock(Project.class);
        AtomicReference<Project> managerProject = new AtomicReference<>(previous);
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
            () -> null, security, () -> manager, () -> controller);
        Map<String, Object> result = JsonHelper.parseJson(
            service.openProject(marker.toString(), true, null));

        assertEquals(List.of("save:true", "close:true", "notify-closed:true",
            "tool:null:true", "open:true", "tool:opened:true"), events);
        assertEquals(Boolean.TRUE, result.get("success"));
        assertSame(opened, AppInfo.getActiveProject());
        assertSame(opened, controller.getActiveProject());
    }

    @Test
    public void openCleansManagerProjectWhenRestoreFailsBeforeReturn() throws Exception {
        Path parent = temporaryFolder.newFolder("projects").toPath();
        Path marker = Files.createFile(parent.resolve("NewProject.gpr"));
        Files.createDirectory(parent.resolve("NewProject.rep"));
        ProjectManager manager = mock(ProjectManager.class);
        Project partiallyOpened = mock(Project.class);
        ProjectLocator locator = new ProjectLocator(parent.toString(), "NewProject");
        AtomicReference<Project> managerProject = new AtomicReference<>();
        AtomicReference<Project> toolProject = new AtomicReference<>();

        when(manager.getActiveProject()).thenAnswer(invocation -> managerProject.get());
        when(manager.openProject(any(ProjectLocator.class), eq(true), eq(false)))
            .thenAnswer(invocation -> {
                assertTrue(SwingUtilities.isEventDispatchThread());
                managerProject.set(partiallyOpened);
                AppInfo.setActiveProject(partiallyOpened);
                throw new IOException("restore failed after activation");
            });
        when(partiallyOpened.getProjectLocator()).thenReturn(locator);
        doAnswer(invocation -> {
            assertTrue(SwingUtilities.isEventDispatchThread());
            managerProject.set(null);
            AppInfo.setActiveProject(null);
            return null;
        }).when(partiallyOpened).close();

        GuiProjectService service = new GuiProjectService(
            () -> null, security, () -> manager,
            () -> activeProjectController(toolProject));
        Map<String, Object> result = JsonHelper.parseJson(
            service.openProject(marker.toString(), true, null));

        assertTrue(result.get("error").toString().contains("restore failed"));
        verify(partiallyOpened).close();
        assertNull(managerProject.get());
        assertNull(toolProject.get());
        assertNull(AppInfo.getActiveProject());
    }

    @Test
    public void createRechecksDestinationOnEdtBeforeClosingCurrentProject() throws Exception {
        Path parent = temporaryFolder.newFolder("projects").toPath();
        Path marker = parent.resolve("NewProject.gpr");
        ProjectManager manager = mock(ProjectManager.class);

        GuiProjectService service = new GuiProjectService(() -> null, security, () -> {
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
        Path parent = temporaryFolder.newFolder("projects").toPath();
        Path projectDir = parent.resolve("NewProject.rep");
        ProjectManager manager = mock(ProjectManager.class);

        GuiProjectService service = new GuiProjectService(() -> null, security, () -> {
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
        Path parent = temporaryFolder.newFolder("projects").toPath();
        ProjectManager manager = mock(ProjectManager.class);

        GuiProjectService service = new GuiProjectService(() -> null, security, () -> {
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
        Path parent = temporaryFolder.newFolder("projects").toPath();
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
                    () -> null, security, () -> manager, () -> controller);
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
        Path parent = temporaryFolder.newFolder("projects").toPath();
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
            () -> null, security, () -> manager,
            () -> activeProjectController(toolProject));

        Map<String, Object> result = parse(service.createProject(
            parent.toString(), "NewProject"));

        assertError(result, "project_creation_failed");
        assertEquals(Boolean.FALSE, result.get("created"));
        assertEquals(parent.resolve("NewProject").toString(), result.get("path"));
        verify(previous).save();
        verify(previous).close();
        verify(manager, never()).openProject(
            any(ProjectLocator.class), anyBoolean(), anyBoolean());
        assertNull(AppInfo.getActiveProject());
        assertNull(toolProject.get());
        assertFalse(Files.exists(parent.resolve("NewProject.gpr")));
        assertFalse(Files.exists(parent.resolve("NewProject.rep")));
    }

    @Test
    public void createFailureClosesNewlyActiveProjectWithoutDeletingArtifacts() throws Exception {
        Path parent = temporaryFolder.newFolder("projects").toPath();
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
            () -> null, security, () -> manager,
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
        Path parent = temporaryFolder.newFolder("projects").toPath();
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
            () -> null, security, () -> manager,
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

    private Map<String, Object> createWithNoTool(Path parent, String name) {
        GuiProjectService service = new GuiProjectService(() -> null, security);
        return parse(service.createProject(parent.toString(), name));
    }

    private Map<String, Object> parse(Response response) {
        return JsonHelper.parseJson(response.toJson());
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
