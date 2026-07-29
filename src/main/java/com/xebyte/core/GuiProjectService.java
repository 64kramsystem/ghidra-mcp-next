package com.xebyte.core;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import javax.swing.SwingUtilities;

import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectListener;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.PluginToolAccessUtils;

/** Project lifecycle operations that require a live Ghidra GUI tool. */
public final class GuiProjectService {

    interface ActiveProjectController {
        Project getActiveProject();

        void setActiveProject(Project project);

        default void projectClosed(Project project) {
            // Test controllers and non-FrontEnd implementations have no listeners.
        }
    }

    private final SecurityConfig security;
    private final Supplier<ProjectManager> projectManagerSupplier;
    private final Supplier<ActiveProjectController> activeProjectControllerSupplier;

    public GuiProjectService(Supplier<PluginTool> toolSupplier) {
        this(toolSupplier, SecurityConfig.getInstance());
    }

    GuiProjectService(Supplier<PluginTool> toolSupplier, SecurityConfig security) {
        this(security, () -> {
            PluginTool tool = toolSupplier.get();
            return tool != null ? tool.getProjectManager() : null;
        }, GuiProjectService::frontEndProjectController);
    }

    GuiProjectService(SecurityConfig security,
            Supplier<ProjectManager> projectManagerSupplier) {
        this(security, projectManagerSupplier,
            GuiProjectService::frontEndProjectController);
    }

    GuiProjectService(SecurityConfig security,
            Supplier<ProjectManager> projectManagerSupplier,
            Supplier<ActiveProjectController> activeProjectControllerSupplier) {
        this.security = security;
        this.projectManagerSupplier = projectManagerSupplier;
        this.activeProjectControllerSupplier = activeProjectControllerSupplier;
    }

    private static ActiveProjectController frontEndProjectController() {
        FrontEndTool frontEnd = AppInfo.getFrontEndTool();
        return new ActiveProjectController() {
            @Override
            public Project getActiveProject() {
                return frontEnd.getProject();
            }

            @Override
            public void setActiveProject(Project project) {
                frontEnd.setActiveProject(project);
            }

            @Override
            public void projectClosed(Project project) {
                notifyProjectClosed(frontEnd, project);
            }
        };
    }

    private static void notifyProjectClosed(FrontEndTool frontEnd, Project project) {
        try {
            // Ghidra 12.1.2 keeps listener enumeration package-private. Its own
            // FileActionManager calls projectClosed after Project.close(), but
            // ProjectManager's public API does not. Mirror that required step so
            // RecoverySnapshotMgr and other FrontEnd listeners release the old
            // project before setActiveProject advertises the replacement.
            Method getListeners = FrontEndTool.class.getDeclaredMethod("getListeners");
            getListeners.setAccessible(true);
            Object listeners = getListeners.invoke(frontEnd);
            if (listeners instanceof Iterable<?> iterable) {
                for (Object listener : iterable) {
                    ((ProjectListener) listener).projectClosed(project);
                }
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            throw new IllegalStateException(
                "Unable to notify FrontEnd project listeners of project closure", e);
        }
    }

    @McpTool(path = "/create_project", method = "POST",
        description = "Create and activate a new local Ghidra project")
    public Response createProject(
            @Param(value = "parentDir", source = ParamSource.BODY,
                description = "Existing local directory that will contain the project")
            String parentDir,
            @Param(value = "name", source = ParamSource.BODY,
                description = "Name for the new Ghidra project")
            String name) {
        if (parentDir == null || parentDir.isBlank() || name == null || name.isBlank()) {
            return error("invalid_request", "parentDir and name are required");
        }

        File parent;
        try {
            parent = new File(parentDir).getCanonicalFile();
        } catch (IOException e) {
            return error("invalid_request", "Invalid parent directory: " + e.getMessage());
        }
        if (!parent.exists()) {
            return error("parent_not_found", "Parent directory does not exist: " + parent);
        }
        if (!parent.isDirectory()) {
            return error("parent_not_directory", "Parent path is not a directory: " + parent);
        }

        ProjectLocator locator;
        try {
            locator = new ProjectLocator(parent.getPath(), name);
        } catch (IllegalArgumentException e) {
            return error("invalid_project_name", e.getMessage());
        }

        Path markerPath = locator.getMarkerFile().toPath();
        Path projectDirPath = locator.getProjectDir().toPath();
        String destination = destination(parent, locator.getName());
        if (security.resolveWithinFileRoot(parent.getPath()) == null
                || security.resolveWithinFileRoot(markerPath.toString()) == null
                || security.resolveWithinFileRoot(projectDirPath.toString()) == null) {
            return error("path_not_allowed", "Project destination is outside GHIDRA_MCP_FILE_ROOT");
        }
        if (artifactsExist(markerPath, projectDirPath)) {
            return error("destination_exists", "Project destination already exists: "
                + destination);
        }

        ProjectManager manager = projectManagerSupplier.get();
        if (manager == null) {
            return error("project_manager_unavailable", "ProjectManager is not available");
        }

        Response[] result = new Response[1];
        try {
            runOnEdt(() -> result[0] = createOnEdt(
                parent, locator, manager, markerPath, projectDirPath, destination));
        } catch (Exception e) {
            return creationError(destination, artifactsExist(markerPath, projectDirPath),
                "EDT invocation failed: " + message(e));
        }
        return result[0];
    }

    @McpTool(path = "/open_project", method = "POST",
        description = "Open an existing local project; refuses unsaved data or "
            + "busy/unclosable tools, saves project state best-effort, then closes the active "
            + "project")
    public Response openProject(
            @Param(value = "path", source = ParamSource.BODY,
                description = "Absolute path to an existing .gpr file")
            String projectPath) {
        if (projectPath == null || projectPath.isBlank()) {
            return error("invalid_request", "path is required");
        }

        File marker = new File(projectPath);
        if (!marker.isAbsolute()
                || !marker.getName().endsWith(ProjectLocator.getProjectExtension())) {
            return error("invalid_request", "path must be an absolute .gpr file");
        }
        try {
            marker = marker.getCanonicalFile();
        } catch (IOException e) {
            return error("invalid_request", "Invalid project path: " + e.getMessage());
        }
        if (security.resolveWithinFileRoot(marker.getPath()) == null) {
            return error("path_not_allowed", "Project is outside GHIDRA_MCP_FILE_ROOT");
        }

        String fileName = marker.getName();
        String name = fileName.substring(
            0, fileName.length() - ProjectLocator.getProjectExtension().length());
        ProjectLocator locator;
        try {
            locator = new ProjectLocator(marker.getParent(), name);
        } catch (IllegalArgumentException e) {
            return error("invalid_request", "Invalid project path: " + e.getMessage());
        }
        try {
            if (security.resolveWithinFileRoot(
                    locator.getProjectDir().getCanonicalPath()) == null) {
                return error("path_not_allowed",
                    "Project directory is outside GHIDRA_MCP_FILE_ROOT");
            }
        } catch (IOException e) {
            return error("invalid_request", "Invalid project directory: " + e.getMessage());
        }

        ProjectManager manager = projectManagerSupplier.get();
        if (manager == null) {
            return error("project_manager_unavailable", "ProjectManager is not available");
        }

        Response[] result = new Response[1];
        File canonicalMarker = marker;
        try {
            runOnEdt(() -> result[0] = openOnEdt(
                canonicalMarker, locator, manager));
        } catch (Exception e) {
            return error("project_open_failed", "EDT invocation failed: " + message(e));
        }
        return result[0];
    }

    private Response openOnEdt(File marker, ProjectLocator locator, ProjectManager manager) {
        if (!locator.exists()) {
            return error("project_not_found", "Project does not exist: " + marker);
        }

        ActiveProjectController activeProjects = activeProjectControllerSupplier.get();
        if (activeProjects == null) {
            return error("project_open_failed", "FrontEndTool is not available");
        }

        Project current = manager.getActiveProject();
        if (current != null) {
            try {
                if (marker.equals(
                        current.getProjectLocator().getMarkerFile().getCanonicalFile())) {
                    return Response.ok(JsonHelper.mapOf(
                        "success", true,
                        "project", locator.getName(),
                        "path", marker.getPath(),
                        "active", true,
                        "already_active", true));
                }
            } catch (IOException e) {
                return error("project_open_failed",
                    "Failed to identify current project: " + message(e));
            }

            Response preparationFailure = prepareToClose(current);
            if (preparationFailure != null) {
                return preparationFailure;
            }

            Exception closeFailure = null;
            try {
                current.close();
            } catch (Exception e) {
                closeFailure = e;
            }

            boolean closed = closeFailure == null;
            if (!closed) {
                try {
                    closed = current.isClosed();
                } catch (RuntimeException ignored) {
                    closed = false;
                }
            }
            if (closed) {
                try {
                    activeProjects.projectClosed(current);
                } catch (Exception e) {
                    if (closeFailure == null) {
                        closeFailure = e;
                    }
                }
                try {
                    activeProjects.setActiveProject(null);
                } finally {
                    AppInfo.setActiveProject(null);
                }
            }
            if (closeFailure != null) {
                return error("project_open_failed",
                    "Failed to close current project: " + message(closeFailure));
            }
        }

        Project opened = null;
        try {
            opened = manager.openProject(locator, true, false);
            if (opened == null) {
                throw new IOException("ProjectManager.openProject returned null");
            }
            activeProjects.setActiveProject(opened);
            AppInfo.setActiveProject(opened);
            if (activeProjects.getActiveProject() != opened
                    || AppInfo.getActiveProject() != opened) {
                throw new IllegalStateException("Opened project did not become active");
            }
            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "project", opened.getName(),
                "path", marker.getPath(),
                "active", true,
                "already_active", false));
        } catch (Exception e) {
            boolean cleaned = closeFailedProject(
                manager, locator, opened, activeProjects);
            String detail = "Failed to open project: " + message(e);
            if (!cleaned) {
                detail += "; cleanup failed and the partial project remains active";
            }
            return error("project_open_failed", detail);
        }
    }

    private Response prepareToClose(Project project) {
        if (project.getToolManager() != null) {
            PluginTool[] tools = project.getToolManager().getRunningTools();
            Map<String, Integer> changedToolNames = new HashMap<>();
            for (PluginTool tool : tools) {
                if (tool.isExecutingCommand()) {
                    return error("project_close_refused",
                        "A project tool is busy: " + tool.getName());
                }
                if (tool.hasConfigChanged()) {
                    changedToolNames.merge(tool.getToolName(), 1, Integer::sum);
                }
            }
            if (changedToolNames.values().stream().anyMatch(count -> count > 1)) {
                return error("project_close_refused",
                    "Multiple changed session tools share a name; save them before switching");
            }
            for (PluginTool tool : tools) {
                if (!PluginToolAccessUtils.canClose(tool)) {
                    return error("project_close_refused",
                        "A project tool refused to close: " + tool.getName());
                }
            }
        }

        List<DomainFile> openData = project.getOpenData();
        if (openData != null) {
            for (DomainFile file : openData) {
                if (file.isChanged()) {
                    return error("unsaved_changes",
                        "Save modified project data before opening another project: "
                            + file.getPathname());
                }
            }
        }

        if (project.getToolManager() != null && !project.saveSessionTools()) {
            return error("project_open_failed",
                "Failed to save current project session tools");
        }

        project.save();
        return null;
    }

    private Response createOnEdt(File parent, ProjectLocator locator, ProjectManager manager,
            Path markerPath, Path projectDirPath, String destination) {
        if (!parent.exists()) {
            return error("parent_not_found", "Parent directory does not exist: " + parent);
        }
        if (!parent.isDirectory()) {
            return error("parent_not_directory", "Parent path is not a directory: " + parent);
        }
        if (artifactsExist(markerPath, projectDirPath)) {
            return error("destination_exists", "Project destination already exists: "
                + destination);
        }
        ActiveProjectController activeProjects = activeProjectControllerSupplier.get();
        if (activeProjects == null) {
            return creationError(destination, false,
                "FrontEndTool is not available for project activation");
        }

        Project created = null;
        boolean createdKnown = false;
        boolean clearOnFailure = false;
        try {
            Project current = manager.getActiveProject();
            if (current != null) {
                try {
                    current.save();
                } catch (Exception ignored) {
                    // Preserve the current project when possible.
                }
                current.close();
                activeProjects.projectClosed(current);
                clearOnFailure = true;
                activeProjects.setActiveProject(null);
                AppInfo.setActiveProject(null);
            }

            clearOnFailure = true;
            created = manager.createProject(locator, null, true);
            if (created == null) {
                throw new IOException("ProjectManager.createProject returned null");
            }
            createdKnown = true;
            activeProjects.setActiveProject(created);
            AppInfo.setActiveProject(created);
            if (AppInfo.getActiveProject() != created
                    || activeProjects.getActiveProject() != created) {
                throw new IllegalStateException("Created project did not become active");
            }
            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "project", created.getName(),
                "path", destination,
                "active", true));
        } catch (Exception e) {
            boolean cleaned = true;
            if (clearOnFailure) {
                cleaned = closeFailedProject(
                    manager, locator, created, activeProjects);
            }
            String detail = message(e);
            if (!cleaned) {
                detail += "; cleanup failed and the partial project remains active";
            }
            return creationError(destination,
                createdKnown || artifactsExist(markerPath, projectDirPath), detail);
        }
    }

    private boolean closeFailedProject(ProjectManager manager, ProjectLocator locator,
            Project created, ActiveProjectController activeProjects) {
        Project failed = created;
        if (failed == null) {
            failed = manager.getActiveProject();
        }
        if (failed == null) {
            failed = AppInfo.getActiveProject();
        }
        if (failed == null) {
            return true;
        }
        if (!locator.equals(failed.getProjectLocator())) {
            return false;
        }

        Exception closeFailure = null;
        try {
            failed.close();
        } catch (Exception e) {
            closeFailure = e;
        }

        boolean closed = closeFailure == null;
        if (!closed) {
            try {
                closed = failed.isClosed();
            } catch (RuntimeException ignored) {
                closed = false;
            }
        }
        if (!closed) {
            return false;
        }

        try {
            activeProjects.projectClosed(failed);
        } catch (Exception ignored) {
            // The project is closed; holder normalization must still complete.
        }

        try {
            activeProjects.setActiveProject(null);
        } catch (Exception ignored) {
            // AppInfo must still be cleared when FrontEnd cleanup fails.
        }
        AppInfo.setActiveProject(null);
        return true;
    }

    private void runOnEdt(Runnable task) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            task.run();
        } else {
            SwingUtilities.invokeAndWait(task);
        }
    }

    private boolean artifactsExist(Path markerPath, Path projectDirPath) {
        return Files.exists(markerPath, LinkOption.NOFOLLOW_LINKS)
            || Files.exists(projectDirPath, LinkOption.NOFOLLOW_LINKS);
    }

    private String destination(File parent, String name) {
        return parent.toPath().resolve(name).toString();
    }

    private String message(Exception e) {
        String detail = e.getMessage();
        return e.getClass().getSimpleName() + (detail != null ? ": " + detail : "");
    }

    private Response creationError(String destination, boolean created, String message) {
        return Response.ok(JsonHelper.mapOf(
            "success", false,
            "category", "project_creation_failed",
            "message", message,
            "path", destination,
            "created", created));
    }

    private Response error(String category, String message) {
        return Response.ok(JsonHelper.mapOf(
            "success", false,
            "category", category,
            "message", message));
    }

}
