package com.xebyte.core;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.function.Supplier;

import javax.swing.SwingUtilities;

import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectListener;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.plugintool.PluginTool;

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
            if (clearOnFailure) {
                closeFailedProject(manager, locator, created, activeProjects);
            }
            return creationError(destination,
                createdKnown || artifactsExist(markerPath, projectDirPath), message(e));
        }
    }

    private void closeFailedProject(ProjectManager manager, ProjectLocator locator,
            Project created, ActiveProjectController activeProjects) {
        Project failed = created;
        if (failed == null) {
            failed = manager.getActiveProject();
        }
        if (failed == null) {
            failed = AppInfo.getActiveProject();
        }
        if (failed != null && locator.equals(failed.getProjectLocator())) {
            try {
                failed.close();
                activeProjects.projectClosed(failed);
            } catch (Exception ignored) {
                // Keep the failure response; disk artifacts are intentionally preserved.
            }
        }
        try {
            activeProjects.setActiveProject(null);
        } catch (Exception ignored) {
            // AppInfo must still be cleared when FrontEnd cleanup fails.
        }
        AppInfo.setActiveProject(null);
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
