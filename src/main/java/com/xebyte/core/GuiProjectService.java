package com.xebyte.core;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Map;
import java.util.function.Supplier;

import javax.swing.SwingUtilities;

import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** Project lifecycle operations that require a live Ghidra GUI tool. */
public final class GuiProjectService {

    private final Supplier<PluginTool> toolSupplier;
    private final SecurityConfig security;
    private final Supplier<ProjectManager> projectManagerSupplier;

    public GuiProjectService(Supplier<PluginTool> toolSupplier) {
        this(toolSupplier, SecurityConfig.getInstance());
    }

    GuiProjectService(Supplier<PluginTool> toolSupplier, SecurityConfig security) {
        this(toolSupplier, security, () -> {
            PluginTool tool = toolSupplier.get();
            return tool != null ? tool.getProjectManager() : null;
        });
    }

    GuiProjectService(Supplier<PluginTool> toolSupplier, SecurityConfig security,
            Supplier<ProjectManager> projectManagerSupplier) {
        this.toolSupplier = toolSupplier;
        this.security = security;
        this.projectManagerSupplier = projectManagerSupplier;
    }

    /** Register project lifecycle endpoints on the shared UDS server. */
    public static void registerUdsEndpoints(UdsHttpServer server) {
        GuiProjectService service = new GuiProjectService(
            () -> ServerManager.getInstance().getActiveTool());
        registerUdsEndpoints(server, service);
    }

    static void registerUdsEndpoints(UdsHttpServer server, GuiProjectService service) {
        server.createContext("/create_project", exchange -> {
            Map<String, Object> params = JsonHelper.parseBody(exchange.getRequestBody());
            String parentDir = stringParam(params, "parentDir");
            String name = stringParam(params, "name");
            ServerManager.sendJsonResponse(exchange,
                service.createProject(parentDir, name).toJson());
        });

        server.createContext("/open_project", exchange -> {
            Map<String, Object> params = JsonHelper.parseBody(exchange.getRequestBody());
            String projectPath = stringParam(params, "path");
            boolean headless = params.get("headless") == null
                || Boolean.parseBoolean(String.valueOf(params.get("headless")));
            String program = stringParam(params, "program");
            ServerManager.sendJsonResponse(exchange,
                service.openProject(projectPath, headless, program));
        });
    }

    private static String stringParam(Map<String, Object> params, String name) {
        Object value = params.get(name);
        return value != null ? value.toString() : null;
    }

    public Response createProject(String parentDir, String name) {
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

    /** Open or switch to an existing GUI project. */
    public String openProject(String projectPath, boolean headless,
            String programToLaunch) {
        if (projectPath == null || projectPath.trim().isEmpty()) {
            return "{\"error\": \"path parameter is required\"}";
        }

        File pathFile = new File(projectPath);
        String location;
        String name;
        String projectExtension = ProjectLocator.getProjectExtension();
        String directoryExtension = ProjectLocator.getProjectDirExtension();
        String filename = pathFile.getName();
        if (filename.endsWith(projectExtension)) {
            location = pathFile.getParent();
            name = filename.substring(0, filename.length() - projectExtension.length());
        } else if (filename.endsWith(directoryExtension)) {
            location = pathFile.getParent();
            name = filename.substring(0, filename.length() - directoryExtension.length());
        } else {
            location = pathFile.getParent();
            name = filename;
        }
        if (location == null || location.isEmpty()) {
            return "{\"error\": \"path must include a parent directory: "
                + escapeJson(projectPath) + "\"}";
        }

        ProjectLocator locator;
        try {
            locator = new ProjectLocator(location, name);
        } catch (IllegalArgumentException e) {
            return "{\"error\": \"Invalid project path: " + escapeJson(e.getMessage())
                + "\"}";
        }
        if (!locator.exists()) {
            return "{\"error\": \"Project does not exist: " + escapeJson(projectPath)
                + "\"}";
        }

        PluginTool tool = toolSupplier.get();
        if (tool == null) {
            return "{\"error\": \"No active GUI tool\"}";
        }
        Project currentProject = tool.getProject();
        if (currentProject != null && locator.equals(currentProject.getProjectLocator())) {
            String launchResult = null;
            if (!headless && programToLaunch != null && !programToLaunch.isEmpty()) {
                launchResult = launchCodeBrowser(programToLaunch);
            }
            return "{\"success\": true, \"project\": \"" + escapeJson(name) + "\", "
                + "\"already_open\": true, \"headless\": " + headless
                + (launchResult != null
                    ? ", \"program_launch_result\": " + launchResult : "")
                + "}";
        }

        ProjectManager manager = tool.getProjectManager();
        if (manager == null) {
            return "{\"error\": \"ProjectManager not available on this tool\"}";
        }

        String[] error = {null};
        Project[] opened = {null};
        Runnable openTask = () -> {
            try {
                if (currentProject != null) {
                    try {
                        currentProject.save();
                    } catch (Exception ignored) {
                        // Preserve the existing best-effort save policy.
                    }
                    currentProject.close();
                }
                Project project = manager.openProject(locator, true, false);
                if (project == null) {
                    error[0] = "ProjectManager.openProject returned null";
                    return;
                }
                AppInfo.setActiveProject(project);
                opened[0] = project;
            } catch (Exception e) {
                error[0] = e.getClass().getSimpleName() + ": " + e.getMessage();
            }
        };
        try {
            if (SwingUtilities.isEventDispatchThread()) {
                openTask.run();
            } else {
                SwingUtilities.invokeAndWait(openTask);
            }
        } catch (Exception e) {
            return "{\"error\": \"EDT invocation failed: " + escapeJson(e.getMessage())
                + "\"}";
        }
        if (error[0] != null) {
            return "{\"error\": \"Failed to open project: " + escapeJson(error[0])
                + "\"}";
        }
        if (opened[0] == null) {
            return "{\"error\": \"openProject returned null without an error\"}";
        }

        String launchResult = null;
        if (!headless && programToLaunch != null && !programToLaunch.isEmpty()) {
            launchResult = launchCodeBrowser(programToLaunch);
        }
        StringBuilder json = new StringBuilder(256);
        json.append("{\"success\": true, \"project\": \"")
            .append(escapeJson(opened[0].getName()))
            .append("\", \"headless\": ").append(headless);
        if (launchResult != null) {
            json.append(", \"program_launch_result\": ").append(launchResult);
        }
        json.append("}");
        return json.toString();
    }

    /** Launch a CodeBrowser, optionally opening a project file. */
    public String launchCodeBrowser(String filePath) {
        PluginTool tool = toolSupplier.get();
        Project project = tool != null ? tool.getProject() : null;
        if (project == null) {
            return "{\"error\": \"No project open\"}";
        }

        DomainFile domainFile = null;
        if (filePath != null && !filePath.trim().isEmpty()) {
            domainFile = project.getProjectData().getFile(filePath);
            if (domainFile == null) {
                return "{\"error\": \"File not found in project: " + escapeJson(filePath)
                    + "\"}";
            }
        }

        try {
            ghidra.framework.model.ToolServices toolServices = project.getToolServices();
            if (toolServices == null) {
                return "{\"error\": \"ToolServices not available\"}";
            }

            ghidra.framework.model.ToolManager toolManager = project.getToolManager();
            PluginTool codeBrowser = null;
            if (toolManager != null) {
                for (PluginTool runningTool : toolManager.getRunningTools()) {
                    if (runningTool.getService(ghidra.app.services.ProgramManager.class)
                            != null) {
                        codeBrowser = runningTool;
                        break;
                    }
                }
            }

            if (codeBrowser != null && domainFile != null) {
                ghidra.app.services.ProgramManager programManager = codeBrowser.getService(
                    ghidra.app.services.ProgramManager.class);
                Program program = (Program) domainFile.getDomainObject(
                    this, false, false, TaskMonitor.DUMMY);
                SwingUtilities.invokeAndWait(() -> {
                    programManager.openProgram(program);
                    programManager.setCurrentProgram(program);
                });
                return "{\"success\": true, \"message\": "
                    + "\"Opened in existing CodeBrowser\", \"tool\": \""
                    + escapeJson(codeBrowser.getName()) + "\", \"program\": \""
                    + escapeJson(program.getName()) + "\", \"path\": \""
                    + escapeJson(filePath) + "\"}";
            }
            if (domainFile != null) {
                DomainFile file = domainFile;
                SwingUtilities.invokeAndWait(() ->
                    toolServices.launchDefaultTool(Collections.singletonList(file)));
                return "{\"success\": true, \"message\": "
                    + "\"Launched new CodeBrowser\", \"path\": \""
                    + escapeJson(filePath) + "\"}";
            }

            SwingUtilities.invokeAndWait(() ->
                toolServices.launchDefaultTool(Collections.emptyList()));
            return "{\"success\": true, \"message\": "
                + "\"Launched new CodeBrowser (no file)\"}";
        } catch (Exception e) {
            return "{\"error\": \"Failed to launch CodeBrowser: "
                + escapeJson(e.getMessage()) + "\"}";
        }
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

        Project current = manager.getActiveProject();
        if (current != null) {
            try {
                current.save();
            } catch (Exception ignored) {
                // Match the existing /open_project best-effort save policy.
            }
            current.close();
        }

        Project created = null;
        boolean createdKnown = false;
        try {
            created = manager.createProject(locator, null, true);
            if (created == null) {
                throw new IOException("ProjectManager.createProject returned null");
            }
            createdKnown = true;
            AppInfo.setActiveProject(created);
            if (AppInfo.getActiveProject() != created) {
                throw new IllegalStateException("Created project did not become active");
            }
            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "project", created.getName(),
                "path", destination,
                "active", true));
        } catch (Exception e) {
            closeFailedProject(manager, locator, created);
            return creationError(destination,
                createdKnown || artifactsExist(markerPath, projectDirPath), message(e));
        }
    }

    private void closeFailedProject(ProjectManager manager, ProjectLocator locator,
            Project created) {
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
            } catch (Exception ignored) {
                // Keep the failure response; disk artifacts are intentionally preserved.
            }
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

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }
}
