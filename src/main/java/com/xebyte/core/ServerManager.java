package com.xebyte.core;

import com.sun.net.httpserver.HttpServer;

import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

/** Owns one schema and the local transports shared by all Ghidra tool windows. */
public final class ServerManager {

    private static ServerManager instance;

    public static synchronized ServerManager getInstance() {
        if (instance == null) {
            instance = new ServerManager();
        }
        return instance;
    }

    private final Map<String, PluginTool> tools = new ConcurrentHashMap<>();
    private final AtomicReference<String> activeToolId = new AtomicReference<>();
    private MultiToolProgramProvider programProvider;
    private UdsHttpServer udsServer;
    private HttpServer tcpServer;
    private ExecutorService tcpExecutor;
    private AnnotationScanner scanner;
    private String serviceOwner;
    private boolean tcpRequested;
    private int tcpPort = 8089;

    private ServerManager() {
    }

    public synchronized void registerTool(
            PluginTool tool, boolean enableTcp, int port) throws IOException {
        String toolId = String.valueOf(System.identityHashCode(tool));
        tools.put(toolId, tool);
        activeToolId.compareAndSet(null, toolId);
        tcpRequested |= enableTcp;
        if (enableTcp) {
            tcpPort = port;
        }

        if (udsServer == null) {
            start(toolId, tool);
        } else if (enableTcp && tcpServer == null) {
            startTcp(port);
        }
    }

    public synchronized void deregisterTool(PluginTool tool) {
        String toolId = String.valueOf(System.identityHashCode(tool));
        tools.remove(toolId);
        if (toolId.equals(activeToolId.get())) {
            activeToolId.set(tools.keySet().stream().findFirst().orElse(null));
        }
        if (tools.isEmpty()) {
            stop(true);
            instance = null;
            return;
        }
        if (toolId.equals(serviceOwner)) {
            String nextId = tools.keySet().iterator().next();
            PluginTool nextTool = tools.get(nextId);
            stop(false);
            try {
                start(nextId, nextTool);
            } catch (IOException error) {
                Msg.error(this, "Could not restart GhidraMCP-next", error);
            }
        }
    }

    public PluginTool getActiveTool() {
        return programProvider == null ? null : programProvider.getActiveTool();
    }

    public Path getSocketPath() {
        return udsServer == null ? null : udsServer.getSocketPath();
    }

    public int getBoundTcpPort() {
        return tcpServer == null ? -1 : tcpServer.getAddress().getPort();
    }

    private void start(String owner, PluginTool tool) throws IOException {
        serviceOwner = owner;
        if (programProvider == null) {
            programProvider = new MultiToolProgramProvider(tools, activeToolId);
        }
        ThreadingStrategy threading = new SwingThreadingStrategy();

        FunctionService functions = new FunctionService(programProvider, threading);
        scanner = new AnnotationScanner(
            new ListingService(programProvider),
            functions,
            new CommentService(programProvider, threading),
            new SymbolLabelService(programProvider, threading),
            new EquateService(programProvider, threading),
            new XrefCallGraphService(programProvider, threading),
            new DataTypeService(programProvider, threading),
            new AnalysisService(programProvider),
            new ProgramScriptService(programProvider, threading),
            new MemoryBlockService(programProvider, threading),
            new DataRegionService(programProvider, threading),
            new ControlFlowService(programProvider, threading),
            new ExportService(programProvider),
            new ProjectArchiveService(this::activeProject, threading),
            new FlowDisassemblyService(programProvider, threading),
            new ListingRangeService(programProvider, threading),
            new ListingMutationService(programProvider, threading),
            new AddressEncodingSearchService(programProvider, threading),
            new CoverageService(programProvider, threading),
            new DebuggerService(programProvider, threading, tool),
            new GuiProjectService(
                this::getActiveTool, programProvider::releaseOwnedPrograms),
            new GuiContextService(this::getActiveTool, programProvider));

        startUds();
        if (tcpRequested) {
            startTcp(tcpPort);
        }
        Msg.info(
            this,
            VersionPayload.getFullVersion() + ", "
                + scanner.getDescriptors().size() + " MCP tools");
    }

    private Project activeProject() {
        PluginTool active = getActiveTool();
        return active == null ? null : active.getProject();
    }

    private void startUds() throws IOException {
        Path socketDir = resolveSocketDir(
            System.getenv("XDG_RUNTIME_DIR"),
            System.getenv("TMPDIR"),
            System.getProperty("java.io.tmpdir"),
            System.getProperty("user.name", "unknown"));
        Files.createDirectories(socketDir);
        hardenSocketDir(socketDir);
        cleanStaleSockets(socketDir);
        udsServer = new UdsHttpServer(
            socketDir.resolve("ghidra-" + ProcessHandle.current().pid() + ".sock"));
        registerUdsContexts();
        udsServer.start();
    }

    private void startTcp(int port) {
        try {
            tcpServer = HttpServer.create(
                new InetSocketAddress("127.0.0.1", port), 0);
            for (EndpointDef endpoint : scanner.getEndpoints()) {
                tcpServer.createContext(
                    endpoint.path(),
                    exchange -> dispatch(
                        endpoint, new SunHttpExchangeAdapter(exchange)));
            }
            registerTcpContext("/mcp/schema", scanner.generateSchema());
            registerTcpContext(
                "/get_version",
                VersionPayload.toJson(scanner.getDescriptors().size()));
            tcpServer.createContext(
                "/mcp/instance_info",
                exchange -> sendJsonResponse(
                    new SunHttpExchangeAdapter(exchange),
                    buildInstanceInfoJson()));
            registerTcpContext("/mcp/health", "{\"status\":\"ok\"}");
            tcpExecutor = Executors.newFixedThreadPool(3, runnable -> {
                Thread thread = new Thread(runnable, "GhidraMCP-next-TCP");
                thread.setDaemon(true);
                return thread;
            });
            tcpServer.setExecutor(tcpExecutor);
            tcpServer.start();
        } catch (IOException error) {
            tcpServer = null;
            Msg.warn(
                this,
                "TCP transport was requested but could not bind 127.0.0.1:"
                    + port + ": " + error.getMessage());
        }
    }

    private void registerUdsContexts() {
        for (EndpointDef endpoint : scanner.getEndpoints()) {
            udsServer.createContext(
                endpoint.path(), exchange -> dispatch(endpoint, exchange));
        }
        String schema = scanner.generateSchema();
        udsServer.createContext(
            "/mcp/schema", exchange -> sendJsonResponse(exchange, schema));
        udsServer.createContext(
            "/get_version",
            exchange -> sendJsonResponse(
                exchange,
                VersionPayload.toJson(scanner.getDescriptors().size())));
        udsServer.createContext(
            "/mcp/instance_info",
            exchange -> sendJsonResponse(exchange, buildInstanceInfoJson()));
        udsServer.createContext(
            "/mcp/health",
            exchange -> sendJsonResponse(exchange, "{\"status\":\"ok\"}"));
    }

    private void registerTcpContext(String path, String body) {
        tcpServer.createContext(
            path,
            exchange -> sendJsonResponse(
                new SunHttpExchangeAdapter(exchange), body));
    }

    private void dispatch(EndpointDef endpoint, HttpExchange exchange) {
        try {
            if (!endpoint.method().equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, Response.err("wrong HTTP method").toJson());
                return;
            }
            Map<String, String> query =
                parseQueryString(exchange.getRequestURI().getRawQuery());
            Map<String, Object> body = "POST".equals(endpoint.method())
                ? endpoint.parseBody(exchange.getRequestBody())
                : Map.of();
            sendJsonResponse(
                exchange, endpoint.handler().handle(query, body).toJson());
        } catch (Exception error) {
            sendJsonResponse(
                exchange,
                Response.err(
                    error.getMessage() == null
                        ? error.getClass().getSimpleName()
                        : error.getMessage()).toJson());
        }
    }

    static void sendJsonResponse(HttpExchange exchange, String json) {
        try {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set(
                "Content-Type", "application/json; charset=UTF-8");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(bytes);
            }
        } catch (IOException error) {
            Msg.error(ServerManager.class, "Could not send MCP response", error);
        }
    }

    static Map<String, String> parseQueryString(String query) {
        Map<String, String> parameters = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) {
            return parameters;
        }
        for (String pair : query.split("&")) {
            int separator = pair.indexOf('=');
            String key = separator < 0 ? pair : pair.substring(0, separator);
            String value = separator < 0 ? "" : pair.substring(separator + 1);
            parameters.put(
                URLDecoder.decode(key, StandardCharsets.UTF_8),
                URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return parameters;
    }

    public String buildInstanceInfoJson() {
        return Response.ok(buildInstanceInfo()).toJson();
    }

    private Map<String, Object> buildInstanceInfo() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("pid", ProcessHandle.current().pid());
        Project project = activeProject();
        info.put("project", project == null ? null : project.getName());
        info.put(
            "project_path",
            project == null ? null : project.getProjectLocator().toString());
        info.put("tcp_port", getBoundTcpPort());

        Set<String> names = new LinkedHashSet<>();
        MultiToolProgramProvider provider = programProvider;
        if (provider != null) {
            for (Program program : provider.getAllOpenPrograms()) {
                names.add(program.getName());
            }
        }
        List<Map<String, Object>> programs = new ArrayList<>();
        for (String name : names) {
            programs.add(Map.of("name", name, "open", true));
        }
        info.put("programs", programs);
        return info;
    }

    private void stop(boolean releasePrograms) {
        if (tcpServer != null) {
            tcpServer.stop(0);
            tcpServer = null;
        }
        if (tcpExecutor != null) {
            tcpExecutor.shutdownNow();
            tcpExecutor = null;
        }
        if (udsServer != null) {
            udsServer.stop();
            udsServer = null;
        }
        if (releasePrograms && programProvider != null) {
            programProvider.releaseOwnedPrograms();
        }
        scanner = null;
        if (releasePrograms) {
            programProvider = null;
        }
        serviceOwner = null;
    }

    private static void cleanStaleSockets(Path directory) {
        try (var entries = Files.list(directory)) {
            for (Path path : entries.filter(
                    item -> item.getFileName().toString().endsWith(".sock")).toList()) {
                String stem = path.getFileName().toString();
                int dash = stem.lastIndexOf('-');
                int dot = stem.lastIndexOf('.');
                if (dash < 0 || dot < dash) {
                    continue;
                }
                try {
                    long pid = Long.parseLong(stem.substring(dash + 1, dot));
                    if (ProcessHandle.of(pid).isEmpty()) {
                        Files.deleteIfExists(path);
                    }
                } catch (NumberFormatException ignored) {
                    // Not one of this plugin's socket names.
                }
            }
        } catch (IOException error) {
            Msg.warn(
                ServerManager.class,
                "Could not clean stale MCP sockets: " + error.getMessage());
        }
    }

    private static void hardenSocketDir(Path directory) throws IOException {
        if (!directory.getFileSystem()
                .supportedFileAttributeViews().contains("posix")) {
            return;
        }
        var attributes = Files.readAttributes(
            directory,
            java.nio.file.attribute.PosixFileAttributes.class);
        String expected = System.getProperty("user.name");
        if (expected != null && !expected.equals(attributes.owner().getName())) {
            throw new IOException(
                "socket directory is owned by another user: " + directory);
        }
        Files.setPosixFilePermissions(
            directory,
            java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
    }

    public static Path resolveSocketDir(
            String xdgRuntimeDir,
            String tmpdir,
            String javaTmpdir,
            String user) {
        if (xdgRuntimeDir != null && !xdgRuntimeDir.isEmpty()) {
            return Path.of(xdgRuntimeDir, "ghidra-mcp");
        }
        String name = user == null || user.isEmpty() ? "unknown" : user;
        if (tmpdir != null && !tmpdir.isEmpty()) {
            return Path.of(tmpdir, "ghidra-mcp-" + name);
        }
        if (javaTmpdir != null && !javaTmpdir.isEmpty()) {
            return Path.of(javaTmpdir, "ghidra-mcp-" + name);
        }
        return Path.of("/tmp", "ghidra-mcp-" + name);
    }
}
