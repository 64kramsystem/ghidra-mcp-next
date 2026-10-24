package com.xebyte.core;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin;
import ghidra.app.services.*;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;

/** Real TraceRMI and MCP services; only the GUI service container is substituted. */
public final class DebuggerStackHarness {
    private DebuggerStackHarness() {}

    public static void main(String[] args) throws Exception {
        System.setProperty("java.awt.headless", "true");
        GhidraTestRuntime.initialize();
        // Keep real EDT/worker separation for the GUI services under test.
        // Ghidra's headless mode otherwise treats every thread as the EDT.
        System.setProperty(ghidra.util.SystemUtilities.HEADLESS_PROPERTY, "false");
        Path directory = Path.of(args[0]);
        ProjectData data = new DefaultProjectData(
                new ProjectLocator(directory.toString(), "integration"), null, true);
        Project project = mock(Project.class);
        PluginTool tool = mock(PluginTool.class);
        ToolManager tools = mock(ToolManager.class);
        Map<Class<?>, Object> services = new ConcurrentHashMap<>();
        when(tool.getService(any())).thenAnswer(call -> services.get(call.getArgument(0)));
        when(tool.getProject()).thenReturn(project);
        when(project.getProjectData()).thenReturn(data);
        when(project.getToolManager()).thenReturn(tools);
        when(tools.getRunningTools()).thenReturn(new PluginTool[]{tool});
        var coordinates = new AtomicReference<>(DebuggerCoordinates.NOWHERE);
        var activeTarget = new AtomicReference<Target>();
        DebuggerTraceManagerService traces = mock(DebuggerTraceManagerService.class);
        DebuggerTargetService targets = mock(DebuggerTargetService.class);
        services.put(DebuggerTraceManagerService.class, traces);
        services.put(DebuggerTargetService.class, targets);
        when(traces.getCurrent()).thenAnswer(call -> coordinates.get());
        when(traces.getCurrentFor(any())).thenAnswer(call -> coordinates.get());
        when(traces.getCurrentTrace()).thenAnswer(call -> coordinates.get().getTrace());
        when(traces.getOpenTraces()).thenAnswer(call -> coordinates.get().getTrace() == null
                ? List.of() : List.of(coordinates.get().getTrace()));
        when(traces.isSaveTracesByDefault()).thenReturn(false);
        doAnswer(call -> { coordinates.set(call.getArgument(0)); return null; })
                .when(traces).activate(any(), any());
        doAnswer(call -> { activeTarget.set(call.getArgument(0)); return null; })
                .when(targets).publishTarget(any());
        when(targets.getTarget(any())).thenAnswer(call -> activeTarget.get());
        TraceRmiPlugin rmi = new TraceRmiPlugin(tool);
        services.put(TraceRmiService.class, rmi);
        rmi.setTargetService(targets);
        rmi.setServerAddress(new InetSocketAddress("127.0.0.1", 0));
        rmi.startServer();
        var scanner = new AnnotationScanner(new DebuggerService(null, null, tool));
        HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        ExecutorService executor = Executors.newCachedThreadPool();
        http.setExecutor(executor);
        for (EndpointDef endpoint : scanner.getEndpoints()) {
            http.createContext(endpoint.path(), exchange -> {
                try {
                    Map<String, String> query = new HashMap<>();
                    String raw = exchange.getRequestURI().getRawQuery();
                    if (raw != null && !raw.isBlank()) for (String item : raw.split("&")) {
                        String[] pair = item.split("=", 2);
                        query.put(URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                                URLDecoder.decode(pair.length == 1 ? "" : pair[1], StandardCharsets.UTF_8));
                    }
                    Map<String, Object> body = exchange.getRequestMethod().equals("POST")
                            ? endpoint.parseBody(exchange.getRequestBody()) : Map.of();
                    String response = endpoint.handler().handle(query, body).toJson();
                    System.out.println("HTTP " + endpoint.path() + " " + response);
                    byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, bytes.length);
                    exchange.getResponseBody().write(bytes);
                } catch (Exception e) {
                    byte[] bytes = JsonHelper.errorJson(e.toString()).getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(500, bytes.length);
                    exchange.getResponseBody().write(bytes);
                } finally { exchange.close(); }
            });
        }
        http.start();
        Files.writeString(directory.resolve("ready.json"), JsonHelper.toJson(Map.of(
                "trace_port", ((InetSocketAddress) rmi.getServerAddress()).getPort(),
                "http_port", http.getAddress().getPort())));
        try {
            while (!Files.exists(directory.resolve("stop"))) Thread.sleep(50);
        } finally {
            http.stop(0);
            executor.shutdownNow();
            rmi.stopServer();
            for (var connection : rmi.getAllConnections()) connection.close();
            data.close();
        }
        System.exit(0);
    }
}
