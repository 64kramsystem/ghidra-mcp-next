package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.GuiProjectService;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import junit.framework.TestCase;

/** Guards the live GUI schemas served by both TCP and Unix sockets. */
public class GuiTransportSchemaParityTest extends TestCase {
    private static final Path ROOT = Path.of(System.getProperty("user.dir"));

    public void testGuiProjectLifecycleEndpointsAreAnnotationScanned() {
        AnnotationScanner scanner = new AnnotationScanner(
                new GuiProjectService(() -> null));
        Map<String, AnnotationScanner.ToolDescriptor> tools = scanner.getDescriptors()
                .stream()
                .collect(Collectors.toMap(
                        AnnotationScanner.ToolDescriptor::path,
                        Function.identity()));

        assertTrue("GUI schema must advertise /create_project",
                tools.containsKey("/create_project"));
        assertTrue("GUI schema must advertise /open_project",
                tools.containsKey("/open_project"));
        assertEquals(Set.of("parentDir", "name"),
                parameterNames(tools.get("/create_project")));
        assertEquals(Set.of("path", "headless", "program"),
                parameterNames(tools.get("/open_project")));
        assertEquals("headless", tools.get("/create_project").category());
        assertEquals("headless", tools.get("/open_project").category());
    }

    public void testTcpScannerIncludesExportAndProtectedGuiServices() throws IOException {
        String source = Files.readString(ROOT.resolve(
                "src/main/java/com/xebyte/GhidraMCPPlugin.java"));
        assertTrue("TCP must construct ExportService", source.contains(
                "this.exportService = new com.xebyte.core.ExportService(programProvider)"));
        assertTrue("TCP must construct MemoryBlockService", source.contains(
                "new com.xebyte.core.MemoryBlockService(programProvider, threadingStrategy)"));
        assertTrue("TCP must construct DataRegionService", source.contains(
                "new com.xebyte.core.DataRegionService(programProvider, threadingStrategy)"));
        assertTrue("TCP must construct FlowDisassemblyService", source.contains(
                "new com.xebyte.core.FlowDisassemblyService(programProvider, threadingStrategy)"));
        assertTrue("TCP must construct ListingRangeService with GUI threading",
                source.matches("(?s).*new com\\.xebyte\\.core\\.ListingRangeService\\(\\s*"
                    + "programProvider,\\s*threadingStrategy\\).*"));
        assertTrue("TCP must construct ListingMutationService with GUI threading",
                source.matches("(?s).*new com\\.xebyte\\.core\\.ListingMutationService\\(\\s*"
                    + "programProvider,\\s*threadingStrategy\\).*"));
        assertTrue("TCP scanner must include GuiProjectService so schema and routes agree",
                source.matches("(?s).*new AnnotationScanner\\(programProvider,.*"
                        + "programScriptService,\\s*memoryBlockService,\\s*dataRegionService,\\s*"
                        + "emulationService,\\s*exportService,\\s*"
                        + "flowDisassemblyService,\\s*listingRangeService,\\s*"
                        + "listingMutationService,\\s*"
                        + "debuggerService,\\s*"
                        + "guiProjectService\\).*"));
    }

    public void testUdsScannerIncludesProtectedGuiServices() throws IOException {
        String source = Files.readString(ROOT.resolve(
                "src/main/java/com/xebyte/core/ServerManager.java"));
        assertTrue("UDS must construct EmulationService", source.contains(
                "EmulationService emulationService = new EmulationService"));
        assertTrue("UDS must construct MemoryBlockService", source.contains(
                "MemoryBlockService memoryBlockService ="));
        assertTrue("UDS must construct DataRegionService", source.contains(
                "DataRegionService dataRegionService ="));
        assertTrue("UDS must construct ExportService", source.contains(
                "ExportService exportService = new ExportService"));
        assertTrue("UDS must construct FlowDisassemblyService", source.contains(
                "FlowDisassemblyService flowDisassemblyService ="));
        assertTrue("UDS must construct ListingRangeService", source.contains(
                "new ListingRangeService(programProvider, ts)"));
        assertTrue("UDS must construct ListingMutationService", source.contains(
                "new ListingMutationService(programProvider, ts)"));
        assertTrue("UDS must construct DebuggerService", source.contains(
                "DebuggerService debuggerService = new DebuggerService"));
        assertTrue("UDS must construct GuiProjectService", source.contains(
                "GuiProjectService guiProjectService = new GuiProjectService"));
        assertTrue("UDS scanner must advertise emulation, export, debugger, and project tools",
                source.matches("(?s).*new AnnotationScanner\\(programProvider,.*"
                        + "programScriptService,\\s*memoryBlockService,\\s*dataRegionService,\\s*"
                        + "emulationService,\\s*exportService,\\s*"
                        + "flowDisassemblyService,\\s*listingRangeService,\\s*"
                        + "listingMutationService,\\s*"
                        + "debuggerService,\\s*"
                        + "guiProjectService\\).*"));
    }

    public void testHeadlessScannerIncludesExportService() throws IOException {
        String handlerSource = Files.readString(ROOT.resolve(
                "src/main/java/com/xebyte/headless/HeadlessEndpointHandler.java"));
        assertTrue("Headless handler must construct ExportService", handlerSource.contains(
                "this.exportService = new com.xebyte.core.ExportService(programProvider)"));
        assertTrue("Headless handler must construct MemoryBlockService",
                handlerSource.contains(
                    "new com.xebyte.core.MemoryBlockService(programProvider, threadingStrategy)"));
        assertTrue("Headless handler must expose MemoryBlockService",
                handlerSource.contains("getMemoryBlockService()"));
        assertTrue("Headless handler must expose DataRegionService",
                handlerSource.contains("getDataRegionService()"));
        assertTrue("Headless handler must expose ExportService to the scanner",
                handlerSource.contains(
                        "getExportService() { return exportService; }"));
        assertTrue("Headless handler must construct FlowDisassemblyService",
                handlerSource.contains(
                        "new com.xebyte.core.FlowDisassemblyService(programProvider, threadingStrategy)"));
        assertTrue("Headless handler must expose FlowDisassemblyService to the scanner",
                handlerSource.contains("getFlowDisassemblyService()"));
        assertTrue("Headless handler must construct ListingRangeService with its threading",
                handlerSource.matches(
                    "(?s).*new com\\.xebyte\\.core\\.ListingRangeService\\(\\s*"
                        + "programProvider,\\s*threadingStrategy\\).*"));
        assertTrue("Headless handler must expose ListingRangeService to the scanner",
                handlerSource.contains("getListingRangeService()"));
        assertTrue("Headless handler must construct ListingMutationService with its threading",
                handlerSource.matches(
                    "(?s).*new com\\.xebyte\\.core\\.ListingMutationService\\(\\s*"
                        + "programProvider,\\s*threadingStrategy\\).*"));
        assertTrue("Headless handler must expose ListingMutationService to the scanner",
                handlerSource.contains("getListingMutationService()"));

        String serverSource = Files.readString(ROOT.resolve(
                "src/main/java/com/xebyte/headless/GhidraMCPHeadlessServer.java"));
        assertTrue("Headless scanner must advertise export tools",
                serverSource.matches("(?s).*new AnnotationScanner\\("
                        + "endpointHandler\\.getProgramProvider\\(\\),.*"
                        + "endpointHandler\\.getMemoryBlockService\\(\\),\\s*"
                        + "endpointHandler\\.getDataRegionService\\(\\),\\s*"
                        + "endpointHandler\\.getEmulationService\\(\\),\\s*"
                        + "endpointHandler\\.getExportService\\(\\),\\s*"
                        + "endpointHandler\\.getFlowDisassemblyService\\(\\),\\s*"
                        + "endpointHandler\\.getListingRangeService\\(\\),\\s*"
                        + "endpointHandler\\.getListingMutationService\\(\\),\\s*"
                        + "managementService\\).*"));
    }

    public void testAllAnnotatedTransportsUseEndpointSpecificBodyParsing()
            throws IOException {
        for (String relative : Set.of(
                "src/main/java/com/xebyte/GhidraMCPPlugin.java",
                "src/main/java/com/xebyte/core/ServerManager.java",
                "src/main/java/com/xebyte/headless/GhidraMCPHeadlessServer.java")) {
            String source = Files.readString(ROOT.resolve(relative));
            assertTrue(
                relative + " must honor endpoint native-byte parse hints",
                source.contains("ep.parseBody(exchange.getRequestBody())"));
        }
    }

    private Set<String> parameterNames(AnnotationScanner.ToolDescriptor tool) {
        return tool.params().stream()
                .map(AnnotationScanner.ParamDescriptor::name)
                .collect(Collectors.toSet());
    }
}
