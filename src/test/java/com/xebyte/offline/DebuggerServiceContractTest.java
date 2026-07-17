package com.xebyte.offline;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import junit.framework.TestCase;

public class DebuggerServiceContractTest extends TestCase {
    public void testTraceRmiSeamEndpointsRemainAnnotated() throws Exception {
        String source = Files.readString(Path.of(System.getProperty("user.dir"),
                "src/main/java/com/xebyte/core/DebuggerService.java"));
        assertTrue(source.contains("@McpToolGroup(value = \"debugger\""));
        for (String path : List.of(
                "/debugger/launch_offers", "/debugger/status",
                "/debugger/modules", "/debugger/read_memory",
                "/debugger/static_to_dynamic", "/debugger/dynamic_to_static")) {
            assertTrue("missing TraceRMI seam " + path,
                    source.contains("path = \"" + path + "\""));
        }
        assertTrue(source.contains("launcherSvc.getOffers(program)"));
        assertTrue(source.contains("offer.supportsImage()"));
        assertTrue(source.contains("offer.requiresImage()"));
    }

    public void testPidAttachEndpointUsesTraceRmiSelectionSeams() throws Exception {
        String source = Files.readString(Path.of(System.getProperty("user.dir"),
                "src/main/java/com/xebyte/core/DebuggerService.java"));
        assertTrue(source.contains("path = \"/debugger/attach\""));
        assertTrue(source.contains("DebuggerAttachSemantics.selectOffer"));
        assertTrue(source.contains("DebuggerAttachSemantics.selectAttachMethod"));
        String attach = source.substring(source.indexOf("public Response attach("),
                source.indexOf("public Response getStatus("));
        assertTrue(attach.indexOf("method.invokeAsync(arguments)") <
                attach.indexOf("DebuggerCoordinates postAttachCoordinates"));
    }

    public void testRemainingFutureEndpointsAreNotFalselyAdvertised() throws Exception {
        String source = Files.readString(Path.of(System.getProperty("user.dir"),
                "src/main/java/com/xebyte/core/DebuggerService.java"));
        assertFalse(source.contains("/debugger/wait_for_stop"));
        assertFalse(source.contains("/debugger/memory_maps"));
        assertFalse(source.contains("/debugger/copy_memory_to_program"));
    }
}
