package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.GuiContextService;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import junit.framework.TestCase;

public class GuiContextSchemaTest extends TestCase {
    private static final Path ROOT = Path.of(System.getProperty("user.dir"));

    public void testGuiScannerAdvertisesOnlyNormalizedContextTools() {
        AnnotationScanner scanner = new AnnotationScanner(
            new GuiContextService(() -> null, ServiceFactory.stubProvider()));
        Map<String, AnnotationScanner.ToolDescriptor> tools =
            scanner.getDescriptors().stream().collect(Collectors.toMap(
                AnnotationScanner.ToolDescriptor::path,
                Function.identity()));

        assertEquals(Set.of(
            "/get_current_address",
            "/get_current_selection",
            "/go_to_address"), tools.keySet());
        assertEquals(Set.of(), parameterNames(tools.get("/get_current_address")));
        assertEquals(Set.of(), parameterNames(tools.get("/get_current_selection")));
        assertEquals(Set.of("address", "program"),
            parameterNames(tools.get("/go_to_address")));
        assertEquals("gui", tools.get("/get_current_address").category());
        assertEquals("gui", tools.get("/get_current_selection").category());
        assertEquals("gui", tools.get("/go_to_address").category());
        assertEquals("POST", tools.get("/go_to_address").method());
    }

    public void testHeadlessScannerOmitsGuiTools() {
        AnnotationScanner scanner = new AnnotationScanner(
            ServiceFactory.stubProvider(), ServiceFactory.buildAllServices());
        Set<String> paths = scanner.getDescriptors().stream()
            .map(AnnotationScanner.ToolDescriptor::path)
            .collect(Collectors.toSet());

        assertFalse(paths.contains("/get_current_address"));
        assertFalse(paths.contains("/get_current_selection"));
        assertFalse(paths.contains("/go_to_address"));
    }

    public void testHeadlessRawRoutesReturnExplicitUnsupportedResponses()
            throws Exception {
        String source = Files.readString(ROOT.resolve(
            "src/main/java/com/xebyte/headless/GhidraMCPHeadlessServer.java"));

        for (String path : Set.of(
                "/get_current_address",
                "/get_current_selection",
                "/go_to_address")) {
            assertTrue(path + " must remain callable as an unsupported raw route",
                source.contains("safeContext(\"" + path + "\""));
        }
        assertTrue(source.contains("GUI context tools are unavailable in headless mode"));
    }

    private Set<String> parameterNames(
            AnnotationScanner.ToolDescriptor tool) {
        return tool.params().stream()
            .map(AnnotationScanner.ParamDescriptor::name)
            .collect(Collectors.toSet());
    }
}
