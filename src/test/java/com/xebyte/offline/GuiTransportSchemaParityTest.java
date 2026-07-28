package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.GuiContextService;
import com.xebyte.core.GuiProjectService;

import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import junit.framework.TestCase;

/** Guards the live schemas generated for GUI services. */
public class GuiTransportSchemaParityTest extends TestCase {

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

    public void testGuiContextEndpointsAreAnnotationScanned() {
        AnnotationScanner scanner = new AnnotationScanner(
                new GuiContextService(() -> null, ServiceFactory.stubProvider()));
        Set<String> paths = scanner.getDescriptors().stream()
                .map(AnnotationScanner.ToolDescriptor::path)
                .collect(Collectors.toSet());

        assertEquals(Set.of(
            "/get_current_address",
            "/get_current_selection",
            "/go_to_address"), paths);
    }

    public void testHeadlessImportEndpointIsAnnotationScanned() {
        AnnotationScanner scanner = new AnnotationScanner(
                ServiceFactory.stubProvider(),
                ServiceFactory.buildAllServices());
        Set<String> paths = scanner.getDescriptors().stream()
                .map(AnnotationScanner.ToolDescriptor::path)
                .collect(Collectors.toSet());

        assertTrue("headless schema must advertise /import_file",
                paths.contains("/import_file"));
    }

    private Set<String> parameterNames(AnnotationScanner.ToolDescriptor tool) {
        return tool.params().stream()
                .map(AnnotationScanner.ParamDescriptor::name)
                .collect(Collectors.toSet());
    }
}
