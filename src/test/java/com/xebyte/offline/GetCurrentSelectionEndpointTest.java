package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.GuiContextService;

import java.util.Set;
import java.util.stream.Collectors;

import junit.framework.TestCase;

public class GetCurrentSelectionEndpointTest extends TestCase {

    public void testSelectionIsAGroupedGuiTool() {
        AnnotationScanner scanner = new AnnotationScanner(
            new GuiContextService(() -> null, ServiceFactory.stubProvider()));
        AnnotationScanner.ToolDescriptor selection = scanner.getDescriptors()
            .stream()
            .filter(tool -> tool.path().equals("/get_current_selection"))
            .findFirst()
            .orElseThrow();

        assertEquals("GET", selection.method());
        assertEquals("gui", selection.category());
        assertEquals(Set.of(), selection.params().stream()
            .map(AnnotationScanner.ParamDescriptor::name)
            .collect(Collectors.toSet()));
    }
}
