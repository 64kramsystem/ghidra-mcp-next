package com.xebyte.offline;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import junit.framework.TestCase;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.DebuggerService;

public class DebuggerServiceContractTest extends TestCase {
    public void testLaunchEndpointPublishesOfferSpecificLauncherArguments() {
        AnnotationScanner scanner = new AnnotationScanner(
                new DebuggerService(null, null, null));
        AnnotationScanner.ToolDescriptor launch = scanner.getDescriptors().stream()
                .filter(tool -> tool.path().equals("/debugger/launch"))
                .findFirst()
                .orElseThrow();
        Map<String, AnnotationScanner.ParamDescriptor> params =
                launch.params().stream().collect(Collectors.toMap(
                        AnnotationScanner.ParamDescriptor::name,
                        Function.identity()));

        assertEquals("any", params.get("launcher_args").type());
        assertEquals("{\"type\":\"object\"}", params.get("launcher_args").schema());
        assertTrue(params.get("launcher_args").optional());
    }
}
