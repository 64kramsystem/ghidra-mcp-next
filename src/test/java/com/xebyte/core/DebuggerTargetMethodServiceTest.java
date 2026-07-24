package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.Test;

/** Contract tests for the GUI-only generic TraceRMI HTTP surface. */
public class DebuggerTargetMethodServiceTest {
    @Test
    public void scannerPublishesOnlyTheTwoGenericMethodEndpoints() {
        AnnotationScanner scanner = new AnnotationScanner(
            new DebuggerService(null, null, null));
        Map<String, AnnotationScanner.ToolDescriptor> tools =
            scanner.getDescriptors().stream()
                .collect(Collectors.toMap(
                    AnnotationScanner.ToolDescriptor::path,
                    Function.identity()));

        AnnotationScanner.ToolDescriptor discovery =
            tools.get("/debugger/target_methods");
        assertNotNull(discovery);
        assertEquals("GET", discovery.method());
        assertTrue(discovery.params().isEmpty());

        AnnotationScanner.ToolDescriptor invoke =
            tools.get("/debugger/invoke_target_method");
        assertNotNull(invoke);
        assertEquals("POST", invoke.method());
        assertEquals(
            List.of(
                "target_token", "method", "arguments", "timeout_ms"),
            invoke.params().stream()
                .map(AnnotationScanner.ParamDescriptor::name)
                .toList());
        assertTrue(invoke.params().stream()
            .allMatch(param -> !param.optional()));
        assertFalse(tools.keySet().stream()
            .anyMatch(path -> path.contains("vice")
                || path.contains("c64")));
    }

    @Test
    public void invocationSchemaKeepsNativeObjectAndTimeoutBounds() {
        AnnotationScanner scanner = new AnnotationScanner(
            new DebuggerService(null, null, null));
        AnnotationScanner.ToolDescriptor invoke =
            scanner.getDescriptors().stream()
                .filter(tool -> tool.path().equals(
                    "/debugger/invoke_target_method"))
                .findFirst()
                .orElseThrow();
        Map<String, AnnotationScanner.ParamDescriptor> params =
            invoke.params().stream()
                .collect(Collectors.toMap(
                    AnnotationScanner.ParamDescriptor::name,
                    Function.identity()));

        assertEquals("any", params.get("arguments").type());
        assertEquals(
            "{\"type\":\"object\"}",
            params.get("arguments").schema());
        assertEquals("integer", params.get("timeout_ms").type());
        assertEquals(
            "{\"minimum\":1,\"maximum\":60000}",
            params.get("timeout_ms").schema());
    }
}
