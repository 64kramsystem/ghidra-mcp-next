package com.xebyte.offline;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.Test;

import com.xebyte.core.AnnotationScanner;

public class FlowDisassemblySchemaTest {

    private static final Path ROOT = Path.of(System.getProperty("user.dir"));

    @Test
    public void offlineSchemaContainsOnlyCorrectedFlowEndpoint() {
        AnnotationScanner scanner =
            new AnnotationScanner(ServiceFactory.stubProvider(), ServiceFactory.buildAllServices());
        Map<String, AnnotationScanner.ToolDescriptor> tools = scanner.getDescriptors()
            .stream()
            .collect(Collectors.toMap(
                AnnotationScanner.ToolDescriptor::path,
                Function.identity()));

        assertFalse(tools.containsKey("/disassemble_bytes"));
        assertTrue(tools.containsKey("/disassemble_flow"));
        AnnotationScanner.ToolDescriptor flow = tools.get("/disassemble_flow");
        assertEquals("POST", flow.method());
        assertEquals("disassembly", flow.category());
        assertFalse(flow.supportsDryRun());
        assertEquals(List.of(
            "seeds",
            "restrict_start",
            "restrict_end",
            "dry_run",
            "follow_calls",
            "preserve_defined_data",
            "create_functions",
            "enable_analysis",
            "max_instructions",
            "program"),
            flow.params().stream().map(AnnotationScanner.ParamDescriptor::name).toList());
        assertEquals(List.of(
            "body", "body", "body", "body", "body",
            "body", "body", "body", "body", "query"),
            flow.params().stream().map(AnnotationScanner.ParamDescriptor::source).toList());
    }

    @Test
    public void compiledProductionSourcesContainNoRetiredContract() throws IOException {
        Path sourceRoot = ROOT.resolve("src/main/java");
        try (var files = Files.walk(sourceRoot)) {
            List<Path> offenders = files
                .filter(path -> path.toString().endsWith(".java"))
                .filter(path -> {
                    try {
                        String source = Files.readString(path);
                        return source.contains("/disassemble_bytes") ||
                            source.contains("restrict_to_execute_memory");
                    }
                    catch (IOException e) {
                        throw new IllegalStateException(e);
                    }
                })
                .toList();
            assertTrue("retired disassembly contract remains in " + offenders,
                offenders.isEmpty());
        }
    }
}
