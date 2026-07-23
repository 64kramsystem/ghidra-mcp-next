package com.xebyte.offline;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.Test;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.JsonHelper;
import com.xebyte.core.Response;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class MemoryBlockServiceSchemaTest {

    @Test
    public void rawSchemaEmitsMemoryDefaultsAsTheirDeclaredJsonTypes() {
        AnnotationScanner scanner = new AnnotationScanner(
            ServiceFactory.stubProvider(), ServiceFactory.buildAllServices());
        JsonObject schema = JsonParser.parseString(scanner.generateSchema())
            .getAsJsonObject();
        JsonObject create = schema.getAsJsonArray("tools").asList().stream()
            .map(element -> element.getAsJsonObject())
            .filter(tool -> tool.get("path").getAsString()
                .equals("/create_memory_block"))
            .findFirst().orElseThrow();
        Map<String, JsonObject> parameters = create.getAsJsonArray("params")
            .asList().stream()
            .map(element -> element.getAsJsonObject())
            .collect(Collectors.toMap(
                parameter -> parameter.get("name").getAsString(),
                Function.identity()));

        assertTrue(parameters.get("file_offset").get("default")
            .getAsJsonPrimitive().isNumber());
        assertEquals(0,
            parameters.get("file_offset").get("default").getAsInt());
        for (String name : List.of(
                "overlay", "read", "write", "execute", "volatile",
                "dry_run")) {
            assertTrue(name, parameters.get(name).get("default")
                .getAsJsonPrimitive().isBoolean());
        }
        assertFalse(parameters.get("overlay").get("default").getAsBoolean());
        assertTrue(parameters.get("read").get("default").getAsBoolean());
        assertTrue(parameters.get("dry_run").get("default").getAsBoolean());

        JsonObject resize = schema.getAsJsonArray("tools").asList().stream()
            .map(element -> element.getAsJsonObject())
            .filter(tool -> tool.get("path").getAsString()
                .equals("/resize_memory_block"))
            .findFirst().orElseThrow();
        Map<String, JsonObject> resizeParameters =
            resize.getAsJsonArray("params").asList().stream()
                .map(element -> element.getAsJsonObject())
                .collect(Collectors.toMap(
                    parameter -> parameter.get("name").getAsString(),
                    Function.identity()));
        assertTrue(resizeParameters.get("file_offset").get("default")
            .getAsJsonPrimitive().isNumber());
        assertEquals(0,
            resizeParameters.get("file_offset").get("default").getAsInt());
        assertTrue(resizeParameters.get("dry_run").get("default")
            .getAsJsonPrimitive().isBoolean());
        assertTrue(resizeParameters.get("dry_run").get("default")
            .getAsBoolean());
        assertEquals("error", resizeParameters.get("on_inbound_refs")
            .get("default").getAsString());

        JsonObject delete = schema.getAsJsonArray("tools").asList().stream()
            .map(element -> element.getAsJsonObject())
            .filter(tool -> tool.get("path").getAsString()
                .equals("/delete_memory_block"))
            .findFirst().orElseThrow();
        Map<String, JsonObject> deleteParameters =
            delete.getAsJsonArray("params").asList().stream()
                .map(element -> element.getAsJsonObject())
                .collect(Collectors.toMap(
                    parameter -> parameter.get("name").getAsString(),
                    Function.identity()));
        assertTrue(deleteParameters.get("dry_run").get("default")
            .getAsJsonPrimitive().isBoolean());
        assertTrue(deleteParameters.get("dry_run").get("default")
            .getAsBoolean());
        assertEquals("error", deleteParameters.get("on_inbound_refs")
            .get("default").getAsString());

        JsonObject patch = schema.getAsJsonArray("tools").asList().stream()
            .map(element -> element.getAsJsonObject())
            .filter(tool -> tool.get("path").getAsString()
                .equals("/patch_bytes"))
            .findFirst().orElseThrow();
        Map<String, JsonObject> patchParameters =
            patch.getAsJsonArray("params").asList().stream()
                .map(element -> element.getAsJsonObject())
                .collect(Collectors.toMap(
                    parameter -> parameter.get("name").getAsString(),
                    Function.identity()));
        assertTrue(patchParameters.get("clear_code_units")
            .get("default").getAsBoolean());
        assertFalse(patchParameters.get("allow_readonly")
            .get("default").getAsBoolean());
        assertTrue(patchParameters.get("dry_run")
            .get("default").getAsBoolean());
    }

    @Test
    public void canonicalMemoryRoutesHaveExactBodyAndQueryContracts() {
        AnnotationScanner scanner = new AnnotationScanner(
            ServiceFactory.stubProvider(), ServiceFactory.buildAllServices());
        Map<String, AnnotationScanner.ToolDescriptor> tools =
            scanner.getDescriptors().stream().collect(Collectors.toMap(
                AnnotationScanner.ToolDescriptor::path, Function.identity()));

        assertEquals(1, tools.keySet().stream()
            .filter("/create_memory_block"::equals).count());
        for (String path : List.of(
                "/create_memory_block",
                "/update_memory_block",
                "/split_memory_block",
                "/move_memory_block",
                "/write_memory_bytes",
                "/delete_memory_block",
                "/resize_memory_block",
                "/patch_bytes")) {
            assertEquals(path, "memory", tools.get(path).category());
        }
        assertEquals(
            List.of(
                "name", "start", "length", "bytes", "file_path",
                "file_offset", "source_length", "overlay", "fill",
                "read", "write", "execute", "volatile", "comment",
                "dry_run", "program"),
            tools.get("/create_memory_block").params().stream()
                .map(AnnotationScanner.ParamDescriptor::name).toList());
        assertEquals(
            List.of(
                "name", "new_name", "read", "write", "execute",
                "volatile", "comment", "dry_run", "program"),
            tools.get("/update_memory_block").params().stream()
                .map(AnnotationScanner.ParamDescriptor::name).toList());
        assertEquals(
            List.of("name", "split_address", "dry_run", "program"),
            tools.get("/split_memory_block").params().stream()
                .map(AnnotationScanner.ParamDescriptor::name).toList());
        assertEquals(
            List.of("name", "new_start", "dry_run", "program"),
            tools.get("/move_memory_block").params().stream()
                .map(AnnotationScanner.ParamDescriptor::name).toList());
        assertEquals(
            List.of("start", "bytes", "conflict_policy", "dry_run", "program"),
            tools.get("/write_memory_bytes").params().stream()
                .map(AnnotationScanner.ParamDescriptor::name).toList());
        assertEquals(
            List.of("name", "on_inbound_refs", "dry_run", "program"),
            tools.get("/delete_memory_block").params().stream()
                .map(AnnotationScanner.ParamDescriptor::name).toList());
        assertEquals(
            List.of(
                "name", "new_end", "new_length", "on_inbound_refs",
                "fill", "bytes", "file_path", "file_offset",
                "source_length", "dry_run", "program"),
            tools.get("/resize_memory_block").params().stream()
                .map(AnnotationScanner.ParamDescriptor::name).toList());
        assertEquals(
            List.of(
                "address", "bytes", "block", "clear_code_units",
                "expected_current", "allow_readonly", "dry_run",
                "program"),
            tools.get("/patch_bytes").params().stream()
                .map(AnnotationScanner.ParamDescriptor::name).toList());
        assertEquals("address",
            tools.get("/patch_bytes").params().get(0).paramType());
        assertEquals("true",
            tools.get("/patch_bytes").params().stream()
                .filter(parameter ->
                    parameter.name().equals("clear_code_units"))
                .findFirst().orElseThrow().defaultValue());
        assertEquals("false",
            tools.get("/patch_bytes").params().stream()
                .filter(parameter ->
                    parameter.name().equals("allow_readonly"))
                .findFirst().orElseThrow().defaultValue());
        assertTrue(tools.get("/create_memory_block").description()
            .contains("initialized"));
        assertTrue(tools.get("/write_memory_bytes").description()
            .contains("4096"));
        assertTrue(tools.get("/write_memory_bytes").description()
            .contains("split"));
        var conflictPolicy = tools.get("/write_memory_bytes").params().stream()
            .filter(parameter -> parameter.name().equals("conflict_policy"))
            .findFirst().orElseThrow();
        assertTrue(conflictPolicy.description().contains("4096"));
        assertTrue(conflictPolicy.description().contains("split"));
        for (String path : List.of(
                "/create_memory_block",
                "/update_memory_block",
                "/split_memory_block",
                "/move_memory_block",
                "/write_memory_bytes",
                "/delete_memory_block",
                "/resize_memory_block",
                "/patch_bytes")) {
            assertTrue(path, tools.get(path).supportsDryRun());
        }
    }

    @Test
    public void scannerEndpointStreamsBytesAndSeparatesExplicitFromSyntheticDryRun()
            throws Exception {
        AnnotationScanner scanner = new AnnotationScanner(
            ServiceFactory.stubProvider(), ServiceFactory.buildAllServices());
        var create = scanner.getEndpoints().stream()
            .filter(endpoint -> endpoint.path().equals("/create_memory_block"))
            .findFirst().orElseThrow();

        Map<String, Object> body = create.parseBody(
            new ByteArrayInputStream(
                ("{\"name\":\"bank\",\"start\":\"0x8000\","
                    + "\"bytes\":[0,255,16],\"dry_run\":true}")
                    .getBytes(StandardCharsets.UTF_8)));
        assertTrue(body.get("bytes") instanceof byte[]);
        assertTrue(java.util.Arrays.equals(
            new byte[] { 0, (byte) 255, 16 },
            (byte[]) body.get("bytes")));

        Response synthetic = create.handler().handle(
            Map.of("dry_run", "true"), Map.of());
        assertTrue(synthetic.toJson(), synthetic instanceof Response.Err);
        assertTrue(synthetic.toJson(),
            synthetic.toJson().contains("synthetic query dry_run"));
    }

    @Test
    public void malformedStrictNumbersAndBooleansAreRejectedBeforeInvocation()
            throws Exception {
        AnnotationScanner scanner = new AnnotationScanner(
            ServiceFactory.stubProvider(), ServiceFactory.buildAllServices());
        var create = scanner.getEndpoints().stream()
            .filter(endpoint -> endpoint.path().equals("/create_memory_block"))
            .findFirst().orElseThrow();

        Response fractional = create.handler().handle(
            Map.of(),
            Map.of(
                "name", "ram", "start", "0x1000",
                "length", new java.math.BigDecimal("1.5"),
                "dry_run", true));
        Response malformedBoolean = create.handler().handle(
            Map.of(),
            Map.of(
                "name", "ram", "start", "0x1000",
                "length", new java.math.BigDecimal("16"),
                "overlay", "false", "dry_run", true));
        Response overflow = create.handler().handle(
            Map.of(),
            Map.of(
                "name", "ram", "start", "0x1000",
                "length", new java.math.BigDecimal("9223372036854775808"),
                "dry_run", true));

        assertTrue(fractional.toJson(), fractional instanceof Response.Err);
        assertTrue(fractional.toJson(), fractional.toJson().contains("length"));
        assertTrue(malformedBoolean.toJson(),
            malformedBoolean instanceof Response.Err);
        assertTrue(malformedBoolean.toJson(),
            malformedBoolean.toJson().contains("JSON boolean"));
        assertTrue(overflow.toJson(), overflow instanceof Response.Err);
        assertTrue(overflow.toJson(), overflow.toJson().contains("length"));
    }

    @Test
    public void httpBodyParsingPreservesExactLargeAndFractionalNumbers()
            throws Exception {
        AnnotationScanner scanner = new AnnotationScanner(
            ServiceFactory.stubProvider(), ServiceFactory.buildAllServices());
        var create = scanner.getEndpoints().stream()
            .filter(endpoint -> endpoint.path().equals("/create_memory_block"))
            .findFirst().orElseThrow();

        Map<String, Object> aboveSafeInteger = parse(
            "{\"name\":\"ram\",\"start\":\"0x1000\","
                + "\"length\":9007199254740993,\"dry_run\":true}");
        assertEquals(
            new java.math.BigDecimal("9007199254740993"),
            aboveSafeInteger.get("length"));
        Response exact = create.handler().handle(
            Map.of(), aboveSafeInteger);
        assertTrue(exact.toJson(), exact instanceof Response.Err);
        assertFalse(
            "the parser must not round 9007199254740993 to a nearby Double",
            exact.toJson().contains("9007199254740992"));

        Response fractional = create.handler().handle(
            Map.of(),
            parse("{\"name\":\"ram\",\"start\":\"0x1000\","
                + "\"length\":1.5,\"dry_run\":true}"));
        Response overflow = create.handler().handle(
            Map.of(),
            parse("{\"name\":\"ram\",\"start\":\"0x1000\","
                + "\"length\":9223372036854775808,\"dry_run\":true}"));
        assertTrue(fractional.toJson(), fractional instanceof Response.Err);
        assertTrue(fractional.toJson(), fractional.toJson().contains("length"));
        assertTrue(overflow.toJson(), overflow instanceof Response.Err);
        assertTrue(overflow.toJson(), overflow.toJson().contains("length"));
    }

    @Test
    public void productionSourcesContainOnlyOneCanonicalCreateRoute()
            throws IOException {
        Path root = Path.of(System.getProperty("user.dir"))
            .resolve("src/main/java");
        long occurrences;
        try (var files = Files.walk(root)) {
            occurrences = files
                .filter(path -> path.toString().endsWith(".java"))
                .mapToLong(path -> {
                    try {
                        return count(Files.readString(path),
                            "path = \"/create_memory_block\"");
                    }
                    catch (IOException error) {
                        throw new IllegalStateException(error);
                    }
                })
                .sum();
        }
        assertEquals(1, occurrences);

        var catalog = JsonParser.parseString(
            Files.readString(Path.of("tests/endpoints.json")))
            .getAsJsonObject();
        assertEquals(
            "Create, transform, inspect, and write program memory blocks",
            catalog.getAsJsonObject("categories")
                .get("memory").getAsString());
        var createEntry = catalog.getAsJsonArray("endpoints").asList()
            .stream()
            .map(element -> element.getAsJsonObject())
            .filter(element -> element.get("path").getAsString()
                .equals("/create_memory_block"))
            .findFirst().orElseThrow();
        assertEquals("memory",
            createEntry.get("category").getAsString());
        assertEquals(
            "Create an initialized or uninitialized ordinary or overlay memory block",
            createEntry.get("description").getAsString());
        var writeEntry = catalog.getAsJsonArray("endpoints").asList()
            .stream()
            .map(element -> element.getAsJsonObject())
            .filter(element -> element.get("path").getAsString()
                .equals("/write_memory_bytes"))
            .findFirst().orElseThrow();
        assertTrue(writeEntry.get("description").getAsString()
            .contains("4096"));
        assertTrue(writeEntry.get("description").getAsString()
            .contains("split"));
        for (String path : List.of(
                "/create_memory_block",
                "/update_memory_block",
                "/split_memory_block",
                "/move_memory_block",
                "/write_memory_bytes",
                "/delete_memory_block",
                "/resize_memory_block",
                "/patch_bytes")) {
            var entry = catalog.getAsJsonArray("endpoints").asList()
                .stream()
                .map(element -> element.getAsJsonObject())
                .filter(element -> element.get("path").getAsString()
                    .equals(path))
                .findFirst().orElseThrow();
            assertFalse(path, entry.has("supports_dry_run"));
        }
    }

    private static long count(String text, String token) {
        long count = 0;
        int cursor = 0;
        while ((cursor = text.indexOf(token, cursor)) >= 0) {
            count++;
            cursor += token.length();
        }
        return count;
    }

    private static Map<String, Object> parse(String json) {
        return JsonHelper.parseBody(new ByteArrayInputStream(
            json.getBytes(StandardCharsets.UTF_8)));
    }
}
