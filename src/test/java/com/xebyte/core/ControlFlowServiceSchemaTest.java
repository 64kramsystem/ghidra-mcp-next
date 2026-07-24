package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class ControlFlowServiceSchemaTest {
    @Test
    public void scannerPublishesAllStrictNestedSchemas() {
        AnnotationScanner scanner = new AnnotationScanner(
            new ControlFlowService(
                new EmptyProvider(), new DirectThreading()));
        JsonArray tools = JsonParser.parseString(scanner.generateSchema())
            .getAsJsonObject().getAsJsonArray("tools");

        assertEquals(5, tools.size());
        JsonObject references = endpoint(
            tools, "/batch_update_references");
        JsonObject addSchema = parameter(references, "add")
            .getAsJsonObject("schema");
        assertTrue(addSchema.getAsJsonObject("items")
            .get("additionalProperties").isJsonPrimitive());
        assertEquals(false, addSchema.getAsJsonObject("items")
            .get("additionalProperties").getAsBoolean());
        assertEquals(-1, addSchema.getAsJsonObject("items")
            .getAsJsonObject("properties")
            .getAsJsonObject("operand_index")
            .get("default").getAsInt());
        assertEquals(false, addSchema.getAsJsonObject("items")
            .getAsJsonObject("properties")
            .getAsJsonObject("primary")
            .get("default").getAsBoolean());

        JsonObject jump = endpoint(tools, "/describe_jump_table");
        assertEquals(2, parameter(jump, "table")
            .getAsJsonObject("schema")
            .getAsJsonArray("oneOf").size());
        assertEquals(1024, parameter(jump, "dispatch_addresses")
            .getAsJsonObject("schema")
            .get("maxItems").getAsInt());

        for (var element : tools) {
            JsonObject tool = element.getAsJsonObject();
            JsonObject dry = parameter(tool, "dry_run");
            assertEquals(true, dry.get("default").getAsBoolean());
        }
    }

    @Test
    public void parsersRejectEncodedAndInexactNativeValues() {
        assertThrows(IllegalArgumentException.class, () ->
            ControlFlowService.parseStringArray(
                "[\"1000\"]", "add", 10, true));

        Map<String, Object> encodedBoolean = reference();
        encodedBoolean.put("primary", "false");
        assertThrows(IllegalArgumentException.class, () ->
            ControlFlowService.parseReferenceRequests(
                List.of(encodedBoolean), true, "add"));

        Map<String, Object> fractional = reference();
        fractional.put("operand_index", new BigDecimal("1.5"));
        assertThrows(IllegalArgumentException.class, () ->
            ControlFlowService.parseReferenceRequests(
                List.of(fractional), true, "add"));

        Map<String, Object> unknown = reference();
        unknown.put("surprise", true);
        assertThrows(IllegalArgumentException.class, () ->
            ControlFlowService.parseReferenceRequests(
                List.of(unknown), true, "add"));
    }

    private static Map<String, Object> reference() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("from", "1000");
        result.put("to", "2000");
        result.put("type", "data");
        return result;
    }

    private static JsonObject endpoint(
            JsonArray tools, String path) {
        for (var element : tools) {
            JsonObject tool = element.getAsJsonObject();
            if (path.equals(tool.get("path").getAsString())) {
                return tool;
            }
        }
        throw new AssertionError("missing endpoint " + path);
    }

    private static JsonObject parameter(
            JsonObject tool, String name) {
        for (var element : tool.getAsJsonArray("params")) {
            JsonObject parameter = element.getAsJsonObject();
            if (name.equals(parameter.get("name").getAsString())) {
                return parameter;
            }
        }
        throw new AssertionError("missing parameter " + name);
    }

    private static final class EmptyProvider implements ProgramProvider {
        public ghidra.program.model.listing.Program getCurrentProgram() {
            return null;
        }
        public ghidra.program.model.listing.Program getProgram(String name) {
            return null;
        }
        public ghidra.program.model.listing.Program[] getAllOpenPrograms() {
            return new ghidra.program.model.listing.Program[0];
        }
        public void setCurrentProgram(
                ghidra.program.model.listing.Program program) {
        }
    }

    private static final class DirectThreading
            implements ThreadingStrategy {
        public <T> T executeRead(
                java.util.concurrent.Callable<T> action) throws Exception {
            return action.call();
        }
        public <T> T executeWrite(
                ghidra.program.model.listing.Program program,
                String description,
                java.util.concurrent.Callable<T> action) throws Exception {
            return action.call();
        }
        public boolean isHeadless() {
            return true;
        }
    }
}
