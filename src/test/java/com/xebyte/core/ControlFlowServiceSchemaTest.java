package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.RefTypeFactory;

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
    public void batchReferenceSchemasPublishSafeAddAndExactRemoveTypes() {
        AnnotationScanner scanner = new AnnotationScanner(
            new ControlFlowService(
                new EmptyProvider(), new DirectThreading()));
        JsonArray tools = JsonParser.parseString(scanner.generateSchema())
            .getAsJsonObject().getAsJsonArray("tools");
        JsonObject references = endpoint(
            tools, "/batch_update_references");

        JsonObject addType = itemProperty(references, "add", "type");
        Set<String> actualAddTypes = new LinkedHashSet<>();
        addType.getAsJsonArray("enum").forEach(
            value -> actualAddTypes.add(value.getAsString()));
        assertTrue(
            addType.get("description").getAsString()
                .contains("Creatable"));
        RefType[] factoryTypes = RefTypeFactory.getMemoryRefTypes();
        Set<String> expectedAddTypes = Arrays.stream(
                Arrays.copyOf(factoryTypes, factoryTypes.length))
            .map(type -> type.getName().toLowerCase(Locale.ROOT))
            .collect(Collectors.toCollection(LinkedHashSet::new));
        expectedAddTypes.add("call");
        expectedAddTypes.add("jump");
        assertEquals(expectedAddTypes, actualAddTypes);

        JsonObject removeType =
            itemProperty(references, "remove", "type");
        assertEquals("string", removeType.get("type").getAsString());
        assertEquals(1, removeType.get("minLength").getAsInt());
        assertFalse(removeType.has("enum"));
        assertTrue(
            removeType.get("description").getAsString()
                .contains("public Ghidra RefType"));
    }

    @Test
    public void batchReferenceParsersRoundTripEverySupportedRefType()
            throws Exception {
        RefType[] factoryTypes = RefTypeFactory.getMemoryRefTypes();
        RefType[] memoryTypes = Arrays.copyOf(
            factoryTypes, factoryTypes.length);
        for (RefType type : memoryTypes) {
            Map<String, Object> add = reference();
            add.put("type", ControlFlowService.wireType(type));
            assertSame(
                type,
                ControlFlowService.parseReferenceRequests(
                    List.of(add), true, "add").get(0).type());
        }

        Map<String, RefType> publicNames = new LinkedHashMap<>();
        for (Field field : RefType.class.getFields()) {
            if (!Modifier.isStatic(field.getModifiers())
                    || !RefType.class.isAssignableFrom(field.getType())) {
                continue;
            }
            RefType type = (RefType) field.get(null);
            assertNoResolverCollision(
                publicNames, field.getName(), type);
            assertNoResolverCollision(
                publicNames, type.getName(), type);

            for (String token :
                    List.of(field.getName(), type.getName(),
                        ControlFlowService.wireType(type))) {
                Map<String, Object> remove = reference();
                remove.put("type", token);
                assertSame(
                    type,
                    ControlFlowService.parseReferenceRequests(
                        List.of(remove), false, "remove").get(0).type());
            }
        }
        assertSame(
            RefType.EXTERNAL_REF,
            parseType("EXTERNAL_REF", false));
        assertSame(
            RefType.EXTERNAL_REF,
            parseType("external", false));
    }

    @Test
    public void batchReferenceParserRejectsUnknownAndUnsafeAddTypes() {
        Map<String, Object> unknown = reference();
        unknown.put("type", "not_a_ref_type");
        assertThrows(IllegalArgumentException.class, () ->
            ControlFlowService.parseReferenceRequests(
                List.of(unknown), true, "add"));
        assertThrows(IllegalArgumentException.class, () ->
            ControlFlowService.parseReferenceRequests(
                List.of(unknown), false, "remove"));

        Map<String, Object> externalAdd = reference();
        externalAdd.put("type", "external");
        assertThrows(IllegalArgumentException.class, () ->
            ControlFlowService.parseReferenceRequests(
                List.of(externalAdd), true, "add"));
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

    private static RefType parseType(
            String token, boolean additions) {
        Map<String, Object> request = reference();
        request.put("type", token);
        return ControlFlowService.parseReferenceRequests(
            List.of(request), additions,
            additions ? "add" : "remove").get(0).type();
    }

    private static void assertNoResolverCollision(
            Map<String, RefType> names, String name, RefType type) {
        RefType previous = names.putIfAbsent(
            name.toUpperCase(Locale.ROOT), type);
        assertTrue(
            "resolver collision for " + name,
            previous == null || previous == type);
    }

    private static JsonObject itemProperty(
            JsonObject tool, String parameterName,
            String propertyName) {
        return parameter(tool, parameterName)
            .getAsJsonObject("schema")
            .getAsJsonObject("items")
            .getAsJsonObject("properties")
            .getAsJsonObject(propertyName);
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
