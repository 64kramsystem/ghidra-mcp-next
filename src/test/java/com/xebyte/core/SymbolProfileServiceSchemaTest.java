package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.Test;

public class SymbolProfileServiceSchemaTest {
    @Test
    public void scannerPublishesBothStrictProfileEndpoints() {
        SymbolProfileService service = new SymbolProfileService(
            new EmptyProvider(), new DirectThreading());
        AnnotationScanner scanner = new AnnotationScanner(service);

        Map<String, AnnotationScanner.ToolDescriptor> tools =
            scanner.getDescriptors().stream().collect(
                Collectors.toMap(
                    AnnotationScanner.ToolDescriptor::path,
                    item -> item));
        assertEquals(
            Set.of("/validate_symbol_profile", "/apply_symbol_profile"),
            tools.keySet());
        assertEquals(
            Set.of("profile", "program"),
            names(tools.get("/validate_symbol_profile")));
        assertEquals(
            Set.of(
                "profile",
                "dry_run",
                "conflict_policy",
                "replace_user_definitions",
                "create_memory_blocks",
                "program"),
            names(tools.get("/apply_symbol_profile")));
        assertTrue(
            tools.get("/apply_symbol_profile").supportsDryRun());
    }

    @Test
    public void schemaDeclaresNativeJsonAndTypedSafetyDefaults() {
        JsonArray tools = JsonParser.parseString(
                new AnnotationScanner(
                    new SymbolProfileService(
                        new EmptyProvider(),
                        new DirectThreading()))
                    .generateSchema())
            .getAsJsonObject()
            .getAsJsonArray("tools");
        JsonObject apply = endpoint(tools, "/apply_symbol_profile");
        JsonObject profile = parameter(apply, "profile");
        JsonObject dryRun = parameter(apply, "dry_run");
        JsonObject replace = parameter(
            apply, "replace_user_definitions");
        JsonObject blocks = parameter(
            apply, "create_memory_blocks");

        assertEquals("any", profile.get("type").getAsString());
        assertEquals(
            "object",
            profile.getAsJsonObject("schema").get("type").getAsString());
        assertFalse(profile.getAsJsonObject("schema")
            .get("additionalProperties").getAsBoolean());
        assertEquals("body", profile.get("source").getAsString());
        assertTrue(profile.get("required").getAsBoolean());
        assertTrue(dryRun.get("default").getAsBoolean());
        assertFalse(replace.get("default").getAsBoolean());
        assertFalse(blocks.get("default").getAsBoolean());
    }

    @Test
    public void transportPassesNativeProfileObjectsAndTypedDefaults()
            throws Exception {
        SymbolProfileService service = new SymbolProfileService(
            new EmptyProvider(), new DirectThreading());
        Map<String, Object> profile = new LinkedHashMap<>();
        profile.put("schema_version", 1);
        profile.put("id", "native");
        profile.put("version", "1");

        EndpointDef validate = new AnnotationScanner(service)
            .getEndpoints().stream()
            .filter(item ->
                "/validate_symbol_profile".equals(item.path()))
            .findFirst()
            .orElseThrow();
        JsonObject validated = JsonParser.parseString(
            validate.handler().handle(
                Map.of(), Map.of("profile", profile)).toJson())
            .getAsJsonObject();
        assertTrue(validated.get("valid").getAsBoolean());
        assertFalse(
            validated.get("program_checks_performed").getAsBoolean());

        EndpointDef apply = new AnnotationScanner(service)
            .getEndpoints().stream()
            .filter(item ->
                "/apply_symbol_profile".equals(item.path()))
            .findFirst()
            .orElseThrow();
        Response response = apply.handler().handle(
            Map.of(), Map.of("profile", profile));
        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(
            response.toJson(),
            !response.toJson().contains("JSON boolean"));
    }

    private static Set<String> names(
            AnnotationScanner.ToolDescriptor tool) {
        assertNotNull(tool);
        return tool.params().stream()
            .map(AnnotationScanner.ParamDescriptor::name)
            .collect(Collectors.toSet());
    }

    private static JsonObject endpoint(
            JsonArray tools, String path) {
        for (var value : tools) {
            JsonObject endpoint = value.getAsJsonObject();
            if (path.equals(endpoint.get("path").getAsString())) {
                return endpoint;
            }
        }
        throw new AssertionError("missing endpoint " + path);
    }

    private static JsonObject parameter(
            JsonObject endpoint, String name) {
        for (var value : endpoint.getAsJsonArray("params")) {
            JsonObject parameter = value.getAsJsonObject();
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
                java.util.concurrent.Callable<T> action)
                throws Exception {
            return action.call();
        }
        public <T> T executeWrite(
                ghidra.program.model.listing.Program program,
                String description,
                java.util.concurrent.Callable<T> action)
                throws Exception {
            return action.call();
        }
        public boolean isHeadless() {
            return true;
        }
    }
}
