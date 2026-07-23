package com.xebyte.core;

import static org.junit.Assert.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class DataRegionServiceSchemaTest {
    @Test
    public void regionsSchemaKeepsNestedFlatUnion() {
        AnnotationScanner scanner = new AnnotationScanner(
            new DataRegionService(new EmptyProvider(), new DirectThreading()));
        String schema = scanner.generateSchema();
        assertTrue(schema.contains("\"path\": \"/apply_data_regions\""));
        assertTrue(schema.contains("\"oneOf\""));
        assertTrue(schema.contains("\"pointers\""));
        assertTrue(schema.contains("\"split_pointer_table\""));

        JsonArray tools = JsonParser.parseString(schema)
            .getAsJsonObject().getAsJsonArray("tools");
        JsonObject endpoint = null;
        for (var element : tools) {
            JsonObject candidate = element.getAsJsonObject();
            if ("/apply_data_regions".equals(
                    candidate.get("path").getAsString())) {
                endpoint = candidate;
                break;
            }
        }
        assertTrue(endpoint != null);
        JsonObject regions = endpoint.getAsJsonArray("params")
            .get(0).getAsJsonObject().getAsJsonObject("schema");
        assertTrue(regions.get("minItems").getAsInt() == 1);
        assertTrue(regions.get("maxItems").getAsInt() == 1024);
        assertTrue(regions.getAsJsonObject("items")
            .getAsJsonArray("oneOf").size() == 2);
        assertTrue(regions.getAsJsonObject("items")
            .getAsJsonArray("oneOf").get(1).getAsJsonObject()
            .getAsJsonObject("properties").getAsJsonObject("count")
            .get("maximum").getAsInt() == 1_000_000);
    }

    @Test
    public void scannerPassesNativeRegionArrayToBodyBinding()
            throws Exception {
        DataRegionService service =
            new DataRegionService(new EmptyProvider(), new DirectThreading());
        EndpointDef endpoint = new AnnotationScanner(service)
            .getEndpoints().stream()
            .filter(candidate ->
                "/apply_data_regions".equals(candidate.path()))
            .findFirst().orElseThrow();
        Map<String, Object> region = new LinkedHashMap<>();
        region.put("kind", "contiguous");
        region.put("start", "1000");
        region.put("end", "1000");
        region.put("type_name", "byte");

        Response response = endpoint.handler().handle(
            Map.of(), Map.of("regions", List.of(region)));

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(
            response.toJson(),
            !response.toJson().contains("native JSON array"));
        assertTrue(
            response.toJson(),
            response.toJson().contains("program")
                || response.toJson().contains("Program"));
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

    private static final class DirectThreading implements ThreadingStrategy {
        @Override
        public <T> T executeRead(java.util.concurrent.Callable<T> action)
                throws Exception {
            return action.call();
        }

        @Override
        public <T> T executeWrite(
                ghidra.program.model.listing.Program program,
                String description,
                java.util.concurrent.Callable<T> action) throws Exception {
            return action.call();
        }

        @Override
        public boolean isHeadless() {
            return true;
        }
    }
}
