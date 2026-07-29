package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.Test;

public class VersionPayloadTest {

    private static final class FixtureService {
        @McpTool(path = "/fixture", description = "fixture")
        public Response fixture() {
            return Response.ok("fixture");
        }
    }

    @Test
    public void exposesTheRequiredShape() {
        JsonObject payload = JsonParser.parseString(
            VersionPayload.toJson(17)).getAsJsonObject();

        for (String field : new String[] {
                "plugin_name", "plugin_version", "build_timestamp",
                "build_number", "full_version", "ghidra_version",
                "java_version", "endpoint_count"}) {
            assertTrue(field, payload.has(field));
        }
        assertEquals(17, payload.get("endpoint_count").getAsInt());
        assertTrue("plugin_version must be semantic",
            payload.get("plugin_version").getAsString().matches("\\d+\\.\\d+\\.\\d+"));
        assertNotEquals(
            payload.get("build_timestamp").getAsString(),
            payload.get("plugin_version").getAsString());
        assertEquals(
            payload.get("plugin_name").getAsString() + " "
                + payload.get("plugin_version").getAsString(),
            payload.get("full_version").getAsString());
    }

    @Test
    public void endpointCountEqualsTheGeneratedSchemaToolCount() {
        AnnotationScanner scanner = new AnnotationScanner(new FixtureService());
        JsonObject schema = JsonParser.parseString(
            scanner.generateSchema()).getAsJsonObject();
        JsonObject version = JsonParser.parseString(
            VersionPayload.toJson(
                scanner.getDescriptors().size())).getAsJsonObject();

        assertEquals(
            schema.getAsJsonArray("tools").size(),
            version.get("endpoint_count").getAsInt());
        assertEquals(
            schema.get("count").getAsInt(),
            version.get("endpoint_count").getAsInt());
    }
}
