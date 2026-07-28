package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertFalse;
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
    public void guiAndHeadlessExposeTheSameRequiredShape() {
        JsonObject gui = JsonParser.parseString(
            VersionPayload.toJson("gui", 17)).getAsJsonObject();
        JsonObject headless = JsonParser.parseString(
            VersionPayload.toJson("headless", 19)).getAsJsonObject();

        for (String field : new String[] {
                "plugin_name", "plugin_version", "build_timestamp",
                "build_number", "full_version", "ghidra_version",
                "java_version", "endpoint_count", "mode"}) {
            assertTrue(field, gui.has(field));
            assertTrue(field, headless.has(field));
            assertFalse(field, gui.get(field).isJsonNull());
            assertFalse(field, headless.get(field).isJsonNull());
        }
        assertEquals("gui", gui.get("mode").getAsString());
        assertEquals("headless", headless.get("mode").getAsString());
        assertEquals(17, gui.get("endpoint_count").getAsInt());
        assertEquals(19, headless.get("endpoint_count").getAsInt());
        // plugin_version is the semantic version; build_timestamp is the build
        // time. They were identical while both came from release.timestamp, and
        // asserting that again would re-couple two deliberately separate facts.
        assertTrue("plugin_version must be semantic",
            gui.get("plugin_version").getAsString().matches("\\d+\\.\\d+\\.\\d+"));
        assertNotEquals(
            gui.get("build_timestamp").getAsString(),
            gui.get("plugin_version").getAsString());
        assertEquals(
            gui.get("plugin_name").getAsString() + " "
                + gui.get("plugin_version").getAsString(),
            gui.get("full_version").getAsString());
        for (String field : new String[] {
                "plugin_name", "plugin_version", "build_timestamp",
                "build_number", "full_version", "ghidra_version",
                "java_version"}) {
            assertEquals(field, gui.get(field), headless.get(field));
        }
    }

    @Test
    public void endpointCountEqualsTheGeneratedSchemaToolCount() {
        AnnotationScanner scanner = new AnnotationScanner(new FixtureService());
        JsonObject schema = JsonParser.parseString(
            scanner.generateSchema()).getAsJsonObject();
        JsonObject version = JsonParser.parseString(
            VersionPayload.toJson(
                "gui", scanner.getDescriptors().size())).getAsJsonObject();

        assertEquals(
            schema.getAsJsonArray("tools").size(),
            version.get("endpoint_count").getAsInt());
        assertEquals(
            schema.get("count").getAsInt(),
            version.get("endpoint_count").getAsInt());
    }
}
