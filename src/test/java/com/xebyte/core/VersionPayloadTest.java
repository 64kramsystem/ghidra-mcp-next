package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.Path;
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

    @Test
    public void everyServerTransportUsesTheSharedPayload() throws Exception {
        String guiTcp = Files.readString(Path.of(
            "src/main/java/com/xebyte/GhidraMCPPlugin.java"));
        String guiUds = Files.readString(Path.of(
            "src/main/java/com/xebyte/core/ServerManager.java"));
        String headlessTcp = Files.readString(Path.of(
            "src/main/java/com/xebyte/headless/GhidraMCPHeadlessServer.java"));

        assertTrue(guiTcp.contains("VersionPayload.toJson("));
        assertTrue(guiTcp.contains("VersionInfo.getEndpointCount()"));
        assertTrue(guiUds.contains("VersionPayload.toJson(\"gui\", scanner.getDescriptors().size())"));
        assertTrue(headlessTcp.contains("VersionPayload.toJson("));
        assertTrue(headlessTcp.contains("\"headless\", registeredEndpointCount"));
        assertTrue(guiTcp.contains("setEndpointCount(scanner.getDescriptors().size())"));
        assertTrue(headlessTcp.contains(
            "registeredEndpointCount = scanner.getDescriptors().size()"));
    }
}
