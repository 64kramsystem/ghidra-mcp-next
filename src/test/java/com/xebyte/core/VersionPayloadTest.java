package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.Test;

public class VersionPayloadTest {

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
    }
}
