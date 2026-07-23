package com.xebyte.offline;

import static org.junit.Assert.assertThrows;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.JsonHelper;
import junit.framework.TestCase;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Characterizes JSON escaping and typed conversion used by endpoint schemas and requests. */
public class JsonHelperTest extends TestCase {

    public void testSerializesStringsAndNestedValuesWithoutLosingEscapes() {
        String special = "quote=\" slash=\\ newline=\n tab=\t snowman=\u2603";
        String json = JsonHelper.toJson(JsonHelper.mapOf(
            "text", special,
            "nested", List.of(JsonHelper.mapOf("enabled", true, "missing", null))));

        Map<String, Object> parsed = JsonHelper.parseJson(json);
        assertEquals(special, parsed.get("text"));
        assertEquals(json, JsonHelper.toJson(parsed));
    }

    public void testParsesRequestBodyIntoTypedStringObjectMap() {
        String json = "{\"name\":\"demo\",\"count\":3,\"nested\":{\"ok\":true}}";
        Map<String, Object> parsed = JsonHelper.parseBody(new ByteArrayInputStream(
            json.getBytes(StandardCharsets.UTF_8)));

        assertEquals("demo", parsed.get("name"));
        assertEquals(3, ((Number) parsed.get("count")).intValue());
        assertTrue(parsed.get("nested") instanceof Map<?, ?>);
    }

    public void testStreamsMarkedNativeByteArraysWithoutMaterializingAList() {
        String json =
            "{\"name\":\"bank\",\"bytes\":[0,255,16],\"count\":3}";
        Map<String, Object> parsed = JsonHelper.parseBody(
            new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)),
            Map.of("bytes", 3));

        assertEquals("bank", parsed.get("name"));
        assertTrue(parsed.get("bytes") instanceof byte[]);
        assertTrue(java.util.Arrays.equals(
            new byte[] { 0, (byte) 255, 16 },
            (byte[]) parsed.get("bytes")));
        assertEquals(3, ((Number) parsed.get("count")).intValue());
    }

    public void testStreamingByteArraysRejectOverflowAndNonBytesExactly() {
        assertThrows(IllegalArgumentException.class, () ->
            JsonHelper.parseBody(
                new ByteArrayInputStream(
                    "{\"bytes\":[0,1,2,3]}".getBytes(StandardCharsets.UTF_8)),
                Map.of("bytes", 3)));
        assertThrows(IllegalArgumentException.class, () ->
            JsonHelper.parseBody(
                new ByteArrayInputStream(
                    "{\"bytes\":[1.5]}".getBytes(StandardCharsets.UTF_8)),
                Map.of("bytes", 3)));
    }

    public void testConvertsJsonArrayObjectsToStringMaps() {
        List<Map<String, String>> converted = JsonHelper.toMapStringList(
            JsonParser.parseString("[{\"name\":\"alpha\",\"count\":2,\"empty\":null}]"));

        assertNotNull(converted);
        assertEquals(1, converted.size());
        assertEquals("alpha", converted.get(0).get("name"));
        assertEquals("2.0", converted.get(0).get("count"));
        assertNull(converted.get(0).get("empty"));
    }

    public void testEndpointSchemaUsesCompleteJsonStringLiterals() {
        EndpointDef.ParamDef param = new EndpointDef.ParamDef(
            "na\"me", "string", "body", false, "line\nvalue", "path \\ detail");
        EndpointDef endpoint = new EndpointDef(
            "/quoted\"path", "POST", (query, body) -> null, "snowman \u2603", List.of(param));

        Map<String, Object> schema = JsonHelper.parseJson(endpoint.schemaJson());
        assertEquals("/quoted\"path", schema.get("path"));
        assertEquals("snowman \u2603", schema.get("description"));
        List<Map<String, String>> params = JsonHelper.toMapStringList(schema.get("params"));
        assertNotNull(params);
        assertEquals("na\"me", params.get(0).get("name"));
        assertEquals("line\nvalue", params.get(0).get("default"));
        assertEquals("path \\ detail", params.get(0).get("description"));
    }

    public void testExplicitNullInJsonTreeIsPreserved() {
        JsonObject tree = new JsonObject();
        tree.add("previous", JsonNull.INSTANCE);
        tree.addProperty("changed", true);

        assertEquals(
            "{\"previous\":null,\"changed\":true}",
            JsonHelper.toJson(tree));
    }
}
