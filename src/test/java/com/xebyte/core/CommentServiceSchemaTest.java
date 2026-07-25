package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The two batch_set_comments arrays are declared {@code Object} so the raw request value reaches
 * the strict decoder unconverted. That declaration is invisible to the scanner, which would
 * otherwise infer {@code "any"} — and the Python bridge renders {@code any} as {@code str}, so the
 * published signature would tell native-array callers to send a string. The schemaFragment is what
 * keeps the wire contract honest, and nothing else in the build would notice if it were dropped.
 */
public class CommentServiceSchemaTest {

    private static JsonObject commentParam(String name) {
        AnnotationScanner scanner =
                new AnnotationScanner(new CommentService(new EmptyProvider(), new DirectThreading()));
        JsonArray tools =
                JsonParser.parseString(scanner.generateSchema()).getAsJsonObject().getAsJsonArray("tools");

        for (var toolElement : tools) {
            JsonObject tool = toolElement.getAsJsonObject();
            if (!"/batch_set_comments".equals(tool.get("path").getAsString())) {
                continue;
            }
            for (var paramElement : tool.getAsJsonArray("params")) {
                JsonObject param = paramElement.getAsJsonObject();
                if (name.equals(param.get("name").getAsString())) {
                    return param;
                }
            }
            throw new AssertionError("missing parameter " + name);
        }
        throw new AssertionError("missing endpoint /batch_set_comments");
    }

    private static void assertPublishedAsCommentArray(String name) {
        JsonObject param = commentParam(name);

        assertTrue(name + " lost its schema: " + param, param.has("schema"));
        JsonObject schema = param.getAsJsonObject("schema");
        assertEquals(name + " is not published as an array: " + schema,
                "array", schema.get("type").getAsString());

        JsonObject items = schema.getAsJsonObject("items");
        assertEquals("object", items.get("type").getAsString());
        assertEquals(false, items.get("additionalProperties").getAsBoolean());
        assertEquals("string",
                items.getAsJsonObject("properties").getAsJsonObject("address").get("type").getAsString());
        assertEquals("string",
                items.getAsJsonObject("properties").getAsJsonObject("comment").get("type").getAsString());

        JsonArray required = items.getAsJsonArray("required");
        assertEquals(2, required.size());
        assertTrue(required.toString(), required.toString().contains("address"));
        assertTrue(required.toString(), required.toString().contains("comment"));
    }

    @Test
    public void decompilerCommentsIsPublishedAsATypedArray() {
        assertPublishedAsCommentArray("decompiler_comments");
    }

    @Test
    public void disassemblyCommentsIsPublishedAsATypedArray() {
        assertPublishedAsCommentArray("disassembly_comments");
    }

    @Test
    public void theFragmentIsWhatTheBridgeReadsBecauseTheInferredTypeIsAny() {
        // The scanner infers "any" from the Object declaration and there is no way to override
        // that field. It is harmless only because the bridge prefers "schema" when present, so
        // the fragment is load-bearing rather than decorative: drop it and the bridge falls back
        // to this "any" and publishes both arrays as strings.
        for (String name : new String[] {"decompiler_comments", "disassembly_comments"}) {
            JsonObject param = commentParam(name);
            assertEquals("any", param.get("type").getAsString());
            assertTrue(name + " relies on the fragment the bridge reads", param.has("schema"));
        }
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
        public void setCurrentProgram(ghidra.program.model.listing.Program program) {
        }
    }

    private static final class DirectThreading implements ThreadingStrategy {
        public <T> T executeRead(java.util.concurrent.Callable<T> action) throws Exception {
            return action.call();
        }
        public <T> T executeWrite(ghidra.program.model.listing.Program program, String description,
                                  java.util.concurrent.Callable<T> action) throws Exception {
            return action.call();
        }
        public boolean isHeadless() {
            return true;
        }
    }
}
