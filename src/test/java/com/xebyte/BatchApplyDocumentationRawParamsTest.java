package com.xebyte;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;

import org.junit.Test;

/**
 * batch_apply_documentation forwards its two comment arrays to CommentService, which validates
 * them strictly. It used to run them through the permissive converter first, which drops malformed
 * array elements and stringifies non-string values, so the decoder only ever saw an already-cleaned
 * request and rejected nothing. Nothing caught it: a converted List is an Object, so re-introducing
 * the conversion compiles silently and the endpoint keeps reporting success.
 *
 * <p>The signature check is the structural half; the source check is the behavioural half, since
 * the conversion can be re-added at the call site without touching any signature.
 */
public class BatchApplyDocumentationRawParamsTest {

    private static final Path PLUGIN_SOURCE =
            Path.of("src", "main", "java", "com", "xebyte", "GhidraMCPPlugin.java");

    @Test
    public void theForwardingHelperTakesTheArraysRaw() throws Exception {
        Method helper = null;
        for (Method candidate : GhidraMCPPlugin.class.getDeclaredMethods()) {
            if (candidate.getName().equals("batchSetComments")
                    && candidate.getParameterCount() == 4) {
                helper = candidate;
                break;
            }
        }

        assertTrue("no 4-arg batchSetComments helper on GhidraMCPPlugin", helper != null);
        Class<?>[] types = helper.getParameterTypes();
        assertEquals("decompiler_comments must arrive raw", Object.class, types[1]);
        assertEquals("disassembly_comments must arrive raw", Object.class, types[2]);
    }

    @Test
    public void theCallSiteDoesNotPreConvertTheCommentArrays() throws Exception {
        String source = Files.readString(PLUGIN_SOURCE, StandardCharsets.UTF_8);

        for (String field : new String[] {"decompiler_comments", "disassembly_comments"}) {
            Pattern lossy = Pattern.compile(
                    "convertToMapList\\s*\\(\\s*params\\.get\\(\\s*\"" + field + "\"");
            assertFalse(
                    field + " is converted before validation -- the strict decoder will see a "
                            + "cleaned request and reject nothing",
                    lossy.matcher(source).find());
        }
    }
}
