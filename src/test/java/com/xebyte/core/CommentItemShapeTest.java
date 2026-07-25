package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

/**
 * batch_set_comments used to skip malformed items in silence and still report success, so a
 * caller who sent the wrong shape saw {@code disassembly_comments_set: 0} alongside
 * {@code success: true} and reasonably concluded the write had happened. These cover the shape
 * half of the validation, which needs no Program; address resolution is covered by
 * CommentServiceAddressGhidraTest.
 */
public class CommentItemShapeTest {

    private static Map<String, String> item(String... keyValues) {
        Map<String, String> map = new LinkedHashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            map.put(keyValues[i], keyValues[i + 1]);
        }
        return map;
    }

    @Test
    public void wellFormedItemsRaiseNothing() {
        List<Map<String, String>> items =
                List.of(item("address", "0x1000", "comment", "hello"),
                        item("comment", "world", "address", "0x1004"));

        assertEquals(List.of(), CommentService.commentItemShapeProblems("disassembly_comments", items));
    }

    @Test
    public void theShapeThatSilentlyWroteNothingIsNowRejected() {
        // {address, type, text} — what a caller naturally sends when guessing the schema.
        List<Map<String, String>> items =
                List.of(item("address", "0x9da6", "type", "eol", "text", "-> overlay"));

        List<String> problems =
                CommentService.commentItemShapeProblems("disassembly_comments", items);

        assertEquals(problems.toString(), 2, problems.size());
        assertTrue(problems.toString(), problems.get(0).contains("unrecognised key(s) [text, type]"));
        assertTrue(problems.toString(), problems.get(1).contains("missing \"comment\""));
    }

    @Test
    public void missingAddressIsReported() {
        List<String> problems = CommentService.commentItemShapeProblems(
                "decompiler_comments", List.of(item("comment", "no address here")));

        assertEquals(1, problems.size());
        assertTrue(problems.get(0), problems.get(0).contains("missing \"address\""));
    }

    @Test
    public void problemsNameTheFieldAndIndex() {
        List<Map<String, String>> items =
                List.of(item("address", "0x1000", "comment", "fine"),
                        item("address", "0x1004"));

        List<String> problems =
                CommentService.commentItemShapeProblems("decompiler_comments", items);

        assertEquals(1, problems.size());
        assertTrue(problems.get(0), problems.get(0).startsWith("decompiler_comments[1]"));
    }

    @Test
    public void everyBadItemIsReportedNotJustTheFirst() {
        List<Map<String, String>> items =
                List.of(item("address", "0x1000"), item("comment", "x"), item("bogus", "y"));

        List<String> problems =
                CommentService.commentItemShapeProblems("disassembly_comments", items);

        assertTrue(problems.toString(), problems.size() >= 3);
    }

    @Test
    public void nullListAndNullItemAreHandled() {
        assertEquals(List.of(), CommentService.commentItemShapeProblems("decompiler_comments", null));

        List<Map<String, String>> withNull = new ArrayList<>(Arrays.asList((Map<String, String>) null));
        List<String> problems =
                CommentService.commentItemShapeProblems("decompiler_comments", withNull);

        assertEquals(1, problems.size());
        assertTrue(problems.get(0), problems.get(0).contains("is null"));
    }

    // ---- wire-boundary decoding -------------------------------------------------------
    // The service-level checks below were reachable only if the request survived conversion
    // intact. It did not: the direct path dropped non-object elements and the stringified path
    // used a different converter that still did. Both are decoded here by one strict route.

    private static List<String> decodeProblems(Object raw) {
        List<String> problems = new ArrayList<>();
        CommentService.decodeCommentItems("disassembly_comments", raw, problems);
        return problems;
    }

    @Test
    public void aStringifiedArrayWithAScalarElementIsRejected() {
        List<String> problems =
                decodeProblems("[{\"address\":\"0x1000\",\"comment\":\"ok\"},42]");

        assertEquals(problems.toString(), 1, problems.size());
        assertTrue(problems.get(0), problems.get(0).contains("[1] must be an object"));
    }

    @Test
    public void aDirectListWithAScalarElementIsRejected() {
        List<Object> raw = new ArrayList<>();
        raw.add(item("address", "0x1000", "comment", "ok"));
        raw.add(42);

        List<String> problems = decodeProblems(raw);

        assertEquals(problems.toString(), 1, problems.size());
        assertTrue(problems.get(0), problems.get(0).contains("[1] must be an object"));
    }

    @Test
    public void aStringifiedObjectInsteadOfAnArrayIsRejected() {
        List<String> problems = decodeProblems("{\"address\":\"0x1000\",\"comment\":\"ok\"}");

        assertEquals(1, problems.size());
        assertTrue(problems.get(0), problems.get(0).contains("must be a JSON array"));
    }

    @Test
    public void nonStringValuesAreRejectedRatherThanStringified() {
        // These used to become the literal comments "123.0" and "{nested=true}".
        assertTrue(decodeProblems("[{\"address\":\"0x1000\",\"comment\":123}]").toString()
                .contains("must be a string"));
        assertTrue(decodeProblems("[{\"address\":\"0x1000\",\"comment\":{\"nested\":true}}]")
                .toString().contains("must be a string"));
        assertTrue(decodeProblems("[{\"address\":1000,\"comment\":\"ok\"}]").toString()
                .contains("must be a string"));
    }

    @Test
    public void wellFormedInputDecodesFromEitherForm() {
        List<String> problems = new ArrayList<>();
        List<Map<String, String>> fromString = CommentService.decodeCommentItems(
                "disassembly_comments",
                "[{\"address\":\"0x1000\",\"comment\":\"hello\"}]", problems);
        List<Map<String, String>> fromList = CommentService.decodeCommentItems(
                "disassembly_comments",
                List.of(item("address", "0x1000", "comment", "hello")), problems);

        assertEquals(List.of(), problems);
        assertEquals(fromString, fromList);
        assertEquals("hello", fromString.get(0).get("comment"));
    }

    @Test
    public void anEmptyCommentStaysValidBecauseItClears() {
        List<String> problems = new ArrayList<>();
        List<Map<String, String>> decoded = CommentService.decodeCommentItems(
                "disassembly_comments",
                "[{\"address\":\"0x1000\",\"comment\":\"\"}]", problems);

        assertEquals(List.of(), problems);
        assertEquals("", decoded.get(0).get("comment"));
    }

    @Test
    public void anAbsentOrBlankArrayIsNotAnError() {
        assertEquals(List.of(), decodeProblems(null));
        assertEquals(List.of(), decodeProblems(""));
        assertEquals(List.of(), decodeProblems("[]"));
    }
}
