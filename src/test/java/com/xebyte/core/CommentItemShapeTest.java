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
}
