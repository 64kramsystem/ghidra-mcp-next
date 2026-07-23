package com.xebyte.offline;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.Test;

import com.xebyte.core.AnnotationScanner;

public class ListingMutationSchemaTest {

    @Test
    public void sharedSchemaAdvertisesUndefinitionBodyDefaultsAndProgramQuery() {
        AnnotationScanner scanner =
            new AnnotationScanner(
                ServiceFactory.stubProvider(), ServiceFactory.buildAllServices());
        Map<String, AnnotationScanner.ToolDescriptor> tools =
            scanner.getDescriptors().stream().collect(Collectors.toMap(
                AnnotationScanner.ToolDescriptor::path,
                Function.identity()));

        assertTrue(tools.containsKey("/undefine_range"));
        AnnotationScanner.ToolDescriptor undefine = tools.get("/undefine_range");
        assertEquals("POST", undefine.method());
        assertEquals("listing", undefine.category());
        assertTrue(undefine.supportsDryRun());
        assertEquals(List.of(
            "start",
            "end",
            "clear_instructions",
            "clear_data",
            "preserve_labels",
            "preserve_comments",
            "preserve_bookmarks",
            "preserve_user_references",
            "remove_intersecting_functions",
            "dry_run",
            "program"),
            undefine.params().stream()
                .map(AnnotationScanner.ParamDescriptor::name)
                .toList());
        assertEquals(List.of(
            "body", "body", "body", "body", "body", "body",
            "body", "body", "body", "body", "query"),
            undefine.params().stream()
                .map(AnnotationScanner.ParamDescriptor::source)
                .toList());
        assertEquals(java.util.Arrays.asList(
            null, null,
            "true", "true",
            "true", "true", "true", "true",
            "false", "true", ""),
            undefine.params().stream()
                .map(AnnotationScanner.ParamDescriptor::defaultValue)
                .toList());
    }
}
