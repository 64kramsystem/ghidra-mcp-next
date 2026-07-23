package com.xebyte.offline;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.Test;

import com.xebyte.core.AnnotationScanner;

public class ListingRangeSchemaTest {

    @Test
    public void sharedSchemaAdvertisesListingRangeWithQueryPagination() {
        AnnotationScanner scanner =
            new AnnotationScanner(ServiceFactory.stubProvider(), ServiceFactory.buildAllServices());
        Map<String, AnnotationScanner.ToolDescriptor> tools = scanner.getDescriptors()
            .stream()
            .collect(Collectors.toMap(
                AnnotationScanner.ToolDescriptor::path,
                Function.identity()));

        assertTrue(tools.containsKey("/get_listing_range"));
        AnnotationScanner.ToolDescriptor listing = tools.get("/get_listing_range");
        assertEquals("GET", listing.method());
        assertEquals("listing", listing.category());
        assertEquals(List.of(
            "start",
            "end",
            "max_units",
            "max_bytes",
            "max_incoming_refs_per_unit",
            "cursor",
            "program"),
            listing.params().stream()
                .map(AnnotationScanner.ParamDescriptor::name)
                .toList());
        assertEquals(List.of(
            "query", "query", "query", "query", "query", "query", "query"),
            listing.params().stream()
                .map(AnnotationScanner.ParamDescriptor::source)
                .toList());
        assertEquals(java.util.Arrays.asList(
            null, null, "1000", "65536", "1000", "", ""),
            listing.params().stream()
                .map(AnnotationScanner.ParamDescriptor::defaultValue)
                .toList());
    }
}
