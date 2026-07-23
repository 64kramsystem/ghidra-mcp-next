package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DataRegionCoreTest {
    @Test
    public void inclusiveMathReportsTrailingBytes() {
        DataRegionCore.RangeMath math =
            DataRegionCore.rangeMath(0x1000, 0x1010, 6, 6, true);
        assertEquals(2, math.elementCount());
        assertEquals(0x100c, math.trailingStart());
        assertEquals(0x1010, math.trailingEnd());
    }

    @Test
    public void shortRangeContainsNoElementsAndIsEntirelyTrailing() {
        DataRegionCore.RangeMath math =
            DataRegionCore.rangeMath(0x1000, 0x1002, 6, 6, true);
        assertEquals(0, math.elementCount());
        assertEquals(0x1000, math.trailingStart());
        assertEquals(0x1002, math.trailingEnd());
    }

    @Test
    public void rejectsTrailingBytesUnlessAllowed() {
        assertThrows(IllegalArgumentException.class,
            () -> DataRegionCore.rangeMath(
                0x1000, 0x1010, 6, 6, false));
    }

    @Test
    public void rejectsStrideSmallerThanType() {
        assertThrows(IllegalArgumentException.class,
            () -> DataRegionCore.rangeMath(
                0x1000, 0x1010, 6, 5, true));
    }

    @Test
    public void splitSourcesMayNotOverlap() {
        assertThrows(IllegalArgumentException.class,
            () -> DataRegionCore.validateSplitRanges(
                0x2000, 0x2004, 8));
    }

    @Test
    public void decodesAllApprovedPointerOrders() {
        assertEquals(0x1234,
            DataRegionCore.decodeWord(0x34, 0x12, "little_endian_words"));
        assertEquals(0x3412,
            DataRegionCore.decodeWord(0x34, 0x12, "big_endian_words"));
        assertEquals(0x1234,
            DataRegionCore.decodeWord(0x34, 0x12, "split_low_high"));
        assertEquals(0x3412,
            DataRegionCore.decodeWord(0x34, 0x12, "split_high_low"));
    }

    @Test
    public void parserRequiresNativeArrayAndStrictScalars() {
        assertThrows(IllegalArgumentException.class,
            () -> DataRegionService.parseRegions(
                "[{\"kind\":\"contiguous\"}]"));
        Map<String, Object> wrongBoolean = contiguousRegion();
        wrongBoolean.put("clear_conflicts", "true");
        assertThrows(IllegalArgumentException.class,
            () -> DataRegionService.parseRegions(List.of(wrongBoolean)));
        Map<String, Object> fractional = contiguousRegion();
        fractional.put("stride", new BigDecimal("1.5"));
        assertThrows(IllegalArgumentException.class,
            () -> DataRegionService.parseRegions(List.of(fractional)));
        Map<String, Object> unknown = contiguousRegion();
        unknown.put("surprise", true);
        assertThrows(IllegalArgumentException.class,
            () -> DataRegionService.parseRegions(List.of(unknown)));
    }

    @Test
    public void parserEnforcesReviewedRegionCountBound() {
        assertThrows(IllegalArgumentException.class,
            () -> DataRegionService.parseRegions(List.of()));
        List<Map<String, Object>> maximum = new ArrayList<>();
        for (int i = 0; i < 1024; i++) {
            maximum.add(contiguousRegion());
        }
        assertEquals(1024,
            DataRegionService.parseRegions(maximum).size());
        maximum.add(contiguousRegion());
        assertThrows(IllegalArgumentException.class,
            () -> DataRegionService.parseRegions(maximum));
    }

    private static Map<String, Object> contiguousRegion() {
        Map<String, Object> region = new LinkedHashMap<>();
        region.put("kind", "contiguous");
        region.put("start", "1000");
        region.put("end", "1001");
        region.put("type_name", "byte");
        return region;
    }
}
