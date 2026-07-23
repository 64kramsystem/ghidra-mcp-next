package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
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
        assertEquals(BigInteger.valueOf(0x100c), math.trailingStart());
        assertEquals(BigInteger.valueOf(0x1010), math.trailingEnd());
        assertTrue(math.hasTrailing());
    }

    @Test
    public void shortRangeContainsNoElementsAndIsEntirelyTrailing() {
        DataRegionCore.RangeMath math =
            DataRegionCore.rangeMath(0x1000, 0x1002, 6, 6, true);
        assertEquals(0, math.elementCount());
        assertEquals(BigInteger.valueOf(0x1000), math.trailingStart());
        assertEquals(BigInteger.valueOf(0x1002), math.trailingEnd());
    }

    @Test
    public void unsignedMathHandlesHighBitAndTrailingSentinel() {
        DataRegionCore.RangeMath trailing =
            DataRegionCore.rangeMath(
                0xffff_ffff_ffff_fff0L,
                0xffff_ffff_ffff_fffeL,
                8, 8, true);
        assertEquals(1, trailing.elementCount());
        assertTrue(trailing.hasTrailing());
        assertEquals(
            new BigInteger("fffffffffffffff8", 16),
            trailing.trailingStart());
        assertEquals(
            new BigInteger("fffffffffffffffe", 16),
            trailing.trailingEnd());

        DataRegionCore.RangeMath crossingSignedBoundary =
            DataRegionCore.rangeMath(
                0x7fff_ffff_ffff_fff0L,
                0x8000_0000_0000_000fL,
                16, 16, false);
        assertEquals(2, crossingSignedBoundary.elementCount());
        assertFalse(crossingSignedBoundary.hasTrailing());
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
    public void splitRangeValidationUsesUnsignedOverflowSafeMath() {
        DataRegionCore.validateSplitRanges(
            0xffff_ffff_ffff_ffe0L,
            0xffff_ffff_ffff_fff0L,
            8);
        assertThrows(IllegalArgumentException.class,
            () -> DataRegionCore.validateSplitRanges(
                0xffff_ffff_ffff_fffcL,
                0x1000,
                8));
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

        Map<String, Object> oversizedCount = splitRegion();
        oversizedCount.put("count", new BigDecimal("2147483648"));
        assertThrows(IllegalArgumentException.class,
            () -> DataRegionService.parseRegions(List.of(oversizedCount)));

        Map<String, Object> negativeBase = splitRegion();
        negativeBase.put("target_base", -1);
        assertThrows(IllegalArgumentException.class,
            () -> DataRegionService.parseRegions(List.of(negativeBase)));

        Map<String, Object> unsignedBase = splitRegion();
        unsignedBase.put(
            "target_base",
            new BigDecimal("18446744073709551615"));
        DataRegionCore.SplitPointerRequest parsed =
            (DataRegionCore.SplitPointerRequest)
                DataRegionService.parseRegions(
                    List.of(unsignedBase)).get(0);
        assertEquals(
            new BigInteger("18446744073709551615"),
            parsed.pointers().targetBase());
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

    @Test
    public void aggregatePlannedElementBoundIsExact() {
        assertEquals(
            DataRegionCore.MAX_PLANNED_ELEMENTS,
            DataRegionCore.addPlannedElements(
                0, DataRegionCore.MAX_PLANNED_ELEMENTS));
        assertThrows(
            IllegalArgumentException.class,
            () -> DataRegionCore.addPlannedElements(
                0, DataRegionCore.MAX_PLANNED_ELEMENTS + 1));
        assertThrows(
            IllegalArgumentException.class,
            () -> DataRegionCore.addPlannedElements(
                DataRegionCore.MAX_PLANNED_ELEMENTS, 1));

        Map<String, Object> split = splitRegion();
        split.put("count", DataRegionCore.MAX_PLANNED_ELEMENTS);
        assertEquals(
            DataRegionCore.MAX_PLANNED_ELEMENTS,
            ((DataRegionCore.SplitPointerRequest)
                DataRegionService.parseRegions(List.of(split)).get(0))
                    .count());
        split.put("count", DataRegionCore.MAX_PLANNED_ELEMENTS + 1);
        assertThrows(
            IllegalArgumentException.class,
            () -> DataRegionService.parseRegions(List.of(split)));
    }

    private static Map<String, Object> contiguousRegion() {
        Map<String, Object> region = new LinkedHashMap<>();
        region.put("kind", "contiguous");
        region.put("start", "1000");
        region.put("end", "1001");
        region.put("type_name", "byte");
        return region;
    }

    private static Map<String, Object> splitRegion() {
        Map<String, Object> region = new LinkedHashMap<>();
        region.put("kind", "split_pointer_table");
        region.put("first_start", "2000");
        region.put("second_start", "2040");
        region.put("count", 2);
        region.put("layout", "split_low_high");
        region.put("target_space", "ram");
        return region;
    }

}
