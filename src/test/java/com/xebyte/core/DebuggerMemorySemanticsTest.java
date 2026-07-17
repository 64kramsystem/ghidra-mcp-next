package com.xebyte.core;

import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

public class DebuggerMemorySemanticsTest extends TestCase {
    public void testParsePidAcceptsNumbersDecimalAndHex() {
        assertEquals(Long.valueOf(42), DebuggerMemorySemantics.parsePid(42));
        assertEquals(Long.valueOf(42), DebuggerMemorySemantics.parsePid(42L));
        assertEquals(Long.valueOf(42), DebuggerMemorySemantics.parsePid("42"));
        assertEquals(Long.valueOf(42), DebuggerMemorySemantics.parsePid("0x2a"));
        assertEquals(Long.valueOf(42), DebuggerMemorySemantics.parsePid("0X2A"));
        assertNull(DebuggerMemorySemantics.parsePid("not-a-pid"));
        assertNull(DebuggerMemorySemantics.parsePid(null));
    }

    public void testDescribeRegionsSortsBySpaceAndUnsignedStart() {
        var high = region("high", 1L, "ram", -16L, "ram:fffffffffffffff0");
        var low = region("low", 1L, "ram", 16L, "ram:0000000000000010");
        var otherSpace = region("register", 1L, "register", 1L, "register:1");

        List<Map<String, Object>> result = DebuggerMemorySemantics.describeRegions(
                List.of(high, otherSpace, low), null);

        assertEquals("low", result.get(0).get("name"));
        assertEquals("high", result.get(1).get("name"));
        assertEquals("register", result.get(2).get("name"));
    }

    public void testDescribeRegionsFiltersByPidAndKeepsCompleteShape() {
        var selected = region("text", 77L, "ram", 0x1000L, "ram:00001000");
        var other = region("other", 88L, "ram", 0x2000L, "ram:00002000");
        var unknown = region("unknown", null, "ram", 0x3000L, "ram:00003000");

        List<Map<String, Object>> result = DebuggerMemorySemantics.describeRegions(
                List.of(other, unknown, selected), 77L);

        assertEquals(1, result.size());
        Map<String, Object> map = result.get(0);
        assertEquals("text", map.get("name"));
        assertEquals("Processes[77].Memory[text]", map.get("path"));
        assertEquals(77L, map.get("process_pid"));
        assertEquals("Processes[77]", map.get("process_path"));
        assertEquals("ram", map.get("address_space"));
        assertEquals("ram:00001000", map.get("start"));
        assertEquals("ram:00001fff", map.get("end"));
        assertEquals(0x1000L, map.get("length"));
        assertEquals(Boolean.TRUE, map.get("read"));
        assertEquals(Boolean.FALSE, map.get("write"));
        assertEquals(Boolean.TRUE, map.get("execute"));
        assertEquals(Boolean.FALSE, map.get("volatile"));
    }

    private DebuggerMemorySemantics.RegionInfo region(String name, Long pid,
                                                       String addressSpace,
                                                       long startOffset,
                                                       String start) {
        return new DebuggerMemorySemantics.RegionInfo(
                name,
                "Processes[" + pid + "].Memory[" + name + "]",
                pid,
                pid == null ? null : "Processes[" + pid + "]",
                addressSpace,
                startOffset,
                start,
                addressSpace + ":00001fff",
                0x1000L,
                true,
                false,
                true,
                false);
    }
}
