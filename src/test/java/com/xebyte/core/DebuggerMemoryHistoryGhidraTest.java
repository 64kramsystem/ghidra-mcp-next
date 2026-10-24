package com.xebyte.core;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

import org.junit.*;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.Lifespan;

@SuppressWarnings("try")
public class DebuggerMemoryHistoryGhidraTest {
    private DBTrace trace;
    private Address start;

    @BeforeClass
    public static void initialize() throws Exception { GhidraTestRuntime.initialize(); }

    @Before
    public void setUp() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
                .getLanguage(new LanguageID("6502:LE:16:default"));
        trace = new DBTrace("history", language.getDefaultCompilerSpec(), this);
        start = trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        try (var tx = trace.openTransaction("memory history")) {
            trace.getTimeManager().getSnapshot(0, true);
            trace.getTimeManager().getSnapshot(5, true);
            trace.getMemoryManager().putBytes(0, start,
                    ByteBuffer.wrap(new byte[]{0x11, 0x22, 0x11, 0x22}));
            trace.getMemoryManager().putBytes(5, start, ByteBuffer.wrap(new byte[]{0, 0}));
        }
    }

    @After
    public void tearDown() { if (trace != null) trace.release(this); }

    @Test
    public void clipsLifespansAndExcludesMatchesCrossingTheAddressBoundary() throws Exception {
        Map<String, Object> result = DebuggerMemoryHistory.search(trace.getMemoryManager(),
                new AddressRangeImpl(start.add(1), start.add(3)), Lifespan.span(1, 3), "11 22", 100);
        assertEquals(1, result.get("total_matches"));
        List<?> matches = (List<?>) result.get("matches");
        Map<?, ?> hit = (Map<?, ?>) matches.getFirst();
        assertEquals(start.add(2).toString(), hit.get("address"));
        assertEquals(1L, hit.get("first_snap"));
        assertEquals(3L, hit.get("last_snap"));
    }

    @Test
    public void preservesHistoryAndReportsTruncation() throws Exception {
        var result = DebuggerMemoryHistory.search(trace.getMemoryManager(),
                new AddressRangeImpl(start, start.add(3)), Lifespan.span(1, 7), "1122", 1);
        assertEquals(2, result.get("total_matches"));
        assertEquals(true, result.get("truncated"));
        Map<?, ?> hit = (Map<?, ?>) ((List<?>) result.get("matches")).getFirst();
        assertEquals(start.toString(), hit.get("address"));
        assertEquals(1L, hit.get("first_snap"));
        assertEquals(4L, hit.get("last_snap"));
    }

    @Test
    public void rejectsInvalidPatternsAndLimits() {
        var range = new AddressRangeImpl(start, start.add(3));
        assertThrows(IllegalArgumentException.class, () -> DebuggerMemoryHistory.search(
                trace.getMemoryManager(), range, Lifespan.span(0, 1), "??", 1));
        assertThrows(IllegalArgumentException.class, () -> DebuggerMemoryHistory.search(
                trace.getMemoryManager(), range, Lifespan.span(0, 1), "11", 0));
    }

    @Test
    public void unrecordedBytesAreNotReportedAsZeroFilledMemory() throws Exception {
        assertThrows(java.io.IOException.class, () -> DebuggerMemorySemantics.readKnownBytes(
                trace.getMemoryManager(), 0, start.add(100), 4, null,
                ghidra.util.task.TaskMonitor.DUMMY));
        assertArrayEquals(new byte[]{0x11, 0x22, 0x11, 0x22},
                DebuggerMemorySemantics.readKnownBytes(trace.getMemoryManager(), 0, start, 4, null,
                        ghidra.util.task.TaskMonitor.DUMMY));
    }
}
