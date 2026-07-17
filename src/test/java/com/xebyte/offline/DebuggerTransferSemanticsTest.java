package com.xebyte.offline;

import com.xebyte.core.DebuggerTransferSemantics;
import junit.framework.TestCase;

public class DebuggerTransferSemanticsTest extends TestCase {
    public void testRebasePreservesModuleOffset() {
        assertEquals(0x180001234L,
                DebuggerTransferSemantics.rebase(0x7ff612341234L,
                        0x7ff612340000L, 0x180000000L));
    }

    public void testChunkPlanCoversRangeWithoutOverlap() {
        var chunks = DebuggerTransferSemantics.planChunks(9000, 4096);
        assertEquals(3, chunks.size());
        assertEquals(new DebuggerTransferSemantics.Chunk(0, 4096), chunks.get(0));
        assertEquals(new DebuggerTransferSemantics.Chunk(4096, 4096), chunks.get(1));
        assertEquals(new DebuggerTransferSemantics.Chunk(8192, 808), chunks.get(2));
    }

    public void testChunkPlanRejectsInvalidLengths() {
        assertInvalid(() -> DebuggerTransferSemantics.planChunks(0, 4096));
        assertInvalid(() -> DebuggerTransferSemantics.planChunks(1, 0));
    }

    public void testCheckedRangeUsesInclusiveEnd() {
        assertEquals(new DebuggerTransferSemantics.OffsetRange(0x1000, 0x101f, 0x20),
                DebuggerTransferSemantics.checkedRange(0x1000, 0x20));
    }

    public void testCheckedRangeRejectsInvalidLengthAndOverflow() {
        assertInvalid(() -> DebuggerTransferSemantics.checkedRange(0x1000, 0));
        assertInvalid(() -> DebuggerTransferSemantics.checkedRange(0x1000, -1));
        assertInvalid(() -> DebuggerTransferSemantics.checkedRange(Long.MAX_VALUE, 2));
    }

    public void testChunkPlanUsesExact4096Boundaries() {
        var chunks = DebuggerTransferSemantics.planChunks(8192, 4096);
        assertEquals(2, chunks.size());
        assertEquals(new DebuggerTransferSemantics.Chunk(0, 4096), chunks.get(0));
        assertEquals(new DebuggerTransferSemantics.Chunk(4096, 4096), chunks.get(1));
    }

    private void assertInvalid(Runnable action) {
        try {
            action.run();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }
}
