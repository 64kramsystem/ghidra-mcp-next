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

    private void assertInvalid(Runnable action) {
        try {
            action.run();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }
}
