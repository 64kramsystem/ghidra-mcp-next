package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

/**
 * Run coalescing for diff_memory.
 *
 * <p>The motivating question was where an overlay diverges from the block it shadows. Answering
 * it previously meant two full range reads and an external diff -- roughly 4k tokens of hex
 * moved through the client to compute a one-line answer.
 *
 * <p>Only differing runs are emitted: the gaps between them are equal by construction, so
 * returning "same" runs as well would double the payload and allow the two to disagree.
 */
public class MemoryDiffCoalescingTest {

    private static byte[] bytes(int... values) {
        byte[] result = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            result[i] = (byte) values[i];
        }
        return result;
    }

    private static ProgramScriptService.DiffSummary diff(byte[] a, byte[] b) {
        return ProgramScriptService.coalesceDifferences(a, b, Integer.MAX_VALUE);
    }

    @Test
    public void identicalRangesProduceNoRuns() {
        ProgramScriptService.DiffSummary summary = diff(bytes(1, 2, 3), bytes(1, 2, 3));

        assertEquals(0, summary.runCount());
        assertEquals(0, summary.differingBytes());
        assertEquals(List.of(), summary.runs());
    }

    @Test
    public void adjacentDifferencesCoalesceIntoOneRun() {
        ProgramScriptService.DiffSummary summary = diff(bytes(0, 1, 2, 3, 4), bytes(0, 9, 9, 9, 4));

        assertEquals(1, summary.runCount());
        assertEquals(1, summary.runs().get(0).offset());
        assertEquals(3, summary.runs().get(0).length());
    }

    @Test
    public void equalBytesSplitARun() {
        // The case that makes "one run of length N" and "N differing bytes" diverge.
        ProgramScriptService.DiffSummary summary = diff(bytes(1, 1, 1, 1, 1), bytes(9, 1, 9, 1, 9));

        assertEquals(3, summary.runCount());
        assertEquals(3, summary.differingBytes());
    }

    @Test
    public void aRunEndingAtTheLastByteIsClosed() {
        ProgramScriptService.DiffSummary summary = diff(bytes(1, 2, 3), bytes(1, 9, 9));

        assertEquals(1, summary.runCount());
        assertEquals(1, summary.runs().get(0).offset());
        assertEquals(2, summary.runs().get(0).length());
    }

    @Test
    public void aRunStartingAtOffsetZeroIsFound() {
        ProgramScriptService.DiffSummary summary = diff(bytes(9, 2, 3), bytes(1, 2, 3));

        assertEquals(1, summary.runCount());
        assertEquals(0, summary.runs().get(0).offset());
    }

    @Test
    public void everyByteDifferingIsASingleRun() {
        ProgramScriptService.DiffSummary summary = diff(bytes(1, 1, 1), bytes(2, 2, 2));

        assertEquals(1, summary.runCount());
        assertEquals(3, summary.runs().get(0).length());
        assertEquals(3, summary.differingBytes());
    }

    @Test
    public void theOverlayShape() {
        // The real case: a leading block differs entirely, the tail is identical apart from a
        // two-byte self-modified operand. Two runs, and differing_bytes is not the extent.
        byte[] a = new byte[100];
        byte[] b = new byte[100];
        for (int i = 0; i < 40; i++) {
            a[i] = (byte) i;
            b[i] = (byte) (i + 1);
        }
        a[70] = 0x12;
        a[71] = 0x34;

        ProgramScriptService.DiffSummary summary = diff(a, b);

        assertEquals(2, summary.runCount());
        assertEquals(0, summary.runs().get(0).offset());
        assertEquals(40, summary.runs().get(0).length());
        assertEquals(70, summary.runs().get(1).offset());
        assertEquals(2, summary.runs().get(1).length());
        assertEquals(42, summary.differingBytes());
        assertTrue(summary.differingBytes() < 72);
    }

    @Test
    public void maxRunsCapsWhatIsRetainedButNotWhatIsCounted() {
        // 16MB of alternating bytes would otherwise allocate ~8.4M run objects to return one.
        byte[] a = new byte[1000];
        byte[] b = new byte[1000];
        for (int i = 0; i < 1000; i += 2) {
            b[i] = 1;
        }

        ProgramScriptService.DiffSummary summary =
                ProgramScriptService.coalesceDifferences(a, b, 3);

        assertEquals(3, summary.runs().size());
        assertEquals(500, summary.runCount());
        assertEquals(500, summary.differingBytes());
        assertEquals(0, summary.firstOffset());
        assertEquals(998, summary.lastOffset());
    }

    @Test
    public void zeroRetainedRunsStillReportsTheTotals() {
        ProgramScriptService.DiffSummary summary =
                ProgramScriptService.coalesceDifferences(bytes(1, 2), bytes(9, 9), 0);

        assertEquals(List.of(), summary.runs());
        assertEquals(1, summary.runCount());
        assertEquals(2, summary.differingBytes());
    }
}
