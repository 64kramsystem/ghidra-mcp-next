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

    private static int differingBytes(List<ProgramScriptService.DiffRun> runs) {
        return runs.stream().mapToInt(ProgramScriptService.DiffRun::length).sum();
    }

    @Test
    public void identicalRangesProduceNoRuns() {
        List<ProgramScriptService.DiffRun> runs = ProgramScriptService.coalesceDifferences(
                bytes(1, 2, 3), bytes(1, 2, 3));

        assertEquals(List.of(), runs);
    }

    @Test
    public void adjacentDifferencesCoalesceIntoOneRun() {
        List<ProgramScriptService.DiffRun> runs = ProgramScriptService.coalesceDifferences(
                bytes(0, 1, 2, 3, 4), bytes(0, 9, 9, 9, 4));

        assertEquals(1, runs.size());
        assertEquals(1, runs.get(0).offset());
        assertEquals(3, runs.get(0).length());
    }

    @Test
    public void equalBytesSplitARun() {
        // The case that makes "one run of length N" and "N differing bytes" diverge.
        List<ProgramScriptService.DiffRun> runs = ProgramScriptService.coalesceDifferences(
                bytes(1, 1, 1, 1, 1), bytes(9, 1, 9, 1, 9));

        assertEquals(3, runs.size());
        assertEquals(3, differingBytes(runs));
    }

    @Test
    public void aRunEndingAtTheLastByteIsClosed() {
        List<ProgramScriptService.DiffRun> runs = ProgramScriptService.coalesceDifferences(
                bytes(1, 2, 3), bytes(1, 9, 9));

        assertEquals(1, runs.size());
        assertEquals(1, runs.get(0).offset());
        assertEquals(2, runs.get(0).length());
    }

    @Test
    public void aRunStartingAtOffsetZeroIsFound() {
        List<ProgramScriptService.DiffRun> runs = ProgramScriptService.coalesceDifferences(
                bytes(9, 2, 3), bytes(1, 2, 3));

        assertEquals(1, runs.size());
        assertEquals(0, runs.get(0).offset());
    }

    @Test
    public void everyByteDifferingIsASingleRun() {
        List<ProgramScriptService.DiffRun> runs = ProgramScriptService.coalesceDifferences(
                bytes(1, 1, 1), bytes(2, 2, 2));

        assertEquals(1, runs.size());
        assertEquals(3, runs.get(0).length());
        assertEquals(3, differingBytes(runs));
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

        List<ProgramScriptService.DiffRun> runs = ProgramScriptService.coalesceDifferences(a, b);

        assertEquals(2, runs.size());
        assertEquals(0, runs.get(0).offset());
        assertEquals(40, runs.get(0).length());
        assertEquals(70, runs.get(1).offset());
        assertEquals(2, runs.get(1).length());
        assertEquals(42, differingBytes(runs));
        assertTrue(differingBytes(runs) < 72);
    }
}
