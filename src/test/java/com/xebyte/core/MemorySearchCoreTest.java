package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * The bounded chunk scanner both search endpoints share.
 *
 * <p>The memory bound is asserted against a recording fake rather than against a
 * multi-megabyte fixture: a real giant block would only make the suite slow while
 * proving less, because nothing in it observes how much the scanner asked for.</p>
 */
public class MemorySearchCoreTest {

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace("RAM", 32, AddressSpace.TYPE_RAM, 0);
    private static final GenericAddressSpace PLAYER =
        new GenericAddressSpace("SND_PLAYER", 32, AddressSpace.TYPE_RAM, 1);

    // ------------------------------------------------------------- fake source

    /**
     * A {@link MemorySearchCore.ByteSource} over flat per-space images that records the
     * largest buffer and the largest length the core ever asked for, and can fail one
     * chosen read either by throwing or by returning short.
     */
    private static final class RecordingSource implements MemorySearchCore.ByteSource {
        private final Map<String, byte[]> images = new HashMap<>();
        int maxBufferLength;
        int maxRequestedLength;
        int reads;
        int throwAtRead = -1;
        int shortAtRead = -1;

        RecordingSource put(AddressSpace space, byte[] image) {
            images.put(space.getName(), image);
            return this;
        }

        @Override
        public int read(Address start, byte[] buffer, int destinationOffset, int length)
                throws MemoryAccessException {
            reads++;
            maxBufferLength = Math.max(maxBufferLength, buffer.length);
            maxRequestedLength = Math.max(maxRequestedLength, length);
            if (reads == throwAtRead) {
                throw new MemoryAccessException("simulated read failure");
            }
            byte[] image = images.get(start.getAddressSpace().getName());
            int served = reads == shortAtRead ? Math.max(0, length - 1) : length;
            for (int index = 0; index < served; index++) {
                buffer[destinationOffset + index] =
                    image[(int) start.getOffset() + index];
            }
            return served;
        }
    }

    private static MemorySearchCore.WindowMatcher literal(int... bytes) {
        byte[] pattern = new byte[bytes.length];
        for (int index = 0; index < bytes.length; index++) {
            pattern[index] = (byte) bytes[index];
        }
        return (buffer, offset) -> {
            for (int index = 0; index < pattern.length; index++) {
                if (buffer[offset + index] != pattern[index]) return false;
            }
            return true;
        };
    }

    private static MemorySearchCore.ScanRange range(
            String block, AddressSpace space, long start, long end) {
        return new MemorySearchCore.ScanRange(
            block, space.getAddress(start), space.getAddress(end));
    }

    private static List<String> scanCollecting(
            RecordingSource source,
            List<MemorySearchCore.ScanRange> ranges,
            int width,
            int chunkSize,
            MemorySearchCore.WindowMatcher matcher,
            List<String> hits) {
        MemorySearchCore.ScanOutcome outcome = MemorySearchCore.scan(
            source, ranges, width, chunkSize, matcher,
            address -> {
                hits.add(address.toString(true));
                return true;
            });
        assertFalse("unexpected scan error: " + outcome.error(), outcome.failed());
        return hits;
    }

    // ---------------------------------------------------------- memory bounds

    @Test
    public void scanNeverRequestsMoreThanOneChunkPlusThePattern() {
        byte[] image = new byte[1 << 20];
        image[0x4000] = 0x20;
        image[0x4001] = 0x11;
        image[0x4002] = (byte) 0x97;
        RecordingSource source = new RecordingSource().put(RAM, image);

        List<String> hits = new ArrayList<>();
        scanCollecting(source,
            List.of(range("ram", RAM, 0, image.length - 1)),
            3, 4096, literal(0x20, 0x11, 0x97), hits);

        assertEquals(List.of("RAM:00004000"), hits);
        assertTrue("the scanner read the whole range in one allocation: "
                + source.maxBufferLength,
            source.maxBufferLength <= 4096 + 3);
        assertTrue(source.maxRequestedLength <= 4096);
        assertTrue("a chunked scan must issue many reads, got " + source.reads,
            source.reads > 100);
    }

    @Test
    public void aSixtyFourKilobytePatternStillBoundsTheBuffer() {
        // The pattern cap exists for exactly this term of the bound: the scanner
        // retains patternLength - 1 bytes across a seam, so an unbounded pattern
        // would defeat the fixed buffer.
        int width = 65_536;
        byte[] image = new byte[width * 3];
        Arrays.fill(image, (byte) 0x00);
        RecordingSource source = new RecordingSource().put(RAM, image);

        int[] pattern = new int[width];
        MemorySearchCore.ScanOutcome outcome = MemorySearchCore.scan(
            source, List.of(range("ram", RAM, 0, image.length - 1)),
            width, 65_536, literal(pattern), address -> true);

        assertFalse(outcome.failed());
        assertTrue("buffer " + source.maxBufferLength + " exceeded chunk + pattern",
            source.maxBufferLength <= 65_536 + width);
    }

    // --------------------------------------------------------------- chunking

    @Test
    public void matchStraddlingAChunkSeamIsFound() {
        byte[] image = new byte[64];
        image[15] = 0x20;
        image[16] = 0x11;
        image[17] = (byte) 0x97;
        RecordingSource source = new RecordingSource().put(RAM, image);

        List<String> hits = new ArrayList<>();
        scanCollecting(source, List.of(range("ram", RAM, 0, 63)),
            3, 16, literal(0x20, 0x11, 0x97), hits);

        // Chunk 0 is [0,15]: without the retained width-1 overlap the match at 15
        // is invisible to both chunks.
        assertEquals(List.of("RAM:0000000f"), hits);
    }

    @Test
    public void matchStraddlingABlockBoundaryIsNotFound() {
        // The documented limitation: adjacent ranges are scanned independently,
        // because a pattern spanning the seam would assume unrelated content abuts.
        byte[] image = new byte[64];
        image[15] = 0x20;
        image[16] = 0x11;
        image[17] = (byte) 0x97;
        RecordingSource source = new RecordingSource().put(RAM, image);

        List<String> hits = new ArrayList<>();
        scanCollecting(source,
            List.of(range("first", RAM, 0, 15), range("second", RAM, 16, 63)),
            3, 4096, literal(0x20, 0x11, 0x97), hits);

        assertEquals(List.of(), hits);
    }

    @Test
    public void theLastLegalCandidateIsRangeEndMinusPatternLengthPlusOne() {
        byte[] image = new byte[32];
        image[13] = 0x11;
        image[14] = 0x22;
        image[15] = 0x33;
        // A second, identical window one byte later would run past the range end.
        image[16] = 0x11;
        image[17] = 0x22;
        image[18] = 0x33;
        RecordingSource source = new RecordingSource().put(RAM, image);

        List<String> hits = new ArrayList<>();
        scanCollecting(source, List.of(range("ram", RAM, 0, 15)),
            3, 8, literal(0x11, 0x22, 0x33), hits);

        assertEquals("the whole match must fit inside the range",
            List.of("RAM:0000000d"), hits);
    }

    @Test
    public void overlappingMatchesAreAllReported() {
        byte[] image = new byte[] {0x00, 0x55, 0x55, 0x55, 0x55, 0x00};
        RecordingSource source = new RecordingSource().put(RAM, image);

        List<String> hits = new ArrayList<>();
        scanCollecting(source, List.of(range("ram", RAM, 0, 5)),
            2, 4, literal(0x55, 0x55), hits);

        assertEquals(List.of("RAM:00000001", "RAM:00000002", "RAM:00000003"), hits);
    }

    @Test
    public void aRangeShorterThanThePatternIsSkippedWithoutReading() {
        RecordingSource source = new RecordingSource().put(RAM, new byte[8]);
        List<String> hits = new ArrayList<>();
        scanCollecting(source, List.of(range("ram", RAM, 0, 1)),
            3, 4096, literal(0x00, 0x00, 0x00), hits);
        assertEquals(List.of(), hits);
        assertEquals(0, source.reads);
    }

    @Test
    public void visitorCanStopTheTraversalEarly() {
        byte[] image = new byte[] {0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
        RecordingSource source = new RecordingSource().put(RAM, image);

        List<String> hits = new ArrayList<>();
        MemorySearchCore.ScanOutcome outcome = MemorySearchCore.scan(
            source, List.of(range("ram", RAM, 0, 5)), 1, 4, literal(0x55),
            address -> {
                hits.add(address.toString(true));
                return hits.size() < 2;
            });

        assertFalse(outcome.failed());
        assertEquals(List.of("RAM:00000000", "RAM:00000001"), hits);
    }

    // ---------------------------------------------------------- read failures

    @Test
    public void aThrowingReadIsAStructuredErrorNamingTheBlockAndAddress() {
        RecordingSource source = new RecordingSource().put(RAM, new byte[64]);
        source.throwAtRead = 2;

        List<String> hits = new ArrayList<>();
        MemorySearchCore.ScanOutcome outcome = MemorySearchCore.scan(
            source, List.of(range("CODE", RAM, 0, 63)), 3, 16, literal(0xff, 0xff, 0xff),
            address -> {
                hits.add(address.toString());
                return true;
            });

        assertTrue("a read failure must never be reported as a miss", outcome.failed());
        assertTrue(outcome.error(), outcome.error().contains("CODE"));
        // The first read takes one 16-byte chunk, so the second starts at 0010.
        assertTrue(outcome.error(), outcome.error().contains("RAM:00000010"));
    }

    @Test
    public void aShortReadIsAStructuredErrorAndNotASilentlyShortScan() {
        // Distinct code path from the throwing read: the source returns normally
        // and simply serves fewer bytes than were asked for.
        RecordingSource source = new RecordingSource().put(RAM, new byte[64]);
        source.shortAtRead = 1;

        MemorySearchCore.ScanOutcome outcome = MemorySearchCore.scan(
            source, List.of(range("CODE", RAM, 0, 63)), 3, 16, literal(0x00, 0x00, 0x00),
            address -> true);

        assertTrue(outcome.failed());
        assertTrue(outcome.error(), outcome.error().contains("CODE"));
        assertTrue(outcome.error(), outcome.error().contains("RAM:00000000"));
        assertTrue(outcome.error(), outcome.error().toLowerCase().contains("read"));
    }

    // ------------------------------------------------------------ range build

    private static MemoryBlock block(String name, Address start, Address end) {
        MemoryBlock block = mock(MemoryBlock.class);
        when(block.getName()).thenReturn(name);
        when(block.getStart()).thenReturn(start);
        when(block.getEnd()).thenReturn(end);
        return block;
    }

    private static Program programWith(AddressSet initialized, MemoryBlock... blocks) {
        Program program = mock(Program.class);
        Memory memory = mock(Memory.class);
        when(program.getMemory()).thenReturn(memory);
        when(memory.getBlocks()).thenReturn(blocks);
        when(memory.getAllInitializedAddressSet()).thenReturn(initialized);
        return program;
    }

    @Test
    public void rangesFollowInitializationRatherThanBlockExtent() {
        // A hole inside a mapped block must not be scanned: reading it would fail,
        // and treating the block as one contiguous run is what makes that happen.
        AddressSet initialized = new AddressSet(RAM.getAddress(0), RAM.getAddress(0x0f));
        initialized.add(RAM.getAddress(0x20), RAM.getAddress(0x2f));

        List<MemorySearchCore.ScanRange> ranges = MemorySearchCore.initializedRanges(
            programWith(initialized,
                block("ram", RAM.getAddress(0), RAM.getAddress(0x2f))),
            null, null);

        assertEquals(2, ranges.size());
        assertEquals(RAM.getAddress(0x00), ranges.get(0).start());
        assertEquals(RAM.getAddress(0x0f), ranges.get(0).end());
        assertEquals(RAM.getAddress(0x20), ranges.get(1).start());
    }

    @Test
    public void abuttingBlocksProduceSeparateRanges() {
        // Two adjacent initialized blocks coalesce inside an AddressSet; intersecting
        // per block is what keeps the seam, so a match cannot span two blocks.
        AddressSet initialized = new AddressSet(RAM.getAddress(0), RAM.getAddress(0x1f));

        List<MemorySearchCore.ScanRange> ranges = MemorySearchCore.initializedRanges(
            programWith(initialized,
                block("low", RAM.getAddress(0x00), RAM.getAddress(0x0f)),
                block("high", RAM.getAddress(0x10), RAM.getAddress(0x1f))),
            null, null);

        assertEquals(2, ranges.size());
        assertEquals("low", ranges.get(0).blockName());
        assertEquals("high", ranges.get(1).blockName());
    }

    @Test
    public void rangesAreOrderedBySpaceNameThenOffset() {
        AddressSet initialized = new AddressSet(RAM.getAddress(0), RAM.getAddress(0x1f));
        initialized.add(PLAYER.getAddress(0x00), PLAYER.getAddress(0x0f));

        List<MemorySearchCore.ScanRange> ranges = MemorySearchCore.initializedRanges(
            programWith(initialized,
                block("player", PLAYER.getAddress(0x00), PLAYER.getAddress(0x0f)),
                block("high", RAM.getAddress(0x10), RAM.getAddress(0x1f)),
                block("low", RAM.getAddress(0x00), RAM.getAddress(0x0f))),
            null, null);

        assertEquals(List.of("RAM", "RAM", "SND_PLAYER"),
            ranges.stream()
                .map(r -> r.start().getAddressSpace().getName())
                .toList());
        assertEquals(0x00L, ranges.get(0).start().getOffset());
        assertEquals(0x10L, ranges.get(1).start().getOffset());
    }

    @Test
    public void anExplicitRangeSearchesOnlyItsOwnSpace() {
        AddressSet initialized = new AddressSet(RAM.getAddress(0), RAM.getAddress(0x1f));
        initialized.add(PLAYER.getAddress(0x00), PLAYER.getAddress(0x1f));

        List<MemorySearchCore.ScanRange> ranges = MemorySearchCore.initializedRanges(
            programWith(initialized,
                block("ram", RAM.getAddress(0x00), RAM.getAddress(0x1f)),
                block("player", PLAYER.getAddress(0x00), PLAYER.getAddress(0x1f))),
            PLAYER.getAddress(0x08), PLAYER.getAddress(0x0f));

        assertEquals(1, ranges.size());
        assertEquals("SND_PLAYER", ranges.get(0).start().getAddressSpace().getName());
        assertEquals(0x08L, ranges.get(0).start().getOffset());
        assertEquals(0x0fL, ranges.get(0).end().getOffset());
    }

    @Test
    public void memorySourceDelegatesToTheProgramMemory() throws Exception {
        Memory memory = mock(Memory.class);
        when(memory.getBytes(any(Address.class), any(byte[].class),
            org.mockito.ArgumentMatchers.anyInt(), org.mockito.ArgumentMatchers.anyInt()))
            .thenReturn(7);
        assertEquals(7, MemorySearchCore.memorySource(memory)
            .read(RAM.getAddress(0), new byte[8], 0, 7));
    }
}
