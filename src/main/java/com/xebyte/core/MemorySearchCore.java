package com.xebyte.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Bounded chunk scanner shared by {@code /search_byte_patterns} and
 * {@code /search_address_encodings}.
 *
 * <p><b>Why not {@code Memory.findBytes}.</b> {@code MemoryMapDB.findBytes} wraps its
 * candidate reads in {@code try}/{@code catch} and returns {@code null} on failure, so a
 * read error is indistinguishable from "no match". An endpoint that promises to surface
 * read failures cannot be built on it. It also constrains only a candidate's <em>start</em>
 * against the end address, so it cannot by itself enforce that a whole match lies inside
 * the requested range.</p>
 *
 * <p>The traversal instead walks the initialized address set intersected with each memory
 * block, <b>never crossing a block boundary</b>, reading fixed-size chunks and retaining
 * {@code width - 1} bytes of overlap within one range so a match spanning a chunk seam is
 * still found while memory use stays bounded by {@code chunkSize + width}. A match
 * straddling the end of one range and the start of the next is deliberately not found:
 * ranges are scanned independently, because a pattern spanning the seam would assume
 * adjacency of unrelated content.</p>
 *
 * <p>Matches are streamed to a visitor rather than accumulated. An all-wildcard pattern
 * matches at nearly every offset, so retaining every hit would reintroduce an unbounded
 * allocation by another route.</p>
 */
public final class MemorySearchCore {

    /** Default bytes read per chunk. Bounds the scanner's working set with the pattern. */
    public static final int DEFAULT_CHUNK_SIZE = 65_536;

    private MemorySearchCore() {
    }

    /**
     * Reads program bytes. A seam, so tests can drive the scanner's failure paths and
     * observe exactly how much it ever asks for.
     */
    public interface ByteSource {
        /**
         * @return the number of bytes actually read; anything less than {@code length} is
         *     treated as a read failure by the scanner, never as a miss.
         */
        int read(Address start, byte[] buffer, int destinationOffset, int length)
            throws Exception;
    }

    /** The production source: Ghidra's memory, read directly rather than through findBytes. */
    public static ByteSource memorySource(Memory memory) {
        return (start, buffer, destinationOffset, length) ->
            memory.getBytes(start, buffer, destinationOffset, length);
    }

    /** One contiguous initialized run inside one memory block. */
    public record ScanRange(String blockName, Address start, Address end) {

        /** Byte count, as an unsigned-safe long. */
        public long length() {
            return end.subtract(start) + 1;
        }
    }

    /** Decides whether a window of {@code width} bytes at {@code offset} matches. */
    public interface WindowMatcher {
        boolean matches(byte[] buffer, int offset);
    }

    /** Receives each match in traversal order. Returning false ends the scan. */
    public interface MatchVisitor {
        boolean visit(Address address);
    }

    /** Either a completed scan or the structured error that stopped it. */
    public record ScanOutcome(String error) {

        public boolean failed() {
            return error != null;
        }

        static ScanOutcome ok() {
            return new ScanOutcome(null);
        }
    }

    /**
     * The ranges a scan will cover, in the traversal order the endpoints promise:
     * address-space name, then offset.
     *
     * <p>Each memory block is intersected with {@code Memory.getAllInitializedAddressSet()}
     * — not filtered on {@code MemoryBlock.isInitialized()}, which is false for byte- and
     * bit-mapped blocks whose underlying bytes are initialized. Intersecting per block is
     * also what keeps two abutting blocks separate: their initialized runs coalesce inside
     * an {@code AddressSet}, and a merged range would let a match span the seam.
     *
     * @param start optional inclusive scope start; when non-null only its own address space
     *     is searched
     * @param end inclusive scope end, required when {@code start} is given
     */
    public static List<ScanRange> initializedRanges(
            Program program, Address start, Address end) {
        Memory memory = program.getMemory();
        AddressSetView initialized = memory.getAllInitializedAddressSet();
        AddressSet scope = start == null ? null : new AddressSet(start, end);

        List<ScanRange> ranges = new ArrayList<>();
        MemoryBlock[] blocks = memory.getBlocks();
        if (blocks == null) {
            return ranges;
        }
        for (MemoryBlock block : blocks) {
            if (block == null || block.getStart() == null || block.getEnd() == null) {
                continue;
            }
            AddressSet blockSet = new AddressSet(block.getStart(), block.getEnd());
            AddressSet usable = blockSet.intersect(initialized);
            if (scope != null) {
                // Intersection carries the space test: a range in another space
                // shares no address with this one however its offsets look.
                usable = usable.intersect(scope);
            }
            for (AddressRange range : usable) {
                ranges.add(new ScanRange(
                    block.getName(), range.getMinAddress(), range.getMaxAddress()));
            }
        }
        ranges.sort(Comparator
            .comparing((ScanRange range) -> range.start().getAddressSpace().getName())
            .thenComparing(range -> range.start().getOffsetAsBigInteger()));
        return ranges;
    }

    /**
     * Scan {@code ranges} in order, reporting every offset where {@code matcher} accepts a
     * {@code width}-byte window that lies wholly inside one range.
     *
     * <p>The last legal candidate in a range is {@code rangeEnd - (width - 1)}, which is
     * what makes "the whole match is inside the range" true rather than aspirational.
     * Candidates advance one byte at a time, so overlapping matches all appear.</p>
     */
    public static ScanOutcome scan(
            ByteSource source,
            List<ScanRange> ranges,
            int width,
            int chunkSize,
            WindowMatcher matcher,
            MatchVisitor visitor) {
        if (width < 1) {
            throw new IllegalArgumentException("pattern width must be positive");
        }
        if (chunkSize < 1) {
            throw new IllegalArgumentException("chunk size must be positive");
        }
        for (ScanRange range : ranges) {
            ScanOutcome outcome =
                scanRange(source, range, width, chunkSize, matcher, visitor);
            if (outcome != null) {
                return outcome;
            }
        }
        return ScanOutcome.ok();
    }

    /** @return null to continue with the next range, otherwise the terminating outcome. */
    private static ScanOutcome scanRange(
            ByteSource source,
            ScanRange range,
            int width,
            int chunkSize,
            WindowMatcher matcher,
            MatchVisitor visitor) {
        long rangeLength = range.length();
        if (rangeLength < width) {
            return null;
        }
        long lastCandidate = rangeLength - width;
        int capacity = (int) Math.min(chunkSize, rangeLength) + width - 1;
        byte[] buffer = new byte[capacity];

        long consumed = 0;
        int held = 0;
        while (true) {
            // At most one chunk per read, into the space after any retained overlap:
            // the buffer is capped at chunkSize + width - 1 and each request at chunkSize.
            int want = (int) Math.min(
                Math.min(chunkSize, capacity - held), rangeLength - (consumed + held));
            if (want > 0) {
                Address readAt = range.start().add(consumed + held);
                final int read;
                try {
                    read = source.read(readAt, buffer, held, want);
                }
                catch (Exception exception) {
                    return new ScanOutcome(readError(
                        range, readAt, want, exception.getMessage()));
                }
                if (read != want) {
                    return new ScanOutcome(readError(
                        range, readAt, want, "only " + read + " byte(s) were readable"));
                }
                held += read;
            }

            long lastInBuffer = Math.min((long) held - width, lastCandidate - consumed);
            for (int index = 0; index <= lastInBuffer; index++) {
                if (matcher.matches(buffer, index)) {
                    if (!visitor.visit(range.start().add(consumed + index))) {
                        return ScanOutcome.ok();
                    }
                }
            }

            if (consumed + held >= rangeLength) {
                return null;
            }
            // Retain the trailing width-1 bytes so a window straddling the seam is
            // still tested exactly once, from the earlier of the two chunks.
            int retained = width - 1;
            System.arraycopy(buffer, held - retained, buffer, 0, retained);
            consumed += held - retained;
            held = retained;
        }
    }

    /**
     * A read failure names the block and the address so it can be acted on. It is never
     * folded into "no match": that is the defect that made the previous implementation's
     * counts silently incomplete.
     */
    private static String readError(
            ScanRange range, Address at, int requested, String detail) {
        return "Could not read " + requested + " byte(s) at " + at.toString(true)
            + " in block '" + range.blockName() + "' (range " + range.start().toString(true)
            + "-" + range.end().toString(true) + "): "
            + (detail == null ? "read failed" : detail);
    }
}
