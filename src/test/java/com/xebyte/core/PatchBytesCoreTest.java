package com.xebyte.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HexFormat;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;

public class PatchBytesCoreTest {

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace(
            "ram", 16, AddressSpace.TYPE_RAM, 0);

    @Test
    public void hexadecimalPayloadGrammarIsExactAndBounded() {
        assertArrayEquals(
            hex("00aaff10"),
            PatchBytesCore.decodeHex("  0x00 aa\nff\t10  ", "bytes"));
        assertArrayEquals(
            hex("00aaff10"),
            PatchBytesCore.decodeHex("00 AA ff 10", "bytes"));

        for (String invalid : new String[] {
                "", " \n\t", "0x", "0", "00x1", "0x0x00", "00-11", "gg"
        }) {
            IllegalArgumentException error = assertThrows(
                invalid,
                IllegalArgumentException.class,
                () -> PatchBytesCore.decodeHex(invalid, "bytes"));
            assertTrue(error.getMessage(), error.getMessage().contains("bytes"));
        }

        String exactCap = "00".repeat(PatchBytesCore.MAX_PAYLOAD_BYTES);
        assertEquals(
            PatchBytesCore.MAX_PAYLOAD_BYTES,
            PatchBytesCore.decodeHex(exactCap, "bytes").length);
        IllegalArgumentException overflow = assertThrows(
            IllegalArgumentException.class,
            () -> PatchBytesCore.decodeHex(exactCap + "00", "bytes"));
        assertTrue(overflow.getMessage(), overflow.getMessage().contains("1048576"));
    }

    @Test
    public void expectedCurrentLengthAndFirstMismatchAreExact() {
        byte[] current = hex("00112233");
        PatchBytesCore.validateExpected(hex("00112233"), current);

        IllegalArgumentException length = assertThrows(
            IllegalArgumentException.class,
            () -> PatchBytesCore.validateExpected(hex("0011"), current));
        assertEquals(
            "expected_current must decode to exactly 4 bytes",
            length.getMessage());

        IllegalArgumentException mismatch = assertThrows(
            IllegalArgumentException.class,
            () -> PatchBytesCore.validateExpected(hex("0011ff33"), current));
        assertEquals(
            "expected_current mismatch at offset 2: expected ff, actual 22",
            mismatch.getMessage());
    }

    @Test
    public void payloadSummaryUsesExactFullAndDigestBoundaries() {
        byte[] one = hex("ab");
        PatchBytesCore.PayloadSummary oneSummary =
            PatchBytesCore.summarize(one, one, false);
        assertEquals("ab", oneSummary.previous());
        assertEquals("ab", oneSummary.written());

        byte[] threshold =
            new byte[PatchBytesCore.FULL_HEX_LIMIT];
        PatchBytesCore.PayloadSummary thresholdSummary =
            PatchBytesCore.summarize(threshold, threshold, false);
        assertEquals(
            PatchBytesCore.FULL_HEX_LIMIT * 2,
            thresholdSummary.previous().length());

        byte[] large =
            new byte[PatchBytesCore.FULL_HEX_LIMIT + 1];
        large[0] = 1;
        large[large.length - 1] = (byte) 0xfe;
        PatchBytesCore.PayloadSummary largeSummary =
            PatchBytesCore.summarize(large, large, false);
        assertEquals(null, largeSummary.previous());
        assertEquals(null, largeSummary.written());
        assertEquals(
            MemoryBlockCore.sha256(large),
            largeSummary.previousSha256());
        assertEquals("01" + "00".repeat(31), largeSummary.previousFirst());
        assertEquals("00".repeat(31) + "fe", largeSummary.previousLast());

        PatchBytesCore.PayloadSummary dry =
            PatchBytesCore.summarize(large, large, true);
        assertEquals(large.length * 2, dry.previous().length());
        assertEquals(large.length * 2, dry.written().length());
    }

    @Test
    public void exactBlockLookupRejectsAbsentAndAmbiguousNamesBeforeReads()
            throws Exception {
        Program program = mock(Program.class);
        Memory memory = mock(Memory.class);
        when(program.getMemory()).thenReturn(memory);
        MemoryBlock first = mock(MemoryBlock.class);
        MemoryBlock second = mock(MemoryBlock.class);
        when(first.getName()).thenReturn("bank");
        when(second.getName()).thenReturn("bank");
        when(memory.getBlocks()).thenReturn(
            new MemoryBlock[] { first, second });
        PatchBytesCore.Request request = new PatchBytesCore.Request(
            "8000", "bank", hex("01"), null,
            true, false);

        IllegalArgumentException ambiguous = assertThrows(
            IllegalArgumentException.class,
            () -> new PatchBytesCore().plan(program, request));
        assertEquals(
            "memory block name is ambiguous: bank",
            ambiguous.getMessage());

        when(memory.getBlocks()).thenReturn(new MemoryBlock[0]);
        IllegalArgumentException absent = assertThrows(
            IllegalArgumentException.class,
            () -> new PatchBytesCore().plan(program, request));
        assertEquals(
            "memory block not found: bank",
            absent.getMessage());
    }

    @Test
    public void shortCurrentReadAndShortWriteAreHardFailures()
            throws Exception {
        Program program = mock(Program.class);
        Memory memory = mock(Memory.class);
        MemoryBlock block = block("bank", 0x1000, 0x10ff);
        when(program.getMemory()).thenReturn(memory);
        when(memory.getBlocks()).thenReturn(
            new MemoryBlock[] { block });
        when(block.getBytes(
            any(Address.class), any(byte[].class))).thenReturn(0);
        PatchBytesCore.Request request = new PatchBytesCore.Request(
            "1000", "bank", hex("aa"), null,
            false, false);

        IllegalStateException shortRead = assertThrows(
            IllegalStateException.class,
            () -> new PatchBytesCore().plan(program, request));
        assertEquals(
            "Ghidra read only 0 of 1 bytes",
            shortRead.getMessage());

        PatchBytesCore.Plan plan = new PatchBytesCore.Plan(
            block,
            RAM.getAddress(0x1000),
            RAM.getAddress(0x1000),
            hex("aa"),
            hex("00"),
            ListingClearCore.emptyPlan(),
            true,
            false);
        when(block.putBytes(
            any(Address.class), any(byte[].class))).thenReturn(0);
        IllegalStateException shortWrite = assertThrows(
            IllegalStateException.class,
            () -> new PatchBytesCore().apply(
                emptyProgram(), plan,
                ghidra.util.task.TaskMonitor.DUMMY));
        assertEquals(
            "Ghidra wrote only 0 of 1 bytes",
            shortWrite.getMessage());
    }

    private static MemoryBlock block(
            String name, long startOffset, long endOffset)
            throws Exception {
        MemoryBlock block = mock(MemoryBlock.class);
        Address start = RAM.getAddress(startOffset);
        Address end = RAM.getAddress(endOffset);
        when(block.getName()).thenReturn(name);
        when(block.getStart()).thenReturn(start);
        when(block.getEnd()).thenReturn(end);
        when(block.contains(any(Address.class))).thenAnswer(
            invocation -> {
                Address address = invocation.getArgument(0);
                return address.compareTo(start) >= 0
                    && address.compareTo(end) <= 0;
            });
        when(block.isMapped()).thenReturn(false);
        when(block.getType()).thenReturn(MemoryBlockType.DEFAULT);
        when(block.isInitialized()).thenReturn(true);
        when(block.isWrite()).thenReturn(true);
        return block;
    }

    private static Program emptyProgram() {
        Program program = mock(Program.class);
        when(program.getListing()).thenReturn(
            mock(ghidra.program.model.listing.Listing.class));
        when(program.getFunctionManager()).thenReturn(
            mock(ghidra.program.model.listing.FunctionManager.class));
        when(program.getSymbolTable()).thenReturn(
            mock(ghidra.program.model.symbol.SymbolTable.class));
        when(program.getBookmarkManager()).thenReturn(
            mock(ghidra.program.model.listing.BookmarkManager.class));
        when(program.getReferenceManager()).thenReturn(
            mock(ghidra.program.model.symbol.ReferenceManager.class));
        return program;
    }

    private static byte[] hex(String value) {
        return HexFormat.of().parseHex(value);
    }
}
