package com.xebyte.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class PatchBytesCoreTest {

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace(
            "ram", 16, AddressSpace.TYPE_RAM, 0);
    private static final GenericAddressSpace WIDE_RAM =
        new GenericAddressSpace(
            "wide", 32, AddressSpace.TYPE_RAM, 0);

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

        byte[] maximumDryRun =
            new byte[PatchBytesCore.MAX_PAYLOAD_BYTES];
        maximumDryRun[0] = (byte) 0xaa;
        maximumDryRun[maximumDryRun.length - 1] = (byte) 0x55;
        PatchBytesCore.PayloadSummary maximumSummary =
            PatchBytesCore.summarize(
                maximumDryRun, maximumDryRun, true);
        assertEquals(
            PatchBytesCore.MAX_PAYLOAD_BYTES * 2,
            maximumSummary.previous().length());
        assertTrue(maximumSummary.previous().startsWith("aa"));
        assertTrue(maximumSummary.previous().endsWith("55"));
    }

    @Test
    public void responseShapeOrderingAndLargeDigestsAreExact()
            throws Exception {
        MemoryBlock block = block("bank", 0x1000, 0xffff);
        byte[] previous = hex("0102");
        byte[] written = hex("aabb");
        ListingClearCore.AnnotationSnapshot empty =
            new ListingClearCore.AnnotationSnapshot(
                List.of(), List.of(), List.of(), List.of());
        ListingClearCore.Plan clearPlan =
            new ListingClearCore.Plan(
                new AddressSet(
                    RAM.getAddress(0x1000),
                    RAM.getAddress(0x1002)),
                List.of(
                    new ListingClearCore.CodeUnitSnapshot(
                        RAM.getAddress(0x1002),
                        RAM.getAddress(0x1002),
                        ListingClearCore.UnitKind.DATA),
                    new ListingClearCore.CodeUnitSnapshot(
                        RAM.getAddress(0x1000),
                        RAM.getAddress(0x1001),
                        ListingClearCore.UnitKind.INSTRUCTION)),
                List.of(
                    new ListingClearCore.FunctionSnapshot(
                        RAM.getAddress(0x1020), "later"),
                    new ListingClearCore.FunctionSnapshot(
                        RAM.getAddress(0x1010), "earlier")),
                empty,
                empty,
                Map.of(),
                new ListingClearCore.RemovalCounts(1, 1, 2),
                List.of());
        PatchBytesCore.Plan small = new PatchBytesCore.Plan(
            block,
            RAM.getAddress(0x1000),
            RAM.getAddress(0x1001),
            written,
            previous,
            clearPlan,
            false,
            true);

        JsonObject dry =
            MemoryBlockService.patchResult(small, true, false);
        assertEquals(
            Set.of(
                "success", "address", "address_space", "length",
                "block", "cleared_code_units", "removed_functions",
                "original_write", "temporary_write_enabled",
                "dry_run", "committed", "previous", "written"),
            dry.keySet());
        assertEquals(
            List.of(
                "success", "address", "address_space", "length",
                "block", "cleared_code_units", "removed_functions",
                "original_write", "temporary_write_enabled",
                "dry_run", "committed", "previous", "written"),
            List.copyOf(dry.keySet()));
        assertEquals("0102", dry.get("previous").getAsString());
        assertEquals("aabb", dry.get("written").getAsString());
        JsonArray units = dry.getAsJsonArray("cleared_code_units");
        assertEquals("1000",
            units.get(0).getAsJsonObject().get("start").getAsString());
        assertEquals("instruction",
            units.get(0).getAsJsonObject().get("kind").getAsString());
        assertEquals("1002",
            units.get(1).getAsJsonObject().get("start").getAsString());
        JsonArray functions = dry.getAsJsonArray("removed_functions");
        assertEquals("earlier",
            functions.get(0).getAsJsonObject().get("name").getAsString());
        assertEquals("later",
            functions.get(1).getAsJsonObject().get("name").getAsString());
        assertEquals(
            "{\"success\":true,\"address\":\"1000\","
                + "\"address_space\":\"ram\",\"length\":2,"
                + "\"block\":\"bank\",\"cleared_code_units\":["
                + "{\"kind\":\"instruction\",\"start\":\"1000\","
                + "\"end\":\"1001\",\"length\":2},"
                + "{\"kind\":\"data\",\"start\":\"1002\","
                + "\"end\":\"1002\",\"length\":1}],"
                + "\"removed_functions\":["
                + "{\"entry\":\"1010\",\"name\":\"earlier\"},"
                + "{\"entry\":\"1020\",\"name\":\"later\"}],"
                + "\"original_write\":false,"
                + "\"temporary_write_enabled\":true,"
                + "\"dry_run\":true,\"committed\":false,"
                + "\"previous\":\"0102\",\"written\":\"aabb\"}",
            dry.toString());

        byte[] large =
            new byte[PatchBytesCore.FULL_HEX_LIMIT + 1];
        large[0] = 1;
        large[large.length - 1] = 2;
        PatchBytesCore.Plan committed = new PatchBytesCore.Plan(
            block,
            RAM.getAddress(0),
            RAM.getMaxAddress(),
            large,
            large,
            ListingClearCore.emptyPlan(),
            true,
            false);
        JsonObject compact =
            MemoryBlockService.patchResult(
                committed, false, true);
        assertEquals(
            Set.of(
                "success", "address", "address_space", "length",
                "block", "cleared_code_units", "removed_functions",
                "original_write", "temporary_write_enabled",
                "dry_run", "committed",
                "previous_sha256", "written_sha256",
                "previous_first", "previous_last",
                "written_first", "written_last"),
            compact.keySet());
        assertFalse(compact.has("previous"));
        assertFalse(compact.has("written"));
        assertEquals(
            MemoryBlockCore.sha256(large),
            compact.get("previous_sha256").getAsString());
        assertEquals(
            MemoryBlockCore.sha256(large),
            compact.get("written_sha256").getAsString());
        assertEquals(
            "01" + "00".repeat(31),
            compact.get("previous_first").getAsString());
        assertEquals(
            "00".repeat(31) + "02",
            compact.get("previous_last").getAsString());

        byte[] maximum =
            new byte[PatchBytesCore.MAX_PAYLOAD_BYTES];
        maximum[0] = (byte) 0xa5;
        maximum[maximum.length - 1] = 0x5a;
        PatchBytesCore.Plan maximumPreview =
            new PatchBytesCore.Plan(
                block,
                WIDE_RAM.getAddress(0x100000),
                WIDE_RAM.getAddress(
                    0x100000L + maximum.length - 1L),
                maximum,
                maximum,
                ListingClearCore.emptyPlan(),
                true,
                false);
        JsonObject maximumDry =
            MemoryBlockService.patchResult(
                maximumPreview, true, false);
        assertEquals(
            PatchBytesCore.MAX_PAYLOAD_BYTES * 2,
            maximumDry.get("previous").getAsString().length());
        assertEquals(
            PatchBytesCore.MAX_PAYLOAD_BYTES * 2,
            maximumDry.get("written").getAsString().length());
        assertFalse(maximumDry.has("previous_sha256"));
        assertTrue(maximumDry.get("previous").getAsString()
            .startsWith("a5"));
        assertTrue(maximumDry.get("previous").getAsString()
            .endsWith("5a"));
    }

    @Test
    public void suppliedBlankBlockNameIsNeverTreatedAsOmitted()
            throws Exception {
        Program program = mock(Program.class);
        Memory memory = mock(Memory.class);
        when(program.getMemory()).thenReturn(memory);
        MemoryBlock ordinary = block("ordinary", 0x8000, 0x80ff);
        MemoryBlock overlay = block("overlay", 0x8000, 0x80ff);
        when(memory.getBlocks()).thenReturn(
            new MemoryBlock[] { ordinary, overlay });

        for (String supplied : new String[] { "", " ", "\n\t" }) {
            PatchBytesCore.Request request = new PatchBytesCore.Request(
                "8000", supplied, hex("01"), null,
                true, false);
            IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> new PatchBytesCore().plan(program, request));
            assertEquals("block must not be blank", error.getMessage());
        }
        verify(memory, never()).getBlock(any(Address.class));
        verify(ordinary, never()).getBytes(
            any(Address.class), any(byte[].class));
        verify(overlay, never()).getBytes(
            any(Address.class), any(byte[].class));
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

    @Test
    public void shortAndMismatchedReadbackAreHardFailures()
            throws Exception {
        Program program = emptyProgram();
        MemoryBlock block = block("bank", 0x1000, 0x10ff);
        PatchBytesCore.Plan plan =
            plan(block, hex("aa"), true, false);
        when(block.putBytes(
            any(Address.class), any(byte[].class))).thenReturn(1);
        when(block.getBytes(
            any(Address.class), any(byte[].class))).thenReturn(0);

        IllegalStateException shortReadback = assertThrows(
            IllegalStateException.class,
            () -> new PatchBytesCore().apply(
                program, plan, TaskMonitor.DUMMY));
        assertEquals(
            "Ghidra read only 0 of 1 bytes",
            shortReadback.getMessage());

        doAnswer(invocation -> {
            byte[] destination = invocation.getArgument(1);
            destination[0] = 0x55;
            return 1;
        }).when(block).getBytes(
            any(Address.class), any(byte[].class));
        IllegalStateException mismatch = assertThrows(
            IllegalStateException.class,
            () -> new PatchBytesCore().apply(
                program, plan, TaskMonitor.DUMMY));
        assertEquals(
            "readback mismatch at offset 0: expected aa, actual 55",
            mismatch.getMessage());
    }

    @Test
    public void temporaryPermissionEnableAndRestoreFailuresAreFatal()
            throws Exception {
        Program program = emptyProgram();
        MemoryBlock enableFailure =
            block("readonly_enable", 0x1000, 0x10ff);
        when(enableFailure.isWrite()).thenReturn(false);
        doAnswer(invocation -> {
            if (invocation.getArgument(0, Boolean.class)) {
                throw new IllegalStateException("enable failed");
            }
            return null;
        }).when(enableFailure).setWrite(any(Boolean.class));
        IllegalStateException enableError = assertThrows(
            IllegalStateException.class,
            () -> new PatchBytesCore().apply(
                program,
                plan(enableFailure, hex("aa"), false, true),
                TaskMonitor.DUMMY));
        assertEquals("enable failed", enableError.getMessage());
        verify(enableFailure).setWrite(false);
        verify(enableFailure, never()).putBytes(
            any(Address.class), any(byte[].class));

        MemoryBlock restoreFailure =
            block("readonly_restore", 0x1000, 0x10ff);
        AtomicBoolean writable = new AtomicBoolean(false);
        when(restoreFailure.isWrite()).thenAnswer(
            invocation -> writable.get());
        doAnswer(invocation -> {
            boolean value =
                invocation.getArgument(0, Boolean.class);
            if (!value) {
                throw new IllegalStateException("restore failed");
            }
            writable.set(true);
            return null;
        }).when(restoreFailure).setWrite(any(Boolean.class));
        when(restoreFailure.putBytes(
            any(Address.class), any(byte[].class))).thenReturn(1);

        IllegalStateException restoreError = assertThrows(
            IllegalStateException.class,
            () -> new PatchBytesCore().apply(
                program,
                plan(restoreFailure, hex("aa"), false, true),
                TaskMonitor.DUMMY));
        assertEquals(
            "failed to restore original write permission",
            restoreError.getMessage());
        assertTrue(writable.get());
    }

    @Test
    public void cancellationPropagatesDuringClearVerifyAndAroundIo()
            throws Exception {
        Program program = emptyProgram();
        MemoryBlock block = block("bank", 0x1000, 0x10ff);
        when(block.putBytes(
            any(Address.class), any(byte[].class))).thenReturn(1);
        doAnswer(invocation -> {
            byte[] destination = invocation.getArgument(1);
            destination[0] = (byte) 0xaa;
            return 1;
        }).when(block).getBytes(
            any(Address.class), any(byte[].class));
        PatchBytesCore.Plan plan =
            plan(block, hex("aa"), true, false);

        FaultClearCore applyCancellation =
            new FaultClearCore(FaultPoint.APPLY);
        assertThrows(
            CancelledException.class,
            () -> new PatchBytesCore(applyCancellation).apply(
                program, plan, new TaskMonitorAdapter()));

        FaultClearCore verifyCancellation =
            new FaultClearCore(FaultPoint.VERIFY);
        assertThrows(
            CancelledException.class,
            () -> new PatchBytesCore(verifyCancellation).apply(
                program, plan, new TaskMonitorAdapter()));

        TaskMonitorAdapter beforeWrite = new TaskMonitorAdapter();
        beforeWrite.setCancelEnabled(true);
        FaultClearCore cancelBeforeWrite =
            new FaultClearCore(FaultPoint.NONE) {
                @Override
                void apply(
                        Program selected,
                        ListingClearCore.Plan clearPlan,
                        TaskMonitor monitor) {
                    beforeWrite.cancel();
                }
            };
        assertThrows(
            CancelledException.class,
            () -> new PatchBytesCore(cancelBeforeWrite).apply(
                program, plan, beforeWrite));

        TaskMonitorAdapter afterWrite = new TaskMonitorAdapter();
        afterWrite.setCancelEnabled(true);
        doAnswer(invocation -> {
            afterWrite.cancel();
            return 1;
        }).when(block).putBytes(
            any(Address.class), any(byte[].class));
        assertThrows(
            CancelledException.class,
            () -> new PatchBytesCore(
                new FaultClearCore(FaultPoint.NONE)).apply(
                    program, plan, afterWrite));

        TaskMonitorAdapter afterReadback = new TaskMonitorAdapter();
        afterReadback.setCancelEnabled(true);
        when(block.putBytes(
            any(Address.class), any(byte[].class))).thenReturn(1);
        doAnswer(invocation -> {
            byte[] destination = invocation.getArgument(1);
            destination[0] = (byte) 0xaa;
            afterReadback.cancel();
            return 1;
        }).when(block).getBytes(
            any(Address.class), any(byte[].class));
        assertThrows(
            CancelledException.class,
            () -> new PatchBytesCore(
                new FaultClearCore(FaultPoint.NONE)).apply(
                    program, plan, afterReadback));
    }

    private enum FaultPoint {
        NONE,
        APPLY,
        VERIFY
    }

    private static class FaultClearCore extends ListingClearCore {
        private final FaultPoint fault;

        FaultClearCore(FaultPoint fault) {
            this.fault = fault;
        }

        @Override
        void apply(
                Program program, ListingClearCore.Plan plan,
                TaskMonitor monitor) throws Exception {
            if (fault == FaultPoint.APPLY) {
                throw new CancelledException();
            }
        }

        @Override
        void verify(
                Program program, ListingClearCore.Plan plan,
                TaskMonitor monitor) throws Exception {
            if (fault == FaultPoint.VERIFY) {
                throw new CancelledException();
            }
        }
    }

    private static PatchBytesCore.Plan plan(
            MemoryBlock block, byte[] payload,
            boolean originalWrite, boolean temporaryWrite) {
        return new PatchBytesCore.Plan(
            block,
            RAM.getAddress(0x1000),
            RAM.getAddress(0x1000 + payload.length - 1L),
            payload,
            new byte[payload.length],
            ListingClearCore.emptyPlan(),
            originalWrite,
            temporaryWrite);
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
