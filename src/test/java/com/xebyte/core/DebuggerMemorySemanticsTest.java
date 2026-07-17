package com.xebyte.core;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyByte;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
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

    public void testRequireContainingRegionNeedsExactlyOneCompleteMatch() {
        AddressRange source = range(0x1100, 0x11ff);
        var containing = new DebuggerMemorySemantics.RegionRange<>(
                "containing", range(0x1000, 0x1fff));
        var partial = new DebuggerMemorySemantics.RegionRange<>(
                "partial", range(0x1180, 0x2000));

        assertEquals("containing", DebuggerMemorySemantics.requireContainingRegionRange(
                List.of(partial, containing), source));
        assertInvalid(() -> DebuggerMemorySemantics.requireContainingRegionRange(
                List.of(partial), source));
        assertInvalid(() -> DebuggerMemorySemantics.requireContainingRegionRange(
                List.of(containing, new DebuggerMemorySemantics.RegionRange<>(
                        "second", range(0x1000, 0x1200))), source));
    }

    public void testRequireKnownRejectsUnknownFirstMiddleAndLastBytes() {
        AddressRange source = range(0x1000, 0x100f);
        for (long unknown : List.of(0x1000L, 0x1008L, 0x100fL)) {
            AddressSet known = new AddressSet(source);
            known.delete(space.getAddress(unknown), space.getAddress(unknown));

            assertInvalid(() -> DebuggerMemorySemantics.requireKnown(known, source));
        }
    }

    public void testRequireKnownAcceptsCompleteRange() {
        AddressRange source = range(0x1000, 0x100f);
        DebuggerMemorySemantics.requireKnown(new AddressSet(source), source);
    }

    public void testRequireDestinationFreeRejectsAnyOverlap() {
        AddressRange destination = range(0x2000, 0x20ff);
        Memory free = mock(Memory.class);
        when(free.intersect(any(AddressSetView.class))).thenReturn(new AddressSet());
        DebuggerMemorySemantics.requireDestinationFree(free, destination);

        Memory occupied = mock(Memory.class);
        when(occupied.intersect(any(AddressSetView.class)))
                .thenReturn(new AddressSet(space.getAddress(0x2080), space.getAddress(0x2080)));
        assertInvalid(() -> DebuggerMemorySemantics.requireDestinationFree(
                occupied, destination));
    }

    public void testProgramBlockWriterCommitsPopulatedBlockWithPermissions()
            throws Exception {
        Program program = mock(Program.class);
        Memory memory = mock(Memory.class);
        MemoryBlock block = mock(MemoryBlock.class);
        var start = space.getAddress(0x4000);
        byte[] first = {1, 2};
        byte[] second = {3, 4, 5};
        when(program.getMemory()).thenReturn(memory);
        when(program.startTransaction("Copy debugger memory")).thenReturn(17);
        when(memory.createInitializedBlock(eq("runtime"), eq(start), eq(5L),
                anyByte(), eq(TaskMonitor.DUMMY), eq(false))).thenReturn(block);
        when(block.putBytes(any(), any())).thenAnswer(invocation ->
                ((byte[]) invocation.getArgument(1)).length);

        MemoryBlock result = DebuggerMemorySemantics.programBlockWriter(TaskMonitor.DUMMY)
                .create(program, "runtime", start, 5, true, false, true,
                        List.of(first, second));

        assertSame(block, result);
        verify(memory).createInitializedBlock("runtime", start, 5, (byte) 0,
                TaskMonitor.DUMMY, false);
        verify(block).putBytes(start, first);
        verify(block).putBytes(start.add(2), second);
        verify(block).setRead(true);
        verify(block).setWrite(false);
        verify(block).setExecute(true);
        verify(program).endTransaction(17, true);
    }

    public void testProgramBlockWriterRollsBackCreateWriteAndPermissionFailures()
            throws Exception {
        assertWriterRollsBack(FailureStage.CREATE);
        assertWriterRollsBack(FailureStage.WRITE);
        assertWriterRollsBack(FailureStage.PERMISSION);
    }

    private enum FailureStage { CREATE, WRITE, PERMISSION }

    private void assertWriterRollsBack(FailureStage failureStage) throws Exception {
        Program program = mock(Program.class);
        Memory memory = mock(Memory.class);
        MemoryBlock block = mock(MemoryBlock.class);
        var start = space.getAddress(0x5000);
        when(program.getMemory()).thenReturn(memory);
        when(program.startTransaction("Copy debugger memory")).thenReturn(23);
        if (failureStage == FailureStage.CREATE) {
            when(memory.createInitializedBlock(any(), any(), anyLong(), anyByte(),
                    any(), eq(false))).thenThrow(new IllegalStateException("create"));
        } else {
            when(memory.createInitializedBlock(any(), any(), anyLong(), anyByte(),
                    any(), eq(false))).thenReturn(block);
            if (failureStage == FailureStage.WRITE) {
                when(block.putBytes(any(), any()))
                        .thenThrow(new IllegalStateException("write"));
            } else {
                when(block.putBytes(any(), any())).thenReturn(1);
                doThrow(new IllegalStateException("permission"))
                        .when(block).setExecute(true);
            }
        }

        try {
            DebuggerMemorySemantics.programBlockWriter(TaskMonitor.DUMMY)
                    .create(program, "runtime", start, 1, true, false, true,
                            List.of(new byte[] {1}));
            fail("Expected writer failure");
        } catch (IllegalStateException expected) {
            assertEquals(failureStage.name().toLowerCase(), expected.getMessage());
        }
        verify(program).endTransaction(23, false);
        verify(program, never()).endTransaction(23, true);
    }

    private final GenericAddressSpace space = new GenericAddressSpace(
            "ram", 64, AddressSpace.TYPE_RAM, 0);

    private AddressRange range(long start, long end) {
        return new AddressRangeImpl(space.getAddress(start), space.getAddress(end));
    }

    private void assertInvalid(Runnable action) {
        try {
            action.run();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // expected
        }
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
