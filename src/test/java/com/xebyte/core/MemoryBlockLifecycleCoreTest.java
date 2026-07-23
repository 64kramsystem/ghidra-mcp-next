package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class MemoryBlockLifecycleCoreTest {

    @Test
    public void subtypeOrderingIsNullSafeAndNumericallyNatural() {
        Address source = address(0x1000);
        Address target = address(0x2000);
        Address base = address(0x3000);
        var plain = reference(source, target, null, null, null, null);
        var offsetTen = reference(source, target, base, 10L, null, null);
        var offsetTwo = reference(source, target, base, 2L, null, null);
        var shiftedTen = reference(source, target, null, null, 10L, 1);
        var shiftedTwo = reference(source, target, null, null, 2L, 1);
        List<MemoryBlockLifecycleCore.ReferenceRecord> records =
            new ArrayList<>(List.of(
                offsetTen, shiftedTen, offsetTwo, shiftedTwo, plain));

        records.sort(MemoryBlockLifecycleCore.referenceOrder());

        assertEquals(
            List.of(plain, shiftedTwo, shiftedTen, offsetTwo, offsetTen),
            records);
    }

    @Test
    public void exactBlockResolutionRejectsAbsenceAndAmbiguity() {
        Program program = mock(Program.class);
        MemoryBlock first = mock(MemoryBlock.class);
        MemoryBlock second = mock(MemoryBlock.class);
        when(first.getName()).thenReturn("bank");
        when(second.getName()).thenReturn("bank");
        when(program.getMemory()).thenReturn(
            mock(ghidra.program.model.mem.Memory.class));

        when(program.getMemory().getBlocks()).thenReturn(
            new MemoryBlock[] { first });
        assertSame(
            first,
            MemoryBlockLifecycleCore.requireExactBlock(program, "bank"));

        when(program.getMemory().getBlocks()).thenReturn(
            new MemoryBlock[] { first, second });
        IllegalArgumentException ambiguous = assertThrows(
            IllegalArgumentException.class,
            () -> MemoryBlockLifecycleCore.requireExactBlock(
                program, "bank"));
        assertEquals(
            "memory block name is ambiguous: bank",
            ambiguous.getMessage());

        when(program.getMemory().getBlocks()).thenReturn(
            new MemoryBlock[] { first });
        IllegalArgumentException absent = assertThrows(
            IllegalArgumentException.class,
            () -> MemoryBlockLifecycleCore.requireExactBlock(
                program, "missing"));
        assertEquals(
            "memory block not found: missing",
            absent.getMessage());
    }

    @Test
    public void collateralCapAcceptsExactLimitAndRejectsOneMore() {
        MemoryBlockLifecycleCore.rejectCap(
            "symbols", MemoryBlockLifecycleCore.MAX_COLLATERAL);

        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> MemoryBlockLifecycleCore.rejectCap(
                "symbols",
                MemoryBlockLifecycleCore.MAX_COLLATERAL + 1));
        assertEquals(
            "symbols collateral count 65537 exceeds maximum of 65536",
            error.getMessage());
    }

    @Test
    public void imageBaseInsideRemovedTailIsRejected() {
        AddressSpace space = new GenericAddressSpace(
            "RAM", 16, AddressSpace.TYPE_RAM, 0);
        MemoryBlockLifecycleCore.Range tail =
            new MemoryBlockLifecycleCore.Range(
                space.getAddress(0x2002), space.getAddress(0x2003));
        Program program = mock(Program.class);
        when(program.getImageBase()).thenReturn(space.getAddress(0x2002));

        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> MemoryBlockLifecycleCore.rejectImageBaseInRemovedRange(
                program, tail));
        assertEquals(
            "cannot shrink a tail containing the program image base",
            error.getMessage());
    }

    @Test
    public void growthLimitsAcceptExactBoundsAndRejectEitherOverflow() {
        MemoryBlockLifecycleCore.validateGrowthLimits(
            Memory.MAX_BLOCK_SIZE - 1,
            1,
            Memory.MAX_BINARY_SIZE - 1);

        IllegalArgumentException blockError = assertThrows(
            IllegalArgumentException.class,
            () -> MemoryBlockLifecycleCore.validateGrowthLimits(
                Memory.MAX_BLOCK_SIZE, 1, 1));
        assertEquals(
            "result exceeds Memory.MAX_BLOCK_SIZE",
            blockError.getMessage());

        IllegalArgumentException binaryError = assertThrows(
            IllegalArgumentException.class,
            () -> MemoryBlockLifecycleCore.validateGrowthLimits(
                1, 1, Memory.MAX_BINARY_SIZE));
        assertEquals(
            "result exceeds Memory.MAX_BINARY_SIZE",
            binaryError.getMessage());
    }

    @Test
    public void eitherDelaySlotBoundaryIsRejected() {
        Address rootStart = RAM.getAddress(0x4000);
        Address rootEnd = RAM.getAddress(0x4001);
        Address slotStart = RAM.getAddress(0x4002);
        Address slotEnd = RAM.getAddress(0x4003);
        Instruction root = instruction(rootStart, rootEnd);
        Instruction slot = instruction(slotStart, slotEnd);
        when(root.getDelaySlotDepth()).thenReturn(1);
        when(root.getNext()).thenReturn(slot);
        when(slot.isInDelaySlot()).thenReturn(true);
        Listing listing = mock(Listing.class);
        Program program = mock(Program.class);
        when(program.getListing()).thenReturn(listing);

        when(listing.getCodeUnitContaining(rootStart)).thenReturn(root);
        when(listing.getCodeUnitContaining(rootEnd)).thenReturn(root);
        when(listing.getInstructionAt(rootStart)).thenReturn(root);
        InstructionIterator rootInstructions = instructions(List.of(root));
        when(listing.getInstructions(any(AddressSetView.class), eq(true)))
            .thenReturn(rootInstructions);
        assertThrows(
            IllegalArgumentException.class,
            () -> MemoryBlockLifecycleCore.validateListingBoundary(
                program,
                new MemoryBlockLifecycleCore.Range(rootStart, rootEnd)));

        when(listing.getCodeUnitContaining(slotStart)).thenReturn(slot);
        when(listing.getCodeUnitContaining(slotEnd)).thenReturn(slot);
        when(listing.getInstructionAt(slotStart)).thenReturn(slot);
        assertThrows(
            IllegalArgumentException.class,
            () -> MemoryBlockLifecycleCore.validateListingBoundary(
                program,
                new MemoryBlockLifecycleCore.Range(slotStart, slotEnd)));
    }

    private static MemoryBlockLifecycleCore.ReferenceRecord reference(
            Address source,
            Address target,
            Address offsetBase,
            Long signedOffset,
            Long shiftedBase,
            Integer shift) {
        return new MemoryBlockLifecycleCore.ReferenceRecord(
            null, source, target, "DATA", "USER_DEFINED", 0, false,
            -1, -1, false, null, "RAM", "target", "RAM",
            offsetBase, signedOffset, shiftedBase, shift, "keep");
    }

    private static Address address(long offset) {
        Address address = mock(Address.class);
        when(address.compareTo(org.mockito.ArgumentMatchers.any()))
            .thenAnswer(invocation -> Long.compare(
                offset,
                invocation.<Address>getArgument(0).getOffset()));
        when(address.getOffset()).thenReturn(offset);
        return address;
    }

    private static Instruction instruction(Address start, Address end) {
        Instruction instruction = mock(Instruction.class);
        when(instruction.getMinAddress()).thenReturn(start);
        when(instruction.getMaxAddress()).thenReturn(end);
        return instruction;
    }

    private static InstructionIterator instructions(
            List<Instruction> values) {
        Iterator<Instruction> iterator = values.iterator();
        InstructionIterator result = mock(InstructionIterator.class);
        when(result.iterator()).thenReturn(iterator);
        return result;
    }

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0);
}
