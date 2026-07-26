package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;

/**
 * The assembly logic inside {@code XrefCallGraphService.render}: mnemonic and operand joining,
 * picking the primitive inside an aggregate, and the fallbacks.
 *
 * <p>Driven through the {@code OperandRenderer} seam, so no Ghidra installation is needed. What
 * this cannot show is Ghidra's own formatting behaviour — whether {@code CodeUnitFormat} resolves
 * an operand into an overlay space at all. That is covered by {@link XrefRangeRenderGhidraTest},
 * against a real program, because it was a live run and not a mock that caught it going wrong.</p>
 */
public class XrefRangeRenderLogicTest {

    private final GenericAddressSpace ram =
        new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0);

    private Address ramAddr(long offset) {
        return ram.getAddress(offset);
    }


    /*
     * These drive XrefCallGraphService.render through its OperandRenderer seam. The
     * end-to-end tests above cannot: their code units are Mockito mocks whose
     * getMnemonicString() returns null, so they only ever exercise the toString() fallback,
     * which is how a cross-space rendering regression reached a live run unnoticed.
     *
     * What the seam does NOT cover is Ghidra's own behaviour — whether CodeUnitFormat
     * resolves an operand into an overlay space at all. That is not this code's logic and
     * only a real program can show it; it is recorded in the spec against the live run.
     */

    private static CodeUnit unitWithMnemonic(String mnemonic, Address start) {
        CodeUnit unit = mock(CodeUnit.class);
        when(unit.getMnemonicString()).thenReturn(mnemonic);
        when(unit.getMinAddress()).thenReturn(start);
        return unit;
    }

    @Test
    public void renderJoinsMnemonicAndEveryOperand() {
        Instruction instruction = mock(Instruction.class);
        when(instruction.getMnemonicString()).thenReturn("STA");
        when(instruction.getMinAddress()).thenReturn(ramAddr(0x0733));
        when(instruction.getNumOperands()).thenReturn(2);

        String rendered = XrefCallGraphService.render(
            (unit, index) -> index == 0 ? "LOAD_NEXT_GAME_PART" : "Y",
            instruction, ramAddr(0x0733));

        // Space after the mnemonic, comma between operands, no trailing separator.
        assertEquals("STA LOAD_NEXT_GAME_PART,Y", rendered);
    }

    @Test
    public void renderEmitsBareMnemonicForAnOperandlessInstruction() {
        Instruction instruction = mock(Instruction.class);
        when(instruction.getMnemonicString()).thenReturn("RTS");
        when(instruction.getMinAddress()).thenReturn(ramAddr(0x0761));
        when(instruction.getNumOperands()).thenReturn(0);

        assertEquals("RTS", XrefCallGraphService.render(
            (unit, index) -> { throw new AssertionError("must not ask for an operand"); },
            instruction, ramAddr(0x0761)));
    }

    @Test
    public void renderPrefersThePrimitiveAtTheSourceOffsetInsideAnAggregate() {
        // A dispatch-table entry: the array renders as "dw[15]" and names no slot, so the
        // row has to show the element that actually holds the in-range address.
        Data slot = mock(Data.class);
        when(slot.getMnemonicString()).thenReturn("dw");
        Data table = mock(Data.class);
        when(table.getMnemonicString()).thenReturn("dw[15]");
        when(table.getMinAddress()).thenReturn(ramAddr(0x9913));
        when(table.getPrimitiveAt(4)).thenReturn(slot);

        String rendered = XrefCallGraphService.render(
            (unit, index) -> unit == slot ? "96A1h" : "should have used the slot",
            table, ramAddr(0x9917));

        assertEquals("dw 96A1h", rendered);
    }

    @Test
    public void renderFallsBackToTheWholeAggregateWhenThereIsNoPrimitive() {
        Data table = mock(Data.class);
        when(table.getMnemonicString()).thenReturn("dw[15]");
        when(table.getMinAddress()).thenReturn(ramAddr(0x9913));
        when(table.getPrimitiveAt(anyInt())).thenReturn(null);

        assertEquals("dw[15] 9897h", XrefCallGraphService.render(
            (unit, index) -> "9897h", table, ramAddr(0x9917)));
    }

    @Test
    public void renderUsesTheDefaultValueWhenTheFormatterYieldsNothing() {
        Data data = mock(Data.class);
        when(data.getMnemonicString()).thenReturn("dw");
        when(data.getMinAddress()).thenReturn(ramAddr(0x9913));
        when(data.getDefaultValueRepresentation()).thenReturn("9897h");

        assertEquals("dw 9897h",
            XrefCallGraphService.render((unit, index) -> "  ", data, ramAddr(0x9913)));
    }

    @Test
    public void renderFallsBackToToStringWithoutAMnemonic() {
        CodeUnit unit = mock(CodeUnit.class);
        when(unit.getMnemonicString()).thenReturn(null);
        when(unit.toString()).thenReturn("?? 00");

        assertEquals("?? 00", XrefCallGraphService.render(
            (u, index) -> { throw new AssertionError("must not format without a mnemonic"); },
            unit, ramAddr(0x1000)));
    }

    @Test
    public void renderLeavesANonAggregateUnitAlone() {
        // Neither Instruction nor Data: mnemonic only, and no operand lookup.
        CodeUnit unit = unitWithMnemonic("align", ramAddr(0x9a8b));
        assertEquals("align", XrefCallGraphService.render(
            (u, index) -> { throw new AssertionError("must not ask for an operand"); },
            unit, ramAddr(0x9a8b)));
    }
}
