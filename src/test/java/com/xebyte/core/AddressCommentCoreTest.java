package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

public class AddressCommentCoreTest {

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0);
    private static final GenericAddressSpace EXTERNAL =
        new GenericAddressSpace(
            "EXTERNAL", 32, AddressSpace.TYPE_EXTERNAL, 1);

    private Program program;
    private Listing listing;
    private Memory memory;
    private AddressFactory addressFactory;
    private Address address;
    private AddressCommentCore core;

    @Before
    public void setUp() {
        program = mock(Program.class);
        listing = mock(Listing.class);
        memory = mock(Memory.class);
        addressFactory = mock(AddressFactory.class);
        address = RAM.getAddress(0x1000);
        when(program.getListing()).thenReturn(listing);
        when(program.getMemory()).thenReturn(memory);
        when(program.getAddressFactory()).thenReturn(addressFactory);
        when(addressFactory.getAddressSpace("ram")).thenReturn(RAM);
        when(memory.contains(address)).thenReturn(true);
        core = new AddressCommentCore();
    }

    @Test
    public void replacePlanCapturesReadBeforeWriteState() {
        when(listing.getComment(CommentType.PLATE, address))
            .thenReturn("before");

        AddressCommentCore.Plan plan = core.plan(
            program,
            address,
            CommentType.PLATE,
            "after",
            AddressCommentCore.WriteMode.REPLACE);

        assertEquals(address, plan.address());
        assertEquals(CommentType.PLATE, plan.type());
        assertEquals("before", plan.previous());
        assertEquals("after", plan.requested());
        assertEquals("after", plan.resulting());
        assertTrue(plan.changed());
        verify(listing).getComment(CommentType.PLATE, address);
        verify(listing, never()).setComment(
            address, CommentType.PLATE, "after");
    }

    @Test
    public void applyWritesOnlyChangedPlans() {
        AddressCommentCore.Plan changed = core.plan(
            program,
            address,
            CommentType.PLATE,
            "after",
            AddressCommentCore.WriteMode.REPLACE);

        core.apply(program, changed);

        verify(listing).setComment(
            address, CommentType.PLATE, "after");
    }

    @Test
    public void repeatedReplaceIsNoOp() {
        when(listing.getComment(CommentType.PLATE, address))
            .thenReturn("same");
        AddressCommentCore.Plan plan = core.plan(
            program,
            address,
            CommentType.PLATE,
            "same",
            AddressCommentCore.WriteMode.REPLACE);

        core.apply(program, plan);

        assertFalse(plan.changed());
        verify(listing, never()).setComment(
            address, CommentType.PLATE, "same");
    }

    @Test
    public void removePlanUsesNullResult() {
        when(listing.getComment(CommentType.PLATE, address))
            .thenReturn("before");

        AddressCommentCore.Plan plan = core.plan(
            program,
            address,
            CommentType.PLATE,
            "",
            AddressCommentCore.WriteMode.REMOVE);
        core.apply(program, plan);

        assertEquals("before", plan.previous());
        assertNull(plan.resulting());
        assertTrue(plan.changed());
        verify(listing).setComment(
            address, CommentType.PLATE, null);
    }

    @Test
    public void appendIdempotentAddsOnlyMissingExactLine() {
        when(listing.getComment(CommentType.EOL, address))
            .thenReturn("first\nsecond", "first\nsecond");

        AddressCommentCore.Plan repeated = core.plan(
            program,
            address,
            CommentType.EOL,
            "second",
            AddressCommentCore.WriteMode.APPEND_IDEMPOTENT);
        AddressCommentCore.Plan appended = core.plan(
            program,
            address,
            CommentType.EOL,
            "third",
            AddressCommentCore.WriteMode.APPEND_IDEMPOTENT);

        assertEquals("first\nsecond", repeated.resulting());
        assertFalse(repeated.changed());
        assertEquals("first\nsecond\nthird", appended.resulting());
        assertTrue(appended.changed());
    }

    @Test
    public void unmappedAndExternalAddressesAreRejectedBeforeListingRead() {
        Address unmapped = RAM.getAddress(0x2000);
        when(memory.contains(unmapped)).thenReturn(false);
        Address external = EXTERNAL.getAddress(0x10);
        when(memory.contains(external)).thenReturn(true);

        IllegalArgumentException unmappedError =
            assertThrows(IllegalArgumentException.class, () -> core.plan(
                program,
                unmapped,
                CommentType.PLATE,
                "text",
                AddressCommentCore.WriteMode.REPLACE));
        IllegalArgumentException externalError =
            assertThrows(IllegalArgumentException.class, () -> core.plan(
                program,
                external,
                CommentType.PLATE,
                "text",
                AddressCommentCore.WriteMode.REPLACE));

        assertTrue(
            unmappedError.getMessage().toLowerCase().contains("mapped"));
        assertTrue(
            externalError.getMessage().toLowerCase().contains("external"));
        verify(listing, never()).getComment(CommentType.PLATE, unmapped);
        verify(listing, never()).getComment(CommentType.PLATE, external);
    }

    @Test
    public void foreignAddressSpaceWithSameNameAndOffsetIsRejected() {
        GenericAddressSpace foreignRam =
            new GenericAddressSpace(
                "ram", 16, AddressSpace.TYPE_RAM, 7);
        Address foreignAddress = foreignRam.getAddress(0x1000);
        when(memory.contains(foreignAddress)).thenReturn(true);

        IllegalArgumentException error =
            assertThrows(IllegalArgumentException.class, () -> core.plan(
                program,
                foreignAddress,
                CommentType.PLATE,
                "text",
                AddressCommentCore.WriteMode.REPLACE));

        assertTrue(
            error.getMessage().toLowerCase().contains("target program"));
        verify(listing, never()).getComment(
            CommentType.PLATE, foreignAddress);
    }

    @Test
    public void nullCommentTypeTextAndModeAreRejected() {
        assertThrows(NullPointerException.class, () -> core.plan(
            program,
            address,
            null,
            "text",
            AddressCommentCore.WriteMode.REPLACE));
        assertThrows(NullPointerException.class, () -> core.plan(
            program,
            address,
            CommentType.PLATE,
            null,
            AddressCommentCore.WriteMode.REPLACE));
        assertThrows(NullPointerException.class, () -> core.plan(
            program,
            address,
            CommentType.PLATE,
            "text",
            null));
    }
}
