package com.xebyte.offline;

import com.xebyte.core.ServiceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for the one shared overlay-ambiguity guard that every mutating
 * address-taking endpoint runs.
 *
 * <p>The fixture is the shape that produced the defect: a 16-bit physical space
 * holding a resident routine, and an overlay block holding the different code
 * that displaced it at runtime. One offset, two occupants — so a mutation aimed
 * at the wrong one silently corrupts the other's analysis.
 *
 * <p>Reads are the deliberate exception: a bare hex address resolves to the
 * physical space and must keep doing so.
 */
public class MutationAddressGuardTest {

    private static final long OVERLAPPED = 0x9762L;
    private static final long UNIQUE = 0x1000L;

    private final GenericAddressSpace ram =
        new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0);
    private final GenericAddressSpace sndPlayer =
        new GenericAddressSpace("SND_PLAYER", 16, AddressSpace.TYPE_RAM, 1);

    private Program program;

    @Before
    public void setUp() {
        // A real overlay space renders its name in Address.toString(); GenericAddressSpace
        // suppresses it for TYPE_RAM, so opt in to match what the caller actually sees.
        sndPlayer.setShowSpaceName(true);

        // Build the blocks before stubbing getBlocks(): stubbing a mock inside an
        // in-progress when(...) leaves Mockito with unfinished stubbing.
        MemoryBlock ramBlock = block(ram, 0x0000, 0xcfff);
        MemoryBlock overlayBlock = block(sndPlayer, 0x9680, 0x98ff);
        MemoryBlock[] blocks = { ramBlock, overlayBlock };

        Memory memory = mock(Memory.class);
        when(memory.getBlocks()).thenReturn(blocks);

        AddressFactory factory = mock(AddressFactory.class);
        when(factory.getAddressSpaces())
            .thenReturn(new AddressSpace[] { ram, sndPlayer });
        when(factory.getDefaultAddressSpace()).thenReturn(ram);
        when(factory.getAddress("9762")).thenReturn(ram.getAddress(OVERLAPPED));
        when(factory.getAddress("1000")).thenReturn(ram.getAddress(UNIQUE));
        when(factory.getAddress("SND_PLAYER:9762"))
            .thenReturn(sndPlayer.getAddress(OVERLAPPED));
        when(factory.getAddress("ram:9762")).thenReturn(ram.getAddress(OVERLAPPED));

        program = mock(Program.class);
        when(program.getMemory()).thenReturn(memory);
        when(program.getAddressFactory()).thenReturn(factory);
    }

    private MemoryBlock block(AddressSpace space, long start, long end) {
        MemoryBlock block = mock(MemoryBlock.class);
        Address from = space.getAddress(start);
        Address to = space.getAddress(end);
        when(block.getStart()).thenReturn(from);
        when(block.getEnd()).thenReturn(to);
        when(block.contains(org.mockito.ArgumentMatchers.any(Address.class)))
            .thenAnswer(invocation -> {
                Address candidate = invocation.getArgument(0);
                return candidate != null
                    && candidate.getAddressSpace() == space
                    && candidate.compareTo(from) >= 0
                    && candidate.compareTo(to) <= 0;
            });
        return block;
    }

    // ------------------------------------------------------------ candidates

    @Test
    public void overlappedOffsetReportsBothOccupants() {
        List<Address> candidates =
            ServiceUtils.mappedCandidatesAtOffset(program, OVERLAPPED);

        assertEquals(2, candidates.size());
        assertSame(ram, candidates.get(0).getAddressSpace());
        assertSame(sndPlayer, candidates.get(1).getAddressSpace());
    }

    @Test
    public void offsetOutsideTheOverlayHasOneOccupant() {
        assertEquals(
            1, ServiceUtils.mappedCandidatesAtOffset(program, UNIQUE).size());
    }

    // ------------------------------------------------------- ambiguity error

    @Test
    public void unqualifiedOverlappedAddressIsRefusedWithTheStandardMessage() {
        String error = ServiceUtils.ambiguousUnqualifiedAddressError(
            program, "9762", ram.getAddress(OVERLAPPED));

        assertNotNull(error);
        assertTrue(error, error.startsWith(
            "Ambiguous unqualified address '9762' "
                + "maps to multiple program address spaces: "));
        assertTrue(error, error.contains("SND_PLAYER"));
        assertTrue(error, error.endsWith(
            ". Use a qualified <space>:<hex> address."));
    }

    @Test
    public void qualifiedAddressInEitherSpaceIsAccepted() {
        assertNull(ServiceUtils.ambiguousUnqualifiedAddressError(
            program, "SND_PLAYER:9762", sndPlayer.getAddress(OVERLAPPED)));
        assertNull(ServiceUtils.ambiguousUnqualifiedAddressError(
            program, "ram:9762", ram.getAddress(OVERLAPPED)));
    }

    @Test
    public void unqualifiedAddressOutsideTheOverlayIsAccepted() {
        assertNull(ServiceUtils.ambiguousUnqualifiedAddressError(
            program, "1000", ram.getAddress(UNIQUE)));
    }

    @Test
    public void aTextThatIsNotAnAddressIsNotAmbiguous() {
        assertNull(ServiceUtils.ambiguousUnqualifiedAddressError(
            program, "sound_player_tick", null));
    }

    // ------------------------------------------------ parseMutationAddress

    @Test
    public void parseMutationAddressRefusesTheAmbiguousOffset() {
        Address resolved = ServiceUtils.parseMutationAddress(program, "9762");

        assertNull(resolved);
        String error = ServiceUtils.getLastParseError();
        assertNotNull(error);
        assertTrue(error, error.contains("Ambiguous unqualified address '9762'"));
        assertTrue(error, error.contains("SND_PLAYER"));
    }

    @Test
    public void parseMutationAddressResolvesAQualifiedOverlayAddress() {
        Address resolved =
            ServiceUtils.parseMutationAddress(program, "SND_PLAYER:9762");

        assertNotNull(resolved);
        assertSame(sndPlayer, resolved.getAddressSpace());
        assertEquals(OVERLAPPED, resolved.getOffset());
    }

    @Test
    public void parseMutationAddressResolvesAnUnambiguousBareOffset() {
        Address resolved = ServiceUtils.parseMutationAddress(program, "1000");

        assertNotNull(resolved);
        assertSame(ram, resolved.getAddressSpace());
        assertNull(ServiceUtils.getLastParseError());
    }

    // ------------------------------------------------------- read convention

    @Test
    public void readsStillResolveABareOverlappedOffsetToThePhysicalSpace() {
        // Deliberate, documented behaviour for read-only endpoints; see
        // docs/superpowers/specs/2026-07-26-references-into-range-design.md,
        // "Bare, unqualified ranges resolve to the physical space".
        Address resolved = ServiceUtils.parseAddress(program, "9762");

        assertNotNull(resolved);
        assertSame(ram, resolved.getAddressSpace());
        assertNull(ServiceUtils.getLastParseError());
    }

    // ----------------------------------------------------------- batch guard

    @Test
    public void batchGuardNamesTheFirstOffendingAddress() {
        String error = ServiceUtils.firstAmbiguousUnqualifiedAddress(
            program, Arrays.asList("1000", "SND_PLAYER:9762", "9762", "1000"));

        assertNotNull(error);
        assertTrue(error, error.contains("'9762'"));
    }

    @Test
    public void batchGuardPassesWhenEveryEntryIsUnambiguous() {
        assertNull(ServiceUtils.firstAmbiguousUnqualifiedAddress(
            program, Arrays.asList("1000", "ram:9762", "SND_PLAYER:9762", null)));
    }

    // ----------------------------------------------------------- name probe

    @Test
    public void probeFlagsAnAmbiguousAddressButLetsANameThrough() {
        assertNotNull(ServiceUtils.probeMutationAddressAmbiguity(program, "9762"));
        assertNull(ServiceUtils.probeMutationAddressAmbiguity(
            program, "sound_player_tick"));
        assertNull(ServiceUtils.probeMutationAddressAmbiguity(program, ""));
        assertNull(ServiceUtils.probeMutationAddressAmbiguity(program, null));
    }

    @Test
    public void probeLeavesTheThreadLocalParseErrorUntouched() {
        assertNull(ServiceUtils.parseAddress(program, "not-an-address"));
        String before = ServiceUtils.getLastParseError();
        assertNotNull(before);

        ServiceUtils.probeMutationAddressAmbiguity(program, "sound_player_tick");

        assertEquals(before, ServiceUtils.getLastParseError());
    }
}
