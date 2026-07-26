package com.xebyte.offline;

import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ServiceUtils;
import com.xebyte.core.XrefCallGraphService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Offline coverage for get_references_into_range.
 *
 * <p>The endpoint exists to disambiguate two occupants of the same 16-bit
 * addresses, so the fixtures here deliberately include an overlay whose *block*
 * covers only part of the shadowed space: an overlay address space spans the
 * full range of the space it shadows, which is why overlap must be computed from
 * blocks rather than space bounds.</p>
 */
public class ReferencesIntoRangeTest {

    // ---------------------------------------------------------------- fixture

    private final GenericAddressSpace ram =
        new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0);

    private Address ramAddr(long offset) {
        return ram.getAddress(offset);
    }

    /** An overlay space reporting `ram` as its physical root, as Ghidra does. */
    private AddressSpace overlaySpace(String name) {
        AddressSpace space = mock(AddressSpace.class);
        when(space.isOverlaySpace()).thenReturn(true);
        when(space.getName()).thenReturn(name);
        when(space.getPhysicalSpace()).thenReturn(ram);
        when(space.getType()).thenReturn(AddressSpace.TYPE_RAM);
        return space;
    }

    /** A second physical space, unrelated to `ram`. */
    private AddressSpace foreignSpace(String name) {
        AddressSpace space = mock(AddressSpace.class);
        when(space.isOverlaySpace()).thenReturn(false);
        when(space.getName()).thenReturn(name);
        when(space.getType()).thenReturn(AddressSpace.TYPE_RAM);
        when(space.getPhysicalSpace()).thenReturn(space);
        return space;
    }

    /** An address in a mocked space, with the operations the endpoint needs. */
    private Address addr(AddressSpace space, long offset) {
        // Resolve the name up front: calling a mock inside an in-progress
        // when(...) leaves Mockito with unfinished stubbing.
        String spaceName = space.getName();
        String bare = String.format("%04x", offset);
        Address address = mock(Address.class);
        when(address.getAddressSpace()).thenReturn(space);
        when(address.getOffset()).thenReturn(offset);
        when(address.getOffsetAsBigInteger())
            .thenReturn(new java.math.BigInteger(Long.toUnsignedString(offset)));
        when(address.toString(false)).thenReturn(bare);
        when(address.toString(true)).thenReturn(spaceName + "::" + bare);
        when(address.compareTo(any(Address.class))).thenAnswer(invocation -> {
            Address other = invocation.getArgument(0);
            return Long.compareUnsigned(offset, other.getOffset());
        });
        return address;
    }

    private MemoryBlock block(String name, Address start, Address end) {
        MemoryBlock block = mock(MemoryBlock.class);
        when(block.getName()).thenReturn(name);
        when(block.getStart()).thenReturn(start);
        when(block.getEnd()).thenReturn(end);
        return block;
    }

    private Reference ref(Address from, Address to, RefType type,
                          SourceType source, int operandIndex) {
        Reference reference = mock(Reference.class);
        when(reference.getFromAddress()).thenReturn(from);
        when(reference.getToAddress()).thenReturn(to);
        when(reference.getReferenceType()).thenReturn(type);
        when(reference.getSource()).thenReturn(source);
        when(reference.getOperandIndex()).thenReturn(operandIndex);
        return reference;
    }

    /** Builds a program whose reference manager answers from the given refs. */
    private class Fixture {
        final Program program = mock(Program.class);
        final ReferenceManager refMgr = mock(ReferenceManager.class);
        final Memory memory = mock(Memory.class);
        final Listing listing = mock(Listing.class);
        final SymbolTable symbolTable = mock(SymbolTable.class);
        final FunctionManager functionManager = mock(FunctionManager.class);
        final AddressFactory factory = mock(AddressFactory.class);
        final List<Reference> references = new ArrayList<>();
        final List<AddressSpace> spaces = new ArrayList<>();
        final List<MemoryBlock> blocks = new ArrayList<>();
        final List<Address> extraDestinations = new ArrayList<>();
        final RecordingThreadingStrategy threading = new RecordingThreadingStrategy();
        final List<Boolean> modelAccessInsideRead = new ArrayList<>();
        /** See {@link #withOverDeliveringDestinations()}. */
        boolean overDeliverDestinations = false;
        final List<AddressSetView> requestedSets = new ArrayList<>();

        Fixture() {
            // Every model access records whether it happened inside the read hop.
            // Without this, a service could enter an empty hop and read outside it.
            when(program.getReferenceManager()).thenAnswer(invocation -> {
                modelAccessInsideRead.add(threading.isInsideRead());
                return refMgr;
            });
            when(program.getMemory()).thenReturn(memory);
            when(program.getListing()).thenReturn(listing);
            when(program.getSymbolTable()).thenReturn(symbolTable);
            when(program.getFunctionManager()).thenReturn(functionManager);
            when(program.getAddressFactory()).thenReturn(factory);
            when(factory.getDefaultAddressSpace()).thenReturn(ram);
            when(symbolTable.getPrimarySymbol(any())).thenReturn(null);
            when(functionManager.getFunctionContaining(any())).thenReturn(null);
            when(listing.getCodeUnitContaining(any())).thenReturn(null);
            SymbolIterator empty = mock(SymbolIterator.class);
            when(empty.hasNext()).thenReturn(false);
            when(symbolTable.getPrimarySymbolIterator(
                    any(AddressSetView.class), anyBoolean()))
                .thenReturn(empty);
            when(memory.getBlock(any(Address.class))).thenReturn(null);
            spaces.add(ram);
        }

        Fixture withSpaces(AddressSpace... extra) {
            spaces.addAll(Arrays.asList(extra));
            return this;
        }

        Fixture withBlocks(MemoryBlock... items) {
            blocks.addAll(Arrays.asList(items));
            return this;
        }

        Fixture withExtraDestinations(Address... items) {
            extraDestinations.addAll(Arrays.asList(items));
            return this;
        }

        Fixture withRefs(Reference... items) {
            references.addAll(Arrays.asList(items));
            return this;
        }

        /**
         * Makes the destination iterator ignore the set it is given and hand back every
         * destination in the fixture, so the endpoint's own {@code inRange} filter is the only
         * thing standing between the caller and the wrong occupant.
         *
         * <p>A faithful iterator filters by space and offset itself, which leaves
         * {@code inRange} with nothing observable to do: delete its space check and every test
         * still passes. That is a real gap — {@code inRange} is the endpoint's own guarantee, not
         * the mock's, and on real Ghidra data it is what holds if the iterator is ever handed a
         * set built in the wrong space. Modelling a source that over-delivers is how that
         * guarantee gets tested. Use it only for that; the default is the faithful behaviour.</p>
         */
        Fixture withOverDeliveringDestinations() {
            overDeliverDestinations = true;
            return this;
        }

        XrefCallGraphService build() {
            when(factory.getAddressSpaces())
                .thenReturn(spaces.toArray(new AddressSpace[0]));
            when(factory.getAddress(anyString())).thenAnswer(invocation -> {
                String text = invocation.getArgument(0);
                return resolve(text);
            });
            when(memory.getBlocks())
                .thenReturn(blocks.toArray(new MemoryBlock[0]));

            // The iterator honours the AddressSetView it is handed, as Ghidra's does.
            // Returning every fixture destination regardless would leave the endpoint's
            // own inRange filter as the only thing under test, and the space dimension
            // of that filter — whether a RAM query can see an overlay destination — is
            // precisely the property this endpoint exists to get right.
            when(refMgr.getReferenceDestinationIterator(any(AddressSetView.class), anyBoolean()))
                .thenAnswer(invocation -> {
                    AddressSetView requested = invocation.getArgument(0);
                    requestedSets.add(requested);
                    return destinationIterator(requested);
                });
            when(refMgr.getReferencesTo(any(Address.class)))
                .thenAnswer(invocation -> {
                    Address target = invocation.getArgument(0);
                    List<Reference> hits = new ArrayList<>();
                    for (Reference reference : references) {
                        if (sameAddress(reference.getToAddress(), target)) {
                            hits.add(reference);
                        }
                    }
                    return referenceIterator(hits);
                });

            ProgramProvider provider = mock(ProgramProvider.class);
            when(provider.getCurrentProgram()).thenReturn(program);
            // NoopThreadingStrategy throws from executeRead, so using it here
            // would let an implementation that never enters the read hop pass.
            return new XrefCallGraphService(provider, threading);
        }

        private Address resolve(String text) {
            String offsetPart = text;
            String spaceName = ram.getName();
            int colon = text.lastIndexOf(':');
            if (colon >= 0) {
                spaceName = text.substring(0, colon).replace(":", "");
                offsetPart = text.substring(colon + 1);
            }
            long offset;
            try {
                offset = Long.parseUnsignedLong(offsetPart, 16);
            } catch (NumberFormatException e) {
                return null;
            }
            for (AddressSpace space : spaces) {
                if (space.getName().equals(spaceName)) {
                    return space == ram ? ramAddr(offset) : addr(space, offset);
                }
            }
            return null;
        }

        /**
         * The distinct destinations of the fixture's references, restricted to
         * {@code requested} the way {@code ReferenceManager} restricts to the set it is
         * given — including the space test: an address in another space is not in the set
         * even when its offset falls between the set's bounds.
         */
        private ghidra.program.model.address.AddressIterator destinationIterator(
                AddressSetView requested) {
            List<Address> targets = new ArrayList<>();
            for (Address extra : extraDestinations) {
                if (overDeliverDestinations || containedIn(requested, extra)) targets.add(extra);
            }
            for (Reference reference : references) {
                Address destination = reference.getToAddress();
                if (!overDeliverDestinations && !containedIn(requested, destination)) continue;
                boolean seen = false;
                for (Address existing : targets) {
                    if (sameAddress(existing, destination)) {
                        seen = true;
                        break;
                    }
                }
                if (!seen) targets.add(destination);
            }
            Collections.sort(targets);
            Iterator<Address> delegate = targets.iterator();
            ghidra.program.model.address.AddressIterator iterator =
                mock(ghidra.program.model.address.AddressIterator.class);
            when(iterator.hasNext()).thenAnswer(i -> delegate.hasNext());
            when(iterator.next()).thenAnswer(i -> delegate.next());
            return iterator;
        }
    }

    /**
     * Whether {@code candidate} lies in {@code requested}, judged on space name and unsigned
     * offset bounds rather than by delegating to {@code AddressSetView.contains}: the fixture's
     * addresses are mocks, and a real AddressSet built over them cannot be trusted to apply the
     * space test that this comparison exists to reproduce. The endpoint always builds a single
     * contiguous range, so min/max is the whole set.
     */
    private static boolean containedIn(AddressSetView requested, Address candidate) {
        Address min = requested.getMinAddress();
        Address max = requested.getMaxAddress();
        if (min == null || max == null) return false;
        if (!candidate.getAddressSpace().getName().equals(min.getAddressSpace().getName())) {
            return false;
        }
        return Long.compareUnsigned(candidate.getOffset(), min.getOffset()) >= 0
            && Long.compareUnsigned(candidate.getOffset(), max.getOffset()) <= 0;
    }

    private static boolean sameAddress(Address left, Address right) {
        return left.getAddressSpace().getName().equals(
                   right.getAddressSpace().getName())
            && left.getOffset() == right.getOffset();
    }

    private ReferenceIterator referenceIterator(List<Reference> items) {
        Iterator<Reference> delegate = items.iterator();
        ReferenceIterator iterator = mock(ReferenceIterator.class);
        when(iterator.hasNext()).thenAnswer(i -> delegate.hasNext());
        when(iterator.next()).thenAnswer(i -> delegate.next());
        return iterator;
    }

    private static boolean isError(Response response) {
        return response instanceof Response.Err;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> body(Response response) {
        assertNotNull("expected a response", response);
        assertFalse("unexpected error: " + response.toJson(), isError(response));
        assertTrue("expected a structured body, got: " + response.toJson(),
            response instanceof Response.Ok);
        Object data = ((Response.Ok) response).data();
        assertTrue("expected a map body, got: " + data, data instanceof Map);
        return (Map<String, Object>) data;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> rows(Response response) {
        return (List<Map<String, Object>>) body(response).get("references");
    }

    // ------------------------------------------------------- validation

    @Test
    public void rejectsStartAfterEnd() {
        XrefCallGraphService service = new Fixture().build();
        Response response = service.getReferencesIntoRange("98ff", "9680", 2000, "");
        assertTrue(isError(response));
    }

    @Test
    public void rejectsEndpointsInDifferentSpaces() {
        AddressSpace player = overlaySpace("SND_PLAYER");
        XrefCallGraphService service = new Fixture().withSpaces(player).build();
        Response response =
            service.getReferencesIntoRange("9680", "SND_PLAYER:98ff", 2000, "");
        assertTrue(isError(response));
    }

    @Test
    public void rejectsUnresolvableEndpointWithTheParseErrorUnchanged() {
        Fixture fixture = new Fixture();
        XrefCallGraphService service = fixture.build();
        Response response =
            service.getReferencesIntoRange("nonsense", "98ff", 2000, "");
        assertTrue(isError(response));
        // Exact equality, not containment: a substring check also passes a
        // production path that wraps or prefixes the parseAddress message.
        assertNull(ServiceUtils.parseAddress(fixture.program, "nonsense"));
        assertEquals(ServiceUtils.getLastParseError(),
            ((Response.Err) response).message());
    }

    @Test
    public void rejectsLimitOutsideBounds() {
        XrefCallGraphService service = new Fixture().build();
        assertTrue(isError(service.getReferencesIntoRange("9680", "98ff", 0, "")));
        assertTrue(isError(service.getReferencesIntoRange("9680", "98ff", -1, "")));
        assertTrue(
            isError(service.getReferencesIntoRange("9680", "98ff", 10001, "")));
        assertFalse(
            isError(service.getReferencesIntoRange("9680", "98ff", 10000, "")));
    }

    // ------------------------------------------------------- result set

    @Test
    public void inclusiveBoundsIncludeBothEndpointsAndExcludeNeighbours() {
        XrefCallGraphService service = new Fixture()
            .withRefs(
                ref(ramAddr(0x0700), ramAddr(0x9680), RefType.READ,
                    SourceType.ANALYSIS, 0),
                ref(ramAddr(0x0702), ramAddr(0x98ff), RefType.READ,
                    SourceType.ANALYSIS, 0),
                ref(ramAddr(0x0704), ramAddr(0x967f), RefType.READ,
                    SourceType.ANALYSIS, 0),
                ref(ramAddr(0x0706), ramAddr(0x9900), RefType.READ,
                    SourceType.ANALYSIS, 0))
            .build();

        List<Map<String, Object>> rows =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, ""));
        assertEquals(2, rows.size());
        assertEquals("0700", rows.get(0).get("from"));
        assertEquals("0702", rows.get(1).get("from"));
    }

    @Test
    public void indexedStoreYieldsTwoAdjacentRowsSharingASource() {
        Address source = ramAddr(0x0733);
        XrefCallGraphService service = new Fixture()
            .withRefs(
                ref(source, ramAddr(0x9700), RefType.WRITE, SourceType.ANALYSIS, 0),
                ref(source, ramAddr(0x9701), RefType.WRITE, SourceType.ANALYSIS, 0))
            .build();

        Response response = service.getReferencesIntoRange("9680", "98ff", 2000, "");
        List<Map<String, Object>> rows = rows(response);
        assertEquals(2, rows.size());
        assertEquals("0733", rows.get(0).get("from"));
        assertEquals("0733", rows.get(1).get("from"));
        assertEquals("9700", rows.get(0).get("to"));
        assertEquals("9701", rows.get(1).get("to"));
        assertEquals(2, body(response).get("count"));
    }

    @Test
    public void destinationsWithoutReferencesAreAbsent() {
        // The destination iterator also reports 0x9690, which no reference
        // targets. Deriving fixture destinations only from references would make
        // this test unable to exercise its own name.
        XrefCallGraphService service = new Fixture()
            .withExtraDestinations(ramAddr(0x9690))
            .withRefs(ref(ramAddr(0x0700), ramAddr(0x9680), RefType.READ,
                          SourceType.ANALYSIS, 0))
            .build();

        List<Map<String, Object>> rows =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, ""));
        assertEquals(1, rows.size());
        assertEquals("9680", rows.get(0).get("to"));
    }

    @Test
    public void orderedBySourceThenDestination() {
        XrefCallGraphService service = new Fixture()
            .withRefs(
                ref(ramAddr(0x0739), ramAddr(0x9800), RefType.WRITE,
                    SourceType.ANALYSIS, 0),
                ref(ramAddr(0x0703), ramAddr(0x96a1), RefType.UNCONDITIONAL_CALL,
                    SourceType.USER_DEFINED, 0),
                ref(ramAddr(0x0733), ramAddr(0x9701), RefType.WRITE,
                    SourceType.ANALYSIS, 0),
                ref(ramAddr(0x0733), ramAddr(0x9700), RefType.WRITE,
                    SourceType.ANALYSIS, 0))
            .build();

        List<Map<String, Object>> rows =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, ""));
        assertEquals(Arrays.asList("0703", "0733", "0733", "0739"),
            Arrays.asList(rows.get(0).get("from"), rows.get(1).get("from"),
                          rows.get(2).get("from"), rows.get(3).get("from")));
        assertEquals("9700", rows.get(1).get("to"));
        assertEquals("9701", rows.get(2).get("to"));
    }

    @Test
    public void sameSourceAndDestinationDifferingOperandBothAppear() {
        Address source = ramAddr(0x0800);
        Address target = ramAddr(0x9680);
        XrefCallGraphService service = new Fixture()
            .withRefs(
                ref(source, target, RefType.READ, SourceType.ANALYSIS, 1),
                ref(source, target, RefType.READ, SourceType.ANALYSIS, 0))
            .build();

        List<Map<String, Object>> rows =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, ""));
        assertEquals(2, rows.size());
        assertEquals(0, rows.get(0).get("operand_index"));
        assertEquals(1, rows.get(1).get("operand_index"));
    }

    // ------------------------------------------------------- cap semantics

    @Test
    public void truncationReportsMatchesFoundNotRowsReturned() {
        Fixture fixture = new Fixture();
        for (int index = 0; index < 5; index++) {
            fixture.withRefs(ref(ramAddr(0x0700 + index), ramAddr(0x9680),
                RefType.READ, SourceType.ANALYSIS, 0));
        }
        Response response =
            fixture.build().getReferencesIntoRange("9680", "98ff", 2, "");

        assertEquals(5, body(response).get("count"));
        assertEquals(2, rows(response).size());
        assertEquals(Boolean.TRUE, body(response).get("truncated"));
    }

    @Test
    public void untruncatedResultReportsFalse() {
        XrefCallGraphService service = new Fixture()
            .withRefs(ref(ramAddr(0x0700), ramAddr(0x9680), RefType.READ,
                          SourceType.ANALYSIS, 0))
            .build();
        assertEquals(Boolean.FALSE,
            body(service.getReferencesIntoRange("9680", "98ff", 2000, ""))
                .get("truncated"));
    }

    // ------------------------------------------------- cross-space isolation

    /**
     * The property the endpoint exists for, and the one a mocked-away destination iterator
     * cannot prove: with the SAME offsets occupied in both spaces, each query must return only
     * its own occupant. A filter that compared offsets and forgot the space would return four
     * rows from either query, and a sweep built on it would silently attribute one occupant's
     * callers to the other.
     */
    private Fixture bothOccupants(AddressSpace player) {
        return new Fixture()
            .withSpaces(player)
            .withBlocks(block("RAM", ramAddr(0x0000), ramAddr(0xcfff)),
                        block("SND_PLAYER", addr(player, 0x9680), addr(player, 0x98ff)))
            // Same destination offset $9700 in both spaces: the disk loader in RAM,
            // the recovered SID player in the overlay.
            .withRefs(ref(ramAddr(0x0453), ramAddr(0x9700),
                          RefType.UNCONDITIONAL_CALL, SourceType.DEFAULT, 0),
                      ref(ramAddr(0x0733), ramAddr(0x9700),
                          RefType.WRITE, SourceType.ANALYSIS, 0),
                      ref(ramAddr(0xa884), addr(player, 0x9700),
                          RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0),
                      ref(addr(player, 0x9695), addr(player, 0x9700),
                          RefType.UNCONDITIONAL_CALL, SourceType.DEFAULT, 0));
    }

    @Test
    public void physicalQueryReturnsOnlyThePhysicalOccupant() {
        AddressSpace player = overlaySpace("SND_PLAYER");
        XrefCallGraphService service = bothOccupants(player).build();

        Map<String, Object> body =
            body(service.getReferencesIntoRange("9680", "98ff", 2000, ""));
        assertEquals(2, body.get("count"));
        List<String> sources = new ArrayList<>();
        for (Map<String, Object> row : rows(service.getReferencesIntoRange(
                "9680", "98ff", 2000, ""))) {
            sources.add((String) row.get("from"));
            assertEquals("every row must name the RAM occupant",
                "ram:9700", row.get("to"));
        }
        assertEquals(Arrays.asList("ram:0453", "ram:0733"), sources);
    }

    @Test
    public void overlayQueryReturnsOnlyTheOverlayOccupant() {
        AddressSpace player = overlaySpace("SND_PLAYER");
        XrefCallGraphService service = bothOccupants(player).build();

        Map<String, Object> body = body(service.getReferencesIntoRange(
            "SND_PLAYER:9680", "SND_PLAYER:98ff", 2000, ""));
        assertEquals(2, body.get("count"));
        List<String> sources = new ArrayList<>();
        for (Map<String, Object> row : rows(service.getReferencesIntoRange(
                "SND_PLAYER:9680", "SND_PLAYER:98ff", 2000, ""))) {
            sources.add((String) row.get("from"));
            assertEquals("every row must name the overlay occupant",
                "SND_PLAYER::9700", row.get("to"));
        }
        // Both a cross-space caller and a player-internal one, so the query is not
        // accidentally filtering on the SOURCE space. Sorted because the fixture's
        // mock addresses compare on offset alone; source ordering has its own test.
        Collections.sort(sources);
        assertEquals(Arrays.asList("SND_PLAYER::9695", "ram:a884"), sources);
    }

    @Test
    public void inRangeRejectsTheWrongSpaceEvenWhenTheSourceOverDelivers() {
        // Kills the mutant the two tests above do not: delete the space comparison from
        // inRange and this fails, because the iterator is deliberately handing back both
        // occupants' destinations and inRange is the only thing left to separate them.
        AddressSpace player = overlaySpace("SND_PLAYER");
        XrefCallGraphService service =
            bothOccupants(player).withOverDeliveringDestinations().build();

        Map<String, Object> body =
            body(service.getReferencesIntoRange("9680", "98ff", 2000, ""));
        assertEquals("overlay destinations must not leak into a RAM query",
            2, body.get("count"));
        for (Map<String, Object> row : rows(service.getReferencesIntoRange(
                "9680", "98ff", 2000, ""))) {
            assertEquals("ram:9700", row.get("to"));
        }
    }

    @Test
    public void inRangeRejectsOffsetsOutsideTheRangeEvenWhenTheSourceOverDelivers() {
        // The offset half of the same guarantee. $9700 is in range, $a884 is not.
        XrefCallGraphService service = new Fixture()
            .withOverDeliveringDestinations()
            .withRefs(ref(ramAddr(0x0453), ramAddr(0x9700),
                          RefType.UNCONDITIONAL_CALL, SourceType.DEFAULT, 0),
                      ref(ramAddr(0x0456), ramAddr(0xa884),
                          RefType.UNCONDITIONAL_CALL, SourceType.DEFAULT, 0))
            .build();

        Map<String, Object> body =
            body(service.getReferencesIntoRange("9680", "98ff", 2000, ""));
        assertEquals(1, body.get("count"));
        // Bare, not "ram:9700": one physical space and no overlay, so nothing is qualified.
        assertEquals("9700", rows(service.getReferencesIntoRange(
            "9680", "98ff", 2000, "")).get(0).get("to"));
    }

    @Test
    public void theRangeHandedToTheIteratorIsExactlyTheQueriedSpaceAndBounds() {
        // What the endpoint actually controls. A faithful iterator does the filtering, so
        // asking for the wrong space or the wrong bounds is the failure mode that would
        // silently return another occupant's references on real Ghidra data.
        AddressSpace player = overlaySpace("SND_PLAYER");
        Fixture fixture = bothOccupants(player);
        XrefCallGraphService service = fixture.build();

        service.getReferencesIntoRange("SND_PLAYER:9680", "SND_PLAYER:98ff", 2000, "");

        assertEquals(1, fixture.requestedSets.size());
        AddressSetView requested = fixture.requestedSets.get(0);
        assertEquals("SND_PLAYER",
            requested.getMinAddress().getAddressSpace().getName());
        assertEquals(0x9680L, requested.getMinAddress().getOffset());
        assertEquals(0x98ffL, requested.getMaxAddress().getOffset());
    }

    // ------------------------------------------------------- range echo

    @Test
    public void resolvedRangeAlwaysPresentAndOverlapEmptyWithoutOverlays() {
        XrefCallGraphService service = new Fixture().build();
        Map<String, Object> body =
            body(service.getReferencesIntoRange("9680", "98ff", 2000, ""));
        assertEquals("ram:9680 - ram:98ff", body.get("resolved_range"));
        assertEquals(Collections.emptyList(), body.get("overlapping_spaces"));
    }

    @Test
    public void emptyRangeReportsZeroUntruncatedAndAnEmptyList() {
        // Asserting resolved_range alone would pass while count, truncated or
        // references were absent, null, or carried a stale value.
        XrefCallGraphService service = new Fixture().build();
        Map<String, Object> body =
            body(service.getReferencesIntoRange("9680", "98ff", 2000, ""));
        assertEquals(0, body.get("count"));
        assertEquals(Boolean.FALSE, body.get("truncated"));
        assertEquals(Collections.emptyList(), body.get("references"));
    }

    @Test
    public void scopeNamesTheCompletenessBoundaryInEveryResponse() {
        // The caveat has to survive being read without the tool description in view.
        XrefCallGraphService service = new Fixture().build();
        assertEquals("recorded_references_only",
            body(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get("scope"));
    }

    @Test
    public void physicalQueryReportsOverlappingOverlayBlock() {
        AddressSpace player = overlaySpace("SND_PLAYER");
        XrefCallGraphService service = new Fixture()
            .withSpaces(player)
            .withBlocks(block("SND_PLAYER", addr(player, 0x9680),
                              addr(player, 0x98ff)))
            .build();

        assertEquals(Collections.singletonList("SND_PLAYER"),
            body(service.getReferencesIntoRange("9680", "98ff", 2000, ""))
                .get("overlapping_spaces"));
    }

    @Test
    public void nonOverlappingOverlayBlockIsNotReported() {
        AddressSpace player = overlaySpace("SND_PLAYER");
        XrefCallGraphService service = new Fixture()
            .withSpaces(player)
            .withBlocks(block("SND_PLAYER", addr(player, 0xa000),
                              addr(player, 0xa0ff)))
            .build();

        assertEquals(Collections.emptyList(),
            body(service.getReferencesIntoRange("9680", "98ff", 2000, ""))
                .get("overlapping_spaces"));
    }

    @Test
    public void overlayQueryReportsPhysicalAndSiblingOverlay() {
        // The direction an isOverlay() filter gets wrong: querying the overlay
        // must report the underlying physical space, which is not an overlay.
        AddressSpace player = overlaySpace("SND_PLAYER");
        AddressSpace sibling = overlaySpace("SND_OTHER");
        XrefCallGraphService service = new Fixture()
            .withSpaces(player, sibling)
            .withBlocks(
                block("RAM", ramAddr(0x9680), ramAddr(0x98ff)),
                block("SND_OTHER", addr(sibling, 0x9700), addr(sibling, 0x97ff)))
            .build();

        assertEquals(Arrays.asList("SND_OTHER", "ram"),
            body(service.getReferencesIntoRange(
                "SND_PLAYER:9680", "SND_PLAYER:98ff", 2000, ""))
                .get("overlapping_spaces"));
    }

    @Test
    public void overlayAddressesAreSpaceQualifiedInRows() {
        // The entire reason the endpoint exists: two occupants of the same
        // 16-bit addresses must be distinguishable in the output.
        AddressSpace player = overlaySpace("SND_PLAYER");
        XrefCallGraphService service = new Fixture()
            .withSpaces(player)
            .withRefs(ref(addr(player, 0x9750), addr(player, 0x9747),
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0))
            .build();

        Map<String, Object> row = rows(service.getReferencesIntoRange(
            "SND_PLAYER:9680", "SND_PLAYER:98ff", 2000, "")).get(0);
        assertEquals("SND_PLAYER::9750", row.get("from"));
        assertEquals("SND_PLAYER::9747", row.get("to"));
    }

    @Test
    public void queriedSpaceNeverAppearsInItsOwnOverlapList() {
        XrefCallGraphService service = new Fixture()
            .withBlocks(block("RAM", ramAddr(0x0000), ramAddr(0xffff)))
            .build();

        assertEquals(Collections.emptyList(),
            body(service.getReferencesIntoRange("9680", "98ff", 2000, ""))
                .get("overlapping_spaces"));
    }

    @Test
    public void unrelatedPhysicalSpaceIsNotReported() {
        AddressSpace other = foreignSpace("io");
        XrefCallGraphService service = new Fixture()
            .withSpaces(other)
            .withBlocks(block("io", addr(other, 0x9680), addr(other, 0x98ff)))
            .build();

        assertEquals(Collections.emptyList(),
            body(service.getReferencesIntoRange("9680", "98ff", 2000, ""))
                .get("overlapping_spaces"));
    }

    @Test
    public void overlapListIsSortedRegardlessOfBlockOrder() {
        AddressSpace zebra = overlaySpace("ZEBRA");
        AddressSpace alpha = overlaySpace("ALPHA");
        XrefCallGraphService service = new Fixture()
            .withSpaces(zebra, alpha)
            .withBlocks(
                block("ZEBRA", addr(zebra, 0x9680), addr(zebra, 0x98ff)),
                block("ALPHA", addr(alpha, 0x9680), addr(alpha, 0x98ff)))
            .build();

        assertEquals(Arrays.asList("ALPHA", "ZEBRA"),
            body(service.getReferencesIntoRange("9680", "98ff", 2000, ""))
                .get("overlapping_spaces"));
    }

    @Test
    public void highHalfOffsetsIntersectCorrectly() {
        // The range deliberately straddles the signed boundary: the query low
        // (0x7fff...f000) is a positive long while the query high
        // (0x8000...0fff) is negative, so a signed-long implementation computes
        // blockHigh >= queryLow as negative >= positive and reports no overlap.
        // Both bounds inside the high half would intersect either way, which is
        // why an earlier version of this test passed against signed comparison.
        GenericAddressSpace wide =
            new GenericAddressSpace("wide", 64, AddressSpace.TYPE_RAM, 1);
        AddressSpace shadow = mock(AddressSpace.class);
        when(shadow.isOverlaySpace()).thenReturn(true);
        when(shadow.getName()).thenReturn("HIGH_OVERLAY");
        when(shadow.getPhysicalSpace()).thenReturn(wide);
        when(shadow.getType()).thenReturn(AddressSpace.TYPE_RAM);

        Fixture fixture = new Fixture();
        fixture.spaces.clear();
        fixture.spaces.add(wide);
        fixture.spaces.add(shadow);
        fixture.withBlocks(block("HIGH_OVERLAY",
            addr(shadow, 0x8000000000000000L), addr(shadow, 0x8000000000000fffL)));

        XrefCallGraphService service = fixture.build();
        Map<String, Object> body = body(service.getReferencesIntoRange(
            "wide:7ffffffffffff000", "wide:8000000000000fff", 2000, ""));
        assertEquals(Collections.singletonList("HIGH_OVERLAY"),
            body.get("overlapping_spaces"));
    }

    // ------------------------------------------------------- formatting

    @Test
    public void singlePhysicalSpaceWithoutOverlayLeavesAddressesBare() {
        XrefCallGraphService service = new Fixture()
            .withRefs(ref(ramAddr(0x0733), ramAddr(0x9700), RefType.WRITE,
                          SourceType.ANALYSIS, 0))
            .build();

        Map<String, Object> row =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get(0);
        assertEquals("0733", row.get("from"));
        assertEquals("9700", row.get("to"));
    }

    @Test
    public void onePhysicalSpacePlusOverlayQualifiesPhysicalAddresses() {
        // The case ServiceUtils.addressToJson gets wrong: one physical space
        // plus an overlay leaves getPhysicalSpaceCount() at 1.
        AddressSpace player = overlaySpace("SND_PLAYER");
        XrefCallGraphService service = new Fixture()
            .withSpaces(player)
            .withRefs(ref(ramAddr(0x0733), ramAddr(0x9700), RefType.WRITE,
                          SourceType.ANALYSIS, 0))
            .build();

        Map<String, Object> row =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get(0);
        assertEquals("ram:0733", row.get("from"));
        assertEquals("ram:9700", row.get("to"));
    }

    @Test
    public void multiplePhysicalSpacesQualifyAddresses() {
        XrefCallGraphService service = new Fixture()
            .withSpaces(foreignSpace("io"))
            .withRefs(ref(ramAddr(0x0733), ramAddr(0x9700), RefType.WRITE,
                          SourceType.ANALYSIS, 0))
            .build();

        assertEquals("ram:0733",
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, ""))
                .get(0).get("from"));
    }

    // ------------------------------------------------------- payload fields

    @Test
    public void sourceKindAndOperandIndexRoundTrip() {
        XrefCallGraphService service = new Fixture()
            .withRefs(
                ref(ramAddr(0x0700), ramAddr(0x9680), RefType.READ,
                    SourceType.USER_DEFINED, -1),
                ref(ramAddr(0x0702), ramAddr(0x9680), RefType.READ,
                    SourceType.DEFAULT, 0),
                ref(ramAddr(0x0704), ramAddr(0x9680), RefType.READ,
                    SourceType.IMPORTED, 1),
                ref(ramAddr(0x0706), ramAddr(0x9680), RefType.READ,
                    SourceType.ANALYSIS, 0),
                ref(ramAddr(0x0708), ramAddr(0x9680), RefType.READ,
                    SourceType.AI, 0),
                ref(ramAddr(0x070a), ramAddr(0x9680), RefType.READ, null, 0))
            .build();

        List<Map<String, Object>> rows =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, ""));
        assertEquals("user_defined", rows.get(0).get("source_kind"));
        assertEquals("default", rows.get(1).get("source_kind"));
        assertEquals("imported", rows.get(2).get("source_kind"));
        assertEquals("analysis", rows.get(3).get("source_kind"));
        assertEquals("ai", rows.get(4).get("source_kind"));
        // ReferenceOrdering.sourceKind maps null to "", not to a crash.
        assertEquals("", rows.get(5).get("source_kind"));
        assertEquals(-1, rows.get(0).get("operand_index"));
    }

    @Test
    public void instructionSourceRendersItsInstruction() {
        Instruction instruction = mock(Instruction.class);
        when(instruction.toString()).thenReturn("JSR 0x96a1");
        Fixture fixture = new Fixture()
            .withRefs(ref(ramAddr(0x0703), ramAddr(0x96a1),
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0));
        XrefCallGraphService service = fixture.build();
        when(fixture.listing.getCodeUnitContaining(any())).thenReturn(instruction);

        Map<String, Object> row =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get(0);
        assertEquals("instruction", row.get("from_kind"));
        assertEquals("JSR 0x96a1", row.get("from_instruction"));
    }

    @Test
    public void dataSourceRendersItsCodeUnitAndIsNotEmpty() {
        Data data = mock(Data.class);
        when(data.toString()).thenReturn("addr 96A1h");
        Fixture fixture = new Fixture()
            .withRefs(ref(ramAddr(0x1000), ramAddr(0x96a1), RefType.DATA,
                SourceType.ANALYSIS, -1));
        XrefCallGraphService service = fixture.build();
        when(fixture.listing.getCodeUnitContaining(any())).thenReturn(data);

        Map<String, Object> row =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get(0);
        assertEquals("data", row.get("from_kind"));
        assertEquals("addr 96A1h", row.get("from_instruction"));
    }

    @Test
    public void sourceWithoutACodeUnitIsUndefinedAndOmitsRendering() {
        XrefCallGraphService service = new Fixture()
            .withRefs(ref(ramAddr(0x1000), ramAddr(0x96a1), RefType.DATA,
                SourceType.ANALYSIS, -1))
            .build();

        Map<String, Object> row =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get(0);
        assertEquals("undefined", row.get("from_kind"));
        assertFalse(row.containsKey("from_instruction"));
    }

    // ------------------------------------------------------- symbols

    @Test
    public void exactPrimaryLabelBeatsContainingFunction() {
        Symbol label = mock(Symbol.class);
        when(label.getName()).thenReturn("EXACT_LABEL");
        when(label.getAddress()).thenReturn(ramAddr(0x0733));
        Function function = mock(Function.class);
        when(function.getName()).thenReturn("CONTAINING_FUNC");
        when(function.getEntryPoint()).thenReturn(ramAddr(0x0700));

        Fixture fixture = new Fixture()
            .withRefs(ref(ramAddr(0x0733), ramAddr(0x9700), RefType.WRITE,
                SourceType.ANALYSIS, 0));
        XrefCallGraphService service = fixture.build();
        when(fixture.symbolTable.getPrimarySymbol(any())).thenReturn(label);
        when(fixture.functionManager.getFunctionContaining(any()))
            .thenReturn(function);

        Map<String, Object> row =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get(0);
        assertEquals("EXACT_LABEL", row.get("from_symbol"));
        assertEquals(BigInteger.ZERO, row.get("from_symbol_offset"));
        assertEquals("at", row.get("from_symbol_relation"));
    }

    @Test
    public void containingFunctionBeatsNearerPrecedingLabel() {
        Function function = mock(Function.class);
        when(function.getName()).thenReturn("CONTAINING_FUNC");
        when(function.getEntryPoint()).thenReturn(ramAddr(0x0730));

        Symbol nearer = mock(Symbol.class);
        when(nearer.getName()).thenReturn("NEARER_LABEL");
        when(nearer.getAddress()).thenReturn(ramAddr(0x0732));

        Fixture fixture = new Fixture()
            .withRefs(ref(ramAddr(0x0733), ramAddr(0x9700), RefType.WRITE,
                SourceType.ANALYSIS, 0));
        XrefCallGraphService service = fixture.build();
        when(fixture.functionManager.getFunctionContaining(any()))
            .thenReturn(function);
        SymbolIterator iterator = mock(SymbolIterator.class);
        when(iterator.hasNext()).thenReturn(true, false);
        when(iterator.next()).thenReturn(nearer);
        when(fixture.symbolTable.getPrimarySymbolIterator(
                any(AddressSetView.class), anyBoolean()))
            .thenReturn(iterator);

        Map<String, Object> row =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get(0);
        assertEquals("CONTAINING_FUNC", row.get("from_symbol"));
        assertEquals(BigInteger.valueOf(3), row.get("from_symbol_offset"));
        assertEquals("containing", row.get("from_symbol_relation"));
    }

    @Test
    public void defaultLabelIsReportedAsItselfAndPlateCommentIsIgnored() {
        Symbol generated = mock(Symbol.class);
        when(generated.getName()).thenReturn("LAB_0730");
        when(generated.getAddress()).thenReturn(ramAddr(0x0730));

        Fixture fixture = new Fixture()
            .withRefs(ref(ramAddr(0x0730), ramAddr(0x9700), RefType.WRITE,
                SourceType.ANALYSIS, 0));
        XrefCallGraphService service = fixture.build();
        when(fixture.symbolTable.getPrimarySymbol(any())).thenReturn(generated);
        // A plate comment naming the routine INSTALL_DISK_LOADER must not win:
        // comment text is not a symbol.
        when(fixture.listing.getComment(eq(CommentType.PLATE), any()))
            .thenReturn("INSTALL_DISK_LOADER");

        Map<String, Object> row =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get(0);
        assertEquals("LAB_0730", row.get("from_symbol"));
    }

    @Test
    public void symbolFieldsOmittedWhenNothingPrecedesInBlock() {
        XrefCallGraphService service = new Fixture()
            .withRefs(ref(ramAddr(0x0703), ramAddr(0x96a1),
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0))
            .build();

        Map<String, Object> row =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get(0);
        assertFalse(row.containsKey("from_symbol"));
        assertFalse(row.containsKey("from_symbol_offset"));
    }

    @Test
    public void precedingLabelInsideTheBlockIsReturnedWithItsOffset() {
        // Positive case for the fallback. Without it, replacing the whole
        // nearest-preceding lookup with null would leave every other test green.
        Symbol preceding = mock(Symbol.class);
        when(preceding.getName()).thenReturn("IN_BLOCK_LABEL");
        when(preceding.getAddress()).thenReturn(ramAddr(0x0700));

        Fixture fixture = new Fixture()
            .withRefs(ref(ramAddr(0x0703), ramAddr(0x96a1),
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0));
        XrefCallGraphService service = fixture.build();
        SymbolIterator iterator = mock(SymbolIterator.class);
        when(iterator.hasNext()).thenReturn(true, false);
        when(iterator.next()).thenReturn(preceding);
        when(fixture.symbolTable.getPrimarySymbolIterator(
                any(AddressSetView.class), anyBoolean()))
            .thenReturn(iterator);
        MemoryBlock codeBlock = block("CODE", ramAddr(0x0700), ramAddr(0x0fff));
        when(fixture.memory.getBlock(any(Address.class))).thenReturn(codeBlock);

        Map<String, Object> row =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get(0);
        assertEquals("IN_BLOCK_LABEL", row.get("nearest_preceding_symbol"));
        assertEquals(BigInteger.valueOf(3), row.get("nearest_preceding_distance"));
        assertEquals("preceding", row.get("from_symbol_relation"));
        assertFalse("proximity must not be spelled from_symbol",
            row.containsKey("from_symbol"));
    }

    @Test
    public void distantPrecedingLabelIsMarkedPrecedingNotContaining() {
        // The reason from_symbol_relation exists. On a program laid out as one large
        // block the preceding walk is unbounded in practice: here a 5-byte filename
        // buffer 475 bytes back is the nearest label, and the row reads
        // "PART_FILENAME+475" — indistinguishable from an offset INTO something 475
        // bytes long unless the relation says otherwise.
        Symbol distant = mock(Symbol.class);
        when(distant.getName()).thenReturn("PART_FILENAME");
        when(distant.getAddress()).thenReturn(ramAddr(0x9735));

        Fixture fixture = new Fixture()
            .withRefs(ref(ramAddr(0x9902), ramAddr(0x98d1),
                RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0));
        XrefCallGraphService service = fixture.build();
        SymbolIterator iterator = mock(SymbolIterator.class);
        when(iterator.hasNext()).thenReturn(true, false);
        when(iterator.next()).thenReturn(distant);
        when(fixture.symbolTable.getPrimarySymbolIterator(
                any(AddressSetView.class), anyBoolean()))
            .thenReturn(iterator);
        // Built before the when(...), or Mockito sees stubbing inside stubbing.
        MemoryBlock wholeRam = block("RAM", ramAddr(0x0000), ramAddr(0xcfff));
        when(fixture.memory.getBlock(any(Address.class))).thenReturn(wholeRam);

        Map<String, Object> row =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get(0);
        assertEquals("PART_FILENAME", row.get("nearest_preceding_symbol"));
        assertEquals(BigInteger.valueOf(0x9902 - 0x9735),
            row.get("nearest_preceding_distance"));
        assertEquals("preceding", row.get("from_symbol_relation"));
        // The point of the rename: a caller reading only from_symbol cannot print
        // "PART_FILENAME+461" for code nowhere near PART_FILENAME.
        assertFalse(row.containsKey("from_symbol"));
        assertFalse(row.containsKey("from_symbol_offset"));
    }

    @Test
    public void relationIsAbsentWheneverTheSymbolFieldsAre() {
        XrefCallGraphService service = new Fixture()
            .withRefs(ref(ramAddr(0x0703), ramAddr(0x96a1),
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0))
            .build();

        Map<String, Object> row =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get(0);
        assertFalse(row.containsKey("from_symbol"));
        assertFalse(row.containsKey("nearest_preceding_symbol"));
        assertFalse(row.containsKey("from_symbol_relation"));
    }

    @Test
    public void precedingSearchIsBoundedByTheBlockAndUsesPrimarySymbolsOnly() {
        // The boundary is enforced by the searched AddressSet rather than by
        // post-filtering, and the primary-symbol overload is what excludes
        // secondary labels and other addressable symbol types. Assert both,
        // since a mock iterator would happily return an ineligible symbol.
        Symbol preceding = mock(Symbol.class);
        when(preceding.getName()).thenReturn("IN_BLOCK_LABEL");
        when(preceding.getAddress()).thenReturn(ramAddr(0x0700));

        Fixture fixture = new Fixture()
            .withRefs(ref(ramAddr(0x0703), ramAddr(0x96a1),
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0));
        XrefCallGraphService service = fixture.build();
        SymbolIterator iterator = mock(SymbolIterator.class);
        when(iterator.hasNext()).thenReturn(true, false);
        when(iterator.next()).thenReturn(preceding);
        ArgumentCaptor<AddressSetView> searched =
            ArgumentCaptor.forClass(AddressSetView.class);
        when(fixture.symbolTable.getPrimarySymbolIterator(
                searched.capture(), eq(false)))
            .thenReturn(iterator);
        MemoryBlock codeBlock = block("CODE", ramAddr(0x0700), ramAddr(0x0fff));
        when(fixture.memory.getBlock(any(Address.class))).thenReturn(codeBlock);

        rows(service.getReferencesIntoRange("9680", "98ff", 2000, ""));

        assertEquals(ramAddr(0x0700), searched.getValue().getMinAddress());
        assertEquals(ramAddr(0x0703), searched.getValue().getMaxAddress());
        // The all-symbol iterator returns secondary labels; it must not be used.
        verify(fixture.symbolTable, never())
            .getSymbolIterator(any(Address.class), anyBoolean());
    }

    @Test
    public void noContainingBlockMeansNoPrecedingSymbolSearch() {
        Fixture fixture = new Fixture()
            .withRefs(ref(ramAddr(0x0703), ramAddr(0x96a1),
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0));
        XrefCallGraphService service = fixture.build();
        when(fixture.memory.getBlock(any(Address.class))).thenReturn(null);

        Map<String, Object> row =
            rows(service.getReferencesIntoRange("9680", "98ff", 2000, "")).get(0);
        assertFalse(row.containsKey("from_symbol"));
        // Without a block there is no boundary, so no walk may happen at all.
        verify(fixture.symbolTable, never())
            .getPrimarySymbolIterator(any(AddressSetView.class), anyBoolean());
    }

    @Test
    public void largeSymbolOffsetDoesNotWrap() {
        // Ghidra permits blocks far larger than 2 GiB, so a delta above
        // Integer.MAX_VALUE is reachable within one block. Narrowing would wrap.
        GenericAddressSpace wide =
            new GenericAddressSpace("wide", 64, AddressSpace.TYPE_RAM, 2);
        Address source = wide.getAddress(0x80000000L);
        Address target = wide.getAddress(0x100L);
        Symbol preceding = mock(Symbol.class);
        when(preceding.getName()).thenReturn("FAR_BEHIND");
        when(preceding.getAddress()).thenReturn(wide.getAddress(0L));

        Fixture fixture = new Fixture();
        fixture.spaces.clear();
        fixture.spaces.add(wide);
        fixture.withRefs(ref(source, target, RefType.READ, SourceType.ANALYSIS, 0));
        XrefCallGraphService service = fixture.build();
        SymbolIterator iterator = mock(SymbolIterator.class);
        when(iterator.hasNext()).thenReturn(true, false);
        when(iterator.next()).thenReturn(preceding);
        when(fixture.symbolTable.getPrimarySymbolIterator(
                any(AddressSetView.class), anyBoolean()))
            .thenReturn(iterator);
        MemoryBlock huge =
            block("HUGE", wide.getAddress(0L), wide.getAddress(0xffffffffL));
        when(fixture.memory.getBlock(any(Address.class))).thenReturn(huge);

        Map<String, Object> row = rows(service.getReferencesIntoRange(
            "wide:0", "wide:1000", 2000, "")).get(0);
        // A nearest-preceding match, so the distance is the renamed field. Still a BigInteger:
        // narrowing to int would wrap this to a negative number.
        assertEquals(BigInteger.valueOf(0x80000000L), row.get("nearest_preceding_distance"));
    }

    // ------------------------------------------------------- threading

    @Test
    public void modelReadsHappenInsideTheReadHopAndParsingBeforeIt() {
        Fixture fixture = new Fixture()
            .withRefs(ref(ramAddr(0x0700), ramAddr(0x9680), RefType.READ,
                SourceType.ANALYSIS, 0));
        XrefCallGraphService service = fixture.build();

        // parseAddress must run before the hop: it records failures in a
        // ThreadLocal that the GUI strategy's EDT transfer would hide.
        List<String> order = new ArrayList<>();
        fixture.threading.onBeforeRead(() -> order.add("read-hop"));
        when(fixture.factory.getAddress(anyString())).thenAnswer(invocation -> {
            order.add("parse");
            String text = invocation.getArgument(0);
            long offset = Long.parseUnsignedLong(
                text.contains(":") ? text.substring(text.lastIndexOf(':') + 1) : text,
                16);
            return ramAddr(offset);
        });

        assertFalse(isError(service.getReferencesIntoRange("9680", "98ff", 2000, "")));
        assertEquals(1, fixture.threading.readCount());
        assertEquals(0, fixture.threading.writeCount());
        assertEquals(Arrays.asList("parse", "parse", "read-hop"), order);

        // The decisive assertion: model access must occur while the hop is
        // active. Counting hops alone passes an empty hop with reads outside it.
        assertFalse("no model access was recorded at all",
            fixture.modelAccessInsideRead.isEmpty());
        assertEquals(Collections.singletonList(Boolean.TRUE),
            fixture.modelAccessInsideRead.stream().distinct().toList());
    }

    @Test
    public void validationFailuresNeverEnterTheReadHop() {
        Fixture fixture = new Fixture();
        XrefCallGraphService service = fixture.build();
        assertTrue(isError(service.getReferencesIntoRange("98ff", "9680", 2000, "")));
        assertTrue(isError(service.getReferencesIntoRange("9680", "98ff", 0, "")));
        assertEquals(0, fixture.threading.readCount());
    }
}
