package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Offline coverage for {@code /analyze_coverage}.
 *
 * <p>Several fixtures exist to kill one specific wrong choice each: classifying with
 * {@code Data.isDefined()}, merging two abutting blocks into one run, treating in-run
 * labels as exclusive of the endpoints, and taking initialization from
 * {@code MemoryBlock.isInitialized()}. Each is marked where it appears.</p>
 */
public class CoverageServiceTest {

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace("RAM", 16, AddressSpace.TYPE_RAM, 0);
    private static final GenericAddressSpace PLAYER =
        new GenericAddressSpace("SND_PLAYER", 16, AddressSpace.TYPE_RAM, 1);

    // ---------------------------------------------------------------- fixture

    private static final class Fixture {
        final Program program = mock(Program.class);
        final Memory memory = mock(Memory.class);
        final Listing listing = mock(Listing.class);
        final SymbolTable symbols = mock(SymbolTable.class);
        final ReferenceManager references = mock(ReferenceManager.class);
        final ProgramProvider provider = mock(ProgramProvider.class);
        final List<MemoryBlock> blocks = new ArrayList<>();
        final AddressSet initialized = new AddressSet();
        final List<Instruction> instructions = new ArrayList<>();
        final List<Data> definedData = new ArrayList<>();
        final List<Symbol> allSymbols = new ArrayList<>();
        final Map<String, Map<CommentType, String>> comments = new HashMap<>();
        final Map<String, Integer> incoming = new HashMap<>();
        final com.xebyte.offline.RecordingThreadingStrategy threading =
            new com.xebyte.offline.RecordingThreadingStrategy();
        long modificationNumber = 4213;
        boolean bumpModificationOnSymbolPass;

        Fixture block(String name, AddressSpace space, long start, long end) {
            return block(name, space, start, end, start, end);
        }

        /**
         * A block whose initialized extent may be narrower than its mapped extent.
         * {@code isInitialized()} is deliberately stubbed false: it is false for
         * byte-mapped blocks whose bytes are initialized, so an implementation reading
         * it instead of the initialized address set must fail.
         */
        Fixture block(String name, AddressSpace space, long start, long end,
                long initializedFrom, long initializedTo) {
            MemoryBlock block = mock(MemoryBlock.class);
            when(block.getName()).thenReturn(name);
            when(block.getStart()).thenReturn(space.getAddress(start));
            when(block.getEnd()).thenReturn(space.getAddress(end));
            when(block.isInitialized()).thenReturn(false);
            when(block.isOverlay()).thenReturn(space != RAM);
            blocks.add(block);
            if (initializedFrom <= initializedTo) {
                initialized.add(
                    space.getAddress(initializedFrom), space.getAddress(initializedTo));
            }
            return this;
        }

        Fixture instruction(AddressSpace space, long start, int length) {
            Instruction unit = mock(Instruction.class);
            when(unit.getMinAddress()).thenReturn(space.getAddress(start));
            when(unit.getMaxAddress()).thenReturn(space.getAddress(start + length - 1));
            when(unit.getLength()).thenReturn(length);
            instructions.add(unit);
            return this;
        }

        /**
         * A stored data unit. {@code isDefined()} answers true exactly as Ghidra's does
         * for anything returned by {@code getDefinedData} — including an explicitly
         * applied {@code undefined1} — so classifying on it misclassifies.
         */
        Fixture data(AddressSpace space, long start, int length, DataType type) {
            Data unit = mock(Data.class);
            when(unit.getMinAddress()).thenReturn(space.getAddress(start));
            when(unit.getMaxAddress()).thenReturn(space.getAddress(start + length - 1));
            when(unit.getLength()).thenReturn(length);
            when(unit.getDataType()).thenReturn(type);
            when(unit.isDefined()).thenReturn(true);
            definedData.add(unit);
            return this;
        }

        Fixture symbol(AddressSpace space, long at, String name) {
            return symbol(space, at, name, "Global");
        }

        Fixture symbol(AddressSpace space, long at, String name, String namespace) {
            Symbol symbol = mock(Symbol.class);
            Namespace parent = mock(Namespace.class);
            when(parent.getName(true)).thenReturn(namespace);
            when(symbol.getAddress()).thenReturn(space.getAddress(at));
            when(symbol.getName()).thenReturn(name);
            when(symbol.getParentNamespace()).thenReturn(parent);
            when(symbol.isPrimary()).thenReturn(true);
            allSymbols.add(symbol);
            return this;
        }

        Fixture comment(AddressSpace space, long at, CommentType type, String text) {
            comments.computeIfAbsent(key(space, at), ignored -> new HashMap<>())
                .put(type, text);
            return this;
        }

        Fixture incoming(AddressSpace space, long at, int count) {
            incoming.put(key(space, at), count);
            return this;
        }

        private static String key(AddressSpace space, long offset) {
            return space.getName() + ":" + offset;
        }

        CoverageService build() {
            when(program.getName()).thenReturn("fixture");
            when(program.getMemory()).thenReturn(memory);
            when(program.getListing()).thenReturn(listing);
            when(program.getSymbolTable()).thenReturn(symbols);
            when(program.getReferenceManager()).thenReturn(references);
            when(program.getModificationNumber()).thenAnswer(i -> modificationNumber);
            when(memory.getBlocks()).thenReturn(blocks.toArray(new MemoryBlock[0]));
            when(memory.getAllInitializedAddressSet()).thenReturn(initialized);

            when(listing.getInstructions(any(AddressSetView.class), anyBoolean()))
                .thenAnswer(invocation -> {
                    AddressSetView set = invocation.getArgument(0);
                    List<Instruction> selected = instructions.stream()
                        .filter(unit -> set.contains(unit.getMinAddress()))
                        .sorted(Comparator.comparing(Instruction::getMinAddress))
                        .toList();
                    return instructionIterator(selected);
                });
            when(listing.getDefinedData(any(AddressSetView.class), anyBoolean()))
                .thenAnswer(invocation -> {
                    AddressSetView set = invocation.getArgument(0);
                    List<Data> selected = definedData.stream()
                        .filter(unit -> set.contains(unit.getMinAddress()))
                        .sorted(Comparator.comparing(Data::getMinAddress))
                        .toList();
                    return dataIterator(selected);
                });
            when(listing.getCommentAddressIterator(
                    any(CommentType.class), any(AddressSetView.class), anyBoolean()))
                .thenAnswer(invocation -> {
                    CommentType type = invocation.getArgument(0);
                    AddressSetView set = invocation.getArgument(1);
                    List<Address> found = new ArrayList<>();
                    for (Map.Entry<String, Map<CommentType, String>> entry
                            : comments.entrySet()) {
                        if (!entry.getValue().containsKey(type)) continue;
                        Address at = parseKey(entry.getKey());
                        if (set.contains(at)) found.add(at);
                    }
                    found.sort(Comparator.naturalOrder());
                    return addressIterator(found);
                });
            when(listing.getComment(any(CommentType.class), any(Address.class)))
                .thenAnswer(invocation -> {
                    CommentType type = invocation.getArgument(0);
                    Address at = invocation.getArgument(1);
                    return comments
                        .getOrDefault(key(at.getAddressSpace(), at.getOffset()), Map.of())
                        .get(type);
                });
            when(symbols.getAllSymbols(anyBoolean())).thenAnswer(invocation -> {
                if (bumpModificationOnSymbolPass) modificationNumber++;
                return symbolIterator(allSymbols);
            });
            when(symbols.getPrimarySymbolIterator(
                    any(AddressSetView.class), anyBoolean()))
                .thenAnswer(invocation -> {
                    AddressSetView set = invocation.getArgument(0);
                    boolean forward = invocation.getArgument(1);
                    List<Symbol> found = new ArrayList<>(allSymbols.stream()
                        .filter(symbol -> set.contains(symbol.getAddress()))
                        .sorted(Comparator
                            .comparing((Symbol symbol) -> symbol.getAddress())
                            .thenComparing(symbol -> symbol.getName()))
                        .toList());
                    if (!forward) java.util.Collections.reverse(found);
                    return symbolIterator(found);
                });
            when(references.getReferenceDestinationIterator(
                    any(AddressSetView.class), anyBoolean()))
                .thenAnswer(invocation -> {
                    AddressSetView set = invocation.getArgument(0);
                    List<Address> found = new ArrayList<>();
                    for (String at : incoming.keySet()) {
                        Address address = parseKey(at);
                        if (set.contains(address)) found.add(address);
                    }
                    found.sort(Comparator.naturalOrder());
                    return addressIterator(found);
                });
            when(references.getReferenceCountTo(any(Address.class)))
                .thenAnswer(invocation -> {
                    Address at = invocation.getArgument(0);
                    return incoming.getOrDefault(
                        key(at.getAddressSpace(), at.getOffset()), 0);
                });
            when(provider.getCurrentProgram()).thenReturn(program);
            when(provider.getProgram(anyString())).thenReturn(program);
            when(provider.getAllOpenPrograms()).thenReturn(new Program[] {program});
            return new CoverageService(provider, threading);
        }

        private static Address parseKey(String key) {
            int colon = key.lastIndexOf(':');
            String name = key.substring(0, colon);
            long offset = Long.parseLong(key.substring(colon + 1));
            return (RAM.getName().equals(name) ? RAM : PLAYER).getAddress(offset);
        }
    }

    private static InstructionIterator instructionIterator(List<Instruction> items) {
        Iterator<Instruction> delegate = items.iterator();
        return new InstructionIterator() {
            @Override public boolean hasNext() { return delegate.hasNext(); }
            @Override public Instruction next() { return delegate.next(); }
            @Override public Iterator<Instruction> iterator() { return this; }
        };
    }

    private static DataIterator dataIterator(List<Data> items) {
        Iterator<Data> delegate = items.iterator();
        return new DataIterator() {
            @Override public boolean hasNext() { return delegate.hasNext(); }
            @Override public Data next() { return delegate.next(); }
            @Override public Iterator<Data> iterator() { return this; }
        };
    }

    private static SymbolIterator symbolIterator(List<Symbol> items) {
        Iterator<Symbol> delegate = new ArrayList<>(items).iterator();
        return new SymbolIterator() {
            @Override public boolean hasNext() { return delegate.hasNext(); }
            @Override public Symbol next() { return delegate.next(); }
            @Override public Iterator<Symbol> iterator() { return this; }
        };
    }

    private static AddressIterator addressIterator(List<Address> items) {
        Iterator<Address> delegate = new ArrayList<>(items).iterator();
        return new AddressIterator() {
            @Override public boolean hasNext() { return delegate.hasNext(); }
            @Override public Address next() { return delegate.next(); }
        };
    }

    // ------------------------------------------------------------- accessors

    private static final com.google.gson.Gson WIRE_JSON = new com.google.gson.GsonBuilder()
        .setObjectToNumberStrategy(com.google.gson.ToNumberPolicy.LONG_OR_DOUBLE)
        .create();

    private static Map<String, Object> body(Response response) {
        assertNotNull(response);
        assertFalse("unexpected error: " + response.toJson(),
            response instanceof Response.Err);
        return WIRE_JSON.fromJson(response.toJson(),
            new com.google.gson.reflect.TypeToken<Map<String, Object>>() { }.getType());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Map<String, Object> parent, String key) {
        return (Map<String, Object>) parent.get(key);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> list(Map<String, Object> parent, String key) {
        return (List<Map<String, Object>>) parent.get(key);
    }

    private static Map<String, Object> spaceRow(Response response, String space) {
        for (Map<String, Object> row
                : list(map(body(response), "memory_coverage"), "spaces")) {
            if (space.equals(row.get("space"))) return row;
        }
        return null;
    }

    private static Map<String, Object> runsEnvelope(Response response) {
        return map(map(body(response), "memory_coverage"), "undefined_runs");
    }

    private static List<Map<String, Object>> runs(Response response) {
        return list(runsEnvelope(response), "items");
    }

    private static boolean isError(Response response) {
        return response instanceof Response.Err;
    }

    private static Response coverage(CoverageService service) {
        return service.analyzeCoverage(1, 100, 0, 100, 0, "TODO",
            "DAT_,SUB_,LAB_,FUN_,UNK_", "");
    }

    // -------------------------------------------------------- classification

    @Test
    public void explicitlyUndefinedDataCountsAsUndefinedAndRealDataAsData() {
        // The load-bearing predicate. Data.isDefined() returns true for every one of
        // these units, so an implementation using it reports zero undefined bytes.
        CoverageService service = new Fixture()
            .block("ram", RAM, 0x00, 0x0f)
            .data(RAM, 0x00, 1, Undefined1DataType.dataType)
            .data(RAM, 0x01, 2, Undefined2DataType.dataType)
            .data(RAM, 0x03, 4, new ArrayDataType(Undefined1DataType.dataType, 4, 1))
            .data(RAM, 0x07, 1, ByteDataType.dataType)
            .data(RAM, 0x08, 2, WordDataType.dataType)
            .instruction(RAM, 0x0a, 3)
            .build();

        Map<String, Object> row = spaceRow(coverage(service), "RAM");
        assertEquals(16L, row.get("total"));
        assertEquals(3L, row.get("instruction"));
        assertEquals(3L, row.get("data"));
        // 7 explicitly-undefined bytes plus the 3-byte gap at $0d-$0f.
        assertEquals(10L, row.get("undefined"));
        assertEquals(1L, row.get("blocks"));
        assertEquals(62.5, row.get("undefined_pct"));
    }

    @Test
    public void theThreeClassesSumToTheInitializedTotalInEverySpace() {
        CoverageService service = new Fixture()
            .block("ram", RAM, 0x00, 0x1f)
            .block("player", PLAYER, 0x00, 0x0f)
            .instruction(RAM, 0x00, 3)
            .data(RAM, 0x10, 4, ByteDataType.dataType)
            .instruction(PLAYER, 0x04, 2)
            .build();

        Response response = coverage(service);
        for (String space : List.of("RAM", "SND_PLAYER")) {
            Map<String, Object> row = spaceRow(response, space);
            assertEquals(space, (Long) row.get("total"),
                Long.valueOf((Long) row.get("instruction") + (Long) row.get("data")
                    + (Long) row.get("undefined")));
        }
        assertEquals(Boolean.TRUE, spaceRow(response, "SND_PLAYER").get("overlay"));
        assertNull("a physical space carries no overlay flag",
            spaceRow(response, "RAM").get("overlay"));
    }

    @Test
    public void aProgramWithNoFunctionsIsStillFullyClassified() {
        // The premise the endpoint exists for: find_code_gaps reports a labels-only
        // program as one giant gap. Nothing here consults the function manager.
        CoverageService service = new Fixture()
            .block("ram", RAM, 0x00, 0x0f)
            .instruction(RAM, 0x00, 16)
            .build();

        Map<String, Object> row = spaceRow(coverage(service), "RAM");
        assertEquals(16L, row.get("instruction"));
        assertEquals(0L, row.get("undefined"));
        assertEquals(0.0, row.get("undefined_pct"));
        assertEquals(List.of(), runs(coverage(service)));
    }

    // ------------------------------------------------------------ memory shape

    @Test
    public void aBlockReportingIsInitializedFalseIsStillCounted() {
        // Byte- and bit-mapped blocks report isInitialized() == false while their bytes
        // are initialized; the address set is the authority. Every fixture block here
        // stubs isInitialized() false, so filtering on it reports an empty program.
        CoverageService service = new Fixture()
            .block("mapped", RAM, 0x00, 0x07)
            .build();

        assertEquals(8L, spaceRow(coverage(service), "RAM").get("total"));
        assertEquals(8L, spaceRow(coverage(service), "RAM").get("undefined"));
    }

    @Test
    public void anUninitializedHoleIsReportedAndNeverCountedAsUndefined() {
        CoverageService service = new Fixture()
            .block("ram", RAM, 0x00, 0x1f, 0x00, 0x0f)
            .build();

        Response response = coverage(service);
        assertEquals(16L, spaceRow(response, "RAM").get("total"));
        assertEquals(16L, spaceRow(response, "RAM").get("undefined"));
        List<Map<String, Object>> holes =
            list(map(body(response), "memory_coverage"), "uninitialized_ranges");
        assertEquals(1, holes.size());
        assertEquals("ram", holes.get(0).get("block"));
        assertEquals("RAM:0010", holes.get(0).get("start"));
        assertEquals("RAM:001f", holes.get(0).get("end"));
        assertEquals(16L, holes.get(0).get("length"));
    }

    @Test
    public void aRunNeverBridgesAnUninitializedHole() {
        CoverageService service = new Fixture()
            .block("ram", RAM, 0x00, 0x2f, 0x00, 0x0f)
            .build();
        Fixture second = new Fixture().block("ram", RAM, 0x00, 0x2f, 0x00, 0x0f);
        second.initialized.add(RAM.getAddress(0x20), RAM.getAddress(0x2f));

        assertEquals(1, runs(coverage(service)).size());
        List<Map<String, Object>> split = runs(coverage(second.build()));
        assertEquals("a run must close at the initialized-range boundary",
            2, split.size());
        assertEquals("RAM:0000", split.get(0).get("start"));
        assertEquals("RAM:000f", split.get(0).get("end"));
        assertEquals("RAM:0020", split.get(1).get("start"));
    }

    @Test
    public void twoAbuttingInitializedBlocksDoNotMergeIntoOneRun() {
        // Their initialized runs coalesce inside an AddressSet, so an implementation
        // closing runs only on the set's boundaries reports one 32-byte run here.
        CoverageService service = new Fixture()
            .block("low", RAM, 0x00, 0x0f)
            .block("high", RAM, 0x10, 0x1f)
            .build();

        List<Map<String, Object>> runs = runs(coverage(service));
        assertEquals(2, runs.size());
        assertEquals(16L, runs.get(0).get("length"));
        assertEquals(16L, runs.get(1).get("length"));
        assertEquals(2L, spaceRow(coverage(service), "RAM").get("blocks"));
    }

    @Test
    public void runsCloseAtSpaceBoundaries() {
        CoverageService service = new Fixture()
            .block("ram", RAM, 0x00, 0x0f)
            .block("player", PLAYER, 0x10, 0x1f)
            .build();

        List<Map<String, Object>> runs = runs(coverage(service));
        assertEquals(2, runs.size());
        assertEquals(List.of("RAM:0000", "SND_PLAYER:0010"),
            List.of(runs.get(0).get("start"), runs.get(1).get("start")));
    }

    // ------------------------------------------------------------------ runs

    @Test
    public void anExplicitUndefinedUnitDoesNotSplitTheRunAroundIt() {
        // The motivating case: three apparently separate runs are one run once the
        // explicit undefined1 units between them are classified correctly.
        CoverageService service = new Fixture()
            .block("ram", RAM, 0x00, 0x1f)
            .data(RAM, 0x08, 1, Undefined1DataType.dataType)
            .data(RAM, 0x10, 1, Undefined1DataType.dataType)
            .build();

        List<Map<String, Object>> runs = runs(coverage(service));
        assertEquals(1, runs.size());
        assertEquals(32L, runs.get(0).get("length"));
        assertEquals("RAM:0000", runs.get(0).get("start"));
        assertEquals("RAM:001f", runs.get(0).get("end"));
    }

    @Test
    public void labelsDoNotSplitARunAndBothEndpointsAreDisclosed() {
        // Inclusive of the first and last byte: a label at either end would otherwise
        // fall between "inside the run" and "the outside neighbours" and vanish.
        CoverageService service = new Fixture()
            .block("ram", RAM, 0x00, 0x1f)
            .instruction(RAM, 0x00, 4)
            .symbol(RAM, 0x04, "AT_FIRST_BYTE")
            .symbol(RAM, 0x10, "INTERIOR")
            .symbol(RAM, 0x1f, "AT_LAST_BYTE")
            .build();

        List<Map<String, Object>> runs = runs(coverage(service));
        assertEquals(1, runs.size());
        Map<String, Object> labels = map(runs.get(0), "primary_labels_in_run");
        assertEquals(3L, labels.get("count"));
        List<String> names = new ArrayList<>();
        for (Map<String, Object> sample : list(labels, "samples")) {
            names.add((String) sample.get("name"));
        }
        assertEquals(List.of("AT_FIRST_BYTE", "INTERIOR", "AT_LAST_BYTE"), names);
    }

    @Test
    public void precedingAndFollowingLabelsCarryAddressNameAndDistance() {
        CoverageService service = new Fixture()
            .block("ram", RAM, 0x00, 0x2f)
            .instruction(RAM, 0x00, 0x10)
            .instruction(RAM, 0x20, 0x10)
            .symbol(RAM, 0x04, "ROOM_TEXT_28")
            .symbol(RAM, 0x20, "SND_TICK")
            .build();

        Map<String, Object> run = runs(coverage(service)).get(0);
        assertEquals("RAM:0010", run.get("start"));
        Map<String, Object> preceding = map(run, "preceding_label");
        assertEquals("RAM:0004", preceding.get("address"));
        assertEquals("ROOM_TEXT_28", preceding.get("name"));
        assertEquals(12L, preceding.get("distance"));
        Map<String, Object> following = map(run, "following_label");
        assertEquals("RAM:0020", following.get("address"));
        assertEquals("SND_TICK", following.get("name"));
        assertEquals(1L, following.get("distance"));
    }

    @Test
    public void labelsAtABlockEdgeYieldNullNeighbours() {
        CoverageService service = new Fixture().block("ram", RAM, 0x00, 0x0f).build();
        Map<String, Object> run = runs(coverage(service)).get(0);
        assertTrue(run.containsKey("preceding_label"));
        assertNull(run.get("preceding_label"));
        assertNull(run.get("following_label"));
    }

    @Test
    public void aNeighbourLabelIsNeverTakenFromAnotherBlock() {
        CoverageService service = new Fixture()
            .block("low", RAM, 0x00, 0x0f)
            .block("high", RAM, 0x10, 0x1f)
            .symbol(RAM, 0x08, "IN_THE_LOW_BLOCK")
            .build();

        List<Map<String, Object>> runs = runs(coverage(service));
        Map<String, Object> highRun = runs.stream()
            .filter(run -> "RAM:0010".equals(run.get("start")))
            .findFirst().orElseThrow();
        assertNull(highRun.get("preceding_label"));
    }

    @Test
    public void incomingReferencesAreCountedAtBothRunEndpoints() {
        CoverageService service = new Fixture()
            .block("ram", RAM, 0x00, 0x1f)
            .instruction(RAM, 0x00, 0x10)
            .incoming(RAM, 0x0f, 5)
            .incoming(RAM, 0x10, 3)
            .incoming(RAM, 0x1f, 4)
            .build();

        Map<String, Object> run = runs(coverage(service)).get(0);
        assertEquals("only the references landing inside the run count",
            7L, run.get("incoming_reference_count"));
    }

    @Test
    public void runsAreOrderedByLengthThenSpaceThenAddress() {
        CoverageService service = new Fixture()
            .block("ram", RAM, 0x00, 0x2f)
            .block("player", PLAYER, 0x00, 0x0f)
            .instruction(RAM, 0x10, 0x10)
            .build();

        // RAM has two 16-byte runs and the overlay one; the tie is broken by space
        // name and then by address, so the order is total.
        List<Map<String, Object>> runs = runs(coverage(service));
        assertEquals(List.of("RAM:0000", "RAM:0020", "SND_PLAYER:0000"),
            List.of(runs.get(0).get("start"), runs.get(1).get("start"),
                runs.get(2).get("start")));
    }

    @Test
    public void theLongestRunSortsFirst() {
        CoverageService service = new Fixture()
            .block("ram", RAM, 0x00, 0x3f)
            .instruction(RAM, 0x04, 1)
            .build();

        List<Map<String, Object>> runs = runs(coverage(service));
        assertEquals(59L, runs.get(0).get("length"));
        assertEquals(4L, runs.get(1).get("length"));
    }

    // ---------------------------------------------------------------- paging

    /** Runs of 1, 2, 3 and 4 bytes, separated by single instructions. */
    private Fixture gradedRuns() {
        Fixture fixture = new Fixture().block("ram", RAM, 0x00, 0x0d);
        fixture.instruction(RAM, 0x01, 1);   // run [0,0]   length 1
        fixture.instruction(RAM, 0x04, 1);   // run [2,3]   length 2
        fixture.instruction(RAM, 0x08, 1);   // run [5,7]   length 3
        fixture.instruction(RAM, 0x0d, 1);   // run [9,12]  length 4
        return fixture;
    }

    @Test
    public void minRunLengthMovesRowsIntoBelowMinWithoutChangingAllCount() {
        Response response = gradedRuns().build()
            .analyzeCoverage(3, 100, 0, 100, 0, "TODO", "DAT_", "");
        Map<String, Object> envelope = map(map(body(response), "memory_coverage"),
            "undefined_runs");

        assertEquals(4L, envelope.get("all_count"));
        assertEquals(2L, envelope.get("eligible_count"));
        assertEquals(2L, map(envelope, "below_min").get("count"));
        assertEquals(3L, map(envelope, "below_min").get("bytes"));
        assertEquals(2L, envelope.get("returned"));
        assertEquals(Boolean.FALSE, envelope.get("has_more"));
    }

    @Test
    public void theEnvelopeInvariantsHold() {
        Response response = gradedRuns().build()
            .analyzeCoverage(2, 2, 1, 100, 0, "TODO", "DAT_", "");
        Map<String, Object> envelope = runsEnvelope(response);

        long all = (Long) envelope.get("all_count");
        long eligible = (Long) envelope.get("eligible_count");
        long below = (Long) map(envelope, "below_min").get("count");
        long returned = (Long) envelope.get("returned");
        long offset = (Long) envelope.get("offset");
        assertEquals(all, eligible + below);
        assertEquals(returned, list(envelope, "items").size());
        assertEquals(offset + returned < eligible, envelope.get("has_more"));
        assertEquals(1L, offset);
        assertEquals(2L, returned);
    }

    @Test
    public void anOffsetPastTheEndIsAnEmptyPageWithStatisticsIntact() {
        Response response = gradedRuns().build()
            .analyzeCoverage(1, 100, 99, 100, 0, "TODO", "DAT_", "");
        Map<String, Object> envelope = runsEnvelope(response);
        assertEquals(4L, envelope.get("all_count"));
        assertEquals(List.of(), envelope.get("items"));
        assertEquals(Boolean.FALSE, envelope.get("has_more"));
    }

    @Test
    public void statisticsAreIdenticalAcrossPages() {
        CoverageService service = gradedRuns().build();
        Map<String, Object> first = runsEnvelope(
            service.analyzeCoverage(1, 2, 0, 100, 0, "TODO", "DAT_", ""));
        Map<String, Object> second = runsEnvelope(
            service.analyzeCoverage(1, 2, 2, 100, 0, "TODO", "DAT_", ""));

        assertEquals(first.get("all_count"), second.get("all_count"));
        assertEquals(first.get("eligible_count"), second.get("eligible_count"));
        assertEquals(Boolean.TRUE, first.get("has_more"));
        assertEquals(Boolean.FALSE, second.get("has_more"));
        // Longest first, so page one holds the 4- and 3-byte runs.
        assertEquals(List.of(4L, 3L), List.of(
            list(first, "items").get(0).get("length"),
            list(first, "items").get(1).get("length")));
        assertEquals(List.of(2L, 1L), List.of(
            list(second, "items").get(0).get("length"),
            list(second, "items").get(1).get("length")));
    }

    @Test
    public void aMinRunLengthAboveTheProgramSizeSimplyMatchesNothing() {
        Response response = gradedRuns().build()
            .analyzeCoverage(0x7fffffffffffffffL, 100, 0, 100, 0, "TODO", "DAT_", "");
        Map<String, Object> envelope = runsEnvelope(response);
        assertEquals(4L, envelope.get("all_count"));
        assertEquals(0L, envelope.get("eligible_count"));
        assertEquals(List.of(), envelope.get("items"));
    }

    // --------------------------------------------------------------- backlog

    @Test
    public void genericPrefixTotalsAndSamplesAreReported() {
        Fixture fixture = new Fixture().block("ram", RAM, 0x00, 0xff);
        fixture.symbol(RAM, 0x10, "DAT_0010");
        fixture.symbol(RAM, 0x20, "DAT_0020");
        fixture.symbol(RAM, 0x30, "SUB_0030");
        fixture.symbol(RAM, 0x40, "MEANINGFUL_NAME");
        Response response = coverage(fixture.build());

        Map<String, Object> generic =
            map(map(body(response), "annotation_backlog"), "generic_symbols");
        Map<String, Object> totals = map(generic, "totals");
        assertEquals(2L, totals.get("DAT_"));
        assertEquals(1L, totals.get("SUB_"));
        assertEquals(0L, totals.get("LAB_"));
        @SuppressWarnings("unchecked")
        List<String> samples = (List<String>) map(generic, "samples").get("DAT_");
        assertEquals(List.of("RAM:0010", "RAM:0020"), samples);
    }

    @Test
    public void unknownMarkersCoverLabelsAndEveryCommentType() {
        Fixture fixture = new Fixture().block("ram", RAM, 0x00, 0xff);
        fixture.symbol(RAM, 0x0460, "TODO_UNKNOWN_BYTE_0460");
        fixture.symbol(RAM, 0x0050, "todo_lowercase_is_not_a_marker");
        fixture.comment(RAM, 0x11, CommentType.EOL, "TODO: classify this");
        fixture.comment(RAM, 0x12, CommentType.PLATE, "TODO plate");
        fixture.comment(RAM, 0x13, CommentType.PRE, "TODO pre");
        fixture.comment(RAM, 0x14, CommentType.POST, "TODO post");
        fixture.comment(RAM, 0x15, CommentType.REPEATABLE, "TODO repeatable");
        fixture.comment(RAM, 0x16, CommentType.EOL, "nothing to see");
        Response response = coverage(fixture.build());

        Map<String, Object> markers =
            map(map(body(response), "annotation_backlog"), "unknown_markers");
        assertEquals(6L, markers.get("all_count"));
        List<String> kinds = new ArrayList<>();
        for (Map<String, Object> item : list(markers, "items")) {
            kinds.add((String) item.get("kind"));
        }
        assertEquals(List.of("eol", "plate", "pre", "post", "repeatable", "label"), kinds);
    }

    @Test
    public void markerCommentTextIsTruncatedAtTwoHundredCharacters() {
        Fixture fixture = new Fixture().block("ram", RAM, 0x00, 0xff);
        fixture.comment(RAM, 0x10, CommentType.EOL, "TODO " + "x".repeat(300));
        Response response = coverage(fixture.build());

        String text = (String)
            list(map(map(body(response), "annotation_backlog"), "unknown_markers"),
                "items").get(0).get("text");
        assertEquals(200, text.length());
        assertTrue(text.endsWith("…"));
    }

    @Test
    public void markersAreOrderedByAddressThenKindRegardlessOfInsertionOrder() {
        Fixture fixture = new Fixture().block("ram", RAM, 0x00, 0xff);
        // Inserted in reverse address order; a label and a comment share $0020, and
        // the kind order breaks that tie deterministically.
        fixture.comment(RAM, 0x30, CommentType.EOL, "TODO third");
        fixture.comment(RAM, 0x20, CommentType.EOL, "TODO second");
        fixture.symbol(RAM, 0x20, "TODO_SECOND_LABEL");
        fixture.comment(RAM, 0x10, CommentType.PLATE, "TODO first");
        Response response = coverage(fixture.build());

        List<Map<String, Object>> items = list(
            map(map(body(response), "annotation_backlog"), "unknown_markers"), "items");
        assertEquals(List.of("RAM:0010", "RAM:0020", "RAM:0020", "RAM:0030"),
            items.stream().map(item -> item.get("address")).toList());
        assertEquals("label sorts before eol at one address",
            List.of("plate", "label", "eol", "eol"),
            items.stream().map(item -> item.get("kind")).toList());
    }

    @Test
    public void markersPageIndependentlyOfRuns() {
        Fixture fixture = gradedRuns();
        fixture.comment(RAM, 0x01, CommentType.EOL, "TODO one");
        fixture.comment(RAM, 0x02, CommentType.EOL, "TODO two");
        fixture.comment(RAM, 0x03, CommentType.EOL, "TODO three");
        Response response = fixture.build()
            .analyzeCoverage(1, 100, 0, 2, 1, "TODO", "DAT_", "");

        Map<String, Object> markers =
            map(map(body(response), "annotation_backlog"), "unknown_markers");
        assertEquals(3L, markers.get("all_count"));
        assertEquals(2L, markers.get("returned"));
        assertEquals(1L, markers.get("offset"));
        assertEquals(2L, markers.get("limit"));
        assertEquals(Boolean.FALSE, markers.get("has_more"));
        assertEquals(4L, runsEnvelope(response).get("returned"));
    }

    @Test
    public void aMarkerPageBoundaryCanFallBetweenALabelAndACommentAtOneAddress() {
        // The tie-break has to survive being split by paging, not merely sorted.
        Fixture fixture = new Fixture().block("ram", RAM, 0x00, 0xff);
        fixture.comment(RAM, 0x20, CommentType.EOL, "TODO the comment");
        fixture.symbol(RAM, 0x20, "TODO_THE_LABEL");
        CoverageService service = fixture.build();

        Map<String, Object> first = map(map(body(
            service.analyzeCoverage(1, 100, 0, 1, 0, "TODO", "DAT_", "")),
            "annotation_backlog"), "unknown_markers");
        Map<String, Object> second = map(map(body(
            service.analyzeCoverage(1, 100, 0, 1, 1, "TODO", "DAT_", "")),
            "annotation_backlog"), "unknown_markers");

        assertEquals(2L, first.get("all_count"));
        assertEquals(Boolean.TRUE, first.get("has_more"));
        assertEquals("label", list(first, "items").get(0).get("kind"));
        assertEquals("eol", list(second, "items").get(0).get("kind"));
        assertEquals(Boolean.FALSE, second.get("has_more"));
    }

    @Test
    public void theMarkerPrefixIsConfigurableAndCaseSensitive() {
        Fixture fixture = new Fixture().block("ram", RAM, 0x00, 0xff);
        fixture.comment(RAM, 0x10, CommentType.EOL, "FIXME: later");
        fixture.comment(RAM, 0x11, CommentType.EOL, "TODO: later");
        Response response = fixture.build()
            .analyzeCoverage(1, 100, 0, 100, 0, "FIXME", "DAT_", "");

        Map<String, Object> markers =
            map(map(body(response), "annotation_backlog"), "unknown_markers");
        assertEquals(1L, markers.get("all_count"));
        assertEquals("RAM:0010", list(markers, "items").get(0).get("address"));
    }

    // ------------------------------------------------------------- validation

    @Test
    public void outOfRangeParametersAreRejectedWithThePermittedRange() {
        CoverageService service = new Fixture().block("ram", RAM, 0x00, 0x0f).build();
        assertTrue(isError(service.analyzeCoverage(0, 100, 0, 100, 0, "TODO", "DAT_", "")));
        assertTrue(isError(service.analyzeCoverage(-1, 100, 0, 100, 0, "TODO", "DAT_", "")));
        assertTrue(isError(service.analyzeCoverage(1, 0, 0, 100, 0, "TODO", "DAT_", "")));
        assertTrue(isError(
            service.analyzeCoverage(1, 10_001, 0, 100, 0, "TODO", "DAT_", "")));
        assertTrue(isError(service.analyzeCoverage(1, 100, -1, 100, 0, "TODO", "DAT_", "")));
        assertTrue(isError(service.analyzeCoverage(1, 100, 0, 0, 0, "TODO", "DAT_", "")));
        assertTrue(isError(
            service.analyzeCoverage(1, 100, 0, 10_001, 0, "TODO", "DAT_", "")));
        assertTrue(isError(service.analyzeCoverage(1, 100, 0, 100, -1, "TODO", "DAT_", "")));
        assertFalse(isError(
            service.analyzeCoverage(1, 10_000, 0, 10_000, 0, "TODO", "DAT_", "")));
    }

    @Test
    public void emptyPrefixesAreRejected() {
        CoverageService service = new Fixture().block("ram", RAM, 0x00, 0x0f).build();
        // An empty marker prefix matches every label and comment, turning the backlog
        // into a dump of the whole program.
        assertTrue(isError(service.analyzeCoverage(1, 100, 0, 100, 0, "  ", "DAT_", "")));
        assertTrue(isError(service.analyzeCoverage(1, 100, 0, 100, 0, "TODO", " , ", "")));
    }

    @Test
    public void aLargeMinRunLengthIsAcceptedRatherThanCapped() {
        // An earlier draft capped this at 0x1000000, which is a 24-bit-target
        // assumption in an endpoint that must also serve 64-bit programs.
        CoverageService service = new Fixture().block("ram", RAM, 0x00, 0x0f).build();
        assertFalse(isError(service.analyzeCoverage(
            0x100000000L, 100, 0, 100, 0, "TODO", "DAT_", "")));
    }

    // ------------------------------------------------------------ concurrency

    @Test
    public void aModificationLandingMidReadFailsTheCall() {
        Fixture fixture = new Fixture().block("ram", RAM, 0x00, 0x0f);
        fixture.bumpModificationOnSymbolPass = true;
        assertTrue("mixed numbers must never be returned", isError(coverage(fixture.build())));
    }

    @Test
    public void theModificationNumberIsEchoed() {
        Response response = coverage(new Fixture().block("ram", RAM, 0x00, 0x0f).build());
        assertEquals(4213L, body(response).get("program_modification_number"));
        assertEquals("fixture", body(response).get("program"));
    }

    @Test
    public void modelReadsHappenInsideTheReadHop() {
        Fixture fixture = new Fixture().block("ram", RAM, 0x00, 0x0f);
        CoverageService service = fixture.build();
        assertFalse(isError(coverage(service)));
        assertEquals(1, fixture.threading.readCount());
        assertEquals(0, fixture.threading.writeCount());
    }
}
