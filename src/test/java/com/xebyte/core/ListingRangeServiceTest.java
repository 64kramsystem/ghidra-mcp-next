package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class ListingRangeServiceTest {

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0);
    private static final GenericAddressSpace OTHER =
        new GenericAddressSpace("other", 16, AddressSpace.TYPE_RAM, 1);

    @Test
    public void mixedRangeExpandsAndRepresentsEveryAddressExactlyOnce() throws Exception {
        Fixture fixture = fixture(0x1000, 0x1020);
        fixture.instruction(0x1000, 3, "lda", "#$01");
        fixture.data(0x1003, 3, "word[3]", "/word[3]", "{ 1, 2, 3 }");

        JsonObject page = ok(fixture.query("1001", "1008", 100, 4096, 100, null));

        assertRange(page.getAsJsonObject("requested_range"), "1001", "1008");
        assertRange(page.getAsJsonObject("effective_range"), "1000", "1008");
        assertRange(page.getAsJsonObject("returned_range"), "1000", "1008");
        assertTrue(page.get("complete").getAsBoolean());
        JsonArray units = page.getAsJsonArray("units");
        assertEquals(List.of("instruction", "data", "undefined"),
            strings(units, "kind"));
        assertNoGapsOrOverlaps(units, 0x1000, 0x1008);
        assertEquals("000102", units.get(0).getAsJsonObject().get("bytes").getAsString());
        assertEquals("lda", units.get(0).getAsJsonObject().get("mnemonic").getAsString());
        assertEquals("#$01", units.get(0).getAsJsonObject().get("operand_text").getAsString());
        assertTrue(units.get(1).getAsJsonObject().get("data_type").isJsonNull());
    }

    @Test
    public void oversizedDefinedUnitDelegatesBytesAndMakesProgress() throws Exception {
        Fixture fixture = fixture(0x2000, 0x3fff);
        fixture.data(0x2000, 0x2000, "blob", "/blob", "<8192 bytes>");

        JsonObject page = ok(fixture.query("2000", "3fff", 1, 256, 100, null));
        JsonObject unit = page.getAsJsonArray("units").get(0).getAsJsonObject();

        assertEquals("2000", unit.get("start").getAsString());
        assertEquals("3fff", unit.get("end").getAsString());
        assertTrue(unit.get("bytes").isJsonNull());
        assertFalse(unit.get("bytes_complete").getAsBoolean());
        assertEquals("2000",
            unit.getAsJsonObject("bytes_request").get("address").getAsString());
        assertEquals(8192,
            unit.getAsJsonObject("bytes_request").get("length").getAsInt());
        assertTrue(page.get("complete").getAsBoolean());
    }

    @Test
    public void paginationUsesWholeUnitsAndCursorBindsEveryLimit() throws Exception {
        Fixture fixture = fixture(0x3000, 0x31ff);
        fixture.data(0x3000, 4, "dword", "/dword", "1");

        JsonObject first = ok(fixture.query("3000", "31ff", 1, 256, 7, null));
        assertFalse(first.get("complete").getAsBoolean());
        assertRange(first.getAsJsonObject("returned_range"), "3000", "3003");
        String cursor = first.get("next_cursor").getAsString();

        JsonObject second = ok(fixture.query("3000", "31ff", 1, 256, 7, cursor));
        assertEquals("3004",
            second.getAsJsonArray("units").get(0).getAsJsonObject().get("start").getAsString());
        assertNoGapsOrOverlaps(second.getAsJsonArray("units"), 0x3004, 0x3103);

        assertErrorContains(fixture.query("3000", "31ff", 2, 256, 7, cursor),
            "limits");
        assertErrorContains(fixture.query("3000", "31ff", 1, 512, 7, cursor),
            "limits");
        assertErrorContains(fixture.query("3000", "31ff", 1, 256, 8, cursor),
            "limits");
    }

    @Test
    public void modificationAfterCursorIssuanceRequiresRetry() throws Exception {
        Fixture fixture = fixture(0x4000, 0x41ff);
        JsonObject first = ok(fixture.query("4000", "41ff", 1, 256, 100, null));
        String cursor = first.get("next_cursor").getAsString();

        fixture.modificationNumber = 12;
        assertErrorContains(fixture.query("4000", "41ff", 1, 256, 100, cursor),
            "program changed");
    }

    @Test
    public void cursorRejectsDifferentBoundsAndProgramIdentity() throws Exception {
        Fixture fixture = fixture(0x4200, 0x43ff);
        JsonObject first = ok(fixture.query("4200", "43ff", 1, 256, 100, null));
        String cursor = first.get("next_cursor").getAsString();

        assertErrorContains(
            fixture.query("4201", "43ff", 1, 256, 100, cursor),
            "bounds");
        fixture.uniqueProgramId++;
        assertErrorContains(
            fixture.query("4200", "43ff", 1, 256, 100, cursor),
            "different program");
    }

    @Test
    public void byteBudgetStopsBeforeDefinedUnitWithoutSplittingIt() throws Exception {
        Fixture fixture = fixture(0x4400, 0x452b);
        fixture.data(0x4400, 200, "first", "/first", "...");
        fixture.data(0x44c8, 100, "second", "/second", "...");

        JsonObject first = ok(fixture.query("4400", "452b", 100, 256, 100, null));
        assertFalse(first.get("complete").getAsBoolean());
        assertEquals(1, first.getAsJsonArray("units").size());
        assertRange(first.getAsJsonObject("returned_range"), "4400", "44c7");

        JsonObject second = ok(fixture.query(
            "4400", "452b", 100, 256, 100,
            first.get("next_cursor").getAsString()));
        assertTrue(second.get("complete").getAsBoolean());
        assertRange(second.getAsJsonObject("returned_range"), "44c8", "452b");
    }

    @Test
    public void uninitializedBytesAreNeverInvented() throws Exception {
        Fixture fixture = fixture(0x5000, 0x5007);
        fixture.initialized = new AddressSet(addr(0x5000), addr(0x5003));

        JsonObject page = ok(fixture.query("5000", "5007", 100, 256, 100, null));
        JsonArray units = page.getAsJsonArray("units");

        assertEquals(2, units.size());
        JsonObject initialized = units.get(0).getAsJsonObject();
        assertTrue(initialized.get("initialized").getAsBoolean());
        assertEquals("00010203", initialized.get("bytes").getAsString());
        JsonObject uninitialized = units.get(1).getAsJsonObject();
        assertFalse(uninitialized.get("initialized").getAsBoolean());
        assertTrue(uninitialized.get("bytes").isJsonNull());
        assertFalse(uninitialized.get("bytes_complete").getAsBoolean());
    }

    @Test
    public void annotationsAndDirectionalReferencesCoverEveryAddressInUnit() throws Exception {
        Fixture fixture = fixture(0x6000, 0x6003);
        fixture.data(0x6000, 4, "blob", "/blob", "...");
        fixture.label(0x6001, "byte_one", "scope", SourceType.USER_DEFINED, true, true);
        fixture.comment(0x6002, CommentType.PLATE, "inside data");
        fixture.outgoing(0x6003, 0x6100, RefType.DATA, SourceType.ANALYSIS, 1);
        fixture.incoming(0x6201, 0x6001, RefType.WRITE, SourceType.IMPORTED, 1);
        fixture.incoming(0x6200, 0x6001, RefType.READ, SourceType.USER_DEFINED, 0);

        JsonObject page = ok(fixture.query("6000", "6003", 100, 256, 1, null));
        JsonObject unit = page.getAsJsonArray("units").get(0).getAsJsonObject();

        JsonObject label = unit.getAsJsonArray("labels").get(0).getAsJsonObject();
        assertEquals("6001", label.get("address").getAsString());
        assertEquals("byte_one", label.get("name").getAsString());
        assertEquals("scope", label.get("namespace").getAsString());
        assertTrue(label.get("primary").getAsBoolean());
        assertTrue(label.get("entry_point").getAsBoolean());
        JsonObject comment = unit.getAsJsonArray("comments").get(0).getAsJsonObject();
        assertEquals("6002", comment.get("address").getAsString());
        assertEquals("plate", comment.get("type").getAsString());
        assertEquals(1, unit.getAsJsonArray("outgoing_references").size());
        assertEquals(1, unit.getAsJsonArray("incoming_references").size());
        assertFalse(unit.get("incoming_references_complete").getAsBoolean());
        assertEquals("6001", unit.get("incoming_references_next_address").getAsString());
        assertEquals(1, unit.get("incoming_references_next_offset").getAsInt());
        assertEquals("6200", unit.getAsJsonArray("incoming_references").get(0)
            .getAsJsonObject().get("source").getAsString());
        Response handoff = fixture.xrefs.getXrefsTo(
            "6001", unit.get("incoming_references_next_offset").getAsInt(),
            1, "fixture");
        assertTrue(handoff.toJson(), handoff.toJson().contains("6201"));
        assertNotNull(unit.getAsJsonArray("incoming_references").get(0)
            .getAsJsonObject().get("id").getAsString());

        String firstId = unit.getAsJsonArray("incoming_references").get(0)
            .getAsJsonObject().get("id").getAsString();
        String repeatedId = ok(fixture.query("6000", "6003", 100, 256, 1, null))
            .getAsJsonArray("units").get(0).getAsJsonObject()
            .getAsJsonArray("incoming_references").get(0).getAsJsonObject()
            .get("id").getAsString();
        assertEquals(firstId, repeatedId);
        fixture.modificationNumber++;
        String changedId = ok(fixture.query("6000", "6003", 100, 256, 1, null))
            .getAsJsonArray("units").get(0).getAsJsonObject()
            .getAsJsonArray("incoming_references").get(0).getAsJsonObject()
            .get("id").getAsString();
        assertNotEquals(firstId, changedId);
    }

    @Test
    public void undefinedUnitsSplitAtAnnotationAndReferenceBoundaries() throws Exception {
        Fixture fixture = fixture(0x7000, 0x7007);
        fixture.comment(0x7002, CommentType.EOL, "boundary");
        fixture.outgoing(0x7005, 0x7100, RefType.DATA, SourceType.ANALYSIS, -1);

        JsonArray units = ok(fixture.query("7000", "7007", 100, 256, 100, null))
            .getAsJsonArray("units");

        assertEquals(List.of("7000", "7002", "7005"), strings(units, "start"));
        assertEquals(List.of("7001", "7004", "7007"), strings(units, "end"));
        assertNoGapsOrOverlaps(units, 0x7000, 0x7007);
    }

    @Test
    public void rejectsUnmappedCrossSpaceAndOutOfRangeBudgets() throws Exception {
        Fixture fixture = fixture(0x8000, 0x80ff);

        assertErrorContains(fixture.query("8000", "8100", 100, 256, 100, null),
            "mapped");
        assertErrorContains(fixture.query("8000", "other:8001", 100, 256, 100, null),
            "address space");
        assertErrorContains(fixture.query("8000", "8001", 0, 256, 100, null),
            "max_units");
        assertErrorContains(fixture.query("8000", "8001", 10001, 256, 100, null),
            "max_units");
        assertErrorContains(fixture.query("8000", "8001", 1, 255, 100, null),
            "max_bytes");
        assertErrorContains(fixture.query("8000", "8001", 1, 1048577, 100, null),
            "max_bytes");
        assertErrorContains(fixture.query("8000", "8001", 1, 256, 0, null),
            "max_incoming_refs_per_unit");
        assertErrorContains(fixture.query("8000", "8001", 1, 256, 10001, null),
            "max_incoming_refs_per_unit");
    }

    @Test
    public void initializedBytesMustBeReadCompletely() throws Exception {
        Fixture fixture = fixture(0x9000, 0x9003);
        fixture.memoryReadLimit = 2;

        assertErrorContains(
            fixture.query("9000", "9003", 100, 256, 100, null),
            "read all initialized bytes");
    }

    private static Fixture fixture(int start, int end) throws Exception {
        return new Fixture(start, end);
    }

    private static Address addr(int offset) {
        return RAM.getAddress(offset);
    }

    private static JsonObject ok(Response response) {
        assertFalse("Expected success, got: " + response.toJson(),
            response instanceof Response.Err);
        return JsonParser.parseString(response.toJson()).getAsJsonObject();
    }

    private static void assertErrorContains(Response response, String expected) {
        assertTrue("Expected error, got: " + response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().toLowerCase().contains(expected.toLowerCase()));
    }

    private static void assertRange(JsonObject range, String start, String end) {
        assertEquals(start, range.get("start").getAsString());
        assertEquals(end, range.get("end").getAsString());
    }

    private static List<String> strings(JsonArray array, String field) {
        List<String> values = new ArrayList<>();
        array.forEach(e -> values.add(e.getAsJsonObject().get(field).getAsString()));
        return values;
    }

    private static void assertNoGapsOrOverlaps(JsonArray units, int start, int end) {
        int expected = start;
        for (var element : units) {
            JsonObject unit = element.getAsJsonObject();
            assertEquals(expected, Integer.parseInt(unit.get("start").getAsString(), 16));
            expected = Integer.parseInt(unit.get("end").getAsString(), 16) + 1;
        }
        assertEquals(end + 1, expected);
    }

    private static final class Fixture {
        final Program program = mock(Program.class);
        final Listing listing = mock(Listing.class);
        final Memory memory = mock(Memory.class);
        final SymbolTable symbols = mock(SymbolTable.class);
        final ReferenceManager references = mock(ReferenceManager.class);
        final FunctionManager functions = mock(FunctionManager.class);
        final AddressFactory addresses = mock(AddressFactory.class);
        final Map<Integer, Instruction> instructions = new HashMap<>();
        final Map<Integer, Data> data = new HashMap<>();
        final Map<Integer, List<Symbol>> labels = new HashMap<>();
        final Map<Integer, Map<CommentType, String>> comments = new HashMap<>();
        final Map<Integer, List<Reference>> outgoing = new HashMap<>();
        final Map<Integer, List<Reference>> incoming = new HashMap<>();
        final ListingRangeService service;
        final XrefCallGraphService xrefs;
        final ProgramProvider provider = mock(ProgramProvider.class);
        long modificationNumber = 11;
        long uniqueProgramId = 0x1234L;
        int memoryReadLimit = -1;
        AddressSet initialized;

        Fixture(int start, int end) throws Exception {
            Address min = addr(start);
            Address max = addr(end);
            initialized = new AddressSet(min, max);
            when(program.getName()).thenReturn("fixture");
            when(program.getUniqueProgramID()).thenAnswer(invocation -> uniqueProgramId);
            when(program.getModificationNumber()).thenAnswer(invocation -> modificationNumber);
            when(program.getAddressFactory()).thenReturn(addresses);
            when(program.getListing()).thenReturn(listing);
            when(program.getMemory()).thenReturn(memory);
            when(program.getSymbolTable()).thenReturn(symbols);
            when(program.getReferenceManager()).thenReturn(references);
            when(program.getFunctionManager()).thenReturn(functions);
            when(addresses.getAddress(anyString())).thenAnswer(invocation -> {
                String text = invocation.getArgument(0);
                String space = "ram";
                String offset = text;
                int colon = text.lastIndexOf(':');
                if (colon >= 0) {
                    space = text.substring(0, text.indexOf(':'));
                    offset = text.substring(colon + 1);
                }
                return ("other".equals(space) ? OTHER : RAM)
                    .getAddress(Long.parseLong(offset.replaceFirst("(?i)^0x", ""), 16));
            });
            when(memory.contains(any(Address.class), any(Address.class))).thenAnswer(invocation -> {
                Address a = invocation.getArgument(0);
                Address b = invocation.getArgument(1);
                return a.getAddressSpace().equals(RAM)
                    && b.getAddressSpace().equals(RAM)
                    && a.compareTo(min) >= 0 && b.compareTo(max) <= 0;
            });
            when(memory.getAllInitializedAddressSet()).thenAnswer(invocation -> initialized);
            when(memory.getBytes(any(Address.class), any(byte[].class))).thenAnswer(invocation -> {
                Address at = invocation.getArgument(0);
                byte[] target = invocation.getArgument(1);
                for (int i = 0; i < target.length; i++) {
                    target[i] = (byte) (at.getOffset() + i);
                }
                return memoryReadLimit < 0
                    ? target.length : Math.min(target.length, memoryReadLimit);
            });
            when(listing.getInstructionContaining(any(Address.class))).thenAnswer(invocation ->
                containing(instructions, invocation.getArgument(0)));
            when(listing.getDefinedDataContaining(any(Address.class))).thenAnswer(invocation ->
                containing(data, invocation.getArgument(0)));
            when(symbols.getSymbols(any(Address.class))).thenAnswer(invocation ->
                labels.getOrDefault(offset(invocation.getArgument(0)), List.of())
                    .toArray(Symbol[]::new));
            when(symbols.hasSymbol(any(Address.class))).thenAnswer(invocation ->
                !labels.getOrDefault(offset(invocation.getArgument(0)), List.of()).isEmpty());
            when(symbols.isExternalEntryPoint(any(Address.class))).thenAnswer(invocation ->
                labels.getOrDefault(offset(invocation.getArgument(0)), List.of()).stream()
                    .anyMatch(Symbol::isExternalEntryPoint));
            when(listing.getComment(any(CommentType.class), any(Address.class)))
                .thenAnswer(invocation -> comments
                    .getOrDefault(offset(invocation.getArgument(1)), Map.of())
                    .get(invocation.getArgument(0)));
            when(references.getReferencesFrom(any(Address.class))).thenAnswer(invocation ->
                outgoing.getOrDefault(offset(invocation.getArgument(0)), List.of())
                    .toArray(Reference[]::new));
            when(references.hasReferencesFrom(any(Address.class))).thenAnswer(invocation ->
                !outgoing.getOrDefault(offset(invocation.getArgument(0)), List.of()).isEmpty());
            when(references.hasReferencesTo(any(Address.class))).thenAnswer(invocation ->
                !incoming.getOrDefault(offset(invocation.getArgument(0)), List.of()).isEmpty());
            when(references.getReferencesTo(any(Address.class))).thenAnswer(invocation ->
                iterator(incoming.getOrDefault(offset(invocation.getArgument(0)), List.of())));
            when(provider.getCurrentProgram()).thenReturn(program);
            when(provider.getProgram("fixture")).thenReturn(program);
            when(provider.getAllOpenPrograms()).thenReturn(new Program[] { program });
            service = new ListingRangeService(provider);
            xrefs = new XrefCallGraphService(
                provider, new com.xebyte.headless.DirectThreadingStrategy());
        }

        Response query(String start, String end, int maxUnits, int maxBytes,
                int maxIncoming, String cursor) {
            return service.getListingRange(
                start, end, maxUnits, maxBytes, maxIncoming, cursor, "fixture");
        }

        void instruction(int start, int length, String mnemonic, String operands) throws Exception {
            Instruction unit = mock(Instruction.class);
            when(unit.getMinAddress()).thenReturn(addr(start));
            when(unit.getMaxAddress()).thenReturn(addr(start + length - 1));
            when(unit.getLength()).thenReturn(length);
            when(unit.getMnemonicString()).thenReturn(mnemonic);
            when(unit.getNumOperands()).thenReturn(operands.isEmpty() ? 0 : 1);
            when(unit.getDefaultOperandRepresentation(0)).thenReturn(operands);
            FlowType flow = mock(FlowType.class);
            when(flow.getName()).thenReturn("FALL_THROUGH");
            when(unit.getFlowType()).thenReturn(flow);
            when(unit.getFallThrough()).thenReturn(addr(start + length));
            when(unit.getFlows()).thenReturn(new Address[0]);
            instructions.put(start, unit);
        }

        void data(int start, int length, String name, String path, String representation) {
            Data unit = mock(Data.class);
            when(unit.getMinAddress()).thenReturn(addr(start));
            when(unit.getMaxAddress()).thenReturn(addr(start + length - 1));
            when(unit.getLength()).thenReturn(length);
            when(unit.getDefaultValueRepresentation()).thenReturn(representation);
            data.put(start, unit);
        }

        void label(int at, String name, String namespace, SourceType source,
                boolean primary, boolean entryPoint) {
            Symbol symbol = mock(Symbol.class);
            Namespace parent = mock(Namespace.class);
            when(symbol.getAddress()).thenReturn(addr(at));
            when(symbol.getName()).thenReturn(name);
            when(symbol.getParentNamespace()).thenReturn(parent);
            when(parent.getName(true)).thenReturn(namespace);
            when(symbol.getSource()).thenReturn(source);
            when(symbol.isPrimary()).thenReturn(primary);
            when(symbol.isExternalEntryPoint()).thenReturn(entryPoint);
            labels.computeIfAbsent(at, ignored -> new ArrayList<>()).add(symbol);
        }

        void comment(int at, CommentType type, String text) {
            comments.computeIfAbsent(at, ignored -> new HashMap<>()).put(type, text);
        }

        void outgoing(int from, int to, RefType type, SourceType source, int operand) {
            outgoing.computeIfAbsent(from, ignored -> new ArrayList<>())
                .add(reference(from, to, type, source, operand));
        }

        void incoming(int from, int to, RefType type, SourceType source, int operand) {
            incoming.computeIfAbsent(to, ignored -> new ArrayList<>())
                .add(reference(from, to, type, source, operand));
        }

        private Reference reference(int from, int to, RefType type,
                SourceType source, int operand) {
            Reference reference = mock(Reference.class);
            when(reference.getFromAddress()).thenReturn(addr(from));
            when(reference.getToAddress()).thenReturn(addr(to));
            when(reference.getReferenceType()).thenReturn(type);
            when(reference.getSource()).thenReturn(source);
            when(reference.getOperandIndex()).thenReturn(operand);
            return reference;
        }

        private static <T> T containing(Map<Integer, T> starts, Address address) {
            long at = address.getOffset();
            for (T candidate : starts.values()) {
                ghidra.program.model.listing.CodeUnit unit =
                    (ghidra.program.model.listing.CodeUnit) candidate;
                if (unit.getMinAddress().getOffset() <= at
                        && unit.getMaxAddress().getOffset() >= at) {
                    return candidate;
                }
            }
            return null;
        }

        private static int offset(Address address) {
            return (int) address.getOffset();
        }

        private static ReferenceIterator iterator(List<Reference> refs) {
            Iterator<Reference> delegate = refs.iterator();
            return new ReferenceIterator() {
                @Override public boolean hasNext() { return delegate.hasNext(); }
                @Override public Reference next() { return delegate.next(); }
                @Override public Iterator<Reference> iterator() { return this; }
            };
        }
    }
}
