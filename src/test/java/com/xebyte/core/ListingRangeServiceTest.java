package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atMost;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
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
import ghidra.program.model.symbol.SymbolIterator;
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
        assertEquals("word[3]",
            units.get(1).getAsJsonObject().get("data_type").getAsString());
        assertEquals("/word[3]",
            units.get(1).getAsJsonObject().get("data_type_path").getAsString());
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

        ListingRangeService secondService =
            new ListingRangeService(fixture.provider, fixture.threading);
        JsonObject second = ok(secondService.getListingRange(
            "3000", "31ff", 1, 256, 7, cursor, "fixture"));
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
    public void cursorIntegrityRejectsForwardBackwardAndMidSyntheticTampering()
            throws Exception {
        Fixture fixture = fixture(0x4200, 0x43ff);
        fixture.data(0x4200, 4, "head", "/head", "...");
        String cursor = ok(fixture.query("4200", "43ff", 1, 256, 100, null))
            .get("next_cursor").getAsString();

        assertErrorContains(fixture.query(
            "4200", "43ff", 1, 256, 100,
            tamperPayload(cursor, json -> json.addProperty("next_address", "4300"))),
            "integrity");
        assertErrorContains(fixture.query(
            "4200", "43ff", 1, 256, 100,
            tamperPayload(cursor, json -> json.addProperty("next_address", "4200"))),
            "integrity");
        assertErrorContains(fixture.query(
            "4200", "43ff", 1, 256, 100,
            tamperPayload(cursor, json -> json.addProperty("next_address", "4205"))),
            "integrity");
    }

    @Test
    public void cursorIntegrityRejectsPayloadAndMacTampering() throws Exception {
        Fixture fixture = fixture(0x4300, 0x44ff);
        String cursor = ok(fixture.query("4300", "44ff", 1, 256, 100, null))
            .get("next_cursor").getAsString();

        assertErrorContains(fixture.query(
            "4300", "44ff", 1, 256, 100,
            tamperPayload(cursor, json -> json.addProperty("max_bytes", 512))),
            "integrity");
        assertErrorContains(fixture.query(
            "4300", "44ff", 1, 256, 100, tamperMac(cursor)),
            "integrity");
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
    public void incomingContinuationIsDestinationGroupedAndLossless() throws Exception {
        Fixture fixture = fixture(0xa000, 0xa003);
        fixture.data(0xa000, 4, "blob", "/blob", "...");
        fixture.incoming(0xb003, 0xa001, RefType.READ, SourceType.ANALYSIS, 0);
        fixture.incoming(0xb001, 0xa001, RefType.READ, SourceType.ANALYSIS, 0);
        fixture.incoming(0xb004, 0xa002, RefType.READ, SourceType.ANALYSIS, 0);
        fixture.incoming(0xb000, 0xa002, RefType.READ, SourceType.ANALYSIS, 0);
        fixture.incoming(0xb002, 0xa002, RefType.READ, SourceType.ANALYSIS, 0);

        JsonObject unit = ok(fixture.query("a000", "a003", 100, 256, 3, null))
            .getAsJsonArray("units").get(0).getAsJsonObject();
        JsonArray listed = unit.getAsJsonArray("incoming_references");

        assertEquals(List.of("a001", "a001", "a002"),
            strings(listed, "destination"));
        assertEquals(List.of("b001", "b003", "b000"),
            strings(listed, "source"));
        assertEquals("a002",
            unit.get("incoming_references_next_address").getAsString());
        assertEquals(1, unit.get("incoming_references_next_offset").getAsInt());

        Response handoff = fixture.xrefs.getXrefsTo("a002", 1, 10, "fixture");
        String continuation = handoff.toJson();
        assertFalse(continuation, continuation.contains("b000"));
        assertTrue(continuation, continuation.contains("b002"));
        assertTrue(continuation, continuation.contains("b004"));
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
    public void dynamicLabelsAtReferenceDestinationsAreIndexedWithoutByteScan()
            throws Exception {
        Fixture fixture = fixture(0x7100, 0x7107);
        fixture.incoming(0x7200, 0x7103, RefType.READ, SourceType.ANALYSIS, 0);
        fixture.dynamicLabel(
            0x7103, "LAB_7103", "Global", SourceType.DEFAULT, true, false);

        JsonArray units = ok(fixture.query("7100", "7107", 100, 256, 100, null))
            .getAsJsonArray("units");
        JsonObject boundary = units.get(1).getAsJsonObject();

        assertEquals("7103", boundary.get("start").getAsString());
        assertEquals("LAB_7103",
            boundary.getAsJsonArray("labels").get(0).getAsJsonObject()
                .get("name").getAsString());
        verify(fixture.symbols).getSymbols(addr(0x7103));
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

    @Test
    public void completeAuthoritativeReadRunsInsideOneThreadingRead()
            throws Exception {
        RecordingThreadingStrategy threading = new RecordingThreadingStrategy();
        Fixture fixture = new Fixture(0x9100, 0x91ff, threading);
        fixture.requireThreadedModelAccess = true;

        JsonObject page = ok(fixture.query("9100", "91ff", 10, 256, 100, null));

        assertTrue(page.get("complete").getAsBoolean());
        assertEquals(1, threading.readCalls.get());
        assertTrue("modification snapshot must be the first model access",
            fixture.modificationReadWasFirst.get());
    }

    @Test
    public void mutationDuringReadReturnsRetryAndNeverReturnsShiftedUnits()
            throws Exception {
        RecordingThreadingStrategy threading = new RecordingThreadingStrategy();
        Fixture fixture = new Fixture(0x9200, 0x92ff, threading);
        fixture.data(0x9200, 4, "head", "/head", "...");

        JsonObject stable =
            ok(fixture.query("9201", "92ff", 10, 256, 100, null));
        String returnedStart =
            stable.getAsJsonObject("returned_range").get("start").getAsString();
        for (var element : stable.getAsJsonArray("units")) {
            assertTrue(element.getAsJsonObject().get("start").getAsString()
                .compareTo(returnedStart) >= 0);
        }

        fixture.mutateAfterMemoryRead = true;

        Response response = fixture.query("9201", "92ff", 10, 256, 100, null);

        assertErrorContains(response, "program changed");
    }

    @Test
    public void sparse64KiBRangeUsesBoundedIndexesInsteadOfPerByteLookups()
            throws Exception {
        Fixture fixture = fixture(0x0000, 0xffff);

        JsonObject page = ok(
            fixture.query("0000", "ffff", 10, 1_048_576, 100, null));

        assertTrue(page.get("complete").getAsBoolean());
        assertEquals(1, page.getAsJsonArray("units").size());
        verify(fixture.listing, atMost(10)).getInstructionContaining(any(Address.class));
        verify(fixture.listing, atMost(10)).getDefinedDataContaining(any(Address.class));
        verify(fixture.symbols, atMost(10)).getSymbols(any(Address.class));
        for (CommentType type : CommentType.values()) {
            verify(fixture.listing, atMost(10))
                .getComment(any(CommentType.class), any(Address.class));
        }
        verify(fixture.references, atMost(10)).hasReferencesFrom(any(Address.class));
        verify(fixture.references, atMost(10)).hasReferencesTo(any(Address.class));
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

    private static String tamperPayload(
            String cursor, Consumer<JsonObject> mutation) {
        String[] parts = cursor.split("\\.", -1);
        JsonObject payload = JsonParser.parseString(new String(
            Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8))
            .getAsJsonObject();
        mutation.accept(payload);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(
            payload.toString().getBytes(StandardCharsets.UTF_8));
        return encoded + "." + parts[1];
    }

    private static String tamperMac(String cursor) {
        String[] parts = cursor.split("\\.", -1);
        char first = parts[1].charAt(0);
        char replacement = first == 'A' ? 'B' : 'A';
        return parts[0] + "." + replacement + parts[1].substring(1);
    }

    private static final class RecordingThreadingStrategy
            implements ThreadingStrategy {
        final AtomicBoolean inRead = new AtomicBoolean();
        final AtomicInteger readCalls = new AtomicInteger();

        @Override
        public <T> T executeRead(Callable<T> action) throws Exception {
            readCalls.incrementAndGet();
            inRead.set(true);
            try {
                return action.call();
            }
            finally {
                inRead.set(false);
            }
        }

        @Override
        public <T> T executeWrite(
                Program program, String txName, Callable<T> action) throws Exception {
            return action.call();
        }

        @Override
        public boolean isHeadless() {
            return true;
        }
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
        final Map<Data, ListingRangeService.DataMetadata> dataMetadata =
            new HashMap<>();
        final Map<Integer, List<Symbol>> labels = new HashMap<>();
        final Map<Integer, List<Symbol>> dynamicLabels = new HashMap<>();
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
        final RecordingThreadingStrategy threading;
        boolean requireThreadedModelAccess;
        boolean mutateAfterMemoryRead;
        final AtomicInteger modelAccesses = new AtomicInteger();
        final AtomicBoolean modificationReadWasFirst = new AtomicBoolean();

        Fixture(int start, int end) throws Exception {
            this(start, end, new RecordingThreadingStrategy());
        }

        Fixture(int start, int end, RecordingThreadingStrategy threading)
                throws Exception {
            this.threading = threading;
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
                assertModelAccess();
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
                assertModelAccess();
                Address a = invocation.getArgument(0);
                Address b = invocation.getArgument(1);
                return a.getAddressSpace().equals(RAM)
                    && b.getAddressSpace().equals(RAM)
                    && a.compareTo(min) >= 0 && b.compareTo(max) <= 0;
            });
            when(memory.getAllInitializedAddressSet()).thenAnswer(invocation -> {
                assertModelAccess();
                return initialized;
            });
            when(memory.getBytes(any(Address.class), any(byte[].class))).thenAnswer(invocation -> {
                assertModelAccess();
                Address at = invocation.getArgument(0);
                byte[] target = invocation.getArgument(1);
                for (int i = 0; i < target.length; i++) {
                    target[i] = (byte) (at.getOffset() + i);
                }
                if (mutateAfterMemoryRead) {
                    modificationNumber++;
                }
                return memoryReadLimit < 0
                    ? target.length : Math.min(target.length, memoryReadLimit);
            });
            when(listing.getInstructionContaining(any(Address.class))).thenAnswer(invocation -> {
                assertModelAccess();
                return containing(instructions, invocation.getArgument(0));
            });
            when(listing.getDefinedDataContaining(any(Address.class))).thenAnswer(invocation -> {
                assertModelAccess();
                return containing(data, invocation.getArgument(0));
            });
            when(listing.getCodeUnits(any(AddressSetView.class), eq(true)))
                .thenAnswer(invocation -> {
                    assertModelAccess();
                    AddressSetView requested = invocation.getArgument(0);
                    List<CodeUnit> units = new ArrayList<>();
                    instructions.values().stream()
                        .filter(unit -> requested.contains(unit.getMinAddress()))
                        .forEach(units::add);
                    data.values().stream()
                        .filter(unit -> requested.contains(unit.getMinAddress()))
                        .forEach(units::add);
                    units.sort(java.util.Comparator.comparing(CodeUnit::getMinAddress));
                    return codeUnitIterator(units);
                });
            when(symbols.getSymbols(any(Address.class))).thenAnswer(invocation -> {
                assertModelAccess();
                int at = offset(invocation.getArgument(0));
                List<Symbol> combined = new ArrayList<>(
                    labels.getOrDefault(at, List.of()));
                combined.addAll(dynamicLabels.getOrDefault(at, List.of()));
                return combined.toArray(Symbol[]::new);
            });
            when(symbols.getSymbolIterator(any(Address.class), eq(true)))
                .thenAnswer(invocation -> {
                    assertModelAccess();
                    Address requestedStart = invocation.getArgument(0);
                    List<Symbol> ordered = labels.values().stream()
                        .flatMap(List::stream)
                        .filter(symbol ->
                            symbol.getAddress().compareTo(requestedStart) >= 0)
                        .sorted(java.util.Comparator
                            .comparing(Symbol::getAddress)
                            .thenComparing(symbol -> symbol.getName()))
                        .toList();
                    return symbolIterator(ordered);
                });
            when(symbols.hasSymbol(any(Address.class))).thenAnswer(invocation ->
                !allLabelsAt(offset(invocation.getArgument(0))).isEmpty());
            when(symbols.isExternalEntryPoint(any(Address.class))).thenAnswer(invocation -> {
                assertModelAccess();
                return allLabelsAt(offset(invocation.getArgument(0))).stream()
                    .anyMatch(Symbol::isExternalEntryPoint);
            });
            when(listing.getComment(any(CommentType.class), any(Address.class)))
                .thenAnswer(invocation -> {
                    assertModelAccess();
                    return comments
                        .getOrDefault(offset(invocation.getArgument(1)), Map.of())
                        .get(invocation.getArgument(0));
                });
            when(listing.getCommentAddressIterator(
                    any(AddressSetView.class), eq(true)))
                .thenAnswer(invocation -> {
                    assertModelAccess();
                    AddressSetView requested = invocation.getArgument(0);
                    List<Address> ordered = comments.keySet().stream()
                        .map(ListingRangeServiceTest::addr)
                        .filter(requested::contains)
                        .sorted()
                        .toList();
                    return addressIterator(ordered);
                });
            when(references.getReferencesFrom(any(Address.class))).thenAnswer(invocation -> {
                assertModelAccess();
                return outgoing.getOrDefault(offset(invocation.getArgument(0)), List.of())
                    .toArray(Reference[]::new);
            });
            when(references.hasReferencesFrom(any(Address.class))).thenAnswer(invocation ->
                !outgoing.getOrDefault(offset(invocation.getArgument(0)), List.of()).isEmpty());
            when(references.hasReferencesTo(any(Address.class))).thenAnswer(invocation ->
                !incoming.getOrDefault(offset(invocation.getArgument(0)), List.of()).isEmpty());
            when(references.getReferencesTo(any(Address.class))).thenAnswer(invocation -> {
                assertModelAccess();
                return iterator(
                    incoming.getOrDefault(offset(invocation.getArgument(0)), List.of()));
            });
            when(references.getReferenceSourceIterator(
                    any(AddressSetView.class), eq(true)))
                .thenAnswer(invocation -> {
                    assertModelAccess();
                    AddressSetView requested = invocation.getArgument(0);
                    return addressIterator(outgoing.keySet().stream()
                        .map(ListingRangeServiceTest::addr)
                        .filter(requested::contains)
                        .sorted()
                        .toList());
                });
            when(references.getReferenceDestinationIterator(
                    any(AddressSetView.class), eq(true)))
                .thenAnswer(invocation -> {
                    assertModelAccess();
                    AddressSetView requested = invocation.getArgument(0);
                    return addressIterator(incoming.keySet().stream()
                        .map(ListingRangeServiceTest::addr)
                        .filter(requested::contains)
                        .sorted()
                        .toList());
                });
            when(provider.getCurrentProgram()).thenReturn(program);
            when(provider.getProgram("fixture")).thenReturn(program);
            when(provider.getAllOpenPrograms()).thenReturn(new Program[] { program });
            service = new ListingRangeService(
                provider, threading,
                unit -> dataMetadata.getOrDefault(
                    unit, new ListingRangeService.DataMetadata(null, null)));
            xrefs = new XrefCallGraphService(
                provider, new com.xebyte.headless.DirectThreadingStrategy());

            when(program.getModificationNumber()).thenAnswer(invocation -> {
                assertModelAccess();
                modificationReadWasFirst.compareAndSet(
                    false, modelAccesses.get() == 1);
                return modificationNumber;
            });
            when(program.getAddressFactory()).thenAnswer(invocation -> {
                assertModelAccess();
                return addresses;
            });
            when(program.getMemory()).thenAnswer(invocation -> {
                assertModelAccess();
                return memory;
            });
            when(program.getListing()).thenAnswer(invocation -> {
                assertModelAccess();
                return listing;
            });
            when(program.getSymbolTable()).thenAnswer(invocation -> {
                assertModelAccess();
                return symbols;
            });
            when(program.getReferenceManager()).thenAnswer(invocation -> {
                assertModelAccess();
                return references;
            });
            when(program.getUniqueProgramID()).thenAnswer(invocation -> {
                assertModelAccess();
                return uniqueProgramId;
            });
            when(program.getName()).thenAnswer(invocation -> {
                assertModelAccess();
                return "fixture";
            });
        }

        private void assertModelAccess() {
            modelAccesses.incrementAndGet();
            if (requireThreadedModelAccess) {
                assertTrue("program model access escaped executeRead", threading.inRead.get());
            }
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
            dataMetadata.put(
                unit, new ListingRangeService.DataMetadata(name, path));
        }

        void label(int at, String name, String namespace, SourceType source,
                boolean primary, boolean entryPoint) {
            labelInto(
                labels, at, name, namespace, source, primary, entryPoint);
        }

        void dynamicLabel(int at, String name, String namespace, SourceType source,
                boolean primary, boolean entryPoint) {
            labelInto(
                dynamicLabels, at, name, namespace, source, primary, entryPoint);
        }

        private void labelInto(
                Map<Integer, List<Symbol>> destination,
                int at,
                String name,
                String namespace,
                SourceType source,
                boolean primary,
                boolean entryPoint) {
            Symbol symbol = mock(Symbol.class);
            Namespace parent = mock(Namespace.class);
            when(symbol.getAddress()).thenReturn(addr(at));
            when(symbol.getName()).thenReturn(name);
            when(symbol.getParentNamespace()).thenReturn(parent);
            when(parent.getName(true)).thenReturn(namespace);
            when(symbol.getSource()).thenReturn(source);
            when(symbol.isPrimary()).thenReturn(primary);
            when(symbol.isExternalEntryPoint()).thenReturn(entryPoint);
            destination.computeIfAbsent(at, ignored -> new ArrayList<>()).add(symbol);
        }

        private List<Symbol> allLabelsAt(int at) {
            List<Symbol> combined =
                new ArrayList<>(labels.getOrDefault(at, List.of()));
            combined.addAll(dynamicLabels.getOrDefault(at, List.of()));
            return combined;
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

        private static CodeUnitIterator codeUnitIterator(List<CodeUnit> units) {
            Iterator<CodeUnit> delegate = units.iterator();
            return new CodeUnitIterator() {
                @Override public boolean hasNext() { return delegate.hasNext(); }
                @Override public CodeUnit next() { return delegate.next(); }
                @Override public Iterator<CodeUnit> iterator() { return this; }
            };
        }

        private static SymbolIterator symbolIterator(List<Symbol> symbols) {
            Iterator<Symbol> delegate = symbols.iterator();
            return new SymbolIterator() {
                @Override public boolean hasNext() { return delegate.hasNext(); }
                @Override public Symbol next() { return delegate.next(); }
                @Override public Iterator<Symbol> iterator() { return this; }
            };
        }

        private static AddressIterator addressIterator(List<Address> addresses) {
            Iterator<Address> delegate = addresses.iterator();
            return new AddressIterator() {
                @Override public boolean hasNext() { return delegate.hasNext(); }
                @Override public Address next() { return delegate.next(); }
            };
        }
    }
}
