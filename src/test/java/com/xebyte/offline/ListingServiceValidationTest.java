package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.ListingService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import junit.framework.TestCase;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.mockito.Mockito.*;

/**
 * Coverage for ListingService (previously no behavioral tests). convert_number is a pure
 * utility (no program needed) and is exercised functionally; the program-scoped listers are
 * checked for graceful "No program loaded" degradation.
 */
public class ListingServiceValidationTest extends TestCase {

    private ListingService listing;

    @Override
    protected void setUp() {
        listing = new ListingService(ServiceFactory.stubProvider());
    }

    // --- convert_number: pure utility, works with no program ---

    public void testConvertNumberDecimalProducesHex() {
        Response r = listing.convertNumber("255", 4);
        assertTrue(r instanceof Response.Text);
        String out = ((Response.Text) r).content().toLowerCase();
        assertTrue("expected hex ff in conversion of 255, got: " + out, out.contains("ff"));
    }

    public void testConvertNumberHexInputAccepted() {
        Response r = listing.convertNumber("0x10", 4);
        assertTrue(r instanceof Response.Text);
        String out = ((Response.Text) r).content();
        assertTrue("expected decimal 16 in conversion of 0x10, got: " + out, out.contains("16"));
    }

    public void testConvertNumberEmptyReports() {
        Response r = listing.convertNumber("", 4);
        assertTrue(r instanceof Response.Text);
        assertTrue(((Response.Text) r).content().contains("No number provided"));
    }

    // --- program-scoped listers degrade gracefully with no program ---

    private static void assertNoProgram(Response r) {
        assertNotNull(r);
        assertTrue("expected 'No program loaded', got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }

    public void testGetFunctionCountDegradesGracefully() {
        assertNoProgram(listing.getFunctionCount(""));
    }

    public void testSearchStringsDegradesGracefully() {
        assertNoProgram(listing.searchStrings("pattern", 4, "", 0, 100, ""));
    }

    public void testSearchFunctionsByNameDegradesGracefully() {
        assertNoProgram(listing.searchFunctionsByName("Foo", 0, 100, ""));
    }

    public void testListImportsDegradesGracefully() {
        assertNoProgram(listing.listImports(0, 100, ""));
    }

    public void testListingFilterAxesAndFormatRejectUnknownValues() {
        ListingService service = serviceFor(emptyProgram());

        assertErrorContains(
            service.listGlobals(0, 100, "DAT_", "all", 1, true, "", ""),
            "filter", "all", "defined", "undefined");
        assertErrorContains(
            service.listGlobals(0, 100, "all", " ", 1, true, "", ""),
            "type_filter", "all", "defined", "undefined");
        assertErrorContains(
            service.listDataItemsByXrefs(
                0, 100, "yaml", "all", "all", 1, true, ""),
            "format", "text", "json");
        assertErrorContains(
            service.listDataItemsByXrefs(
                0, 100, "text", "all", "typed", 1, true, ""),
            "type_filter", "all", "defined", "undefined");
    }

    @SuppressWarnings("unchecked")
    public void testCaseInsensitiveFiltersAndEmptyResultsAreObservable() {
        ListingService service = serviceFor(emptyProgram());

        Response globals = service.listGlobals(
            0, 100, "ALL", "UNDEFINED", 1, true, "", "");
        Response dataText = service.listDataItemsByXrefs(
            0, 100, "TEXT", "ALL", "ALL", 1, true, "");
        Response dataJson = service.listDataItemsByXrefs(
            0, 100, "JSON", "ALL", "ALL", 1, true, "");

        assertEquals("No matching globals",
            ((Response.Text) globals).content());
        assertEquals("No matching data items",
            ((Response.Text) dataText).content());
        assertTrue(dataJson instanceof Response.Ok);
        assertTrue(((List<Map<String, Object>>) ((Response.Ok) dataJson).data())
            .isEmpty());
    }

    public void testExhaustedTextPagesUseNoMatchSentinels() {
        ListingService globals = serviceFor(oneGlobalProgram());
        ListingService dataItems = serviceFor(oneDataItemProgram());

        Response globalPage = globals.listGlobals(
            1, 100, "defined", "all", 1, true, "", "");
        Response dataPage = dataItems.listDataItemsByXrefs(
            1, 100, "text", "defined", "all", 1, true, "");

        assertEquals("No matching globals",
            ((Response.Text) globalPage).content());
        assertEquals("No matching data items",
            ((Response.Text) dataPage).content());
    }

    public void testListingSchemaPinsAxesDefaultsAndFlatMemoryGuidance() {
        Map<String, AnnotationScanner.ToolDescriptor> tools =
            new AnnotationScanner(
                ServiceFactory.stubProvider(), ServiceFactory.buildAllServices())
                .getDescriptors().stream()
                .collect(Collectors.toMap(
                    AnnotationScanner.ToolDescriptor::path,
                    Function.identity()));
        AnnotationScanner.ToolDescriptor globals = tools.get("/list_globals");
        AnnotationScanner.ToolDescriptor data =
            tools.get("/list_data_items_by_xrefs");
        Map<String, AnnotationScanner.ParamDescriptor> globalParams =
            globals.params().stream().collect(Collectors.toMap(
                AnnotationScanner.ParamDescriptor::name, Function.identity()));
        Map<String, AnnotationScanner.ParamDescriptor> dataParams =
            data.params().stream().collect(Collectors.toMap(
                AnnotationScanner.ParamDescriptor::name, Function.identity()));

        assertEquals("all", globalParams.get("filter").defaultValue());
        assertEquals("all", globalParams.get("type_filter").defaultValue());
        assertEquals("defined", dataParams.get("filter").defaultValue());
        assertEquals("all", dataParams.get("type_filter").defaultValue());
        assertFalse(globals.description().contains("filter=named"));
        assertTrue(globalParams.get("include_all_sections").description()
            .contains("flat executable memory snapshots"));
        assertTrue(dataParams.get("include_all_sections").description()
            .contains("flat executable memory snapshots"));
    }

    @SuppressWarnings("unchecked")
    public void testListExternalLocationsHandlesNullExternalAddress() {
        Program program = mock(Program.class);
        ExternalManager extMgr = mock(ExternalManager.class);
        ExternalLocation loc = mock(ExternalLocation.class);
        ExternalLocationIterator iter = mock(ExternalLocationIterator.class);
        ProgramProvider provider = mock(ProgramProvider.class);

        when(provider.getCurrentProgram()).thenReturn(program);
        when(program.getExternalManager()).thenReturn(extMgr);
        when(extMgr.getExternalLibraryNames()).thenReturn(new String[]{"liblog.so"});
        when(extMgr.getExternalLocations("liblog.so")).thenReturn(iter);
        when(iter.hasNext()).thenReturn(true, false);
        when(iter.next()).thenReturn(loc);
        when(loc.getLabel()).thenReturn("__android_log_write");
        when(loc.getAddress()).thenReturn(null);
        when(loc.getOriginalImportedName()).thenReturn("__android_log_write");

        ListingService svc = new ListingService(provider);
        Response r = svc.listExternalLocations(0, 10, "");

        assertTrue(r instanceof Response.Ok);
        List<Map<String, Object>> data = (List<Map<String, Object>>) ((Response.Ok) r).data();
        assertEquals(1, data.size());
        assertEquals("liblog.so", data.get(0).get("library"));
        assertEquals("__android_log_write", data.get(0).get("name"));
        assertTrue(data.get(0).containsKey("address"));
        assertNull(data.get(0).get("address"));
    }

    private static void assertErrorContains(
            Response response, String... fragments) {
        assertTrue(response.toJson(), response instanceof Response.Err);
        for (String fragment : fragments) {
            assertTrue(response.toJson(),
                response.toJson().contains(fragment));
        }
    }

    private static ListingService serviceFor(Program program) {
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(program);
        when(provider.getAllOpenPrograms()).thenReturn(
            new Program[] { program });
        return new ListingService(provider);
    }

    private static Program emptyProgram() {
        Program program = mock(Program.class);
        Memory memory = mock(Memory.class);
        Listing listing = mock(Listing.class);
        FunctionManager functions = mock(FunctionManager.class);
        ReferenceManager references = mock(ReferenceManager.class);
        SymbolTable symbols = mock(SymbolTable.class);
        Namespace global = mock(Namespace.class);
        SymbolIterator iterator = mock(SymbolIterator.class);

        when(program.getMemory()).thenReturn(memory);
        when(program.getListing()).thenReturn(listing);
        when(program.getFunctionManager()).thenReturn(functions);
        when(program.getReferenceManager()).thenReturn(references);
        when(program.getSymbolTable()).thenReturn(symbols);
        when(program.getGlobalNamespace()).thenReturn(global);
        when(memory.getBlocks()).thenReturn(new MemoryBlock[0]);
        when(symbols.getSymbols(global)).thenReturn(iterator);
        when(iterator.hasNext()).thenReturn(false);
        return program;
    }

    private static Program oneDataItemProgram() {
        Program program = emptyProgram();
        Memory memory = program.getMemory();
        Listing listing = program.getListing();
        ReferenceManager references = program.getReferenceManager();
        SymbolTable symbols = program.getSymbolTable();
        MemoryBlock block = mock(MemoryBlock.class);
        Address address = mock(Address.class);
        DataIterator iterator = mock(DataIterator.class);
        Data data = mock(Data.class);
        Symbol symbol = mock(Symbol.class);

        when(memory.getBlocks()).thenReturn(new MemoryBlock[] { block });
        when(block.isExecute()).thenReturn(false);
        when(block.getName()).thenReturn("data");
        when(block.getStart()).thenReturn(address);
        when(block.contains(address)).thenReturn(true);
        when(listing.getDefinedData(address, true)).thenReturn(iterator);
        when(iterator.hasNext()).thenReturn(true, false);
        when(iterator.next()).thenReturn(data);
        when(data.getAddress()).thenReturn(address);
        when(data.getLength()).thenReturn(1);
        when(symbols.getPrimarySymbol(address)).thenReturn(symbol);
        when(symbol.getName()).thenReturn("item");
        when(references.getReferenceCountTo(address)).thenReturn(1);
        return program;
    }

    private static Program oneGlobalProgram() {
        Program program = emptyProgram();
        Listing listing = program.getListing();
        ReferenceManager references = program.getReferenceManager();
        SymbolTable symbols = program.getSymbolTable();
        Namespace global = program.getGlobalNamespace();
        SymbolIterator iterator = mock(SymbolIterator.class);
        Symbol symbol = mock(Symbol.class);
        Address address = mock(Address.class);
        Data data = mock(Data.class);

        when(symbols.getSymbols(global)).thenReturn(iterator);
        when(iterator.hasNext()).thenReturn(true, false);
        when(iterator.next()).thenReturn(symbol);
        when(symbol.getSymbolType()).thenReturn(SymbolType.LABEL);
        when(symbol.getAddress()).thenReturn(address);
        when(symbol.getName()).thenReturn("global_item");
        when(listing.getDefinedDataAt(address)).thenReturn(data);
        when(references.getReferenceCountTo(address)).thenReturn(1);
        return program;
    }
}
