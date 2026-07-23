package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.headless.HeadlessProgramProvider;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class ListingRangeServiceGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;
    private ListingRangeService service;

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDir)), configuration);
        }
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder(
            "listing-range-6502", "6502:LE:16:default", "default", this);
        program = builder.getProgram();
        builder.createMemory(".ram", "0x0800", 0x40);
        builder.setBytes(
            "0x0800",
            "a9 01 8d 00 02 60 10 11 12 13 00 00 00 00 00 00");
        builder.disassemble("0x0800", 6);
        builder.applyDataType(
            "0x0806", new ArrayDataType(ByteDataType.dataType, 4, 1));
        builder.createLabel("0x0807", "inside_data");
        builder.createEntryPoint("0x080a", "undefined_entry");
        builder.createComment("0x080b", "undefined plate", CommentType.PLATE);
        builder.createMemoryReference(
            "0x080c", "0x0807", RefType.DATA, SourceType.USER_DEFINED, 0);
        builder.createMemoryReference(
            "0x0810", "0x080c", RefType.READ, SourceType.IMPORTED, 1);

        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        service = new ListingRangeService(
            provider, new com.xebyte.headless.DirectThreadingStrategy());
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void functionFree6502RangeReturnsMixedListingAndAllAnnotations() {
        assertEquals(0, program.getFunctionManager().getFunctionCount());
        long modificationBefore = program.getModificationNumber();

        JsonObject page = query("0x0801", "0x080f", 100, 256, 100, null);

        assertEquals(modificationBefore, program.getModificationNumber());
        assertEquals(0, program.getFunctionManager().getFunctionCount());
        assertEquals("0800",
            page.getAsJsonObject("effective_range").get("start").getAsString());
        assertTrue(page.get("complete").getAsBoolean());
        JsonArray units = page.getAsJsonArray("units");
        assertTrue(hasKind(units, "instruction"));
        assertTrue(hasKind(units, "data"));
        assertTrue(hasKind(units, "undefined"));
        assertEquals(1, nestedCount(units, "labels", "inside_data"));
        assertEquals(1, nestedCount(units, "labels", "undefined_entry"));
        assertEquals(1, nestedCount(units, "comments", "undefined plate"));
        assertEquals(1, nestedCount(units, "outgoing_references", "0807"));
        assertEquals(1, nestedCount(units, "incoming_references", "080c"));
        JsonObject data = findKind(units, "data");
        assertNotNull(data);
        assertFalse(data.get("data_type").isJsonNull());
    }

    @Test
    public void unitPaginationCoversEffectiveRangeExactlyOnce() {
        String cursor = null;
        int expected = 0x0800;
        int pages = 0;
        do {
            JsonObject page = query("0x0801", "0x080f", 1, 256, 100, cursor);
            JsonArray units = page.getAsJsonArray("units");
            assertEquals(1, units.size());
            JsonObject unit = units.get(0).getAsJsonObject();
            assertEquals(expected, Integer.parseInt(unit.get("start").getAsString(), 16));
            expected = Integer.parseInt(unit.get("end").getAsString(), 16) + 1;
            cursor = page.get("complete").getAsBoolean()
                ? null : page.get("next_cursor").getAsString();
            pages++;
        }
        while (cursor != null);

        assertEquals(0x0810, expected);
        assertTrue(pages >= 3);
        assertEquals(0, program.getFunctionManager().getFunctionCount());
    }

    private JsonObject query(
            String start, String end, int maxUnits, int maxBytes,
            int maxIncoming, String cursor) {
        Response response = service.getListingRange(
            start, end, maxUnits, maxBytes, maxIncoming, cursor, "");
        assertFalse(response.toJson(), response instanceof Response.Err);
        return JsonParser.parseString(response.toJson()).getAsJsonObject();
    }

    private static boolean hasKind(JsonArray units, String kind) {
        return findKind(units, kind) != null;
    }

    private static JsonObject findKind(JsonArray units, String kind) {
        for (var element : units) {
            JsonObject unit = element.getAsJsonObject();
            if (kind.equals(unit.get("kind").getAsString())) {
                return unit;
            }
        }
        return null;
    }

    private static int nestedCount(
            JsonArray units, String collection, String value) {
        List<String> flattened = new ArrayList<>();
        for (var unitElement : units) {
            for (var itemElement
                    : unitElement.getAsJsonObject().getAsJsonArray(collection)) {
                JsonObject item = itemElement.getAsJsonObject();
                for (String field
                        : List.of("name", "text", "source", "destination")) {
                    if (item.has(field)) {
                        flattened.add(item.get(field).getAsString());
                    }
                }
            }
        }
        return (int) flattened.stream().filter(value::equals).count();
    }
}
