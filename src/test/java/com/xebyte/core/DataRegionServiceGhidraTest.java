package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;

public class DataRegionServiceGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private DataRegionService service;

    @BeforeClass
    public static void initializeGhidraOrSkip() throws Exception {
        String installDir = System.getProperty("ghidra.test.install.dir");
        assumeTrue(installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration =
                new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDir)),
                configuration);
        }
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder(
            "data-regions-6502", "6502:LE:16:default", "default", this);
        program = builder.getProgram();
        builder.createMemory("ram", "0x0800", 0x7800);
        StructureDataType record = new StructureDataType("Record6", 0);
        for (int i = 0; i < 6; i++) {
            record.add(ByteDataType.dataType, "b" + i, null);
        }
        int transaction = program.startTransaction("add Record6");
        try {
            program.getDataTypeManager().addDataType(
                record, DataTypeConflictHandler.REPLACE_HANDLER);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        service = new DataRegionService(
            provider, new DirectThreadingStrategy());
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void dryRunThenCommitSixByteRecords() {
        Map<String, Object> records = contiguous(
            "0x0c15", "0x0d4f", "Record6");
        records.put("allow_trailing_bytes", true);
        JsonObject preview = response(
            service.applyDataRegions(List.of(records), true, ""));
        assertEquals(52,
            preview.getAsJsonArray("regions").get(0).getAsJsonObject()
                .get("element_count").getAsInt());
        assertNull(program.getListing().getDefinedDataAt(
            program.getAddressFactory().getAddress("0x0c15")));
        JsonObject committed = response(
            service.applyDataRegions(List.of(records), false, ""));
        assertTrue(committed.get("committed").getAsBoolean());
        assertNotNull(program.getListing().getDefinedDataAt(
            program.getAddressFactory().getAddress("0x0c15")));
    }

    @Test
    public void splitTableCreatesTwoReferencesPerValidPointer()
            throws Exception {
        builder.setBytes("0x2000", "00 10");
        builder.setBytes("0x2040", "30 30");
        Map<String, Object> split = new LinkedHashMap<>();
        split.put("kind", "split_pointer_table");
        split.put("first_start", "0x2000");
        split.put("second_start", "0x2040");
        split.put("count", 2);
        split.put("layout", "split_low_high");
        split.put("target_space",
            program.getAddressFactory().getDefaultAddressSpace().getName());
        split.put("create_references", true);
        split.put("validate_targets", true);
        JsonObject result = response(
            service.applyDataRegions(List.of(split), false, ""));
        assertEquals(4, result.getAsJsonArray("references").size());
        assertEquals(2, program.getReferenceManager().getReferenceCountTo(
            program.getAddressFactory().getAddress("0x3000")));
    }

    private static Map<String, Object> contiguous(
            String start, String end, String type) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("kind", "contiguous");
        result.put("start", start);
        result.put("end", end);
        result.put("type_name", type);
        return result;
    }

    private static JsonObject response(Response response) {
        if (response instanceof Response.Err error) {
            throw new AssertionError(error.message());
        }
        return JsonParser.parseString(response.toJson()).getAsJsonObject();
    }
}
