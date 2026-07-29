package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class Search6502IndexedOperandsGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private AddressEncodingSearchService service;
    private String ram;

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
            "indexed-6502", "6502:LE:16:default", "default", this);
        program = builder.getProgram();
        builder.createMemory("ram", "0x1000", 0x9000);
        builder.setBytes("0x1000",
            "bd 00 9f 99 00 9f fe 00 9f b5 80 6c 00 9f ad 00 9f");
        builder.disassemble("0x1000", 3);
        builder.disassemble("0x1003", 3);
        builder.disassemble("0x1006", 3);
        builder.disassemble("0x1009", 2);
        builder.disassemble("0x100b", 3);
        builder.disassemble("0x100e", 3);
        builder.createOverlayMemory("bank", "0x9f00", 0x100);
        ram = program.getAddressFactory().getDefaultAddressSpace().getName();

        int transaction = program.startTransaction("wrong-space fixture");
        try {
            Address source = builder.addr("0x1000");
            program.getReferenceManager().removeAllReferencesFrom(source);
            program.getReferenceManager().addMemoryReference(
                source, builder.addr("0x9f00"), RefType.READ,
                SourceType.ANALYSIS, 0);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        service = new AddressEncodingSearchService(
            provider, new DirectThreadingStrategy());
    }

    @After
    public void tearDown() {
        if (builder != null) builder.dispose();
    }

    @Test
    public void findsOnlyAbsoluteIndexedAccessesAndBuildsOverlayRepair() {
        Map<String, Object> body = ok(service.search6502IndexedOperands(
            "bank:9f00", "bank:9fff", ram + ":1000", ram + ":1010",
            100, 0, ""));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rows =
            (List<Map<String, Object>>) body.get("operands");

        assertEquals(3, rows.size());
        assertEquals(List.of("X", "Y", "X"),
            rows.stream().map(row -> row.get("index_register")).toList());
        assertEquals(List.of("READ", "WRITE", "READ_WRITE"),
            rows.stream().map(row -> row.get("access_type")).toList());
        assertEquals("wrong_space_reference", rows.get(0).get("status"));
        assertTrue(rows.stream().allMatch(
            row -> "bank::9f00".equals(row.get("base_target"))));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> slot =
            (List<Map<String, Object>>) rows.get(0).get("slot_references");
        assertEquals(1, slot.size());
        assertEquals(ram + ":9f00", slot.get(0).get("to"));

        @SuppressWarnings("unchecked")
        Map<String, Object> repair =
            (Map<String, Object>) rows.get(0).get("batch_update_references");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> add =
            (List<Map<String, Object>>) repair.get("add");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> remove =
            (List<Map<String, Object>>) repair.get("remove");
        assertEquals("bank::9f00", add.get(0).get("to"));
        assertEquals("read", add.get(0).get("type"));
        assertEquals(ram + ":9f00", remove.get(0).get("to"));
        assertEquals(true, repair.get("allow_non_user_removal"));
        assertEquals(true, repair.get("dry_run"));
        assertEquals(3, body.get("total_matched"));
        assertFalse((Boolean) body.get("has_more"));
    }

    @Test
    public void requiresQualifiedRangesAndPagesDeterministically() {
        Response unqualified = service.search6502IndexedOperands(
            "0x9f00", "bank:9fff", ram + ":1000", ram + ":1010",
            100, 0, "");
        assertTrue(unqualified.toJson(), unqualified instanceof Response.Err);
        assertTrue(unqualified.toJson().contains("explicitly qualified"));

        Map<String, Object> page = ok(service.search6502IndexedOperands(
            "bank:9f00", "bank:9fff", ram + ":1000", ram + ":1010",
            1, 1, ""));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rows =
            (List<Map<String, Object>>) page.get("operands");
        assertEquals(1, rows.size());
        assertEquals(ram + ":1003", rows.get(0).get("instruction_address"));
        assertTrue((Boolean) page.get("has_more"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ok(Response response) {
        if (response instanceof Response.Err error) {
            throw new AssertionError(error.message());
        }
        return (Map<String, Object>) ((Response.Ok) response).data();
    }
}
