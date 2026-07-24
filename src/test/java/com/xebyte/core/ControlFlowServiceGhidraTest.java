package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class ControlFlowServiceGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private ControlFlowService service;
    private String targetSpaceName;

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
            "manual-flow-6502",
            "6502:LE:16:default", "default", this);
        program = builder.getProgram();
        targetSpaceName =
            program.getAddressFactory().getDefaultAddressSpace().getName();
        builder.createMemory("ram", "0x0800", 0x7800);
        builder.setBytes("0x1000", "4c 00 20");
        builder.setBytes("0x1010", "8d 01 12");
        builder.setBytes("0x1100", "a9 00");
        builder.setBytes("0x1200", "6c 00 20");
        builder.setBytes("0x1300", "ea");
        builder.setBytes("0x2000", "00 30 10 30");
        builder.disassemble("0x1000", 3);
        builder.disassemble("0x1010", 3);
        builder.disassemble("0x1100", 2);
        builder.disassemble("0x1200", 3);
        builder.disassemble("0x1300", 1);
        int dataTypeTx = program.startTransaction("add table datatypes");
        try {
            program.getDataTypeManager().addDataType(
                ByteDataType.dataType,
                DataTypeConflictHandler.REPLACE_HANDLER);
            program.getDataTypeManager().addDataType(
                WordDataType.dataType,
                DataTypeConflictHandler.REPLACE_HANDLER);
        }
        finally {
            program.endTransaction(dataTypeTx, true);
        }
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        service = new ControlFlowService(
            provider, new DirectThreadingStrategy());
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void entryPointsAreAtomicIdempotentAndFunctionFree() {
        JsonObject preview = ok(service.updateEntryPoints(
            List.of("0x1000"), List.of(), true, ""));
        assertFalse(preview.get("committed").getAsBoolean());
        assertFalse(program.getSymbolTable().isExternalEntryPoint(
            builder.addr("0x1000")));

        ok(service.updateEntryPoints(
            List.of("0x1000"), List.of(), false, ""));
        assertTrue(program.getSymbolTable().isExternalEntryPoint(
            builder.addr("0x1000")));
        assertNull(program.getFunctionManager().getFunctionAt(
            builder.addr("0x1000")));

        JsonObject repeated = ok(service.updateEntryPoints(
            List.of("0x1000"), List.of(), false, ""));
        assertEquals("unchanged", repeated.getAsJsonArray("actions")
            .get(0).getAsJsonObject().get("action").getAsString());

        Response overlap = service.updateEntryPoints(
            List.of("0x1010"), List.of("0x1010"), false, "");
        assertTrue(overlap.toJson(), overlap instanceof Response.Err);
        assertFalse(program.getSymbolTable().isExternalEntryPoint(
            builder.addr("0x1010")));

        ok(service.updateEntryPoints(
            List.of(), List.of("0x1000"), false, ""));
        assertFalse(program.getSymbolTable().isExternalEntryPoint(
            builder.addr("0x1000")));
    }

    @Test
    public void everyFlowOverrideCanBeSetAndClearedWithoutFunction() {
        for (FlowOverride override : FlowOverride.values()) {
            ok(service.setInstructionFlowOverride(
                "0x1000", override.name(), false, ""));
            assertEquals(
                override,
                program.getListing().getInstructionAt(
                    builder.addr("0x1000")).getFlowOverride());
            assertNull(program.getFunctionManager().getFunctionAt(
                builder.addr("0x1000")));
        }
        ok(service.setInstructionFlowOverride(
            "0x1000", "NONE", false, ""));
        JsonObject repeated = ok(service.setInstructionFlowOverride(
            "0x1000", "NONE", false, ""));
        assertEquals(
            "unchanged", repeated.get("action").getAsString());
    }

    @Test
    public void exactReferenceBatchHonorsSourceOperandAndPrimary()
            throws Exception {
        Map<String, Object> add = reference(
            "0x1010", "0x3000", "write", 0);
        add.put("primary", false);
        ok(service.batchUpdateReferences(
            List.of(add), List.of(), false, false, ""));
        Reference created = program.getReferenceManager().getReference(
            builder.addr("0x1010"), builder.addr("0x3000"), 0);
        assertNotNull(created);
        assertEquals(RefType.WRITE, created.getReferenceType());
        assertEquals(SourceType.USER_DEFINED, created.getSource());
        assertFalse(created.isPrimary());

        JsonObject repeated = ok(service.batchUpdateReferences(
            List.of(add), List.of(), false, false, ""));
        assertEquals("unchanged", repeated.getAsJsonArray("add")
            .get(0).getAsJsonObject().get("action").getAsString());

        Map<String, Object> primary = new LinkedHashMap<>(add);
        primary.put("primary", true);
        Map<String, Object> generatedPrimary = reference(
            "0x1010", "0x1201", "write", 0);
        ok(service.batchUpdateReferences(
            List.of(primary), List.of(generatedPrimary),
            true, false, ""));
        assertTrue(program.getReferenceManager().getReference(
            builder.addr("0x1010"), builder.addr("0x3000"), 0)
            .isPrimary());

        int tx = program.startTransaction("analysis reference");
        try {
            program.getReferenceManager().addMemoryReference(
                builder.addr("0x1300"), builder.addr("0x3010"),
                RefType.DATA, SourceType.ANALYSIS, Reference.MNEMONIC);
        }
        finally {
            program.endTransaction(tx, true);
        }
        Map<String, Object> remove = reference(
            "0x1300", "0x3010", "data", -1);
        Response denied = service.batchUpdateReferences(
            List.of(), List.of(remove), false, false, "");
        assertTrue(denied.toJson(), denied instanceof Response.Err);
        assertNotNull(program.getReferenceManager().getReference(
            builder.addr("0x1300"), builder.addr("0x3010"),
            Reference.MNEMONIC));
        ok(service.batchUpdateReferences(
            List.of(), List.of(remove), true, false, ""));
        assertNull(program.getReferenceManager().getReference(
            builder.addr("0x1300"), builder.addr("0x3010"),
            Reference.MNEMONIC));
    }

    @Test
    public void primaryReferenceChangesMustBeExplicitAndOrdered() {
        Map<String, Object> first = reference(
            "0x1300", "0x3000", "data", -1);
        first.put("primary", true);
        ok(service.batchUpdateReferences(
            List.of(first), List.of(), false, false, ""));

        Map<String, Object> second = reference(
            "0x1300", "0x3010", "data", -1);
        second.put("primary", true);
        Response implicitDemotion = service.batchUpdateReferences(
            List.of(second), List.of(), false, false, "");
        assertTrue(
            implicitDemotion.toJson(),
            implicitDemotion instanceof Response.Err);
        assertNull(program.getReferenceManager().getReference(
            builder.addr("0x1300"), builder.addr("0x3010"),
            Reference.MNEMONIC));

        Map<String, Object> demote = new LinkedHashMap<>(first);
        demote.put("primary", false);
        ok(service.batchUpdateReferences(
            List.of(demote, second), List.of(),
            false, false, ""));
        assertFalse(program.getReferenceManager().getReference(
            builder.addr("0x1300"), builder.addr("0x3000"),
            Reference.MNEMONIC).isPrimary());
        assertTrue(program.getReferenceManager().getReference(
            builder.addr("0x1300"), builder.addr("0x3010"),
            Reference.MNEMONIC).isPrimary());
    }

    @Test
    public void referencePlanningFailureLeavesEveryEarlierAddUntouched() {
        Map<String, Object> valid = reference(
            "0x1300", "0x3020", "data", -1);
        Map<String, Object> incompatible = reference(
            "0x1000", "0x2000", "data", 0);

        Response rejected = service.batchUpdateReferences(
            List.of(valid, incompatible), List.of(),
            false, false, "");

        assertTrue(rejected.toJson(), rejected instanceof Response.Err);
        assertNull(program.getReferenceManager().getReference(
            builder.addr("0x1300"), builder.addr("0x3020"),
            Reference.MNEMONIC));
        Reference original = program.getReferenceManager().getReference(
            builder.addr("0x1000"), builder.addr("0x2000"), 0);
        assertNotNull(original);
        assertEquals(
            RefType.UNCONDITIONAL_JUMP,
            original.getReferenceType());
    }

    @Test
    public void jumpTableTypesLabelsCommentsAndDispatchReferences() {
        Map<String, Object> table = contiguousTable();
        JsonObject result = ok(service.describeJumpTable(
            table, List.of("0x1200"), "computed_jump", false, ""));

        assertEquals(2,
            result.getAsJsonArray("decoded_targets").size());
        assertNotNull(program.getListing().getDefinedDataAt(
            builder.addr("0x2000")));
        Reference first = program.getReferenceManager().getReference(
            builder.addr("0x1200"), builder.addr("0x3000"),
            Reference.MNEMONIC);
        assertNotNull(first);
        assertEquals(RefType.COMPUTED_JUMP, first.getReferenceType());
        assertEquals(SourceType.USER_DEFINED, first.getSource());
        assertFalse(first.isPrimary());
        assertNotNull(program.getSymbolTable().getGlobalSymbol(
            "CASE_3000", builder.addr("0x3000")));
        String plate = program.getListing().getComment(
            CommentType.PLATE, builder.addr("0x2000"));
        assertTrue(plate, plate.contains("Manual jump table"));
        assertTrue(plate, plate.contains("1200"));

        JsonObject repeated = ok(service.describeJumpTable(
            table, List.of("0x1200"), "computed_jump", false, ""));
        assertEquals("unchanged",
            repeated.getAsJsonArray("references").get(0)
                .getAsJsonObject().get("action").getAsString());
    }

    @Test
    public void splitJumpTableAndInvalidTargetsAreExplicit()
            throws Exception {
        Map<String, Object> split = new LinkedHashMap<>();
        split.put("kind", "split_pointer_table");
        split.put("first_start", "0x2100");
        split.put("second_start", "0x2120");
        split.put("count", 2);
        split.put("layout", "split_low_high");
        split.put("target_space", targetSpaceName);
        split.put("validate_targets", true);
        builder.setBytes("0x2100", "00 10");
        builder.setBytes("0x2120", "30 30");

        JsonObject result = ok(service.describeJumpTable(
            split, List.of("0x1200"), "jump", false, ""));
        assertEquals("split_pointer_table",
            result.getAsJsonObject("table").get("kind").getAsString());

        Map<String, Object> invalid =
            new LinkedHashMap<>(contiguousTable());
        @SuppressWarnings("unchecked")
        Map<String, Object> pointers =
            new LinkedHashMap<>((Map<String, Object>) invalid.get("pointers"));
        pointers.put("target_base", 0xf000);
        pointers.put("validate_targets", true);
        invalid.put("pointers", pointers);
        Response rejected = service.describeJumpTable(
            invalid, List.of("0x1300"), "jump", false, "");
        assertTrue(rejected.toJson(), rejected instanceof Response.Err);
        assertNull(program.getReferenceManager().getReference(
            builder.addr("0x1300"), builder.addr("0x3000"),
            Reference.MNEMONIC));
    }

    @Test
    public void removedDispatchDuringTableTypingRollsBackExactly()
            throws Exception {
        builder.setBytes("0x2200", "6c 00 30");
        builder.disassemble("0x2200", 3);
        Map<String, Object> table = contiguousTable();
        table.put("start", "0x2200");
        table.put("end", "0x2201");
        table.put("clear_conflicts", true);
        @SuppressWarnings("unchecked")
        Map<String, Object> pointers =
            (Map<String, Object>) table.get("pointers");
        pointers.put("validate_targets", false);

        Response rejected = service.describeJumpTable(
            table, List.of("0x2200"), "computed_jump", false, "");

        assertTrue(rejected.toJson(), rejected instanceof Response.Err);
        assertNotNull(program.getListing().getInstructionAt(
            builder.addr("0x2200")));
        assertNull(program.getListing().getDefinedDataAt(
            builder.addr("0x2200")));
    }

    @Test
    public void selfModifiedOperandLinksBytesAndAppendsCommentsOnce() {
        JsonObject result = ok(service.annotateSelfModifiedOperand(
            "0x1010", 0, "0x1100", List.of("0x1101"),
            "accumulator value", "Patched immediate", false,
            false, ""));
        assertEquals(1, result.getAsJsonArray("references").size());
        Reference reference = program.getReferenceManager().getReference(
            builder.addr("0x1010"), builder.addr("0x1101"), 0);
        assertNotNull(reference);
        assertEquals(RefType.WRITE, reference.getReferenceType());
        assertFalse(reference.isPrimary());
        String evidence = program.getListing().getComment(
            CommentType.PRE, builder.addr("0x1010"));
        assertTrue(evidence, evidence.contains("Self-modifying"));
        assertTrue(evidence, evidence.contains("accumulator value"));

        ok(service.annotateSelfModifiedOperand(
            "0x1010", 0, "0x1100", List.of("0x1101"),
            "accumulator value", "Patched immediate", false,
            false, ""));
        assertEquals(evidence, program.getListing().getComment(
            CommentType.PRE, builder.addr("0x1010")));

        Response outside = service.annotateSelfModifiedOperand(
            "0x1010", 0, "0x1100", List.of("0x1102"),
            null, null, false, false, "");
        assertTrue(outside.toJson(), outside instanceof Response.Err);
    }

    @Test
    public void selfModifiedTargetCommentRequiresExplicitAppend() {
        int tx = program.startTransaction("existing target comment");
        try {
            program.getListing().setComment(
                builder.addr("0x1100"), CommentType.PLATE, "Existing");
        }
        finally {
            program.endTransaction(tx, true);
        }

        Response conflict = service.annotateSelfModifiedOperand(
            "0x1010", 0, "0x1100", List.of("0x1101"),
            null, "New evidence", false, false, "");
        assertTrue(conflict.toJson(), conflict instanceof Response.Err);
        assertNull(program.getReferenceManager().getReference(
            builder.addr("0x1010"), builder.addr("0x1101"), 0));

        ok(service.annotateSelfModifiedOperand(
            "0x1010", 0, "0x1100", List.of("0x1101"),
            null, "New evidence", true, false, ""));
        assertEquals(
            "Existing\nNew evidence",
            program.getListing().getComment(
                CommentType.PLATE, builder.addr("0x1100")));

        Response duplicateBytes = service.annotateSelfModifiedOperand(
            "0x1010", 0, "0x1100",
            List.of("0x1101", "0x1101"),
            null, null, false, false, "");
        assertTrue(
            duplicateBytes.toJson(),
            duplicateBytes instanceof Response.Err);
    }

    @Test
    public void selfModifiedOverlayBytesUseGhidrasStoredIdentityIdempotently()
            throws Exception {
        builder.createOverlayMemory("bank", "0x3000", 0x10);
        int tx = program.startTransaction("seed overlay instruction");
        try {
            program.getMemory().setBytes(
                builder.addr("bank::3000"),
                new byte[] {(byte) 0xa9, 0});
        }
        finally {
            program.endTransaction(tx, true);
        }
        builder.disassemble("bank::3000", 2);

        ok(service.annotateSelfModifiedOperand(
            "0x1300", -1, "bank:3000", List.of("bank:3001"),
            "", "", false, false, ""));
        JsonObject repeated = ok(service.annotateSelfModifiedOperand(
            "0x1300", -1, "bank:3000", List.of("bank:3001"),
            "", "", false, false, ""));

        assertEquals(
            "unchanged",
            repeated.getAsJsonArray("references").get(0)
                .getAsJsonObject().get("action").getAsString());
        assertNotNull(program.getReferenceManager().getReference(
            builder.addr("0x1300"), builder.addr("bank::3001"),
            Reference.MNEMONIC));
    }

    private static JsonObject ok(Response response) {
        assertTrue(response.toJson(), response instanceof Response.Ok);
        return JsonParser.parseString(response.toJson())
            .getAsJsonObject();
    }

    private static Map<String, Object> reference(
            String from, String to, String type, int operandIndex) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("from", from);
        result.put("to", to);
        result.put("type", type);
        result.put("operand_index", operandIndex);
        return result;
    }

    private Map<String, Object> contiguousTable() {
        Map<String, Object> pointers = new LinkedHashMap<>();
        pointers.put("layout", "little_endian_words");
        pointers.put("target_space", targetSpaceName);
        pointers.put("validate_targets", true);
        pointers.put("target_label_prefix", "CASE_");
        Map<String, Object> table = new LinkedHashMap<>();
        table.put("kind", "contiguous");
        table.put("start", "0x2000");
        table.put("end", "0x2003");
        table.put("type_name", "word");
        table.put("pointers", pointers);
        return table;
    }
}
