package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

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
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

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
            program.getDataTypeManager().addDataType(
                WordDataType.dataType,
                DataTypeConflictHandler.REPLACE_HANDLER);
            program.getDataTypeManager().addDataType(
                StringDataType.dataType,
                DataTypeConflictHandler.REPLACE_HANDLER);
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
        JsonObject normalized =
            preview.getAsJsonArray("regions").get(0).getAsJsonObject();
        assertEquals("0c15", normalized.get("start").getAsString());
        assertEquals("0d4f", normalized.get("end").getAsString());
        assertEquals(6, normalized.get("stride").getAsInt());
        assertTrue(
            normalized.get("allow_trailing_bytes").getAsBoolean());
        assertTrue(normalized.get("clear_conflicts").isJsonPrimitive());
        assertTrue(normalized.get("pointer_options").isJsonNull());
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

    @Test
    public void splitSourcesMayUseDifferentAddressSpaces()
            throws Exception {
        builder.createOverlayMemory("bank", "0x2e00", 0x10);
        builder.setBytes("0x2d00", "00");
        int tx = program.startTransaction("seed overlay high byte");
        try {
            program.getMemory().setByte(
                builder.addr("bank::2e00"), (byte) 0x30);
        }
        finally {
            program.endTransaction(tx, true);
        }
        Map<String, Object> split = splitRegion(
            "0x2d00", "bank:2e00", 1, "split_low_high");
        split.put("validate_targets", true);

        JsonObject preview = response(
            service.applyDataRegions(List.of(split), true, ""));

        JsonObject region = preview.getAsJsonArray("regions")
            .get(0).getAsJsonObject();
        assertEquals("2d00", region.get("first_start").getAsString());
        assertEquals(
            "bank::2e00", region.get("second_start").getAsString());
        assertEquals("3000", pointerTarget(preview, 0));

        response(service.applyDataRegions(List.of(split), false, ""));
        assertNotNull(program.getListing().getDefinedDataAt(
            builder.addr("0x2d00")));
        assertNotNull(program.getListing().getDefinedDataAt(
            builder.addr("bank::2e00")));
    }

    @Test
    public void splitSourceEnumerationUsesEachAddressSpaceBounds()
            throws Exception {
        builder.createOverlayMemory("edge", "0xffff", 1);
        Map<String, Object> split = splitRegion(
            "0x2d20", "edge:ffff", 2, "split_low_high");

        Response result = service.applyDataRegions(
            List.of(split), true, "");

        assertTrue(result.toJson(), result instanceof Response.Err);
        assertTrue(
            result.toJson().contains(
                "second split pointer source range exceeds address space"));
    }

    @Test
    public void strideLeavesGapsUndefinedAndRequestedDefinitionsCannotOverlap() {
        Map<String, Object> strided = contiguous(
            "0x2800", "0x2811", "Record6");
        strided.put("stride", 12);
        JsonObject preview = response(
            service.applyDataRegions(List.of(strided), true, ""));
        assertEquals(2,
            preview.getAsJsonArray("created_data").size());
        response(service.applyDataRegions(
            List.of(strided), false, ""));
        assertNotNull(program.getListing().getDefinedDataAt(
            builder.addr("0x2800")));
        assertNotNull(program.getListing().getDefinedDataAt(
            builder.addr("0x280c")));
        assertNull(program.getListing().getDefinedDataContaining(
            builder.addr("0x2806")));

        Map<String, Object> bytes = contiguous(
            "0x2900", "0x2902", "byte");
        Map<String, Object> overlap = contiguous(
            "0x2902", "0x2902", "byte");
        Response rejected = service.applyDataRegions(
            List.of(bytes, overlap), true, "");
        assertTrue(rejected.toJson(), rejected instanceof Response.Err);
        assertTrue(rejected.toJson().toLowerCase().contains("overlap"));
    }

    @Test
    public void allPointerOrdersAndTargetBaseDecodeCorrectly()
            throws Exception {
        builder.setBytes("0x2a00", "00 10");
        builder.setBytes("0x2a10", "10 00");
        builder.setBytes("0x2a20", "30");
        builder.setBytes("0x2a30", "10");
        Map<String, Object> little = contiguous(
            "0x2a00", "0x2a01", "word");
        little.put("pointers", pointerOptionsWith(
            "little_endian_words", 0x2000, false, true));
        Map<String, Object> big = contiguous(
            "0x2a10", "0x2a11", "word");
        big.put("pointers", pointerOptionsWith(
            "big_endian_words", 0x2000, false, true));
        Map<String, Object> split = splitRegion(
            "0x2a20", "0x2a30", 1, "split_high_low");
        split.put("target_base", 0);
        split.put("validate_targets", true);

        JsonObject result = response(service.applyDataRegions(
            List.of(little, big, split), true, ""));

        assertEquals("3000", pointerTarget(result, 0));
        assertEquals("3000", pointerTarget(result, 1));
        assertEquals("3010", pointerTarget(result, 2));
    }

    @Test
    public void dynamicAndTopLevelBitFieldTypesFailInPreview()
            throws Exception {
        Map<String, Object> dynamic = contiguous(
            "0x2b00", "0x2b03", "string");
        Response dynamicResult = service.applyDataRegions(
            List.of(dynamic), true, "");
        assertTrue(dynamicResult.toJson(),
            dynamicResult instanceof Response.Err);

        DataType bitField;
        TestBitFieldDataType candidate =
            new TestBitFieldDataType();
        assertThrows(
            IllegalArgumentException.class,
            () -> DataRegionCore.requireFixedPlaceable(
                candidate, "bits"));
        int tx = program.startTransaction("add bitfield");
        try {
            bitField = program.getDataTypeManager().addDataType(
                candidate,
                DataTypeConflictHandler.REPLACE_HANDLER);
        }
        finally {
            program.endTransaction(tx, true);
        }
        Map<String, Object> bit = contiguous(
            "0x2b10", "0x2b10", bitField.getPathName());
        Response bitResult = service.applyDataRegions(
            List.of(bit), true, "");
        assertTrue(bitResult.toJson(), bitResult instanceof Response.Err);
    }

    @Test
    public void typedefChainsAroundUndefinedTypesFailInPreview()
            throws Exception {
        TypedefDataType inner = new TypedefDataType(
            "UndefinedAlias", Undefined1DataType.dataType);
        TypedefDataType outer = new TypedefDataType(
            "NestedUndefinedAlias", inner);
        DataType nested;
        int tx = program.startTransaction("add undefined typedef chain");
        try {
            nested = program.getDataTypeManager().addDataType(
                outer, DataTypeConflictHandler.REPLACE_HANDLER);
        }
        finally {
            program.endTransaction(tx, true);
        }
        Map<String, Object> request = contiguous(
            "0x2b20", "0x2b20", nested.getPathName());

        Response result = service.applyDataRegions(
            List.of(request), true, "");

        assertTrue(result.toJson(), result instanceof Response.Err);
        assertTrue(result.toJson().contains("fixed and placeable"));
    }

    @Test
    public void labelCollisionAtAnotherAddressIsRejected()
            throws Exception {
        int tx = program.startTransaction("seed namespace symbol");
        try {
            Namespace game = program.getSymbolTable().createNameSpace(
                program.getGlobalNamespace(), "ExistingGame",
                SourceType.USER_DEFINED);
            program.getSymbolTable().createLabel(
                builder.addr("0x2c00"), "records", game,
                SourceType.USER_DEFINED);
        }
        finally {
            program.endTransaction(tx, true);
        }
        Map<String, Object> request = contiguous(
            "0x2c10", "0x2c10", "byte");
        request.put("name", "records");
        request.put("namespace", "ExistingGame");

        Response result = service.applyDataRegions(
            List.of(request), true, "");

        assertTrue(result.toJson(), result instanceof Response.Err);
        assertTrue(result.toJson().toLowerCase().contains("another address"));
    }

    @Test
    public void combinedC64ShapedBatchTypesRecordsAndSplitDispatch()
            throws Exception {
        builder.setBytes("0x2000", "00 ".repeat(64));
        builder.setBytes("0x2040", "00 ".repeat(64));
        Map<String, Object> records = contiguous(
            "0x0c15", "0x0d4f", "Record6");
        records.put("allow_trailing_bytes", true);
        Map<String, Object> split = splitRegion(
            "0x2000", "0x2040", 64, "split_low_high");
        split.put("target_base", 0x3000);
        split.put("create_references", true);
        split.put("validate_targets", true);

        JsonObject preview = response(service.applyDataRegions(
            List.of(records, split), true, ""));
        assertEquals(52,
            preview.getAsJsonArray("regions").get(0).getAsJsonObject()
                .get("element_count").getAsInt());
        assertEquals(64,
            preview.getAsJsonArray("regions").get(1).getAsJsonObject()
                .get("count").getAsInt());
        assertEquals(128, preview.getAsJsonArray("references").size());

        JsonObject committed = response(service.applyDataRegions(
            List.of(records, split), false, ""));
        assertPlanFieldsEqual(preview, committed);
    }

    @Test
    public void previewCommitAndRepeatReportStableExplicitActions()
            throws Exception {
        builder.setBytes("0x2200", "00 30 00 30");
        Map<String, Object> words = contiguous(
            "0x2200", "0x2203", "word");
        words.put("name", "dispatch_words");
        words.put("namespace", "Game");
        words.put("plate_comment", "Dispatch words");
        words.put("pointers", pointerOptions(
            true, true, "target_", "Game"));

        JsonObject preview = response(
            service.applyDataRegions(List.of(words), true, ""));
        JsonObject committed = response(
            service.applyDataRegions(List.of(words), false, ""));
        assertPlanFieldsEqual(preview, committed);
        assertEquals("create", actionAt(preview, "created_data", 0));
        assertEquals("create", actionAt(preview, "references", 0));
        assertEquals("create", actionAt(preview, "symbols", 0));
        assertEquals("create", actionAt(preview, "namespaces", 0));
        assertEquals("create", actionAt(preview, "comments", 0));

        JsonObject repeatedPreview = response(
            service.applyDataRegions(List.of(words), true, ""));
        JsonObject repeatedCommit = response(
            service.applyDataRegions(List.of(words), false, ""));
        assertPlanFieldsEqual(repeatedPreview, repeatedCommit);
        repeatedPreview.getAsJsonArray("created_data").forEach(
            item -> assertEquals(
                "unchanged",
                item.getAsJsonObject().get("action").getAsString()));
        repeatedPreview.getAsJsonArray("references").forEach(
            item -> assertEquals(
                "unchanged",
                item.getAsJsonObject().get("action").getAsString()));
        repeatedPreview.getAsJsonArray("symbols").forEach(
            item -> assertEquals(
                "unchanged",
                item.getAsJsonObject().get("action").getAsString()));
        assertEquals(
            "unchanged", actionAt(repeatedPreview, "namespaces", 0));
        assertEquals(
            "unchanged", actionAt(repeatedPreview, "comments", 0));

        Namespace game = program.getSymbolTable().getNamespace(
            "Game", program.getGlobalNamespace());
        assertNotNull(game);
        assertNotNull(program.getSymbolTable().getSymbol(
            "dispatch_words", builder.addr("0x2200"), game));
        assertEquals("Dispatch words", program.getListing().getComment(
            CommentType.PLATE, builder.addr("0x2200")));
        assertEquals(2, countMnemonicUserDataReferences(
            builder.addr("0x2200"), builder.addr("0x3000"))
            + countMnemonicUserDataReferences(
                builder.addr("0x2202"), builder.addr("0x3000")));
    }

    @Test
    public void existingOperandReferenceDoesNotSuppressMnemonicReference()
            throws Exception {
        builder.setBytes("0x2300", "00 30");
        int tx = program.startTransaction("seed operand reference");
        try {
            program.getReferenceManager().addMemoryReference(
                builder.addr("0x2300"), builder.addr("0x3000"),
                RefType.DATA, SourceType.USER_DEFINED, 0);
        }
        finally {
            program.endTransaction(tx, true);
        }
        Map<String, Object> words = contiguous(
            "0x2300", "0x2301", "word");
        words.put("pointers", pointerOptions(
            true, true, null, null));

        JsonObject preview = response(
            service.applyDataRegions(List.of(words), true, ""));
        assertEquals("create", actionAt(preview, "references", 0));
        response(service.applyDataRegions(List.of(words), false, ""));
        assertEquals(1, countMnemonicUserDataReferences(
            builder.addr("0x2300"), builder.addr("0x3000")));

        JsonObject repeated = response(
            service.applyDataRegions(List.of(words), true, ""));
        assertEquals("unchanged", actionAt(repeated, "references", 0));
    }

    @Test
    public void invalidTargetsExposeSkippedReferenceAndLabelActions()
            throws Exception {
        builder.setBytes("0x2400", "00 01");
        Map<String, Object> words = contiguous(
            "0x2400", "0x2401", "word");
        words.put("pointers", pointerOptions(
            true, false, "bad_", "Targets"));

        JsonObject preview = response(
            service.applyDataRegions(List.of(words), true, ""));
        JsonObject pointer = preview.getAsJsonArray("regions")
            .get(0).getAsJsonObject().getAsJsonArray("pointers")
            .get(0).getAsJsonObject();
        assertFalse(pointer.get("valid").getAsBoolean());
        assertEquals("invalid_target",
            pointer.get("skipped").getAsString());
        assertEquals("skipped",
            actionAt(preview, "references", 0));
        assertEquals("invalid_target",
            preview.getAsJsonArray("references").get(0).getAsJsonObject()
                .get("reason").getAsString());
        assertEquals("skipped",
            actionAt(preview, "symbols", 0));
        assertEquals("invalid_target",
            preview.getAsJsonArray("symbols").get(0).getAsJsonObject()
                .get("reason").getAsString());
        assertEquals(0, preview.getAsJsonArray("namespaces").size());

        JsonObject committed = response(
            service.applyDataRegions(List.of(words), false, ""));
        assertPlanFieldsEqual(preview, committed);
        assertEquals(0, program.getReferenceManager()
            .getReferenceCountTo(builder.addr("0x0100")));
        assertNull(program.getSymbolTable().getNamespace(
            "Targets", program.getGlobalNamespace()));
    }

    @Test
    public void malformedTargetSpaceAndSymbolNamesAlwaysFailInPreview()
            throws Exception {
        Map<String, Object> noElements = contiguous(
            "0x2400", "0x2400", "word");
        noElements.put("allow_trailing_bytes", true);
        Map<String, Object> badSpace = pointerOptions(
            true, false, null, null);
        badSpace.put("target_space", "not_a_space");
        noElements.put("pointers", badSpace);
        Response unknownSpace = service.applyDataRegions(
            List.of(noElements), true, "");
        assertTrue(unknownSpace.toJson(),
            unknownSpace instanceof Response.Err);
        assertTrue(unknownSpace.toJson().contains("target_space"));

        Map<String, Object> blankName = contiguous(
            "0x2410", "0x2410", "byte");
        blankName.put("name", "");
        Response blank = service.applyDataRegions(
            List.of(blankName), true, "");
        assertTrue(blank.toJson(), blank instanceof Response.Err);

        builder.setBytes("0x2420", "00 30");
        Map<String, Object> invalidGenerated = contiguous(
            "0x2420", "0x2421", "word");
        invalidGenerated.put("pointers", pointerOptions(
            false, true, "bad name ", null));
        Response badLabel = service.applyDataRegions(
            List.of(invalidGenerated), true, "");
        assertTrue(badLabel.toJson(), badLabel instanceof Response.Err);
    }

    @Test
    public void samePlacementBatchMetadataConflictsAreRejected() {
        Map<String, Object> first = contiguous(
            "0x2440", "0x2440", "Record6");
        first.put("allow_trailing_bytes", true);
        first.put("name", "first_name");
        first.put("plate_comment", "first comment");
        Map<String, Object> second = contiguous(
            "0x2440", "0x2440", "Record6");
        second.put("allow_trailing_bytes", true);
        second.put("name", "second_name");
        second.put("plate_comment", "second comment");

        Response response = service.applyDataRegions(
            List.of(first, second), true, "");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertNull(program.getSymbolTable().getPrimarySymbol(
            builder.addr("0x2440")));
        assertNull(program.getListing().getComment(
            CommentType.PLATE, builder.addr("0x2440")));
    }

    @Test
    public void requestedNamespaceCannotAlsoBeRequestedAsGlobalLabel() {
        Map<String, Object> global = contiguous(
            "0x2460", "0x2460", "byte");
        global.put("name", "Game");
        Map<String, Object> namespaced = contiguous(
            "0x2470", "0x2470", "byte");
        namespaced.put("name", "records");
        namespaced.put("namespace", "Game");

        for (List<Map<String, Object>> batch : List.of(
                List.of(global, namespaced),
                List.of(namespaced, global))) {
            Response result = service.applyDataRegions(
                batch, true, "");
            assertTrue(result.toJson(), result instanceof Response.Err);
            assertTrue(
                result.toJson().contains(
                    "requested namespace conflicts with requested global label"));
        }
        assertNull(program.getSymbolTable().getGlobalSymbol(
            "Game", builder.addr("0x2460")));
        assertNull(program.getSymbolTable().getNamespace(
            "Game", program.getGlobalNamespace()));
    }

    @Test
    public void clearConflictsPreservesAnnotationsAndReportsWholeUnit()
            throws Exception {
        builder.setBytes("0x2500", "a9 01 60");
        builder.disassemble("0x2500", 3);
        builder.createLabel("0x2500", "keep_label");
        builder.createComment(
            "0x2500", "keep comment", CommentType.PLATE);
        Map<String, Object> byteRegion = contiguous(
            "0x2501", "0x2501", "byte");
        byteRegion.put("clear_conflicts", true);

        JsonObject preview = response(
            service.applyDataRegions(List.of(byteRegion), true, ""));
        assertEquals(1, preview.getAsJsonArray("conflicts").size());
        JsonObject cleared = preview.getAsJsonObject("clear_plan")
            .getAsJsonArray("code_units").get(0).getAsJsonObject();
        assertEquals("2500", cleared.get("start").getAsString());
        assertEquals("2501", cleared.get("end").getAsString());

        response(service.applyDataRegions(
            List.of(byteRegion), false, ""));
        assertNotNull(program.getListing().getDefinedDataAt(
            builder.addr("0x2501")));
        assertNotNull(program.getSymbolTable().getGlobalSymbol(
            "keep_label", builder.addr("0x2500")));
        assertEquals("keep comment", program.getListing().getComment(
            CommentType.PLATE, builder.addr("0x2500")));
    }

    @Test
    public void clearPlanReportsIntersectingFunctionRemoval()
            throws Exception {
        builder.setBytes("0x2520", "ea 60");
        builder.disassemble("0x2520", 2);
        builder.createFunction("0x2520");
        Map<String, Object> byteRegion = contiguous(
            "0x2520", "0x2520", "byte");
        byteRegion.put("clear_conflicts", true);

        JsonObject preview = response(
            service.applyDataRegions(List.of(byteRegion), true, ""));
        JsonObject clearPlan = preview.getAsJsonObject("clear_plan");
        assertEquals(1, clearPlan.getAsJsonArray("functions").size());
        assertEquals("2520",
            clearPlan.getAsJsonArray("functions").get(0).getAsJsonObject()
                .get("entry").getAsString());

        response(service.applyDataRegions(
            List.of(byteRegion), false, ""));
        assertNull(program.getFunctionManager()
            .getFunctionAt(builder.addr("0x2520")));
    }

    @Test
    public void fullDefinitionMustBeMappedEvenWhenEndpointsAreMapped()
            throws Exception {
        int tx = program.startTransaction("make memory hole");
        try {
            program.getMemory().split(
                program.getMemory().getBlock(builder.addr("0x7000")),
                builder.addr("0x7000"));
            program.getMemory().split(
                program.getMemory().getBlock(builder.addr("0x7000")),
                builder.addr("0x7003"));
            program.getMemory().removeBlock(
                program.getMemory().getBlock(builder.addr("0x7000")),
                ghidra.util.task.TaskMonitor.DUMMY);
        }
        finally {
            program.endTransaction(tx, true);
        }
        Map<String, Object> crossing = contiguous(
            "0x6ffe", "0x7003", "Record6");

        Response result = service.applyDataRegions(
            List.of(crossing), true, "");
        assertTrue(result.toJson(), result instanceof Response.Err);
        assertTrue(result.toJson().toLowerCase().contains("mapped"));
    }

    @Test
    public void cancelledLateApplyRollsBackEarlierRegions() {
        AtomicInteger checks = new AtomicInteger();
        TaskMonitorAdapter monitor = new TaskMonitorAdapter() {
            @Override
            public void checkCancelled() throws CancelledException {
                if (checks.incrementAndGet() == 7) {
                    throw new CancelledException();
                }
            }
        };
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        DataRegionService cancelling = new DataRegionService(
            provider, new DirectThreadingStrategy(),
            new DataRegionCore(), monitor);
        Map<String, Object> first = contiguous(
            "0x2600", "0x2600", "byte");
        Map<String, Object> second = contiguous(
            "0x2610", "0x2610", "byte");

        Response result = cancelling.applyDataRegions(
            List.of(first, second), false, "");
        assertTrue(result.toJson(), result instanceof Response.Err);
        assertNull(program.getListing().getDefinedDataAt(
            builder.addr("0x2600")));
        assertNull(program.getListing().getDefinedDataAt(
            builder.addr("0x2610")));
    }

    @Test
    public void cancellationDuringConflictClearingRollsBackClearedUnits()
            throws Exception {
        builder.applyDataType("0x2700", WordDataType.dataType);
        builder.applyDataType("0x2702", WordDataType.dataType);
        Map<String, Object> bytes = contiguous(
            "0x2700", "0x2703", "byte");
        bytes.put("clear_conflicts", true);
        DataRegionCore core = new DataRegionCore();
        DataRegionCore.Plan plan = core.plan(
            program, DataRegionService.parseRegions(List.of(bytes)));
        AtomicInteger checks = new AtomicInteger();
        TaskMonitorAdapter monitor = cancellingMonitor(checks, 5);

        int tx = program.startTransaction("cancel conflict clearing");
        try {
            assertThrows(
                CancelledException.class,
                () -> core.apply(program, plan, monitor));
        }
        finally {
            program.endTransaction(tx, false);
        }

        assertTrue(checks.get() >= 5);
        assertNotNull(program.getListing().getDefinedDataAt(
            builder.addr("0x2700")));
        assertNotNull(program.getListing().getDefinedDataAt(
            builder.addr("0x2702")));
    }

    @Test
    public void cancellationBetweenDataElementsRollsBackEarlierElements()
            throws Exception {
        Map<String, Object> bytes = contiguous(
            "0x2720", "0x2723", "byte");
        DataRegionCore core = new DataRegionCore();
        DataRegionCore.Plan plan = core.plan(
            program, DataRegionService.parseRegions(List.of(bytes)));
        AtomicInteger checks = new AtomicInteger();
        TaskMonitorAdapter monitor = cancellingMonitor(checks, 4);

        int tx = program.startTransaction("cancel data elements");
        try {
            assertThrows(
                CancelledException.class,
                () -> core.apply(program, plan, monitor));
        }
        finally {
            program.endTransaction(tx, false);
        }

        assertTrue(checks.get() >= 4);
        for (int i = 0; i < 4; i++) {
            assertNull(program.getListing().getDefinedDataAt(
                builder.addr("0x" + Integer.toHexString(0x2720 + i))));
        }
    }

    @Test
    public void cancellationIsCheckedDuringPlanningEnumeration() {
        AtomicInteger checks = new AtomicInteger();
        TaskMonitorAdapter monitor = new TaskMonitorAdapter() {
            @Override
            public void checkCancelled() throws CancelledException {
                if (checks.incrementAndGet() == 2) {
                    throw new CancelledException();
                }
            }
        };
        DataRegionCore core = new DataRegionCore();
        List<DataRegionCore.RegionRequest> requests =
            DataRegionService.parseRegions(List.of(
                contiguous("0x0800", "0x7fff", "byte")));

        assertThrows(
            CancelledException.class,
            () -> core.plan(program, requests, monitor));
        assertEquals(2, checks.get());
        assertNull(program.getListing().getDefinedDataAt(
            builder.addr("0x0800")));
    }

    @Test
    public void unsignedTargetBaseSupportsHighHalfAndRejectsOverflow()
            throws Exception {
        ProgramBuilder wideBuilder = new ProgramBuilder(
            "data-regions-x64", "x86:LE:64:default",
            "gcc", this);
        try {
            ProgramDB wide = wideBuilder.getProgram();
            wideBuilder.createMemory("source", "0x1000", 0x100);
            wideBuilder.createMemory(
                "high_target", "0x8000000000003000", 0x100);
            wideBuilder.setBytes("0x1000", "00 30");
            int tx = wide.startTransaction("add word");
            try {
                wide.getDataTypeManager().addDataType(
                    WordDataType.dataType,
                    DataTypeConflictHandler.REPLACE_HANDLER);
            }
            finally {
                wide.endTransaction(tx, true);
            }
            HeadlessProgramProvider provider = new HeadlessProgramProvider();
            provider.setCurrentProgram(wide);
            DataRegionService wideService = new DataRegionService(
                provider, new DirectThreadingStrategy());
            Map<String, Object> high = contiguous(
                "0x1000", "0x1001", "word");
            Map<String, Object> options = new LinkedHashMap<>();
            options.put("layout", "little_endian_words");
            options.put("target_space",
                wide.getAddressFactory().getDefaultAddressSpace().getName());
            options.put(
                "target_base",
                new java.math.BigDecimal("9223372036854775808"));
            options.put("validate_targets", true);
            high.put("pointers", options);

            JsonObject preview = response(
                wideService.applyDataRegions(List.of(high), true, ""));
            assertEquals(
                "8000000000003000", pointerTarget(preview, 0));

            options.put(
                "target_base",
                new java.math.BigDecimal("18446744073709551615"));
            Response overflow = wideService.applyDataRegions(
                List.of(high), true, "");
            assertTrue(overflow.toJson(), overflow instanceof Response.Err);
            assertTrue(overflow.toJson().contains("overflowing_target"));
        }
        finally {
            wideBuilder.dispose();
        }
    }

    @Test
    public void planCannotBeAppliedToAnotherProgram() throws Exception {
        DataRegionCore core = new DataRegionCore();
        DataRegionCore.Plan plan = core.plan(
            program,
            DataRegionService.parseRegions(List.of(
                contiguous("0x2700", "0x2700", "byte"))));
        ProgramBuilder otherBuilder = new ProgramBuilder(
            "other-data-regions-6502", "6502:LE:16:default",
            "default", this);
        try {
            ProgramDB other = otherBuilder.getProgram();
            otherBuilder.createMemory("ram", "0x0800", 0x7800);
            int tx = other.startTransaction("wrong owner");
            try {
                IllegalArgumentException error = assertThrows(
                    IllegalArgumentException.class,
                    () -> core.apply(
                        other, plan, ghidra.util.task.TaskMonitor.DUMMY));
                assertTrue(error.getMessage().contains("different program"));
            }
            finally {
                other.endTransaction(tx, false);
            }
            assertNull(other.getListing().getDefinedDataAt(
                otherBuilder.addr("0x2700")));
        }
        finally {
            otherBuilder.dispose();
        }
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

    private static TaskMonitorAdapter cancellingMonitor(
            AtomicInteger checks, int cancellationCheck) {
        return new TaskMonitorAdapter() {
            @Override
            public void checkCancelled() throws CancelledException {
                if (checks.incrementAndGet() == cancellationCheck) {
                    throw new CancelledException();
                }
            }
        };
    }

    private String defaultSpace() {
        return program.getAddressFactory()
            .getDefaultAddressSpace().getName();
    }

    private Map<String, Object> pointerOptions(
            boolean createReferences, boolean validateTargets,
            String prefix, String namespace) {
        Map<String, Object> pointers = new LinkedHashMap<>();
        pointers.put("layout", "little_endian_words");
        pointers.put("target_space", defaultSpace());
        pointers.put("create_references", createReferences);
        pointers.put("validate_targets", validateTargets);
        if (prefix != null) {
            pointers.put("target_label_prefix", prefix);
        }
        if (namespace != null) {
            pointers.put("label_namespace", namespace);
        }
        return pointers;
    }

    private Map<String, Object> pointerOptionsWith(
            String layout, Object targetBase,
            boolean createReferences, boolean validateTargets) {
        Map<String, Object> pointers = new LinkedHashMap<>();
        pointers.put("layout", layout);
        pointers.put("target_space", defaultSpace());
        pointers.put("target_base", targetBase);
        pointers.put("create_references", createReferences);
        pointers.put("validate_targets", validateTargets);
        return pointers;
    }

    private Map<String, Object> splitRegion(
            String first, String second, int count, String layout) {
        Map<String, Object> split = new LinkedHashMap<>();
        split.put("kind", "split_pointer_table");
        split.put("first_start", first);
        split.put("second_start", second);
        split.put("count", count);
        split.put("layout", layout);
        split.put("target_space", defaultSpace());
        return split;
    }

    private static String pointerTarget(
            JsonObject result, int region) {
        return result.getAsJsonArray("regions")
            .get(region).getAsJsonObject()
            .getAsJsonArray("pointers")
            .get(0).getAsJsonObject()
            .get("target").getAsString();
    }

    private int countMnemonicUserDataReferences(
            ghidra.program.model.address.Address from,
            ghidra.program.model.address.Address to) {
        int count = 0;
        for (Reference reference
                : program.getReferenceManager().getReferencesFrom(from)) {
            if (reference.getToAddress().equals(to)
                    && reference.getReferenceType() == RefType.DATA
                    && reference.getSource() == SourceType.USER_DEFINED
                    && reference.getOperandIndex() == Reference.MNEMONIC) {
                count++;
            }
        }
        return count;
    }

    private static String actionAt(
            JsonObject result, String array, int index) {
        return result.getAsJsonArray(array).get(index).getAsJsonObject()
            .get("action").getAsString();
    }

    private static void assertPlanFieldsEqual(
            JsonObject expected, JsonObject actual) {
        for (String field : List.of(
                "regions", "created_data", "symbols", "references",
                "namespaces", "comments", "conflicts", "clear_plan")) {
            assertEquals(field, expected.get(field), actual.get(field));
        }
    }

    private static JsonObject response(Response response) {
        if (response instanceof Response.Err error) {
            throw new AssertionError(error.message());
        }
        return JsonParser.parseString(response.toJson()).getAsJsonObject();
    }

    private static final class TestBitFieldDataType
            extends BitFieldDataType {
        TestBitFieldDataType() throws InvalidDataTypeException {
            super(ByteDataType.dataType, 4, 0);
        }
    }
}
