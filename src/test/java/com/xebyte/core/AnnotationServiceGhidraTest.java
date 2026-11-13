package com.xebyte.core;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class AnnotationServiceGhidraTest {
    private static final String SHA = "0123456789abcdef".repeat(4);
    private ProgramBuilder source;
    private ProgramBuilder target;
    private Path directory;

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration config = new ApplicationConfiguration();
            config.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(
                new File(System.getProperty("ghidra.test.install.dir"))), config);
        }
    }

    @Before
    public void setUp() throws Exception {
        directory = Files.createTempDirectory("annotation-test");
        source = program("source");
        target = program("target");
    }

    @After
    public void tearDown() {
        if (source != null) source.dispose();
        if (target != null) target.dispose();
    }

    private ProgramBuilder program(String name) throws Exception {
        ProgramBuilder builder = new ProgramBuilder(name, "6502:LE:16:default", "default", this);
        builder.createMemory("ram", "0x1000", 0x100);
        builder.createOverlayMemory("bank_a", "0x1000", 0x20);
        builder.createOverlayMemory("bank_b", "0x1000", 0x20);
        builder.setBytes("0x1000", Files.readString(
            Path.of("src/test/resources/fixtures/annotations/code.hex")).trim());
        int tx = builder.getProgram().startTransaction("source identity");
        try { builder.getProgram().setExecutableSHA256(SHA); }
        finally { builder.getProgram().endTransaction(tx, true); }
        return builder;
    }

    private AnnotationService service(ProgramBuilder builder) {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(builder.getProgram());
        return new AnnotationService(provider, new DirectThreadingStrategy(),
            SecurityConfig.forFileRootTesting(directory));
    }

    private static void ok(Response response) {
        assertFalse(response.toJson(), response instanceof Response.Err);
    }

    private static void error(Response response) {
        assertTrue(response.toJson(), response instanceof Response.Err);
    }

    @Test
    public void roundTripPreservesAnnotationsAcrossSpacesAndIsIdempotent() throws Exception {
        source.disassemble("0x1000", 2);
        target.disassemble("0x1000", 2);
        source.applyDataType("0x1010", new ArrayDataType(ByteDataType.dataType, 4, 1));
        source.applyDataType("0x1020", new PointerDataType(ByteDataType.dataType, 2));
        source.applyDataType("0x1024", new PointerDataType(ByteDataType.dataType));
        ProgramDB program = source.getProgram();
        int tx = program.startTransaction("annotations");
        try {
            program.getUsrPropertyManager().createVoidPropertyMap("listing.opaque").add(source.addr("0x1010"));
            program.getListing().setComment(source.addr("0x1000"), CommentType.EOL, "instruction");
            program.getListing().setComment(source.addr("0x1001"), CommentType.PLATE, "instruction interior");
            program.getListing().setComment(source.addr("0x1012"), CommentType.REPEATABLE, "data interior");
            program.getSymbolTable().createLabel(source.addr("0x1000"), "ENTRY", SourceType.USER_DEFINED);
            program.getSymbolTable().createLabel(source.addr("0x1000"), "ALIAS", SourceType.IMPORTED);
            program.getSymbolTable().createLabel(source.addr("bank_a::1000"), "BANK_A", SourceType.USER_DEFINED);
            program.getSymbolTable().createLabel(source.addr("bank_b::1000"), "BANK_B", SourceType.USER_DEFINED);
        }
        finally { program.endTransaction(tx, true); }
        Path first = directory.resolve("first.json");
        Path second = directory.resolve("second.json");
        ok(service(source).exportAnnotations(first.toString(), false, false, ""));
        JsonObject snapshot = JsonParser.parseString(Files.readString(first)).getAsJsonObject();
        assertEquals(3, snapshot.getAsJsonArray("comments").size());
        assertEquals(4, snapshot.getAsJsonArray("symbols").size());
        assertEquals(3, snapshot.getAsJsonArray("data").size());
        ok(service(target).importAnnotations(first.toString(), ""));
        long modification = target.getProgram().getModificationNumber();
        ok(service(target).importAnnotations(first.toString(), ""));
        assertEquals(modification, target.getProgram().getModificationNumber());
        ok(service(target).exportAnnotations(second.toString(), false, false, ""));
        assertEquals(Files.readString(first), Files.readString(second));
    }

    @Test
    public void changedBytesAndSourceIdentityRejectImportWithoutMutation() throws Exception {
        Path snapshot = directory.resolve("snapshot.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        target.setBytes("0x1000", "00");
        long before = target.getProgram().getModificationNumber();
        error(service(target).importAnnotations(snapshot.toString(), ""));
        assertEquals(before, target.getProgram().getModificationNumber());
        target.setBytes("0x1000", "a9");
        int tx = target.getProgram().startTransaction("change identity");
        try { target.getProgram().setExecutableSHA256("f".repeat(64)); }
        finally { target.getProgram().endTransaction(tx, true); }
        before = target.getProgram().getModificationNumber();
        error(service(target).importAnnotations(snapshot.toString(), ""));
        assertEquals(before, target.getProgram().getModificationNumber());
    }

    @Test
    public void replacementDetectsLossDespiteAdditionsAndLeavesFileUntouched() throws Exception {
        ProgramDB program = source.getProgram();
        int tx = program.startTransaction("original comment");
        try { program.getListing().setComment(source.addr("0x1000"), CommentType.EOL, "old"); }
        finally { program.endTransaction(tx, true); }
        Path snapshot = directory.resolve("snapshot.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        String original = Files.readString(snapshot);
        tx = program.startTransaction("move comment");
        try {
            program.getListing().setComment(source.addr("0x1000"), CommentType.EOL, null);
            program.getListing().setComment(source.addr("0x1002"), CommentType.EOL, "new");
        }
        finally { program.endTransaction(tx, true); }
        error(service(source).exportAnnotations(snapshot.toString(), true, false, ""));
        assertEquals(original, Files.readString(snapshot));
        ok(service(source).exportAnnotations(snapshot.toString(), true, true, ""));
    }
    @Test
    public void conflictingDataRejectsWholeImport() throws Exception {
        source.applyDataType("0x1010", new ArrayDataType(ByteDataType.dataType, 4, 1));
        ProgramDB sourceProgram = source.getProgram();
        int tx = sourceProgram.startTransaction("comment before conflict");
        try {
            sourceProgram.getListing().setComment(source.addr("0x1000"), CommentType.EOL, "incoming");
        }
        finally { sourceProgram.endTransaction(tx, true); }
        target.applyDataType("0x1010", ByteDataType.dataType);
        Path snapshot = directory.resolve("conflict.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        long before = target.getProgram().getModificationNumber();
        Response conflict = service(target).importAnnotations(snapshot.toString(), "");
        error(conflict);
        assertTrue(conflict.toJson(), conflict.toJson().toLowerCase().contains("conflict"));
        assertEquals(before, target.getProgram().getModificationNumber());
        assertNull(target.getProgram().getListing().getComment(CommentType.EOL, target.addr("0x1000")));
        assertEquals(1, target.getProgram().getListing().getDataAt(target.addr("0x1010")).getLength());
    }

    @Test
    public void importDoesNotRequireInstructionsOrFunctions() throws Exception {
        source.disassemble("0x1000", 2);
        var function = source.createFunction("0x1000");
        ProgramDB program = source.getProgram();
        int tx = program.startTransaction("name function");
        try { function.setName("START", SourceType.USER_DEFINED); }
        finally { program.endTransaction(tx, true); }
        Path snapshot = directory.resolve("function.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        ok(service(target).importAnnotations(snapshot.toString(), ""));
        assertNull(target.getProgram().getFunctionManager().getFunctionAt(target.addr("0x1000")));
        assertNotNull(target.getProgram().getSymbolTable().getGlobalSymbol("START", target.addr("0x1000")));
    }

    @Test
    public void malformedRecordsAndDifferentMappingsAreRejected() throws Exception {
        Path snapshot = directory.resolve("invalid.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        String valid = Files.readString(snapshot);
        JsonObject invalid = JsonParser.parseString(valid).getAsJsonObject();
        invalid.addProperty("unexpected", true);
        Files.writeString(snapshot, invalid.toString());
        long before = target.getProgram().getModificationNumber();
        error(service(target).importAnnotations(snapshot.toString(), ""));
        assertEquals(before, target.getProgram().getModificationNumber());
        Files.writeString(snapshot, valid);
        target.createOverlayMemory("extra", "0x1000", 0x20);
        before = target.getProgram().getModificationNumber();
        error(service(target).importAnnotations(snapshot.toString(), ""));
        assertEquals(before, target.getProgram().getModificationNumber());
    }

    @Test
    public void replacingLostLabelFailsEvenWhenAnotherLabelIsAdded() throws Exception {
        ProgramDB program = source.getProgram();
        int tx = program.startTransaction("original label");
        try { program.getSymbolTable().createLabel(source.addr("0x1000"), "OLD", SourceType.USER_DEFINED); }
        finally { program.endTransaction(tx, true); }
        Path snapshot = directory.resolve("labels.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        String original = Files.readString(snapshot);
        tx = program.startTransaction("move label");
        try {
            program.getSymbolTable().getGlobalSymbol("OLD", source.addr("0x1000")).delete();
            program.getSymbolTable().createLabel(source.addr("0x1001"), "NEW", SourceType.USER_DEFINED);
        }
        finally { program.endTransaction(tx, true); }
        error(service(source).exportAnnotations(snapshot.toString(), true, false, ""));
        assertEquals(original, Files.readString(snapshot));
    }

    @Test
    public void customTypeMustExistAndRoundTripsByPath() throws Exception {
        StructureDataType record = new StructureDataType("SnapshotRecord", 3);
        source.applyDataType("0x1010", record);
        Path first = directory.resolve("custom.json");
        ok(service(source).exportAnnotations(first.toString(), false, false, ""));
        long before = target.getProgram().getModificationNumber();
        Response missing = service(target).importAnnotations(first.toString(), "");
        error(missing);
        assertTrue(missing.toJson(), missing.toJson().contains("SnapshotRecord"));
        assertEquals(before, target.getProgram().getModificationNumber());
        int tx = target.getProgram().startTransaction("install custom type");
        try {
            target.getProgram().getDataTypeManager().addDataType(record,
                DataTypeConflictHandler.DEFAULT_HANDLER);
        }
        finally { target.getProgram().endTransaction(tx, true); }
        ok(service(target).importAnnotations(first.toString(), ""));
        assertEquals("/SnapshotRecord", target.getProgram().getListing()
            .getDefinedDataAt(target.addr("0x1010")).getDataType().getPathName());
        Path second = directory.resolve("custom-roundtrip.json");
        ok(service(target).exportAnnotations(second.toString(), false, false, ""));
        assertEquals(Files.readString(first), Files.readString(second));
    }

    @Test
    public void realModeCanonicalOffsetsRoundTripAtPhysicalAddress() throws Exception {
        ProgramBuilder from = new ProgramBuilder("real-source", "x86:LE:16:Real Mode", "default", this);
        ProgramBuilder to = new ProgramBuilder("real-target", "x86:LE:16:Real Mode", "default", this);
        try {
            for (ProgramBuilder builder : new ProgramBuilder[] {from, to}) {
                builder.createMemory("ram", "1234:0000", 0x100);
                int tx = builder.getProgram().startTransaction("identity");
                try { builder.getProgram().setExecutableSHA256(SHA); }
                finally { builder.getProgram().endTransaction(tx, true); }
            }
            var physical = from.addr("1234:0010");
            int tx = from.getProgram().startTransaction("annotations");
            try {
                from.getProgram().getSymbolTable().createLabel(physical, "SEGMENTED", SourceType.USER_DEFINED);
                from.getProgram().getListing().setComment(physical, CommentType.EOL, "physical location");
            }
            finally { from.getProgram().endTransaction(tx, true); }
            Path first = directory.resolve("real.json");
            Path second = directory.resolve("real-roundtrip.json");
            ok(service(from).exportAnnotations(first.toString(), false, false, ""));
            JsonObject json = JsonParser.parseString(Files.readString(first)).getAsJsonObject();
            assertEquals(Long.toUnsignedString(physical.getOffset(), 16), json.getAsJsonArray("symbols")
                .get(0).getAsJsonObject().get("offset").getAsString());
            ok(service(to).importAnnotations(first.toString(), ""));
            var destination = to.addr("1234:0010");
            assertNotNull(to.getProgram().getSymbolTable().getGlobalSymbol("SEGMENTED", destination));
            assertEquals("physical location", to.getProgram().getListing().getComment(CommentType.EOL, destination));
            ok(service(to).exportAnnotations(second.toString(), false, false, ""));
            assertEquals(Files.readString(first), Files.readString(second));
        }
        finally { from.dispose(); to.dispose(); }
    }

    @Test
    public void missingNamespaceAfterDataWriteRollsBackImport() throws Exception {
        source.applyDataType("0x1010", ByteDataType.dataType);
        int tx = source.getProgram().startTransaction("namespaced label");
        try {
            var namespace = source.getProgram().getSymbolTable().createNameSpace(
                source.getProgram().getGlobalNamespace(), "SCOPE", SourceType.USER_DEFINED);
            source.getProgram().getSymbolTable().createLabel(source.addr("0x1000"), "ENTRY", namespace, SourceType.USER_DEFINED);
        }
        finally { source.getProgram().endTransaction(tx, true); }
        Path snapshot = directory.resolve("rollback.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        Response result = service(target).importAnnotations(snapshot.toString(), "");
        error(result);
        assertTrue(result.toJson(), result.toJson().contains("SCOPE"));
        assertNull(target.getProgram().getListing().getDefinedDataAt(target.addr("0x1010")));
        assertNull(target.getProgram().getSymbolTable().getNamespace("SCOPE", target.getProgram().getGlobalNamespace()));
        tx = target.getProgram().startTransaction("matching namespace");
        try { target.getProgram().getSymbolTable().createNameSpace(
            target.getProgram().getGlobalNamespace(), "SCOPE", SourceType.USER_DEFINED); }
        finally { target.getProgram().endTransaction(tx, true); }
        ok(service(target).importAnnotations(snapshot.toString(), ""));
        var namespace = target.getProgram().getSymbolTable().getNamespace("SCOPE", target.getProgram().getGlobalNamespace());
        assertNotNull(target.getProgram().getSymbolTable().getSymbol("ENTRY", target.addr("0x1000"), namespace));
    }

    @Test
    public void primaryLabelAtExistingFunctionIsReportedAsSkipped() throws Exception {
        int tx = source.getProgram().startTransaction("source label");
        try { source.getProgram().getSymbolTable().createLabel(source.addr("0x1000"), "ENTRY", SourceType.USER_DEFINED); }
        finally { source.getProgram().endTransaction(tx, true); }
        target.disassemble("0x1000", 2);
        var function = target.createFunction("0x1000");
        tx = target.getProgram().startTransaction("name existing function");
        try { function.setName("EXISTING", SourceType.USER_DEFINED); }
        finally { target.getProgram().endTransaction(tx, true); }
        Path snapshot = directory.resolve("primary.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        Response result = service(target).importAnnotations(snapshot.toString(), "");
        ok(result);
        assertEquals(1, JsonParser.parseString(result.toJson()).getAsJsonObject().getAsJsonArray("skipped").size());
        assertEquals("EXISTING", function.getName());
        assertTrue(function.getSymbol().isPrimary());
        assertNotNull(target.getProgram().getSymbolTable().getGlobalSymbol("ENTRY", target.addr("0x1000")));
    }
    @Test
    public void functionImportAbsorbsMatchingLabel() throws Exception {
        int tx = source.getProgram().startTransaction("source label");
        try { source.getProgram().getSymbolTable().createLabel(source.addr("0x1000"), "ENTRY", SourceType.USER_DEFINED); }
        finally { source.getProgram().endTransaction(tx, true); }
        target.disassemble("0x1000", 2);
        var function = target.createFunction("0x1000");
        tx = target.getProgram().startTransaction("target symbols");
        try {
            function.setName("EXISTING", SourceType.USER_DEFINED);
            target.getProgram().getSymbolTable().createLabel(target.addr("0x1000"), "OTHER", SourceType.USER_DEFINED);
        } finally { target.getProgram().endTransaction(tx, true); }
        Path labels = directory.resolve("labels.json");
        ok(service(source).exportAnnotations(labels.toString(), false, false, ""));
        ok(service(target).importAnnotations(labels.toString(), ""));
        source.disassemble("0x1000", 2);
        var sourceFunction = source.createFunction("0x1000");
        assertEquals("ENTRY", sourceFunction.getName());
        Path functions = directory.resolve("functions.json");
        ok(service(source).exportAnnotations(functions.toString(), false, false, ""));
        ok(service(target).importAnnotations(functions.toString(), ""));
        assertEquals("ENTRY", function.getName());
        assertTrue(function.getSymbol().isPrimary());
        assertNotNull(target.getProgram().getSymbolTable().getGlobalSymbol("OTHER", target.addr("0x1000")));
        long modification = target.getProgram().getModificationNumber();
        ok(service(target).importAnnotations(functions.toString(), ""));
        assertEquals(modification, target.getProgram().getModificationNumber());
    }

    @Test
    public void reportsOverwrittenComment() throws Exception {
        for (ProgramBuilder builder : new ProgramBuilder[] {source, target}) {
            int tx = builder.getProgram().startTransaction("comment");
            try { builder.getProgram().getListing().setComment(builder.addr("0x1000"), CommentType.EOL,
                builder == source ? "new text" : "old text"); }
            finally { builder.getProgram().endTransaction(tx, true); }
        }
        Path snapshot = directory.resolve("overwrite-comment.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        Response response = service(target).importAnnotations(snapshot.toString(), "");
        ok(response);
        assertTrue(response.toJson(), response.toJson().contains("old text"));
        assertEquals("new text", target.getProgram().getListing().getComment(CommentType.EOL, target.addr("0x1000")));
    }

    @Test
    public void lostDataCodeAndOpaqueAreReported() throws Exception {
        source.disassemble("0x1000", 2);
        source.applyDataType("0x1010", new ArrayDataType(ByteDataType.dataType, 4, 1));
        int tx = source.getProgram().startTransaction("opaque");
        try { source.getProgram().getUsrPropertyManager().createVoidPropertyMap("listing.opaque").add(source.addr("0x1010")); }
        finally { source.getProgram().endTransaction(tx, true); }
        Path snapshot = directory.resolve("coverage.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        String original = Files.readString(snapshot);
        tx = source.getProgram().startTransaction("remove classifications");
        try {
            source.getProgram().getListing().clearCodeUnits(source.addr("0x1000"), source.addr("0x1001"), false);
            source.getProgram().getListing().clearCodeUnits(source.addr("0x1010"), source.addr("0x1013"), false);
            source.getProgram().getUsrPropertyManager().getVoidPropertyMap("listing.opaque").remove(source.addr("0x1010"));
        }
        finally { source.getProgram().endTransaction(tx, true); }
        Response response = service(source).exportAnnotations(snapshot.toString(), true, false, "");
        error(response);
        assertTrue(response.toJson(), response.toJson().contains("instructions"));
        assertTrue(response.toJson(), response.toJson().contains("data"));
        assertTrue(response.toJson(), response.toJson().contains("opaque"));
        assertEquals(original, Files.readString(snapshot));
    }

    @Test
    public void defaultFunctionPromotionIsReported() throws Exception {
        int tx = source.getProgram().startTransaction("source label");
        try { source.getProgram().getSymbolTable().createLabel(source.addr("0x1000"), "ENTRY", SourceType.USER_DEFINED); }
        finally { source.getProgram().endTransaction(tx, true); }
        target.disassemble("0x1000", 2);
        var function = target.createFunction("0x1000");
        String oldName = function.getName();
        Path snapshot = directory.resolve("default-function.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        Response response = service(target).importAnnotations(snapshot.toString(), "");
        ok(response);
        assertTrue(response.toJson(), response.toJson().contains(oldName));
        assertEquals("ENTRY", function.getName());
    }

    @Test
    public void nonIntegralAndOutOfRangeNumbersAreRejected() throws Exception {
        source.applyDataType("0x1010", new ArrayDataType(ByteDataType.dataType, 4, 1));
        Path snapshot = directory.resolve("numbers.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        JsonObject valid = JsonParser.parseString(Files.readString(snapshot)).getAsJsonObject();
        for (String field : new String[] {"schema", "length", "count"}) {
            for (String number : new String[] {"1.5", "2147483648"}) {
                JsonObject invalid = valid.deepCopy();
                JsonObject row = invalid.getAsJsonArray("data").get(0).getAsJsonObject();
                JsonObject object = field.equals("schema") ? invalid : field.equals("length") ? row : row.getAsJsonObject("type");
                object.add(field, JsonParser.parseString(number));
                Files.writeString(snapshot, invalid.toString());
                long before = target.getProgram().getModificationNumber();
                error(service(target).importAnnotations(snapshot.toString(), ""));
                assertEquals(before, target.getProgram().getModificationNumber());
            }
        }
    }

    @Test
    public void rewordRenameAndSplitDataPreserveCoverage() throws Exception {
        source.applyDataType("0x1010", new ArrayDataType(ByteDataType.dataType, 4, 1));
        int tx = source.getProgram().startTransaction("initial annotations");
        try {
            source.getProgram().getListing().setComment(source.addr("0x1000"), CommentType.EOL, "old");
            source.getProgram().getSymbolTable().createLabel(source.addr("0x1000"), "OLD", SourceType.USER_DEFINED);
        }
        finally { source.getProgram().endTransaction(tx, true); }
        Path snapshot = directory.resolve("edits.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        tx = source.getProgram().startTransaction("edit annotations");
        try {
            source.getProgram().getListing().setComment(source.addr("0x1000"), CommentType.EOL, "new");
            source.getProgram().getSymbolTable().getGlobalSymbol("OLD", source.addr("0x1000"))
                .setName("NEW", SourceType.USER_DEFINED);
            source.getProgram().getListing().clearCodeUnits(source.addr("0x1010"), source.addr("0x1013"), false);
            for (int offset = 0x1010; offset < 0x1014; offset++)
                source.getProgram().getListing().createData(source.addr(Integer.toHexString(offset)), ByteDataType.dataType);
        }
        finally { source.getProgram().endTransaction(tx, true); }
        ok(service(source).exportAnnotations(snapshot.toString(), true, false, ""));
    }

    @Test
    public void unsignedHighAddressRoundTrips() throws Exception {
        ProgramBuilder from = new ProgramBuilder("high-source", ProgramBuilder._X64, "gcc", this);
        ProgramBuilder to = new ProgramBuilder("high-target", ProgramBuilder._X64, "gcc", this);
        try {
            for (ProgramBuilder builder : new ProgramBuilder[] {from, to}) {
                builder.createMemory("high", "0x8000000000003000", 0x100);
                int tx = builder.getProgram().startTransaction("identity");
                try { builder.getProgram().setExecutableSHA256(SHA); }
                finally { builder.getProgram().endTransaction(tx, true); }
            }
            var address = from.addr("0x8000000000003004");
            int tx = from.getProgram().startTransaction("high annotations");
            try {
                from.getProgram().getSymbolTable().createLabel(address, "HIGH", SourceType.USER_DEFINED);
                from.getProgram().getListing().setComment(address, CommentType.EOL, "high address");
            }
            finally { from.getProgram().endTransaction(tx, true); }
            Path first = directory.resolve("high.json");
            Path second = directory.resolve("high-roundtrip.json");
            ok(service(from).exportAnnotations(first.toString(), false, false, ""));
            JsonObject snapshot = JsonParser.parseString(Files.readString(first)).getAsJsonObject();
            assertEquals("8000000000003004", snapshot.getAsJsonArray("symbols").get(0)
                .getAsJsonObject().get("offset").getAsString());
            ok(service(to).importAnnotations(first.toString(), ""));
            var destination = to.addr("0x8000000000003004");
            assertNotNull(to.getProgram().getSymbolTable().getGlobalSymbol("HIGH", destination));
            assertEquals("high address", to.getProgram().getListing().getComment(CommentType.EOL, destination));
            ok(service(to).exportAnnotations(second.toString(), false, false, ""));
            assertEquals(Files.readString(first), Files.readString(second));
        }
        finally { from.dispose(); to.dispose(); }
    }

    @Test
    public void modificationDuringExportKeepsPreviousFile() throws Exception {
        Path snapshot = directory.resolve("changed-during-export.json");
        ok(service(source).exportAnnotations(snapshot.toString(), false, false, ""));
        String original = Files.readString(snapshot);
        ProgramDB spied = spy(source.getProgram());
        long version = source.getProgram().getModificationNumber();
        doReturn(version, version + 1).when(spied).getModificationNumber();
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(spied);
        AnnotationService instrumented = new AnnotationService(provider, new DirectThreadingStrategy(),
            SecurityConfig.forFileRootTesting(directory));
        Response response = instrumented.exportAnnotations(snapshot.toString(), true, false, "");
        error(response);
        assertTrue(response.toJson(), response.toJson().contains("changed during export"));
        assertEquals(original, Files.readString(snapshot));
    }

}