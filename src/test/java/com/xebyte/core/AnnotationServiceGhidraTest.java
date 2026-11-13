package com.xebyte.core;

import static org.junit.Assert.*;

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
        assertEquals(2, snapshot.getAsJsonArray("data").size());
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

}
