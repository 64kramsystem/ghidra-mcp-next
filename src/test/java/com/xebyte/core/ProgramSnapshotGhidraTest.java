package com.xebyte.core;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import com.google.gson.JsonParser;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class ProgramSnapshotGhidraTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private ProgramBuilder builder;

    @BeforeClass public static void initialize() throws Exception {
        if (!Application.isInitialized()) {
            var config = new ApplicationConfiguration();
            config.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(
                new File(System.getProperty("ghidra.test.install.dir"))), config);
        }
    }

    @After public void cleanup() { if (builder != null) builder.dispose(); }

    @Test public void exportsCompleteSnapshotAndRefusesReplacement() throws Exception {
        builder = new ProgramBuilder("snapshot-fixture", ProgramBuilder._X64, "gcc", this);
        var program = builder.getProgram();
        builder.createMemory("text", "0x1000", 2);
        builder.setBytes("0x1000", Files.readString(Path.of("src/test/resources/snapshot/bytes.txt")).trim());
        builder.disassemble("0x1000", 2);
        int tx = program.startTransaction("fixture");
        try {
            program.getSymbolTable().createLabel(builder.addr("0x1000"), "entry", SourceType.USER_DEFINED);
            program.getListing().setComment(builder.addr("0x1000"), CommentType.EOL, "hello");
            program.getReferenceManager().addMemoryReference(builder.addr("0x1000"),
                builder.addr("0x1001"), RefType.DATA, SourceType.USER_DEFINED, 0);
            program.getUsrPropertyManager().createVoidPropertyMap("listing.opaque").add(builder.addr("0x1001"));
        } finally { program.endTransaction(tx, true); }
        var provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        var security = mock(SecurityConfig.class);
        when(security.resolveWithinFileRoot(anyString())).thenAnswer(i -> Path.of(i.getArgument(0, String.class)));
        var service = new ExportService(provider, security);
        Path output = temp.getRoot().toPath().resolve("snapshot.json");
        Response response = service.exportProgramSnapshot(output.toString(), "");
        assertTrue(response.toJson(), response instanceof Response.Ok);
        var result = (com.google.gson.JsonObject) ((Response.Ok) response).data();
        assertEquals(output.toString(), result.get("output_path").getAsString());
        assertEquals(1, result.get("blocks").getAsInt());
        assertEquals(2, result.get("symbols").getAsInt());
        assertEquals(1, result.get("references").getAsInt());
        assertEquals(2, result.get("instructions").getAsInt());
        assertEquals(1, result.get("opaque").getAsInt());
        String actual = Files.readString(output);
        assertEquals(JsonParser.parseString(Files.readString(Path.of("src/test/resources/snapshot/expected.json"))), JsonParser.parseString(actual));
        assertFalse(service.exportProgramSnapshot(output.toString(), "") instanceof Response.Ok);
        assertEquals(actual, Files.readString(output));
        try (var paths = Files.list(temp.getRoot().toPath())) { assertEquals(1, paths.count()); }
    }
}
