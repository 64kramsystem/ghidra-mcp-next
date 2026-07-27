package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assume.assumeTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import java.io.File;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Real-Ghidra coverage for dynamic-name parsing in ordinary and overlay spaces.
 */
public class CoverageServiceGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private CoverageService coverage;

    @BeforeClass
    public static void initializeGhidraOrSkip() throws Exception {
        String installDir = System.getProperty("ghidra.test.install.dir");
        assumeTrue("ghidra.test.install.dir is required",
            installDir != null && !installDir.isBlank());
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
            "stale-comment-names-6502",
            "6502:LE:16:default",
            "default",
            this);
        program = builder.getProgram();
        builder.createMemory("ram", "0x0000", 0x10000);
        builder.createOverlayMemory("SND_PLAYER", "0x1600", 0x20);
        builder.applyDataType("0x3000", ByteDataType.dataType);

        Address room = builder.addr("0x2942");
        Address script = builder.addr("SND_PLAYER::1605");
        Address typedByte = builder.addr("0x3000");
        String roomDefault =
            SymbolUtilities.getDynamicName(SymbolUtilities.DAT_LEVEL, room);
        String scriptDefault =
            SymbolUtilities.getDynamicName(SymbolUtilities.SUB_LEVEL, script);
        String typedByteDefault =
            SymbolUtilities.getDynamicName(program, typedByte);
        int transaction = program.startTransaction("stale comments");
        try {
            program.getSymbolTable().createLabel(
                room, "CURRENT_ROOM_GRAPHIC_ID", SourceType.USER_DEFINED);
            program.getSymbolTable().createLabel(
                script, "RUN_SCRIPT", SourceType.USER_DEFINED);
            program.getSymbolTable().createLabel(
                typedByte, "ROOM_FLAGS", SourceType.USER_DEFINED);
            program.getListing().setComment(
                builder.addr("0x0801"), CommentType.EOL, roomDefault);
            program.getListing().setComment(
                builder.addr("0x0802"), CommentType.PLATE, scriptDefault);
            program.getListing().setComment(
                builder.addr("0x0803"), CommentType.REPEATABLE, typedByteDefault);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        coverage = new CoverageService(provider, new DirectThreadingStrategy());
    }

    @After
    public void tearDown() {
        if (builder != null) builder.dispose();
    }

    @Test
    public void nativeParserResolvesDefaultAndOverlayGeneratedNames() {
        JsonObject result = ok(
            coverage.auditStaleCommentNames(100, 0, program.getName()));
        JsonArray items = result.getAsJsonArray("items");

        assertEquals(3, items.size());
        assertEquals("CURRENT_ROOM_GRAPHIC_ID",
            items.get(0).getAsJsonObject().get("current_primary_name").getAsString());
        assertEquals("RAM:2942",
            items.get(0).getAsJsonObject().get("target_address").getAsString());
        assertEquals("RUN_SCRIPT",
            items.get(1).getAsJsonObject().get("current_primary_name").getAsString());
        assertEquals("SND_PLAYER::1605",
            items.get(1).getAsJsonObject().get("target_address").getAsString());
        assertEquals("BYTE_3000",
            items.get(2).getAsJsonObject().get("stale_name").getAsString());
        assertEquals("ROOM_FLAGS",
            items.get(2).getAsJsonObject().get("current_primary_name").getAsString());
    }

    private static JsonObject ok(Response response) {
        assertFalse(response.toJson(), response instanceof Response.Err);
        return JsonParser.parseString(response.toJson()).getAsJsonObject();
    }
}
