package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;

/**
 * ProgramBuilder-backed regression coverage for exact-address plate comments.
 */
public class CommentServiceAddressGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;
    private CommentService comments;

    @BeforeClass
    public static void initializeGhidraOrSkip() throws Exception {
        String installDir = System.getProperty("ghidra.test.install.dir");
        assumeTrue(
            "ghidra.test.install.dir is required for real Ghidra tests",
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
            "address-comments-6502",
            "6502:LE:16:default",
            "default",
            this);
        program = builder.getProgram();
        builder.createMemory(".ram", "0x1000", 0x100);
        builder.setBytes("0x1000", "ea 60");
        builder.disassemble("0x1000", 2);
        builder.applyDataType("0x1010", ByteDataType.dataType);
        builder.createLabel("0x1030", "label_only");
        builder.createMemory(".bank-base", "0x2000", 0x20);
        builder.createOverlayMemory("bank", "0x2000", 0x20);

        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        comments = new CommentService(
            provider, new DirectThreadingStrategy());
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void plateCommentUsesExactInstructionAddressWithoutFunction() {
        assertEquals(0, program.getFunctionManager().getFunctionCount());

        JsonObject result = setPlate("0x1000", "instruction note");

        assertEquals(
            "instruction note",
            program.getListing().getComment(
                CommentType.PLATE, builder.addr("0x1000")));
        assertEquals("1000", result.get("address").getAsString());
        assertTrue(result.get("changed").getAsBoolean());
        assertEquals(0, program.getFunctionManager().getFunctionCount());
    }

    @Test
    public void plateCommentUsesExactDefinedDataAddressWithoutFunction() {
        JsonObject result = setPlate("0x1010", "data note");

        assertEquals(
            "data note",
            program.getListing().getComment(
                CommentType.PLATE, builder.addr("0x1010")));
        assertTrue(result.get("changed").getAsBoolean());
    }

    @Test
    public void plateCommentUsesExactUndefinedLabelOnlyAddressWithoutCode() {
        long codeUnitsBefore = countCodeUnits();
        int functionsBefore =
            program.getFunctionManager().getFunctionCount();

        JsonObject result = setPlate("0x1030", "table note");

        assertEquals(
            "table note",
            program.getListing().getComment(
                CommentType.PLATE, builder.addr("0x1030")));
        assertTrue(result.get("changed").getAsBoolean());
        assertEquals(codeUnitsBefore, countCodeUnits());
        assertEquals(
            functionsBefore,
            program.getFunctionManager().getFunctionCount());
    }

    @Test
    public void repeatedPlateValueIsSuccessfulNoOp() {
        setPlate("0x1020", "stable");

        JsonObject repeated = setPlate("0x1020", "stable");

        assertFalse(repeated.get("changed").getAsBoolean());
        assertEquals("stable", repeated.get("previous").getAsString());
        assertEquals("stable", repeated.get("resulting").getAsString());
    }

    @Test
    public void createReplaceAndRemoveReportPreviousAndResultingState() {
        JsonObject created = setPlate("0x1020", "first");
        assertTrue(created.has("previous"));
        assertTrue(created.get("previous").isJsonNull());
        assertEquals("first", created.get("resulting").getAsString());
        assertTrue(created.get("changed").getAsBoolean());

        JsonObject replaced = setPlate("0x1020", "second");
        assertEquals("first", replaced.get("previous").getAsString());
        assertEquals("second", replaced.get("resulting").getAsString());
        assertTrue(replaced.get("changed").getAsBoolean());

        JsonObject removed = setPlate("0x1020", "");
        assertEquals("second", removed.get("previous").getAsString());
        assertTrue(removed.has("resulting"));
        assertTrue(removed.get("resulting").isJsonNull());
        assertTrue(removed.get("changed").getAsBoolean());
        assertNull(program.getListing().getComment(
            CommentType.PLATE, builder.addr("0x1020")));
    }

    @Test
    public void nullAndOmittedCommentAreRejectedBeforeMutation() throws Exception {
        Address address = builder.addr("0x1020");
        builder.createComment("0x1020", "keep", CommentType.PLATE);

        Response nullComment =
            comments.setPlateComment("0x1020", null, "");
        assertTrue(nullComment.toJson(), nullComment instanceof Response.Err);
        assertTrue(
            nullComment.toJson(),
            nullComment.toJson().toLowerCase().contains("comment") &&
                nullComment.toJson().toLowerCase().contains("required"));

        EndpointDef endpoint =
            new AnnotationScanner(comments).getEndpoints().stream()
                .filter(candidate ->
                    "/set_plate_comment".equals(candidate.path()))
                .findFirst()
                .orElseThrow();
        Response omitted =
            endpoint.handler().handle(Map.of(), Map.of("address", "0x1020"));
        assertTrue(omitted.toJson(), omitted instanceof Response.Err);
        assertTrue(
            omitted.toJson(),
            omitted.toJson().toLowerCase().contains("comment") &&
                omitted.toJson().toLowerCase().contains("required"));
        assertEquals(
            "keep",
            program.getListing().getComment(CommentType.PLATE, address));
    }

    @Test
    public void invalidUnmappedAddressIsRejectedBeforeMutation() {
        Response response =
            comments.setPlateComment("0x3000", "outside", "");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(
            response.toJson(),
            response.toJson().toLowerCase().contains("mapped") ||
                response.toJson().toLowerCase().contains("memory"));
    }

    @Test
    public void qualifiedOverlayAddressSucceedsAndBareOffsetIsAmbiguous() {
        Address overlay = builder.addr("bank::2000");
        assertTrue(program.getMemory().contains(overlay));

        JsonObject result = setPlate("bank:2000", "overlay note");

        assertEquals(
            "overlay note",
            program.getListing().getComment(CommentType.PLATE, overlay));
        assertEquals("bank", result.get("address_space").getAsString());
        assertEquals("bank::2000", result.get("address_full").getAsString());

        Response ambiguous =
            comments.setPlateComment("0x2000", "wrong space", "");
        assertTrue(ambiguous.toJson(), ambiguous instanceof Response.Err);
        assertTrue(
            ambiguous.toJson(),
            ambiguous.toJson().toLowerCase().contains("ambiguous") &&
                ambiguous.toJson().contains("bank"));
        assertNull(program.getListing().getComment(
            CommentType.PLATE, builder.addr("0x2000")));
    }

    @Test
    public void setAndBatchPlatePathsHaveParityAtLabelOnlyAddress() {
        setPlate("0x1030", "single");
        assertEquals(
            "single",
            program.getListing().getComment(
                CommentType.PLATE, builder.addr("0x1030")));

        Response batch = comments.batchSetComments(
            "0x1030", List.of(), List.of(), "batch", "");

        assertTrue(batch.toJson(), batch instanceof Response.Ok);
        assertTrue(batch.toJson(), batch.toJson().contains(
            "\"plate_comment_set\":true"));
        assertEquals(
            "batch",
            program.getListing().getComment(
                CommentType.PLATE, builder.addr("0x1030")));
    }

    @Test
    public void failedTransactionRollsBackPreviousComment() {
        builder.createComment("0x1030", "before", CommentType.PLATE);
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        CommentService aborting =
            new CommentService(provider, new AbortAfterActionStrategy());

        Response response =
            aborting.setPlateComment("0x1030", "after", "");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(
            response.toJson(),
            response.toJson().contains("forced rollback"));
        assertEquals(
            "before",
            program.getListing().getComment(
                CommentType.PLATE, builder.addr("0x1030")));
    }

    @Test
    public void plateWritesCreateNoProgramArtifactsAtAnyAddressKind() {
        ProgramState before = state();

        setPlate("0x1000", "instruction");
        setPlate("0x1010", "data");
        setPlate("0x1020", "undefined");
        setPlate("0x1030", "label");

        assertEquals(before, state());
    }

    private JsonObject setPlate(String address, String text) {
        Response response = comments.setPlateComment(address, text, "");
        assertTrue(response.toJson(), response instanceof Response.Ok);
        return JsonParser.parseString(response.toJson()).getAsJsonObject();
    }

    private long countCodeUnits() {
        long count = 0;
        var units = program.getListing().getCodeUnits(true);
        while (units.hasNext()) {
            units.next();
            count++;
        }
        return count;
    }

    private ProgramState state() {
        return new ProgramState(
            program.getFunctionManager().getFunctionCount(),
            program.getListing().getNumCodeUnits(),
            program.getListing().getNumInstructions(),
            program.getListing().getNumDefinedData(),
            program.getSymbolTable().getNumSymbols());
    }

    private record ProgramState(
            int functions,
            long codeUnits,
            long instructions,
            long definedData,
            int symbols) {
    }

    private static final class AbortAfterActionStrategy
            implements ThreadingStrategy {

        @Override
        public <T> T executeRead(Callable<T> action) throws Exception {
            return action.call();
        }

        @Override
        public <T> T executeWrite(
                Program program, String txName, Callable<T> action)
                throws Exception {
            int transaction = program.startTransaction(txName);
            try {
                action.call();
            }
            finally {
                program.endTransaction(transaction, false);
            }
            throw new IllegalStateException("forced rollback");
        }

        @Override
        public boolean isHeadless() {
            return true;
        }
    }
}
