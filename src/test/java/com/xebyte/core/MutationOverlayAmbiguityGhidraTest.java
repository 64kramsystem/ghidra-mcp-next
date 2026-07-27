package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
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
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.Symbol;

/**
 * End-to-end coverage for the overlay-ambiguity guard on mutating endpoints.
 *
 * <p>The fixture reproduces the shape that exposed the defect: a 16-bit program
 * whose physical space holds a resident routine, plus an overlay block holding
 * the different code that displaced it at runtime. {@code 0x9762} therefore
 * denotes two distinct occupants, and a mutation aimed at the wrong one corrupts
 * the other's analysis with no visible signal.
 *
 * <p>Each guarded endpoint is asserted three ways: an unqualified ambiguous
 * address is refused with the standard message, a qualified address still lands
 * in the space it names, and an unqualified address at an offset no overlay
 * covers works exactly as before. Read-only endpoints are asserted to keep
 * resolving bare hex to the physical space.
 */
public class MutationOverlayAmbiguityGhidraTest {

    /** Mapped in both `ram` and the SND_PLAYER overlay. */
    private static final String AMBIGUOUS = "9762";
    private static final String RAM_QUALIFIED = "ram:9762";
    private static final String OVERLAY_QUALIFIED = "SND_PLAYER:9762";
    /** Mapped only in `ram`. */
    private static final String UNIQUE = "1000";

    private ProgramBuilder builder;
    private ProgramDB program;

    private CommentService comments;
    private SymbolLabelService symbols;
    private DataTypeService dataTypes;
    private XrefCallGraphService xrefs;
    private FunctionService functions;
    private MemoryBlockService memoryBlocks;
    private ListingMutationService listingMutations;
    private ProgramScriptService scripts;
    private ControlFlowService controlFlow;
    private FlowDisassemblyService flowDisassembly;

    @BeforeClass
    public static void initializeGhidraOrSkip() throws Exception {
        String installDir = System.getProperty("ghidra.test.install.dir");
        assumeTrue(
            "ghidra.test.install.dir is required for real Ghidra tests",
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
            "overlay-mutations-6502", "6502:LE:16:default", "default", this);
        program = builder.getProgram();
        builder.createMemory(".ram", "0x1000", 0x100);
        builder.createMemory(".loader", "0x9000", 0x1000);
        builder.setBytes("0x9762", "ea ea ea ea");
        builder.createOverlayMemory("SND_PLAYER", "0x9680", 0x280);

        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        DirectThreadingStrategy threading = new DirectThreadingStrategy();

        comments = new CommentService(provider, threading);
        symbols = new SymbolLabelService(provider, threading);
        dataTypes = new DataTypeService(provider, threading);
        xrefs = new XrefCallGraphService(provider, threading);
        functions = new FunctionService(provider, threading);
        memoryBlocks = new MemoryBlockService(provider, threading);
        listingMutations = new ListingMutationService(provider, threading);
        scripts = new ProgramScriptService(provider, threading);
        controlFlow = new ControlFlowService(provider, threading);
        flowDisassembly = new FlowDisassemblyService(provider, threading);
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    // ------------------------------------------------------------ the fixture

    @Test
    public void fixtureReallyOverlapsTheOffsetInTwoSpaces() {
        assertTrue(program.getMemory().contains(builder.addr("0x9762")));
        assertTrue(program.getMemory().contains(builder.addr("SND_PLAYER::9762")));
        assertEquals(
            2,
            ServiceUtils.mappedCandidatesAtOffset(program, 0x9762L).size());
        assertEquals(
            1,
            ServiceUtils.mappedCandidatesAtOffset(program, 0x1000L).size());
    }

    // ------------------------------------------------------------- labels

    @Test
    public void createLabelRefusesTheAmbiguousAddress() {
        assertRefused(symbols.createLabel(AMBIGUOUS, "sound_tick", ""));
        assertNoSymbolAt("0x9762");
        assertNoSymbolAt("SND_PLAYER::9762");
    }

    @Test
    public void createLabelHitsTheSpaceTheCallerNamed() {
        assertOk(symbols.createLabel(OVERLAY_QUALIFIED, "sound_tick", ""));
        assertOk(symbols.createLabel(RAM_QUALIFIED, "loader_tick", ""));

        assertSymbolNamed("SND_PLAYER::9762", "sound_tick");
        assertSymbolNamed("0x9762", "loader_tick");
    }

    @Test
    public void createLabelStillAcceptsAnUnambiguousBareOffset() {
        assertOk(symbols.createLabel(UNIQUE, "plain", ""));
        assertSymbolNamed("0x1000", "plain");
    }

    @Test
    public void deleteLabelRefusesTheAmbiguousAddress() {
        assertOk(symbols.createLabel(OVERLAY_QUALIFIED, "sound_tick", ""));

        assertRefused(symbols.deleteLabel(AMBIGUOUS, "sound_tick", ""));

        assertSymbolNamed("SND_PLAYER::9762", "sound_tick");
    }

    @Test
    public void renameLabelRefusesTheAmbiguousAddress() {
        assertOk(symbols.createLabel(OVERLAY_QUALIFIED, "sound_tick", ""));

        assertRefused(symbols.renameLabel(AMBIGUOUS, "sound_tick", "renamed", ""));

        assertSymbolNamed("SND_PLAYER::9762", "sound_tick");
    }

    @Test
    public void renameOrLabelRefusesTheAmbiguousAddress() {
        assertRefused(symbols.renameOrLabel(AMBIGUOUS, "sound_tick", "", ""));
        assertNoSymbolAt("0x9762");
    }

    @Test
    public void renameDataRefusesTheAmbiguousAddress() {
        assertRefused(symbols.renameDataAtAddress(AMBIGUOUS, "sound_tick", ""));
        assertNoSymbolAt("0x9762");
    }

    // ----------------------------------------------------------- batch labels

    @Test
    public void batchCreateLabelsAppliesNothingWhenOneEntryIsAmbiguous() {
        Response response = symbols.batchCreateLabels(
            List.of(
                Map.of("address", UNIQUE, "name", "first_is_fine"),
                Map.of("address", AMBIGUOUS, "name", "second_is_ambiguous")),
            "");

        assertRefused(response);
        assertTrue(response.toJson(), response.toJson().contains(AMBIGUOUS));
        assertNoSymbolAt("0x1000");
        assertNoSymbolAt("0x9762");
        assertNoSymbolAt("SND_PLAYER::9762");
    }

    @Test
    public void batchCreateLabelsStillAppliesAnUnambiguousBatch() {
        assertOk(symbols.batchCreateLabels(
            List.of(
                Map.of("address", UNIQUE, "name", "first"),
                Map.of("address", OVERLAY_QUALIFIED, "name", "second")),
            ""));

        assertSymbolNamed("0x1000", "first");
        assertSymbolNamed("SND_PLAYER::9762", "second");
    }

    @Test
    public void batchDeleteLabelsDeletesNothingWhenOneEntryIsAmbiguous() {
        assertOk(symbols.createLabel(UNIQUE, "keep_me", ""));

        Response response = symbols.batchDeleteLabels(
            List.of(
                Map.of("address", UNIQUE, "name", "keep_me"),
                Map.of("address", AMBIGUOUS, "name", "whatever")),
            "");

        assertRefused(response);
        assertSymbolNamed("0x1000", "keep_me");
    }

    // ---------------------------------------------------------------- data

    @Test
    public void applyDataTypeRefusesTheAmbiguousAddress() {
        assertRefused(dataTypes.applyDataType(AMBIGUOUS, "byte", true, "", ""));
        assertNull(program.getListing().getDefinedDataAt(builder.addr("0x9762")));
        assertNull(program.getListing().getDefinedDataAt(
            builder.addr("SND_PLAYER::9762")));
    }

    @Test
    public void applyDataTypeHitsTheSpaceTheCallerNamed() {
        // apply_data_type reports success as plain text, so assert the effect.
        dataTypes.applyDataType(OVERLAY_QUALIFIED, "byte", true, "", "");

        assertNotNull(program.getListing().getDefinedDataAt(
            builder.addr("SND_PLAYER::9762")));
        assertNull(program.getListing().getDefinedDataAt(builder.addr("0x9762")));
    }

    @Test
    public void applyDataTypeStillAcceptsAnUnambiguousBareOffset() {
        dataTypes.applyDataType(UNIQUE, "byte", true, "", "");
        assertNotNull(program.getListing().getDefinedDataAt(builder.addr("0x1000")));
    }

    @Test
    public void setGlobalRefusesTheAmbiguousAddress() {
        assertRefused(
            dataTypes.setGlobal(AMBIGUOUS, "g_sound", "byte", 0, "", "", ""));
        assertNoSymbolAt("0x9762");
    }

    @Test
    public void applyDataClassificationRefusesTheAmbiguousAddress() {
        assertRefused(dataTypes.applyDataClassification(
            AMBIGUOUS, "byte", "g_sound", "", null, ""));
        assertNull(program.getListing().getDefinedDataAt(builder.addr("0x9762")));
    }

    @Test
    public void renameExternalLocationRefusesTheAmbiguousAddress() {
        assertRefused(symbols.renameExternalLocation(AMBIGUOUS, "renamed", ""));
    }

    // ------------------------------------------------------------- comments

    @Test
    public void setDisassemblyCommentRefusesTheAmbiguousAddress() {
        assertRefused(comments.setDisassemblyComment(AMBIGUOUS, "note", ""));
        assertNull(program.getListing().getComment(
            CommentType.EOL, builder.addr("0x9762")));
    }

    @Test
    public void setDecompilerCommentRefusesTheAmbiguousAddress() {
        assertRefused(comments.setDecompilerComment(AMBIGUOUS, "note", ""));
        assertNull(program.getListing().getComment(
            CommentType.PRE, builder.addr("0x9762")));
    }

    @Test
    public void setDisassemblyCommentHitsTheSpaceTheCallerNamed() {
        assertOk(comments.setDisassemblyComment(OVERLAY_QUALIFIED, "overlay", ""));
        assertOk(comments.setDisassemblyComment(RAM_QUALIFIED, "physical", ""));

        assertEquals("overlay", program.getListing().getComment(
            CommentType.EOL, builder.addr("SND_PLAYER::9762")));
        assertEquals("physical", program.getListing().getComment(
            CommentType.EOL, builder.addr("0x9762")));
    }

    @Test
    public void setPlateCommentKeepsItsReferenceBehaviour() {
        // The comment endpoints already carried the guard; they are the behaviour
        // every other endpoint was brought into line with.
        assertRefused(comments.setPlateComment(AMBIGUOUS, "note", ""));
        assertOk(comments.setPlateComment(OVERLAY_QUALIFIED, "note", ""));
        assertEquals("note", program.getListing().getComment(
            CommentType.PLATE, builder.addr("SND_PLAYER::9762")));
    }

    @Test
    public void batchSetCommentsWritesNothingWhenOneItemIsAmbiguous() {
        Response response = comments.batchSetComments(
            UNIQUE,
            List.of(
                Map.of("address", UNIQUE, "comment", "fine"),
                Map.of("address", AMBIGUOUS, "comment", "ambiguous")),
            List.of(),
            "null",
            "");

        assertRefused(response);
        assertTrue(response.toJson(),
            response.toJson().toLowerCase().contains("ambiguous"));
        assertNull(program.getListing().getComment(
            CommentType.PRE, builder.addr("0x1000")));
        assertNull(program.getListing().getComment(
            CommentType.PRE, builder.addr("0x9762")));
    }

    @Test
    public void clearFunctionCommentsRefusesTheAmbiguousAddress() {
        assertRefused(
            comments.clearFunctionComments(AMBIGUOUS, true, true, true, ""));
    }

    // ----------------------------------------------------------- references

    @Test
    public void addMemoryReferenceRefusesAnAmbiguousEndpoint() {
        assertRefused(xrefs.addMemoryReference(
            AMBIGUOUS, UNIQUE, "DATA", "USER_DEFINED", -1, ""));
        assertRefused(xrefs.addMemoryReference(
            UNIQUE, AMBIGUOUS, "DATA", "USER_DEFINED", -1, ""));

        assertEquals(0, program.getReferenceManager()
            .getReferenceCountFrom(builder.addr("0x9762")));
        assertEquals(0, program.getReferenceManager()
            .getReferenceCountFrom(builder.addr("0x1000")));
    }

    @Test
    public void addMemoryReferenceHitsTheSpaceTheCallerNamed() {
        assertOk(xrefs.addMemoryReference(
            OVERLAY_QUALIFIED, UNIQUE, "DATA", "USER_DEFINED", -1, ""));

        assertEquals(1, program.getReferenceManager()
            .getReferenceCountFrom(builder.addr("SND_PLAYER::9762")));
        assertEquals(0, program.getReferenceManager()
            .getReferenceCountFrom(builder.addr("0x9762")));
    }

    @Test
    public void removeReferenceRefusesAnAmbiguousEndpoint() {
        assertOk(xrefs.addMemoryReference(
            OVERLAY_QUALIFIED, UNIQUE, "DATA", "USER_DEFINED", -1, ""));

        assertRefused(xrefs.removeReference(AMBIGUOUS, UNIQUE, -1, ""));

        assertEquals(1, program.getReferenceManager()
            .getReferenceCountFrom(builder.addr("SND_PLAYER::9762")));
    }

    // --------------------------------------------------------------- bytes

    @Test
    public void writeMemoryBytesRefusesTheAmbiguousAddress() {
        assertRefused(memoryBlocks.writeMemoryBytes(
            AMBIGUOUS, "ff", "overwrite_bytes", false, ""));
        assertEquals((byte) 0xea, readByte("0x9762"));
    }

    @Test
    public void writeMemoryBytesStillAcceptsAnUnambiguousBareOffset() {
        assertOk(memoryBlocks.writeMemoryBytes(
            UNIQUE, "ff", "overwrite_bytes", false, ""));
        assertEquals((byte) 0xff, readByte("0x1000"));
    }

    @Test
    public void patchBytesRefusesTheAmbiguousAddress() {
        assertRefused(memoryBlocks.patchBytes(
            AMBIGUOUS, "ff", null, true, null, true, false, ""));
        assertEquals((byte) 0xea, readByte("0x9762"));
    }

    @Test
    public void patchBytesHitsTheSpaceTheCallerNamed() {
        // ProgramBuilder blocks are read-only, hence allow_readonly.
        assertOk(memoryBlocks.patchBytes(
            RAM_QUALIFIED, "ff", null, true, null, true, false, ""));

        assertEquals((byte) 0xff, readByte("0x9762"));
    }

    // -------------------------------------------------------------- listing

    @Test
    public void undefineRangeRefusesAnAmbiguousEndpoint() {
        assertRefused(listingMutations.undefineRange(
            AMBIGUOUS, AMBIGUOUS,
            true, true, true, true, true, true, false, false, ""));
    }

    // ------------------------------------------------------------ bookmarks

    @Test
    public void setBookmarkRefusesTheAmbiguousAddress() {
        assertRefused(scripts.setBookmark(AMBIGUOUS, "Note", "text", ""));
        assertEquals(0, program.getBookmarkManager()
            .getBookmarks(builder.addr("0x9762")).length);
    }

    @Test
    public void setBookmarkHitsTheSpaceTheCallerNamed() {
        assertOk(scripts.setBookmark(OVERLAY_QUALIFIED, "Note", "text", ""));

        assertEquals(1, program.getBookmarkManager()
            .getBookmarks(builder.addr("SND_PLAYER::9762")).length);
        assertEquals(0, program.getBookmarkManager()
            .getBookmarks(builder.addr("0x9762")).length);
    }

    @Test
    public void deleteBookmarkRefusesTheAmbiguousAddress() {
        assertOk(scripts.setBookmark(OVERLAY_QUALIFIED, "Note", "text", ""));

        assertRefused(scripts.deleteBookmark(AMBIGUOUS, "Note", ""));

        assertEquals(1, program.getBookmarkManager()
            .getBookmarks(builder.addr("SND_PLAYER::9762")).length);
    }

    @Test
    public void setImageBaseRefusesTheAmbiguousAddress() {
        Address before = program.getImageBase();

        assertRefused(scripts.setImageBase(AMBIGUOUS, ""));

        assertEquals(before, program.getImageBase());
    }

    // ------------------------------------------------------------ functions

    @Test
    public void createFunctionRefusesTheAmbiguousAddress() {
        assertRefused(
            functions.createFunctionAtAddress(AMBIGUOUS, "sound_tick", true, ""));
        assertEquals(0, program.getFunctionManager().getFunctionCount());
    }

    @Test
    public void deleteFunctionRefusesTheAmbiguousAddress() {
        assertOk(functions.createFunctionAtAddress(
            OVERLAY_QUALIFIED, "sound_tick", true, ""));
        int before = program.getFunctionManager().getFunctionCount();

        assertRefused(functions.deleteFunctionAtAddress(AMBIGUOUS, ""));

        assertEquals(before, program.getFunctionManager().getFunctionCount());
    }

    @Test
    public void clearFlowAndRepairRefusesAnAmbiguousEndpoint() {
        assertRefused(functions.clearFlowAndRepair(AMBIGUOUS, "", ""));
        assertRefused(functions.clearFlowAndRepair(UNIQUE, AMBIGUOUS, ""));
    }

    @Test
    public void functionAddressMutatorsRefuseTheAmbiguousAddress() {
        // function_address may also carry a name, so these go through the probe.
        assertRefused(functions.setFunctionNoReturn(AMBIGUOUS, true, ""));
        assertRefused(functions.renameFunctionByAddress(AMBIGUOUS, "renamed", ""));
    }

    @Test
    public void functionTagMutatorsRefuseTheAmbiguousAddress() {
        // `function` is declared paramType="address" and may also carry a name, so
        // these go through the probe too.
        assertRefused(functions.addFunctionTag(AMBIGUOUS, "syscall", ""));
        assertRefused(functions.removeFunctionTag(AMBIGUOUS, "syscall", ""));
    }

    @Test
    public void batchFunctionTagsChangeNothingWhenOneEntryIsAmbiguous() {
        assertOk(functions.createFunctionAtAddress(UNIQUE, "plain", true, ""));
        assertOk(functions.addFunctionTag(UNIQUE, "keep", ""));

        Response response = functions.batchAddFunctionTags(
            List.of(
                Map.of("function", UNIQUE, "tags", "added"),
                Map.of("function", AMBIGUOUS, "tags", "added")),
            "");

        assertRefused(response);
        assertEquals(
            1,
            program.getFunctionManager()
                .getFunctionAt(builder.addr("0x1000")).getTags().size());
    }

    // ---------------------------------------------------------- disassembly

    @Test
    public void disassembleFlowRefusesAnAmbiguousSeedOrRestriction() {
        assertRefused(flowDisassembly.disassembleFlow(
            "[\"" + AMBIGUOUS + "\"]", "9000", "9fff",
            true, false, true, false, false, 64, ""));
        assertRefused(flowDisassembly.disassembleFlow(
            "[\"" + UNIQUE + "\"]", AMBIGUOUS, AMBIGUOUS,
            true, false, true, false, false, 64, ""));
    }

    // --------------------------------------------------------- control flow

    @Test
    public void batchUpdateReferencesAddsNothingWhenOneEntryIsAmbiguous() {
        Response response = controlFlow.batchUpdateReferences(
            List.of(
                Map.of("from", UNIQUE, "to", UNIQUE, "type", "data",
                       "operand_index", -1),
                Map.of("from", AMBIGUOUS, "to", UNIQUE, "type", "data",
                       "operand_index", -1)),
            List.of(), false, false, "");

        assertRefused(response);
        assertEquals(0, program.getReferenceManager()
            .getReferenceCountFrom(builder.addr("0x1000")));
    }

    @Test
    public void annotateSelfModifiedOperandRefusesTheAmbiguousAddress() {
        assertRefused(controlFlow.annotateSelfModifiedOperand(
            AMBIGUOUS, -1, UNIQUE, List.of(UNIQUE), "", "", false, false, ""));
    }

    // ------------------------------------------------- read-only convention

    @Test
    public void readOnlyEndpointsStillResolveBareHexToThePhysicalSpace() {
        // Deliberate, documented behaviour; see
        // docs/superpowers/specs/2026-07-26-references-into-range-design.md,
        // "Bare, unqualified ranges resolve to the physical space". Guarding a read
        // would break every caller that reasonably reads by plain address.
        assertOk(comments.setDisassemblyComment(RAM_QUALIFIED, "physical", ""));
        assertOk(comments.setDisassemblyComment(OVERLAY_QUALIFIED, "overlay", ""));

        Response read = comments.getComment(AMBIGUOUS, "");
        assertOk(read);
        assertTrue(read.toJson(), read.toJson().contains("physical"));
        assertFalse(read.toJson(), read.toJson().contains("overlay"));

        assertOk(scripts.readMemory(AMBIGUOUS, 4, ""));
        assertOk(xrefs.getReferencesIntoRange(AMBIGUOUS, AMBIGUOUS, 100, 0, ""));
        assertOk(scripts.listBookmarks("", AMBIGUOUS, ""));
        assertOk(symbols.canRenameAtAddress(AMBIGUOUS, ""));
        // These resolve the address and then report on what they found, so assert
        // only that resolution itself was never refused.
        assertNotRefused(xrefs.getXrefsTo(AMBIGUOUS, 0, 100, ""));
        assertNotRefused(dataTypes.validateDataType(AMBIGUOUS, "byte", ""));
    }

    // ---------------------------------------------------------------- helpers

    private void assertRefused(Response response) {
        String json = response.toJson();
        assertTrue("expected an error, got: " + json, response instanceof Response.Err);
        assertTrue(
            "expected the standard ambiguity refusal, got: " + json,
            json.contains("Ambiguous unqualified address"));
        assertTrue(
            "the refusal must name the overlay occupant: " + json,
            json.contains("SND_PLAYER"));
        assertTrue(
            "the refusal must say how to qualify: " + json,
            json.contains("Use a qualified <space>:<hex> address."));
    }

    private void assertNotRefused(Response response) {
        assertFalse(
            "a read must never be refused for ambiguity: " + response.toJson(),
            response.toJson().contains("Ambiguous unqualified address"));
    }

    private void assertOk(Response response) {
        assertTrue(
            "expected success, got: " + response.toJson(),
            response instanceof Response.Ok);
    }

    private void assertSymbolNamed(String addressText, String expected) {
        Symbol[] found =
            program.getSymbolTable().getSymbols(builder.addr(addressText));
        assertEquals(
            "symbol count at " + addressText, 1, found == null ? 0 : found.length);
        assertEquals(expected, found[0].getName());
    }

    private void assertNoSymbolAt(String addressText) {
        Symbol[] found =
            program.getSymbolTable().getSymbols(builder.addr(addressText));
        assertEquals(
            "expected no symbol at " + addressText,
            0,
            found == null ? 0 : found.length);
    }

    private byte readByte(String addressText) {
        try {
            return program.getMemory().getByte(builder.addr(addressText));
        }
        catch (Exception e) {
            throw new AssertionError("could not read " + addressText, e);
        }
    }
}
