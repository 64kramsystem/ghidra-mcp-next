package com.xebyte.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

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
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

/**
 * Real-Ghidra coverage for initialized overlays, transformations, byte writes,
 * rollback, and the C64-oriented generic fixture required by Feature 9.
 */
public class MemoryBlockServiceGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;
    private MemoryBlockService memory;
    private ListingService listing;

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
            "memory-blocks-6502", "6502:LE:16:default", "default", this);
        program = builder.getProgram();
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        memory = new MemoryBlockService(
            provider, new DirectThreadingStrategy());
        listing = new ListingService(provider);
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void creationSourcesFillPermissionsCommentAndOrdinaryOverlap()
            throws Exception {
        JsonObject preview = create(
            "bss", "0x1000", 0x20L, null, null, null,
            false, null, true, false, false, false, null, true);
        assertFalse(preview.get("committed").getAsBoolean());
        assertNull(program.getMemory().getBlock("bss"));

        JsonObject bss = create(
            "bss", "0x1000", 0x20L, null, null, null,
            false, null, true, false, false, true, "scratch", false);
        assertFalse(bss.getAsJsonObject("after")
            .get("initialized").getAsBoolean());
        assertEquals("r--", bss.getAsJsonObject("after")
            .get("permissions").getAsString());
        assertEquals("scratch", program.getMemory().getBlock("bss").getComment());
        assertTrue(program.getMemory().getBlock("bss").isVolatile());
        assertCompleteDescriptor(bss.getAsJsonObject("after"));

        JsonObject filled = create(
            "filled", "0x1100", 4L, null, null, null,
            false, 0xea, true, true, true, false, "code", false);
        assertTrue(filled.getAsJsonObject("after")
            .get("initialized").getAsBoolean());
        assertArrayEquals(hex("eaeaeaea"), bytes("0x1100", 4));

        create(
            "payload", "0x1200", null, "001122ff", null, null,
            false, null, true, false, false, false, null, false);
        assertArrayEquals(hex("001122ff"), bytes("0x1200", 4));

        Path root = Files.createTempDirectory("memory-file-root");
        Path source = root.resolve("kernal.bin");
        Files.write(source, hex("aabbccddee"));
        memory = serviceForRoot(root, new DirectThreadingStrategy());
        create(
            "file", "0x1300", null, null, source.toString(), 1L,
            false, null, true, false, false, false, null, false,
            3L);
        assertArrayEquals(hex("bbccdd"), bytes("0x1300", 3));

        Response overlap = memory.createMemoryBlock(
            "overlap", "0x1010", 4L, null, null, 0L, null,
            false, null, true, false, false, false, null, false, "");
        assertError(overlap, "overlap");
        assertNull(program.getMemory().getBlock("overlap"));
    }

    @Test
    public void twoInitializedOverlaysAtSameOffsetKeepDistinctSpacesAndBytes() {
        JsonObject firstPreview = create(
            "rom_a", "0x8000", null, "aa55", null, null,
            true, null, true, false, true, false, "A", true);
        JsonObject first = create(
            "rom_a", "0x8000", null, "aa55", null, null,
            true, null, true, false, true, false, "A", false);
        JsonObject second = create(
            "rom_b", "0x8000", null, "1122", null, null,
            true, null, true, false, true, false, "B", false);

        JsonObject a = first.getAsJsonObject("after");
        JsonObject b = second.getAsJsonObject("after");
        assertEquals(firstPreview.get("after"), first.get("after"));
        assertNotEquals(a.get("address_space").getAsString(),
            b.get("address_space").getAsString());
        assertArrayEquals(hex("aa55"), bytes(
            a.get("address_space").getAsString() + ":8000", 2));
        assertArrayEquals(hex("1122"), bytes(
            b.get("address_space").getAsString() + ":8000", 2));

        JsonObject uninitialized = create(
            "uninit_overlay", "0x9000", 0x10L, null, null, null,
            true, null, true, true, false, true, "window", false);
        assertFalse(uninitialized.getAsJsonObject("after")
            .get("initialized").getAsBoolean());

        assertError(memory.createMemoryBlock(
            "overlay_on_overlay",
            a.get("address_space").getAsString() + ":9000",
            null, "01", null, null, null,
            true, null, true, false, false, false, null, false, ""),
            "existing overlay");

        ok(memory.writeMemoryBytes(
            a.get("address_space").getAsString() + ":8000",
            "fe55", "overwrite_bytes", false, ""));
        assertArrayEquals(hex("fe55"), bytes(
            a.get("address_space").getAsString() + ":8000", 2));
        assertArrayEquals(hex("1122"), bytes(
            b.get("address_space").getAsString() + ":8000", 2));
    }

    @Test
    public void everyCreateRejectsAnExistingOverlayAsItsBaseInPreviewAndCommit() {
        JsonObject parent = create(
            "parent_overlay", "0x8000", null, "0102", null, null,
            true, null, true, false, false, false, null, false);
        String overlayStart = parent.getAsJsonObject("after")
            .get("address_space").getAsString() + ":9000";
        int blockCount = program.getMemory().getBlocks().length;
        int spaceCount =
            program.getAddressFactory().getAddressSpaces().length;

        for (boolean overlay : new boolean[] { false, true }) {
            for (boolean dryRun : new boolean[] { true, false }) {
                String name = "nested_" + overlay + "_" + dryRun;
                Response response = memory.createMemoryBlock(
                    name, overlayStart, 0x10L, null, null, null, null,
                    overlay, null, true, false, false, false,
                    null, dryRun, "");
                assertError(response, "existing overlay address space");
                assertNull(program.getMemory().getBlock(name));
            }
        }
        assertEquals(blockCount, program.getMemory().getBlocks().length);
        assertEquals(
            spaceCount,
            program.getAddressFactory().getAddressSpaces().length);
    }

    @Test
    public void overlayPreviewPredictsSanitizedAndUniquifiedGhidraSpaceNames() {
        assertOverlayPreviewCommitSpace("bank:rom", "bank_rom");
        assertOverlayPreviewCommitSpace("bank rom", "bank_rom.1");

        String physicalName =
            program.getAddressFactory().getDefaultAddressSpace().getName();
        assertOverlayPreviewCommitSpace(
            physicalName, physicalName + ".1");
    }

    @Test
    public void genericFixtureRepresentsRamBasicKernalAndIoWithoutBankLogic() {
        create("ram", "0x0000", 0x10000L, null, null, null,
            false, 0, true, true, true, false, "ordinary RAM", false);
        create("basic_rom", "0xa000", null, "01020304", null, null,
            true, null, true, false, true, false, "BASIC image", false);
        create("io", "0xd000", null, "11121314", null, null,
            true, null, true, true, false, true, "I/O image", false);
        create("kernal_rom", "0xe000", null, "21222324", null, null,
            true, null, true, false, true, false, "KERNAL image", false);

        JsonArray blocks = JsonParser.parseString(
            listing.listSegments(0, 100, "").toJson()).getAsJsonArray();
        assertEquals(4, blocks.size());
        assertEquals(3, blocks.asList().stream()
            .filter(element -> element.getAsJsonObject()
                .get("overlay").getAsBoolean()).count());
        for (var element : blocks) {
            JsonObject block = element.getAsJsonObject();
            assertTrue(block.has("address_space"));
            assertTrue(block.has("initialized"));
            assertTrue(block.has("source"));
            assertTrue(block.has("permissions"));
            assertTrue(block.has("comment"));
        }
    }

    @Test
    public void updateSplitAndMovePreserveBytesMetadataAndHaveFullDescriptors() {
        create("ram", "0x2000", 0x100L, null, null, null,
            false, 0xea, true, true, false, true, "before", false);

        JsonObject update = ok(memory.updateMemoryBlock(
            "ram", "workspace", true, false, true, false,
            "after", false, ""));
        assertEquals("ram", update.getAsJsonObject("before")
            .get("name").getAsString());
        assertEquals("workspace", update.getAsJsonObject("after")
            .get("name").getAsString());
        assertEquals("r-x", update.getAsJsonObject("after")
            .get("permissions").getAsString());
        assertEquals("after", update.getAsJsonObject("after")
            .get("comment").getAsString());
        assertCompleteDescriptor(update.getAsJsonObject("before"));
        assertCompleteDescriptor(update.getAsJsonObject("after"));

        JsonObject cleared = ok(memory.updateMemoryBlock(
            "workspace", null, null, null, null, null,
            "", false, ""));
        assertEquals("", cleared.getAsJsonObject("after")
            .get("comment").getAsString());

        byte[] original = bytes("0x2000", 0x100);
        JsonObject split = ok(memory.splitMemoryBlock(
            "workspace", "0x2080", false, ""));
        JsonObject prefix = split.getAsJsonObject("prefix");
        JsonObject suffix = split.getAsJsonObject("suffix");
        assertEquals("workspace", prefix.get("name").getAsString());
        assertEquals("workspace_split_2080", suffix.get("name").getAsString());
        assertEquals(prefix.get("permissions"), suffix.get("permissions"));
        assertEquals(prefix.get("comment"), suffix.get("comment"));
        assertEquals(prefix.get("volatile"), suffix.get("volatile"));
        assertEquals(prefix.get("source"), suffix.get("source"));
        assertCompleteDescriptor(split.getAsJsonObject("before"));
        assertCompleteDescriptor(prefix);
        assertCompleteDescriptor(suffix);
        byte[] joined = new byte[0x100];
        System.arraycopy(bytes("0x2000", 0x80), 0, joined, 0, 0x80);
        System.arraycopy(bytes("0x2080", 0x80), 0, joined, 0x80, 0x80);
        assertArrayEquals(original, joined);

        JsonObject moved = ok(memory.moveMemoryBlock(
            "workspace_split_2080", "0x3000", false, ""));
        assertEquals("2080", moved.getAsJsonObject("before")
            .get("start").getAsString());
        assertEquals("3000", moved.getAsJsonObject("after")
            .get("start").getAsString());
        assertArrayEquals(
            java.util.Arrays.copyOfRange(original, 0x80, 0x100),
            bytes("0x3000", 0x80));
        assertEquals(
            moved.getAsJsonObject("before").get("permissions"),
            moved.getAsJsonObject("after").get("permissions"));
        assertEquals(
            moved.getAsJsonObject("before").get("source"),
            moved.getAsJsonObject("after").get("source"));
        assertCompleteDescriptor(moved.getAsJsonObject("before"));
        assertCompleteDescriptor(moved.getAsJsonObject("after"));
    }

    @Test
    public void transformsRejectCollisionsInvalidSplitsOverlapsAndOverlayMoves() {
        create("a", "0x1000", 0x100L, null, null, null,
            false, 0, true, true, false, false, null, false);
        create("a_split_1080", "0x3000", 0x10L, null, null, null,
            false, null, true, false, false, false, null, false);
        create("overlay", "0x4000", null, "0102", null, null,
            true, null, true, false, false, false, null, false);
        create("collision", "0x5000", 0x10L, null, null, null,
            false, null, true, false, false, false, null, false);

        assertError(memory.updateMemoryBlock(
            "a", "collision", null, null, null, null,
            null, false, ""), "collid");
        assertError(memory.splitMemoryBlock("a", "0x1080", false, ""),
            "collision");
        assertError(memory.splitMemoryBlock("a", "0x1000", false, ""),
            "inside");
        assertError(memory.moveMemoryBlock("a", "0x3000", false, ""),
            "overlap");
        assertError(memory.moveMemoryBlock("overlay", "0x5000", false, ""),
            "overlay");
        assertEquals("1000", program.getMemory().getBlock("a")
            .getStart().toString(false));

        long beforeNoOp = program.getModificationNumber();
        JsonObject noOp = ok(memory.updateMemoryBlock(
            "a", null, null, null, null, null, null, false, ""));
        assertFalse(noOp.get("changed").getAsBoolean());
        assertEquals(noOp.get("before"), noOp.get("after"));
        assertEquals(beforeNoOp, program.getModificationNumber());

        JsonObject moveNoOp = ok(memory.moveMemoryBlock(
            "a", "0x1000", false, ""));
        assertFalse(moveNoOp.get("changed").getAsBoolean());
        assertEquals(moveNoOp.get("before"), moveNoOp.get("after"));
        assertEquals(beforeNoOp, program.getModificationNumber());
    }

    @Test
    public void byteWritesPreviewDigestConflictsMappingsAndCommit() {
        create("ram", "0x4000", null, "000102030405", null, null,
            false, null, true, true, false, false, null, false);
        create("bss", "0x5000", 0x10L, null, null, null,
            false, null, true, true, false, false, null, false);

        JsonObject preview = ok(memory.writeMemoryBytes(
            "0x4000", "090108070406", "overwrite_bytes", true, ""));
        JsonObject commit = ok(memory.writeMemoryBytes(
            "0x4000", "090108070406", "overwrite_bytes", false, ""));
        assertEquals(preview.get("sha256"), commit.get("sha256"));
        assertEquals(preview.get("differing_ranges"),
            commit.get("differing_ranges"));
        assertEquals(preview.get("before"), commit.get("before"));
        assertEquals(preview.get("after"), commit.get("after"));
        assertCompleteDescriptor(preview.getAsJsonObject("before"));
        assertCompleteDescriptor(preview.getAsJsonObject("after"));
        assertFalse(preview.get("committed").getAsBoolean());
        assertTrue(commit.get("committed").getAsBoolean());
        assertArrayEquals(hex("090108070406"), bytes("0x4000", 6));

        long beforeIdentical = program.getModificationNumber();
        JsonObject identical = ok(memory.writeMemoryBytes(
            "0x4000", "090108070406", "error", false, ""));
        assertEquals(0, identical.getAsJsonArray("differing_ranges").size());
        assertFalse(identical.get("changed").getAsBoolean());
        assertEquals(beforeIdentical, program.getModificationNumber());
        assertError(memory.writeMemoryBytes(
            "0x4000", "ff0108070406", "error", false, ""), "differ");
        assertError(memory.writeMemoryBytes(
            "0x5000", "01", "overwrite_bytes", false, ""),
            "initialized");
        assertError(memory.writeMemoryBytes(
            "0x6000", "01", "overwrite_bytes", false, ""), "existing");
        assertError(memory.writeMemoryBytes(
            "0x4005", "0102", "overwrite_bytes", false, ""), "extend");
        assertError(memory.writeMemoryBytes(
            "0x4000", "01", "merge", false, ""), "conflict_policy");
    }

    @Test
    public void byteWriteRangeLimitIsAtomicAtTheExactBoundary() {
        int limit = 4096;
        byte[] accepted = alternatingDifferences(limit);
        byte[] rejected = alternatingDifferences(limit + 1);
        create("bounded_write", "0xa000", (long) rejected.length,
            null, null, null, false, 0,
            true, true, false, false, null, false);

        JsonObject preview = ok(memory.writeMemoryBytes(
            "0xa000", accepted, "overwrite_bytes", true, ""));
        assertEquals(limit,
            preview.getAsJsonArray("differing_ranges").size());
        assertFalse(preview.get("committed").getAsBoolean());

        Response response = memory.writeMemoryBytes(
            "0xa000", rejected, "overwrite_bytes", false, "");
        assertError(response, "4096");
        assertTrue(response.toJson(), response.toJson().contains("split"));
        assertArrayEquals(
            new byte[rejected.length],
            bytes("0xa000", rejected.length));
    }

    @Test
    public void dryRunsAndInjectedFailuresRollbackEveryMutation() {
        create("ram", "0x6000", null, "00010203", null, null,
            false, null, true, true, false, false, "stable", false);

        ok(memory.updateMemoryBlock(
            "ram", "preview", false, false, false, true,
            "changed", true, ""));
        ok(memory.splitMemoryBlock("ram", "0x6002", true, ""));
        ok(memory.moveMemoryBlock("ram", "0x6100", true, ""));
        ok(memory.writeMemoryBytes(
            "0x6000", "ffffffff", "overwrite_bytes", true, ""));
        assertEquals("ram", program.getMemory().getBlock("ram").getName());
        assertEquals("6000", program.getMemory().getBlock("ram")
            .getStart().toString(false));
        assertEquals(1, program.getMemory().getBlocks().length);
        assertArrayEquals(hex("00010203"), bytes("0x6000", 4));

        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        MemoryBlockService aborting = new MemoryBlockService(
            provider, new AbortAfterActionStrategy());

        assertError(aborting.createMemoryBlock(
            "failed_create", "0x7000", null, "0102", null,
            0L, null, false, null, true, false, false, false,
            "never", false, ""), "forced rollback");
        assertNull(program.getMemory().getBlock("failed_create"));

        assertError(aborting.createMemoryBlock(
            "failed_overlay", "0x8000", null, "0102", null,
            0L, null, true, null, true, false, false, false,
            "never", false, ""), "forced rollback");
        assertNull(program.getMemory().getBlock("failed_overlay"));
        assertNull(program.getAddressFactory().getAddressSpace("failed_overlay"));

        assertError(aborting.updateMemoryBlock(
            "ram", "renamed", false, false, false, true,
            "changed", false, ""), "forced rollback");
        assertNull(program.getMemory().getBlock("renamed"));
        assertEquals("stable", program.getMemory().getBlock("ram").getComment());

        assertError(aborting.splitMemoryBlock(
            "ram", "0x6002", false, ""), "forced rollback");
        assertEquals(1, program.getMemory().getBlocks().length);
        assertNull(program.getMemory().getBlock("ram_split_6002"));

        assertError(aborting.moveMemoryBlock(
            "ram", "0x6100", false, ""), "forced rollback");
        assertEquals("6000", program.getMemory().getBlock("ram")
            .getStart().toString(false));

        assertError(aborting.writeMemoryBytes(
            "0x6000", "aabbccdd", "overwrite_bytes", false, ""),
            "forced rollback");
        assertArrayEquals(hex("00010203"), bytes("0x6000", 4));
    }

    @Test
    public void previewAndCommitExposeMatchingCompleteCreationDescriptors() {
        JsonObject preview = create(
            "previewed", "0x7000", null, "010203", null, null,
            false, null, true, false, true, true, "meta", true);
        JsonObject commit = create(
            "previewed", "0x7000", null, "010203", null, null,
            false, null, true, false, true, true, "meta", false);

        assertTrue(preview.has("before"));
        assertTrue(preview.get("before").isJsonNull());
        assertEquals(preview.get("after"), commit.get("after"));
        assertCompleteDescriptor(preview.getAsJsonObject("after"));
        assertCompleteDescriptor(commit.getAsJsonObject("after"));
    }

    @Test
    public void overflowAndCancellationAreReportedWithoutLeakedBlocks() {
        assertError(memory.createMemoryBlock(
            "overflow", "0xffff", 2L, null, null, null, null,
            false, null, true, false, false, false, null, false, ""),
            "overflow");
        assertNull(program.getMemory().getBlock("overflow"));

        ghidra.util.task.TaskMonitorAdapter cancelled =
            new ghidra.util.task.TaskMonitorAdapter();
        cancelled.setCancelEnabled(true);
        cancelled.cancel();
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        MemoryBlockService cancelledService = new MemoryBlockService(
            provider,
            new DirectThreadingStrategy(),
            SecurityConfig.getInstance(),
            MemoryBlockService::readFileRange,
            new MemoryBlockCore(),
            cancelled);

        Response response = cancelledService.createMemoryBlock(
            "cancelled", "0x7000", null, "0102", null, null, null,
            false, null, true, false, false, false, null, false, "");

        assertError(response, "cancel");
        assertNull(program.getMemory().getBlock("cancelled"));
    }

    @Test
    public void deletePreviewsCollateralAndAppliesExplicitReferencePolicies()
            throws Exception {
        create("source", "0x2000", null, "01020304", null, null,
            false, null, true, false, false, false, null, false);
        create("target", "0x3000", null, "aabbccdd", null, null,
            false, null, true, false, false, false, "obsolete", false);
        Address source = ServiceUtils.parseAddress(program, "0x2000");
        Address target = ServiceUtils.parseAddress(program, "0x3000");
        int transaction = program.startTransaction("collateral");
        try {
            var symbol = program.getSymbolTable().createLabel(
                target, "TARGET_DATA", SourceType.USER_DEFINED);
            var reference = program.getReferenceManager().addMemoryReference(
                source, target, RefType.DATA, SourceType.USER_DEFINED, 0);
            program.getReferenceManager().setAssociation(symbol, reference);
            program.getListing().setComment(
                target, CommentType.PLATE, "delete me");
            program.getBookmarkManager().setBookmark(
                target, "Info", "test", "delete me");
        }
        finally {
            program.endTransaction(transaction, true);
        }

        assertError(memory.deleteMemoryBlock(
            "target", "error", true, ""), "inbound");
        JsonObject preview = ok(memory.deleteMemoryBlock(
            "target", "keep", true, ""));
        assertFalse(preview.get("committed").getAsBoolean());
        assertEquals(1, preview.getAsJsonObject("counts")
            .get("symbols").getAsInt());
        assertEquals(1, preview.getAsJsonObject("counts")
            .get("bookmarks").getAsInt());
        assertEquals(
            java.util.List.of("eol", "pre", "post", "plate", "repeatable"),
            preview.getAsJsonObject("counts").getAsJsonObject("comments")
                .keySet().stream().toList());
        JsonObject inbound = preview.getAsJsonArray("inbound_references")
            .get(0).getAsJsonObject();
        assertTrue(inbound.get("association_cleared").getAsBoolean());
        assertEquals(-1,
            inbound.get("associated_symbol_id_after").getAsLong());

        JsonObject committed = ok(memory.deleteMemoryBlock(
            "target", "keep", false, ""));
        assertTrue(committed.get("committed").getAsBoolean());
        assertNull(program.getMemory().getBlock("target"));
        var kept = program.getReferenceManager().getReference(
            source, target, 0);
        assertTrue(kept != null);
        assertEquals(-1, kept.getSymbolID());

        create("clear_target", "0x3100", null, "0102", null, null,
            false, null, true, false, false, false, null, false);
        Address clearTarget = ServiceUtils.parseAddress(program, "0x3100");
        transaction = program.startTransaction("clear reference");
        try {
            program.getReferenceManager().addMemoryReference(
                source, clearTarget, RefType.DATA,
                SourceType.USER_DEFINED, 1);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        JsonObject dynamicPreview = ok(memory.deleteMemoryBlock(
            "clear_target", "clear", true, ""));
        JsonObject dynamic = dynamicPreview.getAsJsonArray("symbols")
            .get(0).getAsJsonObject();
        assertTrue(dynamic.get("dynamic").getAsBoolean());
        assertTrue(dynamic.get("name").getAsString().startsWith("DAT_"));
        ok(memory.deleteMemoryBlock(
            "clear_target", "clear", false, ""));
        assertNull(program.getReferenceManager().getReference(
            source, clearTarget, 1));
    }

    @Test
    public void resizeGrowsAndShrinksAtomicallyWhilePreservingMetadata() {
        create("resizable", "0x4000", null, "00010203", null, null,
            false, null, true, true, true, true, "stable", false);
        int transaction = program.startTransaction("artificial");
        try {
            program.getMemory().getBlock("resizable").setArtificial(true);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        JsonObject growPreview = ok(memory.resizeMemoryBlock(
            "resizable", null, 6L, "error", null, "aabb",
            null, 0L, null, true, ""));
        assertEquals("grow", growPreview.get("operation").getAsString());
        JsonObject predictedSource = growPreview.getAsJsonObject("after")
            .getAsJsonArray("source_infos").get(1).getAsJsonObject();
        assertEquals("4004",
            predictedSource.get("min_address").getAsString());
        assertEquals("4005",
            predictedSource.get("max_address").getAsString());
        assertArrayEquals(hex("00010203"), bytes("0x4000", 4));
        JsonObject grown = ok(memory.resizeMemoryBlock(
            "resizable", null, 6L, "error", null, "aabb",
            null, 0L, null, false, ""));
        assertArrayEquals(hex("00010203aabb"), bytes("0x4000", 6));
        JsonObject descriptor = grown.getAsJsonObject("after");
        assertEquals("rwx", descriptor.get("permissions").getAsString());
        assertEquals("stable", descriptor.get("comment").getAsString());
        assertTrue(descriptor.get("volatile").getAsBoolean());
        assertTrue(descriptor.get("artificial").getAsBoolean());
        assertEquals(
            growPreview.getAsJsonObject("after").get("start"),
            descriptor.get("start"));
        assertEquals(
            growPreview.getAsJsonObject("after").get("end"),
            descriptor.get("end"));
        assertEquals(
            growPreview.getAsJsonObject("after").get("length"),
            descriptor.get("length"));

        JsonObject shrinkPreview = ok(memory.resizeMemoryBlock(
            "resizable", null, 3L, "error", null, null,
            null, 0L, null, true, ""));
        assertEquals("shrink", shrinkPreview.get("operation").getAsString());
        JsonObject shrunk = ok(memory.resizeMemoryBlock(
            "resizable", null, 3L, "error", null, null,
            null, 0L, null, false, ""));
        assertEquals(3, shrunk.getAsJsonObject("after")
            .get("length").getAsInt());
        assertArrayEquals(hex("000102"), bytes("0x4000", 3));
        assertEquals("stable",
            program.getMemory().getBlock("resizable").getComment());
    }

    @Test
    public void overlayLifecycleChecksBackingAndCleansTheFinalSpace()
            throws Exception {
        create("backing", "0x5000", 0x20L, null, null, null,
            false, 0, true, true, false, false, null, false);
        JsonObject overlay = create(
            "bank", "0x5000", null, "01020304", null, null,
            true, null, true, false, true, false, "banked", false);
        String space = overlay.getAsJsonObject("after")
            .get("address_space").getAsString();

        JsonObject grown = ok(memory.resizeMemoryBlock(
            "bank", null, 6L, "error", 0xff, null,
            null, 0L, null, false, ""));
        assertEquals(6, grown.getAsJsonObject("after")
            .get("length").getAsInt());
        assertArrayEquals(
            hex("01020304ffff"),
            bytes(space + "::0x5000", 6));
        int transaction = program.startTransaction("second overlay block");
        try {
            var overlaySpace =
                (ghidra.program.model.address.OverlayAddressSpace)
                    program.getAddressFactory().getAddressSpace(space);
            program.getMemory().createInitializedBlock(
                "bank_extra",
                overlaySpace.getAddressInThisSpaceOnly(0x5010),
                2,
                (byte) 0,
                ghidra.util.task.TaskMonitor.DUMMY,
                false);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        JsonObject deleted = ok(memory.deleteMemoryBlock(
            "bank", "error", false, ""));
        assertEquals("retained",
            deleted.get("overlay_space_observed").getAsString());
        assertTrue(program.getAddressFactory().getAddressSpace(space) != null);
        assertError(memory.deleteMemoryBlock(
            "bank_extra", "keep", true, ""), "final block");
        deleted = ok(memory.deleteMemoryBlock(
            "bank_extra", "error", false, ""));
        assertEquals("removed",
            deleted.get("overlay_space_observed").getAsString());
        assertNull(program.getAddressFactory().getAddressSpace(space));
    }

    @Test
    public void lifecycleSafetyPoliciesRejectImageMappedAndSplitBoundaries()
            throws Exception {
        create("image", "0x0000", null, "00010203", null, null,
            false, null, true, false, false, false, null, false);
        create("boundary", "0x6000", null, "00010203", null, null,
            false, null, true, false, false, false, null, false);
        int transaction = program.startTransaction("image and data");
        try {
            program.getListing().createData(
                ServiceUtils.parseAddress(program, "0x6002"),
                WordDataType.dataType);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        assertError(memory.deleteMemoryBlock(
            "image", "error", true, ""), "image base");
        assertError(memory.resizeMemoryBlock(
            "boundary", null, 3L, "error", null, null,
            null, 0L, null, true, ""), "code unit");

        create("mapped_source", "0x7000", 0x10L, null, null, null,
            false, 0, true, true, false, false, null, false);
        transaction = program.startTransaction("mapped");
        try {
            program.getMemory().createByteMappedBlock(
                "mapped",
                ServiceUtils.parseAddress(program, "0x7100"),
                ServiceUtils.parseAddress(program, "0x7000"),
                4,
                false);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        MemoryBlockCore.BlockDescriptor mappedDescriptor =
            MemoryBlockCore.descriptor(
                java.util.Arrays.stream(program.getMemory().getBlocks())
                    .filter(block -> block.getName().equals("mapped"))
                    .findFirst().orElseThrow());
        assertTrue(mappedDescriptor.sourceInfos().get(0)
            .mappedRange().start().startsWith("RAM::"));
        assertTrue(mappedDescriptor.sourceInfos().get(0)
            .mappedRange().end().startsWith("RAM::"));
        assertError(memory.deleteMemoryBlock(
            "mapped", "error", true, ""), "mapped");
        assertError(memory.resizeMemoryBlock(
            "mapped", null, 2L, "error", null, null,
            null, 0L, null, true, ""), "mapped");
    }

    @Test
    public void lifecycleRejectsMissingBlocksOverlapAndInvalidGrowSources()
            throws Exception {
        assertError(memory.deleteMemoryBlock(
            "missing", "error", true, ""), "not found");
        assertError(memory.deleteMemoryBlock(
            "missing", "error", false, ""), "not found");
        assertError(memory.resizeMemoryBlock(
            "missing", null, 2L, "error", 0, null,
            null, 0L, null, true, ""), "not found");

        create("growth", "0x9000", null, "0102", null, null,
            false, null, true, true, false, false, null, false);
        create("blocker", "0x9004", null, "ffff", null, null,
            false, null, true, true, false, false, null, false);
        assertError(memory.resizeMemoryBlock(
            "growth", null, 5L, "error", 0, null,
            null, 0L, null, true, ""), "overlap");
        assertError(memory.resizeMemoryBlock(
            "growth", null, 4L, "error", 0, "aabb",
            null, 0L, null, true, ""), "exactly one");
        assertError(memory.resizeMemoryBlock(
            "growth", null, 4L, "error", null, "aa",
            null, 0L, null, true, ""), "length");
        assertError(memory.resizeMemoryBlock(
            "growth", null, 1L, "error", 0, null,
            null, 0L, null, true, ""), "grow-source");
        create("uninitialized", "0x9100", 2L, null, null, null,
            false, null, true, true, false, false, null, false);
        assertError(memory.resizeMemoryBlock(
            "uninitialized", null, 4L, "error", 0, null,
            null, 0L, null, true, ""), "initialized DEFAULT");

        create("wrap", "0xffff", null, "01", null, null,
            false, null, true, false, false, false, null, false);
        assertError(memory.resizeMemoryBlock(
            "wrap", null, 2L, "error", 0, null,
            null, 0L, null, true, ""), "overflow");

        assertEquals(2, program.getMemory().getBlock("growth").getSize());
        assertArrayEquals(hex("0102"), bytes("0x9000", 2));
    }

    @Test
    public void lifecycleFileGrowAndCancellationPreserveAtomicity()
            throws Exception {
        create("file_growth", "0x9200", null, "0102", null, null,
            false, null, true, true, false, false, "stable", false);
        Path root = Files.createTempDirectory("memory-resize-file-root");
        Path source = root.resolve("tail.bin");
        Files.write(source, hex("aabbcc"));
        memory = serviceForRoot(root, new DirectThreadingStrategy());

        JsonObject preview = ok(memory.resizeMemoryBlock(
            "file_growth", null, 5L, "error", null, null,
            source.toString(), 0L, 3L, true, ""));
        JsonObject committed = ok(memory.resizeMemoryBlock(
            "file_growth", null, 5L, "error", null, null,
            source.toString(), 0L, 3L, false, ""));
        assertEquals(preview.get("added_ranges"), committed.get("added_ranges"));
        assertEquals("file", committed.getAsJsonArray("added_ranges")
            .get(0).getAsJsonObject().get("source_kind").getAsString());
        assertArrayEquals(hex("0102aabbcc"), bytes("0x9200", 5));
        assertEquals(
            "stable",
            program.getMemory().getBlock("file_growth").getComment());

        create("cancel_delete", "0x9300", null, "0102", null, null,
            false, null, true, false, false, false, null, false);
        create("cancel_resize", "0x9400", null, "0102", null, null,
            false, null, true, true, false, false, null, false);
        ghidra.util.task.TaskMonitorAdapter cancelled =
            new ghidra.util.task.TaskMonitorAdapter();
        cancelled.setCancelEnabled(true);
        cancelled.cancel();
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        MemoryBlockService cancelledService = new MemoryBlockService(
            provider,
            new DirectThreadingStrategy(),
            SecurityConfig.forFileRootTesting(root),
            MemoryBlockService::readFileRange,
            new MemoryBlockCore(),
            cancelled);

        assertError(cancelledService.deleteMemoryBlock(
            "cancel_delete", "error", false, ""), "cancel");
        assertError(cancelledService.resizeMemoryBlock(
            "cancel_resize", null, 4L, "error", 0xea, null,
            null, 0L, null, false, ""), "cancel");
        assertTrue(program.getMemory().getBlock("cancel_delete") != null);
        assertEquals(
            2, program.getMemory().getBlock("cancel_resize").getSize());
        assertArrayEquals(hex("0102"), bytes("0x9400", 2));
    }

    @Test
    public void overlayResizeRejectsFragmentedBacking() throws Exception {
        create("backing_a", "0xa000", 4L, null, null, null,
            false, 0, true, true, false, false, null, false);
        create("backing_b", "0xa006", 2L, null, null, null,
            false, 0, true, true, false, false, null, false);
        JsonObject overlay = create(
            "fragmented_bank", "0xa000", null, "0102", null, null,
            true, null, true, true, false, false, null, false);
        String space = overlay.getAsJsonObject("after")
            .get("address_space").getAsString();

        assertError(memory.resizeMemoryBlock(
            "fragmented_bank", null, 8L, "error", 0, null,
            null, 0L, null, true, ""), "one complete backing");
        assertEquals(
            2, program.getMemory().getBlock("fragmented_bank").getSize());
        assertArrayEquals(
            hex("0102"), bytes(space + "::0xa000", 2));
    }

    @Test
    public void retainedOverlaySupportsEveryInboundReferencePolicy()
            throws Exception {
        create("policy_backing", "0xa000", 0x30L, null, null, null,
            false, 0, true, true, false, false, null, false);
        create("policy_source", "0xb000", null, "0102", null, null,
            false, null, true, false, false, false, null, false);
        JsonObject overlay = create(
            "policy_keep", "0xa000", null, "1122", null, null,
            true, null, true, true, false, false, null, false);
        String spaceName = overlay.getAsJsonObject("after")
            .get("address_space").getAsString();
        var space =
            (ghidra.program.model.address.OverlayAddressSpace)
                program.getAddressFactory().getAddressSpace(spaceName);
        Address keepTarget = space.getAddressInThisSpaceOnly(0xa000);
        Address clearTarget = space.getAddressInThisSpaceOnly(0xa010);
        Address source = ServiceUtils.parseAddress(program, "0xb000");
        int transaction = program.startTransaction(
            "overlay reference policies");
        try {
            program.getMemory().createInitializedBlock(
                "policy_clear", clearTarget, 2, (byte) 0,
                ghidra.util.task.TaskMonitor.DUMMY, false);
            program.getMemory().createInitializedBlock(
                "policy_final",
                space.getAddressInThisSpaceOnly(0xa020),
                2,
                (byte) 0,
                ghidra.util.task.TaskMonitor.DUMMY,
                false);
            var keepSymbol = program.getSymbolTable().createLabel(
                keepTarget, "KEEP_TARGET", SourceType.USER_DEFINED);
            var clearSymbol = program.getSymbolTable().createLabel(
                clearTarget, "CLEAR_TARGET", SourceType.USER_DEFINED);
            var keepReference =
                program.getReferenceManager().addMemoryReference(
                    source, keepTarget, RefType.DATA,
                    SourceType.USER_DEFINED, 0);
            var clearReference =
                program.getReferenceManager().addMemoryReference(
                    source, clearTarget, RefType.DATA,
                    SourceType.USER_DEFINED, 1);
            program.getReferenceManager().setAssociation(
                keepSymbol, keepReference);
            program.getReferenceManager().setAssociation(
                clearSymbol, clearReference);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        assertError(memory.deleteMemoryBlock(
            "policy_keep", "error", true, ""), "inbound");
        JsonObject keepPreview = ok(memory.deleteMemoryBlock(
            "policy_keep", "keep", true, ""));
        assertTrue(keepPreview.getAsJsonArray("inbound_references")
            .get(0).getAsJsonObject()
            .get("association_cleared").getAsBoolean());
        JsonObject kept = ok(memory.deleteMemoryBlock(
            "policy_keep", "keep", false, ""));
        assertEquals(
            "retained",
            kept.get("overlay_space_observed").getAsString());
        assertEquals(
            -1,
            program.getReferenceManager()
                .getReference(source, keepTarget, 0)
                .getSymbolID());

        JsonObject cleared = ok(memory.deleteMemoryBlock(
            "policy_clear", "clear", false, ""));
        assertEquals(
            "retained",
            cleared.get("overlay_space_observed").getAsString());
        assertNull(program.getReferenceManager().getReference(
            source, clearTarget, 1));

        assertError(memory.deleteMemoryBlock(
            "policy_final", "keep", true, ""), "final block");
        ok(memory.deleteMemoryBlock(
            "policy_final", "error", false, ""));
        assertNull(program.getAddressFactory().getAddressSpace(spaceName));
    }

    @Test
    public void lifecycleDryRunsAndLateFailuresRollbackCompositeChanges() {
        create("delete_me", "0x8000", null, "0102", null, null,
            false, null, true, false, false, false, null, false);
        create("resize_me", "0x8100", null, "01020304", null, null,
            false, null, true, true, false, false, "stable", false);

        ok(memory.deleteMemoryBlock(
            "delete_me", "error", true, ""));
        ok(memory.resizeMemoryBlock(
            "resize_me", null, 6L, "error", null, "aabb",
            null, 0L, null, true, ""));
        assertTrue(program.getMemory().getBlock("delete_me") != null);
        assertArrayEquals(hex("01020304"), bytes("0x8100", 4));

        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        MemoryBlockService aborting = new MemoryBlockService(
            provider, new AbortAfterActionStrategy());
        assertError(aborting.deleteMemoryBlock(
            "delete_me", "error", false, ""), "forced rollback");
        assertTrue(program.getMemory().getBlock("delete_me") != null);
        assertError(aborting.resizeMemoryBlock(
            "resize_me", null, 6L, "error", null, "aabb",
            null, 0L, null, false, ""), "forced rollback");
        assertEquals(4,
            program.getMemory().getBlock("resize_me").getSize());
        assertArrayEquals(hex("01020304"), bytes("0x8100", 4));
    }

    private MemoryBlockService serviceForRoot(
            Path root, DirectThreadingStrategy strategy) {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        return new MemoryBlockService(
            provider, strategy, SecurityConfig.forFileRootTesting(root),
            MemoryBlockService::readFileRange);
    }

    private void assertOverlayPreviewCommitSpace(
            String name, String expectedSpace) {
        JsonObject preview = create(
            name, "0xa000", null, "0102", null, null,
            true, null, true, false, false, false, null, true);
        JsonObject commit = create(
            name, "0xa000", null, "0102", null, null,
            true, null, true, false, false, false, null, false);

        assertEquals(expectedSpace, preview.getAsJsonObject("after")
            .get("address_space").getAsString());
        assertEquals(preview.get("after"), commit.get("after"));
        assertEquals(expectedSpace, commit.get("address_space").getAsString());
    }

    private JsonObject create(
            String name, String start, Long length, String bytes,
            String filePath, Long fileOffset, boolean overlay, Integer fill,
            boolean read, boolean write, boolean execute, boolean volatileFlag,
            String comment, boolean dryRun) {
        return create(name, start, length, bytes, filePath, fileOffset,
            overlay, fill, read, write, execute, volatileFlag, comment, dryRun,
            null);
    }

    private JsonObject create(
            String name, String start, Long length, String bytes,
            String filePath, Long fileOffset, boolean overlay, Integer fill,
            boolean read, boolean write, boolean execute, boolean volatileFlag,
            String comment, boolean dryRun, Long sourceLength) {
        return ok(memory.createMemoryBlock(
            name, start, length, bytes, filePath,
            fileOffset, sourceLength,
            overlay, fill, read, write, execute, volatileFlag, comment,
            dryRun, ""));
    }

    private byte[] bytes(String address, int length) {
        byte[] result = new byte[length];
        Address start = ServiceUtils.parseAddress(program, address);
        try {
            assertEquals(length, program.getMemory().getBytes(start, result));
            return result;
        }
        catch (Exception error) {
            throw new AssertionError(error);
        }
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(
                value.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    private static byte[] alternatingDifferences(int rangeCount) {
        byte[] requested = new byte[Math.multiplyExact(rangeCount, 2) - 1];
        for (int index = 0; index < requested.length; index += 2) {
            requested[index] = 1;
        }
        return requested;
    }

    private static JsonObject ok(Response response) {
        assertTrue(response.toJson(), response instanceof Response.Ok);
        return JsonParser.parseString(response.toJson()).getAsJsonObject();
    }

    private static void assertError(Response response, String fragment) {
        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(),
            response.toJson().toLowerCase().contains(fragment.toLowerCase()));
    }

    private static void assertCompleteDescriptor(JsonObject descriptor) {
        assertEquals(
            java.util.Set.of(
                "name", "start", "end", "length", "address_space",
                "overlay", "initialized", "source", "read", "write",
                "execute", "permissions", "volatile", "comment", "type",
                "artificial", "loaded", "source_name",
                "overlay_base_space", "source_infos"),
            descriptor.keySet());
    }

    private static final class AbortAfterActionStrategy
            extends DirectThreadingStrategy {
        @Override
        public <T> T executeWrite(
                ghidra.program.model.listing.Program program,
                String txName,
                Callable<T> action) throws Exception {
            return super.executeWrite(program, txName, () -> {
                action.call();
                throw new Exception("forced rollback");
            });
        }
    }
}
