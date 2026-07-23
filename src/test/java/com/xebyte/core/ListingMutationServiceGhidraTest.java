package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.headless.HeadlessProgramProvider;
import com.xebyte.headless.DirectThreadingStrategy;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

/**
 * Endpoint-level transaction and response-contract tests. Real ProgramDB
 * fixtures are added below for Ghidra's code-unit and annotation semantics.
 */
public class ListingMutationServiceGhidraTest {

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0);

    @Test
    public void dryRunIsReadOnlyAndCommitReplansInsideTheWriteTransaction() {
        Program program = program("fixture", address(0x1000), address(0x10ff));
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        RecordingThreadingStrategy threading = new RecordingThreadingStrategy();
        AtomicInteger planCalls = new AtomicInteger();
        AtomicInteger applyCalls = new AtomicInteger();
        AtomicBoolean commitPlanWasTransactionLocal = new AtomicBoolean();
        AtomicReference<ListingClearCore.Plan> committedPlan = new AtomicReference<>();

        ListingMutationService service = new ListingMutationService(
            provider,
            threading,
            (ignoredProgram, requested, selection, preservation) -> {
                int call = planCalls.incrementAndGet();
                if (call == 2) {
                    commitPlanWasTransactionLocal.set(threading.inWrite);
                }
                return plan(address(0x1000), address(0x1002));
            },
            (ignoredProgram, plan) -> {
                applyCalls.incrementAndGet();
                committedPlan.set(plan);
            });

        Response preview = call(service, true);
        Response commit = call(service, false);

        assertFalse(preview.toJson(), preview instanceof Response.Err);
        assertFalse(commit.toJson(), commit instanceof Response.Err);
        assertTrue(preview.toJson(), preview.toJson().contains("\"committed\":false"));
        assertTrue(commit.toJson(), commit.toJson().contains("\"committed\":true"));
        assertEquals(2, planCalls.get());
        assertEquals(1, applyCalls.get());
        assertEquals(1, threading.readCalls);
        assertEquals(1, threading.writeCalls);
        assertTrue("commit must plan after the transaction has opened",
            commitPlanWasTransactionLocal.get());
        assertEquals(plan(address(0x1000), address(0x1002)), committedPlan.get());
    }

    @Test
    public void rejectsAnEmptyKindSelectionBeforeStartingAReadOrWrite() {
        Program program = program("fixture", address(0x1000), address(0x10ff));
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        RecordingThreadingStrategy threading = new RecordingThreadingStrategy();
        AtomicInteger planCalls = new AtomicInteger();
        ListingMutationService service = new ListingMutationService(
            provider,
            threading,
            (ignoredProgram, requested, selection, preservation) -> {
                planCalls.incrementAndGet();
                return plan(address(0x1000), address(0x1000));
            },
            (ignoredProgram, plan) -> {
                throw new AssertionError("invalid request reached apply");
            });

        Response response = service.undefineRange(
            "ram:1000", "ram:1000",
            false, false,
            true, true, true, true,
            false, true, "");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains(
            "clear_instructions or clear_data"));
        assertEquals(0, planCalls.get());
        assertEquals(0, threading.readCalls);
        assertEquals(0, threading.writeCalls);
    }

    @Test
    public void nonDryRunWithFunctionConflictIsRejectedWithoutApplying() {
        Program program = program("fixture", address(0x1000), address(0x10ff));
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        RecordingThreadingStrategy threading = new RecordingThreadingStrategy();
        AtomicInteger applyCalls = new AtomicInteger();
        ListingClearCore.Plan blocked = new ListingClearCore.Plan(
            new AddressSet(address(0x1000), address(0x1000)),
            List.of(new ListingClearCore.CodeUnitSnapshot(
                address(0x1000), address(0x1000),
                ListingClearCore.UnitKind.INSTRUCTION)),
            List.of(),
            emptyAnnotations(),
            emptyAnnotations(),
            java.util.Map.of(),
            new ListingClearCore.RemovalCounts(1, 0, 0),
            List.of("instruction intersects function routine at ram:1000"));
        ListingMutationService service = new ListingMutationService(
            provider,
            threading,
            (ignoredProgram, requested, selection, preservation) -> blocked,
            (ignoredProgram, plan) -> applyCalls.incrementAndGet());

        Response response = call(service, false);

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains(
            "blocked by preflight conflicts"));
        assertTrue(response.toJson(), response.toJson().contains("routine"));
        assertEquals(0, applyCalls.get());
        assertEquals(1, threading.writeCalls);
    }

    @Test
    public void responseReportsRealRemovedCountsAndReferenceSourceGroups() {
        Program program = program("fixture", address(0x1000), address(0x10ff));
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        ListingClearCore.LabelSnapshot removedLabel =
            new ListingClearCore.LabelSnapshot(
                address(0x1000), "gone", null, SourceType.ANALYSIS,
                ghidra.program.model.symbol.SymbolType.LABEL, false, false);
        ListingClearCore.CommentSnapshot removedComment =
            new ListingClearCore.CommentSnapshot(
                address(0x1000),
                ghidra.program.model.listing.CommentType.EOL,
                "gone");
        ListingClearCore.BookmarkSnapshot removedBookmark =
            new ListingClearCore.BookmarkSnapshot(
                address(0x1000), "NOTE", "review", "gone");
        ListingClearCore.ReferenceSnapshot removedUserReference =
            memoryReference(SourceType.USER_DEFINED, address(0x1010));
        ListingClearCore.ReferenceSnapshot removedAnalysisReference =
            memoryReference(SourceType.ANALYSIS, address(0x1011));
        ListingClearCore.AnnotationSnapshot removed =
            new ListingClearCore.AnnotationSnapshot(
                List.of(removedLabel),
                List.of(removedComment),
                List.of(removedBookmark),
                List.of(removedUserReference, removedAnalysisReference));
        ListingClearCore.Plan planned = new ListingClearCore.Plan(
            new AddressSet(address(0x1000), address(0x1000)),
            List.of(new ListingClearCore.CodeUnitSnapshot(
                address(0x1000), address(0x1000), ListingClearCore.UnitKind.DATA)),
            List.of(),
            emptyAnnotations(),
            removed,
            java.util.Map.of(SourceType.USER_DEFINED, 1, SourceType.ANALYSIS, 1),
            new ListingClearCore.RemovalCounts(0, 1, 0),
            List.of());
        ListingMutationService service = new ListingMutationService(
            provider,
            new RecordingThreadingStrategy(),
            (ignoredProgram, requested, selection, preservation) -> planned,
            (ignoredProgram, plan) -> {
            });

        Response response = call(service, true);

        assertFalse(response.toJson(), response instanceof Response.Err);
        com.google.gson.JsonObject json =
            com.google.gson.JsonParser.parseString(response.toJson()).getAsJsonObject();
        assertEquals(1, json.getAsJsonObject("removed_annotation_counts")
            .get("labels").getAsInt());
        assertEquals(1, json.getAsJsonObject("removed_annotation_counts")
            .get("comments").getAsInt());
        assertEquals(1, json.getAsJsonObject("removed_annotation_counts")
            .get("bookmarks").getAsInt());
        assertEquals(2, json.getAsJsonObject("removed_annotation_counts")
            .get("references").getAsInt());
        assertEquals(1, json.getAsJsonObject("removed_references_by_source_type")
            .get("USER_DEFINED").getAsInt());
        assertEquals(1, json.getAsJsonObject("removed_references_by_source_type")
            .get("ANALYSIS").getAsInt());
        assertEquals(2, json.getAsJsonObject("source_rules")
            .getAsJsonArray("preserved_label_sources").size());
        assertEquals(2, json.getAsJsonObject("source_rules")
            .getAsJsonArray("preserved_outgoing_reference_sources").size());
        assertEquals("untouched", json.getAsJsonObject("source_rules")
            .get("incoming_references").getAsString());
    }

    @Test
    public void sourceRulesEchoDisabledLabelAndReferencePreservation() {
        Program program = program("fixture", address(0x1000), address(0x10ff));
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        ListingMutationService service = new ListingMutationService(
            provider,
            new RecordingThreadingStrategy(),
            (ignoredProgram, requested, selection, preservation) ->
                plan(address(0x1000), address(0x1000)),
            (ignoredProgram, plan) -> {
            });

        Response response = service.undefineRange(
            "ram:1000", "ram:1000",
            false, true,
            false, true, true, false,
            false, true, "");

        assertFalse(response.toJson(), response instanceof Response.Err);
        JsonObject rules = JsonParser.parseString(response.toJson())
            .getAsJsonObject()
            .getAsJsonObject("source_rules");
        assertEquals(0, rules.getAsJsonArray("preserved_label_sources").size());
        assertEquals(0, rules.getAsJsonArray(
            "preserved_outgoing_reference_sources").size());
        assertEquals("untouched", rules.get("incoming_references").getAsString());
    }

    @Test
    public void noOpKindSelectionHasNoExpansionAndCanCommitAtomically() {
        Program program = program("fixture", address(0x1000), address(0x10ff));
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        RecordingThreadingStrategy threading = new RecordingThreadingStrategy();
        AtomicInteger applyCalls = new AtomicInteger();
        ListingMutationService service = new ListingMutationService(
            provider,
            threading,
            (ignoredProgram, requested, selection, preservation) -> emptyPlan(),
            (ignoredProgram, plan) -> applyCalls.incrementAndGet());

        Response response = service.undefineRange(
            "ram:1000", "ram:1002",
            true, false,
            true, true, true, true,
            false, false, "");

        assertFalse(response.toJson(), response instanceof Response.Err);
        JsonObject json =
            JsonParser.parseString(response.toJson()).getAsJsonObject();
        assertTrue(response.toJson(), json.has("expanded_range"));
        assertTrue(json.get("expanded_range").isJsonNull());
        assertEquals(0, json.getAsJsonArray("expanded_ranges").size());
        assertEquals(0, json.getAsJsonArray("affected_code_units").size());
        assertTrue(json.get("committed").getAsBoolean());
        assertEquals(1, applyCalls.get());
        assertEquals(1, threading.writeCalls);
    }

    @Test
    public void rejectsCrossSpaceAndMappedGapsBeforePlanning() {
        GenericAddressSpace other =
            new GenericAddressSpace("other", 16, AddressSpace.TYPE_RAM, 1);
        Program crossSpaceProgram = mock(Program.class);
        AddressFactory crossSpaceFactory = mock(AddressFactory.class);
        when(crossSpaceFactory.getAddress("ram:1000")).thenReturn(address(0x1000));
        when(crossSpaceFactory.getAddress("other:1000"))
            .thenReturn(other.getAddress(0x1000));
        when(crossSpaceProgram.getAddressFactory()).thenReturn(crossSpaceFactory);
        when(crossSpaceProgram.getName()).thenReturn("cross-space");
        when(crossSpaceProgram.getMemory()).thenReturn(mock(Memory.class));

        HeadlessProgramProvider crossSpaceProvider = new HeadlessProgramProvider();
        crossSpaceProvider.setCurrentProgram(crossSpaceProgram);
        RecordingThreadingStrategy crossSpaceThreading =
            new RecordingThreadingStrategy();
        AtomicInteger planCalls = new AtomicInteger();
        ListingMutationService crossSpaceService = new ListingMutationService(
            crossSpaceProvider,
            crossSpaceThreading,
            (ignoredProgram, requested, selection, preservation) -> {
                planCalls.incrementAndGet();
                return emptyPlan();
            },
            (ignoredProgram, plan) -> {
            });

        Response crossSpaceResponse = crossSpaceService.undefineRange(
            "ram:1000", "other:1000",
            true, true,
            true, true, true, true,
            false, true, "");

        assertTrue(crossSpaceResponse.toJson(),
            crossSpaceResponse instanceof Response.Err);
        assertTrue(crossSpaceResponse.toJson(),
            crossSpaceResponse.toJson().contains("same address space"));
        assertEquals(0, planCalls.get());

        Program gapProgram = program("gap", address(0x1000), address(0x10ff));
        when(gapProgram.getMemory().contains(
            any(Address.class), any(Address.class))).thenReturn(false);
        HeadlessProgramProvider gapProvider = new HeadlessProgramProvider();
        gapProvider.setCurrentProgram(gapProgram);
        ListingMutationService gapService = new ListingMutationService(
            gapProvider,
            new RecordingThreadingStrategy(),
            (ignoredProgram, requested, selection, preservation) -> {
                planCalls.incrementAndGet();
                return emptyPlan();
            },
            (ignoredProgram, plan) -> {
            });

        Response gapResponse = call(gapService, true);

        assertTrue(gapResponse.toJson(), gapResponse instanceof Response.Err);
        assertTrue(gapResponse.toJson(), gapResponse.toJson().contains("mapped"));
        assertEquals(0, planCalls.get());
    }

    @Test
    public void liveMixedPartialRangePreservesOwnedAnnotationsAndMatchesPreview()
            throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("undefine-mixed-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x1000", 0x40);
            builder.setBytes(
                "0x1000",
                "a9 01 60 ea 11 22 33 ea ea ea ea ea ea ea ea ea "
                    + "ea ea ea ea ea ea ea ea ea ea ea ea ea ea ea ea");
            builder.disassemble("0x1000", 3);
            builder.applyDataType(
                "0x1004", new ArrayDataType(ByteDataType.dataType, 3, 1));
            builder.createFunction("0x1000");
            builder.withTransaction(() -> {
                try {
                    Symbol user = liveProgram.getSymbolTable().createLabel(
                        builder.addr("0x1001"), "user_inside",
                        SourceType.USER_DEFINED);
                    user.setPrimary();
                    liveProgram.getSymbolTable().createLabel(
                        builder.addr("0x1001"), "imported_inside",
                        SourceType.IMPORTED);
                    liveProgram.getSymbolTable().createLabel(
                        builder.addr("0x1001"), "analysis_inside",
                        SourceType.ANALYSIS);
                    Symbol promoted = liveProgram.getSymbolTable().createLabel(
                        builder.addr("0x1005"), "promoted_survivor",
                        SourceType.USER_DEFINED);
                    Symbol removedPrimary =
                        liveProgram.getSymbolTable().createLabel(
                            builder.addr("0x1005"), "removed_primary",
                            SourceType.ANALYSIS);
                    removedPrimary.setPrimary();
                    assertFalse(promoted.isPrimary());
                    for (CommentType type : CommentType.values()) {
                        liveProgram.getListing().setComment(
                            builder.addr("0x1001"), type,
                            type.name().toLowerCase() + " comment");
                    }
                    liveProgram.getBookmarkManager().setBookmark(
                        builder.addr("0x1001"), "NOTE", "review", "keep once");
                    addReference(
                        liveProgram, builder, "0x1001", "0x1010", 0,
                        SourceType.USER_DEFINED);
                    addReference(
                        liveProgram, builder, "0x1001", "0x1011", 1,
                        SourceType.IMPORTED);
                    addReference(
                        liveProgram, builder, "0x1001", "0x1012", 2,
                        SourceType.ANALYSIS);
                    addReference(
                        liveProgram, builder, "0x1001", "0x1013", 3,
                        SourceType.DEFAULT);
                    addReference(
                        liveProgram, builder, "0x1020", "0x1001", 0,
                        SourceType.USER_DEFINED);
                }
                catch (Exception exception) {
                    throw new AssertionError(exception);
                }
            });

            ListingMutationService service = liveService(liveProgram);
            Response preview = service.undefineRange(
                "0x1001", "0x1005",
                true, true,
                true, true, true, true,
                true, true, "");
            Response commit = service.undefineRange(
                "0x1001", "0x1005",
                true, true,
                true, true, true, true,
                true, false, "");

            assertFalse(preview.toJson(), preview instanceof Response.Err);
            assertFalse(commit.toJson(), commit instanceof Response.Err);
            JsonObject previewJson =
                JsonParser.parseString(preview.toJson()).getAsJsonObject();
            JsonObject commitJson =
                JsonParser.parseString(commit.toJson()).getAsJsonObject();
            assertPlanFieldsEqual(previewJson, commitJson);
            assertFalse(previewJson.get("committed").getAsBoolean());
            assertTrue(commitJson.get("committed").getAsBoolean());
            assertEquals(3,
                previewJson.getAsJsonArray("affected_code_units").size());
            assertEquals(3, previewJson.getAsJsonObject(
                "preserved_annotation_counts").get("labels").getAsInt());
            assertEquals(CommentType.values().length, previewJson.getAsJsonObject(
                "preserved_annotation_counts").get("comments").getAsInt());
            assertEquals(1, previewJson.getAsJsonObject(
                "preserved_annotation_counts").get("bookmarks").getAsInt());
            assertEquals(2, previewJson.getAsJsonObject(
                "preserved_annotation_counts").get("references").getAsInt());
            assertEquals(1, previewJson.getAsJsonObject(
                "removed_references_by_source_type").get("ANALYSIS").getAsInt());
            assertEquals(1, previewJson.getAsJsonObject(
                "removed_references_by_source_type").get("DEFAULT").getAsInt());
            assertEquals(
                "preserved when representable; a surviving preserved secondary "
                    + "may be promoted when its removed ANALYSIS/DEFAULT primary "
                    + "disappears",
                previewJson.getAsJsonObject("source_rules")
                    .get("primary_label_state").getAsString());

            assertNull(liveProgram.getListing()
                .getInstructionContaining(builder.addr("0x1001")));
            assertNull(liveProgram.getListing()
                .getDefinedDataContaining(builder.addr("0x1005")));
            assertNull(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x1002")));
            assertNull(liveProgram.getFunctionManager()
                .getFunctionAt(builder.addr("0x1000")));
            Symbol restoredUser = liveProgram.getSymbolTable().getSymbol(
                "user_inside", builder.addr("0x1001"),
                liveProgram.getGlobalNamespace());
            Symbol restoredImported = liveProgram.getSymbolTable().getSymbol(
                "imported_inside", builder.addr("0x1001"),
                liveProgram.getGlobalNamespace());
            assertNotNull(restoredUser);
            assertNotNull(restoredImported);
            assertTrue(restoredUser.isPrimary());
            assertFalse(restoredImported.isPrimary());
            assertNull(liveProgram.getSymbolTable().getSymbol(
                "analysis_inside", builder.addr("0x1001"),
                liveProgram.getGlobalNamespace()));
            Symbol promotedSurvivor = liveProgram.getSymbolTable().getSymbol(
                "promoted_survivor", builder.addr("0x1005"),
                liveProgram.getGlobalNamespace());
            assertNotNull(promotedSurvivor);
            assertTrue(promotedSurvivor.isPrimary());
            assertNull(liveProgram.getSymbolTable().getSymbol(
                "removed_primary", builder.addr("0x1005"),
                liveProgram.getGlobalNamespace()));
            for (CommentType type : CommentType.values()) {
                assertEquals(
                    type.name().toLowerCase() + " comment",
                    liveProgram.getListing().getComment(
                        type, builder.addr("0x1001")));
            }
            assertEquals(1,
                liveProgram.getBookmarkManager()
                    .getBookmarks(builder.addr("0x1001")).length);
            assertEquals(
                List.of(SourceType.USER_DEFINED, SourceType.IMPORTED),
                Arrays.stream(liveProgram.getReferenceManager()
                    .getReferencesFrom(builder.addr("0x1001")))
                    .map(reference -> reference.getSource())
                    .toList());
            assertTrue(
                liveProgram.getReferenceManager()
                    .getReferencesTo(builder.addr("0x1001")).hasNext());
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void livePreservationFalseRemovesOnlyAnnotationsOnSelectedUnits()
            throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("undefine-removal-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x2000", 0x30);
            builder.setBytes(
                "0x2000",
                "01 02 03 ea ea ea ea ea ea ea ea ea ea ea ea ea "
                    + "04 ea ea ea ea ea ea ea ea ea ea ea ea ea ea ea");
            builder.applyDataType(
                "0x2000", new ArrayDataType(ByteDataType.dataType, 3, 1));
            builder.applyDataType("0x2010", ByteDataType.dataType);
            builder.withTransaction(() -> {
                try {
                    liveProgram.getSymbolTable().createLabel(
                        builder.addr("0x2001"), "selected_label",
                        SourceType.USER_DEFINED);
                    liveProgram.getSymbolTable().createLabel(
                        builder.addr("0x2010"), "untouched_label",
                        SourceType.USER_DEFINED);
                    liveProgram.getListing().setComment(
                        builder.addr("0x2001"), CommentType.EOL, "remove");
                    liveProgram.getListing().setComment(
                        builder.addr("0x2010"), CommentType.EOL, "keep");
                    liveProgram.getBookmarkManager().setBookmark(
                        builder.addr("0x2001"), "NOTE", "review", "remove");
                    liveProgram.getBookmarkManager().setBookmark(
                        builder.addr("0x2010"), "NOTE", "review", "keep");
                    addReference(
                        liveProgram, builder, "0x2001", "0x2020", 0,
                        SourceType.USER_DEFINED);
                    addReference(
                        liveProgram, builder, "0x2021", "0x2001", 0,
                        SourceType.USER_DEFINED);
                }
                catch (Exception exception) {
                    throw new AssertionError(exception);
                }
            });

            ListingMutationService service = liveService(liveProgram);
            Response response = service.undefineRange(
                "0x2001", "0x2001",
                false, true,
                false, false, false, false,
                false, false, "");

            assertFalse(response.toJson(), response instanceof Response.Err);
            assertNull(liveProgram.getListing()
                .getDefinedDataContaining(builder.addr("0x2001")));
            assertNull(liveProgram.getSymbolTable().getSymbol(
                "selected_label", builder.addr("0x2001"),
                liveProgram.getGlobalNamespace()));
            assertNull(liveProgram.getListing().getComment(
                CommentType.EOL, builder.addr("0x2001")));
            assertEquals(0, liveProgram.getBookmarkManager()
                .getBookmarks(builder.addr("0x2001")).length);
            assertEquals(0, liveProgram.getReferenceManager()
                .getReferencesFrom(builder.addr("0x2001")).length);
            assertTrue(liveProgram.getReferenceManager()
                .getReferencesTo(builder.addr("0x2001")).hasNext());
            assertNotNull(liveProgram.getListing()
                .getDefinedDataAt(builder.addr("0x2010")));
            assertNotNull(liveProgram.getSymbolTable().getSymbol(
                "untouched_label", builder.addr("0x2010"),
                liveProgram.getGlobalNamespace()));
            assertEquals("keep", liveProgram.getListing().getComment(
                CommentType.EOL, builder.addr("0x2010")));
            assertEquals(1, liveProgram.getBookmarkManager()
                .getBookmarks(builder.addr("0x2010")).length);
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void liveApplyFailureRollsBackListingAndAnnotations() throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("undefine-rollback-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x3000", 4);
            builder.setBytes("0x3000", "01 02 03 04");
            builder.applyDataType(
                "0x3000", new ArrayDataType(ByteDataType.dataType, 4, 1));
            builder.createLabel("0x3001", "rollback_label");
            builder.createComment(
                "0x3001", "rollback comment", CommentType.EOL);
            builder.withTransaction(() -> {
                liveProgram.getBookmarkManager().setBookmark(
                    builder.addr("0x3001"), "NOTE", "rollback",
                    "rollback bookmark");
                addReference(
                    liveProgram, builder, "0x3001", "0x3003", 0,
                    SourceType.USER_DEFINED);
            });
            ListingClearCore core = new ListingClearCore();
            HeadlessProgramProvider provider = new HeadlessProgramProvider();
            provider.setCurrentProgram(liveProgram);
            ListingMutationService service = new ListingMutationService(
                provider,
                new DirectThreadingStrategy(),
                core::plan,
                (program, plan) -> {
                    core.apply(program, plan);
                    throw new IllegalStateException("forced rollback");
                });

            Response response = service.undefineRange(
                "0x3001", "0x3001",
                false, true,
                true, true, true, true,
                false, false, "");

            assertTrue(response.toJson(), response instanceof Response.Err);
            assertTrue(response.toJson(), response.toJson().contains("forced rollback"));
            assertNotNull(liveProgram.getListing()
                .getDefinedDataContaining(builder.addr("0x3001")));
            assertNotNull(liveProgram.getSymbolTable().getSymbol(
                "rollback_label", builder.addr("0x3001"),
                liveProgram.getGlobalNamespace()));
            assertEquals("rollback comment", liveProgram.getListing().getComment(
                CommentType.EOL, builder.addr("0x3001")));
            Bookmark[] bookmarks = liveProgram.getBookmarkManager()
                .getBookmarks(builder.addr("0x3001"));
            assertEquals(1, bookmarks.length);
            assertEquals("NOTE", bookmarks[0].getTypeString());
            assertEquals("rollback", bookmarks[0].getCategory());
            assertEquals("rollback bookmark", bookmarks[0].getComment());
            Reference[] references = liveProgram.getReferenceManager()
                .getReferencesFrom(builder.addr("0x3001"));
            assertEquals(1, references.length);
            assertEquals(builder.addr("0x3003"), references[0].getToAddress());
            assertEquals(SourceType.USER_DEFINED, references[0].getSource());
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void liveFunctionRemovalRejectsLocalLabelsAndCollateralReferences()
            throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("undefine-function-collateral-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x4000", 0x20);
            builder.setBytes(
                "0x4000",
                "ea ea 60 ea ea ea ea ea ea ea ea ea ea ea ea ea "
                    + "ea ea ea ea ea ea ea ea ea ea ea ea ea ea ea ea");
            builder.disassemble("0x4000", 3);
            builder.createFunction("0x4000");
            AtomicReference<Symbol> selectedLocal = new AtomicReference<>();
            AtomicReference<Symbol> outsideLocal = new AtomicReference<>();
            builder.withTransaction(() -> {
                try {
                    Function function = liveProgram.getFunctionManager()
                        .getFunctionAt(builder.addr("0x4000"));
                    selectedLocal.set(liveProgram.getSymbolTable().createLabel(
                        builder.addr("0x4000"), "selected_local", function,
                        SourceType.USER_DEFINED));
                    outsideLocal.set(liveProgram.getSymbolTable().createLabel(
                        builder.addr("0x4001"), "outside_local", function,
                        SourceType.USER_DEFINED));
                    function.getStackFrame().createVariable(
                        "stack_local", -2, ByteDataType.dataType,
                        SourceType.USER_DEFINED);
                    liveProgram.getReferenceManager().addStackReference(
                        builder.addr("0x4001"), 0, -2, RefType.DATA,
                        SourceType.USER_DEFINED);
                    Register register = liveProgram.getRegister("A");
                    assertNotNull(register);
                    liveProgram.getReferenceManager().addRegisterReference(
                        builder.addr("0x4002"), 1, register, RefType.DATA,
                        SourceType.IMPORTED);
                }
                catch (Exception exception) {
                    throw new AssertionError(exception);
                }
            });

            ListingMutationService service = liveService(liveProgram);
            Response bothLabels = service.undefineRange(
                "0x4000", "0x4000",
                true, false,
                true, true, true, false,
                true, true, "");
            assertFalse(bothLabels.toJson(), bothLabels instanceof Response.Err);
            JsonObject bothJson =
                JsonParser.parseString(bothLabels.toJson()).getAsJsonObject();
            assertEquals(4, bothJson.getAsJsonArray("conflicts").size());

            Response outsideOnly = service.undefineRange(
                "0x4000", "0x4000",
                true, false,
                false, true, true, false,
                true, true, "");
            assertFalse(outsideOnly.toJson(), outsideOnly instanceof Response.Err);
            assertEquals(3, JsonParser.parseString(outsideOnly.toJson())
                .getAsJsonObject().getAsJsonArray("conflicts").size());

            builder.withTransaction(() -> outsideLocal.get().delete());
            Response selectedOnly = service.undefineRange(
                "0x4000", "0x4000",
                true, false,
                true, true, true, false,
                true, true, "");
            assertFalse(selectedOnly.toJson(), selectedOnly instanceof Response.Err);
            assertEquals(3, JsonParser.parseString(selectedOnly.toJson())
                .getAsJsonObject().getAsJsonArray("conflicts").size());

            builder.withTransaction(() -> selectedLocal.get().delete());
            Response stackConflict = service.undefineRange(
                "0x4000", "0x4000",
                true, false,
                true, true, true, false,
                true, true, "");
            JsonObject stackConflictJson =
                JsonParser.parseString(stackConflict.toJson()).getAsJsonObject();
            assertEquals(2,
                stackConflictJson.getAsJsonArray("conflicts").size());
            assertTrue(stackConflictJson.getAsJsonArray("conflicts").toString()
                .contains("function-variable association"));
            assertTrue(stackConflictJson.getAsJsonArray("conflicts").toString()
                .contains("register reference"));

            Response rejectedCommit = service.undefineRange(
                "0x4000", "0x4000",
                true, false,
                true, true, true, false,
                true, false, "");
            assertTrue(rejectedCommit.toJson(),
                rejectedCommit instanceof Response.Err);
            assertNotNull(liveProgram.getFunctionManager()
                .getFunctionAt(builder.addr("0x4000")));
            assertNotNull(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x4000")));
            assertEquals(1, liveProgram.getReferenceManager()
                .getReferencesFrom(builder.addr("0x4001")).length);
            assertEquals(1, liveProgram.getReferenceManager()
                .getReferencesFrom(builder.addr("0x4002")).length);

            builder.withTransaction(() -> {
                for (Reference reference : liveProgram.getReferenceManager()
                        .getReferencesFrom(builder.addr("0x4001"))) {
                    liveProgram.getReferenceManager().delete(reference);
                }
                for (Reference reference : liveProgram.getReferenceManager()
                        .getReferencesFrom(builder.addr("0x4002"))) {
                    liveProgram.getReferenceManager().delete(reference);
                }
            });

            Response preview = service.undefineRange(
                "0x4000", "0x4000",
                true, false,
                true, true, true, false,
                true, true, "");
            Response commit = service.undefineRange(
                "0x4000", "0x4000",
                true, false,
                true, true, true, false,
                true, false, "");
            assertFalse(preview.toJson(), preview instanceof Response.Err);
            assertFalse(commit.toJson(), commit instanceof Response.Err);
            JsonObject previewJson =
                JsonParser.parseString(preview.toJson()).getAsJsonObject();
            assertTrue(previewJson.getAsJsonArray("conflicts").isEmpty());
            assertNull(liveProgram.getFunctionManager()
                .getFunctionAt(builder.addr("0x4000")));
            assertNull(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x4000")));
            assertNotNull(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x4001")));
            assertEquals(0, liveProgram.getReferenceManager()
                .getReferencesFrom(builder.addr("0x4001")).length);
            assertEquals(0, liveProgram.getReferenceManager()
                .getReferencesFrom(builder.addr("0x4002")).length);
        }
        finally {
            builder.dispose();
        }
    }

    private static Response call(ListingMutationService service, boolean dryRun) {
        return service.undefineRange(
            "ram:1000", "ram:1002",
            true, true,
            true, true, true, true,
            false, dryRun, "");
    }

    private static ListingClearCore.Plan plan(Address start, Address end) {
        AddressSet expanded = new AddressSet(start, end);
        return new ListingClearCore.Plan(
            expanded,
            List.of(new ListingClearCore.CodeUnitSnapshot(
                start, end, ListingClearCore.UnitKind.DATA)),
            List.of(),
            emptyAnnotations(),
            emptyAnnotations(),
            java.util.Map.of(),
            new ListingClearCore.RemovalCounts(0, 1, 0),
            List.of());
    }

    private static ListingClearCore.Plan emptyPlan() {
        return new ListingClearCore.Plan(
            new AddressSet(),
            List.of(),
            List.of(),
            emptyAnnotations(),
            emptyAnnotations(),
            java.util.Map.of(),
            new ListingClearCore.RemovalCounts(0, 0, 0),
            List.of());
    }

    private static ListingClearCore.AnnotationSnapshot emptyAnnotations() {
        return new ListingClearCore.AnnotationSnapshot(
            List.of(), List.of(), List.of(), List.of());
    }

    private static ListingClearCore.ReferenceSnapshot memoryReference(
            SourceType source, Address to) {
        return new ListingClearCore.ReferenceSnapshot(
            address(0x1000),
            to,
            RefType.DATA,
            source,
            0,
            false,
            ListingClearCore.ReferenceKind.MEMORY,
            null,
            0,
            0,
            null);
    }

    private static void addReference(
            ProgramDB program,
            ProgramBuilder builder,
            String from,
            String to,
            int operandIndex,
            SourceType source) {
        program.getReferenceManager().addMemoryReference(
            builder.addr(from),
            builder.addr(to),
            RefType.DATA,
            source,
            operandIndex);
    }

    private static void assertPlanFieldsEqual(
            JsonObject preview, JsonObject commit) {
        for (String field : List.of(
                "requested_range",
                "expanded_range",
                "expanded_ranges",
                "affected_code_units",
                "preserved_annotation_counts",
                "removed_annotation_counts",
                "removed_references_by_source_type",
                "removed_functions",
                "conflicts",
                "source_rules")) {
            assertEquals(field, preview.get(field), commit.get(field));
        }
    }

    private static ListingMutationService liveService(ProgramDB program) {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        return new ListingMutationService(provider, new DirectThreadingStrategy());
    }

    private static void initializeGhidraOrSkip() throws Exception {
        String installDir = System.getProperty("ghidra.test.install.dir");
        assumeTrue(
            "A Ghidra install is required for ProgramBuilder-backed tests",
            installDir != null && !installDir.isBlank()
                && new File(installDir).isDirectory());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDir)), configuration);
        }
    }

    private static Program program(String name, Address start, Address end) {
        Program program = mock(Program.class);
        AddressFactory factory = mock(AddressFactory.class);
        when(factory.getAddress("ram:1000")).thenReturn(address(0x1000));
        when(factory.getAddress("ram:1002")).thenReturn(address(0x1002));
        when(program.getAddressFactory()).thenReturn(factory);
        when(program.getName()).thenReturn(name);
        Memory memory = mock(Memory.class);
        when(memory.contains(any(Address.class), any(Address.class))).thenReturn(true);
        when(memory.contains(any(ghidra.program.model.address.AddressSetView.class)))
            .thenReturn(true);
        when(program.getMemory()).thenReturn(memory);
        return program;
    }

    private static Address address(long offset) {
        return RAM.getAddress(offset);
    }

    private static final class RecordingThreadingStrategy implements ThreadingStrategy {
        int readCalls;
        int writeCalls;
        boolean inWrite;

        @Override
        public <T> T executeRead(Callable<T> action) throws Exception {
            readCalls++;
            return action.call();
        }

        @Override
        public <T> T executeWrite(
                Program program, String txName, Callable<T> action) throws Exception {
            writeCalls++;
            inWrite = true;
            try {
                return action.call();
            }
            finally {
                inWrite = false;
            }
        }

        @Override
        public boolean isHeadless() {
            return true;
        }
    }
}
