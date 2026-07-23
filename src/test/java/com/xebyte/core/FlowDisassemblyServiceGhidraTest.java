package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.headless.HeadlessProgramProvider;
import com.xebyte.headless.DirectThreadingStrategy;

import ghidra.GhidraApplicationLayout;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.disassemble.Disassembler;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.RefType;

public class FlowDisassemblyServiceGhidraTest {

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0);

    private Program program;
    private HeadlessProgramProvider provider;
    private RecordingThreadingStrategy threading;
    private AtomicInteger planCalls;
    private AtomicInteger commitCalls;
    private AtomicInteger analysisCalls;
    private FlowDisassemblyService.FlowPlan plan;

    @Before
    public void setUp() {
        program = mock(Program.class);
        AddressFactory factory = mock(AddressFactory.class);
        when(factory.getAddress("ram:1000")).thenReturn(address(0x1000));
        when(factory.getAddress("ram:1001")).thenReturn(address(0x1001));
        when(factory.getAddress("ram:10ff")).thenReturn(address(0x10ff));
        when(program.getAddressFactory()).thenReturn(factory);
        when(program.getName()).thenReturn("fixture");

        Memory memory = mock(Memory.class);
        when(memory.getLoadedAndInitializedAddressSet())
            .thenReturn(new AddressSet(address(0x1000), address(0x10ff)));
        when(program.getMemory()).thenReturn(memory);

        provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        threading = new RecordingThreadingStrategy();
        planCalls = new AtomicInteger();
        commitCalls = new AtomicInteger();
        analysisCalls = new AtomicInteger();
        plan = oneInstructionPlan();
    }

    @Test
    public void dryRunUsesPlannerWithoutWriteTransactionOrAnalysis() {
        FlowDisassemblyService service = service(
            (ignoredProgram, request) -> {
                planCalls.incrementAndGet();
                return plan;
            },
            (ignoredProgram, ignoredPlan, ignoredClearPlan) -> {
                commitCalls.incrementAndGet();
                throw new AssertionError("dry run called commit");
            },
            (ignoredProgram, ignoredSet) -> {
                analysisCalls.incrementAndGet();
                return new FlowDisassemblyService.AnalysisSubmission(true, null);
            });

        Response response = call(service, true, false);

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertTrue(response.toJson(), response.toJson().contains("\"committed\":false"));
        assertEquals(1, planCalls.get());
        assertEquals(1, threading.readCalls);
        assertEquals(0, threading.writeCalls);
        assertEquals(0, commitCalls.get());
        assertEquals(0, analysisCalls.get());
    }

    @Test
    public void commitReturnsCreatedSetAndDoesNotCreateFunctionsOrAnalysisByDefault() {
        FlowDisassemblyService service = service(
            (ignoredProgram, request) -> plan,
            (ignoredProgram, ignoredPlan, ignoredClearPlan) -> {
                commitCalls.incrementAndGet();
                return new FlowDisassemblyService.CommitResult(
                    plan.plannedNewInstructions(), List.of());
            },
            (ignoredProgram, ignoredSet) -> {
                analysisCalls.incrementAndGet();
                return new FlowDisassemblyService.AnalysisSubmission(true, null);
            });

        Response response = call(service, false, false);

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertTrue(response.toJson(), response.toJson().contains("\"committed\":true"));
        assertTrue(response.toJson(), response.toJson().contains("\"analysis_status\":\"not_requested\""));
        assertEquals(0, threading.readCalls);
        assertEquals(1, threading.writeCalls);
        assertEquals(1, commitCalls.get());
        assertEquals(0, analysisCalls.get());
    }

    @Test
    public void analysisQueueFailureDoesNotTurnCommittedMutationIntoError() {
        FlowDisassemblyService service = service(
            (ignoredProgram, request) -> plan,
            (ignoredProgram, ignoredPlan, ignoredClearPlan) ->
                new FlowDisassemblyService.CommitResult(
                plan.plannedNewInstructions(), List.of()),
            (ignoredProgram, ignoredSet) -> {
                analysisCalls.incrementAndGet();
                throw new IllegalStateException("scheduler unavailable");
            });

        Response response = call(service, false, true);

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertTrue(response.toJson(), response.toJson().contains("\"committed\":true"));
        assertTrue(response.toJson(), response.toJson().contains("\"analysis_status\":\"queue_failed\""));
        assertTrue(response.toJson(), response.toJson().contains("scheduler unavailable"));
        assertEquals(1, analysisCalls.get());
    }

    @Test
    public void queuedAnalysisReturnsRequestDescriptor() {
        FlowDisassemblyService service = service(
            (ignoredProgram, request) -> plan,
            (ignoredProgram, ignoredPlan, ignoredClearPlan) ->
                new FlowDisassemblyService.CommitResult(
                    plan.plannedNewInstructions(), List.of()),
            (ignoredProgram, ignoredSet) -> {
                analysisCalls.incrementAndGet();
                return new FlowDisassemblyService.AnalysisSubmission(
                    true, "analysis-request-42");
            });

        Response response = call(service, false, true);

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertTrue(response.toJson(),
            response.toJson().contains("\"analysis_status\":\"queued\""));
        assertTrue(response.toJson(),
            response.toJson().contains("\"request_identity\":\"analysis-request-42\""));
        assertTrue(response.toJson(),
            response.toJson().contains("\"analysis_request\""));
        assertEquals(1, analysisCalls.get());
    }

    @Test
    public void rejectsSeedOutsideRestrictionBeforePlanning() {
        FlowDisassemblyService service = service(
            (ignoredProgram, request) -> {
                planCalls.incrementAndGet();
                return plan;
            },
            (ignoredProgram, ignoredPlan, ignoredClearPlan) ->
                new FlowDisassemblyService.CommitResult(new AddressSet(), List.of()),
            (ignoredProgram, ignoredSet) ->
                new FlowDisassemblyService.AnalysisSubmission(true, null));

        Response response = service.disassembleFlow(
            "[\"ram:10ff\"]",
            "ram:1000",
            "ram:1001",
            true,
            true,
            true,
            false,
            false,
            100,
            "");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains("inside restriction"));
        assertEquals(0, planCalls.get());
    }

    @Test
    public void rejectsNonStringSeedBeforePlanning() {
        FlowDisassemblyService service = service(
            (ignoredProgram, request) -> {
                planCalls.incrementAndGet();
                return plan;
            },
            (ignoredProgram, ignoredPlan, ignoredClearPlan) ->
                new FlowDisassemblyService.CommitResult(new AddressSet(), List.of()),
            (ignoredProgram, ignoredSet) ->
                new FlowDisassemblyService.AnalysisSubmission(true, null));

        Response response = service.disassembleFlow(
            "[4096]",
            "ram:1000",
            "ram:1001",
            true,
            true,
            true,
            false,
            false,
            100,
            "");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains("address strings"));
        assertEquals(0, planCalls.get());
    }

    @Test
    public void blockedCommitStillReportsRequestedDryRunFalse() {
        FlowDisassemblyService.FlowPlan blockedPlan =
            new FlowDisassemblyService.FlowPlan(
                plan.normalizedSeeds(),
                plan.restriction(),
                plan.instructions(),
                plan.plannedNewInstructions(),
                plan.existingInstructions(),
                plan.directCallTargets(),
                plan.directBranchTargets(),
                plan.unresolvedFlows(),
                List.of(new FlowDisassemblyService.Conflict(
                    address(0x1000),
                    null,
                    FlowDisassemblyService.EdgeKind.SEED,
                    "defined_data",
                    address(0x1000),
                    address(0x1000))),
                plan.stopReasons(),
                plan.clearedData(),
                plan.functions(),
                plan.instructionCapReached());
        FlowDisassemblyService service = service(
            (ignoredProgram, request) -> blockedPlan,
            (ignoredProgram, ignoredPlan, ignoredClearPlan) -> {
                throw new AssertionError("blocked plan called commit");
            },
            (ignoredProgram, ignoredSet) ->
                new FlowDisassemblyService.AnalysisSubmission(true, null));

        Response response = call(service, false, false);

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertTrue(response.toJson(), response.toJson().contains("\"dry_run\":false"));
        assertTrue(response.toJson(), response.toJson().contains("\"commit_status\":\"blocked\""));
        assertEquals(0, threading.readCalls);
        assertEquals(1, threading.writeCalls);
    }

    @Test
    public void commitUsesOneFlowFollowingInvocationFromMinimalUndefinedFrontier() {
        Address existing = address(0x1000);
        Address crossedRoot = address(0x1001);
        Address continued = address(0x1002);
        Address undefinedSeed = address(0x1010);
        FlowDisassemblyService.FlowPlan frontierPlan =
            new FlowDisassemblyService.FlowPlan(
                List.of(existing, undefinedSeed),
                new AddressSet(existing, address(0x10ff)),
                List.of(
                    new FlowDisassemblyService.InstructionRecord(
                        existing, 1, "existing", true, crossedRoot,
                        List.of(), RefType.FLOW),
                    new FlowDisassemblyService.InstructionRecord(
                        crossedRoot, 1, "crossed", false, continued,
                        List.of(), RefType.FLOW),
                    new FlowDisassemblyService.InstructionRecord(
                        continued, 1, "continued", false, null,
                        List.of(), RefType.TERMINATOR),
                    new FlowDisassemblyService.InstructionRecord(
                        undefinedSeed, 1, "seed", false, null,
                        List.of(), RefType.TERMINATOR)),
                new AddressSet(crossedRoot, continued)
                    .union(new AddressSet(undefinedSeed, undefinedSeed)),
                new AddressSet(existing, existing),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                false);
        RecordingStockDisassembler stock = new RecordingStockDisassembler();
        FlowDisassemblyService service = new FlowDisassemblyService(
            provider,
            threading,
            (ignoredProgram, request) -> frontierPlan,
            stock,
            (ignoredProgram, ignoredSet) ->
                new FlowDisassemblyService.AnalysisSubmission(true, null));

        Response response = call(service, false, false);

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertEquals(1, stock.calls);
        assertTrue(stock.starts.hasSameAddresses(
            new AddressSet(crossedRoot, crossedRoot)
                .union(new AddressSet(undefinedSeed, undefinedSeed))));
        assertTrue(stock.restriction.hasSameAddresses(
            frontierPlan.plannedNewInstructions()));
        assertTrue(stock.followFlow);
    }

    @Test
    public void live6502DryRunAndCommitHaveEqualNewInstructionSet() throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("flow-6502", "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x1000", 0x200);
            builder.setBytes(
                "0x1000",
                "20 10 10 d0 03 4c 0d 10 6c 00 20 ea ea 40 00 02 4c 00 11 60");
            builder.disassemble("0x1010", 3);

            HeadlessProgramProvider liveProvider = new HeadlessProgramProvider();
            liveProvider.setCurrentProgram(liveProgram);
            FlowDisassemblyService service = new FlowDisassemblyService(
                liveProvider, new DirectThreadingStrategy());

            long modificationBefore = liveProgram.getModificationNumber();
            int functionCountBefore =
                liveProgram.getFunctionManager().getFunctionCount();
            int symbolCountBefore = liveProgram.getSymbolTable().getNumSymbols();
            int referenceSourcesBefore =
                liveProgram.getReferenceManager().getReferenceSourceCount();
            int referenceDestinationsBefore =
                liveProgram.getReferenceManager().getReferenceDestinationCount();
            AtomicInteger events = new AtomicInteger();
            boolean hadAnalysisManager =
                AutoAnalysisManager.hasAutoAnalysisManager(liveProgram);
            boolean analyzingBefore = hadAnalysisManager &&
                AutoAnalysisManager.getAnalysisManager(liveProgram).isAnalyzing();
            liveProgram.flushEvents();
            liveProgram.addListener(event -> events.addAndGet(event.numRecords()));

            Response preview = service.disassembleFlow(
                "[\"0x1000\",\"0x100e\",\"0x100f\",\"0x1013\"]",
                "0x1000",
                "0x1013",
                true,
                true,
                true,
                false,
                false,
                100,
                "");
            liveProgram.flushEvents();

            assertTrue(preview.toJson(), preview instanceof Response.Ok);
            assertEquals(modificationBefore, liveProgram.getModificationNumber());
            assertEquals(0, events.get());
            assertEquals(1, liveProgram.getListing().getNumInstructions());
            assertEquals(functionCountBefore,
                liveProgram.getFunctionManager().getFunctionCount());
            assertEquals(symbolCountBefore,
                liveProgram.getSymbolTable().getNumSymbols());
            assertEquals(referenceSourcesBefore,
                liveProgram.getReferenceManager().getReferenceSourceCount());
            assertEquals(referenceDestinationsBefore,
                liveProgram.getReferenceManager().getReferenceDestinationCount());
            assertEquals(hadAnalysisManager,
                AutoAnalysisManager.hasAutoAnalysisManager(liveProgram));
            if (hadAnalysisManager) {
                assertEquals(analyzingBefore,
                    AutoAnalysisManager.getAnalysisManager(liveProgram).isAnalyzing());
            }
            JsonObject previewJson =
                JsonParser.parseString(preview.toJson()).getAsJsonObject();
            assertTrue(preview.toJson(), preview.toJson().contains("\"text\":\"RTS\""));
            assertTrue(preview.toJson(), preview.toJson().contains("\"text\":\"RTI\""));
            assertTrue(preview.toJson(), preview.toJson().contains("\"text\":\"BRK\""));
            assertTrue(preview.toJson(), preview.toJson().contains("\"decode_failure\""));
            assertTrue(preview.toJson(), preview.toJson().contains("\"COMPUTED_JUMP\""));

            Response commit = service.disassembleFlow(
                "[\"0x1000\",\"0x100e\",\"0x100f\",\"0x1013\"]",
                "0x1000",
                "0x1013",
                false,
                true,
                true,
                false,
                false,
                100,
                "");
            assertTrue(commit.toJson(), commit instanceof Response.Ok);
            JsonObject commitJson =
                JsonParser.parseString(commit.toJson()).getAsJsonObject();
            assertEquals(
                previewJson.get("candidate_instruction_ranges"),
                commitJson.get("created_instruction_ranges"));
            assertEquals(0, liveProgram.getFunctionManager().getFunctionCount());
            assertTrue("unreachable byte was disassembled",
                liveProgram.getListing().getInstructionAt(builder.addr("0x100b")) == null);
            assertTrue(commit.toJson(), commit.toJson().contains("\"COMPUTED_JUMP\""));
            assertTrue(commit.toJson(), commit.toJson().contains("\"restricted_boundary\""));
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void live6502DefinedDataIsBarrierOrAnnotationPreservingClear()
            throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("flow-data-6502", "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x1000", 0x20);
            builder.setBytes("0x1000", "4c 08 10 ea ea ea ea ea 60");
            builder.applyDataType("0x1008", ByteDataType.dataType);
            builder.createLabel("0x1008", "preserved_data_label");
            builder.createMemoryReference(
                "0x1008", "0x1010", RefType.DATA,
                ghidra.program.model.symbol.SourceType.USER_DEFINED);

            HeadlessProgramProvider liveProvider = new HeadlessProgramProvider();
            liveProvider.setCurrentProgram(liveProgram);
            FlowDisassemblyService service = new FlowDisassemblyService(
                liveProvider, new DirectThreadingStrategy());

            Response blocked = service.disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1010",
                true,
                true,
                true,
                false,
                false,
                100,
                "");
            assertTrue(blocked.toJson(), blocked instanceof Response.Ok);
            assertTrue(blocked.toJson(), blocked.toJson().contains("\"defined_data\""));
            assertTrue(liveProgram.getListing().getDefinedDataAt(builder.addr("0x1008")) != null);

            Response preview = service.disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1010",
                true,
                true,
                false,
                false,
                false,
                100,
                "");
            assertTrue(preview.toJson(), preview instanceof Response.Ok);
            assertTrue(preview.toJson(), preview.toJson().contains("\"cleared_data\""));
            assertTrue(liveProgram.getListing().getDefinedDataAt(builder.addr("0x1008")) != null);

            Response commit = service.disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1010",
                false,
                true,
                false,
                false,
                false,
                100,
                "");
            assertTrue(commit.toJson(), commit instanceof Response.Ok);
            assertTrue(liveProgram.getListing().getDefinedDataAt(builder.addr("0x1008")) == null);
            assertTrue(liveProgram.getListing().getInstructionAt(builder.addr("0x1008")) != null);
            assertTrue(liveProgram.getSymbolTable()
                .getSymbolsAsIterator(builder.addr("0x1008")).hasNext());
            assertTrue(java.util.Arrays.stream(liveProgram.getReferenceManager()
                .getReferencesFrom(builder.addr("0x1008")))
                .anyMatch(reference -> reference.getToAddress().equals(builder.addr("0x1010"))));
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void liveExistingInstructionCanCrossIntoUndefinedCommitFrontier()
            throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("flow-existing-frontier-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x1000", 0x20);
            builder.setBytes("0x1000", "4c 05 10 ea ea a9 01 60");
            builder.disassemble("0x1000", 3);
            assertTrue(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x1000")) != null);
            assertTrue(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x1005")) == null);

            FlowDisassemblyService service = liveService(liveProgram);
            Response preview = service.disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1007",
                true,
                true,
                true,
                false,
                false,
                100,
                "");
            Response commit = service.disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1007",
                false,
                true,
                true,
                false,
                false,
                100,
                "");

            assertTrue(preview.toJson(), preview instanceof Response.Ok);
            assertTrue(commit.toJson(), commit instanceof Response.Ok);
            JsonObject previewJson =
                JsonParser.parseString(preview.toJson()).getAsJsonObject();
            JsonObject commitJson =
                JsonParser.parseString(commit.toJson()).getAsJsonObject();
            assertEquals(
                previewJson.get("candidate_instruction_ranges"),
                commitJson.get("created_instruction_ranges"));
            assertTrue(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x1005")) != null);
            assertTrue(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x1007")) != null);
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void liveMultiByteDataClearsOnceAndPreservesInteriorAnnotations()
            throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("flow-array-data-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x1000", 0x20);
            builder.setBytes("0x1000", "ea ea 60");
            builder.applyDataType(
                "0x1000", new ArrayDataType(ByteDataType.dataType, 3, 1));
            builder.createLabel("0x1001", "interior_data_label");
            builder.createComment(
                "0x1001", "interior data comment", CommentType.EOL);
            builder.createMemoryReference(
                "0x1001", "0x1010", RefType.DATA,
                ghidra.program.model.symbol.SourceType.USER_DEFINED);

            FlowDisassemblyService service = liveService(liveProgram);
            Response preview = service.disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1002",
                true,
                true,
                false,
                false,
                false,
                100,
                "");

            assertTrue(preview.toJson(), preview instanceof Response.Ok);
            JsonObject previewJson =
                JsonParser.parseString(preview.toJson()).getAsJsonObject();
            assertEquals(1, previewJson.getAsJsonArray("cleared_data").size());
            JsonObject cleared =
                previewJson.getAsJsonArray("cleared_data").get(0).getAsJsonObject();
            assertEquals("1000", cleared.get("start").getAsString());
            assertEquals("1002", cleared.get("end").getAsString());
            assertTrue(liveProgram.getListing()
                .getDefinedDataAt(builder.addr("0x1000")) != null);

            Response commit = service.disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1002",
                false,
                true,
                false,
                false,
                false,
                100,
                "");

            assertTrue(commit.toJson(), commit instanceof Response.Ok);
            assertTrue(liveProgram.getListing()
                .getDefinedDataAt(builder.addr("0x1000")) == null);
            assertTrue(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x1000")) != null);
            assertTrue(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x1001")) != null);
            assertTrue(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x1002")) != null);
            assertTrue(liveProgram.getSymbolTable()
                .getSymbolsAsIterator(builder.addr("0x1001")).hasNext());
            assertEquals(
                "interior data comment",
                liveProgram.getListing().getComment(
                    CommentType.EOL, builder.addr("0x1001")));
            assertTrue(java.util.Arrays.stream(liveProgram.getReferenceManager()
                .getReferencesFrom(builder.addr("0x1001")))
                .anyMatch(reference ->
                    reference.getToAddress().equals(builder.addr("0x1010"))));
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void liveDecodeFailureDoesNotClearDefinedData() throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("flow-decode-failure-data-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x1000", 1);
            builder.setBytes("0x1000", "02");
            builder.applyDataType("0x1000", ByteDataType.dataType);

            Response response = liveService(liveProgram).disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1000",
                false,
                true,
                false,
                false,
                false,
                100,
                "");

            assertTrue(response.toJson(), response instanceof Response.Ok);
            assertTrue(response.toJson(), response.toJson().contains("\"decode_failure\""));
            assertTrue(liveProgram.getListing()
                .getDefinedDataAt(builder.addr("0x1000")) != null);
            assertEquals(0, liveProgram.getListing().getNumInstructions());
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void liveBoundaryCrossingDoesNotClearDefinedData() throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("flow-boundary-data-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x1000", 3);
            builder.setBytes("0x1000", "4c 00 10");
            builder.applyDataType("0x1000", ByteDataType.dataType);

            Response response = liveService(liveProgram).disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1001",
                false,
                true,
                false,
                false,
                false,
                100,
                "");

            assertTrue(response.toJson(), response instanceof Response.Ok);
            assertTrue(response.toJson(),
                response.toJson().contains("\"restricted_boundary\""));
            assertTrue(liveProgram.getListing()
                .getDefinedDataAt(builder.addr("0x1000")) != null);
            assertEquals(0, liveProgram.getListing().getNumInstructions());
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void liveFailedDisassemblyRollsBackDataClearAndAnnotations()
            throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("flow-rollback-data-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x1000", 2);
            builder.setBytes("0x1000", "ea 60");
            builder.applyDataType(
                "0x1000", new ArrayDataType(ByteDataType.dataType, 2, 1));
            builder.createLabel("0x1001", "rollback_label");
            builder.createComment("0x1001", "rollback comment", CommentType.EOL);

            HeadlessProgramProvider liveProvider = new HeadlessProgramProvider();
            liveProvider.setCurrentProgram(liveProgram);
            FlowDisassemblyService planningService =
                new FlowDisassemblyService(
                    liveProvider, new DirectThreadingStrategy());
            FlowDisassemblyService service = new FlowDisassemblyService(
                liveProvider,
                new DirectThreadingStrategy(),
                planningService::plan,
                (ignoredProgram, ignoredStarts, ignoredRestriction, ignoredFollowFlow) -> {
                    throw new IllegalStateException("injected disassembler failure");
                },
                (ignoredProgram, ignoredSet) ->
                    new FlowDisassemblyService.AnalysisSubmission(true, null));

            Response response = service.disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1001",
                false,
                true,
                false,
                false,
                false,
                100,
                "");

            assertTrue(response.toJson(), response instanceof Response.Err);
            assertTrue(response.toJson(),
                response.toJson().contains("injected disassembler failure"));
            assertTrue(liveProgram.getListing()
                .getDefinedDataAt(builder.addr("0x1000")) != null);
            assertEquals(0, liveProgram.getListing().getNumInstructions());
            assertTrue(liveProgram.getSymbolTable()
                .getSymbolsAsIterator(builder.addr("0x1001")).hasNext());
            assertEquals(
                "rollback comment",
                liveProgram.getListing().getComment(
                    CommentType.EOL, builder.addr("0x1001")));
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void liveFunctionCreationSeparatesSeedAndDirectCallTarget()
            throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("flow-functions-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x1000", 0x20);
            builder.setBytes("0x1000", "20 05 10 60 ea 60");

            Response response = liveService(liveProgram).disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1005",
                false,
                true,
                true,
                true,
                false,
                100,
                "");

            assertTrue(response.toJson(), response instanceof Response.Ok);
            assertTrue(response.toJson(),
                response.toJson().contains("\"commit_status\":\"committed\""));
            assertTrue(liveProgram.getFunctionManager()
                .getFunctionAt(builder.addr("0x1000")) != null);
            assertTrue(liveProgram.getFunctionManager()
                .getFunctionAt(builder.addr("0x1005")) != null);
            assertTrue(liveProgram.getFunctionManager()
                .getFunctionAt(builder.addr("0x1000")).getBody()
                .contains(builder.addr("0x1003")));
            assertTrue(!liveProgram.getFunctionManager()
                .getFunctionAt(builder.addr("0x1000")).getBody()
                .contains(builder.addr("0x1005")));
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void liveFunctionPreflightBlocksBodyOverlap() throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("flow-function-overlap-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x1000", 3);
            builder.setBytes("0x1000", "ea ea 60");
            builder.disassemble("0x1002", 1);
            builder.createFunction("0x1002");

            Response response = liveService(liveProgram).disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1002",
                false,
                true,
                true,
                true,
                false,
                100,
                "");

            assertTrue(response.toJson(), response instanceof Response.Ok);
            assertTrue(response.toJson(),
                response.toJson().contains("\"commit_status\":\"blocked\""));
            assertTrue(response.toJson(),
                response.toJson().contains(
                    "\"function_body_overlaps_existing_function\""));
            assertTrue(liveProgram.getFunctionManager()
                .getFunctionAt(builder.addr("0x1000")) == null);
            assertTrue(liveProgram.getFunctionManager()
                .getFunctionAt(builder.addr("0x1002")) != null);
            assertTrue(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x1000")) == null);
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void liveNonDryRunReplansInsideWriteAfterInterleaving()
            throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("flow-interleaving-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x1000", 3);
            builder.setBytes("0x1000", "4c 00 10");
            builder.applyDataType("0x1001", ByteDataType.dataType);

            HeadlessProgramProvider liveProvider = new HeadlessProgramProvider();
            liveProvider.setCurrentProgram(liveProgram);
            InterleavingThreadingStrategy interleaving =
                new InterleavingThreadingStrategy(() -> {
                    builder.withTransaction(() ->
                        liveProgram.getListing().clearCodeUnits(
                            builder.addr("0x1001"), builder.addr("0x1001"), false));
                    builder.disassemble("0x1000", 3);
                    builder.createFunction("0x1000");
                    builder.createLabel("0x1001", "interleaved_label");
                    builder.createComment(
                        "0x1001", "interleaved comment", CommentType.EOL);
                });
            FlowDisassemblyService service =
                new FlowDisassemblyService(liveProvider, interleaving);

            Response response = service.disassembleFlow(
                "[\"0x1001\"]",
                "0x1000",
                "0x1002",
                false,
                true,
                false,
                false,
                false,
                100,
                "");

            assertTrue(response.toJson(), response instanceof Response.Ok);
            assertTrue(response.toJson(),
                response.toJson().contains("\"commit_status\":\"blocked\""));
            assertTrue(response.toJson(),
                response.toJson().contains("\"middle_of_code_unit\""));
            assertTrue(response.toJson(),
                response.toJson().contains("\"committed\":false"));
            assertEquals(0, interleaving.readCalls);
            assertEquals(1, interleaving.writeCalls);
            assertTrue(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x1000")) != null);
            assertTrue(liveProgram.getFunctionManager()
                .getFunctionAt(builder.addr("0x1000")) != null);
            assertTrue(liveProgram.getSymbolTable()
                .getSymbolsAsIterator(builder.addr("0x1001")).hasNext());
            assertEquals(
                "interleaved comment",
                liveProgram.getListing().getComment(
                    CommentType.EOL, builder.addr("0x1001")));
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void liveCommitIgnoresExecuteRestrictionWithoutDiagnosticBookmarks()
            throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("flow-non-executable-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x1000", 2);
            builder.setBytes("0x1000", "ea 60");
            builder.withTransaction(() -> {
                liveProgram.getMemory().getBlock(builder.addr("0x1000"))
                    .setExecute(false);
                liveProgram.getOptions(Program.DISASSEMBLER_PROPERTIES).setBoolean(
                    Disassembler.RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY,
                    true);
            });
            assertTrue(Disassembler.isRestrictToExecuteMemory(liveProgram));

            FlowDisassemblyService service = liveService(liveProgram);
            Response preview = service.disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1001",
                true,
                true,
                true,
                false,
                false,
                100,
                "");
            Response commit = service.disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1001",
                false,
                true,
                true,
                false,
                false,
                100,
                "");

            assertTrue(preview.toJson(), preview instanceof Response.Ok);
            assertTrue(commit.toJson(), commit instanceof Response.Ok);
            JsonObject previewJson =
                JsonParser.parseString(preview.toJson()).getAsJsonObject();
            JsonObject commitJson =
                JsonParser.parseString(commit.toJson()).getAsJsonObject();
            assertEquals(
                previewJson.get("candidate_instruction_ranges"),
                commitJson.get("created_instruction_ranges"));
            assertTrue(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x1000")) != null);
            assertTrue(liveProgram.getListing()
                .getInstructionAt(builder.addr("0x1001")) != null);
            assertEquals(0, liveProgram.getBookmarkManager().getBookmarkCount());
        }
        finally {
            builder.dispose();
        }
    }

    @Test
    public void liveNonDryRequestParsingObservesInterleavedUninitializedSeed()
            throws Exception {
        initializeGhidraOrSkip();
        ProgramBuilder builder =
            new ProgramBuilder("flow-uninitialized-interleaving-6502",
                "6502:LE:16:default", "default", this);
        try {
            ProgramDB liveProgram = builder.getProgram();
            builder.createMemory(".ram", "0x1000", 2);
            builder.setBytes("0x1000", "ea 60");

            HeadlessProgramProvider liveProvider = new HeadlessProgramProvider();
            liveProvider.setCurrentProgram(liveProgram);
            InterleavingThreadingStrategy interleaving =
                new InterleavingThreadingStrategy(() ->
                    builder.withTransaction(() -> {
                        try {
                            liveProgram.getMemory().convertToUninitialized(
                                liveProgram.getMemory().getBlock(
                                    builder.addr("0x1000")));
                        }
                        catch (Exception e) {
                            throw new AssertionError(e);
                        }
                    }));
            FlowDisassemblyService service =
                new FlowDisassemblyService(liveProvider, interleaving);

            Response response = service.disassembleFlow(
                "[\"0x1000\"]",
                "0x1000",
                "0x1001",
                false,
                true,
                true,
                false,
                false,
                100,
                "");

            assertTrue(response.toJson(), response instanceof Response.Err);
            assertTrue(response.toJson(),
                response.toJson().contains(
                    "every seed must be in initialized memory"));
            assertEquals(0, interleaving.readCalls);
            assertEquals(1, interleaving.writeCalls);
            assertTrue(!liveProgram.getMemory()
                .getBlock(builder.addr("0x1000")).isInitialized());
            assertEquals(0, liveProgram.getListing().getNumInstructions());
        }
        finally {
            builder.dispose();
        }
    }

    private static FlowDisassemblyService liveService(ProgramDB liveProgram) {
        HeadlessProgramProvider liveProvider = new HeadlessProgramProvider();
        liveProvider.setCurrentProgram(liveProgram);
        return new FlowDisassemblyService(
            liveProvider, new DirectThreadingStrategy());
    }

    private FlowDisassemblyService service(
            FlowDisassemblyService.PlanningEngine planning,
            FlowDisassemblyService.MutationEngine mutation,
            FlowDisassemblyService.AnalysisQueue analysis) {
        return new FlowDisassemblyService(
            provider, threading, planning, mutation, analysis);
    }

    private Response call(
            FlowDisassemblyService service,
            boolean dryRun,
            boolean enableAnalysis) {
        return service.disassembleFlow(
            "[\"ram:1000\"]",
            "ram:1000",
            "ram:10ff",
            dryRun,
            true,
            true,
            false,
            enableAnalysis,
            100,
            "");
    }

    private static FlowDisassemblyService.FlowPlan oneInstructionPlan() {
        Address start = address(0x1000);
        FlowDisassemblyService.InstructionRecord instruction =
            new FlowDisassemblyService.InstructionRecord(
                start, 1, "rts", false, null, List.of(), RefType.TERMINATOR);
        return new FlowDisassemblyService.FlowPlan(
            List.of(start),
            new AddressSet(start, address(0x10ff)),
            List.of(instruction),
            new AddressSet(start, start),
            new AddressSet(),
            List.of(),
            List.of(),
            List.of(),
            List.of(),
            List.of(),
            List.of(),
            List.of(),
            false);
    }

    private static Address address(long offset) {
        return RAM.getAddress(offset);
    }

    private static void initializeGhidraOrSkip() throws Exception {
        String installDir = System.getProperty("ghidra.test.install.dir");
        assumeTrue(
            "A Ghidra install is required for ProgramBuilder-backed tests",
            installDir != null && !installDir.isBlank() &&
                new File(installDir).isDirectory());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDir)), configuration);
        }
    }

    private static final class RecordingThreadingStrategy implements ThreadingStrategy {
        int readCalls;
        int writeCalls;

        @Override
        public <T> T executeRead(Callable<T> action) throws Exception {
            readCalls++;
            return action.call();
        }

        @Override
        public <T> T executeWrite(
                Program ignoredProgram,
                String ignoredName,
                Callable<T> action) throws Exception {
            writeCalls++;
            return action.call();
        }

        @Override
        public boolean isHeadless() {
            return true;
        }
    }

    private static final class InterleavingThreadingStrategy
            implements ThreadingStrategy {
        private final Runnable beforeWrite;
        private final DirectThreadingStrategy delegate =
            new DirectThreadingStrategy();
        int readCalls;
        int writeCalls;

        InterleavingThreadingStrategy(Runnable beforeWrite) {
            this.beforeWrite = beforeWrite;
        }

        @Override
        public <T> T executeRead(Callable<T> action) throws Exception {
            readCalls++;
            return action.call();
        }

        @Override
        public <T> T executeWrite(
                Program targetProgram,
                String transactionName,
                Callable<T> action) throws Exception {
            writeCalls++;
            beforeWrite.run();
            return delegate.executeWrite(targetProgram, transactionName, action);
        }

        @Override
        public boolean isHeadless() {
            return true;
        }
    }

    private static final class RecordingStockDisassembler
            implements FlowDisassemblyService.StockDisassembler {
        int calls;
        AddressSet starts = new AddressSet();
        AddressSet restriction = new AddressSet();
        boolean followFlow;

        @Override
        public AddressSet disassemble(
                Program ignoredProgram,
                AddressSetView requestedStarts,
                AddressSetView requestedRestriction,
                boolean requestedFollowFlow) {
            calls++;
            starts = new AddressSet(requestedStarts);
            restriction = new AddressSet(requestedRestriction);
            followFlow = requestedFollowFlow;
            return new AddressSet(requestedRestriction);
        }
    }
}
