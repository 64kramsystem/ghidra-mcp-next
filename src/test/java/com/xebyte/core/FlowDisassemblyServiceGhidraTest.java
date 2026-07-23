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
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
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
        assertEquals(0, threading.writeCalls);
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
            liveProgram.flushEvents();
            liveProgram.addListener(event -> events.addAndGet(event.numRecords()));

            Response preview = service.disassembleFlow(
                "[\"0x1000\"]",
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
            JsonObject previewJson =
                JsonParser.parseString(preview.toJson()).getAsJsonObject();

            Response commit = service.disassembleFlow(
                "[\"0x1000\"]",
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
            assertTrue(commit.toJson(), commit.toJson().contains("\"computed_jump\""));
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
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue(
            "GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDir)), configuration);
        }
    }

    private static final class RecordingThreadingStrategy implements ThreadingStrategy {
        int writeCalls;

        @Override
        public <T> T executeRead(Callable<T> action) throws Exception {
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
}
