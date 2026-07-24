package com.xebyte.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.math.BigInteger;
import java.util.List;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

public class AddressEmulationServiceGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;

    @BeforeClass
    public static void initializeGhidraOrSkip() throws Exception {
        String installDir = System.getProperty("ghidra.test.install.dir");
        assumeTrue("ghidra.test.install.dir is required",
            installDir != null && !installDir.isBlank());
        System.setProperty(
            "class.searcher.search.all.jars", Boolean.TRUE.toString());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration =
                new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDir)),
                configuration);
        }
        ClassSearcher.search(TaskMonitor.DUMMY);
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder(
            "address-emulation-6502",
            "6502:LE:16:default",
            "default",
            this);
        program = builder.getProgram();
        builder.createMemory("code", "1000", 0x1000);
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void functionFree6502RoutineHonorsInitialStateAndRecordsSemanticAccesses()
            throws Exception {
        setBytes("1000", "a9428510a510eae860");
        byte[] before = read("1000", 9);
        long instructionsBefore =
            program.getListing().getNumCodeUnits();
        assertNull(program.getFunctionManager().getFunctionAt(address("1000")));

        AddressEmulationEngine.Result result = execute(
            "1000",
            "{\"A\":\"0x11\",\"X\":0,\"Y\":2,\"P\":\"0x20\",\"SP\":\"0x01fd\"}",
            "[]",
            "[]",
            "[]",
            null,
            "stop",
            100,
            100,
            100);

        assertEquals(result.error(), "terminal_instruction", result.stopReason());
        assertEquals(5, result.steps());
        assertEquals(address("1008"), result.finalPc());
        assertEquals(BigInteger.valueOf(0x42), result.finalRegisters().get("A"));
        assertEquals(BigInteger.ONE, result.finalRegisters().get("X"));
        assertEquals(BigInteger.valueOf(2), result.finalRegisters().get("Y"));
        assertEquals(BigInteger.valueOf(0x01fd), result.finalRegisters().get("SP"));

        assertEquals(result.error(), 2, result.accesses().size());
        assertEquals(AddressEmulationEngine.AccessKind.WRITE,
            result.accesses().get(0).kind());
        assertEquals(address("0010"), result.accesses().get(0).start());
        assertEquals(2, result.accesses().get(0).step());
        assertArrayEquals(bytes(0x42), result.accesses().get(0).bytes());
        assertEquals(AddressEmulationEngine.AccessKind.READ,
            result.accesses().get(1).kind());
        assertEquals(address("0010"), result.accesses().get(1).start());
        assertEquals(3, result.accesses().get(1).step());

        assertEquals(6, result.trace().size());
        AddressEmulationEngine.TraceRecord terminal =
            result.trace().get(result.trace().size() - 1);
        assertEquals(address("1008"), terminal.address());
        assertFalse(terminal.executed());
        assertTrue(terminal.instruction().startsWith("RTS"));
        assertFalse(result.traceTruncated());
        assertFalse(result.accessLogTruncated());
        assertArrayEquals(before, read("1000", 9));
        assertEquals(instructionsBefore, program.getListing().getNumCodeUnits());
        assertNull(program.getFunctionManager().getFunctionAt(address("1000")));
    }

    @Test
    public void publicEndpointSerializesBoundedFunctionFreeEvidence()
            throws Exception {
        setBytes("1000", "a942851060");
        HeadlessProgramProvider provider =
            new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        EmulationService service = new EmulationService(
            provider, new DirectThreadingStrategy());

        Response response = service.emulateAddress(
            "1000",
            "{\"A\":0,\"SP\":\"0x01fd\"}",
            "[]",
            "[]",
            "[{\"start\":\"0010\",\"end\":\"0010\"}]",
            "",
            "stop",
            20,
            20,
            20,
            "");
        JsonObject json = JsonParser.parseString(
            response.toJson()).getAsJsonObject();

        assertEquals("terminal_instruction",
            json.get("stop_reason").getAsString());
        assertEquals(2, json.get("steps").getAsInt());
        assertEquals("0x42",
            json.getAsJsonObject("final_registers")
                .get("A").getAsString());
        assertEquals(1,
            json.getAsJsonArray("access_log").size());
        assertEquals("write",
            json.getAsJsonArray("access_log")
                .get(0).getAsJsonObject()
                .get("kind").getAsString());
        assertEquals("42",
            json.getAsJsonArray("captured_memory")
                .get(0).getAsJsonObject()
                .get("bytes").getAsString());
        assertTrue(json.get("unresolved_control_flow").isJsonNull());
        assertFalse(json.get("trace_truncated").getAsBoolean());
        assertFalse(
            json.get("access_log_truncated").getAsBoolean());
    }

    @Test
    public void functionAdapterUsesSharedEngineAndPreservesEssentials()
            throws Exception {
        setBytes("1000", "a94260");
        builder.disassemble("1000", 3);
        builder.createFunction("1000");
        HeadlessProgramProvider provider =
            new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        EmulationService service = new EmulationService(
            provider, new DirectThreadingStrategy());

        JsonObject json = JsonParser.parseString(
            service.emulateFunction(
                "1000",
                "{\"SP\":\"0x01fd\"}",
                "",
                20,
                "A,SP",
                "").toJson()).getAsJsonObject();

        assertTrue(json.get("success").getAsBoolean());
        assertTrue(json.get("hit_return").getAsBoolean());
        assertEquals("return",
            json.get("stop_reason").getAsString());
        assertEquals("0x42",
            json.getAsJsonObject("registers")
                .get("A").getAsString());
    }

    @Test
    public void returnAddressInjectionUsesPageOneAndExecutesRts()
            throws Exception {
        setBytes("1100", "60");

        AddressEmulationEngine.Result result = execute(
            "1100",
            "{\"SP\":\"0x01fd\"}",
            "[]",
            "[\"1200\"]",
            "[{\"start\":\"01fe\",\"end\":\"01ff\"}]",
            "1200",
            "execute",
            10,
            10,
            20);

        assertEquals(result.error(), "stop_address", result.stopReason());
        assertEquals(1, result.steps());
        assertEquals(address("1200"), result.finalPc());
        assertNotNull(result.returnInjection());
        assertEquals(address("01fe"), result.returnInjection().lowAddress());
        assertEquals(address("01ff"), result.returnInjection().highAddress());
        assertEquals(0xff, result.returnInjection().lowByte() & 0xff);
        assertEquals(0x11, result.returnInjection().highByte() & 0xff);
        assertEquals(BigInteger.valueOf(0x01ff), result.finalRegisters().get("SP"));
        assertEquals(2, result.accesses().size());
        assertArrayEquals(
            bytes(0xff, 0x11),
            result.capturedMemory().get(0).bytes());
    }

    @Test
    public void missingIndirectTargetStateStopsAsUnresolvedFlow()
            throws Exception {
        setBytes("1200", "6c0020");

        AddressEmulationEngine.Result result = execute(
            "1200",
            "{}",
            "[{\"start\":\"2000\",\"bytes\":\"34\"}]",
            "[]",
            "[]",
            null,
            "execute",
            10,
            10,
            20);

        assertEquals(result.error(), "unresolved_flow", result.stopReason());
        assertEquals(0, result.steps());
        assertNotNull(result.unresolvedControlFlow());
        assertEquals(address("1200"), result.unresolvedControlFlow().instruction());
        assertTrue(result.unresolvedControlFlow().missingState()
            .stream().anyMatch(range -> range.start().equals(address("2001"))));
        assertTrue(result.unresolvedControlFlow().availableMemory()
            .stream().anyMatch(range ->
                range.start().equals(address("2000"))
                    && range.bytes().length == 1
                    && (range.bytes()[0] & 0xff) == 0x34));

        HeadlessProgramProvider provider =
            new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        JsonObject serialized = JsonParser.parseString(
            new EmulationService(
                provider, new DirectThreadingStrategy())
                .emulateAddress(
                    "1200",
                    "{}",
                    "[{\"start\":\"2000\",\"bytes\":\"34\"}]",
                    "[]",
                    "[]",
                    "",
                    "execute",
                    10,
                    10,
                    20,
                    "").toJson()).getAsJsonObject()
            .getAsJsonObject("unresolved_control_flow");
        assertTrue(serialized.has("available_registers"));
        assertEquals(
            "34",
            serialized.getAsJsonArray("available_memory")
                .get(0).getAsJsonObject()
                .get("bytes").getAsString());
    }

    @Test
    public void executedInstructionWriteIsClassifiedWithoutChangingProgram()
            throws Exception {
        setBytes("1300", "a9ea8d011360");
        byte[] before = read("1300", 6);

        AddressEmulationEngine.Result result = execute(
            "1300",
            "{\"SP\":\"0x01fd\"}",
            "[]",
            "[]",
            "[]",
            null,
            "stop",
            10,
            10,
            20);

        assertEquals("terminal_instruction", result.stopReason());
        assertEquals(result.error(), 1, result.selfModifyingWrites().size());
        assertEquals(address("1301"), result.selfModifyingWrites().get(0).start());
        assertArrayEquals(bytes(0xea), result.selfModifyingWrites().get(0).bytes());
        assertArrayEquals(before, read("1300", 6));
    }

    @Test
    public void traceAndAccessLimitsTruncateIndependently()
            throws Exception {
        setBytes("1400", "a9018510a5108511a51160");

        AddressEmulationEngine.Result result = execute(
            "1400",
            "{}",
            "[]",
            "[]",
            "[]",
            null,
            "stop",
            20,
            2,
            3);

        assertEquals(2, result.trace().size());
        assertEquals(result.error(), 3, result.accesses().size());
        assertTrue(result.traceTruncated());
        assertTrue(result.accessLogTruncated());
    }

    @Test
    public void selfModificationAfterAccessLogCapIsStillClassified()
            throws Exception {
        setBytes("1e00", "a9018510a9ea8d001e60");

        AddressEmulationEngine.Result result = execute(
            "1e00", "{}", "[]", "[]", "[]",
            null, "stop", 20, 20, 1);

        assertEquals(1, result.accesses().size());
        assertTrue(result.accessLogTruncated());
        assertEquals(1, result.selfModifyingWrites().size());
        assertEquals(
            address("1e00"),
            result.selfModifyingWrites().get(0).start());
        assertArrayEquals(
            bytes(0xea),
            result.selfModifyingWrites().get(0).bytes());
    }

    @Test
    public void runtimeWrittenCodeCanExecuteOutsideProgramBlocks()
            throws Exception {
        setBytes("1e20",
            "a9a98d0090"
                + "a9428d0190"
                + "a9608d0290"
                + "a9ea8d0390"
                + "a9ea8d0490"
                + "a9ea8d0590"
                + "a9ea8d0690"
                + "a9ea8d0790"
                + "a9ea8d0890"
                + "a9ea8d0990"
                + "4c0090");

        AddressEmulationEngine.Result result = execute(
            "1e20",
            "{\"SP\":\"0x01fd\"}",
            "[]",
            "[]",
            "[{\"start\":\"9000\",\"end\":\"9009\"}]",
            null,
            "stop",
            40,
            50,
            50);

        assertEquals(result.error(),
            "terminal_instruction", result.stopReason());
        assertEquals(address("9002"), result.finalPc());
        assertEquals(
            BigInteger.valueOf(0x42),
            result.finalRegisters().get("A"));
        assertArrayEquals(
            bytes(0xa9, 0x42, 0x60, 0xea,
                0xea, 0xea, 0xea, 0xea,
                0xea, 0xea),
            result.capturedMemory().get(0).bytes());
    }

    @Test
    public void authoritativeListingInstructionWriteIsSelfModifying()
            throws Exception {
        setBytes("1500", "a9ea8d001660");
        setBytes("1600", "eaea");
        builder.disassemble("1600", 2);
        Instruction authoritative =
            program.getListing().getInstructionAt(address("1600"));
        assertNotNull(authoritative);

        AddressEmulationEngine.Result result = execute(
            "1500",
            "{}",
            "[]",
            "[]",
            "[]",
            null,
            "stop",
            10,
            10,
            20);

        assertEquals(result.error(), 1, result.selfModifyingWrites().size());
        assertEquals(address("1600"), result.selfModifyingWrites().get(0).start());
        assertEquals(authoritative,
            program.getListing().getInstructionAt(address("1600")));
    }

    @Test
    public void jsrAndRtsUseThe6502PageOneStackAndReturnToCaller()
            throws Exception {
        setBytes("1700", "201017ea");
        setBytes("1710", "e860");

        AddressEmulationEngine.Result result = execute(
            "1700",
            "{\"X\":0,\"SP\":\"0x01fd\"}",
            "[]",
            "[\"1703\"]",
            "[{\"start\":\"01fc\",\"end\":\"01fd\"}]",
            null,
            "execute",
            10,
            20,
            20);

        assertEquals(result.error(), "stop_address", result.stopReason());
        assertEquals(3, result.steps());
        assertEquals(BigInteger.ONE, result.finalRegisters().get("X"));
        assertEquals(BigInteger.valueOf(0x01fd),
            result.finalRegisters().get("SP"));
        assertArrayEquals(
            bytes(0x02, 0x17),
            result.capturedMemory().get(0).bytes());
        assertEquals(List.of(
                AddressEmulationEngine.AccessKind.WRITE,
                AddressEmulationEngine.AccessKind.WRITE,
                AddressEmulationEngine.AccessKind.READ,
                AddressEmulationEngine.AccessKind.READ),
            result.accesses().stream()
                .map(AddressEmulationEngine.MemoryAccess::kind)
                .toList());
    }

    @Test
    public void rtiRestoresStatusAndPcUsingPageOneWrapSemantics()
            throws Exception {
        setBytes("1800", "40");

        AddressEmulationEngine.Result result = execute(
            "1800",
            "{\"SP\":\"0x01fc\",\"P\":\"0x20\"}",
            "[{\"start\":\"01fd\",\"bytes\":\"a50019\"}]",
            "[\"1900\"]",
            "[]",
            null,
            "execute",
            10,
            10,
            20);

        assertEquals(result.error(), "stop_address", result.stopReason());
        assertEquals(1, result.steps());
        assertEquals(address("1900"), result.finalPc());
        assertEquals(BigInteger.valueOf(0xa5),
            result.finalRegisters().get("P"));
        assertEquals(BigInteger.valueOf(0x01ff),
            result.finalRegisters().get("SP"));
        assertEquals(3, result.accesses().size());
    }

    @Test
    public void brkPushesHardwareFrameAndReadsSuppliedVector()
            throws Exception {
        setBytes("1900", "00ea");

        AddressEmulationEngine.Result result = execute(
            "1900",
            "{\"SP\":\"0x01fd\",\"P\":\"0x21\"}",
            "[{\"start\":\"fffe\",\"bytes\":\"001a\"}]",
            "[\"1a00\"]",
            "[{\"start\":\"01fb\",\"end\":\"01fd\"}]",
            null,
            "execute",
            10,
            10,
            20);

        assertEquals(result.error(), "stop_address", result.stopReason());
        assertEquals(1, result.steps());
        assertEquals(address("1a00"), result.finalPc());
        assertEquals(BigInteger.valueOf(0x01fa),
            result.finalRegisters().get("SP"));
        assertArrayEquals(
            bytes(0x31, 0x02, 0x19),
            result.capturedMemory().get(0).bytes());
        assertEquals(5, result.accesses().size());
    }

    @Test
    public void overlayJsrRtsAndSyntheticReturnPreserveCodeSpace()
            throws Exception {
        builder.createOverlayMemory("bank", "0x1000", 0x100);
        builder.setBytes("bank::1000", "201010ea");
        builder.setBytes("bank::1010", "60");
        builder.setBytes("bank::1020", "60");
        builder.setBytes("bank::1040", "00");
        setBytes("1080", "40");

        AddressEmulationEngine.Result nested =
            AddressEmulationEngine.execute(
                program,
                AddressEmulationEngine.parseRequest(
                    program,
                    "bank:1000",
                    "{\"SP\":\"0x01fd\"}",
                    "[]",
                    "[\"bank:1003\"]",
                    "[]",
                    "1003",
                    "execute",
                    10,
                    20,
                    20));
        assertEquals(nested.error(),
            "stop_address", nested.stopReason());
        assertEquals(builder.addr("bank::1003"), nested.finalPc());
        assertEquals(
            "bank",
            nested.trace().get(0).address()
                .getAddressSpace().getName());
        assertEquals(
            "bank",
            nested.trace().get(1).address()
                .getAddressSpace().getName());

        AddressEmulationEngine.Result synthetic =
            AddressEmulationEngine.execute(
                program,
                AddressEmulationEngine.parseRequest(
                    program,
                    "bank:1020",
                    "{\"SP\":\"0x01fd\"}",
                    "[]",
                    "[\"bank:1030\"]",
                    "[]",
                    "bank:1030",
                    "execute",
                    10,
                    20,
                    20));
        assertEquals(synthetic.error(),
            "stop_address", synthetic.stopReason());
        assertEquals(
            builder.addr("bank::1030"),
            synthetic.finalPc());

        AddressEmulationEngine.Result interrupt =
            AddressEmulationEngine.execute(
                program,
                AddressEmulationEngine.parseRequest(
                    program,
                    "bank:1040",
                    "{\"SP\":\"0x01fd\",\"P\":\"0x20\"}",
                    "[{\"start\":\"ram:fffe\",\"bytes\":\"8010\"}]",
                    "[\"bank:1042\"]",
                    "[]",
                    null,
                    "execute",
                    10,
                    20,
                    30));
        assertEquals(interrupt.error(),
            "stop_address", interrupt.stopReason());
        assertEquals(
            builder.addr("bank::1042"),
            interrupt.finalPc());
        assertEquals(2, interrupt.steps());
    }

    @Test
    public void skippedOverlayStackFramesCannotBecomeStaleProvenance()
            throws Exception {
        builder.createOverlayMemory("bank", "0x1000", 0x300);
        builder.setBytes("bank::1100", "201011ea");
        builder.setBytes("bank::1110", "a2fd9a60");
        setBytes("1190", "a2fb9a60");

        AddressEmulationEngine.Result skipped =
            AddressEmulationEngine.execute(
                program,
                AddressEmulationEngine.parseRequest(
                    program,
                    "bank:1100",
                    "{\"SP\":\"0x01fd\"}",
                    "[]",
                    "[\"ram:1103\"]",
                    "[]",
                    "ram:1190",
                    "execute",
                    20,
                    30,
                    50));
        assertEquals(skipped.error(),
            "stop_address", skipped.stopReason());
        assertEquals(
            builder.addr("1103"),
            skipped.finalPc());
    }

    @Test
    public void overlayStackProvenanceSurvivesLiveFrameEdits()
            throws Exception {
        builder.createOverlayMemory("bank", "0x1000", 0x300);
        builder.setBytes("bank::1120", "00");
        setBytes("11a0", "a9408dfc01a9118dfd01a9218dfb0140");
        AddressEmulationEngine.Result edited =
            AddressEmulationEngine.execute(
                program,
                AddressEmulationEngine.parseRequest(
                    program,
                    "bank:1120",
                    "{\"SP\":\"0x01fd\",\"P\":\"0x20\"}",
                    "[{\"start\":\"ram:fffe\",\"bytes\":\"a011\"}]",
                    "[\"bank:1140\"]",
                    "[]",
                    null,
                    "execute",
                    20,
                    30,
                    80));
        assertEquals(edited.error(),
            "stop_address", edited.stopReason());
        assertEquals(
            builder.addr("bank::1140"),
            edited.finalPc());
        assertEquals(
            BigInteger.valueOf(0x21),
            edited.finalRegisters().get("P"));
    }

    @Test
    public void unmatchedReturnClearsStaleOverlayStackProvenance()
            throws Exception {
        builder.createOverlayMemory("bank", "0x1000", 0x300);
        builder.setBytes("bank::1150", "206011ea");
        builder.setBytes("bank::1160", "a2f09a60");
        builder.setBytes("bank::11b0", "00");
        setBytes("11c0", "a2fb9a60");

        AddressEmulationEngine.Result result =
            AddressEmulationEngine.execute(
                program,
                AddressEmulationEngine.parseRequest(
                    program,
                    "bank:1150",
                    "{\"SP\":\"0x01fd\",\"P\":\"0x20\"}",
                    "["
                        + "{\"start\":\"ram:01f1\","
                        + "\"bytes\":\"af11\"},"
                        + "{\"start\":\"ram:fffe\","
                        + "\"bytes\":\"c011\"}"
                        + "]",
                    "[\"ram:1153\"]",
                    "[]",
                    null,
                    "execute",
                    20,
                    30,
                    80));

        assertEquals(result.error(),
            "stop_address", result.stopReason());
        assertEquals(builder.addr("1153"), result.finalPc());
    }

    @Test
    public void wrappedStackReuseInvalidatesOverwrittenOverlayProvenance()
            throws Exception {
        builder.createOverlayMemory("bank", "0x1000", 0x500);
        for (int index = 0; index < 128; index++) {
            int start = 0x1200 + index * 4;
            int target = start + 4;
            builder.setBytes(
                Integer.toHexString(start),
                String.format(
                    "20%02x%02x60",
                    target & 0xff,
                    (target >>> 8) & 0xff));
        }
        setBytes("1400", "60");

        AddressEmulationEngine.Result result =
            AddressEmulationEngine.execute(
                program,
                AddressEmulationEngine.parseRequest(
                    program,
                    "ram:1200",
                    "{\"SP\":\"0x01fd\"}",
                    "[]",
                    "[]",
                    "[]",
                    "bank:13ff",
                    "execute",
                    257,
                    300,
                    600));

        assertEquals(result.error(),
            "max_steps", result.stopReason());
        assertEquals(257, result.steps());
        assertEquals(builder.addr("13ff"), result.finalPc());
    }

    @Test
    public void resolvedIndirectAndDirectJumpsReachCallerStops()
            throws Exception {
        setBytes("1a00", "6c0020");
        AddressEmulationEngine.Result indirect = execute(
            "1a00",
            "{}",
            "[{\"start\":\"2000\",\"bytes\":\"001b\"}]",
            "[\"1b00\"]",
            "[]",
            null,
            "execute",
            10,
            10,
            20);
        assertEquals(indirect.error(), "stop_address", indirect.stopReason());
        assertEquals(1, indirect.steps());
        assertEquals(address("1b00"), indirect.finalPc());

        setBytes("1b00", "4c001c");
        AddressEmulationEngine.Result direct = execute(
            "1b00", "{}", "[]", "[\"1c00\"]", "[]",
            null, "execute", 10, 10, 20);
        assertEquals(direct.error(), "stop_address", direct.stopReason());
        assertEquals(1, direct.steps());
        assertEquals(address("1c00"), direct.finalPc());
    }

    @Test
    public void statusRegisterOverrideControls6502Branches()
            throws Exception {
        setBytes("1c00", "d002eaeaea60");

        AddressEmulationEngine.Result notTaken = execute(
            "1c00",
            "{\"P\":\"0x22\"}",
            "[]",
            "[\"1c02\"]",
            "[]",
            null,
            "stop",
            10,
            10,
            20);
        assertEquals("stop_address", notTaken.stopReason());

        AddressEmulationEngine.Result taken = execute(
            "1c00",
            "{\"P\":\"0x20\"}",
            "[]",
            "[\"1c04\"]",
            "[]",
            null,
            "stop",
            10,
            10,
            20);
        assertEquals("stop_address", taken.stopReason());
    }

    @Test
    public void validationRejectsOverlapsUnknownFieldsCaptureOverflowAndReturnCollision() {
        IllegalArgumentException overlap = assertThrows(
            IllegalArgumentException.class,
            () -> AddressEmulationEngine.parseRequest(
                program, "1000", "{}",
                "[{\"start\":\"2000\",\"bytes\":\"0102\"},"
                    + "{\"start\":\"2001\",\"bytes\":\"03\"}]",
                "[]", "[]", null, "stop", 10, 10, 10));
        assertTrue(overlap.getMessage(), overlap.getMessage().contains("overlap"));

        IllegalArgumentException unknown = assertThrows(
            IllegalArgumentException.class,
            () -> AddressEmulationEngine.parseRequest(
                program, "1000", "{}",
                "[{\"start\":\"2000\",\"bytes\":\"01\",\"extra\":1}]",
                "[]", "[]", null, "stop", 10, 10, 10));
        assertTrue(unknown.getMessage(), unknown.getMessage().contains("extra"));

        String manyCaptures =
            "[" + String.join(",",
                java.util.Collections.nCopies(
                    17, "{\"start\":\"0000\",\"end\":\"ffff\"}"))
                + "]";
        IllegalArgumentException capture = assertThrows(
            IllegalArgumentException.class,
            () -> AddressEmulationEngine.parseRequest(
                program, "1000", "{}", "[]", "[]",
                manyCaptures, null, "stop", 10, 10, 10));
        assertTrue(capture.getMessage(), capture.getMessage().contains("1048576"));

        AddressEmulationEngine.Request collision =
            AddressEmulationEngine.parseRequest(
                program, "1100", "{\"SP\":\"0x01fd\"}",
                "[{\"start\":\"01fe\",\"bytes\":\"00\"}]",
                "[]", "[]", "1200", "execute", 10, 10, 10);
        IllegalArgumentException returnOverlap = assertThrows(
            IllegalArgumentException.class,
            () -> AddressEmulationEngine.execute(program, collision));
        assertTrue(returnOverlap.getMessage(),
            returnOverlap.getMessage().contains("overlaps"));
    }

    @Test
    public void unmappedFlowLeavesProgramBytesAndListingUnchanged()
            throws Exception {
        setBytes("1d00", "4c0090");
        byte[] before = read("1d00", 3);
        long listingBefore = program.getListing().getNumCodeUnits();

        AddressEmulationEngine.Result result = execute(
            "1d00", "{}", "[]", "[]", "[]",
            null, "execute", 10, 10, 10);

        assertEquals("unmapped_memory", result.stopReason());
        assertArrayEquals(before, read("1d00", 3));
        assertEquals(listingBefore, program.getListing().getNumCodeUnits());
    }

    @Test
    public void x64ChildRegistersSurvivePublicAndLegacyAdapters()
            throws Exception {
        ProgramBuilder x64Builder = new ProgramBuilder(
            "address-emulation-x64-adapters",
            ProgramBuilder._X64,
            "gcc",
            this);
        try {
            ProgramDB x64 = x64Builder.getProgram();
            x64Builder.createMemory("code", "1000", 0x200);
            x64Builder.setBytes("1000", "b878563412");
            x64Builder.setBytes("1020", "b878563412c3");
            x64Builder.setBytes("1040", "b878563412c3");
            x64Builder.setBytes("1060", "ffe0");
            HeadlessProgramProvider provider =
                new HeadlessProgramProvider();
            provider.setCurrentProgram(x64);
            EmulationService service = new EmulationService(
                provider, new DirectThreadingStrategy());

            JsonObject publicResult = JsonParser.parseString(
                service.emulateAddress(
                    "1000",
                    "{\"EAX\":1,\"ECX\":\"0x22\"}",
                    "[]",
                    "[\"1005\"]",
                    "[]",
                    "",
                    "execute",
                    10,
                    10,
                    10,
                    "").toJson()).getAsJsonObject();
            assertEquals("stop_address",
                publicResult.get("stop_reason").getAsString());
            assertEquals("0x12345678",
                publicResult.getAsJsonObject("final_registers")
                    .get("EAX").getAsString());
            assertEquals("0x22",
                publicResult.getAsJsonObject("final_registers")
                    .get("ECX").getAsString());

            x64Builder.disassemble("1020", 6);
            x64Builder.createFunction("1020");
            JsonObject functionResult = JsonParser.parseString(
                service.emulateFunction(
                    "1020",
                    "{\"EAX\":1,\"ECX\":\"0x22\"}",
                    "",
                    20,
                    "EAX,ECX,EIP",
                    "").toJson()).getAsJsonObject();
            assertTrue(functionResult.toString(),
                functionResult.get("success").getAsBoolean());
            assertEquals("0x12345678",
                functionResult.getAsJsonObject("registers")
                    .get("EAX").getAsString());
            assertEquals("0x22",
                functionResult.getAsJsonObject("registers")
                    .get("ECX").getAsString());
            assertEquals("0xdeadbeef",
                functionResult.getAsJsonObject("registers")
                    .get("EIP").getAsString());

            x64Builder.disassemble("1040", 6);
            x64Builder.createFunction("1040");
            JsonObject batchResult = JsonParser.parseString(
                service.emulateHashBatch(
                    "1040",
                    "ECX",
                    "EAX",
                    "0x12345678",
                    "[\"name\"]",
                    "",
                    false,
                    "").toJson()).getAsJsonObject();
            assertTrue(batchResult.toString(),
                batchResult.get("resolved").getAsBoolean());
            assertEquals(
                "name",
                batchResult.get("best_match").getAsString());

            AddressEmulationEngine.Result indirect =
                AddressEmulationEngine.execute(
                    x64,
                    AddressEmulationEngine.parseRequest(
                        x64,
                        "1060",
                        "{\"RAX\":\"0x9000\"}",
                        "[]",
                        "[]",
                        "[]",
                        null,
                        "execute",
                        10,
                        10,
                        10));
            assertEquals(indirect.error(),
                "unresolved_flow", indirect.stopReason());
            assertEquals(
                BigInteger.valueOf(0x9000),
                indirect.unresolvedControlFlow()
                    .availableRegisters().get("RAX"));

            IllegalArgumentException pcOverride = assertThrows(
                IllegalArgumentException.class,
                () -> AddressEmulationEngine.parseRequest(
                    x64,
                    "1000",
                    "{\"EIP\":\"0x1000\"}",
                    "[]",
                    "[]",
                    "[]",
                    null,
                    "execute",
                    10,
                    10,
                    10));
            assertTrue(
                pcOverride.getMessage(),
                pcOverride.getMessage()
                    .contains("program counter"));

            JsonObject functionPcInput = JsonParser.parseString(
                service.emulateFunction(
                    "1020",
                    "{\"RIP\":\"0x1020\"}",
                    "",
                    20,
                    "EAX",
                    "").toJson()).getAsJsonObject();
            assertTrue(
                functionPcInput.toString(),
                functionPcInput.get("error").getAsString()
                    .contains("program counter"));

            JsonObject batchPcInput = JsonParser.parseString(
                service.emulateHashBatch(
                    "1040",
                    "EIP",
                    "EAX",
                    "0x12345678",
                    "[\"name\"]",
                    "",
                    false,
                    "").toJson()).getAsJsonObject();
            assertTrue(
                batchPcInput.toString(),
                batchPcInput.get("error").getAsString()
                    .contains("program counter"));

            Register contextRegister =
                x64.getLanguage().getRegisters().stream()
                    .filter(register ->
                        register.isProcessorContext()
                            || register.getBaseRegister()
                                .isProcessorContext())
                    .findFirst()
                    .orElseThrow();
            String contextJson =
                "{\"" + contextRegister.getName() + "\":0}";
            IllegalArgumentException contextOverride = assertThrows(
                IllegalArgumentException.class,
                () -> AddressEmulationEngine.parseRequest(
                    x64,
                    "1000",
                    contextJson,
                    "[]",
                    "[]",
                    "[]",
                    null,
                    "execute",
                    10,
                    10,
                    10));
            assertTrue(
                contextOverride.getMessage(),
                contextOverride.getMessage()
                    .contains("processor context"));

            JsonObject functionContextInput =
                JsonParser.parseString(
                    service.emulateFunction(
                        "1020",
                        contextJson,
                        "",
                        20,
                        "EAX",
                        "").toJson()).getAsJsonObject();
            assertTrue(
                functionContextInput.toString(),
                functionContextInput.get("error").getAsString()
                    .contains("processor context"));

            JsonObject batchContextInput =
                JsonParser.parseString(
                    service.emulateHashBatch(
                        "1040",
                        "ECX",
                        "EAX",
                        "0x12345678",
                        "[\"name\"]",
                        contextJson,
                        false,
                        "").toJson()).getAsJsonObject();
            assertTrue(
                batchContextInput.toString(),
                batchContextInput.get("error").getAsString()
                    .contains("processor context"));
        }
        finally {
            x64Builder.dispose();
        }
    }

    @Test
    public void non6502ExecutionIsGenericAndClassifiesSelfModification()
            throws Exception {
        ProgramBuilder x64Builder = new ProgramBuilder(
            "address-emulation-x64",
            ProgramBuilder._X64,
            "gcc",
            this);
        try {
            ProgramDB x64 = x64Builder.getProgram();
            x64Builder.createMemory("code", "1000", 0x100);
            x64Builder.setBytes("1000", "c605f9ffffff90");
            AddressEmulationEngine.Request request =
                AddressEmulationEngine.parseRequest(
                    x64, "1000", "{}", "[]", "[\"1007\"]", "[]",
                    null, "execute", 10, 10, 20);

            AddressEmulationEngine.Result result =
                AddressEmulationEngine.execute(x64, request);

            assertEquals(result.error(), "stop_address", result.stopReason());
            assertEquals(1, result.steps());
            assertEquals(1, result.accesses().size());
            assertEquals(1, result.selfModifyingWrites().size());
            assertEquals(
                x64.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(0x1000),
                result.selfModifyingWrites().get(0).start());
            assertFalse(result.finalRegisters().containsKey("A"));

            IllegalArgumentException returnAddress = assertThrows(
                IllegalArgumentException.class,
                () -> AddressEmulationEngine.parseRequest(
                    x64, "1000", "{}", "[]", "[]", "[]",
                    "1007", "execute", 10, 10, 20));
            assertTrue(returnAddress.getMessage(),
                returnAddress.getMessage().contains("6502"));

            x64Builder.setBytes("1020", "f7f0");
            byte[] faultBytes = new byte[2];
            assertEquals(2, x64.getMemory().getBytes(
                x64.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(0x1020),
                faultBytes));
            long listingBefore =
                x64.getListing().getNumCodeUnits();
            AddressEmulationEngine.Result fault =
                AddressEmulationEngine.execute(
                    x64,
                    AddressEmulationEngine.parseRequest(
                        x64, "1020", "{\"RAX\":0,\"RDX\":0}",
                        "[]", "[]", "[]", null, "execute",
                        10, 10, 20));
            assertEquals(fault.error(), "fault", fault.stopReason());
            byte[] afterFault = new byte[2];
            assertEquals(2, x64.getMemory().getBytes(
                x64.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(0x1020),
                afterFault));
            assertArrayEquals(faultBytes, afterFault);
            assertEquals(
                listingBefore,
                x64.getListing().getNumCodeUnits());
        }
        finally {
            x64Builder.dispose();
        }
    }

    private AddressEmulationEngine.Result execute(
            String entry,
            String registers,
            String memory,
            String stops,
            String captures,
            String returnAddress,
            String terminalPolicy,
            int maxSteps,
            int traceLimit,
            int accessLimit) {
        AddressEmulationEngine.Request request =
            AddressEmulationEngine.parseRequest(
                program,
                entry,
                registers,
                memory,
                stops,
                captures,
                returnAddress,
                terminalPolicy,
                maxSteps,
                traceLimit,
                accessLimit);
        return AddressEmulationEngine.execute(program, request);
    }

    private void setBytes(String address, String hex) throws Exception {
        builder.setBytes(address, hex);
    }

    private byte[] read(String start, int length)
            throws MemoryAccessException {
        byte[] result = new byte[length];
        assertEquals(length, program.getMemory().getBytes(
            address(start), result));
        return result;
    }

    private Address address(String value) {
        return program.getAddressFactory()
            .getDefaultAddressSpace()
            .getAddress(Long.parseUnsignedLong(value, 16));
    }

    private static byte[] bytes(int... values) {
        byte[] result = new byte[values.length];
        for (int index = 0; index < values.length; index++) {
            result[index] = (byte) values[index];
        }
        return result;
    }
}
