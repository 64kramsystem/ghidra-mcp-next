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
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;

public class AddressEmulationServiceGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;

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
            "[]",
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
            .stream().anyMatch(range -> range.start().equals(address("2000"))));
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
