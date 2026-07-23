package com.xebyte.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.List;

import org.junit.Test;

import com.google.gson.JsonParser;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;

public class AddressEmulationEngineTest {

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0);

    @Test
    public void exactAndHardLimitBoundariesAreAccepted() {
        AddressEmulationEngine.Limits limits =
            AddressEmulationEngine.validateLimits(100_000, 100_000, 1_000_000);

        assertEquals(100_000, limits.maxSteps());
        assertEquals(100_000, limits.traceLimit());
        assertEquals(1_000_000, limits.accessLogLimit());
    }

    @Test
    public void nonPositiveAndExcessiveLimitsAreRejected() {
        assertLimitRejected(0, 1, 1, "max_steps");
        assertLimitRejected(100_001, 1, 1, "100000");
        assertLimitRejected(1, 0, 1, "trace_limit");
        assertLimitRejected(1, 100_001, 1, "100000");
        assertLimitRejected(1, 1, 0, "access_log_limit");
        assertLimitRejected(1, 1, 1_000_001, "1000000");
    }

    @Test
    public void bytePayloadAcceptsExactHexAndNumericArrayGrammar() {
        assertArrayEquals(
            bytes(0x00, 0xaa, 0xff, 0x10),
            AddressEmulationEngine.decodeBytes(
                JsonParser.parseString("\"0x00 aa\\nff\\t10\""), "memory.bytes"));
        assertArrayEquals(
            bytes(0x00, 0xaa, 0xff, 0x10),
            AddressEmulationEngine.decodeBytes(
                JsonParser.parseString("[0,170,255,16]"), "memory.bytes"));
    }

    @Test
    public void bytePayloadRejectsEmptyOddNonHexFractionalAndOutOfRangeValues() {
        for (String json : List.of(
                "\"\"", "\"0x\"", "\"0\"", "\"gg\"", "[]",
                "[1.5]", "[-1]", "[256]", "[\"1\"]", "null")) {
            IllegalArgumentException error = assertThrows(
                json,
                IllegalArgumentException.class,
                () -> AddressEmulationEngine.decodeBytes(
                    JsonParser.parseString(json), "memory.bytes"));
            assertTrue(error.getMessage(), error.getMessage().contains("memory.bytes"));
        }
    }

    @Test
    public void unsignedValuesAcceptIntegersAndHexWithinRegisterWidth() {
        assertEquals(
            BigInteger.valueOf(255),
            AddressEmulationEngine.parseUnsigned(
                JsonParser.parseString("255"), 8, "registers.A"));
        assertEquals(
            BigInteger.valueOf(255),
            AddressEmulationEngine.parseUnsigned(
                JsonParser.parseString("\"0xff\""), 8, "registers.A"));
        assertEquals(
            BigInteger.valueOf(255),
            AddressEmulationEngine.parseUnsigned(
                JsonParser.parseString("\"255\""), 8, "registers.A"));
    }

    @Test
    public void unsignedValuesRejectNegativeFractionalMalformedAndOverflowValues() {
        for (String json : List.of("-1", "1.5", "\"-1\"", "\"0xgg\"", "256", "true")) {
            IllegalArgumentException error = assertThrows(
                json,
                IllegalArgumentException.class,
                () -> AddressEmulationEngine.parseUnsigned(
                    JsonParser.parseString(json), 8, "registers.A"));
            assertTrue(error.getMessage(), error.getMessage().contains("registers.A"));
        }
    }

    @Test
    public void terminalPolicyIsExact() {
        assertEquals(
            AddressEmulationEngine.TerminalPolicy.STOP,
            AddressEmulationEngine.TerminalPolicy.parse("stop"));
        assertEquals(
            AddressEmulationEngine.TerminalPolicy.EXECUTE,
            AddressEmulationEngine.TerminalPolicy.parse("execute"));

        for (String invalid : new String[]{"", "STOP", "run", null}) {
            IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> AddressEmulationEngine.TerminalPolicy.parse(invalid));
            assertTrue(error.getMessage(), error.getMessage().contains("terminal_policy"));
        }
    }

    @Test
    public void orderedAccessLogIsPreservedWhileSameKindAdjacentRangesCoalesce() {
        List<AddressEmulationEngine.MemoryAccess> ordered = List.of(
            access(0, 1, AddressEmulationEngine.AccessKind.READ, 0x10, 0xaa),
            access(1, 1, AddressEmulationEngine.AccessKind.READ, 0x11, 0xbb),
            access(2, 1, AddressEmulationEngine.AccessKind.WRITE, 0x20, 0xcc),
            access(3, 2, AddressEmulationEngine.AccessKind.READ, 0x12, 0xdd));

        List<AddressEmulationEngine.MemoryRange> reads =
            AddressEmulationEngine.coalesceAccesses(
                ordered, AddressEmulationEngine.AccessKind.READ);

        assertEquals(ordered, List.copyOf(ordered));
        assertEquals(2, reads.size());
        assertEquals(address(0x10), reads.get(0).start());
        assertEquals(address(0x11), reads.get(0).end());
        assertArrayEquals(bytes(0xaa, 0xbb), reads.get(0).bytes());
        assertEquals(address(0x12), reads.get(1).start());
        assertEquals(address(0x12), reads.get(1).end());
    }

    @Test
    public void selfModifyingWritesIntersectAuthoritativeOrExecutedInstructions() {
        AddressSet authoritative =
            new AddressSet(address(0x1000), address(0x1001));
        AddressSet executed =
            new AddressSet(address(0x2000), address(0x2002));

        assertTrue(AddressEmulationEngine.isSelfModifying(
            access(0, 1, AddressEmulationEngine.AccessKind.WRITE, 0x1001, 0xea),
            authoritative, executed));
        assertTrue(AddressEmulationEngine.isSelfModifying(
            access(0, 1, AddressEmulationEngine.AccessKind.WRITE, 0x2002, 0xea),
            authoritative, executed));
        assertFalse(AddressEmulationEngine.isSelfModifying(
            access(0, 1, AddressEmulationEngine.AccessKind.WRITE, 0x3000, 0xea),
            authoritative, executed));
        assertFalse(AddressEmulationEngine.isSelfModifying(
            access(0, 1, AddressEmulationEngine.AccessKind.READ, 0x1000, 0xea),
            authoritative, executed));
    }

    private static void assertLimitRejected(
            int maxSteps, int traceLimit, int accessLimit, String message) {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> AddressEmulationEngine.validateLimits(
                maxSteps, traceLimit, accessLimit));
        assertTrue(error.getMessage(), error.getMessage().contains(message));
    }

    private static AddressEmulationEngine.MemoryAccess access(
            long sequence, int step, AddressEmulationEngine.AccessKind kind,
            long address, int... data) {
        return new AddressEmulationEngine.MemoryAccess(
            sequence, step, kind, RAM.getAddress(address), bytes(data));
    }

    private static Address address(long offset) {
        return RAM.getAddress(offset);
    }

    private static byte[] bytes(int... values) {
        byte[] result = new byte[values.length];
        for (int index = 0; index < values.length; index++) {
            result[index] = (byte) values[index];
        }
        return result;
    }
}
