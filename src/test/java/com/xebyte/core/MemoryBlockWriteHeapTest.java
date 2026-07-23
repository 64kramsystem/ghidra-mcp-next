package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import org.junit.Test;
import org.mockito.Mockito;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;

/**
 * Exercises write planning and response creation with adversarial differences
 * under a heap small enough to catch unbounded range materialization.
 */
public class MemoryBlockWriteHeapTest {

    private static final int RANGE_LIMIT = 4096;
    private static final int LARGE_LENGTH = 4_000_000;

    @Test
    public void alternatingWritesRemainBoundedUnder192MiBHeap()
            throws Exception {
        String java = Path.of(
            System.getProperty("java.home"), "bin", "java").toString();
        String mockitoAgent = Path.of(
            Mockito.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()).toString();
        Process process = new ProcessBuilder(
            java,
            "-Xmx192m",
            "-Xshare:off",
            "-Dnet.bytebuddy.experimental=true",
            "-javaagent:" + mockitoAgent,
            "-cp",
            System.getProperty("java.class.path"),
            MemoryBlockWriteHeapTest.class.getName(),
            "probe")
            .redirectErrorStream(true)
            .start();
        boolean finished = process.waitFor(120, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            process.waitFor();
        }
        byte[] output = process.getInputStream().readNBytes(65_536);

        assertTrue("write planning probe timed out", finished);
        assertEquals(
            new String(output, StandardCharsets.UTF_8),
            0,
            process.exitValue());
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1 || !"probe".equals(args[0])) {
            throw new IllegalArgumentException("probe argument required");
        }
        Fixture fixture = fixtureForZeroFilledBlock();
        MemoryBlockService service = fixture.service();

        byte[] atLimit = alternatingDifferences(RANGE_LIMIT);
        Response accepted = service.writeMemoryBytes(
            "0x1000", atLimit, "overwrite_bytes", true, "");
        JsonObject acceptedJson =
            JsonParser.parseString(accepted.toJson()).getAsJsonObject();
        if (!(accepted instanceof Response.Ok)
                || acceptedJson.getAsJsonArray("differing_ranges").size()
                    != RANGE_LIMIT) {
            throw new AssertionError(
                "limit response was not generated correctly: "
                    + accepted.toJson());
        }

        byte[] adversarial = alternatingBytes(LARGE_LENGTH);
        assertBoundedError(
            service.writeMemoryBytes(
                "0x1000", adversarial, "overwrite_bytes", false, ""),
            "4096",
            "split");
        verify(fixture.block(), never()).putBytes(
            any(Address.class), any(byte[].class));
        verify(fixture.program()).endTransaction(0, false);
        assertBoundedError(
            service.writeMemoryBytes(
                "0x1000", adversarial, "error", true, ""),
            "differ");
    }

    private static Fixture fixtureForZeroFilledBlock()
            throws Exception {
        Program program = mock(Program.class);
        AddressFactory factory = mock(AddressFactory.class);
        AddressSpace space = mock(AddressSpace.class);
        Address start = mock(Address.class);
        Address end = mock(Address.class);
        Memory memory = mock(Memory.class);
        MemoryBlock block = mock(MemoryBlock.class);

        when(program.getName()).thenReturn("heap-fixture");
        when(program.getAddressFactory()).thenReturn(factory);
        when(program.getMemory()).thenReturn(memory);
        when(factory.getAddress("0x1000")).thenReturn(start);
        when(start.isExternalAddress()).thenReturn(false);
        when(start.addNoWrap(anyLong())).thenReturn(end);
        when(start.getAddressSpace()).thenReturn(space);
        when(start.getOffset()).thenReturn(0x1000L);
        when(start.toString(false)).thenReturn("1000");
        when(end.toString(false)).thenReturn("3d18ff");
        when(space.getName()).thenReturn("ram");
        when(memory.getBlock(start)).thenReturn(block);
        when(block.contains(end)).thenReturn(true);
        when(block.isInitialized()).thenReturn(true);
        when(block.getName()).thenReturn("ram");
        when(block.getStart()).thenReturn(start);
        when(block.getEnd()).thenReturn(end);
        when(block.getSize()).thenReturn((long) LARGE_LENGTH);
        when(block.getType()).thenReturn(MemoryBlockType.DEFAULT);
        when(block.getSourceInfos()).thenReturn(java.util.List.of());
        when(block.getSourceName()).thenReturn("fixture");
        when(block.isRead()).thenReturn(true);
        when(block.isWrite()).thenReturn(true);
        doAnswer(invocation -> {
            byte[] destination = invocation.getArgument(1);
            return destination.length;
        }).when(block).getBytes(eq(start), any(byte[].class));

        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        return new Fixture(
            new MemoryBlockService(
                provider, new DirectThreadingStrategy()),
            program,
            block);
    }

    private static void assertBoundedError(
            Response response, String... fragments) {
        if (!(response instanceof Response.Err)) {
            throw new AssertionError(
                "expected a normal error response: " + response.toJson());
        }
        String json = response.toJson();
        for (String fragment : fragments) {
            if (!json.contains(fragment)) {
                throw new AssertionError(
                    "missing '" + fragment + "' in " + json);
            }
        }
    }

    private static byte[] alternatingDifferences(int rangeCount) {
        return alternatingBytes(Math.multiplyExact(rangeCount, 2) - 1);
    }

    private static byte[] alternatingBytes(int length) {
        byte[] requested = new byte[length];
        for (int index = 0; index < requested.length; index += 2) {
            requested[index] = 1;
        }
        return requested;
    }

    private record Fixture(
            MemoryBlockService service,
            Program program,
            MemoryBlock block) {
    }
}
