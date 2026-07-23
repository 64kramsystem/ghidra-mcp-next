package com.xebyte.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;

import ghidra.program.model.listing.Program;

/**
 * Pure contract coverage for request normalization. ProgramDB-backed memory
 * behavior is covered by {@link MemoryBlockServiceGhidraTest}.
 */
public class MemoryBlockCoreTest {

    @Test
    public void sourceMustBeExactlyOneOfLengthBytesOrFile() {
        IllegalArgumentException none = assertThrows(
            IllegalArgumentException.class,
            () -> MemoryBlockCore.normalizeSource(null, null, null, null, null, null));
        IllegalArgumentException two = assertThrows(
            IllegalArgumentException.class,
            () -> MemoryBlockCore.normalizeSource(
                16L, "00", null, null, null, null));

        assertTrue(none.getMessage(), none.getMessage().contains("exactly one"));
        assertTrue(two.getMessage(), two.getMessage().contains("exactly one"));
    }

    @Test
    public void bytesAcceptHexOrByteArrayAndRejectMalformedOrOversizedValues() {
        assertArrayEquals(
            new byte[] { 0, (byte) 0xff, 0x10 },
            MemoryBlockCore.decodeBytes("00ff10"));
        assertArrayEquals(
            new byte[] { 0, (byte) 0xff, 0x10 },
            MemoryBlockCore.decodeBytes("[0,255,16]"));
        assertArrayEquals(
            new byte[] { 0, (byte) 0xff, 0x10 },
            MemoryBlockCore.decodeBytes("00 ff\n10"));
        assertArrayEquals(
            new byte[] { 0, (byte) 0xff, 0x10 },
            MemoryBlockCore.decodeBytes(
                List.of(
                    BigDecimal.ZERO,
                    new BigDecimal("255"),
                    new BigDecimal("16"))));
        byte[] compact = new byte[] { 0, (byte) 0xff, 0x10 };
        assertTrue(compact == MemoryBlockCore.decodeBytes(compact));

        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.decodeBytes("0"));
        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.decodeBytes("gg"));
        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.decodeBytes("[0,256]"));
        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.decodeBytes("[0,1.5]"));
        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.validatePayloadLength(
                MemoryBlockCore.MAX_SOURCE_BYTES + 1));
    }

    @Test
    public void exactIntegerParsingRejectsFractionalLossyAndOverflowingNumbers() {
        assertEquals(Long.valueOf(16),
            MemoryBlockCore.exactLong(new BigDecimal("16"), "length", false));
        assertEquals(Integer.valueOf(255),
            MemoryBlockCore.exactByte(new BigDecimal("255"), "fill"));

        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.exactLong(
                new BigDecimal("1.5"), "length", false));
        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.exactLong(
                new BigDecimal("9223372036854775808"), "length", false));
        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.exactLong(-1L, "file_offset", true));
        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.exactByte(256, "fill"));
    }

    @Test
    public void fileRootPolicyRunsBeforeAnyFilesystemRead() throws Exception {
        Path root = Files.createTempDirectory("memory-root");
        Path outside = Files.createTempFile("outside-bank", ".bin");
        AtomicInteger reads = new AtomicInteger();
        SecurityConfig security = SecurityConfig.forFileRootTesting(root);
        Program program = mock(Program.class);
        when(program.getName()).thenReturn("fixture");
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        MemoryBlockService service = new MemoryBlockService(
            provider,
            new DirectThreadingStrategy(),
            security,
            (path, offset, length) -> {
                reads.incrementAndGet();
                return Files.readAllBytes(path);
            });

        Response response = service.createMemoryBlock(
            "bank", "0x8000", null, null, outside.toString(),
            0L, 1L, false, null,
            true, false, false, false, null, true, "");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(),
            response.toJson().contains("outside GHIDRA_MCP_FILE_ROOT"));
        assertEquals(0, reads.get());
        verify(program, never()).getMemory();
    }

    @Test
    public void selectedProgramIsValidatedBeforeFileInputIsRead()
            throws Exception {
        Path root = Files.createTempDirectory("memory-program-first");
        Path source = root.resolve("bank.bin");
        Files.write(source, new byte[] { 1 });
        AtomicInteger reads = new AtomicInteger();
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        MemoryBlockService service = new MemoryBlockService(
            provider,
            new DirectThreadingStrategy(),
            SecurityConfig.forFileRootTesting(root),
            (path, offset, length) -> {
                reads.incrementAndGet();
                return new byte[] { 1 };
            });

        Response response = service.createMemoryBlock(
            "bank", "0x8000", null, null, source.toString(),
            0L, 1L, false, null,
            true, false, false, false, null, true, "missing");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(),
            response.toJson().contains("Program not found: missing"));
        assertEquals(0, reads.get());
    }

    @Test
    public void securedFileReadRejectsApprovedPathsReplacedBySymlinks()
            throws Exception {
        Path sandbox = Files.createTempDirectory("memory-secure-swaps");
        Path root = Files.createDirectory(sandbox.resolve("root"));
        Path outside = Files.createDirectory(sandbox.resolve("outside"));
        Path outsideFile = outside.resolve("bank.bin");
        Files.write(outsideFile, new byte[] { 9 });

        Path finalPath = root.resolve("final.bin");
        Files.write(finalPath, new byte[] { 1 });
        SecurityConfig finalSecurity =
            SecurityConfig.forFileRootTesting(root);
        Path approvedFinal =
            finalSecurity.resolveWithinFileRoot(finalPath.toString());
        Files.delete(finalPath);
        Files.createSymbolicLink(finalPath, outsideFile);
        assertThrows(java.io.IOException.class, () ->
            finalSecurity.readFileRangeWithinRoot(
                approvedFinal, 0, 1));

        Path parent = Files.createDirectory(root.resolve("parent"));
        Path parentFile = parent.resolve("bank.bin");
        Files.write(parentFile, new byte[] { 2 });
        SecurityConfig parentSecurity =
            SecurityConfig.forFileRootTesting(root);
        Path approvedParent =
            parentSecurity.resolveWithinFileRoot(parentFile.toString());
        Files.move(parent, root.resolve("saved-parent"),
            StandardCopyOption.ATOMIC_MOVE);
        Files.createSymbolicLink(parent, outside);
        assertThrows(java.io.IOException.class, () ->
            parentSecurity.readFileRangeWithinRoot(
                approvedParent, 0, 1));

        Path rootSwap = Files.createDirectory(
            sandbox.resolve("root-swap"));
        Path rootSwapFile = rootSwap.resolve("bank.bin");
        Files.write(rootSwapFile, new byte[] { 3 });
        SecurityConfig rootSecurity =
            SecurityConfig.forFileRootTesting(rootSwap);
        Path approvedRoot =
            rootSecurity.resolveWithinFileRoot(rootSwapFile.toString());
        Files.move(rootSwap, sandbox.resolve("saved-root"),
            StandardCopyOption.ATOMIC_MOVE);
        Files.createSymbolicLink(rootSwap, outside);
        assertThrows(java.io.IOException.class, () ->
            rootSecurity.readFileRangeWithinRoot(
                approvedRoot, 0, 1));
    }

    @Test
    public void securedFileReadUsesPinnedSizeAndReadsOnlyTheRequestedSlice()
            throws Exception {
        Path root = Files.createTempDirectory("memory-secure-range");
        Path sparse = root.resolve("sparse.bin");
        long offset = (long) Integer.MAX_VALUE + 4096L;
        try (var channel = java.nio.channels.FileChannel.open(
                sparse,
                java.nio.file.StandardOpenOption.CREATE_NEW,
                java.nio.file.StandardOpenOption.WRITE)) {
            channel.position(offset);
            channel.write(java.nio.ByteBuffer.wrap(
                new byte[] { 9, 8, 7 }));
        }
        Path directory = Files.createDirectory(root.resolve("directory"));
        SecurityConfig security = SecurityConfig.forFileRootTesting(root);

        assertArrayEquals(
            new byte[] { 9, 8, 7 },
            security.readFileRangeWithinRoot(
                security.resolveWithinFileRoot(sparse.toString()),
                offset,
                3));
        assertThrows(java.io.IOException.class, () ->
            security.readFileRangeWithinRoot(
                security.resolveWithinFileRoot(sparse.toString()),
                offset + 2,
                2));
        assertThrows(java.io.IOException.class, () ->
            security.readFileRangeWithinRoot(
                security.resolveWithinFileRoot(directory.toString()),
                0,
                1));
    }

    @Test
    public void fileRangesMustBePositiveBoundedAndFitTheRegularReadableFile()
            throws Exception {
        Path root = Files.createTempDirectory("memory-files");
        Path file = root.resolve("bank.bin");
        Files.write(file, new byte[] { 1, 2, 3, 4 });
        Path directory = root.resolve("dir");
        Files.createDirectory(directory);

        assertArrayEquals(
            new byte[] { 2, 3 },
            MemoryBlockCore.readFileSource(
                file, 1, 2, MemoryBlockCoreTest::readRange));
        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.readFileSource(
                file, 0, 0, MemoryBlockCoreTest::readRange));
        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.readFileSource(
                file, 3, 2, MemoryBlockCoreTest::readRange));
        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.readFileSource(
                directory, 0, 1, MemoryBlockCoreTest::readRange));
    }

    @Test
    public void fileOnlyOptionsAreRejectedForOtherCreationSources() {
        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.normalizeSource(
                16L, null, null, 1L, null, null));
        assertThrows(IllegalArgumentException.class,
            () -> MemoryBlockCore.normalizeSource(
                null, "00", null, null, 1L, null));
    }

    @Test
    public void explicitlyMissingProgramNeverFallsBackToCurrentForAnyMutation() {
        Program current = mock(Program.class);
        when(current.getName()).thenReturn("current");
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(current);
        MemoryBlockService service = new MemoryBlockService(
            provider, new DirectThreadingStrategy());

        List<Response> responses = List.of(
            service.createMemoryBlock(
                "new", "0x1000", 16L, null, null, null, null,
                false, null, true, false, false, false,
                null, false, "missing"),
            service.updateMemoryBlock(
                "ram", null, null, null, null, null,
                null, false, "missing"),
            service.splitMemoryBlock(
                "ram", "0x1008", false, "missing"),
            service.moveMemoryBlock(
                "ram", "0x2000", false, "missing"),
            service.writeMemoryBytes(
                "0x1000", "00", "overwrite_bytes", false, "missing"));

        for (Response response : responses) {
            assertTrue(response.toJson(), response instanceof Response.Err);
            assertTrue(response.toJson(),
                response.toJson().contains("Program not found: missing"));
        }
        verify(current, never()).getMemory();
    }

    @Test
    public void fileReaderReceivesOnlyTheBoundedSliceAtLargeOffsets()
            throws Exception {
        Path sparse = Files.createTempFile("large-sparse-bank", ".bin");
        long offset = (long) Integer.MAX_VALUE + 4096L;
        try (var channel = java.nio.channels.FileChannel.open(
                sparse,
                java.nio.file.StandardOpenOption.WRITE)) {
            channel.position(offset);
            channel.write(java.nio.ByteBuffer.wrap(new byte[] { 9, 8, 7 }));
        }
        AtomicInteger requestedLength = new AtomicInteger();

        byte[] selected = MemoryBlockCore.readFileSource(
            sparse, offset, 3, (path, actualOffset, length) -> {
                assertEquals(offset, actualOffset);
                requestedLength.set(length);
                return readRange(path, actualOffset, length);
            });

        assertArrayEquals(new byte[] { 9, 8, 7 }, selected);
        assertEquals(3, requestedLength.get());
    }

    @Test
    public void differingRangesAreCoalescedAndDigestIsStable() {
        byte[] before = { 0, 1, 2, 3, 4, 5 };
        byte[] requested = { 9, 1, 8, 7, 4, 6 };

        List<MemoryBlockCore.DifferingRange> ranges =
            MemoryBlockCore.differingRanges("ram", 0x1000, before, requested);

        assertEquals(3, ranges.size());
        assertEquals("ram:1000", ranges.get(0).start());
        assertEquals("ram:1000", ranges.get(0).end());
        assertEquals("ram:1002", ranges.get(1).start());
        assertEquals("ram:1003", ranges.get(1).end());
        assertEquals(
            "5aac6c53ca22a50073466dbffa46438bbe82e10d9c1a329a208d87adda5d2366",
            MemoryBlockCore.sha256(requested));
    }

    @Test
    public void differingRangesAcceptTheLimitAndRejectTheNextRange() {
        int limit = 4096;
        byte[] atLimit = alternatingDifferences(limit);
        byte[] overLimit = alternatingDifferences(limit + 1);

        List<MemoryBlockCore.DifferingRange> accepted =
            MemoryBlockCore.differingRanges(
                "ram", 0x1000, new byte[atLimit.length], atLimit);
        IllegalArgumentException rejected = assertThrows(
            IllegalArgumentException.class,
            () -> MemoryBlockCore.differingRanges(
                "ram", 0x1000, new byte[overLimit.length], overLimit));

        assertEquals(limit, accepted.size());
        assertTrue(rejected.getMessage(),
            rejected.getMessage().contains("4096"));
        assertTrue(rejected.getMessage(),
            rejected.getMessage().contains("split"));
    }

    private static byte[] alternatingDifferences(int rangeCount) {
        byte[] requested = new byte[Math.multiplyExact(rangeCount, 2) - 1];
        for (int index = 0; index < requested.length; index += 2) {
            requested[index] = 1;
        }
        return requested;
    }

    private static byte[] readRange(Path path, long offset, int length)
            throws java.io.IOException {
        byte[] result = new byte[length];
        try (var channel = java.nio.channels.FileChannel.open(
                path, java.nio.file.StandardOpenOption.READ)) {
            channel.position(offset);
            java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(result);
            while (buffer.hasRemaining() && channel.read(buffer) >= 0) {
                // Continue until the requested range is complete or EOF.
            }
            if (buffer.hasRemaining()) {
                return java.util.Arrays.copyOf(
                    result, length - buffer.remaining());
            }
            return result;
        }
    }
}
