package com.xebyte.core;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Optional filesystem root for endpoints that read or write local files.
 *
 * <p>The MCP server is local and unauthenticated. When
 * {@code GHIDRA_MCP_FILE_ROOT} is unset, absolute local paths are accepted.
 */
public final class SecurityConfig {
    private static final SecurityConfig INSTANCE =
        new SecurityConfig(System.getenv("GHIDRA_MCP_FILE_ROOT"));

    private final Path fileRoot;

    private SecurityConfig(String rawRoot) {
        fileRoot = rawRoot == null || rawRoot.isBlank()
            ? null
            : Path.of(rawRoot).toAbsolutePath().normalize();
    }

    static SecurityConfig forFileRootTesting(Path root) {
        if (root == null) {
            throw new IllegalArgumentException("fileRoot is required");
        }
        return new SecurityConfig(root.toString());
    }

    public static SecurityConfig getInstance() {
        return INSTANCE;
    }

    public boolean hasFileRoot() {
        return fileRoot != null;
    }

    public String getFileRoot() {
        return fileRoot == null ? null : fileRoot.toString();
    }

    public Path resolveWithinFileRoot(String value) {
        if (value == null) {
            return null;
        }
        Path requested = Path.of(value).toAbsolutePath().normalize();
        return fileRoot == null || requested.startsWith(fileRoot)
            ? requested
            : null;
    }

    byte[] readFileRangeWithinRoot(Path path, long offset, int length)
            throws IOException {
        Path resolved = resolveWithinFileRoot(path == null ? null : path.toString());
        if (resolved == null) {
            throw new IOException("file path is outside GHIDRA_MCP_FILE_ROOT");
        }
        try (SeekableByteChannel channel =
                Files.newByteChannel(resolved, StandardOpenOption.READ)) {
            long size = channel.size();
            if (offset < 0 || length < 0 || offset > size || length > size - offset) {
                throw new IOException("requested range exceeds file size");
            }
            byte[] result = new byte[length];
            ByteBuffer buffer = ByteBuffer.wrap(result);
            channel.position(offset);
            while (buffer.hasRemaining()) {
                if (channel.read(buffer) < 0) {
                    throw new IOException("file changed while reading");
                }
            }
            return result;
        }
    }
}
