package com.xebyte.core;

import java.util.ArrayList;
import java.util.List;

public final class DebuggerTransferSemantics {
    private DebuggerTransferSemantics() {}

    public record Chunk(long offset, int length) {}

    public static long rebase(long address, long runtimeBase, long staticBase) {
        if (Long.compareUnsigned(address, runtimeBase) < 0) {
            throw new IllegalArgumentException("address precedes runtime base");
        }
        return Math.addExact(staticBase, Math.subtractExact(address, runtimeBase));
    }

    public static List<Chunk> planChunks(long length, int maximumChunkSize) {
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive");
        }
        if (maximumChunkSize <= 0) {
            throw new IllegalArgumentException("maximum chunk size must be positive");
        }
        List<Chunk> chunks = new ArrayList<>();
        for (long offset = 0; offset < length; ) {
            int chunk = (int) Math.min((long) maximumChunkSize, length - offset);
            chunks.add(new Chunk(offset, chunk));
            offset = Math.addExact(offset, chunk);
        }
        return List.copyOf(chunks);
    }
}
