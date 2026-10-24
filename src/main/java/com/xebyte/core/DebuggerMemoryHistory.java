package com.xebyte.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.util.task.TimeoutTaskMonitor;

final class DebuggerMemoryHistory {
    private DebuggerMemoryHistory() {}

    static Map<String, Object> search(TraceMemoryManager memory, AddressRange range,
            Lifespan span, String pattern, int limit) throws Exception {
        if (range.getLength() < 1 || range.getLength() > 1_048_576) {
            throw new IllegalArgumentException("address range must contain 1..1048576 bytes");
        }
        if (span.min() < 0 || span.max() == Long.MAX_VALUE) {
            throw new IllegalArgumentException("use a finite non-negative snapshot interval");
        }
        if (limit < 1 || limit > 10_000) {
            throw new IllegalArgumentException("limit must be from 1 to 10000");
        }
        byte[] bytes = HexFormat.of().parseHex(pattern.replaceAll("\\s+", ""));
        if (bytes.length < 1 || bytes.length > 4096) {
            throw new IllegalArgumentException("pattern must contain 1..4096 exact bytes");
        }
        var monitor = TimeoutTaskMonitor.timeoutIn(10, TimeUnit.SECONDS);
        try {
            List<TraceAddressSnapRange> hits = memory.findBytesAcrossLifespan(
                    span, range, bytes, monitor);
            monitor.checkCancelled();
            List<TraceAddressSnapRange> contained = hits.stream()
                    // 12.2 reports start + pattern.length as its inclusive end.
                    // Derive the actual last byte before enforcing our range contract.
                    .filter(hit -> range.contains(hit.getX1()) &&
                            range.contains(hit.getX1().add(bytes.length - 1L)))
                    .sorted(Comparator.comparing(TraceAddressSnapRange::getX1)
                            .thenComparingLong(TraceAddressSnapRange::getY1))
                    .toList();
            List<Map<String, Object>> matches = new ArrayList<>();
            for (TraceAddressSnapRange hit : contained.subList(0, Math.min(limit, contained.size()))) {
                matches.add(Map.of(
                        "address", hit.getX1().toString(),
                        "end", hit.getX1().add(bytes.length - 1L).toString(),
                        "first_snap", Math.max(span.min(), hit.getY1()),
                        "last_snap", Math.min(span.max(), hit.getY2())));
            }
            return Map.of("matches", matches, "total_matches", contained.size(),
                    "truncated", contained.size() > limit);
        } finally {
            monitor.finished();
        }
    }
}
