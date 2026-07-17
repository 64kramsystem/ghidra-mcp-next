package com.xebyte.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.thread.TraceProcess;

final class DebuggerMemorySemantics {
    record RegionInfo(
            String name,
            String path,
            Long processPid,
            String processPath,
            String addressSpace,
            long startOffset,
            String start,
            String end,
            long length,
            boolean read,
            boolean write,
            boolean execute,
            boolean volatileMemory) {}

    private DebuggerMemorySemantics() {}

    static Long parsePid(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (!(value instanceof String text) || text.isBlank()) {
            return null;
        }
        String normalized = text.trim().toLowerCase(Locale.ROOT);
        try {
            if (normalized.startsWith("0x")) {
                return Long.parseUnsignedLong(normalized.substring(2), 16);
            }
            return Long.parseLong(normalized);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static RegionInfo fromRegion(TraceMemoryRegion region, long snap) {
        AddressRange range = region.getRange(snap);
        if (range == null) {
            throw new IllegalArgumentException("Memory region has no range at snap " + snap +
                    ": " + region.getPath());
        }

        Long processPid = null;
        String processPath = null;
        TraceObject regionObject = region.getObject();
        if (regionObject != null) {
            TraceProcess process = regionObject
                    .queryCanonicalAncestorsInterface(TraceProcess.class)
                    .findFirst()
                    .orElse(null);
            if (process != null && process.getObject() != null) {
                TraceObject processObject = process.getObject();
                processPath = processObject.getCanonicalPath().toString();
                TraceObjectValue pidValue = processObject.getValue(snap, TraceProcess.KEY_PID);
                processPid = parsePid(pidValue == null ? null : pidValue.getValue());
            }
        }

        return new RegionInfo(
                region.getName(snap),
                region.getPath(),
                processPid,
                processPath,
                range.getAddressSpace().getName(),
                range.getMinAddress().getUnsignedOffset(),
                range.getMinAddress().toString(),
                range.getMaxAddress().toString(),
                range.getLength(),
                region.isRead(snap),
                region.isWrite(snap),
                region.isExecute(snap),
                region.isVolatile(snap));
    }

    static List<Map<String, Object>> describeRegions(Collection<RegionInfo> regions,
                                                     Long pid) {
        List<RegionInfo> sorted = regions.stream()
                .filter(region -> pid == null || pid.equals(region.processPid()))
                .sorted(Comparator.comparing(RegionInfo::addressSpace)
                        .thenComparing((left, right) ->
                                Long.compareUnsigned(left.startOffset(), right.startOffset())))
                .toList();
        List<Map<String, Object>> result = new ArrayList<>(sorted.size());
        for (RegionInfo region : sorted) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", region.name());
            item.put("path", region.path());
            item.put("process_pid", region.processPid());
            item.put("process_path", region.processPath());
            item.put("address_space", region.addressSpace());
            item.put("start", region.start());
            item.put("end", region.end());
            item.put("length", region.length());
            item.put("read", region.read());
            item.put("write", region.write());
            item.put("execute", region.execute());
            item.put("volatile", region.volatileMemory());
            result.add(item);
        }
        return List.copyOf(result);
    }
}
