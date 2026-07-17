package com.xebyte.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.thread.TraceProcess;
import ghidra.util.task.TaskMonitor;

final class DebuggerMemorySemantics {
    interface ProgramBlockWriter {
        MemoryBlock create(Program program, String name, Address start, long length,
                           boolean read, boolean write, boolean execute,
                           List<byte[]> chunks) throws Exception;
    }

    record RegionRange<T>(T region, AddressRange range) {}

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

    static TraceMemoryRegion requireContainingRegion(
            Collection<? extends TraceMemoryRegion> regions,
            long snap,
            AddressRange source) {
        List<RegionRange<TraceMemoryRegion>> ranges = regions.stream()
                .map(region -> new RegionRange<>(region, region.getRange(snap)))
                .toList();
        return requireContainingRegionRange(ranges, source);
    }

    static <T> T requireContainingRegionRange(
            Collection<RegionRange<T>> regions,
            AddressRange source) {
        List<RegionRange<T>> matches = regions.stream()
                .filter(region -> region.range() != null &&
                        region.range().contains(source.getMinAddress()) &&
                        region.range().contains(source.getMaxAddress()))
                .toList();
        if (matches.size() != 1) {
            throw new IllegalArgumentException(
                    "Source range must be contained in exactly one current memory region; " +
                            "matched " + matches.size());
        }
        return matches.get(0).region();
    }

    static void requireKnown(TraceMemoryManager memory, long snap, AddressRange source) {
        AddressSet requested = new AddressSet(source);
        AddressSetView known = memory.getAddressesWithState(
                snap, requested, state -> state == TraceMemoryState.KNOWN);
        requireKnown(known, source);
    }

    static void requireKnown(AddressSetView known, AddressRange source) {
        if (!known.contains(source.getMinAddress(), source.getMaxAddress())) {
            throw new IllegalArgumentException(
                    "Source range contains bytes not known at the current trace snapshot");
        }
    }

    static void requireDestinationFree(Memory memory, AddressRange destination) {
        if (!memory.intersect(new AddressSet(destination)).isEmpty()) {
            throw new IllegalArgumentException(
                    "Destination range overlaps existing program memory");
        }
    }

    static ProgramBlockWriter programBlockWriter(TaskMonitor monitor) {
        return (program, name, start, length, read, write, execute, chunks) -> {
            int transaction = program.startTransaction("Copy debugger memory");
            boolean commit = false;
            try {
                MemoryBlock block = program.getMemory().createInitializedBlock(
                        name, start, length, (byte) 0, monitor, false);
                long offset = 0;
                for (byte[] chunk : chunks) {
                    int written = block.putBytes(start.addNoWrap(offset), chunk);
                    if (written != chunk.length) {
                        throw new IllegalStateException(
                                "Short program-memory write: expected " + chunk.length +
                                        " bytes, wrote " + written);
                    }
                    offset = Math.addExact(offset, chunk.length);
                }
                if (offset != length) {
                    throw new IllegalStateException(
                            "Chunk length mismatch: expected " + length +
                                    " bytes, received " + offset);
                }
                block.setRead(read);
                block.setWrite(write);
                block.setExecute(execute);
                commit = true;
                return block;
            } finally {
                program.endTransaction(transaction, commit);
            }
        };
    }
}
