package com.xebyte.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.Reference;

import java.util.LinkedHashSet;
import java.util.TreeMap;

final class DataObjectInventory {
    private final Program currentProgram;
    private final TaskMonitor monitor = TaskMonitor.DUMMY;

    DataObjectInventory(Program program) {
        currentProgram = program;
    }

    JsonObject collect() throws Exception {
        var listing = currentProgram.getListing();
        var remaining = new AddressSet(currentProgram.getMemory());
        var rows = new TreeMap<Address, JsonObject>();
        int arrays = 0;
        int definitions = 0;
        int undefinedRanges = 0;
        for (var instruction : listing.getInstructions(true)) {
            monitor.checkCancelled();
            remaining.delete(instruction.getMinAddress(), instruction.getMaxAddress());
        }
        for (var data : listing.getDefinedData(true)) {
            monitor.checkCancelled();
            var start = data.getMinAddress();
            var end = data.getMaxAddress();
            remaining.delete(start, end);
            var row = describe(start, end);
            row.addProperty("type", data.getDataType().getPathName());
            row.addProperty("array", data.isArray());
            boolean undefined = Undefined.isUndefined(data.getDataType());
            row.addProperty("undefined", undefined);
            rows.put(start, row);
            definitions++;
            if (data.isArray()) arrays++;
            if (undefined) undefinedRanges++;
        }
        for (var block : currentProgram.getMemory().getBlocks()) {
            // Keep adjacent blocks and initialization states separate.
            var gaps = remaining.intersect(new AddressSet(block.getStart(), block.getEnd()));
            for (var range : gaps) {
                monitor.checkCancelled();
                var row = describe(range.getMinAddress(), range.getMaxAddress());
                row.addProperty("type", "undefined");
                row.addProperty("array", false);
                row.addProperty("undefined", true);
                rows.put(range.getMinAddress(), row);
                undefinedRanges++;
            }
        }
        var report = new JsonObject();
        report.addProperty("program", currentProgram.getName());
        report.addProperty("data_definitions", definitions);
        report.addProperty("arrays", arrays);
        report.addProperty("undefined_ranges", undefinedRanges);
        report.addProperty("references_note",
            "Only recorded Ghidra references; indirect accesses may have none.");
        var objects = new JsonArray();
        rows.values().forEach(objects::add);
        report.add("objects", objects);
        return report;
    }

    private JsonObject describe(Address start, Address end) throws Exception {
        var range = new AddressSet(start, end);
        var listing = currentProgram.getListing();
        var row = new JsonObject();
        row.addProperty("start", start.toString(true));
        row.addProperty("end", end.toString(true));
        row.addProperty("length", end.subtract(start) + 1);
        row.addProperty("fully_initialized",
            currentProgram.getMemory().getAllInitializedAddressSet().contains(start, end));
        var opaqueMarkers = new JsonArray();
        var opaque = currentProgram.getUsrPropertyManager().getPropertyMap("listing.opaque");
        if (opaque != null) {
            for (var address : opaque.getPropertyIterator(start, end)) {
                opaqueMarkers.add(address.toString(true));
            }
        }
        row.add("opaque_markers", opaqueMarkers);

        var labels = new JsonArray();
        for (var symbol : currentProgram.getSymbolTable().getSymbolIterator(start, true)) {
            if (symbol.getAddress().compareTo(end) > 0) break;
            var label = new JsonObject();
            label.addProperty("address", symbol.getAddress().toString(true));
            label.addProperty("name", symbol.getName(true));
            labels.add(label);
        }
        row.add("labels", labels);
        var comments = new JsonArray();
        for (var address : listing.getCommentAddressIterator(range, true)) {
            for (var kind : CommentType.values()) {
                var text = listing.getComment(kind, address);
                if (text == null) continue;
                var comment = new JsonObject();
                comment.addProperty("address", address.toString(true));
                comment.addProperty("kind", kind.name());
                comment.addProperty("text", text);
                comments.add(comment);
            }
        }
        row.add("comments", comments);

        // Include references to interior bytes, not just the object's start address.
        var manager = currentProgram.getReferenceManager();
        var references = new LinkedHashSet<Reference>();
        for (var address : manager.getReferenceDestinationIterator(range, true)) {
            for (var reference : manager.getReferencesTo(address)) references.add(reference);
        }
        for (var address : manager.getReferenceSourceIterator(range, true)) {
            for (var reference : manager.getReferencesFrom(address)) references.add(reference);
        }
        var refs = new JsonArray();
        for (var reference : references) {
            monitor.checkCancelled();
            var ref = new JsonObject();
            ref.addProperty("from", reference.getFromAddress().toString(true));
            ref.addProperty("to", reference.getToAddress().toString(true));
            ref.addProperty("type", reference.getReferenceType().getName());
            ref.addProperty("operand", reference.getOperandIndex());
            ref.addProperty("source_is_code",
                listing.getInstructionContaining(reference.getFromAddress()) != null);
            refs.add(ref);
        }
        row.add("references", refs);
        return row;
    }
}
