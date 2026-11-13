package com.xebyte.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.CommentType;
import java.util.HexFormat;

/** Collects the native program snapshot. */
final class ProgramSnapshot {
    static JsonObject collect(Program currentProgram) throws Exception {
        TaskMonitor monitor = TaskMonitor.DUMMY;
        long modification = currentProgram.getModificationNumber();
        var report = new JsonObject();
        report.addProperty("program", currentProgram.getName());

        var blocks = new JsonArray();
        for (var block : currentProgram.getMemory().getBlocks()) {
            monitor.checkCancelled();
            var row = new JsonObject();
            row.addProperty("name", block.getName());
            row.addProperty("start", block.getStart().toString(true));
            row.addProperty("end", block.getEnd().toString(true));
            row.addProperty("initialized", block.isInitialized());
            row.addProperty("permissions", (block.isRead() ? "r" : "-")
                + (block.isWrite() ? "w" : "-") + (block.isExecute() ? "x" : "-"));
            row.addProperty("comment", block.getComment());
            if (block.isInitialized()) {
                var bytes = new byte[Math.toIntExact(block.getSize())];
                if (block.getBytes(block.getStart(), bytes) != bytes.length) {
                    throw new IllegalStateException("Incomplete byte read: " + block.getName());
                }
                row.addProperty("bytes", HexFormat.of().formatHex(bytes));
            }
            blocks.add(row);
        }
        report.add("blocks", blocks);

        var symbols = new JsonArray();
        for (var symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
            monitor.checkCancelled();
            var row = new JsonObject();
            row.addProperty("address", symbol.getAddress().toString(true));
            row.addProperty("name", symbol.getName(true));
            row.addProperty("type", symbol.getSymbolType().toString());
            row.addProperty("source", symbol.getSource().toString());
            row.addProperty("primary", symbol.isPrimary());
            symbols.add(row);
        }
        report.add("symbols", symbols);

        var references = new JsonArray();
        var manager = currentProgram.getReferenceManager();
        for (var address : manager.getReferenceSourceIterator(currentProgram.getMemory(), true)) {
            monitor.checkCancelled();
            for (var reference : manager.getReferencesFrom(address)) {
                var row = new JsonObject();
                row.addProperty("from", reference.getFromAddress().toString(true));
                row.addProperty("to", reference.getToAddress().toString(true));
                row.addProperty("type", reference.getReferenceType().getName());
                row.addProperty("operand", reference.getOperandIndex());
                row.addProperty("source", reference.getSource().toString());
                row.addProperty("primary", reference.isPrimary());
                references.add(row);
            }
        }
        report.add("references", references);

        var instructions = new JsonArray();
        for (var instruction : currentProgram.getListing().getInstructions(true)) {
            monitor.checkCancelled();
            var row = new JsonObject();
            row.addProperty("address", instruction.getAddress().toString(true));
            row.addProperty("bytes", HexFormat.of().formatHex(instruction.getBytes()));
            row.addProperty("text", instruction.toString());
            row.addProperty("fallthrough", instruction.getFallThrough() == null
                ? null : instruction.getFallThrough().toString(true));
            row.addProperty("flow_type", instruction.getFlowType().toString());
            row.addProperty("override", instruction.getFlowOverride().toString());
            var flows = new JsonArray();
            for (var address : instruction.getFlows()) flows.add(address.toString(true));
            row.add("flows", flows);
            var comments = new JsonObject();
            for (var kind : CommentType.values()) {
                comments.addProperty(kind.name(), instruction.getComment(kind));
            }
            row.add("comments", comments);
            instructions.add(row);
        }
        report.add("instructions", instructions);

        var markers = new JsonArray();
        var opaque = currentProgram.getUsrPropertyManager().getPropertyMap("listing.opaque");
        if (opaque != null) {
            var addresses = opaque.getPropertyIterator();
            while (addresses.hasNext()) {
                monitor.checkCancelled();
                markers.add(addresses.next().toString(true));
            }
        }
        report.add("opaque", markers);
        monitor.checkCancelled();
        if (currentProgram.getModificationNumber() != modification) {
            throw new IllegalStateException("Program changed during snapshot");
        }
        return report;
    }
}
