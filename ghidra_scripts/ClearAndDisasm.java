//Clear and disassemble a range
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class ClearAndDisasm extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Address start = null;
        Address end = null;

        if (args != null && args.length > 0 && args[0] != null && !args[0].isBlank()) {
            start = toAddr(args[0].trim());
        }
        if (args != null && args.length > 1 && args[1] != null && !args[1].isBlank()) {
            end = toAddr(args[1].trim());
        }

        if (start == null && end == null
                && currentSelection != null && !currentSelection.isEmpty()) {
            start = currentSelection.getMinAddress();
            end = currentSelection.getMaxAddress();
        }

        if (!isRunningHeadless()) {
            if (start == null) {
                start = askAddress("Clear and Disassemble", "Start address:");
            }
            if (end == null) {
                end = askAddress("Clear and Disassemble", "End address:");
            }
        }

        if (start == null || end == null) {
            printerr("Start and end addresses are required");
            return;
        }
        if (start.compareTo(end) > 0) {
            printerr("Start address must not be after end address");
            return;
        }

        clearListing(start, end);
        println("Cleared " + start + " to " + end);
        disassemble(start);
        println("Disassembled from " + start);
    }
}
