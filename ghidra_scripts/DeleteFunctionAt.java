//Delete a function at a specific address
//@author GhidraMCP-next
//@category Functions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class DeleteFunctionAt extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        Address addr = null;
        if (args != null && args.length > 0 && args[0] != null && !args[0].isBlank()) {
            addr = toAddr(args[0].trim());
        } else if (currentAddress != null) {
            addr = currentAddress;
        } else if (!isRunningHeadless()) {
            addr = askAddress("Delete Function", "Function address:");
        }

        if (addr == null) {
            printerr("Function address is required");
            return;
        }

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function func = funcMgr.getFunctionAt(addr);
        
        if (func == null) {
            println("No function found at " + addr);
            return;
        }
        
        String funcName = func.getName();
        
        int txId = currentProgram.startTransaction("Delete function " + funcName);
        try {
            boolean success = funcMgr.removeFunction(addr);
            if (success) {
                println("Deleted function: " + funcName + " at " + addr);
            } else {
                println("Failed to delete function at " + addr);
            }
            currentProgram.endTransaction(txId, success);
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            throw e;
        }
    }
}
