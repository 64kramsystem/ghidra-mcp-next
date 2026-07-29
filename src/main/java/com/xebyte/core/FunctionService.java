package com.xebyte.core;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Service for function-related operations: decompilation, renaming, prototype management,
 * variable typing, and function creation/deletion.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
public class FunctionService {

    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;  // Increased from 30s to 60s for large functions

    /** Matches any of the five Windows calling-convention keywords. */
    private static final Pattern CALLING_CONV_PATTERN = Pattern.compile(
            "\\b(__cdecl|__stdcall|__thiscall|__fastcall|__vectorcall)\\b");

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public FunctionService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // Inner classes

    /**
     * Class to hold the result of a prototype setting operation.
     */
    public static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    static record NoReturnUpdateResult(
            boolean functionNoReturn,
            boolean terminalNoReturn) {
    }

    // ========================================================================
    // Decompilation methods
    // ========================================================================

    /**
     * Decompile a function at the given address.
     * If programName is provided, uses that program instead of the current one.
     */
    @McpTool(path = "/decompile_function", description = "Decompile function at address to pseudocode. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response decompileFunctionByAddress(
            @Param(value = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String addressStr,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName,
            @Param(value = "timeout", defaultValue = "60", description = "Decompile timeout in seconds") int timeoutSeconds) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address or function name is required");

        DecompInterface decomp = null;
        try {
            Function func = ServiceUtils.resolveFunction(program, addressStr);
            if (func == null) return Response.err("No function found for " + addressStr);

            decomp = ServiceUtils.createConfiguredDecompiler(program);
            DecompileResults decompResult = decomp.decompileFunction(func, timeoutSeconds, new ConsoleTaskMonitor());

            if (decompResult == null) {
                return Response.err("Decompiler returned null result for function at " + addressStr);
            }

            if (!decompResult.decompileCompleted()) {
                String errorMsg = decompResult.getErrorMessage();
                return Response.err("Decompilation did not complete. " +
                       (errorMsg != null ? "Reason: " + errorMsg : "Function may be too complex or have invalid code flow."));
            }

            if (decompResult.getDecompiledFunction() == null) {
                return Response.err("Decompiler completed but returned null decompiled function.");
            }

            return Response.text(decompResult.getDecompiledFunction().getC());
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("Error decompiling function: " + msg);
        } finally {
            if (decomp != null) {
                try { decomp.dispose(); } catch (Exception ignored) {}
            }
        }
    }

    /** Decompile once for mutation helpers that need a high function. */
    public DecompileResults decompileFunction(Function func, Program program) {
        DecompInterface decomp = null;
        try {
            decomp = ServiceUtils.createConfiguredDecompiler(program);
            return decomp.decompileFunction(
                func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
        } catch (Exception e) {
            Msg.warn(this, "Decompilation failed for " + func.getName()
                + ": " + e.getMessage());
            return null;
        } finally {
            if (decomp != null) {
                try { decomp.dispose(); } catch (Exception ignored) {}
            }
        }
    }


    // ========================================================================
    // Disassembly
    // ========================================================================

    /**
     * Get assembly code for a function.
     * If programName is provided, uses that program instead of the current one.
     */
    @McpTool(path = "/disassemble_function", description = "Get assembly listing of function. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response disassembleFunction(
            @Param(value = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String addressStr,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address is required");

        try {
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) return Response.err(ServiceUtils.getLastParseError());
            Function func = ServiceUtils.getFunctionForAddress(program, addr);
            if (func == null) return Response.err("No function found at or containing address " + addressStr);

            StringBuilder sb = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CommentType.EOL, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                sb.append(String.format("%s: %s %s\n",
                    instr.getAddress(),
                    instr.toString(),
                    comment));
            }

            return Response.text(sb.toString());
        } catch (Exception e) {
            return Response.err("Error disassembling function: " + e.getMessage());
        }
    }

    // ========================================================================
    // Function lookup
    // ========================================================================

    /**
     * Get function by address.
     */
    @McpTool(path = "/get_function_by_address", description = "Get function info at a specific address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response getFunctionByAddress(
            @Param(value = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String addressStr,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address or function name is required");
        }

        try {
            Function func = ServiceUtils.resolveFunction(program, addressStr);
            if (func == null) return Response.err("No function found for " + addressStr);

            return Response.text(String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress()));
        } catch (Exception e) {
            return Response.err("Error getting function: " + e.getMessage());
        }
    }

    // ========================================================================
    // Rename methods
    // ========================================================================


    /**
     * Rename a variable in a function.
     */
    @McpTool(path = "/rename_variable", method = "POST", description = "Rename a variable in a function. Accepts function_name or function_address; address is more stable after recent renames.")
    public Response renameVariableInFunction(
            @Param(value = "function_name", source = ParamSource.BODY, defaultValue = "") String functionName,
            @Param(value = "function_address", source = ParamSource.BODY, defaultValue = "") String functionAddress,
            @Param(value = "old_variable_name", source = ParamSource.BODY) String oldVarName,
            @Param(value = "new_variable_name", source = ParamSource.BODY) String newVarName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if ((functionName == null || functionName.isEmpty()) && (functionAddress == null || functionAddress.isEmpty())) {
            return Response.err("Function name or address is required");
        }

        // function_address may also carry a name, so probe rather than parse: only a
        // value that really is an unqualified, doubly-mapped address is refused.
        String addressAmbiguity =
            ServiceUtils.probeMutationAddressAmbiguity(program, functionAddress);
        if (addressAmbiguity != null) return Response.err(addressAmbiguity);

        DecompInterface decomp = ServiceUtils.createConfiguredDecompiler(program);
        try {
            String functionRef = (functionAddress != null && !functionAddress.isEmpty()) ? functionAddress : functionName;
            Function func = ServiceUtils.resolveFunction(program, functionRef);
            if (func == null) {
                return Response.err("Function not found: " + functionRef);
            }

            DecompileResults result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
            if (result == null || !result.decompileCompleted()) {
                return Response.err("Decompilation failed");
            }

            HighFunction highFunction = result.getHighFunction();
            if (highFunction == null) {
                return Response.err("Decompilation failed (no high function)");
            }

            LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
            if (localSymbolMap == null) {
                return Response.err("Decompilation failed (no local symbol map)");
            }

            HighSymbol highSymbol = null;
            Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                String symbolName = symbol.getName();

                if (symbolName.equals(oldVarName)) {
                    highSymbol = symbol;
                }
                if (symbolName.equals(newVarName)) {
                    return Response.err("A variable with name '" + newVarName + "' already exists in this function");
                }
            }

            if (highSymbol == null) {
                return Response.err("Variable not found: " + oldVarName);
            }

            boolean commitRequired = checkFullCommit(highSymbol, highFunction);

            final HighSymbol finalHighSymbol = highSymbol;
            final HighFunction finalHighFunction = highFunction;
            final Function finalFunction = func;
            AtomicBoolean successFlag = new AtomicBoolean(false);

            threadingStrategy.executeWrite(program, "Rename variable", () -> {
                if (commitRequired) {
                    HighFunctionDBUtil.commitParamsToDatabase(finalHighFunction, false,
                        ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                }
                HighFunctionDBUtil.updateDBVariable(
                    finalHighSymbol,
                    newVarName,
                    null,
                    SourceType.USER_DEFINED
                );
                successFlag.set(true);
                return null;
            });

            if (successFlag.get()) {
                return Response.text("Variable renamed");
            }
        } catch (Exception e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return Response.err(errorMsg);
        } finally {
            decomp.dispose();
        }
        return Response.err("Failed to rename variable");
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
     * Compare the given HighFunction's idea of the prototype with the Function's idea.
     * Return true if there is a difference. If a specific symbol is being changed,
     * it can be passed in to check whether or not the prototype is being affected.
     * @param highSymbol (if not null) is the symbol being modified
     * @param hfunction is the given HighFunction
     * @return true if there is a difference (and a full commit is required)
     */
    public static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }
        Function function = hfunction.getFunction();
        Parameter[] parameters = function.getParameters();
        LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) {
            return true;
        }

        for (int i = 0; i < numParams; i++) {
            HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) {
                return true;
            }
            VariableStorage storage = param.getStorage();
            // Don't compare using the equals method so that DynamicVariableStorage can match
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Rename a function by its address.
     */
    @McpTool(path = "/rename_function_by_address", method = "POST", description = "Rename function at specific address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response renameFunctionByAddress(
            @Param(value = "function_address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String functionAddrStr,
            @Param(value = "new_name", source = ParamSource.BODY) String newName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address or name is required");
        }

        if (newName == null || newName.isEmpty()) {
            return Response.err("New function name is required");
        }

        // function_address may also carry a name, so probe rather than parse: only a
        // value that really is an unqualified, doubly-mapped address is refused.
        String addressAmbiguity =
            ServiceUtils.probeMutationAddressAmbiguity(program, functionAddrStr);
        if (addressAmbiguity != null) return Response.err(addressAmbiguity);

        Function targetFunc = ServiceUtils.resolveFunction(program, functionAddrStr);
        if (targetFunc == null) {
            return Response.err("No function found for " + functionAddrStr);
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeWrite(program, "Rename function by address", () -> {
                String oldName = targetFunc.getName();
                targetFunc.setName(newName, SourceType.USER_DEFINED);
                success.set(true);
                resultMsg.append("Success: Renamed function at ").append(functionAddrStr)
                        .append(" from '").append(oldName).append("' to '").append(newName).append("'");
                return null;
            });
        } catch (Exception e) {
            resultMsg.append("Error: Failed to execute rename on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        String text = resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
        if (success.get()) {
            return Response.ok(JsonHelper.mapOf("status", "success", "message", text));
        }
        return Response.err(text.startsWith("Error: ") ? text.substring(7) : text);
    }

    // ========================================================================
    // Prototype / Signature methods
    // ========================================================================

    /**
     * Extract the function-level calling convention (the token between the return type and
     * the function name) from a C prototype string.
     *
     * <p>Only the substring <em>before</em> the first {@code '('} is scanned so that
     * conventions embedded inside callback parameter types — e.g. the {@code __cdecl} in
     * {@code int __stdcall Foo(void (__cdecl *cb)(int))} — are left intact in the cleaned
     * prototype.
     *
     * @param prototype the raw C prototype string (may be empty or {@code null}-safe)
     * @return a two-element array {@code {convention, cleanedPrototype}} where
     *         {@code convention} is the matched keyword or {@code ""} if none was found,
     *         and {@code cleanedPrototype} has that single occurrence removed and whitespace
     *         normalised.
     */
    public static String[] extractCallingConvention(String prototype) {
        if (prototype == null || prototype.isEmpty()) {
            return new String[]{"", prototype == null ? "" : prototype};
        }
        // Only look at the part before the first '(' so callback-param conventions survive.
        int paren = prototype.indexOf('(');
        String head = paren >= 0 ? prototype.substring(0, paren) : prototype;
        Matcher m = CALLING_CONV_PATTERN.matcher(head);
        if (!m.find()) {
            return new String[]{"", prototype};
        }
        String cc = m.group(1);
        // Remove only this single occurrence from the head; leave the parameter list alone.
        String cleanedHead = head.substring(0, m.start()) + head.substring(m.end());
        String cleaned = paren >= 0 ? cleanedHead + prototype.substring(paren) : cleanedHead;
        return new String[]{cc, cleaned.replaceAll("\\s+", " ").trim()};
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd.
     */
    public PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        return setFunctionPrototype(functionAddrStr, prototype, null, null);
    }

    /**
     * Set a function's prototype with calling convention support (backward compatible).
     */
    public PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype, String callingConvention) {
        return setFunctionPrototype(functionAddrStr, prototype, callingConvention, null);
    }

    /**
     * Set a function's prototype with calling convention and program name support.
     */
    public PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype, String callingConvention, String programName) {
        // Input validation
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return new PrototypeResult(false, pe.error().toJson());
        Program program = pe.program();
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        // v3.0.1 / v5.13.x: Extract inline calling convention from prototype string if present.
        // Handles cases like "void __cdecl MyFunc(int x)" -> prototype="void MyFunc(int x)", cc="__cdecl"
        // The helper only scans before the first '(' so conventions inside callback param types survive.
        String[] ccResult = extractCallingConvention(prototype);
        String cleanPrototype = ccResult[1];
        String resolvedConvention = (callingConvention != null && !callingConvention.isEmpty())
                ? callingConvention : ccResult[0];
        if (!ccResult[0].isEmpty()) {
            Msg.info(this, "Extracted calling convention '" + ccResult[0] + "' from prototype string");
        }
        final String finalPrototype = cleanPrototype;
        final String finalConvention = resolvedConvention;

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeRead(() -> {
                applyFunctionPrototype(program, functionAddrStr, finalPrototype, finalConvention, success, errorMessage);
                return null;
            });
        } catch (Exception e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Endpoint wrapper for setFunctionPrototype that converts PrototypeResult to Response.
     */
    @McpTool(path = "/set_function_prototype", method = "POST", description = "Set function prototype (return type, parameter types, calling convention) by address. NOTE: the function name in the prototype string is used only for parsing — it does NOT rename the function. To rename, call rename_function_by_address separately. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response setFunctionPrototypeEndpoint(
            @Param(value = "function_address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String functionAddress,
            @Param(value = "prototype", source = ParamSource.BODY) String prototype,
            @Param(value = "calling_convention", source = ParamSource.BODY, defaultValue = "") String callingConvention,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        PrototypeResult result = setFunctionPrototype(functionAddress, prototype, callingConvention, programName);
        if (result.isSuccess()) {
            String msg = "Successfully set prototype for function at " + functionAddress;
            if (callingConvention != null && !callingConvention.isEmpty()) {
                msg += " with " + callingConvention + " calling convention";
            }
            // Warn about __thiscall ECX auto-param limitation
            String cc = callingConvention != null ? callingConvention : "";
            boolean protoHasThiscall = prototype != null && (prototype.contains("__thiscall") || cc.contains("__thiscall"));
            if (protoHasThiscall && prototype != null && !prototype.contains("void *this") && !prototype.contains("void * this")) {
                msg += "\n\nNOTE: For __thiscall/__fastcall member functions, also call set_function_this_type "
                     + "with the concrete struct/class pointer (e.g. MyWidget *) so the decompiler "
                     + "uses typed 'this' field access instead of void*.";
            }
            if (!result.getErrorMessage().isEmpty()) {
                msg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
            }
            return Response.text(msg);
        } else {
            return Response.err("Failed to set function prototype: " + result.getErrorMessage());
        }
    }

    /**
     * Helper method that applies the function prototype within a transaction.
     * v3.0.1: Preserves existing plate comment across prototype changes.
     */
    void applyFunctionPrototype(Program program, String functionAddrStr, String prototype,
                                       String callingConvention, AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = ServiceUtils.parseMutationAddress(program, functionAddrStr);
            if (addr == null) {
                String msg = ServiceUtils.getLastParseError();
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }
            Function func = ServiceUtils.getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // v3.0.1: Save existing plate comment before prototype change (which may wipe it)
            String savedPlateComment = func.getComment();

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, callingConvention, success, errorMessage);

            // v3.0.1: Restore plate comment if it was wiped by prototype change
            if (savedPlateComment != null && !savedPlateComment.isEmpty()) {
                String currentComment = func.getComment();
                if (currentComment == null || currentComment.isEmpty() ||
                    currentComment.startsWith("Setting prototype:")) {
                    int txRestore = program.startTransaction("Restore plate comment after prototype");
                    try {
                        func.setComment(savedPlateComment);
                        Msg.info(this, "Restored plate comment after prototype change for " + func.getName());
                    } finally {
                        program.endTransaction(txRestore, true);
                    }
                }
            }

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Parse and apply the function signature with error handling.
     */
    void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              String callingConvention, AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        boolean signatureApplied = false;
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Create function signature parser without DataTypeManagerService
            // to prevent UI dialogs from popping up (pass null instead of dtms)
            ghidra.app.util.parser.FunctionSignatureParser parser =
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, null);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                signatureApplied = true;
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, signatureApplied);
        }

        // Apply calling convention in a SEPARATE transaction after signature is committed
        // This ensures the calling convention isn't overridden by ApplyFunctionSignatureCmd
        if (signatureApplied && callingConvention != null && !callingConvention.isEmpty()) {
            int txConv = program.startTransaction("Set calling convention");
            boolean conventionApplied = false;
            try {
                conventionApplied = applyCallingConvention(program, addr, callingConvention, errorMessage);
                if (conventionApplied) {
                    success.set(true);
                } else {
                    success.set(false);  // Fail if calling convention couldn't be applied
                }
            } catch (Exception e) {
                String msg = "Error in calling convention transaction: " + e.getMessage();
                errorMessage.append(msg);
                Msg.error(this, msg, e);
                success.set(false);
            } finally {
                program.endTransaction(txConv, conventionApplied);
            }
        } else if (signatureApplied) {
            success.set(true);
        }
    }

    /**
     * Apply a calling convention to a function at the given address.
     */
    public boolean applyCallingConvention(Program program, Address addr, String callingConvention, StringBuilder errorMessage) {
        try {
            Function func = ServiceUtils.getFunctionForAddress(program, addr);
            if (func == null) {
                errorMessage.append("Could not find function to set calling convention");
                return false;
            }

            // Get the program's calling convention manager
            ghidra.program.model.lang.CompilerSpec compilerSpec = program.getCompilerSpec();
            ghidra.program.model.lang.PrototypeModel callingConv = null;

            // Get all available calling conventions
            ghidra.program.model.lang.PrototypeModel[] available = compilerSpec.getCallingConventions();

            // Try to find matching calling convention by name
            String targetName = callingConvention.toLowerCase();
            for (ghidra.program.model.lang.PrototypeModel model : available) {
                String modelName = model.getName().toLowerCase();
                if (modelName.equals(targetName) ||
                    modelName.equals("__" + targetName) ||
                    modelName.replace("__", "").equals(targetName.replace("__", ""))) {
                    callingConv = model;
                    break;
                }
            }

            if (callingConv != null) {
                func.setCallingConvention(callingConv.getName());
                Msg.info(this, "Set calling convention to: " + callingConv.getName());
                return true;  // Successfully applied
            } else {
                String msg = "Unknown calling convention: " + callingConvention + ". ";
                // List available calling conventions for debugging
                StringBuilder availList = new StringBuilder("Available calling conventions: ");
                for (ghidra.program.model.lang.PrototypeModel model : available) {
                    availList.append(model.getName()).append(", ");
                }
                String availMsg = availList.toString();
                msg += availMsg;

                errorMessage.append(msg);
                Msg.warn(this, msg);
                Msg.info(this, availMsg);

                return false;  // Convention not found
            }

        } catch (Exception e) {
            String msg = "Error setting calling convention: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
            return false;
        }
    }

    // ========================================================================
    // Variable type methods
    // ========================================================================

    /**
     * Build the decompiler-default-name guidance appended to a "variable not found"
     * error from set_variable_type. Pure function of the requested name and the
     * current high-symbol names, so it is unit-testable without a live decompile.
     *
     * <p>Ghidra default names follow {@code <prefix>Var<digits>} (uVar1, puVar3, iVar5,
     * psVar7, ...). When such a name misses, there are two recoverable causes:
     * <ul>
     *   <li><b>SSA-renumber drift</b> — same-prefix default names still exist but with
     *       different digits, because a previous set_variable_type call re-decompiled
     *       and renumbered the temporaries. Fix: decompile again before the next edit.</li>
     *   <li><b>Renamed-away / register-resident</b> — no default-named variables remain at
     *       all (they were renamed, or the function is register/SIMD-heavy so Ghidra names
     *       them local_&lt;REG&gt;_*). The caller is working from a stale decompilation. Fix:
     *       re-decompile for current names.</li>
     * </ul>
     *
     * @return the hint sentence (with trailing space), or "" when no hint applies.
     */
    public static String buildVariableNameHint(String variableName, List<String> availableNames) {
        if (variableName == null || !variableName.matches("^[a-z]+Var\\d+$")) {
            return "";
        }
        if (availableNames == null) {
            availableNames = java.util.Collections.emptyList();
        }
        String prefix = variableName.replaceAll("\\d+$", "");
        boolean hasSamePrefix = availableNames.stream()
                .anyMatch(n -> n != null && n.startsWith(prefix) && n.matches("^[a-z]+Var\\d+$"));
        if (hasSamePrefix) {
            return "Hint: this looks like SSA-renumber drift from a previous "
                    + "set_variable_type call in the same function. "
                    + "Call decompile_function again and use the current variable name. ";
        }
        boolean hasAnyDefaultName = availableNames.stream()
                .anyMatch(n -> n != null && n.matches("^[a-z]+Var\\d+$"));
        if (!hasAnyDefaultName) {
            return "Hint: '" + variableName + "' is a Ghidra decompiler default name, but no "
                    + "default-named (uVarN/iVarN/puVarN) variables remain in this function — "
                    + "they have been renamed already, or the variables are register-resident "
                    + "(e.g. local_ESI_*, local_MM*) in a register/SIMD-heavy function. You are "
                    + "likely working from a stale decompilation: call decompile_function and use "
                    + "a current name from the Available list, then retry. ";
        }
        return "";
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable.
     */
    @McpTool(path = "/set_variable_type", method = "POST", description = "Set the data type of a local variable or parameter. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response setLocalVariableType(
            @Param(value = "function_address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String functionAddrStr,
            @Param(value = "variable_name", source = ParamSource.BODY) String variableName,
            @Param(value = "new_type", source = ParamSource.BODY) String newType,
            @Param(value = "program", defaultValue = "") String programName) {
        // Input validation
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }

        if (variableName == null || variableName.isEmpty()) {
            return Response.err("Variable name is required");
        }

        if (newType == null || newType.isEmpty()) {
            return Response.err("New type is required");
        }

        // Reject undefined -> undefined (no improvement)
        if (newType.startsWith("undefined")) {
            return Response.err("Rejected: new type '" + newType + "' is still undefined. "
                    + "Resolve to a concrete type: byte, ushort, int, uint, void *, etc.");
        }

        // Resolve address before entering threading lambda
        Address addr = ServiceUtils.parseMutationAddress(program, functionAddrStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeRead(() -> {
                try {
                    // Find the function
                    Function func = ServiceUtils.getFunctionForAddress(program, addr);
                    if (func == null) {
                        resultMsg.append("Error: No function found at address ").append(functionAddrStr);
                        return null;
                    }

                    DecompileResults results = decompileFunction(func, program);
                    if (results == null || !results.decompileCompleted()) {
                        resultMsg.append("Error: Decompilation failed for function at ").append(functionAddrStr);
                        return null;
                    }

                    ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
                    if (highFunction == null) {
                        resultMsg.append("Error: No high function available");
                        return null;
                    }

                    // Find the symbol by name
                    HighSymbol symbol = findSymbolByName(highFunction, variableName);
                    if (symbol == null) {
                        // PRIORITY 2 FIX: Provide helpful diagnostic information
                        resultMsg.append("Error: Variable '").append(variableName)
                                .append("' not found in decompiled function. ");

                        // List available variables for user guidance
                        List<String> availableNames = new ArrayList<>();
                        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                        while (symbols.hasNext()) {
                            availableNames.add(symbols.next().getName());
                        }

                        if (!availableNames.isEmpty()) {
                            resultMsg.append("Available variables: ")
                                    .append(String.join(", ", availableNames))
                                    .append(". ");
                        }

                        // Decompiler-default-name guidance (SSA churn / renamed-away /
                        // register-resident). Pure function of the requested name + the
                        // available high-symbol names — see buildVariableNameHint.
                        resultMsg.append(buildVariableNameHint(variableName, availableNames));

                        // Check if variable exists in low-level API but not high-level (phantom variable)
                        Variable[] lowLevelVars = func.getLocalVariables();
                        boolean isPhantomVariable = false;
                        for (Variable v : lowLevelVars) {
                            if (v.getName().equals(variableName)) {
                                isPhantomVariable = true;
                                break;
                            }
                        }

                        if (isPhantomVariable) {
                            resultMsg.append("NOTE: Variable '").append(variableName)
                                    .append("' exists in stack frame but not in decompiled code. ")
                                    .append("This is a phantom variable created by Ghidra's stack analysis ")
                                    .append("that was optimized away during decompilation. ")
                                    .append("You cannot set the type of phantom variables. ")
                                    .append("Only variables visible in the decompiled code can be typed.");
                        }

                        return null;
                    }

                    // Get high variable -- may be null for EBP-pinned / SSA-only symbols.
                    // updateDBVariable works without a HighVariable (rename path proves this),
                    // so we skip the null guard and fall through to updateVariableType directly.
                    HighVariable highVar = symbol.getHighVariable();
                    String oldType = highVar != null
                        ? highVar.getDataType().getName()
                        : symbol.getDataType().getName();

                    // Find the data type
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = ServiceUtils.resolveDataType(dtm, newType);

                    if (dataType == null) {
                        resultMsg.append("Error: Could not resolve data type: ").append(newType);
                        // Provide actionable hint for pointer types
                        if (newType.endsWith("*")) {
                            String baseTypeName = newType.substring(0, newType.length() - 1).trim();
                            if (!baseTypeName.isEmpty() && !baseTypeName.equals("void")) {
                                resultMsg.append(". Hint: struct '").append(baseTypeName)
                                    .append("' does not exist. Create it first with create_struct(name=\"")
                                    .append(baseTypeName).append("\", fields=[...]), then retry set_variable_type.");
                            }
                        }
                        return null;
                    }

                    // Apply the type change in a transaction
                    StringBuilder errorDetails = new StringBuilder();
                    if (updateVariableType(program, symbol, dataType, success, errorDetails)) {
                        resultMsg.append("Success: Changed type of variable '").append(variableName)
                                .append("' from '").append(oldType).append("' to '")
                                .append(dataType.getName()).append("'")
                                .append(". WARNING: Type changes trigger re-decompilation which may create new SSA variables. ")
                                .append("Call get_function_variables after all type changes to discover any new variables.");
                    } else {
                        // Provide detailed error message including storage location
                        String storageInfo = "unknown";
                        try {
                            storageInfo = symbol.getStorage().toString();
                        } catch (Exception e) {
                            // If we can't get storage, continue without it
                        }

                        resultMsg.append("Error: Failed to update variable type for '").append(variableName).append("'");
                        resultMsg.append(" (Storage: ").append(storageInfo).append(")");

                        if (errorDetails.length() > 0) {
                            resultMsg.append(". Details: ").append(errorDetails.toString());
                        }

                        // Add helpful guidance for known limitations
                        if (storageInfo.startsWith("Stack[-") && storageInfo.contains(":4")) {
                            resultMsg.append(". Note: Stack-based local variables with 4-byte size may have type-setting limitations in Ghidra's API");
                        }
                    }

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error setting variable type", e);
                }
                return null;
            });
        } catch (Exception e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        String text = resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
        if (success.get()) {
            return Response.ok(JsonHelper.mapOf("status", "success", "message", text));
        }
        return Response.err(text.startsWith("Error: ") ? text.substring(7) : text);
    }

    /**
     * Retype the implicit {@code this} pointer for {@code __thiscall} / {@code __fastcall} member
     * functions so decompilation shows {@code this->field} with the correct struct/class type.
     */
    @McpTool(path = "/set_function_this_type", method = "POST",
            description = "Type the implicit 'this' of a __thiscall/__fastcall member function by associating the function with its class. Ghidra's auto-'this' (ECX on x86) is an immutable auto-parameter; with auto-storage it derives its type from the function's parent Class namespace, matched by name to a same-named structure. This tool finds/creates a class namespace for the struct and moves the function into it (no custom storage). Pass 'MyClass *' or 'MyClass'; the structure MyClass must already exist (create_struct). On programs with multiple address spaces, prefix function_address with the space name (mem:1000).")
    public Response setFunctionThisType(
            @Param(value = "function_address", source = ParamSource.BODY,
                   description = "Function entry address (0x<hex> or <space>:<hex>).") String functionAddrStr,
            @Param(value = "this_type", source = ParamSource.BODY,
                   description = "Class type for this, e.g. 'MyWidget *' or 'MyWidget'. The base struct name becomes the function's class.") String thisType,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }
        if (thisType == null || thisType.isEmpty()) {
            return Response.err("this_type is required");
        }
        if (thisType.startsWith("undefined")) {
            return Response.err("Rejected: this_type must be a concrete struct/class pointer, not " + thisType);
        }

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address addr = ServiceUtils.parseMutationAddress(program, functionAddrStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeWrite(program, "Associate function with class for 'this'", () -> {
                Function func = ServiceUtils.getFunctionForAddress(program, addr);
                if (func == null) {
                    resultMsg.append("Error: No function found at ").append(functionAddrStr);
                    return null;
                }

                // The this_type names the owning class. Its base must be an existing structure,
                // because Ghidra derives the auto-'this' type from a class namespace that is
                // associated by name with a same-named struct.
                DataTypeManager dtm = program.getDataTypeManager();
                DataType pointerType = resolveThisPointerType(dtm, thisType);
                if (!(pointerType instanceof Pointer)) {
                    resultMsg.append("Error: Could not resolve this_type '").append(thisType)
                            .append("' to a pointer. Create the structure first with create_struct, then retry.");
                    return null;
                }
                DataType base = ((Pointer) pointerType).getDataType();
                if (!(base instanceof Structure)) {
                    resultMsg.append("Error: 'this' must point to a structure/class type; '")
                            .append(base != null ? base.getName() : "void")
                            .append("' is not a structure. Ghidra derives the 'this' type from a same-named struct.");
                    return null;
                }
                String className = base.getName();

                // The member function must already have an implicit 'this'; that only exists for a
                // hasThis convention (__thiscall/__fastcall). Bail out before mutating anything so
                // non-member functions are not silently re-parented into a class.
                Parameter thisParam = findAutoThisParameter(func);
                if (thisParam == null) {
                    String cc;
                    try {
                        cc = func.getCallingConventionName();
                    } catch (Exception ignored) {
                        cc = "";
                    }
                    resultMsg.append("Error: ").append(func.getName())
                            .append(" has no implicit 'this' parameter (calling convention '")
                            .append(cc == null || cc.isEmpty() ? "(default)" : cc)
                            .append("'). Set it to __thiscall with set_function_prototype, then retry.");
                    return null;
                }

                // Auto-parameters are immutable via the API; the 'this' auto-parameter instead
                // obtains its type from the function's parent Class namespace (auto-storage). So we
                // place the function in a GhidraClass named after the struct rather than retyping
                // 'this' directly. This is the same model as the decompiler's "Auto Fill in Class
                // Structure" / re-parenting via the Symbol Tree — no custom storage required.
                SymbolTable st = program.getSymbolTable();
                Namespace global = program.getGlobalNamespace();
                GhidraClass classNs;
                Namespace existing = st.getNamespace(className, global);
                if (existing == null) {
                    classNs = st.createClass(global, className, SourceType.USER_DEFINED);
                } else if (existing instanceof GhidraClass) {
                    classNs = (GhidraClass) existing;
                } else {
                    classNs = st.convertNamespaceToClass(existing);
                }

                Namespace currentNs = func.getParentNamespace();
                boolean alreadyInClass = currentNs instanceof GhidraClass
                        && className.equals(currentNs.getName());
                if (!alreadyInClass) {
                    func.getSymbol().setNamespace(classNs);
                }

                // Re-read the auto-'this' so we report the type Ghidra now derives from the class.
                thisParam = findAutoThisParameter(func);
                DataType resolvedThis = thisParam != null ? thisParam.getDataType() : pointerType;
                String resolvedName = resolvedThis != null ? resolvedThis.getDisplayName() : (className + " *");
                success.set(true);
                resultMsg.append(alreadyInClass ? "Confirmed " : "Moved ").append(func.getName())
                        .append(alreadyInClass ? " in class " : " into class ").append(className)
                        .append("; 'this' types as ").append(resolvedName)
                        .append(" (auto-storage). Call decompile_function to refresh output.");
                return null;
            });
        } catch (Exception e) {
            return Response.err("set_function_this_type failed: " + e.getMessage());
        }

        if (success.get()) {
            return Response.ok(JsonHelper.mapOf("status", "success", "message", resultMsg.toString()));
        }
        String text = resultMsg.length() > 0 ? resultMsg.toString() : "Failed to set 'this' type";
        return Response.err(text.startsWith("Error: ") ? text.substring(7) : text);
    }

    /** Locate the implicit {@code this} (auto-parameter or explicit) on a member function. */
    static Parameter findAutoThisParameter(Function func) {
        if (func == null) {
            return null;
        }
        for (Parameter param : func.getParameters()) {
            if (param.isAutoParameter() && param.getAutoParameterType() == AutoParameterType.THIS) {
                return param;
            }
            if ("this".equals(param.getName())) {
                return param;
            }
        }
        return null;
    }

    static DataType resolveThisPointerType(DataTypeManager dtm, String thisType) {
        if (dtm == null) {
            return null;
        }
        String normalized = thisType.trim();
        if (normalized.isEmpty()) {
            return null;
        }
        if (!normalized.contains("*")) {
            normalized = normalized + " *";
        }
        return ServiceUtils.resolveDataType(dtm, normalized);
    }

    private static HighSymbol findSymbolByName(
            HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols =
            highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            if (symbol.getName().equals(variableName)) {
                return symbol;
            }
        }
        return null;
    }

    private static boolean updateVariableType(
            Program program,
            HighSymbol symbol,
            DataType dataType,
            AtomicBoolean success,
            StringBuilder errorDetails) {
        try {
            HighFunctionDBUtil.updateDBVariable(
                symbol, symbol.getName(), dataType, SourceType.USER_DEFINED);
            success.set(true);
            return true;
        } catch (Exception error) {
            if (errorDetails != null) {
                errorDetails.append(error.getMessage());
            }
            return false;
        }
    }

    static NoReturnUpdateResult setNoReturnState(Function function, boolean noReturn) {
        List<Function> chain = new ArrayList<>();
        Function current = function;

        while (true) {
            chain.add(current);
            Function directTarget = current.getThunkedFunction(false);
            if (directTarget == null) {
                break;
            }

            if (current.hasNoReturn() != noReturn) {
                boolean detached = false;
                try {
                    current.setThunkedFunction(null);
                    detached = true;
                    current.setNoReturn(noReturn);
                } finally {
                    if (detached) {
                        current.setThunkedFunction(directTarget);
                    }
                }
            }

            current = directTarget;
        }

        Function terminal = current;
        terminal.setNoReturn(noReturn);

        for (Function candidate : chain) {
            boolean actual = candidate.hasNoReturn();
            if (actual != noReturn) {
                throw new IllegalStateException(
                    "No-return state did not persist for function " + candidate.getName()
                        + ": expected " + noReturn + ", actual " + actual);
            }
        }

        return new NoReturnUpdateResult(
            function.hasNoReturn(),
            terminal.hasNoReturn());
    }

    /**
     * Set a function's "No Return" attribute.
     *
     * This method controls whether Ghidra treats a function as non-returning (like exit(), abort(), etc.).
     * When a function is marked as non-returning:
     * - Call sites are treated as terminators (CALL_TERMINATOR)
     * - Decompiler doesn't show code execution continuing after the call
     * - Control flow analysis treats the call like a RET instruction
     *
     * @param functionAddrStr The function address in hex format (e.g., "0x401000")
     * @param noReturn true to mark as non-returning, false to mark as returning
     * @return Success or error message
     */
    @McpTool(path = "/set_function_no_return", method = "POST", description = "Mark function as no-return. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response setFunctionNoReturn(
            @Param(value = "function_address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String functionAddrStr,
            @Param(value = "no_return", source = ParamSource.BODY) boolean noReturn,
            @Param(value = "program", defaultValue = "") String programName) {
        // Input validation
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }

        // Resolve address before entering threading lambda
        Address addr = ServiceUtils.parseMutationAddress(program, functionAddrStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<NoReturnUpdateResult> verifiedResult = new AtomicReference<>();

        try {
            threadingStrategy.executeWrite(program, "Set function no return", () -> {

                Function func = ServiceUtils.getFunctionForAddress(program, addr);
                if (func == null) {
                    resultMsg.append("Error: No function found at address ").append(functionAddrStr);
                    return null;
                }

                String oldState = func.hasNoReturn() ? "non-returning" : "returning";

                NoReturnUpdateResult verified = setNoReturnState(func, noReturn);
                String newState = verified.functionNoReturn() ? "non-returning" : "returning";
                verifiedResult.set(verified);
                success.set(true);

                resultMsg.append("Success: Set function '").append(func.getName())
                        .append("' at ").append(functionAddrStr)
                        .append(" from ").append(oldState)
                        .append(" to ").append(newState);

                Msg.info(this, "Set no-return=" + noReturn + " for function " + func.getName() + " at " + functionAddrStr);
                return null;
            });
        } catch (Exception e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute set no-return on Swing thread", e);
        }

        String text = resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
        if (success.get()) {
            NoReturnUpdateResult verified = verifiedResult.get();
            return Response.ok(JsonHelper.mapOf(
                "status", "success",
                "message", text,
                "function_no_return", verified.functionNoReturn(),
                "terminal_no_return", verified.terminalNoReturn()));
        }
        return Response.err(text.startsWith("Error: ") ? text.substring(7) : text);
    }

    // ========================================================================
    // Function variables query
    // ========================================================================

    @McpTool(path = "/get_function_variables",
        description = "List the parameters and local variables of a function")
    public Response getFunctionVariables(
            @Param(value = "address")
                String addressText,
            @Param(value = "program", defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved =
            ServiceUtils.getProgramOrError(programProvider, programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Program program = resolved.program();
        Address address = ServiceUtils.parseAddress(program, addressText);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }
        try {
            return threadingStrategy.executeRead(() -> {
                Function function =
                    ServiceUtils.getFunctionForAddress(program, address);
                if (function == null) {
                    return Response.err("No function contains " + addressText);
                }
                List<Map<String, Object>> parameters = new ArrayList<>();
                for (Parameter parameter : function.getParameters()) {
                    parameters.add(variableRecord(parameter));
                }
                List<Map<String, Object>> locals = new ArrayList<>();
                for (Variable local : function.getLocalVariables()) {
                    locals.add(variableRecord(local));
                }
                return Response.ok(JsonHelper.mapOf(
                    "function", function.getName(true),
                    "address", function.getEntryPoint().toString(),
                    "parameters", parameters,
                    "locals", locals));
            });
        } catch (Exception error) {
            return Response.err("Could not list variables: " + error.getMessage());
        }
    }

    private static Map<String, Object> variableRecord(Variable variable) {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("name", variable.getName());
        record.put("type", variable.getDataType().getPathName());
        record.put("storage", variable.getVariableStorage().toString());
        if (variable instanceof Parameter parameter) {
            record.put("ordinal", parameter.getOrdinal());
        }
        return record;
    }


    // ========================================================================
    // Function creation / deletion
    // ========================================================================

    /**
     * Delete a function at the given address.
     */
    @McpTool(path = "/delete_function", method = "POST", description = "Delete function at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response deleteFunctionAtAddress(
            @Param(value = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String addressStr,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter required");
        }

        // Resolve address before entering threading lambda
        Address addr = ServiceUtils.parseMutationAddress(program, addressStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>(null);
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            threadingStrategy.executeWrite(program, "Delete function at address", () -> {

                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    errorMsg.set("No function found at address " + addressStr);
                    return null;
                }

                String funcName = func.getName();
                long bodySize = func.getBody().getNumAddresses();
                program.getFunctionManager().removeFunction(addr);

                Map<String, Object> delResult = new LinkedHashMap<>();
                delResult.put("success", true);
                delResult.putAll(ServiceUtils.addressToJson(addr, program));
                delResult.put("deleted_function", funcName);
                delResult.put("body_size", bodySize);
                delResult.put("message", "Function '" + funcName + "' deleted at " + addr);
                resultData.set(delResult);
                return null;
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("Failed to execute on Swing thread: " + msg);
        }

        if (resultData.get() != null) {
            return Response.ok(resultData.get());
        }
        return Response.err("Unknown failure");
    }

    /**
     * Create a function at the given address.
     */
    @McpTool(path = "/create_function", method = "POST", description = "Create function at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response createFunctionAtAddress(
            @Param(value = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String addressStr,
            @Param(value = "name", source = ParamSource.BODY, defaultValue = "") String name,
            @Param(value = "disassemble_first", source = ParamSource.BODY, defaultValue = "true") boolean disassembleFirst,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter required");
        }

        // Resolve address before entering threading lambda
        Address addr = ServiceUtils.parseMutationAddress(program, addressStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>(null);
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            threadingStrategy.executeWrite(program, "Create function at address", () -> {

                // Check if a function already exists at this address
                Function existing = program.getFunctionManager().getFunctionAt(addr);
                if (existing != null) {
                    errorMsg.set("Function already exists at " + addressStr + ": " + existing.getName());
                    return null;
                }

                // Optionally disassemble first
                if (disassembleFirst) {
                    if (program.getListing().getInstructionAt(addr) == null) {
                        AddressSet addrSet = new AddressSet(addr, addr);
                        ghidra.app.cmd.disassemble.DisassembleCommand disCmd =
                            new ghidra.app.cmd.disassemble.DisassembleCommand(addrSet, null, true);
                        if (!disCmd.applyTo(program, ghidra.util.task.TaskMonitor.DUMMY)) {
                            errorMsg.set("Failed to disassemble at " + addressStr + ": " + disCmd.getStatusMsg());
                            return null;
                        }
                    }
                }

                // Create the function using CreateFunctionCmd
                ghidra.app.cmd.function.CreateFunctionCmd cmd =
                    new ghidra.app.cmd.function.CreateFunctionCmd(addr);
                if (!cmd.applyTo(program, ghidra.util.task.TaskMonitor.DUMMY)) {
                    errorMsg.set("Failed to create function at " + addressStr + ": " + cmd.getStatusMsg());
                    return null;
                }

                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    errorMsg.set("Function creation reported success but function not found at " + addressStr);
                    return null;
                }

                // Optionally rename the function
                if (name != null && !name.isEmpty()) {
                    func.setName(name, SourceType.USER_DEFINED);
                }

                Map<String, Object> createResult = new LinkedHashMap<>();
                createResult.put("success", true);
                createResult.putAll(ServiceUtils.addressToJson(addr, program));
                createResult.put("function_name", func.getName());
                Address ep = func.getEntryPoint();
                createResult.put("entry_point", ep.toString(false));
                if (ServiceUtils.getPhysicalSpaceCount(program) > 1) {
                    createResult.put("entry_point_full", ep.toString());
                    createResult.put("entry_point_space", ep.getAddressSpace().getName());
                }
                createResult.put("body_size", func.getBody().getNumAddresses());
                createResult.put("message", "Function created successfully at " + addr);
                resultData.set(createResult);
                return null;
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("Failed to execute on Swing thread: " + msg);
        }

        if (resultData.get() != null) {
            return Response.ok(resultData.get());
        }
        return Response.err("Unknown failure");
    }

}
