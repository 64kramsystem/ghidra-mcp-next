package com.xebyte.core;

import ghidra.app.util.template.TemplateSimplifier;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.math.BigInteger;
import java.util.*;

/**
 * Service for cross-reference and call graph operations: xrefs to/from, function callees/callers,
 * call graph traversal, cycle detection, path finding, and bulk xref analysis.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
@McpToolGroup(value = "xref", description = "Cross-references, call graphs, incoming/outgoing calls, data refs")
public class XrefCallGraphService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public XrefCallGraphService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // -----------------------------------------------------------------------
    // Xref Methods
    // -----------------------------------------------------------------------

    /**
     * Get all references to a specific address (xref to)
     */
    @McpTool(path = "/get_xrefs_to", description = "Get cross-references to an address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "xref")
    public Response getXrefsTo(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address is required");

        try {
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) return Response.err(ServiceUtils.getLastParseError());
            ReferenceManager refManager = program.getReferenceManager();

            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            int pageOffset = Math.max(0, offset);
            int pageLimit = Math.max(0, limit);
            long requested = (long) pageOffset + pageLimit;
            int horizon = (int) Math.min(Integer.MAX_VALUE, requested);
            if (horizon == 0) {
                return Response.text("");
            }
            List<Reference> references =
                ReferenceOrdering.takeStored(refIter, horizon);

            List<String> refs = new ArrayList<>();
            int pageEnd = Math.min(references.size(), horizon);
            for (Reference ref :
                    references.subList(Math.min(pageOffset, references.size()), pageEnd)) {
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }

            // Return meaningful message if no references found
            if (references.isEmpty() && pageOffset == 0) {
                return Response.text("No references found to address: " + addressStr);
            }

            return Response.text(String.join("\n", refs));
        } catch (Exception e) {
            return Response.err("Error getting references to address: " + e.getMessage());
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    @McpTool(path = "/get_xrefs_from", description = "Get cross-references from an address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "xref")
    public Response getXrefsFrom(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address is required");

        try {
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) return Response.err(ServiceUtils.getLastParseError());
            ReferenceManager refManager = program.getReferenceManager();

            Reference[] references = refManager.getReferencesFrom(addr);

            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();

                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }

                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }

            // Return meaningful message if no references found
            if (refs.isEmpty()) {
                return Response.text("No references found from address: " + addressStr);
            }

            return Response.text(ServiceUtils.paginateList(refs, offset, limit));
        } catch (Exception e) {
            return Response.err("Error getting references from address: " + e.getMessage());
        }
    }

    /**
     * Create a user-defined memory cross-reference that the analyzer could not infer
     * (e.g. runtime-populated dispatch tables, late-bound function pointers, missed jump tables).
     */
    @McpTool(path = "/add_memory_reference", method = "POST",
            description = "Create a cross-reference between two memory addresses that the auto-analyzer "
                        + "can't infer (runtime-populated pointer tables, vtables, late-bound function "
                        + "pointers, missed jump/switch tables). Leaves the underlying bytes untouched and "
                        + "adds proper bidirectional navigation. On programs with multiple address spaces "
                        + "(e.g. embedded targets), prefix addresses with the space name (mem:1000).",
            category = "xref")
    public Response addMemoryReference(
            @Param(value = "from_address", paramType = "address", source = ParamSource.BODY,
                   description = "Source address the reference originates from (the table slot / instruction). "
                               + "Accepts 0x<hex> or <space>:<hex> (e.g. mem:1000).") String fromAddressStr,
            @Param(value = "to_address", paramType = "address", source = ParamSource.BODY,
                   description = "Target address the reference points to. Accepts 0x<hex> or <space>:<hex>.") String toAddressStr,
            @Param(value = "ref_type", source = ParamSource.BODY, defaultValue = "DATA",
                   description = "Reference type (case-insensitive RefType name): DATA, READ, WRITE, READ_WRITE, "
                               + "COMPUTED_CALL, UNCONDITIONAL_CALL, COMPUTED_JUMP, UNCONDITIONAL_JUMP, "
                               + "CONDITIONAL_JUMP, INDIRECTION, etc.") String refTypeStr,
            @Param(value = "source_type", source = ParamSource.BODY, defaultValue = "USER_DEFINED",
                   description = "SourceType: USER_DEFINED (default — distinct from analyzer refs and survives "
                               + "re-analysis), ANALYSIS, IMPORTED, DEFAULT.") String sourceTypeStr,
            @Param(value = "operand_index", source = ParamSource.BODY, defaultValue = "-1",
                   description = "Operand index the reference attaches to. -1 = mnemonic/data operand.") int operandIndex,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (fromAddressStr == null || fromAddressStr.isEmpty()) return Response.err("from_address is required");
        if (toAddressStr == null || toAddressStr.isEmpty()) return Response.err("to_address is required");

        Address fromAddr = ServiceUtils.parseAddress(program, fromAddressStr);
        if (fromAddr == null) return Response.err("from_address: " + ServiceUtils.getLastParseError());
        Address toAddr = ServiceUtils.parseAddress(program, toAddressStr);
        if (toAddr == null) return Response.err("to_address: " + ServiceUtils.getLastParseError());

        RefType refType = resolveMemoryRefType(refTypeStr);
        if (refType == null) {
            return Response.err("Unknown ref_type '" + refTypeStr + "'. Valid names include: "
                    + "DATA, READ, WRITE, READ_WRITE, COMPUTED_CALL, UNCONDITIONAL_CALL, CONDITIONAL_CALL, "
                    + "COMPUTED_JUMP, UNCONDITIONAL_JUMP, CONDITIONAL_JUMP, INDIRECTION");
        }
        SourceType sourceType;
        try {
            sourceType = SourceType.valueOf(sourceTypeStr == null ? "" : sourceTypeStr.trim().toUpperCase(Locale.ROOT));
        } catch (Exception e) {
            return Response.err("Unknown source_type '" + sourceTypeStr
                    + "'. Valid values: USER_DEFINED, ANALYSIS, IMPORTED, DEFAULT.");
        }

        try {
            return threadingStrategy.executeWrite(program, "Add memory reference", () -> {
                ReferenceManager refMgr = program.getReferenceManager();
                Reference ref = refMgr.addMemoryReference(fromAddr, toAddr, refType, sourceType, operandIndex);
                if (ref == null) {
                    return Response.err("Failed to create reference from " + fromAddr + " to " + toAddr);
                }
                return Response.ok(JsonHelper.mapOf(
                        "status", "success",
                        "from_address", fromAddr.toString(),
                        "to_address", toAddr.toString(),
                        "ref_type", refType.getName(),
                        "source_type", sourceType.toString(),
                        "operand_index", operandIndex,
                        "is_primary", ref.isPrimary()));
            });
        } catch (Exception e) {
            return Response.err("Error adding memory reference: " + e.getMessage());
        }
    }

    /**
     * Remove memory cross-reference(s) between two addresses — the inverse of
     * {@link #addMemoryReference}. Useful for clearing references the analyzer got wrong
     * or for undoing a manual reference.
     */
    @McpTool(path = "/remove_reference", method = "POST",
            description = "Remove memory cross-reference(s) from one address to another (the inverse of "
                        + "add_memory_reference). Removes every reference from_address -> to_address "
                        + "regardless of operand by default; pass operand_index >= 0 to remove only the "
                        + "reference on that operand. Removes both user-defined and analyzer-inferred "
                        + "references — the response reports each removed reference's source_type. "
                        + "On multi-space programs, prefix addresses with the space name (mem:1000).",
            category = "xref")
    public Response removeReference(
            @Param(value = "from_address", paramType = "address", source = ParamSource.BODY,
                   description = "Source address the reference originates from. Accepts 0x<hex> or <space>:<hex>.") String fromAddressStr,
            @Param(value = "to_address", paramType = "address", source = ParamSource.BODY,
                   description = "Target address the reference points to. Accepts 0x<hex> or <space>:<hex>.") String toAddressStr,
            @Param(value = "operand_index", source = ParamSource.BODY, defaultValue = "-1",
                   description = "Operand index to match. -1 (default) = remove references on any operand; "
                               + ">= 0 = remove only the reference on that operand.") int operandIndex,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (fromAddressStr == null || fromAddressStr.isEmpty()) return Response.err("from_address is required");
        if (toAddressStr == null || toAddressStr.isEmpty()) return Response.err("to_address is required");

        Address fromAddr = ServiceUtils.parseAddress(program, fromAddressStr);
        if (fromAddr == null) return Response.err("from_address: " + ServiceUtils.getLastParseError());
        Address toAddr = ServiceUtils.parseAddress(program, toAddressStr);
        if (toAddr == null) return Response.err("to_address: " + ServiceUtils.getLastParseError());

        // Collect the matching references up front, then delete inside the transaction.
        List<Reference> matches = new ArrayList<>();
        for (Reference ref : program.getReferenceManager().getReferencesFrom(fromAddr)) {
            if (!ref.getToAddress().equals(toAddr)) continue;
            if (operandIndex >= 0 && ref.getOperandIndex() != operandIndex) continue;
            matches.add(ref);
        }

        List<Map<String, Object>> details = new ArrayList<>();
        for (Reference ref : matches) {
            details.add(JsonHelper.mapOf(
                    "to_address", ref.getToAddress().toString(),
                    "operand_index", ref.getOperandIndex(),
                    "ref_type", ref.getReferenceType().getName(),
                    "source_type", ref.getSource().toString()));
        }

        if (matches.isEmpty()) {
            return Response.ok(JsonHelper.mapOf(
                    "status", "success",
                    "removed", 0,
                    "message", "No reference found from " + fromAddr + " to " + toAddr));
        }

        try {
            return threadingStrategy.executeWrite(program, "Remove memory reference", () -> {
                ReferenceManager refMgr = program.getReferenceManager();
                for (Reference ref : matches) {
                    refMgr.delete(ref);
                }
                return Response.ok(JsonHelper.mapOf(
                        "status", "success",
                        "from_address", fromAddr.toString(),
                        "to_address", toAddr.toString(),
                        "removed", matches.size(),
                        "references", details));
            });
        } catch (Exception e) {
            return Response.err("Error removing reference: " + e.getMessage());
        }
    }

    /**
     * Resolve a case-insensitive {@link RefType} name to its static constant.
     * Reflects over RefType's public static fields so every valid name (data + flow types)
     * is accepted, matching the names callers see in the listing.
     */
    private static RefType resolveMemoryRefType(String name) {
        if (name == null || name.trim().isEmpty()) return null;
        String want = name.trim().toUpperCase(Locale.ROOT);
        for (java.lang.reflect.Field f : RefType.class.getFields()) {
            if (java.lang.reflect.Modifier.isStatic(f.getModifiers())
                    && RefType.class.isAssignableFrom(f.getType())
                    && f.getName().equals(want)) {
                try {
                    return (RefType) f.get(null);
                } catch (IllegalAccessException e) {
                    return null;
                }
            }
        }
        return null;
    }

    /**
     * Get all references to a specific function by name
     */
    @McpTool(path = "/get_function_xrefs", description = "Get cross-references to a function. Accepts function name or address (pass address as 'address' param, or as 'name').", category = "xref")
    public Response getFunctionXrefs(
            @Param(value = "name", defaultValue = "", description = "Function name") String functionName,
            @Param(value = "address", defaultValue = "", description = "Function entry-point address (hex) — alternative to name") String address,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            FunctionRef.Result resolved = FunctionRef.ofNameOrAddress(functionName, address).tryResolve(program);
            if (!resolved.isSuccess()) return Response.text("No references found to function: " + functionName);
            Function function = resolved.function();

            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            Address entryPoint = function.getEntryPoint();
            ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }

            if (refs.isEmpty()) {
                return Response.text("No references found to function: " + functionName);
            }

            return Response.text(ServiceUtils.paginateList(refs, offset, limit));
        } catch (Exception e) {
            return Response.err("Error getting function references: " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Jump Target Methods
    // -----------------------------------------------------------------------

    /**
     * Get all jump target addresses from a function's disassembly
     */
    public Response getFunctionJumpTargets(String functionName, int offset, int limit) {
        return getFunctionJumpTargets(functionName, null, offset, limit, null);
    }

    @McpTool(path = "/get_function_jump_targets", description = "Get jump targets within a function. Accepts function name or address.", category = "xref")
    public Response getFunctionJumpTargets(
            @Param(value = "name", defaultValue = "", description = "Function name") String functionName,
            @Param(value = "address", defaultValue = "", description = "Function entry-point address (hex) — alternative to name") String address,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();

        // Find the function by name or address
        FunctionRef.Result resolved = FunctionRef.ofNameOrAddress(functionName, address).tryResolve(program);
        if (!resolved.isSuccess()) {
            return Response.text("Function not found: " + functionName);
        }
        Function function = resolved.function();

        AddressSetView functionBody = function.getBody();
        Listing listing = program.getListing();
        Set<Address> jumpTargets = new HashSet<>();

        // Iterate through all instructions in the function
        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();

            // Check if this is a jump instruction
            if (instr.getFlowType().isJump()) {
                // Get all reference addresses from this instruction
                Reference[] references = instr.getReferencesFrom();
                for (Reference ref : references) {
                    Address targetAddr = ref.getToAddress();
                    // Only include targets within the function or program space
                    if (targetAddr != null && program.getMemory().contains(targetAddr)) {
                        jumpTargets.add(targetAddr);
                    }
                }

                // Also check for fall-through addresses for conditional jumps
                if (instr.getFlowType().isConditional()) {
                    Address fallThroughAddr = instr.getFallThrough();
                    if (fallThroughAddr != null) {
                        jumpTargets.add(fallThroughAddr);
                    }
                }
            }
        }

        // Convert to sorted list and apply pagination
        List<Address> sortedTargets = new ArrayList<>(jumpTargets);
        Collections.sort(sortedTargets);

        int count = 0;
        int skipped = 0;

        for (Address target : sortedTargets) {
            if (count >= limit) break;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            if (sb.length() > 0) {
                sb.append("\n");
            }

            // Add context about what's at this address
            String context = "";
            Function targetFunc = functionManager.getFunctionContaining(target);
            if (targetFunc != null) {
                context = " (in " + targetFunc.getName() + ")";
            } else {
                // Check if there's a label at this address
                Symbol symbol = program.getSymbolTable().getPrimarySymbol(target);
                if (symbol != null) {
                    context = " (" + symbol.getName() + ")";
                }
            }

            sb.append(target.toString()).append(context);
            count++;
        }

        if (sb.length() == 0) {
            return Response.text("No jump targets found in function: " + functionName);
        }

        return Response.text(sb.toString());
    }

    // -----------------------------------------------------------------------
    // Callee/Caller Methods
    // -----------------------------------------------------------------------

    /**
     * Get all functions called by the specified function (callees)
     */
    @McpTool(path = "/get_function_callees", description = "Get functions called by a function. Accepts function name or address.", category = "xref")
    public Response getFunctionCallees(
            @Param(value = "name", defaultValue = "", description = "Function name") String functionName,
            @Param(value = "address", defaultValue = "", description = "Function entry-point address (hex) — alternative to name") String address,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();

        // Find the function by name or address
        FunctionRef.Result resolved = FunctionRef.ofNameOrAddress(functionName, address).tryResolve(program);
        if (!resolved.isSuccess()) {
            return Response.text("Function not found: " + functionName);
        }
        Function function = resolved.function();

        Set<Function> callees = new HashSet<>();
        AddressSetView functionBody = function.getBody();
        Listing listing = program.getListing();
        ReferenceManager refManager = program.getReferenceManager();

        // Iterate through all instructions in the function
        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();

            // Check if this is a call instruction
            if (instr.getFlowType().isCall()) {
                // Get all reference addresses from this instruction
                Reference[] references = refManager.getReferencesFrom(instr.getAddress());
                for (Reference ref : references) {
                    if (ref.getReferenceType().isCall()) {
                        Address targetAddr = ref.getToAddress();
                        Function targetFunc = functionManager.getFunctionAt(targetAddr);
                        if (targetFunc != null) {
                            callees.add(targetFunc);
                        }
                    }
                }
            }
        }

        // Convert to sorted list and apply pagination
        List<Function> sortedCallees = new ArrayList<>(callees);
        sortedCallees.sort((f1, f2) -> f1.getName().compareTo(f2.getName()));

        int count = 0;
        int skipped = 0;

        for (Function callee : sortedCallees) {
            if (count >= limit) break;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            if (sb.length() > 0) {
                sb.append("\n");
            }

            sb.append(String.format("%s @ %s", callee.getName(), callee.getEntryPoint()));
            count++;
        }

        if (sb.length() == 0) {
            return Response.text("No callees found for function: " + functionName);
        }

        return Response.text(sb.toString());
    }

    /**
     * Get all functions that call the specified function (callers)
     */
    @McpTool(path = "/get_function_callers", description = "Get functions calling a function. Accepts function name or address.", category = "xref")
    public Response getFunctionCallers(
            @Param(value = "name", defaultValue = "", description = "Function name") String functionName,
            @Param(value = "address", defaultValue = "", description = "Function entry-point address (hex) — alternative to name") String address,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();

        // Find the function by name or address
        Function targetFunction = null;
        FunctionRef.Result resolved = FunctionRef.ofNameOrAddress(functionName, address).tryResolve(program);
        if (!resolved.isSuccess()) {
            return Response.text("Function not found: " + functionName);
        }
        targetFunction = resolved.function();

        Set<Function> callers = new HashSet<>();
        ReferenceManager refManager = program.getReferenceManager();

        collectCallersFromAddressRefs(callers, functionManager, refManager, targetFunction.getEntryPoint());

        try {
            callers.addAll(targetFunction.getCallingFunctions(null));
        } catch (Exception ignored) {
            // Fall back to address refs only if Ghidra cannot compute calling functions.
        }

        // Convert to sorted list and apply pagination
        List<Function> sortedCallers = new ArrayList<>(callers);
        sortedCallers.sort((f1, f2) -> f1.getName().compareTo(f2.getName()));

        int count = 0;
        int skipped = 0;

        for (Function caller : sortedCallers) {
            if (count >= limit) break;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            if (sb.length() > 0) {
                sb.append("\n");
            }

            sb.append(String.format("%s @ %s", caller.getName(), caller.getEntryPoint()));
            count++;
        }

        if (sb.length() == 0) {
            return Response.text("No callers found for function: " + functionName);
        }

        return Response.text(sb.toString());
    }

    // -----------------------------------------------------------------------
    // Call Graph Methods
    // -----------------------------------------------------------------------

    /**
     * Get a call graph subgraph centered on the specified function
     */
    @McpTool(path = "/get_function_call_graph", description = "Traverse call graph from a function. Accepts function name or address.", category = "xref")
    public Response getFunctionCallGraph(
            @Param(value = "name", defaultValue = "", description = "Function name") String functionName,
            @Param(value = "address", defaultValue = "", description = "Function entry-point address (hex) — alternative to name") String address,
            @Param(value = "depth", defaultValue = "2", description = "Traversal depth") int depth,
            @Param(value = "direction", defaultValue = "both", description = "Traversal direction (both/callers/callees)") String direction,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();

        // Find the function by name or address
        Function rootFunction = null;
        FunctionRef.Result resolved = FunctionRef.ofNameOrAddress(functionName, address).tryResolve(program);
        if (!resolved.isSuccess()) {
            return Response.text("Function not found: " + functionName);
        }
        rootFunction = resolved.function();

        Set<String> visited = new HashSet<>();
        Map<String, Set<String>> callGraph = new HashMap<>();

        // Build call graph based on direction
        if ("callees".equals(direction) || "both".equals(direction)) {
            buildCallGraphCallees(rootFunction, depth, visited, callGraph, functionManager, program);
        }

        if ("callers".equals(direction) || "both".equals(direction)) {
            visited.clear(); // Reset for callers traversal
            buildCallGraphCallers(rootFunction, depth, visited, callGraph, functionManager, program);
        }

        // Format output as edges
        for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
            String caller = entry.getKey();
            for (String callee : entry.getValue()) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(caller).append(" -> ").append(callee);
            }
        }

        if (sb.length() == 0) {
            return Response.text("No call graph relationships found for function: " + functionName);
        }

        return Response.text(sb.toString());
    }

    /**
     * Graph-identity key for a function. Namespace-qualified name plus entry
     * address — unique across namespaces, overloads, and overlay spaces while
     * keeping text-format output (dot/mermaid/adjacency) human-readable.
     * Bare {@code getName()} collapsed distinct same-named functions: the
     * second was skipped by {@code visited}, its callee set was overwritten by
     * {@code callGraph.put}, and SCC/cycle results were computed on a merged
     * pseudo-node.
     */
    private static String graphKey(Function f) {
        return f.getName(true) + "@" + f.getEntryPoint();
    }

    /**
     * Resolve a user-supplied function name (or address) to its graph key.
     * Returns the input unchanged if resolution fails so a caller who already
     * passes a {@code name@addr} key still matches.
     */
    private static String resolveToGraphKey(Program program, String nameOrAddr) {
        if (nameOrAddr == null || nameOrAddr.isEmpty()) return nameOrAddr;
        FunctionRef.Result r = FunctionRef.ofNameOrAddress(nameOrAddr, null).tryResolve(program);
        return r.isSuccess() ? graphKey(r.function()) : nameOrAddr;
    }

    private void buildCallGraphCallees(Function function, int depth, Set<String> visited,
                                     Map<String, Set<String>> callGraph, FunctionManager functionManager,
                                     Program program) {
        String key = graphKey(function);
        if (depth <= 0 || visited.contains(key)) {
            return;
        }

        visited.add(key);
        Set<String> callees = new HashSet<>();

        // Find callees of this function
        AddressSetView functionBody = function.getBody();
        Listing listing = program.getListing();
        ReferenceManager refManager = program.getReferenceManager();

        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();

            if (instr.getFlowType().isCall()) {
                Reference[] references = refManager.getReferencesFrom(instr.getAddress());
                for (Reference ref : references) {
                    if (ref.getReferenceType().isCall()) {
                        Address targetAddr = ref.getToAddress();
                        Function targetFunc = functionManager.getFunctionAt(targetAddr);
                        if (targetFunc != null) {
                            callees.add(graphKey(targetFunc));
                            // Recursively build graph for callees
                            buildCallGraphCallees(targetFunc, depth - 1, visited, callGraph, functionManager, program);
                        }
                    }
                }
            }
        }

        if (!callees.isEmpty()) {
            callGraph.put(key, callees);
        }
    }

    /**
     * Helper method to build call graph for callers (what calls this function)
     */
    private void buildCallGraphCallers(Function function, int depth, Set<String> visited,
                                     Map<String, Set<String>> callGraph, FunctionManager functionManager,
                                     Program program) {
        String key = graphKey(function);
        if (depth <= 0 || visited.contains(key)) {
            return;
        }

        visited.add(key);
        ReferenceManager refManager = program.getReferenceManager();

        Set<Function> callers = new HashSet<>();
        collectCallersFromAddressRefs(callers, functionManager, refManager, function.getEntryPoint());
        try {
            callers.addAll(function.getCallingFunctions(null));
        } catch (Exception ignored) {
            // Keep the reference-only result if Ghidra cannot compute callers here.
        }

        for (Function callerFunc : callers) {
            if (callerFunc != null) {
                callGraph.computeIfAbsent(graphKey(callerFunc), k -> new HashSet<>()).add(key);
                buildCallGraphCallers(callerFunc, depth - 1, visited, callGraph, functionManager, program);
            }
        }
    }

    private static void collectCallersFromAddressRefs(Set<Function> callers, FunctionManager functionManager,
                                                      ReferenceManager refManager, Address entryPoint) {
        ReferenceIterator refIter = refManager.getReferencesTo(entryPoint);
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (!ref.getReferenceType().isCall()) {
                continue;
            }
            Address fromAddr = ref.getFromAddress();
            Function callerFunc = functionManager.getFunctionContaining(fromAddr);
            if (callerFunc != null) {
                callers.add(callerFunc);
            }
        }
    }

    /**
     * Get the complete call graph for the entire program
     */
    @McpTool(path = "/get_full_call_graph", description = "Get entire program call graph", category = "xref")
    public Response getFullCallGraph(
            @Param(value = "format", defaultValue = "edges", description = "Output format: edges (text), adjacency, dot, mermaid, json_edges (address-based JSON for automation)") String format,
            @Param(value = "limit", defaultValue = "1000", description = "Max edges to return. 0 = unlimited.") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // limit=0 means unlimited
        int effectiveLimit = (limit <= 0) ? Integer.MAX_VALUE : limit;

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refManager = program.getReferenceManager();
        Listing listing = program.getListing();

        Map<String, Set<String>> callGraph = new HashMap<>();
        // Address-based edge list for the json_edges format — built alongside
        // the name-based graph so we iterate instructions only once.
        List<Map<String, String>> addressEdges = "json_edges".equals(format) ? new ArrayList<>() : null;
        int relationshipCount = 0;

        // Build complete call graph
        for (Function function : functionManager.getFunctions(true)) {
            if (relationshipCount >= effectiveLimit) {
                break;
            }

            String functionKey = graphKey(function);
            String callerAddr = function.getEntryPoint().toString();
            Set<String> callees = new HashSet<>();
            // Dedupe json_edges on callee ADDRESS, independent of the
            // name-based callees set used by the text formats — otherwise a
            // call to a *different* function that happens to share a name
            // would be dropped from json_edges too.
            Set<String> calleeAddrs = addressEdges != null ? new HashSet<>() : null;

            // Find all functions called by this function
            AddressSetView functionBody = function.getBody();
            InstructionIterator instructions = listing.getInstructions(functionBody, true);

            while (instructions.hasNext() && relationshipCount < effectiveLimit) {
                Instruction instr = instructions.next();

                if (instr.getFlowType().isCall()) {
                    Reference[] references = refManager.getReferencesFrom(instr.getAddress());
                    for (Reference ref : references) {
                        if (ref.getReferenceType().isCall()) {
                            Address targetAddr = ref.getToAddress();
                            Function targetFunc = functionManager.getFunctionAt(targetAddr);
                            if (targetFunc != null) {
                                String calleeKey = graphKey(targetFunc);
                                String calleeAddr = targetFunc.getEntryPoint().toString();
                                // Deduplicate: only count each caller→callee pair once.
                                // For json_edges, dedupe on address (the stable id);
                                // for text formats, dedupe on the graph key.
                                boolean newForText = callees.add(calleeKey);
                                boolean newForJson = calleeAddrs != null && calleeAddrs.add(calleeAddr);
                                if (newForText || newForJson) {
                                    relationshipCount++;
                                    if (newForJson) {
                                        addressEdges.add(Map.of(
                                            "caller_addr", callerAddr,
                                            "callee_addr", calleeAddr,
                                            "caller_name", function.getName(),
                                            "callee_name", targetFunc.getName()
                                        ));
                                    }
                                    if (relationshipCount >= effectiveLimit) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (!callees.isEmpty()) {
                callGraph.put(functionKey, callees);
            }
        }

        // Format output based on requested format
        if ("json_edges".equals(format)) {
            // Address-based JSON edge list — designed for automation tools
            // (automated call-graph traversal) that need stable identifiers.
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("edge_count", addressEdges != null ? addressEdges.size() : 0);
            result.put("caller_count", callGraph.size());
            result.put("edges", addressEdges != null ? addressEdges : List.of());
            return Response.ok(result);
        } else if ("dot".equals(format)) {
            sb.append("digraph CallGraph {\n");
            sb.append("  rankdir=TB;\n");
            sb.append("  node [shape=box];\n");
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey().replace("\"", "\\\"");
                for (String callee : entry.getValue()) {
                    callee = callee.replace("\"", "\\\"");
                    sb.append("  \"").append(caller).append("\" -> \"").append(callee).append("\";\n");
                }
            }
            sb.append("}");
        } else if ("mermaid".equals(format)) {
            sb.append("graph TD\n");
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey().replace(" ", "_");
                for (String callee : entry.getValue()) {
                    callee = callee.replace(" ", "_");
                    sb.append("  ").append(caller).append(" --> ").append(callee).append("\n");
                }
            }
        } else if ("adjacency".equals(format)) {
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(entry.getKey()).append(": ");
                sb.append(String.join(", ", entry.getValue()));
            }
        } else { // Default "edges" format
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey();
                for (String callee : entry.getValue()) {
                    if (sb.length() > 0) {
                        sb.append("\n");
                    }
                    sb.append(caller).append(" -> ").append(callee);
                }
            }
        }

        if (sb.length() == 0) {
            return Response.text("No call relationships found in the program");
        }

        return Response.text(sb.toString());
    }

    // -----------------------------------------------------------------------
    // Call Graph Analysis Methods
    // -----------------------------------------------------------------------

    /**
     * Enhanced call graph analysis with cycle detection and path finding
     * Provides advanced graph algorithms for understanding function relationships
     */
    @McpTool(path = "/analyze_call_graph", description = "Analyze call graph paths between functions", category = "xref")
    public Response analyzeCallGraph(
            @Param(value = "start_function", description = "Start function name") String startFunction,
            @Param(value = "end_function", description = "End function name") String endFunction,
            @Param(value = "analysis_type", defaultValue = "summary", description = "Analysis type (summary/paths/cycles)") String analysisType,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            FunctionManager functionManager = program.getFunctionManager();
            ReferenceManager refManager = program.getReferenceManager();

            // Build adjacency list representation of call graph
            Map<String, Set<String>> callGraph = new LinkedHashMap<>();
            Map<String, String> functionAddresses = new LinkedHashMap<>();

            for (Function func : functionManager.getFunctions(true)) {
                if (func.isThunk()) continue;

                String funcKey = graphKey(func);
                functionAddresses.put(funcKey, func.getEntryPoint().toString());
                Set<String> callees = new HashSet<>();

                Listing listing = program.getListing();
                InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);

                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    if (instr.getFlowType().isCall()) {
                        for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                            if (ref.getReferenceType().isCall()) {
                                Function calledFunc = functionManager.getFunctionAt(ref.getToAddress());
                                if (calledFunc != null && !calledFunc.isThunk()) {
                                    callees.add(graphKey(calledFunc));
                                }
                            }
                        }
                    }
                }

                if (!callees.isEmpty()) {
                    callGraph.put(funcKey, callees);
                }
            }

            if ("cycles".equals(analysisType)) {
                // Detect cycles in the call graph using DFS
                List<List<String>> cycles = findCycles(callGraph);

                List<Map<String, Object>> cyclesList = new ArrayList<>();
                for (int i = 0; i < Math.min(cycles.size(), 20); i++) {
                    List<String> cycle = cycles.get(i);
                    cyclesList.add(JsonHelper.mapOf(
                        "length", cycle.size(),
                        "path", cycle
                    ));
                }
                if (cycles.size() > 20) {
                    cyclesList.add(JsonHelper.mapOf("note", (cycles.size() - 20) + " additional cycles omitted"));
                }

                return Response.ok(JsonHelper.mapOf(
                    "analysis_type", "cycle_detection",
                    "cycles_found", cycles.size(),
                    "cycles", cyclesList
                ));

            } else if ("path".equals(analysisType) && startFunction != null && endFunction != null) {
                // Resolve user-supplied names to graph keys so they match the
                // callGraph's name@addr keying. Falls back to the raw input so
                // a caller who already passes a fully-qualified key still works.
                String startKey = resolveToGraphKey(program, startFunction);
                String endKey = resolveToGraphKey(program, endFunction);
                // Find shortest path between two functions using BFS
                List<String> path = findShortestPath(callGraph, startKey, endKey);

                if (path != null) {
                    return Response.ok(JsonHelper.mapOf(
                        "analysis_type", "path_finding",
                        "start_function", startFunction,
                        "end_function", endFunction,
                        "path_found", true,
                        "path_length", path.size() - 1,
                        "path", path
                    ));
                } else {
                    return Response.ok(JsonHelper.mapOf(
                        "analysis_type", "path_finding",
                        "start_function", startFunction,
                        "end_function", endFunction,
                        "path_found", false,
                        "message", "No path exists between the specified functions"
                    ));
                }

            } else if ("strongly_connected".equals(analysisType)) {
                // Find strongly connected components using Kosaraju's algorithm
                List<Set<String>> sccs = findStronglyConnectedComponents(callGraph);

                // Filter to only non-trivial SCCs (size > 1)
                List<Set<String>> nonTrivialSCCs = new ArrayList<>();
                for (Set<String> scc : sccs) {
                    if (scc.size() > 1) {
                        nonTrivialSCCs.add(scc);
                    }
                }

                List<Map<String, Object>> componentsList = new ArrayList<>();
                for (int i = 0; i < Math.min(nonTrivialSCCs.size(), 20); i++) {
                    Set<String> scc = nonTrivialSCCs.get(i);
                    List<String> funcNames = new ArrayList<>();
                    int j = 0;
                    for (String func : scc) {
                        if (j >= 10) break;
                        funcNames.add(func);
                        j++;
                    }
                    if (scc.size() > 10) {
                        funcNames.add("..." + (scc.size() - 10) + " more");
                    }
                    componentsList.add(JsonHelper.mapOf(
                        "size", scc.size(),
                        "functions", funcNames
                    ));
                }

                return Response.ok(JsonHelper.mapOf(
                    "analysis_type", "strongly_connected_components",
                    "total_sccs", sccs.size(),
                    "non_trivial_sccs", nonTrivialSCCs.size(),
                    "components", componentsList
                ));

            } else if ("entry_points".equals(analysisType)) {
                // Find functions that are never called (potential entry points)
                Set<String> allFunctions = new HashSet<>(functionAddresses.keySet());
                Set<String> calledFunctions = new HashSet<>();
                for (Set<String> callees : callGraph.values()) {
                    calledFunctions.addAll(callees);
                }

                Set<String> entryPoints = new HashSet<>(allFunctions);
                entryPoints.removeAll(calledFunctions);

                List<Map<String, Object>> entryPointsList = new ArrayList<>();
                int idx = 0;
                for (String ep : entryPoints) {
                    if (idx >= 50) {
                        entryPointsList.add(JsonHelper.mapOf("note", (entryPoints.size() - 50) + " more entry points"));
                        break;
                    }
                    entryPointsList.add(JsonHelper.mapOf(
                        "name", ep,
                        "address", functionAddresses.getOrDefault(ep, "unknown")
                    ));
                    idx++;
                }

                return Response.ok(JsonHelper.mapOf(
                    "analysis_type", "entry_point_detection",
                    "total_functions", allFunctions.size(),
                    "entry_points_found", entryPoints.size(),
                    "entry_points", entryPointsList
                ));

            } else if ("leaf_functions".equals(analysisType)) {
                // Find functions that don't call any other functions
                Set<String> leafFunctions = new HashSet<>(functionAddresses.keySet());
                leafFunctions.removeAll(callGraph.keySet());

                List<Map<String, Object>> leafFunctionsList = new ArrayList<>();
                int idx = 0;
                for (String lf : leafFunctions) {
                    if (idx >= 50) {
                        leafFunctionsList.add(JsonHelper.mapOf("note", (leafFunctions.size() - 50) + " more leaf functions"));
                        break;
                    }
                    leafFunctionsList.add(JsonHelper.mapOf(
                        "name", lf,
                        "address", functionAddresses.getOrDefault(lf, "unknown")
                    ));
                    idx++;
                }

                return Response.ok(JsonHelper.mapOf(
                    "analysis_type", "leaf_function_detection",
                    "leaf_functions_found", leafFunctions.size(),
                    "leaf_functions", leafFunctionsList
                ));

            } else {
                // Default: summary statistics
                int totalEdges = 0;
                int maxOutDegree = 0;
                String maxOutDegreeFunc = "";
                Map<String, Integer> inDegree = new HashMap<>();

                for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                    totalEdges += entry.getValue().size();
                    if (entry.getValue().size() > maxOutDegree) {
                        maxOutDegree = entry.getValue().size();
                        maxOutDegreeFunc = entry.getKey();
                    }
                    for (String callee : entry.getValue()) {
                        inDegree.put(callee, inDegree.getOrDefault(callee, 0) + 1);
                    }
                }

                int maxInDegree = 0;
                String maxInDegreeFunc = "";
                for (Map.Entry<String, Integer> entry : inDegree.entrySet()) {
                    if (entry.getValue() > maxInDegree) {
                        maxInDegree = entry.getValue();
                        maxInDegreeFunc = entry.getKey();
                    }
                }

                return Response.ok(JsonHelper.mapOf(
                    "analysis_type", "summary",
                    "total_functions", functionAddresses.size(),
                    "functions_with_calls", callGraph.size(),
                    "total_call_edges", totalEdges,
                    "max_out_degree", JsonHelper.mapOf("function", maxOutDegreeFunc, "calls", maxOutDegree),
                    "max_in_degree", JsonHelper.mapOf("function", maxInDegreeFunc, "called_by", maxInDegree),
                    "available_analyses", Arrays.asList("cycles", "path", "strongly_connected", "entry_points", "leaf_functions")
                ));
            }

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Graph Algorithm Helpers
    // -----------------------------------------------------------------------

    /**
     * Find cycles in directed graph using DFS
     */
    private List<List<String>> findCycles(Map<String, Set<String>> graph) {
        List<List<String>> cycles = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        Set<String> recStack = new HashSet<>();
        Map<String, String> parent = new HashMap<>();

        for (String node : graph.keySet()) {
            if (!visited.contains(node)) {
                findCyclesDFS(node, graph, visited, recStack, parent, cycles);
            }
        }

        return cycles;
    }

    private void findCyclesDFS(String node, Map<String, Set<String>> graph, Set<String> visited,
                               Set<String> recStack, Map<String, String> parent, List<List<String>> cycles) {
        visited.add(node);
        recStack.add(node);

        Set<String> neighbors = graph.getOrDefault(node, Collections.emptySet());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                parent.put(neighbor, node);
                findCyclesDFS(neighbor, graph, visited, recStack, parent, cycles);
            } else if (recStack.contains(neighbor)) {
                // Found a cycle - reconstruct it
                List<String> cycle = new ArrayList<>();
                cycle.add(neighbor);
                String current = node;
                while (current != null && !current.equals(neighbor)) {
                    cycle.add(0, current);
                    current = parent.get(current);
                }
                cycle.add(0, neighbor);
                if (cycles.size() < 100) { // Limit cycles
                    cycles.add(cycle);
                }
            }
        }

        recStack.remove(node);
    }

    /**
     * Find shortest path using BFS
     */
    private List<String> findShortestPath(Map<String, Set<String>> graph, String start, String end) {
        if (start.equals(end)) {
            return Arrays.asList(start);
        }

        Queue<String> queue = new LinkedList<>();
        Map<String, String> parent = new HashMap<>();
        Set<String> visited = new HashSet<>();

        queue.add(start);
        visited.add(start);

        while (!queue.isEmpty()) {
            String current = queue.poll();
            Set<String> neighbors = graph.getOrDefault(current, Collections.emptySet());

            for (String neighbor : neighbors) {
                if (!visited.contains(neighbor)) {
                    visited.add(neighbor);
                    parent.put(neighbor, current);

                    if (neighbor.equals(end)) {
                        // Reconstruct path
                        List<String> path = new ArrayList<>();
                        String node = end;
                        while (node != null) {
                            path.add(0, node);
                            node = parent.get(node);
                        }
                        return path;
                    }

                    queue.add(neighbor);
                }
            }
        }

        return null; // No path found
    }

    /**
     * Find strongly connected components using Kosaraju's algorithm
     */
    private List<Set<String>> findStronglyConnectedComponents(Map<String, Set<String>> graph) {
        // Step 1: Fill vertices in stack according to finishing times
        Stack<String> stack = new Stack<>();
        Set<String> visited = new HashSet<>();

        // Get all nodes
        Set<String> allNodes = new HashSet<>(graph.keySet());
        for (Set<String> neighbors : graph.values()) {
            allNodes.addAll(neighbors);
        }

        for (String node : allNodes) {
            if (!visited.contains(node)) {
                fillOrder(node, graph, visited, stack);
            }
        }

        // Step 2: Create reversed graph
        Map<String, Set<String>> reversedGraph = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : graph.entrySet()) {
            for (String neighbor : entry.getValue()) {
                reversedGraph.computeIfAbsent(neighbor, k -> new HashSet<>()).add(entry.getKey());
            }
        }

        // Step 3: Process vertices in order of decreasing finish time
        visited.clear();
        List<Set<String>> sccs = new ArrayList<>();

        while (!stack.isEmpty()) {
            String node = stack.pop();
            if (!visited.contains(node)) {
                Set<String> scc = new HashSet<>();
                dfsCollect(node, reversedGraph, visited, scc);
                sccs.add(scc);
            }
        }

        return sccs;
    }

    private void fillOrder(String node, Map<String, Set<String>> graph, Set<String> visited, Stack<String> stack) {
        visited.add(node);
        Set<String> neighbors = graph.getOrDefault(node, Collections.emptySet());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                fillOrder(neighbor, graph, visited, stack);
            }
        }
        stack.push(node);
    }

    private void dfsCollect(String node, Map<String, Set<String>> graph, Set<String> visited, Set<String> component) {
        visited.add(node);
        component.add(node);
        Set<String> neighbors = graph.getOrDefault(node, Collections.emptySet());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                dfsCollect(neighbor, graph, visited, component);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Bulk Xref Methods
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Range Xref Query
    // -----------------------------------------------------------------------

    /** Upper bound for {@code limit}; keeps a wide range from returning an unbounded body. */
    private static final int MAX_RANGE_REFERENCE_LIMIT = 10_000;

    @McpTool(path = "/get_references_into_range",
             description = "List every recorded reference whose DESTINATION falls in [start, end] "
                         + "(inclusive), as a flat list ordered by source address — by (space, "
                         + "offset), so on a multi-space program sources group by space rather than "
                         + "forming one monotonic hex sequence. Answers \"what touches this address "
                         + "span\" in one call — the recurring query on overlay/banked-memory "
                         + "targets. Returns RECORDED REFERENCES ONLY, echoed as `scope`: the result "
                         + "is complete for what Ghidra's reference database currently holds and "
                         + "says nothing beyond that. Bytes that encode an in-range address without "
                         + "a recorded reference never appear — untyped pointer tables, computed "
                         + "targets, operands the analyzer left unresolved. No single follow-up pass "
                         + "closes that gap: decoding instructions finds missed control flow but not "
                         + "untyped data pointers, so treat a wider sweep as raising confidence, not "
                         + "as proving exhaustiveness. `search_address_encodings` is the companion "
                         + "pass for bytes that encode an in-range address without one. Plain hex "
                         + "resolves in the default physical space; `resolved_range` echoes what "
                         + "was queried and `overlapping_spaces` lists other spaces occupying "
                         + "those offsets. Paged with `offset`/`limit`: `count` is the total over "
                         + "the whole range and `has_more` says whether rows remain after this "
                         + "page.",
             category = "xref")
    public Response getReferencesIntoRange(
            @Param(value = "start", paramType = "address",
                   description = "First address of the range, inclusive. Accepts 0x<hex> (default "
                               + "space) or <space>:<hex> (e.g., SND_PLAYER:9680).") String startStr,
            @Param(value = "end", paramType = "address",
                   description = "Last address of the range, inclusive. Must resolve in the same "
                               + "address space as `start`.") String endStr,
            @Param(value = "limit", defaultValue = "2000",
                   description = "Maximum rows returned per page, 1..10000. `count` still "
                               + "reports total matches over the whole range.") int limit,
            @Param(value = "offset", defaultValue = "0",
                   description = "Page start within the ordered result, 0-based. An offset past "
                               + "the end returns an empty page with `count` unchanged.") int offset,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (limit < 1 || limit > MAX_RANGE_REFERENCE_LIMIT) {
            return Response.err("limit must be in 1.." + MAX_RANGE_REFERENCE_LIMIT
                + " (got " + limit + ")");
        }
        // Rejected, not clamped: a negative offset is a caller bug, and silently
        // treating it as 0 hands back page one while the caller believes otherwise.
        if (offset < 0) {
            return Response.err("offset must not be negative (got " + offset + ")");
        }

        // parseAddress records its error in a ThreadLocal, so both endpoints are
        // resolved here on the calling thread before any threading strategy hop.
        Address start = ServiceUtils.parseAddress(program, startStr);
        if (start == null) return Response.err(ServiceUtils.getLastParseError());
        Address end = ServiceUtils.parseAddress(program, endStr);
        if (end == null) return Response.err(ServiceUtils.getLastParseError());

        AddressSpace startSpace = start.getAddressSpace();
        AddressSpace endSpace = end.getAddressSpace();
        if (!startSpace.getName().equals(endSpace.getName())) {
            return Response.err("start and end must resolve in the same address space; got '"
                + startSpace.getName() + "' and '" + endSpace.getName()
                + "'. A range spanning two spaces has no meaning.");
        }
        BigInteger startOffset = start.getOffsetAsBigInteger();
        BigInteger endOffset = end.getOffsetAsBigInteger();
        if (startOffset.compareTo(endOffset) > 0) {
            return Response.err("start must not be greater than end; got '"
                + startStr + "' > '" + endStr + "'");
        }

        // Every model read below goes through the threading strategy: under the
        // GUI strategy that transfers to the EDT, which is why both parseAddress
        // calls had to happen above — a ThreadLocal set inside is invisible here.
        try {
            return threadingStrategy.executeRead(() ->
                collectReferencesIntoRange(program, start, end, startSpace,
                    startOffset, endOffset, limit, offset));
        } catch (Exception e) {
            return Response.err("Error listing references into range: " + e.getMessage());
        }
    }

    private Response collectReferencesIntoRange(Program program, Address start, Address end,
                                                AddressSpace startSpace, BigInteger startOffset,
                                                BigInteger endOffset, int limit, int pageOffset) {
        {
            ReferenceManager refMgr = program.getReferenceManager();
            AddressSet range = new AddressSet(start, end);

            List<Reference> matches = new ArrayList<>();
            AddressIterator destinations = refMgr.getReferenceDestinationIterator(range, true);
            while (destinations != null && destinations.hasNext()) {
                Address destination = destinations.next();
                if (destination == null || !inRange(destination, startSpace, startOffset, endOffset)) {
                    continue;
                }
                ReferenceIterator refIter = refMgr.getReferencesTo(destination);
                while (refIter != null && refIter.hasNext()) {
                    Reference reference = refIter.next();
                    if (reference != null) matches.add(reference);
                }
            }

            // Total order over (from, to, type, operand, source kind): the same
            // comparator get_listing_range uses, so equal from/to never tie.
            matches.sort(ReferenceOrdering.outgoing());
            int total = matches.size();
            // The whole result is collected and sorted before the page is cut, which
            // is why count is exact and why paging is a cheap slice rather than a
            // second traversal. An offset past the end is an empty page, not an error.
            int from = Math.min(pageOffset, total);
            int to = (int) Math.min((long) from + limit, total);
            List<Reference> page = matches.subList(from, to);
            int returned = page.size();
            // long arithmetic: a near-maximum offset would overflow an int sum and
            // report has_more from a wrapped comparison.
            boolean hasMore = (long) pageOffset + returned < total;

            boolean qualify = ServiceUtils.getOverlaySpaceCount(program) > 0
                || ServiceUtils.getPhysicalSpaceCount(program) > 1;

            // One format per request, not per row: operands must resolve to symbols,
            // including overlay-qualified ones. See operandAwareFormat.
            CodeUnitFormat format = operandAwareFormat();
            OperandRenderer operands = format::getOperandRepresentationString;
            List<Map<String, Object>> rows = new ArrayList<>(page.size());
            for (Reference reference : page) {
                rows.add(describeReference(program, reference, qualify, operands));
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("resolved_range", start.toString(true) + " - " + end.toString(true));
            result.put("overlapping_spaces",
                overlappingSpaces(program, startSpace, startOffset, endOffset));
            // The completeness boundary travels with the data. A caller reading a
            // stored result, or a transcript of one, no longer has the tool
            // description in view, and "count: 7" reads as "there are 7" unless
            // the response itself says what was counted.
            result.put("scope", "recorded_references_only");
            result.put("count", total);
            result.put("offset", pageOffset);
            result.put("limit", limit);
            result.put("returned", returned);
            result.put("has_more", hasMore);
            // Page continuity holds only while the program is unchanged; the echo is
            // what lets a caller notice two pages came from different revisions
            // instead of silently stitching them.
            result.put("program_modification_number", program.getModificationNumber());
            result.put("references", rows);
            return Response.ok(result);
        }
    }

    /** True when {@code candidate} sits in the queried space and within the offset bounds. */
    private static boolean inRange(Address candidate, AddressSpace space,
                                   BigInteger low, BigInteger high) {
        if (!candidate.getAddressSpace().getName().equals(space.getName())) return false;
        BigInteger offset = candidate.getOffsetAsBigInteger();
        return offset.compareTo(low) >= 0 && offset.compareTo(high) <= 0;
    }

    /**
     * Other spaces occupying the requested offsets, excluding the queried space.
     *
     * <p>Computed from memory BLOCKS, not address spaces: an overlay space spans the
     * full range of the space it shadows, so intersecting on space bounds would report
     * every overlay for every query. Iterating all blocks (not just overlay blocks) is
     * what lets an overlay-space query report the underlying physical space.</p>
     */
    private static List<String> overlappingSpaces(Program program, AddressSpace queried,
                                                  BigInteger low, BigInteger high) {
        AddressSpace queriedPhysical = queried.getPhysicalSpace();
        Set<String> names = new TreeSet<>();
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        if (blocks == null) return new ArrayList<>(names);
        for (MemoryBlock block : blocks) {
            if (block == null || block.getStart() == null || block.getEnd() == null) continue;
            AddressSpace candidate = block.getStart().getAddressSpace();
            if (candidate.getName().equals(queried.getName())) continue;
            AddressSpace candidatePhysical = candidate.getPhysicalSpace();
            if (candidatePhysical == null || queriedPhysical == null
                    || !candidatePhysical.getName().equals(queriedPhysical.getName())) {
                continue;
            }
            // BigInteger comparison: signed long would order high-half 64-bit
            // offsets wrongly.
            BigInteger blockLow = block.getStart().getOffsetAsBigInteger();
            BigInteger blockHigh = block.getEnd().getOffsetAsBigInteger();
            if (blockLow.compareTo(high) <= 0 && blockHigh.compareTo(low) >= 0) {
                names.add(candidate.getName());
            }
        }
        return new ArrayList<>(names);
    }

    /** One flat row per reference. */
    private static Map<String, Object> describeReference(Program program, Reference reference,
                                                         boolean qualify, OperandRenderer operands) {
        Address from = reference.getFromAddress();
        Address to = reference.getToAddress();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("from", format(from, qualify));

        // Containment and proximity get DIFFERENT FIELD NAMES, not one field plus a qualifier.
        // A caller that reads from_symbol and from_symbol_offset and ignores everything else
        // must not be able to print "PART_FILENAME+475" for code 475 bytes past a five-byte
        // buffer. from_symbol is emitted only when the offset really indexes into the named
        // thing; the nearest-label guess is a separate pair a caller has to ask for by name.
        // On a labels-only program with zero functions this matters on every single row: the
        // sweep this endpoint was built for produced `preceding` for all 7 of them.
        Symbol exact = program.getSymbolTable().getPrimarySymbol(from);
        Function containing = program.getFunctionManager().getFunctionContaining(from);
        if (exact != null) {
            row.put("from_symbol", exact.getName());
            row.put("from_symbol_offset", BigInteger.ZERO);
            row.put("from_symbol_relation", "at");
        } else if (containing != null && containing.getEntryPoint() != null) {
            row.put("from_symbol", containing.getName());
            row.put("from_symbol_offset", delta(containing.getEntryPoint(), from));
            row.put("from_symbol_relation", "containing");
        } else {
            Symbol preceding = nearestPrecedingSymbol(program, from);
            if (preceding != null) {
                row.put("nearest_preceding_symbol", preceding.getName());
                row.put("nearest_preceding_distance", delta(preceding.getAddress(), from));
                row.put("from_symbol_relation", "preceding");
            }
        }

        CodeUnit unit = program.getListing().getCodeUnitContaining(from);
        if (unit instanceof Instruction) {
            row.put("from_kind", "instruction");
            row.put("from_instruction", render(operands, unit, from));
        } else if (unit != null) {
            row.put("from_kind", "data");
            row.put("from_instruction", render(operands, unit, from));
        } else {
            // References can be recorded from mapped-but-undefined addresses;
            // rendering must be absent rather than an empty string.
            row.put("from_kind", "undefined");
        }

        row.put("to", format(to, qualify));
        row.put("type", reference.getReferenceType().getName());
        row.put("source_kind", ReferenceOrdering.sourceKind(reference.getSource()));
        row.put("operand_index", reference.getOperandIndex());
        return row;
    }

    /**
     * The same {@link CodeUnitFormat} configuration Ghidra's own exporter and
     * {@code CompleteListingWriter} use.
     *
     * <p>{@code CodeUnit.toString()} and {@code getDefaultOperandRepresentation} render an
     * operand as a bare number even where a symbol exists for its target, so a call into a
     * recovered overlay reads as {@code JSR 0x9695} rather than
     * {@code JSR SND_PLAYER::SND_TICK}. On this endpoint that is the difference between a row
     * that answers "which occupant does this site mean" and one that restates the bytes.
     * {@code ShowBlockName.NON_LOCAL} is what keeps the overlay qualifier on the operand.</p>
     *
     * <p>The simplifier must be non-null and disabled, exactly as Ghidra's exporter builds it:
     * {@code CodeUnitFormatOptions.simplifyTemplate} dereferences it unconditionally, so passing
     * null throws as soon as an operand resolves to a symbol — the common case here.</p>
     */
    // Package-private: /search_address_encodings renders its site rows through the
    // same configuration, so the two endpoints cannot drift in how an operand resolves.
    static CodeUnitFormat operandAwareFormat() {
        TemplateSimplifier simplifier = new TemplateSimplifier();
        simplifier.setEnabled(false);
        return new CodeUnitFormat(new CodeUnitFormatOptions(
            CodeUnitFormatOptions.ShowBlockName.NON_LOCAL,
            CodeUnitFormatOptions.ShowNamespace.NON_LOCAL,
            null, true, true, true, true, true, true, true, simplifier));
    }

    /** How one operand of a code unit is rendered. Seam so {@link #render} is testable. */
    interface OperandRenderer {
        String render(CodeUnit unit, int operandIndex);
    }

    /**
     * The source code unit as a listing would show it, with operands resolved to symbols.
     *
     * <p>Assembled mnemonic-then-operands, one operand at a time, exactly as
     * {@code CompleteListingWriter} does it — and deliberately NOT through
     * {@code CodeUnitFormat.getRepresentationString(CodeUnit)}. That overload does not resolve an
     * operand whose reference target lies in another address space. Measured on the program this
     * endpoint was built for: {@code RAM:$9910 JMP $97A9} into the SND_PLAYER overlay rendered as
     * {@code "JMP 0x97a9"} through the {@code toString()} this replaced, and as a bare
     * {@code "JMP 97a9"} through that overload — losing precisely the cross-space symbol the row
     * exists to show. The per-operand call renders
     * {@code "JMP SND_PLAYER:SND_V1_STREAM_ADVANCE3"}.</p>
     *
     * <p>A caveat learned while verifying that: the operand resolves through the PRIMARY
     * reference. A site whose cross-space reference was added while the operand still carried its
     * original one is left non-primary, and renders as a bare offset however this method behaves.
     * That is a defect in the program's references, not in the rendering.</p>
     *
     * <p>For a reference recorded from the interior of an aggregate — a dispatch table entry, the
     * usual case for a jump table — the whole unit renders as just {@code dw[15]}, naming the
     * array and none of its slots. The primitive at {@code from} is rendered instead, so the row
     * carries the entry that actually holds the in-range address.</p>
     *
     * <p>A null mnemonic falls back to {@code toString()}. That guard is narrow on purpose and
     * should not be read as protection against a malformed unit: for a real {@code DataDB} the
     * fallback itself calls {@code getMnemonicString()}, so it is no safer than the thing it
     * replaces. Formatter exceptions are deliberately not caught — a throw from
     * {@code CodeUnitFormat} is a real defect and silently degrading a classification row would
     * hide it.</p>
     */

    static String render(OperandRenderer operands, CodeUnit unit, Address from) {
        CodeUnit target = unit;
        Address unitStart = unit.getMinAddress();
        if (unit instanceof Data && unitStart != null && !from.equals(unitStart)) {
            BigInteger offset = delta(unitStart, from);
            // Non-negative and inside a positive signed int. intValueExact would throw on the
            // 32-bit boundary rather than fall back, and an aggregate that large is not worth
            // failing a whole request over.
            if (offset.signum() >= 0 && offset.bitLength() < 32) {
                Data primitive = ((Data) unit).getPrimitiveAt(offset.intValue());
                if (primitive != null) target = primitive;
            }
        }
        String mnemonic = target.getMnemonicString();
        if (mnemonic == null) return target.toString();

        StringBuilder rendered = new StringBuilder(mnemonic);
        if (target instanceof Instruction) {
            Instruction instruction = (Instruction) target;
            for (int index = 0; index < instruction.getNumOperands(); index++) {
                rendered.append(index == 0 ? " " : ",");
                rendered.append(operands.render(instruction, index));
            }
        } else if (target instanceof Data) {
            String value = operands.render(target, 0);
            if (value == null || value.isBlank()) {
                value = ((Data) target).getDefaultValueRepresentation();
            }
            if (value != null && !value.isBlank()) rendered.append(' ').append(value);
        }

        String text = rendered.toString().trim();
        return text.isBlank() ? target.toString() : text;
    }

    /**
     * Nearest preceding primary label or function entry, never crossing out of the
     * source's own memory block. Plate comments are not symbols and are not consulted.
     *
     * <p>The block boundary is the only bound, and on a program laid out as one large block it
     * does not bite: a 53 KiB RAM block will happily report a label 475 bytes back, which is why
     * every row says which of the three rules matched. {@code from_symbol_relation} is
     * {@code at} or {@code containing} when the offset is an offset *into* the named thing, and
     * {@code preceding} when it is only a distance to the nearest label behind it. A caller must
     * not read a {@code preceding} row as containment; the two are indistinguishable from the
     * name and offset alone.</p>
     */
    private static Symbol nearestPrecedingSymbol(Program program, Address from) {
        MemoryBlock block = program.getMemory().getBlock(from);
        if (block == null || block.getStart() == null) {
            // Without a containing block there is no boundary to respect, and
            // walking past one would report a symbol from unrelated memory.
            return null;
        }
        // getPrimarySymbolIterator over [blockStart, from] does the work the
        // contract describes: primary label/function symbols only, and the set
        // itself enforces the block boundary. The all-symbol iterator would
        // return secondary labels and other addressable symbol types.
        AddressSet searched = new AddressSet(block.getStart(), from);
        SymbolIterator iterator =
            program.getSymbolTable().getPrimarySymbolIterator(searched, false);
        while (iterator != null && iterator.hasNext()) {
            Symbol symbol = iterator.next();
            if (symbol == null || symbol.getAddress() == null) continue;
            return symbol;
        }
        return null;
    }

    /**
     * Byte delta as a BigInteger. Not narrowed to int: Ghidra permits memory blocks
     * far larger than 2 GiB, so a preceding symbol that distance behind the source is
     * reachable inside one block, and narrowing would wrap the offset. Gson emits a
     * BigInteger as an ordinary exact JSON number.
     */
    private static BigInteger delta(Address base, Address target) {
        return target.getOffsetAsBigInteger().subtract(base.getOffsetAsBigInteger());
    }

    private static String format(Address address, boolean qualify) {
        return qualify ? address.toString(true) : address.toString(false);
    }

    /**
     * Retrieve xrefs for multiple addresses in one call
     */
    public Response getBulkXrefs(Object addressesObj) {
        return getBulkXrefs(addressesObj, null);
    }

    @McpTool(path = "/get_bulk_xrefs", method = "POST", description = "Batch cross-reference retrieval", category = "xref")
    public Response getBulkXrefs(
            @Param(value = "addresses", source = ParamSource.BODY) Object addressesObj,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            List<String> addresses = new ArrayList<>();

            // Parse addresses array
            if (addressesObj instanceof List) {
                for (Object addr : (List<?>) addressesObj) {
                    if (addr != null) {
                        addresses.add(addr.toString());
                    }
                }
            } else if (addressesObj instanceof String) {
                // Handle comma-separated string
                String[] parts = ((String) addressesObj).split(",");
                for (String part : parts) {
                    addresses.add(part.trim());
                }
            }

            ReferenceManager refMgr = program.getReferenceManager();
            Map<String, Object> resultMap = new LinkedHashMap<>();

            for (String addrStr : addresses) {
                List<Map<String, Object>> refsList = new ArrayList<>();

                try {
                    Address addr = ServiceUtils.parseAddress(program, addrStr);
                    if (addr != null) {
                        ReferenceIterator refIter = refMgr.getReferencesTo(addr);

                        while (refIter.hasNext()) {
                            Reference ref = refIter.next();
                            Address fromAddr = ref.getFromAddress();
                            Map<String, Object> refItem = new LinkedHashMap<>();
                            refItem.put("from", fromAddr.toString(false));
                            if (ServiceUtils.getPhysicalSpaceCount(program) > 1) {
                                refItem.put("from_full", fromAddr.toString());
                                refItem.put("from_space", fromAddr.getAddressSpace().getName());
                            }
                            refItem.put("type", ref.getReferenceType().getName());
                            refsList.add(refItem);
                        }
                    }
                } catch (Exception e) {
                    // Address parsing failed, return empty array
                }

                resultMap.put(addrStr, refsList);
            }

            return Response.ok(resultMap);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Assembly pattern analysis - get assembly context around xref source addresses
     */
    public Response getAssemblyContext(Object xrefSourcesObj, int contextInstructions,
                                      Object includePatternsObj) {
        return getAssemblyContext(xrefSourcesObj, contextInstructions, includePatternsObj, null);
    }

    @McpTool(path = "/get_assembly_context", method = "POST", description = "Get assembly pattern context for xref sources", category = "xref")
    public Response getAssemblyContext(
            @Param(value = "xref_sources", source = ParamSource.BODY) Object xrefSourcesObj,
            @Param(value = "context_instructions", source = ParamSource.BODY, defaultValue = "5") int contextInstructions,
            @Param(value = "include_patterns", source = ParamSource.BODY) Object includePatternsObj,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            List<String> xrefSources = new ArrayList<>();

            if (xrefSourcesObj instanceof List) {
                for (Object addr : (List<?>) xrefSourcesObj) {
                    if (addr != null) {
                        xrefSources.add(addr.toString());
                    }
                }
            } else if (xrefSourcesObj instanceof String s) {
                for (String part : s.split(",")) {
                    String trimmed = part.trim();
                    if (!trimmed.isEmpty()) {
                        xrefSources.add(trimmed);
                    }
                }
            }

            Listing listing = program.getListing();
            Map<String, Object> resultMap = new LinkedHashMap<>();

            for (String addrStr : xrefSources) {
                try {
                    Address addr = ServiceUtils.parseAddress(program, addrStr);
                    if (addr != null) {
                        Instruction instr = listing.getInstructionAt(addr);

                        if (instr != null) {
                            // Get context before
                            List<String> contextBefore = new ArrayList<>();
                            Address prevAddr = addr;
                            for (int i = 0; i < contextInstructions; i++) {
                                Instruction prevInstr = listing.getInstructionBefore(prevAddr);
                                if (prevInstr == null) break;
                                prevAddr = prevInstr.getAddress();
                                contextBefore.add(prevAddr + ": " + prevInstr.toString());
                            }

                            // Get context after
                            List<String> contextAfter = new ArrayList<>();
                            Address nextAddr = addr;
                            for (int i = 0; i < contextInstructions; i++) {
                                Instruction nextInstr = listing.getInstructionAfter(nextAddr);
                                if (nextInstr == null) break;
                                nextAddr = nextInstr.getAddress();
                                contextAfter.add(nextAddr + ": " + nextInstr.toString());
                            }

                            // Detect patterns
                            String mnemonic = instr.getMnemonicString().toUpperCase();

                            List<String> patterns = new ArrayList<>();
                            if (mnemonic.equals("MOV") || mnemonic.equals("LEA")) {
                                patterns.add("data_access");
                            }
                            if (mnemonic.equals("CMP") || mnemonic.equals("TEST")) {
                                patterns.add("comparison");
                            }
                            if (mnemonic.equals("IMUL") || mnemonic.equals("SHL") || mnemonic.equals("SHR")) {
                                patterns.add("arithmetic");
                            }
                            if (mnemonic.equals("PUSH") || mnemonic.equals("POP")) {
                                patterns.add("stack_operation");
                            }
                            if (mnemonic.startsWith("J") || mnemonic.equals("CALL")) {
                                patterns.add("control_flow");
                            }

                            resultMap.put(addrStr, JsonHelper.mapOf(
                                "address", addrStr,
                                "instruction", instr.toString(),
                                "context_before", contextBefore,
                                "context_after", contextAfter,
                                "mnemonic", mnemonic,
                                "patterns_detected", patterns
                            ));
                        } else {
                            resultMap.put(addrStr, JsonHelper.mapOf(
                                "address", addrStr,
                                "error", "No instruction at address"
                            ));
                        }
                    }
                } catch (Exception e) {
                    resultMap.put(addrStr, JsonHelper.mapOf(
                        "error", e.getMessage()
                    ));
                }
            }

            return Response.ok(resultMap);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }
}
