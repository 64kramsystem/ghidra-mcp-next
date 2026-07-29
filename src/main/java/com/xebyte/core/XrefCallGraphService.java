package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Cross-reference facts and direct reference mutations. */
public final class XrefCallGraphService {

    private static final int MAX_LIMIT = 10_000;

    private final ProgramProvider programs;
    private final ThreadingStrategy threading;

    public XrefCallGraphService(
            ProgramProvider programs, ThreadingStrategy threading) {
        this.programs = programs;
        this.threading = threading;
    }

    @McpTool(path = "/get_xrefs_to",
        description = "List references to an address")
    public Response getXrefsTo(
            @Param(value = "address")
                String addressText,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Response bounds = validatePage(offset, limit);
        if (bounds != null) {
            return bounds;
        }
        Program program = resolved.program();
        Address address = ServiceUtils.parseAddress(program, addressText);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }
        List<Reference> referencesTo = new ArrayList<>();
        ReferenceIterator references =
            program.getReferenceManager().getReferencesTo(address);
        while (references.hasNext()) {
            referencesTo.add(references.next());
        }
        referencesTo.sort(referenceComparator());
        List<Map<String, Object>> rows =
            referencesTo.stream().map(XrefCallGraphService::referenceRecord).toList();
        return paged(rows, offset, limit);
    }

    @McpTool(path = "/get_xrefs_from",
        description = "List references from an address")
    public Response getXrefsFrom(
            @Param(value = "address")
                String addressText,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Response bounds = validatePage(offset, limit);
        if (bounds != null) {
            return bounds;
        }
        Program program = resolved.program();
        Address address = ServiceUtils.parseAddress(program, addressText);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }
        List<Reference> referencesFrom = new ArrayList<>();
        for (Reference reference
                : program.getReferenceManager().getReferencesFrom(address)) {
            referencesFrom.add(reference);
        }
        referencesFrom.sort(referenceComparator());
        List<Map<String, Object>> rows =
            referencesFrom.stream().map(XrefCallGraphService::referenceRecord).toList();
        return paged(rows, offset, limit);
    }

    @McpTool(path = "/add_memory_reference", method = "POST",
        description = "Add one user-defined memory reference")
    public Response addMemoryReference(
            @Param(value = "from_address",
                source = ParamSource.BODY) String fromText,
            @Param(value = "to_address",
                source = ParamSource.BODY) String toText,
            @Param(value = "ref_type", source = ParamSource.BODY,
                defaultValue = "DATA") String refTypeText,
            @Param(value = "operand_index", source = ParamSource.BODY,
                defaultValue = "-1") int operandIndex,
            @Param(value = "program", defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Program program = resolved.program();
        Address from = ServiceUtils.parseMutationAddress(program, fromText);
        if (from == null) {
            return Response.err("from_address: "
                + ServiceUtils.getLastParseError());
        }
        Address to = ServiceUtils.parseMutationAddress(program, toText);
        if (to == null) {
            return Response.err("to_address: "
                + ServiceUtils.getLastParseError());
        }
        RefType refType = ServiceUtils.resolveRefType(refTypeText);
        if (refType == null) {
            return Response.err("Unknown ref_type: " + refTypeText);
        }
        try {
            return threading.executeWrite(
                program, "Add memory reference", () -> {
                    Reference reference =
                        program.getReferenceManager().addMemoryReference(
                            from, to, refType, SourceType.USER_DEFINED,
                            operandIndex);
                    return Response.ok(referenceRecord(reference));
                });
        } catch (Exception error) {
            return Response.err("Could not add reference: "
                + error.getMessage());
        }
    }

    @McpTool(path = "/remove_reference", method = "POST",
        description = "Remove references between two addresses")
    public Response removeReference(
            @Param(value = "from_address",
                source = ParamSource.BODY) String fromText,
            @Param(value = "to_address",
                source = ParamSource.BODY) String toText,
            @Param(value = "operand_index", source = ParamSource.BODY,
                defaultValue = "-1") int operandIndex,
            @Param(value = "program", defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Program program = resolved.program();
        Address from = ServiceUtils.parseMutationAddress(program, fromText);
        if (from == null) {
            return Response.err("from_address: "
                + ServiceUtils.getLastParseError());
        }
        Address to = ServiceUtils.parseMutationAddress(program, toText);
        if (to == null) {
            return Response.err("to_address: "
                + ServiceUtils.getLastParseError());
        }
        List<Reference> matches = new ArrayList<>();
        for (Reference reference
                : program.getReferenceManager().getReferencesFrom(from)) {
            if (reference.getToAddress().equals(to)
                    && (operandIndex < 0
                        || reference.getOperandIndex() == operandIndex)) {
                matches.add(reference);
            }
        }
        try {
            return threading.executeWrite(
                program, "Remove memory reference", () -> {
                    for (Reference reference : matches) {
                        program.getReferenceManager().delete(reference);
                    }
                    return Response.ok(JsonHelper.mapOf(
                        "removed", matches.size(),
                        "from", from.toString(),
                        "to", to.toString()));
                });
        } catch (Exception error) {
            return Response.err("Could not remove reference: "
                + error.getMessage());
        }
    }

    @McpTool(path = "/get_function_jump_targets",
        description = "List direct jump targets in a function")
    public Response getFunctionJumpTargets(
            @Param(value = "address")
                String addressText,
            @Param(value = "program", defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Program program = resolved.program();
        Function function = function(program, addressText);
        if (function == null) {
            return Response.err("No function contains " + addressText);
        }
        Set<String> targets = new LinkedHashSet<>();
        InstructionIterator instructions =
            program.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (!instruction.getFlowType().isJump()) {
                continue;
            }
            for (Address target : instruction.getFlows()) {
                targets.add(target.toString());
            }
        }
        return Response.ok(List.copyOf(targets));
    }

    @McpTool(path = "/get_function_callees",
        description = "List functions directly called by a function")
    public Response getFunctionCallees(
            @Param(value = "address")
                String addressText,
            @Param(value = "program", defaultValue = "")
                String programName) {
        return relatedFunctions(addressText, programName, true);
    }

    @McpTool(path = "/get_function_callers",
        description = "List functions that directly call a function")
    public Response getFunctionCallers(
            @Param(value = "address")
                String addressText,
            @Param(value = "program", defaultValue = "")
                String programName) {
        return relatedFunctions(addressText, programName, false);
    }

    @McpTool(path = "/get_references_into_range",
        description = "List references whose destinations are in a range")
    public Response getReferencesIntoRange(
            @Param(value = "start") String startText,
            @Param(value = "end") String endText,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Response bounds = validatePage(offset, limit);
        if (bounds != null) {
            return bounds;
        }
        Program program = resolved.program();
        Address start = ServiceUtils.parseAddress(program, startText);
        if (start == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }
        Address end = ServiceUtils.parseAddress(program, endText);
        if (end == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }
        if (!start.getAddressSpace().equals(end.getAddressSpace())
                || start.compareTo(end) > 0) {
            return Response.err(
                "start and end must be ordered in the same address space");
        }
        ReferenceManager manager = program.getReferenceManager();
        List<Reference> referencesIntoRange = new ArrayList<>();
        var destinations = manager.getReferenceDestinationIterator(
            new AddressSet(start, end), true);
        while (destinations.hasNext()) {
            ReferenceIterator references =
                manager.getReferencesTo(destinations.next());
            while (references.hasNext()) {
                referencesIntoRange.add(references.next());
            }
        }
        referencesIntoRange.sort(referenceComparator());
        List<Map<String, Object>> rows = referencesIntoRange.stream()
            .map(XrefCallGraphService::referenceRecord).toList();
        return paged(rows, offset, limit);
    }

    private Response relatedFunctions(
            String addressText, String programName, boolean callees) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Function function = function(resolved.program(), addressText);
        if (function == null) {
            return Response.err("No function contains " + addressText);
        }
        Set<Function> related = callees
            ? function.getCalledFunctions(TaskMonitor.DUMMY)
            : function.getCallingFunctions(TaskMonitor.DUMMY);
        List<Map<String, Object>> rows = related.stream()
            .sorted(Comparator.comparing(Function::getEntryPoint))
            .map(XrefCallGraphService::functionRecord)
            .toList();
        return Response.ok(rows);
    }

    private ServiceUtils.ProgramOrError resolve(String programName) {
        return ServiceUtils.getProgramOrError(programs, programName);
    }

    private static Function function(Program program, String addressText) {
        Address address = ServiceUtils.parseAddress(program, addressText);
        return address == null
            ? null : ServiceUtils.getFunctionForAddress(program, address);
    }

    private static Map<String, Object> functionRecord(Function function) {
        return Map.of(
            "address", function.getEntryPoint().toString(),
            "name", function.getName(true));
    }

    private static Map<String, Object> referenceRecord(
            Reference reference) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("from", reference.getFromAddress().toString());
        row.put("to", reference.getToAddress().toString());
        row.put("type", reference.getReferenceType().getName());
        row.put("source_kind",
            ReferenceOrdering.sourceKind(reference.getSource()));
        row.put("operand_index", reference.getOperandIndex());
        return row;
    }

    private static Comparator<Reference> referenceComparator() {
        return Comparator
            .comparing(Reference::getToAddress)
            .thenComparing(Reference::getFromAddress)
            .thenComparingInt(Reference::getOperandIndex);
    }

    private static Response validatePage(int offset, int limit) {
        if (offset < 0) {
            return Response.err("offset must be non-negative");
        }
        if (limit < 1 || limit > MAX_LIMIT) {
            return Response.err("limit must be between 1 and " + MAX_LIMIT);
        }
        return null;
    }

    private static Response paged(
            List<Map<String, Object>> rows, int offset, int limit) {
        List<Map<String, Object>> page = offset >= rows.size()
            ? List.of()
            : List.copyOf(rows.subList(
                offset, Math.min(rows.size(), offset + limit)));
        return Response.ok(JsonHelper.mapOf(
            "references", page,
            "total", rows.size(),
            "offset", offset,
            "limit", limit));
    }
}
