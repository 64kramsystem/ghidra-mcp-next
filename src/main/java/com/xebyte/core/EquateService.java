package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;

import java.util.Arrays;
import java.util.List;

/** Apply a named value to one instruction operand. */
public final class EquateService {

    private final ProgramProvider programs;
    private final ThreadingStrategy threading;

    public EquateService(
            ProgramProvider programs, ThreadingStrategy threading) {
        this.programs = programs;
        this.threading = threading;
    }

    @McpTool(
        path = "/set_equate",
        method = "POST",
        description = "Apply a named scalar value to one instruction operand"
    )
    public Response setEquate(
            @Param(value = "address",
                source = ParamSource.BODY)
                String addressText,
            @Param(value = "operand_index", source = ParamSource.BODY)
                int operandIndex,
            @Param(value = "name", source = ParamSource.BODY)
                String name,
            @Param(value = "value", source = ParamSource.BODY)
                long value,
            @Param(value = "program", description = "Target program name",
                defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved =
            ServiceUtils.getProgramOrError(programs, programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        if (name == null || name.isBlank()) {
            return Response.err("name is required");
        }

        Program program = resolved.program();
        Address address =
            ServiceUtils.parseMutationAddress(program, addressText);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }
        Instruction instruction =
            program.getListing().getInstructionAt(address);
        if (instruction == null) {
            return Response.err("address is not an instruction");
        }
        if (operandIndex < 0 || operandIndex >= instruction.getNumOperands()) {
            return Response.err("operand_index is outside the instruction");
        }
        boolean matches = Arrays.stream(
                instruction.getOpObjects(operandIndex))
            .filter(Scalar.class::isInstance)
            .map(Scalar.class::cast)
            .anyMatch(scalar ->
                scalar.getValue() == value
                    || scalar.getUnsignedValue() == value
                    || scalar.getSignedValue() == value);
        if (!matches) {
            return Response.err("value is not a scalar in the operand");
        }

        try {
            boolean changed = threading.executeWrite(
                program,
                "Set equate",
                () -> apply(
                    program.getEquateTable(),
                    address,
                    operandIndex,
                    name,
                    value));
            return Response.ok(JsonHelper.mapOf(
                "address",
                    ServiceUtils.addressToJson(address, program).get("address"),
                "operand_index", operandIndex,
                "name", name,
                "value", value,
                "changed", changed));
        } catch (Exception error) {
            return Response.err(
                error.getMessage() == null
                    ? "failed to set equate"
                    : error.getMessage());
        }
    }

    private static boolean apply(
            EquateTable table,
            Address address,
            int operandIndex,
            String name,
            long value) throws Exception {
        Equate named = table.getEquate(name);
        if (named != null && named.getValue() != value) {
            throw new IllegalArgumentException(
                "equate name already has another value");
        }
        List<Equate> atSite = table.getEquates(address, operandIndex);
        for (Equate equate : atSite) {
            if (equate.getName().equals(name)
                    && equate.getValue() == value) {
                return false;
            }
            throw new IllegalArgumentException(
                "operand already has equate " + equate.getName());
        }
        if (named == null) {
            named = table.createEquate(name, value);
        }
        named.addReference(address, operandIndex);
        return true;
    }
}
