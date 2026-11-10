package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Apply named values to instruction operands atomically. */
public final class EquateService {
    private static final String SCHEMA = "{\"type\":\"array\",\"minItems\":1,\"items\":{"
        + "\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\"},"
        + "\"operand_index\":{\"type\":\"integer\"},\"value\":{\"type\":\"integer\"},"
        + "\"name\":{\"type\":\"string\"},\"replaces\":{\"type\":\"string\"}},"
        + "\"required\":[\"address\",\"operand_index\",\"value\",\"name\"]}}";
    private final ProgramProvider programs;
    private final ThreadingStrategy threading;

    public EquateService(ProgramProvider programs, ThreadingStrategy threading) {
        this.programs = programs;
        this.threading = threading;
    }

    @McpTool(path = "/apply_equates", method = "POST",
        description = "Atomically apply named scalar values to instruction operands")
    public Response applyEquates(
            @Param(value = "assignments", source = ParamSource.BODY,
                schemaFragment = SCHEMA) Object assignments,
            @Param(value = "program", defaultValue = "", description = "Target program name")
                String programName) {
        ServiceUtils.ProgramOrError resolved = ServiceUtils.getProgramOrError(programs, programName);
        if (resolved.hasError()) return resolved.error();
        if (!(assignments instanceof List<?> items) || items.isEmpty()) {
            return Response.err("assignments must be a nonempty native JSON array");
        }
        Program program = resolved.program();
        try {
            return threading.executeWrite(program, "Apply equates", () -> {
                List<Object> results = new ArrayList<>();
                for (int i = 0; i < items.size(); i++) {
                    try {
                        results.add(apply(program, items.get(i)));
                    }
                    catch (Exception e) {
                        throw new IllegalArgumentException("assignments[" + i + "]: " + e.getMessage(), e);
                    }
                }
                return Response.ok(JsonHelper.mapOf("assignments", results));
            });
        }
        catch (Exception e) {
            return Response.err(e.getMessage() == null ? "failed to apply equates" : e.getMessage());
        }
    }

    private static Map<String, Object> apply(Program program, Object item) throws Exception {
        if (!(item instanceof Map<?, ?> map)) throw new IllegalArgumentException("must be an object");
        String addressText = string(map, "address", true);
        String name = string(map, "name", true);
        String replaces = string(map, "replaces", false);
        long value = integer(map, "value");
        int operandIndex = Math.toIntExact(integer(map, "operand_index"));
        Address address = ServiceUtils.parseMutationAddress(program, addressText);
        if (address == null) throw new IllegalArgumentException(ServiceUtils.getLastParseError());
        Instruction instruction = program.getListing().getInstructionAt(address);
        if (instruction == null) throw new IllegalArgumentException("address is not an instruction");
        if (operandIndex < 0 || operandIndex >= instruction.getNumOperands()) {
            throw new IllegalArgumentException("operand_index is outside the instruction");
        }
        boolean matches = Arrays.stream(instruction.getOpObjects(operandIndex))
            .filter(Scalar.class::isInstance).map(Scalar.class::cast)
            .anyMatch(s -> s.getValue() == value || s.getUnsignedValue() == value || s.getSignedValue() == value);
        if (!matches) throw new IllegalArgumentException("value is not a scalar in the operand");
        EquateTable table = program.getEquateTable();
        List<Equate> atSite = table.getEquates(address, operandIndex);
        if (atSite.size() > 1) throw new IllegalArgumentException("operand has multiple equates");
        Equate named = table.getEquate(name);
        if (named != null && named.getValue() != value) {
            throw new IllegalArgumentException("equate name already has another value");
        }
        boolean changed = true;
        if (!atSite.isEmpty()) {
            Equate old = atSite.get(0);
            if (old.getName().equals(name) && old.getValue() == value) changed = false;
            else {
                if (!old.getName().equals(replaces)) {
                    throw new IllegalArgumentException("operand already has equate " + old.getName());
                }
                old.removeReference(address, operandIndex);
                if (old.getReferenceCount() == 0) table.removeEquate(old.getName());
            }
        }
        if (changed) {
            if (named == null) named = table.createEquate(name, value);
            named.addReference(address, operandIndex);
        }
        return JsonHelper.mapOf("address", ServiceUtils.addressToJson(address, program).get("address"),
            "operand_index", operandIndex, "name", name, "value", value, "changed", changed);
    }

    private static String string(Map<?, ?> map, String key, boolean required) {
        Object value = map.get(key);
        if (value == null && !required) return null;
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException(key + " must be a nonempty string");
        }
        return text;
    }

    private static long integer(Map<?, ?> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof Number number)) throw new IllegalArgumentException(key + " must be an integer");
        try { return new BigDecimal(number.toString()).longValueExact(); }
        catch (ArithmeticException | NumberFormatException e) {
            throw new IllegalArgumentException(key + " must be an exact 64-bit integer", e);
        }
    }
}
