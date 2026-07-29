package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Basic analysis, memory inspection, and code searches. */
public final class AnalysisService {

    private static final int MAX_READ_BYTES = 1_048_576;
    private static final int MAX_PATTERN_BYTES = 4_096;

    private final ProgramProvider programs;
    public AnalysisService(ProgramProvider programs) {
        this.programs = programs;
    }

    @McpTool(
        path = "/inspect_memory_content",
        description = "Read a bounded byte range from program memory"
    )
    public Response inspectMemoryContent(
            @Param(value = "address")
                String addressText,
            @Param(value = "length", defaultValue = "64")
                int length,
            @Param(value = "program", defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved =
            ServiceUtils.getProgramOrError(programs, programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        if (length < 1 || length > MAX_READ_BYTES) {
            return Response.err(
                "length must be between 1 and " + MAX_READ_BYTES);
        }
        Program program = resolved.program();
        Address address = ServiceUtils.parseAddress(program, addressText);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }
        try {
            byte[] bytes = new byte[length];
            int count = program.getMemory().getBytes(address, bytes);
            StringBuilder hex = new StringBuilder(count * 2);
            for (int index = 0; index < count; index++) {
                hex.append(String.format("%02X", bytes[index] & 0xff));
            }
            return Response.ok(JsonHelper.mapOf(
                "address",
                    ServiceUtils.addressToJson(address, program).get("address"),
                "bytes_read", count,
                "hex_dump", hex.toString()));
        } catch (Exception error) {
            return Response.err(error.getMessage());
        }
    }

    @McpTool(
        path = "/search_byte_patterns",
        description = "Search initialized memory for hex bytes and ?? wildcards"
    )
    public Response searchBytePatterns(
            @Param(value = "pattern")
                String patternText,
            @Param(value = "start", defaultValue = "")
                String startText,
            @Param(value = "end", defaultValue = "")
                String endText,
            @Param(value = "limit", defaultValue = "1000")
                int limit,
            @Param(value = "program", defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved =
            ServiceUtils.getProgramOrError(programs, programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        if (limit < 1 || limit > 10_000) {
            return Response.err("limit must be between 1 and 10000");
        }
        final Pattern pattern;
        try {
            pattern = Pattern.parse(patternText);
        } catch (IllegalArgumentException error) {
            return Response.err(error.getMessage());
        }

        Program program = resolved.program();
        Address start = null;
        Address end = null;
        if ((startText == null || startText.isBlank())
                != (endText == null || endText.isBlank())) {
            return Response.err("start and end must be supplied together");
        }
        if (startText != null && !startText.isBlank()) {
            start = ServiceUtils.parseAddress(program, startText);
            end = ServiceUtils.parseAddress(program, endText);
            if (start == null || end == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }
            if (!start.getAddressSpace().equals(end.getAddressSpace())
                    || end.compareTo(start) < 0) {
                return Response.err(
                    "start and end must form one forward address-space range");
            }
        }

        List<Map<String, Object>> matches = new ArrayList<>();
        boolean[] more = {false};
        MemorySearchCore.ScanOutcome outcome = MemorySearchCore.scan(
            MemorySearchCore.memorySource(program.getMemory()),
            MemorySearchCore.initializedRanges(program, start, end),
            pattern.bytes.length,
            MemorySearchCore.DEFAULT_CHUNK_SIZE,
            pattern::matches,
            address -> {
                if (matches.size() == limit) {
                    more[0] = true;
                    return false;
                }
                matches.add(ServiceUtils.addressToJson(address, program));
                return true;
            });
        if (outcome.failed()) {
            return Response.err(outcome.error());
        }
        return Response.ok(JsonHelper.mapOf(
            "matches", matches,
            "returned", matches.size(),
            "has_more", more[0]));
    }

    @McpTool(
        path = "/search_instructions",
        description = "Search instructions by mnemonic and operand text"
    )
    public Response searchInstructions(
            @Param(value = "mnemonic", defaultValue = "")
                String mnemonic,
            @Param(value = "operand_pattern", defaultValue = "")
                String operandPattern,
            @Param(value = "function", defaultValue = "")
                String functionScope,
            @Param(value = "limit", defaultValue = "500")
                int limit,
            @Param(value = "program", defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved =
            ServiceUtils.getProgramOrError(programs, programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        String wantedMnemonic = mnemonic == null ? "" : mnemonic.trim();
        String wantedOperand = operandPattern == null
            ? ""
            : operandPattern.trim().toLowerCase(Locale.ROOT);
        if (wantedMnemonic.isEmpty() && wantedOperand.isEmpty()) {
            return Response.err("mnemonic or operand_pattern is required");
        }
        if (limit < 1 || limit > 10_000) {
            return Response.err("limit must be between 1 and 10000");
        }

        Program program = resolved.program();
        AddressSetView scope = program.getMemory();
        if (functionScope != null && !functionScope.isBlank()) {
            FunctionRef.Result function =
                FunctionRef.ofNameOrAddress(functionScope, "")
                    .tryResolve(program);
            if (!function.isSuccess()) {
                return Response.err("function not found: " + functionScope);
            }
            scope = function.function().getBody();
        }

        Listing listing = program.getListing();
        FunctionManager functions = program.getFunctionManager();
        InstructionIterator iterator = listing.getInstructions(scope, true);
        List<Map<String, Object>> matches = new ArrayList<>();
        boolean truncated = false;
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            if (!wantedMnemonic.isEmpty()
                    && !instruction.getMnemonicString()
                        .equalsIgnoreCase(wantedMnemonic)) {
                continue;
            }
            String operands = operands(instruction);
            if (!wantedOperand.isEmpty()
                    && !operands.toLowerCase(Locale.ROOT)
                        .contains(wantedOperand)) {
                continue;
            }
            if (matches.size() == limit) {
                truncated = true;
                break;
            }
            Function function =
                functions.getFunctionContaining(instruction.getAddress());
            Map<String, Object> row = new LinkedHashMap<>(
                ServiceUtils.addressToJson(
                    instruction.getAddress(), program));
            row.put(
                "function", function == null ? null : function.getName());
            row.put("mnemonic", instruction.getMnemonicString());
            row.put("operands", operands);
            matches.add(row);
        }
        return Response.ok(JsonHelper.mapOf(
            "matches", matches,
            "returned", matches.size(),
            "truncated", truncated));
    }

    @McpTool(
        path = "/get_language_metadata",
        description = "Get processor, endian, and address-space metadata"
    )
    public Response getLanguageMetadata(
            @Param(value = "program", defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved =
            ServiceUtils.getProgramOrError(programs, programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Program program = resolved.program();
        var language = program.getLanguage();
        List<Map<String, Object>> spaces = new ArrayList<>();
        for (var space : program.getAddressFactory().getAllAddressSpaces()) {
            spaces.add(JsonHelper.mapOf(
                "name", space.getName(),
                "size", space.getSize(),
                "pointer_size", space.getPointerSize(),
                "type", space.getType()));
        }
        return Response.ok(JsonHelper.mapOf(
            "language_id", language.getLanguageID().getIdAsString(),
            "processor", language.getProcessor().toString(),
            "endian",
                language.getLanguageDescription().getEndian().toString(),
            "default_space", language.getDefaultSpace().getName(),
            "address_spaces", spaces));
    }

    private static String operands(Instruction instruction) {
        StringBuilder text = new StringBuilder();
        for (int index = 0; index < instruction.getNumOperands(); index++) {
            if (index > 0) {
                text.append(", ");
            }
            text.append(
                instruction.getDefaultOperandRepresentation(index));
        }
        return text.toString();
    }

    private record Pattern(byte[] bytes, byte[] mask) {

        static Pattern parse(String text) {
            if (text == null || text.isBlank()) {
                throw new IllegalArgumentException("pattern is required");
            }
            String compact = text.replaceAll("\\s+", "");
            if ((compact.length() & 1) != 0) {
                throw new IllegalArgumentException(
                    "pattern must contain whole hex bytes");
            }
            int length = compact.length() / 2;
            if (length < 1 || length > MAX_PATTERN_BYTES) {
                throw new IllegalArgumentException(
                    "pattern must contain 1 to "
                        + MAX_PATTERN_BYTES + " bytes");
            }
            byte[] bytes = new byte[length];
            byte[] mask = new byte[length];
            for (int index = 0; index < length; index++) {
                String token =
                    compact.substring(index * 2, index * 2 + 2);
                if ("??".equals(token)) {
                    continue;
                }
                try {
                    bytes[index] =
                        (byte) Integer.parseInt(token, 16);
                    mask[index] = (byte) 0xff;
                } catch (NumberFormatException error) {
                    throw new IllegalArgumentException(
                        "invalid pattern byte: " + token, error);
                }
            }
            return new Pattern(bytes, mask);
        }

        boolean matches(byte[] buffer, int offset) {
            for (int index = 0; index < bytes.length; index++) {
                if ((buffer[offset + index] & mask[index])
                        != bytes[index]) {
                    return false;
                }
            }
            return true;
        }
    }
}
