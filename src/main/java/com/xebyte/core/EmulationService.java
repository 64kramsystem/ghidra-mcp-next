package com.xebyte.core;

import ghidra.pcode.emu.EmulatorUtilities;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * MCP endpoints for targeted function emulation via Ghidra's P-code emulator.
 *
 * <p>Designed for API hash resolution: emulate a hash function with controlled
 * inputs (candidate API name string in memory, hash parameters in registers)
 * and read the computed hash from the output register. No full process needed —
 * the emulator runs the function's P-code in isolation.</p>
 *
 * <h3>Typical agent workflow for API hash resolution</h3>
 * <pre>{@code
 * 1. decompile_function(hash_func_addr) → understand calling convention
 * 2. get_function_variables(hash_func) → identify input/output registers
 * 3. emulate_function(hash_func_addr, registers={ECX: string_ptr},
 *        memory=[{addr: string_ptr, data: "CreateProcessW\0"}])
 *    → returns {EAX: 0x7C0DFCAA}
 * 4. Compare 0x7C0DFCAA against target hash → match!
 * 5. batch_set_comments(hash_call_addr, "Resolved: CreateProcessW")
 * }</pre>
 *
 * <h3>Batch mode for brute-forcing</h3>
 * <pre>{@code
 * emulate_hash_batch(hash_func_addr, register_template={ECX: "${STRING_PTR}"},
 *     candidates=["CreateProcessW", "VirtualAlloc", "LoadLibraryA", ...],
 *     target_hash=0x7C0DFCAA, result_register="EAX")
 *   → returns {matched: "CreateProcessW", hash: 0x7C0DFCAA, iterations: 42}
 * }</pre>
 *
 * @since 5.4.0
 */
@McpToolGroup(value = "emulation",
        description = "Targeted function emulation for hash resolution, crypto analysis, " +
                "and controlled execution of isolated code paths")
public class EmulationService {

    private static final int DEFAULT_MAX_STEPS = 10_000;
    private static final int MAX_STEPS = 100_000;
    private static final int MAX_CANDIDATES = 10_000;
    // Scratch memory for writing candidate strings during emulation
    private static final long SCRATCH_BASE = 0x7FFE0000L;

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public EmulationService(ProgramProvider programProvider,
                            ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    /** Thin typed facade over Ghidra's concrete 12.1 P-code machine and one execution thread. */
    private static final class EmulationSession {
        private final Program program;
        private final PcodeEmulator emulator;
        private final PcodeThread<byte[]> thread;

        EmulationSession(Program program, Address entry) throws Exception {
            this.program = program;
            emulator = new PcodeEmulator(program.getLanguage());
            EmulatorUtilities.loadProgram(emulator, program);
            thread = emulator.newThread();
            EmulatorUtilities.initializeRegisters(thread, program, entry);
        }

        void writeRegister(String name, long value) {
            Register register = program.getRegister(name);
            if (register == null) {
                throw new IllegalArgumentException("Unknown register: " + name);
            }
            writeRegister(register, value);
        }

        void writeRegister(Register register, long value) {
            thread.getState().setRegisterValue(new RegisterValue(register, BigInteger.valueOf(value)));
        }

        BigInteger readRegister(String name) {
            Register register = program.getRegister(name);
            if (register == null) {
                throw new IllegalArgumentException("Unknown register: " + name);
            }
            return thread.getState().inspectRegisterValue(register).getUnsignedValue();
        }

        void writeMemory(Address address, byte[] bytes) {
            emulator.getSharedState().setConcrete(address, bytes);
        }

        Address counter() {
            return thread.getCounter();
        }

        void stepInstruction() {
            thread.stepInstruction();
        }
    }

    private record ExecutionResult(
            int steps, boolean success, boolean hitReturn, String stopReason, String error) {
    }

    // ========================================================================
    // Single-function emulation
    // ========================================================================

    /**
     * Emulate a function with controlled inputs and return the final state.
     *
     * <p>Sets up the P-code emulator with the specified register values and
     * memory contents, runs the function until RET or step limit, and returns
     * all register values at completion.</p>
     */
    @McpTool(path = "/emulate_function", method = "POST",
            description = "Emulate a single function with controlled register/memory inputs. " +
                    "Returns final register state after execution. Ideal for understanding " +
                    "hash functions, crypto routines, or any pure-computation code path.",
            category = "emulation")
    public Response emulateFunction(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                    description = "Entry point address of the function to emulate") String addressStr,
            @Param(value = "registers", source = ParamSource.BODY, fieldsJson = true,
                    description = "Initial register values as JSON: {\"EAX\": \"0x1234\", \"ECX\": \"0x7FFE0000\"}") String registersJson,
            @Param(value = "memory", source = ParamSource.BODY, fieldsJson = true,
                    description = "Memory regions to pre-populate as JSON array: [{\"address\": \"0x7FFE0000\", \"data\": \"base64...\"}] " +
                            "or [{\"address\": \"0x7FFE0000\", \"string\": \"CreateProcessW\\u0000\"}]") String memoryJson,
            @Param(value = "max_steps", source = ParamSource.BODY, defaultValue = "10000",
                    description = "Maximum P-code steps before timeout") int maxSteps,
            @Param(value = "return_registers", source = ParamSource.BODY, defaultValue = "",
                    description = "Comma-separated register names to return (empty = all general-purpose)") String returnRegisters,
            @Param(value = "program", defaultValue = "") String programName) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address entryAddr = ServiceUtils.parseAddress(program, addressStr);
        if (entryAddr == null) return Response.err(ServiceUtils.getLastParseError());

        Function func = program.getFunctionManager().getFunctionAt(entryAddr);
        if (func == null) return Response.err("No function at address: " + addressStr);

        try {
            EmulationSession session = new EmulationSession(program, entryAddr);
            long returnOffset = 0xDEADBEEFL;
            Address returnSentinel = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(returnOffset);
            configureStack(session, program, 0x7FFF0000L, returnOffset);

            if (registersJson != null && !registersJson.isEmpty()) {
                Map<String, Object> regs = JsonHelper.parseJson(registersJson);
                for (Map.Entry<String, Object> entry : regs.entrySet()) {
                    session.writeRegister(
                        entry.getKey(), parseLongValue(String.valueOf(entry.getValue())));
                }
            }

            if (memoryJson != null && !memoryJson.isEmpty()) {
                List<Map<String, String>> regions = ServiceUtils.convertToMapList(
                    JsonHelper.parseJson(memoryJson).get("regions"));
                if (regions == null) {
                    regions = ServiceUtils.convertToMapList(memoryJson);
                }
                if (regions != null) {
                    for (Map<String, String> region : regions) {
                        Address memoryAddress = ServiceUtils.parseAddress(
                            program, String.valueOf(region.get("address")));
                        if (memoryAddress == null) {
                            continue;
                        }
                        if (region.containsKey("string")) {
                            session.writeMemory(memoryAddress,
                                (String.valueOf(region.get("string")) + "\0")
                                    .getBytes(StandardCharsets.UTF_8));
                        } else if (region.containsKey("data")) {
                            session.writeMemory(memoryAddress,
                                Base64.getDecoder().decode(String.valueOf(region.get("data"))));
                        } else if (region.containsKey("hex")) {
                            session.writeMemory(memoryAddress,
                                hexToBytes(String.valueOf(region.get("hex"))));
                        }
                    }
                }
            }

            int effectiveMaxSteps = Math.min(
                maxSteps > 0 ? maxSteps : DEFAULT_MAX_STEPS, MAX_STEPS);
            ExecutionResult execution = executeUntilReturn(
                session, returnSentinel, effectiveMaxSteps);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", execution.success());
            result.put("function", func.getName());
            result.put("entry_address", entryAddr.toString());
            result.put("steps_executed", execution.steps());
            result.put("max_steps", effectiveMaxSteps);
            result.put("stop_reason", execution.stopReason());
            Address finalPc = session.counter();
            result.put("final_pc", finalPc != null ? finalPc.toString() : "unknown");
            result.put("hit_return", execution.hitReturn());

            Map<String, String> regValues = new LinkedHashMap<>();
            if (returnRegisters != null && !returnRegisters.isEmpty()) {
                for (String registerName : returnRegisters.split(",")) {
                    registerName = registerName.trim();
                    try {
                        BigInteger value = session.readRegister(registerName);
                        regValues.put(registerName, "0x" + value.toString(16));
                    } catch (Exception e) {
                        regValues.put(registerName, "error: " + exceptionMessage(e));
                    }
                }
            } else {
                for (String registerName : new String[]{"EAX", "EBX", "ECX", "EDX",
                        "ESI", "EDI", "ESP", "EBP", "EIP"}) {
                    try {
                        BigInteger value = session.readRegister(registerName);
                        regValues.put(registerName, "0x" + value.toString(16));
                    } catch (Exception ignored) {
                        // Register may not exist for this architecture.
                    }
                }
            }
            result.put("registers", regValues);
            if (execution.error() != null) {
                result.put("emulation_error", execution.error());
            }
            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("Emulation failed: " + exceptionMessage(e));
        }
    }

    // ========================================================================
    // Batch hash resolution
    // ========================================================================

    /**
     * Brute-force API hash resolution by emulating a hash function with
     * a list of candidate API name strings.
     *
     * <p>For each candidate, writes the string to scratch memory, sets the
     * string pointer register, emulates the hash function, reads the result
     * register, and compares against the target hash. Stops on first match
     * or after exhausting all candidates.</p>
     */
    @McpTool(path = "/emulate_hash_batch", method = "POST",
            description = "Brute-force API hash resolution. Emulates a hash function with " +
                    "each candidate API name and returns the one that produces the target hash. " +
                    "Ideal for resolving ROR13, CRC32, djb2, FNV, and custom hash algorithms.",
            category = "emulation")
    public Response emulateHashBatch(
            @Param(value = "hash_function_address", paramType = "address", source = ParamSource.BODY,
                    description = "Address of the hash computation function") String hashFuncAddr,
            @Param(value = "string_register", source = ParamSource.BODY,
                    description = "Register that receives the pointer to the API name string (e.g., ECX, RCX, EDI)") String stringRegister,
            @Param(value = "result_register", source = ParamSource.BODY, defaultValue = "EAX",
                    description = "Register that contains the computed hash after emulation (e.g., EAX, RAX)") String resultRegister,
            @Param(value = "target_hash", source = ParamSource.BODY,
                    description = "Target hash value to match (hex string like 0x7C0DFCAA)") String targetHashStr,
            @Param(value = "candidates", source = ParamSource.BODY, fieldsJson = true,
                    description = "JSON array of candidate API name strings: [\"CreateProcessW\", \"VirtualAlloc\", ...]") String candidatesJson,
            @Param(value = "initial_registers", source = ParamSource.BODY, fieldsJson = true, defaultValue = "",
                    description = "Additional register values to set before each emulation (JSON object)") String initialRegistersJson,
            @Param(value = "wide_string", source = ParamSource.BODY, defaultValue = "false",
                    description = "Write candidate strings as UTF-16LE (wide) instead of ASCII") boolean wideString,
            @Param(value = "program", defaultValue = "") String programName) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address entryAddr = ServiceUtils.parseAddress(program, hashFuncAddr);
        if (entryAddr == null) return Response.err(ServiceUtils.getLastParseError());

        Function func = program.getFunctionManager().getFunctionAt(entryAddr);
        if (func == null) return Response.err("No function at address: " + hashFuncAddr);

        long targetHash;
        try {
            targetHash = parseLongValue(targetHashStr);
        } catch (Exception e) {
            return Response.err("Invalid target_hash: " + targetHashStr);
        }

        // Parse candidates
        List<String> candidates = new ArrayList<>();
        if (candidatesJson != null && !candidatesJson.isEmpty()) {
            try {
                Object parsed = JsonHelper.parseJson("{\"c\":" + candidatesJson + "}").get("c");
                if (parsed instanceof List<?> list) {
                    for (Object item : list) {
                        candidates.add(String.valueOf(item));
                    }
                }
            } catch (Exception e) {
                return Response.err("Invalid candidates JSON: " + e.getMessage());
            }
        }
        if (candidates.isEmpty()) {
            return Response.err("No candidates provided");
        }
        if (candidates.size() > MAX_CANDIDATES) {
            return Response.err("Too many candidates (max " + MAX_CANDIDATES + ")");
        }

        // Parse additional registers
        Map<String, Long> extraRegs = new LinkedHashMap<>();
        if (initialRegistersJson != null && !initialRegistersJson.isEmpty()) {
            Map<String, Object> parsed = JsonHelper.parseJson(initialRegistersJson);
            for (Map.Entry<String, Object> entry : parsed.entrySet()) {
                extraRegs.put(entry.getKey(), parseLongValue(String.valueOf(entry.getValue())));
            }
        }

        try {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("function", func.getName());
            result.put("target_hash", "0x" + Long.toHexString(targetHash));
            result.put("total_candidates", candidates.size());

            Address scratchAddr = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(SCRATCH_BASE);
            long returnOffset = 0xDEADBEEFL;
            Address returnSentinel = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(returnOffset);

            List<Map<String, String>> matches = new ArrayList<>();
            int tested = 0;

            for (String candidate : candidates) {
                tested++;
                EmulationSession session = new EmulationSession(program, entryAddr);
                configureStack(session, program, 0x7FFF0000L, returnOffset);

                byte[] stringBytes = (candidate + "\0").getBytes(
                    wideString ? StandardCharsets.UTF_16LE : StandardCharsets.US_ASCII);
                session.writeMemory(scratchAddr, stringBytes);
                session.writeRegister(stringRegister, SCRATCH_BASE);
                for (Map.Entry<String, Long> entry : extraRegs.entrySet()) {
                    session.writeRegister(entry.getKey(), entry.getValue());
                }

                ExecutionResult execution = executeUntilReturn(
                    session, returnSentinel, DEFAULT_MAX_STEPS);
                if (!execution.success()) {
                    return Response.err("Batch emulation failed for candidate " + tested
                        + " ('" + candidate + "'): " + execution.stopReason());
                }

                BigInteger hashResult = session.readRegister(resultRegister);
                long computedHash = hashResult.longValue() & 0xFFFFFFFFL;
                if (computedHash == (targetHash & 0xFFFFFFFFL)) {
                    Map<String, String> match = new LinkedHashMap<>();
                    match.put("api_name", candidate);
                    match.put("computed_hash", "0x" + Long.toHexString(computedHash));
                    match.put("iteration", String.valueOf(tested));
                    matches.add(match);
                }
            }

            result.put("tested", tested);
            result.put("matches", matches);
            result.put("resolved", !matches.isEmpty());
            if (!matches.isEmpty()) {
                result.put("best_match", matches.get(0).get("api_name"));
            }

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("Batch emulation failed: " + exceptionMessage(e));
        }
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private static ExecutionResult executeUntilReturn(
            EmulationSession session, Address returnSentinel, int maxSteps) {
        for (int steps = 1; steps <= maxSteps; steps++) {
            try {
                session.stepInstruction();
            } catch (RuntimeException e) {
                String error = exceptionMessage(e);
                return new ExecutionResult(
                    steps, false, false, "fault: " + error, error);
            }
            if (returnSentinel.equals(session.counter())) {
                return new ExecutionResult(steps, true, true, "return", null);
            }
        }
        return new ExecutionResult(
            maxSteps, false, false, "max_steps_exceeded", null);
    }

    private static Address configureStack(
            EmulationSession session, Program program, long stackOffset, long returnOffset) {
        Address stackAddress = program.getAddressFactory()
            .getDefaultAddressSpace().getAddress(stackOffset);
        Register stackPointer = program.getCompilerSpec().getStackPointer();
        if (stackPointer == null) {
            throw new IllegalStateException("Program compiler spec does not define a stack pointer");
        }
        session.writeRegister(stackPointer, stackAddress.getOffset());

        // Preserve the legacy x86 frame setup where a frame-pointer register is available.
        for (String framePointerName : new String[]{"RBP", "EBP"}) {
            Register framePointer = program.getRegister(framePointerName);
            if (framePointer != null) {
                session.writeRegister(framePointer, stackAddress.getOffset());
                break;
            }
        }

        session.writeMemory(stackAddress, encodePointer(program, returnOffset));
        return stackAddress;
    }

    private static byte[] encodePointer(Program program, long value) {
        int size = Math.max(1, program.getDefaultPointerSize());
        byte[] bytes = new byte[size];
        int encodedBytes = Math.min(size, Long.BYTES);
        boolean bigEndian = program.getLanguage().isBigEndian();
        for (int i = 0; i < encodedBytes; i++) {
            int index = bigEndian ? size - 1 - i : i;
            bytes[index] = (byte) (value >>> (Byte.SIZE * i));
        }
        return bytes;
    }

    private static String exceptionMessage(Throwable error) {
        String message = error.getMessage();
        if (message != null && !message.isBlank()) {
            return message;
        }
        return error.getClass().getSimpleName();
    }

    private static long parseLongValue(String s) {
        if (s == null || s.isEmpty()) return 0;
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return Long.parseUnsignedLong(s.substring(2), 16);
        }
        return Long.parseLong(s);
    }

    private static byte[] hexToBytes(String hex) {
        hex = hex.replace(" ", "").replace("0x", "");
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
