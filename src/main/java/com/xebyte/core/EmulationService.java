package com.xebyte.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
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

    /**
     * Execute bounded P-code from an exact address without requiring a function.
     */
    @McpTool(path = "/emulate_address", method = "POST",
            description = "Execute bounded P-code from an exact address without "
                    + "creating or requiring a function. Returns an instruction "
                    + "trace, semantic memory accesses, changed registers, "
                    + "self-modifying writes, and optional final memory captures.",
            category = "emulation")
    public Response emulateAddress(
            @Param(value = "address", paramType = "address",
                    source = ParamSource.BODY,
                    description = "Mapped program address where execution starts")
                    String address,
            @Param(value = "registers", source = ParamSource.BODY,
                    fieldsJson = true, defaultValue = "",
                    description = "Initial register values as a JSON object")
                    String registers,
            @Param(value = "memory", source = ParamSource.BODY,
                    fieldsJson = true, defaultValue = "",
                    description = "Ordered JSON array of {start, bytes} memory overrides")
                    String memory,
            @Param(value = "stop_addresses", source = ParamSource.BODY,
                    fieldsJson = true, defaultValue = "",
                    description = "JSON array of addresses checked before execution")
                    String stopAddresses,
            @Param(value = "capture_memory", source = ParamSource.BODY,
                    fieldsJson = true, defaultValue = "",
                    description = "JSON array of inclusive {start, end} final-memory ranges")
                    String captureMemory,
            @Param(value = "return_address", source = ParamSource.BODY,
                    defaultValue = "",
                    description = "6502-family synthetic return address")
                    String returnAddress,
            @Param(value = "terminal_policy", source = ParamSource.BODY,
                    defaultValue = "stop",
                    description = "stop or execute for terminal instructions")
                    String terminalPolicy,
            @Param(value = "max_steps", source = ParamSource.BODY,
                    defaultValue = "10000",
                    description = "Instruction limit, from 1 through 100000")
                    int maxSteps,
            @Param(value = "trace_limit", source = ParamSource.BODY,
                    defaultValue = "10000",
                    description = "Trace record limit, from 1 through 100000")
                    int traceLimit,
            @Param(value = "access_log_limit", source = ParamSource.BODY,
                    defaultValue = "100000",
                    description = "Memory-access limit, from 1 through 1000000")
                    int accessLogLimit,
            @Param(value = "program", defaultValue = "") String programName) {

        ServiceUtils.ProgramOrError pe =
            ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) {
            return pe.error();
        }
        Program program = pe.program();

        try {
            return threadingStrategy.executeRead(() -> {
                AddressEmulationEngine.Request request =
                    AddressEmulationEngine.parseRequest(
                        program,
                        address,
                        registers,
                        memory,
                        stopAddresses,
                        captureMemory,
                        returnAddress,
                        terminalPolicy,
                        maxSteps,
                        traceLimit,
                        accessLogLimit);
                return Response.ok(
                    serializeResult(
                        AddressEmulationEngine.execute(program, request)));
            });
        }
        catch (Exception error) {
            return Response.err(
                "Address emulation failed: " + exceptionMessage(error));
        }
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
            int effectiveMaxSteps = Math.min(
                maxSteps > 0 ? maxSteps : DEFAULT_MAX_STEPS, MAX_STEPS);
            Map<Register, BigInteger> registers =
                parseLegacyRegisters(program, registersJson);
            Set<String> requestedRegisters =
                requestedRegisterNames(program, returnRegisters);
            Set<Register> resultRegisters =
                new LinkedHashSet<>(registers.keySet());
            for (String registerName : requestedRegisters) {
                Register register = program.getRegister(registerName);
                if (register != null) {
                    resultRegisters.add(register);
                }
            }
            LegacyExecution execution = executeLegacy(
                program,
                entryAddr,
                registers,
                resultRegisters,
                parseLegacyMemory(program, memoryJson),
                effectiveMaxSteps);
            AddressEmulationEngine.Result emulation = execution.result();

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", execution.hitReturn());
            result.put("function", func.getName());
            result.put("entry_address", entryAddr.toString());
            result.put("steps_executed", emulation.steps());
            result.put("max_steps", effectiveMaxSteps);
            result.put("stop_reason", execution.hitReturn()
                ? "return" : emulation.stopReason());
            Address finalPc = emulation.finalPc();
            result.put("final_pc",
                finalPc != null ? finalPc.toString() : "unknown");
            result.put("hit_return", execution.hitReturn());

            Map<String, String> regValues = new LinkedHashMap<>();
            for (String registerName : requestedRegisters) {
                BigInteger value =
                    emulation.finalRegisters().get(registerName);
                if (value != null) {
                    regValues.put(registerName, hex(value));
                }
                else {
                    regValues.put(
                        registerName,
                        "error: register not available in final state");
                }
            }
            result.put("registers", regValues);
            if (emulation.error() != null) {
                result.put("emulation_error", emulation.error());
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
        Map<Register, BigInteger> extraRegs;
        try {
            extraRegs =
                parseLegacyRegisters(program, initialRegistersJson);
        }
        catch (Exception error) {
            return Response.err(
                "Invalid initial_registers: " + exceptionMessage(error));
        }

        try {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("function", func.getName());
            result.put("target_hash", "0x" + Long.toHexString(targetHash));
            result.put("total_candidates", candidates.size());

            Address scratchAddr = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(SCRATCH_BASE);
            Register inputRegister = requireRegister(
                program, stringRegister);
            Register outputRegister = requireRegister(
                program, resultRegister);

            List<Map<String, String>> matches = new ArrayList<>();
            int tested = 0;

            for (String candidate : candidates) {
                tested++;
                byte[] stringBytes = (candidate + "\0").getBytes(
                    wideString ? StandardCharsets.UTF_16LE : StandardCharsets.US_ASCII);
                Map<Register, BigInteger> registers =
                    new LinkedHashMap<>(extraRegs);
                registers.put(
                    inputRegister,
                    BigInteger.valueOf(SCRATCH_BASE));
                Set<Register> resultRegisters =
                    new LinkedHashSet<>(registers.keySet());
                resultRegisters.add(outputRegister);
                AddressEmulationEngine.MemoryOverride stringMemory =
                    memoryOverride(scratchAddr, stringBytes);
                LegacyExecution execution = executeLegacy(
                    program,
                    entryAddr,
                    registers,
                    resultRegisters,
                    List.of(stringMemory),
                    DEFAULT_MAX_STEPS);
                if (!execution.hitReturn()) {
                    return Response.err("Batch emulation failed for candidate " + tested
                        + " ('" + candidate + "'): "
                        + execution.result().stopReason());
                }

                BigInteger hashResult =
                    execution.result().finalRegisters().get(resultRegister);
                if (hashResult == null) {
                    return Response.err(
                        "Result register unavailable after emulation: "
                            + resultRegister);
                }
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

    private record LegacyExecution(
            AddressEmulationEngine.Result result,
            Address returnSentinel) {

        boolean hitReturn() {
            return returnSentinel.equals(result.finalPc())
                && "stop_address".equals(result.stopReason());
        }
    }

    private static LegacyExecution executeLegacy(
            Program program,
            Address entry,
            Map<Register, BigInteger> requestedRegisters,
            Set<Register> resultRegisters,
            List<AddressEmulationEngine.MemoryOverride> requestedMemory,
            int maxSteps) {
        Map<Register, BigInteger> registers =
            new LinkedHashMap<>(requestedRegisters);
        List<AddressEmulationEngine.MemoryOverride> memory =
            new ArrayList<>(requestedMemory);
        AddressSpace space =
            program.getAddressFactory().getDefaultAddressSpace();
        Address returnSentinel;
        Address injectedReturn = null;
        if (is6502Family(program)) {
            returnSentinel = space.getAddress(0xdead);
            Register stackPointer = requireStackPointer(program);
            registers.putIfAbsent(
                stackPointer, BigInteger.valueOf(0x01fd));
            injectedReturn = returnSentinel;
        }
        else {
            long returnOffset =
                boundedOffset(space, 0xdeadbeefL, 1);
            returnSentinel = space.getAddress(returnOffset);
            configureLegacyStack(
                program,
                registers,
                memory,
                boundedOffset(
                    space,
                    0x7fff0000L,
                    Math.max(1, program.getDefaultPointerSize())),
                returnOffset);
        }

        AddressEmulationEngine.Request request =
            new AddressEmulationEngine.Request(
                entry,
                registers,
                resultRegisters,
                memory,
                Set.of(returnSentinel),
                List.of(),
                injectedReturn,
                AddressEmulationEngine.TerminalPolicy.EXECUTE,
                AddressEmulationEngine.validateLimits(
                    maxSteps, 1, 1));
        return new LegacyExecution(
            AddressEmulationEngine.execute(program, request),
            returnSentinel);
    }

    private static void configureLegacyStack(
            Program program,
            Map<Register, BigInteger> registers,
            List<AddressEmulationEngine.MemoryOverride> memory,
            long stackOffset,
            long returnOffset) {
        Address stackAddress = program.getAddressFactory()
            .getDefaultAddressSpace().getAddress(stackOffset);
        Register stackPointer = program.getCompilerSpec().getStackPointer();
        if (stackPointer == null) {
            throw new IllegalStateException("Program compiler spec does not define a stack pointer");
        }
        registers.put(stackPointer, unsignedAddress(stackAddress));

        // Preserve the legacy x86 frame setup where a frame-pointer register is available.
        for (String framePointerName : new String[]{"RBP", "EBP"}) {
            Register framePointer = program.getRegister(framePointerName);
            if (framePointer != null) {
                registers.put(framePointer, unsignedAddress(stackAddress));
                break;
            }
        }

        memory.add(
            memoryOverride(
                stackAddress, encodePointer(program, returnOffset)));
    }

    private static AddressEmulationEngine.MemoryOverride memoryOverride(
            Address start, byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            throw new IllegalArgumentException(
                "Memory override must contain at least one byte");
        }
        try {
            Address end = start.addNoWrap(bytes.length - 1L);
            return new AddressEmulationEngine.MemoryOverride(
                start, end, bytes);
        }
        catch (Exception error) {
            throw new IllegalArgumentException(
                "Memory override overflows its address space", error);
        }
    }

    private static long boundedOffset(
            AddressSpace space, long preferred, int reservedBytes) {
        BigInteger maximum =
            new BigInteger(
                Long.toUnsignedString(
                    space.getMaxAddress().getUnsignedOffset()));
        BigInteger reserve =
            BigInteger.valueOf(Math.max(1, reservedBytes));
        BigInteger highest =
            maximum.subtract(reserve).max(BigInteger.ZERO);
        BigInteger desired =
            new BigInteger(Long.toUnsignedString(preferred));
        return desired.min(highest).longValue();
    }

    private static BigInteger unsignedAddress(Address address) {
        return new BigInteger(
            Long.toUnsignedString(address.getUnsignedOffset()));
    }

    private static Register requireStackPointer(Program program) {
        Register stackPointer =
            program.getCompilerSpec().getStackPointer();
        if (stackPointer == null) {
            throw new IllegalStateException(
                "Program compiler spec does not define a stack pointer");
        }
        return stackPointer;
    }

    private static Register requireRegister(
            Program program, String name) {
        Register register = program.getRegister(name);
        if (register == null) {
            throw new IllegalArgumentException(
                "Unknown register: " + name);
        }
        return register;
    }

    private static boolean is6502Family(Program program) {
        String processor =
            program.getLanguage().getProcessor().toString();
        return "6502".equalsIgnoreCase(processor)
            || "65C02".equalsIgnoreCase(processor);
    }

    private static Map<Register, BigInteger> parseLegacyRegisters(
            Program program, String json) {
        Map<Register, BigInteger> result = new LinkedHashMap<>();
        if (json == null || json.isBlank()) {
            return result;
        }
        JsonElement root = JsonParser.parseString(json);
        if (!root.isJsonObject()) {
            throw new IllegalArgumentException(
                "registers must be a JSON object");
        }
        for (Map.Entry<String, JsonElement> entry
                : root.getAsJsonObject().entrySet()) {
            Register register =
                requireRegister(program, entry.getKey());
            BigInteger value =
                AddressEmulationEngine.parseUnsigned(
                    entry.getValue(),
                    register.getBitLength(),
                    "registers." + entry.getKey());
            result.put(register, value);
        }
        return result;
    }

    private static List<AddressEmulationEngine.MemoryOverride>
            parseLegacyMemory(Program program, String memoryJson) {
        List<AddressEmulationEngine.MemoryOverride> result =
            new ArrayList<>();
        if (memoryJson == null || memoryJson.isBlank()) {
            return result;
        }
        JsonElement root = JsonParser.parseString(memoryJson);
        if (root.isJsonObject()
                && root.getAsJsonObject().has("regions")) {
            root = root.getAsJsonObject().get("regions");
        }
        if (!root.isJsonArray()) {
            throw new IllegalArgumentException(
                "memory must be a JSON array of regions");
        }
        for (int index = 0;
                index < root.getAsJsonArray().size();
                index++) {
            JsonElement item = root.getAsJsonArray().get(index);
            if (!item.isJsonObject()) {
                throw new IllegalArgumentException(
                    "memory[" + index + "] must be an object");
            }
            JsonObject region = item.getAsJsonObject();
            if (!region.has("address")) {
                throw new IllegalArgumentException(
                    "memory[" + index + "].address is required");
            }
            Address memoryAddress = ServiceUtils.parseAddress(
                program, region.get("address").getAsString());
            if (memoryAddress == null) {
                throw new IllegalArgumentException(
                    ServiceUtils.getLastParseError());
            }
            byte[] bytes;
            if (region.has("string")) {
                bytes =
                    (region.get("string").getAsString() + "\0")
                        .getBytes(StandardCharsets.UTF_8);
            }
            else if (region.has("data")) {
                bytes = Base64.getDecoder().decode(
                    region.get("data").getAsString());
            }
            else if (region.has("hex")) {
                bytes = hexToBytes(
                    region.get("hex").getAsString());
            }
            else {
                throw new IllegalArgumentException(
                    "memory region requires string, data, or hex");
            }
            AddressEmulationEngine.MemoryOverride override =
                memoryOverride(memoryAddress, bytes);
            for (AddressEmulationEngine.MemoryOverride existing
                    : result) {
                if (existing.start().hasSameAddressSpace(
                            override.start())
                        && existing.start().compareTo(
                            override.end()) <= 0
                        && override.start().compareTo(
                            existing.end()) <= 0) {
                    throw new IllegalArgumentException(
                        "memory regions must not overlap");
                }
            }
            result.add(override);
        }
        return result;
    }

    private static Set<String> requestedRegisterNames(
            Program program, String names) {
        Set<String> result = new LinkedHashSet<>();
        if (names != null && !names.isBlank()) {
            for (String name : names.split(",")) {
                String trimmed = name.trim();
                if (!trimmed.isEmpty()) {
                    result.add(trimmed);
                }
            }
            return result;
        }
        for (String name : new String[]{
                "EAX", "EBX", "ECX", "EDX",
                "ESI", "EDI", "ESP", "EBP", "EIP"}) {
            if (program.getRegister(name) != null) {
                result.add(name);
            }
        }
        return result;
    }

    private static JsonObject serializeResult(
            AddressEmulationEngine.Result result) {
        JsonObject json = new JsonObject();
        json.addProperty("entry", result.entry().toString());
        json.addProperty("stop_reason", result.stopReason());
        json.addProperty("steps", result.steps());
        addNullableAddress(json, "final_pc", result.finalPc());

        JsonObject finalRegisters = new JsonObject();
        addRegisterValues(finalRegisters, result.finalRegisters());
        json.add("final_registers", finalRegisters);

        JsonObject changedRegisters = new JsonObject();
        for (Map.Entry<String, AddressEmulationEngine.RegisterChange>
                change : result.changedRegisters().entrySet()) {
            JsonObject values = new JsonObject();
            values.addProperty("before", hex(change.getValue().before()));
            values.addProperty("after", hex(change.getValue().after()));
            changedRegisters.add(change.getKey(), values);
        }
        json.add("changed_registers", changedRegisters);

        JsonArray trace = new JsonArray();
        for (AddressEmulationEngine.TraceRecord record : result.trace()) {
            JsonObject item = new JsonObject();
            item.addProperty("step", record.step());
            item.addProperty("address", record.address().toString());
            if (record.instruction() == null) {
                item.add("instruction", JsonNull.INSTANCE);
            }
            else {
                item.addProperty("instruction", record.instruction());
            }
            item.addProperty(
                "bytes", HexFormat.of().formatHex(record.bytes()));
            item.addProperty("executed", record.executed());
            JsonObject pre = new JsonObject();
            addRegisterValues(pre, record.preRegisters());
            item.add("pre_registers", pre);
            JsonObject post = new JsonObject();
            addRegisterValues(post, record.postRegisters());
            item.add("post_registers", post);
            item.add(
                "memory_accesses",
                serializeAccesses(record.memoryAccesses()));
            addNullableAddress(item, "next_pc", record.nextPc());
            trace.add(item);
        }
        json.add("trace", trace);

        json.add("access_log", serializeAccesses(result.accesses()));
        json.add(
            "memory_reads",
            serializeRanges(
                AddressEmulationEngine.coalesceAccesses(
                    result.accesses(),
                    AddressEmulationEngine.AccessKind.READ)));
        json.add(
            "memory_writes",
            serializeRanges(
                AddressEmulationEngine.coalesceAccesses(
                    result.accesses(),
                    AddressEmulationEngine.AccessKind.WRITE)));
        json.add(
            "self_modifying_writes",
            serializeAccesses(result.selfModifyingWrites()));

        AddressEmulationEngine.UnresolvedControlFlow unresolved =
            result.unresolvedControlFlow();
        if (unresolved == null) {
            json.add("unresolved_control_flow", JsonNull.INSTANCE);
        }
        else {
            JsonObject flow = new JsonObject();
            flow.addProperty(
                "instruction", unresolved.instruction().toString());
            if (unresolved.instructionText() == null) {
                flow.add("instruction_text", JsonNull.INSTANCE);
            }
            else {
                flow.addProperty(
                    "instruction_text", unresolved.instructionText());
            }
            flow.add(
                "missing_state",
                serializeRanges(unresolved.missingState()));
            JsonObject availableRegisters = new JsonObject();
            addRegisterValues(
                availableRegisters,
                unresolved.availableRegisters());
            flow.add(
                "available_registers",
                availableRegisters);
            flow.add(
                "available_memory",
                serializeRanges(unresolved.availableMemory()));
            json.add("unresolved_control_flow", flow);
        }

        JsonArray captured = new JsonArray();
        for (AddressEmulationEngine.CapturedMemory range
                : result.capturedMemory()) {
            JsonObject item = new JsonObject();
            item.addProperty("start", range.start().toString());
            item.addProperty("end", range.end().toString());
            item.addProperty("size", range.bytes().length);
            item.addProperty(
                "bytes", HexFormat.of().formatHex(range.bytes()));
            captured.add(item);
        }
        json.add("captured_memory", captured);

        AddressEmulationEngine.ReturnInjection injection =
            result.returnInjection();
        if (injection == null) {
            json.add("return_injection", JsonNull.INSTANCE);
        }
        else {
            JsonObject injected = new JsonObject();
            injected.addProperty(
                "low_address", injection.lowAddress().toString());
            injected.addProperty(
                "low_byte",
                HexFormat.of().toHexDigits(injection.lowByte()));
            injected.addProperty(
                "high_address", injection.highAddress().toString());
            injected.addProperty(
                "high_byte",
                HexFormat.of().toHexDigits(injection.highByte()));
            json.add("return_injection", injected);
        }
        json.addProperty("trace_truncated", result.traceTruncated());
        json.addProperty(
            "access_log_truncated", result.accessLogTruncated());
        if (result.error() == null) {
            json.add("error", JsonNull.INSTANCE);
        }
        else {
            json.addProperty("error", result.error());
        }
        return json;
    }

    private static JsonArray serializeAccesses(
            List<AddressEmulationEngine.MemoryAccess> accesses) {
        JsonArray result = new JsonArray();
        for (AddressEmulationEngine.MemoryAccess access : accesses) {
            JsonObject item = new JsonObject();
            item.addProperty("sequence", access.sequence());
            item.addProperty("step", access.step());
            item.addProperty(
                "kind", access.kind().name().toLowerCase(Locale.ROOT));
            item.addProperty("start", access.start().toString());
            item.addProperty("end", access.end().toString());
            item.addProperty("size", access.bytes().length);
            item.addProperty(
                "bytes", HexFormat.of().formatHex(access.bytes()));
            result.add(item);
        }
        return result;
    }

    private static JsonArray serializeRanges(
            List<AddressEmulationEngine.MemoryRange> ranges) {
        JsonArray result = new JsonArray();
        for (AddressEmulationEngine.MemoryRange range : ranges) {
            JsonObject item = new JsonObject();
            item.addProperty("start", range.start().toString());
            item.addProperty("end", range.end().toString());
            item.addProperty(
                "size",
                range.end().subtract(range.start()) + 1);
            if (range.bytes().length > 0) {
                item.addProperty(
                    "bytes",
                    HexFormat.of().formatHex(range.bytes()));
            }
            result.add(item);
        }
        return result;
    }

    private static void addRegisterValues(
            JsonObject json, Map<String, BigInteger> values) {
        for (Map.Entry<String, BigInteger> value : values.entrySet()) {
            json.addProperty(value.getKey(), hex(value.getValue()));
        }
    }

    private static void addNullableAddress(
            JsonObject json, String field, Address address) {
        if (address == null) {
            json.add(field, JsonNull.INSTANCE);
        }
        else {
            json.addProperty(field, address.toString());
        }
    }

    private static String hex(BigInteger value) {
        return "0x" + value.toString(16);
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
