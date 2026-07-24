package com.xebyte.core;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import ghidra.pcode.emu.EmulatorUtilities;
import ghidra.pcode.emu.PcodeEmulationCallbacks;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.mem.MemoryAccessException;

/** Shared bounded p-code execution from an exact program address. */
public final class AddressEmulationEngine {

    static final int DEFAULT_MAX_STEPS = 10_000;
    static final int MAX_STEPS = 100_000;
    static final int DEFAULT_TRACE_LIMIT = 10_000;
    static final int MAX_TRACE_LIMIT = 100_000;
    static final int DEFAULT_ACCESS_LOG_LIMIT = 100_000;
    static final int MAX_ACCESS_LOG_LIMIT = 1_000_000;
    static final long MAX_CAPTURE_BYTES = 1_048_576L;

    enum AccessKind {
        READ,
        WRITE
    }

    enum TerminalPolicy {
        STOP,
        EXECUTE;

        static TerminalPolicy parse(String value) {
            if ("stop".equals(value)) {
                return STOP;
            }
            if ("execute".equals(value)) {
                return EXECUTE;
            }
            throw new IllegalArgumentException(
                "terminal_policy must be 'stop' or 'execute'");
        }
    }

    record Limits(int maxSteps, int traceLimit, int accessLogLimit) {
    }

    record MemoryAccess(
            long sequence,
            int step,
            AccessKind kind,
            Address start,
            byte[] bytes) {

        MemoryAccess {
            if (bytes == null || bytes.length == 0) {
                throw new IllegalArgumentException(
                    "memory access bytes must not be empty");
            }
            bytes = Arrays.copyOf(bytes, bytes.length);
        }

        @Override
        public byte[] bytes() {
            return Arrays.copyOf(bytes, bytes.length);
        }

        Address end() {
            return start.add(bytes.length - 1L);
        }
    }

    record MemoryRange(Address start, Address end, byte[] bytes) {
        MemoryRange {
            bytes = Arrays.copyOf(bytes, bytes.length);
        }

        @Override
        public byte[] bytes() {
            return Arrays.copyOf(bytes, bytes.length);
        }
    }

    record MemoryOverride(Address start, Address end, byte[] bytes) {
        MemoryOverride {
            bytes = Arrays.copyOf(bytes, bytes.length);
        }

        @Override
        public byte[] bytes() {
            return Arrays.copyOf(bytes, bytes.length);
        }
    }

    record CaptureRange(Address start, Address end) {
    }

    record Request(
            Address entry,
            Map<Register, BigInteger> registers,
            Set<Register> resultRegisters,
            List<MemoryOverride> memory,
            Set<Address> stopAddresses,
            List<CaptureRange> captureMemory,
            Address returnAddress,
            TerminalPolicy terminalPolicy,
            Limits limits) {

        Request {
            registers = Collections.unmodifiableMap(
                new LinkedHashMap<>(registers));
            resultRegisters = Collections.unmodifiableSet(
                new LinkedHashSet<>(resultRegisters));
            memory = List.copyOf(memory);
            stopAddresses = Collections.unmodifiableSet(
                new LinkedHashSet<>(stopAddresses));
            captureMemory = List.copyOf(captureMemory);
        }
    }

    record RegisterChange(BigInteger before, BigInteger after) {
    }

    record TraceRecord(
            int step,
            Address address,
            String instruction,
            byte[] bytes,
            boolean executed,
            Map<String, BigInteger> preRegisters,
            Map<String, BigInteger> postRegisters,
            List<MemoryAccess> memoryAccesses,
            Address nextPc) {

        TraceRecord {
            bytes = Arrays.copyOf(bytes, bytes.length);
            preRegisters = Collections.unmodifiableMap(
                new LinkedHashMap<>(preRegisters));
            postRegisters = Collections.unmodifiableMap(
                new LinkedHashMap<>(postRegisters));
            memoryAccesses = List.copyOf(memoryAccesses);
        }

        @Override
        public byte[] bytes() {
            return Arrays.copyOf(bytes, bytes.length);
        }
    }

    record ReturnInjection(
            Address lowAddress,
            byte lowByte,
            Address highAddress,
            byte highByte) {
    }

    record CapturedMemory(Address start, Address end, byte[] bytes) {
        CapturedMemory {
            bytes = Arrays.copyOf(bytes, bytes.length);
        }

        @Override
        public byte[] bytes() {
            return Arrays.copyOf(bytes, bytes.length);
        }
    }

    record UnresolvedControlFlow(
            Address instruction,
            String instructionText,
            List<MemoryRange> missingState,
            Map<String, BigInteger> availableRegisters,
            List<MemoryRange> availableMemory) {

        UnresolvedControlFlow {
            missingState = List.copyOf(missingState);
            availableRegisters = Collections.unmodifiableMap(
                new LinkedHashMap<>(availableRegisters));
            availableMemory = List.copyOf(availableMemory);
        }
    }

    record Result(
            Address entry,
            String stopReason,
            int steps,
            Address finalPc,
            Map<String, BigInteger> finalRegisters,
            Map<String, RegisterChange> changedRegisters,
            List<TraceRecord> trace,
            List<MemoryAccess> accesses,
            List<MemoryAccess> selfModifyingWrites,
            UnresolvedControlFlow unresolvedControlFlow,
            List<CapturedMemory> capturedMemory,
            ReturnInjection returnInjection,
            boolean traceTruncated,
            boolean accessLogTruncated,
            String error) {

        Result {
            finalRegisters = Collections.unmodifiableMap(
                new LinkedHashMap<>(finalRegisters));
            changedRegisters = Collections.unmodifiableMap(
                new LinkedHashMap<>(changedRegisters));
            trace = List.copyOf(trace);
            accesses = List.copyOf(accesses);
            selfModifyingWrites = List.copyOf(selfModifyingWrites);
            capturedMemory = List.copyOf(capturedMemory);
        }
    }

    private AddressEmulationEngine() {
    }

    static Limits validateLimits(
            int maxSteps, int traceLimit, int accessLogLimit) {
        requireLimit("max_steps", maxSteps, MAX_STEPS);
        requireLimit("trace_limit", traceLimit, MAX_TRACE_LIMIT);
        requireLimit(
            "access_log_limit", accessLogLimit, MAX_ACCESS_LOG_LIMIT);
        return new Limits(maxSteps, traceLimit, accessLogLimit);
    }

    private static void requireLimit(String name, int value, int maximum) {
        if (value <= 0 || value > maximum) {
            throw new IllegalArgumentException(
                name + " must be from 1 to " + maximum);
        }
    }

    static Request parseRequest(
            Program program,
            String address,
            String registersJson,
            String memoryJson,
            String stopAddressesJson,
            String captureMemoryJson,
            String returnAddress,
            String terminalPolicy,
            int maxSteps,
            int traceLimit,
            int accessLogLimit) {
        Objects.requireNonNull(program, "program");
        Limits limits =
            validateLimits(maxSteps, traceLimit, accessLogLimit);
        Address entry = parseAddress(program, address, "address");
        if (!program.getMemory().contains(entry)) {
            throw new IllegalArgumentException(
                "address is not mapped program memory: " + entry);
        }

        Map<Register, BigInteger> registers =
            parseRegisters(program, registersJson);
        List<MemoryOverride> memory =
            parseMemoryOverrides(program, memoryJson);
        Set<Address> stopAddresses =
            parseAddressArray(program, stopAddressesJson, "stop_addresses");
        List<CaptureRange> captureMemory =
            parseCaptureRanges(program, captureMemoryJson);
        Address parsedReturn =
            returnAddress == null || returnAddress.isBlank()
                ? null
                : parseAddress(program, returnAddress, "return_address");
        if (parsedReturn != null && !is6502(program)) {
            throw new IllegalArgumentException(
                "return_address is supported only for 6502-family languages");
        }
        return new Request(
            entry,
            registers,
            registers.keySet(),
            memory,
            stopAddresses,
            captureMemory,
            parsedReturn,
            TerminalPolicy.parse(terminalPolicy),
            limits);
    }

    private static Map<Register, BigInteger> parseRegisters(
            Program program, String json) {
        JsonElement root = parseJsonOrDefault(json, "{}", "registers");
        if (!root.isJsonObject()) {
            throw new IllegalArgumentException(
                "registers must be a JSON object");
        }
        Map<Register, BigInteger> result = new LinkedHashMap<>();
        for (Map.Entry<String, JsonElement> item
                : root.getAsJsonObject().entrySet()) {
            Register register = program.getRegister(item.getKey());
            if (register == null) {
                throw new IllegalArgumentException(
                    "Unknown register: " + item.getKey());
            }
            validateInputRegister(
                register, "registers." + item.getKey());
            result.put(
                register,
                parseUnsigned(
                    item.getValue(),
                    register.getBitLength(),
                    "registers." + item.getKey()));
        }
        return result;
    }

    static void validateInputRegister(
            Register register, String field) {
        if (isProgramCounterAlias(register)) {
            throw new IllegalArgumentException(
                field + " cannot override the program counter "
                    + "or one of its aliases; use address to "
                    + "select the execution entry");
        }
        Register base = register.getBaseRegister();
        if (register.isProcessorContext()
                || (base != null && base.isProcessorContext())) {
            throw new IllegalArgumentException(
                field + " cannot override processor context; "
                    + "select a program address whose context is "
                    + "already defined");
        }
    }

    private static List<MemoryOverride> parseMemoryOverrides(
            Program program, String json) {
        JsonElement root = parseJsonOrDefault(json, "[]", "memory");
        if (!root.isJsonArray()) {
            throw new IllegalArgumentException(
                "memory must be a JSON array");
        }
        List<MemoryOverride> result = new ArrayList<>();
        AddressSet used = new AddressSet();
        for (int index = 0; index < root.getAsJsonArray().size(); index++) {
            JsonElement item = root.getAsJsonArray().get(index);
            String field = "memory[" + index + "]";
            JsonObject object =
                exactObject(item, field, Set.of("start", "bytes"));
            requireFields(object, field, "start", "bytes");
            Address start = parseAddress(
                program, jsonString(object.get("start"), field + ".start"),
                field + ".start");
            byte[] bytes = decodeBytes(object.get("bytes"), field + ".bytes");
            Address end = checkedEnd(start, bytes.length, field + ".bytes");
            if (used.intersects(start, end)) {
                throw new IllegalArgumentException(
                    field + " overlaps another memory override");
            }
            used.add(start, end);
            result.add(new MemoryOverride(start, end, bytes));
        }
        return List.copyOf(result);
    }

    private static Set<Address> parseAddressArray(
            Program program, String json, String field) {
        JsonElement root = parseJsonOrDefault(json, "[]", field);
        if (!root.isJsonArray()) {
            throw new IllegalArgumentException(
                field + " must be a JSON array");
        }
        Set<Address> result = new LinkedHashSet<>();
        for (int index = 0; index < root.getAsJsonArray().size(); index++) {
            String itemField = field + "[" + index + "]";
            result.add(parseAddress(
                program,
                jsonString(root.getAsJsonArray().get(index), itemField),
                itemField));
        }
        return result;
    }

    private static List<CaptureRange> parseCaptureRanges(
            Program program, String json) {
        JsonElement root =
            parseJsonOrDefault(json, "[]", "capture_memory");
        if (!root.isJsonArray()) {
            throw new IllegalArgumentException(
                "capture_memory must be a JSON array");
        }
        List<CaptureRange> result = new ArrayList<>();
        long total = 0;
        for (int index = 0; index < root.getAsJsonArray().size(); index++) {
            String field = "capture_memory[" + index + "]";
            JsonObject object = exactObject(
                root.getAsJsonArray().get(index),
                field,
                Set.of("start", "end"));
            requireFields(object, field, "start", "end");
            Address start = parseAddress(
                program, jsonString(object.get("start"), field + ".start"),
                field + ".start");
            Address end = parseAddress(
                program, jsonString(object.get("end"), field + ".end"),
                field + ".end");
            if (!start.hasSameAddressSpace(end)
                    || end.compareTo(start) < 0) {
                throw new IllegalArgumentException(
                    field + " must be an inclusive non-reversed range "
                        + "in one address space");
            }
            long length = end.subtract(start) + 1;
            if (length <= 0 || total > MAX_CAPTURE_BYTES - length) {
                throw new IllegalArgumentException(
                    "capture_memory exceeds combined maximum of "
                        + MAX_CAPTURE_BYTES + " bytes");
            }
            total += length;
            result.add(new CaptureRange(start, end));
        }
        return List.copyOf(result);
    }

    private static JsonElement parseJsonOrDefault(
            String json, String defaultJson, String field) {
        String value = json == null || json.isBlank() ? defaultJson : json;
        try {
            return JsonParser.parseString(value);
        }
        catch (Exception error) {
            throw new IllegalArgumentException(
                field + " must be valid JSON", error);
        }
    }

    private static JsonObject exactObject(
            JsonElement item, String field, Set<String> allowed) {
        if (item == null || !item.isJsonObject()) {
            throw new IllegalArgumentException(
                field + " must be a JSON object");
        }
        JsonObject object = item.getAsJsonObject();
        for (String name : object.keySet()) {
            if (!allowed.contains(name)) {
                throw new IllegalArgumentException(
                    field + " contains unknown field '" + name + "'");
            }
        }
        return object;
    }

    private static void requireFields(
            JsonObject object, String field, String... names) {
        for (String name : names) {
            if (!object.has(name)) {
                throw new IllegalArgumentException(
                    field + "." + name + " is required");
            }
        }
    }

    private static String jsonString(JsonElement value, String field) {
        if (value == null || !value.isJsonPrimitive()
                || !value.getAsJsonPrimitive().isString()
                || value.getAsString().isBlank()) {
            throw new IllegalArgumentException(
                field + " must be a non-empty address string");
        }
        return value.getAsString();
    }

    private static Address parseAddress(
            Program program, String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        Address address = ServiceUtils.parseAddress(program, value);
        if (address == null) {
            throw new IllegalArgumentException(
                field + ": " + ServiceUtils.getLastParseError());
        }
        return address;
    }

    private static Address checkedEnd(
            Address start, int length, String field) {
        try {
            return start.addNoWrap(length - 1L);
        }
        catch (Exception error) {
            throw new IllegalArgumentException(
                field + " range overflows its address space", error);
        }
    }

    static Result execute(Program program, Request request) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(request, "request");
        RecordingCallbacks callbacks =
            new RecordingCallbacks(program, request);
        PcodeEmulator emulator =
            new PcodeEmulator(program.getLanguage(), callbacks);
        PcodeThread<byte[]> thread;
        ReturnInjection returnInjection = null;
        try {
            EmulatorUtilities.loadProgram(emulator, program);
            thread = emulator.newThread();
            EmulatorUtilities.initializeRegisters(
                thread, program, request.entry());
            initializeUnspecifiedRegisters(program, thread);
            applyRegisterOverrides(
                program, thread, request.registers());
            for (MemoryOverride override : request.memory()) {
                emulator.getSharedState().setConcrete(
                    override.start(), override.bytes());
            }
            if (request.returnAddress() != null) {
                returnInjection = inject6502ReturnAddress(
                    program, request, emulator, thread);
                callbacks.recordSyntheticReturn(
                    returnInjection, request.returnAddress());
            }
        }
        catch (Exception error) {
            throw new IllegalArgumentException(
                "Emulator initialization failed: "
                    + exceptionMessage(error),
                error);
        }

        callbacks.activate(thread);
        Map<String, BigInteger> initialRegisters =
            callbacks.snapshotRegisters(thread);
        String stopReason = null;
        String errorMessage = null;
        UnresolvedControlFlow unresolved = null;
        int steps = 0;
        while (steps < request.limits().maxSteps()) {
            Address pc = thread.getCounter();
            if (request.stopAddresses().contains(pc)) {
                stopReason = "stop_address";
                break;
            }
            if (!isInitialized(
                    request,
                    program,
                    returnInjection,
                    callbacks.runtimeInitialized(),
                    pc)) {
                stopReason = "unmapped_memory";
                break;
            }
            callbacks.beginStep(steps + 1);
            try {
                thread.stepInstruction();
                steps++;
                Address nextPc = thread.getCounter();
                if (!request.stopAddresses().contains(nextPc)
                        && callbacks.lastInstructionIsIndirect()
                        && !isInitialized(
                            request,
                            program,
                            returnInjection,
                            callbacks.runtimeInitialized(),
                            nextPc)) {
                    stopReason = "unresolved_flow";
                    unresolved =
                        callbacks.unresolvedAtTarget(nextPc);
                    break;
                }
            }
            catch (ManualInstructionExecuted executed) {
                steps++;
            }
            catch (TerminalStopException terminal) {
                stopReason = "terminal_instruction";
                break;
            }
            catch (MissingStateException missing) {
                callbacks.finishFailedTrace(thread);
                Instruction instruction = callbacks.currentInstruction();
                if (isUnresolvedFlow(instruction, missing)) {
                    stopReason = "unresolved_flow";
                    unresolved =
                        callbacks.unresolved(pc, missing.missing());
                }
                else if (missing.decode()) {
                    stopReason = "decode_error";
                }
                else {
                    stopReason = "unmapped_memory";
                }
                errorMessage = missing.getMessage();
                break;
            }
            catch (RuntimeException executionError) {
                callbacks.finishFailedTrace(thread);
                MissingStateException missing =
                    findMissingState(executionError);
                if (missing != null) {
                    Instruction instruction =
                        callbacks.currentInstruction();
                    if (isUnresolvedFlow(instruction, missing)) {
                        stopReason = "unresolved_flow";
                        unresolved =
                            callbacks.unresolved(
                                pc, missing.missing());
                    }
                    else {
                        stopReason = missing.decode()
                            ? "decode_error" : "unmapped_memory";
                    }
                    errorMessage = missing.getMessage();
                }
                else {
                    errorMessage = exceptionMessage(executionError);
                    stopReason = callbacks.currentInstruction() == null
                        ? "decode_error" : "fault";
                }
                break;
            }
        }
        if (stopReason == null) {
            stopReason = "max_steps";
        }
        callbacks.deactivate();

        Map<String, BigInteger> finalSnapshot =
            callbacks.snapshotRegisters(thread);
        Map<String, RegisterChange> changed =
            registerChanges(initialRegisters, finalSnapshot);
        Map<String, BigInteger> finalRegisters =
            requestedAndChangedRegisters(
                program,
                request,
                thread,
                callbacks,
                finalSnapshot,
                changed.keySet());
        List<CapturedMemory> captured =
            captureMemory(emulator, request.captureMemory());
        return new Result(
            request.entry(),
            stopReason,
            steps,
            thread.getCounter(),
            finalRegisters,
            changed,
            callbacks.trace(),
            callbacks.accesses(),
            callbacks.selfModifyingWrites(),
            unresolved,
            captured,
            returnInjection,
            callbacks.traceTruncated(),
            callbacks.accessLogTruncated(),
            errorMessage);
    }

    private static void initializeUnspecifiedRegisters(
            Program program, PcodeThread<byte[]> thread) {
        for (Register register : program.getLanguage().getRegisters()) {
            if (register.isProgramCounter()
                    || register.isProcessorContext()
                    || register.isZero()) {
                continue;
            }
            thread.getState().setRegisterValue(
                new RegisterValue(register, BigInteger.ZERO));
        }
    }

    private static void applyRegisterOverrides(
            Program program,
            PcodeThread<byte[]> thread,
            Map<Register, BigInteger> overrides) {
        for (Map.Entry<Register, BigInteger> register
                : overrides.entrySet()) {
            thread.getState().setRegisterValue(
                new RegisterValue(
                    register.getKey(), register.getValue()));
            if (is6502(program)
                    && "P".equals(register.getKey().getName())) {
                write6502Status(
                    program, thread, register.getValue().intValue());
            }
        }
    }

    private static void write6502Status(
            Program program,
            PcodeThread<byte[]> thread,
            int status) {
        Register packed = program.getRegister("P");
        if (packed != null) {
            thread.getState().setRegisterValue(
                new RegisterValue(
                    packed, BigInteger.valueOf(status & 0xff)));
        }
        String[] flags = {"N", "V", "B", "D", "I", "Z", "C"};
        int[] bits = {7, 6, 4, 3, 2, 1, 0};
        for (int index = 0; index < flags.length; index++) {
            Register flag = program.getRegister(flags[index]);
            if (flag != null) {
                thread.getState().setRegisterValue(
                    new RegisterValue(
                        flag,
                        BigInteger.valueOf(
                            (status >>> bits[index]) & 1)));
            }
        }
    }

    private static MissingStateException findMissingState(
            Throwable error) {
        for (Throwable current = error;
                current != null;
                current = current.getCause()) {
            if (current instanceof MissingStateException missing) {
                return missing;
            }
        }
        return null;
    }

    private static ReturnInjection inject6502ReturnAddress(
            Program program,
            Request request,
            PcodeEmulator emulator,
            PcodeThread<byte[]> thread) {
        Register stack = program.getCompilerSpec().getStackPointer();
        if (stack == null) {
            throw new IllegalArgumentException(
                "6502 compiler specification has no stack register");
        }
        RegisterValue value = thread.getState().inspectRegisterValue(stack);
        BigInteger unsigned = value.getUnsignedValue();
        int sp = unsigned == null ? 0 : unsigned.intValue() & 0xff;
        AddressSpace space =
            program.getAddressFactory().getDefaultAddressSpace();
        Address lowAddress =
            space.getAddress(0x100L + ((sp + 1) & 0xff));
        Address highAddress =
            space.getAddress(0x100L + ((sp + 2) & 0xff));
        for (MemoryOverride override : request.memory()) {
            if (contains(override.start(), override.end(), lowAddress)
                    || contains(
                        override.start(), override.end(), highAddress)) {
                throw new IllegalArgumentException(
                    "return_address injection overlaps an explicit "
                        + "memory override");
            }
        }
        int stacked =
            ((int) request.returnAddress().getUnsignedOffset() - 1)
                & 0xffff;
        byte low = (byte) stacked;
        byte high = (byte) (stacked >>> 8);
        emulator.getSharedState().setConcrete(
            lowAddress, new byte[]{low});
        emulator.getSharedState().setConcrete(
            highAddress, new byte[]{high});
        return new ReturnInjection(
            lowAddress, low, highAddress, high);
    }

    private static boolean isInitialized(
            Request request,
            Program program,
            ReturnInjection injection,
            AddressSetView runtimeInitialized,
            Address address) {
        if (program.getMemory().getAllInitializedAddressSet()
                .contains(address)) {
            return true;
        }
        if (runtimeInitialized.contains(address)) {
            return true;
        }
        for (MemoryOverride override : request.memory()) {
            if (contains(override.start(), override.end(), address)) {
                return true;
            }
        }
        return injection != null
            && (injection.lowAddress().equals(address)
                || injection.highAddress().equals(address));
    }

    private static boolean contains(
            Address start, Address end, Address address) {
        return start.hasSameAddressSpace(address)
            && start.compareTo(address) <= 0
            && end.compareTo(address) >= 0;
    }

    private static boolean isUnresolvedFlow(
            Instruction instruction, MissingStateException missing) {
        if (missing.registerState()) {
            return true;
        }
        if (instruction == null) {
            return false;
        }
        FlowType flow = instruction.getFlowType();
        return flow != null
            && (flow.isIndirect() || flow.isComputed());
    }

    private static List<MemoryRange> missingRanges(
            AddressSetView missing) {
        List<MemoryRange> result = new ArrayList<>();
        for (AddressRange range : missing) {
            result.add(new MemoryRange(
                range.getMinAddress(),
                range.getMaxAddress(),
                new byte[0]));
        }
        return List.copyOf(result);
    }

    private static Map<String, RegisterChange> registerChanges(
            Map<String, BigInteger> before,
            Map<String, BigInteger> after) {
        Map<String, RegisterChange> result = new LinkedHashMap<>();
        for (Map.Entry<String, BigInteger> entry : after.entrySet()) {
            BigInteger oldValue = before.get(entry.getKey());
            if (oldValue != null && !oldValue.equals(entry.getValue())) {
                result.put(
                    entry.getKey(),
                    new RegisterChange(oldValue, entry.getValue()));
            }
        }
        return result;
    }

    private static Map<String, BigInteger> requestedAndChangedRegisters(
            Program program,
            Request request,
            PcodeThread<byte[]> thread,
            RecordingCallbacks callbacks,
            Map<String, BigInteger> finalSnapshot,
            Set<String> changed) {
        Map<String, BigInteger> result = new LinkedHashMap<>();
        for (Register register : request.resultRegisters()) {
            BigInteger value;
            if (is6502(program)
                    && "P".equals(register.getName())) {
                value = finalSnapshot.get("P");
            }
            else if (isProgramCounterAlias(register)) {
                value = truncateToRegister(
                    unsignedOffset(thread.getCounter()), register);
            }
            else {
                value = callbacks.readRegister(thread, register);
            }
            if (value != null) {
                result.put(register.getName(), value);
            }
        }
        for (String name : changed) {
            result.putIfAbsent(name, finalSnapshot.get(name));
        }
        return result;
    }

    private static boolean isProgramCounterAlias(Register register) {
        Register base = register.getBaseRegister();
        return register.isProgramCounter()
            || (base != null && base.isProgramCounter());
    }

    private static BigInteger truncateToRegister(
            BigInteger value, Register register) {
        if (value == null || register.getBitLength() <= 0) {
            return value;
        }
        return value.and(
            BigInteger.ONE.shiftLeft(register.getBitLength())
                .subtract(BigInteger.ONE));
    }

    private static BigInteger unsignedOffset(Address address) {
        if (address == null) {
            return null;
        }
        return new BigInteger(
            Long.toUnsignedString(address.getUnsignedOffset()));
    }

    private static List<CapturedMemory> captureMemory(
            PcodeEmulator emulator, List<CaptureRange> ranges) {
        List<CapturedMemory> result = new ArrayList<>();
        for (CaptureRange range : ranges) {
            int length = (int) (range.end().subtract(range.start()) + 1);
            result.add(new CapturedMemory(
                range.start(),
                range.end(),
                emulator.getSharedState().inspectConcrete(
                    range.start(), length)));
        }
        return List.copyOf(result);
    }

    private static boolean is6502(Program program) {
        String processor =
            program.getLanguage().getProcessor().toString();
        return "6502".equalsIgnoreCase(processor)
            || "65C02".equalsIgnoreCase(processor);
    }

    private static String exceptionMessage(Throwable error) {
        String message = error.getMessage();
        return message == null || message.isBlank()
            ? error.getClass().getSimpleName()
            : message;
    }

    private static final class TerminalStopException
            extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    private static final class ManualInstructionExecuted
            extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    private static final class MissingStateException
            extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final transient AddressSet missing;
        private final boolean decode;
        private final boolean registerState;

        MissingStateException(
                AddressSetView missing,
                PcodeExecutorStatePiece.Reason reason) {
            super("Uninitialized emulator state: " + missing);
            this.missing = new AddressSet(missing);
            decode =
                reason == PcodeExecutorStatePiece.Reason.EXECUTE_DECODE;
            Address first = this.missing.getMinAddress();
            registerState = first != null
                && first.getAddressSpace().isRegisterSpace();
        }

        AddressSetView missing() {
            return missing;
        }

        boolean decode() {
            return decode;
        }

        boolean registerState() {
            return registerState;
        }
    }

    private static final class RecordingCallbacks
            implements PcodeEmulationCallbacks<byte[]> {
        private final Program program;
        private final Request request;
        private final List<Register> registers;
        private final AddressSet authoritativeInstructions =
            new AddressSet();
        private final AddressSet executedInstructions =
            new AddressSet();
        private final AddressSet runtimeInitialized =
            new AddressSet();
        private final List<TraceRecord> trace = new ArrayList<>();
        private final List<MemoryAccess> accesses = new ArrayList<>();
        private final List<MemoryAccess> selfModifying =
            new ArrayList<>();
        private final List<StackFrameProvenance> stackFrames =
            new ArrayList<>();
        private PcodeThread<byte[]> thread;
        private CurrentTrace current;
        private CurrentTrace lastCompleted;
        private PendingLoad pendingLoad;
        private int step;
        private long accessSequence;
        private boolean active;
        private boolean traceTruncated;
        private boolean accessLogTruncated;

        RecordingCallbacks(Program program, Request request) {
            this.program = program;
            this.request = request;
            registers = program.getLanguage().getRegisters()
                .stream()
                .filter(Register::isBaseRegister)
                .filter(register -> !register.isHidden())
                .filter(register -> !register.isProcessorContext())
                .filter(register -> !register.isProgramCounter())
                .filter(register -> !register.isZero())
                .sorted(Comparator.comparing(Register::getName))
                .toList();
            InstructionIterator iterator =
                program.getListing().getInstructions(true);
            while (iterator.hasNext()) {
                Instruction instruction = iterator.next();
                authoritativeInstructions.add(
                    instruction.getMinAddress(),
                    instruction.getMaxAddress());
            }
        }

        void activate(PcodeThread<byte[]> executionThread) {
            thread = executionThread;
            active = true;
        }

        void deactivate() {
            active = false;
        }

        void beginStep(int nextStep) {
            step = nextStep;
            current = null;
            pendingLoad = null;
        }

        Instruction currentInstruction() {
            return current == null ? null : current.instruction();
        }

        AddressSetView runtimeInitialized() {
            return runtimeInitialized;
        }

        void recordSyntheticReturn(
                ReturnInjection injection, Address returnAddress) {
            stackFrames.add(new StackFrameProvenance(
                StackFrameKind.SYNTHETIC_RETURN,
                null,
                null,
                injection.lowAddress(),
                injection.lowByte(),
                injection.highAddress(),
                injection.highByte(),
                returnAddress.getAddressSpace()));
        }

        boolean lastInstructionIsIndirect() {
            if (lastCompleted == null) {
                return false;
            }
            FlowType flow =
                lastCompleted.instruction().getFlowType();
            return flow != null
                && (flow.isIndirect() || flow.isComputed());
        }

        UnresolvedControlFlow unresolved(
                Address fallback, AddressSetView missing) {
            CurrentTrace evidence =
                current != null ? current : lastCompleted;
            return unresolved(
                fallback, missing, evidence);
        }

        UnresolvedControlFlow unresolvedAtTarget(Address target) {
            return unresolved(
                target,
                new AddressSet(target, target),
                lastCompleted);
        }

        private UnresolvedControlFlow unresolved(
                Address fallback,
                AddressSetView missing,
                CurrentTrace evidence) {
            Instruction instruction =
                evidence == null ? null : evidence.instruction();
            return new UnresolvedControlFlow(
                instruction == null
                    ? fallback : instruction.getMinAddress(),
                instruction == null
                    ? null : instruction.toString(),
                missingRanges(missing),
                evidence == null
                    ? Map.of() : evidence.beforeRegisters(),
                availableMemory(evidence, missing));
        }

        private List<MemoryRange> availableMemory(
                CurrentTrace evidence, AddressSetView missing) {
            if (evidence == null) {
                return List.of();
            }
            List<MemoryRange> result = new ArrayList<>(
                coalesceAccesses(
                    evidence.evidenceReads(), AccessKind.READ));
            if (evidence == current && pendingLoad != null) {
                for (int index = 0;
                        index < pendingLoad.size();
                        index++) {
                    Address address;
                    try {
                        address =
                            pendingLoad.start().addNoWrap(index);
                    }
                    catch (Exception overflow) {
                        break;
                    }
                    if (missing.contains(address)) {
                        continue;
                    }
                    byte value = thread.getMachine().getSharedState()
                        .inspectByte(address);
                    result.add(new MemoryRange(
                        address, address, new byte[]{value}));
                }
            }
            return List.copyOf(result);
        }

        BigInteger readRegister(
                PcodeThread<byte[]> executionThread,
                Register register) {
            boolean previouslyActive = active;
            active = false;
            try {
                return executionThread.getState()
                    .inspectRegisterValue(register)
                    .getUnsignedValue();
            }
            finally {
                active = previouslyActive;
            }
        }

        @Override
        public void beforeExecuteInstruction(
                PcodeThread<byte[]> executionThread,
                Instruction instruction,
                PcodeProgram programCode) {
            executedInstructions.add(
                instruction.getMinAddress(),
                instruction.getMaxAddress());
            current = new CurrentTrace(
                instruction,
                instructionBytes(instruction),
                snapshotRegisters(executionThread),
                new ArrayList<>(),
                new ArrayList<>());
            if (request.terminalPolicy() == TerminalPolicy.STOP
                    && isTerminal6502(instruction)) {
                completeTrace(executionThread, false);
                throw new TerminalStopException();
            }
            if (request.terminalPolicy() == TerminalPolicy.EXECUTE
                    && is6502(program)
                    && "RTS".equals(instruction.getMnemonicString())) {
                execute6502Rts(executionThread);
                completeTrace(executionThread, true);
                throw new ManualInstructionExecuted();
            }
            if (request.terminalPolicy() == TerminalPolicy.EXECUTE
                    && is6502(program)
                    && "RTI".equals(instruction.getMnemonicString())) {
                execute6502Rti(executionThread);
                completeTrace(executionThread, true);
                throw new ManualInstructionExecuted();
            }
            if (request.terminalPolicy() == TerminalPolicy.EXECUTE
                    && is6502(program)
                    && "BRK".equals(instruction.getMnemonicString())) {
                execute6502Brk(executionThread, instruction);
                completeTrace(executionThread, true);
                throw new ManualInstructionExecuted();
            }
            if (is6502(program)
                    && "JSR".equals(instruction.getMnemonicString())) {
                execute6502Jsr(executionThread, instruction);
                completeTrace(executionThread, true);
                throw new ManualInstructionExecuted();
            }
        }

        @Override
        public void afterExecuteInstruction(
                PcodeThread<byte[]> executionThread,
                Instruction instruction) {
            if (current != null) {
                completeTrace(executionThread, true);
            }
        }

        private void completeTrace(
                PcodeThread<byte[]> executionThread,
                boolean executed) {
            CurrentTrace completed = current;
            if (completed == null) {
                return;
            }
            addTrace(recordTrace(
                executionThread, completed, executed));
            lastCompleted = completed;
            current = null;
            pendingLoad = null;
        }

        @Override
        public void beforeStepOp(
                PcodeThread<byte[]> executionThread,
                PcodeOp op,
                ghidra.pcode.exec.PcodeFrame frame) {
            // Some Sleigh languages, notably 6502, express a semantic
            // operand read/write as a direct memory varnode instead of a
            // LOAD/STORE op. These callbacks see decoded p-code only, never
            // instruction fetches. Flow destinations are excluded below so
            // only actual operand memory participates in the access log.
            if (op.getOpcode() == PcodeOp.LOAD
                    || op.getOpcode() == PcodeOp.STORE) {
                return;
            }
            Varnode[] inputs = op.getInputs();
            for (int index = 0; index < inputs.length; index++) {
                if (isFlowDestination(op, index)) {
                    continue;
                }
                Varnode input = inputs[index];
                if (isDirectMemory(input)) {
                    recordAccess(
                        executionThread,
                        AccessKind.READ,
                        input.getAddress(),
                        input.getSize());
                }
            }
        }

        @Override
        public void afterStepOp(
                PcodeThread<byte[]> executionThread,
                PcodeOp op,
                ghidra.pcode.exec.PcodeFrame frame) {
            if (op.getOpcode() == PcodeOp.STORE) {
                return;
            }
            Varnode output = op.getOutput();
            if (isDirectMemory(output)) {
                recordAccess(
                    executionThread,
                    AccessKind.WRITE,
                    output.getAddress(),
                    output.getSize());
            }
        }

        @Override
        public void beforeLoad(
                PcodeThread<byte[]> executionThread,
                PcodeOp op,
                AddressSpace space,
                byte[] offset,
                int size) {
            Address address = executionThread.getArithmetic().toAddress(
                offset, space, PcodeArithmetic.Purpose.LOAD);
            pendingLoad = new PendingLoad(address, size);
        }

        @Override
        public void afterLoad(
                PcodeThread<byte[]> executionThread,
                PcodeOp op,
                AddressSpace space,
                byte[] offset,
                int size,
                byte[] value) {
            Address address = executionThread.getArithmetic().toAddress(
                offset, space, PcodeArithmetic.Purpose.LOAD);
            recordAccess(executionThread, AccessKind.READ, address, size);
            pendingLoad = null;
        }

        @Override
        public void afterStore(
                PcodeThread<byte[]> executionThread,
                PcodeOp op,
                AddressSpace space,
                byte[] offset,
                int size,
                byte[] value) {
            Address address = executionThread.getArithmetic().toAddress(
                offset, space, PcodeArithmetic.Purpose.STORE);
            recordAccess(executionThread, AccessKind.WRITE, address, size);
        }

        @Override
        public <A, U> AddressSetView readUninitialized(
                PcodeThread<byte[]> executionThread,
                PcodeExecutorStatePiece<A, U> state,
                AddressSetView missing,
                PcodeExecutorStatePiece.Reason reason) {
            if (active && !missing.isEmpty()) {
                throw new MissingStateException(missing, reason);
            }
            return missing;
        }

        private void recordAccess(
                PcodeThread<byte[]> executionThread,
                AccessKind kind,
                Address address,
                int size) {
            long sequence = accessSequence++;
            byte[] bytes =
                executionThread.getMachine().getSharedState()
                    .inspectConcrete(address, size);
            MemoryAccess access =
                new MemoryAccess(sequence, step, kind, address, bytes);
            if (kind == AccessKind.WRITE) {
                runtimeInitialized.add(
                    access.start(), access.end());
            }
            if (isSelfModifying(
                    access,
                    authoritativeInstructions,
                    executedInstructions)) {
                selfModifying.add(access);
            }
            if (kind == AccessKind.READ && current != null) {
                current.evidenceReads().add(access);
            }
            if (accesses.size()
                    >= request.limits().accessLogLimit()) {
                accessLogTruncated = true;
                return;
            }
            accesses.add(access);
            if (current != null) {
                current.accesses().add(access);
            }
        }

        private void execute6502Rts(
                PcodeThread<byte[]> executionThread) {
            Register stack = program.getCompilerSpec().getStackPointer();
            BigInteger stackValue = executionThread.getState()
                .inspectRegisterValue(stack)
                .getUnsignedValue();
            int sp = stackValue == null
                ? 0 : stackValue.intValue() & 0xff;
            AddressSpace stackSpace =
                program.getAddressFactory().getDefaultAddressSpace();
            Address lowAddress =
                stackSpace.getAddress(0x100L + ((sp + 1) & 0xff));
            Address highAddress =
                stackSpace.getAddress(0x100L + ((sp + 2) & 0xff));
            byte low = executionThread.getMachine().getSharedState()
                .inspectByte(lowAddress);
            byte high = executionThread.getMachine().getSharedState()
                .inspectByte(highAddress);
            recordAccess(
                executionThread, AccessKind.READ, lowAddress, 1);
            recordAccess(
                executionThread, AccessKind.READ, highAddress, 1);
            int target =
                ((((high & 0xff) << 8) | (low & 0xff)) + 1)
                    & 0xffff;
            AddressSpace returnSpace = consumeStackFrame(
                Set.of(
                    StackFrameKind.JSR_RETURN,
                    StackFrameKind.SYNTHETIC_RETURN),
                null,
                null,
                lowAddress,
                low,
                highAddress,
                high,
                current.instruction().getMinAddress()
                    .getAddressSpace());
            executionThread.getState().setRegisterValue(
                new RegisterValue(
                    stack,
                    BigInteger.valueOf(
                        0x100L + ((sp + 2) & 0xff))));
            executionThread.overrideCounter(
                returnSpace.getAddress(target));
        }

        private void execute6502Jsr(
                PcodeThread<byte[]> executionThread,
                Instruction instruction) {
            Address[] flows = instruction.getFlows();
            if (flows.length != 1) {
                throw new IllegalStateException(
                    "6502 JSR does not have one direct target");
            }
            Register stack = program.getCompilerSpec().getStackPointer();
            BigInteger stackValue = executionThread.getState()
                .inspectRegisterValue(stack)
                .getUnsignedValue();
            int sp = stackValue == null
                ? 0 : stackValue.intValue() & 0xff;
            AddressSpace space =
                program.getAddressFactory().getDefaultAddressSpace();
            Address highAddress =
                space.getAddress(0x100L + sp);
            Address lowAddress =
                space.getAddress(0x100L + ((sp - 1) & 0xff));
            int stacked =
                (int) instruction.getMaxAddress().getUnsignedOffset();
            byte high = (byte) (stacked >>> 8);
            byte low = (byte) stacked;
            executionThread.getMachine().getSharedState()
                .setConcrete(highAddress, new byte[]{high});
            recordAccess(
                executionThread, AccessKind.WRITE, highAddress, 1);
            executionThread.getMachine().getSharedState()
                .setConcrete(lowAddress, new byte[]{low});
            recordAccess(
                executionThread, AccessKind.WRITE, lowAddress, 1);
            stackFrames.add(new StackFrameProvenance(
                StackFrameKind.JSR_RETURN,
                null,
                null,
                lowAddress,
                low,
                highAddress,
                high,
                instruction.getMinAddress().getAddressSpace()));
            executionThread.getState().setRegisterValue(
                new RegisterValue(
                    stack,
                    BigInteger.valueOf(
                        0x100L + ((sp - 2) & 0xff))));
            executionThread.overrideCounter(flows[0]);
        }

        private void execute6502Rti(
                PcodeThread<byte[]> executionThread) {
            Register stack = program.getCompilerSpec().getStackPointer();
            BigInteger stackValue = executionThread.getState()
                .inspectRegisterValue(stack)
                .getUnsignedValue();
            int sp = stackValue == null
                ? 0 : stackValue.intValue() & 0xff;
            AddressSpace stackSpace =
                program.getAddressFactory().getDefaultAddressSpace();
            Address statusAddress =
                stackSpace.getAddress(0x100L + ((sp + 1) & 0xff));
            Address lowAddress =
                stackSpace.getAddress(0x100L + ((sp + 2) & 0xff));
            Address highAddress =
                stackSpace.getAddress(0x100L + ((sp + 3) & 0xff));
            byte status = executionThread.getMachine().getSharedState()
                .inspectByte(statusAddress);
            byte low = executionThread.getMachine().getSharedState()
                .inspectByte(lowAddress);
            byte high = executionThread.getMachine().getSharedState()
                .inspectByte(highAddress);
            recordAccess(
                executionThread, AccessKind.READ, statusAddress, 1);
            recordAccess(
                executionThread, AccessKind.READ, lowAddress, 1);
            recordAccess(
                executionThread, AccessKind.READ, highAddress, 1);
            write6502Status(program, executionThread, status & 0xff);
            executionThread.getState().setRegisterValue(
                new RegisterValue(
                    stack,
                    BigInteger.valueOf(
                        0x100L + ((sp + 3) & 0xff))));
            int target =
                ((high & 0xff) << 8) | (low & 0xff);
            AddressSpace returnSpace = consumeStackFrame(
                Set.of(StackFrameKind.INTERRUPT_RETURN),
                statusAddress,
                status,
                lowAddress,
                low,
                highAddress,
                high,
                current.instruction().getMinAddress()
                    .getAddressSpace());
            executionThread.overrideCounter(
                returnSpace.getAddress(target));
        }

        private void execute6502Brk(
                PcodeThread<byte[]> executionThread,
                Instruction instruction) {
            Register stack = program.getCompilerSpec().getStackPointer();
            BigInteger stackValue = executionThread.getState()
                .inspectRegisterValue(stack)
                .getUnsignedValue();
            int sp = stackValue == null
                ? 0 : stackValue.intValue() & 0xff;
            AddressSpace space =
                program.getAddressFactory().getDefaultAddressSpace();
            Address highAddress =
                space.getAddress(0x100L + sp);
            Address lowAddress =
                space.getAddress(0x100L + ((sp - 1) & 0xff));
            Address statusAddress =
                space.getAddress(0x100L + ((sp - 2) & 0xff));
            int returnAddress =
                ((int) instruction.getMinAddress().getUnsignedOffset()
                    + 2) & 0xffff;
            byte high = (byte) (returnAddress >>> 8);
            byte low = (byte) returnAddress;
            byte status = (byte) (
                read6502Status(program, executionThread).intValue()
                    | 0x10);
            storeSemanticByte(
                executionThread, highAddress, high);
            storeSemanticByte(
                executionThread, lowAddress, low);
            storeSemanticByte(
                executionThread, statusAddress, status);
            stackFrames.add(new StackFrameProvenance(
                StackFrameKind.INTERRUPT_RETURN,
                statusAddress,
                status,
                lowAddress,
                low,
                highAddress,
                high,
                instruction.getMinAddress().getAddressSpace()));
            executionThread.getState().setRegisterValue(
                new RegisterValue(
                    stack,
                    BigInteger.valueOf(
                        0x100L + ((sp - 3) & 0xff))));
            write6502Status(
                program, executionThread, (status & 0xff) | 0x04);

            Address vectorLow = space.getAddress(0xfffe);
            Address vectorHigh = space.getAddress(0xffff);
            byte targetLow =
                executionThread.getMachine().getSharedState()
                    .inspectByte(vectorLow);
            byte targetHigh =
                executionThread.getMachine().getSharedState()
                    .inspectByte(vectorHigh);
            recordAccess(
                executionThread, AccessKind.READ, vectorLow, 1);
            recordAccess(
                executionThread, AccessKind.READ, vectorHigh, 1);
            int target =
                ((targetHigh & 0xff) << 8) | (targetLow & 0xff);
            executionThread.overrideCounter(space.getAddress(target));
        }

        private void storeSemanticByte(
                PcodeThread<byte[]> executionThread,
                Address address,
                byte value) {
            executionThread.getMachine().getSharedState()
                .setConcrete(address, new byte[]{value});
            recordAccess(
                executionThread, AccessKind.WRITE, address, 1);
        }

        private AddressSpace consumeStackFrame(
                Set<StackFrameKind> kinds,
                Address statusAddress,
                Byte statusByte,
                Address lowAddress,
                byte lowByte,
                Address highAddress,
                byte highByte,
                AddressSpace fallback) {
            for (int index = stackFrames.size() - 1;
                    index >= 0;
                    index--) {
                StackFrameProvenance frame =
                    stackFrames.get(index);
                if (!kinds.contains(frame.kind())
                        || !Objects.equals(
                            statusAddress, frame.statusAddress())
                        || !Objects.equals(
                            statusByte, frame.statusByte())
                        || !lowAddress.equals(frame.lowAddress())
                        || lowByte != frame.lowByte()
                        || !highAddress.equals(frame.highAddress())
                        || highByte != frame.highByte()) {
                    continue;
                }
                stackFrames.remove(index);
                return frame.returnSpace();
            }
            return fallback;
        }

        private static boolean isDirectMemory(Varnode varnode) {
            return varnode != null
                && varnode.getAddress().getAddressSpace().isMemorySpace();
        }

        private static boolean isFlowDestination(
                PcodeOp op, int inputIndex) {
            if (inputIndex != 0) {
                return false;
            }
            return switch (op.getOpcode()) {
                case PcodeOp.BRANCH,
                        PcodeOp.CBRANCH,
                        PcodeOp.CALL -> true;
                default -> false;
            };
        }

        private TraceRecord recordTrace(
                PcodeThread<byte[]> executionThread,
                CurrentTrace state,
                boolean executed) {
            Map<String, BigInteger> after =
                snapshotRegisters(executionThread);
            Map<String, BigInteger> beforeChanged =
                new LinkedHashMap<>();
            Map<String, BigInteger> afterChanged =
                new LinkedHashMap<>();
            for (Map.Entry<String, BigInteger> value : after.entrySet()) {
                BigInteger before =
                    state.beforeRegisters().get(value.getKey());
                if (before != null && !before.equals(value.getValue())) {
                    beforeChanged.put(value.getKey(), before);
                    afterChanged.put(value.getKey(), value.getValue());
                }
            }
            return new TraceRecord(
                step,
                state.instruction().getMinAddress(),
                state.instruction().toString(),
                state.bytes(),
                executed,
                beforeChanged,
                afterChanged,
                state.accesses(),
                executionThread.getCounter());
        }

        void finishFailedTrace(PcodeThread<byte[]> executionThread) {
            if (current != null) {
                addTrace(recordTrace(
                    executionThread, current, false));
            }
        }

        private void addTrace(TraceRecord record) {
            if (trace.size() < request.limits().traceLimit()) {
                trace.add(record);
            }
            else {
                traceTruncated = true;
            }
        }

        Map<String, BigInteger> snapshotRegisters(
                PcodeThread<byte[]> executionThread) {
            Map<String, BigInteger> result = new LinkedHashMap<>();
            boolean previouslyActive = active;
            active = false;
            try {
                for (Register register : registers) {
                    RegisterValue value = executionThread.getState()
                        .inspectRegisterValue(register);
                    BigInteger unsigned = value.getUnsignedValue();
                    if (unsigned != null) {
                        result.put(register.getName(), unsigned);
                    }
                }
                if (is6502(program)) {
                    result.put("P", read6502Status(
                        program, executionThread));
                }
            }
            finally {
                active = previouslyActive;
            }
            return result;
        }

        private static BigInteger read6502Status(
                Program program,
                PcodeThread<byte[]> executionThread) {
            int status = 0x20;
            String[] flags = {"N", "V", "B", "D", "I", "Z", "C"};
            int[] bits = {7, 6, 4, 3, 2, 1, 0};
            for (int index = 0; index < flags.length; index++) {
                Register flag = program.getRegister(flags[index]);
                if (flag == null) {
                    continue;
                }
                BigInteger value = executionThread.getState()
                    .inspectRegisterValue(flag)
                    .getUnsignedValue();
                if (value != null && value.testBit(0)) {
                    status |= 1 << bits[index];
                }
            }
            return BigInteger.valueOf(status);
        }

        List<TraceRecord> trace() {
            return List.copyOf(trace);
        }

        List<MemoryAccess> accesses() {
            return List.copyOf(accesses);
        }

        List<MemoryAccess> selfModifyingWrites() {
            return List.copyOf(selfModifying);
        }

        boolean traceTruncated() {
            return traceTruncated;
        }

        boolean accessLogTruncated() {
            return accessLogTruncated;
        }

        private boolean isTerminal6502(Instruction instruction) {
            if (!is6502(program)) {
                return false;
            }
            return switch (instruction.getMnemonicString()) {
                case "RTS", "RTI", "BRK" -> true;
                default -> false;
            };
        }

        private static byte[] instructionBytes(
                Instruction instruction) {
            try {
                return instruction.getBytes();
            }
            catch (MemoryAccessException error) {
                throw new IllegalStateException(
                    "Unable to capture instruction bytes at "
                        + instruction.getMinAddress(),
                    error);
            }
        }
    }

    private record CurrentTrace(
            Instruction instruction,
            byte[] bytes,
            Map<String, BigInteger> beforeRegisters,
            List<MemoryAccess> accesses,
            List<MemoryAccess> evidenceReads) {
    }

    private record PendingLoad(Address start, int size) {
    }

    private enum StackFrameKind {
        SYNTHETIC_RETURN,
        JSR_RETURN,
        INTERRUPT_RETURN
    }

    private record StackFrameProvenance(
            StackFrameKind kind,
            Address statusAddress,
            Byte statusByte,
            Address lowAddress,
            byte lowByte,
            Address highAddress,
            byte highByte,
            AddressSpace returnSpace) {
    }

    static byte[] decodeBytes(JsonElement value, String field) {
        if (value == null || value.isJsonNull()) {
            throw new IllegalArgumentException(field + " is required");
        }
        if (value.isJsonPrimitive()
                && value.getAsJsonPrimitive().isString()) {
            return decodeHex(value.getAsString(), field);
        }
        if (!value.isJsonArray() || value.getAsJsonArray().isEmpty()) {
            throw new IllegalArgumentException(
                field + " must be a non-empty hex string or byte array");
        }
        byte[] result = new byte[value.getAsJsonArray().size()];
        for (int index = 0; index < result.length; index++) {
            JsonElement item = value.getAsJsonArray().get(index);
            if (!item.isJsonPrimitive()
                    || !item.getAsJsonPrimitive().isNumber()
                    || !isJsonInteger(item)) {
                throw new IllegalArgumentException(
                    field + " array values must be integers from 0 to 255");
            }
            int byteValue;
            try {
                byteValue = item.getAsBigDecimal().intValueExact();
            }
            catch (ArithmeticException error) {
                throw new IllegalArgumentException(
                    field + " array values must be integers from 0 to 255",
                    error);
            }
            if (byteValue < 0 || byteValue > 255) {
                throw new IllegalArgumentException(
                    field + " array values must be integers from 0 to 255");
            }
            result[index] = (byte) byteValue;
        }
        return result;
    }

    private static byte[] decodeHex(String value, String field) {
        StringBuilder compact = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!Character.isWhitespace(character)) {
                compact.append(character);
            }
        }
        if (compact.length() >= 2
                && compact.charAt(0) == '0'
                && (compact.charAt(1) == 'x'
                    || compact.charAt(1) == 'X')) {
            compact.delete(0, 2);
        }
        if (compact.length() == 0 || (compact.length() & 1) != 0) {
            throw new IllegalArgumentException(
                field + " must contain complete hexadecimal bytes");
        }
        try {
            return HexFormat.of().parseHex(compact);
        }
        catch (IllegalArgumentException error) {
            throw new IllegalArgumentException(
                field + " contains a non-hexadecimal character", error);
        }
    }

    static BigInteger parseUnsigned(
            JsonElement value, int bitLength, String field) {
        if (bitLength <= 0) {
            throw new IllegalArgumentException(
                field + " register width must be positive");
        }
        BigInteger parsed;
        try {
            if (!isJsonInteger(value)) {
                throw new NumberFormatException();
            }
            JsonPrimitive primitive = value.getAsJsonPrimitive();
            if (primitive.isString()) {
                String text = primitive.getAsString();
                parsed = text.startsWith("0x") || text.startsWith("0X")
                    ? new BigInteger(text.substring(2), 16)
                    : new BigInteger(text);
            }
            else {
                parsed = value.getAsBigDecimal().toBigIntegerExact();
            }
        }
        catch (ArithmeticException | NumberFormatException error) {
            throw new IllegalArgumentException(
                field + " must be an unsigned integer or hexadecimal string",
                error);
        }
        if (parsed.signum() < 0 || parsed.bitLength() > bitLength) {
            throw new IllegalArgumentException(
                field + " does not fit unsigned " + bitLength + "-bit value");
        }
        return parsed;
    }

    private static boolean isJsonInteger(JsonElement value) {
        if (value == null || !value.isJsonPrimitive()) {
            return false;
        }
        JsonPrimitive primitive = value.getAsJsonPrimitive();
        if (primitive.isBoolean()) {
            return false;
        }
        if (primitive.isString()) {
            String text = primitive.getAsString();
            if (text.startsWith("0x") || text.startsWith("0X")) {
                return text.length() > 2;
            }
            try {
                new BigInteger(text);
                return true;
            }
            catch (NumberFormatException error) {
                return false;
            }
        }
        try {
            BigDecimal decimal = primitive.getAsBigDecimal();
            decimal.toBigIntegerExact();
            return true;
        }
        catch (ArithmeticException | NumberFormatException error) {
            return false;
        }
    }

    static List<MemoryRange> coalesceAccesses(
            List<MemoryAccess> accesses, AccessKind kind) {
        List<MemoryRange> result = new ArrayList<>();
        MemoryAccess previous = null;
        Address rangeStart = null;
        Address rangeEnd = null;
        byte[] rangeBytes = null;
        for (MemoryAccess access : accesses) {
            Address nextAddress =
                rangeEnd == null ? null : rangeEnd.next();
            boolean extendsRange =
                previous != null
                    && access.kind() == kind
                    && previous.kind() == kind
                    && previous.sequence() + 1 == access.sequence()
                    && nextAddress != null
                    && nextAddress.equals(access.start());
            if (access.kind() == kind && extendsRange) {
                byte[] joined =
                    Arrays.copyOf(rangeBytes, rangeBytes.length + access.bytes().length);
                System.arraycopy(
                    access.bytes(), 0, joined, rangeBytes.length, access.bytes().length);
                rangeBytes = joined;
                rangeEnd = access.end();
            }
            else if (access.kind() == kind) {
                if (rangeStart != null) {
                    result.add(new MemoryRange(rangeStart, rangeEnd, rangeBytes));
                }
                rangeStart = access.start();
                rangeEnd = access.end();
                rangeBytes = access.bytes();
            }
            else if (rangeStart != null) {
                result.add(new MemoryRange(rangeStart, rangeEnd, rangeBytes));
                rangeStart = null;
                rangeEnd = null;
                rangeBytes = null;
            }
            previous = access;
        }
        if (rangeStart != null) {
            result.add(new MemoryRange(rangeStart, rangeEnd, rangeBytes));
        }
        return List.copyOf(result);
    }

    static boolean isSelfModifying(
            MemoryAccess access,
            AddressSetView authoritativeInstructions,
            AddressSetView executedInstructions) {
        if (access.kind() != AccessKind.WRITE) {
            return false;
        }
        return authoritativeInstructions.intersects(
            access.start(), access.end())
            || executedInstructions.intersects(
                access.start(), access.end());
    }
}
