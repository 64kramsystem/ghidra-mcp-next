package com.xebyte.core;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.task.TaskMonitor;

/**
 * Transaction-free planning and transaction-owned application for raw program
 * byte patches.
 */
final class PatchBytesCore {

    static final int MAX_PAYLOAD_BYTES = 1_048_576;
    static final int FULL_HEX_LIMIT = 65_536;
    static final int SAMPLE_BYTES = 32;

    record Request(
            String address,
            String block,
            byte[] payload,
            byte[] expectedCurrent,
            boolean clearCodeUnits,
            boolean allowReadonly) {

        Request {
            payload = payload == null
                ? null : Arrays.copyOf(payload, payload.length);
            expectedCurrent = expectedCurrent == null
                ? null : Arrays.copyOf(expectedCurrent, expectedCurrent.length);
        }
    }

    record Plan(
            MemoryBlock block,
            Address start,
            Address end,
            byte[] payload,
            byte[] previous,
            ListingClearCore.Plan clearPlan,
            boolean originalWrite,
            boolean temporaryWriteEnabled) {

        Plan {
            payload = Arrays.copyOf(payload, payload.length);
            previous = Arrays.copyOf(previous, previous.length);
        }

        @Override
        public byte[] payload() {
            return Arrays.copyOf(payload, payload.length);
        }

        @Override
        public byte[] previous() {
            return Arrays.copyOf(previous, previous.length);
        }
    }

    record PayloadSummary(
            String previous,
            String written,
            String previousSha256,
            String writtenSha256,
            String previousFirst,
            String previousLast,
            String writtenFirst,
            String writtenLast) {
    }

    private final ListingClearCore listingClear;

    PatchBytesCore() {
        this(new ListingClearCore());
    }

    PatchBytesCore(ListingClearCore listingClear) {
        this.listingClear =
            Objects.requireNonNull(listingClear, "listingClear");
    }

    static byte[] decodeHex(String text, String parameter) {
        String name = parameter == null || parameter.isBlank()
            ? "hex payload" : parameter;
        if (text == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        StringBuilder compact = new StringBuilder(text.length());
        for (int index = 0; index < text.length(); index++) {
            char value = text.charAt(index);
            if (!isHexWhitespace(value)) {
                compact.append(value);
            }
        }
        if (compact.length() >= 2
                && compact.charAt(0) == '0'
                && (compact.charAt(1) == 'x'
                    || compact.charAt(1) == 'X')) {
            compact.delete(0, 2);
        }
        if (compact.length() == 0) {
            throw new IllegalArgumentException(name + " must not be empty");
        }
        if ((compact.length() & 1) != 0) {
            throw new IllegalArgumentException(
                name + " must contain complete hexadecimal bytes");
        }
        long decodedLength = compact.length() / 2L;
        if (decodedLength > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException(
                name + " exceeds maximum of "
                    + MAX_PAYLOAD_BYTES + " bytes");
        }
        byte[] decoded = new byte[(int) decodedLength];
        for (int index = 0; index < decoded.length; index++) {
            int high = hexNibble(compact.charAt(index * 2));
            int low = hexNibble(compact.charAt(index * 2 + 1));
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException(
                    name + " contains a non-hexadecimal character");
            }
            decoded[index] = (byte) ((high << 4) | low);
        }
        return decoded;
    }

    static void validateExpected(byte[] expected, byte[] current) {
        if (expected == null) {
            return;
        }
        if (expected.length != current.length) {
            throw new IllegalArgumentException(
                "expected_current must decode to exactly "
                    + current.length + " bytes");
        }
        for (int index = 0; index < current.length; index++) {
            if (expected[index] != current[index]) {
                throw new IllegalArgumentException(
                    "expected_current mismatch at offset " + index
                        + ": expected " + twoDigitHex(expected[index])
                        + ", actual " + twoDigitHex(current[index]));
            }
        }
    }

    Plan plan(
            Program program, Request request, TaskMonitor monitor)
            throws Exception {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(request, "request");
        TaskMonitor taskMonitor =
            monitor == null ? TaskMonitor.DUMMY : monitor;
        taskMonitor.checkCancelled();
        byte[] payload = request.payload();
        if (payload == null || payload.length == 0) {
            throw new IllegalArgumentException("bytes must not be empty");
        }
        if (payload.length > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException(
                "bytes exceeds maximum of "
                    + MAX_PAYLOAD_BYTES + " bytes");
        }

        ResolvedTarget target = resolveTarget(
            program, request.address(), request.block());
        Address end = checkedEnd(target.start(), payload.length);
        MemoryBlock block = target.block();
        if (!block.contains(end)) {
            throw new IllegalArgumentException(
                "patch range leaves memory block '" + block.getName() + "'");
        }
        if (block.isMapped()
                || block.getType() != MemoryBlockType.DEFAULT) {
            throw new IllegalArgumentException(
                "mapped memory blocks are unsupported: "
                    + block.getName());
        }
        if (!block.isInitialized()) {
            throw new IllegalArgumentException(
                "patch requires an initialized memory block");
        }
        if (!block.isWrite() && !request.allowReadonly()) {
            throw new IllegalArgumentException(
                "memory block '" + block.getName()
                    + "' is read-only; pass allow_readonly=true "
                    + "to enable a temporary write permission");
        }

        byte[] previous = readComplete(block, target.start(), payload.length);
        validateExpected(request.expectedCurrent(), previous);
        AddressSet requestedRange =
            new AddressSet(target.start(), end);
        ListingClearCore.Plan clearPlan;
        if (request.clearCodeUnits()) {
            clearPlan = listingClear.plan(
                program,
                requestedRange,
                new ListingClearCore.Selection(true, true, true),
                ListingClearCore.Preservation.defaults(),
                taskMonitor);
            if (!clearPlan.conflicts().isEmpty()) {
                throw new IllegalArgumentException(
                    "listing clear conflict: "
                        + String.join("; ", clearPlan.conflicts()));
            }
        }
        else {
            ListingClearCore.Plan instructionPlan = listingClear.plan(
                program,
                requestedRange,
                new ListingClearCore.Selection(true, false, false),
                new ListingClearCore.Preservation(
                    false, false, false, false),
                taskMonitor);
            if (!instructionPlan.units().isEmpty()) {
                ListingClearCore.CodeUnitSnapshot instruction =
                    instructionPlan.units().get(0);
                throw new IllegalArgumentException(
                    "patch intersects instruction "
                        + instruction.start() + ".." + instruction.end()
                        + " while clear_code_units=false");
            }
            clearPlan = ListingClearCore.emptyPlan();
        }
        taskMonitor.checkCancelled();
        return new Plan(
            block,
            target.start(),
            end,
            payload,
            previous,
            clearPlan,
            block.isWrite(),
            !block.isWrite());
    }

    Plan plan(Program program, Request request) throws Exception {
        return plan(program, request, TaskMonitor.DUMMY);
    }

    void apply(Program program, Plan plan, TaskMonitor monitor)
            throws Exception {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(plan, "plan");
        TaskMonitor taskMonitor =
            monitor == null ? TaskMonitor.DUMMY : monitor;
        taskMonitor.checkCancelled();
        listingClear.apply(program, plan.clearPlan(), taskMonitor);

        Exception pending = null;
        boolean permissionChanged = false;
        try {
            if (plan.temporaryWriteEnabled()) {
                taskMonitor.checkCancelled();
                permissionChanged = true;
                plan.block().setWrite(true);
                if (!plan.block().isWrite()) {
                    throw new IllegalStateException(
                        "failed to enable temporary write permission");
                }
            }
            taskMonitor.checkCancelled();
            int count = plan.block().putBytes(
                plan.start(), plan.payload());
            taskMonitor.checkCancelled();
            if (count != plan.payload().length) {
                throw new IllegalStateException(
                    "Ghidra wrote only " + count + " of "
                        + plan.payload().length + " bytes");
            }
            if (permissionChanged) {
                restoreWritePermission(plan);
                permissionChanged = false;
            }
            taskMonitor.checkCancelled();
            byte[] readback = readComplete(
                plan.block(), plan.start(), plan.payload().length);
            taskMonitor.checkCancelled();
            int mismatch = firstMismatch(plan.payload(), readback);
            if (mismatch >= 0) {
                throw new IllegalStateException(
                    "readback mismatch at offset " + mismatch
                        + ": expected "
                        + twoDigitHex(plan.payload()[mismatch])
                        + ", actual " + twoDigitHex(readback[mismatch]));
            }
            listingClear.verify(program, plan.clearPlan(), taskMonitor);
        }
        catch (Exception error) {
            pending = error;
        }
        finally {
            if (permissionChanged) {
                try {
                    restoreWritePermission(plan);
                }
                catch (Exception restoration) {
                    IllegalStateException failure =
                        new IllegalStateException(
                            "failed to restore original write permission",
                            restoration);
                    if (pending != null) {
                        failure.addSuppressed(pending);
                    }
                    pending = failure;
                }
            }
        }
        if (pending != null) {
            throw pending;
        }
        taskMonitor.checkCancelled();
    }

    private static void restoreWritePermission(Plan plan) {
        try {
            plan.block().setWrite(plan.originalWrite());
            if (plan.block().isWrite() == plan.originalWrite()) {
                return;
            }
        }
        catch (RuntimeException error) {
            throw new IllegalStateException(
                "failed to restore original write permission",
                error);
        }
        throw new IllegalStateException(
            "failed to restore original write permission");
    }

    static PayloadSummary summarize(
            byte[] previous, byte[] written, boolean dryRun) {
        if (previous.length != written.length) {
            throw new IllegalArgumentException(
                "previous and written payload lengths differ");
        }
        HexFormat hex = HexFormat.of();
        if (dryRun || written.length <= FULL_HEX_LIMIT) {
            return new PayloadSummary(
                hex.formatHex(previous),
                hex.formatHex(written),
                null, null, null, null, null, null);
        }
        return new PayloadSummary(
            null,
            null,
            MemoryBlockCore.sha256(previous),
            MemoryBlockCore.sha256(written),
            sample(previous, true),
            sample(previous, false),
            sample(written, true),
            sample(written, false));
    }

    private record ResolvedTarget(MemoryBlock block, Address start) {
    }

    private static ResolvedTarget resolveTarget(
            Program program, String addressText, String blockName) {
        if (addressText == null || addressText.isBlank()) {
            throw new IllegalArgumentException("address is required");
        }
        if (blockName != null && blockName.isBlank()) {
            throw new IllegalArgumentException(
                "block must not be blank");
        }
        if (blockName == null) {
            Address address = parseAddress(
                program, addressText, "address");
            MemoryBlock block =
                program.getMemory().getBlock(address);
            if (block == null) {
                throw new IllegalArgumentException(
                    "address is outside mapped program memory: "
                        + addressText);
            }
            return new ResolvedTarget(block, address);
        }

        List<MemoryBlock> matches = new ArrayList<>();
        for (MemoryBlock candidate :
                program.getMemory().getBlocks()) {
            if (blockName.equals(candidate.getName())) {
                matches.add(candidate);
            }
        }
        if (matches.isEmpty()) {
            throw new IllegalArgumentException(
                "memory block not found: " + blockName);
        }
        if (matches.size() > 1) {
            throw new IllegalArgumentException(
                "memory block name is ambiguous: " + blockName);
        }
        MemoryBlock block = matches.get(0);
        Address start;
        if (addressText.contains(":")) {
            start = parseAddress(program, addressText, "address");
            if (!start.getAddressSpace().equals(
                    block.getStart().getAddressSpace())) {
                throw new IllegalArgumentException(
                    "block/address-space conflict: block '"
                        + blockName + "' uses "
                        + block.getStart().getAddressSpace().getName()
                        + " but address uses "
                        + start.getAddressSpace().getName());
            }
        }
        else {
            start = parseOffsetInSpace(
                block.getStart().getAddressSpace(), addressText);
        }
        if (!block.contains(start)) {
            throw new IllegalArgumentException(
                "address is outside memory block '" + blockName + "'");
        }
        return new ResolvedTarget(block, start);
    }

    private static Address parseOffsetInSpace(
            AddressSpace space, String text) {
        String value = text.trim();
        if (value.startsWith("0x") || value.startsWith("0X")) {
            value = value.substring(2);
        }
        if (value.isEmpty()
                || !value.chars().allMatch(PatchBytesCore::isHexDigit)) {
            throw new IllegalArgumentException(
                "invalid address offset: " + text);
        }
        try {
            BigInteger offset = new BigInteger(value, 16);
            BigInteger max = unsignedOffset(
                space.getMaxAddress().getOffset(), space.getSize());
            if (offset.compareTo(max) > 0) {
                throw new IllegalArgumentException(
                    "address offset is outside address space "
                        + space.getName() + ": " + text);
            }
            return space.getAddress(offset.longValue());
        }
        catch (RuntimeException error) {
            if (error instanceof IllegalArgumentException
                    && error.getMessage() != null
                    && error.getMessage().startsWith("address offset")) {
                throw error;
            }
            throw new IllegalArgumentException(
                "invalid address offset: " + text, error);
        }
    }

    private static BigInteger unsignedOffset(long offset, int bits) {
        if (offset >= 0) {
            return BigInteger.valueOf(offset);
        }
        return BigInteger.valueOf(offset & Long.MAX_VALUE)
            .setBit(63)
            .and(BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE));
    }

    private static Address parseAddress(
            Program program, String text, String parameter) {
        Address address = ServiceUtils.parseAddress(program, text);
        if (address == null || address.isExternalAddress()) {
            String detail = ServiceUtils.getLastParseError();
            throw new IllegalArgumentException(
                "invalid " + parameter + ": "
                    + (detail == null ? text : detail));
        }
        return address;
    }

    private static Address checkedEnd(Address start, int length) {
        try {
            return start.addNoWrap(length - 1L);
        }
        catch (AddressOverflowException error) {
            throw new IllegalArgumentException(
                "patch range overflows its address space", error);
        }
    }

    private static byte[] readComplete(
            MemoryBlock block, Address start, int length)
            throws Exception {
        byte[] bytes = new byte[length];
        int count = block.getBytes(start, bytes);
        if (count != length) {
            throw new IllegalStateException(
                "Ghidra read only " + count + " of "
                    + length + " bytes");
        }
        return bytes;
    }

    private static int firstMismatch(byte[] expected, byte[] actual) {
        for (int index = 0; index < expected.length; index++) {
            if (expected[index] != actual[index]) {
                return index;
            }
        }
        return -1;
    }

    private static String sample(byte[] bytes, boolean first) {
        int length = Math.min(SAMPLE_BYTES, bytes.length);
        int offset = first ? 0 : bytes.length - length;
        return HexFormat.of().formatHex(bytes, offset, offset + length);
    }

    private static String twoDigitHex(byte value) {
        return String.format("%02x", value & 0xff);
    }

    private static boolean isHexWhitespace(char value) {
        return value == ' ' || value == '\t' || value == '\n'
            || value == '\u000b' || value == '\f' || value == '\r';
    }

    private static boolean isHexDigit(int value) {
        return value >= '0' && value <= '9'
            || value >= 'a' && value <= 'f'
            || value >= 'A' && value <= 'F';
    }

    private static int hexNibble(char value) {
        if (value >= '0' && value <= '9') {
            return value - '0';
        }
        if (value >= 'a' && value <= 'f') {
            return value - 'a' + 10;
        }
        if (value >= 'A' && value <= 'F') {
            return value - 'A' + 10;
        }
        return -1;
    }
}
