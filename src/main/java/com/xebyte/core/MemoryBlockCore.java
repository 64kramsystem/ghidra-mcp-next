package com.xebyte.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * Transaction-free planner/applicator for memory block mutations.
 *
 * <p>Every plan performs all validation and captures before-state. Apply
 * methods assume that the caller already owns one Ghidra transaction.
 */
final class MemoryBlockCore {

    static final long MAX_SOURCE_BYTES = 67_108_864L;

    @FunctionalInterface
    interface FileReader {
        byte[] read(Path path, long offset, int length) throws IOException;
    }

    record SourceData(
            Long length,
            byte[] bytes,
            Integer fill,
            String source) {
        boolean initialized() {
            return bytes != null || fill != null;
        }

        long size() {
            return bytes != null ? bytes.length : length;
        }
    }

    record CreateRequest(
            String name,
            String start,
            SourceData source,
            boolean overlay,
            boolean read,
            boolean write,
            boolean execute,
            boolean volatileFlag,
            String comment) {
    }

    record BlockDescriptor(
            String name,
            String start,
            String end,
            long length,
            String addressSpace,
            boolean overlay,
            boolean initialized,
            String source,
            boolean read,
            boolean write,
            boolean execute,
            String permissions,
            boolean volatileFlag,
            String comment) {
    }

    record CreatePlan(
            CreateRequest request,
            Address start,
            long length,
            BlockDescriptor predicted) {
    }

    record UpdateRequest(
            String name,
            String newName,
            Boolean read,
            Boolean write,
            Boolean execute,
            Boolean volatileFlag,
            String comment) {
    }

    record UpdatePlan(
            MemoryBlock block,
            BlockDescriptor before,
            BlockDescriptor predicted,
            UpdateRequest request) {
    }

    record SplitPlan(
            MemoryBlock block,
            Address split,
            String suffixName,
            BlockDescriptor before,
            BlockDescriptor prefix,
            BlockDescriptor suffix) {
    }

    record MovePlan(
            MemoryBlock block,
            Address destination,
            BlockDescriptor before,
            BlockDescriptor predicted) {
    }

    record DifferingRange(String start, String end, long length) {
    }

    record WritePlan(
            MemoryBlock block,
            Address start,
            byte[] requested,
            BlockDescriptor before,
            String sha256,
            List<DifferingRange> differingRanges,
            String conflictPolicy) {
    }

    record SplitApplied(
            BlockDescriptor before,
            BlockDescriptor prefix,
            BlockDescriptor suffix) {
    }

    static SourceData normalizeSource(
            Long length,
            Object encodedBytes,
            Path filePath,
            Long fileOffset,
            Long sourceLength,
            FileReader reader) {
        int count = (length != null ? 1 : 0)
            + (encodedBytes != null ? 1 : 0)
            + (filePath != null ? 1 : 0);
        if (count != 1) {
            throw new IllegalArgumentException(
                "exactly one of length, bytes, or file_path is required");
        }
        if (filePath == null
                && ((fileOffset != null && fileOffset != 0)
                    || sourceLength != null)) {
            throw new IllegalArgumentException(
                "file_offset and source_length are valid only with file_path");
        }
        if (length != null) {
            if (length <= 0) {
                throw new IllegalArgumentException("length must be positive");
            }
            return new SourceData(length, null, null, "uninitialized");
        }
        if (encodedBytes != null) {
            byte[] bytes = decodeBytes(encodedBytes);
            if (bytes.length == 0) {
                throw new IllegalArgumentException("bytes must not be empty");
            }
            validatePayloadLength(bytes.length);
            return new SourceData((long) bytes.length, bytes, null, "bytes");
        }
        if (sourceLength == null) {
            throw new IllegalArgumentException(
                "source_length is required with file_path");
        }
        long offset = fileOffset == null ? 0L : fileOffset;
        byte[] bytes = readFileSource(
            filePath, offset, sourceLength, Objects.requireNonNull(reader));
        return new SourceData(
            (long) bytes.length,
            bytes,
            null,
            "file:" + filePath);
    }

    static SourceData withFill(SourceData source, Integer fill) {
        if (fill == null) {
            return source;
        }
        if (source.bytes() != null || !"uninitialized".equals(source.source())) {
            throw new IllegalArgumentException(
                "fill is valid only when length is the creation source");
        }
        exactByte(fill, "fill");
        return new SourceData(
            source.length(), null, fill,
            String.format(Locale.ROOT, "fill:%02X", fill));
    }

    static byte[] readFileSource(
            Path path,
            long fileOffset,
            long sourceLength,
            FileReader reader) {
        if (path == null) {
            throw new IllegalArgumentException("file_path is required");
        }
        if (fileOffset < 0) {
            throw new IllegalArgumentException(
                "file_offset must be non-negative");
        }
        if (sourceLength <= 0) {
            throw new IllegalArgumentException(
                "source_length must be positive");
        }
        validatePayloadLength(sourceLength);
        try {
            byte[] selected =
                reader.read(path, fileOffset, Math.toIntExact(sourceLength));
            if (selected.length != sourceLength) {
                throw new IllegalArgumentException(
                    "file changed while reading; requested range no longer fits");
            }
            return selected;
        }
        catch (IOException error) {
            throw new IllegalArgumentException(
                "cannot read file_path: " + error.getMessage(), error);
        }
    }

    static byte[] decodeBytes(Object encoded) {
        if (encoded == null) {
            throw new IllegalArgumentException("bytes is required");
        }
        if (encoded instanceof byte[] compact) {
            validatePayloadLength(compact.length);
            return compact;
        }
        if (encoded instanceof List<?> values) {
            validatePayloadLength(values.size());
            byte[] result = new byte[values.size()];
            for (int i = 0; i < values.size(); i++) {
                Integer item = exactByte(values.get(i), "bytes[" + i + "]");
                result[i] = (byte) (item & 0xff);
            }
            return result;
        }
        if (!(encoded instanceof String text)) {
            throw new IllegalArgumentException(
                "bytes must be a hex string or byte array");
        }
        String value = text;
        int first = 0;
        while (first < value.length()
                && isHexWhitespace(value.charAt(first))) {
            first++;
        }
        if (first < value.length() && value.charAt(first) == '[') {
            try {
                return decodeJsonByteArray(value);
            }
            catch (RuntimeException error) {
                if (error instanceof IllegalArgumentException argument) {
                    throw argument;
                }
                throw new IllegalArgumentException(
                    "bytes must be a hex string or byte array", error);
            }
        }
        int digits = 0;
        for (int i = 0; i < value.length(); i++) {
            if (!isHexWhitespace(value.charAt(i))) {
                digits++;
            }
        }
        if ((digits & 1) != 0) {
            throw new IllegalArgumentException(
                "hex bytes must contain an even number of digits");
        }
        validatePayloadLength(digits / 2L);
        byte[] result = new byte[digits / 2];
        int high = -1;
        int output = 0;
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            if (isHexWhitespace(character)) {
                continue;
            }
            int nibble = hexNibble(character);
            if (nibble < 0) {
                throw new IllegalArgumentException(
                    "bytes contains invalid hexadecimal digits");
            }
            if (high < 0) {
                high = nibble;
            }
            else {
                result[output++] = (byte) ((high << 4) | nibble);
                high = -1;
            }
        }
        return result;
    }

    private static boolean isHexWhitespace(char value) {
        return value == ' ' || value == '\t' || value == '\n'
            || value == '\u000b' || value == '\f' || value == '\r';
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

    private static byte[] decodeJsonByteArray(String value) {
        return JsonHelper.parseNativeByteArray(
            value, "bytes", Math.toIntExact(MAX_SOURCE_BYTES));
    }

    static void validatePayloadLength(long length) {
        if (length > MAX_SOURCE_BYTES) {
            throw new IllegalArgumentException(
                "byte source exceeds maximum of " + MAX_SOURCE_BYTES
                    + " bytes");
        }
    }

    static Long exactLong(Object raw, String name, boolean allowZero) {
        if (raw == null) {
            return null;
        }
        BigDecimal decimal;
        try {
            decimal = raw instanceof BigDecimal value
                ? value
                : new BigDecimal(String.valueOf(raw));
        }
        catch (NumberFormatException error) {
            throw new IllegalArgumentException(
                name + " must be an exact integer", error);
        }
        long value;
        try {
            value = decimal.longValueExact();
        }
        catch (ArithmeticException error) {
            throw new IllegalArgumentException(
                name + " must be an exact 64-bit integer", error);
        }
        if (allowZero ? value < 0 : value <= 0) {
            throw new IllegalArgumentException(
                name + (allowZero
                    ? " must be non-negative"
                    : " must be positive"));
        }
        return value;
    }

    static Integer exactByte(Object raw, String name) {
        if (raw == null) {
            return null;
        }
        long value = exactLong(raw, name, true);
        if (value > 255) {
            throw new IllegalArgumentException(
                name + " must be between 0 and 255");
        }
        return (int) value;
    }

    CreatePlan planCreate(Program program, CreateRequest request) {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(request, "request");
        validateName(request.name(), "name");
        if (program.getMemory().getBlock(request.name()) != null) {
            throw new IllegalArgumentException(
                "memory block name already exists: " + request.name());
        }
        Address start = parseAddress(program, request.start(), "start");
        if (start.getAddressSpace().isOverlaySpace()) {
            throw new IllegalArgumentException(
                "create start must not use an existing overlay address space");
        }
        long length = request.source().size();
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive");
        }
        Address end = checkedEnd(start, length);
        if (!request.overlay()) {
            rejectOverlap(program.getMemory(), start, end, null);
        }
        BlockDescriptor predicted = predictedCreate(
            request,
            start,
            end,
            length,
            request.overlay()
                ? predictOverlaySpaceName(program, request.name())
                : start.getAddressSpace().getName());
        return new CreatePlan(request, start, length, predicted);
    }

    MemoryBlock applyCreate(
            Program program, CreatePlan plan, TaskMonitor monitor)
            throws Exception {
        Memory memory = program.getMemory();
        SourceData source = plan.request().source();
        MemoryBlock block;
        if (source.bytes() != null) {
            block = memory.createInitializedBlock(
                plan.request().name(),
                plan.start(),
                new ByteArrayInputStream(source.bytes()),
                plan.length(),
                monitor,
                plan.request().overlay());
        }
        else if (source.fill() != null) {
            block = memory.createInitializedBlock(
                plan.request().name(),
                plan.start(),
                plan.length(),
                (byte) (source.fill() & 0xff),
                monitor,
                plan.request().overlay());
        }
        else {
            block = memory.createUninitializedBlock(
                plan.request().name(),
                plan.start(),
                plan.length(),
                plan.request().overlay());
        }
        block.setPermissions(
            plan.request().read(),
            plan.request().write(),
            plan.request().execute());
        block.setVolatile(plan.request().volatileFlag());
        block.setComment(normalizeComment(plan.request().comment()));
        block.setSourceName(source.source());
        return block;
    }

    UpdatePlan planUpdate(Program program, UpdateRequest request) {
        MemoryBlock block = requireBlock(program, request.name());
        BlockDescriptor before = descriptor(block);
        String name = normalizeOptional(request.newName()) == null
            ? before.name()
            : request.newName().trim();
        validateName(name, "new_name");
        MemoryBlock collision = program.getMemory().getBlock(name);
        if (collision != null && collision != block) {
            throw new IllegalArgumentException(
                "new_name collides with existing memory block: " + name);
        }
        BlockDescriptor predicted = new BlockDescriptor(
            name,
            before.start(),
            before.end(),
            before.length(),
            before.addressSpace(),
            before.overlay(),
            before.initialized(),
            before.source(),
            request.read() == null ? before.read() : request.read(),
            request.write() == null ? before.write() : request.write(),
            request.execute() == null ? before.execute() : request.execute(),
            permissions(
                request.read() == null ? before.read() : request.read(),
                request.write() == null ? before.write() : request.write(),
                request.execute() == null ? before.execute() : request.execute()),
            request.volatileFlag() == null
                ? before.volatileFlag()
                : request.volatileFlag(),
            request.comment() == null
                ? before.comment()
                : normalizeComment(request.comment()));
        return new UpdatePlan(block, before, predicted, request);
    }

    MemoryBlock applyUpdate(UpdatePlan plan) throws Exception {
        MemoryBlock block = plan.block();
        BlockDescriptor after = plan.predicted();
        if (plan.before().equals(after)) {
            return block;
        }
        if (!block.getName().equals(after.name())) {
            block.setName(after.name());
        }
        block.setPermissions(after.read(), after.write(), after.execute());
        block.setVolatile(after.volatileFlag());
        block.setComment(after.comment());
        return block;
    }

    SplitPlan planSplit(Program program, String blockName, String splitText) {
        MemoryBlock block = requireBlock(program, blockName);
        Address split = parseAddress(program, splitText, "split_address");
        if (!split.getAddressSpace().equals(
                block.getStart().getAddressSpace())
                || split.compareTo(block.getStart()) <= 0
                || split.compareTo(block.getEnd()) > 0) {
            throw new IllegalArgumentException(
                "split_address must be strictly inside the memory block");
        }
        String suffixName = block.getName() + "_split_"
            + paddedOffset(split);
        if (program.getMemory().getBlock(suffixName) != null) {
            throw new IllegalArgumentException(
                "split suffix name collision: " + suffixName);
        }
        BlockDescriptor before = descriptor(block);
        long prefixLength = split.subtract(block.getStart());
        long suffixLength = before.length() - prefixLength;
        BlockDescriptor prefix = descriptorWithRange(
            before, before.name(), block.getStart(), split.previous(),
            prefixLength);
        BlockDescriptor suffix = descriptorWithRange(
            before, suffixName, split, block.getEnd(), suffixLength);
        return new SplitPlan(
            block, split, suffixName, before, prefix, suffix);
    }

    SplitApplied applySplit(Program program, SplitPlan plan)
            throws Exception {
        Memory memory = program.getMemory();
        memory.split(plan.block(), plan.split());
        MemoryBlock prefix = memory.getBlock(plan.before().name());
        MemoryBlock suffix = null;
        for (MemoryBlock candidate : memory.getBlocks()) {
            if (candidate != prefix
                    && candidate.getStart().equals(plan.split())
                    && candidate.getStart().getAddressSpace().equals(
                        plan.split().getAddressSpace())) {
                suffix = candidate;
                break;
            }
        }
        if (prefix == null || suffix == null) {
            throw new IllegalStateException(
                "Ghidra split did not produce expected prefix and suffix");
        }
        suffix.setName(plan.suffixName());
        copyMetadata(prefix, plan.before());
        copyMetadata(suffix, plan.before());
        return new SplitApplied(
            plan.before(), descriptor(prefix), descriptor(suffix));
    }

    MovePlan planMove(
            Program program, String blockName, String destinationText) {
        MemoryBlock block = requireBlock(program, blockName);
        if (block.isOverlay()) {
            throw new IllegalArgumentException(
                "moving overlay blocks is unsupported");
        }
        Address destination =
            parseAddress(program, destinationText, "new_start");
        if (!destination.getAddressSpace().equals(
                block.getStart().getAddressSpace())) {
            throw new IllegalArgumentException(
                "new_start must use the block address space");
        }
        Address end = checkedEnd(destination, block.getSize());
        rejectOverlap(program.getMemory(), destination, end, block);
        BlockDescriptor before = descriptor(block);
        return new MovePlan(
            block,
            destination,
            before,
            descriptorWithRange(
                before, before.name(), destination, end, before.length()));
    }

    MemoryBlock applyMove(
            Program program, MovePlan plan, TaskMonitor monitor)
            throws Exception {
        if (plan.before().equals(plan.predicted())) {
            return plan.block();
        }
        program.getMemory().moveBlock(
            plan.block(), plan.destination(), monitor);
        return plan.block();
    }

    WritePlan planWrite(
            Program program,
            String startText,
            byte[] requested,
            String conflictPolicy) throws Exception {
        if (requested == null || requested.length == 0) {
            throw new IllegalArgumentException("bytes must not be empty");
        }
        validatePayloadLength(requested.length);
        String policy = conflictPolicy == null
            ? "error"
            : conflictPolicy.trim().toLowerCase(Locale.ROOT);
        if (!"error".equals(policy)
                && !"overwrite_bytes".equals(policy)) {
            throw new IllegalArgumentException(
                "conflict_policy must be error or overwrite_bytes");
        }
        Address start = parseAddress(program, startText, "start");
        Address end = checkedEnd(start, requested.length);
        MemoryBlock block = program.getMemory().getBlock(start);
        if (block == null) {
            throw new IllegalArgumentException(
                "write requires an existing initialized block");
        }
        if (!block.contains(end)) {
            throw new IllegalArgumentException(
                "write may not extend beyond its existing memory block");
        }
        if (!block.isInitialized()) {
            throw new IllegalArgumentException(
                "write requires an existing initialized block");
        }
        byte[] existing = new byte[requested.length];
        int count = block.getBytes(start, existing);
        if (count != existing.length) {
            throw new IllegalArgumentException(
                "could not read the complete initialized destination");
        }
        List<DifferingRange> differences = differingRanges(
            start.getAddressSpace().getName(),
            start.getOffset(),
            existing,
            requested);
        if ("error".equals(policy) && !differences.isEmpty()) {
            throw new IllegalArgumentException(
                "requested bytes differ from initialized program memory");
        }
        return new WritePlan(
            block,
            start,
            Arrays.copyOf(requested, requested.length),
            descriptor(block),
            sha256(requested),
            differences,
            policy);
    }

    void applyWrite(WritePlan plan) throws Exception {
        if (plan.differingRanges().isEmpty()) {
            return;
        }
        int count = plan.block().putBytes(
            plan.start(), plan.requested());
        if (count != plan.requested().length) {
            throw new IllegalStateException(
                "Ghidra wrote only " + count + " of "
                    + plan.requested().length + " bytes");
        }
    }

    static List<DifferingRange> differingRanges(
            String addressSpace,
            long startOffset,
            byte[] before,
            byte[] requested) {
        if (before.length != requested.length) {
            throw new IllegalArgumentException(
                "before and requested byte sequences must have equal length");
        }
        List<DifferingRange> result = new ArrayList<>();
        int index = 0;
        while (index < before.length) {
            if (before[index] == requested[index]) {
                index++;
                continue;
            }
            int first = index;
            while (index + 1 < before.length
                    && before[index + 1] != requested[index + 1]) {
                index++;
            }
            int last = index;
            result.add(new DifferingRange(
                formatAddress(addressSpace, startOffset + first),
                formatAddress(addressSpace, startOffset + last),
                last - first + 1L));
            index++;
        }
        return List.copyOf(result);
    }

    static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(bytes));
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    static BlockDescriptor descriptor(MemoryBlock block) {
        String source = normalizeComment(block.getSourceName());
        return new BlockDescriptor(
            block.getName(),
            block.getStart().toString(false),
            block.getEnd().toString(false),
            block.getSize(),
            block.getStart().getAddressSpace().getName(),
            block.isOverlay(),
            block.isInitialized(),
            source,
            block.isRead(),
            block.isWrite(),
            block.isExecute(),
            permissions(
                block.isRead(), block.isWrite(), block.isExecute()),
            block.isVolatile(),
            normalizeComment(block.getComment()));
    }

    static List<BlockDescriptor> descriptors(Program program) {
        return Arrays.stream(program.getMemory().getBlocks())
            .map(MemoryBlockCore::descriptor)
            .toList();
    }

    private static BlockDescriptor predictedCreate(
            CreateRequest request,
            Address start,
            Address end,
            long length,
            String space) {
        return new BlockDescriptor(
            request.name(),
            start.toString(false),
            end.toString(false),
            length,
            space,
            request.overlay(),
            request.source().initialized(),
            request.source().source(),
            request.read(),
            request.write(),
            request.execute(),
            permissions(
                request.read(), request.write(), request.execute()),
            request.volatileFlag(),
            normalizeComment(request.comment()));
    }

    /**
     * Mirrors MemoryMapDB.fixupOverlaySpaceName/createUniqueOverlaySpace so a
     * dry run reports the exact address-space name Ghidra will assign.
     */
    private static String predictOverlaySpaceName(
            Program program, String blockName) {
        StringBuilder fixed = new StringBuilder(blockName.length());
        for (int i = 0; i < blockName.length(); i++) {
            char value = blockName.charAt(i);
            fixed.append(value == ':' || value <= ' ' ? '_' : value);
        }
        String base = fixed.toString();
        String candidate = base;
        int suffix = 1;
        while (program.getAddressFactory().getAddressSpace(candidate)
                != null) {
            candidate = base + "." + suffix++;
        }
        return candidate;
    }

    private static BlockDescriptor descriptorWithRange(
            BlockDescriptor base,
            String name,
            Address start,
            Address end,
            long length) {
        return new BlockDescriptor(
            name,
            start.toString(false),
            end.toString(false),
            length,
            start.getAddressSpace().getName(),
            base.overlay(),
            base.initialized(),
            base.source(),
            base.read(),
            base.write(),
            base.execute(),
            base.permissions(),
            base.volatileFlag(),
            base.comment());
    }

    private static MemoryBlock requireBlock(
            Program program, String name) {
        if (normalizeOptional(name) == null) {
            throw new IllegalArgumentException("name is required");
        }
        MemoryBlock block = program.getMemory().getBlock(name.trim());
        if (block == null) {
            throw new IllegalArgumentException(
                "memory block not found: " + name);
        }
        return block;
    }

    private static Address parseAddress(
            Program program, String text, String name) {
        if (normalizeOptional(text) == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        Address address = ServiceUtils.parseAddress(program, text);
        if (address == null || address.isExternalAddress()) {
            String detail = ServiceUtils.getLastParseError();
            throw new IllegalArgumentException(
                "invalid " + name + ": "
                    + (detail == null ? text : detail));
        }
        return address;
    }

    private static Address checkedEnd(Address start, long length) {
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive");
        }
        try {
            return start.addNoWrap(Math.subtractExact(length, 1L));
        }
        catch (AddressOverflowException | ArithmeticException error) {
            throw new IllegalArgumentException(
                "memory range overflows its address space", error);
        }
    }

    private static void rejectOverlap(
            Memory memory,
            Address start,
            Address end,
            MemoryBlock ignored) {
        for (MemoryBlock existing : memory.getBlocks()) {
            if (existing == ignored) {
                continue;
            }
            if (!existing.getStart().getAddressSpace().equals(
                    start.getAddressSpace())) {
                continue;
            }
            if (start.compareTo(existing.getEnd()) <= 0
                    && end.compareTo(existing.getStart()) >= 0) {
                throw new IllegalArgumentException(
                    "destination range overlaps memory block '"
                        + existing.getName() + "'");
            }
        }
    }

    private static void validateName(String name, String parameter) {
        if (normalizeOptional(name) == null) {
            throw new IllegalArgumentException(parameter + " is required");
        }
        if (!Memory.isValidMemoryBlockName(name.trim())) {
            throw new IllegalArgumentException(
                parameter + " is not a valid memory block name: " + name);
        }
    }

    private static void copyMetadata(
            MemoryBlock block, BlockDescriptor descriptor) {
        block.setPermissions(
            descriptor.read(),
            descriptor.write(),
            descriptor.execute());
        block.setVolatile(descriptor.volatileFlag());
        block.setComment(descriptor.comment());
        block.setSourceName(descriptor.source());
    }

    private static String paddedOffset(Address address) {
        int width = Math.max(
            1, (address.getAddressSpace().getSize() + 3) / 4);
        return String.format(
            Locale.ROOT, "%0" + width + "X", address.getOffset());
    }

    private static String permissions(
            boolean read, boolean write, boolean execute) {
        return (read ? "r" : "-")
            + (write ? "w" : "-")
            + (execute ? "x" : "-");
    }

    private static String formatAddress(
            String addressSpace, long offset) {
        return addressSpace + ":" + Long.toHexString(offset);
    }

    private static String normalizeComment(String value) {
        return value == null ? "" : value;
    }

    private static String normalizeOptional(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
