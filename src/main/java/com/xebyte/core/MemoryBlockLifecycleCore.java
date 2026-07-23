package com.xebyte.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.model.symbol.OffsetReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.ShiftedReference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Transaction-free planner and applicator for destructive block lifecycle
 * operations.
 */
final class MemoryBlockLifecycleCore {

    static final int MAX_COLLATERAL = 65_536;
    private static final int DIGEST_BUFFER_SIZE = 1 << 20;

    enum InboundPolicy {
        ERROR,
        CLEAR,
        KEEP;

        static InboundPolicy parse(String value) {
            String normalized = value == null
                ? "error"
                : value.trim().toLowerCase(Locale.ROOT);
            return switch (normalized) {
                case "error" -> ERROR;
                case "clear" -> CLEAR;
                case "keep" -> KEEP;
                default -> throw new IllegalArgumentException(
                    "on_inbound_refs must be error, clear, or keep");
            };
        }

        String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    enum ResizeKind {
        SHRINK,
        GROW
    }

    record Range(Address start, Address end) {
        long length() {
            return end.subtract(start) + 1;
        }

        boolean contains(Address address) {
            return address != null
                && address.getAddressSpace().equals(start.getAddressSpace())
                && address.compareTo(start) >= 0
                && address.compareTo(end) <= 0;
        }
    }

    record SymbolRecord(
            Address address,
            String namespacePath,
            String name,
            String symbolType,
            String sourceType,
            boolean primary,
            boolean dynamic,
            long symbolId) {
    }

    record InstructionRecord(
            Address start,
            Address end,
            String mnemonic,
            int length,
            int delaySlotDepth) {
    }

    record DataRecord(
            Address start,
            Address end,
            String datatypePath,
            int length) {
    }

    record CommentRecord(
            Address address,
            CommentType type,
            String text) {
    }

    record BookmarkRecord(
            Address address,
            String type,
            String category,
            String comment,
            long id) {
    }

    record ReferenceRecord(
            Reference reference,
            Address source,
            Address target,
            String referenceType,
            String sourceType,
            int operandIndex,
            boolean primary,
            long associatedSymbolIdBefore,
            long associatedSymbolIdAfter,
            boolean associationCleared,
            String sourceBlock,
            String sourceAddressSpace,
            String targetBlock,
            String targetAddressSpace,
            Address offsetBase,
            Long signedOffset,
            Long shiftedBaseValue,
            Integer shift,
            String policyAction) {
    }

    record Collateral(
            Range range,
            List<SymbolRecord> symbols,
            List<InstructionRecord> instructions,
            List<DataRecord> definedData,
            List<CommentRecord> comments,
            List<BookmarkRecord> bookmarks,
            List<ReferenceRecord> inboundReferences,
            Map<CommentType, Integer> commentCounts) {
    }

    record DeletePlan(
            Program program,
            long modificationNumber,
            MemoryBlock block,
            MemoryBlockCore.BlockDescriptor before,
            Collateral collateral,
            InboundPolicy policy,
            boolean overlay,
            boolean overlaySpaceRemoved,
            String overlaySpaceName) {
    }

    record GrowSource(
            byte[] bytes,
            Integer fill,
            String kind) {
        long length() {
            return bytes == null ? 0 : bytes.length;
        }
    }

    record ResizePlan(
            Program program,
            long modificationNumber,
            MemoryBlock block,
            MemoryBlockCore.BlockDescriptor before,
            MemoryBlockCore.BlockDescriptor predicted,
            ResizeKind kind,
            Range changedRange,
            Collateral collateral,
            InboundPolicy policy,
            GrowSource growSource,
            String retainedDigest,
            List<MemoryBlockCore.SourceInfoDescriptor> retainedFileProvenance) {
    }

    DeletePlan planDelete(
            Program program,
            String name,
            String inboundPolicy,
            TaskMonitor monitor) throws Exception {
        Objects.requireNonNull(program, "program");
        MemoryBlock block = requireExactBlock(program, name);
        rejectDeletionPolicy(program, block);
        Range range = new Range(block.getStart(), block.getEnd());
        validateListingBoundary(program, range);
        InboundPolicy policy = InboundPolicy.parse(inboundPolicy);
        Collateral collateral = collectCollateral(
            program, range, block, policy, monitor);
        boolean finalOverlay =
            block.getStart().getAddressSpace().isOverlaySpace()
            && countBlocksInSpace(program, block.getStart().getAddressSpace()) == 1;
        if (policy == InboundPolicy.KEEP && finalOverlay) {
            throw new IllegalArgumentException(
                "keep is unavailable when deleting the final block in an "
                    + "overlay address space");
        }
        return new DeletePlan(
            program,
            program.getModificationNumber(),
            block,
            MemoryBlockCore.descriptor(block),
            collateral,
            policy,
            block.getStart().getAddressSpace().isOverlaySpace(),
            finalOverlay,
            block.getStart().getAddressSpace().isOverlaySpace()
                ? block.getStart().getAddressSpace().getName()
                : null);
    }

    DeletePlan applyDelete(DeletePlan plan, TaskMonitor monitor)
            throws Exception {
        assertCurrent(plan.program(), plan.modificationNumber(), plan.block(),
            plan.before());
        applyInboundPolicy(
            plan.program(), plan.collateral().inboundReferences(),
            plan.policy(), monitor);
        monitor.checkCancelled();
        plan.program().getMemory().removeBlock(plan.block(), monitor);
        monitor.checkCancelled();
        verifyInboundPolicy(
            plan.program(), plan.collateral().inboundReferences(),
            plan.policy());
        verifyOverlayOutcome(
            plan.program(), plan.overlaySpaceName(),
            plan.overlaySpaceRemoved());
        return plan;
    }

    ResizePlan planResize(
            Program program,
            String name,
            String newEndText,
            Long newLength,
            String inboundPolicy,
            GrowSource growSource,
            TaskMonitor monitor) throws Exception {
        Objects.requireNonNull(program, "program");
        MemoryBlock block = requireExactBlock(program, name);
        if (block.isMapped()) {
            throw new IllegalArgumentException(
                "mapped, bit-mapped, and byte-mapped blocks cannot be resized");
        }
        if ((newEndText == null || newEndText.isBlank())
                == (newLength == null)) {
            throw new IllegalArgumentException(
                "exactly one of new_end or new_length is required");
        }
        Address newEnd;
        if (newLength != null) {
            if (newLength <= 0) {
                throw new IllegalArgumentException(
                    "new_length must be positive");
            }
            newEnd = checkedEnd(block.getStart(), newLength);
        }
        else {
            newEnd = parseAddress(program, newEndText, "new_end");
        }
        if (!newEnd.getAddressSpace().equals(
                block.getStart().getAddressSpace())) {
            throw new IllegalArgumentException(
                "new_end must use the block address space");
        }
        if (newEnd.equals(block.getEnd())) {
            throw new IllegalArgumentException(
                "requested memory block range is unchanged");
        }
        if (newEnd.compareTo(block.getStart()) < 0) {
            throw new IllegalArgumentException(
                "new_end must not precede the block start");
        }
        InboundPolicy policy = InboundPolicy.parse(inboundPolicy);
        MemoryBlockCore.BlockDescriptor before =
            MemoryBlockCore.descriptor(block);
        if (newEnd.compareTo(block.getEnd()) < 0) {
            return planShrink(
                program, block, before, newEnd, policy, growSource, monitor);
        }
        return planGrow(
            program, block, before, newEnd, policy, growSource, monitor);
    }

    ResizePlan applyResize(ResizePlan plan, TaskMonitor monitor)
            throws Exception {
        assertCurrent(plan.program(), plan.modificationNumber(), plan.block(),
            plan.before());
        return plan.kind() == ResizeKind.SHRINK
            ? applyShrink(plan, monitor)
            : applyGrow(plan, monitor);
    }

    static GrowSource bytesSource(byte[] bytes, String kind) {
        if (bytes == null || bytes.length == 0) {
            throw new IllegalArgumentException(
                "grow initialization source must not be empty");
        }
        MemoryBlockCore.validatePayloadLength(bytes.length);
        return new GrowSource(
            Arrays.copyOf(bytes, bytes.length), null, kind);
    }

    static GrowSource fillSource(Integer fill) {
        MemoryBlockCore.exactByte(fill, "fill");
        return new GrowSource(null, fill, "fill");
    }

    static GrowSource fillSource(Integer fill, long length) {
        MemoryBlockCore.exactByte(fill, "fill");
        if (length > MemoryBlockCore.MAX_SOURCE_BYTES) {
            throw new IllegalArgumentException(
                "grow source exceeds maximum of "
                    + MemoryBlockCore.MAX_SOURCE_BYTES + " bytes");
        }
        byte[] bytes = new byte[Math.toIntExact(length)];
        Arrays.fill(bytes, (byte) (fill & 0xff));
        return new GrowSource(bytes, fill, "fill");
    }

    private ResizePlan planShrink(
            Program program,
            MemoryBlock block,
            MemoryBlockCore.BlockDescriptor before,
            Address newEnd,
            InboundPolicy policy,
            GrowSource growSource,
            TaskMonitor monitor) throws Exception {
        if (growSource != null) {
            throw new IllegalArgumentException(
                "grow-source fields are invalid when shrinking");
        }
        Address tailStart = newEnd.next();
        if (tailStart == null) {
            throw new IllegalArgumentException(
                "new range overflows its address space");
        }
        Range removed = new Range(tailStart, block.getEnd());
        if (removed.contains(program.getImageBase())) {
            throw new IllegalArgumentException(
                "cannot shrink a tail containing the program image base");
        }
        if (block.getStart().getAddressSpace().isOverlaySpace()
                && ((OverlayAddressSpace) block.getStart().getAddressSpace())
                    .getOverlayedSpace().getType() == AddressSpace.TYPE_OTHER) {
            throw new IllegalArgumentException(
                "Ghidra cannot split an overlay over an OTHER address space");
        }
        validateListingBoundary(program, removed);
        Collateral collateral = collectCollateral(
            program, removed, block, policy, monitor);
        List<MemoryBlockCore.SourceInfoDescriptor> retainedFileProvenance =
            retainedFileProvenance(block, newEnd);
        MemoryBlockCore.BlockDescriptor predicted = descriptorWithRange(
            before, block.getStart(), newEnd,
            clippedSourceInfos(block, newEnd, false));
        return new ResizePlan(
            program,
            program.getModificationNumber(),
            block,
            before,
            predicted,
            ResizeKind.SHRINK,
            removed,
            collateral,
            policy,
            null,
            digestRange(block, block.getStart(), newEnd, monitor),
            retainedFileProvenance);
    }

    private ResizePlan planGrow(
            Program program,
            MemoryBlock block,
            MemoryBlockCore.BlockDescriptor before,
            Address newEnd,
            InboundPolicy policy,
            GrowSource growSource,
            TaskMonitor monitor) throws Exception {
        if (!block.isInitialized()
                || block.getType() != MemoryBlockType.DEFAULT) {
            throw new IllegalArgumentException(
                "grow requires an initialized DEFAULT block");
        }
        Address addedStart = block.getEnd().next();
        if (addedStart == null) {
            throw new IllegalArgumentException(
                "new range overflows its address space");
        }
        long growth = newEnd.subtract(block.getEnd());
        if (growSource == null) {
            throw new IllegalArgumentException(
                "grow requires exactly one of fill, bytes, or file_path");
        }
        if (growSource.fill() != null) {
            growSource = fillSource(growSource.fill(), growth);
        }
        if (growSource.length() != growth) {
            throw new IllegalArgumentException(
                "grow source length must equal the added range length");
        }
        long total = Math.addExact(block.getSize(), growth);
        if (total > Memory.MAX_BLOCK_SIZE) {
            throw new IllegalArgumentException(
                "result exceeds Memory.MAX_BLOCK_SIZE");
        }
        if (growth > Memory.MAX_BINARY_SIZE - program.getMemory().getSize()) {
            throw new IllegalArgumentException(
                "result exceeds Memory.MAX_BINARY_SIZE");
        }
        rejectOverlap(program.getMemory(), addedStart, newEnd, block);
        if (block.getStart().getAddressSpace().isOverlaySpace()) {
            validateOverlayBacking(
                program, (OverlayAddressSpace) block.getStart()
                    .getAddressSpace(),
                addedStart, newEnd);
        }
        MemoryBlockCore.BlockDescriptor predicted = descriptorWithRange(
            before, block.getStart(), newEnd, before.sourceInfos());
        return new ResizePlan(
            program,
            program.getModificationNumber(),
            block,
            before,
            predicted,
            ResizeKind.GROW,
            new Range(addedStart, newEnd),
            null,
            policy,
            growSource,
            digestRange(block, block.getStart(), block.getEnd(), monitor),
            retainedFileProvenance(block, block.getEnd()));
    }

    private ResizePlan applyShrink(ResizePlan plan, TaskMonitor monitor)
            throws Exception {
        Memory memory = plan.program().getMemory();
        Address split = plan.changedRange().start();
        memory.split(plan.block(), split);
        MemoryBlock prefix = memory.getBlock(plan.before().name());
        MemoryBlock tail = findBlockAt(memory, split, prefix);
        if (prefix == null || tail == null) {
            throw new IllegalStateException(
                "Ghidra split did not produce the expected retained prefix "
                    + "and removed tail");
        }
        applyInboundPolicy(
            plan.program(), plan.collateral().inboundReferences(),
            plan.policy(), monitor);
        monitor.checkCancelled();
        memory.removeBlock(tail, monitor);
        monitor.checkCancelled();
        normalizeMetadata(prefix, plan.before());
        verifyInboundPolicy(
            plan.program(), plan.collateral().inboundReferences(),
            plan.policy());
        verifyRetained(plan, prefix, monitor);
        return new ResizePlan(
            plan.program(),
            plan.program().getModificationNumber(),
            prefix,
            plan.before(),
            MemoryBlockCore.descriptor(prefix),
            plan.kind(),
            plan.changedRange(),
            plan.collateral(),
            plan.policy(),
            null,
            plan.retainedDigest(),
            plan.retainedFileProvenance());
    }

    private ResizePlan applyGrow(ResizePlan plan, TaskMonitor monitor)
            throws Exception {
        Memory memory = plan.program().getMemory();
        String temporaryName = temporaryName(memory, plan.before().name());
        MemoryBlock temporary = memory.createInitializedBlock(
            temporaryName,
            plan.changedRange().start(),
            new ByteArrayInputStream(plan.growSource().bytes()),
            plan.changedRange().length(),
            monitor,
            false);
        normalizeMetadata(temporary, plan.before());
        temporary.setName(temporaryName);
        monitor.checkCancelled();
        MemoryBlock joined = memory.join(plan.block(), temporary);
        normalizeMetadata(joined, plan.before());
        monitor.checkCancelled();
        verifyRetained(plan, joined, monitor);
        byte[] observed = new byte[Math.toIntExact(plan.changedRange().length())];
        int read = joined.getBytes(plan.changedRange().start(), observed);
        if (read != observed.length
                || !Arrays.equals(observed, plan.growSource().bytes())) {
            throw new IllegalStateException(
                "added bytes differ after Ghidra join");
        }
        return new ResizePlan(
            plan.program(),
            plan.program().getModificationNumber(),
            joined,
            plan.before(),
            MemoryBlockCore.descriptor(joined),
            plan.kind(),
            plan.changedRange(),
            null,
            plan.policy(),
            plan.growSource(),
            plan.retainedDigest(),
            plan.retainedFileProvenance());
    }

    private static void rejectDeletionPolicy(
            Program program, MemoryBlock block) {
        if (block.contains(program.getImageBase())) {
            throw new IllegalArgumentException(
                "cannot delete a block containing the program image base");
        }
        if (block.isExternalBlock()) {
            throw new IllegalArgumentException(
                "cannot delete the external memory block");
        }
        if (block.isMapped()) {
            throw new IllegalArgumentException(
                "cannot delete mapped, bit-mapped, or byte-mapped blocks");
        }
    }

    private static Collateral collectCollateral(
            Program program,
            Range range,
            MemoryBlock targetBlock,
            InboundPolicy policy,
            TaskMonitor monitor) throws Exception {
        AddressSet set = new AddressSet(range.start(), range.end());
        List<SymbolRecord> symbols = collectSymbols(program, set, monitor);
        List<InstructionRecord> instructions =
            collectInstructions(program, set, monitor);
        List<DataRecord> data = collectData(program, set, monitor);
        Map<CommentType, Integer> commentCounts =
            new EnumMap<>(CommentType.class);
        List<CommentRecord> comments =
            collectComments(program, set, commentCounts, monitor);
        List<BookmarkRecord> bookmarks =
            collectBookmarks(program, range, monitor);
        List<ReferenceRecord> inbound =
            collectInbound(program, set, range, targetBlock, policy, monitor);
        if (policy == InboundPolicy.ERROR && !inbound.isEmpty()) {
            throw new IllegalArgumentException(
                "inbound references exist; choose clear or keep");
        }
        return new Collateral(
            range, symbols, instructions, data, comments, bookmarks,
            inbound, Map.copyOf(commentCounts));
    }

    private static List<SymbolRecord> collectSymbols(
            Program program, AddressSet set, TaskMonitor monitor)
            throws Exception {
        List<SymbolRecord> result = new ArrayList<>();
        var iterator = program.getSymbolTable().getSymbolIterator(
            set.getMinAddress(), true);
        int count = 0;
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Symbol symbol = iterator.next();
            Address address = symbol.getAddress();
            if (!address.getAddressSpace().equals(
                    set.getMinAddress().getAddressSpace())
                    || address.compareTo(set.getMaxAddress()) > 0) {
                break;
            }
            if (!set.contains(address)) {
                continue;
            }
            count++;
            if (count <= MAX_COLLATERAL) {
                result.add(new SymbolRecord(
                    address,
                    symbol.getParentNamespace().getName(true),
                    symbol.getName(),
                    symbol.getSymbolType().toString(),
                    symbol.getSource().name(),
                    symbol.isPrimary(),
                    symbol.isDynamic(),
                    symbol.getID()));
            }
        }
        rejectCap("symbols", count);
        result.sort(Comparator
            .comparing(SymbolRecord::address)
            .thenComparing(SymbolRecord::namespacePath)
            .thenComparing(SymbolRecord::name)
            .thenComparingLong(SymbolRecord::symbolId));
        return List.copyOf(result);
    }

    private static List<InstructionRecord> collectInstructions(
            Program program, AddressSet set, TaskMonitor monitor)
            throws Exception {
        List<InstructionRecord> result = new ArrayList<>();
        int count = 0;
        for (Instruction instruction
                : program.getListing().getInstructions(set, true)) {
            monitor.checkCancelled();
            count++;
            if (count <= MAX_COLLATERAL) {
                result.add(new InstructionRecord(
                    instruction.getMinAddress(),
                    instruction.getMaxAddress(),
                    instruction.getMnemonicString(),
                    instruction.getLength(),
                    instruction.getDelaySlotDepth()));
            }
        }
        rejectCap("instructions", count);
        result.sort(Comparator
            .comparing(InstructionRecord::start)
            .thenComparing(InstructionRecord::end));
        return List.copyOf(result);
    }

    private static List<DataRecord> collectData(
            Program program, AddressSet set, TaskMonitor monitor)
            throws Exception {
        List<DataRecord> result = new ArrayList<>();
        int count = 0;
        for (Data data : program.getListing().getDefinedData(set, true)) {
            monitor.checkCancelled();
            count++;
            if (count <= MAX_COLLATERAL) {
                result.add(new DataRecord(
                    data.getMinAddress(),
                    data.getMaxAddress(),
                    data.getDataType().getPathName(),
                    data.getLength()));
            }
        }
        rejectCap("defined_data", count);
        result.sort(Comparator
            .comparing(DataRecord::start)
            .thenComparing(DataRecord::end));
        return List.copyOf(result);
    }

    private static List<CommentRecord> collectComments(
            Program program,
            AddressSet set,
            Map<CommentType, Integer> counts,
            TaskMonitor monitor) throws Exception {
        List<CommentRecord> result = new ArrayList<>();
        int total = 0;
        Listing listing = program.getListing();
        for (CommentType type : CommentType.values()) {
            int typeCount = 0;
            var iterator = listing.getCommentAddressIterator(type, set, true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Address address = iterator.next();
                String text = listing.getComment(type, address);
                if (text == null) {
                    continue;
                }
                total++;
                typeCount++;
                if (total <= MAX_COLLATERAL) {
                    result.add(new CommentRecord(address, type, text));
                }
            }
            counts.put(type, typeCount);
        }
        rejectCap("comments", total);
        result.sort(Comparator
            .comparing(CommentRecord::address)
            .thenComparing(record -> record.type().name()));
        return List.copyOf(result);
    }

    private static List<BookmarkRecord> collectBookmarks(
            Program program, Range range, TaskMonitor monitor)
            throws Exception {
        List<BookmarkRecord> result = new ArrayList<>();
        int count = 0;
        Iterator<Bookmark> iterator =
            program.getBookmarkManager().getBookmarksIterator();
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Bookmark bookmark = iterator.next();
            if (!range.contains(bookmark.getAddress())) {
                continue;
            }
            count++;
            if (count <= MAX_COLLATERAL) {
                result.add(new BookmarkRecord(
                    bookmark.getAddress(),
                    bookmark.getTypeString(),
                    bookmark.getCategory(),
                    bookmark.getComment(),
                    bookmark.getId()));
            }
        }
        rejectCap("bookmarks", count);
        result.sort(Comparator
            .comparing(BookmarkRecord::address)
            .thenComparing(BookmarkRecord::type)
            .thenComparing(BookmarkRecord::category)
            .thenComparingLong(BookmarkRecord::id));
        return List.copyOf(result);
    }

    private static List<ReferenceRecord> collectInbound(
            Program program,
            AddressSet set,
            Range range,
            MemoryBlock targetBlock,
            InboundPolicy policy,
            TaskMonitor monitor) throws Exception {
        List<ReferenceRecord> result = new ArrayList<>();
        int count = 0;
        ReferenceManager manager = program.getReferenceManager();
        var destinations =
            manager.getReferenceDestinationIterator(set, true);
        while (destinations.hasNext()) {
            monitor.checkCancelled();
            Address target = destinations.next();
            var references = manager.getReferencesTo(target);
            while (references.hasNext()) {
                monitor.checkCancelled();
                Reference reference = references.next();
                if (range.contains(reference.getFromAddress())) {
                    continue;
                }
                count++;
                if (count <= MAX_COLLATERAL) {
                    result.add(referenceRecord(
                        program, targetBlock, reference, range, policy));
                }
            }
        }
        rejectCap("inbound_references", count);
        result.sort(Comparator
            .comparing(ReferenceRecord::source)
            .thenComparing(ReferenceRecord::target)
            .thenComparingInt(ReferenceRecord::operandIndex)
            .thenComparing(ReferenceRecord::referenceType)
            .thenComparing(ReferenceRecord::sourceType)
            .thenComparing(
                record -> Objects.toString(record.offsetBase(), ""))
            .thenComparing(
                record -> Objects.toString(record.signedOffset(), ""))
            .thenComparing(
                record -> Objects.toString(record.shiftedBaseValue(), ""))
            .thenComparing(record -> Objects.toString(record.shift(), "")));
        return List.copyOf(result);
    }

    private static ReferenceRecord referenceRecord(
            Program program,
            MemoryBlock targetBlock,
            Reference reference,
            Range range,
            InboundPolicy policy) {
        long before = reference.getSymbolID();
        Symbol associated = before < 0
            ? null
            : program.getSymbolTable().getSymbol(before);
        boolean losesAssociation = policy == InboundPolicy.CLEAR
            || associated != null && range.contains(associated.getAddress());
        long after = losesAssociation ? -1 : before;
        MemoryBlock sourceBlock =
            program.getMemory().getBlock(reference.getFromAddress());
        Address offsetBase = reference instanceof OffsetReference offset
            ? offset.getBaseAddress()
            : null;
        Long signedOffset = reference instanceof OffsetReference offset
            ? offset.getOffset()
            : null;
        Long shiftedBase = reference instanceof ShiftedReference shifted
            ? shifted.getValue()
            : null;
        Integer shift = reference instanceof ShiftedReference shifted
            ? shifted.getShift()
            : null;
        return new ReferenceRecord(
            reference,
            reference.getFromAddress(),
            reference.getToAddress(),
            reference.getReferenceType().toString(),
            reference.getSource().name(),
            reference.getOperandIndex(),
            reference.isPrimary(),
            before,
            after,
            before >= 0 && after < 0,
            sourceBlock == null ? null : sourceBlock.getName(),
            reference.getFromAddress().getAddressSpace().getName(),
            targetBlock.getName(),
            reference.getToAddress().getAddressSpace().getName(),
            offsetBase,
            signedOffset,
            shiftedBase,
            shift,
            policy.wireName());
    }

    private static void applyInboundPolicy(
            Program program,
            List<ReferenceRecord> references,
            InboundPolicy policy,
            TaskMonitor monitor) throws Exception {
        if (policy != InboundPolicy.CLEAR) {
            if (policy == InboundPolicy.KEEP) {
                for (ReferenceRecord record : references) {
                    monitor.checkCancelled();
                    if (!record.associationCleared()) {
                        continue;
                    }
                    Reference current = findReference(
                        program.getReferenceManager(), record);
                    if (current == null) {
                        throw new IllegalStateException(
                            "planned inbound reference changed before "
                                + "deletion");
                    }
                    program.getReferenceManager().removeAssociation(current);
                }
            }
            return;
        }
        for (ReferenceRecord record : references) {
            monitor.checkCancelled();
            Reference current = findReference(
                program.getReferenceManager(), record);
            if (current == null) {
                throw new IllegalStateException(
                    "planned inbound reference changed before deletion");
            }
            program.getReferenceManager().delete(current);
        }
    }

    private static void verifyInboundPolicy(
            Program program,
            List<ReferenceRecord> references,
            InboundPolicy policy) {
        for (ReferenceRecord record : references) {
            Reference current = findReference(
                program.getReferenceManager(), record);
            if (policy == InboundPolicy.CLEAR) {
                if (current != null) {
                    throw new IllegalStateException(
                        "an inbound reference remained after clear");
                }
                continue;
            }
            if (policy == InboundPolicy.KEEP) {
                if (current == null || current.getSymbolID()
                        != record.associatedSymbolIdAfter()) {
                    throw new IllegalStateException(
                        "an inbound reference changed after keep: expected "
                            + record.associatedSymbolIdAfter() + ", observed "
                            + (current == null
                                ? "missing"
                                : current.getSymbolID()));
                }
            }
        }
    }

    private static Reference findReference(
            ReferenceManager manager, ReferenceRecord expected) {
        for (Reference candidate
                : manager.getReferencesFrom(expected.source())) {
            if (sameReference(candidate, expected)) {
                return candidate;
            }
        }
        return null;
    }

    private static boolean sameReference(
            Reference candidate, ReferenceRecord expected) {
        if (!candidate.getToAddress().equals(expected.target())
                || candidate.getOperandIndex() != expected.operandIndex()
                || !candidate.getReferenceType().toString()
                    .equals(expected.referenceType())
                || !candidate.getSource().name().equals(expected.sourceType())
                || candidate.isPrimary() != expected.primary()) {
            return false;
        }
        if (expected.offsetBase() != null) {
            return candidate instanceof OffsetReference offset
                && offset.getBaseAddress().equals(expected.offsetBase())
                && offset.getOffset() == expected.signedOffset();
        }
        if (expected.shift() != null) {
            return candidate instanceof ShiftedReference shifted
                && shifted.getValue() == expected.shiftedBaseValue()
                && shifted.getShift() == expected.shift();
        }
        return !candidate.isOffsetReference()
            && !candidate.isShiftedReference();
    }

    private static void validateListingBoundary(
            Program program, Range range) {
        Listing listing = program.getListing();
        CodeUnit atStart = listing.getCodeUnitContaining(range.start());
        if (atStart != null
                && atStart.getMinAddress().compareTo(range.start()) < 0) {
            throw new IllegalArgumentException(
                "removal range begins inside a code unit");
        }
        CodeUnit atEnd = listing.getCodeUnitContaining(range.end());
        if (atEnd != null
                && atEnd.getMaxAddress().compareTo(range.end()) > 0) {
            throw new IllegalArgumentException(
                "removal range ends inside a code unit");
        }
        Instruction first = listing.getInstructionAt(range.start());
        if (first != null && first.isInDelaySlot()) {
            throw new IllegalArgumentException(
                "removal boundary splits an instruction delay-slot group");
        }
        AddressSet set = new AddressSet(range.start(), range.end());
        for (Instruction instruction : listing.getInstructions(set, true)) {
            if (instruction.getDelaySlotDepth() == 0) {
                continue;
            }
            Instruction cursor = instruction;
            for (int i = 0; i < instruction.getDelaySlotDepth(); i++) {
                cursor = cursor.getNext();
                if (cursor == null || !range.contains(cursor.getMinAddress())) {
                    throw new IllegalArgumentException(
                        "removal boundary splits an instruction "
                            + "delay-slot group");
                }
            }
        }
    }

    private static void validateOverlayBacking(
            Program program,
            OverlayAddressSpace overlay,
            Address start,
            Address end) {
        Address overlayStart =
            overlay.getAddressInThisSpaceOnly(start.getOffset());
        Address overlayEnd =
            overlay.getAddressInThisSpaceOnly(end.getOffset());
        if (!overlayStart.equals(start) || !overlayEnd.equals(end)) {
            throw new IllegalArgumentException(
                "overlay growth must remain in the overlay address space");
        }
        AddressSpace base = overlay.getOverlayedSpace();
        Address baseStart = base.getAddress(start.getOffset());
        Address baseEnd = base.getAddress(end.getOffset());
        MemoryBlock backing = program.getMemory().getBlock(baseStart);
        if (backing == null || !backing.contains(baseEnd)) {
            throw new IllegalArgumentException(
                "overlay growth requires one complete backing memory block");
        }
    }

    private static void verifyRetained(
            ResizePlan plan, MemoryBlock block, TaskMonitor monitor)
            throws Exception {
        Address retainedEnd = plan.kind() == ResizeKind.SHRINK
            ? plan.changedRange().start().previous()
            : plan.before().end().equals(block.getEnd().toString(false))
                ? block.getEnd()
                : block.getStart().addNoWrap(plan.before().length() - 1);
        String digest =
            digestRange(block, block.getStart(), retainedEnd, monitor);
        if (!digest.equals(plan.retainedDigest())) {
            throw new IllegalStateException(
                "retained bytes changed during resize");
        }
        List<MemoryBlockCore.SourceInfoDescriptor> observed =
            retainedFileProvenance(block, retainedEnd);
        if (!observed.equals(plan.retainedFileProvenance())) {
            throw new IllegalStateException(
                "retained file provenance changed during resize");
        }
        MemoryBlockCore.BlockDescriptor descriptor =
            MemoryBlockCore.descriptor(block);
        if (!sameMetadata(plan.before(), descriptor)) {
            throw new IllegalStateException(
                "retained block metadata changed during resize");
        }
    }

    private static boolean sameMetadata(
            MemoryBlockCore.BlockDescriptor expected,
            MemoryBlockCore.BlockDescriptor observed) {
        return expected.name().equals(observed.name())
            && expected.addressSpace().equals(observed.addressSpace())
            && expected.overlay() == observed.overlay()
            && expected.initialized() == observed.initialized()
            && expected.type().equals(observed.type())
            && expected.read() == observed.read()
            && expected.write() == observed.write()
            && expected.execute() == observed.execute()
            && expected.volatileFlag() == observed.volatileFlag()
            && expected.artificial() == observed.artificial()
            && Objects.equals(expected.comment(), observed.comment())
            && Objects.equals(expected.sourceName(), observed.sourceName())
            && expected.loaded() == observed.loaded()
            && Objects.equals(
                expected.overlayBaseSpace(), observed.overlayBaseSpace());
    }

    private static void normalizeMetadata(
            MemoryBlock block, MemoryBlockCore.BlockDescriptor before)
            throws Exception {
        if (!block.getName().equals(before.name())) {
            block.setName(before.name());
        }
        block.setPermissions(
            before.read(), before.write(), before.execute());
        block.setVolatile(before.volatileFlag());
        block.setArtificial(before.artificial());
        block.setComment(before.comment());
        block.setSourceName(before.sourceName());
    }

    private static List<MemoryBlockCore.SourceInfoDescriptor>
            retainedFileProvenance(
                MemoryBlock block, Address retainedEnd) {
        List<MemoryBlockCore.SourceInfoDescriptor> clipped =
            clippedSourceInfos(block, retainedEnd, true);
        List<MemoryBlockCore.SourceInfoDescriptor> normalized =
            new ArrayList<>();
        for (MemoryBlockCore.SourceInfoDescriptor info : clipped) {
            MemoryBlockCore.SourceInfoDescriptor value =
                new MemoryBlockCore.SourceInfoDescriptor(
                    info.minAddress(),
                    info.maxAddress(),
                    info.length(),
                    null,
                    info.file(),
                    info.fileOffset(),
                    null,
                    null);
            if (!normalized.isEmpty()) {
                MemoryBlockCore.SourceInfoDescriptor previous =
                    normalized.get(normalized.size() - 1);
                Address previousEnd = parseInSpace(
                    block.getStart().getAddressSpace(),
                    previous.maxAddress());
                Address currentStart = parseInSpace(
                    block.getStart().getAddressSpace(),
                    value.minAddress());
                if (previous.file().equals(value.file())
                        && previous.fileOffset() + previous.length()
                            == value.fileOffset()
                        && previousEnd.next().equals(currentStart)) {
                    normalized.set(
                        normalized.size() - 1,
                        new MemoryBlockCore.SourceInfoDescriptor(
                            previous.minAddress(),
                            value.maxAddress(),
                            previous.length() + value.length(),
                            null,
                            previous.file(),
                            previous.fileOffset(),
                            null,
                            null));
                    continue;
                }
            }
            normalized.add(value);
        }
        return List.copyOf(normalized);
    }

    private static List<MemoryBlockCore.SourceInfoDescriptor>
            clippedSourceInfos(
                MemoryBlock block,
                Address retainedEnd,
                boolean fileOnly) {
        List<MemoryBlockCore.SourceInfoDescriptor> result = new ArrayList<>();
        for (MemoryBlockCore.SourceInfoDescriptor info
                : MemoryBlockCore.descriptor(block).sourceInfos()) {
            if (fileOnly && info.file() == null) {
                continue;
            }
            Address min = parseInSpace(
                block.getStart().getAddressSpace(), info.minAddress());
            Address max = parseInSpace(
                block.getStart().getAddressSpace(), info.maxAddress());
            if (min.compareTo(retainedEnd) > 0) {
                continue;
            }
            Address clippedEnd = max.compareTo(retainedEnd) > 0
                ? retainedEnd
                : max;
            long length = clippedEnd.subtract(min) + 1;
            result.add(new MemoryBlockCore.SourceInfoDescriptor(
                info.minAddress(),
                clippedEnd.toString(false),
                length,
                info.description(),
                info.file(),
                info.fileOffset(),
                info.mappedRange(),
                info.byteMappingScheme()));
        }
        return List.copyOf(result);
    }

    private static Address parseInSpace(
            AddressSpace space, String offset) {
        try {
            Address address = space.getAddress(offset);
            if (address != null) {
                return address;
            }
        }
        catch (Exception error) {
            throw new IllegalStateException(
                "invalid source-info address: " + offset, error);
        }
        throw new IllegalStateException(
            "invalid source-info address: " + offset);
    }

    private static String digestRange(
            MemoryBlock block,
            Address start,
            Address end,
            TaskMonitor monitor) throws Exception {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[DIGEST_BUFFER_SIZE];
            Address cursor = start;
            long remaining = end.subtract(start) + 1;
            while (remaining > 0) {
                monitor.checkCancelled();
                int length = (int) Math.min(buffer.length, remaining);
                int count = block.getBytes(cursor, buffer, 0, length);
                if (count != length) {
                    throw new IllegalStateException(
                        "could not read complete retained block bytes");
                }
                digest.update(buffer, 0, length);
                remaining -= length;
                if (remaining > 0) {
                    cursor = cursor.addNoWrap(length);
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(
                "SHA-256 unavailable", impossible);
        }
    }

    private static MemoryBlockCore.BlockDescriptor descriptorWithRange(
            MemoryBlockCore.BlockDescriptor before,
            Address start,
            Address end,
            List<MemoryBlockCore.SourceInfoDescriptor> sourceInfos) {
        return new MemoryBlockCore.BlockDescriptor(
            before.name(),
            start.toString(false),
            end.toString(false),
            end.subtract(start) + 1,
            before.addressSpace(),
            before.overlay(),
            before.initialized(),
            before.source(),
            before.read(),
            before.write(),
            before.execute(),
            before.permissions(),
            before.volatileFlag(),
            before.comment(),
            before.type(),
            before.artificial(),
            before.loaded(),
            before.sourceName(),
            before.overlayBaseSpace(),
            sourceInfos);
    }

    private static MemoryBlock requireExactBlock(
            Program program, String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("name is required");
        }
        List<MemoryBlock> matches = Arrays.stream(
                program.getMemory().getBlocks())
            .filter(block -> block.getName().equals(name))
            .toList();
        if (matches.isEmpty()) {
            throw new IllegalArgumentException(
                "memory block not found: " + name);
        }
        if (matches.size() > 1) {
            throw new IllegalArgumentException(
                "memory block name is ambiguous: " + name);
        }
        return matches.get(0);
    }

    private static Address parseAddress(
            Program program, String text, String name) {
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
            throw new IllegalArgumentException("new_length must be positive");
        }
        try {
            return start.addNoWrap(Math.subtractExact(length, 1));
        }
        catch (Exception error) {
            throw new IllegalArgumentException(
                "new range overflows its address space", error);
        }
    }

    private static void rejectOverlap(
            Memory memory,
            Address start,
            Address end,
            MemoryBlock ignored) {
        for (MemoryBlock block : memory.getBlocks()) {
            if (block == ignored
                    || !block.getStart().getAddressSpace().equals(
                        start.getAddressSpace())) {
                continue;
            }
            if (start.compareTo(block.getEnd()) <= 0
                    && end.compareTo(block.getStart()) >= 0) {
                throw new IllegalArgumentException(
                    "added range overlaps memory block '"
                        + block.getName() + "'");
            }
        }
    }

    private static int countBlocksInSpace(
            Program program, AddressSpace space) {
        return (int) Arrays.stream(program.getMemory().getBlocks())
            .filter(block -> block.getStart().getAddressSpace().equals(space))
            .count();
    }

    private static MemoryBlock findBlockAt(
            Memory memory, Address start, MemoryBlock ignored) {
        return Arrays.stream(memory.getBlocks())
            .filter(block -> block != ignored
                && block.getStart().equals(start))
            .findFirst()
            .orElse(null);
    }

    private static String temporaryName(
            Memory memory, String originalName) {
        String base = originalName + "_resize";
        String candidate = base;
        int suffix = 1;
        while (memory.getBlock(candidate) != null) {
            candidate = base + "_" + suffix++;
        }
        return candidate;
    }

    private static void assertCurrent(
            Program program,
            long modificationNumber,
            MemoryBlock block,
            MemoryBlockCore.BlockDescriptor before) {
        if (program.getModificationNumber() != modificationNumber
                || !Arrays.asList(program.getMemory().getBlocks())
                    .contains(block)
                || !MemoryBlockCore.descriptor(block).equals(before)) {
            throw new IllegalStateException(
                "program or memory block changed after planning");
        }
    }

    private static void verifyOverlayOutcome(
            Program program,
            String spaceName,
            boolean removed) {
        if (spaceName == null) {
            return;
        }
        boolean exists =
            program.getAddressFactory().getAddressSpace(spaceName) != null;
        if (removed == exists) {
            throw new IllegalStateException(
                "overlay address-space cleanup outcome differs from plan");
        }
    }

    private static void rejectCap(String category, int count) {
        if (count > MAX_COLLATERAL) {
            throw new IllegalArgumentException(
                category + " collateral count " + count
                    + " exceeds maximum of " + MAX_COLLATERAL);
        }
    }
}
