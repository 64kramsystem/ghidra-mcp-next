package com.xebyte.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.OffsetReference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.ShiftedReference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.StackReference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

/**
 * Plans complete-code-unit clears without opening a transaction.
 *
 * <p>The caller owns the transaction used by {@link #apply(Program, Plan)} so
 * larger mutations can compose clearing with disassembly or data creation.
 */
final class ListingClearCore {

    @FunctionalInterface
    interface AnnotationRestorer {
        void restore(Program program, AnnotationSnapshot annotations) throws Exception;
    }

    enum UnitKind {
        INSTRUCTION,
        DATA
    }

    enum ReferenceKind {
        MEMORY,
        OFFSET,
        SHIFTED,
        STACK,
        REGISTER,
        EXTERNAL
    }

    record Selection(
            boolean clearInstructions,
            boolean clearData,
            boolean removeIntersectingFunctions) {
    }

    record Preservation(
            boolean labels,
            boolean comments,
            boolean bookmarks,
            boolean userReferences) {

        static Preservation defaults() {
            return new Preservation(true, true, true, true);
        }
    }

    record CodeUnitSnapshot(Address start, Address end, UnitKind kind) {
    }

    record FunctionSnapshot(Address entry, String name) {
    }

    record LabelSnapshot(
            Address address,
            String name,
            Namespace namespace,
            SourceType source,
            SymbolType symbolType,
            boolean primary,
            boolean pinned) {
    }

    record CommentSnapshot(Address address, CommentType type, String text) {
    }

    record BookmarkSnapshot(
            Address address,
            String type,
            String category,
            String comment) {
    }

    record ReferenceSnapshot(
            Address from,
            Address to,
            RefType type,
            SourceType source,
            int operandIndex,
            boolean primary,
            ReferenceKind kind,
            Address baseAddress,
            long offset,
            int shift,
            ExternalLocation externalLocation) {
    }

    record RemovalCounts(int instructions, int data, int functions) {
    }

    record AnnotationSnapshot(
            List<LabelSnapshot> labels,
            List<CommentSnapshot> comments,
            List<BookmarkSnapshot> bookmarks,
            List<ReferenceSnapshot> references) {

        AnnotationSnapshot {
            labels = List.copyOf(labels);
            comments = List.copyOf(comments);
            bookmarks = List.copyOf(bookmarks);
            references = List.copyOf(references);
        }
    }

    record Plan(
            AddressSet expanded,
            List<CodeUnitSnapshot> units,
            List<FunctionSnapshot> functions,
            AnnotationSnapshot annotations,
            AnnotationSnapshot removedAnnotations,
            Map<SourceType, Integer> removedReferencesBySource,
            RemovalCounts removalCounts,
            List<String> conflicts) {

        Plan {
            expanded = new AddressSet(expanded);
            units = List.copyOf(units);
            functions = List.copyOf(functions);
            removedReferencesBySource =
                Collections.unmodifiableMap(
                    new LinkedHashMap<>(removedReferencesBySource));
            conflicts = List.copyOf(conflicts);
        }

        @Override
        public AddressSet expanded() {
            return new AddressSet(expanded);
        }
    }

    private final AnnotationRestorer annotationRestorer;

    ListingClearCore() {
        this(ListingClearCore::restoreAnnotations);
    }

    ListingClearCore(AnnotationRestorer annotationRestorer) {
        if (annotationRestorer == null) {
            throw new IllegalArgumentException("annotationRestorer is required");
        }
        this.annotationRestorer = annotationRestorer;
    }

    Plan plan(
            Program program,
            AddressSetView requested,
            Selection selection,
            Preservation preservation) {
        if (program == null) {
            throw new IllegalArgumentException("program is required");
        }
        if (requested == null || requested.isEmpty()) {
            throw new IllegalArgumentException("requested address set must not be empty");
        }
        if (selection == null) {
            throw new IllegalArgumentException("selection is required");
        }
        if (preservation == null) {
            throw new IllegalArgumentException("preservation is required");
        }

        Listing listing = program.getListing();
        Map<Address, CodeUnit> intersecting = new LinkedHashMap<>();
        for (AddressRange range : requested) {
            addUnit(intersecting, definedUnitContaining(
                listing, range.getMinAddress()));
            AddressSet bounded =
                new AddressSet(range.getMinAddress(), range.getMaxAddress());
            InstructionIterator instructions = listing.getInstructions(bounded, true);
            while (instructions.hasNext()) {
                addUnit(intersecting, instructions.next());
            }
            DataIterator data = listing.getDefinedData(bounded, true);
            while (data.hasNext()) {
                addUnit(intersecting, data.next());
            }
            addUnit(intersecting, definedUnitContaining(
                listing, range.getMaxAddress()));
        }
        if (selection.clearInstructions()) {
            expandDelaySlotGroups(listing, intersecting);
        }

        List<CodeUnitSnapshot> units = intersecting.values()
            .stream()
            .filter(unit -> isSelected(unit, selection))
            .map(ListingClearCore::snapshot)
            .sorted(Comparator.comparing(CodeUnitSnapshot::start))
            .toList();

        AddressSet expanded = new AddressSet();
        for (CodeUnitSnapshot unit : units) {
            expanded.add(unit.start(), unit.end());
        }

        List<FunctionSnapshot> functions = new ArrayList<>();
        List<String> conflicts = new ArrayList<>();
        AddressSet selectedInstructions = new AddressSet();
        for (CodeUnitSnapshot unit : units) {
            if (unit.kind() == UnitKind.INSTRUCTION) {
                selectedInstructions.add(unit.start(), unit.end());
            }
        }
        if (!selectedInstructions.isEmpty()) {
            Iterator<Function> iterator =
                program.getFunctionManager().getFunctionsOverlapping(selectedInstructions);
            while (iterator.hasNext()) {
                Function function = iterator.next();
                FunctionSnapshot snapshot =
                    new FunctionSnapshot(function.getEntryPoint(), function.getName());
                functions.add(snapshot);
                if (!selection.removeIntersectingFunctions()) {
                    conflicts.add("instruction intersects function " + function.getName() +
                        " at " + function.getEntryPoint());
                }
            }
        }
        functions.sort(Comparator.comparing(FunctionSnapshot::entry));
        conflicts.sort(String::compareTo);
        if (!selection.removeIntersectingFunctions()) {
            functions = List.of();
        }

        AnnotationPartition annotationPartition =
            partitionAnnotations(program, expanded, preservation);
        int instructionCount =
            (int) units.stream().filter(unit -> unit.kind() == UnitKind.INSTRUCTION).count();
        int dataCount =
            (int) units.stream().filter(unit -> unit.kind() == UnitKind.DATA).count();
        RemovalCounts removalCounts =
            new RemovalCounts(instructionCount, dataCount, functions.size());
        return new Plan(
            expanded,
            units,
            functions,
            annotationPartition.preserved(),
            annotationPartition.removed(),
            countReferencesBySource(annotationPartition.removed().references()),
            removalCounts,
            conflicts);
    }

    private static void addUnit(Map<Address, CodeUnit> units, CodeUnit unit) {
        if (unit != null) {
            units.putIfAbsent(unit.getMinAddress(), unit);
        }
    }

    private static CodeUnit definedUnitContaining(
            Listing listing, Address address) {
        Instruction instruction = listing.getInstructionContaining(address);
        return instruction != null
            ? instruction
            : listing.getDefinedDataContaining(address);
    }

    private static boolean isSelected(CodeUnit unit, Selection selection) {
        return (unit instanceof Instruction && selection.clearInstructions()) ||
            (unit instanceof Data && selection.clearData());
    }

    private static void expandDelaySlotGroups(
            Listing listing,
            Map<Address, CodeUnit> intersecting) {
        List<Instruction> selectedInstructions = intersecting.values()
            .stream()
            .filter(Instruction.class::isInstance)
            .map(Instruction.class::cast)
            .toList();
        for (Instruction selected : selectedInstructions) {
            Instruction root = selected;
            while (root.isInDelaySlot()) {
                Instruction instruction =
                    listing.getInstructionBefore(root.getMinAddress());
                if (instruction == null) {
                    break;
                }
                root = instruction;
                addUnit(intersecting, root);
            }

            boolean followDelaySlots =
                root.getPrototype() != null && root.getPrototype().hasDelaySlots();
            Instruction current = root;
            while (followDelaySlots || current.isInDelaySlot()) {
                Instruction instruction =
                    listing.getInstructionAfter(current.getMaxAddress());
                if (instruction == null || !instruction.isInDelaySlot()) {
                    break;
                }
                addUnit(intersecting, instruction);
                current = instruction;
                followDelaySlots = false;
            }
        }
    }

    private static CodeUnitSnapshot snapshot(CodeUnit unit) {
        UnitKind kind = unit instanceof Instruction ? UnitKind.INSTRUCTION : UnitKind.DATA;
        return new CodeUnitSnapshot(unit.getMinAddress(), unit.getMaxAddress(), kind);
    }

    void apply(Program program, Plan plan) throws Exception {
        if (program == null) {
            throw new IllegalArgumentException("program is required");
        }
        if (plan == null) {
            throw new IllegalArgumentException("plan is required");
        }
        if (!plan.conflicts().isEmpty()) {
            throw new IllegalStateException(
                "listing clear plan has conflicts: " + String.join("; ", plan.conflicts()));
        }

        for (FunctionSnapshot function : plan.functions()) {
            if (!program.getFunctionManager().removeFunction(function.entry())) {
                throw new IllegalStateException(
                    "failed to remove function " + function.name() +
                        " at " + function.entry());
            }
        }
        removePlannedLabels(program, plan.removedAnnotations().labels());
        removePlannedComments(program, plan.removedAnnotations().comments());
        removePlannedBookmarks(program, plan.removedAnnotations().bookmarks());
        removeOutgoingReferences(program, plan.expanded());
        for (CodeUnitSnapshot unit : plan.units()) {
            program.getListing().clearCodeUnits(unit.start(), unit.end(), false);
        }
        annotationRestorer.restore(program, plan.annotations());
    }

    private record AnnotationPartition(
            AnnotationSnapshot preserved,
            AnnotationSnapshot removed) {
    }

    private static AnnotationPartition partitionAnnotations(
            Program program,
            AddressSetView expanded,
            Preservation preservation) {
        List<LabelSnapshot> preservedLabels = new ArrayList<>();
        List<CommentSnapshot> preservedComments = new ArrayList<>();
        List<BookmarkSnapshot> preservedBookmarks = new ArrayList<>();
        List<ReferenceSnapshot> preservedReferences = new ArrayList<>();
        List<LabelSnapshot> removedLabels = new ArrayList<>();
        List<CommentSnapshot> removedComments = new ArrayList<>();
        List<BookmarkSnapshot> removedBookmarks = new ArrayList<>();
        List<ReferenceSnapshot> removedReferences = new ArrayList<>();
        if (expanded.isEmpty()) {
            AnnotationSnapshot empty =
                new AnnotationSnapshot(List.of(), List.of(), List.of(), List.of());
            return new AnnotationPartition(empty, empty);
        }

        Listing listing = program.getListing();
        SymbolTable symbolTable = program.getSymbolTable();
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        ReferenceManager referenceManager = program.getReferenceManager();

        var addresses = expanded.getAddresses(true);
        while (addresses.hasNext()) {
            Address address = addresses.next();
            Symbol[] atAddress = symbolTable.getSymbols(address);
            if (atAddress != null) {
                for (Symbol symbol : atAddress) {
                    // Dynamic symbols are projections of surviving references, not
                    // owned annotations. They may disappear and reappear as Ghidra
                    // recomputes them, so neither preservation nor removal counts
                    // claim them.
                    if (symbol.isDynamic()
                            || symbol.getSymbolType() != SymbolType.LABEL) {
                        continue;
                    }
                    LabelSnapshot snapshot = new LabelSnapshot(
                        address,
                        symbol.getName(),
                        symbol.getParentNamespace(),
                        symbol.getSource(),
                        symbol.getSymbolType(),
                        symbol.isPrimary(),
                        symbol.isPinned());
                    if (preservation.labels() && !symbol.isDynamic()
                            && isPreservedSource(symbol.getSource())) {
                        preservedLabels.add(snapshot);
                    }
                    else {
                        removedLabels.add(snapshot);
                    }
                }
            }
            for (CommentType type : CommentType.values()) {
                String text = listing.getComment(type, address);
                if (text != null) {
                    (preservation.comments()
                        ? preservedComments
                        : removedComments).add(
                            new CommentSnapshot(address, type, text));
                }
            }
            Bookmark[] bookmarksAtAddress = bookmarkManager.getBookmarks(address);
            if (bookmarksAtAddress != null) {
                for (Bookmark bookmark : bookmarksAtAddress) {
                    (preservation.bookmarks()
                        ? preservedBookmarks
                        : removedBookmarks).add(new BookmarkSnapshot(
                            address,
                            bookmark.getTypeString(),
                            bookmark.getCategory(),
                            bookmark.getComment()));
                }
            }
            Reference[] fromAddress = referenceManager.getReferencesFrom(address);
            if (fromAddress != null) {
                for (Reference reference : fromAddress) {
                    ReferenceSnapshot snapshot = snapshot(reference);
                    if (preservation.userReferences()
                            && isPreservedSource(reference.getSource())) {
                        preservedReferences.add(snapshot);
                    }
                    else {
                        removedReferences.add(snapshot);
                    }
                }
            }
        }

        Comparator<LabelSnapshot> labelOrder = Comparator.comparing(LabelSnapshot::address)
            .thenComparing(LabelSnapshot::name)
            .thenComparing(label -> label.source().name());
        Comparator<CommentSnapshot> commentOrder = Comparator.comparing(CommentSnapshot::address)
            .thenComparingInt(comment -> comment.type().ordinal());
        Comparator<BookmarkSnapshot> bookmarkOrder = Comparator.comparing(
                BookmarkSnapshot::address)
            .thenComparing(
                BookmarkSnapshot::type,
                Comparator.nullsFirst(String::compareTo))
            .thenComparing(
                BookmarkSnapshot::category,
                Comparator.nullsFirst(String::compareTo))
            .thenComparing(
                BookmarkSnapshot::comment,
                Comparator.nullsFirst(String::compareTo));
        Comparator<ReferenceSnapshot> referenceOrder = Comparator.comparing(
                ReferenceSnapshot::from)
            .thenComparingInt(ReferenceSnapshot::operandIndex)
            .thenComparing(ReferenceSnapshot::to)
            .thenComparing(reference -> reference.source().name());
        preservedLabels.sort(labelOrder);
        removedLabels.sort(labelOrder);
        preservedComments.sort(commentOrder);
        removedComments.sort(commentOrder);
        preservedBookmarks.sort(bookmarkOrder);
        removedBookmarks.sort(bookmarkOrder);
        preservedReferences.sort(referenceOrder);
        removedReferences.sort(referenceOrder);
        return new AnnotationPartition(
            new AnnotationSnapshot(
                preservedLabels,
                preservedComments,
                preservedBookmarks,
                preservedReferences),
            new AnnotationSnapshot(
                removedLabels,
                removedComments,
                removedBookmarks,
                removedReferences));
    }

    private static Map<SourceType, Integer> countReferencesBySource(
            List<ReferenceSnapshot> references) {
        Map<SourceType, Integer> counts = new LinkedHashMap<>();
        for (SourceType source : SourceType.values()) {
            int count = (int) references.stream()
                .filter(reference -> reference.source() == source)
                .count();
            if (count > 0) {
                counts.put(source, count);
            }
        }
        return counts;
    }

    private static void removePlannedLabels(
            Program program, List<LabelSnapshot> labels) {
        SymbolTable table = program.getSymbolTable();
        for (LabelSnapshot snapshot : labels) {
            Symbol[] atAddress = table.getSymbols(snapshot.address());
            if (atAddress == null) {
                continue;
            }
            for (Symbol symbol : atAddress) {
                if (!symbol.isDynamic()
                        && symbol.getSymbolType() == SymbolType.LABEL
                        && snapshot.name().equals(symbol.getName())
                        && snapshot.source() == symbol.getSource()
                        && Objects.equals(
                            snapshot.namespace(), symbol.getParentNamespace())) {
                    if (!symbol.delete() && !symbol.isDeleted()) {
                        throw new IllegalStateException(
                            "failed to remove label " + snapshot.name()
                                + " at " + snapshot.address());
                    }
                    break;
                }
            }
        }
    }

    private static void removePlannedComments(
            Program program, List<CommentSnapshot> comments) {
        Listing listing = program.getListing();
        for (CommentSnapshot comment : comments) {
            listing.setComment(comment.address(), comment.type(), null);
        }
    }

    private static void removePlannedBookmarks(
            Program program, List<BookmarkSnapshot> snapshots) {
        BookmarkManager manager = program.getBookmarkManager();
        for (BookmarkSnapshot snapshot : snapshots) {
            Bookmark[] atAddress = manager.getBookmarks(snapshot.address());
            if (atAddress == null) {
                continue;
            }
            for (Bookmark bookmark : atAddress) {
                if (Objects.equals(snapshot.type(), bookmark.getTypeString())
                        && Objects.equals(
                            snapshot.category(), bookmark.getCategory())
                        && Objects.equals(
                            snapshot.comment(), bookmark.getComment())) {
                    manager.removeBookmark(bookmark);
                    break;
                }
            }
        }
    }

    private static void removeOutgoingReferences(
            Program program, AddressSetView affected) {
        ReferenceManager manager = program.getReferenceManager();
        var addresses = affected.getAddresses(true);
        while (addresses.hasNext()) {
            manager.removeAllReferencesFrom(addresses.next());
        }
    }

    private static boolean isPreservedSource(SourceType source) {
        return source == SourceType.USER_DEFINED || source == SourceType.IMPORTED;
    }

    private static ReferenceSnapshot snapshot(Reference reference) {
        ReferenceKind kind = ReferenceKind.MEMORY;
        Address baseAddress = null;
        long offset = 0;
        int shift = 0;
        ExternalLocation externalLocation = null;
        if (reference.isExternalReference()) {
            kind = ReferenceKind.EXTERNAL;
            externalLocation = ((ExternalReference) reference).getExternalLocation();
        }
        else if (reference.isStackReference()) {
            kind = ReferenceKind.STACK;
            offset = ((StackReference) reference).getStackOffset();
        }
        else if (reference.isRegisterReference()) {
            kind = ReferenceKind.REGISTER;
        }
        else if (reference.isOffsetReference()) {
            kind = ReferenceKind.OFFSET;
            OffsetReference offsetReference = (OffsetReference) reference;
            baseAddress = offsetReference.getBaseAddress();
            offset = offsetReference.getOffset();
        }
        else if (reference.isShiftedReference()) {
            kind = ReferenceKind.SHIFTED;
            shift = ((ShiftedReference) reference).getShift();
        }
        return new ReferenceSnapshot(
            reference.getFromAddress(),
            reference.getToAddress(),
            reference.getReferenceType(),
            reference.getSource(),
            reference.getOperandIndex(),
            reference.isPrimary(),
            kind,
            baseAddress,
            offset,
            shift,
            externalLocation);
    }

    private static void restoreAnnotations(
            Program program,
            AnnotationSnapshot annotations) throws Exception {
        restoreLabels(program, annotations.labels());
        Listing listing = program.getListing();
        for (CommentSnapshot comment : annotations.comments()) {
            listing.setComment(comment.address(), comment.type(), comment.text());
            if (!Objects.equals(
                    comment.text(),
                    listing.getComment(comment.type(), comment.address()))) {
                throw new IllegalStateException(
                    "failed to restore " + comment.type()
                        + " comment at " + comment.address());
            }
        }
        BookmarkManager bookmarks = program.getBookmarkManager();
        for (BookmarkSnapshot bookmark : annotations.bookmarks()) {
            Bookmark restored = bookmarks.setBookmark(
                bookmark.address(),
                bookmark.type(),
                bookmark.category(),
                bookmark.comment());
            if (restored == null) {
                throw new IllegalStateException(
                    "failed to restore bookmark at " + bookmark.address());
            }
        }
        restoreReferences(program, annotations.references());
    }

    private static void restoreLabels(Program program, List<LabelSnapshot> labels)
            throws Exception {
        SymbolTable table = program.getSymbolTable();
        for (LabelSnapshot label : labels) {
            Namespace namespace = label.namespace();
            if (namespace == null || namespace instanceof Function function && function.isDeleted()) {
                namespace = program.getGlobalNamespace();
            }
            Symbol symbol = table.getSymbol(label.name(), label.address(), namespace);
            if (symbol == null) {
                symbol = table.createLabel(
                    label.address(), label.name(), namespace, label.source());
            }
            if (symbol == null) {
                throw new IllegalStateException(
                    "failed to restore label " + label.name()
                        + " at " + label.address());
            }
            if (label.primary() && !symbol.isPrimary()) {
                symbol.setPrimary();
            }
            if (label.pinned() != symbol.isPinned()) {
                symbol.setPinned(label.pinned());
            }
        }
    }

    private static void restoreReferences(
            Program program,
            List<ReferenceSnapshot> references) throws Exception {
        ReferenceManager manager = program.getReferenceManager();
        for (ReferenceSnapshot snapshot : references) {
            Reference restored = switch (snapshot.kind()) {
                case EXTERNAL -> manager.addExternalReference(
                    snapshot.from(),
                    snapshot.externalLocation().getParentNameSpace(),
                    snapshot.externalLocation().getLabel(),
                    snapshot.externalLocation().getAddress(),
                    snapshot.source(),
                    snapshot.operandIndex(),
                    snapshot.type());
                case STACK -> manager.addStackReference(
                    snapshot.from(),
                    snapshot.operandIndex(),
                    (int) snapshot.offset(),
                    snapshot.type(),
                    snapshot.source());
                case REGISTER -> {
                    Register register = program.getRegister(snapshot.to());
                    if (register == null) {
                        throw new IllegalStateException(
                            "register no longer exists at " + snapshot.to());
                    }
                    yield manager.addRegisterReference(
                        snapshot.from(),
                        snapshot.operandIndex(),
                        register,
                        snapshot.type(),
                        snapshot.source());
                }
                case OFFSET -> manager.addOffsetMemReference(
                    snapshot.from(),
                    snapshot.baseAddress(),
                    true,
                    snapshot.offset(),
                    snapshot.type(),
                    snapshot.source(),
                    snapshot.operandIndex());
                case SHIFTED -> manager.addShiftedMemReference(
                    snapshot.from(),
                    snapshot.to(),
                    snapshot.shift(),
                    snapshot.type(),
                    snapshot.source(),
                    snapshot.operandIndex());
                case MEMORY -> manager.addMemoryReference(
                    snapshot.from(),
                    snapshot.to(),
                    snapshot.type(),
                    snapshot.source(),
                    snapshot.operandIndex());
            };
            if (restored == null) {
                throw new IllegalStateException(
                    "failed to restore reference from " + snapshot.from() +
                        " to " + snapshot.to());
            }
            if (snapshot.primary() != restored.isPrimary()) {
                manager.setPrimary(restored, snapshot.primary());
            }
        }
    }
}
