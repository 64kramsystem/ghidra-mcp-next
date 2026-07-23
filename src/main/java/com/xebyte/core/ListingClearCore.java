package com.xebyte.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
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
            RemovalCounts removalCounts,
            List<String> conflicts) {

        Plan {
            expanded = new AddressSet(expanded);
            units = List.copyOf(units);
            functions = List.copyOf(functions);
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
            addUnit(intersecting, listing.getCodeUnitContaining(range.getMinAddress()));
            CodeUnitIterator iterator =
                listing.getCodeUnits(new AddressSet(range.getMinAddress(), range.getMaxAddress()),
                    true);
            while (iterator.hasNext()) {
                addUnit(intersecting, iterator.next());
            }
            addUnit(intersecting, listing.getCodeUnitContaining(range.getMaxAddress()));
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

        AnnotationSnapshot annotations = captureAnnotations(program, expanded, preservation);
        int instructionCount =
            (int) units.stream().filter(unit -> unit.kind() == UnitKind.INSTRUCTION).count();
        int dataCount =
            (int) units.stream().filter(unit -> unit.kind() == UnitKind.DATA).count();
        RemovalCounts removalCounts =
            new RemovalCounts(instructionCount, dataCount, functions.size());
        return new Plan(expanded, units, functions, annotations, removalCounts, conflicts);
    }

    private static void addUnit(Map<Address, CodeUnit> units, CodeUnit unit) {
        if (unit != null) {
            units.putIfAbsent(unit.getMinAddress(), unit);
        }
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
                CodeUnit previous = listing.getCodeUnitBefore(root.getMinAddress());
                if (!(previous instanceof Instruction instruction)) {
                    break;
                }
                root = instruction;
                addUnit(intersecting, root);
            }

            boolean followDelaySlots =
                root.getPrototype() != null && root.getPrototype().hasDelaySlots();
            Instruction current = root;
            while (followDelaySlots || current.isInDelaySlot()) {
                CodeUnit next = listing.getCodeUnitAfter(current.getMaxAddress());
                if (!(next instanceof Instruction instruction) || !instruction.isInDelaySlot()) {
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
        for (CodeUnitSnapshot unit : plan.units()) {
            program.getListing().clearCodeUnits(unit.start(), unit.end(), false);
        }
        annotationRestorer.restore(program, plan.annotations());
    }

    private static AnnotationSnapshot captureAnnotations(
            Program program,
            AddressSetView expanded,
            Preservation preservation) {
        List<LabelSnapshot> labels = new ArrayList<>();
        List<CommentSnapshot> comments = new ArrayList<>();
        List<BookmarkSnapshot> bookmarks = new ArrayList<>();
        List<ReferenceSnapshot> references = new ArrayList<>();
        if (expanded.isEmpty()) {
            return new AnnotationSnapshot(labels, comments, bookmarks, references);
        }

        Listing listing = program.getListing();
        SymbolTable symbolTable = program.getSymbolTable();
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        ReferenceManager referenceManager = program.getReferenceManager();

        var addresses = expanded.getAddresses(true);
        while (addresses.hasNext()) {
            Address address = addresses.next();
            if (preservation.labels()) {
                Symbol[] atAddress = symbolTable.getSymbols(address);
                if (atAddress != null) {
                    for (Symbol symbol : atAddress) {
                        if (!symbol.isDynamic() && isPreservedSource(symbol.getSource())) {
                            labels.add(new LabelSnapshot(
                                address,
                                symbol.getName(),
                                symbol.getParentNamespace(),
                                symbol.getSource(),
                                symbol.getSymbolType(),
                                symbol.isPrimary(),
                                symbol.isPinned()));
                        }
                    }
                }
            }
            if (preservation.comments()) {
                for (CommentType type : CommentType.values()) {
                    String text = listing.getComment(type, address);
                    if (text != null) {
                        comments.add(new CommentSnapshot(address, type, text));
                    }
                }
            }
            if (preservation.bookmarks()) {
                Bookmark[] atAddress = bookmarkManager.getBookmarks(address);
                if (atAddress != null) {
                    for (Bookmark bookmark : atAddress) {
                        bookmarks.add(new BookmarkSnapshot(
                            address,
                            bookmark.getTypeString(),
                            bookmark.getCategory(),
                            bookmark.getComment()));
                    }
                }
            }
            if (preservation.userReferences()) {
                Reference[] fromAddress = referenceManager.getReferencesFrom(address);
                if (fromAddress != null) {
                    for (Reference reference : fromAddress) {
                        if (isPreservedSource(reference.getSource())) {
                            references.add(snapshot(reference));
                        }
                    }
                }
            }
        }

        labels.sort(Comparator.comparing(LabelSnapshot::address)
            .thenComparing(LabelSnapshot::name)
            .thenComparing(label -> label.source().name()));
        comments.sort(Comparator.comparing(CommentSnapshot::address)
            .thenComparingInt(comment -> comment.type().ordinal()));
        bookmarks.sort(Comparator.comparing(BookmarkSnapshot::address)
            .thenComparing(BookmarkSnapshot::type)
            .thenComparing(BookmarkSnapshot::category)
            .thenComparing(BookmarkSnapshot::comment));
        references.sort(Comparator.comparing(ReferenceSnapshot::from)
            .thenComparingInt(ReferenceSnapshot::operandIndex)
            .thenComparing(ReferenceSnapshot::to)
            .thenComparing(reference -> reference.source().name()));
        return new AnnotationSnapshot(labels, comments, bookmarks, references);
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
        }
        BookmarkManager bookmarks = program.getBookmarkManager();
        for (BookmarkSnapshot bookmark : annotations.bookmarks()) {
            bookmarks.setBookmark(
                bookmark.address(), bookmark.type(), bookmark.category(), bookmark.comment());
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
            if (symbol != null) {
                if (label.primary() && !symbol.isPrimary()) {
                    symbol.setPrimary();
                }
                if (label.pinned() != symbol.isPinned()) {
                    symbol.setPinned(label.pinned());
                }
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
