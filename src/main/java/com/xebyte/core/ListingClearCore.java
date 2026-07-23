package com.xebyte.core;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

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
import ghidra.util.task.TaskMonitor;

/**
 * Plans complete-code-unit clears without opening a transaction.
 *
 * <p>The caller owns the transaction used by {@link #apply(Program, Plan)} so
 * larger mutations can compose clearing with disassembly or data creation.
 */
class ListingClearCore {

    static final int MAX_PLAN_ENTRIES = 65_536;
    private static final String CLEARED_CODE_UNITS =
        "cleared_code_units";
    private static final String REMOVED_FUNCTIONS =
        "removed_functions";
    private static final String PRESERVED_LABELS =
        "preserved_labels";
    private static final String PRESERVED_COMMENTS =
        "preserved_comments";
    private static final String PRESERVED_BOOKMARKS =
        "preserved_bookmarks";
    private static final String PRESERVED_OUTGOING_REFERENCES =
        "preserved_outgoing_references";
    private static final String REMOVED_LABELS =
        "removed_labels";
    private static final String REMOVED_COMMENTS =
        "removed_comments";
    private static final String REMOVED_BOOKMARKS =
        "removed_bookmarks";
    private static final String REMOVED_OUTGOING_REFERENCES =
        "removed_outgoing_references";
    static final List<String> PLAN_CATEGORIES = List.of(
        CLEARED_CODE_UNITS,
        REMOVED_FUNCTIONS,
        PRESERVED_LABELS,
        PRESERVED_COMMENTS,
        PRESERVED_BOOKMARKS,
        PRESERVED_OUTGOING_REFERENCES,
        REMOVED_LABELS,
        REMOVED_COMMENTS,
        REMOVED_BOOKMARKS,
        REMOVED_OUTGOING_REFERENCES);

    static final class PlanLimitException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        private final String category;
        private final int countAtLeast;

        PlanLimitException(String category, int countAtLeast) {
            super("listing clear category '" + category
                + "' exceeds maximum of " + MAX_PLAN_ENTRIES
                + " entries (count at least " + countAtLeast + ")");
            this.category = category;
            this.countAtLeast = countAtLeast;
        }

        String category() {
            return category;
        }

        int countAtLeast() {
            return countAtLeast;
        }
    }

    @FunctionalInterface
    interface AnnotationRestorer {
        void restore(
            Program program, AnnotationSnapshot annotations,
            TaskMonitor monitor) throws Exception;
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

    private enum VisitState {
        VISITING,
        VISITED
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
        try {
            return planInternal(
                program, requested, selection, preservation,
                TaskMonitor.DUMMY, false);
        }
        catch (RuntimeException error) {
            throw error;
        }
        catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    Plan plan(
            Program program,
            AddressSetView requested,
            Selection selection,
            Preservation preservation,
            TaskMonitor monitor) throws Exception {
        return planInternal(
            program, requested, selection, preservation,
            monitor, true);
    }

    private Plan planInternal(
            Program program,
            AddressSetView requested,
            Selection selection,
            Preservation preservation,
            TaskMonitor monitor,
            boolean bounded) throws Exception {
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
        TaskMonitor taskMonitor =
            monitor == null ? TaskMonitor.DUMMY : monitor;
        taskMonitor.checkCancelled();

        Listing listing = program.getListing();
        Map<Address, CodeUnit> intersecting = new LinkedHashMap<>();
        Set<Address> selectedUnitStarts = new LinkedHashSet<>();
        for (AddressRange range : requested) {
            taskMonitor.checkCancelled();
            addUnit(
                intersecting,
                selectedUnitStarts,
                definedUnitContaining(
                    listing, range.getMinAddress()),
                selection,
                bounded);
            AddressSet requestedRange =
                new AddressSet(range.getMinAddress(), range.getMaxAddress());
            InstructionIterator instructions =
                listing.getInstructions(requestedRange, true);
            while (instructions.hasNext()) {
                taskMonitor.checkCancelled();
                addUnit(
                    intersecting,
                    selectedUnitStarts,
                    instructions.next(),
                    selection,
                    bounded);
            }
            DataIterator data =
                listing.getDefinedData(requestedRange, true);
            while (data.hasNext()) {
                taskMonitor.checkCancelled();
                addUnit(
                    intersecting,
                    selectedUnitStarts,
                    data.next(),
                    selection,
                    bounded);
            }
            addUnit(
                intersecting,
                selectedUnitStarts,
                definedUnitContaining(
                    listing, range.getMaxAddress()),
                selection,
                bounded);
        }
        if (selection.clearInstructions()) {
            expandDelaySlotGroups(
                listing, intersecting, selectedUnitStarts,
                selection, bounded, taskMonitor);
        }

        List<CodeUnitSnapshot> units = new ArrayList<>();
        for (CodeUnit unit : intersecting.values()) {
            taskMonitor.checkCancelled();
            if (isSelected(unit, selection)) {
                addPlanned(
                    units, snapshot(unit), CLEARED_CODE_UNITS,
                    bounded);
            }
        }
        units.sort(Comparator.comparing(CodeUnitSnapshot::start)
            .thenComparing(CodeUnitSnapshot::end)
            .thenComparing(unit -> unit.kind().name()));

        AddressSet expanded = new AddressSet();
        for (CodeUnitSnapshot unit : units) {
            taskMonitor.checkCancelled();
            expanded.add(unit.start(), unit.end());
        }

        List<FunctionSnapshot> functions = new ArrayList<>();
        List<Function> intersectingFunctions = new ArrayList<>();
        List<String> conflicts = new ArrayList<>();
        AddressSet selectedInstructions = new AddressSet();
        for (CodeUnitSnapshot unit : units) {
            taskMonitor.checkCancelled();
            if (unit.kind() == UnitKind.INSTRUCTION) {
                selectedInstructions.add(unit.start(), unit.end());
            }
        }
        if (!selectedInstructions.isEmpty()) {
            Iterator<Function> iterator =
                program.getFunctionManager().getFunctionsOverlapping(selectedInstructions);
            while (iterator.hasNext()) {
                taskMonitor.checkCancelled();
                Function function = iterator.next();
                FunctionSnapshot snapshot =
                    new FunctionSnapshot(function.getEntryPoint(), function.getName());
                addPlanned(
                    functions, snapshot, REMOVED_FUNCTIONS,
                    bounded);
                intersectingFunctions.add(function);
                if (!selection.removeIntersectingFunctions()) {
                    conflicts.add("instruction intersects function " + function.getName() +
                        " at " + function.getEntryPoint());
                }
            }
        }
        if (!selection.removeIntersectingFunctions()) {
            functions = List.of();
        }
        else {
            FunctionRemovalOrder removalOrder =
                orderFunctionRemovals(
                    intersectingFunctions, taskMonitor);
            functions = removalOrder.functions();
            conflicts.addAll(removalOrder.conflicts());
            conflicts.addAll(preflightFunctionRemoval(
                program,
                intersectingFunctions,
                functions.stream()
                    .map(FunctionSnapshot::entry)
                    .collect(java.util.stream.Collectors.toSet()),
                expanded,
                preservation,
                taskMonitor));
        }
        conflicts.sort(String::compareTo);

        AnnotationPartition annotationPartition =
            partitionAnnotations(
                program, expanded, preservation, taskMonitor,
                bounded);
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

    static Plan emptyPlan() {
        AnnotationSnapshot empty =
            new AnnotationSnapshot(List.of(), List.of(), List.of(), List.of());
        return new Plan(
            new AddressSet(),
            List.of(),
            List.of(),
            empty,
            empty,
            Map.of(),
            new RemovalCounts(0, 0, 0),
            List.of());
    }

    private static void addUnit(
            Map<Address, CodeUnit> units,
            Set<Address> selectedStarts,
            CodeUnit unit,
            Selection selection,
            boolean bounded) {
        if (unit == null
                || units.containsKey(unit.getMinAddress())) {
            return;
        }
        if (isSelected(unit, selection)) {
            if (bounded
                    && selectedStarts.size()
                        >= MAX_PLAN_ENTRIES) {
                throw new PlanLimitException(
                    CLEARED_CODE_UNITS,
                    MAX_PLAN_ENTRIES + 1);
            }
            selectedStarts.add(unit.getMinAddress());
        }
        units.put(unit.getMinAddress(), unit);
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
            Map<Address, CodeUnit> intersecting,
            Set<Address> selectedStarts,
            Selection selection,
            boolean bounded,
            TaskMonitor monitor) throws Exception {
        List<Instruction> selectedInstructions = intersecting.values()
            .stream()
            .filter(Instruction.class::isInstance)
            .map(Instruction.class::cast)
            .toList();
        for (Instruction selected : selectedInstructions) {
            monitor.checkCancelled();
            Instruction root = selected;
            while (root.isInDelaySlot()) {
                monitor.checkCancelled();
                Instruction instruction =
                    listing.getInstructionBefore(root.getMinAddress());
                if (instruction == null) {
                    break;
                }
                root = instruction;
                addUnit(
                    intersecting, selectedStarts, root,
                    selection, bounded);
            }

            boolean followDelaySlots =
                root.getPrototype() != null && root.getPrototype().hasDelaySlots();
            Instruction current = root;
            while (followDelaySlots || current.isInDelaySlot()) {
                monitor.checkCancelled();
                Instruction instruction =
                    listing.getInstructionAfter(current.getMaxAddress());
                if (instruction == null || !instruction.isInDelaySlot()) {
                    break;
                }
                addUnit(
                    intersecting, selectedStarts, instruction,
                    selection, bounded);
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
        apply(program, plan, TaskMonitor.DUMMY);
    }

    void apply(
            Program program, Plan plan, TaskMonitor monitor)
            throws Exception {
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
        TaskMonitor taskMonitor =
            monitor == null ? TaskMonitor.DUMMY : monitor;
        taskMonitor.checkCancelled();

        for (FunctionSnapshot function : plan.functions()) {
            taskMonitor.checkCancelled();
            if (!program.getFunctionManager().removeFunction(function.entry())) {
                throw new IllegalStateException(
                    "failed to remove function " + function.name() +
                        " at " + function.entry());
            }
        }
        removePlannedLabels(
            program, plan.removedAnnotations().labels(), taskMonitor);
        removePlannedComments(
            program, plan.removedAnnotations().comments(), taskMonitor);
        removePlannedBookmarks(
            program, plan.removedAnnotations().bookmarks(), taskMonitor);
        removeOutgoingReferences(program, plan.expanded(), taskMonitor);
        for (CodeUnitSnapshot unit : plan.units()) {
            taskMonitor.checkCancelled();
            program.getListing().clearCodeUnits(unit.start(), unit.end(), false);
        }
        taskMonitor.checkCancelled();
        annotationRestorer.restore(
            program, plan.annotations(), taskMonitor);
    }

    /**
     * Verifies the exact postconditions promised by a clear plan. The caller
     * owns the transaction, so any failure can roll the complete composite
     * mutation back.
     */
    void verify(
            Program program, Plan plan, TaskMonitor monitor)
            throws Exception {
        if (program == null) {
            throw new IllegalArgumentException("program is required");
        }
        if (plan == null) {
            throw new IllegalArgumentException("plan is required");
        }
        TaskMonitor taskMonitor =
            monitor == null ? TaskMonitor.DUMMY : monitor;
        Listing listing = program.getListing();
        for (CodeUnitSnapshot unit : plan.units()) {
            taskMonitor.checkCancelled();
            AddressSet range =
                new AddressSet(unit.start(), unit.end());
            if (definedUnitContaining(listing, unit.start()) != null
                    || definedUnitContaining(listing, unit.end()) != null
                    || listing.getInstructions(range, true).hasNext()
                    || listing.getDefinedData(range, true).hasNext()) {
                throw new IllegalStateException(
                    "listing clear verification found a defined code unit in "
                        + unit.start() + ".." + unit.end());
            }
        }
        for (FunctionSnapshot function : plan.functions()) {
            taskMonitor.checkCancelled();
            if (program.getFunctionManager().getFunctionAt(
                    function.entry()) != null) {
                throw new IllegalStateException(
                    "listing clear verification found function "
                        + function.name() + " at " + function.entry());
            }
        }
        verifyLabels(
            program, plan.annotations().labels(), true, taskMonitor);
        verifyComments(
            program, plan.annotations().comments(), true, taskMonitor);
        verifyBookmarks(
            program, plan.annotations().bookmarks(), true, taskMonitor);
        verifyReferences(
            program, plan.annotations().references(), true, taskMonitor);
        verifyLabels(
            program, plan.removedAnnotations().labels(), false,
            taskMonitor);
        verifyComments(
            program, plan.removedAnnotations().comments(), false,
            taskMonitor);
        verifyBookmarks(
            program, plan.removedAnnotations().bookmarks(), false,
            taskMonitor);
        verifyReferences(
            program, plan.removedAnnotations().references(), false,
            taskMonitor);
        taskMonitor.checkCancelled();
    }

    void verify(Program program, Plan plan) throws Exception {
        verify(program, plan, TaskMonitor.DUMMY);
    }

    private record AnnotationPartition(
            AnnotationSnapshot preserved,
            AnnotationSnapshot removed) {
    }

    private record FunctionRemovalOrder(
            List<FunctionSnapshot> functions,
            List<String> conflicts) {
    }

    static <T> void addBounded(
            List<T> destination, T value, String category) {
        addPlanned(destination, value, category, true);
    }

    private static <T> void addPlanned(
            List<T> destination, T value, String category,
            boolean bounded) {
        if (bounded
                && destination.size() >= MAX_PLAN_ENTRIES) {
            throw new PlanLimitException(
                category, MAX_PLAN_ENTRIES + 1);
        }
        destination.add(value);
    }

    private static FunctionRemovalOrder orderFunctionRemovals(
            List<Function> functions,
            TaskMonitor monitor) throws Exception {
        Map<Address, Function> selectedByEntry = new LinkedHashMap<>();
        functions.stream()
            .sorted(Comparator.comparing(Function::getEntryPoint))
            .forEach(function ->
                selectedByEntry.put(function.getEntryPoint(), function));
        Map<Address, VisitState> states = new HashMap<>();
        List<FunctionSnapshot> ordered = new ArrayList<>();
        Set<String> conflicts = new LinkedHashSet<>();
        for (Function function : selectedByEntry.values()) {
            monitor.checkCancelled();
            visitFunctionForRemoval(
                function, selectedByEntry, states, ordered, conflicts,
                monitor);
        }
        return new FunctionRemovalOrder(
            List.copyOf(ordered), List.copyOf(conflicts));
    }

    private static void visitFunctionForRemoval(
            Function function,
            Map<Address, Function> selectedByEntry,
            Map<Address, VisitState> states,
            List<FunctionSnapshot> ordered,
            Set<String> conflicts,
            TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        Address entry = function.getEntryPoint();
        VisitState state = states.get(entry);
        if (state == VisitState.VISITED) {
            return;
        }
        if (state == VisitState.VISITING) {
            conflicts.add(
                "cycle detected among selected direct thunks at " + entry);
            return;
        }

        states.put(entry, VisitState.VISITING);
        Address[] directThunkAddresses =
            function.getFunctionThunkAddresses(false);
        if (directThunkAddresses != null) {
            List<Address> sortedThunks =
                new ArrayList<>(List.of(directThunkAddresses));
            sortedThunks.sort(Address::compareTo);
            for (Address thunkAddress : sortedThunks) {
                Function selectedThunk = selectedByEntry.get(thunkAddress);
                if (selectedThunk != null) {
                    visitFunctionForRemoval(
                        selectedThunk,
                        selectedByEntry,
                        states,
                        ordered,
                        conflicts,
                        monitor);
                }
            }
        }
        states.put(entry, VisitState.VISITED);
        ordered.add(new FunctionSnapshot(entry, function.getName()));
    }

    private static List<String> preflightFunctionRemoval(
            Program program,
            List<Function> functions,
            Set<Address> selectedFunctionEntries,
            AddressSetView expanded,
            Preservation preservation,
            TaskMonitor monitor) throws Exception {
        SymbolTable symbolTable = program.getSymbolTable();
        ReferenceManager referenceManager = program.getReferenceManager();
        Set<String> conflicts = new LinkedHashSet<>();

        for (Function function : functions) {
            monitor.checkCancelled();
            Address[] directThunkAddresses =
                function.getFunctionThunkAddresses(false);
            if (directThunkAddresses != null) {
                for (Address thunkAddress : directThunkAddresses) {
                    monitor.checkCancelled();
                    if (!selectedFunctionEntries.contains(thunkAddress)) {
                        conflicts.add(
                            "removing function " + function.getName() + " at "
                                + function.getEntryPoint()
                                + " would also remove direct thunk at "
                                + thunkAddress
                                + " outside the explicit function removal set");
                    }
                }
            }

            Symbol functionSymbol = function.getSymbol();
            if (functionSymbol != null) {
                for (Symbol child :
                        descendantSymbols(
                            symbolTable, functionSymbol, monitor)) {
                    monitor.checkCancelled();
                    if (child.isDynamic()
                            || child.getSymbolType() != SymbolType.LABEL) {
                        continue;
                    }
                    Address address = child.getAddress();
                    boolean outside = address == null || !expanded.contains(address);
                    boolean selectedForPreservation =
                        preservation.labels()
                            && isPreservedSource(child.getSource());
                    if (outside || selectedForPreservation) {
                        conflicts.add(
                            "removing function " + function.getName() + " at "
                                + function.getEntryPoint()
                                + " would destroy function-local label "
                                + child.getName() + " at " + address
                                + (outside
                                    ? " outside the affected range"
                                    : " selected for exact preservation"));
                    }
                }
            }

            AddressSetView body = function.getBody();
            if (body == null || body.isEmpty()) {
                continue;
            }
            var sources =
                referenceManager.getReferenceSourceIterator(body, true);
            if (sources == null) {
                continue;
            }
            while (sources.hasNext()) {
                monitor.checkCancelled();
                Address from = sources.next();
                Reference[] references = referenceManager.getReferencesFrom(from);
                if (references == null) {
                    continue;
                }
                for (Reference reference : references) {
                    monitor.checkCancelled();
                    boolean outside = !expanded.contains(from);
                    boolean preservationRequired = outside
                        || preservation.userReferences()
                            && isPreservedSource(reference.getSource());
                    Symbol associated = symbolTable.getSymbol(reference);
                    boolean associationWouldBeLost =
                        isFunctionOwned(associated, function)
                            && preservationRequired;
                    if (associationWouldBeLost) {
                        conflicts.add(
                            "removing function " + function.getName() + " at "
                                + function.getEntryPoint()
                                + " would destroy the function-variable association "
                                + associated.getName() + " for reference from "
                                + from + " operand " + reference.getOperandIndex()
                                + (outside
                                    ? " outside the affected range"
                                    : " selected for exact preservation"));
                    }
                    if (outside && (reference.isStackReference()
                            || reference.isRegisterReference())
                            && !associationWouldBeLost) {
                        conflicts.add(
                            "removing function " + function.getName() + " at "
                                + function.getEntryPoint()
                                + " would destroy "
                                + (reference.isStackReference()
                                    ? "stack" : "register")
                                + " reference from " + from + " operand "
                                + reference.getOperandIndex()
                                + " outside the affected range");
                    }
                }
            }
        }
        return List.copyOf(conflicts);
    }

    private static List<Symbol> descendantSymbols(
            SymbolTable symbolTable, Symbol root,
            TaskMonitor monitor) throws Exception {
        List<Symbol> descendants = new ArrayList<>();
        Deque<Symbol> pending = new ArrayDeque<>();
        Set<Symbol> visited =
            Collections.newSetFromMap(new IdentityHashMap<>());
        pending.add(root);
        visited.add(root);
        while (!pending.isEmpty()) {
            monitor.checkCancelled();
            var children = symbolTable.getChildren(pending.removeFirst());
            if (children == null) {
                continue;
            }
            while (children.hasNext()) {
                monitor.checkCancelled();
                Symbol child = children.next();
                if (child != null && visited.add(child)) {
                    descendants.add(child);
                    pending.addLast(child);
                }
            }
        }
        return descendants;
    }

    private static boolean isFunctionOwned(
            Symbol symbol, Function function) {
        if (symbol == null) {
            return false;
        }
        return Objects.equals(symbol.getParentNamespace(), function)
            || symbol.isDescendant(function);
    }

    private static AnnotationPartition partitionAnnotations(
            Program program,
            AddressSetView expanded,
            Preservation preservation,
            TaskMonitor monitor,
            boolean bounded) throws Exception {
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

        var symbols = symbolTable.getSymbols(
            expanded, SymbolType.LABEL, true);
        if (symbols != null) {
            while (symbols.hasNext()) {
                monitor.checkCancelled();
                Symbol symbol = symbols.next();
                // Dynamic symbols are projections of surviving references, not
                // owned annotations. They may disappear and reappear as Ghidra
                // recomputes them, so neither preservation nor removal counts
                // claim them.
                if (symbol == null || symbol.isDynamic()) {
                    continue;
                }
                LabelSnapshot snapshot = new LabelSnapshot(
                    symbol.getAddress(),
                    symbol.getName(),
                    symbol.getParentNamespace(),
                    symbol.getSource(),
                    symbol.getSymbolType(),
                    symbol.isPrimary(),
                    symbol.isPinned());
                if (preservation.labels()
                        && isPreservedSource(symbol.getSource())) {
                    addPlanned(
                        preservedLabels, snapshot,
                        PRESERVED_LABELS, bounded);
                }
                else {
                    addPlanned(
                        removedLabels, snapshot,
                        REMOVED_LABELS, bounded);
                }
            }
        }

        var commentAddresses =
            listing.getCommentAddressIterator(expanded, true);
        if (commentAddresses != null) {
            while (commentAddresses.hasNext()) {
                monitor.checkCancelled();
                Address address = commentAddresses.next();
                for (CommentType type : CommentType.values()) {
                    monitor.checkCancelled();
                    String text = listing.getComment(type, address);
                    if (text != null) {
                        addPlanned(
                            preservation.comments()
                                ? preservedComments
                                : removedComments,
                            new CommentSnapshot(address, type, text),
                            preservation.comments()
                                ? PRESERVED_COMMENTS
                                : REMOVED_COMMENTS,
                            bounded);
                    }
                }
            }
        }

        Iterator<Bookmark> bookmarkIterator =
            bookmarkManager.getBookmarksIterator(
                expanded.getMinAddress(), true);
        if (bookmarkIterator != null) {
            while (bookmarkIterator.hasNext()) {
                monitor.checkCancelled();
                Bookmark bookmark = bookmarkIterator.next();
                Address address = bookmark.getAddress();
                if (address.compareTo(expanded.getMaxAddress()) > 0) {
                    break;
                }
                if (expanded.contains(address)) {
                    addPlanned(
                        preservation.bookmarks()
                            ? preservedBookmarks
                            : removedBookmarks,
                        new BookmarkSnapshot(
                            address,
                            bookmark.getTypeString(),
                            bookmark.getCategory(),
                            bookmark.getComment()),
                        preservation.bookmarks()
                            ? PRESERVED_BOOKMARKS
                            : REMOVED_BOOKMARKS,
                        bounded);
                }
            }
        }

        var referenceSources =
            referenceManager.getReferenceSourceIterator(expanded, true);
        if (referenceSources != null) {
            while (referenceSources.hasNext()) {
                monitor.checkCancelled();
                Address address = referenceSources.next();
                Reference[] fromAddress =
                    referenceManager.getReferencesFrom(address);
                if (fromAddress == null) {
                    continue;
                }
                for (Reference reference : fromAddress) {
                    monitor.checkCancelled();
                    ReferenceSnapshot snapshot = snapshot(reference);
                    if (preservation.userReferences()
                            && isPreservedSource(reference.getSource())) {
                        addPlanned(
                            preservedReferences, snapshot,
                            PRESERVED_OUTGOING_REFERENCES,
                            bounded);
                    }
                    else {
                        addPlanned(
                            removedReferences, snapshot,
                            REMOVED_OUTGOING_REFERENCES,
                            bounded);
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
            Program program, List<LabelSnapshot> labels,
            TaskMonitor monitor) throws Exception {
        SymbolTable table = program.getSymbolTable();
        for (LabelSnapshot snapshot : labels) {
            monitor.checkCancelled();
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
            Program program, List<CommentSnapshot> comments,
            TaskMonitor monitor) throws Exception {
        Listing listing = program.getListing();
        for (CommentSnapshot comment : comments) {
            monitor.checkCancelled();
            listing.setComment(comment.address(), comment.type(), null);
        }
    }

    private static void removePlannedBookmarks(
            Program program, List<BookmarkSnapshot> snapshots,
            TaskMonitor monitor) throws Exception {
        BookmarkManager manager = program.getBookmarkManager();
        for (BookmarkSnapshot snapshot : snapshots) {
            monitor.checkCancelled();
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
            Program program, AddressSetView affected,
            TaskMonitor monitor) throws Exception {
        ReferenceManager manager = program.getReferenceManager();
        for (AddressRange range : affected) {
            monitor.checkCancelled();
            manager.removeAllReferencesFrom(
                range.getMinAddress(), range.getMaxAddress());
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

    private static void verifyLabels(
            Program program, List<LabelSnapshot> snapshots,
            boolean expectedPresent, TaskMonitor monitor)
            throws Exception {
        SymbolTable table = program.getSymbolTable();
        for (LabelSnapshot snapshot : snapshots) {
            monitor.checkCancelled();
            boolean present = false;
            Symbol[] symbols = table.getSymbols(snapshot.address());
            if (symbols != null) {
                for (Symbol symbol : symbols) {
                    monitor.checkCancelled();
                    if (!symbol.isDynamic()
                            && symbol.getSymbolType()
                                == snapshot.symbolType()
                            && snapshot.name().equals(symbol.getName())
                            && snapshot.source() == symbol.getSource()
                            && Objects.equals(
                                snapshot.namespace(),
                                symbol.getParentNamespace())
                            && snapshot.primary() == symbol.isPrimary()
                            && snapshot.pinned() == symbol.isPinned()) {
                        present = true;
                        break;
                    }
                }
            }
            requirePresence(
                "label " + snapshot.name() + " at "
                    + snapshot.address(),
                expectedPresent,
                present);
        }
    }

    private static void verifyComments(
            Program program, List<CommentSnapshot> snapshots,
            boolean expectedPresent, TaskMonitor monitor)
            throws Exception {
        Listing listing = program.getListing();
        for (CommentSnapshot snapshot : snapshots) {
            monitor.checkCancelled();
            boolean present = Objects.equals(
                snapshot.text(),
                listing.getComment(
                    snapshot.type(), snapshot.address()));
            requirePresence(
                snapshot.type() + " comment at "
                    + snapshot.address(),
                expectedPresent,
                present);
        }
    }

    private static void verifyBookmarks(
            Program program, List<BookmarkSnapshot> snapshots,
            boolean expectedPresent, TaskMonitor monitor)
            throws Exception {
        BookmarkManager manager = program.getBookmarkManager();
        for (BookmarkSnapshot snapshot : snapshots) {
            monitor.checkCancelled();
            boolean present = false;
            Bookmark[] bookmarks =
                manager.getBookmarks(snapshot.address());
            if (bookmarks != null) {
                for (Bookmark bookmark : bookmarks) {
                    monitor.checkCancelled();
                    if (Objects.equals(
                            snapshot.type(),
                            bookmark.getTypeString())
                            && Objects.equals(
                                snapshot.category(),
                                bookmark.getCategory())
                            && Objects.equals(
                                snapshot.comment(),
                                bookmark.getComment())) {
                        present = true;
                        break;
                    }
                }
            }
            requirePresence(
                "bookmark at " + snapshot.address(),
                expectedPresent,
                present);
        }
    }

    private static void verifyReferences(
            Program program, List<ReferenceSnapshot> snapshots,
            boolean expectedPresent, TaskMonitor monitor)
            throws Exception {
        ReferenceManager manager =
            program.getReferenceManager();
        for (ReferenceSnapshot expected : snapshots) {
            monitor.checkCancelled();
            boolean present = false;
            Reference[] references =
                manager.getReferencesFrom(expected.from());
            if (references != null) {
                for (Reference reference : references) {
                    monitor.checkCancelled();
                    if (expected.equals(snapshot(reference))) {
                        present = true;
                        break;
                    }
                }
            }
            requirePresence(
                "reference from " + expected.from()
                    + " operand " + expected.operandIndex()
                    + " to " + expected.to(),
                expectedPresent,
                present);
        }
    }

    private static void requirePresence(
            String identity, boolean expectedPresent,
            boolean present) {
        if (present != expectedPresent) {
            throw new IllegalStateException(
                "listing clear verification "
                    + (expectedPresent
                        ? "did not preserve " : "did not remove ")
                    + identity);
        }
    }

    private static void restoreAnnotations(
            Program program,
            AnnotationSnapshot annotations,
            TaskMonitor monitor) throws Exception {
        restoreLabels(program, annotations.labels(), monitor);
        Listing listing = program.getListing();
        for (CommentSnapshot comment : annotations.comments()) {
            monitor.checkCancelled();
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
            monitor.checkCancelled();
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
        restoreReferences(program, annotations.references(), monitor);
    }

    private static void restoreLabels(
            Program program, List<LabelSnapshot> labels,
            TaskMonitor monitor)
            throws Exception {
        SymbolTable table = program.getSymbolTable();
        for (LabelSnapshot label : labels) {
            monitor.checkCancelled();
            Namespace namespace = label.namespace();
            if (namespace == null) {
                throw new IllegalStateException(
                    "cannot restore label " + label.name() + " at "
                        + label.address() + " without its exact namespace");
            }
            if (namespace instanceof Function function && function.isDeleted()) {
                throw new IllegalStateException(
                    "cannot restore label " + label.name() + " at "
                        + label.address() + " because its function namespace "
                        + function.getName() + " was removed");
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
            List<ReferenceSnapshot> references,
            TaskMonitor monitor) throws Exception {
        ReferenceManager manager = program.getReferenceManager();
        for (ReferenceSnapshot snapshot : references) {
            monitor.checkCancelled();
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
