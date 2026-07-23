package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.junit.Test;
import org.mockito.InOrder;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

public class ListingClearCoreTest {

    private static final GenericAddressSpace RAM =
        new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0);

    @Test
    public void partialUnitSelectionExpandsToCompleteInstruction() {
        Address start = RAM.getAddress(0x1000);
        Address middle = RAM.getAddress(0x1001);
        Address end = RAM.getAddress(0x1002);

        Instruction instruction = mock(Instruction.class);
        when(instruction.getMinAddress()).thenReturn(start);
        when(instruction.getMaxAddress()).thenReturn(end);

        Listing listing = mock(Listing.class);
        when(listing.getInstructions(
            org.mockito.ArgumentMatchers.any(AddressSetView.class),
            org.mockito.ArgumentMatchers.eq(true)))
            .thenReturn(instructionIterator(Collections.emptyIterator()));
        when(listing.getDefinedData(
            org.mockito.ArgumentMatchers.any(AddressSetView.class),
            org.mockito.ArgumentMatchers.eq(true)))
            .thenReturn(dataIterator(Collections.emptyIterator()));
        when(listing.getInstructionContaining(middle)).thenReturn(instruction);

        FunctionManager functions = mock(FunctionManager.class);
        when(functions.getFunctionsOverlapping(org.mockito.ArgumentMatchers.any()))
            .thenReturn(Collections.<Function>emptyIterator());

        Program program = mock(Program.class);
        when(program.getListing()).thenReturn(listing);
        when(program.getFunctionManager()).thenReturn(functions);
        when(program.getSymbolTable()).thenReturn(mock(SymbolTable.class));
        when(program.getReferenceManager()).thenReturn(mock(ReferenceManager.class));
        when(program.getBookmarkManager()).thenReturn(mock(BookmarkManager.class));

        ListingClearCore.Plan plan = new ListingClearCore().plan(
            program,
            new AddressSet(middle, middle),
            new ListingClearCore.Selection(true, false, false),
            new ListingClearCore.Preservation(false, false, false, false));

        assertTrue(plan.expanded().contains(start, end));
        assertEquals(1, plan.units().size());
        assertEquals(ListingClearCore.UnitKind.INSTRUCTION, plan.units().get(0).kind());
    }

    @Test
    public void delaySlotSelectionIncludesTheInstructionGhidraWillAlsoClear() {
        Address rootStart = RAM.getAddress(0x1010);
        Address rootEnd = RAM.getAddress(0x1011);
        Address slotStart = RAM.getAddress(0x1012);
        Address slotEnd = RAM.getAddress(0x1013);
        Instruction root = unit(Instruction.class, rootStart, rootEnd);
        Instruction slot = unit(Instruction.class, slotStart, slotEnd);
        InstructionPrototype prototype = mock(InstructionPrototype.class);
        when(prototype.hasDelaySlots()).thenReturn(true);
        when(root.getPrototype()).thenReturn(prototype);
        when(slot.isInDelaySlot()).thenReturn(true);
        Fixture fixture = fixture(List.of(root, slot));
        when(fixture.listing().getInstructionBefore(slotStart)).thenReturn(root);
        when(fixture.listing().getInstructionAfter(rootEnd)).thenReturn(slot);

        ListingClearCore.Plan plan = new ListingClearCore().plan(
            fixture.program(),
            new AddressSet(slotStart, slotEnd),
            new ListingClearCore.Selection(true, false, false),
            new ListingClearCore.Preservation(false, false, false, false));

        assertEquals(List.of(rootStart, slotStart),
            plan.units().stream().map(ListingClearCore.CodeUnitSnapshot::start).toList());
        assertTrue(plan.expanded().contains(rootStart, slotEnd));
    }

    @Test
    public void planSelectsRequestedKindsAndLeavesNoOpBytesUnchanged() {
        Address instructionStart = RAM.getAddress(0x1000);
        Address instructionEnd = RAM.getAddress(0x1001);
        Address dataStart = RAM.getAddress(0x1002);
        Address dataEnd = RAM.getAddress(0x1004);

        Instruction instruction = unit(Instruction.class, instructionStart, instructionEnd);
        Data data = unit(Data.class, dataStart, dataEnd);
        Fixture fixture = fixture(List.of(instruction, data));

        ListingClearCore.Plan plan = new ListingClearCore().plan(
            fixture.program(),
            new AddressSet(instructionStart, dataEnd),
            new ListingClearCore.Selection(false, true, false),
            new ListingClearCore.Preservation(false, false, false, false));

        assertEquals(List.of(new ListingClearCore.CodeUnitSnapshot(
            dataStart, dataEnd, ListingClearCore.UnitKind.DATA)), plan.units());
        assertEquals(new ListingClearCore.RemovalCounts(0, 1, 0), plan.removalCounts());
        assertFalse(plan.expanded().contains(instructionStart));
        assertTrue(plan.expanded().contains(dataStart, dataEnd));
    }

    @Test
    public void whollyUndefinedBytesAreANoOpWithoutSynthesizedDataUnits() {
        Address start = RAM.getAddress(0x1080);
        Address end = RAM.getAddress(0x10ff);
        Fixture fixture = fixture(List.of());

        ListingClearCore.Plan plan = new ListingClearCore().plan(
            fixture.program(),
            new AddressSet(start, end),
            new ListingClearCore.Selection(true, true, false),
            ListingClearCore.Preservation.defaults());

        assertTrue(plan.units().isEmpty());
        assertTrue(plan.expanded().isEmpty());
        assertEquals(new ListingClearCore.RemovalCounts(0, 0, 0),
            plan.removalCounts());
        assertTrue(plan.annotations().labels().isEmpty());
        assertTrue(plan.removedAnnotations().references().isEmpty());
        verify(fixture.listing(), never()).getCodeUnits(
            any(AddressSetView.class), eq(true));
    }

    @Test
    public void instructionInFunctionIsConflictUnlessRemovalWasSelected() {
        Address start = RAM.getAddress(0x1100);
        Address end = RAM.getAddress(0x1101);
        Instruction instruction = unit(Instruction.class, start, end);
        Fixture fixture = fixture(List.of(instruction));

        Function function = mock(Function.class);
        when(function.getEntryPoint()).thenReturn(start);
        when(function.getName()).thenReturn("routine");
        when(fixture.functions().getFunctionsOverlapping(any(AddressSetView.class)))
            .thenReturn(List.of(function).iterator());

        ListingClearCore.Plan refused = new ListingClearCore().plan(
            fixture.program(), new AddressSet(start, end),
            new ListingClearCore.Selection(true, false, false),
            new ListingClearCore.Preservation(false, false, false, false));
        assertEquals(1, refused.conflicts().size());
        assertTrue(refused.functions().isEmpty());

        when(fixture.functions().getFunctionsOverlapping(any(AddressSetView.class)))
            .thenReturn(List.of(function).iterator());
        ListingClearCore.Plan allowed = new ListingClearCore().plan(
            fixture.program(), new AddressSet(start, end),
            new ListingClearCore.Selection(true, false, true),
            new ListingClearCore.Preservation(false, false, false, false));
        assertTrue(allowed.conflicts().isEmpty());
        assertEquals(List.of(new ListingClearCore.FunctionSnapshot(start, "routine")),
            allowed.functions());
    }

    @Test
    public void capturesOnlyPreservedSourcesAndAllCommentAndBookmarkTypes() {
        Address start = RAM.getAddress(0x1200);
        Address end = RAM.getAddress(0x1200);
        Address target = RAM.getAddress(0x1300);
        Data data = unit(Data.class, start, end);
        Fixture fixture = fixture(List.of(data));

        Symbol user = symbol("user_label", start, SourceType.USER_DEFINED);
        Symbol imported = symbol("imported_label", start, SourceType.IMPORTED);
        Symbol analysis = symbol("analysis_label", start, SourceType.ANALYSIS);
        when(fixture.symbols().getSymbols(start))
            .thenReturn(new Symbol[] { analysis, imported, user });

        for (CommentType type : CommentType.values()) {
            when(fixture.listing().getComment(type, start))
                .thenReturn(type.name().toLowerCase() + " comment");
        }

        Bookmark bookmark = mock(Bookmark.class);
        when(bookmark.getAddress()).thenReturn(start);
        when(bookmark.getTypeString()).thenReturn("NOTE");
        when(bookmark.getCategory()).thenReturn("review");
        when(bookmark.getComment()).thenReturn("keep");
        when(fixture.bookmarks().getBookmarks(start)).thenReturn(new Bookmark[] { bookmark });

        Reference userReference =
            reference(start, target, SourceType.USER_DEFINED, RefType.DATA);
        Reference importedReference =
            reference(start, target.next(), SourceType.IMPORTED, RefType.READ);
        Reference analysisReference =
            reference(start, target.next().next(), SourceType.ANALYSIS, RefType.WRITE);
        when(fixture.references().getReferencesFrom(start))
            .thenReturn(new Reference[] { analysisReference, importedReference, userReference });

        ListingClearCore.Plan plan = new ListingClearCore().plan(
            fixture.program(), new AddressSet(start, end),
            new ListingClearCore.Selection(false, true, false),
            ListingClearCore.Preservation.defaults());

        assertEquals(List.of("imported_label", "user_label"),
            plan.annotations().labels().stream()
                .map(ListingClearCore.LabelSnapshot::name)
                .toList());
        assertEquals(CommentType.values().length, plan.annotations().comments().size());
        assertEquals(1, plan.annotations().bookmarks().size());
        assertEquals(List.of(SourceType.USER_DEFINED, SourceType.IMPORTED),
            plan.annotations().references().stream()
                .map(ListingClearCore.ReferenceSnapshot::source)
                .toList());
        verify(fixture.references(), never()).getReferencesTo(any(Address.class));
    }

    @Test
    public void partitionsEveryAnnotationSourceIntoPreservedAndRemovedPlans() {
        Address start = RAM.getAddress(0x1320);
        Address target = RAM.getAddress(0x1380);
        Fixture fixture = fixture(List.of(unit(Data.class, start, start)));

        Symbol user = symbol("user_label", start, SourceType.USER_DEFINED);
        Symbol imported = symbol("imported_label", start, SourceType.IMPORTED);
        Symbol analysis = symbol("analysis_label", start, SourceType.ANALYSIS);
        Symbol defaultSymbol = symbol("default_label", start, SourceType.DEFAULT);
        Symbol dynamic = symbol("dynamic_label", start, SourceType.DEFAULT);
        when(dynamic.isDynamic()).thenReturn(true);
        when(fixture.symbols().getSymbols(start))
            .thenReturn(new Symbol[] { user, imported, analysis, defaultSymbol, dynamic });
        when(fixture.listing().getComment(CommentType.EOL, start)).thenReturn("comment");
        Bookmark bookmark = mock(Bookmark.class);
        when(bookmark.getTypeString()).thenReturn("NOTE");
        when(bookmark.getCategory()).thenReturn("review");
        when(bookmark.getComment()).thenReturn("bookmark");
        when(fixture.bookmarks().getBookmarks(start)).thenReturn(new Bookmark[] { bookmark });
        Reference userReference =
            reference(start, target, SourceType.USER_DEFINED, RefType.DATA);
        Reference importedReference =
            reference(start, target.next(), SourceType.IMPORTED, RefType.READ);
        Reference analysisReference =
            reference(start, target.next().next(), SourceType.ANALYSIS, RefType.WRITE);
        Reference defaultReference =
            reference(start, target.next().next().next(), SourceType.DEFAULT, RefType.FLOW);
        when(fixture.references().getReferencesFrom(start)).thenReturn(
            new Reference[] {
                defaultReference, analysisReference, importedReference, userReference
            });

        ListingClearCore.Plan preserved = new ListingClearCore().plan(
            fixture.program(), new AddressSet(start, start),
            new ListingClearCore.Selection(false, true, false),
            ListingClearCore.Preservation.defaults());

        assertEquals(
            List.of(SourceType.IMPORTED, SourceType.USER_DEFINED),
            preserved.annotations().labels().stream()
                .map(ListingClearCore.LabelSnapshot::source).toList());
        assertEquals(
            List.of(SourceType.ANALYSIS, SourceType.DEFAULT),
            preserved.removedAnnotations().labels().stream()
                .map(ListingClearCore.LabelSnapshot::source).toList());
        assertEquals(
            List.of(SourceType.USER_DEFINED, SourceType.IMPORTED),
            preserved.annotations().references().stream()
                .map(ListingClearCore.ReferenceSnapshot::source).toList());
        assertEquals(
            List.of(SourceType.ANALYSIS, SourceType.DEFAULT),
            preserved.removedAnnotations().references().stream()
                .map(ListingClearCore.ReferenceSnapshot::source).toList());
        assertEquals(1, preserved.annotations().comments().size());
        assertEquals(0, preserved.removedAnnotations().comments().size());
        assertEquals(1, preserved.annotations().bookmarks().size());
        assertEquals(0, preserved.removedAnnotations().bookmarks().size());

        ListingClearCore.Plan removeAll = new ListingClearCore().plan(
            fixture.program(), new AddressSet(start, start),
            new ListingClearCore.Selection(false, true, false),
            new ListingClearCore.Preservation(false, false, false, false));

        assertEquals(0, removeAll.annotations().labels().size());
        assertEquals(4, removeAll.removedAnnotations().labels().size());
        assertEquals(0, removeAll.annotations().comments().size());
        assertEquals(1, removeAll.removedAnnotations().comments().size());
        assertEquals(0, removeAll.annotations().bookmarks().size());
        assertEquals(1, removeAll.removedAnnotations().bookmarks().size());
        assertEquals(0, removeAll.annotations().references().size());
        assertEquals(4, removeAll.removedAnnotations().references().size());
        assertEquals(
            java.util.Map.of(
                SourceType.USER_DEFINED, 1,
                SourceType.IMPORTED, 1,
                SourceType.ANALYSIS, 1,
                SourceType.DEFAULT, 1),
            removeAll.removedReferencesBySource());
    }

    @Test
    public void applyDeletesOnlyPlannedCommentsBookmarksAndOutgoingReferences()
            throws Exception {
        Address start = RAM.getAddress(0x13a0);
        Address target = RAM.getAddress(0x13b0);
        Fixture fixture = fixture(List.of(unit(Data.class, start, start)));
        when(fixture.listing().getComment(CommentType.EOL, start)).thenReturn("remove");
        Bookmark bookmark = mock(Bookmark.class);
        when(bookmark.getTypeString()).thenReturn("NOTE");
        when(bookmark.getCategory()).thenReturn("review");
        when(bookmark.getComment()).thenReturn("remove");
        when(fixture.bookmarks().getBookmarks(start)).thenReturn(new Bookmark[] { bookmark });
        Reference outgoing =
            reference(start, target, SourceType.USER_DEFINED, RefType.DATA);
        when(fixture.references().getReferencesFrom(start))
            .thenReturn(new Reference[] { outgoing });

        ListingClearCore core = new ListingClearCore();
        ListingClearCore.Plan plan = core.plan(
            fixture.program(), new AddressSet(start, start),
            new ListingClearCore.Selection(false, true, false),
            new ListingClearCore.Preservation(true, false, false, false));

        core.apply(fixture.program(), plan);

        verify(fixture.listing()).setComment(start, CommentType.EOL, null);
        verify(fixture.bookmarks()).removeBookmark(bookmark);
        verify(fixture.references()).removeAllReferencesFrom(start);
        verify(fixture.references(), never()).removeAllReferencesTo(any(Address.class));
    }

    @Test
    public void applyRemovesFunctionsClearsUnitsThenRestoresAnnotations() throws Exception {
        Address start = RAM.getAddress(0x1400);
        Address end = RAM.getAddress(0x1401);
        Instruction instruction = unit(Instruction.class, start, end);
        Fixture fixture = fixture(List.of(instruction));

        Function function = mock(Function.class);
        when(function.getEntryPoint()).thenReturn(start);
        when(function.getName()).thenReturn("routine");
        when(fixture.functions().getFunctionsOverlapping(any(AddressSetView.class)))
            .thenReturn(List.of(function).iterator());
        when(fixture.functions().removeFunction(start)).thenReturn(true);

        ListingClearCore core = new ListingClearCore((program, annotations) -> {
            assertTrue(annotations.labels().isEmpty());
            verify(fixture.listing()).clearCodeUnits(start, end, false);
        });
        ListingClearCore.Plan plan = core.plan(
            fixture.program(), new AddressSet(start, end),
            new ListingClearCore.Selection(true, false, true),
            new ListingClearCore.Preservation(false, false, false, false));

        core.apply(fixture.program(), plan);

        InOrder order = inOrder(fixture.functions(), fixture.listing());
        order.verify(fixture.functions()).removeFunction(start);
        order.verify(fixture.listing()).clearCodeUnits(start, end, false);
    }

    @Test
    public void failedFunctionRemovalAbortsBeforeCodeUnitClear() {
        Address start = RAM.getAddress(0x1440);
        Instruction instruction = unit(Instruction.class, start, start);
        Fixture fixture = fixture(List.of(instruction));
        Function function = mock(Function.class);
        when(function.getEntryPoint()).thenReturn(start);
        when(function.getName()).thenReturn("routine");
        when(fixture.functions().getFunctionsOverlapping(any(AddressSetView.class)))
            .thenReturn(List.of(function).iterator());
        when(fixture.functions().removeFunction(start)).thenReturn(false);

        ListingClearCore core = new ListingClearCore();
        ListingClearCore.Plan plan = core.plan(
            fixture.program(), new AddressSet(start, start),
            new ListingClearCore.Selection(true, false, true),
            new ListingClearCore.Preservation(false, false, false, false));

        assertThrows(IllegalStateException.class, () -> core.apply(fixture.program(), plan));
        verify(fixture.listing(), never()).clearCodeUnits(any(), any(), eq(false));
    }

    @Test
    public void defaultRestorerRecreatesCapturedAnnotations() throws Exception {
        Address start = RAM.getAddress(0x1450);
        Address target = RAM.getAddress(0x1460);
        Data data = unit(Data.class, start, start);
        Fixture fixture = fixture(List.of(data));

        Namespace namespace = mock(Namespace.class);
        Symbol user = symbol("user_label", start, SourceType.USER_DEFINED);
        when(user.getParentNamespace()).thenReturn(namespace);
        when(user.isPrimary()).thenReturn(true);
        when(user.isPinned()).thenReturn(true);
        when(fixture.symbols().getSymbols(start)).thenReturn(new Symbol[] { user });

        when(fixture.listing().getComment(CommentType.EOL, start)).thenReturn("comment");
        Bookmark bookmark = mock(Bookmark.class);
        when(bookmark.getTypeString()).thenReturn("NOTE");
        when(bookmark.getCategory()).thenReturn("review");
        when(bookmark.getComment()).thenReturn("keep");
        when(fixture.bookmarks().getBookmarks(start)).thenReturn(new Bookmark[] { bookmark });

        Reference original =
            reference(start, target, SourceType.USER_DEFINED, RefType.DATA);
        when(original.isPrimary()).thenReturn(true);
        when(fixture.references().getReferencesFrom(start))
            .thenReturn(new Reference[] { original });

        Symbol restoredLabel = mock(Symbol.class);
        when(fixture.symbols().getSymbol("user_label", start, namespace)).thenReturn(null);
        when(fixture.symbols().createLabel(
            start, "user_label", namespace, SourceType.USER_DEFINED))
                .thenReturn(restoredLabel);
        Reference restoredReference = mock(Reference.class);
        when(fixture.references().addMemoryReference(
            start, target, RefType.DATA, SourceType.USER_DEFINED, 0))
                .thenReturn(restoredReference);
        when(fixture.bookmarks().setBookmark(
            start, "NOTE", "review", "keep")).thenReturn(bookmark);

        ListingClearCore core = new ListingClearCore();
        ListingClearCore.Plan plan = core.plan(
            fixture.program(), new AddressSet(start, start),
            new ListingClearCore.Selection(false, true, false),
            ListingClearCore.Preservation.defaults());
        core.apply(fixture.program(), plan);

        verify(fixture.symbols()).createLabel(
            start, "user_label", namespace, SourceType.USER_DEFINED);
        verify(restoredLabel).setPrimary();
        verify(restoredLabel).setPinned(true);
        verify(fixture.listing()).setComment(start, CommentType.EOL, "comment");
        verify(fixture.bookmarks()).setBookmark(start, "NOTE", "review", "keep");
        verify(fixture.references()).addMemoryReference(
            start, target, RefType.DATA, SourceType.USER_DEFINED, 0);
        verify(fixture.references()).setPrimary(restoredReference, true);
    }

    @Test
    public void applyRejectsConflictsBeforeMutating() {
        Address start = RAM.getAddress(0x1500);
        Instruction instruction = unit(Instruction.class, start, start);
        Fixture fixture = fixture(List.of(instruction));
        Function function = mock(Function.class);
        when(function.getEntryPoint()).thenReturn(start);
        when(function.getName()).thenReturn("routine");
        when(fixture.functions().getFunctionsOverlapping(any(AddressSetView.class)))
            .thenReturn(List.of(function).iterator());

        ListingClearCore core = new ListingClearCore();
        ListingClearCore.Plan plan = core.plan(
            fixture.program(), new AddressSet(start, start),
            new ListingClearCore.Selection(true, false, false),
            new ListingClearCore.Preservation(false, false, false, false));

        assertThrows(IllegalStateException.class, () -> core.apply(fixture.program(), plan));
        verify(fixture.listing(), never()).clearCodeUnits(any(), any(), eq(false));
    }

    @Test
    public void restorationFailurePropagatesForCallerTransactionRollback() {
        Address start = RAM.getAddress(0x1600);
        Data data = unit(Data.class, start, start);
        Fixture fixture = fixture(List.of(data));
        ListingClearCore core = new ListingClearCore((program, annotations) -> {
            throw new Exception("restore failed");
        });
        ListingClearCore.Plan plan = core.plan(
            fixture.program(), new AddressSet(start, start),
            new ListingClearCore.Selection(false, true, false),
            new ListingClearCore.Preservation(false, false, false, false));

        Exception error =
            assertThrows(Exception.class, () -> core.apply(fixture.program(), plan));
        assertEquals("restore failed", error.getMessage());
        verify(fixture.listing()).clearCodeUnits(start, start, false);
    }

    @SuppressWarnings("unchecked")
    private static <T extends CodeUnit> T unit(
            Class<T> type,
            Address start,
            Address end) {
        T unit = mock(type);
        when(unit.getMinAddress()).thenReturn(start);
        when(unit.getMaxAddress()).thenReturn(end);
        return unit;
    }

    private static Symbol symbol(String name, Address address, SourceType source) {
        Symbol symbol = mock(Symbol.class);
        when(symbol.getName()).thenReturn(name);
        when(symbol.getAddress()).thenReturn(address);
        when(symbol.getSource()).thenReturn(source);
        when(symbol.getSymbolType()).thenReturn(SymbolType.LABEL);
        when(symbol.getParentNamespace()).thenReturn(mock(Namespace.class));
        return symbol;
    }

    private static Reference reference(
            Address from,
            Address to,
            SourceType source,
            RefType type) {
        Reference reference = mock(Reference.class);
        when(reference.getFromAddress()).thenReturn(from);
        when(reference.getToAddress()).thenReturn(to);
        when(reference.getSource()).thenReturn(source);
        when(reference.getReferenceType()).thenReturn(type);
        when(reference.getOperandIndex()).thenReturn(0);
        return reference;
    }

    private static Fixture fixture(List<? extends CodeUnit> units) {
        Listing listing = mock(Listing.class);
        when(listing.getInstructions(any(AddressSetView.class), eq(true)))
            .thenAnswer(invocation -> {
                AddressSetView requested = invocation.getArgument(0);
                return instructionIterator(units.stream()
                    .filter(Instruction.class::isInstance)
                    .map(Instruction.class::cast)
                    .filter(unit -> requested.contains(unit.getMinAddress()))
                    .iterator());
            });
        when(listing.getDefinedData(any(AddressSetView.class), eq(true)))
            .thenAnswer(invocation -> {
                AddressSetView requested = invocation.getArgument(0);
                return dataIterator(units.stream()
                    .filter(Data.class::isInstance)
                    .map(Data.class::cast)
                    .filter(unit -> requested.contains(unit.getMinAddress()))
                    .iterator());
            });
        for (CodeUnit unit : units) {
            Address current = unit.getMinAddress();
            while (current.compareTo(unit.getMaxAddress()) <= 0) {
                if (unit instanceof Instruction instruction) {
                    when(listing.getInstructionContaining(current))
                        .thenReturn(instruction);
                }
                else if (unit instanceof Data data) {
                    when(listing.getDefinedDataContaining(current)).thenReturn(data);
                }
                current = current.next();
            }
        }

        FunctionManager functions = mock(FunctionManager.class);
        when(functions.getFunctionsOverlapping(any(AddressSetView.class)))
            .thenReturn(Collections.<Function>emptyIterator());
        SymbolTable symbols = mock(SymbolTable.class);
        ReferenceManager references = mock(ReferenceManager.class);
        BookmarkManager bookmarks = mock(BookmarkManager.class);

        Program program = mock(Program.class);
        when(program.getListing()).thenReturn(listing);
        when(program.getFunctionManager()).thenReturn(functions);
        when(program.getSymbolTable()).thenReturn(symbols);
        when(program.getReferenceManager()).thenReturn(references);
        when(program.getBookmarkManager()).thenReturn(bookmarks);
        when(program.getGlobalNamespace()).thenReturn(mock(Namespace.class));
        return new Fixture(program, listing, functions, symbols, references, bookmarks);
    }

    private record Fixture(
            Program program,
            Listing listing,
            FunctionManager functions,
            SymbolTable symbols,
            ReferenceManager references,
            BookmarkManager bookmarks) {
    }

    private static InstructionIterator instructionIterator(
            Iterator<? extends Instruction> delegate) {
        return new InstructionIterator() {
            @Override
            public boolean hasNext() {
                return delegate.hasNext();
            }

            @Override
            public Instruction next() {
                return delegate.next();
            }

            @Override
            public Iterator<Instruction> iterator() {
                return this;
            }
        };
    }

    private static DataIterator dataIterator(
            Iterator<? extends Data> delegate) {
        return new DataIterator() {
            @Override
            public boolean hasNext() {
                return delegate.hasNext();
            }

            @Override
            public Data next() {
                return delegate.next();
            }

            @Override
            public Iterator<Data> iterator() {
                return this;
            }
        };
    }
}
