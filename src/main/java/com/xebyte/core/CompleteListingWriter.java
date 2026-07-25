package com.xebyte.core;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.xebyte.core.ListingRangeService.CommentRecord;
import com.xebyte.core.ListingRangeService.LabelRecord;
import com.xebyte.core.ListingRangeService.RangeIndex;
import com.xebyte.core.ListingRangeService.UnitMetadata;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CodeUnitFormatOptions;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;

/**
 * Renders a listing that never discards content.
 *
 * <p>Ghidra's {@code AsciiExporter} loses material four ways: {@code clip()} on
 * width-constrained fields, a hardcoded six-line ceiling on EOL comments, a hardcoded
 * twenty-one direct reference ceiling, and stack-variable widths its option list never
 * publishes. Measured on a real 6502 program, a whole-program Ascii export clipped 1164
 * lines and dropped 7 of the 28 references to one address behind an {@code XREF[21]} header
 * that misreported the total.
 *
 * <p>This writer has no clip step and no ceilings. Columns are minimum widths: a long
 * operand pushes the comment column right rather than being shortened. Authored newlines in
 * comments are emitted as-is and never re-flowed, so aligned tables and diagrams survive.
 * Only the machine-generated cross-reference list wraps.
 *
 * <p>Annotation gathering is delegated to {@link RangeIndex}, which is driven from
 * {@code getCommentAddressIterator}, {@code getReferenceSourceIterator} and
 * {@code getReferenceDestinationIterator}. Those enumerate every annotated address including
 * offcut positions inside a multi-byte instruction, which a naive walk over code-unit start
 * addresses would miss.
 */
final class CompleteListingWriter {

    /** Bytes per emitted undefined-data line. */
    private static final int UNDEFINED_RUN_LIMIT = 16;

    /**
     * Per-unit incoming-reference budget handed to {@link RangeIndex#collectMetadata}, which
     * pre-sizes a list of this length. Chosen well above anything observed (28 on the real
     * program) while staying cheap to allocate for every code unit; when a unit does exceed
     * it, {@link #incomingReferences} refetches that unit without a limit rather than
     * dropping the tail.
     */
    private static final int INCOMING_BUDGET = 64;

    private static final String ADDRESS_INDENT = "                ";

    private final Program program;
    private final int xrefWrapColumn;
    private final CodeUnitFormat format;
    private final ReferenceManager references;

    private final Map<CommentType, Integer> collectedComments =
        new EnumMap<>(CommentType.class);
    private final Map<CommentType, Integer> emittedComments =
        new EnumMap<>(CommentType.class);
    private int collectedLabels;
    private int emittedLabels;
    private int collectedReferences;
    private int emittedReferences;
    private int codeUnits;

    CompleteListingWriter(Program program, int xrefWrapColumn) {
        this.program = program;
        this.xrefWrapColumn = xrefWrapColumn;
        this.references = program.getReferenceManager();
        // The same options Ghidra's own exporter uses. ShowBlockName.NON_LOCAL is
        // load-bearing on programs with overlay spaces: an operand reaching into an overlay
        // must stay block-qualified. getDefaultOperandRepresentation would render a bare
        // address instead of the symbol, which is why operand_text is not reused here.
        this.format = new CodeUnitFormat(new CodeUnitFormatOptions(
            CodeUnitFormatOptions.ShowBlockName.NON_LOCAL,
            CodeUnitFormatOptions.ShowNamespace.NON_LOCAL,
            null, true, true, true, true, true, true, true, null));
    }

    /** Renders every range of {@code selection}, in address order. */
    void write(PrintWriter out, AddressSetView selection) {
        writeHeader(out, selection);
        for (AddressRange range : selection) {
            writeRange(out, range.getMinAddress(), range.getMaxAddress());
        }
        writeSymbolIndex(out, selection);
    }

    private void writeHeader(PrintWriter out, AddressSetView selection) {
        out.println(";" + "=".repeat(78));
        out.println("; " + program.getName());
        out.println(";" + "-".repeat(78));
        out.println("; language:      " + program.getLanguageID());
        out.println("; compiler:      " + program.getCompilerSpec().getCompilerSpecID());
        out.println("; image base:    " + program.getImageBase());
        // Ghidra stores the literal string "unknown" when a hash was never computed;
        // printing that is noise, so the line is omitted instead.
        String sha256 = program.getExecutableSHA256();
        if (sha256 != null && !sha256.isBlank() && !"unknown".equals(sha256)) {
            out.println("; sha256:        " + sha256);
        }
        String md5 = program.getExecutableMD5();
        if (md5 != null && !md5.isBlank() && !"unknown".equals(md5)) {
            out.println("; md5:           " + md5);
        }
        // Deliberately no export timestamp: repeated exports of an unchanged program stay
        // byte-identical, so the artifact can be diffed between revisions.
        for (AddressRange range : selection) {
            out.println("; range:         " + range.getMinAddress()
                + " - " + range.getMaxAddress());
        }
        out.println(";" + "-".repeat(78));
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            out.println("; block " + pad(block.getName(), 20)
                + block.getStart() + " - " + block.getEnd()
                + "  " + (block.isRead() ? "r" : "-")
                + (block.isWrite() ? "w" : "-")
                + (block.isExecute() ? "x" : "-")
                + (block.isInitialized() ? "  initialized" : "  uninitialized")
                + (block.isOverlay() ? "  overlay" : ""));
        }
        out.println(";" + "=".repeat(78));
        out.println();
    }

    private void writeRange(PrintWriter out, Address requestedStart, Address requestedEnd) {
        // Snap to whole code units. A requested bound landing inside a multi-byte instruction
        // would otherwise make codeUnitAt return null for an address that is really part of a
        // decoded instruction, and the walk would emit "undefined" over its bytes. A listing
        // view shows the containing unit, so this does too.
        Address rangeStart = containingBound(requestedStart, true);
        Address rangeEnd = containingBound(requestedEnd, false);
        RangeIndex index = RangeIndex.build(program, rangeStart, rangeEnd);
        Address current = rangeStart;
        while (current != null && current.compareTo(rangeEnd) <= 0) {
            CodeUnit existing = index.codeUnitAt(current);
            Address unitEnd = existing != null
                ? existing.getMaxAddress()
                : index.undefinedEnd(current, UNDEFINED_RUN_LIMIT);
            if (unitEnd.compareTo(rangeEnd) > 0) {
                unitEnd = rangeEnd;
            }
            UnitMetadata metadata =
                index.collectMetadata(current, unitEnd, INCOMING_BUDGET);
            writeUnit(out, existing, current, unitEnd, metadata, index);
            codeUnits++;
            current = unitEnd.equals(rangeEnd) ? null : next(unitEnd);
        }
    }

    /**
     * The containing code unit's bound, or the address itself where nothing is defined.
     *
     * @param start true for the unit's first address, false for its last
     */
    private Address containingBound(Address requested, boolean start) {
        CodeUnit containing = program.getListing().getCodeUnitContaining(requested);
        if (containing == null) {
            return requested;
        }
        return start ? containing.getMinAddress() : containing.getMaxAddress();
    }

    private void writeUnit(PrintWriter out, CodeUnit existing, Address start, Address end,
            UnitMetadata metadata, RangeIndex index) {
        tally(metadata);

        writeComments(out, metadata, CommentType.PLATE, true, start);
        writeComments(out, metadata, CommentType.PRE, false, start);
        writeLabelsAndFunction(out, metadata, start);
        writeCrossReferences(out, start, end);

        writeCodeLine(out, existing, start, end, index, metadata);

        writeComments(out, metadata, CommentType.POST, false, start);
        writeComments(out, metadata, CommentType.REPEATABLE, false, start);
    }

    private void writeComments(PrintWriter out, UnitMetadata metadata, CommentType type,
            boolean boxed, Address unitStart) {
        for (CommentRecord comment : metadata.comments()) {
            if (comment.type() != type) {
                continue;
            }
            // Offcut is relative to the unit start, not to the unit's other comments: a unit
            // whose only comment sits at an interior address is still offcut.
            boolean offcut = !comment.address().equals(unitStart);
            if (boxed) {
                out.println(ADDRESS_INDENT + ";" + "*".repeat(70));
            }
            for (String line : comment.text().split("\n", -1)) {
                out.println(ADDRESS_INDENT + "; "
                    + (offcut ? "[offcut " + comment.address() + "] " : "") + line);
            }
            if (boxed) {
                out.println(ADDRESS_INDENT + ";" + "*".repeat(70));
            }
            emittedComments.merge(type, 1, Integer::sum);
        }
    }

    private void writeLabelsAndFunction(PrintWriter out, UnitMetadata metadata,
            Address start) {
        for (LabelRecord label : metadata.labels()) {
            String qualified = "Global".equals(label.namespace())
                ? label.name()
                : label.namespace() + "::" + label.name();
            String suffix = label.primary() ? "" : "  ; secondary";
            String offcut = label.address().equals(start)
                ? "" : "  ; offcut at " + label.address();
            out.println(qualified + ":" + suffix + offcut);
            emittedLabels++;
        }

        Function function = program.getFunctionManager().getFunctionAt(start);
        if (function != null) {
            out.println(ADDRESS_INDENT + "; function: " + function.getPrototypeString(true, true));
            for (Variable parameter : function.getParameters()) {
                out.println(ADDRESS_INDENT + ";   param  "
                    + variableText(parameter));
            }
            for (Variable local : function.getLocalVariables()) {
                out.println(ADDRESS_INDENT + ";   local  "
                    + variableText(local));
            }
        }
    }

    private String variableText(Variable variable) {
        // Full text: these are the fields AsciiExporter clips at 15/15/8/20 characters.
        DataType type = variable.getDataType();
        String comment = variable.getComment();
        return variable.getName()
            + " : " + (type == null ? "?" : type.getDisplayName())
            + " @ " + variable.getVariableStorage()
            + (comment == null || comment.isBlank() ? "" : "  ; " + comment);
    }

    private void writeCrossReferences(PrintWriter out, Address start, Address end) {
        List<Reference> direct = new ArrayList<>();
        List<Reference> offcut = new ArrayList<>();
        for (Reference reference : incomingReferences(start, end)) {
            if (reference.getToAddress().equals(start)) {
                direct.add(reference);
            }
            else {
                offcut.add(reference);
            }
        }
        writeReferenceGroup(out, "XREF", direct);
        writeReferenceGroup(out, "XREF offcut", offcut);
    }

    /**
     * Every reference into {@code [start, end]}, with no ceiling. Ghidra's exporter stops at
     * twenty-one and reports that count as the total.
     */
    private List<Reference> incomingReferences(Address start, Address end) {
        List<Reference> collected = new ArrayList<>();
        Address at = start;
        while (at != null && at.compareTo(end) <= 0) {
            if (references.hasReferencesTo(at)) {
                for (Reference reference : references.getReferencesTo(at)) {
                    collected.add(reference);
                }
            }
            at = at.equals(end) ? null : next(at);
        }
        collected.sort(Comparator
            .comparing((Reference reference) -> reference.getToAddress())
            .thenComparing(Reference::getFromAddress));
        return collected;
    }

    private void writeReferenceGroup(PrintWriter out, String heading,
            List<Reference> group) {
        if (group.isEmpty()) {
            return;
        }
        String label = ADDRESS_INDENT + "; " + heading + "[" + group.size() + "]: ";
        String continuation = " ".repeat(label.length());
        StringBuilder line = new StringBuilder(label);
        boolean first = true;
        for (Reference reference : group) {
            String item = reference.getFromAddress()
                + "(" + abbreviate(reference) + ")";
            if (!first && line.length() + item.length() + 2 > xrefWrapColumn) {
                // Trailing comma before the break, so a wrapped list still reads as a list.
                out.println(line.append(",").toString());
                line = new StringBuilder(continuation);
            }
            else if (!first) {
                line.append(", ");
            }
            line.append(item);
            emittedReferences++;
            first = false;
        }
        out.println(line.toString());
    }

    private String abbreviate(Reference reference) {
        if (reference.getReferenceType().isCall()) {
            return "c";
        }
        if (reference.getReferenceType().isJump()) {
            return "j";
        }
        if (reference.getReferenceType().isWrite()) {
            return "W";
        }
        if (reference.getReferenceType().isRead()) {
            return "R";
        }
        return "*";
    }

    private void writeCodeLine(PrintWriter out, CodeUnit existing, Address start, Address end,
            RangeIndex index, UnitMetadata metadata) {
        StringBuilder line = new StringBuilder();
        line.append(pad(start.toString(), 16));
        line.append(pad(bytesText(existing, start, end, index), 26));

        if (existing instanceof Instruction instruction) {
            line.append(pad(instruction.getMnemonicString(), 10));
            line.append(operandText(instruction));
        }
        else if (existing instanceof Data data) {
            line.append(pad(data.getDataType().getDisplayName(), 10));
            line.append(data.getDefaultValueRepresentation());
        }
        else {
            line.append(pad("??", 10));
            line.append(undefinedText(start, end, index));
        }

        List<String> eol = eolLines(metadata, start);
        if (eol.isEmpty()) {
            out.println(rstrip(line.toString()));
            return;
        }
        int commentColumn = Math.max(line.length() + 2, 58);
        out.println(rstrip(pad(line.toString(), commentColumn) + "; " + eol.get(0)));
        String continuation = " ".repeat(commentColumn) + "; ";
        for (int index2 = 1; index2 < eol.size(); index2++) {
            out.println(rstrip(continuation + eol.get(index2)));
        }
    }

    /**
     * Every authored EOL line, in order. AsciiExporter stops after six.
     *
     * <p>EOL comments do not pass through {@link #writeComments}, so the offcut marker has to
     * be applied here too: without it an EOL comment attached to an interior address is
     * rendered as though the unit itself carried it.
     */
    private List<String> eolLines(UnitMetadata metadata, Address unitStart) {
        List<String> lines = new ArrayList<>();
        for (CommentRecord comment : metadata.comments()) {
            if (comment.type() != CommentType.EOL) {
                continue;
            }
            String prefix = comment.address().equals(unitStart)
                ? "" : "[offcut " + comment.address() + "] ";
            for (String line : comment.text().split("\n", -1)) {
                lines.add(prefix + line);
            }
            emittedComments.merge(CommentType.EOL, 1, Integer::sum);
        }
        return lines;
    }

    private String bytesText(CodeUnit existing, Address start, Address end,
            RangeIndex index) {
        if (!index.initialized(start, end)) {
            return "";
        }
        StringBuilder hex = new StringBuilder();
        try {
            byte[] bytes = new byte[(int) (end.subtract(start) + 1)];
            index.memory().getBytes(start, bytes);
            for (byte value : bytes) {
                hex.append(String.format("%02x", value));
            }
        }
        catch (Exception e) {
            return "";
        }
        // No clipping: a 32-byte data unit renders all 64 characters. AsciiExporter cuts
        // this column at 12.
        return hex.toString();
    }

    private String undefinedText(Address start, Address end, RangeIndex index) {
        if (!index.initialized(start, end)) {
            return "?? uninitialized";
        }
        return "undefined";
    }

    private String operandText(Instruction instruction) {
        StringBuilder operands = new StringBuilder();
        for (int index = 0; index < instruction.getNumOperands(); index++) {
            if (index > 0) {
                operands.append(",");
            }
            operands.append(format.getOperandRepresentationString(instruction, index));
        }
        return operands.toString();
    }

    private void writeSymbolIndex(PrintWriter out, AddressSetView selection) {
        Set<String> entries = new LinkedHashSet<>();
        List<Symbol> symbols = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            if (selection.contains(symbol.getAddress())) {
                symbols.add(symbol);
            }
        }
        symbols.sort(Comparator.comparing((Symbol symbol) -> symbol.getName())
            .thenComparing(symbol -> symbol.getAddress().toString()));
        out.println();
        out.println(";" + "=".repeat(78));
        out.println("; symbol index");
        out.println(";" + "=".repeat(78));
        for (Symbol symbol : symbols) {
            entries.add("; " + pad(symbol.getName(), 40) + symbol.getAddress());
        }
        for (String entry : entries) {
            out.println(entry);
        }
    }

    private void tally(UnitMetadata metadata) {
        collectedLabels += metadata.labels().size();
        for (CommentRecord comment : metadata.comments()) {
            collectedComments.merge(comment.type(), 1, Integer::sum);
        }
    }

    /**
     * Emit-side completeness check. Gathering is delegated to already-tested,
     * offcut-correct code, so the realistic remaining defect is a renderer that receives a
     * record and fails to write it. Comment kinds are counted per
     * {@link CommentType#values()}, so a kind added by a future Ghidra release is counted
     * rather than silently skipped.
     *
     * @return a description of the shortfall, or null when everything collected was emitted
     */
    String shortfall() {
        for (CommentType type : CommentType.values()) {
            int collected = collectedComments.getOrDefault(type, 0);
            int emitted = emittedComments.getOrDefault(type, 0);
            if (collected != emitted) {
                return "emitted " + emitted + " of " + collected + " "
                    + type.name().toLowerCase() + " comments";
            }
        }
        if (collectedLabels != emittedLabels) {
            return "emitted " + emittedLabels + " of " + collectedLabels + " labels";
        }
        return null;
    }

    Map<String, Object> report() {
        Map<String, Object> comments = new java.util.LinkedHashMap<>();
        for (CommentType type : CommentType.values()) {
            comments.put(type.name().toLowerCase(),
                emittedComments.getOrDefault(type, 0));
        }
        return Map.of(
            "code_units", codeUnits,
            "labels", emittedLabels,
            "references", emittedReferences,
            "comments", comments);
    }

    private Address next(Address address) {
        try {
            return address.addNoWrap(1);
        }
        catch (Exception e) {
            return null;
        }
    }

    private static String pad(String value, int width) {
        // Minimum width, never a maximum: an oversized value pushes what follows right
        // instead of being clipped.
        if (value.length() >= width) {
            return value + " ";
        }
        return value + " ".repeat(width - value.length());
    }

    private static String rstrip(String value) {
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == ' ') {
            end--;
        }
        return value.substring(0, end);
    }

    int collectedReferenceCount() {
        return collectedReferences;
    }
}
