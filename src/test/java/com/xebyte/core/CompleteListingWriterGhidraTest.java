package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;

import com.xebyte.headless.HeadlessProgramProvider;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Behavioural proof that export_full_listing does not lose what AsciiExporter loses.
 *
 * <p>Each test targets a loss measured on the real neverending_story program: see the design
 * note at docs/superpowers/specs/2026-07-25-export-full-listing-design.md.
 */
public class CompleteListingWriterGhidraTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private ProgramBuilder builder;
    private ProgramDB program;
    private HeadlessProgramProvider provider;
    private SecurityConfig security;

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)),
                configuration);
        }
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder("full-listing-fixture", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x200);
        // 0x1000: PUSH RBP; MOV RBP,RSP; MOV EAX,1; POP RBP; RET
        builder.setBytes("0x1000", "55 48 89 e5 b8 01 00 00 00 5d c3");
        builder.disassemble("0x1000", 0xb);
        builder.createFunction("0x1000");

        provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        security = mock(SecurityConfig.class);
        when(security.resolveWithinFileRoot(anyString())).thenAnswer(invocation ->
            new File(invocation.getArgument(0, String.class)).getCanonicalFile().toPath());
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    /** Mechanism 2: AsciiExporter caps EOL comments at 6 lines per code unit. */
    @Test
    public void eolCommentBeyondSixLinesSurvivesInFull() throws Exception {
        StringBuilder comment = new StringBuilder();
        for (int line = 1; line <= 9; line++) {
            comment.append("eol-line-").append(line).append('\n');
        }
        setComment("0x1000", CommentType.EOL, comment.toString().stripTrailing());

        String listing = exportWholeProgram();

        for (int line = 1; line <= 9; line++) {
            assertTrue("EOL comment line " + line + " must survive",
                listing.contains("eol-line-" + line));
        }
    }

    /** Mechanism 1: AsciiExporter clips EOL comments at 40 characters. */
    @Test
    public void longEolCommentIsNotClipped() throws Exception {
        String comment = "an intentionally long end of line comment that runs past "
            + "forty characters and ends with TAIL_MARKER_EOL";
        setComment("0x1000", CommentType.EOL, comment);

        String listing = exportWholeProgram();

        assertTrue("full EOL text must survive", listing.contains("TAIL_MARKER_EOL"));
        assertFalse("no clip marker may be emitted", listing.contains("..."));
    }

    /** Mechanism 1: AsciiExporter clips plate comments too. */
    @Test
    public void longPlateCommentIsNotClipped() throws Exception {
        setComment("0x1000", CommentType.PLATE,
            "a plate comment far longer than the forty character default width, "
                + "ending with TAIL_MARKER_PLATE");

        String listing = exportWholeProgram();

        assertTrue(listing.contains("TAIL_MARKER_PLATE"));
    }

    /** Mechanism 1: AsciiExporter clips labels at 30 characters. */
    @Test
    public void labelLongerThanThirtyCharactersIsNotClipped() throws Exception {
        String label = "a_label_of_more_than_thirty_characters_TAIL";
        builder.createLabel("0x1000", label);

        String listing = exportWholeProgram();

        assertTrue("full label must survive", listing.contains(label));
    }

    /**
     * Mechanism 3: AsciiExporter emits at most 21 direct references. Measured on the real
     * program: RAM:0002 has 28 and the export listed 21.
     */
    @Test
    public void everyIncomingReferenceIsEmittedBeyondTwentyOne() throws Exception {
        int transaction = program.startTransaction("refs");
        try {
            Address destination = builder.addr("0x1000");
            for (int index = 0; index < 25; index++) {
                Address source = builder.addr(0x1100 + index);
                program.getReferenceManager().addMemoryReference(
                    source, destination, RefType.READ, SourceType.USER_DEFINED, 0);
            }
        }
        finally {
            program.endTransaction(transaction, true);
        }

        String listing = exportWholeProgram();

        for (int index = 0; index < 25; index++) {
            String source = Integer.toHexString(0x1100 + index);
            assertTrue("reference from " + source + " must be emitted",
                listing.contains(source));
        }
    }

    /**
     * Mechanism 1: the bytes column clips at 12 characters, so a wide data unit loses most
     * of its bytes. Measured on the real program: 285 occurrences, e.g. {@code 000000010...}
     * for a db[32].
     *
     * <p>The array must be a single 32-byte code unit. Applying ByteDataType with length 32
     * instead produces 32 one-byte units, and then an assertion on a short substring passes
     * for the wrong reason.
     */
    @Test
    public void bytesOfWideDataUnitAreNotClipped() throws Exception {
        builder.setBytes("0x1080",
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f "
                + "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f");
        builder.applyDataType("0x1080", new ghidra.program.model.data.ArrayDataType(
            ghidra.program.model.data.ByteDataType.dataType, 32, 1), 1);

        String listing = exportWholeProgram();

        assertEquals("the array must be one 32-byte code unit", 32,
            program.getListing().getDataAt(builder.addr("0x1080")).getLength());
        assertTrue("all 64 hex characters must be emitted on one line",
            listing.contains("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    }

    /**
     * A structure's own value representation is empty, so without component recursion the
     * listing shows the type name and nothing else: field names, component types and values
     * are all absent. AsciiExporter walks components via processSubData; this writer must too.
     */
    @Test
    public void structureComponentFieldNamesAndValuesAreEmitted() throws Exception {
        builder.setBytes("0x1080", "a5 34 12");
        ghidra.program.model.data.StructureDataType packet =
            new ghidra.program.model.data.StructureDataType("Packet", 0);
        packet.add(ghidra.program.model.data.ByteDataType.dataType, "opcode", null);
        packet.add(ghidra.program.model.data.WordDataType.dataType, "target", null);
        builder.applyDataType("0x1080", packet, 1);

        String listing = exportWholeProgram();

        assertEquals("the struct must be one 3-byte code unit", 3,
            program.getListing().getDataAt(builder.addr("0x1080")).getLength());
        assertTrue("the opcode field name must be emitted", listing.contains("opcode"));
        assertTrue("the target field name must be emitted", listing.contains("target"));
        assertTrue("the opcode component value must be emitted", listing.contains("A5h"));
        assertTrue("the target component value must be emitted", listing.contains("1234h"));
    }

    /**
     * An array of scalars must not emit a line per element. The parent's byte column is uncapped,
     * so {@code [3] byte 1h} restates a value already printed in full on the line above it — on
     * the real program that was 13,800 lines of restatement, over half the artifact. A field name
     * has no such duplicate, so structure components are still emitted, including where the
     * structure is itself an array element: that is what keeps a record table readable.
     */
    @Test
    public void scalarArrayElementsAreNotEmittedButStructureFieldsAre() throws Exception {
        builder.setBytes("0x1080", "00 01 02 03");
        builder.applyDataType("0x1080", new ghidra.program.model.data.ArrayDataType(
            ghidra.program.model.data.ByteDataType.dataType, 4, 1), 1);

        ghidra.program.model.data.StructureDataType record =
            new ghidra.program.model.data.StructureDataType("Exit", 0);
        record.add(ghidra.program.model.data.ByteDataType.dataType, "from_room", null);
        record.add(ghidra.program.model.data.ByteDataType.dataType, "to_room", null);
        builder.setBytes("0x1090", "03 0c 06 0a");
        builder.applyDataType("0x1090", new ghidra.program.model.data.ArrayDataType(
            record, 2, record.getLength()), 1);

        String listing = exportWholeProgram();

        assertTrue("the scalar array's own line must carry every byte",
            listing.contains("00010203"));
        assertFalse("a scalar array element must not get its own line",
            listing.contains("|_00001081"));
        assertTrue("an array element that is a structure must still be emitted",
            listing.contains("|_00001090"));
        assertTrue("and its field names must survive",
            listing.contains("from_room") && listing.contains("to_room"));
    }

    /** Offcut annotations: WORK_PTR on the real program reports 60 offcut references. */
    @Test
    public void offcutCommentIsEmitted() throws Exception {
        // 0x1000 is a 1-byte PUSH; 0x1001 begins MOV RBP,RSP, which is 3 bytes,
        // so 0x1002 is offcut inside that instruction.
        setComment("0x1002", CommentType.EOL, "OFFCUT_MARKER");

        String listing = exportWholeProgram();

        assertTrue("an offcut comment must not vanish", listing.contains("OFFCUT_MARKER"));
    }

    /**
     * An offcut comment must be labelled offcut even when it is the unit's only comment.
     * Comparing a comment's address against the unit's other comments rather than against
     * the unit start silently mislabels exactly this case.
     */
    @Test
    public void soleOffcutCommentIsLabelledAsOffcut() throws Exception {
        setComment("0x1002", CommentType.EOL, "SOLE_OFFCUT");

        String listing = exportWholeProgram();

        assertTrue("the comment must survive", listing.contains("SOLE_OFFCUT"));
        assertTrue("and must be marked offcut, not shown as the unit's own comment",
            listing.contains("[offcut 00001002]"));
    }

    /**
     * A bounded range whose start lands inside a multi-byte instruction must render that
     * instruction, not "undefined" over its bytes.
     */
    @Test
    public void rangeStartingInsideAnInstructionRendersTheContainingUnit() throws Exception {
        Path destination = temporaryFolder.getRoot().toPath().resolve("bounded.asm");
        ExportService service = new ExportService(provider, security);

        // 0x1001 begins a 3-byte MOV, so 0x1002 is interior to it.
        Response response = service.exportFullListing(
            destination.toString(), "0x1002", "0x1003", true, 100, "");
        assertTrue(response.toJson(), response instanceof Response.Ok);

        String listing = Files.readString(destination.toFile().getCanonicalFile().toPath());
        assertTrue("the containing instruction must be rendered",
            listing.contains("MOV") && listing.contains("RBP,RSP"));
        assertFalse("its bytes must not be reported as undefined",
            listing.contains("undefined"));
    }

    /**
     * A symbolized operand must render as the symbol, and must not throw.
     *
     * <p>CodeUnitFormatOptions.simplifyTemplate dereferences its TemplateSimplifier
     * unconditionally, so passing null there throws as soon as an operand resolves to a
     * symbol. Nothing else in this fixture resolves to one, which is how that stayed latent.
     */
    @Test
    public void symbolizedOperandRendersAsSymbolAndDoesNotThrow() throws Exception {
        // JMP rel32 at 0x1010 targeting 0x1000: 0x1015 + (-0x15) == 0x1000.
        builder.setBytes("0x1010", "e9 eb ff ff ff");
        builder.disassemble("0x1010", 5);

        String listing = exportWholeProgram();

        assertTrue("the operand must resolve to the function symbol, not a bare address",
            listing.contains("JMP") && listing.contains("FUN_00001000"));
    }

    /** The provenance header identifies which binary the artifact describes. */
    @Test
    public void headerNamesProgramAndLanguageWithoutTimestamp() throws Exception {
        String listing = exportWholeProgram();

        assertTrue(listing.contains("full-listing-fixture"));
        assertTrue(listing.contains("x86:LE:64:default"));
    }

    /** Reproducibility: no timestamp, so repeated exports are byte-identical. */
    @Test
    public void repeatedExportsAreByteIdentical() throws Exception {
        byte[] first = Files.readAllBytes(exportTo("first.asm"));
        byte[] second = Files.readAllBytes(exportTo("second.asm"));

        assertEquals(new String(first), new String(second));
    }

    /**
     * A range ending at the last address of the space must terminate. Every step of the walk
     * advances with addNoWrap, which throws rather than wrapping, so the loop has to notice it
     * has reached the end instead of asking for the next address.
     */
    @Test
    public void rangeEndingAtTheLastAddressOfTheSpaceTerminates() throws Exception {
        builder.createMemory(".top", "0xfffffffffffffff0", 0x10);
        Path destination = temporaryFolder.getRoot().toPath().resolve("top.asm");
        ExportService service = new ExportService(provider, security);

        Response response = service.exportFullListing(destination.toString(),
            "0xfffffffffffffff0", "0xffffffffffffffff", true, 100, "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        String listing = Files.readString(destination.toFile().getCanonicalFile().toPath());
        assertTrue("the last address of the space must be rendered",
            listing.contains("ffffffffffffffff"));
    }

    /**
     * An overlay unit and a base unit at the same numeric offset are different addresses in
     * different spaces. Both must appear, and each must stay qualified by its space, or a
     * reader cannot tell which occupant of the range a line describes. The real program has
     * exactly this shape: SND_PLAYER overlays part of RAM.
     */
    @Test
    public void baseAndOverlayUnitsAtTheSameOffsetAreBothEmitted() throws Exception {
        builder.createOverlayMemory("SND_PLAYER", "0x1000", 0x10);
        builder.createLabel("0x1000", "base_occupant");

        String listing = exportWholeProgram();

        assertTrue("the base unit must be rendered", listing.contains("base_occupant"));
        assertTrue("the overlay block must be named in the header",
            listing.contains("SND_PLAYER"));
        assertTrue("overlay addresses must stay space-qualified",
            listing.contains("SND_PLAYER::00001000"));
    }

    /**
     * More incoming references on one unit than INCOMING_BUDGET. The budget only pre-sizes the
     * metadata list, which caps at 64 and reports the page as incomplete; the writer must
     * refetch without a limit rather than emit the capped page.
     */
    @Test
    public void moreIncomingReferencesThanTheBudgetAreAllEmitted() throws Exception {
        int transaction = program.startTransaction("refs");
        try {
            Address destination = builder.addr("0x1000");
            for (int index = 0; index < 70; index++) {
                program.getReferenceManager().addMemoryReference(
                    builder.addr(0x1100 + index), destination,
                    RefType.READ, SourceType.USER_DEFINED, 0);
            }
        }
        finally {
            program.endTransaction(transaction, true);
        }

        String listing = exportWholeProgram();

        assertTrue("the header must report the true total, not the budget",
            listing.contains("XREF[70]"));
        for (int index = 0; index < 70; index++) {
            String source = Integer.toHexString(0x1100 + index);
            assertTrue("reference from " + source + " must be emitted",
                listing.contains(source + "(R)"));
        }
    }

    /**
     * A short memory read must fail the export. Padding the tail of the byte array and emitting
     * it would publish bytes the program does not contain, with every counter in agreement.
     */
    @Test
    public void shortMemoryReadFailsTheExport() throws Exception {
        ProgramDB spied = Mockito.spy(program);
        Memory shortReading = Mockito.spy(program.getMemory());
        Mockito.doReturn(shortReading).when(spied).getMemory();
        Mockito.doReturn(1).when(shortReading)
            .getBytes(Mockito.any(Address.class), Mockito.any(byte[].class));
        ExportService.CompleteListingRunner runner =
            new ExportService.CompleteListingRunner(100);

        boolean exported = runner.export(temporaryFolder.newFile("short.asm"), spied,
            program.getMemory(), TaskMonitor.DUMMY);

        assertFalse("a short read must not produce an artifact", exported);
        assertTrue(runner.diagnostic(), runner.diagnostic().contains("short read"));
    }

    /** A destination that cannot be written must fail the export, not publish a partial file. */
    @Test
    public void unwritableDestinationFailsTheExport() throws Exception {
        File directory = temporaryFolder.newFolder("readonly");
        Path destination = directory.toPath().resolve("listing.asm");
        assertTrue("the fixture requires a directory that rejects writes",
            directory.setWritable(false));
        try {
            Response response = new ExportService(provider, security).exportFullListing(
                destination.toString(), null, null, true, 100, "");

            assertTrue(response.toJson(), response instanceof Response.Err);
            assertFalse("nothing may be published", Files.exists(destination));
        }
        finally {
            directory.setWritable(true);
        }
    }

    /**
     * Control characters occur in C64 comments — PETSCII $93 is clear-screen — and must survive
     * verbatim. The content audit reads the artifact back, so anything that re-encodes or
     * re-flows them would fail the export rather than corrupt the listing silently.
     */
    @Test
    public void controlCharactersInACommentSurviveVerbatim() throws Exception {
        String comment = "PETSCII \u0093 clears the screen, \u0007 rings the bell";
        setComment("0x1000", CommentType.EOL, comment);

        String listing = exportWholeProgram();

        assertTrue("the control characters must be emitted as authored",
            listing.contains(comment));
    }

    /**
     * The audit counts comment records, not content, so a body that reaches the artifact only
     * in part still counts as one emitted record. Nothing in the record counts, in
     * {@code checkError}, or in the byte-read checks notices a sink that silently swallows a
     * line, so the content has to be checked against what actually landed in the output.
     */
    @Test
    public void commentBodyMissingFromTheOutputIsDetected() throws Exception {
        setComment("0x1000", CommentType.PLATE,
            "first plate line\nSWALLOWED plate line\nlast plate line");
        setComment("0x1004", CommentType.EOL, "first eol line\nSWALLOWED eol line");
        CompleteListingWriter writer = new CompleteListingWriter(program, 100);
        StringBuilder sink = new StringBuilder();
        try (PrintWriter out = new PrintWriter(new CollectingWriter(sink))) {
            writer.write(out, program.getMemory());
        }

        assertNull("a complete artifact must not be reported as short",
            writer.shortfall(sink.toString().lines()));
        String missing = writer.shortfall(
            sink.toString().lines().filter(line -> !line.contains("SWALLOWED")));
        assertTrue("the lost plate body must be reported, not counted as emitted: " + missing,
            missing != null && missing.contains("SWALLOWED plate line"));
    }

    /**
     * References were counted the same way comments were: the emitted-side counter agrees with
     * the collected-side counter whether or not the lines reach the file. Losing the reference
     * group downstream, or deleting the call that writes it, must block publication.
     */
    @Test
    public void referenceMissingFromTheOutputIsDetected() throws Exception {
        int transaction = program.startTransaction("refs");
        try {
            program.getReferenceManager().addMemoryReference(
                builder.addr("0x1100"), builder.addr("0x1000"),
                RefType.READ, SourceType.USER_DEFINED, 0);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        CompleteListingWriter writer = new CompleteListingWriter(program, 100);
        StringBuilder sink = new StringBuilder();
        try (PrintWriter out = new PrintWriter(new CollectingWriter(sink))) {
            writer.write(out, program.getMemory());
        }

        assertNull("a complete artifact must not be reported as short",
            writer.shortfall(sink.toString().lines()));
        String missing = writer.shortfall(
            sink.toString().lines().filter(line -> !line.contains("XREF")));
        assertTrue("the lost reference must be reported: " + missing,
            missing != null && missing.contains("00001100"));
    }

    /** Accumulates everything written, so a test can drop lines the way a bad sink would. */
    private static final class CollectingWriter extends java.io.Writer {
        private final StringBuilder sink;

        CollectingWriter(StringBuilder sink) {
            this.sink = sink;
        }

        @Override
        public void write(char[] buffer, int offset, int length) {
            sink.append(buffer, offset, length);
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    }

    @Test
    public void dumpForInspection() throws Exception {
        String dump = System.getenv("FULL_LISTING_DUMP");
        assumeTrue("FULL_LISTING_DUMP unset", dump != null && !dump.isBlank());
        setComment("0x1000", CommentType.EOL,
            "first authored line of a long comment that exceeds forty characters\n"
                + "second authored line\nthird authored line");
        setComment("0x1000", CommentType.PLATE, "Plate comment for the fixture function.");
        setComment("0x1004", CommentType.PRE, "pre comment at an interior instruction");
        builder.createLabel("0x1004", "an_interior_label_of_considerable_length");
        int transaction = program.startTransaction("refs");
        try {
            for (int index = 0; index < 25; index++) {
                program.getReferenceManager().addMemoryReference(
                    builder.addr(0x1100 + index), builder.addr("0x1000"),
                    RefType.READ, SourceType.USER_DEFINED, 0);
            }
        }
        finally {
            program.endTransaction(transaction, true);
        }
        builder.setBytes("0x1080",
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f "
                + "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f");
        builder.applyDataType("0x1080", new ghidra.program.model.data.ByteDataType(), 32);
        builder.setBytes("0x10c0", "a5 34 12 07");
        ghidra.program.model.data.StructureDataType inner =
            new ghidra.program.model.data.StructureDataType("Header", 0);
        inner.add(ghidra.program.model.data.ByteDataType.dataType, "opcode", null);
        inner.add(ghidra.program.model.data.WordDataType.dataType, "target", null);
        ghidra.program.model.data.StructureDataType outer =
            new ghidra.program.model.data.StructureDataType("Packet", 0);
        outer.add(inner, "header", null);
        outer.add(ghidra.program.model.data.ByteDataType.dataType, "checksum", null);
        builder.applyDataType("0x10c0", outer, 1);

        Files.writeString(Path.of(dump), exportWholeProgram());
    }

    private void setComment(String address, CommentType type, String text) {
        int transaction = program.startTransaction("comment");
        try {
            program.getListing().setComment(builder.addr(address), type, text);
        }
        finally {
            program.endTransaction(transaction, true);
        }
    }

    private String exportWholeProgram() throws Exception {
        return Files.readString(exportTo("listing.asm"));
    }

    private Path exportTo(String name) throws Exception {
        Path destination = temporaryFolder.getRoot().toPath().resolve(name);
        ExportService service = new ExportService(provider, security);
        Response response = service.exportFullListing(
            destination.toString(), null, null, true, 100, "");
        assertTrue(response.toJson(), response instanceof Response.Ok);
        return destination.toFile().getCanonicalFile().toPath();
    }
}
