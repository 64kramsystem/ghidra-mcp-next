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
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
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

    /** Wrapped EOL text must be reflowed against each physical line's actual capacity. */
    @Test
    public void wrappedEolCommentUsesTheWholeContinuationLine() throws Exception {
        String firstFragment = "Rebuild bytes";
        String remainder =
            "1-2 of the dormant COM mask; 0248 is patched to * below, yielding *.COM.";
        String bareListing = exportWholeProgram();
        String code = lineContaining(bareListing, "00001001");
        int commentPrefixLength = Math.max(code.length() + 2, 58) + 2;
        int width = Math.max(commentPrefixLength + firstFragment.length(),
            "; ".length() + remainder.length());
        setComment("0x1001", CommentType.EOL, firstFragment + " " + remainder);

        String listing = Files.readString(exportTo("reflowed-eol.asm", width));

        assertTrue(lineContaining(listing, firstFragment),
            lineContaining(listing, firstFragment).endsWith("; " + firstFragment));
        assertConsecutiveLines(listing,
            lineContaining(listing, firstFragment),
            "; " + remainder);
        assertFalse("wrapping must not expose bookkeeping markers", listing.contains(";>"));
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

    /** Plate text and borders share column one, with the full width available to each line. */
    @Test
    public void plateCommentsStartAtColumnOneAndUseTheConfiguredWidth() throws Exception {
        setComment("0x1000", CommentType.PLATE,
            "Bootstrap-phase residue or stored host bytes at normalized offsets016Fh..017Ch. "
                + "Their initial-load positions are PSP:028Fh..029Ch; executed startup streams "
                + "are mapped in first_decode and explicit patched overlays. The36-byte "
                + "transition ciphertext at0298h has a separate plaintext view.");

        String listing = Files.readString(exportTo("plate-width-120.asm", 120));

        assertConsecutiveLines(listing,
            ";" + "*".repeat(70),
            "; Bootstrap-phase residue or stored host bytes at normalized offsets016Fh..017Ch."
                + " Their initial-load positions are",
            "; PSP:028Fh..029Ch; executed startup streams are mapped in first_decode and explicit"
                + " patched overlays. The36-byte",
            "; transition ciphertext at0298h has a separate plaintext view.",
            ";" + "*".repeat(70));
        assertFalse(listing.contains("                ;" + "*".repeat(70)));
    }

    /** Decorative borders fit narrow widths without generating extra continuation lines. */
    @Test
    public void plateBordersFitNarrowWidths() throws Exception {
        setComment("0x1000", CommentType.PLATE, "Short plate comment.");

        String listing = Files.readString(exportTo("plate-width-40.asm", 40));

        assertConsecutiveLines(listing,
            ";" + "*".repeat(39),
            "; Short plate comment.",
            ";" + "*".repeat(39));
    }

    /** The requested width applies to every physical line, not only reference groups. */
    @Test
    public void everyPhysicalLineRespectsTheRequiredWidth() throws Exception {
        setComment("0x1000", CommentType.EOL,
            "a deliberately long authored comment whose exact tail is CONTENT_TAIL");
        setComment("0x1000", CommentType.PLATE, "a".repeat(37) + "😀TAIL");
        builder.createLabel("0x1004",
            "a_deliberately_long_label_that_exceeds_the_requested_physical_width");
        int transaction = program.startTransaction("width-limited refs");
        try {
            for (int index = 0; index < 3; index++) {
                program.getReferenceManager().addMemoryReference(
                    builder.addr(0x1100 + index), builder.addr("0x1000"),
                    RefType.READ, SourceType.USER_DEFINED, 0);
            }
        }
        finally {
            program.endTransaction(transaction, true);
        }

        String listing = Files.readString(exportTo("width-limited.asm", 40));

        assertTrue("the wrapped comment tail must be an ordinary continuation",
            lineContaining(listing, "CONTENT_TAIL").startsWith("; "));
        assertFalse("wrapping must not expose bookkeeping markers", listing.contains(";>"));
        assertTrue("the content audit must accept the complete wrapped body",
            listing.contains("CONTENT_TAIL"));
        assertTrue("a surrogate pair at a hard split must survive", listing.contains("😀"));
        assertTrue("narrow xref groups must retain every token", listing.contains("00001102(R)"));
        for (String line : listing.lines().toList()) {
            assertTrue("line exceeds 40 columns: [" + line + "]", line.length() <= 40);
        }

        String widerListing = Files.readString(exportTo("width-limited-60.asm", 60));
        for (String line : widerListing.lines().toList()) {
            assertFalse("wrapped line has trailing whitespace: [" + line + "]",
                line.endsWith(" ") || line.endsWith("\t"));
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void writerRejectsUnsupportedWidth() {
        new CompleteListingWriter(program, 19);
    }

    @Test
    public void usedEquatesAreDefinedOnceInStableOrder() throws Exception {
        builder.setBytes("0x1010", "b8 02 00 00 00");
        builder.disassemble("0x1010", 5);
        builder.setBytes("0x1020", "b8 01 00 00 00");
        builder.disassemble("0x1020", 5);
        builder.setBytes("0x1030", "03");
        builder.applyDataType("0x1030", ByteDataType.dataType, 1);
        int transaction = program.startTransaction("equates");
        try {
            ghidra.program.model.symbol.Equate zed =
                program.getEquateTable().createEquate("ZED", 1);
            zed.addReference(builder.addr("0x1004"), 1);
            zed.addReference(builder.addr("0x1020"), 1);
            ghidra.program.model.symbol.Equate alpha =
                program.getEquateTable().createEquate("ALPHA", 2);
            alpha.addReference(builder.addr("0x1010"), 1);
            ghidra.program.model.symbol.Equate dataValue =
                program.getEquateTable().createEquate("DATA_VALUE", 3);
            dataValue.addReference(builder.addr("0x1030"), 0);
            program.getEquateTable().createEquate("UNUSED", 3);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        String listing = exportWholeProgram();

        int alpha = listing.indexOf("ALPHA equ 0x2");
        int zed = listing.indexOf("ZED equ 0x1");
        assertTrue(listing, alpha >= 0 && alpha < zed);
        assertEquals(1L, listing.lines().filter(line -> line.equals("ZED equ 0x1")).count());
        assertFalse(listing, listing.contains("UNUSED"));
        assertTrue(listing, listing.contains("MOV       EAX,ZED"));
        assertTrue(listing, listing.contains("MOV       EAX,ALPHA"));
        assertTrue(listing, listing.contains("DATA_VALUE equ 0x3"));
        assertTrue(listing, listing.contains("byte      DATA_VALUE"));

        CompleteListingWriter writer = new CompleteListingWriter(program, 100);
        StringBuilder sink = new StringBuilder();
        try (PrintWriter out = new PrintWriter(new CollectingWriter(sink))) {
            writer.write(out, program.getMemory());
        }
        assertNull(writer.shortfall(sink.toString().lines()));
        String missing = writer.shortfall(
            sink.toString().lines().map(line -> line.equals("ALPHA equ 0x2") ? "" : line));
        assertTrue(missing, missing.contains("equate definition did not reach the output"));
    }

    /** Empty authored comment lines must not make the exported artifact fail diff checks. */
    @Test
    public void blankPlateCommentLineHasNoTrailingWhitespace() throws Exception {
        setComment("0x1000", CommentType.PLATE, "first line\n\nlast line");

        String listing = exportWholeProgram();

        assertConsecutiveLines(listing,
            "; first line",
            ";",
            "; last line");
    }

    /** A blank offcut line retains its location marker without a separator at the end. */
    @Test
    public void blankOffcutCommentLineHasNoTrailingWhitespace() throws Exception {
        setComment("0x1002", CommentType.PRE, "offcut first\n\noffcut last");

        String listing = exportWholeProgram();

        assertConsecutiveLines(listing,
            "                ; [offcut 00001002] offcut first",
            "                ; [offcut 00001002]",
            "                ; [offcut 00001002] offcut last");
    }

    /**
     * Whitespace-only authored lines normalize to the same bare comment line as empty ones.
     * The tab in the fixture is load-bearing: trimming spaces alone is not sufficient.
     */
    @Test
    public void whitespaceOnlyPlateCommentLineHasNoTrailingWhitespace() throws Exception {
        setComment("0x1000", CommentType.PLATE, "first line\n \t \nlast line");

        String listing = exportWholeProgram();

        assertConsecutiveLines(listing,
            "; first line",
            ";",
            "; last line");
    }

    /** Function-variable comment lines stay comments and cannot retain trailing whitespace. */
    @Test
    public void multilineVariableCommentHasNoTrailingWhitespace() throws Exception {
        setLocalComment("first variable line \t \nsecond variable line \t ");

        String listing = exportWholeProgram();

        String first = lineContaining(listing, "first variable line");
        String second = lineContaining(listing, "second variable line");
        assertTrue("first variable line must end at its content: [" + first + "]",
            first.endsWith("first variable line"));
        assertTrue("continuation must remain an assembly comment: [" + second + "]",
            second.startsWith("                ;"));
        assertTrue("second variable line must end at its content: [" + second + "]",
            second.endsWith("second variable line"));
        assertEquals("continuation text must align with the first comment line",
            first.indexOf("first variable line"), second.indexOf("second variable line"));
    }

    /** An empty stored variable comment does not add a dangling separator. */
    @Test
    public void emptyVariableCommentAddsNoSeparator() throws Exception {
        setLocalComment("");

        String listing = exportWholeProgram();

        String line = lineContaining(listing, "fixture_local");
        assertFalse("empty variable comment must not add a separator: [" + line + "]",
            line.endsWith(";"));
    }

    /** A whitespace-only stored variable comment also has no content to introduce. */
    @Test
    public void whitespaceOnlyVariableCommentAddsNoSeparator() throws Exception {
        setLocalComment(" \t ");

        String listing = exportWholeProgram();

        String line = lineContaining(listing, "fixture_local");
        assertFalse("whitespace-only variable comment must not add a separator: [" + line + "]",
            line.endsWith(";"));
    }

    /** C64 cursor controls are content even when they are the entire variable comment. */
    @Test
    public void controlOnlyVariableCommentIsNotBlank() throws Exception {
        setLocalComment("\u001d");

        String listing = exportWholeProgram();

        assertTrue("the cursor control must survive as variable-comment content",
            lineContaining(listing, "\u001d").startsWith("                ;"));
    }

    /** The EOL renderer and completeness audit normalize the same trailing tab. */
    @Test
    public void eolCommentContentHasNoTrailingTab() throws Exception {
        setComment("0x1000", CommentType.EOL, "content ends with a tab\t");

        String listing = exportWholeProgram();

        String line = lineContaining(listing, "content ends with a tab");
        assertTrue("EOL comment line must end at its content: [" + line + "]",
            line.endsWith("content ends with a tab"));
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

    @Test
    public void byteTableRetainsEveryValueInCompactRows() throws Exception {
        builder.setBytes("0x1080",
            "1a 1e 22 26 2e 32 3c 40 4c 5c 64 6c 76 aa de f2 14 1a 20 2c 3a 4e 64 "
                + "96 ad c4 fc 20 42 76 9f f0 28 4a 80 b7 df 15 1f 25 2b 31 61 66 a8 fe "
                + "30 86 b3 dd 02 07 07");
        builder.applyDataType("0x1080", new ghidra.program.model.data.ArrayDataType(
            ByteDataType.dataType, 53, 1), 1);

        String listing = Files.readString(exportTo("byte-table.asm", 500));

        assertTrue(listing, listing.contains("byte[53]  {1Ah, 1Eh, 22h, 26h, 2Eh, 32h, 3Ch, "
            + "40h, 4Ch, 5Ch, 64h, 6Ch, 76h, AAh, DEh, F2h, 14h, 1Ah, 20h, 2Ch, 3Ah, "
            + "4Eh, 64h, 96h, ADh, C4h, FCh, 20h, 42h, 76h, 9Fh, F0h, 28h, 4Ah, 80h, "
            + "B7h, DFh, 15h, 1Fh, 25h, 2Bh, 31h, 61h, 66h, A8h, FEh, 30h, 86h, B3h, "
            + "DDh, 2h, 7h, 7h}"));
        assertFalse(listing.contains("|_00001081"));
        assertFalse(listing.contains("1a1e22262e"));
        assertFalse(listing.contains("opaque"));

        listing = Files.readString(exportTo("byte-table-wrapped.asm", 129));
        String first = "00001080                                  byte[53]  "
            + "{1Ah, 1Eh, 22h, 26h, 2Eh, 32h, 3Ch, 40h, 4Ch, 5Ch, 64h, 6Ch, 76h, AAh, DEh,";
        String second = "; F2h, 14h, 1Ah, 20h, 2Ch, 3Ah, 4Eh, 64h, 96h, ADh, C4h, FCh, "
            + "20h, 42h, 76h, 9Fh, F0h, 28h, 4Ah, 80h, B7h, DFh, 15h, 1Fh, 25h,";
        String third = "; 2Bh, 31h, 61h, 66h, A8h, FEh, 30h, 86h, B3h, DDh, 2h, 7h, 7h}";
        assertConsecutiveLines(listing, first, second, third);
        assertTrue(first.length() <= 129 && first.length() + " F2h,".length() > 129);
        assertTrue(second.length() <= 129 && second.length() + " 2Bh,".length() > 129);
        assertTrue(third.length() <= 129);
    }

    @Test
    public void wordDispatchTablePreservesAllValuesAndResolvedTargets() throws Exception {
        builder.setBytes("0x1080",
            "3f 0e 94 0e b0 0e 02 0f 8b 0f b5 0f bf 0f c9 0f 01 10 08 10 7e 10 "
                + "25 11 29 11 99 0f a8 0f 8f 11 2d 11 61 11 89 11 8c 11 dd 0f 68 11 "
                + "6e 11 3d 11 8d 0e 74 11 7a 11 a6 0e ab 0e 33 0e 25 0e f1 0f cc 0f");
        builder.applyDataType("0x1080", new ghidra.program.model.data.ArrayDataType(
            ghidra.program.model.data.WordDataType.dataType, 33, 2), 1);
        builder.createLabel("0x1001", "action_move");
        int transaction = program.startTransaction("dispatch ref");
        try {
            program.getReferenceManager().addMemoryReference(builder.addr("0x1090"),
                builder.addr("0x1001"), RefType.DATA, SourceType.USER_DEFINED, 0);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        String listing = Files.readString(exportTo("word-table.asm", 500));

        assertTrue(listing, listing.contains("word[33]  {E3Fh, E94h, EB0h, F02h, F8Bh, FB5h, "
            + "FBFh, FC9h, action_move, 1008h, 107Eh, 1125h, 1129h, F99h, FA8h, 118Fh, "
            + "112Dh, 1161h, 1189h, 118Ch, FDDh, 1168h, 116Eh, 113Dh, E8Dh, 1174h, "
            + "117Ah, EA6h, EABh, E33h, E25h, FF1h, FCCh}"));
        assertFalse(listing.contains("3f0e940eb00e"));
    }

    @Test
    public void scalarArrayRetainsEnumNames() throws Exception {
        var kind = new ghidra.program.model.data.EnumDataType("Action", 1);
        kind.add("MOVE", 1);
        kind.add("TAKE", 2);
        builder.setBytes("0x1080", "01 02 01 02");
        builder.applyDataType("0x1080", new ghidra.program.model.data.ArrayDataType(kind, 4, 1), 1);

        String listing = exportWholeProgram();

        assertTrue(listing, listing.contains("{MOVE, TAKE, MOVE, TAKE}"));
        assertFalse(listing.contains("01020102"));
    }

    @Test
    public void opaqueArraySummarizesBytesWithoutLosingOffcutAnnotations() throws Exception {
        builder.createMemory("payload", "0x2000", 2280);
        builder.setBytes("0x2000", "cb 8f ee 3d b7 01 10 25");
        builder.applyDataType("0x2000", new ghidra.program.model.data.ArrayDataType(
            ByteDataType.dataType, 2280, 1), 1);
        builder.createLabel("0x2010", "payload_field");
        setComment("0x2010", CommentType.EOL, "PAYLOAD_OFFCUT");
        int transaction = program.startTransaction("payload ref");
        try {
            program.getListing().getDataAt(builder.addr("0x2000"))
                .setProperty(CompleteListingWriter.OPAQUE_DATA_PROPERTY);
            program.getReferenceManager().addMemoryReference(builder.addr("0x1000"),
                builder.addr("0x2010"), RefType.READ, SourceType.USER_DEFINED, 0);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        String listing = Files.readString(exportTo("opaque.asm", 129));
        String row = lineContaining(listing, "opaque (2280 bytes)");
        assertTrue(row, row.startsWith("00002000") && row.contains("byte[2280]"));
        assertFalse(listing.contains("cb8fee3db7011025"));
        assertFalse(listing.contains("|_00002001"));
        assertTrue(listing.contains("payload_field"));
        assertTrue(listing.contains("[offcut 00002010] PAYLOAD_OFFCUT"));
        assertTrue(listing.contains("XREF offcut[1]: 00001000(R)"));
        assertTrue(lineContaining(listing, "PUSH").contains("55"));
    }

    @Test
    public void longStringRetainsItsReadableValueWithoutDuplicateHex() throws Exception {
        String value = "A readable string longer than thirty-two bytes, ending in STRING_TAIL";
        int transaction = program.startTransaction("string");
        try {
            program.getMemory().setBytes(builder.addr("0x1080"),
                (value + "\0").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            program.getListing().createData(builder.addr("0x1080"),
                ghidra.program.model.data.StringDataType.dataType, value.length() + 1);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        String listing = exportWholeProgram();

        assertConsecutiveLines(listing,
            "00001080                                  string    \"A readable string longer"
                + " than thirty-two bytes,",
            "; ending in STRING_TAIL\"");
        assertTrue("the next word must not fit on the first line",
            lineContaining(listing, "string").length() + " ending".length() > 100);
        assertFalse(listing.contains("41207265616461626c65"));
    }

    @Test
    public void uninitializedRunsStopAtAnnotationsDataAndMemoryBoundaries() throws Exception {
        builder.createUninitializedMemory("workspace", "0x2000", 0x100);
        builder.createUninitializedMemory("next_workspace", "0x2100", 0x40);
        builder.createMemory("initialized_tail", "0x2140", 0x20);
        builder.createLabel("0x2000", "workspace_start");
        builder.createLabel("0x2020", "workspace_field");
        setComment("0x2040", CommentType.EOL, "WORKSPACE_COMMENT");
        builder.applyDataType("0x2080", ghidra.program.model.data.WordDataType.dataType, 1);
        int transaction = program.startTransaction("workspace refs");
        try {
            program.getReferenceManager().addMemoryReference(builder.addr("0x2070"),
                builder.addr("0x2060"), RefType.READ, SourceType.USER_DEFINED, 0);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        String listing = exportWholeProgram();

        String[] starts = { "00002000", "00002020", "00002040", "00002060",
            "00002070", "00002082", "00002100" };
        int[] sizes = { 32, 32, 32, 16, 16, 126, 64 };
        for (int index = 0; index < starts.length; index++) {
            final String start = starts[index];
            String row = listing.lines().filter(line -> line.startsWith(start)).findFirst()
                .orElseThrow(() -> new AssertionError("missing row at " + start));
            assertTrue(row, row.contains("uninitialized (" + sizes[index] + " bytes)"));
        }
        assertEquals(7, listing.lines().filter(line -> line.contains("uninitialized (")).count());
        assertFalse(listing.lines().anyMatch(line -> line.startsWith("00002010")));
        assertTrue(listing.lines().anyMatch(line -> line.startsWith("00002080")
            && line.contains("word")));
        assertTrue(listing.contains("WORKSPACE_COMMENT"));
        assertFalse(listing.contains("[offcut"));
        for (String start : new String[] { "00002140", "00002150" }) {
            assertTrue(listing.lines().anyMatch(line -> line.startsWith(start)
                && line.contains("00000000000000000000000000000000")
                && line.endsWith("undefined")));
        }
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
     * Scalar arrays show values on their parent's row; structured elements retain their fields.
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
            record, 20, record.getLength()), 1);

        String listing = exportWholeProgram();

        assertTrue("the scalar array's own line must carry every value",
            listing.contains("{0h, 1h, 2h, 3h}"));
        assertFalse("a scalar array element must not get its own line",
            listing.contains("|_00001081"));
        assertTrue("an array element that is a structure must still be emitted",
            listing.contains("|_00001090"));
        assertTrue("and its field names must survive",
            listing.contains("from_room") && listing.contains("to_room"));
        assertTrue(listing.contains("|_000010b6"));
        assertTrue(listing.lines().anyMatch(line -> line.contains("|_00001091")
            && line.contains("to_room") && line.endsWith("Ch")));
    }

    @Test
    public void packedStructuresAndTheirArraysRetainPaddingBytes() throws Exception {
        var record = new ghidra.program.model.data.StructureDataType("AlignedRecord", 0);
        record.setPackingEnabled(true);
        record.add(ByteDataType.dataType, "tag", null);
        record.add(ghidra.program.model.data.DWordDataType.dataType, "value", null);
        builder.setBytes("0x1080", "01 a1 a2 a3 44 33 22 11");
        builder.applyDataType("0x1080", record, 1);
        assertEquals(8, program.getListing().getDataAt(builder.addr("0x1080")).getLength());
        builder.setBytes("0x1090", "01 a1 a2 a3 44 33 22 11 02 b1 b2 b3 88 77 66 55");
        builder.applyDataType("0x1090", new ghidra.program.model.data.ArrayDataType(record, 2, 8), 1);

        String listing = exportWholeProgram();

        assertTrue(listing.lines().anyMatch(line -> line.startsWith("00001080")
            && line.contains("01a1a2a344332211")));
        assertTrue(listing.contains("01a1a2a34433221102b1b2b388776655"));
        assertTrue(listing.contains("11223344h") && listing.contains("55667788h"));
    }

    /** Pointer elements carry symbolic meaning that their array's raw byte line does not. */
    @Test
    public void pointerArrayElementsAreEmitted() throws Exception {
        builder.setBytes("0x10a0",
            "80 10 00 00 00 00 00 00 90 10 00 00 00 00 00 00");
        builder.applyDataType("0x10a0", new ghidra.program.model.data.ArrayDataType(
            new PointerDataType(), 5, 8), 1);

        String listing = exportWholeProgram();

        assertTrue("the first pointer element must be emitted",
            listing.contains("|_000010a0"));
        assertTrue("the second pointer element must be emitted",
            listing.contains("|_000010a8"));
        assertTrue("the last pointer element must be emitted",
            listing.contains("|_000010c0"));
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
        int transaction = program.startTransaction("bounded equate");
        try {
            ghidra.program.model.symbol.Equate equate =
                program.getEquateTable().createEquate("BOUNDED_VALUE", 1);
            equate.addReference(builder.addr("0x1004"), 1);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        // 0x1004 begins a 5-byte MOV, so 0x1005 is interior to it.
        Response response = service.exportFullListing(
            destination.toString(), "0x1005", "0x1007", true, 100, "");
        assertTrue(response.toJson(), response instanceof Response.Ok);

        String listing = Files.readString(destination.toFile().getCanonicalFile().toPath());
        assertTrue("the containing instruction must be rendered",
            listing.contains("MOV") && listing.contains("EAX,BOUNDED_VALUE"));
        assertTrue("its equate must be defined", listing.contains("BOUNDED_VALUE equ 0x1"));
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

    /** Numeric address operands with exact named targets are reported together. */
    @Test
    public void unreferencedAddressOperandsTargetingSymbolsAreReported() throws Exception {
        // Two absolute loads with analyzer-created references removed, each retaining an exact
        // named target. One response must report both so correction takes one pass.
        builder.setBytes("0x1010", "8b 04 25 80 10 00 00");
        builder.disassemble("0x1010", 7);
        builder.createLabel("0x1080", "resolved_data");
        builder.setBytes("0x1020", "8b 04 25 90 10 00 00");
        builder.disassemble("0x1020", 7);
        builder.createLabel("0x1090", "other_resolved_data");
        int transaction = program.startTransaction("remove operand reference");
        try {
            program.getReferenceManager().removeAllReferencesFrom(builder.addr("0x1010"));
            program.getReferenceManager().removeAllReferencesFrom(builder.addr("0x1020"));
        }
        finally {
            program.endTransaction(transaction, true);
        }

        Path destination = temporaryFolder.getRoot().toPath().resolve("unreferenced.asm");
        Response response = new ExportService(provider, security).exportFullListing(
            destination.toString(), null, null, true, 100, "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertTrue(response.toJson(), response.toJson().contains("resolved_data"));
        assertTrue(response.toJson(), response.toJson().contains("other_resolved_data"));
        assertTrue(response.toJson(), response.toJson().contains("\"count\":2"));
        assertTrue("the diagnostic must not block publication", Files.exists(destination));
    }

    /** A primary reference to another address must not hide the encoded named target. */
    @Test
    public void mismatchedPrimaryReferenceStillReportsEncodedTarget() throws Exception {
        builder.setBytes("0x1010", "8b 04 25 80 10 00 00");
        builder.disassemble("0x1010", 7);
        builder.createLabel("0x1080", "actual_target");
        int transaction = program.startTransaction("replace operand reference");
        try {
            program.getReferenceManager().removeAllReferencesFrom(builder.addr("0x1010"));
            var reference = program.getReferenceManager().addMemoryReference(
                builder.addr("0x1010"), builder.addr("0x1090"), RefType.READ,
                SourceType.USER_DEFINED, 1);
            program.getReferenceManager().setPrimary(reference, true);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        Path destination = temporaryFolder.getRoot().toPath().resolve("mismatched.asm");
        Response response = new ExportService(provider, security).exportFullListing(
            destination.toString(), null, null, true, 100, "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertTrue(response.toJson(), response.toJson().contains("actual_target"));
        assertTrue("the diagnostic must not block publication", Files.exists(destination));
    }

    /** Address-valued data is reported without a reference and symbolized with one. */
    @Test
    public void addressValuedDataReportsMissingReferenceAndUsesPresentReference() throws Exception {
        builder.setBytes("0x1040", "80 10 00 00 00 00 00 00");
        builder.applyDataType("0x1040", new PointerDataType());
        builder.createLabel("0x1080", "pointed_to_data");
        int transaction = program.startTransaction("remove data reference");
        try {
            program.getReferenceManager().removeAllReferencesFrom(builder.addr("0x1040"));
        }
        finally {
            program.endTransaction(transaction, true);
        }

        Path destination = temporaryFolder.getRoot().toPath().resolve("data.asm");
        Response response = new ExportService(provider, security).exportFullListing(
            destination.toString(), null, null, true, 100, "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertTrue(response.toJson(), response.toJson().contains("pointed_to_data"));
        assertTrue(response.toJson(), response.toJson().contains("\"count\":1"));

        transaction = program.startTransaction("restore data reference");
        try {
            var reference = program.getReferenceManager().addMemoryReference(
                builder.addr("0x1040"), builder.addr("0x1080"), RefType.DATA,
                SourceType.USER_DEFINED, 0);
            program.getReferenceManager().setPrimary(reference, true);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        Path referenced = temporaryFolder.getRoot().toPath().resolve("referenced-data.asm");
        Response referencedResponse = new ExportService(provider, security).exportFullListing(
            referenced.toString(), null, null, true, 100, "");

        assertTrue(referencedResponse.toJson(), referencedResponse instanceof Response.Ok);
        assertTrue(referencedResponse.toJson(), referencedResponse.toJson().contains("\"count\":0"));
        assertTrue(Files.readString(referenced).contains("pointed_to_data"));
    }

    /** A scalar equal to a symbol address is not enough evidence to treat it as an address. */
    @Test
    public void scalarMatchingSymbolAddressStillExports() throws Exception {
        builder.setBytes("0x1010", "b8 80 10 00 00");
        builder.disassemble("0x1010", 5);
        builder.createLabel("0x1080", "coincidental_symbol");
        int transaction = program.startTransaction("remove scalar reference");
        try {
            program.getReferenceManager().removeAllReferencesFrom(builder.addr("0x1010"));
        }
        finally {
            program.endTransaction(transaction, true);
        }

        String listing = exportWholeProgram();

        String instruction = listing.lines()
            .filter(line -> line.startsWith("00001010"))
            .findFirst()
            .orElseThrow();
        assertTrue(instruction, instruction.contains("MOV") && instruction.contains("1080"));
        assertFalse(instruction, instruction.contains("coincidental_symbol"));
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
        builder.applyDataType("0x1080", new ghidra.program.model.data.ArrayDataType(
            ByteDataType.dataType, 64, 1), 1);
        ProgramDB spied = Mockito.spy(program);
        Memory shortReading = Mockito.spy(program.getMemory());
        Mockito.doReturn(shortReading).when(spied).getMemory();
        Mockito.doReturn(1).when(shortReading)
            .getBytes(Mockito.any(Address.class), Mockito.any(byte[].class));
        for (String[] range : new String[][] {
            { "0x1001", "0x1003" }, { "0x1080", "0x10bf" } }) {
            ExportService.CompleteListingRunner runner =
                new ExportService.CompleteListingRunner(100);
            boolean exported = runner.export(temporaryFolder.newFile(), spied,
                new ghidra.program.model.address.AddressSet(
                    builder.addr(range[0]), builder.addr(range[1])), TaskMonitor.DUMMY);

            assertFalse("a short read must not produce an artifact", exported);
            assertTrue(runner.diagnostic(), runner.diagnostic().contains("short read"));
        }
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
     * hard wrapping. The content audit unfolds continuation lines before checking the body.
     */
    @Test
    public void controlCharactersInACommentSurviveWordWrapping() throws Exception {
        String comment = "PETSCII \u0093 clears the screen, \u0007 rings the bell, "
            + "\u001d moves the cursor right\u001d";
        setComment("0x1000", CommentType.EOL, comment);

        String listing = exportWholeProgram();

        assertTrue("the exact control sequence must survive",
            unfoldWordWrappedEolParagraph(listing, "PETSCII").endsWith(comment));
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
            sink.toString().lines().map(line -> line.contains("SWALLOWED") ? "" : line));
        assertTrue("the lost plate body must be reported, not counted as emitted: " + missing,
            missing != null && missing.contains("SWALLOWED plate line"));
    }

    /** A C64 cursor-control-only line remains part of the artifact completeness audit. */
    @Test
    public void controlOnlyCommentLineIsAudited() throws Exception {
        setComment("0x1000", CommentType.PLATE, "\u001d");
        CompleteListingWriter writer = new CompleteListingWriter(program, 100);
        StringBuilder sink = new StringBuilder();
        try (PrintWriter out = new PrintWriter(new CollectingWriter(sink))) {
            writer.write(out, program.getMemory());
        }

        assertNull("a complete artifact must not be reported as short",
            writer.shortfall(sink.toString().lines()));
        String missing = writer.shortfall(
            sink.toString().lines().map(line -> line.contains("\u001d") ? "" : line));
        assertTrue("the lost control-only line must be reported: " + missing,
            missing != null && missing.contains("\u001d"));
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
            sink.toString().lines().map(line -> line.contains("XREF") ? "" : line));
        assertTrue("the lost reference must be reported: " + missing,
            missing != null && missing.contains("00001100"));
    }

    /** Outgoing groups must name their destinations, not repeat the source instruction. */
    @Test
    public void outgoingReferenceNamesItsDestination() throws Exception {
        int transaction = program.startTransaction("outgoing ref");
        try {
            program.getReferenceManager().addMemoryReference(
                builder.addr("0x1000"), builder.addr("0x1100"),
                RefType.READ, SourceType.USER_DEFINED, 0);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        String listing = exportWholeProgram();

        assertTrue(listing, listing.contains("XREF to[1]: 00001100(R)"));
        assertFalse(listing, listing.contains("XREF from"));
    }

    /**
     * Ghidra represents an external entry point as a synthetic reference whose source address
     * is the named external location {@code Entry Point}. The space is part of the address
     * text, so the content audit must not split the rendered {@code Entry Point(*)} token and
     * falsely reject an otherwise complete export.
     */
    @Test
    public void entryPointReferenceWithSpacePassesContentAudit() throws Exception {
        int transaction = program.startTransaction("entry point");
        try {
            program.getSymbolTable().addExternalEntryPoint(
                builder.addr("0x1000"));
        }
        finally {
            program.endTransaction(transaction, true);
        }

        String listing = exportWholeProgram();

        assertTrue("the synthetic entry-point reference must be emitted",
            listing.contains("Entry Point(*)"));
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

    private static void assertConsecutiveLines(String listing, String... expected) {
        String sequence = String.join(System.lineSeparator(), expected);
        assertTrue("missing consecutive lines:\n" + sequence, listing.contains(sequence));
    }

    private static String lineContaining(String listing, String text) {
        return listing.lines()
            .filter(line -> line.contains(text))
            .findFirst()
            .orElseThrow(() -> new AssertionError("listing has no line containing: " + text));
    }

    private static String unfoldWordWrappedEolParagraph(String listing, String startText) {
        java.util.List<String> lines = listing.lines().toList();
        int start = 0;
        while (start < lines.size() && !lines.get(start).contains(startText)) {
            start++;
        }
        if (start == lines.size()) {
            throw new AssertionError("listing has no EOL paragraph containing: " + startText);
        }
        StringBuilder unfolded = new StringBuilder(lines.get(start));
        for (int index = start + 1;
                index < lines.size() && lines.get(index).startsWith("; "); index++) {
            unfolded.append(lines.get(index).substring(1));
        }
        return unfolded.toString();
    }

    private void setLocalComment(String text) throws Exception {
        Function function = program.getFunctionManager().getFunctionAt(builder.addr("0x1000"));
        builder.createLocalVariable(function, "fixture_local", ByteDataType.dataType, -8);
        int transaction = program.startTransaction("variable comment");
        try {
            Variable local = java.util.Arrays.stream(function.getLocalVariables())
                .filter(variable -> "fixture_local".equals(variable.getName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                    "fixture_local was not attached to the function"));
            local.setComment(text);
        }
        finally {
            program.endTransaction(transaction, true);
        }
    }

    private String exportWholeProgram() throws Exception {
        return Files.readString(exportTo("listing.asm"));
    }

    private Path exportTo(String name) throws Exception {
        return exportTo(name, 100);
    }

    private Path exportTo(String name, int columnWidth) throws Exception {
        Path destination = temporaryFolder.getRoot().toPath().resolve(name);
        ExportService service = new ExportService(provider, security);
        Response response = service.exportFullListing(
            destination.toString(), null, null, true, columnWidth, "");
        assertTrue(response.toJson(), response instanceof Response.Ok);
        return destination.toFile().getCanonicalFile().toPath();
    }
}
