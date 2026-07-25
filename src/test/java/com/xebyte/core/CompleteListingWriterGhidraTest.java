package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.xebyte.headless.HeadlessProgramProvider;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

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
