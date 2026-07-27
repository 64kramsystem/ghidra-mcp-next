package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

/**
 * How get_references_into_range renders the source of a reference, against a real program.
 *
 * <p>These exist because the mock-based suite could not catch the defect they cover. Its code
 * units are Mockito objects whose {@code getMnemonicString()} returns null, so every rendering
 * assertion there exercises the {@code toString()} fallback and never Ghidra's formatter. A
 * cross-space rendering regression shipped through a green suite and was only caught by running
 * the endpoint against the program it was built for.</p>
 *
 * <p>The shape mirrors that program: an overlay occupying the same offsets as the base space,
 * with references crossing between them.</p>
 */
public class XrefRangeRenderGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;
    private XrefCallGraphService service;

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
        builder = new ProgramBuilder("xref-range-render", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x200);
        // CALL rel32, then a RET, so 0x1000 is a real instruction with one operand.
        builder.setBytes("0x1000", "e8 00 00 00 00 c3");
        builder.disassemble("0x1000", 6);

        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        service = new XrefCallGraphService(provider, new DirectThreadingStrategy());
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    private Address overlayAddress(String overlayName, long offset) {
        return program.getAddressFactory().getAddressSpace(overlayName).getAddress(offset);
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> rows(Response response) {
        assertTrue(response.toJson(), response instanceof Response.Ok);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) response).data();
        return (List<Map<String, Object>>) body.get("references");
    }

    /**
     * The regression this file exists for. A call whose operand reference lands in an overlay
     * must render the overlay-qualified symbol.
     *
     * <p>{@code CodeUnitFormat.getRepresentationString(CodeUnit)} does not resolve an operand
     * across address spaces. On the real program {@code RAM:$9910 JMP $97A9} into the SND_PLAYER
     * overlay rendered as a bare offset through both that overload and the
     * {@code CodeUnit.toString()} it replaced; rendering operand by operand, as the full-listing
     * writer does, yields {@code JMP SND_PLAYER:SND_V1_STREAM_ADVANCE3}.</p>
     *
     * <p>The reference must be PRIMARY on the operand for any of that to happen, which is why
     * this fixture removes the operand's own reference before adding the overlay one.</p>
     */
    @Test
    public void anOperandReachingIntoAnOverlayRendersTheOverlayQualifiedSymbol() throws Exception {
        builder.createOverlayMemory("SND_PLAYER", "0x1000", 0x20);
        Address target = overlayAddress("SND_PLAYER", 0x1008);

        int transaction = program.startTransaction("overlay call");
        try {
            program.getSymbolTable().createLabel(target, "SND_TICK", SourceType.USER_DEFINED);
            // Replaces the operand's own reference, exactly as retargeting a cross-space call
            // site does in the real project.
            program.getReferenceManager().removeAllReferencesFrom(builder.addr("0x1000"));
            program.getReferenceManager().addMemoryReference(builder.addr("0x1000"), target,
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        List<Map<String, Object>> rows = rows(service.getReferencesIntoRange(
            "SND_PLAYER:1000", "SND_PLAYER:101f", 2000, 0, ""));

        assertEquals(1, rows.size());
        String rendered = (String) rows.get(0).get("from_instruction");
        assertTrue("the operand must resolve to the overlay symbol, got: " + rendered,
            rendered.contains("SND_TICK"));
        assertTrue("the mnemonic must still be there, got: " + rendered,
            rendered.startsWith("CALL"));
        // The exact failure mode: a bare offset instead of the symbol.
        assertFalse("must not degrade to a bare offset, got: " + rendered,
            rendered.matches("(?i)CALL\\s+0?x?0*1008h?"));
    }

    /**
     * A reference recorded from inside an aggregate. The whole unit renders as the array and
     * names no element, so the row has to show the element holding the in-range address — the
     * dispatch-table case, where every slot is a separate handler.
     */
    @Test
    public void aReferenceFromInsideAnArrayRendersTheElementNotTheArray() throws Exception {
        builder.createOverlayMemory("SND_PLAYER", "0x1000", 0x20);
        Address handler = overlayAddress("SND_PLAYER", 0x1010);

        int transaction = program.startTransaction("dispatch table");
        try {
            program.getSymbolTable().createLabel(handler, "SND_INIT_ALL", SourceType.USER_DEFINED);
            // A word[4] table at 0x1100; the reference comes from its second slot.
            program.getListing().createData(builder.addr("0x1100"),
                new ArrayDataType(WordDataType.dataType, 4, 2));
            program.getReferenceManager().addMemoryReference(builder.addr("0x1102"), handler,
                RefType.DATA, SourceType.USER_DEFINED, -1);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        List<Map<String, Object>> rows = rows(service.getReferencesIntoRange(
            "SND_PLAYER:1010", "SND_PLAYER:1010", 2000, 0, ""));

        assertEquals(1, rows.size());
        Map<String, Object> row = rows.get(0);
        assertEquals("data", row.get("from_kind"));
        String rendered = (String) row.get("from_instruction");
        assertFalse("the whole array names no slot, got: " + rendered,
            rendered.startsWith("word[4]"));
        assertTrue("the element must be rendered, got: " + rendered,
            rendered.startsWith("word") || rendered.startsWith("dw"));
    }

    /**
     * An instruction whose operand stays in the base space still renders its symbol. Guards the
     * ordinary path against a fix aimed only at the cross-space one.
     */
    @Test
    public void anOperandInTheBaseSpaceStillRendersItsSymbol() throws Exception {
        int transaction = program.startTransaction("base call");
        try {
            program.getSymbolTable().createLabel(builder.addr("0x1100"), "LOCAL_TARGET",
                SourceType.USER_DEFINED);
            program.getReferenceManager().removeAllReferencesFrom(builder.addr("0x1000"));
            program.getReferenceManager().addMemoryReference(builder.addr("0x1000"),
                builder.addr("0x1100"), RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        List<Map<String, Object>> rows =
            rows(service.getReferencesIntoRange("0x1100", "0x1100", 2000, 0, ""));

        assertEquals(1, rows.size());
        String rendered = (String) rows.get(0).get("from_instruction");
        assertTrue("expected the local symbol, got: " + rendered,
            rendered.contains("LOCAL_TARGET"));
    }
}
