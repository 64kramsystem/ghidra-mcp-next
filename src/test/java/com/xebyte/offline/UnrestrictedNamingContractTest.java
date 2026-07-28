package com.xebyte.offline;

import com.xebyte.core.GeneratedSymbolNames;
import java.util.List;
import junit.framework.TestCase;

public class UnrestrictedNamingContractTest extends TestCase {
    public void testGeneratedNameDetectionIsReadOnlyAndGeneric() {
        assertTrue(GeneratedSymbolNames.isGenerated("FUN_401000"));
        assertTrue(GeneratedSymbolNames.isGenerated("sub_401000"));
        assertTrue(GeneratedSymbolNames.isGenerated("UNK_401000"));
        assertTrue(GeneratedSymbolNames.isGenerated("FLOAT_401000"));
        assertTrue(GeneratedSymbolNames.isGenerated("DAT_00401000.1"));
        assertTrue(GeneratedSymbolNames.isGenerated("PTR_DAT_00401000"));
        assertTrue(GeneratedSymbolNames.isGenerated("s_Registration_data_00401000"));
        assertTrue(GeneratedSymbolNames.isGenerated("u_Wine_loader_00401000"));
        assertTrue(GeneratedSymbolNames.isGenerated("Ordinal_12"));
        assertTrue(GeneratedSymbolNames.isGenerated(null));
        assertTrue(GeneratedSymbolNames.isGenerated("  "));
        assertFalse(GeneratedSymbolNames.isGenerated("FileZilla_ParseRegistration"));
        assertFalse(GeneratedSymbolNames.isGenerated("wine_server_call"));
    }

    public void testCommentGeneratedNameScannerUsesWholeTokensAndKnownPrefixes() {
        String comment = "DAT_2942 PTR_DAT_00401000 EXT_401000 OFF_401020 "
                + "BYTE_00402000 s_Message_00403000 dat_beef "
                + "SUB_SND_PLAYER__1605 "
                + "MY_DAT_2942 DAT_123 DAT_2942x DAT_2942.1";

        assertEquals(
            List.of("DAT_2942", "PTR_DAT_00401000", "EXT_401000", "OFF_401020",
                "BYTE_00402000", "s_Message_00403000", "dat_beef",
                "SUB_SND_PLAYER__1605"),
            GeneratedSymbolNames.findCommentNameMentions(comment).stream()
                .map(GeneratedSymbolNames.CommentNameMention::name)
                .toList());
    }
}
