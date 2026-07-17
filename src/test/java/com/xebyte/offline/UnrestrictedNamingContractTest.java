package com.xebyte.offline;

import com.xebyte.core.GeneratedSymbolNames;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import junit.framework.TestCase;

public class UnrestrictedNamingContractTest extends TestCase {
    private static final Path ROOT = Path.of(System.getProperty("user.dir"));

    public void testMutationServicesDoNotUseRemovedNamingPolicy() throws Exception {
        for (String file : List.of("FunctionService.java", "SymbolLabelService.java",
                "DataTypeService.java", "CommentService.java")) {
            String source = Files.readString(ROOT.resolve(
                    "src/main/java/com/xebyte/core/" + file));
            assertFalse(file, source.contains("NamingConventions"));
            assertFalse(file, source.contains("NamingPolicy"));
        }
    }

    public void testStructFieldsAreNotImplicitlyPrefixed() throws Exception {
        String source = Files.readString(ROOT.resolve(
                "src/main/java/com/xebyte/core/DataTypeService.java"));
        assertFalse(source.contains("applyStructFieldNamingPolicy"));
    }

    public void testGhidraInvalidInputHandlingRemains() throws Exception {
        String symbols = Files.readString(ROOT.resolve(
                "src/main/java/com/xebyte/core/SymbolLabelService.java"));
        assertTrue(symbols.contains("InvalidInputException"));
        assertTrue(symbols.contains("Response.err"));
    }

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
}
