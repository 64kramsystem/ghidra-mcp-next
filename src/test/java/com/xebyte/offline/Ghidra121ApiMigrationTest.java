package com.xebyte.offline;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import junit.framework.TestCase;

/** Source-level regression guards for the Ghidra 12.1 API migration. */
public class Ghidra121ApiMigrationTest extends TestCase {
    private static final Path MAIN_SOURCE =
            Path.of(System.getProperty("user.dir"), "src", "main", "java");

    private static String maintainedJava() throws IOException {
        StringBuilder out = new StringBuilder();
        try (var paths = Files.walk(MAIN_SOURCE)) {
            for (Path path : paths.filter(p -> p.toString().endsWith(".java")).toList()) {
                out.append(Files.readString(path)).append('\n');
            }
        }
        return out.toString();
    }

    public void testRemovedGhidraApisAreAbsent() throws Exception {
        String source = maintainedJava();
        for (String forbidden : List.of(
                "CodeUnit.PRE_COMMENT",
                "CodeUnit.EOL_COMMENT",
                "CodeUnit.PLATE_COMMENT",
                "AutoImporter",
                "getPrimaryDomainObject()",
                "EmulatorHelper")) {
            assertFalse("legacy Ghidra API remains: " + forbidden,
                    source.contains(forbidden));
        }
    }

    public void testDeprecatedProjectJsonHelpersAreAbsent() throws Exception {
        String source = maintainedJava();
        for (String forbidden : List.of(
                "ServiceUtils.escapeJson",
                "ServiceUtils.serializeListToJson",
                "ServiceUtils.serializeMapToJson")) {
            assertFalse("deprecated JSON helper remains: " + forbidden,
                    source.contains(forbidden));
        }
    }

    public void testProgramLoaderResultsHaveExplicitOwnership() throws Exception {
        for (String relativePath : List.of(
                "com/xebyte/headless/HeadlessProgramProvider.java",
                "com/xebyte/core/ProgramScriptService.java")) {
            String source = Files.readString(MAIN_SOURCE.resolve(relativePath));
            assertTrue(relativePath + " must use the Ghidra 12.1 ProgramLoader builder",
                    source.contains("ProgramLoader.builder()"));
            assertTrue(relativePath + " must close LoadResults with try-with-resources",
                    source.contains("try (LoadResults<Program>"));
            assertTrue(relativePath + " must add an explicit retained Program consumer",
                    source.contains("getPrimaryDomainObject("));
        }

        String guiSource = Files.readString(
                MAIN_SOURCE.resolve("com/xebyte/core/ProgramScriptService.java"));
        assertTrue("GUI imports must release their temporary service consumer",
                guiSource.contains("program.release(this)"));
    }
}
