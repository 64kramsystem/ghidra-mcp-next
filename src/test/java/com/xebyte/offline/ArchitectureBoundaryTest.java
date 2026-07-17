package com.xebyte.offline;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import junit.framework.TestCase;

public class ArchitectureBoundaryTest extends TestCase {
    private static final Path ROOT = Path.of(System.getProperty("user.dir"));

    private static String maintainedJava() throws IOException {
        StringBuilder out = new StringBuilder();
        try (var paths = Files.walk(ROOT.resolve("src/main/java"))) {
            for (Path path : paths.filter(p -> p.toString().endsWith(".java")).toList()) {
                out.append(Files.readString(path)).append('\n');
            }
        }
        return out.toString();
    }

    public void testRepositoryServerDependenciesAreAbsent() throws Exception {
        String source = maintainedJava();
        for (String forbidden : List.of(
                "GhidraServerManager", "GhidraMCPAuthenticator",
                "GhidraMCPAuthInitializer", "DocumentationHashService",
                "ghidra.framework.client.")) {
            assertFalse("forbidden repository-server dependency: " + forbidden,
                    source.contains(forbidden));
        }
    }

    public void testSecurityConfigRemainsAvailable() throws Exception {
        assertTrue(Files.isRegularFile(ROOT.resolve(
                "src/main/java/com/xebyte/core/SecurityConfig.java")));
        String source = Files.readString(ROOT.resolve(
                "src/main/java/com/xebyte/core/SecurityConfig.java"));
        assertTrue(source.contains("GHIDRA_MCP_ALLOW_SCRIPTS"));
        assertTrue(source.contains("GHIDRA_MCP_FILE_ROOT"));
        assertTrue(source.contains("GHIDRA_MCP_AUTH_TOKEN"));
    }

    public void testRepositoryServerParsingHelpersAreAbsent() throws Exception {
        String source = Files.readString(ROOT.resolve(
                "src/main/java/com/xebyte/headless/GhidraMCPHeadlessServer.java"));
        assertFalse(source.contains("parseIntOrDefault"));
        assertFalse(source.contains("parseDoubleOrDefault"));
    }
}
