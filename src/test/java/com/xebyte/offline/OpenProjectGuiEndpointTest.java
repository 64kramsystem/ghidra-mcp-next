package com.xebyte.offline;

import junit.framework.TestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source-level invariants for GUI project-lifecycle routes.
 *
 * <p>The headless server has had {@code /open_project} since v4.x. The
 * GUI plugin gained its own implementation as part of Option C — a
 * "GUI but no CodeBrowser" mode where automation can point Ghidra at a
 * project programmatically and decide separately whether to spawn a
 * CodeBrowser. The GUI handler accepts an optional {@code headless}
 * boolean (default true) and an optional {@code program} path used only
 * when {@code headless == false}.
 *
 * <p>These are static-analysis checks rather than integration tests
 * because opening + switching projects requires a live FrontEnd tool
 * with a real {@code .gpr} on disk — state CI can't stand up.
 */
public class OpenProjectGuiEndpointTest extends TestCase {

    private String readUtf8(String relativePath) throws IOException {
        return new String(
                Files.readAllBytes(Paths.get(relativePath)),
                StandardCharsets.UTF_8);
    }

    public void testGuiServiceRegistersOpenProjectRoute() throws IOException {
        String src = readUtf8("src/main/java/com/xebyte/core/GuiProjectService.java");
        Pattern p = Pattern.compile(
                "@McpTool\\s*\\(\\s*path\\s*=\\s*\"/open_project\"",
                Pattern.MULTILINE);
        assertTrue(
                "GuiProjectService must annotation-register /open_project so its "
                        + "handler and schema cannot drift.",
                p.matcher(src).find());
    }

    public void testGuiServiceRegistersCreateProjectRouteAndParameters() throws IOException {
        String src = readUtf8("src/main/java/com/xebyte/core/GuiProjectService.java");
        Pattern routeBlock = Pattern.compile(
                "@McpTool\\s*\\(\\s*path\\s*=\\s*\"/create_project\"[\\s\\S]*?"
                        + "public\\s+Response\\s+createProject\\s*\\(",
                Pattern.MULTILINE);
        Matcher m = routeBlock.matcher(src);
        assertTrue("Expected annotation-scanned /create_project on GuiProjectService.",
                m.find());

        String block = src.substring(m.start(), Math.min(src.length(), m.end() + 600));
        assertTrue("Route must read parentDir.", block.contains("\"parentDir\""));
        assertTrue("Route must read name.", block.contains("\"name\""));
    }

    public void testOpenProjectHandlerReadsHeadlessAndProgramParams() throws IOException {
        String src = readUtf8("src/main/java/com/xebyte/core/GuiProjectService.java");
        // The annotation-scanned endpoint should bind the body, default
        // `headless` to true, and forward the optional `program` to the
        // existing project-opening helper.
        Pattern routeBlock = Pattern.compile(
                "@McpTool\\s*\\(\\s*path\\s*=\\s*\"/open_project\"[\\s\\S]*?"
                        + "public\\s+Response\\s+openProjectEndpoint\\s*\\(",
                Pattern.MULTILINE);
        Matcher m = routeBlock.matcher(src);
        assertTrue("Expected annotation-scanned /open_project endpoint",
                m.find());
        String block = src.substring(m.start(), Math.min(src.length(), m.end() + 900));

        assertTrue(
                "Route must read the `headless` body param (with true as the default).",
                block.contains("\"headless\""));
        assertTrue(
                "Default for headless must be true so existing automation "
                        + "doesn't spontaneously start launching CodeBrowsers.",
                block.contains("defaultValue = \"true\""));
        assertTrue(
                "Route must read the optional `program` param so non-headless "
                        + "opens can auto-launch CodeBrowser for a specific file.",
                block.contains("\"program\""));
    }

    public void testOpenProjectHelperRunsOnEDT() throws IOException {
        String src = readUtf8("src/main/java/com/xebyte/core/GuiProjectService.java");
        Pattern decl = Pattern.compile(
                "public\\s+String\\s+openProject\\s*\\(\\s*String[^)]*\\)\\s*\\{",
                Pattern.MULTILINE);
        Matcher m = decl.matcher(src);
        assertTrue(
                "GuiProjectService must expose the shared openProject helper.",
                m.find());

        int braceStart = m.end() - 1;
        int depth = 1;
        int j = braceStart + 1;
        while (j < src.length() && depth > 0) {
            char c = src.charAt(j++);
            if (c == '{') depth++;
            else if (c == '}') depth--;
        }
        String body = src.substring(braceStart, j);

        assertTrue(
                "openProject must invoke ProjectManager.openProject(locator, ...) "
                        + "— that's the canonical API for opening into the FrontEnd.",
                body.contains(".openProject(locator"));
        assertTrue(
                "openProject must run the open/close on the EDT — FrontEnd "
                        + "state updates expect Swing.",
                body.contains("SwingUtilities.invokeAndWait"));
        assertTrue(
                "openProject must call AppInfo.setActiveProject so the FrontEnd "
                        + "UI reflects the new project.",
                body.contains("AppInfo.setActiveProject"));
        assertTrue(
                "openProject must short-circuit when the requested project is "
                        + "already the active one — silent re-open would needlessly "
                        + "close and reopen the same project, dropping CodeBrowser state.",
                body.contains("already_open"));
    }

    public void testLegacyManualUdsProjectRoutesAreRemoved() throws IOException {
        String src = readUtf8("src/main/java/com/xebyte/core/GuiProjectService.java");
        assertFalse("Project routes must have one annotation-scanned implementation.",
                src.contains("registerUdsEndpoints"));
        assertFalse("Project routes must not retain manual UDS contexts.",
                src.contains("server.createContext"));
    }

    public void testBothUdsStartupPathsInstallGuiProjectRoutes() throws IOException {
        String src = readUtf8("src/main/java/com/xebyte/GhidraMCPPlugin.java");
        Pattern registration = Pattern.compile(
                "\\bregisterTool\\s*\\(\\s*tool\\s*\\)");
        assertEquals("Initial startup and menu restart must use scanned UDS routes.",
                2, countMatches(src, registration));
        assertFalse("UDS startup must not overlay manual project routes on scanned routes.",
                src.contains("GuiProjectService::registerUdsEndpoints"));
    }

    public void testCreateProjectHasOneCatalogEntry() throws IOException {
        String catalog = readUtf8("tests/endpoints.json");
        assertEquals("The existing catalogued endpoint must remain unique.",
                1, countOccurrences(catalog, "\"path\": \"/create_project\""));
    }

    public void testCatalogIncludesOpenProjectParams() throws IOException {
        String catalog = readUtf8("tests/endpoints.json");
        // The catalog has a single /open_project entry shared with the
        // headless server. The GUI side added two optional params
        // (`headless`, `program`) — the entry must list both so the
        // bridge schema and parity test see them.
        Pattern entry = Pattern.compile(
                "\\{\\s*\"path\"\\s*:\\s*\"/open_project\"[^}]*?\"params\"\\s*:\\s*\\[(?<params>[^\\]]*)\\]",
                Pattern.DOTALL);
        Matcher m = entry.matcher(catalog);
        assertTrue("tests/endpoints.json must list /open_project.", m.find());
        String params = m.group("params");
        assertTrue(
                "/open_project params must include 'path' (required, both modes).",
                params.contains("\"path\""));
        assertTrue(
                "/open_project params must include 'headless' (GUI mode adds it).",
                params.contains("\"headless\""));
        assertTrue(
                "/open_project params must include 'program' (GUI mode optional auto-launch).",
                params.contains("\"program\""));
    }

    private int countOccurrences(String text, String needle) {
        int count = 0;
        int offset = 0;
        while ((offset = text.indexOf(needle, offset)) >= 0) {
            count++;
            offset += needle.length();
        }
        return count;
    }

    private int countMatches(String text, Pattern pattern) {
        int count = 0;
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            count++;
        }
        return count;
    }
}
