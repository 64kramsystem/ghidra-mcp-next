package com.xebyte.offline;

import com.xebyte.headless.HeadlessProgramProvider.ProgramLoadResult;
import junit.framework.TestCase;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;

/**
 * Unit tests for the structured diagnostic value classes added for
 * local headless project open path.
 *
 * The full {@code loadProgramFromProjectDetailed} path needs a real Ghidra
 * Project to exercise, but the failure-result builders and local diagnostic
 * shape can be regressed offline. These tests pin the
 * shape so the endpoint response stays a contract the operator can rely
 * on — without them, a typo in {@code notFound()}'s message format would
 * break every error path's diagnostic without anyone noticing.
 */
public class ProgramLoadResultTest extends TestCase {

    // -------------------------------------------------------------------
    // ProgramLoadResult.success
    // -------------------------------------------------------------------

    public void testSuccessHasNoErrorAndCarriesProgram() {
        ProgramLoadResult r = ProgramLoadResult.success(null);  // null is ok for shape test
        assertTrue("success flag", r.success);
        assertNull("message must be null on success", r.message);
        assertNull("availablePaths null on success", r.availablePaths);
    }

    // -------------------------------------------------------------------
    // ProgramLoadResult.failure
    // -------------------------------------------------------------------

    public void testFailureCarriesErrorOnly() {
        ProgramLoadResult r = ProgramLoadResult.failure("boom");
        assertFalse("success flag false", r.success);
        assertNull("program null on failure", r.program);
        assertEquals("message stored verbatim", "boom", r.message);
        assertNull("availablePaths absent for generic failure", r.availablePaths);
    }

    // -------------------------------------------------------------------
    // ProgramLoadResult.notFound
    // -------------------------------------------------------------------

    public void testNotFoundMentionsRequestedPath() {
        ProgramLoadResult r = ProgramLoadResult.notFound(
            "/Vanilla/1.13d/D2Common.dll",
            Collections.emptyList());
        assertFalse(r.success);
        assertTrue("message mentions requested path",
            r.message.contains("/Vanilla/1.13d/D2Common.dll"));
        assertTrue("message mentions empty-project case",
            r.message.contains("no program files"));
    }

    public void testNotFoundPreviewsFirstFiveAvailable() {
        ProgramLoadResult r = ProgramLoadResult.notFound(
            "/wrong/path",
            Arrays.asList(
                "/a/1.dll", "/a/2.dll", "/a/3.dll", "/a/4.dll", "/a/5.dll",
                "/a/6.dll", "/a/7.dll"
            ));
        assertFalse(r.success);
        // Total count surfaced
        assertTrue("count surfaced", r.message.contains("7 program file"));
        // First five included
        assertTrue("preview shows first available", r.message.contains("/a/1.dll"));
        assertTrue("preview shows fifth available", r.message.contains("/a/5.dll"));
        // Sixth NOT shown — preview capped at 5
        assertFalse("preview caps at five", r.message.contains("/a/6.dll"));
    }

    public void testNotFoundUnderFivePreviewsAll() {
        ProgramLoadResult r = ProgramLoadResult.notFound(
            "/wrong/path",
            Arrays.asList("/a/1.dll", "/a/2.dll"));
        assertTrue("count surfaced", r.message.contains("2 program file"));
        assertTrue("preview shows /a/1.dll", r.message.contains("/a/1.dll"));
        assertTrue("preview shows /a/2.dll", r.message.contains("/a/2.dll"));
    }

    public void testNotFoundCarriesAvailablePaths() {
        ProgramLoadResult r = ProgramLoadResult.notFound(
            "/wrong/path",
            Arrays.asList("/a/1.dll", "/a/2.dll"));
        assertEquals("availablePaths preserved as-is", 2, r.availablePaths.size());
        assertEquals("/a/1.dll", r.availablePaths.get(0));
    }

    public void testNotFoundHandlesNullAvailableList() {
        // Edge case: collectProgramPaths threw and we passed null.
        // Shouldn't NPE in the formatter.
        ProgramLoadResult r = ProgramLoadResult.notFound(
            "/wrong/path",
            null);
        assertFalse(r.success);
        assertNotNull("message always populated", r.message);
        assertTrue(r.message.contains("/wrong/path"));
        // No paths case — neither "no program files" nor "contains N program"
        // should appear (it's the "no available list at all" branch).
        assertFalse(r.message.contains("no program files"));
        assertFalse(r.message.contains("program file(s)"));
    }

    public void testHeadlessDiagnosticsAreLocalOnly() throws Exception {
        String source = Files.readString(Path.of(System.getProperty("user.dir"),
                "src/main/java/com/xebyte/headless/HeadlessManagementService.java"));
        assertTrue(source.contains("project_location"));
        assertTrue(source.contains("loaded_programs"));
        assertTrue(source.contains("requested_path"));
        assertTrue(source.contains("available_program_paths"));
        assertFalse(source.contains("project_server_bound"));
        assertFalse(source.contains("serverHint"));
        assertFalse(source.contains("server_repo"));
    }
}
