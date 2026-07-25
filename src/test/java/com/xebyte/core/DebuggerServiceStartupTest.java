package com.xebyte.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Regression guards for Debugger tool auto-start.
 *
 * <p>These pin down three defects that made the whole debugger surface unreachable over MCP on a
 * machine where the Debugger tool simply was not open yet:
 *
 * <ol>
 * <li>startDebuggerTool fell back to the CodeBrowser template, which can never provide
 *     DebuggerTraceManagerService -- so it opened a spurious second CodeBrowser window and then
 *     failed anyway.</li>
 * <li>The service wait was 20 x 250ms = 5s, while the code's own comment on debugger_launch notes
 *     that a cold start "takes longer than 20s". The wait therefore always expired.</li>
 * <li>Endpoints that never attempt a start reported "could not auto-start a Debugger tool",
 *     which sent debugging down entirely the wrong path.</li>
 * </ol>
 *
 * <p>The launch path itself needs a live Ghidra tool and is covered by integration tests; these
 * assertions cover the parts that are decidable statically.
 */
public class DebuggerServiceStartupTest {

    @Test
    public void onlyTheDebuggerTemplateIsEverLaunched() {
        assertEquals("only the Debugger template provides DebuggerTraceManagerService",
                java.util.List.of("Debugger"), DebuggerService.DEBUGGER_TOOL_TEMPLATES);
    }

    @Test
    public void codeBrowserIsNotAFallbackTemplate() {
        assertFalse("launching CodeBrowser opens a spurious window and cannot satisfy the wait",
                DebuggerService.DEBUGGER_TOOL_TEMPLATES.contains("CodeBrowser"));
    }

    @Test
    public void serviceWaitOutlastsAColdStart() {
        long budgetMs = DebuggerService.TOOL_SERVICE_POLL_ATTEMPTS
                * DebuggerService.TOOL_SERVICE_POLL_INTERVAL_MS;
        assertTrue("cold start can exceed 20s; budget was " + budgetMs + "ms", budgetMs >= 20_000L);
    }

    @Test
    public void serviceWaitStaysUnderTheCallerTimeout() {
        long budgetMs = DebuggerService.TOOL_SERVICE_POLL_ATTEMPTS
                * DebuggerService.TOOL_SERVICE_POLL_INTERVAL_MS;
        assertTrue("must finish inside the callers' 60s timeout; budget was " + budgetMs + "ms",
                budgetMs <= 60_000L);
    }

    @Test
    public void notRunningMessageDoesNotClaimAFailedStartAttempt() {
        String msg = DebuggerService.MSG_NO_DEBUGGER.toLowerCase();
        assertFalse("endpoints that never try to start must not report a failed auto-start",
                msg.contains("could not auto-start"));
    }

    @Test
    public void notRunningMessageNamesAWayToStartTheTool() {
        String msg = DebuggerService.MSG_NO_DEBUGGER;
        assertTrue("must tell the caller which endpoints bootstrap the tool",
                msg.contains("debugger_launch_offers") || msg.contains("debugger_launch"));
    }

    @Test
    public void theTwoFailureMessagesAreDistinguishable() {
        assertFalse("not-running and start-failed have different causes and different fixes",
                DebuggerService.MSG_NO_DEBUGGER.equals(DebuggerService.MSG_DEBUGGER_START_FAILED));
    }
}
