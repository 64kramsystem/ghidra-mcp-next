package com.xebyte.core;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import java.util.List;

import org.junit.Test;

import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;

/**
 * Regression guards for launch-offer selection.
 *
 * <p>Connector-style offers -- the VICE C64 debugger is the motivating case -- report
 * {@code supportsImage() == false} because they attach to an emulator rather than launching an
 * executable. Selection used to filter the candidate list by {@code supportsImage} <em>before</em>
 * matching the caller's explicit choice, so such an offer could never be selected by name; worse,
 * the no-match fallback returned {@code candidates.get(0)}, silently launching an unrelated
 * backend. Asking for the VICE connector actually started gdb-over-ssh.
 *
 * <p>{@code DebuggerAttachSemantics.selectOffer} already refuses to guess on the attach path;
 * these tests hold the launch path to the same contract.
 */
public class DebuggerLaunchOfferSelectionTest {

    @Test
    public void explicitOfferIsFoundEvenWhenItDoesNotSupportAnImage() {
        TraceRmiLaunchOffer gdb = offer("gdb", "UNIX_SHELL:local-gdb.sh", true);
        TraceRmiLaunchOffer vice = offer("VICE C64 Debugger", "UNIX_SHELL:vice-c64.sh", false);

        assertSame("connector offers must be reachable by config_name",
                vice, DebuggerService.selectLaunchOffer(List.of(gdb, vice),
                        "UNIX_SHELL:vice-c64.sh"));
        assertSame("connector offers must be reachable by title",
                vice, DebuggerService.selectLaunchOffer(List.of(gdb, vice),
                        "VICE C64 Debugger"));
    }

    @Test
    public void explicitOfferMatchesBySubstringToo() {
        TraceRmiLaunchOffer gdb = offer("gdb", "UNIX_SHELL:local-gdb.sh", true);
        TraceRmiLaunchOffer vice = offer("VICE C64 Debugger", "UNIX_SHELL:vice-c64.sh", false);

        assertSame(vice, DebuggerService.selectLaunchOffer(List.of(gdb, vice), "vice-c64"));
    }

    @Test
    public void unmatchedExplicitOfferSelectsNothingRatherThanSomethingElse() {
        TraceRmiLaunchOffer gdb = offer("gdb", "UNIX_SHELL:local-gdb.sh", true);
        TraceRmiLaunchOffer ssh = offer("gdb + gdbserver via ssh", "UNIX_SHELL:ssh-gdbserver.sh", true);

        assertNull("a typo must not silently launch an arbitrary backend",
                DebuggerService.selectLaunchOffer(List.of(gdb, ssh), "no-such-offer"));
    }

    @Test
    public void unmatchedExplicitOfferIsNotRescuedByTheImageFilter() {
        // Every offer supports an image here, so the auto-selection path would happily return the
        // first one. An explicit, unmatched name must still refuse.
        TraceRmiLaunchOffer gdb = offer("gdb", "UNIX_SHELL:local-gdb.sh", true);

        assertNull(DebuggerService.selectLaunchOffer(List.of(gdb), "VICE C64 Debugger"));
    }

    @Test
    public void autoSelectionStillPrefersAnImageCapableOffer() {
        TraceRmiLaunchOffer vice = offer("VICE C64 Debugger", "UNIX_SHELL:vice-c64.sh", false);
        TraceRmiLaunchOffer gdb = offer("gdb", "UNIX_SHELL:local-gdb.sh", true);

        assertSame("with no explicit choice, an executable-launching offer is the sane default",
                gdb, DebuggerService.selectLaunchOffer(List.of(vice, gdb), ""));
    }

    @Test
    public void autoSelectionFallsBackWhenNoOfferSupportsAnImage() {
        TraceRmiLaunchOffer vice = offer("VICE C64 Debugger", "UNIX_SHELL:vice-c64.sh", false);

        assertSame(vice, DebuggerService.selectLaunchOffer(List.of(vice), ""));
    }

    @Test
    public void noOffersSelectsNothing() {
        assertNull(DebuggerService.selectLaunchOffer(List.of(), ""));
        assertNull(DebuggerService.selectLaunchOffer(List.of(), "gdb"));
    }

    private TraceRmiLaunchOffer offer(String title, String configName, boolean supportsImage) {
        TraceRmiLaunchOffer offer = mock(TraceRmiLaunchOffer.class);
        lenient().when(offer.getTitle()).thenReturn(title);
        lenient().when(offer.getConfigName()).thenReturn(configName);
        lenient().when(offer.supportsImage()).thenReturn(supportsImage);
        return offer;
    }
}
