package com.xebyte.core;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import ghidra.debug.api.target.Target;
import ghidra.framework.model.DomainObjectListener;
import junit.framework.TestCase;

public class DebuggerStateWaiterTest extends TestCase {
    public void testMissingTargetIsTerminated() {
        assertEquals(DebuggerStateWaiter.ExecutionState.TERMINATED,
                DebuggerStateWaiter.stateFromActions(false, List.of()));
    }

    public void testNoUsableResumeActionIsAlive() {
        Target.ActionEntry prompted = action(true, true, 100);

        assertEquals(DebuggerStateWaiter.ExecutionState.ALIVE,
                DebuggerStateWaiter.stateFromActions(true, List.of(prompted)));
    }

    public void testEnabledBestResumeActionMeansStopped() {
        Target.ActionEntry lessSpecificRunning = action(false, false, 10);
        Target.ActionEntry mostSpecificStopped = action(false, true, 20);

        assertEquals(DebuggerStateWaiter.ExecutionState.STOPPED,
                DebuggerStateWaiter.stateFromActions(true,
                        List.of(lessSpecificRunning, mostSpecificStopped)));
    }

    public void testDisabledBestResumeActionMeansRunning() {
        Target.ActionEntry lessSpecificStopped = action(false, true, 10);
        Target.ActionEntry mostSpecificRunning = action(false, false, 20);

        assertEquals(DebuggerStateWaiter.ExecutionState.RUNNING,
                DebuggerStateWaiter.stateFromActions(true,
                        List.of(lessSpecificStopped, mostSpecificRunning)));
    }

    public void testAlreadyStoppedReturnsWithoutListener() throws Exception {
        FakeEventSource events = new FakeEventSource();

        DebuggerStateWaiter.WaitResult result = DebuggerStateWaiter.waitForStop(
                events, () -> DebuggerStateWaiter.ExecutionState.STOPPED, 1000);

        assertTrue(result.stopped());
        assertFalse(result.timedOut());
        assertEquals(0, events.addCount);
        assertEquals(0, events.removeCount);
    }

    public void testPostRegistrationRecheckClosesRace() throws Exception {
        AtomicReference<DebuggerStateWaiter.ExecutionState> state =
                new AtomicReference<>(DebuggerStateWaiter.ExecutionState.RUNNING);
        FakeEventSource events = new FakeEventSource();
        events.onAdd = () -> state.set(DebuggerStateWaiter.ExecutionState.STOPPED);

        DebuggerStateWaiter.WaitResult result = DebuggerStateWaiter.waitForStop(
                events, state::get, 1000);

        assertEquals(DebuggerStateWaiter.ExecutionState.STOPPED, result.state());
        assertFalse(result.timedOut());
        assertEquals(1, events.addCount);
        assertEquals(1, events.removeCount);
    }

    public void testTraceEventCompletesWait() throws Exception {
        AtomicReference<DebuggerStateWaiter.ExecutionState> state =
                new AtomicReference<>(DebuggerStateWaiter.ExecutionState.RUNNING);
        FakeEventSource events = new FakeEventSource();
        CompletableFuture<DebuggerStateWaiter.WaitResult> waiting =
                CompletableFuture.supplyAsync(() -> {
                    try {
                        return DebuggerStateWaiter.waitForStop(events, state::get, 5000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new CompletionException(e);
                    }
                });
        assertTrue(events.added.await(2, TimeUnit.SECONDS));

        state.set(DebuggerStateWaiter.ExecutionState.STOPPED);
        events.fire();
        DebuggerStateWaiter.WaitResult result = waiting.get(2, TimeUnit.SECONDS);

        assertTrue(result.stopped());
        assertFalse(result.timedOut());
        assertEquals(1, events.removeCount);
    }

    public void testTimeoutReturnsCurrentRunningStateAndRemovesListener()
            throws Exception {
        FakeEventSource events = new FakeEventSource();

        DebuggerStateWaiter.WaitResult result = DebuggerStateWaiter.waitForStop(
                events, () -> DebuggerStateWaiter.ExecutionState.RUNNING, 0);

        assertEquals(DebuggerStateWaiter.ExecutionState.RUNNING, result.state());
        assertTrue(result.timedOut());
        assertEquals(1, events.addCount);
        assertEquals(1, events.removeCount);
    }

    public void testInterruptionRemovesListener() throws Exception {
        FakeEventSource events = new FakeEventSource();
        AtomicBoolean interrupted = new AtomicBoolean();
        Thread waiter = new Thread(() -> {
            try {
                DebuggerStateWaiter.waitForStop(events,
                        () -> DebuggerStateWaiter.ExecutionState.RUNNING, 10_000);
            } catch (InterruptedException expected) {
                interrupted.set(true);
            }
        });
        waiter.start();
        assertTrue(events.added.await(2, TimeUnit.SECONDS));

        waiter.interrupt();
        waiter.join(2000);

        assertFalse(waiter.isAlive());
        assertTrue(interrupted.get());
        assertEquals(1, events.removeCount);
    }

    public void testNegativeTimeoutIsRejected() {
        try {
            DebuggerStateWaiter.waitForStop(new FakeEventSource(),
                    () -> DebuggerStateWaiter.ExecutionState.RUNNING, -1);
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("non-negative"));
        } catch (InterruptedException unexpected) {
            fail(unexpected.getMessage());
        }
    }

    private Target.ActionEntry action(boolean requiresPrompt, boolean enabled,
                                      long specificity) {
        Target.ActionEntry action = mock(Target.ActionEntry.class);
        when(action.requiresPrompt()).thenReturn(requiresPrompt);
        when(action.isEnabled()).thenReturn(enabled);
        when(action.specificity()).thenReturn(specificity);
        return action;
    }

    private static final class FakeEventSource
            implements DebuggerStateWaiter.EventSource {
        private final CountDownLatch added = new CountDownLatch(1);
        private volatile DomainObjectListener listener;
        private Runnable onAdd;
        private int addCount;
        private int removeCount;

        @Override
        public void addListener(DomainObjectListener addedListener) {
            listener = addedListener;
            addCount++;
            added.countDown();
            if (onAdd != null) {
                onAdd.run();
            }
        }

        @Override
        public void removeListener(DomainObjectListener removedListener) {
            if (listener != removedListener) {
                throw new AssertionError("Removed a different listener");
            }
            removeCount++;
            listener = null;
        }

        void fire() {
            DomainObjectListener current = listener;
            if (current == null) {
                throw new AssertionError("No listener registered");
            }
            current.domainObjectChanged(null);
        }
    }
}
