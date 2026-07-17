package com.xebyte.core;

import java.util.Collection;
import java.util.Comparator;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

import docking.ActionContext;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target;
import ghidra.framework.model.DomainObjectListener;

final class DebuggerStateWaiter {
    interface EventSource {
        void addListener(DomainObjectListener listener);

        void removeListener(DomainObjectListener listener);
    }

    enum ExecutionState {
        ALIVE,
        STOPPED,
        RUNNING,
        TERMINATED
    }

    record WaitResult(ExecutionState state, boolean timedOut) {
        boolean stopped() {
            return state == ExecutionState.STOPPED;
        }
    }

    private DebuggerStateWaiter() {}

    static ExecutionState stateFromActions(boolean targetPresent,
                                           Collection<Target.ActionEntry> resumeActions) {
        if (!targetPresent) {
            return ExecutionState.TERMINATED;
        }
        Target.ActionEntry action = resumeActions.stream()
                .filter(entry -> !entry.requiresPrompt())
                .max(Comparator.comparingLong(Target.ActionEntry::specificity))
                .orElse(null);
        if (action == null) {
            return ExecutionState.ALIVE;
        }
        return action.isEnabled() ? ExecutionState.STOPPED : ExecutionState.RUNNING;
    }

    static ExecutionState state(Target target, ActionContext context) {
        if (target == null || !target.isValid()) {
            return ExecutionState.TERMINATED;
        }
        return stateFromActions(true, target.collectActions(ActionName.RESUME, context,
                Target.ObjectArgumentPolicy.EITHER_AND_RELATED).values());
    }

    static WaitResult waitForStop(EventSource events,
                                  Supplier<ExecutionState> stateSupplier,
                                  long timeoutMs) throws InterruptedException {
        if (timeoutMs < 0) {
            throw new IllegalArgumentException("Timeout must be non-negative");
        }
        ExecutionState initial = stateSupplier.get();
        if (initial != ExecutionState.RUNNING) {
            return new WaitResult(initial, false);
        }

        CompletableFuture<ExecutionState> stopped = new CompletableFuture<>();
        DomainObjectListener listener = event -> {
            ExecutionState state = stateSupplier.get();
            if (state != ExecutionState.RUNNING) {
                stopped.complete(state);
            }
        };
        events.addListener(listener);
        try {
            ExecutionState afterRegistration = stateSupplier.get();
            if (afterRegistration != ExecutionState.RUNNING) {
                return new WaitResult(afterRegistration, false);
            }
            try {
                return new WaitResult(stopped.get(timeoutMs, TimeUnit.MILLISECONDS), false);
            } catch (TimeoutException e) {
                ExecutionState current = stateSupplier.get();
                return new WaitResult(current, current == ExecutionState.RUNNING);
            } catch (ExecutionException e) {
                throw new IllegalStateException("Debugger state listener failed", e.getCause());
            }
        } finally {
            events.removeListener(listener);
        }
    }
}
