package com.xebyte.offline;

import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.listing.Program;

import java.util.concurrent.Callable;

/**
 * Test {@link ThreadingStrategy} that actually runs the action and records that it did.
 *
 * <p>{@link NoopThreadingStrategy} throws from {@code executeRead}, which is right for
 * tests that only reflect on services — but it means a service that never enters
 * {@code executeRead} passes those tests while bypassing the strategy entirely. Use
 * this strategy wherever a test needs to prove the read hop happened.</p>
 */
public class RecordingThreadingStrategy implements ThreadingStrategy {

    private int readCount;
    private int writeCount;
    private Runnable beforeRead;
    private volatile boolean insideRead;

    /** Runs inside executeRead before the action; used to observe ordering. */
    public void onBeforeRead(Runnable hook) {
        this.beforeRead = hook;
    }

    public int readCount() {
        return readCount;
    }

    public int writeCount() {
        return writeCount;
    }

    /**
     * True only while the read action is executing.
     *
     * <p>Counting {@code executeRead} calls is not enough to prove anything: a service
     * can enter an empty hop and then do all its model reads outside it, which counts
     * one read and still runs on the wrong thread. A model getter asserting this flag
     * is what makes that mutation fail.</p>
     */
    public boolean isInsideRead() {
        return insideRead;
    }

    @Override
    public <T> T executeRead(Callable<T> action) throws Exception {
        readCount++;
        if (beforeRead != null) beforeRead.run();
        insideRead = true;
        try {
            return action.call();
        } finally {
            insideRead = false;
        }
    }

    @Override
    public <T> T executeWrite(Program program, String txName, Callable<T> action)
            throws Exception {
        writeCount++;
        return action.call();
    }

}
