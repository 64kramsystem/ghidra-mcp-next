package com.xebyte.core;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.SwingUtilities;
import org.junit.Test;
import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;

public class ProgramSaveTest {
    @Test
    public void retriesActiveTransactionAndKeepsSaveOnEdt() throws Exception {
        DomainFile file = mock(DomainFile.class);
        AtomicInteger calls = new AtomicInteger();
        doAnswer(invocation -> {
            assertTrue(SwingUtilities.isEventDispatchThread());
            if (calls.getAndIncrement() < 2) throw new IOException("Unable to lock due to active transaction");
            return null;
        }).when(file).save(any());
        assertTrue(service(file).saveCurrentProgram("") instanceof Response.Ok);
        assertEquals(3, calls.get());
    }

    @Test
    public void doesNotRetryOtherFailures() throws Exception {
        DomainFile file = mock(DomainFile.class);
        doThrow(new IOException("disk failure")).when(file).save(any());
        assertTrue(service(file).saveCurrentProgram("") instanceof Response.Err);
        verify(file, times(1)).save(any());
    }

    @Test
    public void activeTransactionRetryIsBounded() throws Exception {
        DomainFile file = mock(DomainFile.class);
        doThrow(new IOException("Unable to lock due to active transaction")).when(file).save(any());
        assertTrue(service(file).saveCurrentProgram("") instanceof Response.Err);
        verify(file, times(10)).save(any());
    }

    @Test
    public void activeTransactionOnEdtFailsWithoutWaiting() throws Exception {
        DomainFile file = mock(DomainFile.class);
        doThrow(new IOException("Unable to lock due to active transaction")).when(file).save(any());
        ProgramScriptService service = service(file);
        SwingUtilities.invokeAndWait(() -> assertTrue(service.saveCurrentProgram("") instanceof Response.Err));
        verify(file, times(1)).save(any());
    }

    @Test
    public void analysisCompletionSaveRetriesActiveTransaction() throws Exception {
        Program program = mock(Program.class);
        when(program.canSave()).thenReturn(true);
        AtomicInteger calls = new AtomicInteger();
        doAnswer(invocation -> {
            assertTrue(SwingUtilities.isEventDispatchThread());
            if (calls.getAndIncrement() == 0) throw new IOException("Unable to lock due to active transaction");
            return null;
        }).when(program).save(anyString(), any());
        service(mock(DomainFile.class)).persistProgram(program, "analysis completed");
        assertEquals(2, calls.get());
        verify(program).flushEvents();
    }

    private ProgramScriptService service(DomainFile file) {
        Program program = mock(Program.class);
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(program);
        when(program.getDomainFile()).thenReturn(file);
        return new ProgramScriptService(provider, new DirectThreadingStrategy());
    }
}
