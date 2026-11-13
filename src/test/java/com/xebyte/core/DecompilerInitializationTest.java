package com.xebyte.core;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.Test;
import org.mockito.MockedConstruction;
import ghidra.app.decompiler.DecompInterface;

public class DecompilerInitializationTest {
    @Test
    public void retainsNativeErrorAndDisposesFailedInterface() {
        try (MockedConstruction<DecompInterface> instances = mockConstruction(DecompInterface.class,
                (decompiler, context) -> {
                    when(decompiler.openProgram(null)).thenReturn(false);
                    when(decompiler.getLastMessage()).thenReturn("native initialization failed");
                })) {
            IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> ServiceUtils.createConfiguredDecompiler(null));
            assertEquals("native initialization failed", error.getMessage());
            verify(instances.constructed().get(0)).dispose();
        }
    }
}
