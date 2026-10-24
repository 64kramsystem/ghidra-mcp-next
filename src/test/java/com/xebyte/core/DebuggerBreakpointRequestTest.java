package com.xebyte.core;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.Set;
import java.util.concurrent.CompletableFuture;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import ghidra.app.services.*;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;

public class DebuggerBreakpointRequestTest {
    @Test
    public void rejectsOldNamesAndInvalidExecutionLengths() {
        assertThrows(IllegalArgumentException.class,
                () -> DebuggerBreakpointRequest.kinds("SW_EXECUTE", 1));
        assertThrows(IllegalArgumentException.class,
                () -> DebuggerBreakpointRequest.kinds("x", 2));
        assertThrows(IllegalArgumentException.class,
                () -> DebuggerBreakpointRequest.kinds("R", 0));
    }

    @Test
    public void placesTheRequestedRangeAndRefusesUnsupportedKinds() {
        PluginTool tool = mock(PluginTool.class);
        Project project = mock(Project.class);
        ToolManager tools = mock(ToolManager.class);
        DebuggerTraceManagerService manager = mock(DebuggerTraceManagerService.class);
        DebuggerTargetService targets = mock(DebuggerTargetService.class);
        Trace trace = mock(Trace.class, RETURNS_DEEP_STUBS);
        Target target = mock(Target.class);
        AddressFactory factory = mock(AddressFactory.class);
        Address start = new GenericAddressSpace("ram", 16, AddressSpace.TYPE_RAM, 0).getAddress(0x1000);
        when(tool.getProject()).thenReturn(project);
        when(project.getToolManager()).thenReturn(tools);
        when(tools.getRunningTools()).thenReturn(new PluginTool[]{tool});
        when(tool.getService(DebuggerTraceManagerService.class)).thenReturn(manager);
        when(tool.getService(DebuggerTargetService.class)).thenReturn(targets);
        when(manager.getCurrentTrace()).thenReturn(trace);
        when(manager.getCurrent()).thenReturn(DebuggerCoordinates.NOWHERE);
        when(trace.getBaseAddressFactory()).thenReturn(factory);
        when(factory.getAddress("1000")).thenReturn(start);
        when(targets.getTarget(trace)).thenReturn(target);
        when(target.getSupportedBreakpointKinds()).thenReturn(Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE));
        when(target.placeBreakpointAsync(any(), anySet(), eq(""), eq("")))
                .thenReturn(CompletableFuture.completedFuture(null));
        var service = new DebuggerService(null, null, tool);
        assertTrue(service.setBreakpoint("1000", "RW", 8) instanceof Response.Ok);
        var range = ArgumentCaptor.forClass(AddressRange.class);
        verify(target).placeBreakpointAsync(range.capture(),
                eq(Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE)), eq(""), eq(""));
        assertEquals(8, range.getValue().getLength());
        assertTrue(service.setBreakpoint("1000", "x", 1) instanceof Response.Err);
    }
}
