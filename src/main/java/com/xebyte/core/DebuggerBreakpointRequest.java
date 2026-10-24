package com.xebyte.core;

import java.util.Set;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;

final class DebuggerBreakpointRequest {
    private DebuggerBreakpointRequest() {}

    static Set<TraceBreakpointKind> kinds(String kind, long length) {
        if (length < 1 || length > 65_536) {
            throw new IllegalArgumentException("length must be from 1 to 65536");
        }
        var common = switch (kind) {
            case "x" -> TraceBreakpointKind.CommonSet.SWX;
            case "X" -> TraceBreakpointKind.CommonSet.HWX;
            case "R" -> TraceBreakpointKind.CommonSet.READ;
            case "W" -> TraceBreakpointKind.CommonSet.WRITE;
            case "RW" -> TraceBreakpointKind.CommonSet.ACCESS;
            default -> throw new IllegalArgumentException("kind must be x, X, R, W, or RW");
        };
        if ((kind.equals("x") || kind.equals("X")) && length != 1) {
            throw new IllegalArgumentException("execute breakpoints require length 1");
        }
        return common.kinds();
    }
}
