package com.xebyte.core;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.debug.api.tracermi.RemoteParameter;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.schema.PrimitiveTraceObjectSchema;
import ghidra.trace.model.target.schema.SchemaContext;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;
import junit.framework.TestCase;

public class DebuggerAttachSemanticsTest extends TestCase {
    public void testSelectOfferRequiresExactTitleOrConfigName() {
        TraceRmiLaunchOffer gdb = offer("Local GDB", "local-gdb", false);
        TraceRmiLaunchOffer lldb = offer("Local LLDB", "local-lldb", false);

        assertSame(gdb,
                DebuggerAttachSemantics.selectOffer(List.of(gdb, lldb), "LOCAL GDB"));
        assertSame(gdb,
                DebuggerAttachSemantics.selectOffer(List.of(gdb, lldb), "local-gdb"));
        assertInvalid(() ->
                DebuggerAttachSemantics.selectOffer(List.of(gdb, lldb), "gdb"),
                "Available offers");
    }

    public void testSelectOfferRejectsMissingAndAmbiguousMatches() {
        TraceRmiLaunchOffer first = offer("Local GDB", "local-gdb", false);
        TraceRmiLaunchOffer second = offer("local-gdb", "alternate-gdb", false);

        assertInvalid(() -> DebuggerAttachSemantics.selectOffer(List.of(first), " "),
                "required");
        assertInvalid(() ->
                DebuggerAttachSemantics.selectOffer(List.of(first, second), "local-gdb"),
                "matched 2");
    }

    public void testAttachOnlyOfferRejectsRequiredImage() {
        TraceRmiLaunchOffer attachOnly = offer("Local GDB", "local-gdb", false);
        TraceRmiLaunchOffer imageRequired = offer("Wine GDB", "wine-gdb", true);

        DebuggerAttachSemantics.requireAttachOnlyOffer(attachOnly);
        assertInvalid(() -> DebuggerAttachSemantics.requireAttachOnlyOffer(imageRequired),
                "requires an image");
    }

    public void testSelectAttachMethodRequiresOneIntegerPidParameter() {
        RemoteMethod byObject = method("attach_obj", ActionName.ATTACH,
                parameter("target", PrimitiveTraceObjectSchema.OBJECT.getName(), true));
        RemoteMethod byPid = method("attach_pid", ActionName.ATTACH,
                parameter("inferior", PrimitiveTraceObjectSchema.OBJECT.getName(), true),
                parameter("pid", PrimitiveTraceObjectSchema.INT.getName(), true));
        RemoteMethod other = method("launch", ActionName.LAUNCH,
                parameter("pid", PrimitiveTraceObjectSchema.INT.getName(), true));

        assertSame(byPid, DebuggerAttachSemantics.selectAttachMethod(
                List.of(byObject, byPid, other)));
    }

    public void testSelectAttachMethodRejectsMissingAndAmbiguousPidMethods() {
        RemoteMethod byObject = method("attach_obj", ActionName.ATTACH,
                parameter("target", PrimitiveTraceObjectSchema.OBJECT.getName(), true));
        RemoteMethod first = method("attach_pid", ActionName.ATTACH,
                parameter("pid", PrimitiveTraceObjectSchema.INT.getName(), true));
        RemoteMethod second = method("attach_process_id", ActionName.ATTACH,
                parameter("process_id", PrimitiveTraceObjectSchema.INT.getName(), true));

        assertInvalid(() -> DebuggerAttachSemantics.selectAttachMethod(List.of(byObject)),
                "attach_obj");
        assertInvalid(() ->
                DebuggerAttachSemantics.selectAttachMethod(List.of(first, second)),
                "matched 2");
    }

    public void testBuildArgumentsResolvesObjectAndOptionalDefault() {
        SchemaName inferiorType = new SchemaName("Inferior");
        TraceObjectSchema inferiorSchema = mock(TraceObjectSchema.class);
        doReturn(TraceObject.class).when(inferiorSchema).getType();
        RemoteParameter inferiorParameter = parameter("inferior", inferiorType, true);
        RemoteParameter pidParameter = parameter("pid",
                PrimitiveTraceObjectSchema.INT.getName(), true);
        RemoteParameter optionalParameter = parameter("note",
                PrimitiveTraceObjectSchema.STRING.getName(), false);
        when(optionalParameter.getDefaultValue()).thenReturn("default-note");
        RemoteMethod method = method("attach_pid", ActionName.ATTACH,
                inferiorParameter, pidParameter, optionalParameter);

        SchemaContext schemaContext = mock(SchemaContext.class);
        Object inferior = new Object();
        when(schemaContext.getSchemaOrNull(inferiorType)).thenReturn(inferiorSchema);
        when(schemaContext.getSchemaOrNull(PrimitiveTraceObjectSchema.INT.getName()))
                .thenReturn(PrimitiveTraceObjectSchema.INT);
        when(schemaContext.getSchemaOrNull(PrimitiveTraceObjectSchema.STRING.getName()))
                .thenReturn(PrimitiveTraceObjectSchema.STRING);

        Map<String, Object> arguments = DebuggerAttachSemantics.buildArguments(
                method, schemaContext, schema -> inferior, schema -> null, 4242);

        assertSame(inferior, arguments.get("inferior"));
        assertEquals(4242, arguments.get("pid"));
        assertEquals("default-note", arguments.get("note"));
        verify(method).validate(arguments);
    }

    public void testBuildArgumentsFallsBackToRootObject() {
        SchemaName inferiorType = new SchemaName("Inferior");
        TraceObjectSchema inferiorSchema = mock(TraceObjectSchema.class);
        doReturn(TraceObject.class).when(inferiorSchema).getType();
        RemoteMethod method = method("attach_pid", ActionName.ATTACH,
                parameter("inferior", inferiorType, true),
                parameter("pid", PrimitiveTraceObjectSchema.INT.getName(), true));

        SchemaContext schemaContext = mock(SchemaContext.class);
        Object inferior = new Object();
        when(schemaContext.getSchemaOrNull(inferiorType)).thenReturn(inferiorSchema);
        when(schemaContext.getSchemaOrNull(PrimitiveTraceObjectSchema.INT.getName()))
                .thenReturn(PrimitiveTraceObjectSchema.INT);

        Map<String, Object> arguments = DebuggerAttachSemantics.buildArguments(
                method, schemaContext, schema -> null, schema -> inferior, 7);

        assertSame(inferior, arguments.get("inferior"));
    }

    public void testBuildArgumentsRejectsUnresolvedRequiredParameter() {
        SchemaName processType = new SchemaName("Process");
        TraceObjectSchema processSchema = mock(TraceObjectSchema.class);
        doReturn(TraceObject.class).when(processSchema).getType();
        RemoteMethod method = method("attach_pid", ActionName.ATTACH,
                parameter("process", processType, true),
                parameter("pid", PrimitiveTraceObjectSchema.INT.getName(), true));
        SchemaContext schemaContext = schemas(Map.of(
                processType, processSchema,
                PrimitiveTraceObjectSchema.INT.getName(), PrimitiveTraceObjectSchema.INT));

        assertInvalid(() -> DebuggerAttachSemantics.buildArguments(
                method, schemaContext, schema -> null, schema -> null, 7),
                "process");
    }

    public void testBuildArgumentsRejectsRequiredUnsupportedPrimitive() {
        RemoteMethod method = method("attach_pid", ActionName.ATTACH,
                parameter("pid", PrimitiveTraceObjectSchema.INT.getName(), true),
                parameter("enabled", PrimitiveTraceObjectSchema.BOOL.getName(), true));
        SchemaContext schemaContext = schemas(Map.of(
                PrimitiveTraceObjectSchema.INT.getName(), PrimitiveTraceObjectSchema.INT,
                PrimitiveTraceObjectSchema.BOOL.getName(), PrimitiveTraceObjectSchema.BOOL));

        assertInvalid(() -> DebuggerAttachSemantics.buildArguments(
                method, schemaContext, schema -> null, schema -> null, 7),
                "enabled");
    }

    private TraceRmiLaunchOffer offer(String title, String configName,
                                      boolean requiresImage) {
        TraceRmiLaunchOffer offer = mock(TraceRmiLaunchOffer.class);
        when(offer.getTitle()).thenReturn(title);
        when(offer.getConfigName()).thenReturn(configName);
        when(offer.requiresImage()).thenReturn(requiresImage);
        return offer;
    }

    private RemoteMethod method(String name, ActionName action,
                                RemoteParameter... parameters) {
        RemoteMethod method = mock(RemoteMethod.class);
        var parameterMap = java.util.Arrays.stream(parameters)
                .collect(java.util.stream.Collectors.toMap(RemoteParameter::name,
                        parameter -> parameter, (left, right) -> left,
                        java.util.LinkedHashMap::new));
        when(method.name()).thenReturn(name);
        when(method.action()).thenReturn(action);
        when(method.parameters()).thenReturn(parameterMap);
        return method;
    }

    private RemoteParameter parameter(String name,
                                      ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName type,
                                      boolean required) {
        RemoteParameter parameter = mock(RemoteParameter.class);
        when(parameter.name()).thenReturn(name);
        when(parameter.type()).thenReturn(type);
        when(parameter.required()).thenReturn(required);
        return parameter;
    }

    private SchemaContext schemas(Map<SchemaName, TraceObjectSchema> schemas) {
        SchemaContext schemaContext = mock(SchemaContext.class);
        for (var entry : schemas.entrySet()) {
            when(schemaContext.getSchemaOrNull(entry.getKey())).thenReturn(entry.getValue());
        }
        return schemaContext;
    }

    private void assertInvalid(Runnable action, String messageFragment) {
        try {
            action.run();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage(),
                    expected.getMessage().contains(messageFragment));
        }
    }
}
