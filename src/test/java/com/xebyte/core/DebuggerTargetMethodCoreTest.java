package com.xebyte.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Proxy;
import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.junit.Before;
import org.junit.Test;

import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.tracermi.RemoteAsyncResult;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.debug.api.tracermi.RemoteMethodRegistry;
import ghidra.debug.api.tracermi.RemoteParameter;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectManager;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.SchemaContext;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;

public class DebuggerTargetMethodCoreTest {
    private DebuggerTargetMethodCore core;
    private Trace trace;
    private TraceRmiConnection owner;
    private RemoteMethodRegistry registry;
    private AddressSpace ram;
    private AddressFactory addressFactory;
    private TraceObjectManager objectManager;

    @Before
    public void setUp() {
        core = new DebuggerTargetMethodCore();
        owner = mock(TraceRmiConnection.class);
        registry = mock(RemoteMethodRegistry.class);
        objectManager = mock(TraceObjectManager.class);
        ram = new GenericAddressSpace(
            "RAM", 16, AddressSpace.TYPE_RAM, 0);
        addressFactory = mock(AddressFactory.class);
        when(addressFactory.getAddressSpace("RAM")).thenReturn(ram);
        trace = traceStub(addressFactory, objectManager);
        when(owner.getMethods()).thenReturn(registry);
        when(owner.isClosed()).thenReturn(false);
        when(owner.isTarget(trace)).thenReturn(true);
        when(owner.getDescription()).thenReturn("VICE connector");
    }

    @Test
    public void tokenIsStableOnlyForExactTraceAndOwnerIdentities() {
        DebuggerTargetMethodCore.TargetContext first =
            context(trace, owner, 7);
        String token = core.describe(first).targetToken();

        assertEquals(token, core.describe(context(trace, owner, 8))
            .targetToken());

        TraceRmiConnection replacement = mock(TraceRmiConnection.class);
        when(replacement.getMethods()).thenReturn(registry);
        when(replacement.isClosed()).thenReturn(false);
        when(replacement.isTarget(trace)).thenReturn(true);
        when(replacement.getDescription()).thenReturn("replacement");
        String replacementToken =
            core.describe(context(trace, replacement, 9)).targetToken();

        assertFalse(token.equals(replacementToken));
        DebuggerTargetMethodCore.TargetMethodException stale =
            assertThrows(
                DebuggerTargetMethodCore.TargetMethodException.class,
                () -> core.requireBinding(
                    context(trace, replacement, 9), token));
        assertEquals("stale_target_token", stale.code());
    }

    @Test
    public void ownerSelectionDistinguishesAbsentUntargetedAndAmbiguous() {
        assertProblem("no_trace_rmi_connections", () ->
            DebuggerTargetMethodCore.selectUniqueOwner(List.of(), trace));

        TraceRmiConnection unrelated = mock(TraceRmiConnection.class);
        when(unrelated.isClosed()).thenReturn(false);
        when(unrelated.isTarget(trace)).thenReturn(false);
        assertProblem("no_targeting_connection", () ->
            DebuggerTargetMethodCore.selectUniqueOwner(
                List.of(unrelated), trace));

        TraceRmiConnection second = mock(TraceRmiConnection.class);
        when(second.isClosed()).thenReturn(false);
        when(second.isTarget(trace)).thenReturn(true);
        assertProblem("ambiguous_targeting_connection", () ->
            DebuggerTargetMethodCore.selectUniqueOwner(
                List.of(owner, second), trace));

        when(owner.isClosed()).thenReturn(true);
        assertSame(
            second,
            DebuggerTargetMethodCore.selectUniqueOwner(
                List.of(owner, second), trace));
    }

    @Test
    public void ownerClosureOrRetargetingInvalidatesToken() {
        DebuggerTargetMethodCore.TargetContext context =
            context(trace, owner, 1);
        String token = core.describe(context).targetToken();
        when(owner.isClosed()).thenReturn(true);

        assertEquals(
            "stale_target_token",
            assertThrows(
                DebuggerTargetMethodCore.TargetMethodException.class,
                () -> core.requireBinding(context, token)).code());

        when(owner.isClosed()).thenReturn(false);
        when(owner.isTarget(trace)).thenReturn(false);
        assertEquals(
            "stale_target_token",
            assertThrows(
                DebuggerTargetMethodCore.TargetMethodException.class,
                () -> core.requireBinding(context, token)).code());
    }

    @Test
    public void discoverySortsMethodsAndParametersAndHidesBadDefaults() {
        RemoteMethod zeta = method(
            "zeta", schema("STRING"),
            Map.of(
                "z", parameter("z", "INT", false, 3),
                "a", parameter("a", "VOID", false, null)));
        RemoteMethod alpha = method(
            "alpha", schema("VOID"),
            Map.of(
                "required", parameter(
                    "required", "STRING", true, "ignored"),
                "bad", parameter("bad", "INT", false, "wrong")));
        when(registry.all()).thenReturn(
            Map.of("zeta", zeta, "alpha", alpha));

        DebuggerTargetMethodCore.Discovery discovery =
            core.describe(context(trace, owner, 4));

        assertEquals(
            List.of("alpha", "zeta"),
            discovery.methods().stream()
                .map(DebuggerTargetMethodCore.MethodDescription::name)
                .toList());
        DebuggerTargetMethodCore.MethodDescription describedZeta =
            discovery.methods().get(1);
        assertEquals(
            List.of("a", "z"),
            describedZeta.parameters().stream()
                .map(DebuggerTargetMethodCore.ParameterDescription::name)
                .toList());
        assertTrue(
            describedZeta.parameters().get(0).defaultAvailable());
        assertEquals(null, describedZeta.parameters().get(0).defaultValue());
        assertTrue(
            describedZeta.parameters().get(1).defaultAvailable());
        assertEquals(
            3, describedZeta.parameters().get(1).defaultValue());
        assertFalse(
            discovery.methods().get(0).parameters().get(0)
                .defaultAvailable());
    }

    @Test
    public void exactNumericAndCharacterDecodingRejectsNarrowing() {
        assertEquals(
            (byte) 127,
            DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("BYTE"), new BigDecimal("127"), "p"));
        assertEquals(
            42L,
            DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("LONG"), new BigDecimal("4.2e1"), "p"));
        assertEquals(
            'x',
            DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("CHAR"), "x", "p"));

        assertProblem("invalid_argument", () ->
            DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("BYTE"), 128, "p"));
        assertProblem("invalid_argument", () ->
            DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("INT"), 1.5, "p"));
        assertProblem("invalid_argument", () ->
            DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("CHAR"), "\ud83d\ude00", "p"));
    }

    @Test
    public void arraysAndHexBytesAreStrictAndPrimitive() {
        assertArrayEquals(
            new byte[] {0, (byte) 0xff},
            (byte[]) DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("BYTE_ARR"),
                Map.of("encoding", "hex", "data", "00Ff"), "bytes"));
        assertArrayEquals(
            new int[] {-1, 2},
            (int[]) DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("INT_ARR"),
                List.of(-1, 2), "ints"));
        assertArrayEquals(
            new String[] {"a", "", "b"},
            (String[]) DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("STRING_ARR"),
                List.of("a", "", "b"), "strings"));
        assertEquals(
            "",
            DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("STRING"), "", "string"));
        assertArrayEquals(
            new char[0],
            (char[]) DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("CHAR_ARR"), "", "chars"));

        assertProblem("invalid_argument", () ->
            DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("BYTE_ARR"),
                Map.of("encoding", "hex", "data", "0"), "bytes"));
        Map<String, Object> extra = new LinkedHashMap<>();
        extra.put("encoding", "hex");
        extra.put("data", "00");
        extra.put("extra", true);
        assertProblem("invalid_argument", () ->
            DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("BYTE_ARR"), extra, "bytes"));
        assertProblem("invalid_argument", () ->
            DebuggerTargetMethodCore.decodeValue(
                trace, 0, schema("BOOL_ARR"),
                List.of(true, 1), "flags"));
    }

    @Test
    public void addressRangeAndSameTraceObjectWrappersAreExact() {
        Address address = (Address) DebuggerTargetMethodCore.decodeValue(
            trace, 2, schema("ADDRESS"),
            Map.of("space", "RAM", "offset", 0xc000), "address");
        assertEquals(ram.getAddress(0xc000), address);

        AddressRange range =
            (AddressRange) DebuggerTargetMethodCore.decodeValue(
                trace, 2, schema("RANGE"),
                Map.of(
                    "space", "RAM", "start", 0x1000,
                    "end", 0x10ff),
                "range");
        assertEquals(ram.getAddress(0x1000), range.getMinAddress());
        assertEquals(ram.getAddress(0x10ff), range.getMaxAddress());

        AddressSpace wide = new GenericAddressSpace(
            "WIDE", 64, AddressSpace.TYPE_RAM, 1);
        when(addressFactory.getAddressSpace("WIDE")).thenReturn(wide);
        AddressRange acrossSignedBoundary =
            (AddressRange) DebuggerTargetMethodCore.decodeValue(
                trace, 2, schema("RANGE"),
                Map.of(
                    "space", "WIDE",
                    "start", Long.MAX_VALUE,
                    "end", Long.MIN_VALUE),
                "wide_range");
        assertEquals(
            wide.getAddress(Long.MAX_VALUE),
            acrossSignedBoundary.getMinAddress());
        assertEquals(
            wide.getAddress(Long.MIN_VALUE),
            acrossSignedBoundary.getMaxAddress());

        TraceObject object = mock(TraceObject.class);
        when(objectManager.getObjectByCanonicalPath(KeyPath.parse("C64")))
            .thenReturn(object);
        when(object.getTrace()).thenReturn(trace);
        assertSame(
            object,
            DebuggerTargetMethodCore.decodeValue(
                trace, 2, schema("C64"),
                Map.of("object_path", "C64"), "process"));

        assertProblem("invalid_argument", () ->
            DebuggerTargetMethodCore.decodeValue(
                trace, 2, schema("RANGE"),
                Map.of(
                    "space", "RAM", "start", 5, "end", 4),
                "range"));
    }

    @Test
    public void returnEncodingRequiresExactJavaTypes() {
        assertEquals(
            Map.of("encoding", "hex", "data", "00ff"),
            DebuggerTargetMethodCore.encodeValue(
                trace, schema("BYTE_ARR"),
                new byte[] {0, (byte) 0xff}, "return"));
        assertEquals(
            List.of(1L, 2L),
            DebuggerTargetMethodCore.encodeValue(
                trace, schema("LONG_ARR"),
                new long[] {1, 2}, "return"));
        assertEquals(
            "ab",
            DebuggerTargetMethodCore.encodeValue(
                trace, schema("CHAR_ARR"),
                new char[] {'a', 'b'}, "return"));
        assertEquals(
            List.of("a", "", "b"),
            DebuggerTargetMethodCore.encodeValue(
                trace, schema("STRING_ARR"),
                new String[] {"a", "", "b"}, "return"));

        assertProblem("invalid_return", () ->
            DebuggerTargetMethodCore.encodeValue(
                trace, schema("INT"), 1L, "return"));
        assertProblem("invalid_return", () ->
            DebuggerTargetMethodCore.encodeValue(
                trace, schema("VOID"), "not null", "return"));
        assertProblem("invalid_return", () ->
            DebuggerTargetMethodCore.encodeValue(
                trace, schema("STRING_ARR"),
                new String[] {"a", null}, "return"));
        assertProblem("unsupported_schema", () ->
            DebuggerTargetMethodCore.encodeValue(
                trace, schema("ANY"), "x", "return"));
    }

    @Test
    public void customSchemaReturnMustBeAssignable() {
        TraceObject object = mock(TraceObject.class);
        TraceObjectSchema root = mock(TraceObjectSchema.class);
        TraceObjectSchema expected = mock(TraceObjectSchema.class);
        TraceObjectSchema actual = mock(TraceObjectSchema.class);
        SchemaContext context = mock(SchemaContext.class);
        when(object.getTrace()).thenReturn(trace);
        when(object.getSchema()).thenReturn(actual);
        when(object.getCanonicalPath()).thenReturn(
            KeyPath.parse("C64"));
        when(objectManager.getRootSchema()).thenReturn(root);
        when(root.getContext()).thenReturn(context);
        when(context.getSchemaOrNull(schema("C64")))
            .thenReturn(expected);
        when(expected.isAssignableFrom(actual)).thenReturn(false);

        assertProblem("invalid_return", () ->
            DebuggerTargetMethodCore.encodeValue(
                trace, schema("C64"), object, "return"));

        when(expected.isAssignableFrom(actual)).thenReturn(true);
        assertEquals(
            Map.of("object_path", "C64"),
            DebuggerTargetMethodCore.encodeValue(
                trace, schema("C64"), object, "return"));
    }

    @Test
    public void invocationRejectsMissingExtraAndExplicitVoidBeforeRemoteCall() {
        RemoteMethod method = method(
            "call", schema("VOID"),
            Map.of(
                "required", parameter(
                    "required", "STRING", true, null),
                "optional_void", parameter(
                    "optional_void", "VOID", false, null)));
        when(registry.all()).thenReturn(Map.of("call", method));
        when(registry.get("call")).thenReturn(method);
        DebuggerTargetMethodCore.TargetContext context =
            context(trace, owner, 1);
        String token = core.describe(context).targetToken();

        assertEquals(
            "missing_argument",
            assertThrows(
                DebuggerTargetMethodCore.TargetMethodException.class,
                () -> core.invoke(
                    context, token, "call", Map.of(), 100)).code());
        assertEquals(
            "unknown_argument",
            assertThrows(
                DebuggerTargetMethodCore.TargetMethodException.class,
                () -> core.invoke(
                    context, token, "call",
                    Map.of("required", "x", "extra", 1), 100)).code());
        Map<String, Object> explicitVoid = new LinkedHashMap<>();
        explicitVoid.put("required", "x");
        explicitVoid.put("optional_void", null);
        assertEquals(
            "unsupported_schema",
            assertThrows(
                DebuggerTargetMethodCore.TargetMethodException.class,
                () -> core.invoke(
                    context, token, "call", explicitVoid, 100)).code());
    }

    @Test
    public void invocationUsesTypedArgumentsAndEncodesReturn() throws Exception {
        RemoteAsyncResult future = mock(RemoteAsyncResult.class);
        RemoteMethod method = method(
            "sum", schema("INT"),
            Map.of(
                "value", parameter(
                    "value", "INT", true, null)));
        when(registry.all()).thenReturn(Map.of("sum", method));
        when(registry.get("sum")).thenReturn(method);
        when(method.invokeAsync(any())).thenReturn(future);
        when(future.get(250, TimeUnit.MILLISECONDS)).thenReturn(7);
        when(method.validate(any())).thenReturn(null);
        DebuggerTargetMethodCore.TargetContext context =
            context(trace, owner, 3);
        String token = core.describe(context).targetToken();

        Object result = core.invoke(
            context, token, "sum",
            Map.of("value", new BigDecimal("6")), 250);

        assertEquals(7, result);
        verify(method).validate(Map.of("value", 6));
        verify(method).invokeAsync(Map.of("value", 6));
    }

    @Test
    public void timeoutCancelsAndReportsUnknownOutcome() throws Exception {
        RemoteAsyncResult future = mock(RemoteAsyncResult.class);
        RemoteMethod method = method(
            "slow", schema("VOID"), Map.of());
        when(registry.all()).thenReturn(Map.of("slow", method));
        when(registry.get("slow")).thenReturn(method);
        when(method.invokeAsync(any())).thenReturn(future);
        when(future.get(50, TimeUnit.MILLISECONDS))
            .thenThrow(new TimeoutException("late"));
        DebuggerTargetMethodCore.TargetContext context =
            context(trace, owner, 1);
        String token = core.describe(context).targetToken();

        DebuggerTargetMethodCore.TargetMethodException error =
            assertThrows(
                DebuggerTargetMethodCore.TargetMethodException.class,
                () -> core.invoke(
                    context, token, "slow", Map.of(), 50));

        assertEquals("target_method_timeout", error.code());
        assertTrue(error.outcomeUnknown());
        verify(future).cancel(true);
    }

    private DebuggerTargetMethodCore.TargetContext context(
            Trace contextTrace, TraceRmiConnection contextOwner,
            long snapshot) {
        return new DebuggerTargetMethodCore.TargetContext(
            contextTrace, contextOwner, "trace", snapshot,
            "STOPPED", "C64", "c000");
    }

    private RemoteMethod method(
            String name, SchemaName returnType,
            Map<String, RemoteParameter> parameters) {
        RemoteMethod method = mock(RemoteMethod.class);
        when(method.name()).thenReturn(name);
        when(method.action()).thenReturn(ActionName.name(name));
        when(method.display()).thenReturn(name + " display");
        when(method.description()).thenReturn(name + " description");
        when(method.retType()).thenReturn(returnType);
        when(method.parameters()).thenReturn(parameters);
        return method;
    }

    private RemoteParameter parameter(
            String name, String type, boolean required,
            Object defaultValue) {
        RemoteParameter parameter = mock(RemoteParameter.class);
        when(parameter.name()).thenReturn(name);
        when(parameter.type()).thenReturn(schema(type));
        when(parameter.required()).thenReturn(required);
        when(parameter.getDefaultValue()).thenReturn(defaultValue);
        when(parameter.display()).thenReturn(name + " display");
        when(parameter.description()).thenReturn(name + " description");
        return parameter;
    }

    private static SchemaName schema(String name) {
        return new TraceObjectSchema.SchemaName(name);
    }

    private static Trace traceStub(
            AddressFactory factory, TraceObjectManager objectManager) {
        return (Trace) Proxy.newProxyInstance(
            Trace.class.getClassLoader(),
            new Class<?>[] {Trace.class},
            (proxy, method, arguments) -> switch (method.getName()) {
                case "getBaseAddressFactory" -> factory;
                case "getObjectManager" -> objectManager;
                case "getName" -> "trace";
                case "toString" -> "trace";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" ->
                    proxy == (arguments == null ? null : arguments[0]);
                default -> primitiveDefault(method.getReturnType());
            });
    }

    private static Object primitiveDefault(Class<?> type) {
        if (!type.isPrimitive() || type == void.class) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == char.class) {
            return '\0';
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == float.class) {
            return 0.0f;
        }
        return 0.0d;
    }

    private static void assertProblem(
            String code, ThrowingAction action) {
        DebuggerTargetMethodCore.TargetMethodException error =
            assertThrows(
                DebuggerTargetMethodCore.TargetMethodException.class,
                action::run);
        assertEquals(code, error.code());
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }
}
