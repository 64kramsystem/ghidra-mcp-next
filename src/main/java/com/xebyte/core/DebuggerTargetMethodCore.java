package com.xebyte.core;

import java.lang.reflect.Array;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import ghidra.debug.api.tracermi.RemoteAsyncResult;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.debug.api.tracermi.RemoteParameter;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;

/** Platform-neutral discovery and invocation of active TraceRMI methods. */
final class DebuggerTargetMethodCore {
    static final long MIN_TIMEOUT_MS = 1;
    static final long MAX_TIMEOUT_MS = 60_000;

    record TargetContext(
            Trace trace, TraceRmiConnection owner, String traceName,
            long snapshot, String executionState, String activeObjectPath,
            String programCounter) {
        TargetContext {
            Objects.requireNonNull(trace, "trace");
            Objects.requireNonNull(owner, "owner");
            Objects.requireNonNull(traceName, "traceName");
        }
    }

    record ParameterDescription(
            String name, String type, boolean required,
            boolean defaultAvailable, Object defaultValue,
            String display, String description) {
    }

    record MethodDescription(
            String name, String action, String display,
            String description, String returnType,
            List<ParameterDescription> parameters) {
        MethodDescription {
            parameters = List.copyOf(parameters);
        }
    }

    record Discovery(
            String targetToken, TargetContext context,
            List<MethodDescription> methods) {
        Discovery {
            methods = List.copyOf(methods);
        }
    }

    static final class TargetMethodException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private final String code;
        private final boolean outcomeUnknown;

        TargetMethodException(String code, String message) {
            this(code, message, false, null);
        }

        TargetMethodException(
                String code, String message, boolean outcomeUnknown) {
            this(code, message, outcomeUnknown, null);
        }

        TargetMethodException(
                String code, String message, Throwable cause) {
            this(code, message, false, cause);
        }

        private TargetMethodException(
                String code, String message, boolean outcomeUnknown,
                Throwable cause) {
            super(message, cause);
            this.code = Objects.requireNonNull(code);
            this.outcomeUnknown = outcomeUnknown;
        }

        String code() {
            return code;
        }

        boolean outcomeUnknown() {
            return outcomeUnknown;
        }
    }

    private record Binding(
            String token, Trace trace, TraceRmiConnection owner) {
    }

    private final Object bindingLock = new Object();
    private final Map<String, Binding> bindings = new LinkedHashMap<>();

    static TraceRmiConnection selectUniqueOwner(
            Collection<TraceRmiConnection> connections, Trace trace) {
        Objects.requireNonNull(trace, "trace");
        List<TraceRmiConnection> open =
            connections == null ? List.of() : connections.stream()
                .filter(Objects::nonNull)
                .filter(connection -> !connection.isClosed())
                .toList();
        if (open.isEmpty()) {
            throw problem(
                "no_trace_rmi_connections",
                "there are no open TraceRMI connections");
        }
        List<TraceRmiConnection> owners = open.stream()
            .filter(connection -> connection.isTarget(trace))
            .toList();
        if (owners.isEmpty()) {
            throw problem(
                "no_targeting_connection",
                "no open TraceRMI connection targets the active trace");
        }
        if (owners.size() != 1) {
            throw problem(
                "ambiguous_targeting_connection",
                owners.size()
                    + " open TraceRMI connections target the active trace");
        }
        return owners.get(0);
    }

    Discovery describe(TargetContext context) {
        requireOwnerCurrent(context);
        Binding binding;
        synchronized (bindingLock) {
            binding = bindings.values().stream()
                .filter(item ->
                    item.trace() == context.trace()
                        && item.owner() == context.owner())
                .findFirst()
                .orElse(null);
            if (binding == null) {
                bindings.entrySet().removeIf(entry ->
                    entry.getValue().trace() == context.trace());
                binding = new Binding(
                    UUID.randomUUID().toString(),
                    context.trace(), context.owner());
                bindings.put(binding.token(), binding);
            }
        }

        List<MethodDescription> methods =
            context.owner().getMethods().all().values().stream()
                .sorted(Comparator.comparing(RemoteMethod::name))
                .map(method -> describeMethod(context.trace(), method))
                .toList();
        return new Discovery(binding.token(), context, methods);
    }

    void requireBinding(TargetContext current, String token) {
        if (token == null || token.isBlank()) {
            throw problem(
                "stale_target_token", "target_token must not be blank");
        }
        Binding binding;
        synchronized (bindingLock) {
            binding = bindings.get(token);
        }
        if (binding == null
                || binding.trace() != current.trace()
                || binding.owner() != current.owner()
                || current.owner().isClosed()
                || !current.owner().isTarget(current.trace())) {
            if (binding != null) {
                synchronized (bindingLock) {
                    bindings.remove(token);
                }
            }
            throw problem(
                "stale_target_token",
                "target token no longer names the exact active trace owner");
        }
    }

    Object invoke(
            TargetContext current, String targetToken,
            String methodName, Object rawArguments, long timeoutMs) {
        requireBinding(current, targetToken);
        if (timeoutMs < MIN_TIMEOUT_MS || timeoutMs > MAX_TIMEOUT_MS) {
            throw problem(
                "invalid_timeout",
                "timeout_ms must be between " + MIN_TIMEOUT_MS
                    + " and " + MAX_TIMEOUT_MS);
        }
        if (methodName == null || methodName.isBlank()) {
            throw problem(
                "unknown_method", "method must not be blank");
        }
        RemoteMethod method =
            current.owner().getMethods().get(methodName);
        if (method == null || !methodName.equals(method.name())) {
            throw problem(
                "unknown_method",
                "active target has no exact remote method "
                    + methodName);
        }
        Map<String, Object> supplied =
            requireStringMap(rawArguments, "arguments", "invalid_arguments");
        Map<String, RemoteParameter> parameters = method.parameters();

        Set<String> unknown = new LinkedHashSet<>(supplied.keySet());
        unknown.removeAll(parameters.keySet());
        if (!unknown.isEmpty()) {
            throw problem(
                "unknown_argument",
                "method " + methodName + " has unknown arguments: "
                    + unknown);
        }

        Map<String, Object> decoded = new LinkedHashMap<>();
        for (RemoteParameter parameter : parameters.values().stream()
                .sorted(Comparator.comparing(RemoteParameter::name))
                .toList()) {
            String name = parameter.name();
            boolean present = supplied.containsKey(name);
            if (isSchema(parameter.type(), "VOID")) {
                if (parameter.required() || present) {
                    throw problem(
                        "unsupported_schema",
                        "method " + methodName + " parameter " + name
                            + " uses unsupported explicit VOID input");
                }
                continue;
            }
            if (!present) {
                if (parameter.required()) {
                    throw problem(
                        "missing_argument",
                        "method " + methodName
                            + " is missing required argument " + name);
                }
                continue;
            }
            decoded.put(
                name,
                decodeValue(
                    current.trace(), current.snapshot(),
                    parameter.type(), supplied.get(name),
                    "method " + methodName + " parameter " + name));
        }

        try {
            Trace validated = method.validate(decoded);
            if (validated != null && validated != current.trace()) {
                throw problem(
                    "foreign_trace_object",
                    "method " + methodName
                        + " arguments resolve to a different trace");
            }
        }
        catch (TargetMethodException error) {
            throw error;
        }
        catch (RuntimeException error) {
            throw new TargetMethodException(
                "invalid_argument",
                "method " + methodName
                    + " rejected its arguments: " + message(error),
                error);
        }

        RemoteAsyncResult future;
        try {
            future = method.invokeAsync(decoded);
            if (future == null) {
                throw problem(
                    "target_method_failed",
                    "method " + methodName
                        + " returned no invocation future");
            }
        }
        catch (TargetMethodException error) {
            throw error;
        }
        catch (RuntimeException error) {
            throw new TargetMethodException(
                "target_method_failed",
                "method " + methodName
                    + " failed before invocation: " + message(error),
                error);
        }

        Object result;
        try {
            result = future.get(timeoutMs, TimeUnit.MILLISECONDS);
        }
        catch (TimeoutException error) {
            future.cancel(true);
            throw new TargetMethodException(
                "target_method_timeout",
                "method " + methodName + " exceeded "
                    + timeoutMs + " ms",
                true);
        }
        catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            future.cancel(true);
            throw new TargetMethodException(
                "target_method_interrupted",
                "method " + methodName + " invocation was interrupted",
                true);
        }
        catch (ExecutionException error) {
            throw new TargetMethodException(
                "target_method_failed",
                "method " + methodName + " failed: "
                    + message(error.getCause()),
                error);
        }
        return encodeValue(
            current.trace(), method.retType(), result,
            "method " + methodName + " return");
    }

    static Object decodeValue(
            Trace trace, long snapshot, SchemaName schema,
            Object raw, String field) {
        Objects.requireNonNull(trace);
        Objects.requireNonNull(schema);
        String name = schema.name();
        try {
            return switch (name) {
                case "BOOL" -> requireBoolean(raw, field);
                case "BYTE" -> exactNumber(raw, field).byteValueExact();
                case "SHORT" -> exactNumber(raw, field).shortValueExact();
                case "INT" -> exactNumber(raw, field).intValueExact();
                case "LONG" -> exactNumber(raw, field).longValueExact();
                case "CHAR" -> requireCharacter(raw, field);
                case "STRING" -> requireStringAllowEmpty(raw, field);
                case "BOOL_ARR" -> decodeBooleanArray(raw, field);
                case "BYTE_ARR" -> decodeByteArray(raw, field);
                case "CHAR_ARR" ->
                    requireStringAllowEmpty(raw, field).toCharArray();
                case "SHORT_ARR" -> decodeShortArray(raw, field);
                case "INT_ARR" -> decodeIntArray(raw, field);
                case "LONG_ARR" -> decodeLongArray(raw, field);
                case "STRING_ARR" -> decodeStringArray(raw, field);
                case "ADDRESS" -> decodeAddress(trace, raw, field);
                case "RANGE" -> decodeRange(trace, raw, field);
                case "OBJECT" -> decodeObject(
                    trace, snapshot, raw, field);
                case "VOID" -> throw problem(
                    "unsupported_schema",
                    field + " cannot explicitly supply VOID");
                case "ANY", "TYPE", "EXECUTION_STATE",
                        "MAP_PARAMETERS" -> throw problem(
                    "unsupported_schema",
                    field + " uses unsupported schema " + name);
                default -> decodeObject(
                    trace, snapshot, raw, field);
            };
        }
        catch (TargetMethodException error) {
            throw error;
        }
        catch (ArithmeticException | IllegalArgumentException error) {
            throw new TargetMethodException(
                "invalid_argument",
                field + " is not a valid " + name + ": "
                    + message(error),
                error);
        }
    }

    static Object encodeValue(
            Trace trace, SchemaName schema, Object value,
            String field) {
        Objects.requireNonNull(trace);
        Objects.requireNonNull(schema);
        String name = schema.name();
        try {
            return switch (name) {
                case "VOID" -> {
                    if (value != null) {
                        throw problem(
                            "invalid_return",
                            field + " must be null for VOID");
                    }
                    yield null;
                }
                case "BOOL" -> requireClass(
                    value, Boolean.class, field, name);
                case "BYTE" -> ((Byte) requireClass(
                    value, Byte.class, field, name)).intValue();
                case "SHORT" -> ((Short) requireClass(
                    value, Short.class, field, name)).intValue();
                case "INT" -> requireClass(
                    value, Integer.class, field, name);
                case "LONG" -> requireClass(
                    value, Long.class, field, name);
                case "CHAR" -> String.valueOf(
                    requireClass(value, Character.class, field, name));
                case "STRING" -> requireClass(
                    value, String.class, field, name);
                case "BOOL_ARR" -> listFromArray(
                    requireArray(value, boolean[].class, field, name));
                case "BYTE_ARR" -> Map.of(
                    "encoding", "hex",
                    "data", hex((byte[]) requireArray(
                        value, byte[].class, field, name)));
                case "CHAR_ARR" -> new String(
                    (char[]) requireArray(
                        value, char[].class, field, name));
                case "SHORT_ARR" -> listFromArray(
                    requireArray(value, short[].class, field, name));
                case "INT_ARR" -> listFromArray(
                    requireArray(value, int[].class, field, name));
                case "LONG_ARR" -> listFromArray(
                    requireArray(value, long[].class, field, name));
                case "STRING_ARR" -> encodeStringArray(
                    value, field, name);
                case "ADDRESS" -> encodeAddress(value, field);
                case "RANGE" -> encodeRange(value, field);
                case "OBJECT" ->
                    encodeObject(trace, null, value, field);
                case "ANY", "TYPE", "EXECUTION_STATE",
                        "MAP_PARAMETERS" -> throw problem(
                    "unsupported_schema",
                    field + " uses unsupported schema " + name);
                default ->
                    encodeObject(trace, schema, value, field);
            };
        }
        catch (TargetMethodException error) {
            throw error;
        }
        catch (RuntimeException error) {
            throw new TargetMethodException(
                "invalid_return",
                field + " is not a valid " + name + ": "
                    + message(error),
                error);
        }
    }

    private MethodDescription describeMethod(
            Trace trace, RemoteMethod method) {
        List<ParameterDescription> parameters = new ArrayList<>();
        for (RemoteParameter parameter :
                method.parameters().values().stream()
                    .sorted(Comparator.comparing(RemoteParameter::name))
                    .toList()) {
            boolean available = false;
            Object encodedDefault = null;
            if (!parameter.required()) {
                try {
                    encodedDefault = encodeValue(
                        trace, parameter.type(),
                        parameter.getDefaultValue(),
                        "method " + method.name() + " parameter "
                            + parameter.name() + " default");
                    available = true;
                }
                catch (TargetMethodException ignored) {
                    // An unencodable optional default does not hide the method.
                }
            }
            parameters.add(new ParameterDescription(
                parameter.name(), parameter.type().name(),
                parameter.required(), available, encodedDefault,
                parameter.display(), parameter.description()));
        }
        return new MethodDescription(
            method.name(),
            method.action() == null ? null : method.action().name(),
            method.display(), method.description(),
            method.retType().name(), parameters);
    }

    private static void requireOwnerCurrent(TargetContext context) {
        if (context.owner().isClosed()
                || !context.owner().isTarget(context.trace())) {
            throw problem(
                "target_owner_changed",
                "TraceRMI owner is closed or no longer targets "
                    + context.traceName());
        }
    }

    private static Object decodeAddress(
            Trace trace, Object raw, String field) {
        Map<String, Object> map =
            requireExactMap(
                raw, field, Set.of("space", "offset"),
                "invalid_argument");
        String spaceName = requireString(map.get("space"), field + ".space");
        long offset =
            exactNumber(map.get("offset"), field + ".offset")
                .longValueExact();
        AddressSpace space =
            requireAddressSpace(trace, spaceName, field);
        return space.getAddress(offset);
    }

    private static Object decodeRange(
            Trace trace, Object raw, String field) {
        Map<String, Object> map =
            requireExactMap(
                raw, field, Set.of("space", "start", "end"),
                "invalid_argument");
        String spaceName = requireString(map.get("space"), field + ".space");
        long start =
            exactNumber(map.get("start"), field + ".start")
                .longValueExact();
        long end =
            exactNumber(map.get("end"), field + ".end")
                .longValueExact();
        AddressSpace space =
            requireAddressSpace(trace, spaceName, field);
        Address startAddress = space.getAddress(start);
        Address endAddress = space.getAddress(end);
        if (endAddress.compareTo(startAddress) < 0) {
            throw problem(
                "invalid_argument",
                field + " end precedes start");
        }
        return new AddressRangeImpl(
            startAddress, endAddress);
    }

    private static Object decodeObject(
            Trace trace, long snapshot, Object raw, String field) {
        Map<String, Object> map =
            requireExactMap(
                raw, field, Set.of("object_path"),
                "invalid_argument");
        String pathText =
            requireString(map.get("object_path"), field + ".object_path");
        KeyPath path;
        try {
            path = KeyPath.parse(pathText);
        }
        catch (RuntimeException error) {
            throw new TargetMethodException(
                "invalid_argument",
                field + " has invalid object_path " + pathText,
                error);
        }
        TraceObject object =
            trace.getObjectManager().getObjectByCanonicalPath(path);
        if (object == null || object.getTrace() != trace
                || object.isDeleted()) {
            throw problem(
                "invalid_argument",
                field + " does not name a canonical object in "
                    + trace.getName());
        }
        return object;
    }

    private static AddressSpace requireAddressSpace(
            Trace trace, String name, String field) {
        AddressFactory factory = trace.getBaseAddressFactory();
        AddressSpace space =
            factory == null ? null : factory.getAddressSpace(name);
        if (space == null) {
            throw problem(
                "invalid_argument",
                field + " names unknown address space " + name);
        }
        return space;
    }

    private static Object encodeAddress(Object value, String field) {
        Address address =
            (Address) requireClass(
                value, Address.class, field, "ADDRESS");
        return Map.of(
            "space", address.getAddressSpace().getName(),
            "offset", address.getOffset());
    }

    private static Object encodeRange(Object value, String field) {
        AddressRange range =
            (AddressRange) requireClass(
                value, AddressRange.class, field, "RANGE");
        if (range.getMinAddress().getAddressSpace()
                != range.getMaxAddress().getAddressSpace()) {
            throw problem(
                "invalid_return",
                field + " spans multiple address spaces");
        }
        return Map.of(
            "space",
            range.getMinAddress().getAddressSpace().getName(),
            "start", range.getMinAddress().getOffset(),
            "end", range.getMaxAddress().getOffset());
    }

    private static Object encodeObject(
            Trace trace, SchemaName expectedName,
            Object value, String field) {
        TraceObject object =
            (TraceObject) requireClass(
                value, TraceObject.class, field, "OBJECT");
        if (object.getTrace() != trace || object.isDeleted()) {
            throw problem(
                "invalid_return",
                field + " is not an object in the active trace");
        }
        if (expectedName != null) {
            TraceObjectSchema root =
                trace.getObjectManager().getRootSchema();
            TraceObjectSchema expected =
                root == null ? null :
                    root.getContext().getSchemaOrNull(expectedName);
            if (expected == null
                    || !expected.isAssignableFrom(
                        object.getSchema())) {
                throw problem(
                    "invalid_return",
                    field + " is not assignable to trace schema "
                        + expectedName.name());
            }
        }
        return Map.of(
            "object_path", object.getCanonicalPath().toString());
    }

    private static boolean[] decodeBooleanArray(
            Object raw, String field) {
        List<?> values = requireList(raw, field);
        boolean[] result = new boolean[values.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = requireBoolean(
                values.get(i), field + "[" + i + "]");
        }
        return result;
    }

    private static byte[] decodeByteArray(
            Object raw, String field) {
        Map<String, Object> map =
            requireExactMap(
                raw, field, Set.of("encoding", "data"),
                "invalid_argument");
        if (!"hex".equals(map.get("encoding"))) {
            throw problem(
                "invalid_argument",
                field + ".encoding must be hex");
        }
        String data = requireStringAllowEmpty(
            map.get("data"), field + ".data");
        if ((data.length() & 1) != 0
                || !data.matches("[0-9a-fA-F]*")) {
            throw problem(
                "invalid_argument",
                field + ".data must be even-length hexadecimal");
        }
        byte[] result = new byte[data.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(
                data.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    private static short[] decodeShortArray(
            Object raw, String field) {
        List<?> values = requireList(raw, field);
        short[] result = new short[values.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] =
                exactNumber(values.get(i), field + "[" + i + "]")
                    .shortValueExact();
        }
        return result;
    }

    private static int[] decodeIntArray(
            Object raw, String field) {
        List<?> values = requireList(raw, field);
        int[] result = new int[values.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] =
                exactNumber(values.get(i), field + "[" + i + "]")
                    .intValueExact();
        }
        return result;
    }

    private static long[] decodeLongArray(
            Object raw, String field) {
        List<?> values = requireList(raw, field);
        long[] result = new long[values.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] =
                exactNumber(values.get(i), field + "[" + i + "]")
                    .longValueExact();
        }
        return result;
    }

    private static String[] decodeStringArray(
            Object raw, String field) {
        List<?> values = requireList(raw, field);
        String[] result = new String[values.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] =
                requireStringAllowEmpty(
                    values.get(i), field + "[" + i + "]");
        }
        return result;
    }

    private static Object encodeStringArray(
            Object value, String field, String schema) {
        String[] array =
            (String[]) requireArray(
                value, String[].class, field, schema);
        for (int i = 0; i < array.length; i++) {
            if (array[i] == null) {
                throw problem(
                    "invalid_return",
                    field + "[" + i + "] must not be null");
            }
        }
        return List.of(array);
    }

    private static List<Object> listFromArray(Object array) {
        int length = Array.getLength(array);
        List<Object> result = new ArrayList<>(length);
        for (int i = 0; i < length; i++) {
            result.add(Array.get(array, i));
        }
        return List.copyOf(result);
    }

    private static Object requireArray(
            Object value, Class<?> type, String field, String schema) {
        if (value == null || value.getClass() != type) {
            throw problem(
                "invalid_return",
                field + " must be an exact " + schema
                    + " Java array");
        }
        return value;
    }

    private static Object requireClass(
            Object value, Class<?> type, String field, String schema) {
        if (value == null || !type.isInstance(value)) {
            throw problem(
                "invalid_return",
                field + " must be an exact " + schema
                    + " Java value");
        }
        return value;
    }

    private static boolean requireBoolean(
            Object raw, String field) {
        if (!(raw instanceof Boolean value)) {
            throw problem(
                "invalid_argument",
                field + " must be a JSON boolean");
        }
        return value;
    }

    private static char requireCharacter(Object raw, String field) {
        String text = requireString(raw, field);
        if (text.length() != 1) {
            throw problem(
                "invalid_argument",
                field + " must contain exactly one UTF-16 code unit");
        }
        return text.charAt(0);
    }

    private static String requireString(Object raw, String field) {
        if (!(raw instanceof String text) || text.isEmpty()) {
            throw problem(
                "invalid_argument",
                field + " must be a non-empty JSON string");
        }
        return text;
    }

    private static String requireStringAllowEmpty(
            Object raw, String field) {
        if (!(raw instanceof String text)) {
            throw problem(
                "invalid_argument",
                field + " must be a JSON string");
        }
        return text;
    }

    private static BigDecimal exactNumber(Object raw, String field) {
        if (!(raw instanceof Number number)
                || raw instanceof Boolean) {
            throw problem(
                "invalid_argument",
                field + " must be an exact JSON integer");
        }
        try {
            return new BigDecimal(String.valueOf(number));
        }
        catch (NumberFormatException error) {
            throw new TargetMethodException(
                "invalid_argument",
                field + " must be an exact JSON integer",
                error);
        }
    }

    private static List<?> requireList(Object raw, String field) {
        if (!(raw instanceof List<?> values)) {
            throw problem(
                "invalid_argument",
                field + " must be a native JSON array");
        }
        return values;
    }

    private static Map<String, Object> requireStringMap(
            Object raw, String field, String code) {
        if (!(raw instanceof Map<?, ?> map)) {
            throw problem(code, field + " must be a native JSON object");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw problem(
                    code, field + " keys must be strings");
            }
            result.put(key, entry.getValue());
        }
        return result;
    }

    private static Map<String, Object> requireExactMap(
            Object raw, String field, Set<String> fields,
            String code) {
        Map<String, Object> map =
            requireStringMap(raw, field, code);
        if (!map.keySet().equals(fields)) {
            throw problem(
                code, field + " must contain exactly " + fields);
        }
        return map;
    }

    private static boolean isSchema(
            SchemaName schema, String name) {
        return schema != null && name.equals(schema.name());
    }

    private static String hex(byte[] value) {
        char[] chars = new char[value.length * 2];
        char[] digits = "0123456789abcdef".toCharArray();
        for (int i = 0; i < value.length; i++) {
            int item = value[i] & 0xff;
            chars[i * 2] = digits[item >>> 4];
            chars[i * 2 + 1] = digits[item & 0xf];
        }
        return new String(chars);
    }

    private static String message(Throwable error) {
        if (error == null) {
            return "unknown failure";
        }
        return error.getMessage() == null
            ? error.getClass().getSimpleName()
            : error.getMessage();
    }

    private static TargetMethodException problem(
            String code, String message) {
        return new TargetMethodException(code, message);
    }
}
