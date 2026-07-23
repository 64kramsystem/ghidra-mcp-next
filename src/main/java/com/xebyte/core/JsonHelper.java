package com.xebyte.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.ToNumberPolicy;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.lang.reflect.Type;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Gson-backed JSON utilities replacing hand-built StringBuilder JSON.
 * Thread-safe: Gson instances are immutable and reusable across threads.
 */
public final class JsonHelper {

    private static final Gson GSON = new GsonBuilder()
            .disableHtmlEscaping()
            .create();
    private static final Gson BODY_GSON = new GsonBuilder()
            .disableHtmlEscaping()
            .setObjectToNumberStrategy(ToNumberPolicy.BIG_DECIMAL)
            .create();
    private static final TypeAdapter<Object> BODY_OBJECT_ADAPTER =
            BODY_GSON.getAdapter(Object.class);
    private static final Type STRING_OBJECT_MAP_TYPE =
            new TypeToken<LinkedHashMap<String, Object>>() { }.getType();

    private JsonHelper() {}

    /** Serialize any object to JSON string. */
    public static String toJson(Object obj) {
        // Gson's Object overload drops explicit JsonNull members because its
        // writer has serializeNulls disabled. A pre-built JSON tree is already
        // the caller's exact wire representation, so preserve it verbatim.
        if (obj instanceof JsonElement element) {
            return element.toString();
        }
        return GSON.toJson(obj);
    }

    /** Build a LinkedHashMap from alternating key-value pairs (preserves field order). */
    public static Map<String, Object> mapOf(Object... kvPairs) {
        if (kvPairs.length % 2 != 0) {
            throw new IllegalArgumentException("mapOf requires even number of arguments");
        }
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < kvPairs.length; i += 2) {
            map.put(String.valueOf(kvPairs[i]), kvPairs[i + 1]);
        }
        return map;
    }

    /** Create a standard error JSON response: {"error": "message"} */
    public static String errorJson(String message) {
        return GSON.toJson(Map.of("error", message != null ? message : "Unknown error"));
    }

    /** Parse JSON from an InputStream (for HTTP request bodies). */
    public static Map<String, Object> parseBody(InputStream input) {
        try (InputStreamReader reader = new InputStreamReader(input, StandardCharsets.UTF_8)) {
            Map<String, Object> result =
                BODY_GSON.fromJson(reader, STRING_OBJECT_MAP_TYPE);
            return result != null ? result : new LinkedHashMap<>();
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    /**
     * Parse a request body while decoding selected native byte-array fields
     * directly from the JSON stream.
     *
     * <p>Ordinary fields retain the same Gson/BIG_DECIMAL representation as
     * {@link #parseBody(InputStream)}. A marked field accepts either a string
     * (left for the endpoint's hex decoder) or a JSON numeric array, which is
     * compacted directly to {@code byte[]} without first constructing a
     * {@code List<BigDecimal>} or re-serializing it.
     */
    public static Map<String, Object> parseBody(
            InputStream input, Map<String, Integer> nativeByteLimits) {
        if (nativeByteLimits == null || nativeByteLimits.isEmpty()) {
            return parseBody(input);
        }
        try (InputStreamReader inputReader =
                new InputStreamReader(input, StandardCharsets.UTF_8);
                JsonReader reader = new JsonReader(inputReader)) {
            Map<String, Object> result = new LinkedHashMap<>();
            reader.beginObject();
            while (reader.hasNext()) {
                String name = reader.nextName();
                Integer limit = nativeByteLimits.get(name);
                result.put(
                    name,
                    limit == null
                        ? BODY_OBJECT_ADAPTER.read(reader)
                        : readNativeBytes(reader, name, limit));
            }
            reader.endObject();
            return result;
        }
        catch (IllegalArgumentException error) {
            throw error;
        }
        catch (Exception error) {
            return new LinkedHashMap<>();
        }
    }

    private static Object readNativeBytes(
            JsonReader reader, String name, int limit) throws IOException {
        if (limit <= 0) {
            throw new IllegalArgumentException(
                "native byte limit must be positive for " + name);
        }
        JsonToken token = reader.peek();
        if (token == JsonToken.NULL) {
            reader.nextNull();
            return null;
        }
        if (token == JsonToken.STRING) {
            return reader.nextString();
        }
        if (token != JsonToken.BEGIN_ARRAY) {
            throw new IllegalArgumentException(
                name + " must be a hex string or byte array");
        }

        byte[] result = new byte[Math.min(8192, limit)];
        int count = 0;
        reader.beginArray();
        while (reader.hasNext()) {
            if (count >= limit) {
                throw new IllegalArgumentException(
                    name + " exceeds maximum of " + limit + " bytes");
            }
            if (reader.peek() != JsonToken.NUMBER) {
                throw new IllegalArgumentException(
                    name + " array values must be integers from 0 to 255");
            }
            int value;
            try {
                value = new BigDecimal(reader.nextString()).intValueExact();
            }
            catch (ArithmeticException | NumberFormatException error) {
                throw new IllegalArgumentException(
                    name + " array values must be integers from 0 to 255",
                    error);
            }
            if (value < 0 || value > 255) {
                throw new IllegalArgumentException(
                    name + " array values must be integers from 0 to 255");
            }
            if (count == result.length) {
                int nextLength = Math.min(
                    limit,
                    Math.max(count + 1, result.length * 2));
                result = Arrays.copyOf(result, nextLength);
            }
            result[count++] = (byte) value;
        }
        reader.endArray();
        return count == result.length
            ? result
            : Arrays.copyOf(result, count);
    }

    /** Decode one JSON numeric byte array without building an object tree. */
    static byte[] parseNativeByteArray(
            String json, String name, int limit) {
        try (JsonReader reader = new JsonReader(new StringReader(json))) {
            Object parsed = readNativeBytes(reader, name, limit);
            if (!(parsed instanceof byte[] bytes)
                    || reader.peek() != JsonToken.END_DOCUMENT) {
                throw new IllegalArgumentException(
                    name + " must be a byte array");
            }
            return bytes;
        }
        catch (IllegalArgumentException error) {
            throw error;
        }
        catch (IOException error) {
            throw new IllegalArgumentException(
                name + " must be a byte array", error);
        }
    }

    /** Parse a JSON string into a Map. */
    public static Map<String, Object> parseJson(String json) {
        try {
            Map<String, Object> result = GSON.fromJson(json, STRING_OBJECT_MAP_TYPE);
            return result != null ? result : new LinkedHashMap<>();
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    /**
     * Safely extract an int from a parsed JSON map value.
     * Gson parses JSON numbers as Double by default; this handles Double, Integer, Long, and String.
     */
    public static int getInt(Object obj, int defaultValue) {
        if (obj instanceof Number n) return n.intValue();
        if (obj instanceof String s) {
            try { return Integer.parseInt(s); } catch (NumberFormatException e) { return defaultValue; }
        }
        return defaultValue;
    }

    /**
     * Convert parsed JSON list of objects to List<Map<String, String>> for legacy callers.
     * Gson returns nested objects as LinkedTreeMap<String, Object>; this converts values to strings.
     */
    public static java.util.List<Map<String, String>> toMapStringList(Object obj) {
        if (!(obj instanceof java.util.List<?> list)) return null;
        java.util.List<Map<String, String>> result = new java.util.ArrayList<>();
        for (Object item : list) {
            if (item instanceof Map<?, ?> map) {
                Map<String, String> strMap = new LinkedHashMap<>();
                map.forEach((k, v) -> strMap.put(String.valueOf(k), v != null ? String.valueOf(v) : null));
                result.add(strMap);
            }
        }
        return result;
    }

    /**
     * Convert a parsed JSON array element to List<Map<String, String>>.
     */
    public static List<Map<String, String>> toMapStringList(JsonElement jsonElement) {
        if (jsonElement == null || !jsonElement.isJsonArray()) return null;
        List<Map<String, String>> result = new ArrayList<>();
        for (JsonElement item : jsonElement.getAsJsonArray()) {
            if (item != null && item.isJsonObject()) {
                Map<String, Object> rawMap = GSON.fromJson(item, STRING_OBJECT_MAP_TYPE);
                Map<String, String> strMap = new LinkedHashMap<>();
                rawMap.forEach((k, v) -> strMap.put(String.valueOf(k), v != null ? String.valueOf(v) : null));
                result.add(strMap);
            }
        }
        return result;
    }
}
