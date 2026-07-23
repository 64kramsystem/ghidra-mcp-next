package com.xebyte.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import ghidra.program.model.mem.Memory;

/**
 * Strict, platform-neutral parser for versioned symbol profiles.
 *
 * <p>This class deliberately performs no Ghidra program lookup. It validates
 * the portable profile schema and normalizes optional collections and scalar
 * defaults. Program-dependent address and conflict checks belong to
 * {@link SymbolProfileService}.
 */
public final class SymbolProfileParser {
    private static final Pattern SYMBOL_NAME =
        Pattern.compile("[A-Za-z_.$?][A-Za-z0-9_.$?@-]*");
    private static final Pattern ADDRESS_SPACE =
        Pattern.compile("[A-Za-z0-9_.$?@:+-]+");
    private static final Pattern HEX = Pattern.compile("[0-9A-Fa-f]+");

    private static final Set<String> PROFILE_FIELDS = Set.of(
        "schema_version", "id", "version", "description",
        "symbols", "equates", "comments", "memory_blocks");
    private static final Set<String> SYMBOL_FIELDS = Set.of(
        "address", "name", "namespace", "kind", "primary",
        "source_note");
    private static final Set<String> EQUATE_FIELDS = Set.of(
        "name", "value", "description", "applications");
    private static final Set<String> APPLICATION_FIELDS = Set.of(
        "address", "operand_index", "scalar_index");
    private static final Set<String> COMMENT_FIELDS = Set.of(
        "address", "type", "text");
    private static final Set<String> BLOCK_FIELDS = Set.of(
        "name", "start", "length", "fill", "overlay",
        "read", "write", "execute", "comment");

    public enum SymbolKind {
        LABEL("label"),
        ENTRY_POINT("entry_point");

        private final String wireName;

        SymbolKind(String wireName) {
            this.wireName = wireName;
        }

        static SymbolKind parse(String value, String path) {
            for (SymbolKind kind : values()) {
                if (kind.wireName.equals(value)) {
                    return kind;
                }
            }
            throw invalid(path + " kind must be 'label' or 'entry_point'");
        }
    }

    public enum CommentType {
        PLATE("plate"),
        PRE("pre"),
        POST("post"),
        EOL("eol"),
        REPEATABLE("repeatable");

        private final String wireName;

        CommentType(String wireName) {
            this.wireName = wireName;
        }

        public String wireName() {
            return wireName;
        }

        static CommentType parse(String value, String path) {
            for (CommentType type : values()) {
                if (type.wireName.equals(value)) {
                    return type;
                }
            }
            throw invalid(
                path + " type must be one of plate, pre, post, eol, repeatable");
        }
    }

    public record SymbolProfile(
            int schemaVersion,
            String id,
            String version,
            String description,
            List<ProfileSymbol> symbols,
            List<ProfileEquate> equates,
            List<ProfileComment> comments,
            List<ProfileMemoryBlock> memoryBlocks) {
    }

    public record ProfileSymbol(
            String address,
            String name,
            String namespace,
            SymbolKind kind,
            boolean primary,
            String sourceNote) {

        public String qualifiedName() {
            return namespace.isEmpty()
                ? name
                : namespace + "::" + name;
        }
    }

    public record ProfileEquate(
            String name,
            long value,
            String description,
            List<EquateApplication> applications) {
    }

    public record EquateApplication(
            String address,
            int operandIndex,
            Integer scalarIndex) {
    }

    public record ProfileComment(
            String address,
            CommentType type,
            String text) {
    }

    public record ProfileMemoryBlock(
            String name,
            String start,
            long length,
            Integer fill,
            boolean overlay,
            boolean read,
            boolean write,
            boolean execute,
            String comment) {
    }

    public SymbolProfile parse(Object input) {
        JsonElement root;
        if (input instanceof JsonElement element) {
            root = element;
        }
        else {
            try {
                root = JsonParser.parseString(JsonHelper.toJson(input));
            }
            catch (RuntimeException error) {
                throw invalid("profile must be a JSON object");
            }
        }
        JsonObject object = requireObject(root, "profile");
        rejectUnknown(object, PROFILE_FIELDS, "profile");

        int schemaVersion = requireInt(object, "schema_version", "profile");
        if (schemaVersion != 1) {
            throw invalid(
                "unsupported schema_version " + schemaVersion
                    + "; supported versions: 1");
        }
        String id = requireNonBlankString(object, "id", "profile");
        String version =
            requireNonBlankString(object, "version", "profile");
        String description =
            optionalString(object, "description", "", "profile");

        List<ProfileSymbol> symbols = parseSymbols(
            optionalArray(object, "symbols", "profile"));
        List<ProfileEquate> equates = parseEquates(
            optionalArray(object, "equates", "profile"));
        List<ProfileComment> comments = parseComments(
            optionalArray(object, "comments", "profile"));
        List<ProfileMemoryBlock> blocks = parseBlocks(
            optionalArray(object, "memory_blocks", "profile"));

        return new SymbolProfile(
            schemaVersion,
            id,
            version,
            description,
            List.copyOf(symbols),
            List.copyOf(equates),
            List.copyOf(comments),
            List.copyOf(blocks));
    }

    private static List<ProfileSymbol> parseSymbols(JsonArray array) {
        List<ProfileSymbol> result = new ArrayList<>();
        Set<String> identities = new HashSet<>();
        for (int index = 0; index < array.size(); index++) {
            String path = "symbols[" + index + "]";
            JsonObject object = requireObject(array.get(index), path);
            rejectUnknown(object, SYMBOL_FIELDS, path);
            String address = requireAddress(object, "address", path);
            String name = requireName(object, "name", path, "symbol");
            String namespace =
                optionalString(object, "namespace", "", path);
            validateNamespace(namespace, path);
            SymbolKind kind = SymbolKind.parse(
                optionalString(object, "kind", "label", path), path);
            boolean primary =
                optionalBoolean(object, "primary", false, path);
            String sourceNote =
                optionalString(object, "source_note", "", path);
            ProfileSymbol symbol = new ProfileSymbol(
                address, name, namespace, kind, primary, sourceNote);
            if (!identities.add(symbol.qualifiedName())) {
                throw invalid(
                    "duplicate symbol identity '" + symbol.qualifiedName()
                        + "'");
            }
            result.add(symbol);
        }
        return result;
    }

    private static List<ProfileEquate> parseEquates(JsonArray array) {
        List<ProfileEquate> result = new ArrayList<>();
        Set<String> identities = new HashSet<>();
        Set<String> applicationIdentities = new HashSet<>();
        for (int index = 0; index < array.size(); index++) {
            String path = "equates[" + index + "]";
            JsonObject object = requireObject(array.get(index), path);
            rejectUnknown(object, EQUATE_FIELDS, path);
            String name = requireName(object, "name", path, "equate");
            long value = requireLong(object, "value", path);
            String description =
                optionalString(object, "description", "", path);
            if (!identities.add(name)) {
                throw invalid("duplicate equate identity '" + name + "'");
            }
            List<EquateApplication> applications = new ArrayList<>();
            JsonArray applicationArray =
                optionalArray(object, "applications", path);
            for (int applicationIndex = 0;
                    applicationIndex < applicationArray.size();
                    applicationIndex++) {
                String applicationPath =
                    path + ".applications[" + applicationIndex + "]";
                JsonObject applicationObject = requireObject(
                    applicationArray.get(applicationIndex), applicationPath);
                rejectUnknown(
                    applicationObject,
                    APPLICATION_FIELDS,
                    applicationPath);
                String address = requireAddress(
                    applicationObject, "address", applicationPath);
                int operandIndex = requireNonNegativeInt(
                    applicationObject,
                    "operand_index",
                    applicationPath);
                Integer scalarIndex = optionalNonNegativeInt(
                    applicationObject,
                    "scalar_index",
                    applicationPath);
                EquateApplication application = new EquateApplication(
                    address, operandIndex, scalarIndex);
                String identity =
                    address.toLowerCase(Locale.ROOT)
                        + ":" + operandIndex + ":"
                        + (scalarIndex == null ? "*" : scalarIndex);
                if (!applicationIdentities.add(identity)) {
                    throw invalid(
                        "duplicate equate application identity '"
                            + identity + "'");
                }
                applications.add(application);
            }
            result.add(new ProfileEquate(
                name,
                value,
                description,
                List.copyOf(applications)));
        }
        return result;
    }

    private static List<ProfileComment> parseComments(JsonArray array) {
        List<ProfileComment> result = new ArrayList<>();
        Set<String> identities = new HashSet<>();
        for (int index = 0; index < array.size(); index++) {
            String path = "comments[" + index + "]";
            JsonObject object = requireObject(array.get(index), path);
            rejectUnknown(object, COMMENT_FIELDS, path);
            String address = requireAddress(object, "address", path);
            CommentType type = CommentType.parse(
                requireNonBlankString(object, "type", path), path);
            String text = requireString(object, "text", path);
            String identity =
                address.toLowerCase(Locale.ROOT) + ":" + type.wireName();
            if (!identities.add(identity)) {
                throw invalid(
                    "duplicate comment identity '" + identity + "'");
            }
            result.add(new ProfileComment(address, type, text));
        }
        return result;
    }

    private static List<ProfileMemoryBlock> parseBlocks(JsonArray array) {
        List<ProfileMemoryBlock> result = new ArrayList<>();
        Set<String> identities = new HashSet<>();
        for (int index = 0; index < array.size(); index++) {
            String path = "memory_blocks[" + index + "]";
            JsonObject object = requireObject(array.get(index), path);
            rejectUnknown(object, BLOCK_FIELDS, path);
            String name =
                requireNonBlankString(object, "name", path);
            if (!Memory.isValidMemoryBlockName(name)) {
                throw invalid(
                    path + " invalid memory block name '" + name + "'");
            }
            String start = requireAddress(object, "start", path);
            long length = requireLong(object, "length", path);
            if (length <= 0) {
                throw invalid(path + " length must be positive");
            }
            Integer fill = optionalNonNegativeInt(
                object, "fill", path);
            if (fill != null && fill > 255) {
                throw invalid(path + " fill must be from 0 to 255");
            }
            boolean overlay =
                optionalBoolean(object, "overlay", false, path);
            boolean read =
                optionalBoolean(object, "read", true, path);
            boolean write =
                optionalBoolean(object, "write", false, path);
            boolean execute =
                optionalBoolean(object, "execute", false, path);
            String comment =
                optionalString(object, "comment", "", path);
            if (!identities.add(name)) {
                throw invalid(
                    "duplicate memory block identity '" + name + "'");
            }
            result.add(new ProfileMemoryBlock(
                name,
                start,
                length,
                fill,
                overlay,
                read,
                write,
                execute,
                comment));
        }
        return result;
    }

    private static JsonObject requireObject(
            JsonElement element, String path) {
        if (element == null || !element.isJsonObject()) {
            throw invalid(path + " must be a JSON object");
        }
        return element.getAsJsonObject();
    }

    private static JsonArray optionalArray(
            JsonObject object, String name, String path) {
        JsonElement element = object.get(name);
        if (element == null) {
            return new JsonArray();
        }
        if (!element.isJsonArray()) {
            throw invalid(path + " " + name + " must be an array");
        }
        return element.getAsJsonArray();
    }

    private static void rejectUnknown(
            JsonObject object, Set<String> allowed, String path) {
        Set<String> unknown = new LinkedHashSet<>(object.keySet());
        unknown.removeAll(allowed);
        if (!unknown.isEmpty()) {
            String name = unknown.iterator().next();
            String prefix = "profile".equals(path) ? "" : path + ": ";
            throw invalid(prefix + "unknown field '" + name + "'");
        }
    }

    private static String requireAddress(
            JsonObject object, String name, String path) {
        String value = requireNonBlankString(object, name, path);
        String space = "";
        String offset = value;
        int colon = value.lastIndexOf(':');
        if (colon >= 0) {
            space = value.substring(0, colon);
            offset = value.substring(colon + 1);
            if (space.isEmpty() || !ADDRESS_SPACE.matcher(space).matches()) {
                throw invalid(path + " " + name + " has invalid address space");
            }
        }
        if (offset.startsWith("0x") || offset.startsWith("0X")) {
            offset = offset.substring(2);
        }
        if (offset.isEmpty() || !HEX.matcher(offset).matches()) {
            throw invalid(path + " " + name + " is not a hexadecimal address");
        }
        return value;
    }

    private static String requireName(
            JsonObject object,
            String name,
            String path,
            String kind) {
        String value = requireNonBlankString(object, name, path);
        if (!SYMBOL_NAME.matcher(value).matches()) {
            throw invalid(path + " invalid " + kind + " name '" + value + "'");
        }
        return value;
    }

    private static void validateNamespace(String namespace, String path) {
        if (namespace.isEmpty()) {
            return;
        }
        for (String component : namespace.split("::", -1)) {
            if (!SYMBOL_NAME.matcher(component).matches()) {
                throw invalid(path + " invalid namespace '" + namespace + "'");
            }
        }
    }

    private static String requireString(
            JsonObject object, String name, String path) {
        JsonElement element = object.get(name);
        if (element == null
                || !element.isJsonPrimitive()
                || !element.getAsJsonPrimitive().isString()) {
            throw invalid(path + " " + name + " must be a string");
        }
        return element.getAsString();
    }

    private static String requireNonBlankString(
            JsonObject object, String name, String path) {
        String value = requireString(object, name, path);
        if (value.isBlank()) {
            throw invalid(path + " " + name + " must not be blank");
        }
        return value;
    }

    private static String optionalString(
            JsonObject object,
            String name,
            String defaultValue,
            String path) {
        if (!object.has(name)) {
            return defaultValue;
        }
        return requireString(object, name, path);
    }

    private static boolean optionalBoolean(
            JsonObject object,
            String name,
            boolean defaultValue,
            String path) {
        JsonElement element = object.get(name);
        if (element == null) {
            return defaultValue;
        }
        if (!element.isJsonPrimitive()
                || !element.getAsJsonPrimitive().isBoolean()) {
            throw invalid(path + " " + name + " must be a boolean");
        }
        return element.getAsBoolean();
    }

    private static int requireInt(
            JsonObject object, String name, String path) {
        long value = requireLong(object, name, path);
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
            throw invalid(path + " " + name + " is outside integer range");
        }
        return (int) value;
    }

    private static int requireNonNegativeInt(
            JsonObject object, String name, String path) {
        int value = requireInt(object, name, path);
        if (value < 0) {
            throw invalid(path + " " + name + " must not be negative");
        }
        return value;
    }

    private static Integer optionalNonNegativeInt(
            JsonObject object, String name, String path) {
        if (!object.has(name)) {
            return null;
        }
        return requireNonNegativeInt(object, name, path);
    }

    private static long requireLong(
            JsonObject object, String name, String path) {
        JsonElement element = object.get(name);
        if (element == null
                || !element.isJsonPrimitive()
                || !element.getAsJsonPrimitive().isNumber()) {
            throw invalid(path + " " + name + " must be an integer");
        }
        JsonPrimitive primitive = element.getAsJsonPrimitive();
        try {
            return new BigDecimal(primitive.getAsString()).longValueExact();
        }
        catch (ArithmeticException | NumberFormatException error) {
            throw invalid(path + " " + name + " must be an integer");
        }
    }

    private static IllegalArgumentException invalid(String message) {
        return new IllegalArgumentException(message);
    }
}
