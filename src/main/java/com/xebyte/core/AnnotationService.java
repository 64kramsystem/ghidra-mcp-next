package com.xebyte.core;

import com.google.gson.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Portable annotations for the same mapped program bytes. */
public final class AnnotationService {
    private static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();
    private final ProgramProvider provider;
    private final ThreadingStrategy threading;
    private final SecurityConfig security;

    public AnnotationService(ProgramProvider provider, ThreadingStrategy threading) {
        this(provider, threading, SecurityConfig.getInstance());
    }

    AnnotationService(ProgramProvider provider, ThreadingStrategy threading, SecurityConfig security) {
        this.provider = provider;
        this.threading = threading;
        this.security = security;
    }

    @McpTool(path = "/export_annotations", method = "POST", description = "Export a deterministic annotation snapshot; replacement rejects annotation loss unless allowed.")
    public Response exportAnnotations(
            @Param(value = "output_path", source = ParamSource.BODY) String outputPath,
            @Param(value = "overwrite", source = ParamSource.BODY, defaultValue = "false") boolean overwrite,
            @Param(value = "allow_loss", source = ParamSource.BODY, defaultValue = "false") boolean allowLoss,
            @Param(value = "program", defaultValue = "") String programName) {
        var pe = ServiceUtils.getProgramOrError(provider, programName);
        if (pe.hasError()) return pe.error();
        Path temp = null;
        try {
            Path path = path(outputPath);
            if (!Files.isDirectory(path.getParent())) throw new IllegalArgumentException("destination parent is not a directory");
            boolean replacing = Files.exists(path);
            if (replacing && !overwrite) throw new IllegalArgumentException("destination already exists");
            long version = pe.program().getModificationNumber();
            JsonObject snapshot = collect(pe.program());
            JsonArray losses = new JsonArray();
            if (replacing) {
                JsonObject old = parse(path);
                validateShape(old);
                if (!old.get("source").equals(snapshot.get("source"))) throw new IllegalArgumentException("source identity mismatch");
                losses = losses(old, snapshot, pe.program());
                if (!allowLoss && !losses.isEmpty()) throw new IllegalArgumentException("annotation loss: " + losses);
            }
            temp = ExportService.siblingTemporaryPath(path);
            Files.writeString(temp, JSON.toJson(snapshot) + "\n", StandardOpenOption.CREATE_NEW);
            if (version != pe.program().getModificationNumber()) throw new IllegalStateException("program changed during export");
            ExportService.publish(temp, path, replacing);
            return Response.ok(JsonHelper.mapOf("output_path", path.toString(), "loss_count", losses.size(), "losses", losses));
        } catch (Exception e) {
            return Response.err(message(e));
        } finally {
            if (temp != null) try { Files.deleteIfExists(temp); } catch (Exception ignored) { }
        }
    }

    @McpTool(path = "/import_annotations", method = "POST", description = "Overlay a snapshot on the same mapped program; absent records do not delete annotations. Function names become labels when no function exists.")
    public Response importAnnotations(
            @Param(value = "input_path", source = ParamSource.BODY) String inputPath,
            @Param(value = "program", defaultValue = "") String programName) {
        var pe = ServiceUtils.getProgramOrError(provider, programName);
        if (pe.hasError()) return pe.error();
        try {
            Program program = pe.program();
            JsonObject snapshot = parse(path(inputPath));
            validateShape(snapshot);
            validate(program, snapshot);
            return threading.executeWrite(program, "Import annotations", () -> {
                validate(program, snapshot);
                return Response.ok(apply(program, snapshot));
            });
        } catch (Exception e) { return Response.err(message(e)); }
    }

    private Path path(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("path is required");
        Path path = security.resolveWithinFileRoot(value);
        if (path == null) throw new IllegalArgumentException("path is outside GHIDRA_MCP_FILE_ROOT");
        return path;
    }

    private static String message(Exception e) { return e.getMessage() == null ? e.toString() : e.getMessage(); }
    private static JsonObject parse(Path path) throws Exception { return JsonParser.parseString(Files.readString(path)).getAsJsonObject(); }

    private static JsonObject collect(Program program) throws Exception {
        JsonObject root = new JsonObject();
        root.addProperty("format", "ghidra-mcp-annotations");
        root.addProperty("schema", 1);
        root.add("source", source(program));
        root.add("view", view(program));
        List<JsonObject> symbols = new ArrayList<>(), comments = new ArrayList<>(), data = new ArrayList<>();
        var table = program.getSymbolTable();
        for (var symbol : table.getAllSymbols(false)) {
            if ((symbol.getSource() != SourceType.USER_DEFINED && symbol.getSource() != SourceType.IMPORTED)
                    || !program.getMemory().contains(symbol.getAddress())
                    || (symbol.getSymbolType() != SymbolType.LABEL && symbol.getSymbolType() != SymbolType.FUNCTION)) continue;
            JsonObject row = address(symbol.getAddress());
            JsonArray namespace = new JsonArray();
            List<String> names = new ArrayList<>();
            for (Namespace ns = symbol.getParentNamespace(); !ns.isGlobal(); ns = ns.getParentNamespace()) names.add(ns.getName());
            Collections.reverse(names); names.forEach(namespace::add);
            row.add("namespace", namespace);
            row.addProperty("name", symbol.getName());
            row.addProperty("kind", symbol.getSymbolType() == SymbolType.FUNCTION ? "function" : "label");
            row.addProperty("source", symbol.getSource().name());
            row.addProperty("primary", symbol.isPrimary());
            symbols.add(row);
        }
        var listing = program.getListing();
        for (var addr : listing.getCommentAddressIterator(program.getMemory(), true)) {
            for (CommentType kind : CommentType.values()) {
                String text = listing.getComment(kind, addr);
                if (text == null) continue;
                JsonObject row = address(addr); row.addProperty("kind", kind.name()); row.addProperty("text", text); comments.add(row);
            }
        }
        var opaque = program.getUsrPropertyManager().getPropertyMap("listing.opaque");
        for (var item : listing.getDefinedData(true)) {
            JsonObject row = address(item.getAddress());
            row.addProperty("length", item.getLength()); row.add("type", type(item.getDataType()));
            row.addProperty("opaque", opaque != null && opaque.hasProperty(item.getAddress()));
            data.add(row);
        }
        AddressSet code = new AddressSet();
        for (var instruction : listing.getInstructions(true)) code.add(instruction.getMinAddress(), instruction.getMaxAddress());
        List<JsonObject> instructions = ranges(code);
        Comparator<JsonObject> ordering = Comparator.comparing((JsonObject row) -> row.get("space").getAsString())
            .thenComparing(row -> new java.math.BigInteger(row.get("offset").getAsString(), 16))
            .thenComparing(JsonObject::toString);
        for (var list : List.of(symbols, comments, data, instructions)) list.sort(ordering);
        root.add("symbols", array(symbols)); root.add("comments", array(comments));
        root.add("data", array(data)); root.add("instructions", array(instructions));
        return root;
    }

    private static JsonObject source(Program program) {
        String digest = program.getExecutableSHA256();
        if (digest == null || !digest.matches("(?i)[0-9a-f]{64}")) throw new IllegalArgumentException("program has no valid original SHA-256");
        JsonObject source = new JsonObject(); source.addProperty("sha256", digest.toLowerCase(Locale.ROOT));
        source.addProperty("language", program.getLanguageID().toString());
        source.addProperty("compiler_spec", program.getCompilerSpec().getCompilerSpecID().toString()); return source;
    }

    private static JsonObject view(Program program) throws Exception {
        JsonObject view = new JsonObject(); view.add("image_base", address(program.getImageBase()));
        List<JsonObject> blocks = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            JsonObject row = address(block.getStart()); row.addProperty("length", block.getSize()); row.addProperty("initialized", block.isInitialized());
            if (block.getStart().getAddressSpace() instanceof OverlayAddressSpace overlay) row.addProperty("overlay_base", overlay.getOverlayedSpace().getName());
            if (block.isInitialized()) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256"); byte[] bytes = new byte[65536]; long offset = 0;
                while (offset < block.getSize()) {
                    int count = (int) Math.min(bytes.length, block.getSize() - offset);
                    int read = block.getBytes(block.getStart().add(offset), bytes, 0, count);
                    if (read <= 0) throw new IllegalStateException("could not read memory block");
                    digest.update(bytes, 0, read); offset += read;
                }
                row.addProperty("sha256", HexFormat.of().formatHex(digest.digest()));
            }
            blocks.add(row);
        }
        blocks.sort(Comparator.comparing((JsonObject r) -> r.get("space").getAsString()).thenComparing(r -> new java.math.BigInteger(r.get("offset").getAsString(), 16)));
        view.add("blocks", array(blocks)); return view;
    }

    private static JsonObject address(Address address) {
        JsonObject result = new JsonObject(); result.addProperty("space", address.getAddressSpace().getName());
        result.addProperty("offset", Long.toUnsignedString(address.getOffset(), 16)); return result;
    }
    private static JsonArray array(List<JsonObject> rows) { JsonArray result = new JsonArray(); rows.forEach(result::add); return result; }
    private static List<JsonObject> ranges(AddressSet set) {
        List<JsonObject> rows = new ArrayList<>();
        for (AddressRange range : set) { JsonObject row = address(range.getMinAddress()); row.addProperty("length", range.getLength()); rows.add(row); }
        return rows;
    }

    private static JsonObject type(DataType type) {
        JsonObject result = new JsonObject();
        if (type instanceof Array array) {
            result.addProperty("kind", "array"); result.add("element", type(array.getDataType())); result.addProperty("count", array.getNumElements());
        } else if (type instanceof Pointer pointer) {
            result.addProperty("kind", "pointer"); result.add("target", pointer.getDataType() == null ? JsonNull.INSTANCE : type(pointer.getDataType())); result.addProperty("length", pointer.getLength());
        } else { result.addProperty("kind", "named"); result.addProperty("path", type.getPathName()); }
        return result;
    }

    private static void fields(JsonObject object, String... names) {
        if (!object.keySet().equals(Set.of(names))) throw new IllegalArgumentException("invalid fields: " + object.keySet());
    }
    private static long integer(JsonElement value) {
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) throw new IllegalArgumentException("expected integer");
        try { return value.getAsBigDecimal().longValueExact(); }
        catch (ArithmeticException error) { throw new IllegalArgumentException("expected exact integer", error); }
    }
    private static boolean bool(JsonElement value) {
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) throw new IllegalArgumentException("expected boolean");
        return value.getAsBoolean();
    }
    private static String string(JsonElement value) {
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) throw new IllegalArgumentException("expected string");
        return value.getAsString();
    }
    private static void shapeAddress(JsonObject row) {
        if (string(row.get("space")).isBlank()) throw new IllegalArgumentException("empty address space");
        String offset = string(row.get("offset"));
        if (!offset.matches("0|[1-9a-f][0-9a-f]*") || offset.length() > 16) throw new IllegalArgumentException("invalid address offset: " + offset);
    }
    private static void shapeType(JsonObject type) {
        String kind = string(type.get("kind"));
        switch (kind) {
            case "named" -> { fields(type, "kind", "path"); if (!string(type.get("path")).startsWith("/")) throw new IllegalArgumentException("invalid datatype path"); }
            case "array" -> { fields(type, "kind", "element", "count"); if (integer(type.get("count")) <= 0 || integer(type.get("count")) > Integer.MAX_VALUE) throw new IllegalArgumentException("invalid array count"); shapeType(type.getAsJsonObject("element")); }
            case "pointer" -> { fields(type, "kind", "target", "length"); if (integer(type.get("length")) <= 0 || integer(type.get("length")) > Integer.MAX_VALUE) throw new IllegalArgumentException("invalid pointer length"); if (!type.get("target").isJsonNull()) shapeType(type.getAsJsonObject("target")); }
            default -> throw new IllegalArgumentException("invalid datatype kind");
        }
    }
    private static void validateRanges(JsonArray rows) {
        Map<String, List<java.math.BigInteger[]>> spaces = new HashMap<>();
        for (JsonElement element : rows) {
            JsonObject row = element.getAsJsonObject();
            java.math.BigInteger start = new java.math.BigInteger(string(row.get("offset")), 16);
            java.math.BigInteger end = start.add(java.math.BigInteger.valueOf(integer(row.get("length"))));
            if (end.bitLength() > 65 || end.compareTo(java.math.BigInteger.ONE.shiftLeft(64)) > 0)
                throw new IllegalArgumentException("range exceeds address space");
            spaces.computeIfAbsent(string(row.get("space")), ignored -> new ArrayList<>()).add(new java.math.BigInteger[] {start, end});
        }
        for (var ranges : spaces.values()) {
            ranges.sort(Comparator.comparing(a -> a[0]));
            for (int i = 1; i < ranges.size(); i++) if (ranges.get(i - 1)[1].compareTo(ranges.get(i)[0]) > 0)
                throw new IllegalArgumentException("overlapping ranges");
        }
    }
    private static void validateShape(JsonObject root) {
        fields(root, "format", "schema", "source", "view", "symbols", "comments", "data", "instructions");
        if (!"ghidra-mcp-annotations".equals(string(root.get("format"))) || integer(root.get("schema")) != 1)
            throw new IllegalArgumentException("unsupported annotation format or schema");
        fields(root.getAsJsonObject("source"), "sha256", "language", "compiler_spec");
        JsonObject source = root.getAsJsonObject("source");
        if (!string(source.get("sha256")).matches("[0-9a-f]{64}") || string(source.get("language")).isBlank() || string(source.get("compiler_spec")).isBlank()) throw new IllegalArgumentException("invalid source identity");
        fields(root.getAsJsonObject("view"), "image_base", "blocks");
        fields(root.getAsJsonObject("view").getAsJsonObject("image_base"), "space", "offset");
        shapeAddress(root.getAsJsonObject("view").getAsJsonObject("image_base"));
        for (JsonElement e : root.getAsJsonObject("view").getAsJsonArray("blocks")) {
            JsonObject row = e.getAsJsonObject();
            Set<String> expected = new HashSet<>(Set.of("space", "offset", "length", "initialized"));
            shapeAddress(row);
            if (integer(row.get("length")) <= 0) throw new IllegalArgumentException("invalid block length");
            if (bool(row.get("initialized"))) {
                expected.add("sha256");
                if (!string(row.get("sha256")).matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid block digest");
            }
            if (row.has("overlay_base")) { expected.add("overlay_base"); if (string(row.get("overlay_base")).isBlank()) throw new IllegalArgumentException("invalid overlay base"); }
            if (!row.keySet().equals(expected)) throw new IllegalArgumentException("invalid block fields");
        }
        Set<String> keys = new HashSet<>(), primaries = new HashSet<>();
        for (JsonElement e : root.getAsJsonArray("symbols")) {
            JsonObject row = e.getAsJsonObject(); fields(row, "space", "offset", "namespace", "name", "kind", "source", "primary"); shapeAddress(row);
            String kind = string(row.get("kind")), sourceKind = string(row.get("source"));
            if (!(kind.equals("label") || kind.equals("function")) || !(sourceKind.equals("USER_DEFINED") || sourceKind.equals("IMPORTED")) || string(row.get("name")).isBlank()) throw new IllegalArgumentException("invalid symbol");
            for (JsonElement part : row.getAsJsonArray("namespace")) if (string(part).isBlank()) throw new IllegalArgumentException("invalid namespace");
            if (!keys.add(slot(row, "namespace", "name"))) throw new IllegalArgumentException("duplicate symbol");
            if (bool(row.get("primary")) && !primaries.add(slot(row))) throw new IllegalArgumentException("conflicting primary symbols");
        }
        for (JsonElement e : root.getAsJsonArray("comments")) {
            JsonObject row = e.getAsJsonObject(); fields(row, "space", "offset", "kind", "text"); shapeAddress(row);
            CommentType.valueOf(string(row.get("kind"))); string(row.get("text"));
            if (!keys.add("comment/" + slot(row, "kind"))) throw new IllegalArgumentException("duplicate comment");
        }
        for (JsonElement e : root.getAsJsonArray("data")) {
            JsonObject row = e.getAsJsonObject(); fields(row, "space", "offset", "length", "type", "opaque"); shapeAddress(row);
            if (integer(row.get("length")) <= 0 || integer(row.get("length")) > Integer.MAX_VALUE) throw new IllegalArgumentException("invalid data length");
            bool(row.get("opaque")); shapeType(row.getAsJsonObject("type"));
        }
        for (JsonElement e : root.getAsJsonArray("instructions")) {
            JsonObject row = e.getAsJsonObject(); fields(row, "space", "offset", "length"); shapeAddress(row);
            if (integer(row.get("length")) <= 0) throw new IllegalArgumentException("invalid instruction length");
        }
        validateRanges(root.getAsJsonObject("view").getAsJsonArray("blocks"));
        validateRanges(root.getAsJsonArray("data"));
        validateRanges(root.getAsJsonArray("instructions"));
    }
    private static Address addressInSpace(Program program, JsonObject row) {
        String hex = row.get("offset").getAsString();
        if (!hex.matches("0|[1-9a-f][0-9a-f]*") || hex.length() > 16) throw new IllegalArgumentException("invalid address offset: " + hex);
        AddressSpace space = program.getAddressFactory().getAddressSpace(row.get("space").getAsString());
        if (space == null) throw new IllegalArgumentException("unknown address space: " + row.get("space"));
        return space.getAddress(Long.parseUnsignedLong(hex, 16));
    }
    private static Address resolve(Program program, JsonObject row) {
        Address address = addressInSpace(program, row);
        if (!program.getMemory().contains(address)) throw new IllegalArgumentException("unmapped address: " + address);
        return address;
    }
    private static Address end(Address start, JsonObject row) throws Exception {
        long length = row.get("length").getAsLong();
        if (length <= 0) throw new IllegalArgumentException("invalid range length");
        return start.addNoWrap(length - 1);
    }
    private static DataType resolveType(Program program, JsonObject object) {
        String kind = object.get("kind").getAsString();
        if (kind.equals("named")) {
            fields(object, "kind", "path");
            String path = object.get("path").getAsString();
            if (!path.startsWith("/")) throw new IllegalArgumentException("datatype path must be absolute: " + path);
            DataType result = program.getDataTypeManager().getDataType(path);
            if (result == null) result = BuiltInDataTypeManager.getDataTypeManager().getDataType(path);
            if (result == null && path.indexOf('/', 1) < 0) result = ServiceUtils.resolveWellKnownType(path.substring(1));
            if (result == null || !path.equals(result.getPathName())) throw new IllegalArgumentException("datatype not found: " + path);
            return result;
        }
        if (kind.equals("array")) {
            fields(object, "kind", "element", "count");
            DataType base = resolveType(program, object.getAsJsonObject("element")); int count = object.get("count").getAsInt();
            if (count <= 0 || base.getLength() <= 0) throw new IllegalArgumentException("invalid array type");
            return new ArrayDataType(base, count, base.getLength(), program.getDataTypeManager());
        }
        if (kind.equals("pointer")) {
            fields(object, "kind", "target", "length");
            DataType target = object.get("target").isJsonNull() ? null : resolveType(program, object.getAsJsonObject("target"));
            int length = object.get("length").getAsInt();
            if (length <= 0) throw new IllegalArgumentException("invalid pointer length");
            return new PointerDataType(target, length, program.getDataTypeManager());
        }
        throw new IllegalArgumentException("unknown datatype kind: " + kind);
    }
    private static void validate(Program program, JsonObject root) throws Exception {
        if (!root.get("source").equals(source(program))) throw new IllegalArgumentException("source identity mismatch");
        if (!root.get("view").equals(view(program))) throw new IllegalArgumentException("program view mismatch");
        Set<String> keys = new HashSet<>(); AddressSet dataRanges = new AddressSet();
        for (JsonElement e : root.getAsJsonArray("comments")) {
            JsonObject row = e.getAsJsonObject(); resolve(program, row);
            CommentType.valueOf(row.get("kind").getAsString()); row.get("text").getAsString();
            if (!keys.add("comment" + row.get("space") + row.get("offset") + row.get("kind"))) throw new IllegalArgumentException("duplicate comment");
        }
        for (JsonElement e : root.getAsJsonArray("symbols")) {
            JsonObject row = e.getAsJsonObject(); resolve(program, row);
            String kind = row.get("kind").getAsString(), source = row.get("source").getAsString();
            if (!(kind.equals("label") || kind.equals("function")) || !(source.equals("USER_DEFINED") || source.equals("IMPORTED"))) throw new IllegalArgumentException("invalid symbol kind or source");
            if (row.get("name").getAsString().isBlank()) throw new IllegalArgumentException("empty symbol name");
            for (JsonElement part : row.getAsJsonArray("namespace")) if (part.getAsString().isBlank()) throw new IllegalArgumentException("empty namespace");
            String key = "symbol" + row.get("space") + row.get("offset") + row.get("namespace") + row.get("name");
            if (!keys.add(key)) throw new IllegalArgumentException("duplicate symbol");
        }
        for (JsonElement e : root.getAsJsonArray("data")) {
            JsonObject row = e.getAsJsonObject(); Address start = resolve(program, row), end = end(start, row);
            if (!program.getMemory().contains(start, end) || dataRanges.intersects(start, end)) throw new IllegalArgumentException("invalid or overlapping data range: " + start);
            dataRanges.add(start, end);
            DataType type = resolveType(program, row.getAsJsonObject("type"));
            int length = row.get("length").getAsInt();
            if (length <= 0 || (type.getLength() > 0 && type.getLength() != length)
                    || (type.getLength() <= 0 && (!(type instanceof Dynamic dynamic) || !dynamic.canSpecifyLength())))
                throw new IllegalArgumentException("datatype length mismatch at " + start);
            Data existing = program.getListing().getDefinedDataAt(start);
            if (existing != null && existing.getLength() == length
                    && existing.getDataType().getPathName().equals(type.getPathName())
                    && existing.getDataType().isEquivalent(type)) continue;
            AddressSet range = new AddressSet(start, end);
            if (program.getListing().getDefinedDataContaining(start) != null
                    || program.getListing().getInstructionContaining(start) != null
                    || program.getListing().getDefinedData(range, true).hasNext()
                    || program.getListing().getInstructions(range, true).hasNext())
                throw new IllegalArgumentException("data conflicts at " + start);
        }
        for (JsonElement e : root.getAsJsonArray("instructions")) { JsonObject row = e.getAsJsonObject(); Address start = resolve(program, row); end(start, row); }
    }

    private static JsonArray losses(JsonObject old, JsonObject current, Program program) throws Exception {
        JsonArray result = new JsonArray();
        Set<String> comments = new HashSet<>();
        for (JsonElement e : current.getAsJsonArray("comments")) comments.add(slot(e.getAsJsonObject(), "kind"));
        for (JsonElement e : old.getAsJsonArray("comments")) if (!comments.contains(slot(e.getAsJsonObject(), "kind"))) result.add("comment " + slot(e.getAsJsonObject(), "kind"));
        Map<String, Integer> before = symbolCounts(old), after = symbolCounts(current);
        for (var entry : before.entrySet()) if (entry.getValue() > after.getOrDefault(entry.getKey(), 0)) result.add("symbols " + entry.getKey() + " lost " + (entry.getValue() - after.getOrDefault(entry.getKey(), 0)));
        for (String kind : List.of("data", "instructions")) {
            AddressSet removed = coverage(old.getAsJsonArray(kind), program, result, kind);
            removed.delete(coverage(current.getAsJsonArray(kind), program, result, kind));
            for (JsonObject range : ranges(removed)) result.add(kind + " " + range);
        }
        Set<String> opaque = new HashSet<>();
        for (JsonElement e : current.getAsJsonArray("data")) if (e.getAsJsonObject().get("opaque").getAsBoolean()) opaque.add(slot(e.getAsJsonObject()));
        for (JsonElement e : old.getAsJsonArray("data")) if (e.getAsJsonObject().get("opaque").getAsBoolean() && !opaque.contains(slot(e.getAsJsonObject()))) result.add("opaque " + slot(e.getAsJsonObject()));
        return result;
    }
    private static String slot(JsonObject row, String... extra) {
        StringBuilder key = new StringBuilder(row.get("space").getAsString()).append(':').append(row.get("offset").getAsString());
        for (String field : extra) key.append('/').append(row.get(field));
        return key.toString();
    }
    private static Map<String, Integer> symbolCounts(JsonObject snapshot) {
        Map<String, Integer> counts = new TreeMap<>();
        for (JsonElement e : snapshot.getAsJsonArray("symbols")) counts.merge(slot(e.getAsJsonObject(), "namespace", "kind"), 1, Integer::sum);
        return counts;
    }
    private static AddressSet coverage(JsonArray rows, Program program, JsonArray losses, String kind) throws Exception {
        AddressSet set = new AddressSet();
        for (JsonElement e : rows) {
            JsonObject row = e.getAsJsonObject();
            try { Address start = addressInSpace(program, row); set.add(start, end(start, row)); }
            catch (IllegalArgumentException error) { losses.add(kind + " " + slot(row) + " length " + row.get("length")); }
        }
        return set;
    }
    private static Namespace namespace(Program program, JsonArray components) throws Exception {
        Namespace namespace = program.getGlobalNamespace();
        for (JsonElement part : components) {
            String name = part.getAsString();
            Namespace existing = program.getSymbolTable().getNamespace(name, namespace);
            if (existing == null) existing = program.getSymbolTable().createNameSpace(namespace, name, SourceType.USER_DEFINED);
            namespace = existing;
        }
        return namespace;
    }
    private static Map<String, Object> apply(Program program, JsonObject root) throws Exception {
        int applied = 0, unchanged = 0;
        List<Map<String, Object>> overwritten = new ArrayList<>();
        var listing = program.getListing();
        for (JsonElement e : root.getAsJsonArray("data")) {
            JsonObject row = e.getAsJsonObject(); Address start = resolve(program, row);
            DataType type = resolveType(program, row.getAsJsonObject("type")); int length = row.get("length").getAsInt();
            Data data = listing.getDefinedDataAt(start);
            boolean changed = false;
            if (data == null) { data = listing.createData(start, type, length); changed = true; }
            if (row.get("opaque").getAsBoolean()) {
                var properties = program.getUsrPropertyManager(); var opaque = properties.getVoidPropertyMap("listing.opaque");
                if (opaque == null) opaque = properties.createVoidPropertyMap("listing.opaque");
                if (!opaque.hasProperty(start)) { opaque.add(start); changed = true; }
            }
            if (changed) applied++; else unchanged++;
        }
        for (JsonElement e : root.getAsJsonArray("symbols")) {
            JsonObject row = e.getAsJsonObject(); Address start = resolve(program, row); String name = row.get("name").getAsString();
            Namespace ns = namespace(program, row.getAsJsonArray("namespace")); SourceType source = SourceType.valueOf(row.get("source").getAsString());
            Symbol symbol = program.getSymbolTable().getSymbol(name, start, ns); boolean changed = false;
            Function function = row.get("kind").getAsString().equals("function") ? program.getFunctionManager().getFunctionAt(start) : null;
            if (function != null) {
                symbol = function.getSymbol();
                if (!symbol.getName().equals(name) || !symbol.getParentNamespace().equals(ns)) {
                    overwritten.add(JsonHelper.mapOf("kind", "function", "address", start.toString(true), "name", symbol.getName(true)));
                    symbol.setNameAndNamespace(name, ns, source); changed = true;
                }
            } else if (symbol == null) {
                symbol = program.getSymbolTable().createLabel(start, name, ns, source); changed = true;
            }
            if (symbol.getSource() != source) {
                overwritten.add(JsonHelper.mapOf("kind", "symbol_source", "address", start.toString(true), "source", symbol.getSource().name()));
                symbol.setSource(source); changed = true;
            }
            if (row.get("primary").getAsBoolean() && !symbol.isPrimary()) {
                Symbol primary = program.getSymbolTable().getPrimarySymbol(start);
                if (primary != null) overwritten.add(JsonHelper.mapOf("kind", "primary_symbol", "address", start.toString(true), "name", primary.getName(true)));
                if (!symbol.setPrimary()) throw new IllegalStateException("could not set primary symbol at " + start);
                changed = true;
            }
            if (changed) applied++; else unchanged++;
        }
        for (JsonElement e : root.getAsJsonArray("comments")) {
            JsonObject row = e.getAsJsonObject(); Address start = resolve(program, row); CommentType kind = CommentType.valueOf(row.get("kind").getAsString());
            String text = row.get("text").getAsString(), old = listing.getComment(kind, start);
            if (Objects.equals(old, text)) { unchanged++; continue; }
            if (old != null) overwritten.add(JsonHelper.mapOf("kind", kind.name(), "address", start.toString(true), "text", old));
            listing.setComment(start, kind, text); applied++;
        }
        return JsonHelper.mapOf("applied", applied, "unchanged", unchanged, "overwritten", overwritten);
    }
}
