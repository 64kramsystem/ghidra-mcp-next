package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Bounded, factual program inventories. */
public final class ListingService {

    private static final int MAX_LIMIT = 10_000;

    private final ProgramProvider programs;

    public ListingService(ProgramProvider programs) {
        this.programs = programs;
    }

    @McpTool(path = "/list_segments",
        description = "List memory blocks and their permissions")
    public Response listSegments(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Response bounds = validatePage(offset, limit);
        if (bounds != null) {
            return bounds;
        }
        List<MemoryBlockCore.BlockDescriptor> blocks =
            MemoryBlockCore.descriptors(resolved.program());
        return paged(
            "segments",
            MemoryBlockService.descriptorJson(blocks),
            offset,
            limit);
    }

    @McpTool(path = "/list_functions",
        description = "List functions, optionally filtering by name")
    public Response listFunctions(
            @Param(value = "name", defaultValue = "") String name,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Response bounds = validatePage(offset, limit);
        if (bounds != null) {
            return bounds;
        }
        String needle = normalized(name);
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Function function
                : resolved.program().getFunctionManager().getFunctions(true)) {
            String fullName = function.getName(true);
            if (!needle.isEmpty()
                    && !fullName.toLowerCase(Locale.ROOT).contains(needle)) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("address", function.getEntryPoint().toString());
            row.put("name", function.getName());
            row.put("full_name", fullName);
            row.put("thunk", function.isThunk());
            row.put("external", function.isExternal());
            rows.add(row);
        }
        return paged("functions", rows, offset, limit);
    }

    @McpTool(path = "/list_calling_conventions",
        description = "List available calling conventions")
    public Response listCallingConventions(
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        List<String> names = new ArrayList<>();
        for (var model
                : resolved.program().getCompilerSpec().getCallingConventions()) {
            names.add(model.getName());
        }
        names.sort(String::compareTo);
        return Response.ok(names);
    }

    @McpTool(path = "/list_data_items",
        description = "List defined data, optionally filtering by name or type")
    public Response listDataItems(
            @Param(value = "filter", defaultValue = "") String filter,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Response bounds = validatePage(offset, limit);
        if (bounds != null) {
            return bounds;
        }
        Program program = resolved.program();
        String needle = normalized(filter);
        List<Map<String, Object>> rows = new ArrayList<>();
        DataIterator data = program.getListing().getDefinedData(true);
        while (data.hasNext()) {
            Data item = data.next();
            Symbol symbol =
                program.getSymbolTable().getPrimarySymbol(item.getAddress());
            String name = symbol == null ? "" : symbol.getName(true);
            String type = item.getDataType().getPathName();
            if (!needle.isEmpty()
                    && !name.toLowerCase(Locale.ROOT).contains(needle)
                    && !type.toLowerCase(Locale.ROOT).contains(needle)) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("address", item.getAddress().toString());
            row.put("name", name);
            row.put("type", type);
            row.put("length", item.getLength());
            row.put("xref_count",
                program.getReferenceManager().getReferenceCountTo(
                    item.getAddress()));
            rows.add(row);
        }
        return paged("data_items", rows, offset, limit);
    }

    @McpTool(path = "/list_strings",
        description = "List defined strings, optionally filtering by text")
    public Response listStrings(
            @Param(value = "filter", defaultValue = "") String filter,
            @Param(value = "min_length", defaultValue = "4") int minLength,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Response bounds = validatePage(offset, limit);
        if (bounds != null) {
            return bounds;
        }
        if (minLength < 0) {
            return Response.err("min_length must be non-negative");
        }
        String needle = normalized(filter);
        List<Map<String, Object>> rows = new ArrayList<>();
        DataIterator data = resolved.program().getListing().getDefinedData(true);
        while (data.hasNext()) {
            Data item = data.next();
            if (!ServiceUtils.isStringData(item) || item.getValue() == null) {
                continue;
            }
            String value = item.getValue().toString();
            if (value.length() < minLength
                    || (!needle.isEmpty()
                        && !value.toLowerCase(Locale.ROOT).contains(needle))) {
                continue;
            }
            rows.add(Map.of(
                "address", item.getAddress().toString(),
                "value", value,
                "length", value.length()));
        }
        return paged("strings", rows, offset, limit);
    }

    @McpTool(path = "/get_entry_points",
        description = "List Ghidra external entry points")
    public Response getEntryPoints(
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        SymbolIterator symbols =
            resolved.program().getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (!symbol.isExternalEntryPoint()) {
                continue;
            }
            rows.add(Map.of(
                "address", symbol.getAddress().toString(),
                "name", symbol.getName(true),
                "type", symbol.getSymbolType().toString()));
        }
        rows.sort(Comparator.comparing(row -> row.get("address").toString()));
        return Response.ok(rows);
    }

    @McpTool(path = "/list_external_locations",
        description = "List imported and other external locations")
    public Response listExternalLocations(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Response bounds = validatePage(offset, limit);
        if (bounds != null) {
            return bounds;
        }
        List<Map<String, Object>> rows =
            externalLocations(resolved.program());
        return paged("external_locations", rows, offset, limit);
    }

    @McpTool(path = "/get_external_location",
        description = "Get one external location by address")
    public Response getExternalLocation(
            @Param(value = "address")
                String addressText,
            @Param(value = "program", defaultValue = "")
                String programName) {
        ServiceUtils.ProgramOrError resolved = resolve(programName);
        if (resolved.hasError()) {
            return resolved.error();
        }
        Address address =
            ServiceUtils.parseAddress(resolved.program(), addressText);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }
        for (Map<String, Object> row : externalLocations(resolved.program())) {
            if (address.toString().equals(row.get("address"))) {
                return Response.ok(row);
            }
        }
        return Response.err("No external location at " + addressText);
    }

    private ServiceUtils.ProgramOrError resolve(String programName) {
        return ServiceUtils.getProgramOrError(programs, programName);
    }

    private static List<Map<String, Object>> externalLocations(
            Program program) {
        List<Map<String, Object>> rows = new ArrayList<>();
        ExternalManager manager = program.getExternalManager();
        for (String library : manager.getExternalLibraryNames()) {
            ExternalLocationIterator locations =
                manager.getExternalLocations(library);
            while (locations.hasNext()) {
                ExternalLocation location = locations.next();
                Map<String, Object> row = new LinkedHashMap<>();
                Address address = location.getAddress();
                row.put("address", address == null ? null : address.toString());
                row.put("library", library);
                row.put("name", location.getLabel());
                String original = location.getOriginalImportedName();
                if (original != null && !original.equals(location.getLabel())) {
                    row.put("original_imported_name", original);
                }
                rows.add(row);
            }
        }
        rows.sort(Comparator.<Map<String, Object>, String>comparing(
                row -> String.valueOf(row.get("library")))
            .thenComparing(row -> String.valueOf(row.get("name"))));
        return rows;
    }

    private static Response validatePage(int offset, int limit) {
        if (offset < 0) {
            return Response.err("offset must be non-negative");
        }
        if (limit < 1 || limit > MAX_LIMIT) {
            return Response.err("limit must be between 1 and " + MAX_LIMIT);
        }
        return null;
    }

    private static String normalized(String value) {
        return value == null ? "" : value.strip().toLowerCase(Locale.ROOT);
    }

    private static <T> List<T> page(
            List<T> values, int offset, int limit) {
        if (offset >= values.size()) {
            return List.of();
        }
        return List.copyOf(values.subList(
            offset, Math.min(values.size(), offset + limit)));
    }

    private static Response paged(
            String field,
            List<?> rows,
            int offset,
            int limit) {
        return Response.ok(JsonHelper.mapOf(
            field, page(rows, offset, limit),
            "total", rows.size(),
            "offset", offset,
            "limit", limit));
    }
}
