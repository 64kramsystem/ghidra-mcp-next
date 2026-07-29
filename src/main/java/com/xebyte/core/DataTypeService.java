package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Service for data type operations: list, create, modify, validate, and analyze data types.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
public class DataTypeService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public DataTypeService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // -----------------------------------------------------------------------
    // Helper Classes
    // -----------------------------------------------------------------------

    /**
     * Helper class for field definitions
     */
    private record FieldDefinition(String name, String type, int offset) {

        FieldDefinition(String name, String type, int offset) {
            this.name = name;
            this.type = type;
            this.offset = offset;
        }
    }


    // -----------------------------------------------------------------------
    // Data Type Listing and Query Methods
    // -----------------------------------------------------------------------


    /**
     * Search for data types by pattern
     */
    @McpTool(path = "/search_data_types", description = "Search data types by pattern")
    public Response searchDataTypes(
            @Param(value = "pattern", description = "Search pattern") String pattern,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (pattern == null || pattern.isEmpty()) return Response.err("Search pattern is required");

        List<String> matches = new ArrayList<>();
        DataTypeManager dtm = program.getDataTypeManager();

        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            String name = dt.getName();
            String path = dt.getPathName();

            if (name.toLowerCase().contains(pattern.toLowerCase()) ||
                path.toLowerCase().contains(pattern.toLowerCase())) {
                matches.add(String.format("%s | Size: %d | Path: %s",
                           name, dt.getLength(), path));
            }
        }

        Collections.sort(matches);
        return Response.text(ServiceUtils.paginateList(matches, offset, limit));
    }

    /**
     * Get the size of a data type
     */
    @McpTool(path = "/get_type_size", description = "Get data type size and info")
    public Response getTypeSize(
            @Param(value = "type_name", description = "Data type name") String typeName,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (typeName == null || typeName.isEmpty()) return Response.err("Type name is required");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, typeName);

        if (dataType == null) {
            return Response.err("Data type not found: " + typeName);
        }

        int size = dataType.getLength();
        return Response.text(String.format("Type: %s\nSize: %d bytes\nAlignment: %d\nPath: %s",
                            dataType.getName(),
                            size,
                            dataType.getAlignment(),
                            dataType.getPathName()));
    }

    /**
     * Get the layout of a structure
     */
    @McpTool(path = "/get_struct_layout", description = "Get structure field layout")
    public Response getStructLayout(
            @Param(value = "struct_name", description = "Structure name") String structName,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (structName == null || structName.isEmpty()) return Response.err("Struct name is required");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, structName);

        if (dataType == null) {
            return Response.err("Structure not found: " + structName);
        }

        if (!(dataType instanceof Structure)) {
            return Response.err("Data type is not a structure: " + structName);
        }

        Structure struct = (Structure) dataType;
        StringBuilder result = new StringBuilder();

        result.append("Structure: ").append(struct.getName()).append("\n");
        result.append("Size: ").append(struct.getLength()).append(" bytes\n");
        result.append("Alignment: ").append(struct.getAlignment()).append("\n\n");
        result.append("Layout:\n");
        result.append("Offset | Size | Type | Name\n");
        result.append("-------|------|------|-----\n");

        for (DataTypeComponent component : struct.getDefinedComponents()) {
            result.append(String.format("%6d | %4d | %-20s | %s\n",
                component.getOffset(),
                component.getLength(),
                component.getDataType().getName(),
                component.getFieldName() != null ? component.getFieldName() : "(unnamed)"));
        }

        return Response.text(result.toString());
    }

    /**
     * Get all values in an enumeration
     */
    @McpTool(path = "/get_enum_values", description = "Get enum member values")
    public Response getEnumValues(
            @Param(value = "enum_name", description = "Enum name") String enumName,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (enumName == null || enumName.isEmpty()) return Response.err("Enum name is required");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, enumName);

        if (dataType == null) {
            return Response.err("Enumeration not found: " + enumName);
        }

        if (!(dataType instanceof ghidra.program.model.data.Enum)) {
            return Response.err("Data type is not an enumeration: " + enumName);
        }

        ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
        StringBuilder result = new StringBuilder();

        result.append("Enumeration: ").append(enumType.getName()).append("\n");
        result.append("Size: ").append(enumType.getLength()).append(" bytes\n\n");
        result.append("Values:\n");
        result.append("Name | Value\n");
        result.append("-----|------\n");

        String[] names = enumType.getNames();
        for (String valueName : names) {
            long value = enumType.getValue(valueName);
            result.append(String.format("%-20s | %d (0x%X)\n", valueName, value, value));
        }

        return Response.text(result.toString());
    }

    // -----------------------------------------------------------------------
    // Data Type Creation Methods
    // -----------------------------------------------------------------------

    /**
     * Create a new structure data type with specified fields
     */
    @McpTool(path = "/create_struct", method = "POST",
        description = "Create a structure from fields with name, type, and optional offset")
    public Response createStruct(
            @Param(value = "name", source = ParamSource.BODY,
                   description = "New structure type name, for example UnitAny or SkillTableEntry") String name,
            @Param(value = "fields", source = ParamSource.BODY,
                schemaFragment = "{\"type\":\"array\",\"items\":{\"type\":\"object\","
                    + "\"properties\":{\"name\":{\"type\":\"string\"},"
                    + "\"type\":{\"type\":\"string\"},"
                    + "\"offset\":{\"type\":\"integer\",\"minimum\":0}},"
                    + "\"required\":[\"name\",\"type\"]}}")
                List<Map<String, Object>> fieldValues,
            @Param(value = "replace_placeholder", source = ParamSource.BODY, defaultValue = "false",
                   description = "If true and a same-named type exists with size <= 1 byte (typical /Demangler stub), delete it first then create the struct.") boolean replacePlaceholder,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        if (name == null || name.isEmpty()) {
            return Response.err("Structure name is required");
        }

        if (fieldValues == null || fieldValues.isEmpty()) {
            return Response.err("fields must contain at least one field");
        }

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            List<FieldDefinition> fields = parseFields(fieldValues);

            DataTypeManager dtm = program.getDataTypeManager();

            // Check if struct already exists
            DataType existingType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, name);
            if (existingType != null) {
                if (replacePlaceholder && existingType.getLength() <= 1) {
                    if (!deletePlaceholderType(program, existingType, name, new StringBuilder())) {
                        return Response.err("Failed to remove 1-byte placeholder '"
                                + existingType.getPathName() + "' before create_struct");
                    }
                } else {
                    return Response.err("Structure with name '" + name + "' already exists"
                            + " (" + existingType.getPathName() + ", " + existingType.getLength()
                            + " bytes). Use replace_placeholder=true for 1-byte stubs, "
                            + "or rename/delete the existing type first.");
                }
            }

            // Pre-resolve all field types before entering the transaction
            Map<FieldDefinition, DataType> resolvedTypes = new java.util.LinkedHashMap<>();
            for (FieldDefinition field : fields) {
                DataType fieldType = ServiceUtils.resolveDataType(dtm, field.type);
                if (fieldType == null) {
                    return Response.err("Unknown field type: " + field.type);
                }
                resolvedTypes.put(field, fieldType);
            }

            // Determine if any fields have explicit offsets
            boolean hasOffsets = fields.stream().anyMatch(f -> f.offset >= 0);

            // Calculate required struct size from field offsets
            int requiredSize = 0;
            if (hasOffsets) {
                for (Map.Entry<FieldDefinition, DataType> entry : resolvedTypes.entrySet()) {
                    int off = entry.getKey().offset;
                    int len = entry.getValue().getLength();
                    if (off >= 0 && off + len > requiredSize) {
                        requiredSize = off + len;
                    }
                }
            }
            final int structInitSize = requiredSize;
            final boolean hasOffsetsFinal = hasOffsets;

            // Create the structure under the injected threading strategy so the
            // mutation runs on the EDT (GUI) or under the global write lock
            // with transaction commit/rollback handled centrally.
            try {
                threadingStrategy.executeWrite(program, "Create Structure: " + name, () -> {
                    ghidra.program.model.data.StructureDataType struct =
                        new ghidra.program.model.data.StructureDataType(name, structInitSize);

                    for (Map.Entry<FieldDefinition, DataType> entry : resolvedTypes.entrySet()) {
                        FieldDefinition field = entry.getKey();
                        DataType fieldType = entry.getValue();

                        if (field.offset >= 0 && hasOffsetsFinal) {
                            // Place field at explicit offset
                            struct.replaceAtOffset(field.offset, fieldType,
                                fieldType.getLength(), field.name, "");
                        } else {
                            // Append to end
                            struct.add(fieldType, fieldType.getLength(), field.name, "");
                        }
                    }

                    // Add the structure to the data type manager
                    DataType createdStruct = dtm.addDataType(struct, null);

                    successFlag.set(true);
                    resultMsg.append("Successfully created structure '").append(name).append("' with ")
                            .append(fields.size()).append(" fields, total size: ")
                            .append(createdStruct.getLength()).append(" bytes");
                    return null;
                });
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                Msg.error(this, "Error creating structure", e);
                return Response.err("Error creating structure: " + msg);
            }

            // executeWrite already flushed events; keep the post-create settle.
            if (successFlag.get()) {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err(msg);
        }

        return successFlag.get()
            ? Response.text(resultMsg.toString())
            : Response.err("Unknown failure");
    }

    /**
     * Create a new enumeration data type with name-value pairs
     */
    @McpTool(path = "/create_enum", method = "POST", description = "Create an enum data type")
    public Response createEnum(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "values", source = ParamSource.BODY,
                schemaFragment = "{\"type\":\"object\","
                    + "\"additionalProperties\":{\"oneOf\":["
                    + "{\"type\":\"integer\"},{\"type\":\"string\"}]}}")
                Map<String, Object> valueInput,
            @Param(value = "size", source = ParamSource.BODY, defaultValue = "4") int size,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (name == null || name.isEmpty()) {
            return Response.err("Enumeration name is required");
        }

        if (valueInput == null || valueInput.isEmpty()) {
            return Response.err("values must contain at least one member");
        }

        if (size != 1 && size != 2 && size != 4 && size != 8) {
            return Response.err("Invalid size. Must be 1, 2, 4, or 8 bytes");
        }

        try {
            Map<String, Long> values = parseEnumValues(valueInput);

            DataTypeManager dtm = program.getDataTypeManager();

            // Check if enum already exists
            DataType existingType = dtm.getDataType("/" + name);
            if (existingType != null) {
                return Response.err("Enumeration with name '" + name + "' already exists");
            }

            // Create the enumeration under the injected threading strategy so the
            // mutation runs on the EDT
            // with transaction commit/rollback handled centrally.
            try {
                return threadingStrategy.executeWrite(program, "Create Enumeration: " + name, () -> {
                    ghidra.program.model.data.EnumDataType enumDt =
                        new ghidra.program.model.data.EnumDataType(name, size);

                    for (Map.Entry<String, Long> entry : values.entrySet()) {
                        enumDt.add(entry.getKey(), entry.getValue());
                    }

                    // Add the enumeration to the data type manager
                    dtm.addDataType(enumDt, null);

                    Map<String, Object> resultMap = new LinkedHashMap<>();
                    resultMap.put("status", "success");
                    resultMap.put("message", "Successfully created enumeration '" + name + "' with " + values.size() +
                                   " values, size: " + size + " bytes");
                    return Response.ok(resultMap);
                });
            } catch (Exception e) {
                return Response.err("Error creating enumeration: " + e.getMessage());
            }

        } catch (Exception e) {
            return Response.err("Error creating enumeration: " + e.getMessage());
        }
    }

    @McpTool(path = "/create_union", method = "POST", description = "Create a union data type")
    public Response createUnion(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "fields", source = ParamSource.BODY,
                schemaFragment = "{\"type\":\"array\",\"items\":{\"type\":\"object\","
                    + "\"properties\":{\"name\":{\"type\":\"string\"},"
                    + "\"type\":{\"type\":\"string\"}},"
                    + "\"required\":[\"name\",\"type\"]}}")
                List<Map<String, Object>> fieldValues,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (name == null || name.isEmpty()) return Response.err("Union name is required");
        if (fieldValues == null || fieldValues.isEmpty()) {
            return Response.err("fields must contain at least one field");
        }

        final List<FieldDefinition> fields;
        try {
            fields = parseFields(fieldValues);
        } catch (IllegalArgumentException error) {
            return Response.err(error.getMessage());
        }

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            threadingStrategy.executeWrite(program, "Create union", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                if (dtm.getDataType("/" + name) != null) {
                    result.append("Union with name '").append(name)
                        .append("' already exists");
                    return null;
                }
                UnionDataType union = new UnionDataType(name);

                for (FieldDefinition field : fields) {
                    DataType dt = ServiceUtils.resolveDataType(dtm, field.type);
                    if (dt == null) {
                        result.append("Unknown field type: ").append(field.type);
                        return null;
                    }
                    union.add(dt, field.name, null);
                }

                dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);
                result.append("Union '").append(name)
                    .append("' created successfully with ")
                    .append(union.getNumComponents()).append(" fields");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error creating union: ").append(e.getMessage());
        }

        return success.get() ? Response.text(result.toString()) : Response.err(result.toString());
    }

    /**
     * Create a typedef (type alias)
     */
    @McpTool(path = "/create_typedef", method = "POST", description = "Create a typedef alias")
    public Response createTypedef(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "base_type", source = ParamSource.BODY) String baseType,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (name == null || name.isEmpty()) return Response.err("Typedef name is required");
        if (baseType == null || baseType.isEmpty()) return Response.err("Base type is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            threadingStrategy.executeWrite(program, "Create typedef", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType base = null;

                // Delegate to resolveDataType which handles pointer chains (int**),
                // arrays (type[N]), well-known C types, and DTM lookups recursively.
                base = ServiceUtils.resolveDataType(dtm, baseType);
                if (base == null) {
                    result.append("Could not resolve base type: ").append(baseType);
                    return null;
                }

                TypedefDataType typedef = new TypedefDataType(name, base);
                if (dtm.getDataType(typedef.getPathName()) != null) {
                    result.append("Typedef with name '").append(name)
                        .append("' already exists");
                    return null;
                }
                dtm.addDataType(typedef, DataTypeConflictHandler.REPLACE_HANDLER);

                result.append("Typedef '").append(name).append("' created as alias for '").append(baseType).append("'");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error creating typedef: ").append(e.getMessage());
        }

        return success.get() ? Response.text(result.toString()) : Response.err(result.toString());
    }

    /**
     * Create an array data type
     */
    @McpTool(path = "/create_array_type", method = "POST", description = "Create an array data type")
    public Response createArrayType(
            @Param(value = "base_type", source = ParamSource.BODY) String baseType,
            @Param(value = "length", source = ParamSource.BODY, defaultValue = "1") int length,
            @Param(value = "name", source = ParamSource.BODY, defaultValue = "") String name,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (baseType == null || baseType.isEmpty()) return Response.err("Base type is required");
        if (length <= 0) return Response.err("Array length must be positive");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            threadingStrategy.executeWrite(program, "Create array type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType baseDataType = ServiceUtils.resolveDataType(dtm, baseType);

                if (baseDataType == null) {
                    result.append("Base data type not found: ").append(baseType);
                    return null;
                }

                ArrayDataType arrayType = new ArrayDataType(baseDataType, length, baseDataType.getLength());

                if (name != null && !name.isEmpty()) {
                    arrayType.setName(name);
                }

                if (dtm.getDataType(arrayType.getPathName()) != null) {
                    result.append("Array type '").append(arrayType.getName())
                        .append("' already exists");
                    return null;
                }
                DataType addedType = dtm.addDataType(arrayType, DataTypeConflictHandler.REPLACE_HANDLER);

                result.append("Successfully created array type: ").append(addedType.getName())
                      .append(" (").append(baseType).append("[").append(length).append("])");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error creating array type: ").append(e.getMessage());
        }

        return success.get() ? Response.text(result.toString()) : Response.err(result.toString());
    }

    /**
     * Create a pointer data type
     */
    @McpTool(path = "/create_pointer_type", method = "POST", description = "Create a pointer data type")
    public Response createPointerType(
            @Param(value = "base_type", source = ParamSource.BODY) String baseType,
            @Param(value = "name", source = ParamSource.BODY, defaultValue = "") String name,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (baseType == null || baseType.isEmpty()) return Response.err("Base type is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            threadingStrategy.executeWrite(program, "Create pointer type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType baseDataType = null;

                if ("void".equals(baseType)) {
                    baseDataType = dtm.getDataType("/void");
                    if (baseDataType == null) {
                        baseDataType = VoidDataType.dataType;
                    }
                } else {
                    baseDataType = ServiceUtils.resolveDataType(dtm, baseType);
                }

                if (baseDataType == null) {
                    result.append("Base data type not found: ").append(baseType);
                    return null;
                }

                PointerDataType pointerType = new PointerDataType(baseDataType);

                if (name != null && !name.isEmpty()) {
                    pointerType.setName(name);
                }

                if (dtm.getDataType(pointerType.getPathName()) != null) {
                    result.append("Pointer type '").append(pointerType.getName())
                        .append("' already exists");
                    return null;
                }
                DataType addedType = dtm.addDataType(pointerType, DataTypeConflictHandler.REPLACE_HANDLER);

                result.append("Successfully created pointer type: ").append(addedType.getName())
                      .append(" (").append(baseType).append("*)");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error creating pointer type: ").append(e.getMessage());
        }

        return success.get() ? Response.text(result.toString()) : Response.err(result.toString());
    }

    /**
     * Create a function signature data type
     */
    @McpTool(path = "/create_function_signature", method = "POST", description = "Create a function signature data type")
    public Response createFunctionSignature(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "return_type", source = ParamSource.BODY) String returnType,
            @Param(value = "parameters", source = ParamSource.BODY,
                optional = true,
                description = "Optional parameters with name and type",
                schemaFragment = "{\"type\":\"array\",\"items\":{\"type\":\"object\","
                    + "\"properties\":{\"name\":{\"type\":\"string\"},"
                    + "\"type\":{\"type\":\"string\"}},"
                    + "\"required\":[\"name\",\"type\"]}}")
                List<Map<String, Object>> parameterValues,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (name == null || name.isEmpty()) return Response.err("Function name is required");
        if (returnType == null || returnType.isEmpty()) return Response.err("Return type is required");

        final List<FieldDefinition> parameters;
        try {
            parameters = parameterValues == null
                ? List.of()
                : parseFields(parameterValues);
        } catch (IllegalArgumentException error) {
            return Response.err(error.getMessage());
        }

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            threadingStrategy.executeWrite(program, "Create function signature", () -> {
                DataTypeManager dtm = program.getDataTypeManager();

                // Resolve return type
                DataType returnDataType = ServiceUtils.resolveDataType(dtm, returnType);
                if (returnDataType == null) {
                    result.append("Return type not found: ").append(returnType);
                    return null;
                }

                // Create function definition
                FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(name);
                funcDef.setReturnType(returnDataType);
                if (dtm.getDataType(funcDef.getPathName()) != null) {
                    result.append("Function signature '").append(name)
                        .append("' already exists");
                    return null;
                }

                List<ParameterDefinition> resolvedParameters = new ArrayList<>();
                for (FieldDefinition parameter : parameters) {
                    DataType parameterType =
                        ServiceUtils.resolveDataType(dtm, parameter.type);
                    if (parameterType == null) {
                        result.append("Unknown parameter type: ")
                            .append(parameter.type);
                        return null;
                    }
                    resolvedParameters.add(new ParameterDefinitionImpl(
                        parameter.name, parameterType, null));
                }
                if (!resolvedParameters.isEmpty()) {
                    funcDef.setArguments(
                        resolvedParameters.toArray(new ParameterDefinition[0]));
                }

                DataType addedFuncDef = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);

                result.append("Successfully created function signature: ").append(addedFuncDef.getName());
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error creating function signature: ").append(e.getMessage());
        }

        return success.get() ? Response.text(result.toString()) : Response.err(result.toString());
    }

    // -----------------------------------------------------------------------
    // Data Type Modification Methods
    // -----------------------------------------------------------------------

    /**
     * Apply a specific data type at the given memory address
     */
    @McpTool(path = "/apply_data_type", method = "POST", description = "Apply data type at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response applyDataType(
            @Param(value = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String addressStr,
            @Param(value = "type_name", source = ParamSource.BODY) String typeName,
            @Param(value = "clear_existing", source = ParamSource.BODY, defaultValue = "true") boolean clearExisting,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }

        if (typeName == null || typeName.isEmpty()) {
            return Response.err("Data type name is required");
        }

        Address address = ServiceUtils.parseMutationAddress(program, addressStr);
        if (address == null) {
            // A refused mutation is an error, not a plain-text result: an unqualified
            // address that is mapped in several spaces stops here, and the caller has
            // to see that as a failure rather than as endpoint output.
            return Response.err(ServiceUtils.getLastParseError());
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = ServiceUtils.resolveDataType(dtm, typeName);

        if (dataType == null) {
            return Response.err("Unknown data type: " + typeName + ". " +
                   "For arrays, use syntax 'basetype[count]' (e.g., 'dword[10]'). " +
                   "Or create the type first using create_struct, create_enum, or mcp_ghidra_create_array_type.");
        }

        Listing listing = program.getListing();

        // Check if address is in a valid memory block
        if (!program.getMemory().contains(address)) {
            return Response.err("Address is not in program memory: " + addressStr);
        }

        // Apply the data type under the injected threading strategy so the
        // mutation runs on the EDT
        // with transaction commit/rollback handled centrally.
        try {
            return threadingStrategy.executeWrite(program, "Apply Data Type: " + typeName, () -> {
                    // Clear existing code/data if requested
                    if (clearExisting) {
                        CodeUnit existingCU = listing.getCodeUnitAt(address);
                        if (existingCU != null) {
                            listing.clearCodeUnits(address,
                                address.add(Math.max(dataType.getLength() - 1, 0)), false);
                        }
                    }

                    // Apply the data type
                    Data data = listing.createData(address, dataType);

                    // Validate size matches expectation
                    int expectedSize = dataType.getLength();
                    int actualSize = (data != null) ? data.getLength() : 0;

                    if (actualSize != expectedSize) {
                        Msg.warn(this, String.format("Size mismatch: expected %d bytes but applied %d bytes at %s",
                                                     expectedSize, actualSize, addressStr));
                    }

                    String resultText = "Successfully applied data type '" + typeName + "' at " +
                                   addressStr + " (size: " + actualSize + " bytes)";

                    // Add value information if available
                    if (data != null && data.getValue() != null) {
                        resultText += "\nValue: " + data.getValue().toString();
                    }
                    return Response.text(resultText);
            });
        } catch (Exception e) {
            return Response.err("Error applying data type: " + e.getMessage());
        }
    }

    /**
     * Resolve a type by exact category path when qualified, or by bare name when not.
     *
     * <p>ServiceUtils.findDataTypeByNameInAllCategories compares {@code getName()} only, so a
     * qualified name can never match it, and two same-named types in different categories
     * resolve to whichever the iterator reaches first. Renaming the wrong type is silent and
     * hard to notice, so this refuses to guess.
     *
     * @return the single match, or null with the reason appended to {@code problem}
     */
    static DataType resolveExactDataType(DataTypeManager dtm, String name,
                                         StringBuilder problem) {
        if (name.contains("/")) {
            DataType exact = dtm.getDataType(name);
            if (exact == null) {
                problem.append("Data type not found at path: ").append(name);
            }
            return exact;
        }

        List<DataType> matches = new ArrayList<>();
        Iterator<DataType> all = dtm.getAllDataTypes();
        while (all.hasNext()) {
            DataType candidate = all.next();
            if (candidate.getName().equals(name)) {
                matches.add(candidate);
            }
        }
        if (matches.isEmpty()) {
            problem.append("Data type not found: ").append(name);
            return null;
        }
        if (matches.size() > 1) {
            List<String> paths = matches.stream().map(DataType::getPathName).sorted().toList();
            problem.append("Ambiguous data type name '").append(name)
                   .append("' matches ").append(matches.size()).append(" types: ").append(paths)
                   .append(". Pass the category-qualified path.");
            return null;
        }
        return matches.get(0);
    }

    /**
     * Rename a data type in place, preserving every existing application of it.
     *
     * <p>The only previous route was clone + re-apply + delete, which silently dropped the
     * existing applications of the old type.
     */
    @McpTool(path = "/rename_data_type", method = "POST",
             description = "Rename a data type (struct, union, enum, typedef) in place, preserving existing applications of it")
    public Response renameDataType(
            @Param(value = "old_name", source = ParamSource.BODY,
                   description = "Current type name. Bare (Foo) only when unambiguous; otherwise pass the category-qualified path (/MyCat/Foo).") String oldName,
            @Param(value = "new_name", source = ParamSource.BODY,
                   description = "New type name. Must be unique within the type's category.") String newName,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        // Argument guards run before the program lookup so a malformed call reports the actual
        // problem instead of "No program loaded".
        if (oldName == null || oldName.isEmpty()) return Response.err("Old name is required");
        if (newName == null || newName.isEmpty()) return Response.err("New name is required");

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        StringBuilder result = new StringBuilder();
        AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeWrite(program, "Rename data type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = resolveExactDataType(dtm, oldName, result);
                if (dataType == null) {
                    return null;
                }

                // Built-in types (int, char, ...) belong to the built-in manager, not the
                // program; setName would either fail or corrupt the shared archive.
                if (dataType instanceof BuiltInDataType) {
                    result.append("Cannot rename built-in data type: ").append(oldName);
                    return null;
                }

                if (newName.equals(dataType.getName())) {
                    result.append("Data type '").append(oldName).append("' already has that name");
                    return null;
                }

                // A same-named sibling in the destination category would make the rename
                // ambiguous; report it rather than letting Ghidra auto-uniquify to Foo.conflict.
                Category category = dtm.getCategory(dataType.getCategoryPath());
                if (category != null && category.getDataType(newName) != null) {
                    result.append("A data type named '").append(newName)
                          .append("' already exists in category '")
                          .append(dataType.getCategoryPath().getPath()).append("'");
                    return null;
                }

                String renamed = dataType.getPathName();
                try {
                    dataType.setName(newName);
                } catch (InvalidNameException | DuplicateNameException e) {
                    result.append("Error renaming data type: ").append(e.getMessage());
                    return null;
                }

                result.append("Successfully renamed data type '").append(renamed)
                      .append("' to '").append(newName).append("'");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error renaming data type: ").append(e.getMessage());
        }

        return success.get() ? Response.text(result.toString()) : Response.err(result.toString());
    }

    @McpTool(path = "/delete_data_type", method = "POST",
            description = "Delete an unused data type by name")
    public Response deleteDataType(
            @Param(value = "type_name", source = ParamSource.BODY) String typeName,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        if (typeName == null || typeName.isEmpty()) return Response.err("Type name is required");

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            threadingStrategy.executeWrite(program, "Delete data type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, typeName);

                if (dataType == null) {
                    result.append("Data type not found: ").append(typeName);
                    return null;
                }

                // Check if type is in use (simplified check)
                // Note: Ghidra will prevent deletion if type is in use during remove operation

                boolean deleted = dtm.remove(dataType);
                if (deleted) {
                    result.append("Data type '").append(typeName).append("' deleted successfully");
                    success.set(true);
                } else {
                    result.append("Failed to delete data type '").append(typeName)
                            .append("' (it may be in use)");
                }
                return null;
            });
        } catch (Exception e) {
            result.append("Error deleting data type: ").append(e.getMessage());
        }

        return success.get() ? Response.text(result.toString()) : Response.err(result.toString());
    }

    /**
     * Modify a field in an existing structure
     */
    @McpTool(path = "/modify_struct_field", method = "POST", description = "Modify a field in a structure. Fields can be identified by name or by offset (for unnamed fields). For layout size changes (grow/shrink padding), use resize_struct instead of manual delete+create.")
    public Response modifyStructField(
            @Param(value = "struct_name", source = ParamSource.BODY) String structName,
            @Param(value = "field_name", source = ParamSource.BODY, defaultValue = "",
                   description = "Field name to modify. For unnamed fields, use 'offset:N' (e.g., 'offset:16') to identify by byte offset.") String fieldName,
            @Param(value = "new_type", source = ParamSource.BODY, defaultValue = "") String newType,
            @Param(value = "new_name", source = ParamSource.BODY, defaultValue = "") String newName,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (structName == null || structName.isEmpty()) return Response.err("Structure name is required");
        if ((fieldName == null || fieldName.isEmpty()) && (newName == null || newName.isEmpty())) {
            return Response.err("Field name or offset is required");
        }

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            threadingStrategy.executeWrite(program, "Modify struct field", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, structName);

                if (dataType == null) {
                    result.append("Structure not found: ").append(structName);
                    return null;
                }

                if (!(dataType instanceof Structure)) {
                    result.append("Data type '").append(structName).append("' is not a structure");
                    return null;
                }

                Structure struct = (Structure) dataType;
                DataTypeComponent targetComponent = null;

                // Support offset-based lookup: "offset:16" or "offset:0x10"
                if (fieldName != null && fieldName.startsWith("offset:")) {
                    try {
                        String offsetStr = fieldName.substring(7).trim();
                        int targetOffset = offsetStr.startsWith("0x") || offsetStr.startsWith("0X")
                                ? Integer.parseInt(offsetStr.substring(2), 16)
                                : Integer.parseInt(offsetStr);
                        targetComponent = struct.getComponentAt(targetOffset);
                        if (targetComponent == null) {
                            result.append("No field at offset ").append(targetOffset).append(" in structure '").append(structName).append("'");
                            return null;
                        }
                    } catch (NumberFormatException e) {
                        result.append("Invalid offset format: ").append(fieldName).append(". Use 'offset:16' or 'offset:0x10'");
                        return null;
                    }
                } else {
                    // Find by field name
                    DataTypeComponent[] components = struct.getDefinedComponents();
                    for (DataTypeComponent component : components) {
                        if (fieldName != null && fieldName.equals(component.getFieldName())) {
                            targetComponent = component;
                            break;
                        }
                    }
                }

                if (targetComponent == null) {
                    result.append("Field '").append(fieldName).append("' not found in structure '").append(structName)
                            .append("'. For unnamed fields, use 'offset:N' (e.g., 'offset:16' or 'offset:0x10')");
                    return null;
                }

                // If new type is specified, change the field type
                if (newType != null && !newType.isEmpty()) {
                    DataType newDataType = ServiceUtils.resolveDataType(dtm, newType);
                    if (newDataType == null) {
                        result.append("New data type not found: ").append(newType);
                        return null;
                    }
                    struct.replace(targetComponent.getOrdinal(), newDataType, newDataType.getLength());
                }

                // If new name is specified, pass it unchanged to Ghidra.
                if (newName != null && !newName.isEmpty()) {
                    targetComponent = struct.getComponent(targetComponent.getOrdinal()); // Refresh component
                    targetComponent.setFieldName(newName);
                }

                result.append("Successfully modified field '").append(fieldName).append("' in structure '").append(structName).append("'");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error modifying struct field: ").append(e.getMessage());
        }

        return success.get() ? Response.text(result.toString()) : Response.err(result.toString());
    }

    /**
     * Grow or shrink an existing structure without delete+recreate.
     */
    @McpTool(path = "/resize_struct", method = "POST",
            description = "Grow or shrink an existing structure by total byte size. Defined fields whose end offset fits within new_size are preserved; growth pads with undefined filler. Refuses shrink that would clip defined fields unless force=true. See docs/STRUCT_RESIZE_WORKFLOW.md.")
    public Response resizeStruct(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "new_size", source = ParamSource.BODY) int newSize,
            @Param(value = "preserve_fields", source = ParamSource.BODY, defaultValue = "true",
                   description = "When true (default), keep defined fields that still fit; when false with force, trailing layout may be cleared before resize.") boolean preserveFields,
            @Param(value = "force", source = ParamSource.BODY, defaultValue = "false",
                   description = "Allow shrink even when defined fields extend past new_size (clips trailing layout).") boolean force,
            @Param(value = "program", defaultValue = "") String programName) {

        if (name == null || name.isEmpty()) {
            return Response.err("name is required");
        }
        if (newSize <= 0) {
            return Response.err("new_size must be positive");
        }

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();
        final int[] oldLenOut = new int[1];

        try {
            threadingStrategy.executeWrite(program, "Resize structure: " + name, () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, name);
                if (dataType == null) {
                    result.append("Structure not found: ").append(name);
                    return null;
                }
                if (!(dataType instanceof Structure)) {
                    result.append("Data type '").append(name).append("' is not a structure");
                    return null;
                }

                Structure struct = (Structure) dataType;
                oldLenOut[0] = struct.getLength();
                String clipError = validateStructResize(struct, newSize, force);
                if (clipError != null) {
                    result.append(clipError);
                    return null;
                }

                if (!preserveFields && force && newSize < oldLenOut[0]) {
                    clearStructComponentsFromOffset(struct, newSize);
                }

                struct.setLength(newSize);
                success.set(true);
                result.append("Resized '").append(name).append("' from ")
                        .append(oldLenOut[0]).append(" to ").append(struct.getLength()).append(" bytes");
                return null;
            });
        } catch (IllegalArgumentException e) {
            result.append("Resize failed: ").append(e.getMessage())
                    .append(". Use modify_struct_field, add_struct_field, or remove_struct_field before resizing.");
        } catch (Exception e) {
            result.append("Error resizing structure: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.ok(JsonHelper.mapOf(
                    "status", "success",
                    "name", name,
                    "old_size", oldLenOut[0],
                    "new_size", newSize,
                    "message", result.toString()));
        }
        return result.length() > 0 ? Response.err(result.toString()) : Response.err("Failed to resize structure");
    }


    /** Highest byte offset covered by any defined component (0 if empty). */
    static int structDefinedByteExtent(Structure struct) {
        int max = 0;
        for (DataTypeComponent component : struct.getDefinedComponents()) {
            max = Math.max(max, component.getEndOffset());
        }
        return max;
    }

    /**
     * @return error message when shrink would clip defined fields and force is false; null if OK
     */
    static String validateStructResize(Structure struct, int newSize, boolean force) {
        return validateStructResize(structDefinedByteExtent(struct), struct.getName(), newSize, force);
    }

    static String validateStructResize(int definedByteExtent, String structName, int newSize, boolean force) {
        if (newSize <= 0) {
            return "new_size must be positive";
        }
        if (newSize < definedByteExtent && !force) {
            return "Cannot shrink '" + structName + "' to " + newSize
                    + " bytes: defined fields extend to " + definedByteExtent
                    + " bytes. Set force=true to clip, or adjust the fields before resizing.";
        }
        return null;
    }

    /** Delete components starting at {@code fromOffset} (highest ordinal first). */
    static void clearStructComponentsFromOffset(Structure struct, int fromOffset) {
        for (int i = struct.getNumComponents() - 1; i >= 0; i--) {
            DataTypeComponent component = struct.getComponent(i);
            if (component != null && component.getOffset() >= fromOffset) {
                struct.delete(i);
            }
        }
    }

    boolean deletePlaceholderType(Program program, DataType dataType, String logicalName,
                                         StringBuilder result) {
        AtomicBoolean success = new AtomicBoolean(false);
        try {
            threadingStrategy.executeWrite(program, "Delete placeholder type " + logicalName, () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                boolean deleted = dtm.remove(dataType);
                if (deleted) {
                    result.append("Removed placeholder '").append(dataType.getPathName()).append("'");
                    success.set(true);
                } else {
                    result.append("Could not remove '").append(dataType.getPathName())
                            .append("' (in use or locked)");
                }
                return null;
            });
        } catch (Exception e) {
            result.append("Error: ").append(e.getMessage());
        }
        return success.get();
    }

    /**
     * Add a new field to an existing structure
     */
    @McpTool(path = "/add_struct_field", method = "POST", description = "Add a field to a structure")
    public Response addStructField(
            @Param(value = "struct_name", source = ParamSource.BODY) String structName,
            @Param(value = "field_name", source = ParamSource.BODY) String fieldName,
            @Param(value = "field_type", source = ParamSource.BODY) String fieldType,
            @Param(value = "offset", source = ParamSource.BODY, defaultValue = "-1") int offset,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (structName == null || structName.isEmpty()) return Response.err("Structure name is required");
        if (fieldName == null || fieldName.isEmpty()) return Response.err("Field name is required");
        if (fieldType == null || fieldType.isEmpty()) return Response.err("Field type is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();
        final String finalFieldName = fieldName;

        try {
            threadingStrategy.executeWrite(program, "Add struct field", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, structName);

                if (dataType == null) {
                    result.append("Structure not found: ").append(structName);
                    return null;
                }

                if (!(dataType instanceof Structure)) {
                    result.append("Data type '").append(structName).append("' is not a structure");
                    return null;
                }

                Structure struct = (Structure) dataType;
                DataType newFieldType = ServiceUtils.resolveDataType(dtm, fieldType);
                if (newFieldType == null) {
                    result.append("Field data type not found: ").append(fieldType);
                    return null;
                }

                if (offset >= 0) {
                    // Overlay at specific offset (replace undefined padding, do NOT shift fields)
                    if (offset < struct.getLength()) {
                        struct.replaceAtOffset(offset, newFieldType, newFieldType.getLength(), finalFieldName, null);
                    } else {
                        // At or beyond current struct size — grow to fit, then place
                        int needed = offset + newFieldType.getLength() - struct.getLength();
                        if (needed > 0) {
                            struct.growStructure(needed);
                        }
                        struct.replaceAtOffset(offset, newFieldType, newFieldType.getLength(), finalFieldName, null);
                    }
                } else {
                    // Add at end
                    struct.add(newFieldType, finalFieldName, null);
                }

                result.append("Successfully added field '").append(finalFieldName).append("' to structure '").append(structName).append("'");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error adding struct field: ").append(e.getMessage());
        }

        return success.get() ? Response.text(result.toString()) : Response.err(result.toString());
    }

    /**
     * Remove a field from an existing structure
     */
    @McpTool(path = "/remove_struct_field", method = "POST", description = "Remove a field from a structure")
    public Response removeStructField(
            @Param(value = "struct_name", source = ParamSource.BODY) String structName,
            @Param(value = "field_name", source = ParamSource.BODY) String fieldName,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (structName == null || structName.isEmpty()) return Response.err("Structure name is required");
        if (fieldName == null || fieldName.isEmpty()) return Response.err("Field name is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            threadingStrategy.executeWrite(program, "Remove struct field", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, structName);

                if (dataType == null) {
                    result.append("Structure not found: ").append(structName);
                    return null;
                }

                if (!(dataType instanceof Structure)) {
                    result.append("Data type '").append(structName).append("' is not a structure");
                    return null;
                }

                Structure struct = (Structure) dataType;
                DataTypeComponent[] components = struct.getDefinedComponents();
                int targetOrdinal = -1;

                // Find the field to remove
                for (DataTypeComponent component : components) {
                    if (fieldName.equals(component.getFieldName())) {
                        targetOrdinal = component.getOrdinal();
                        break;
                    }
                }

                if (targetOrdinal == -1) {
                    result.append("Field '").append(fieldName).append("' not found in structure '").append(structName).append("'");
                    return null;
                }

                struct.delete(targetOrdinal);
                result.append("Successfully removed field '").append(fieldName).append("' from structure '").append(structName).append("'");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error removing struct field: ").append(e.getMessage());
        }

        return success.get() ? Response.text(result.toString()) : Response.err(result.toString());
    }

    private static List<FieldDefinition> parseFields(
            List<Map<String, Object>> values) {
        List<FieldDefinition> fields = new ArrayList<>();
        for (int index = 0; index < values.size(); index++) {
            Map<String, Object> value = values.get(index);
            Object rawName = value.get("name");
            Object rawType = value.get("type");
            if (!(rawName instanceof String name) || name.isBlank()) {
                throw new IllegalArgumentException(
                    "fields[" + index + "].name must be a non-empty string");
            }
            if (!(rawType instanceof String type) || type.isBlank()) {
                throw new IllegalArgumentException(
                    "fields[" + index + "].type must be a non-empty string");
            }
            int offset = -1;
            if (value.containsKey("offset")) {
                Object rawOffset = value.get("offset");
                Number number;
                if (rawOffset instanceof Number numeric) {
                    number = numeric;
                } else if (rawOffset instanceof String text) {
                    try {
                        number = Integer.valueOf(text);
                    } catch (NumberFormatException error) {
                        throw new IllegalArgumentException(
                            "fields[" + index
                                + "].offset must be a non-negative integer");
                    }
                } else {
                    throw new IllegalArgumentException(
                        "fields[" + index + "].offset must be a non-negative integer");
                }
                if (number.doubleValue() != Math.rint(number.doubleValue())
                        || number.longValue() < 0
                        || number.longValue() > Integer.MAX_VALUE) {
                    throw new IllegalArgumentException(
                        "fields[" + index + "].offset must be a non-negative integer");
                }
                offset = number.intValue();
            }
            fields.add(new FieldDefinition(name, type, offset));
        }
        return fields;
    }

    private static Map<String, Long> parseEnumValues(
            Map<String, Object> input) {
        Map<String, Long> values = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : input.entrySet()) {
            Object raw = entry.getValue();
            long value;
            if (raw instanceof Number number) {
                if (number.doubleValue() != Math.rint(number.doubleValue())) {
                    throw new IllegalArgumentException(
                        "enum value " + entry.getKey() + " must be an integer");
                }
                value = number.longValue();
            } else if (raw instanceof String text) {
                String trimmed = text.trim();
                value = trimmed.startsWith("0x") || trimmed.startsWith("0X")
                    ? Long.parseUnsignedLong(trimmed.substring(2), 16)
                    : Long.parseLong(trimmed);
            } else {
                throw new IllegalArgumentException(
                    "enum value " + entry.getKey() + " must be an integer");
            }
            values.put(entry.getKey(), value);
        }
        return values;
    }

}
