package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Service for symbol and label operations: create, rename, delete, batch operations.
 */
public class SymbolLabelService {

    private static final String CREATE_LABELS_SCHEMA =
        "{\"type\":\"array\",\"minItems\":1,"
        + "\"items\":{\"type\":\"object\",\"additionalProperties\":false,"
        + "\"properties\":{\"address\":{\"type\":\"string\"},"
        + "\"name\":{\"type\":\"string\"},"
        + "\"namespace\":{\"type\":\"string\"}},"
        + "\"required\":[\"address\",\"name\"]}}";
    private static final String DELETE_LABELS_SCHEMA =
        "{\"type\":\"array\",\"minItems\":1,"
        + "\"items\":{\"type\":\"object\",\"additionalProperties\":false,"
        + "\"properties\":{\"address\":{\"type\":\"string\"},"
        + "\"name\":{\"type\":\"string\"}},"
        + "\"required\":[\"address\"]}}";

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public SymbolLabelService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    /**
     * Pre-flight overlay-ambiguity check for the batch label endpoints.
     *
     * <p>Runs before the transaction opens so one ambiguous entry fails the whole
     * request rather than being reported alongside a set of already-applied labels.
     *
     * @return the refusal message naming the offending address, or null when every
     *     entry is unambiguous
     */
    private static String firstAmbiguousLabelAddress(
            Program program, List<Map<String, String>> labels) {
        List<String> addresses = new ArrayList<>();
        for (Map<String, String> entry : labels) {
            if (entry != null) {
                addresses.add(entry.get("address"));
            }
        }
        return ServiceUtils.firstAmbiguousUnqualifiedAddress(program, addresses);
    }

    // -----------------------------------------------------------------------
    // Label Methods
    // -----------------------------------------------------------------------


    @McpTool(path = "/rename_label", method = "POST", description = "Rename a label at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response renameLabel(
            @Param(value = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String addressStr,
            @Param(value = "old_name", source = ParamSource.BODY) String oldName,
            @Param(value = "new_name", source = ParamSource.BODY) String newName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            Address address = ServiceUtils.parseMutationAddress(program, addressStr);
            if (address == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            SymbolTable symbolTable = program.getSymbolTable();
            Symbol[] symbols = symbolTable.getSymbols(address);

            Symbol targetSymbol = null;
            for (Symbol symbol : symbols) {
                if (symbol.getName().equals(oldName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    targetSymbol = symbol;
                    break;
                }
            }

            if (targetSymbol == null) {
                return Response.err("Label not found: " + oldName + " at address " + addressStr);
            }

            for (Symbol symbol : symbols) {
                if (symbol.getName().equals(newName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    return Response.err("Label with name '" + newName + "' already exists at address " + addressStr);
                }
            }

            int transactionId = program.startTransaction("Rename Label");
            try {
                targetSymbol.setName(newName, SourceType.USER_DEFINED);
                return Response.ok(JsonHelper.mapOf("status", "success", "message",
                        "Renamed label from '" + oldName + "' to '" + newName + "' at address " + addressStr));
            } catch (InvalidInputException e) {
                return Response.err("Error renaming label: " + e.getMessage());
            } catch (Exception e) {
                return Response.err("Error renaming label: " + e.getMessage());
            } finally {
                program.endTransaction(transactionId, true);
            }

        } catch (Exception e) {
            return Response.err("Error processing request: " + e.getMessage());
        }
    }

    @McpTool(path = "/create_label", method = "POST", description = "Create a label at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response createLabel(
            @Param(value = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String addressStr,
            @Param(value = "name", source = ParamSource.BODY) String labelName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }
        if (labelName == null || labelName.isEmpty()) {
            return Response.err("Label name is required");
        }

        try {
            Address address = ServiceUtils.parseMutationAddress(program, addressStr);
            if (address == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            SymbolTable symbolTable = program.getSymbolTable();

            Symbol[] existingSymbols = symbolTable.getSymbols(address);
            for (Symbol symbol : existingSymbols) {
                if (symbol.getName().equals(labelName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    return Response.err("Label '" + labelName + "' already exists at address " + addressStr);
                }
            }

            SymbolIterator existingLabels = symbolTable.getSymbolIterator(labelName, true);
            if (existingLabels.hasNext()) {
                Symbol existingSymbol = existingLabels.next();
                if (existingSymbol.getSymbolType() == SymbolType.LABEL) {
                    Msg.warn(this, "Label name '" + labelName + "' already exists at address " +
                            existingSymbol.getAddress() + ". Creating duplicate at " + addressStr);
                }
            }

            int transactionId = program.startTransaction("Create Label");
            try {
                Symbol newSymbol = symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
                if (newSymbol != null) {
                    return Response.ok(JsonHelper.mapOf("status", "success", "message",
                            "Created label '" + labelName + "' at address " + addressStr));
                } else {
                    return Response.err("Failed to create label '" + labelName + "' at address " + addressStr);
                }
            } catch (InvalidInputException e) {
                return Response.err("Error creating label: " + e.getMessage());
            } catch (Exception e) {
                return Response.err("Error creating label: " + e.getMessage());
            } finally {
                program.endTransaction(transactionId, true);
            }

        } catch (Exception e) {
            return Response.err("Error processing request: " + e.getMessage());
        }
    }

    @McpTool(path = "/batch_create_labels", method = "POST", description = "Create multiple labels at once")
    public Response batchCreateLabels(
            @Param(value = "labels", source = ParamSource.BODY,
                description =
                    "Label objects with address, name, and optional nested "
                        + "namespace path",
                schemaFragment = CREATE_LABELS_SCHEMA)
                List<Map<String, String>> labels,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (labels == null || labels.isEmpty()) {
            return Response.err("No labels provided");
        }

        String ambiguous = firstAmbiguousLabelAddress(program, labels);
        if (ambiguous != null) {
            return Response.err("batch_create_labels wrote nothing: " + ambiguous);
        }

        final AtomicInteger successCount = new AtomicInteger(0);
        final AtomicInteger skipCount = new AtomicInteger(0);
        final AtomicInteger errorCount = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Create Labels");
                try {
                    SymbolTable symbolTable = program.getSymbolTable();

                    for (Map<String, String> labelEntry : labels) {
                            String addressStr = labelEntry.get("address");
                            String labelName = labelEntry.get("name");
                            String namespacePath = labelEntry.get("namespace");

                        if (addressStr == null || addressStr.isEmpty()) {
                            errors.add("Missing address in label entry");
                            errorCount.incrementAndGet();
                            continue;
                        }
                        if (labelName == null || labelName.isEmpty()) {
                            errors.add("Missing name for address " + addressStr);
                            errorCount.incrementAndGet();
                            continue;
                        }

                        try {
                            Address address = ServiceUtils.parseMutationAddress(program, addressStr);
                            if (address == null) {
                                errors.add(ServiceUtils.getLastParseError());
                                errorCount.incrementAndGet();
                                continue;
                            }

                            Symbol[] existingSymbols = symbolTable.getSymbols(address);
                            Namespace namespace =
                                resolveNamespace(program, namespacePath);
                            boolean labelExists = false;
                            for (Symbol symbol : existingSymbols) {
                                if (symbol.getName().equals(labelName)
                                        && symbol.getSymbolType() == SymbolType.LABEL
                                        && symbol.getParentNamespace().equals(namespace)) {
                                    labelExists = true;
                                    break;
                                }
                            }

                            if (labelExists) {
                                skipCount.incrementAndGet();
                                continue;
                            }

                            Symbol newSymbol = symbolTable.createLabel(
                                address, labelName, namespace,
                                SourceType.USER_DEFINED);
                            if (newSymbol != null) {
                                successCount.incrementAndGet();
                            } else {
                                errors.add("Failed to create label '" + labelName + "' at " + addressStr);
                                errorCount.incrementAndGet();
                            }

                        } catch (Exception e) {
                            errors.add("Error at " + addressStr + ": " + e.getMessage());
                            errorCount.incrementAndGet();
                            Msg.error(this, "Error creating label at " + addressStr, e);
                        }
                    }

                } catch (Exception e) {
                    errors.add("Transaction error: " + e.getMessage());
                    Msg.error(this, "Error in batch create labels transaction", e);
                } finally {
                    program.endTransaction(tx, successCount.get() > 0);
                }
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        Map<String, Object> result = JsonHelper.mapOf(
                "success", true,
                "labels_created", successCount.get(),
                "labels_skipped", skipCount.get(),
                "labels_failed", errorCount.get()
        );
        if (!errors.isEmpty()) {
            result.put("errors", errors);
        }
        return Response.ok(result);
    }

    private static Namespace resolveNamespace(
            Program program, String path) throws Exception {
        Namespace namespace = program.getGlobalNamespace();
        if (path == null || path.isBlank()) {
            return namespace;
        }
        SymbolTable symbols = program.getSymbolTable();
        for (String name : path.split("::")) {
            if (name.isBlank()) {
                throw new InvalidInputException("Invalid namespace path: " + path);
            }
            Namespace child = symbols.getNamespace(name, namespace);
            namespace = child == null
                ? symbols.createNameSpace(
                    namespace, name, SourceType.USER_DEFINED)
                : child;
        }
        return namespace;
    }


    @McpTool(path = "/delete_label", method = "POST", description = "Delete a label at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response deleteLabel(
            @Param(value = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String addressStr,
            @Param(value = "name", source = ParamSource.BODY) String labelName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }

        try {
            Address address = ServiceUtils.parseMutationAddress(program, addressStr);
            if (address == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            SymbolTable symbolTable = program.getSymbolTable();
            Symbol[] symbols = symbolTable.getSymbols(address);

            if (symbols == null || symbols.length == 0) {
                return Response.ok(JsonHelper.mapOf("success", false, "message",
                        "No symbols found at address " + addressStr));
            }

            final AtomicInteger deletedCount = new AtomicInteger(0);
            final List<String> deletedNames = new ArrayList<>();
            final List<String> errors = new ArrayList<>();

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete Label");
                try {
                    for (Symbol symbol : symbols) {
                        if (symbol.getSymbolType() != SymbolType.LABEL) {
                            continue;
                        }
                        if (labelName != null && !labelName.isEmpty()) {
                            if (!symbol.getName().equals(labelName)) {
                                continue;
                            }
                        }

                        String name = symbol.getName();
                        boolean deleted = symbol.delete();
                        if (deleted) {
                            deletedCount.incrementAndGet();
                            deletedNames.add(name);
                        } else {
                            errors.add("Failed to delete label: " + name);
                        }
                    }
                } catch (Exception e) {
                    errors.add("Error during deletion: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, deletedCount.get() > 0);
                }
            });

            Map<String, Object> result = JsonHelper.mapOf(
                    "success", deletedCount.get() > 0,
                    "deleted_count", deletedCount.get(),
                    "deleted_names", deletedNames
            );
            if (!errors.isEmpty()) {
                result.put("errors", errors);
            }
            return Response.ok(result);

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    @McpTool(path = "/batch_delete_labels", method = "POST", description = "Delete multiple labels at once")
    public Response batchDeleteLabels(
            @Param(value = "labels", source = ParamSource.BODY,
                description =
                    "Label objects with required address and optional exact name",
                schemaFragment = DELETE_LABELS_SCHEMA)
                List<Map<String, String>> labels,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (labels == null || labels.isEmpty()) {
            return Response.err("No labels provided");
        }

        String ambiguous = firstAmbiguousLabelAddress(program, labels);
        if (ambiguous != null) {
            return Response.err("batch_delete_labels deleted nothing: " + ambiguous);
        }

        final AtomicInteger deletedCount = new AtomicInteger(0);
        final AtomicInteger skippedCount = new AtomicInteger(0);
        final AtomicInteger errorCount = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Delete Labels");
                try {
                    SymbolTable symbolTable = program.getSymbolTable();

                    for (Map<String, String> labelEntry : labels) {
                        String addressStr = labelEntry.get("address");
                        String labelNameEntry = labelEntry.get("name");

                        if (addressStr == null || addressStr.isEmpty()) {
                            errors.add("Missing address in label entry");
                            errorCount.incrementAndGet();
                            continue;
                        }

                        try {
                            Address address = ServiceUtils.parseMutationAddress(program, addressStr);
                            if (address == null) {
                                errors.add(ServiceUtils.getLastParseError());
                                errorCount.incrementAndGet();
                                continue;
                            }

                            Symbol[] symbols = symbolTable.getSymbols(address);
                            if (symbols == null || symbols.length == 0) {
                                skippedCount.incrementAndGet();
                                continue;
                            }

                            for (Symbol symbol : symbols) {
                                if (symbol.getSymbolType() != SymbolType.LABEL) {
                                    continue;
                                }
                                if (labelNameEntry != null && !labelNameEntry.isEmpty()) {
                                    if (!symbol.getName().equals(labelNameEntry)) {
                                        continue;
                                    }
                                }

                                boolean deleted = symbol.delete();
                                if (deleted) {
                                    deletedCount.incrementAndGet();
                                } else {
                                    errors.add("Failed to delete at " + addressStr);
                                    errorCount.incrementAndGet();
                                }
                            }
                        } catch (Exception e) {
                            errors.add("Error at " + addressStr + ": " + e.getMessage());
                            errorCount.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    errors.add("Transaction error: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, deletedCount.get() > 0);
                }
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        Map<String, Object> result = JsonHelper.mapOf(
                "success", true,
                "labels_deleted", deletedCount.get(),
                "labels_skipped", skippedCount.get(),
                "errors_count", errorCount.get()
        );
        if (!errors.isEmpty()) {
            result.put("errors", errors.subList(0, Math.min(errors.size(), 10)));
        }
        return Response.ok(result);
    }


    // -----------------------------------------------------------------------
    // External Location Methods
    // -----------------------------------------------------------------------

    @McpTool(path = "/rename_external_location", method = "POST", description = "Rename external location. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response renameExternalLocation(
            @Param(value = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String address,
            @Param(value = "new_name", source = ParamSource.BODY) String newName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            Address addr = ServiceUtils.parseMutationAddress(program, address);
            if (addr == null) return Response.err(ServiceUtils.getLastParseError());
            ExternalManager extMgr = program.getExternalManager();

            String[] libNames = extMgr.getExternalLibraryNames();
            for (String libName : libNames) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    if (extLoc.getAddress().equals(addr)) {
                        final String finalLibName = libName;
                        final ExternalLocation finalExtLoc = extLoc;
                        final String oldName = extLoc.getLabel();

                        AtomicBoolean success = new AtomicBoolean(false);
                        AtomicReference<String> errorMsg = new AtomicReference<>();

                        try {
                            SwingUtilities.invokeAndWait(() -> {
                                int tx = program.startTransaction("Rename external location");
                                try {
                                    Namespace extLibNamespace = extMgr.getExternalLibrary(finalLibName);
                                    finalExtLoc.setName(extLibNamespace, newName, SourceType.USER_DEFINED);
                                    success.set(true);
                                    Msg.info(this, "Renamed external location: " + oldName + " -> " + newName);
                                } catch (Exception e) {
                                    errorMsg.set(e.getMessage());
                                    Msg.error(this, "Error renaming external location: " + e.getMessage());
                                } finally {
                                    program.endTransaction(tx, success.get());
                                }
                            });
                        } catch (Exception e) {
                            errorMsg.set(e.getMessage());
                        }

                        if (success.get()) {
                            return Response.ok(JsonHelper.mapOf(
                                    "success", true,
                                    "old_name", oldName,
                                    "new_name", newName,
                                    "dll", finalLibName
                            ));
                        } else {
                            return Response.err(errorMsg.get() != null ? errorMsg.get() : "Unknown error");
                        }
                    }
                }
            }

            return Response.err("External location not found at address " + address);
        } catch (Exception e) {
            Msg.error(this, "Exception in renameExternalLocation: " + e.getMessage());
            return Response.err(e.getMessage());
        }
    }

}
