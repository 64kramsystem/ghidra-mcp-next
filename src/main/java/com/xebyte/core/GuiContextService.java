package com.xebyte.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

@McpToolGroup(
    value = "gui",
    description = "Current Ghidra GUI context and navigation")
public final class GuiContextService {

    record GuiContext(
        boolean hasProgram,
        String program,
        boolean hasAddress,
        String address,
        String addressSpace,
        boolean mapped) {
    }

    record GuiSelectionRange(
        String start,
        String end,
        String addressSpace) {
    }

    interface Navigation {
        Program currentProgram();

        void activate(Program program);

        boolean goTo(Address address, Program program);
    }

    interface GuiAccess {
        ProgramLocation currentLocation();

        Program currentProgram();

        ProgramSelection currentSelection();

        List<Program> openPrograms();

        Navigation navigationFor(Program program);
    }

    private final GuiAccess gui;
    private final ThreadingStrategy threading;

    public GuiContextService(
            Supplier<PluginTool> toolSupplier,
            ProgramProvider ignoredProgramProvider) {
        this(
            new ToolGuiAccess(toolSupplier),
            ignoredProgramProvider,
            new SwingThreadingStrategy());
    }

    GuiContextService(
            GuiAccess gui,
            ProgramProvider ignoredProgramProvider,
            ThreadingStrategy threading) {
        this.gui = gui;
        this.threading = threading;
    }

    @McpTool(
        path = "/get_current_address",
        category = "gui",
        description = "Return the normalized active GUI program and cursor address",
        supportsDryRun = false)
    public Response getCurrentAddress() {
        try {
            return Response.ok(toJson(threading.executeRead(this::readContext)));
        }
        catch (Exception error) {
            return Response.err(message(error));
        }
    }

    @McpTool(
        path = "/get_current_selection",
        category = "gui",
        description = "Return the normalized GUI context and every selected address range",
        supportsDryRun = false)
    public Response getCurrentSelection() {
        try {
            return Response.ok(threading.executeRead(() -> {
                GuiContext context = readContext();
                ProgramSelection selection = gui.currentSelection();
                JsonObject result = toJson(context);
                JsonArray ranges = new JsonArray();
                boolean hasSelection =
                    selection != null && !selection.isEmpty();
                if (hasSelection) {
                    for (AddressRange range : selection.getAddressRanges()) {
                        ranges.add(toJson(new GuiSelectionRange(
                            range.getMinAddress().toString(),
                            range.getMaxAddress().toString(),
                            range.getAddressSpace().getName())));
                    }
                }
                result.addProperty("has_selection", hasSelection);
                result.add("ranges", ranges);
                return result;
            }));
        }
        catch (Exception error) {
            return Response.err(message(error));
        }
    }

    @McpTool(
        path = "/go_to_address",
        method = "POST",
        category = "gui",
        description = "Activate an open program and navigate the GUI to an exact address",
        supportsDryRun = false)
    public Response goToAddress(
            @Param(
                value = "address",
                source = ParamSource.BODY,
                paramType = "address",
                description = "Exact target address")
            String addressText,
            @Param(
                value = "program",
                source = ParamSource.BODY,
                defaultValue = "",
                description = "Open program path or unique name; omit for the active program")
            String programSelector) {
        try {
            return Response.ok(threading.executeRead(() ->
                navigate(addressText, programSelector)));
        }
        catch (Exception error) {
            return Response.err(message(error));
        }
    }

    private JsonObject navigate(
            String addressText, String programSelector) {
        GuiContext previous = readContext();
        Program program = resolveTargetProgram(programSelector);
        if (program == null) {
            String error = programSelector == null || programSelector.isBlank()
                ? "No active program"
                : "Open program not found: " + programSelector;
            return navigationResult(false, error, previous, readContext());
        }
        if (addressText == null || addressText.isBlank()) {
            return navigationResult(
                false, "Address is required", previous, readContext());
        }

        Address address =
            program.getAddressFactory().getAddress(addressText.trim());
        if (address == null) {
            return navigationResult(
                false,
                "Invalid address for program " + programIdentity(program)
                    + ": " + addressText,
                previous,
                readContext());
        }

        Navigation target = gui.navigationFor(program);
        if (target == null) {
            return navigationResult(
                false,
                "No GUI tool can navigate the open program: "
                    + programIdentity(program),
                previous,
                readContext());
        }

        try {
            if (target.currentProgram() != program) {
                target.activate(program);
            }
            if (!target.goTo(address, program)) {
                return navigationResult(
                    false,
                    "Ghidra could not navigate to " + address,
                    previous,
                    readContext());
            }
            return navigationResult(true, null, previous, readContext());
        }
        catch (RuntimeException error) {
            return navigationResult(
                false,
                "GUI navigation failed: " + message(error),
                previous,
                readContext());
        }
    }

    private Program resolveTargetProgram(String selector) {
        if (selector == null || selector.isBlank()) {
            ProgramLocation location = currentLocation();
            if (location != null && location.getProgram() != null) {
                return location.getProgram();
            }
            Program guiProgram = gui.currentProgram();
            if (guiProgram != null) {
                return guiProgram;
            }
            return null;
        }

        String requested = selector.trim();
        List<Program> nameMatches = new ArrayList<>();
        for (Program program : gui.openPrograms()) {
            if (requested.equalsIgnoreCase(programIdentity(program))) {
                return program;
            }
            if (requested.equalsIgnoreCase(program.getName())) {
                nameMatches.add(program);
            }
        }
        return nameMatches.size() == 1 ? nameMatches.get(0) : null;
    }

    private GuiContext readContext() {
        ProgramLocation location = currentLocation();
        Program program =
            location != null && location.getProgram() != null
                ? location.getProgram()
                : gui.currentProgram();
        Address address =
            location != null && location.getProgram() == program
                ? location.getAddress()
                : null;
        if (program == null) {
            return new GuiContext(false, null, false, null, null, false);
        }
        if (address == null) {
            return new GuiContext(
                true, programIdentity(program), false, null, null, false);
        }
        return new GuiContext(
            true,
            programIdentity(program),
            true,
            address.toString(),
            address.getAddressSpace().getName(),
            program.getMemory().contains(address));
    }

    private ProgramLocation currentLocation() {
        return gui.currentLocation();
    }

    private static String programIdentity(Program program) {
        if (program.getDomainFile() != null) {
            String path = program.getDomainFile().getPathname();
            if (path != null && !path.isBlank()) {
                return path;
            }
        }
        return program.getName();
    }

    private static JsonObject navigationResult(
            boolean success,
            String error,
            GuiContext previous,
            GuiContext current) {
        JsonObject result = new JsonObject();
        result.addProperty("success", success);
        if (error == null) {
            result.add("error", JsonNull.INSTANCE);
        }
        else {
            result.addProperty("error", error);
        }
        result.addProperty("changed", !previous.equals(current));
        result.add("previous_context", toJson(previous));
        result.add("current_context", toJson(current));
        return result;
    }

    private static JsonObject toJson(GuiContext context) {
        JsonObject result = new JsonObject();
        result.addProperty("has_program", context.hasProgram());
        addNullable(result, "program", context.program());
        result.addProperty("has_address", context.hasAddress());
        addNullable(result, "address", context.address());
        addNullable(result, "address_space", context.addressSpace());
        result.addProperty("mapped", context.mapped());
        return result;
    }

    private static JsonObject toJson(GuiSelectionRange range) {
        JsonObject result = new JsonObject();
        result.addProperty("start", range.start());
        result.addProperty("end", range.end());
        result.addProperty("address_space", range.addressSpace());
        return result;
    }

    private static void addNullable(
            JsonObject object, String name, String value) {
        if (value == null) {
            object.add(name, JsonNull.INSTANCE);
        }
        else {
            object.addProperty(name, value);
        }
    }

    private static String message(Throwable error) {
        return error.getMessage() != null
            ? error.getMessage()
            : error.toString();
    }

    private static final class ToolGuiAccess implements GuiAccess {
        private final Supplier<PluginTool> toolSupplier;
        private PluginTool preferredTool;

        private ToolGuiAccess(Supplier<PluginTool> toolSupplier) {
            this.toolSupplier = toolSupplier;
        }

        @Override
        public ProgramLocation currentLocation() {
            CodeViewerService viewer = codeViewer();
            return viewer != null ? viewer.getCurrentLocation() : null;
        }

        @Override
        public Program currentProgram() {
            for (PluginTool tool : availableTools()) {
                ProgramManager manager =
                    tool.getService(ProgramManager.class);
                if (manager != null && manager.getCurrentProgram() != null) {
                    return manager.getCurrentProgram();
                }
            }
            return null;
        }

        @Override
        public ProgramSelection currentSelection() {
            CodeViewerService viewer = codeViewer();
            return viewer != null ? viewer.getCurrentSelection() : null;
        }

        @Override
        public List<Program> openPrograms() {
            List<Program> result = new ArrayList<>();
            Set<Program> seen =
                Collections.newSetFromMap(new IdentityHashMap<>());
            for (PluginTool tool : availableTools()) {
                ProgramManager manager =
                    tool.getService(ProgramManager.class);
                if (manager == null) {
                    continue;
                }
                for (Program program : manager.getAllOpenPrograms()) {
                    if (program != null && seen.add(program)) {
                        result.add(program);
                    }
                }
            }
            return List.copyOf(result);
        }

        @Override
        public Navigation navigationFor(Program program) {
            for (PluginTool tool : availableTools()) {
                ProgramManager manager =
                    tool.getService(ProgramManager.class);
                GoToService goTo = tool.getService(GoToService.class);
                if (manager == null || goTo == null) {
                    continue;
                }
                for (Program open : manager.getAllOpenPrograms()) {
                    if (open == program) {
                        return new Navigation() {
                            @Override
                            public Program currentProgram() {
                                return manager.getCurrentProgram();
                            }

                            @Override
                            public void activate(Program target) {
                                preferredTool = tool;
                                manager.setCurrentProgram(target);
                            }

                            @Override
                            public boolean goTo(
                                    Address address, Program target) {
                                preferredTool = tool;
                                return goTo.goTo(address, target);
                            }
                        };
                    }
                }
            }
            return null;
        }

        private CodeViewerService codeViewer() {
            for (PluginTool tool : availableTools()) {
                CodeViewerService viewer =
                    tool.getService(CodeViewerService.class);
                if (viewer != null) {
                    return viewer;
                }
            }
            return null;
        }

        private List<PluginTool> availableTools() {
            PluginTool active = toolSupplier.get();
            if (active == null) {
                return List.of();
            }
            List<PluginTool> result = new ArrayList<>();
            Set<PluginTool> seen =
                Collections.newSetFromMap(new IdentityHashMap<>());
            result.add(active);
            seen.add(active);

            Project project = active.getProject();
            ToolManager manager =
                project != null ? project.getToolManager() : null;
            if (manager != null) {
                for (PluginTool tool : manager.getRunningTools()) {
                    if (tool != null && seen.add(tool)) {
                        result.add(tool);
                    }
                }
            }
            if (preferredTool != null && result.remove(preferredTool)) {
                result.add(0, preferredTool);
            }
            return result;
        }
    }
}
