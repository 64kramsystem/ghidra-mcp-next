package com.xebyte.core;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import javax.swing.SwingUtilities;
import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Program, project, analysis, and raw-memory operations.
 */
public class ProgramScriptService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private static final String AUTO_ANALYSIS_COMPLETION_MESSAGE = "Auto-analysis completed";
    public ProgramScriptService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    /** Return the active GUI tool. */
    private PluginTool getToolFromProvider() {
        if (programProvider instanceof MultiToolProgramProvider mtp) {
            return mtp.getActiveTool();
        }
        return null;
    }

    private boolean runAutoAnalysisAndPersistFlags(Program program, boolean force) {
        if (program == null) {
            return false;
        }
        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            // Ghidra's analyzers mutate the program DB, which requires an
            // open transaction. The GUI analysis-task framework opens one
            // for you; a direct mgr.startAnalysis() from the bridge does
            // NOT. Without this wrapper FunctionStartAnalyzer (and any
            // other writing analyzer) throws db.NoTransactionException
            // ("Transaction has not been started") on any program that
            // isn't already fully analyzed — the program-open path then
            // fails. Confirmed root cause of #209. The markProgram* option
            // writes go inside the same transaction since they mutate the
            // program too; persistProgram (save) runs AFTER the
            // transaction is closed.
            int txId = program.startTransaction("GhidraMCP-next auto-analysis");
            boolean txOk = false;
            try {
                ghidra.program.util.GhidraProgramUtilities.markProgramNotToAskToAnalyze(program);
                if (force) {
                    mgr.reAnalyzeAll(null);
                }
                mgr.startAnalysis(ghidra.util.task.TaskMonitor.DUMMY);
                mgr.waitForAnalysis(null, ghidra.util.task.TaskMonitor.DUMMY);
                ghidra.program.util.GhidraProgramUtilities.markProgramAnalyzed(program);
                txOk = true;
            } finally {
                program.endTransaction(txId, txOk);
            }
            persistProgram(program, AUTO_ANALYSIS_COMPLETION_MESSAGE);
            return true;
        } catch (Exception e) {
            Msg.warn(this, "Auto-analysis failed: " + e.getMessage());
            try {
                suppressAnalysisPrompt(program);
            } catch (Exception ignored) {
                // Preserve the original analysis failure in the log.
            }
            return false;
        }
    }

    private void suppressAnalysisPrompt(Program program) throws IOException, ghidra.util.exception.CancelledException {
        ghidra.program.util.GhidraProgramUtilities.markProgramNotToAskToAnalyze(program);
        persistProgram(program, "Suppress analysis prompt");
    }

    private void persistProgram(Program program, String reason)
            throws IOException, ghidra.util.exception.CancelledException {
        if (program == null || !program.canSave()) {
            return;
        }
        program.flushEvents();
        program.save(reason, ghidra.util.task.TaskMonitor.DUMMY);
    }


    // ========================================================================
    // Program Management
    // ========================================================================

    /**
     * Save the currently active program to its domain file.
     */
    @McpTool(path = "/save_program", description = "Save current program")
    public Response saveCurrentProgram(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    ghidra.framework.model.DomainFile df = program.getDomainFile();
                    if (df == null) {
                        errorMsg.set("Program has no domain file");
                        return;
                    }
                    df.save(new ConsoleTaskMonitor());
                    resultData.set(JsonHelper.mapOf(
                        "success", true,
                        "program", program.getName(),
                        "message", "Program saved successfully"
                    ));
                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    errorMsg.set(msg);
                    Msg.error(this, "Error saving program", e);
                }
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err(msg);
        }

        return resultData.get() != null ? Response.ok(resultData.get()) : Response.err("Unknown failure");
    }

    /**
     * Save every currently open program. This is intended for automation paths
     * such as deploy shutdown where Ghidra would otherwise prompt for each
     * modified domain object on exit.
     */
    @McpTool(path = "/save_all_programs", description = "Save all open programs")
    public Response saveAllOpenPrograms() {
        Program[] programs = programProvider.getAllOpenPrograms();
        if (programs == null || programs.length == 0) {
            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "saved_count", 0,
                "open_program_count", 0,
                "programs", List.of(),
                "errors", List.of(),
                "message", "No open programs to save"
            ));
        }

        final AtomicReference<List<Map<String, Object>>> saved = new AtomicReference<>(new ArrayList<>());
        final AtomicReference<List<Map<String, Object>>> errors = new AtomicReference<>(new ArrayList<>());

        Runnable saveTask = () -> {
            Set<Program> seen = Collections.newSetFromMap(new IdentityHashMap<>());
            for (Program program : programs) {
                if (program == null || !seen.add(program)) {
                    continue;
                }

                Map<String, Object> info = new LinkedHashMap<>();
                info.put("program", program.getName());
                try {
                    ghidra.framework.model.DomainFile df = program.getDomainFile();
                    if (df == null) {
                        info.put("error", "Program has no domain file");
                        errors.get().add(info);
                        continue;
                    }
                    info.put("path", df.getPathname());
                    // A DomainFile that is not in a writable project is a proxy
                    // (no on-disk location) \u2014 calling save() on it throws the
                    // cryptic "Location does not exist for a save operation!".
                    // Surface a specific message so callers know to re-load
                    // with an active project open.
                    if (!df.isInWritableProject()) {
                        info.put("error",
                            "Program is not attached to a writable project "
                            + "(transient DomainFileProxy); re-load it with a "
                            + "project open before saving.");
                        errors.get().add(info);
                        continue;
                    }
                    df.save(new ConsoleTaskMonitor());
                    saved.get().add(info);
                } catch (Throwable e) {
                    info.put("error", e.getMessage() != null ? e.getMessage() : e.toString());
                    errors.get().add(info);
                    Msg.error(this, "Error saving program " + program.getName(), e);
                }
            }
        };

        try {
            if (SwingUtilities.isEventDispatchThread()) {
                saveTask.run();
            } else {
                SwingUtilities.invokeAndWait(saveTask);
            }
        } catch (Throwable e) {
            return Response.err("Failed to save all programs: " +
                    (e.getMessage() != null ? e.getMessage() : e.toString()));
        }

        return Response.ok(JsonHelper.mapOf(
            "success", errors.get().isEmpty(),
            "saved_count", saved.get().size(),
            "open_program_count", programs.length,
            "programs", saved.get(),
            "errors", errors.get()
        ));
    }

    /**
     * List all currently open programs in Ghidra.
     */
    @McpTool(path = "/list_open_programs", description = "List all open programs. If more than one program is listed, always pass the program name explicitly in subsequent tool calls — omitting it will silently target the active program, which may not be the intended one.")
    public Response listOpenPrograms() {
        Program[] programs = programProvider.getAllOpenPrograms();
        if (programs == null || programs.length == 0) {
            return Response.ok(JsonHelper.mapOf("programs", List.of(), "count", 0, "current_program", ""));
        }

        Program currentProgram = programProvider.resolveProgram(null);

        List<Map<String, Object>> programList = new ArrayList<>();
        for (Program prog : programs) {
            int physicalSpaceCount = ServiceUtils.getPhysicalSpaceCount(prog);
            int overlaySpaceCount  = ServiceUtils.getOverlaySpaceCount(prog);
            programList.add(JsonHelper.mapOf(
                "name", prog.getName(),
                "path", prog.getDomainFile().getPathname(),
                "is_current", prog == currentProgram,
                "executable_path", prog.getExecutablePath() != null ? prog.getExecutablePath() : "",
                "language", prog.getLanguageID().getIdAsString(),
                "compiler", prog.getCompilerSpec().getCompilerSpecID().getIdAsString(),
                "image_base", prog.getImageBase().toString(),
                "memory_size", prog.getMemory().getSize(),
                "function_count", prog.getFunctionManager().getFunctionCount(),
                // Physical-space ambiguity (true on 8051/AVR with separate
                // CODE/RAM spaces). Overlays do NOT make plain hex ambiguous,
                // so this stays false on single-RAM programs with overlays.
                "has_multiple_address_spaces", physicalSpaceCount > 1,
                "has_overlay_spaces",          overlaySpaceCount > 0,
                "overlay_space_count",         overlaySpaceCount
            ));
        }

        return Response.ok(JsonHelper.mapOf(
            "programs", programList,
            "count", programs.length,
            "current_program", currentProgram != null ? currentProgram.getName() : ""
        ));
    }

    @McpTool(path = "/close_program", method = "POST",
             description = "Close an open program by project path or name")
    public Response closeProgram(
            @Param(value = "name", source = ParamSource.BODY,
                    description = "Program name or project path") String name) {
        if (name == null || name.trim().isEmpty()) {
            return Response.err("Program name or path is required");
        }

        String search = name.trim();
        AtomicInteger closedCount = new AtomicInteger(0);
        AtomicReference<String> error = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    for (ProgramManager pm : findAllProgramManagers()) {
                        for (Program program : pm.getAllOpenPrograms()) {
                            if (programMatches(program, search)) {
                                pm.closeProgram(program, false);
                                closedCount.incrementAndGet();
                            }
                        }
                    }
                } catch (Exception e) {
                    error.set(e.getMessage() != null ? e.getMessage() : e.toString());
                }
            });
        } catch (Exception e) {
            return Response.err("Failed to close program: " +
                    (e.getMessage() != null ? e.getMessage() : e.toString()));
        }

        if (closedCount.get() == 0) {
            for (Program program : programProvider.getAllOpenPrograms()) {
                if (programMatches(program, search) && programProvider.closeProgram(program)) {
                    closedCount.incrementAndGet();
                }
            }
        }

        if (error.get() != null) {
            return Response.err("Failed to close program: " + error.get());
        }

        return Response.ok(JsonHelper.mapOf(
            "success", true,
            "closed_count", closedCount.get(),
            "name", search
        ));
    }


    private List<Map<String, Object>> buildAddressSpacesList(Program program) {
        List<Map<String, Object>> spaces = new ArrayList<>();
        AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
        for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
            if (space.isOverlaySpace()) continue;
            int type = space.getType();
            if (type != AddressSpace.TYPE_RAM && type != AddressSpace.TYPE_CODE) continue;
            long maxOff = space.getMaxAddress().getOffset();
            long minOff = space.getMinAddress().getOffset();
            // Safe unsigned size: (maxOff - minOff + 1) overflows for full 64-bit spaces (maxOff == -1L)
            long size = maxOff - minOff + 1;
            if (size == 0 && Long.compareUnsigned(maxOff, minOff) > 0) {
                size = Long.MAX_VALUE; // Full 64-bit space; clamp to avoid emitting 0
            }
            int unitSize = space.getAddressableUnitSize();
            // size_bytes: guard against overflow when size is clamped or unitSize > 1
            long sizeBytes = (size == Long.MAX_VALUE || unitSize <= 0)
                    ? Long.MAX_VALUE
                    : size * unitSize;
            spaces.add(JsonHelper.mapOf(
                "name",                  space.getName(),
                "start",                 space.getMinAddress().toString(false),
                "end",                   space.getMaxAddress().toString(false),
                "size",                  size,
                "addressable_unit_size", unitSize,
                "size_bytes",            sizeBytes,
                "address_size_bits",     space.getSize(),
                "is_default",            space == defaultSpace,
                "is_overlay",            Boolean.FALSE
            ));
        }
        return spaces;
    }

    /**
     * Build JSON entries for the program's overlay address spaces, each marked
     * is_overlay=true with the name of the physical space it overlays. Kept
     * SEPARATE from buildAddressSpacesList so get_current_program_info's
     * has_multiple_address_spaces flag continues to reflect PHYSICAL ambiguity only.
     */
    private List<Map<String, Object>> buildOverlaySpacesList(Program program) {
        List<Map<String, Object>> spaces = new ArrayList<>();
        for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
            if (!space.isOverlaySpace()) continue;
            String base = "";
            if (space instanceof OverlayAddressSpace) {
                AddressSpace overlayed = ((OverlayAddressSpace) space).getOverlayedSpace();
                if (overlayed != null) base = overlayed.getName();
            }
            int unitSize = space.getAddressableUnitSize();
            spaces.add(JsonHelper.mapOf(
                "name",                  space.getName(),
                "start",                 space.getMinAddress().toString(false),
                "end",                   space.getMaxAddress().toString(false),
                "addressable_unit_size", unitSize,
                "address_size_bits",     space.getSize(),
                "is_overlay",            Boolean.TRUE,
                "overlayed_space",       base
            ));
        }
        return spaces;
    }

    /**
     * Get detailed information about the currently active program.
     */
    @McpTool(path = "/get_current_program_info", description = "Get detailed info about the active program. When multiple programs are open, call this first to confirm which program will receive tool calls that omit the program argument.")
    public Response getCurrentProgramInfo(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<Map<String, Object>> addressSpaces = buildAddressSpacesList(program);
        boolean multiSpace = addressSpaces.size() > 1;
        List<Map<String, Object>> overlaySpaces = buildOverlaySpacesList(program);
        // Combine for the address_spaces array so overlays are visible here too
        // included here. multiSpace is computed BEFORE the
        // append so it continues to reflect physical ambiguity only.
        addressSpaces.addAll(overlaySpaces);

        Map<String, Object> info = new java.util.LinkedHashMap<>();
        info.put("name", program.getName());
        info.put("path", program.getDomainFile().getPathname());
        info.put("executable_path", program.getExecutablePath() != null ? program.getExecutablePath() : "");
        info.put("executable_format", program.getExecutableFormat());
        info.put("language", program.getLanguageID().getIdAsString());
        info.put("compiler", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        info.put("address_size", program.getAddressFactory().getDefaultAddressSpace().getSize());
        info.put("image_base", program.getImageBase().toString());
        info.put("min_address", program.getMinAddress() != null ? program.getMinAddress().toString() : "null");
        info.put("max_address", program.getMaxAddress() != null ? program.getMaxAddress().toString() : "null");
        info.put("memory_size", program.getMemory().getSize());
        info.put("function_count", program.getFunctionManager().getFunctionCount());
        info.put("symbol_count", program.getSymbolTable().getNumSymbols());
        info.put("data_type_count", program.getDataTypeManager().getDataTypeCount(true));
        info.put("creation_date", program.getCreationDate() != null ? program.getCreationDate().toString() : "unknown");
        info.put("memory_block_count", program.getMemory().getBlocks().length);
        info.put("address_spaces", addressSpaces);
        info.put("has_multiple_address_spaces", multiSpace);
        info.put("has_overlay_spaces", !overlaySpaces.isEmpty());
        info.put("overlay_space_count", overlaySpaces.size());
        if (multiSpace) {
            info.put("address_space_warning",
                "This program has multiple physical address spaces. Plain hex addresses will resolve "
                + "to the default space and may be incorrect. Use <space>:<hex> format (e.g., mem:1000) "
                + "and qualify ambiguous addresses explicitly.");
        } else if (!overlaySpaces.isEmpty()) {
            info.put("address_space_warning",
                "This program has overlay address spaces. Overlay addresses must be qualified as "
                + "<overlay>::<hex> (e.g., " + overlaySpaces.get(0).get("name") + "::<hex>) — overlay "
                + "names are case-sensitive. Plain hex resolves to the default physical space.");
        }
        return Response.ok(info);
    }


    /**
     * List all files in the current Ghidra project.
     */
    @McpTool(path = "/list_project_files", description = "List files in the current project")
    public Response listProjectFiles(
            @Param(value = "folder", description = "Project folder path") String folderPath) {
        PluginTool tool = getToolFromProvider();
        if (tool == null) {
            return Response.err("Project listing requires GUI mode (PluginTool not available)");
        }

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }

        ghidra.framework.model.ProjectData projectData = project.getProjectData();
        ghidra.framework.model.DomainFolder rootFolder = projectData.getRootFolder();

        // If folder path specified, navigate to it
        ghidra.framework.model.DomainFolder targetFolder = rootFolder;
        if (folderPath != null && !folderPath.trim().isEmpty() && !folderPath.equals("/")) {
            // Navigate through path segments (handles nested folders like "LoD/1.07")
            String cleanPath = folderPath.startsWith("/") ? folderPath.substring(1) : folderPath;
            String[] pathParts = cleanPath.split("/");
            for (String part : pathParts) {
                if (part.isEmpty()) continue;
                ghidra.framework.model.DomainFolder nextFolder = targetFolder.getFolder(part);
                if (nextFolder == null) {
                    return Response.err("Folder not found: " + folderPath);
                }
                targetFolder = nextFolder;
            }
        }

        // List subfolders
        ghidra.framework.model.DomainFolder[] subfolders = targetFolder.getFolders();
        List<String> folderNames = new ArrayList<>();
        for (ghidra.framework.model.DomainFolder subfolder : subfolders) {
            folderNames.add(subfolder.getName());
        }

        // List files in folder
        ghidra.framework.model.DomainFile[] files = targetFolder.getFiles();
        List<Map<String, Object>> fileList = new ArrayList<>();
        for (ghidra.framework.model.DomainFile file : files) {
            fileList.add(JsonHelper.mapOf(
                "name", file.getName(),
                "path", file.getPathname(),
                "content_type", file.getContentType(),
                "version", file.getVersion(),
                "is_read_only", file.isReadOnly(),
                "is_versioned", file.isVersioned()
            ));
        }

        return Response.ok(JsonHelper.mapOf(
            "project_name", project.getName(),
            "current_folder", targetFolder.getPathname(),
            "folders", folderNames,
            "files", fileList
        ));
    }

    @McpTool(path = "/create_folder", method = "POST", description = "Create a folder in the project")
    public Response createFolder(
            @Param(value = "path", source = ParamSource.BODY, description = "Project folder path to create") String folderPath,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        PluginTool tool = getToolFromProvider();
        if (tool == null) {
            return Response.err("Folder creation requires GUI mode (PluginTool not available)");
        }
        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }
        if (folderPath == null || folderPath.trim().isEmpty() || folderPath.equals("/")) {
            return Response.err("path parameter is required");
        }

        try {
            ghidra.framework.model.DomainFolder current = project.getProjectData().getRootFolder();
            String cleanPath = folderPath.startsWith("/") ? folderPath.substring(1) : folderPath;
            for (String part : cleanPath.split("/")) {
                if (part.isEmpty()) continue;
                ghidra.framework.model.DomainFolder next = current.getFolder(part);
                if (next == null) {
                    next = current.createFolder(part);
                }
                current = next;
            }
            return Response.ok(JsonHelper.mapOf("success", true, "folder", current.getPathname()));
        } catch (Exception e) {
            return Response.err("Failed to create folder: " + e.getMessage());
        }
    }


    /**
     * Open a program from the current project by path.
     */
    @McpTool(path = "/open_program", description = "Open a program from the current project")
    public Response openProgramFromProject(
            @Param(value = "path", description = "Program path in project") String path,
            @Param(value = "auto_analyze", defaultValue = "false", description = "Run auto-analysis") boolean autoAnalyze) {
        if (path == null || path.trim().isEmpty()) {
            return Response.err("Program path is required");
        }

        PluginTool tool = getToolFromProvider();
        if (tool == null) {
            return Response.err("Opening programs requires GUI mode (PluginTool not available)");
        }

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }

        ghidra.framework.model.ProjectData projectData = project.getProjectData();
        ghidra.framework.model.DomainFile domainFile = projectData.getFile(path);

        if (domainFile == null) {
            return Response.err("File not found in project: " + path);
        }

        // Check if already open
        Program[] openPrograms = programProvider.getAllOpenPrograms();
        for (Program prog : openPrograms) {
            if (prog.getDomainFile().getPathname().equals(path)) {
                // Already open, just switch to it
                try {
                    suppressAnalysisPrompt(prog);
                } catch (Exception e) {
                    Msg.warn(this, "Failed to save analysis prompt flags: " + e.getMessage());
                }
                programProvider.setCurrentProgram(prog);
                return Response.ok(JsonHelper.mapOf(
                    "success", true,
                    "message", "Program already open, switched to it",
                    "name", prog.getName(),
                    "path", path
                ));
            }
        }

        // Open the program
        try {
            // Find a ProgramManager from an existing CodeBrowser, or launch one
            ProgramManager pm = findOrCreateProgramManager(tool);
            if (pm == null) {
                return Response.err("Could not find or create a CodeBrowser tool");
            }

            Program program = (Program) domainFile.getDomainObject(
                tool, false, false, ghidra.util.task.TaskMonitor.DUMMY);
            if (program == null) {
                return Response.err("Failed to open program: " + path);
            }

            ghidra.program.util.GhidraProgramUtilities.markProgramNotToAskToAnalyze(program);

            boolean analyzed = false;
            if (autoAnalyze) {
                analyzed = runAutoAnalysisAndPersistFlags(program, true);
            } else {
                try {
                    suppressAnalysisPrompt(program);
                } catch (Exception e) {
                    Msg.warn(this, "Failed to save analysis prompt flags: " + e.getMessage());
                }
            }

            // Open after the analysis flags are persisted so CodeBrowser does not prompt.
            Program finalProgram = program;
            SwingUtilities.invokeAndWait(() -> {
                pm.openProgram(finalProgram);
                pm.setCurrentProgram(finalProgram);
            });

            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "message", "Program opened successfully",
                "name", program.getName(),
                "path", path,
                "auto_analyzed", analyzed,
                "function_count", program.getFunctionManager().getFunctionCount()
            ));
        } catch (Exception e) {
            return Response.err("Failed to open program: " + e.getMessage());
        }
    }

    // ========================================================================
    // Import & Analysis

    /**
     * Load and save an imported program, retaining one temporary consumer reference for this
     * service after the loader results are closed.
     */
    private Program loadImportedProgram(File file, ghidra.framework.model.Project project,
                                        String projectFolder,
                                        ghidra.program.model.lang.Language language,
                                        ghidra.program.model.lang.CompilerSpec compilerSpec,
                                        MessageLog log) throws Exception {
        ProgramLoader.Builder loader = ProgramLoader.builder()
            .source(file)
            .project(project)
            .projectFolderPath(projectFolder)
            .log(log)
            .monitor(ghidra.util.task.TaskMonitor.DUMMY);
        if (language != null) {
            loader.loaders(BinaryLoader.class)
                .language(language)
                .compiler(compilerSpec);
        }

        try (LoadResults<Program> results = loader.load()) {
            results.save(ghidra.util.task.TaskMonitor.DUMMY);
            return results.getPrimaryDomainObject(this);
        }
    }

    @McpTool(path = "/import_file", method = "POST",
            description = "Import a binary file from disk into the current Ghidra project and open it. "
                + "For raw firmware binaries, specify language (e.g. 'ARM:LE:32:Cortex') and optionally compiler_spec (e.g. 'default').")
    public Response importFile(
            @Param(value = "file_path", source = ParamSource.BODY, description = "Absolute path to the binary file on disk") String filePath,
            @Param(value = "project_folder", source = ParamSource.BODY, defaultValue = "/", description = "Destination folder in the Ghidra project") String projectFolder,
            @Param(value = "language", source = ParamSource.BODY, defaultValue = "", description = "Language ID for raw binaries (e.g. 'ARM:LE:32:Cortex', 'x86:LE:64:default'). If omitted, auto-detect.") String languageId,
            @Param(value = "compiler_spec", source = ParamSource.BODY, defaultValue = "", description = "Compiler spec ID (e.g. 'default', 'gcc', 'windows'). If omitted, uses language default.") String compilerSpecId,
            @Param(value = "auto_analyze", source = ParamSource.BODY, defaultValue = "true", description = "Start auto-analysis after import") boolean autoAnalyze) {

        if (filePath == null || filePath.trim().isEmpty()) {
            return Response.err("file_path is required");
        }

        // Enforce GHIDRA_MCP_FILE_ROOT (when configured) for this filesystem-path endpoint,
        // matching other filesystem endpoints. No-op when the root is unset (paths accepted
        // as-is), so default localhost behavior is unchanged.
        SecurityConfig security = SecurityConfig.getInstance();
        java.nio.file.Path resolved = security.resolveWithinFileRoot(filePath);
        if (resolved == null) {
            return Response.err("Path is outside the allowed file root ("
                    + security.getFileRoot() + "): " + filePath);
        }

        File file = resolved.toFile();
        if (!file.exists()) {
            return Response.err("File not found: " + filePath);
        }

        PluginTool tool = getToolFromProvider();
        if (tool == null) {
            return Response.err("Import requires GUI mode (PluginTool not available)");
        }

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }

        boolean hasLanguage = languageId != null && !languageId.isEmpty();
        Program program = null;

        try {
            MessageLog log = new MessageLog();
            ghidra.program.model.lang.Language language = null;
            ghidra.program.model.lang.CompilerSpec compilerSpec = null;

            if (hasLanguage) {
                // Resolve language and compiler spec
                ghidra.program.model.lang.LanguageService langService =
                    ghidra.program.util.DefaultLanguageService.getLanguageService();
                language = langService.getLanguage(
                    new ghidra.program.model.lang.LanguageID(languageId));

                if (compilerSpecId != null && !compilerSpecId.isEmpty()) {
                    compilerSpec = language.getCompilerSpecByID(
                        new ghidra.program.model.lang.CompilerSpecID(compilerSpecId));
                } else {
                    compilerSpec = language.getDefaultCompilerSpec();
                }
            }

            program = loadImportedProgram(
                file, project, projectFolder, language, compilerSpec, log);

            // Suppress the "Analysis Options" dialog — we handle analysis programmatically
            ghidra.program.util.GhidraProgramUtilities.markProgramNotToAskToAnalyze(program);

            boolean autoAnalyzed = false;
            if (autoAnalyze) {
                autoAnalyzed = runAutoAnalysisAndPersistFlags(program, false);
            } else {
                try {
                    suppressAnalysisPrompt(program);
                } catch (Exception e) {
                    Msg.warn(this, "Failed to save analysis prompt flags: " + e.getMessage());
                }
            }

            // Open after the analysis flags are persisted so CodeBrowser does not prompt.
            ProgramManager pm = findOrCreateProgramManager(tool);
            if (pm == null) {
                return Response.err("Could not find or create a CodeBrowser tool");
            }

            Program finalProgram = program;
            SwingUtilities.invokeAndWait(() -> {
                pm.openProgram(finalProgram);
                pm.setCurrentProgram(finalProgram);
            });

            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "name", program.getName(),
                "path", program.getDomainFile().getPathname(),
                "language", program.getLanguageID().getIdAsString(),
                "analyzing", false,
                "auto_analyzed", autoAnalyzed
            ));
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg == null || msg.isEmpty()) {
                msg = e.getClass().getName();
                // Include cause if available
                if (e.getCause() != null) {
                    msg += ": " + (e.getCause().getMessage() != null
                        ? e.getCause().getMessage() : e.getCause().getClass().getName());
                }
            }
            Msg.error(this, "Import failed", e);
            return Response.err("Import failed: " + msg);
        } finally {
            if (program != null) {
                try {
                    program.release(this);
                } catch (Exception e) {
                    Msg.warn(this, "Failed to release temporary import consumer: " + e.getMessage());
                }
            }
        }
    }

    @McpTool(path = "/reanalyze", method = "POST", description = "Trigger full auto-analysis on a program")
    public Response reanalyze(
            @Param(value = "program", defaultValue = "", description = "Program name (default: current program)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            boolean analyzed = runAutoAnalysisAndPersistFlags(program, true);
            return Response.ok(JsonHelper.mapOf(
                "success", analyzed,
                "name", program.getName(),
                "analyzing", false,
                "message", analyzed ? AUTO_ANALYSIS_COMPLETION_MESSAGE + " for " + program.getName()
                    : "Auto-analysis failed for " + program.getName()
            ));
        } catch (Exception e) {
            return Response.err("Failed to start analysis: " + e.getMessage());
        }
    }


    private boolean programMatches(Program prog, String programName) {
        if (prog == null || programName == null || programName.isEmpty()) {
            return true;
        }
        String searchName = programName.trim();
        if (prog.getName().equalsIgnoreCase(searchName)) {
            return true;
        }
        if (prog.getDomainFile() != null) {
            String path = prog.getDomainFile().getPathname();
            return path.equalsIgnoreCase(searchName) || path.toLowerCase().contains(searchName.toLowerCase());
        }
        return false;
    }

    // ========================================================================
    // Script Execution
    private List<ProgramManager> findAllProgramManagers() {
        List<ProgramManager> managers = new ArrayList<>();
        Set<PluginTool> seen = Collections.newSetFromMap(new IdentityHashMap<>());

        PluginTool activeTool = getToolFromProvider();
        if (activeTool != null) {
            seen.add(activeTool);
            ProgramManager pm = activeTool.getService(ProgramManager.class);
            if (pm != null) {
                managers.add(pm);
            }

            try {
                ghidra.framework.model.Project project = activeTool.getProject();
                if (project != null) {
                    ghidra.framework.model.ToolManager tm = project.getToolManager();
                    if (tm != null) {
                        for (PluginTool runningTool : tm.getRunningTools()) {
                            if (!seen.add(runningTool)) {
                                continue;
                            }
                            ProgramManager runningPm = runningTool.getService(ProgramManager.class);
                            if (runningPm != null) {
                                managers.add(runningPm);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                Msg.warn(this, "Error scanning for ProgramManager services: " + e.getMessage());
            }
        }

        if (programProvider instanceof MultiToolProgramProvider mtp) {
            ProgramManager pm = mtp.findProgramManager();
            if (pm != null && !managers.contains(pm)) {
                managers.add(pm);
            }
        }
        return managers;
    }

    /**
     * Find an existing ProgramManager without spawning a new CodeBrowser.
     * Returns null when no CodeBrowser is currently running and exposing
     * ProgramManager. Use this from close paths and other operations that
     * have nothing useful to do in a freshly-spawned empty tool.
     */
    private ProgramManager findExistingProgramManager(PluginTool tool) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null) return pm;

        if (programProvider instanceof MultiToolProgramProvider mtp) {
            pm = mtp.findProgramManager();
            if (pm != null) return pm;
        }

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) return null;
        ghidra.framework.model.ToolManager tm = project.getToolManager();
        if (tm == null) return null;
        try {
            for (PluginTool running : tm.getRunningTools()) {
                if (running == tool) continue;
                ProgramManager rpm = running.getService(ProgramManager.class);
                if (rpm != null) return rpm;
            }
        } catch (Exception e) {
            Msg.warn(this, "Error scanning running tools for ProgramManager: " + e.getMessage());
        }
        return null;
    }

    /**
     * Find an existing ProgramManager or launch a new CodeBrowser to get one.
     *
     * <p>Resolution order matters for window hygiene: when GhidraMCPPlugin lives
     * in the FrontEnd tool, the FrontEnd has no ProgramManager and the
     * MultiToolProgramProvider check is only relevant to that provider — never
     * the case under FrontEndProgramProvider. Without scanning running tools
     * first, every /open_program and /import_file call would fall through to
     * ws.runTool and accumulate a fresh CodeBrowser per call. The scan reuses
     * any existing CodeBrowser so additional programs open as tabs in it.
     */
    private ProgramManager findOrCreateProgramManager(PluginTool tool) {
        ProgramManager pm = findExistingProgramManager(tool);
        if (pm != null) return pm;

        // No CodeBrowser is up — spawn one. This should be rare in practice;
        // it covers sessions where no CodeBrowser is open.
        ghidra.framework.model.Project project = tool.getProject();
        try {
            if (project != null) {
                ghidra.framework.model.ToolManager tm = project.getToolManager();
                if (tm != null) {
                    ghidra.framework.model.ToolTemplate template =
                        project.getLocalToolChest().getToolTemplate("CodeBrowser");
                    if (template != null) {
                        ghidra.framework.model.Workspace ws = tm.getActiveWorkspace();
                        PluginTool newTool = ws.runTool(template);
                        if (newTool != null) {
                            pm = newTool.getService(ProgramManager.class);
                            if (pm != null) return pm;
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to launch CodeBrowser: " + e.getMessage());
        }

        return null;
    }

    // ========================================================================


    // ========================================================================
    // Memory Operations
    // ========================================================================

    /** Same ceiling as read_memory: two ranges of this size are compared, not one. */
    static final int MAX_DIFF_BYTES = 16 * 1024 * 1024;
    static final int MIN_DIFF_RUNS = 1;
    static final int MAX_DIFF_RUNS = 4096;

    /** One maximal run of differing bytes, as an offset from the start of the comparison. */
    record DiffRun(int offset, int length) {}

    /**
     * Whole-comparison totals plus at most {@code maxRuns} retained runs.
     *
     * <p>The totals are accumulated as the scan proceeds, so they describe the entire comparison
     * even when the retained list is clipped. Retaining every run instead would allocate one
     * object per run regardless of {@code maxRuns}: a 16MB input alternating equal and differing
     * bytes yields ~8.4M runs, enough to exhaust the Ghidra heap for a response that returns one.
     */
    record DiffSummary(List<DiffRun> runs, int runCount, int differingBytes,
                       int firstOffset, int lastOffset) {}

    /**
     * Coalesce differing byte positions into maximal runs.
     *
     * <p>Only differences are returned: the gaps between them are equal by construction, so
     * emitting "same" runs too would double the payload and let the two disagree.
     */
    static DiffSummary coalesceDifferences(byte[] a, byte[] b, int maxRuns) {
        List<DiffRun> retained = new ArrayList<>();
        int runCount = 0;
        int differingBytes = 0;
        int firstOffset = -1;
        int lastOffset = -1;
        int start = -1;
        for (int i = 0; i <= a.length; i++) {
            boolean differs = i < a.length && a[i] != b[i];
            if (differs && start < 0) {
                start = i;
            }
            else if (!differs && start >= 0) {
                int length = i - start;
                runCount++;
                differingBytes += length;
                if (firstOffset < 0) {
                    firstOffset = start;
                }
                lastOffset = i - 1;
                if (retained.size() < maxRuns) {
                    retained.add(new DiffRun(start, length));
                }
                start = -1;
            }
        }
        return new DiffSummary(retained, runCount, differingBytes, firstOffset, lastOffset);
    }

    @McpTool(path = "/diff_memory", method = "POST",
             description = "Compare two equal-length memory ranges, which may be in different address spaces (e.g. an overlay against the block it shadows), and return the differing byte runs. Answers 'where exactly do these two occupants diverge' without transferring either range.")
    public Response diffMemory(
            @Param(value = "a", source = ParamSource.BODY,
                   description = "First range start. Accepts 0x<hex> or <space>:<hex>, including overlay spaces (SND_PLAYER::9680).") String aText,
            @Param(value = "b", source = ParamSource.BODY,
                   description = "Second range start, in the same or a different address space.") String bText,
            @Param(value = "length", source = ParamSource.BODY,
                   description = "Number of bytes to compare from each start") int length,
            @Param(value = "max_runs", source = ParamSource.BODY, defaultValue = "256",
                   description = "Cap on returned difference runs (1..4096). differing_bytes and difference_run_count always describe the whole comparison, even when the list is clipped.") int maxRuns,
            @Param(value = "program", description = "Target program name (omit to use the active program)",
                   defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (length <= 0 || length > MAX_DIFF_BYTES) {
            return Response.err("length must be between 1 and " + MAX_DIFF_BYTES + " bytes");
        }
        if (maxRuns < MIN_DIFF_RUNS || maxRuns > MAX_DIFF_RUNS) {
            return Response.err("max_runs must be between " + MIN_DIFF_RUNS
                + " and " + MAX_DIFF_RUNS);
        }

        Address aStart = ServiceUtils.parseAddress(program, aText);
        if (aStart == null) return Response.err("a: " + ServiceUtils.getLastParseError());
        Address bStart = ServiceUtils.parseAddress(program, bText);
        if (bStart == null) return Response.err("b: " + ServiceUtils.getLastParseError());

        Memory memory = program.getMemory();
        byte[] aBytes = new byte[length];
        byte[] bBytes = new byte[length];
        // Read both ranges up front so a partially readable range fails naming the exact
        // address, rather than silently comparing against zero-filled tail bytes.
        Response unreadable = readFully(memory, aStart, aBytes, "a");
        if (unreadable != null) return unreadable;
        unreadable = readFully(memory, bStart, bBytes, "b");
        if (unreadable != null) return unreadable;

        DiffSummary summary = coalesceDifferences(aBytes, bBytes, maxRuns);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("a", aStart.toString(true));
        result.put("b", bStart.toString(true));
        result.put("length", length);
        result.put("differing_bytes", summary.differingBytes());
        result.put("identical", summary.runCount() == 0);
        result.put("difference_run_count", summary.runCount());
        if (summary.runCount() > 0) {
            result.put("first_difference_offset", summary.firstOffset());
            result.put("last_difference_offset", summary.lastOffset());
        }
        List<Map<String, Object>> emitted = new ArrayList<>();
        for (DiffRun run : summary.runs()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("offset", run.offset());
            entry.put("length", run.length());
            entry.put("a", aStart.add(run.offset()).toString(true));
            entry.put("b", bStart.add(run.offset()).toString(true));
            emitted.add(entry);
        }
        result.put("difference_runs", emitted);
        result.put("runs_truncated", summary.runCount() > emitted.size());
        return Response.ok(result);
    }

    /** @return an error Response naming the first unreadable address, or null on success. */
    private static Response readFully(Memory memory, Address start, byte[] into, String label) {
        try {
            // addNoWrap, not add: a range ending at the address-space maximum would otherwise
            // wrap while building the diagnostic and report a generic overflow instead of the
            // address the caller needs.
            try {
                start.addNoWrap(into.length - 1L);
            }
            catch (ghidra.program.model.address.AddressOverflowException overflow) {
                return Response.err(label + ": " + into.length + " bytes from "
                    + start.toString(true) + " runs past the end of address space "
                    + start.getAddressSpace().getName());
            }
            int read = memory.getBytes(start, into);
            if (read != into.length) {
                return Response.err(label + ": only " + read + " of " + into.length
                    + " bytes are readable from " + start.toString(true)
                    + "; first unreadable address is "
                    + start.addNoWrap((long) read).toString(true));
            }
        }
        catch (Exception e) {
            return Response.err(label + ": cannot read " + into.length + " bytes from "
                + start.toString(true) + ": " + e.getMessage());
        }
        return null;
    }

    @McpTool(path = "/read_memory", description = "Read raw memory bytes. Always pass the 'program' argument to target the correct binary — especially when multiple programs are open. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.")
    public Response readMemory(
            @Param(value = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "qualify the address as <space>:<hex> when multiple spaces map the same offset.") String addressStr,
            @Param(value = "length", defaultValue = "16", description = "Number of bytes") int length,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        try {
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
            if (pe.hasError()) return pe.error();
            Program program = pe.program();

            Address address = ServiceUtils.parseAddress(program, addressStr);
            if (address == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            Memory memory = program.getMemory();
            int MAX_READ_BYTES = 16 * 1024 * 1024; // 16 MB safety limit
            if (length <= 0 || length > MAX_READ_BYTES) {
                return Response.err("length must be between 1 and " + MAX_READ_BYTES + " bytes");
            }
            byte[] bytes = new byte[length];

            int bytesRead = memory.getBytes(address, bytes);

            List<Integer> dataList = new ArrayList<>();
            StringBuilder hexStr = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                dataList.add(bytes[i] & 0xFF);
                hexStr.append(String.format("%02x", bytes[i] & 0xFF));
            }

            Map<String, Object> memResult = new LinkedHashMap<>();
            memResult.putAll(ServiceUtils.addressToJson(address, program));
            memResult.put("length", bytesRead);
            memResult.put("data", dataList);
            memResult.put("hex", hexStr.toString());
            return Response.ok(memResult);

        } catch (Exception e) {
            return Response.err("Failed to read memory: " + e.getMessage());
        }
    }


    // ========================================================================
    // Image Base Operations
    // ========================================================================

    @McpTool(path = "/set_image_base", method = "POST", description = "Set the base address of the program (rebases all addresses)")
    public Response setImageBase(
            @Param(value = "address", source = ParamSource.BODY, description = "New base address (e.g. 0x08000000)") String addressStr,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter required");
        }

        Address newBase =
            ServiceUtils.parseMutationAddress(program, addressStr);
        if (newBase == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        try {
            return threadingStrategy.executeWrite(
                program, "Set image base", () -> {
                    Address oldBase = program.getImageBase();
                    program.setImageBase(newBase, true);
                    return Response.ok(JsonHelper.mapOf(
                        "old_base", oldBase.toString(),
                        "new_base", newBase.toString()));
            });
        } catch (Exception error) {
            return Response.err("Failed to set image base: "
                + error.getMessage());
        }
    }
}
