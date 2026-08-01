package com.xebyte.core;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * ProgramProvider that searches across all registered PluginTools AND
 * running CodeBrowser tools discovered via ToolManager.
 *
 * Used by ServerManager to aggregate programs from multiple CodeBrowser
 * windows within the same Ghidra JVM. Thread-safe.
 */
public class MultiToolProgramProvider implements ProgramProvider {

    private final Map<String, PluginTool> tools;
    private final AtomicReference<String> activeToolId;
    private final Object ownedLock = new Object();
    private final Set<Program> ownedPrograms =
        Collections.newSetFromMap(new IdentityHashMap<>());
    private Program ownedCurrent;

    public MultiToolProgramProvider(Map<String, PluginTool> tools,
                                    AtomicReference<String> activeToolId) {
        this.tools = tools;
        this.activeToolId = activeToolId;
    }

    /**
     * Get all ProgramManagers from registered tools AND running CodeBrowser tools.
     */
    private List<ProgramManager> findAllProgramManagers() {
        List<ProgramManager> managers = new ArrayList<>();
        Set<PluginTool> seen = Collections.newSetFromMap(new IdentityHashMap<>());

        // Check registered tools first
        for (PluginTool tool : tools.values()) {
            seen.add(tool);
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm != null) managers.add(pm);
        }

        // Also check running tools via ToolManager (discovers CodeBrowser instances)
        PluginTool anyTool = getActiveTool();
        if (anyTool != null) {
            try {
                ghidra.framework.model.Project proj = anyTool.getProject();
                if (proj != null) {
                    ghidra.framework.model.ToolManager tm = proj.getToolManager();
                    if (tm != null) {
                        for (PluginTool runningTool : tm.getRunningTools()) {
                            if (seen.add(runningTool)) {
                                ProgramManager pm = runningTool.getService(ProgramManager.class);
                                if (pm != null) managers.add(pm);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // ToolManager may not be available
            }
        }

        return managers;
    }

    @Override
    public Program getCurrentProgram() {
        for (ProgramManager pm : findAllProgramManagers()) {
            Program p = pm.getCurrentProgram();
            if (p != null) return p;
        }
        synchronized (ownedLock) {
            pruneClosedOwnedPrograms();
            return ownedCurrent;
        }
    }

    @Override
    public Program getProgram(String name) {
        if (name == null || name.trim().isEmpty()) {
            return getCurrentProgram();
        }
        String searchName = name.trim();

        Program[] programs = getAllOpenPrograms();

        // Exact project-path match (case-insensitive)
        for (Program prog : programs) {
            if (prog.getDomainFile() != null
                    && prog.getDomainFile().getPathname().equalsIgnoreCase(searchName)) {
                return prog;
            }
        }

        // Exact name match (case-insensitive)
        for (Program prog : programs) {
            if (prog.getName().equalsIgnoreCase(searchName)) {
                return prog;
            }
        }

        // Partial match on path
        for (Program prog : programs) {
            if (prog.getDomainFile() != null
                    && prog.getDomainFile().getPathname().toLowerCase().contains(searchName.toLowerCase())) {
                return prog;
            }
        }

        // Match without extension
        for (Program prog : programs) {
            String pname = prog.getName();
            String nameNoExt = pname.contains(".") ?
                pname.substring(0, pname.lastIndexOf('.')) : pname;
            if (nameNoExt.equalsIgnoreCase(searchName)) {
                return prog;
            }
        }

        return null;
    }

    @Override
    public Program[] getAllOpenPrograms() {
        Set<Program> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (ProgramManager pm : findAllProgramManagers()) {
            Collections.addAll(seen, pm.getAllOpenPrograms());
        }
        Collections.addAll(seen, ownedSnapshot());
        return seen.toArray(new Program[0]);
    }

    @Override
    public void setCurrentProgram(Program program) {
        for (ProgramManager pm : findAllProgramManagers()) {
            for (Program prog : pm.getAllOpenPrograms()) {
                if (prog == program) {
                    pm.setCurrentProgram(program);
                    return;
                }
            }
        }
        synchronized (ownedLock) {
            pruneClosedOwnedPrograms();
            if (ownedPrograms.contains(program)) {
                ownedCurrent = program;
            }
        }
    }

    @Override
    public boolean retainProgram(Program program) {
        if (program == null || program.isClosed()) {
            return false;
        }
        synchronized (ownedLock) {
            pruneClosedOwnedPrograms();
            if (ownedPrograms.contains(program)) {
                ownedCurrent = program;
                return true;
            }
            if (!program.addConsumer(this)) {
                return false;
            }
            ownedPrograms.add(program);
            ownedCurrent = program;
            return true;
        }
    }

    @Override
    public boolean ownsProgram(Program program) {
        synchronized (ownedLock) {
            pruneClosedOwnedPrograms();
            return ownedPrograms.contains(program);
        }
    }

    @Override
    public boolean closeProgram(Program program) {
        boolean release;
        synchronized (ownedLock) {
            pruneClosedOwnedPrograms();
            release = ownedPrograms.remove(program);
            if (ownedCurrent == program) {
                ownedCurrent = null;
            }
        }
        if (release && !program.isClosed() && program.isUsedBy(this)) {
            program.release(this);
        }
        return release;
    }

    /** Release every program retained without a GUI ProgramManager. */
    public void releaseOwnedPrograms() {
        Program[] programs;
        synchronized (ownedLock) {
            programs = ownedPrograms.toArray(new Program[0]);
            ownedPrograms.clear();
            ownedCurrent = null;
        }
        for (Program program : programs) {
            if (!program.isClosed() && program.isUsedBy(this)) {
                program.release(this);
            }
        }
    }

    private Program[] ownedSnapshot() {
        synchronized (ownedLock) {
            pruneClosedOwnedPrograms();
            return ownedPrograms.toArray(new Program[0]);
        }
    }

    /** Closed domain objects have already released every consumer. */
    private void pruneClosedOwnedPrograms() {
        ownedPrograms.removeIf(Program::isClosed);
        if (ownedCurrent != null && ownedCurrent.isClosed()) {
            ownedCurrent = null;
        }
    }

    /**
     * Find a ProgramManager from any registered or running tool.
     */
    public ProgramManager findProgramManager() {
        List<ProgramManager> managers = findAllProgramManagers();
        return managers.isEmpty() ? null : managers.get(0);
    }

    /**
     * Get the currently active PluginTool.
     */
    public PluginTool getActiveTool() {
        String id = activeToolId.get();
        if (id != null) {
            PluginTool t = tools.get(id);
            if (t != null) return t;
        }
        var iter = tools.values().iterator();
        return iter.hasNext() ? iter.next() : null;
    }
}
