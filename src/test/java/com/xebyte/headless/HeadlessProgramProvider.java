package com.xebyte.headless;

import com.xebyte.core.ProgramProvider;

import ghidra.program.model.listing.Program;

import java.util.LinkedHashMap;
import java.util.Map;

/** Minimal in-memory provider for service tests. */
public final class HeadlessProgramProvider implements ProgramProvider {

    private final Map<String, Program> programs = new LinkedHashMap<>();
    private Program current;

    @Override
    public Program getCurrentProgram() {
        return current;
    }

    @Override
    public Program getProgram(String name) {
        if (name == null || name.isBlank()) {
            return current;
        }
        Program exact = programs.get(name);
        if (exact != null) {
            return exact;
        }
        return programs.entrySet().stream()
            .filter(entry -> entry.getKey().equalsIgnoreCase(name))
            .map(Map.Entry::getValue)
            .findFirst()
            .orElse(null);
    }

    @Override
    public Program[] getAllOpenPrograms() {
        return programs.values().toArray(Program[]::new);
    }

    @Override
    public void setCurrentProgram(Program program) {
        current = program;
        if (program != null) {
            programs.put(program.getName(), program);
        }
    }
}
