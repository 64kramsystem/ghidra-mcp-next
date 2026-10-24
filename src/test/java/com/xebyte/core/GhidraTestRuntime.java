package com.xebyte.core;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

public final class GhidraTestRuntime {
    private GhidraTestRuntime() {}

    public static synchronized void initialize() throws Exception {
        String install = System.getProperty("ghidra.test.install.dir");
        if (install == null || install.isBlank()) {
            throw new IllegalStateException("Pass -Dghidra.test.install.dir=/path/to/ghidra_12.2_PUBLIC");
        }
        Properties properties = new Properties();
        try (var in = Files.newInputStream(Path.of(install, "Ghidra/application.properties"))) {
            properties.load(in);
        }
        if (!"12.2".equals(properties.getProperty("application.version"))) {
            throw new IllegalStateException("Tests require Ghidra 12.2");
        }
        if (!Application.isInitialized()) {
            ApplicationConfiguration config = new ApplicationConfiguration();
            config.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(install)), config);
        }
        ghidra.framework.protocol.ghidra.Handler.registerHandler();
        ClassSearcher.search(TaskMonitor.DUMMY);
    }
}
