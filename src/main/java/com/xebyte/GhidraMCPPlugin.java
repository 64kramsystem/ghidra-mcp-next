package com.xebyte;

import com.xebyte.core.ServerManager;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

import java.io.IOException;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.framework.main.UtilityPluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "GhidraMCP-next",
    description = "Local MCP access to the active Ghidra project and debugger."
)
public final class GhidraMCPPlugin extends Plugin implements ApplicationLevelPlugin {

    private static final String OPTIONS = "GhidraMCP-next";
    private static final String TCP_ENABLED = "Enable TCP Transport";
    private static final String TCP_PORT = "TCP Port";
    private static final int DEFAULT_PORT = 8089;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Options options = tool.getOptions(OPTIONS);
        options.registerOption(
            TCP_ENABLED,
            false,
            null,
            "Also listen on loopback TCP. Unix-domain sockets are always enabled.");
        options.registerOption(
            TCP_PORT,
            DEFAULT_PORT,
            null,
            "Loopback TCP port used when TCP transport is enabled.");
    }

    @Override
    protected void init() {
        super.init();
        Options options = tool.getOptions(OPTIONS);
        try {
            ServerManager.getInstance().registerTool(
                tool,
                options.getBoolean(TCP_ENABLED, false),
                options.getInt(TCP_PORT, DEFAULT_PORT));
        } catch (IOException error) {
            Msg.showError(
                this,
                null,
                "GhidraMCP-next",
                "Could not start the local MCP server: " + error.getMessage(),
                error);
        }
    }

    @Override
    public void dispose() {
        ServerManager.getInstance().deregisterTool(tool);
        super.dispose();
    }
}
