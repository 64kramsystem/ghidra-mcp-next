package com.xebyte;

import com.xebyte.core.ServerManager;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelPlugin;
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

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();
        try {
            ServerManager.getInstance().registerTool(tool);
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
