"""The MCP server singleton."""

from mcp.server.mcpserver import MCPServer, Context  # noqa: F401  (Context re-exported)

# The MCP server singleton. All static and dynamically registered tools attach
# to this object.
mcp = MCPServer("ghidra-mcp")
