# Project structure

`src/main/java/com/xebyte` contains the GUI extension. `ServerManager` constructs the service objects, scans their `@McpTool` annotations, and serves the resulting endpoints over a per-process Unix-domain socket. Loopback TCP is optional.

`python/ghidra_mcp_bridge` is a stdio MCP adapter. It discovers live sockets, selects one instance, converts `/mcp/schema` into MCP tools, and forwards each call once.

`tools/setup` builds and deploys the extension and bridge. `tests/unit` covers the bridge's UDS transport and schema adaptation; `src/test` covers behavior that requires Ghidra APIs.
