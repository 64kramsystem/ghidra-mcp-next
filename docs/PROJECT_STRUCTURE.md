# Project Structure

GhidraMCP-next has two runtime layers: a Java extension/headless service that owns
Ghidra operations, and a Python bridge that exposes the discovered HTTP schema
as MCP tools.

```text
ghidra-mcp/
├── src/main/java/com/xebyte/
│   ├── GhidraMCPPlugin.java       # GUI plugin and endpoint registration
│   ├── core/                      # analysis, program, project, and utility services
│   └── headless/                  # local headless launcher and endpoint handler
├── src/test/java/com/xebyte/      # Java runtime-behavior tests
├── python/ghidra_mcp_bridge/      # MCP bridge, schema normalization, transports
├── tools/setup/                   # setup/build/deploy/version CLI
├── ghidra_scripts/                # exact reviewed generic-script allowlist
├── tests/
│   ├── unit/                      # Python runtime-behavior tests
│   └── integration/               # optional live HTTP tests
├── docs/                          # maintained guides and release notes
├── .github/workflows/             # CI and release automation
├── pom.xml                        # Java build
├── pyproject.toml                 # Python package and dependency groups
└── uv.lock                        # locked Python dependencies
```

## Java ownership

- `GhidraMCPPlugin` constructs GUI services, scans `@McpTool` annotations, and
  starts TCP/UDS HTTP transports.
- `core/EndpointRegistry` defines the maintained headless registration surface.
- `core/DebuggerService` is the schema-discovered TraceRMI boundary.
- `core/BinaryComparisonService` owns evidence-only local hashes, signatures,
  fuzzy matching, and function diffs.
- `core/ProgramScriptService` owns local project/program and script execution;
  script endpoints consult `SecurityConfig`.
- `core/ListingMutationService` owns dry-run-first, complete-unit listing
  undefinition and delegates annotation capture/restoration to the shared
  `ListingClearCore`.
- `headless/` provides a local headless Ghidra process with deliberate parity
  or explicit unsupported responses.

Caller names and comments are passed to Ghidra unchanged. Generic generated
symbol detection is read-only and used only for filtering/audit signals.

## Python ownership

The `ghidra_mcp_bridge` package:

- discovers running GUI/headless instances;
- handshakes the server version and complete endpoint schema into one
  generation;
- converts endpoint paths into stable MCP names;
- provides management tools such as `search_tools`, `list_tool_groups`, and
  `load_tool_group`, plus connection identity/refresh tools;
- forwards calls over local UDS or TCP; and
- optionally serves stdio, Streamable HTTP, or legacy SSE MCP transports.

It does not implement a second debugger or analysis engine.

## Build and package outputs

Maven produces the extension archive and headless assembly under `target/`:

```bash
python -m tools.setup build
mvn clean package assembly:single -DskipTests
```

The Python wheel contains only `python/ghidra_mcp_bridge`. `uv` dependency
groups provide development and test tooling.
