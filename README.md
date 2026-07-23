# Ghidra MCP Server

Ghidra MCP connects AI clients to Ghidra through a Java extension and a thin
Python MCP bridge. Version 5.15.0 exposes 248 tools for local static analysis,
multi-program work, P-code emulation, local comparison, and Ghidra's built-in
TraceRMI debugger.

The maintained architecture is local-first:

- GUI and headless Ghidra projects are stored locally.
- Maven is the Java build system.
- The Python bridge uses stdio, Streamable HTTP, or the legacy SSE transport.
- Caller-supplied names and comments go to Ghidra unchanged; Ghidra enforces
  syntax, uniqueness, datatype, and transaction constraints.
- Script execution is opt-in and limited to trusted local workflows.
- BSim is optional and uses an explicit caller-supplied database URL.

## Capabilities

- Import, analyze, save, reopen, switch, and compare programs in one local
  project.
- Search strings, bytes, operands, symbols, functions, and references.
- Decompile and disassemble functions; repair flow and function boundaries.
- Create memory blocks, functions, labels, comments, prototypes, structures,
  enums, arrays, and other datatypes.
- Strictly validate, preview, and atomically apply platform-neutral symbol
  profiles containing labels, nested namespaces, entry points, equates,
  comments, and optional memory blocks.
- Read memory and perform static-to-dynamic address mapping through TraceRMI.
- Use six local comparison tools:
  `get_function_hash`, `get_bulk_function_hashes`,
  `get_function_signature`, `find_similar_functions_fuzzy`,
  `bulk_fuzzy_match`, and `diff_functions`.
- Run a small reviewed allowlist of generic Ghidra scripts when explicitly
  enabled.

This surface supports workflows such as the local multi-binary FileZilla
analysis documented in the architecture design: import the main executable and
libraries, follow strings/RTTI/xrefs, repair damaged flow, annotate proprietary
code with project-appropriate names, and optionally use local BSim to recognize
open-source dependency boundaries.

## Requirements

- Ghidra 12.1.2 or a compatible release
- Java 21
- Maven 3.9+
- Python 3.10+
- `uv` is recommended for the locked Python environment

Ghidra 12.1 ships Jython as an optional extension. Java scripts work without
it; retained `.py` scripts require enabling Jython through **File > Install
Extensions** and restarting Ghidra.

## Build and install

Clone the repository, then run the setup CLI against your Ghidra installation:

```bash
uv sync
python -m tools.setup preflight --ghidra-path /path/to/ghidra_12.1.2_PUBLIC
python -m tools.setup ensure-prereqs --ghidra-path /path/to/ghidra_12.1.2_PUBLIC
python -m tools.setup build
python -m tools.setup deploy --ghidra-path /path/to/ghidra_12.1.2_PUBLIC
```

`ensure-prereqs` installs Ghidra's Java artifacts into the local Maven
repository. `build` invokes Maven. `deploy` installs the extension into the
selected user profile.

For a manual build after prerequisites are available:

```bash
mvn clean package assembly:single -DskipTests
```

In a CodeBrowser window, enable **GhidraMCP** through **File > Configure**, then
start the server with **Tools > GhidraMCP > Start MCP Server**. The default TCP
endpoint is `http://127.0.0.1:8089`; Unix-domain sockets are also enabled on
supported local hosts to distinguish multiple GUI instances. The GUI TCP and
Unix-socket transports publish the same discovered tool schema, including
local project lifecycle, emulation, and TraceRMI tools.

## Connect an MCP client

Start the stdio bridge:

```bash
uv run bridge-mcp-ghidra
# equivalent:
python -m bridge_mcp_ghidra
```

Example MCP client configuration:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/ghidra-mcp", "bridge-mcp-ghidra"]
    }
  }
}
```

For Streamable HTTP:

```bash
uv run bridge-mcp-ghidra \
  --transport streamable-http \
  --mcp-host 127.0.0.1 \
  --mcp-port 8081
```

The MCP URL is `http://127.0.0.1:8081/mcp`. SSE remains available for older
clients but should not be selected for new integrations.

## Local projects and multi-program safety

With one GUI instance running, an MCP client can create and populate a local
project without first opening one manually:

```text
list_instances()
create_and_connect_project(parent_dir="/tmp/ghidra-projects", name="FileZilla")
import_file_and_notify(file_path="/path/to/filezilla", auto_analyze=true)
import_file_and_notify(file_path="/path/to/libfilezilla.so", auto_analyze=true)
list_open_programs()
switch_program(program="filezilla")
save_program(program="filezilla")
```

When several programs or clients share an instance, set
`GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1`. Program-scoped calls must then name
their target instead of relying on the active tab. Use an exact `instance=` PID,
socket path, TCP URL, or project name when multiple Ghidra instances are
available.

## Tool groups

The bridge can expose all tools eagerly or start with a smaller lazy surface.
In lazy mode, use the management tools deliberately:

```text
search_tools("rename function")
list_tool_groups()
load_tool_group("function")
check_tools("rename_function_by_address,batch_set_comments")
```

Load a group once, call its tools by their exposed names, and do not repeatedly
load the same group in a retry loop. A tool error should be handled as an
operation error; reloading a group does not change the target's state.

Every connect, switch, reconnect, and `refresh_connection()` validates the
selected server's `/get_version` and complete `/mcp/schema` before publishing
any tools. Use `get_connection_info()` to report the exact plugin, bridge,
transport, manifest digests, callable count, and connection generation.
`check_tools(...)` includes the active manifest digest and generation.
Registration failures never leave a partial tool map; a failed explicit switch
preserves the healthy previous connection, while a failed active refresh or
reconnect disconnects and removes stale dynamic tools.

The friendly bridge wrappers are named `create_and_connect_project` and
`import_file_and_notify`. The schema-discovered server tools retain the names
`create_project` and `import_file`, so both count normally in the server
manifest without colliding with bridge management tools.

## TraceRMI dynamic analysis

Dynamic analysis uses Ghidra's built-in debugger agents and TraceRMI. The
schema-discovered group is named `debugger`; load it once:

```text
load_tool_group("debugger")
debugger_launch_offers()
debugger_launch(offer=..., arguments=...)
debugger_attach(offer=..., pid=..., program=...)
debugger_status()
debugger_modules()
debugger_memory_maps(pid=...)
copy_debugger_memory_to_program(source_address=..., length=..., program=..., destination_address=..., block_name=...)
debugger_set_breakpoint(address=...)
debugger_resume()
debugger_wait_for_stop(timeout_ms=...)
debugger_read_memory(address=..., length=...)
```

The 22 retained tools are:

- `debugger_launch_offers`, `debugger_launch`, `debugger_attach`, `debugger_status`,
  `debugger_traces`, `debugger_modules`, and `debugger_memory_maps`
- `debugger_set_breakpoint`, `debugger_list_breakpoints`, and
  `debugger_remove_breakpoint`
- `debugger_resume`, `debugger_wait_for_stop`, `debugger_interrupt`, `debugger_step_into`,
  `debugger_step_over`, and `debugger_step_out`
- `debugger_registers`, `debugger_stack_trace`, and `debugger_read_memory`
- `debugger_static_to_dynamic`, `debugger_dynamic_to_static`, and
  `copy_debugger_memory_to_program`

For a proprietary Windows application under Wine, import the PE into a local
project, use a suitable Ghidra launch offer for the Wine/GDB environment, break
on the mapped runtime address, and correlate live state with the static program
using the mapping tools. Debugging a defect in Wine's own open-source code is
primarily a Wine source, build, GDB, and test-suite task; Ghidra MCP can provide
supporting disassembly evidence.

Generic selected-offer/PID attach is available through `debugger_attach`, `debugger_wait_for_stop` provides a bounded event-driven wait, and `debugger_memory_maps` enumerates current trace regions with optional PID filtering. Use `copy_debugger_memory_to_program` to create and populate a program block from a known range in the active trace.

## Optional local BSim

BSim can label open-source library boundaries around a proprietary target; it
is not required for ordinary static analysis. Script execution must first be
enabled with `GHIDRA_MCP_ALLOW_SCRIPTS=1`.

The retained scripts are `BSimTestConnection`, `BSimIngestProgram`,
`BSimQueryFunction`, and `BSimBulkQuery`. Each requires an explicit URL
supported by the installed Ghidra BSim client. For example:

```text
run_ghidra_script(
  script_name="BSimTestConnection.java",
  args=["file:/absolute/path/to/local-bsim"]
)
```

GUI runs prompt when the URL is omitted. Headless and MCP runs return
`BSim URL is required`; no host is selected implicitly. See
[`ghidra_scripts/README.md`](ghidra_scripts/README.md).

## Security

Keep the Java server and bridge on loopback unless you have explicitly secured
the deployment.

| Variable | Effect |
| --- | --- |
| `GHIDRA_MCP_AUTH_TOKEN` | Requires `Authorization: Bearer <token>` for non-health HTTP requests. |
| `GHIDRA_MCP_ALLOW_SCRIPTS` | Enables the two arbitrary-code script endpoints; off by default. |
| `GHIDRA_MCP_FILE_ROOT` | Restricts filesystem endpoints to a canonical root. |
| `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS` | Rejects ambiguous program-scoped calls that omit selectors. |

Treat analyzed binaries and decompiler output as untrusted data. Do not expose
script execution or file imports to untrusted MCP clients.

## Test

```bash
uv run pytest tests/unit/ -v --no-cov
mvn test
mvn clean compile -q
```

Live integration tests require a running Ghidra instance and are intentionally
separate from offline unit and contract tests. See [`docs/TESTING.md`](docs/TESTING.md).

## Documentation

- [`docs/README.md`](docs/README.md) — maintained guide index
- [`docs/PROJECT_STRUCTURE.md`](docs/PROJECT_STRUCTURE.md) — repository layout
- [`docs/QUICK_REFERENCE_SCRIPTS.md`](docs/QUICK_REFERENCE_SCRIPTS.md) — common commands and workflows
- [`docs/MULTI_PROGRAM_SUPPORT_ANALYSIS.md`](docs/MULTI_PROGRAM_SUPPORT_ANALYSIS.md) — multi-program routing
- [`docs/prompts/TOOL_USAGE_GUIDE.md`](docs/prompts/TOOL_USAGE_GUIDE.md) — agent tool discipline
- [`CHANGELOG.md`](CHANGELOG.md) — release history

## License

Apache-2.0. See [`LICENSE`](LICENSE).
