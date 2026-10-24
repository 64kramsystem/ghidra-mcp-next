# GhidraMCP-next

GhidraMCP-next exposes useful Ghidra GUI operations to local MCP clients. It has two parts:

- a Java extension that owns the Ghidra and TraceRMI operations;
- a thin Python stdio bridge that discovers a local extension and publishes its schema.

The bridge adds only five management tools: `list_instances`, `connect_instance`, `create_and_connect_project`, `get_connection_info`, and `refresh_connection`. Connecting publishes every tool reported by the selected extension.

## Requirements

- Ghidra 12.2 exactly
- JDK 25 (build and runtime baseline)
- Maven 3.9 or later
- Python 3.11 or later
- `uv`
- a POSIX host for the stdio bridge's Unix-domain socket discovery

## Build and deploy

```bash
uv sync
python -m tools.setup preflight --ghidra-path /path/to/ghidra
python -m tools.setup ensure-prereqs --ghidra-path /path/to/ghidra
python -m tools.setup build
python -m tools.setup deploy --ghidra-path /path/to/ghidra
```

Manual packaging after prerequisites are installed:

```bash
mvn clean package assembly:single -DskipTests
```

Enable **GhidraMCP-next** in the Ghidra Project Window through **File > Configure**. The extension then keeps one per-process Unix-domain socket across project switches.

Loopback TCP is optional. Enable **GhidraMCP-next > Enable TCP Transport** in Ghidra only for a local client that cannot use the stdio bridge, such as `c64-mcp`.

## Connect an MCP client

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/ghidra-mcp-next",
        "ghidra-mcp-bridge"
      ]
    }
  }
}
```

The bridge uses stdio outward and Unix-domain sockets inward. If exactly one Ghidra instance is running, it connects at startup. Otherwise call `list_instances`, then `connect_instance` with an exact project name, PID, or socket path.

`refresh_connection` refetches the selected extension's schema after an extension update. It never retries or replays a failed Ghidra operation.

## Working with programs

Most program-scoped tools accept `program`. Always supply it when more than one program is open.

```text
list_open_programs()
get_current_program_info(program="game")
decompile_function(address="RAM:c000", program="game")
save_program(program="game")
```

The retained surface covers:

- program import, open, save, close, memory reads, and rebasing;
- functions, labels, equates, comments, references, and datatypes;
- memory blocks, data creation, disassembly, flow, bytes, and coverage;
- complete text listings, local project creation and opening, and project archives;
- TraceRMI memory, registers, breakpoints, execution, target methods, and launchers.

Use address-space-qualified addresses for overlays or ambiguous maps.

Call `debugger_terminal_output(max_lines=100)` after debugger operations and shutdown to inspect asynchronous errors. It reads retained terminal tabs, including terminated sessions; starting another terminal removes terminated tabs.

## Tests

```bash
mvn -Dghidra.test.install.dir="$GHIDRA_INSTALL_DIR" test
PYTHONPATH=python uv run pytest tests/unit --no-cov
```

The Java fixture profile uses the Ghidra installation populated by `tools.setup ensure-prereqs`.

## Releases

Breaking public contracts use:

```bash
tools/release minor
```

The command requires clean, synchronized `main`, builds the extension and bridge, commits the version and changelog, tags it, and atomically pushes the commit and tag.

## Focused references

- [Ghidra variable APIs](docs/GHIDRA_VARIABLE_APIS_EXPLAINED.md)
- [C++ `this` typing](docs/THIS_POINTER_TYPING.md)
- [Multiple open programs](docs/MULTI_PROGRAM_SUPPORT_ANALYSIS.md)
- [Structure editing](docs/STRUCT_RESIZE_WORKFLOW.md)

## Ghidra 12.2 debugger features

`debugger_set_breakpoint(address="RAM:1000", kind="RW", length=8)` sets a read/write
watchpoint when the target supports it. Kinds are `x` (software execute), `X`
(hardware execute), `R`, `W`, and `RW`. Execute breakpoints require length 1.

`debugger_search_memory_history(pattern="1122", start="RAM:1000", end="RAM:1fff",
first_snap=0, last_snap=100, limit=100)` searches recorded memory with Ghidra's
history index. Matches stay inside the address range and their lifespans are
clipped to the requested snapshots. This does not read the live target.

Old debugger traces cannot be upgraded to 12.2. Capture new traces. Setup rejects
other Ghidra versions and never selects an older installation's user directory.

## Emulator integration test

With sibling checkouts of `c64-mcp`, `ghidra-vice-connector`, `dosbox-x`, and
`ghidra-dosbox_x-connector`, a built DOSBox-X, VICE, and GDB:

```sh
JAVA_HOME=/path/to/jdk-25 python tools/test_debugger_stacks.py \
  --ghidra /path/to/ghidra_12.2_PUBLIC
```

The Python interpreter needs `protobuf>=6.31.0`. The test creates disposable
emulators and a real Ghidra TraceRMI server; only the GUI service container is
substituted. It exercises C64 MCP calls through the Java extension and the VICE
agent, then the DOSBox-X launcher through Ghidra's bundled GDB agent. Logs and
its temporary project are retained in the printed directory. Use `--stack vice`
or `--stack dos` to run one side.
