# GhidraMCP-next

GhidraMCP-next exposes useful Ghidra GUI operations to local MCP clients. It has two parts:

- a Java extension that owns the Ghidra and TraceRMI operations;
- a thin Python stdio bridge that discovers a local extension and publishes its schema.

The bridge adds only five management tools: `list_instances`, `connect_instance`, `create_and_connect_project`, `get_connection_info`, and `refresh_connection`. Connecting publishes every tool reported by the selected extension.

## Requirements

- Ghidra 12.1.2
- Java 21
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
