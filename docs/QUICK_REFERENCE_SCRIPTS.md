# Quick Reference

## Build and deploy

```bash
uv sync
python -m tools.setup preflight --ghidra-path /path/to/ghidra
python -m tools.setup ensure-prereqs --ghidra-path /path/to/ghidra
python -m tools.setup build
python -m tools.setup deploy --ghidra-path /path/to/ghidra
```

Manual Java package:

```bash
mvn clean package assembly:single -DskipTests
```

## Run the bridge

```bash
uv run bridge-mcp-ghidra
uv run bridge-mcp-ghidra --transport streamable-http --mcp-host 127.0.0.1 --mcp-port 8081
```

## Tool discovery

```text
search_tools("memory block")
list_tool_groups()
load_tool_group("datatype")
check_tools("create_memory_block,apply_data_type")
```

Load each group once and call tools by name. Do not loop on
`load_tool_group(...)` after an operation failure.

## Local project bootstrap

```text
list_instances()
create_project(parent_dir="/tmp/projects", name="analysis")
import_file(file_path="/path/to/main.exe", auto_analyze=true)
import_file(file_path="/path/to/library.dll", auto_analyze=true)
list_open_programs()
switch_program(program="main.exe")
save_program(program="main.exe")
```

Set `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1` for multi-program or multi-client
work and pass `program=` on every scoped call.

## Static analysis loop

```text
search_strings(...)
get_xrefs_to(...)
get_function_by_address(...)
decompile_function(...)
clear_flow_and_repair(...)
rename_function_by_address(...)
set_function_prototype(...)
batch_set_comments(...)
save_program(...)
```

Names and comments are caller-owned. Ghidra reports invalid syntax,
duplicates, bad datatypes, and transaction errors.

## Local comparison

```text
get_function_hash(...)
get_bulk_function_hashes(...)
get_function_signature(...)
find_similar_functions_fuzzy(...)
bulk_fuzzy_match(...)
diff_functions(...)
```

These tools return evidence only. They do not copy names, types, comments, or
other annotations between programs.

## TraceRMI

```text
load_tool_group("debugger")
debugger_launch_offers()
debugger_launch(...)
debugger_status()
debugger_traces()
debugger_modules()
debugger_static_to_dynamic(...)
debugger_set_breakpoint(...)
debugger_resume()
debugger_interrupt()
debugger_registers(...)
debugger_stack_trace(...)
debugger_read_memory(...)
```

Use `debugger_resume` for continuing execution. There is no generic TraceRMI
attach endpoint. Planned gaps are generic selected-offer/PID attach,
`debugger_wait_for_stop(timeout_ms)`, process memory-map enumeration, and
`copy_debugger_memory_to_program`.

## Optional local BSim scripts

Enable scripts only for a trusted local client:

```bash
export GHIDRA_MCP_ALLOW_SCRIPTS=1
```

```text
run_ghidra_script(
  script_name="BSimTestConnection.java",
  args=["file:/absolute/path/to/local-bsim"]
)
run_ghidra_script(
  script_name="BSimIngestProgram.java",
  args=["file:/absolute/path/to/local-bsim"]
)
run_ghidra_script(
  script_name="BSimQueryFunction.java",
  args=["0x401000", "file:/absolute/path/to/local-bsim"]
)
run_ghidra_script(
  script_name="BSimBulkQuery.java",
  args=["file:/absolute/path/to/local-bsim"]
)
```

The URL is illustrative and must be supported by the installed Ghidra BSim
client. No database address is implied.

## Test

```bash
uv run pytest tests/unit/ -v --no-cov
mvn test
mvn clean compile -q
git diff --check
```
