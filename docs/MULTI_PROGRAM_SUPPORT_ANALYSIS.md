# Multi-Program Support

Ghidra MCP supports several open programs inside a local GUI or headless
project. Program routing is explicit at the endpoint boundary but remains
compatible with single-program callers that rely on the active program.

## Routing model

Most program-scoped endpoints accept `program=`. When it is omitted, the Java
service uses the current program: the active CodeBrowser tab in GUI mode or the
headless provider's current selection. `switch_program` changes that shared
selection.

That default is convenient for one client and one binary, but it is unsafe when
multiple clients or programs share a process. Enable strict bridge routing:

```bash
export GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1
uv run bridge-mcp-ghidra
```

With strict routing, any scoped call that omits its selector fails before it is
forwarded. Cross-program tools must provide both selectors (`source_program` and
`target_program`, or `program_a` and `program_b` as declared by the endpoint).

## Local project workflow

```text
list_instances()
create_project(parent_dir="/tmp/projects", name="FileZilla")
import_file(file_path="/opt/targets/filezilla", auto_analyze=true)
import_file(file_path="/opt/targets/libfilezilla.so", auto_analyze=true)
list_open_programs()
switch_program(program="filezilla")
decompile_function(address="0x...", program="filezilla")
search_functions(query="verify", program="libfilezilla.so")
save_program(program="filezilla")
```

The parent directory for `create_project` must already exist. If
`GHIDRA_MCP_FILE_ROOT` is configured, project and imported-file paths must stay
inside its canonical tree.

## Instance selection

The Python bridge discovers GUI/headless instances over UDS and TCP and
deduplicates equivalent transports. When more than one instance is available,
pass `instance=` as an exact:

- PID;
- Unix-domain socket path;
- TCP URL; or
- local project name.

Ambiguous selectors return the available choices. A mutating call is not
blindly replayed over another transport after an uncertain outcome.

## Program lifecycle

Use the lifecycle tools to control local state:

- `open_project` / `create_project`
- `import_file`
- `open_program` / `close_program`
- `list_open_programs`
- `switch_program`
- `save_program`
- `export_program`

Saving one program does not imply saving every open program. Pass the target
explicitly and verify the returned program identity.

## Comparison

The retained comparison service works directly across open programs:

- `get_function_hash`
- `get_bulk_function_hashes`
- `get_function_signature`
- `find_similar_functions_fuzzy`
- `bulk_fuzzy_match`
- `diff_functions`

The result is evidence for an analyst. No endpoint in this set applies names,
comments, types, or documentation from one program to another.

For open-source dependencies, optional BSim can supplement these primitives.
It remains caller-configured and is not required for multi-program work.

## GUI and headless behavior

GUI mode can keep several program tabs open. Headless mode tracks programs in
its local provider. Both surfaces use the same catalog wherever feasible;
offline parity tests document deliberate differences.

Avoid using GUI tab focus as synchronization between clients. Strict selectors
are the stable contract.

## Failure handling

Before a mutation:

1. resolve the intended instance;
2. list or verify the target program;
3. pass its selector on the call;
4. inspect the response identity; and
5. save that same program explicitly.

If a tool reports an ambiguous program or instance, fix the selector. Retrying
without one can target a different binary.

## Tests

```bash
uv run pytest \
  tests/unit/test_bridge_utils.py \
  tests/unit/test_create_project.py \
  tests/unit/test_protected_workflows.py \
  -v --no-cov

mvn test -Dtest='com.xebyte.core.GuiProjectServiceTest,com.xebyte.offline.FrontEndProgramProviderEvictionTest'
```
