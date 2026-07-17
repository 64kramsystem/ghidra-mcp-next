# MCP Tool Usage Guide

This guide is for agents operating Ghidra MCP against local GUI or headless
projects.

## 1. Establish the target

Start by identifying the Ghidra instance and open programs:

```text
list_instances()
list_open_programs()
get_current_program()
```

When multiple instances exist, provide an exact `instance=` selector. When
multiple programs exist, pass `program=` on every scoped call. Enabling
`GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1` turns omissions into explicit bridge
errors.

## 2. Discover and load tools once

The management surface is always available:

```text
search_tools("repair flow")
list_tool_groups()
check_tools("clear_flow_and_repair,decompile_function")
load_tool_group("function")
```

Call `load_tool_group` once for a required group. After it reports success,
call the named tool directly. Do not repeatedly search or reload a group after
an operation error; fix the operation's address, program, datatype, state, or
arguments instead.

Common groups include `listing`, `function`, `program`, `datatype`, `analysis`,
`comment`, `xref`, `search`, `emulation`, and `debugger`.

## 3. Static analysis discipline

A productive evidence loop is:

```text
search_strings(...)
get_xrefs_to(...)
get_function_by_address(...)
decompile_function(...)
get_disassembly(...)
get_call_graph(...)
```

For damaged code boundaries, inspect raw bytes and references before using:

```text
clear_flow_and_repair(...)
create_function(...)
delete_function(...)
```

Verify repaired boundaries with listing and decompiler output. This supports
the FileZilla-style procedure where strings/RTTI/xrefs identify the proprietary
core while libraries are analyzed as separate local programs.

## 4. Mutation discipline

Caller-supplied names and comments are passed unchanged to Ghidra. Choose names
that fit the current reverse-engineering project. Expect structured errors for
invalid symbol syntax, duplicates, unknown datatypes, impossible layouts, and
failed transactions.

Prefer atomic/batch tools where they reduce partial state:

```text
rename_function_by_address(...)
set_function_prototype(...)
set_variables(...)
set_global(...)
batch_set_comments(...)
create_struct(...)
modify_struct_field(...)
```

After a mutation, re-read the function/global/type and save the same explicit
program. Do not infer success from a timeout.

## 5. Address spaces and program selectors

Use `get_address_spaces` before assuming a plain hexadecimal address is
unambiguous. Embedded and overlay programs may require `space:offset` syntax.

For cross-program calls, provide every declared selector. Local comparison
tools do not change either program:

```text
get_function_hash(...)
get_bulk_function_hashes(...)
get_function_signature(...)
find_similar_functions_fuzzy(...)
bulk_fuzzy_match(...)
diff_functions(...)
```

## 6. TraceRMI dynamic discipline

The dynamic group is exactly `debugger`. Load it once, then call the clean
schema-discovered names:

```text
load_tool_group("debugger")
debugger_launch_offers()
debugger_launch(offer=..., arguments=...)
debugger_status()
debugger_traces()
debugger_modules()
debugger_static_to_dynamic(...)
debugger_set_breakpoint(...)
debugger_resume()
debugger_registers(...)
debugger_stack_trace(...)
debugger_read_memory(...)
```

Use `debugger_interrupt`, `debugger_step_into`, `debugger_step_over`, and
`debugger_step_out` when the current trace state permits. Use
`debugger_list_breakpoints` and `debugger_remove_breakpoint` to clean up.

Before setting a runtime breakpoint, obtain the module/trace state and use
`debugger_static_to_dynamic`. After a stop, re-read status rather than assuming
the last action completed synchronously.

There is no generic TraceRMI attach endpoint. Planned additions are:

- Generic TraceRMI attach using a selected launch offer and PID.
- `debugger_wait_for_stop(timeout_ms)`.
- Process memory-map enumeration.
- `copy_debugger_memory_to_program`, creating/populating a program block from a
  trace range.

Do not invent these tool names or emulate them by repeatedly calling unrelated
tools. If a workflow requires one today, record the limitation.

## 7. Wine context

For a proprietary Windows target under Wine, keep the PE in a local project and
use Ghidra's available Wine/GDB-compatible launch offer. Correlate live and
static addresses through the mapping tools.

For a bug in Wine itself, source-level Wine/GDB/build/test work is primary.
Ghidra MCP can support instruction and control-flow analysis but should not be
presented as the source-patching system.

## 8. Trusted scripts and optional BSim

Script endpoints are off by default. Set `GHIDRA_MCP_ALLOW_SCRIPTS=1` only for a
trusted local client. The retained BSim scripts are:

- `BSimTestConnection`
- `BSimIngestProgram`
- `BSimQueryFunction`
- `BSimBulkQuery`

Supply a Ghidra-supported URL on every MCP/headless run, for example
`file:/absolute/path/to/local-bsim`. Single-function query args place the
function address first and URL second. BSimQueryFunction reports matches and
does not apply metadata.

## 9. Timeouts and retries

- Read-only calls may be retried after confirming the target is unchanged.
- Do not automatically retry a mutating request whose outcome is unknown.
- Check current program and object state before a compensating action.
- A tool-group reload does not resolve a server-side timeout.
- Split large analysis jobs into bounded calls with explicit program selectors.

## 10. Save and report

End a work unit by verifying the affected objects, calling `save_program` with
the explicit target, and reporting which live tests or dynamic states were not
available. Separate evidence from inference.
