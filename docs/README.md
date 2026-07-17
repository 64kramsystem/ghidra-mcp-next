# Documentation

This directory contains the maintained guides for the local Ghidra MCP
architecture.

## Start here

- [`../README.md`](../README.md) — install, connect, local projects, TraceRMI,
  BSim, security, and common tests.
- [`PROJECT_STRUCTURE.md`](PROJECT_STRUCTURE.md) — current code and ownership
  boundaries.
- [`TESTING.md`](TESTING.md) — offline, build, package, and live-test gates.
- [`QUICK_REFERENCE_SCRIPTS.md`](QUICK_REFERENCE_SCRIPTS.md) — command and
  workflow cheat sheet.
- [`MULTI_PROGRAM_SUPPORT_ANALYSIS.md`](MULTI_PROGRAM_SUPPORT_ANALYSIS.md) —
  explicit program/instance routing.
- [`prompts/TOOL_USAGE_GUIDE.md`](prompts/TOOL_USAGE_GUIDE.md) — tool-loading
  and safe mutation discipline for agents.
- [`prompts/CROSS_VERSION_FUNCTION_MATCHING.md`](prompts/CROSS_VERSION_FUNCTION_MATCHING.md)
  — evidence-only local comparison and optional BSim.
- [`releases/README.md`](releases/README.md) — retained release notes.

## Focused references

- [`GHIDRA_VARIABLE_APIS_EXPLAINED.md`](GHIDRA_VARIABLE_APIS_EXPLAINED.md)
- [`STRUCT_RESIZE_WORKFLOW.md`](STRUCT_RESIZE_WORKFLOW.md)
- [`THIS_POINTER_TYPING.md`](THIS_POINTER_TYPING.md)
- [`MAVEN_VERSION_MANAGEMENT.md`](MAVEN_VERSION_MANAGEMENT.md)

## Supported command surface

```bash
python -m tools.setup preflight --ghidra-path /path/to/ghidra
python -m tools.setup ensure-prereqs --ghidra-path /path/to/ghidra
python -m tools.setup build
python -m tools.setup deploy --ghidra-path /path/to/ghidra
mvn clean package assembly:single -DskipTests
```

## Maintenance rules

- Describe local GUI/headless projects and the current 232-endpoint catalog.
- Use exact exposed MCP names, especially the 21 `debugger_*` TraceRMI tools.
- Clearly distinguish implemented attach/wait/map behavior from the remaining planned debugger addition.
- Treat BSim as optional and explicitly configured.
- Keep script guidance aligned with the reviewed allowlist and
  `GHIDRA_MCP_ALLOW_SCRIPTS` gate.
- Keep release history separate from current operator guidance.
