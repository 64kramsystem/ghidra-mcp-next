# Workflow Prompts

These guides help an agent use the maintained Ghidra MCP surface. They are
operator aids, not policy engines. The caller chooses project naming and
comment style; Ghidra validates model constraints.

## Start here

- [`TOOL_USAGE_GUIDE.md`](TOOL_USAGE_GUIDE.md) — tool discovery, load-once
  discipline, safe mutations, local projects, and TraceRMI.
- [`DATA_TYPE_INVESTIGATION_WORKFLOW.md`](DATA_TYPE_INVESTIGATION_WORKFLOW.md)
  — systematic structure and datatype investigation.
- [`DATA_TYPE_INVESTIGATION_QUICK.md`](DATA_TYPE_INVESTIGATION_QUICK.md) —
  abbreviated datatype workflow.
- [`DATA_SECTION_WORKFLOW.md`](DATA_SECTION_WORKFLOW.md) — `.data`/`.rdata`
  analysis.
- [`GLOBAL_DATA_ANALYSIS_WORKFLOW.md`](GLOBAL_DATA_ANALYSIS_WORKFLOW.md) —
  type, xref, value, and comment analysis for globals.
- [`ORPHANED_CODE_DISCOVERY_WORKFLOW.md`](ORPHANED_CODE_DISCOVERY_WORKFLOW.md)
  — find and validate missed functions.
- [`CROSS_VERSION_FUNCTION_MATCHING.md`](CROSS_VERSION_FUNCTION_MATCHING.md)
  — compare open programs without applying annotations.

## Operating principles

1. Select the local instance and program explicitly.
2. Load a needed tool group once and call tools by their exposed MCP names.
3. Gather strings, xrefs, bytes, listing, and decompiler evidence before a
   mutation.
4. Make small reversible changes and verify the affected program.
5. Treat local comparison and BSim results as evidence, not automatic truth.
6. Save the explicitly selected program after verification.

For dynamic work, load `load_tool_group("debugger")` once and use the retained
TraceRMI attach, launch, status, wait, mapping, breakpoint, stepping, register, stack, module, and read-memory tools.
