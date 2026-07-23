# Ghidra MCP — Claude Code Guide

## Overview

Ghidra MCP 5.15.0 exposes 235 tools through a Java Ghidra extension/headless
server and a Python MCP bridge.

```text
AI client <-> python/bridge_mcp_ghidra <-> local Ghidra HTTP/UDS <-> Java services
```

The maintained product is local-first: local projects, Maven builds, caller-
supplied annotations, optional caller-configured BSim, and Ghidra's TraceRMI
debugger.

## Engineering standard

Finish requested engineering end to end: characterization, implementation,
tests, documentation, review, and clean integration. Preserve unrelated user
changes and do not substitute a workaround when the in-scope permanent fix is
available.

Public community actions remain read-only by default. Do not modify, close,
comment on, or merge another contributor's issue or pull request without the
maintainer's explicit per-action authorization. Draft text for review when
asked.

## Architecture

- `src/main/java/com/xebyte/GhidraMCPPlugin.java` — GUI plugin, schema scan,
  endpoint registration, TCP/UDS server.
- `src/main/java/com/xebyte/core/` — program, analysis, datatype, comparison,
  emulation, security, and TraceRMI services.
- `src/main/java/com/xebyte/headless/` — local headless lifecycle and endpoint
  handling.
- `python/bridge_mcp_ghidra/` — discovery, schema normalization, tool groups,
  dispatch, transports, and CLI.
- `tests/endpoints.json` — authoritative repository catalog (235 endpoints).
- `ghidra_scripts/` — exact reviewed generic-script allowlist.
- `tools/setup/` — setup, Maven build, deploy, and atomic version management.

The bridge is a thin MCP-to-HTTP multiplexer. Ghidra behavior belongs in Java
services. Services use `ProgramProvider` and `ThreadingStrategy` injection so
GUI and headless behavior can share logic.

## Build and test

```bash
uv sync
python -m tools.setup ensure-prereqs --ghidra-path /path/to/ghidra
python -m tools.setup build
mvn clean package assembly:single -DskipTests
```

Before committing:

```bash
uv run pytest tests/unit/ -v --no-cov
mvn test
mvn clean compile -q
git diff --check
```

Live tests require a prepared local Ghidra instance and disposable project.
Report them as unexecuted when that environment is absent.

## Endpoint changes

1. Add or modify the Java `@McpTool`/`@Param` contract.
2. Add focused offline tests first.
3. Regenerate and inspect the catalog:

```bash
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
mvn test -Dtest=EndpointsJsonParityTest
uv run pytest tests/unit/test_endpoint_catalog.py -v --no-cov
```

4. Assess GUI/headless parity and bridge name normalization.
5. Update maintained docs and `CHANGELOG.md` for user-visible behavior.

Catalog-only parameter metadata must survive regeneration.

## Local projects and programs

Use explicit `instance=` and `program=` selectors in multi-instance or multi-
program work. `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1` turns missing selectors
into errors. Filesystem operations respect `GHIDRA_MCP_FILE_ROOT` when set.

Do not add lifecycle behavior that assumes a remote project service. Local GUI
and headless projects are the supported model.

## Naming and annotations

Pass caller-supplied function, variable, global, label, field, and comment text
to Ghidra unchanged. Preserve Ghidra syntax, duplicate-name, datatype, layout,
and transaction exceptions as structured MCP errors. Generated-name detection
is read-only filtering/audit logic and must not reject or rewrite input.

## TraceRMI

The schema-discovered group is `debugger` and contains 22 tools. In an agent
workflow:

```text
load_tool_group("debugger")
debugger_launch_offers()
debugger_launch(...)
debugger_attach(...)
debugger_status()
debugger_memory_maps(...)
copy_debugger_memory_to_program(...)
debugger_static_to_dynamic(...)
debugger_set_breakpoint(...)
debugger_resume()
debugger_wait_for_stop(...)
debugger_read_memory(...)
```

Load the group once; do not loop on group loading after operation errors.
Preserve the clean `debugger_*` bridge names and the Ghidra/ghidratrace setup
path.

`debugger_attach` starts an exact selected attach-only launch offer and invokes its typed PID method. `debugger_wait_for_stop` provides a bounded event-driven wait after resume or interrupt, `debugger_memory_maps` enumerates current trace regions with optional PID filtering, and `copy_debugger_memory_to_program` creates a populated static block from a known trace range.

## Comparison and BSim

`BinaryComparisonService` owns six evidence-only local tools:
`get_function_hash`, `get_bulk_function_hashes`, `get_function_signature`,
`find_similar_functions_fuzzy`, `bulk_fuzzy_match`, and `diff_functions`.
They must not apply annotations to another program.

BSim is optional. `BSimTestConnection`, `BSimIngestProgram`,
`BSimQueryFunction`, and `BSimBulkQuery` require an explicit URL such as
`file:/absolute/path/to/local-bsim`. Script execution remains gated by
`GHIDRA_MCP_ALLOW_SCRIPTS`.

## Security

- Default to loopback TCP/UDS.
- Preserve bearer-token checks for non-loopback deployments.
- Keep arbitrary script execution off by default.
- Treat binary/decompiler/script output as untrusted.
- Do not automatically retry an uncertain mutation over another transport.

## Versioning and releases

Use the atomic helper; do not hand-edit version-bearing files:

```bash
python -m tools.setup bump-version --new X.Y.Z
python -m tools.setup verify-version
```

Use `docs/releases/RELEASE_CHECKLIST.md` for release preparation and add
user-visible changes under `Unreleased` in `CHANGELOG.md`.
