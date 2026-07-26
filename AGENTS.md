# AGENTS.md — GhidraMCP-next

This is the single instruction file for this repository. `CLAUDE.md` is a symlink to it,
because Claude Code reads `CLAUDE.md` and not `AGENTS.md`. Edit this file; never add
content to `CLAUDE.md`.

## Overview

GhidraMCP-next exposes more than 250 tools through a Java Ghidra extension/headless
server and a Python MCP bridge.

```text
AI client <-> python/bridge_mcp_ghidra <-> local Ghidra HTTP/UDS <-> Java services
```

The maintained product is local-first: local projects, Maven builds, caller-supplied
annotations, optional caller-configured BSim, and Ghidra's TraceRMI debugger.

## Engineering standard

Finish requested engineering end to end: characterization, implementation, tests,
documentation, review, and clean integration. Preserve unrelated user changes and do not
substitute a workaround when the in-scope permanent fix is available.

Public community actions remain read-only by default. Do not modify, close, comment on,
or merge another contributor's issue or pull request without the maintainer's explicit
per-action authorization. Draft text for review when asked.

## Conventions

- Keep GUI and headless endpoint schemas in parity.
- When endpoint registrations change, update and verify `tests/endpoints.json`.
- Update `CHANGELOG.md` for user-facing changes.
- Never use conventional-commit prefixes (`feat/`, …) in commit titles or branch names.

## Architecture

- `src/main/java/com/xebyte/GhidraMCPPlugin.java` — GUI plugin, schema scan, endpoint
  registration, TCP/UDS server.
- `src/main/java/com/xebyte/core/` — program, analysis, datatype, comparison, emulation,
  security, and TraceRMI services.
- `src/main/java/com/xebyte/headless/` — local headless lifecycle and endpoint handling.
- `python/bridge_mcp_ghidra/` — discovery, schema normalization, tool groups, dispatch,
  transports, and CLI.
- `tests/endpoints.json` — authoritative repository catalog (more than 250 endpoints).
- `ghidra_scripts/` — exact reviewed generic-script allowlist.
- `tools/setup/` — setup, Maven build, and deploy automation.

The bridge is a thin MCP-to-HTTP multiplexer. Ghidra behavior belongs in Java services.
Services use `ProgramProvider` and `ThreadingStrategy` injection so GUI and headless
behavior can share logic.

## Build and verify

First-time setup:

```bash
uv sync
python -m tools.setup ensure-prereqs --ghidra-path /path/to/ghidra
python -m tools.setup build
```

Before committing:

```bash
mvn clean compile -q
mvn test
uv run pytest tests/unit/ -v --no-cov
mvn clean package assembly:single -DskipTests
git diff --check
```

These are the same gates `tools/release` runs, in the same order.

Live tests require a prepared local Ghidra instance and disposable project. Report them
as unexecuted when that environment is absent.

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

Use explicit `instance=` and `program=` selectors in multi-instance or multi-program
work. `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1` turns missing selectors into errors.
Filesystem operations respect `GHIDRA_MCP_FILE_ROOT` when set.

Do not add lifecycle behavior that assumes a remote project service. Local GUI and
headless projects are the supported model.

## Naming and annotations

Pass caller-supplied function, variable, global, label, field, and comment text to
Ghidra unchanged. Preserve Ghidra syntax, duplicate-name, datatype, layout, and
transaction exceptions as structured MCP errors. Generated-name detection is read-only
filtering/audit logic and must not reject or rewrite input.

## TraceRMI

The schema-discovered group is `debugger` and contains 22 tools. In an agent workflow:

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

Load the group once; do not loop on group loading after operation errors. Preserve the
clean `debugger_*` bridge names and the Ghidra/ghidratrace setup path.

`debugger_attach` starts an exact selected attach-only launch offer and invokes its typed
PID method. `debugger_wait_for_stop` provides a bounded event-driven wait after resume or
interrupt, `debugger_memory_maps` enumerates current trace regions with optional PID
filtering, and `copy_debugger_memory_to_program` creates a populated static block from a
known trace range.

## Comparison and BSim

`BinaryComparisonService` owns six evidence-only local tools: `get_function_hash`,
`get_bulk_function_hashes`, `get_function_signature`, `find_similar_functions_fuzzy`,
`bulk_fuzzy_match`, and `diff_functions`. They must not apply annotations to another
program.

BSim is optional. `BSimTestConnection`, `BSimIngestProgram`, `BSimQueryFunction`, and
`BSimBulkQuery` require an explicit URL such as `file:/absolute/path/to/local-bsim`.
Script execution remains gated by `GHIDRA_MCP_ALLOW_SCRIPTS`.

## Security

- Default to loopback TCP/UDS.
- Preserve bearer-token checks for non-loopback deployments.
- Keep arbitrary script execution off by default.
- Treat binary/decompiler/script output as untrusted.
- Do not automatically retry an uncertain mutation over another transport.

## Shell scripts

- Call `getopt` unqualified and let `$PATH` resolve it. On this machine that is GNU
  `getopt` (util-linux, from Homebrew `gnu-getopt`), which sits on `$PATH` ahead of
  `/usr/bin/getopt`.
- Never hardcode `/usr/bin/getopt`. That is the ancient BSD build: it has no long
  options, no `--`-terminated output, and mangles arguments containing whitespace.
- So long options work. Do not hand-roll a `while`/`case` argument parser or drop to
  short-only flags on the assumption that macOS `getopt` is too old — that assumption
  is what this section exists to correct.
- Use the standard GNU invocation and quote the result:

  ```bash
  args=$(getopt -o hv --long help,verbose -n "$0" -- "$@") || exit 1
  eval set -- "$args"
  ```

## Releases

Releasing is one command, run by the maintainer on a local checkout:

```bash
tools/release <major|minor|patch>
```

There is **no release automation in CI.** `.github/workflows/tests.yml` runs the gates
and uploads build artifacts; it does not tag or publish. Do not hand-roll a tag, a `gh
release`, or a version bump — `tools/release` does all of it in one ordered pass, and
does it in the order it does deliberately.

The version is semantic and lives in `pom.xml`, which is the single source of truth. The
extension and the bridge wheel are built from one commit and released together carrying
that one version: extension identity is `${project.version}`, and
`tools/bridge_version.py` derives the bridge version from the same pom. The
`release.timestamp` property is build metadata only, not release identity.

`tools/release` refuses unless the checkout is on `main`, clean, and exactly in sync with
`origin`. Anything failing before the push restores the working tree, index, and branch
ref, so a failed release is a no-op. The push is the one-way door; if publishing fails
after it, re-running the same command resumes from the existing tag instead of bumping
again.

### CHANGELOG

Add user-visible changes under `## Unreleased`. `tools/release` retitles that heading as
`## X.Y.Z` and inserts a fresh empty `## Unreleased` above it, and refuses to release
when `Unreleased` is empty. (Sections titled `## GhidraMCP-next <timestamp>` are
published history from the retired CI job. New releases are plain semver.)

The top of `CHANGELOG.md` is therefore a standing conflict point whenever a release has
landed since you branched:

- Add entries only under `## Unreleased`, never to a released section — those are
  published history.
- Before pushing, `git fetch` and rebase.
- **After rebasing, re-read the top of the file.** Git resolves this one cleanly and
  silently in the wrong way: your bullets sit at the same offset as the freshly-retitled
  release section, so they get absorbed into it and `Unreleased` is left empty. Nothing
  conflicts and nothing warns. Move your entries back under `## Unreleased`, recreating
  the `### Fixed`/`### Added` heading if the rebase consumed it.
- Sanity check: every bullet under a released section must already be in that published
  release. If you wrote it after that release was cut, it belongs under `Unreleased`.

### Do not test the release script

**Do not write tests for `tools/release`.** No unit tests, no fixtures, no mutation
checks, no CI assertions about it. Releasing is verified by running
`tools/release <major|minor|patch>` and seeing what happens; a test suite around it has
repeatedly cost more than it caught. If a release breaks, fix the script.

This is a standing instruction from the maintainer, not an oversight to correct.
