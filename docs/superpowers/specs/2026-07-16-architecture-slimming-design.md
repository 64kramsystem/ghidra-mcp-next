# Architecture Slimming Design

**Status:** Approved for specification on 2026-07-16

**Branch:** `refactor/remove-unused-subsystems`

**Scope:** Remove unused subsystems while preserving local reverse engineering,
TraceRMI debugging, and the extension points required by four planned debugger
features.

## Context

The repository has grown into a broad reverse-engineering platform containing
local analysis, shared Ghidra Server workflows, documentation propagation,
application-specific scripts, two unrelated debugger stacks, multiple build
systems, Docker support, and an external BSim deployment assumption. The active
projects are local. Their useful core is narrower:

- FileZilla reverse engineering in local, persistent, multi-program Ghidra
  projects;
- Windows-application analysis under Wine, combining a static PE program with a
  live GDB/TraceRMI trace;
- generic local binary comparison and optional local BSim assistance; and
- GUI and headless access to the same analysis endpoints.

The change will remove unused product surface by cutting one dependency cluster
at a time. It will not replace the current fork architecture or attempt a rewrite.

## Goals

1. Remove unused infrastructure, product-specific automation, and duplicated
   build/deployment paths.
2. Keep local reverse-engineering workflows intact in GUI and headless modes.
3. Keep Ghidra's built-in TraceRMI debugger integration intact while removing the
   separate Windows-only dbgeng HTTP proxy.
4. Preserve explicit seams for these planned TraceRMI additions:
   - generic attach using a selected launch offer and PID;
   - `debugger_wait_for_stop(timeout_ms)`;
   - process memory-map enumeration; and
   - `copy_debugger_memory_to_program`, which creates and populates a static
     program block from a trace range.
5. Add pragmatic regression and architectural tests before removing the code
   those tests protect.
6. Finish with accurate user, developer, build, and workflow documentation.

## Non-goals

- Implementing the four planned debugger features in this removal project.
- Replacing Ghidra's debugger agents, `ghidratrace`, or TraceRMI.
- Providing a Ghidra repository server, shared projects, check-in/check-out, or
  version-control workflows.
- Keeping D2-specific or other application-specific automation.
- Retaining a remote PostgreSQL BSim deployment as a default.
- Rewriting the extension around a new framework or transport.

## Protected Workflows

### FileZilla static analysis

The retained surface must support the procedure demonstrated by
`/home/saverio/code/filezilla_reversing/REGISTRATION_PROTECTION_ANALYSIS.md`:

- create, open, switch, save, and reopen local Ghidra projects;
- import and analyze multiple executables and libraries;
- search strings, symbols, bytes, operands, and functions;
- follow xrefs and call graphs;
- inspect listings, decompile functions, and repair damaged flow/function
  boundaries;
- read and create memory blocks;
- define data types, labels, functions, comments, and prototypes without a
  project-specific naming policy;
- run explicitly enabled generic Ghidra scripts; and
- compare functions locally or use an explicitly configured local BSim database.

The optional BSim layer assists with recognizing open-source dependencies such
as libfilezilla, wxWidgets, and crypto libraries. It is not required for the
proprietary registration state machine and must not become a prerequisite for
ordinary analysis.

### Wine dynamic analysis

There are two distinct Wine cases:

1. A defect in Wine's own open-source implementation is principally a Wine
   source, GDB, build, and test-suite task. ghidra-mcp may provide supporting
   disassembly evidence but is not the source-patching workflow.
2. A proprietary Windows application running under Wine is the protected
   ghidra-mcp workflow. A static PE in a local Ghidra project is correlated with
   a live Wine/GDB process through Ghidra's built-in TraceRMI debugger.

The second workflow is:

```text
local static PE program
        <-> ghidra-mcp analysis and address tools
        <-> Ghidra TraceRMI / GDB launcher
        <-> Windows process running under Wine
```

It must remain possible to select a launch offer, launch the process, control
execution, manage breakpoints, inspect registers/stack/modules/live memory, and
translate between static and dynamic addresses. The planned attach, bounded
wait, memory-map, and trace-copy tools will close the remaining launch-to-static
analysis loop without depending on the removed dbgeng proxy.

### TraceRMI tool-loading contract

The dynamic MCP tool group is `debugger`. In lazy mode it is loaded once with:

```text
load_tool_group("debugger")
```

The retained current tools are:

- `debugger_launch_offers`
- `debugger_launch`
- `debugger_status`
- `debugger_traces`
- `debugger_resume`
- `debugger_interrupt`
- `debugger_step_into`
- `debugger_step_over`
- `debugger_step_out`
- `debugger_set_breakpoint`
- `debugger_remove_breakpoint`
- `debugger_list_breakpoints`
- `debugger_registers`
- `debugger_read_memory`
- `debugger_stack_trace`
- `debugger_modules`
- `debugger_static_to_dynamic`
- `debugger_dynamic_to_static`

There is no generic TraceRMI attach endpoint in version 5.15.0. The existing
`debugger_attach` name belongs to the Windows-only standalone dbgeng proxy and
must not be documented as the Wine attach path. The future TraceRMI endpoint name
and signature will be specified when that feature is designed. Likewise,
`debugger_wait_for_stop`, process memory maps, and debugger-memory copy do not yet
exist and must not be simulated with invented tool calls or unbounded polling.

## Retained Architecture

### Core lifecycle and transports

Retain:

- local `.gpr` project creation, import, persistence, activation, and switching;
- simultaneous access to multiple local programs;
- GUI plugin and local headless operation;
- annotation-scanned endpoint registration and `/mcp/schema`;
- endpoint catalog and GUI/headless parity checks;
- TCP and Unix-domain-socket transports; and
- existing local lifecycle and discovery behavior.

### Security

`SecurityConfig` stays. It is not merely Ghidra Server authentication: it gates
script execution, constrains imported files, scopes local project folders, and
supports the MCP bearer token. Only repository-server authentication and shared
repository/version-control classes leave.

### Generic comparison

Retain these public, pure-local tools and move them to the binary-comparison
boundary:

- `get_function_hash`
- `get_bulk_function_hashes`
- `get_function_signature`
- `find_similar_functions_fuzzy`
- `bulk_fuzzy_match`
- `diff_functions`

Their shared private helpers must be disentangled from documentation archives,
persistent hash indexes, anchors, and propagation rather than copied blindly or
deleted with the enclosing service.

### BSim and scripts

Retain generic script execution and the four generic BSim wrappers. Remove their
hard-coded remote PostgreSQL default and require explicit configuration suitable
for a local BSim database. Retain other genuinely generic repair, comment, and
external-address/IAT utilities that support normal analysis. Remove scripts that
encode D2 addresses, D2 conventions, documentation propagation, or another
specific application's procedure.

### Naming and annotations

Remove repository-specific naming rejection, warnings, prompt policy, and
implicit Hungarian prefixes. Labels, globals, functions, variables, and struct
fields should use the caller's supplied names. Ghidra remains the authority for
syntax, duplicates, and other model constraints; existing handlers must continue
turning Ghidra exceptions into structured MCP errors.

After call sites are removed, delete orphaned naming configuration and policy
classes unless a retained endpoint has a demonstrated generic use.

## Removal Boundaries

### Standalone debugger proxy

Remove together:

- the root `debugger/` dbgeng server and engine;
- `python/bridge_mcp_ghidra/debugger.py`;
- `GHIDRA_DEBUGGER_URL` and proxy registration/configuration;
- proxy-only static tool-name reservations;
- proxy-specific tests and packaging dependencies; and
- WinDbg/D2 conventions used only by that proxy.

Do not remove or rename the schema-discovered Java `DebuggerService` TraceRMI
tools, Ghidra debugger-agent setup, or `ghidratrace` installation support. Once
the proxy reservations disappear, the TraceRMI tools must have stable, clean
`debugger_*` MCP names on every supported host.

`schema.py` normalization is authoritative for MCP-visible dynamic tool names,
not the stale proxy-reservation comment currently in `config.py`. Before removal,
the characterization test must prove that clean `debugger_*` names already apply
to TraceRMI on Linux when the proxy is inactive. The proxy slice removes that
stale comment together with `DEBUGGER_TOOL_NAMES` and `GHIDRA_DEBUGGER_URL`.

Before deleting the proxy, preserve its engine-neutral address-translation and
trace-range-to-static-block semantics as explicit contracts and characterization
fixtures for the retained TraceRMI/static-program seams. This preserves an
executable reference for the future features without retaining WinDbg itself.

`debugger_launch_offers` already returns all Ghidra offers and exposes
image-support flags as data. It must receive a regression contract, not an
unnecessary filtering rewrite. Future PID attach will choose an attach-capable
offer from this complete set rather than assuming every offer has an image
parameter.

The concrete retained seam for each planned feature is:

| Planned feature | Retained, testable seam |
| --- | --- |
| Generic PID attach | complete `debugger_launch_offers` pass-through and launch-parameter metadata |
| Bounded wait for stop | `debugger_status` execution-state reporting; there is no wait endpoint yet |
| Process memory maps | `debugger_modules` and `debugger_read_memory`; there is no map endpoint yet |
| Trace memory to static program | `debugger_read_memory`, `debugger_static_to_dynamic`, `debugger_dynamic_to_static`, and `create_memory_block` |

Tests assert that these endpoints and their relevant parameters survive. They do
not claim that the four future operations already exist.

### Ghidra repository server

Remove repository-server connection, login/auth initialization, binding,
check-in/check-out, shared project, and version-control surfaces. Surgically
decouple retained GUI and headless local-project services, especially any
constructor or diagnostic dependency on the server manager. Do not remove local
project scope or bearer-token security.

### Documentation propagation and archives

Remove function-documentation archives, persistent hash indexes, cross-version
propagation, anchors, fuzzy documentation application, naming enforcement, and
related project-specific reports. “Fuzzy documentation application” means
propagating or applying documentation from a match; it does not include the
retained pure-local fuzzy matching primitives. First carve the generic comparison
endpoints and helpers into `BinaryComparisonService`. Endpoint catalog changes
occur in the same commit as registration changes.

### Build and deployment extras

Maven is the single supported Java build. Remove Gradle files, wrapper and
backend switches, Gradle-only tests, and Gradle workflow paths. Remove Docker
artifacts and Docker-only documentation. Keep `python -m tools.setup build`
working through Maven, along with Python wheel/uv packaging.

### Fun-doc, performance harnesses, and project-management archives

Remove fun-doc, its provider/database dependencies, its performance tests, and
its CI jobs together. Remove obsolete generated documentation, archived release
material, and internal project-management/RFC artifacts that describe deleted
systems. Preserve current user documentation and release history required to
understand the maintained product.

## Staged Change Strategy

Each slice is independently reviewable and keeps the branch buildable:

1. Establish protected endpoint/workflow contracts and a clean baseline.
2. Remove Gradle, Docker, obsolete project-management material, and their CI
   references while preserving Maven/tool-setup behavior.
3. Remove fun-doc, performance harnesses, dependencies, lockfile entries, and CI
   jobs.
4. Carve generic hashes/signatures/fuzzy/diff comparison into the retained
   service, then remove documentation archive/index/propagation endpoints.
5. Remove Ghidra repository-server auth/version control and decouple local GUI
   and headless project services.
6. Preserve debugger mapping/copy contracts, then remove the dbgeng server,
   bridge client, configuration, dependencies, and tests.
7. Remove naming enforcement and implicit prefixes, then delete orphaned policy
   code.
8. Triage scripts by generic applicability; localize BSim configuration.
9. Audit every document and example against the final endpoint and build surface.

Every slice updates affected GitHub workflows, `tests/endpoints.json`, Python
dependencies, and `uv.lock` in lockstep rather than leaving the branch or CI in a
known inconsistent state.

## Testing Strategy

### Characterization before deletion

Add tests before the related cut for:

- the protected FileZilla endpoint set and local multi-program/project lifecycle;
- the complete TraceRMI `debugger` group and stable public names;
- launch-offer pass-through, including non-image/attach-capable offers;
- engine-neutral static/dynamic address translation cases;
- trace-range validation and static memory-block creation/population semantics;
- retained function hash, signature, fuzzy-match, bulk-match, and diff behavior;
- generic script security gating;
- unrestricted rename/label/struct-field behavior; and
- GUI/headless endpoint parity.

Where a live Ghidra or debugger process is unavailable, test service contracts,
selection logic, parameter mapping, and state transitions offline. Live tests are
supplemental and their environmental limits must be documented; they are not
replaced by claims that unexecuted behavior works.

### Negative architecture contracts

Use dependency-free source-contract tests rather than adding ArchUnit or a Python
import-linter solely for this refactor:

- a Java offline test walks maintained Java sources and rejects imports or
  references to removed repository-server/authentication, documentation
  propagation, and legacy naming classes while explicitly allowing
  `SecurityConfig`;
- Python tests reject imports/references to the removed bridge debugger client,
  `GHIDRA_DEBUGGER_URL`, and proxy static-name reservations; and
- endpoint-catalog tests require protected FileZilla/TraceRMI tools and reject
  removed tools.

These tests should assert architectural outcomes, not incidental file counts.

### Per-slice gates

Run the narrow new or changed tests first, then as applicable:

```text
pytest tests/unit/ -v --no-cov
mvn test -Dtest='com.xebyte.offline.*Test'
mvn clean compile -q
```

Regenerate and verify `tests/endpoints.json` in every endpoint-changing slice.
At completion run the full supported unit/parity suite and:

```text
mvn clean package assembly:single -DskipTests
```

Also build the Python package and verify the Maven-backed `tools.setup` path.

## Documentation Strategy

Documentation is updated after the implementation surface stabilizes, but CI and
configuration references are corrected within the slice that removes their
feature. The final audit covers:

- installation and Maven-only build instructions;
- local GUI and headless project workflows;
- lazy tool groups and the exact TraceRMI `debugger` tool contract;
- the distinction between the removed dbgeng proxy and retained TraceRMI agents;
- Wine launch today and the four explicitly planned debugger gaps;
- local script security and optional local BSim configuration;
- endpoint totals/catalogs and examples;
- environment variables and dependency groups; and
- `CHANGELOG.md`.

No document may advertise Ghidra Server, fun-doc, Docker, Gradle, the standalone
dbgeng proxy, removed propagation/naming systems, or a hard-coded remote BSim
server as supported functionality.

## Review and Integration

- Claude reviews the design/specification, the high-fan-in service carves, the
  debugger boundary, and the final integrated diff.
- Major findings are resolved and re-reviewed before proceeding.
- Work remains on the feature branch until all supported verification passes.
- Push the feature branch and create a reviewable PR in accordance with project
  policy.
- Integrate with a merge commit (no squash or rebase merge), then verify and push
  the resulting mainline state.

## Acceptance Criteria

The project is complete when:

1. All named removal clusters and their stale documentation/dependencies are
   absent.
2. Local FileZilla-style reverse engineering remains covered by passing endpoint
   and behavior tests.
3. The retained TraceRMI dynamic path uses the `debugger` group and clean public
   names without the standalone proxy.
4. Tests preserve the concrete seam-to-endpoint map specified above for generic
   PID attach, bounded wait, memory-map enumeration, and trace-memory copying,
   without asserting that the four future endpoints already exist.
5. Local GUI/headless projects, multi-program analysis, generic scripts, optional
   local BSim, schema discovery, and supported transports remain intact.
6. Maven, Python unit tests, offline Java/parity tests, packaging, and maintained
   setup paths pass from a clean worktree.
7. Claude has no unresolved concrete major-review findings.
8. The final change is integrated by merge commit and present on the configured
   remote.
