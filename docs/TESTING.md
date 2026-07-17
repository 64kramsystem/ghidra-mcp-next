# Testing

The supported test strategy separates deterministic offline contracts from
tests that require a particular Ghidra installation, GUI state, trace, or
operating system.

## Python unit suite

Use the locked project environment so pytest plugins and configured options are
available:

```bash
uv run pytest tests/unit/ -v --no-cov
```

Important contracts include:

- endpoint catalog shape and bridge name normalization;
- setup/build/deploy planning;
- local project creation and multi-instance routing;
- absence of retired architecture dependencies;
- preservation of FileZilla static-analysis and TraceRMI workflows;
- the exact generic Ghidra-script inventory; and
- the maintained documentation surface.

Some process-detection cases are intentionally skipped on non-Windows hosts;
the skip reason is reported by pytest.

## Java tests

Run all Java tests:

```bash
mvn test
```

Run a focused offline contract:

```bash
mvn test -Dtest='com.xebyte.offline.DebuggerServiceContractTest,com.xebyte.offline.EndpointsJsonParityTest'
```

The Maven suite includes pure/offline service tests plus a small number of
Ghidra-dependent tests that skip when their fixture environment is unavailable.
Always report pass and skip counts separately.

## Endpoint catalog regeneration

For an endpoint registration or description change:

```bash
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
mvn test -Dtest=EndpointsJsonParityTest
uv run pytest tests/unit/test_endpoint_catalog.py -v --no-cov
```

Inspect the catalog diff. The merge-aware generator preserves curated
catalog-only parameter metadata, so an unexpected broad rewrite is a defect.

## Compile, package, and Python distribution

```bash
mvn clean compile -q
mvn clean package assembly:single -DskipTests
uv build
uv lock --check
```

`python -m tools.setup build` must remain equivalent to the supported Maven
build path. Packaging verification should inspect both the extension archive
and the Python wheel rather than accepting a command's exit code alone.

## Live GUI and headless tests

Live integration tests are supplemental. Prepare a disposable local project,
load a known binary, enable/start Ghidra MCP, and then run only the appropriate
marked suite. For example:

```bash
GHIDRA_MCP_LIVE_TESTS=1 \
  uv run pytest tests/integration/test_global_endpoints.py -v -m safe_write --no-cov
```

Safe-write tests read the original state and restore it in a `finally` block.
Use a disposable project anyway. Do not run mutating tests against the only copy
of an analysis project.

Headless release checks should use a local project directory and an isolated
port. GUI and headless parity is asserted offline where possible; behavior that
depends on a real Ghidra process must be reported as unexecuted if that process
was unavailable.

For a local GUI installation, the deploy contract check verifies the live
schema and protected workflow routes on the installed extension:

```bash
uv run python -m tools.setup deploy \
  --ghidra-path /path/to/ghidra \
  --test selected-contract
```

When project lifecycle code changes, additionally switch between disposable
projects once through TCP and once through the Unix socket. Both schemas must
contain the same paths, and reopening the original project must succeed without
Ghidra reporting multiple active projects.

## TraceRMI testing

Offline tests protect the 18 route names, address-mapping/copy semantics, and
clean bridge names. A live dynamic check additionally needs a Ghidra debugger
agent and a suitable target:

```text
load_tool_group("debugger")
debugger_launch_offers()
debugger_launch(...)
debugger_status()
debugger_set_breakpoint(...)
debugger_resume()
debugger_read_memory(...)
```

The four roadmap operations—generic attach, wait-for-stop, process map, and
copying trace memory into a program block—are not live-test expectations until
their endpoints exist.

## BSim and script testing

Offline source contracts verify that BSim has no implicit host, each script
uses the correct URL argument position, query operations are read-only, and the
retained inventory contains no application addresses or server workflow.

An optional live BSim check requires enabling trusted scripts and supplying a
URL supported by the installed Ghidra client, such as
`file:/absolute/path/to/local-bsim`:

```text
run_ghidra_script(script_name="BSimTestConnection.java", args=[...])
```

## Before committing

```bash
uv run pytest tests/unit/ -v --no-cov
mvn test
mvn clean compile -q
git diff --check
```

Before merging, also run the package gates and inspect `git status` for
generated reports or unrelated files.
