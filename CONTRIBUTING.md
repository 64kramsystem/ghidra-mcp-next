# Contributing

Thanks for improving Ghidra MCP. Changes should preserve the local-first
architecture, GUI/headless endpoint parity, and the catalog contracts that keep
the Python bridge aligned with the Java extension.

## Development environment

Install Java 21, Maven 3.9+, Python 3.10+, `uv`, and a compatible Ghidra
installation. Then prepare the locked Python environment and Ghidra Java
dependencies:

```bash
uv sync
python -m tools.setup ensure-prereqs --ghidra-path /path/to/ghidra_12.1.2_PUBLIC
mvn clean compile -q
```

The supported Java build paths are:

```bash
python -m tools.setup build
mvn clean package assembly:single -DskipTests
```

## Branch and pull-request workflow

1. Create a focused branch from current `main`.
2. Add a failing test or characterization contract before changing behavior.
3. Make the smallest coherent implementation and update affected docs/catalogs.
4. Run focused tests, then the supported full gates.
5. Push the branch and open a pull request. Do not push feature work directly
   to `main`.

Keep unrelated changes out of the branch. Preserve existing user edits and line
endings in files you did not need to touch.

## Required verification

At minimum:

```bash
uv run pytest tests/unit/ -v --no-cov
mvn test
mvn clean compile -q
git diff --check
```

For release or packaging changes also run:

```bash
mvn clean package assembly:single -DskipTests
uv build
uv lock --check
```

Live integration suites require an explicitly prepared local Ghidra instance.
Do not report skipped live tests as executed coverage.

## Endpoint changes

Java `@McpTool` registrations and `tests/endpoints.json` must change together.
Regenerate the catalog and verify parity:

```bash
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
mvn test -Dtest=EndpointsJsonParityTest
uv run pytest tests/unit/test_endpoint_catalog.py -v --no-cov
```

Preserve catalog-only parameter metadata when regenerating. New GUI endpoints
should be assessed for headless parity; intentional differences need a test and
documentation.

## Architecture boundaries

- Local GUI and headless projects are the supported project model.
- Keep the bridge a thin MCP-to-HTTP multiplexer; analysis belongs in the Java
  service layer.
- Preserve the 18 schema-discovered TraceRMI tools and their clean
  `debugger_*` names.
- Do not claim planned attach/wait/map/copy debugger operations before they
  exist and have endpoint/catalog tests.
- Names and comments supplied by callers pass to Ghidra unchanged. Ghidra
  remains responsible for syntax, duplicate-name, datatype, and transaction
  constraints.
- Local comparison endpoints return evidence; they do not apply documentation
  across binaries.
- BSim is optional and explicitly configured by the caller.
- Arbitrary script execution remains gated by `GHIDRA_MCP_ALLOW_SCRIPTS`.

## Adding or changing Ghidra scripts

`ghidra_scripts/` is an exact generic allowlist. A retained script must:

- accept caller input or current GUI context instead of embedding application
  addresses;
- contain no application-specific convention or server workflow;
- avoid remote service defaults;
- state whether it mutates the program; and
- be covered by `tests/unit/test_ghidra_script_inventory.py`.

Prefer native MCP endpoints when the operation is generally useful and can be
implemented safely in the service layer.

## Documentation

Update maintained documentation in the same pull request as a user-visible
change. Current docs must name real endpoint/tool names, supported commands,
and actual limitations. Historical changelog entries may describe old
releases, but current guides must not present retired surfaces as available.

## Releases

User-visible changes require an entry under `Unreleased` in `CHANGELOG.md`.
Version changes must use the atomic helper:

```bash
python -m tools.setup bump-version --new X.Y.Z
python -m tools.setup verify-version
```

Do not edit version-bearing files individually.
