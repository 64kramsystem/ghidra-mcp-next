# Tools

`tools/setup/` is the maintained setup, build, and deploy CLI.

```bash
python -m tools.setup --help
python -m tools.setup preflight --ghidra-path /path/to/ghidra
python -m tools.setup ensure-prereqs --ghidra-path /path/to/ghidra
python -m tools.setup build
python -m tools.setup deploy --ghidra-path /path/to/ghidra
python -m tools.setup verify-ghidra --ghidra-path /path/to/ghidra
```

## Command responsibilities

- `preflight` reports environment and Ghidra-path problems without building.
- `ensure-prereqs` prepares Python dependencies and installs Ghidra Java
  artifacts into the local Maven repository.
- `build` invokes the Maven package path.
- `deploy` installs the freshest extension archive into the selected Ghidra
  profile and performs the requested smoke/release checks.
- `verify-ghidra` checks an installation against the configured Ghidra
  compatibility target.

Release builds derive the Ghidra extension identity from the build timestamp.
The Python bridge version is independently derived from the latest Git commit
that changed bridge or bridge-packaging inputs.

Manual Java packaging remains available:

```bash
mvn clean package assembly:single -DskipTests
```

## Tests

```bash
uv run pytest \
  tests/unit/test_setup_cli.py \
  tests/unit/test_setup_ghidra.py \
  tests/unit/test_setup_requirements.py \
  tests/unit/test_versioning.py \
  -v --no-cov
```

New general-purpose reverse-engineering functionality usually belongs in a Java
service endpoint. Trusted in-Ghidra utilities belong in the reviewed
`ghidra_scripts/` allowlist with inventory tests.
