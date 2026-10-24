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
  profile and starts the configured installation.
- `verify-ghidra` checks an installation against the configured Ghidra
  exact 12.2 target.

The extension and Python bridge share the semantic release version in `pom.xml`.
Build timestamps are metadata only. Build and run with JDK 25.

Run all Java fixtures with:

```sh
python -m tools.setup run-tests --ghidra-path /path/to/ghidra_12.2_PUBLIC
```

Manual Java packaging remains available:

```bash
mvn clean package assembly:single -DskipTests
```

General-purpose reverse-engineering functionality belongs in a Java service endpoint.
