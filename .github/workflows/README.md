# GitHub Workflows

| File | Purpose |
| --- | --- |
| `tests.yml` | Pull-request and push gates for Python, Java/Maven, catalog, packaging, and documentation contracts; release-worthy green `main` pushes also publish timestamp builds. |

## Pull requests

`tests.yml` is the normal merge gate. Live Ghidra regression is run locally
because hosted runners do not have a prepared Ghidra installation and project.

The supported build used in CI is Maven:

```bash
python -m tools.setup build
mvn clean package assembly:single -DskipTests
```

## Timestamp builds

A green, release-worthy push to `main` publishes the extension ZIP, Python
wheel and source distribution from that exact workflow run. Release names use
`GhidraMCP-next <UTC timestamp>` and tags use
`build-<UTC timestamp>-<12-character commit>`.

The workflow examines the complete push range and skips publication when no
distributed plugin or bridge input changed. Manual dispatches from `main`
publish explicitly. Release creation is serialized without canceling an
in-flight publication, and only that job receives `contents: write`.

Each timestamp release includes `release-metadata.json` and `SHA256SUMS` with
the Ghidra version, build timestamp, commit, sizes, and artifact hashes. After
publication, the workflow moves the `Unreleased` changelog entries under the
timestamp release heading and pushes that changelog-only commit as
`github-actions[bot]`.

## Live regression

Live regression needs Java 21, Maven, Python/uv, a compatible Ghidra
installation, and a disposable local project/fixture.

See [`../../docs/TESTING.md`](../../docs/TESTING.md) for local equivalents and
for the distinction between offline gates, expected skips, and executed live
coverage.
