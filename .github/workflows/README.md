# GitHub Workflows

| File | Purpose |
| --- | --- |
| `tests.yml` | Pull-request and push gates for Python, Java/Maven, catalog, packaging, and documentation contracts. |
| `release.yml` | Stable release validation and artifact publication. |

## Pull requests

`tests.yml` is the normal merge gate. Live Ghidra regression is run locally
because hosted runners do not have a prepared Ghidra installation and project.

The supported build used in CI is Maven:

```bash
python -m tools.setup build
mvn clean package assembly:single -DskipTests
```

## Live regression

Live regression needs Java 21, Maven, Python/uv, a compatible Ghidra
installation, and a disposable local project/fixture.

See [`../../docs/TESTING.md`](../../docs/TESTING.md) for local equivalents and
for the distinction between offline gates, expected skips, and executed live
coverage.
