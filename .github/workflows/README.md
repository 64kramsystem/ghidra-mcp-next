# GitHub Workflows

| File | Purpose |
| --- | --- |
| `tests.yml` | Pull-request and push gates for Python, Java/Maven, catalog, packaging, and documentation contracts. |
| `release-regression.yml` | Optional live deployment/regression on a prepared self-hosted Windows runner. |
| `release.yml` | Stable release validation and artifact publication. |
| `pre-release.yml` | Manually initiated prerelease validation and artifacts. |
| `codeql.yml` | CodeQL security analysis. |
| `scorecard.yml` | OpenSSF Scorecard analysis. |

## Pull requests

`tests.yml` is the normal merge gate. The live Ghidra workflow is opt-in because
hosted runners do not have a prepared Ghidra installation and local project.
When a trusted self-hosted runner is available, the `live-ghidra-regression`
label can request the live path configured by the workflow.

The supported build used in CI is Maven:

```bash
python -m tools.setup build
mvn clean package assembly:single -DskipTests
```

## Live runner expectations

A live regression runner needs Java 21, Maven, Python/uv, a compatible Ghidra
installation, and a disposable local project/fixture. Secrets should use
GitHub's protected secret store and must not be written into workflow logs.

See [`../../docs/TESTING.md`](../../docs/TESTING.md) for local equivalents and
for the distinction between offline gates, expected skips, and executed live
coverage.
