# GitHub Workflows

| File | Purpose |
| --- | --- |
| `tests.yml` | Pull-request and push gates for Python, Java/Maven, catalog, packaging, and documentation contracts. Gates only: it publishes nothing. |

## Pull requests

`tests.yml` is the normal merge gate. Live Ghidra regression is run locally
because hosted runners do not have a prepared Ghidra installation and project.

The supported build used in CI is Maven:

```bash
python -m tools.setup build
mvn clean package assembly:single -DskipTests
```

## No release automation

CI does not release. It has no `contents: write`, creates no tag, and calls no
`gh release`. Releasing is a local command — see
[`../../docs/releases/README.md`](../../docs/releases/README.md).

What the workflow does upload, as ordinary run artifacts for inspection rather
than as published downloads, is `java-test-results` (surefire reports),
`jacoco-coverage-report` (an offline-tier baseline, not a gate), and
`GhidraMCP-next-artifact` (the packaged extension ZIP, kept here so the build
output stays available without a second workflow re-downloading Ghidra and
rebuilding).

## Live regression

Live regression needs Java 21, Maven, Python/uv, a compatible Ghidra
installation, and a disposable local project/fixture.

See [`../../docs/TESTING.md`](../../docs/TESTING.md) for local equivalents and
for the distinction between offline gates, expected skips, and executed live
coverage.
