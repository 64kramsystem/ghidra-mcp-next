# Version management

Use the repository helper for every version change:

```bash
python -m tools.setup bump-version --new X.Y.Z
python -m tools.setup verify-version
```

The bump command updates all maintained version locations atomically,
including `pom.xml`, Python package metadata, lock data, and runtime resource
fallbacks. Do not edit just one version file by hand.

After a bump, run:

```bash
python -m tools.setup verify-version
mvn clean package assembly:single -DskipTests
uv build
uv lock --check
uv run pytest tests/unit/ -v --no-cov
```

Maven filters `src/main/resources/version.properties` and
`src/main/resources/extension.properties` during the build. The resulting JAR
and extension ZIP must contain the requested version rather than an unresolved
`${project.version}` placeholder.

Record user-facing changes in `CHANGELOG.md`, but keep command examples and
general documentation version-neutral whenever possible.
