# AGENTS.md

- Keep GUI and headless endpoint schemas in parity.
- When endpoint registrations change, update and verify `tests/endpoints.json`.
- Update `CHANGELOG.md` for user-facing changes.
- Never use conventional-commit prefixes (`feat/`, …) in commit titles or branch names

## Verification

- Java: `mvn test`
- Python: `uv run pytest tests/unit/ -v --no-cov`
- Package: `mvn clean package assembly:single -DskipTests`
- Quick compile: `mvn clean compile -q`

## Versioning

Use `python -m tools.setup bump-version --new X.Y.Z` for version bumps.
