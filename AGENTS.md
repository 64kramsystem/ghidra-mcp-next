# Agent instructions

- `$GHIDRA_INSTALL_DIR` identifies the installation
- Use `$GHIDRA_SOURCE_DIR` when source can replace guesswork
- Run GhidraMCP-next's Java tests with `mvn -Dghidra.test.install.dir="$GHIDRA_INSTALL_DIR" test`; the environment variable alone does not activate Maven's Ghidra runtime-library profile.
- For listing-wrap tests, assert the expected line breaks and that each automatic wrap fits as many whole words as the configured width allows.
- Record public-contract changes in `CHANGELOG.md`; release via `tools/release <major|minor|patch>`, following semver
