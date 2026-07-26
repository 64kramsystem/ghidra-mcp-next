# AGENTS.md

- Keep GUI and headless endpoint schemas in parity.
- When endpoint registrations change, update and verify `tests/endpoints.json`.
- Update `CHANGELOG.md` for user-facing changes.
- Never use conventional-commit prefixes (`feat/`, …) in commit titles or branch names

## CHANGELOG and the release automation

A green push to `main` triggers a release that renames the `## Unreleased` heading to
`## GhidraMCP-next <timestamp>` and appends a fresh, empty `## Unreleased` above it. Anything
sitting under `Unreleased` at that moment ships as part of that release.

This makes the top of `CHANGELOG.md` a standing conflict point. To avoid it:

- Add entries only under `## Unreleased`, never to a timestamped section — those are published
  history.
- Before pushing, `git fetch` and rebase. A release commit may have landed since you branched.
- **After rebasing, re-read the top of the file.** Git resolves this one cleanly and silently in
  the wrong way: your bullets sit at the same offset as the freshly-renamed release section, so
  they get absorbed into it and `Unreleased` is left empty. Nothing conflicts and nothing warns.
  Move your entries back under `## Unreleased`, recreating the `### Fixed`/`### Added` heading if
  the rebase consumed it.
- Sanity check: every bullet under a timestamped section must already be in that published
  release. If you wrote it after that release was cut, it belongs under `Unreleased`.

## Shell scripts

- Call `getopt` unqualified and let `$PATH` resolve it. On this machine that is GNU
  `getopt` (util-linux, from Homebrew `gnu-getopt`), which sits on `$PATH` ahead of
  `/usr/bin/getopt`.
- Never hardcode `/usr/bin/getopt`. That is the ancient BSD build: it has no long
  options, no `--`-terminated output, and mangles arguments containing whitespace.
- So long options work. Do not hand-roll a `while`/`case` argument parser or drop to
  short-only flags on the assumption that macOS `getopt` is too old — that assumption
  is what this section exists to correct.
- Use the standard GNU invocation and quote the result:

  ```bash
  args=$(getopt -o hv --long help,verbose -n "$0" -- "$@") || exit 1
  eval set -- "$args"
  ```

## Verification

- Java: `mvn test`
- Python: `uv run pytest tests/unit/ -v --no-cov`
- Package: `mvn clean package assembly:single -DskipTests`
- Quick compile: `mvn clean compile -q`

## Releasing

- **Do not write tests for the release script.** No unit tests, no fixtures, no
  mutation checks, no CI assertions about it. Releasing is verified by running
  `tools/release <major|minor|patch>` and seeing what happens; a test suite around
  it has repeatedly cost more than it caught. If a release breaks, fix the script.
- This is a standing instruction from the maintainer, not an oversight to correct.
