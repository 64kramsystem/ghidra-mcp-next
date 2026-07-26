# Semantic versioning and scripted releases — design

Date: 2026-07-26
Status: approved decisions, not yet implemented
Scope: three repositories — `ghidra-mcp-next`, `ghidra-vice-connector`, `ghidra-mcp-c64`

## Why

CI-published releases are being retired. The release jobs are already deleted
(`ghidra-mcp-next` `97657b3`, `ghidra-vice-connector` `83d9994`), so nothing
publishes today. Releasing moves to a per-repo script run locally, and version
identity moves from build timestamps to semantic versions.

Two concrete defects motivated dropping the automation rather than repairing it:

- **The release commit fought local work.** `ghidra-mcp-next`'s job ended by
  rolling `CHANGELOG.md` and pushing to `main`. That commit inserted a version
  heading directly beneath `## Unreleased`, and a later automatic merge filed a
  new entry *underneath* it — inside a release that did not contain it, with
  `## Unreleased` left empty.
- **Timestamp versions break for ten hours a day.** PEP 440 strips leading zeros
  from release segments, so a bridge built at 09:30 UTC produces version
  `20260726.93000`, which the `^[0-9]{8}\.[0-9]{6}$` validation in both
  `tools/bridge_version.py` and `tools/release_automation.py` then rejects.
  Semantic versions have no such hazard.

## Decisions

Settled with the maintainer before design; recorded so they are not
re-litigated.

| Decision | Choice |
| --- | --- |
| Version selection | Script flag: `--major` / `--minor` / `--patch` computes and writes the next version |
| Starting version | **0.99.0** in all three repositories |
| Connector semver home | Git tag is authoritative, plus a separate property in the packaged extension |
| Script location | Per-repo `tools/release`; runs that repo's gates; does **not** push |

`0.99.0` is a deliberate pre-1.0 marker. Under semver, `0.x` grants permission
to break on a minor bump, so this states "approaching stable" without yet
promising compatibility.

## Version sources of truth

### ghidra-mcp-next

`pom.xml` `<version>` becomes the single source. It currently holds the sentinel
`0.0.0` with identity supplied by `release.timestamp`; that indirection goes.

- `<version>0.99.0</version>`, and the sentinel comment is removed.
- `<finalName>` becomes `${project.artifactId}-${project.version}`, so the
  extension zip is `GhidraMCP-next-0.99.0.zip`. `update_ghidra`'s glob
  (`target/GhidraMCP-next-*.zip`) still matches.
- `src/main/resources/extension.properties` keeps `version=${ghidra.version}` —
  **Ghidra owns that field and gates installation on it.** Its `description`
  drops `Build ${release.timestamp}` in favour of the project version, and a new
  key carries the semver:

  ```properties
  version=${ghidra.version}
  pluginVersion=${project.version}
  ```

- **The bridge version reads the pom** rather than deriving a timestamp from git
  history. `tools/bridge_version.py` already has a sibling that parses the pom
  (`tools.setup.versioning.read_pom_ghidra_version`), so
  `get_bridge_version()` returns the pom `<version>` and the
  `GHIDRA_MCP_BRIDGE_VERSION` override validates as semver.

  This deliberately couples the wheel and the extension to one version. They are
  built from one commit and released together; two independently-timestamped
  versions for one release was a source of confusion, not flexibility.

- `release.timestamp` and `maven.build.timestamp.format` are removed once nothing
  reads them. The build stops being timestamp-identified, which also makes
  repeated builds of one commit produce identical artifact names.

### ghidra-vice-connector

No version exists anywhere today. `gradle.properties` gains
`version=0.99.0`, Gradle's native version property.

`extension.properties` currently reads `version=12.1.2` — the Ghidra version,
written by hand. It stays that way, because Ghidra requires it. `build.gradle`
appends a separate key to the packaged copy:

```properties
connectorVersion=0.99.0
```

so an installed extension can report which build it is. The uploaded asset keeps
the name Ghidra's own `buildExtension.gradle` produces
(`ghidra_12.1.2_PUBLIC_<date>_ghidra-vice-connector.zip`): it already states the
target Ghidra version, and renaming it would break `update_ghidra`'s glob for no
gain. The semver appears in the tag and release title instead.

### ghidra-mcp-c64

`pyproject.toml` `version` moves from `0.1.0` to `0.99.0`, static, rewritten by
the script. No release script is added: nothing consumes a c64 release, it is
launched from a local venv path, and its compatibility with the connector rests
on the `c64.vice/1` runtime handshake rather than version pairing.

Bumping its version is therefore a versioning change only. If a PyPI channel
ever appears, a release script can follow.

## The release script

`tools/release` in `ghidra-mcp-next` and in `ghidra-vice-connector`. Python, to
match both repos' existing tooling and so it can be tested with pytest.

### Two phases, because "no push" and `gh release create` conflict

`gh release create` needs its target commit to exist on the remote. A script
that neither pushes nor publishes cannot exist, so the work splits:

```text
tools/release prepare --minor     # gates, version write, changelog roll, commit, tag, build
git push && git push --tags       # the maintainer's own hands
tools/release publish             # gh release create from the existing tag and built assets
```

`prepare` leaves a signed-off local state and stops. `publish` refuses unless the
tag it is publishing exists on the remote, which is what makes the pause
meaningful rather than decorative.

### `prepare`

Ordered, and it stops at the first failure:

1. **Refuse a dirty working tree**, and refuse to run off the default branch
   (`main` / `master`). A release must describe a committed state.
2. **Run the repo's gates.** `ghidra-mcp-next`: `mvn clean compile`, `mvn test`,
   `uv run pytest tests/unit/`. `ghidra-vice-connector`:
   `python -m pytest tests/ --ignore=tests/test_live_vice.py`. A red suite must
   make a release impossible, which is the one property CI provided that a script
   could quietly lose.
3. **Refuse an empty `## Unreleased` section.** A release with no recorded
   changes is a mistake, not a no-op.
4. **Compute the next version** from the current one and the bump flag, and
   refuse if the resulting tag already exists locally or on the remote.
5. **Write the version** to the repo's source of truth, and to any file derived
   from it.
6. **Roll the changelog**: `## Unreleased` becomes `## <version>`, and a fresh
   empty `## Unreleased` is inserted above it. Inserting the new heading *above*
   is what prevents the misfiling described earlier.
7. **Commit** (`Release 0.99.0`) and **tag** `v0.99.0` — annotated, so the tag
   carries the changelog section as its message.
8. **Build** the artifacts and verify the produced names match the new version.

### `publish`

1. Resolve the version from the current tag; refuse if `HEAD` is not tagged.
2. Refuse unless that tag is present on the remote (`git ls-remote --tags`).
3. Refuse unless the built artifacts for that exact version are present.
4. `gh release create` with the changelog section as notes, the artifacts as
   assets, and `SHA256SUMS` generated over them.
5. `--latest` is set for `ghidra-vice-connector`, whose releases are its only
   distribution channel, and not for `ghidra-mcp-next`, which is built locally
   and whose releases are a record. This is a per-repo constant, not a flag.
6. Verify every expected asset is present on the created release, failing loudly
   if not — the check the old CI job performed and worth keeping.

### What happens to the existing modules

`tools/release_automation.py` is reworked rather than deleted: `prepare_release`
and `roll_changelog` keep their shape, losing timestamp validation and gaining
semver. `should_publish` / `path_affects_release` and the classify subcommand are
**deleted** — they existed to decide whether a push deserved a release, and an
explicitly invoked script needs no such guess. `tests/unit/test_release_automation.py`
is updated in step with it.

## Tests

Both scripts, driven from their repo's existing framework:

- version arithmetic for each bump flag, including `0.99.0 --minor` → `0.100.0`
  (not `1.0.0`; a reviewer should be able to see that this is deliberate)
- dirty tree, wrong branch, empty `## Unreleased`, and existing-tag refusals
- changelog roll inserts the new `## Unreleased` **above** the released heading,
  and a second consecutive release does not nest or duplicate headings
- `publish` refuses when `HEAD` is untagged, when the tag is absent from the
  remote, and when artifacts are missing or carry a different version
- the version reaches every derived file: for `ghidra-mcp-next`, the pom, the
  bridge version, `pluginVersion` in the packaged `extension.properties`, and the
  zip name; for the connector, `gradle.properties` and `connectorVersion`
- gates are actually invoked, and a failing gate aborts before any file is
  written — asserted by injecting a failing command, not by counting calls

Every one of these must be shown to fail against a deliberately broken
implementation before it is trusted. Three tests in the preceding session's work
passed against code that was provably wrong, in each case because they asserted
that machinery had been *invoked* rather than that it had an *effect*.

## Out of scope

- Publishing `ghidra-mcp-c64` anywhere, and any PyPI publication for the bridge.
- Retagging or rewriting the existing timestamp releases. They stay as they are;
  semver starts at `0.99.0` alongside them.
- Any shared release library across repositories. Two small scripts are
  preferred over one abstraction spanning Maven and Gradle; if a third consumer
  ever appears, that is the moment to extract.
