# Semantic versioning and scripted releases — design

Date: 2026-07-26
Status: approved decisions, not yet implemented
Scope: three repositories — `ghidra-mcp-next`, `ghidra-vice-connector`, `ghidra-mcp-c64`

## Why

CI-published releases are retired. The release jobs are already deleted
(`ghidra-mcp-next` `4d57398`, `ghidra-vice-connector` `83d9994`), so nothing
publishes today. Releasing moves to a per-repo script run locally, and version
identity moves from build timestamps to semantic versions.

Two defects motivated dropping the automation rather than repairing it:

- **The release commit fought local work.** `ghidra-mcp-next`'s job ended by
  rolling `CHANGELOG.md` and pushing to `main`. That commit inserted a version
  heading directly beneath `## Unreleased`, and a later automatic merge filed a
  new entry *underneath* it — inside a release that did not contain it, with
  `## Unreleased` left empty.
- **Timestamp versions break for ten hours a day.** PEP 440 strips leading zeros
  from release segments, so a bridge built at 09:30 UTC becomes
  `20260726.93000`, which the `^[0-9]{8}\.[0-9]{6}$` validation in both
  `tools/bridge_version.py` and `tools/release_automation.py` then rejects.

## Decisions

Settled with the maintainer; recorded so they are not re-litigated.

| Decision | Choice |
| --- | --- |
| Version selection | Script flag: `--major` / `--minor` / `--patch` |
| Starting version | **0.99.0** in all three repositories |
| Connector semver home | `CONNECTOR_VERSION`, which it already publishes; git tag authoritative for releases |
| Script location | Per-repo `tools/release`; runs that repo's gates; does **not** push |

### Two consequences the maintainer accepted explicitly

- **The connector's published version goes down.**
  `src/main/py/src/vice/contracts.py` already holds
  `CONNECTOR_VERSION = "1.0.0"`, returned by `c64_vice_v1_status`. It becomes
  `0.99.0`. Verified safe: nothing compares it. `ghidra-mcp-c64` requires only a
  nonblank value (`vice_contract.py:91`); compatibility is decided by API
  major/minor, machine, method namespace, surface revision, binary-monitor API,
  capabilities and limits. Third-party consumers, if any exist, are unknowable.
- **`ghidra-mcp-next`'s new tags sort below its old ones.** It already has a
  semver line reaching `v6.0.0`, predating the timestamp releases. Starting again
  at `0.99.0` means anything ordering versions ranks `v6.0.0` highest
  indefinitely. This is a deliberate generation reset, not an oversight.

  **Therefore no script may derive the current version from the newest or
  highest tag.** The version is read from the repo's source of truth, and the tag
  is only written. This is a correctness requirement, not a style preference.

## Version sources of truth

### ghidra-mcp-next — `pom.xml` `<version>`

Currently the sentinel `0.0.0`, with identity supplied by `release.timestamp`.
It becomes `0.99.0` and the sentinel comment goes.

`release.timestamp` has more consumers than an earlier draft of this spec
assumed, and they split into two kinds:

| Consumer | Change |
| --- | --- |
| `<finalName>` (`pom.xml`) | `${project.artifactId}-${project.version}` → `GhidraMCP-next-0.99.0.zip` |
| `version.properties` `app.version` | `${project.version}` |
| `META-INF/MANIFEST.MF` `Plugin-Version` | `${project.version}` |
| `extension.properties` `description` | drops `Build ${release.timestamp}`, states the version |
| `version.properties` `build.timestamp`, `build.number` | **keep as timestamps**, backed by `maven.build.timestamp` |

That last row matters: `build.timestamp` and `build.number` are read by
`VersionPayload.java` and surfaced through the bridge handshake
(`handshake.py`). Putting `0.99.0` into a field named `build_timestamp` would
make the field lie. So `release.timestamp` and
`maven.build.timestamp.format` **stay**, scoped to build metadata only, and CI's
existing `-Drelease.timestamp` remains harmless.

Tests asserting a timestamp-shaped `app.version` must move to semver:
`VersionPayloadTest.java`, `tests/unit/test_project_consistency.py`, and
`tests/integration/test_live_safe_smoke.py`.

`extension.properties` keeps `version=${ghidra.version}` — **Ghidra owns that
field.** Verified in the 12.1.2 install: `ExtensionUtils` loads the file as plain
Java `Properties` and reads only `name`, `description`, `author`, `createdOn`,
`version`; `ExtensionInstaller` compares only `version`. Unknown keys are
ignored, so adding `pluginVersion=${project.version}` is safe.

The assembly descriptor needs no change: it follows
`${project.build.finalName}`. Note `tools/setup/ghidra.py` selects an archive by
modification time, so a stale zip can still win — out of scope here, worth
knowing.

### The bridge version

`tools/bridge_version.py` stops deriving a timestamp from git history and reads
the pom. Verified safe to couple: nothing compares bridge and plugin versions,
and the bridge version is only reported as identity (`state.py:122`).

Three details an earlier draft got wrong or omitted:

- **`read_pom_ghidra_version` is the wrong function** — it reads
  `<ghidra.version>` (`12.1.2`), not the project version. Add
  `read_pom_project_version()` beside it.
- **`pom.xml` is not in the sdist include list** (`pyproject.toml`), so an
  unconditional pom reader breaks wheel construction from an extracted sdist.
  Add `pom.xml` to the sdist, and keep a fallback that reads the version from the
  sdist directory name.
- **`GHIDRA_MCP_BRIDGE_VERSION` must not silently disagree.** A semver-valid
  override that differs from the pom defeats the coupling; reject it.

### ghidra-vice-connector — `CONNECTOR_VERSION`

`src/main/py/src/vice/contracts.py` is the source of truth. No
`gradle.properties` entry is added.

`extension.properties` in source reads `version=@extversion@`, which Ghidra's
own `buildExtension.gradle` substitutes from `application.version` — an earlier
draft wrongly described it as a hand-written `12.1.2`. It is left alone: Ghidra
supplies its own version, which is exactly what the installer checks.

`build.gradle` appends `connectorVersion=<CONNECTOR_VERSION>` to the packaged
copy. Ghidra ignores the key; it is inspectable metadata, and the connector may
later read it, but the extension does not "report" it on its own.

**`connector.version` is removed from the static contract JSON**, in both the
connector's `contracts/c64-vice-api-v1.json` and c64's packaged copy. Reasoning:
it is release metadata, not part of the `c64.vice/1` compatibility surface —
nothing compares it — and keeping it there means every connector release forces a
coordinated commit in another repository, enforced only by an opt-in test
(`GHIDRA_MCP_C64_CONTRACT_REPO_CHECK`), so drift would be silent. The runtime
value still comes back from `status` and capabilities, which is where a consumer
should read it.

Implementation must confirm no validator requires the key before removing it, and
must regenerate the connector's JSON: `test_packaged_contract_is_generated_from_declaration`
asserts the file equals `contract_json()` and always runs.

### ghidra-mcp-c64 — `pyproject.toml` `version`

`0.1.0` → `0.99.0`. It has three version locations, not one:

- `pyproject.toml`
- `src/ghidra_mcp_c64/__init__.py` `__version__ = "0.1.0"` — change to derive
  from installed metadata (`importlib.metadata.version`) so it cannot drift
- `uv.lock` — regenerate

c64 **does** get `tools/release prepare` (an earlier draft contradicted the
three-script decision by omitting it). It gets no `publish`: nothing consumes a
c64 release, it runs from a local venv path, and its connector compatibility
rests on the runtime handshake. Its gates are pytest, Ruff, mypy, a lock check,
and a package build.

## The release script

`tools/release` in each repo. Python, matching all three repos' tooling so it is
testable with pytest.

### Two phases, because "no push" and `gh release create` conflict

Verified: `gh release create` can create a missing tag, but only from a commit
GitHub already has; it cannot resolve a local-only SHA, and for an annotated tag
it instructs you to push first. So:

```text
tools/release prepare --minor          # gates, build, then commit and tag
git push origin HEAD && git push origin v0.100.0
tools/release publish                  # gh release create against the pushed tag
```

### `prepare` — mutate first, verify against the candidate, commit last

Ordering is the substance here. An earlier draft ran gates in step 2 and wrote
the version in step 5, which let a broken script pass its tests, write a version,
skip regenerating the contract JSON, and commit that — the gate could not see the
mutation it was supposed to catch. Corrected order:

1. **Capture the pre-release `HEAD`** for rollback.
2. **Refuse a dirty tree**, and refuse to run off the default branch.
3. **Refuse an empty `## Unreleased`.**
4. **Compute the next version** from the *source file* (never from tags) and the
   bump flag. Refuse if the tag already exists locally or on `origin`.
5. **Write every version location and derived file, and roll the changelog in the
   same step** — version locations, the connector's regenerated contract JSON,
   c64's `uv.lock`, and `CHANGELOG.md` (`## Unreleased` → `## <version>`, with a
   fresh empty `## Unreleased` inserted **above** it).

   The changelog must be rolled *before* the build, not after. Ghidra's
   `buildExtension.gradle` copies the project root into the extension, and the
   packaged connector zip demonstrably contains `CHANGELOG.md`. Building first
   would ship an artifact reading `## Unreleased` under a tag that says
   `<version>`.
6. **Run the gates against that release candidate**, so they see the mutation.
7. **Build the artifacts** and inspect their *contents*: the packaged
   `connectorVersion`, the wheel's metadata version, the zip name, and the
   changelog inside the connector zip.
8. **Commit** (`Release <version>`).
9. **Write the manifest** (see below). It records the release commit's SHA, which
   does not exist until step 8, and it must exist before the tag so that a tag
   failure has something to clean up rather than leaving an orphan.
10. **Tag** `v<version>`, annotated with the changelog section. The tag remains the
    last Git mutation.

### Rollback

A failed release must leave the **working tree, the index and all refs** equal to
their pre-run state — `git status --porcelain` empty, with no staged diff.
Mutation-first means files are necessarily written temporarily, so the guarantee
is about the end state, not about never writing.

The index matters specifically: a failed `git commit` can leave every release
change **staged**. Restoring file bytes alone would satisfy a worktree-only
assertion while leaving the repository dirty, which then blocks the next release
at its own dirty-tree check.

- Failure before the commit: restore the files the script wrote, and reset the
  index.
- **Failure writing the manifest, or during tag creation, after the commit:**
  restoring files is not enough — the branch ref has moved. Remove the manifest if
  written, restore index and worktree, and reset the branch to the captured
  pre-release `HEAD`, guarded so it only moves if `HEAD` is still the release
  commit the script created. Without this the "no-op" claim is false in exactly
  the window where it matters.

### `publish`

1. Resolve the version from the tag at `HEAD`; refuse if `HEAD` is untagged.
2. Refuse unless `origin`'s peeled tag (`refs/tags/v<version>^{}`) resolves to
   the same commit as `HEAD`. Name-only existence is not enough: a same-named
   remote tag pointing elsewhere would otherwise pass.
3. Refuse unless the artifacts recorded by `prepare` are present **and their
   hashes still match**. See the manifest below: without this, an artifact
   rebuilt from a different commit but carrying the same version could be
   published in place of the prepared one.
4. `gh release create --verify-tag`, notes from the changelog section, artifacts
   as assets, `SHA256SUMS` generated over them.
5. `--latest` **explicitly**: `--latest` for the connector, whose releases are
   its only distribution channel; `--latest=false` for mcp-next. Omitting the
   flag delegates to GitHub's automatic choice, which is not the same as "not
   latest".
6. Verify the created release's asset set equals the expected set exactly.

### Every `gh` call is pinned to `origin`

**This is not defensive dressing — unpinned, mcp-next currently resolves to the
wrong repository.** `gh repo view` in `ghidra-mcp-next` reports
`bethington/ghidra-mcp`, reached through its `upstream` remote, while `origin` is
`64kramsystem/ghidra-mcp-next`. So a bare `gh release create` there would target
someone else's repository, even though every git-side check in this design uses
`origin`.

Both scripts derive `owner/repo` from `origin`'s URL and pass `--repo owner/repo`
to every `gh release create` and `gh release view`. A test sets `gh`'s default
repository elsewhere and asserts the pinned target is used.

Both scripts print the exact push commands between phases — `git push origin HEAD`
and the single tag by name, never `git push --tags`, which would push unrelated
tags.

## Gates, per repository, exactly

"Run the gates" is too vague to implement, and it matters most for the connector,
whose CI includes packaged Gradle construction, Bats, and a live-VICE suite with
`REQUIRE_LIVE_VICE=1`.

| Repo | Gate commands |
| --- | --- |
| `ghidra-mcp-next` | `mvn clean compile`, `mvn test`, `uv run pytest tests/unit/` |
| `ghidra-vice-connector` | `./gradlew --no-daemon clean buildExtension`, `python -m pytest tests/ --ignore=tests/test_live_vice.py`, `bats test/import-prg.bats` |
| `ghidra-mcp-c64` | `uv run --locked pytest`, `uv run --locked ruff check`, `uv run --locked mypy`, `uv lock --check`, `uv build` |

The connector's bats file is `test/import-prg.bats` — note **`test/`**, while its
pytest suite is in **`tests/`**. An earlier draft globbed `tests/*.bats`, which
matches nothing, and paired it with an "if present" check, so the gate would have
silently skipped the only bats test there is. Name the file explicitly.

c64's gates run through `uv run --locked` rather than bare `pytest`/`ruff`/`mypy`:
its dev tools are declared in a dependency group, so bare invocations would use
whatever happens to be on `PATH`, or nothing.

**The connector's live-VICE suite is deliberately excluded** from the local gate.
It needs a running emulator with the binary monitor open, which is not a
reasonable precondition for cutting a release, and CI already runs it with
`REQUIRE_LIVE_VICE=1` on every push. The release script states plainly that it
skipped it, so the omission is visible rather than silent.

## Release assets, per repository, exactly

| Repo | Assets |
| --- | --- |
| `ghidra-mcp-next` | `GhidraMCP-next-<version>.zip`, the bridge wheel, the bridge sdist, `SHA256SUMS` |
| `ghidra-vice-connector` | the Gradle-produced extension zip, `SHA256SUMS` |

`release-metadata.json` is **dropped**. It existed so CI could hand structured
release facts to a later step; with an explicitly invoked script the release notes
and `SHA256SUMS` carry everything a consumer reads, and a third file that must be
kept consistent is a liability.

### The prepare→publish manifest

`prepare` writes an untracked, git-ignored manifest at step 9 — after the release
commit exists, before the tag — recording that commit's SHA, the version, and each
artifact's path and SHA-256. `publish` refuses unless the
manifest's commit matches the tag at `HEAD` and every recorded hash still matches
the file on disk. This closes the window where an artifact is rebuilt between the
two phases — same name, same embedded version, different bytes.

### Bootstrap

Setting the sources to `0.99.0` is a **plain commit with no tag**; it is a
baseline, not a release. The first scripted release therefore produces `0.100.0`
(`--minor`) or `0.99.1` (`--patch`). There is no `Release 0.99.0` commit.

### What happens to the existing modules

`tools/release_automation.py` is reworked: `prepare_release` and
`roll_changelog` keep their shape, losing timestamp validation and gaining
semver. `should_publish` / `path_affects_release` and the `classify` subcommand
are **deleted** — they guessed whether a push deserved a release, and an
explicitly invoked script needs no guess. `tests/unit/test_release_automation.py`
moves with it.

## Tests

Each must be shown to fail against a deliberately broken implementation. Three
tests in this session's earlier work passed against provably wrong code, every
time because they asserted machinery was *invoked* rather than that it had an
*effect*.

**Fixtures must isolate the thing under test.** Every refusal test satisfies all
*other* preconditions, so "remote tag absent" cannot pass merely because `HEAD`
was untagged or artifacts were missing.

- version arithmetic per flag, including `0.99.0 --minor` → `0.100.0`
- the version is read from the source file, **not** from tags: a repo whose
  newest tag is `v6.0.0` and whose source says `0.99.0` must release `0.100.0`
- refusals: dirty tree, wrong branch, empty `## Unreleased`, tag already present
  locally, tag already present on `origin`
- **gate ordering**: with a gate injected to fail, **all tracked file bytes and
  all refs equal their pre-run state** — not "no version file is written", since
  mutation-first writes them temporarily — and deleting a gate must let the test
  reach the version write, so the test cannot pass because the script aborted
  earlier for an unrelated reason
- **injected commit failure**, **injected manifest-write failure** and **injected
  tag failure** each leave working tree, index and refs at their pre-run state,
  asserted as an empty `git status --porcelain` with no staged diff; the
  manifest-write and tag cases must show the branch reset off the release commit,
  and the manifest absent
- **build failure leaves neither commit nor tag**
- artifact checks inspect **contents, not filenames**: a correctly named
  connector zip carrying the wrong `connectorVersion` must fail
- changelog: the new `## Unreleased` lands **above** the released heading, and a
  second consecutive release — with a real new bullet added in between, so the
  empty-Unreleased guard does not reject it — neither nests nor duplicates
  headings
- `publish` refuses an untagged `HEAD`, a remote tag missing, and **a remote tag
  with the right name on the wrong commit**
- asset verification compares the exact non-empty expected set from
  `gh release view`; a fake that echoes back whatever was requested proves nothing
- **`gh` is pinned**: with `gh`'s default repository set to a different repo, both
  `create` and `view` still target the one derived from `origin`
- **artifact provenance**: replacing a prepared artifact with different bytes that
  carry the same embedded version makes `publish` refuse
- the connector zip's bundled `CHANGELOG.md` **matches the post-roll source
  exactly** — an empty `## Unreleased` above `## <version>`, with the entries
  under the version heading. Asserting the absence of `## Unreleased`, as an
  earlier draft did, is impossible: the roll deliberately re-adds an empty one.
- after a connector bump: runtime `status` and the packaged `connectorVersion`
  both equal the release version, while the regenerated contract JSON equals its
  declaration **and contains no `connector.version` key at all**. An earlier draft
  asked the contract to report the new version, which the removal of that key
  makes impossible.
- the bridge wheel builds **from the produced sdist** with the override unset

## Out of scope

- Publishing `ghidra-mcp-c64` anywhere; PyPI publication for the bridge.
- Retagging or rewriting existing releases, timestamp or `v*`.
- Any shared release library. Three small scripts beat one abstraction spanning
  Maven, Gradle and hatchling; extract only if a fourth consumer appears.
