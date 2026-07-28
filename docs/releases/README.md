# Releases

Releases are semantic-version milestones cut locally by the maintainer. One
command does all of it:

```bash
tools/release <major|minor|patch>
```

CI does not release. `.github/workflows/tests.yml` runs the gates and uploads
run artifacts; it creates no tag and publishes nothing. Do not hand-roll a
version bump, a tag, or a `gh release`.

## What the command does

In order: refuse unless the checkout is on `main`, clean, and exactly in sync
with `origin`; write the version; roll the changelog; run the runtime test
suites; build and inspect the artifacts; commit; tag; push the branch and the
tag; publish the GitHub release.

The order is deliberate. Everything fallible happens *before* the push, because
the push is a one-way door: after it the tag is public and nothing here can
retract it. Until then a failure restores the working tree, the index and the
branch ref, so a failed release is a no-op rather than a mess to unpick.

If the push succeeds but publishing fails, re-run the same command. It sees HEAD
already tagged and that tag already on `origin`, skips to publishing, and says
so — it does not bump the version again.

## Version identity

The version lives in `pom.xml`, which is the single source of truth. The Ghidra
extension and the Python bridge are built from one commit and released together
carrying that one version: extension identity is `${project.version}`, and
`tools/bridge_version.py` derives the bridge version from the same pom. The
`release.timestamp` property is build metadata only (`build.timestamp` and
`build.number` in `version.properties`), never release identity.

Each release carries the extension ZIP, the Python wheel and source
distribution, plus `release-manifest.json` and `SHA256SUMS`. Publishing verifies
that the peeled remote tag points at the released commit and that every artifact
still hashes to what the build produced, so an artifact rebuilt from another
commit cannot be published under the same version. Releases are a record here —
the extension is built locally by `update_ghidra` — so they are not marked
`latest`.

## Changelog

Add user-visible changes under `## Unreleased` in
[`../../CHANGELOG.md`](../../CHANGELOG.md). The command retitles that heading as
`## X.Y.Z`, inserts a fresh empty `## Unreleased` above it, and refuses to
release when `Unreleased` is empty.

Sections titled `## GhidraMCP-next <timestamp>` are published history from the
retired CI job. New releases are plain semver.

## Do not test the release script

No unit tests, no fixtures, no mutation checks, no CI assertions about
`tools/release`. It is verified by running it and seeing what happens; a test
suite around it has repeatedly cost more than it caught. If a release breaks,
fix the script. This is a standing maintainer instruction, not an oversight.
