# Releases

Releases are automatic timestamp snapshots, not semantic-version milestones.
After all tests pass, `.github/workflows/tests.yml` publishes a release-worthy
push to `main`. A manual dispatch from `main` forces publication.

Release names use `GhidraMCP-next <UTC timestamp>` and tags use
`build-<UTC timestamp>-<12-character commit>`. Each release contains the tested
Ghidra extension ZIP, Python wheel, Python source distribution,
`release-metadata.json`, and `SHA256SUMS`.

Add user-visible changes under `Unreleased` in
[`../../CHANGELOG.md`](../../CHANGELOG.md). After publication, the workflow
moves those entries under the timestamp release heading and pushes the
changelog update as `github-actions[bot]`.

No manual release preparation, version bump, or release tag is required.
