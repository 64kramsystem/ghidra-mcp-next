"""Tests for tools/release.

Every refusal test satisfies all *other* preconditions, so a test cannot pass for
the wrong reason — e.g. "remote tag absent" must not pass merely because the
working tree was dirty.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tools import release

POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <artifactId>GhidraMCP-next</artifactId>
    <version>{version}</version>
</project>
"""

CHANGELOG = """# Changelog

## Unreleased

### Added

- A thing worth releasing.

## 0.98.0

- Older news.
"""


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", release.DEFAULT_BRANCH)
    git(root, "config", "user.email", "test@example.com")
    git(root, "config", "user.name", "Test")
    (root / ".gitignore").write_text("/target/\n/dist/\n", encoding="utf-8")
    (root / "pom.xml").write_text(POM.format(version="0.99.0"), encoding="utf-8")
    (root / "CHANGELOG.md").write_text(CHANGELOG, encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "initial")
    # A bare "remote" so ls-remote works without network.
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", str(remote))
    git(root, "remote", "add", "origin", str(remote))
    git(root, "push", "-q", "origin", release.DEFAULT_BRANCH)
    return root


def make_extension(repo: Path, version: str, *, plugin_version: str | None = None) -> None:
    """Only what Maven produces, so a missing uv build is not masked."""
    import zipfile

    (repo / "target").mkdir(exist_ok=True)
    extension = repo / "target" / f"{release.PRODUCT}-{version}.zip"
    with zipfile.ZipFile(extension, "w") as archive:
        archive.writestr(
            f"{release.PRODUCT}/extension.properties",
            "version=12.1.2\n"
            f"pluginVersion={plugin_version or version}\n",
        )


def make_distributions(repo: Path, version: str) -> None:
    """Only what `uv build` produces, so a missing Maven build is not masked."""
    (repo / "dist").mkdir(exist_ok=True)
    (repo / "dist" / f"ghidra_mcp_bridge-{version}-py3-none-any.whl").write_bytes(b"wheel")
    (repo / "dist" / f"ghidra_mcp_bridge-{version}.tar.gz").write_bytes(b"sdist")


def make_artifacts(repo: Path, version: str, *, plugin_version: str | None = None) -> None:
    make_extension(repo, version, plugin_version=plugin_version)
    make_distributions(repo, version)


def recording_runner(repo: Path, *, fail: str | None = None, build: bool = True):
    """Run git for real, stub everything else, optionally failing one command."""
    calls: list[list[str]] = []

    def runner(command, cwd):
        calls.append(list(command))
        joined = " ".join(command)
        if fail and fail in joined:
            raise release.ReleaseError(f"injected failure: {joined}")
        if command[0] == "git":
            return release.run(command, cwd)
        parts = [str(part) for part in command]
        if build and parts[0] == "mvn" and "package" in parts:
            make_extension(repo, release.read_version(repo))
            return ""
        if build and parts[:2] == ["uv", "build"]:
            make_distributions(repo, release.read_version(repo))
            return ""
        return ""

    runner.calls = calls  # type: ignore[attr-defined]
    return runner


# ------------------------------------------------------------------ arithmetic


@pytest.mark.parametrize(
    ("current", "bump", "expected"),
    [
        ("0.99.0", "patch", "0.99.1"),
        ("0.99.0", "minor", "0.100.0"),
        ("0.99.0", "major", "1.0.0"),
        ("0.100.3", "minor", "0.101.0"),
    ],
)
def test_next_version(current: str, bump: str, expected: str):
    assert release.next_version(current, bump) == expected


def test_next_version_rejects_non_semver():
    with pytest.raises(release.ReleaseError, match="not semantic"):
        release.next_version("20260726.113419", "minor")


def test_version_comes_from_the_pom_not_the_newest_tag(repo: Path):
    """This repo has an old v6.0.0 line; highest-tag-wins would pick it forever."""
    git(repo, "tag", "-a", "v6.0.0", "-m", "old line")

    assert release.read_version(repo) == "0.99.0"

    runner = recording_runner(repo)
    release.prepare(repo, "minor", runner)

    assert release.read_version(repo) == "0.100.0"
    assert git(repo, "tag", "--list", "v0.100.0").strip() == "v0.100.0"


# -------------------------------------------------------------------- refusals


def test_refuses_a_dirty_tree(repo: Path):
    (repo / "pom.xml").write_text(POM.format(version="0.99.0") + "\n", encoding="utf-8")

    with pytest.raises(release.ReleaseError, match="not clean"):
        release.prepare(repo, "minor", recording_runner(repo))


def test_refuses_a_non_default_branch(repo: Path):
    git(repo, "checkout", "-qb", "feature")

    with pytest.raises(release.ReleaseError, match="releases run on"):
        release.prepare(repo, "minor", recording_runner(repo))


def test_refuses_an_empty_unreleased_section(repo: Path):
    (repo / "CHANGELOG.md").write_text(
        "# Changelog\n\n## Unreleased\n\n## 0.98.0\n\n- Older news.\n", encoding="utf-8"
    )
    git(repo, "commit", "-aqm", "empty unreleased")

    with pytest.raises(release.ReleaseError, match="nothing to release"):
        release.prepare(repo, "minor", recording_runner(repo))


def test_refuses_a_tag_that_exists_locally(repo: Path):
    git(repo, "tag", "v0.100.0")

    with pytest.raises(release.ReleaseError, match="already exists locally"):
        release.prepare(repo, "minor", recording_runner(repo))


def test_refuses_a_tag_that_exists_on_origin(repo: Path):
    """Everything else is valid: only the remote tag makes this fail."""
    git(repo, "tag", "v0.100.0")
    git(repo, "push", "-q", "origin", "v0.100.0")
    git(repo, "tag", "-d", "v0.100.0")

    with pytest.raises(release.ReleaseError, match="already exists on origin"):
        release.prepare(repo, "minor", recording_runner(repo))


# ------------------------------------------------------------- gate ordering


def test_gates_run_after_the_version_is_written(repo: Path):
    """A gate must see the mutation it exists to catch."""
    observed: list[str] = []

    def runner(command, cwd):
        if command[0] == "mvn" and "test" in command:
            observed.append(release.read_version(repo))
            return ""
        return recording_runner(repo)(command, cwd)

    release.prepare(repo, "minor", runner)

    assert observed == ["0.100.0"]


def test_a_failing_gate_leaves_the_repository_untouched(repo: Path):
    before_head = release.head_sha(repo)
    before_pom = (repo / "pom.xml").read_text()
    before_changelog = (repo / "CHANGELOG.md").read_text()

    with pytest.raises(release.ReleaseError, match="injected failure"):
        release.prepare(repo, "minor", recording_runner(repo, fail="mvn test"))

    assert release.head_sha(repo) == before_head
    assert (repo / "pom.xml").read_text() == before_pom
    assert (repo / "CHANGELOG.md").read_text() == before_changelog
    assert git(repo, "status", "--porcelain").strip() == ""
    assert git(repo, "tag", "--list").strip() == ""


def test_a_failing_build_leaves_neither_commit_nor_tag(repo: Path):
    before_head = release.head_sha(repo)

    with pytest.raises(release.ReleaseError, match="injected failure"):
        release.prepare(repo, "minor", recording_runner(repo, fail="assembly:single"))

    assert release.head_sha(repo) == before_head
    assert git(repo, "status", "--porcelain").strip() == ""
    assert git(repo, "tag", "--list").strip() == ""


def test_a_failing_tag_resets_the_branch(repo: Path):
    """The commit exists by then, so restoring files alone is not enough."""
    before_head = release.head_sha(repo)

    with pytest.raises(release.ReleaseError, match="injected failure"):
        release.prepare(repo, "minor", recording_runner(repo, fail="git tag -a"))

    assert release.head_sha(repo) == before_head
    assert git(repo, "status", "--porcelain").strip() == ""
    assert not (repo / release.MANIFEST_PATH).exists()


def test_a_missing_artifact_fails_before_committing(repo: Path):
    before_head = release.head_sha(repo)

    with pytest.raises(release.ReleaseError, match="build did not produce"):
        release.prepare(repo, "minor", recording_runner(repo, build=False))

    assert release.head_sha(repo) == before_head
    assert git(repo, "status", "--porcelain").strip() == ""


def test_artifact_contents_are_checked_not_just_names(repo: Path):
    """A correctly named zip carrying the wrong pluginVersion must fail."""

    def runner(command, cwd):
        if command[0] == "mvn" and "package" in command:
            make_artifacts(repo, "0.100.0", plugin_version="0.99.0")
            return ""
        return recording_runner(repo, build=False)(command, cwd)

    with pytest.raises(release.ReleaseError, match="pluginVersion=0.100.0"):
        release.prepare(repo, "minor", runner)


# -------------------------------------------------------------------- changelog


def test_roll_inserts_the_new_unreleased_above_the_release(repo: Path):
    release.prepare(repo, "minor", recording_runner(repo))
    text = (repo / "CHANGELOG.md").read_text()

    assert text.index("## Unreleased") < text.index("## 0.100.0")
    assert "- A thing worth releasing." in text.split("## 0.100.0", 1)[1]
    assert release.unreleased_section(repo / "CHANGELOG.md") == ""


def test_two_consecutive_releases_do_not_nest_headings(repo: Path):
    release.prepare(repo, "minor", recording_runner(repo))

    # A real new entry, so the empty-Unreleased guard does not reject release two.
    text = (repo / "CHANGELOG.md").read_text()
    text = text.replace("## Unreleased\n", "## Unreleased\n\n- Something new.\n", 1)
    (repo / "CHANGELOG.md").write_text(text, encoding="utf-8")
    git(repo, "commit", "-aqm", "more news")

    release.prepare(repo, "patch", recording_runner(repo))
    final = (repo / "CHANGELOG.md").read_text()

    assert final.count("## Unreleased") == 1
    assert final.index("## Unreleased") < final.index("## 0.100.1")
    assert final.index("## 0.100.1") < final.index("## 0.100.0")


# ---------------------------------------------------------------------- publish


def prepared(repo: Path) -> str:
    version = release.prepare(repo, "minor", recording_runner(repo))
    git(repo, "push", "-q", "origin", release.DEFAULT_BRANCH)
    git(repo, "push", "-q", "origin", f"v{version}")
    return version


def publish_runner(repo: Path, *, assets: list[str] | None = None):
    def runner(command, cwd):
        if command[0] == "git":
            return release.run(command, cwd)
        if [str(part) for part in command][:3] == ["gh", "release", "view"]:
            names = assets if assets is not None else _expected_names(repo)
            return "\n".join(names)
        return ""

    return runner


def _expected_names(repo: Path) -> list[str]:
    """Derived from the version, not the manifest: the manifest is what we check."""
    version = release.read_version(repo)
    return [
        path.name for path in release.expected_artifacts(repo, version)
    ] + ["SHA256SUMS"]


def test_publish_pins_gh_to_the_origin_repository(repo: Path):
    """gh resolves through other remotes; unpinned it can target another repo."""
    git(repo, "remote", "add", "upstream", "https://github.com/someone/else.git")
    prepared(repo)
    commands: list[list[str]] = []

    def runner(command, cwd):
        commands.append(list(command))
        return publish_runner(repo)(command, cwd)

    release.publish(repo, runner)

    gh_calls = [command for command in commands if command[0] == "gh"]
    assert gh_calls
    for call in gh_calls:
        assert "--repo" in call
        assert call[call.index("--repo") + 1] == release.origin_repo(repo)
        assert "someone/else" not in call


def test_publish_refuses_an_untagged_head(repo: Path):
    with pytest.raises(release.ReleaseError):
        release.publish(repo, publish_runner(repo))


def test_publish_refuses_when_the_tag_is_absent_from_origin(repo: Path):
    version = release.prepare(repo, "minor", recording_runner(repo))
    git(repo, "push", "-q", "origin", release.DEFAULT_BRANCH)
    # Everything else is in place; only the tag was never pushed.
    assert (repo / release.MANIFEST_PATH).is_file()

    with pytest.raises(release.ReleaseError, match=f"origin has no v{version}"):
        release.publish(repo, publish_runner(repo))


def test_publish_refuses_a_remote_tag_on_a_different_commit(repo: Path):
    version = prepared(repo)
    # Move the tag locally to a new commit, leaving origin's pointing elsewhere.
    (repo / "extra.txt").write_text("x", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "later work")
    git(repo, "tag", "-d", f"v{version}")
    git(repo, "tag", "-a", f"v{version}", "-m", "moved")

    with pytest.raises(release.ReleaseError, match="origin has no"):
        release.publish(repo, publish_runner(repo))


def test_publish_refuses_an_artifact_rebuilt_after_prepare(repo: Path):
    """Same name, same embedded version, different bytes."""
    version = prepared(repo)
    manifest = release.read_manifest(repo)
    target = Path(manifest["artifacts"][1]["path"])
    target.write_bytes(b"rebuilt from another commit")

    with pytest.raises(release.ReleaseError, match="changed since prepare"):
        release.publish(repo, publish_runner(repo))
    assert manifest["version"] == version


def test_publish_refuses_a_missing_manifest(repo: Path):
    prepared(repo)
    (repo / release.MANIFEST_PATH).unlink()

    with pytest.raises(release.ReleaseError, match="missing"):
        release.publish(repo, publish_runner(repo))


def test_publish_verifies_the_exact_asset_set(repo: Path):
    prepared(repo)

    with pytest.raises(release.ReleaseError, match="do not match expected"):
        release.publish(repo, publish_runner(repo, assets=["SHA256SUMS"]))


def test_publish_succeeds_and_writes_checksums(repo: Path):
    version = prepared(repo)

    assert release.publish(repo, publish_runner(repo)) == version
    checksums = (repo / release.CHECKSUMS_PATH).read_text()
    assert f"ghidra_mcp_bridge-{version}.tar.gz" in checksums
    assert len(checksums.strip().splitlines()) == 3


def test_manifest_records_the_tagged_commit(repo: Path):
    version = release.prepare(repo, "minor", recording_runner(repo))
    manifest = json.loads((repo / release.MANIFEST_PATH).read_text())

    assert manifest["version"] == version
    assert manifest["commit"] == release.head_sha(repo)


# ------------------------------------------------------- CI must not publish


def test_workflow_no_longer_publishes_releases():
    """Releasing is this script's job; CI must not do it.

    Carried over from the deleted test_release_automation.py. Asserting the
    absence is the point: a job reintroduced by a merge would resurrect the
    CHANGELOG-rewriting push that fought local work.
    """
    import yaml

    repo_root = Path(__file__).resolve().parents[2]
    workflow_path = repo_root / ".github" / "workflows" / "tests.yml"
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow = yaml.load(workflow_text, Loader=yaml.BaseLoader)

    assert "workflow_dispatch" in workflow["on"]
    assert workflow["permissions"] == {"contents": "read"}

    jobs = workflow["jobs"]
    assert "automatic-release" not in jobs
    # Without a write-scoped job nothing can create a release or push a commit,
    # whatever its steps say.
    assert all(
        job.get("permissions", {}).get("contents") != "write" for job in jobs.values()
    )
    assert "gh release create" not in workflow_text
    assert "git push" not in workflow_text


# ------------------------------------------------ blockers found in review


def test_a_concurrent_commit_is_not_destroyed(repo: Path):
    """Rollback must reset only the commit this run created.

    Resetting whenever HEAD moved would erase whatever else landed.
    """
    def runner(command, cwd):
        parts = [str(part) for part in command]
        if parts[:3] == ["git", "tag", "-a"]:
            # Something else commits between our commit and the tag.
            (repo / "other.txt").write_text("concurrent", encoding="utf-8")
            git(repo, "add", "other.txt")
            git(repo, "commit", "-qm", "concurrent work")
            raise release.ReleaseError("injected failure: git tag -a")
        return recording_runner(repo)(command, cwd)

    with pytest.raises(release.ReleaseError, match="not resetting"):
        release.prepare(repo, "minor", runner)

    assert git(repo, "log", "-1", "--format=%s").strip() == "concurrent work"
    assert (repo / "other.txt").is_file()


def test_an_injected_commit_failure_leaves_no_trace(repo: Path):
    before_head = release.head_sha(repo)

    with pytest.raises(release.ReleaseError, match="injected failure"):
        release.prepare(repo, "minor", recording_runner(repo, fail="git commit"))

    assert release.head_sha(repo) == before_head
    assert git(repo, "status", "--porcelain").strip() == ""
    assert git(repo, "tag", "--list").strip() == ""


def test_an_injected_manifest_write_failure_resets_the_branch(
    repo: Path, monkeypatch: pytest.MonkeyPatch
):
    before_head = release.head_sha(repo)

    def explode(*args, **kwargs):
        raise release.ReleaseError("injected failure: manifest write")

    monkeypatch.setattr(release, "write_manifest", explode)

    with pytest.raises(release.ReleaseError, match="injected failure"):
        release.prepare(repo, "minor", recording_runner(repo))

    assert release.head_sha(repo) == before_head
    assert git(repo, "status", "--porcelain").strip() == ""
    assert not (repo / release.MANIFEST_PATH).exists()


def test_publish_rejects_a_manifest_missing_artifacts(repo: Path):
    """The manifest is untrusted input; an empty one must not publish nothing."""
    prepared(repo)
    manifest = json.loads((repo / release.MANIFEST_PATH).read_text())
    manifest["artifacts"] = []
    (repo / release.MANIFEST_PATH).write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(release.ReleaseError, match="manifest lists"):
        release.publish(repo, publish_runner(repo))


def test_publish_rejects_a_manifest_listing_an_unexpected_artifact(repo: Path):
    prepared(repo)
    manifest = json.loads((repo / release.MANIFEST_PATH).read_text())
    stray = repo / "dist" / "something-else.whl"
    stray.write_bytes(b"stray")
    manifest["artifacts"] = [
        {"name": stray.name, "path": str(stray), "sha256": release.sha256(stray)}
    ]
    (repo / release.MANIFEST_PATH).write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(release.ReleaseError, match="manifest lists"):
        release.publish(repo, publish_runner(repo))


def test_release_scratch_files_do_not_dirty_the_repository(repo: Path):
    """The first real publish must not leave a state the next prepare refuses."""
    prepared(repo)
    release.publish(repo, publish_runner(repo))

    assert git(repo, "status", "--porcelain").strip() == ""
    assert str(release.MANIFEST_PATH).startswith("dist/")
    assert str(release.CHECKSUMS_PATH).startswith("dist/")


def test_publish_takes_notes_from_the_tag(repo: Path):
    """Working-tree notes could drift after the tag was written."""
    prepared(repo)
    commands: list[list[str]] = []

    def runner(command, cwd):
        commands.append([str(part) for part in command])
        return publish_runner(repo)(command, cwd)

    release.publish(repo, runner)

    create = next(c for c in commands if c[:3] == ["gh", "release", "create"])
    assert "--notes-from-tag" in create
    assert "--notes" not in create


def test_each_build_command_is_required(repo: Path):
    """The fake creates only what each command produces, so neither can be dropped."""
    import shutil

    for dropped in ("mvn", "uv"):
        # Clear build output first: artifacts left by the previous iteration
        # would otherwise satisfy this one's verification.
        shutil.rmtree(repo / "dist", ignore_errors=True)
        shutil.rmtree(repo / "target", ignore_errors=True)
        target = repo / "pom.xml"
        original = target.read_text()

        def runner(command, cwd, dropped=dropped):
            parts = [str(part) for part in command]
            if parts[0] == dropped and parts[0] != "git":
                return ""
            return recording_runner(repo)(command, cwd)

        with pytest.raises(release.ReleaseError, match="build did not produce"):
            release.prepare(repo, "minor", runner)

        assert target.read_text() == original


def test_the_full_gate_set_is_present():
    """Looping over whatever remains would pass if a gate were deleted."""
    assert release.GATES == (
        ("mvn", "-q", "clean", "compile"),
        ("mvn", "test"),
        ("uv", "run", "pytest", "tests/unit/"),
    )


def test_publish_does_not_mark_the_release_latest(repo: Path):
    """Releases here are a record; the extension is built locally."""
    prepared(repo)
    commands: list[list[str]] = []

    def runner(command, cwd):
        commands.append([str(part) for part in command])
        return publish_runner(repo)(command, cwd)

    release.publish(repo, runner)

    create = next(c for c in commands if c[:3] == ["gh", "release", "create"])
    assert "--latest=false" in create
    assert release.MARK_LATEST is False


def test_checksums_match_recomputed_artifact_hashes(repo: Path):
    """Filenames and a line count would pass a file full of zero hashes."""
    prepared(repo)
    release.publish(repo, publish_runner(repo))

    manifest = release.read_manifest(repo)
    expected = {
        Path(entry["path"]).name: release.sha256(Path(entry["path"]))
        for entry in manifest["artifacts"]
    }
    written = {}
    for line in (repo / release.CHECKSUMS_PATH).read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        written[name] = digest

    assert written == expected
    assert all(len(digest) == 64 and set(digest) != {"0"} for digest in written.values())
