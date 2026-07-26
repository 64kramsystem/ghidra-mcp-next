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
    (root / ".gitignore").write_text(
        f"/target/\n/dist/\n{release.MANIFEST_NAME}\n", encoding="utf-8"
    )
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


def make_artifacts(repo: Path, version: str, *, plugin_version: str | None = None) -> None:
    """Create artifacts the way a successful build would."""
    import zipfile

    (repo / "target").mkdir(exist_ok=True)
    (repo / "dist").mkdir(exist_ok=True)
    extension = repo / "target" / f"{release.PRODUCT}-{version}.zip"
    with zipfile.ZipFile(extension, "w") as archive:
        archive.writestr(
            f"{release.PRODUCT}/extension.properties",
            "version=12.1.2\n"
            f"pluginVersion={plugin_version or version}\n",
        )
    (repo / "dist" / f"ghidra_mcp_bridge-{version}-py3-none-any.whl").write_bytes(b"wheel")
    (repo / "dist" / f"ghidra_mcp_bridge-{version}.tar.gz").write_bytes(b"sdist")


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
        if build and command[:2] == ["mvn", "-q"] and "package" in command:
            make_artifacts(repo, release.read_version(repo))
            return ""
        if build and command[0] == "uv" and "build" in command:
            make_artifacts(repo, release.read_version(repo))
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
    assert not (repo / release.MANIFEST_NAME).exists()


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
        if command[:3] == ["gh", "release", "view"]:
            names = assets if assets is not None else _expected_names(repo)
            return "\n".join(names)
        return ""

    return runner


def _expected_names(repo: Path) -> list[str]:
    manifest = release.read_manifest(repo)
    return [entry["name"] for entry in manifest["artifacts"]] + ["SHA256SUMS"]


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
    assert (repo / release.MANIFEST_NAME).is_file()

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
    (repo / release.MANIFEST_NAME).unlink()

    with pytest.raises(release.ReleaseError, match="is missing"):
        release.publish(repo, publish_runner(repo))


def test_publish_verifies_the_exact_asset_set(repo: Path):
    prepared(repo)

    with pytest.raises(release.ReleaseError, match="do not match expected"):
        release.publish(repo, publish_runner(repo, assets=["SHA256SUMS"]))


def test_publish_succeeds_and_writes_checksums(repo: Path):
    version = prepared(repo)

    assert release.publish(repo, publish_runner(repo)) == version
    checksums = (repo / "SHA256SUMS").read_text()
    assert f"ghidra_mcp_bridge-{version}.tar.gz" in checksums
    assert len(checksums.strip().splitlines()) == 3


def test_manifest_records_the_tagged_commit(repo: Path):
    version = release.prepare(repo, "minor", recording_runner(repo))
    manifest = json.loads((repo / release.MANIFEST_NAME).read_text())

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
