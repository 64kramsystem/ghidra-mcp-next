"""Scripted releases for GhidraMCP-next.

Two phases, because `gh release create` needs its target commit on the remote and
this script deliberately does not push:

    tools/release prepare --minor    # gates, build, commit, manifest, tag
    git push origin HEAD && git push origin v<version>
    tools/release publish            # gh release create against the pushed tag

`prepare` writes the version first and runs the gates against that release
candidate, so a gate sees the mutation it exists to catch. On failure it restores
the working tree, the index and the branch ref, so a failed release is a no-op
rather than a mess to unpick.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

PRODUCT = "GhidraMCP-next"
DEFAULT_BRANCH = "main"
MANIFEST_NAME = ".release-manifest.json"

# Releases are a record here: the extension is built locally by update_ghidra.
MARK_LATEST = False

_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_POM_VERSION_RE = re.compile(r"(?m)^(    <version>)(\d+\.\d+\.\d+)(</version>)$")
_UNRELEASED_RE = re.compile(r"(?m)^## Unreleased[ \t]*$")
_LEVEL_TWO_RE = re.compile(r"(?m)^## .+$")

Runner = Callable[[Sequence[str], Path], str]


class ReleaseError(RuntimeError):
    """A release was refused or failed; the repository is unchanged."""


# --------------------------------------------------------------------------- shell


def run(command: Sequence[str], cwd: Path) -> str:
    completed = subprocess.run(
        list(command), cwd=cwd, capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        raise ReleaseError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout}{completed.stderr}".rstrip()
        )
    return completed.stdout


# ------------------------------------------------------------------------- version


def next_version(current: str, bump: str) -> str:
    """Return the next semantic version.

    Note `0.99.0` + minor is `0.100.0`, not `1.0.0`: semver places no limit on a
    component's magnitude, and both Maven and PEP 440 compare them numerically.
    """
    match = _SEMVER_RE.fullmatch(current)
    if match is None:
        raise ReleaseError(f"current version is not semantic: {current!r}")
    major, minor, patch = (int(part) for part in match.groups())

    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    if bump == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ReleaseError(f"unknown bump: {bump!r}")


def read_version(repo_root: Path) -> str:
    """Read the version from `pom.xml`, the single source of truth.

    Deliberately **not** derived from tags: this repository has an older `v*`
    line reaching `v6.0.0`, so "highest tag wins" would pick that forever.
    """
    match = _POM_VERSION_RE.search((repo_root / "pom.xml").read_text(encoding="utf-8"))
    if match is None:
        raise ReleaseError("pom.xml has no project <version>")
    return match.group(2)


def write_version(repo_root: Path, version: str) -> list[Path]:
    pom_path = repo_root / "pom.xml"
    text = pom_path.read_text(encoding="utf-8")
    updated, count = _POM_VERSION_RE.subn(rf"\g<1>{version}\g<3>", text, count=1)
    if count != 1:
        raise ReleaseError("pom.xml has no project <version>")
    pom_path.write_text(updated, encoding="utf-8")
    # Everything else derives from the pom at build time: version.properties,
    # MANIFEST.MF, extension.properties and the bridge wheel.
    return [pom_path]


# ----------------------------------------------------------------------- changelog


def unreleased_section(changelog_path: Path) -> str:
    text = changelog_path.read_text(encoding="utf-8")
    headings = list(_UNRELEASED_RE.finditer(text))
    if len(headings) != 1:
        raise ReleaseError(
            f"CHANGELOG.md must have exactly one ## Unreleased heading; found {len(headings)}"
        )
    heading = headings[0]
    following = _LEVEL_TWO_RE.search(text, heading.end())
    end = following.start() if following else len(text)
    return text[heading.end() : end].strip()


def roll_changelog(changelog_path: Path, version: str) -> None:
    """Retitle `## Unreleased` as the version, with a fresh empty one above it.

    Above, not below: the retired CI job inserted the version heading directly
    beneath `## Unreleased`, and a later merge then filed a new entry underneath
    it — inside a release that did not contain it.
    """
    text = changelog_path.read_text(encoding="utf-8")
    section = unreleased_section(changelog_path)
    if not section:
        raise ReleaseError("## Unreleased is empty; nothing to release")

    heading = _UNRELEASED_RE.search(text)
    assert heading is not None
    updated = (
        text[: heading.start()]
        + "## Unreleased\n\n"
        + f"## {version}\n"
        + text[heading.end() :].lstrip("\n")
    )
    changelog_path.write_text(updated, encoding="utf-8")


# ----------------------------------------------------------------------------- git


def git_status_porcelain(repo_root: Path, runner: Runner = run) -> str:
    return runner(["git", "status", "--porcelain"], repo_root).strip()


def ensure_clean(repo_root: Path, runner: Runner = run) -> None:
    if git_status_porcelain(repo_root, runner):
        raise ReleaseError("working tree is not clean; commit or stash first")


def ensure_default_branch(repo_root: Path, runner: Runner = run) -> None:
    branch = runner(["git", "branch", "--show-current"], repo_root).strip()
    if branch != DEFAULT_BRANCH:
        raise ReleaseError(f"releases run on {DEFAULT_BRANCH}, not {branch!r}")


def head_sha(repo_root: Path, runner: Runner = run) -> str:
    return runner(["git", "rev-parse", "HEAD"], repo_root).strip()


def ensure_tag_absent(repo_root: Path, tag: str, runner: Runner = run) -> None:
    local = runner(["git", "tag", "--list", tag], repo_root).strip()
    if local:
        raise ReleaseError(f"tag {tag} already exists locally")
    remote = runner(["git", "ls-remote", "--tags", "origin", tag], repo_root).strip()
    if remote:
        raise ReleaseError(f"tag {tag} already exists on origin")


def origin_repo(repo_root: Path, runner: Runner = run) -> str:
    """Return `owner/repo` for `origin`.

    Every `gh` call is pinned to this. Unpinned, `gh` resolves through whichever
    remote it prefers: in this repository that is `upstream`, i.e. a different
    project entirely, so an unpinned publish would target the wrong repo.
    """
    url = runner(["git", "remote", "get-url", "origin"], repo_root).strip()
    match = re.search(r"[:/]([^/:]+/[^/]+?)(?:\.git)?$", url)
    if match is None:
        raise ReleaseError(f"cannot derive owner/repo from origin url {url!r}")
    return match.group(1)


# ------------------------------------------------------------------------ manifest


@dataclass(frozen=True)
class Artifact:
    path: Path
    sha256: str

    def as_json(self) -> dict[str, str]:
        return {"name": self.path.name, "path": str(self.path), "sha256": self.sha256}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(
    repo_root: Path, version: str, commit: str, artifacts: Iterable[Artifact]
) -> Path:
    path = repo_root / MANIFEST_NAME
    path.write_text(
        json.dumps(
            {
                "version": version,
                "commit": commit,
                "artifacts": [artifact.as_json() for artifact in artifacts],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def read_manifest(repo_root: Path) -> dict:
    path = repo_root / MANIFEST_NAME
    if not path.is_file():
        raise ReleaseError(f"{MANIFEST_NAME} is missing; run prepare first")
    return json.loads(path.read_text(encoding="utf-8"))


def verify_manifest(repo_root: Path, manifest: dict, commit: str) -> list[Path]:
    """Confirm the prepared artifacts are still the ones being published.

    Hash-checked, not name-checked: an artifact rebuilt from a different commit
    can carry the same name and the same embedded version.
    """
    if manifest["commit"] != commit:
        raise ReleaseError(
            f"manifest commit {manifest['commit'][:12]} is not the tagged commit {commit[:12]}"
        )
    paths = []
    for entry in manifest["artifacts"]:
        path = Path(entry["path"])
        if not path.is_absolute():
            path = repo_root / path
        if not path.is_file():
            raise ReleaseError(f"prepared artifact is missing: {path}")
        if sha256(path) != entry["sha256"]:
            raise ReleaseError(
                f"prepared artifact changed since prepare: {path.name}"
            )
        paths.append(path)
    return paths


def write_checksums(repo_root: Path, artifacts: Sequence[Path]) -> Path:
    path = repo_root / "SHA256SUMS"
    lines = sorted(f"{sha256(item)}  {item.name}" for item in artifacts)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# ------------------------------------------------------------------------- gates


GATES: tuple[tuple[str, ...], ...] = (
    ("mvn", "-q", "clean", "compile"),
    ("mvn", "test"),
    ("uv", "run", "pytest", "tests/unit/"),
)

BUILD: tuple[tuple[str, ...], ...] = (
    ("mvn", "-q", "clean", "package", "assembly:single", "-DskipTests"),
    ("uv", "build"),
)


def expected_artifacts(repo_root: Path, version: str) -> list[Path]:
    return [
        repo_root / "target" / f"{PRODUCT}-{version}.zip",
        repo_root / "dist" / f"ghidra_mcp_bridge-{version}-py3-none-any.whl",
        repo_root / "dist" / f"ghidra_mcp_bridge-{version}.tar.gz",
    ]


def verify_artifact_contents(repo_root: Path, version: str) -> list[Artifact]:
    """Check the artifacts' contents, not just their names."""
    artifacts = []
    for path in expected_artifacts(repo_root, version):
        if not path.is_file():
            raise ReleaseError(f"build did not produce {path}")
        artifacts.append(Artifact(path, sha256(path)))

    extension = expected_artifacts(repo_root, version)[0]
    with zipfile.ZipFile(extension) as archive:
        name = f"{PRODUCT}/extension.properties"
        if name not in archive.namelist():
            raise ReleaseError(f"{extension.name} has no {name}")
        properties = archive.read(name).decode("utf-8")
    if f"pluginVersion={version}" not in properties:
        raise ReleaseError(
            f"{extension.name} does not carry pluginVersion={version}"
        )
    return artifacts


# ------------------------------------------------------------------------ prepare


def prepare(repo_root: Path, bump: str, runner: Runner = run) -> str:
    changelog = repo_root / "CHANGELOG.md"
    ensure_clean(repo_root, runner)
    ensure_default_branch(repo_root, runner)
    if not unreleased_section(changelog):
        raise ReleaseError("## Unreleased is empty; nothing to release")

    original_head = head_sha(repo_root, runner)
    current = read_version(repo_root)
    version = next_version(current, bump)
    tag = f"v{version}"
    ensure_tag_absent(repo_root, tag, runner)

    print(f"{current} -> {version}")
    committed = False
    manifest_path = repo_root / MANIFEST_NAME
    try:
        written = [*write_version(repo_root, version), changelog]
        roll_changelog(changelog, version)

        for gate in GATES:
            print(f"gate: {' '.join(gate)}")
            runner(gate, repo_root)
        for step in BUILD:
            print(f"build: {' '.join(step)}")
            runner(step, repo_root)

        artifacts = verify_artifact_contents(repo_root, version)

        # Explicit paths, not `add -A`: the latter would stage build output and
        # anything else untracked into the release commit.
        staged = [str(path.relative_to(repo_root)) for path in written]
        runner(["git", "add", *staged], repo_root)
        runner(["git", "commit", "-m", f"Release {version}"], repo_root)
        committed = True
        commit = head_sha(repo_root, runner)

        write_manifest(repo_root, version, commit, artifacts)
        runner(
            ["git", "tag", "-a", tag, "-m", unreleased_or_version(changelog, version)],
            repo_root,
        )
    except BaseException:
        _rollback(repo_root, original_head, committed, manifest_path, runner)
        raise

    print(f"\nprepared {tag}. Now:\n  git push origin HEAD\n  git push origin {tag}\n  tools/release publish")
    return version


def unreleased_or_version(changelog: Path, version: str) -> str:
    """Tag message: the released section, falling back to the bare version."""
    text = changelog.read_text(encoding="utf-8")
    match = re.search(rf"(?m)^## {re.escape(version)}[ \t]*$", text)
    if match is None:
        return version
    following = _LEVEL_TWO_RE.search(text, match.end())
    end = following.start() if following else len(text)
    return f"{version}\n\n{text[match.end():end].strip()}"


def _rollback(
    repo_root: Path,
    original_head: str,
    committed: bool,
    manifest_path: Path,
    runner: Runner,
) -> None:
    """Restore worktree, index and refs. A failed release must be a no-op."""
    if manifest_path.exists():
        manifest_path.unlink()
    if committed:
        # Only move the branch if HEAD is still the commit this run created.
        current = head_sha(repo_root, runner)
        if current != original_head:
            runner(["git", "reset", "--hard", original_head], repo_root)
    else:
        # Unstage anything the failed commit left in the index, then restore the
        # tracked files. `reset --hard` is confined to tracked content, so build
        # output stays where it is.
        runner(["git", "reset", "-q", "HEAD"], repo_root)
        runner(["git", "checkout", "--", "."], repo_root)


# ------------------------------------------------------------------------ publish


def publish(repo_root: Path, runner: Runner = run) -> str:
    tag = runner(["git", "describe", "--tags", "--exact-match", "HEAD"], repo_root).strip()
    if not tag.startswith("v"):
        raise ReleaseError(f"HEAD tag {tag!r} is not a release tag")
    version = tag[1:]
    if _SEMVER_RE.fullmatch(version) is None:
        raise ReleaseError(f"HEAD tag {tag!r} is not semantic")

    commit = head_sha(repo_root, runner)
    peeled = runner(
        ["git", "ls-remote", "origin", f"refs/tags/{tag}^{{}}"], repo_root
    ).split()
    if not peeled or peeled[0] != commit:
        raise ReleaseError(
            f"origin has no {tag} pointing at {commit[:12]}; push the branch and tag first"
        )

    manifest = read_manifest(repo_root)
    if manifest["version"] != version:
        raise ReleaseError(
            f"manifest is for {manifest['version']}, not {version}"
        )
    artifacts = verify_manifest(repo_root, manifest, commit)
    checksums = write_checksums(repo_root, artifacts)

    repo = origin_repo(repo_root, runner)
    notes = unreleased_or_version(repo_root / "CHANGELOG.md", version)
    command = [
        "gh", "release", "create", tag,
        "--repo", repo,
        "--verify-tag",
        "--title", f"{PRODUCT} {version}",
        "--notes", notes,
        f"--latest={'true' if MARK_LATEST else 'false'}",
        *[str(path) for path in [*artifacts, checksums]],
    ]
    runner(command, repo_root)

    listed = runner(
        ["gh", "release", "view", tag, "--repo", repo, "--json", "assets",
         "--jq", ".assets[].name"],
        repo_root,
    ).split()
    expected = sorted(path.name for path in [*artifacts, checksums])
    if sorted(listed) != expected:
        raise ReleaseError(
            f"released assets {sorted(listed)} do not match expected {expected}"
        )
    print(f"published {tag} to {repo}")
    return version


# ---------------------------------------------------------------------------- cli


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"{PRODUCT} release")
    sub = parser.add_subparsers(dest="command", required=True)

    prepare_parser = sub.add_parser("prepare", help="gate, build, commit and tag a release")
    group = prepare_parser.add_mutually_exclusive_group(required=True)
    for bump in ("major", "minor", "patch"):
        group.add_argument(f"--{bump}", action="store_const", const=bump, dest="bump")

    sub.add_parser("publish", help="create the GitHub release for the pushed tag")

    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        if args.command == "prepare":
            prepare(repo_root, args.bump)
        else:
            publish(repo_root)
    except ReleaseError as error:
        print(f"release refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
