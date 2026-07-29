"""Build, tag, and atomically push a release."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_BRANCH = "main"
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
POM_VERSION = re.compile(
    r"(?m)^(    <version>)(\d+\.\d+\.\d+)(</version>)$"
)


class ReleaseError(RuntimeError):
    pass


def run(root: Path, *command: str) -> str:
    result = subprocess.run(
        command, cwd=root, text=True, capture_output=True
    )
    if result.returncode:
        raise ReleaseError(
            f"{' '.join(command)} failed:\n{result.stdout}{result.stderr}"
        )
    return result.stdout.strip()


def next_version(current: str, requested: str) -> str:
    match = SEMVER.fullmatch(current)
    if match is None:
        raise ReleaseError(f"invalid current version {current!r}")
    if SEMVER.fullmatch(requested):
        return requested
    major, minor, patch = map(int, match.groups())
    if requested == "major":
        return f"{major + 1}.0.0"
    if requested == "minor":
        return f"{major}.{minor + 1}.0"
    if requested == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ReleaseError("expected major, minor, patch, or X.Y.Z")


def preflight(root: Path) -> None:
    if run(root, "git", "branch", "--show-current") != DEFAULT_BRANCH:
        raise ReleaseError(f"release from {DEFAULT_BRANCH}")
    if run(root, "git", "status", "--porcelain"):
        raise ReleaseError("working tree is not clean")
    run(root, "git", "fetch", "--quiet", "origin", DEFAULT_BRANCH)
    if run(root, "git", "rev-parse", "HEAD") != run(
        root, "git", "rev-parse", f"origin/{DEFAULT_BRANCH}"
    ):
        raise ReleaseError(f"HEAD must equal origin/{DEFAULT_BRANCH}")


def planned_version(root: Path, requested: str) -> str:
    pom = root / "pom.xml"
    text = pom.read_text()
    match = POM_VERSION.search(text)
    if match is None:
        raise ReleaseError("pom.xml project version not found")
    return next_version(match.group(2), requested)


def update_version(root: Path, version: str) -> None:
    pom = root / "pom.xml"
    text = pom.read_text()
    pom.write_text(
        POM_VERSION.sub(
            rf"\g<1>{version}\g<3>", text, count=1
        )
    )


def roll_changelog(root: Path, version: str) -> None:
    path = root / "CHANGELOG.md"
    text = path.read_text()
    marker = "## Unreleased"
    if text.count(marker) != 1:
        raise ReleaseError("CHANGELOG.md needs one Unreleased section")
    start = text.index(marker) + len(marker)
    next_heading = text.find("\n## ", start)
    end = len(text) if next_heading < 0 else next_heading
    if not text[start:end].strip():
        raise ReleaseError("Unreleased changelog is empty")
    path.write_text(text.replace(marker, f"{marker}\n\n## {version}", 1))


def release(root: Path, requested: str) -> str:
    preflight(root)
    version = planned_version(root, requested)
    tag = f"v{version}"
    if run(root, "git", "tag", "--list", tag):
        raise ReleaseError(f"{tag} already exists")
    if run(root, "git", "ls-remote", "--tags", "origin", tag):
        raise ReleaseError(f"{tag} already exists on origin")
    roll_changelog(root, version)
    update_version(root, version)
    run(root, "mvn", "-q", "clean", "package", "assembly:single", "-DskipTests")
    run(root, "uv", "build")
    run(root, "git", "add", "pom.xml", "CHANGELOG.md")
    run(root, "git", "commit", "-m", f"Release {version}")
    run(root, "git", "tag", "-a", tag, "-m", f"Release {version}")
    run(
        root,
        "git",
        "push",
        "--atomic",
        "origin",
        f"HEAD:refs/heads/{DEFAULT_BRANCH}",
        f"refs/tags/{tag}",
    )
    return version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", help="major, minor, patch, or X.Y.Z")
    args = parser.parse_args(argv)
    try:
        version = release(Path(__file__).resolve().parents[1], args.version)
    except ReleaseError as error:
        print(f"release refused: {error}", file=sys.stderr)
        return 2
    print(f"released {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
