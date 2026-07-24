"""Derive the Python bridge version from its latest source change."""

from __future__ import annotations

import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

BRIDGE_VERSION_ENV = "GHIDRA_MCP_BRIDGE_VERSION"
BRIDGE_VERSION_PATHS = (
    "python/bridge_mcp_ghidra",
    "pyproject.toml",
    "tools/bridge_version.py",
    "README.md",
    "LICENSE",
    "NOTICE",
    ".gitignore",
)
_VERSION_RE = re.compile(r"^[0-9]{8}\.[0-9]{6}$")
_SDIST_RE = re.compile(r"^ghidra_mcp_bridge-([0-9]{8}\.[0-9]{6})$")


def _validate_version(value: str) -> str:
    if not _VERSION_RE.fullmatch(value):
        raise ValueError(f"{BRIDGE_VERSION_ENV} must use PEP 440 format YYYYMMDD.HHMMSS")
    datetime.strptime(value, "%Y%m%d.%H%M%S")
    return value


def _version_from_sdist_root(repo_root: Path) -> str | None:
    match = _SDIST_RE.fullmatch(repo_root.name)
    return match.group(1) if match else None


def _version_from_git(repo_root: Path) -> str | None:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "log",
            "-1",
            "--format=%ct",
            "--",
            *BRIDGE_VERSION_PATHS,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    raw_timestamp = completed.stdout.strip()
    if completed.returncode != 0 or not raw_timestamp.isdigit():
        return None
    changed_at = datetime.fromtimestamp(int(raw_timestamp), tz=UTC)
    return changed_at.strftime("%Y%m%d.%H%M%S")


def get_bridge_version(repo_root: Path | None = None) -> str:
    """Return the bridge build version without modifying the source tree.

    Official source distributions retain their version in the extracted
    directory name. Repository builds derive it from the newest commit that
    touched bridge or bridge-packaging inputs. An environment override supports
    exported source trees that have neither Git history nor an sdist name.
    """

    override = os.environ.get(BRIDGE_VERSION_ENV)
    if override:
        return _validate_version(override)

    root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
    sdist_version = _version_from_sdist_root(root)
    if sdist_version:
        return sdist_version

    git_version = _version_from_git(root)
    if git_version:
        return git_version

    raise RuntimeError(
        "Unable to derive the bridge version: build from a Git checkout, "
        f"an official sdist, or set {BRIDGE_VERSION_ENV}"
    )


if __name__ == "__main__":
    print(get_bridge_version())
