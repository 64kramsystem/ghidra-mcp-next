"""Derive the Python bridge version from the project's semantic version."""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

BRIDGE_VERSION_ENV = "GHIDRA_MCP_BRIDGE_VERSION"
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_SDIST_RE = re.compile(r"^ghidra_mcp_bridge-([0-9]+\.[0-9]+\.[0-9]+)$")


def _validate_version(value: str) -> str:
    if not _VERSION_RE.fullmatch(value):
        raise ValueError(f"{BRIDGE_VERSION_ENV} must be a semantic version X.Y.Z")
    return value


def _version_from_sdist_root(repo_root: Path) -> str | None:
    match = _SDIST_RE.fullmatch(repo_root.name)
    return match.group(1) if match else None


def _version_from_pom(repo_root: Path) -> str | None:
    """Read the project version from the pom, when there is one.

    The pom is the single source of truth: the bridge wheel and the Ghidra
    extension are built from one commit and released together, so they carry one
    version. An sdist may omit the pom, hence the optional return.

    Parsed inline rather than through ``tools.setup.versioning``: hatch invokes
    this file directly as a version hook, with no package context, so a
    ``tools.*`` import fails. Keeping it self-contained also means an sdist needs
    only this file and ``pom.xml``.
    """
    pom_path = repo_root / "pom.xml"
    if not pom_path.is_file():
        return None

    root = ET.parse(pom_path).getroot()
    namespace = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    node = root.find("m:version", namespace) if namespace else root.find("version")
    if node is None or node.text is None or not node.text.strip():
        raise ValueError("pom.xml has no project <version>")
    return _validate_version(node.text.strip())


def get_bridge_version(repo_root: Path | None = None) -> str:
    """Return the bridge version without modifying the source tree.

    Repository builds read ``pom.xml``. Official source distributions retain
    their version in the extracted directory name, since the pom may be absent.
    The environment override exists for exported trees that have neither.
    """

    root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
    override = os.environ.get(BRIDGE_VERSION_ENV)
    pom_version = _version_from_pom(root)

    if override:
        validated = _validate_version(override)
        # Refuse a silent disagreement: an override that differs from the pom
        # would defeat the coupling it exists to work around.
        if pom_version is not None and validated != pom_version:
            raise ValueError(
                f"{BRIDGE_VERSION_ENV}={validated} disagrees with pom.xml "
                f"version {pom_version}; unset the override or align them"
            )
        return validated

    if pom_version is not None:
        return pom_version

    sdist_version = _version_from_sdist_root(root)
    if sdist_version:
        return sdist_version

    raise RuntimeError(
        "Unable to derive the bridge version: build from a checkout containing "
        f"pom.xml, an official sdist, or set {BRIDGE_VERSION_ENV}"
    )


if __name__ == "__main__":
    print(get_bridge_version())
