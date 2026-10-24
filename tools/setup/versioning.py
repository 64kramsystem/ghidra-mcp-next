from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path


def read_pom_ghidra_version(repo_root: Path) -> str:
    pom_path = repo_root / "pom.xml"
    tree = ET.parse(pom_path)
    root = tree.getroot()
    namespace = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}

    def find_text(path: str) -> str:
        if namespace:
            node = root.find(path, namespace)
        else:
            node = root.find(path)
        if node is None or node.text is None:
            raise ValueError(f"Missing expected XML element: {path}")
        return node.text.strip()

    return find_text("m:properties/m:ghidra.version" if namespace else "properties/ghidra.version")


def read_pom_project_version(repo_root: Path) -> str:
    """Return the pom's own ``<version>``, the project's semantic version.

    Distinct from :func:`read_pom_ghidra_version`, which returns the
    ``<ghidra.version>`` property. Both live in the same file and confusing them
    yields Ghidra's version where the project's was wanted.
    """
    # Delegates so the pom-version parse exists once. bridge_version.py owns it
    # because hatch runs that file with no package context.
    from tools.bridge_version import get_bridge_version

    return get_bridge_version(repo_root)


def infer_ghidra_install_meta(ghidra_path: Path) -> tuple[str, str]:
    """Read authoritative version and release metadata from an installation."""
    properties = ghidra_path / "Ghidra" / "application.properties"
    values = dict(
        line.strip().split("=", 1)
        for line in properties.read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    )
    version = values.get("application.version", "")
    release = values.get("application.release.name", "")
    if not version or not release:
        raise ValueError(f"Missing Ghidra version/release metadata in {properties}")
    return version, release


def infer_ghidra_version_from_path(ghidra_path: Path) -> str:
    return infer_ghidra_install_meta(ghidra_path)[0]


def is_ghidra_version_compatible(required: str, installed: str) -> bool:
    """Only the exact Ghidra release used to compile the extension is supported."""
    return required == installed
