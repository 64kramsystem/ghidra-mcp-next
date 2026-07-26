from __future__ import annotations

from pathlib import Path

import pytest

from tools import bridge_version

POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <artifactId>GhidraMCP-next</artifactId>
    <version>{version}</version>
</project>
"""


def write_pom(root: Path, version: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pom.xml").write_text(POM.format(version=version), encoding="utf-8")
    return root


def test_version_comes_from_the_pom(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(bridge_version.BRIDGE_VERSION_ENV, raising=False)
    root = write_pom(tmp_path / "checkout", "1.4.2")

    assert bridge_version.get_bridge_version(root) == "1.4.2"


def test_pom_without_a_version_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(bridge_version.BRIDGE_VERSION_ENV, raising=False)
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0"></project>', encoding="utf-8"
    )

    with pytest.raises(ValueError, match="no project <version>"):
        bridge_version.get_bridge_version(root)


def test_non_semver_pom_version_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(bridge_version.BRIDGE_VERSION_ENV, raising=False)
    root = write_pom(tmp_path / "checkout", "20260724.192926")

    with pytest.raises(ValueError, match="semantic version"):
        bridge_version.get_bridge_version(root)


def test_official_sdist_directory_retains_its_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """An sdist may omit the pom, so the directory name is the fallback."""
    monkeypatch.delenv(bridge_version.BRIDGE_VERSION_ENV, raising=False)
    root = tmp_path / "ghidra_mcp_bridge-1.4.2"
    root.mkdir()

    assert bridge_version.get_bridge_version(root) == "1.4.2"


def test_pom_wins_over_the_sdist_directory_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """With both present the pom decides, so a renamed directory cannot mislead."""
    monkeypatch.delenv(bridge_version.BRIDGE_VERSION_ENV, raising=False)
    root = write_pom(tmp_path / "ghidra_mcp_bridge-9.9.9", "1.4.2")

    assert bridge_version.get_bridge_version(root) == "1.4.2"


def test_override_is_accepted_where_there_is_no_pom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv(bridge_version.BRIDGE_VERSION_ENV, "2.0.0")

    assert bridge_version.get_bridge_version(tmp_path / "exported") == "2.0.0"


def test_override_must_be_semver(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(bridge_version.BRIDGE_VERSION_ENV, "20260724.192926")

    with pytest.raises(ValueError, match="semantic version"):
        bridge_version.get_bridge_version(Path("/not/a/repository"))


def test_override_disagreeing_with_the_pom_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A silent disagreement would defeat the coupling the pom exists to give."""
    monkeypatch.setenv(bridge_version.BRIDGE_VERSION_ENV, "2.0.0")
    root = write_pom(tmp_path / "checkout", "1.4.2")

    with pytest.raises(ValueError, match="disagrees with pom.xml"):
        bridge_version.get_bridge_version(root)


def test_override_agreeing_with_the_pom_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv(bridge_version.BRIDGE_VERSION_ENV, "1.4.2")
    root = write_pom(tmp_path / "checkout", "1.4.2")

    assert bridge_version.get_bridge_version(root) == "1.4.2"


def test_missing_version_source_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(bridge_version.BRIDGE_VERSION_ENV, raising=False)

    with pytest.raises(RuntimeError, match="Unable to derive the bridge version"):
        bridge_version.get_bridge_version(tmp_path / "bare")
