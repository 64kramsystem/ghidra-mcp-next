from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import bridge_version


def test_environment_override_has_priority(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(bridge_version.BRIDGE_VERSION_ENV, "20260724.192926")

    assert bridge_version.get_bridge_version(Path("/not/a/repository")) == ("20260724.192926")


def test_environment_override_must_be_pep440_timestamp(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv(bridge_version.BRIDGE_VERSION_ENV, "20260724-192926")

    with pytest.raises(ValueError, match="YYYYMMDD.HHMMSS"):
        bridge_version.get_bridge_version(Path("/not/a/repository"))


def test_official_sdist_directory_retains_its_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(bridge_version.BRIDGE_VERSION_ENV, raising=False)
    root = tmp_path / "ghidra_mcp_bridge-20260724.192926"
    root.mkdir()

    assert bridge_version.get_bridge_version(root) == "20260724.192926"


def test_git_commit_epoch_becomes_utc_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(bridge_version.BRIDGE_VERSION_ENV, raising=False)
    monkeypatch.setattr(
        bridge_version.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="1784914240\n",
        ),
    )

    assert bridge_version.get_bridge_version(tmp_path) == "20260724.173040"


def test_missing_version_source_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(bridge_version.BRIDGE_VERSION_ENV, raising=False)
    monkeypatch.setattr(
        bridge_version.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=128, stdout=""),
    )

    with pytest.raises(RuntimeError, match="Unable to derive"):
        bridge_version.get_bridge_version(tmp_path)
