from pathlib import Path
import zipfile

import pytest

from tools.setup.ghidra import resolve_ghidra_user_dir
from tools.setup.versioning import (
    infer_ghidra_install_meta,
    is_ghidra_version_compatible,
)


def install(root: Path, version: str) -> Path:
    properties = root / "Ghidra" / "application.properties"
    properties.parent.mkdir(parents=True)
    properties.write_text(
        f"application.version={version}\napplication.release.name=PUBLIC\n"
    )
    return root


def test_installed_metadata_overrides_a_misleading_directory_name(tmp_path):
    root = install(tmp_path / "ghidra_12.2_PUBLIC", "12.1")
    assert infer_ghidra_install_meta(root) == ("12.1", "PUBLIC")
    with pytest.raises(ValueError, match="12.2 is required"):
        resolve_ghidra_user_dir(root, tmp_path / "user")


def test_only_the_exact_release_is_accepted():
    assert is_ghidra_version_compatible("12.2", "12.2")
    for other in ("12.1", "12.2.0", "12.2.1", "13.0", ""):
        assert not is_ghidra_version_compatible("12.2", other)


def test_missing_metadata_does_not_select_an_older_user_directory(tmp_path):
    (tmp_path / "user" / "ghidra_12.1_PUBLIC").mkdir(parents=True)
    with pytest.raises(FileNotFoundError):
        resolve_ghidra_user_dir(tmp_path / "missing", tmp_path / "user")


def test_current_user_directory_does_not_need_to_exist(tmp_path):
    root = install(tmp_path / "custom-name", "12.2")
    assert resolve_ghidra_user_dir(root, tmp_path / "user") == (
        tmp_path / "user" / "ghidra_12.2_PUBLIC"
    )


def test_bad_archive_preserves_the_installed_jar(tmp_path, monkeypatch):
    from tools.setup import ghidra

    root = install(tmp_path / "install", "12.2")
    user = tmp_path / "user"
    monkeypatch.setattr(ghidra, "ghidra_user_base_dir", lambda: user)
    jar = user / "ghidra_12.2_PUBLIC/Extensions/GhidraMCP-next/lib/GhidraMCP-next.jar"
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"existing")
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip")
    with pytest.raises(zipfile.BadZipFile):
        ghidra.install_user_extension(tmp_path, root, bad)
    assert jar.read_bytes() == b"existing"
