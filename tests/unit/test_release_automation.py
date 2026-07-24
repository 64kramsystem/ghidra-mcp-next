from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tools.release_automation import (
    decode_changed_paths,
    path_affects_release,
    prepare_release,
    roll_changelog,
    should_publish,
)


@pytest.mark.parametrize(
    "path",
    [
        ".gitignore",
        "pom.xml",
        "pyproject.toml",
        "tools/bridge_version.py",
        "README.md",
        "LICENSE",
        "NOTICE",
        "python/bridge_mcp_ghidra/server.py",
        "src/main/java/com/xebyte/GhidraMCPPlugin.java",
        "src/assembly/ghidra-extension.xml",
        "./python/bridge_mcp_ghidra/__init__.py",
    ],
)
def test_release_artifact_inputs_are_in_scope(path: str):
    assert path_affects_release(path)


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/tests.yml",
        "docs/TESTING.md",
        "ghidra_scripts/ApplyDWORD.java",
        "src/test/java/com/xebyte/AppTest.java",
        "tests/unit/test_release_automation.py",
        "tools/release_automation.py",
        "uv.lock",
        "CHANGELOG.md",
        "README.md.bak",
        "python-notes/example.txt",
    ],
)
def test_non_artifact_inputs_are_out_of_scope(path: str):
    assert not path_affects_release(path)


def test_should_publish_accepts_full_changed_path_sequence():
    assert should_publish(["docs/TESTING.md", "python/bridge_mcp_ghidra/server.py"])
    assert not should_publish(["docs/TESTING.md", "tests/unit/test_setup_cli.py"])


def test_decode_changed_paths_supports_git_null_output():
    assert decode_changed_paths(b"docs/with spaces.md\0python/package.py\0", nul_terminated=True) == [
        "docs/with spaces.md",
        "python/package.py",
    ]


def _write_project(root: Path):
    (root / "pom.xml").write_text(
        """\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>test</groupId>
  <artifactId>GhidraMCP-next</artifactId>
  <version>0.0.0</version>
  <properties><ghidra.version>12.1.2</ghidra.version></properties>
</project>
""",
        encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text(
        """\
# Changelog

## Unreleased

### Changed

- Removed semantic versions from release identities.

## v1.2.3

- Previous release.
""",
        encoding="utf-8",
    )


def _write_artifacts(root: Path) -> tuple[Path, Path]:
    extension_dir = root / "extension"
    python_dir = root / "python-dist"
    extension_dir.mkdir()
    python_dir.mkdir()
    (extension_dir / "GhidraMCP-next-20260724-184501.zip").write_bytes(b"extension")
    (python_dir / "ghidra_mcp_bridge-20260724.173040-py3-none-any.whl").write_bytes(b"wheel")
    (python_dir / "ghidra_mcp_bridge-20260724.173040.tar.gz").write_bytes(b"sdist")
    return extension_dir, python_dir


def test_prepare_release_writes_verified_metadata_hashes_and_notes(tmp_path: Path):
    _write_project(tmp_path)
    extension_dir, python_dir = _write_artifacts(tmp_path)
    output_dir = tmp_path / "release"
    sha = "0123456789abcdef0123456789abcdef01234567"

    metadata = prepare_release(
        repo_root=tmp_path,
        extension_dir=extension_dir,
        python_dir=python_dir,
        output_dir=output_dir,
        build_timestamp="20260724-184501",
        commit_sha=sha.upper(),
        expected_ghidra_version="12.1.2",
    )

    assert metadata["tag"] == "build-20260724-184501-0123456789ab"
    assert metadata["name"] == "GhidraMCP-next 20260724-184501"
    assert "project_version" not in metadata
    assert metadata["bridge_version"] == "20260724.173040"
    assert metadata["commit_sha"] == sha
    assert [item["kind"] for item in metadata["artifacts"]] == [
        "ghidra_extension",
        "python_wheel",
        "python_sdist",
    ]
    assert json.loads((output_dir / "release-metadata.json").read_text()) == metadata

    expected_hashes = {
        "GhidraMCP-next-20260724-184501.zip": hashlib.sha256(b"extension").hexdigest(),
        "ghidra_mcp_bridge-20260724.173040-py3-none-any.whl": hashlib.sha256(b"wheel").hexdigest(),
        "ghidra_mcp_bridge-20260724.173040.tar.gz": hashlib.sha256(b"sdist").hexdigest(),
    }
    checksum_lines = (output_dir / "SHA256SUMS").read_text().splitlines()
    assert checksum_lines == sorted(f"{digest}  {name}" for name, digest in expected_hashes.items())
    notes = (output_dir / "release-notes.md").read_text()
    assert notes.startswith("# GhidraMCP-next 20260724-184501\n")
    assert "Project version" not in notes
    assert "- Bridge version: `20260724.173040`" in notes
    assert "- Removed semantic versions from release identities." in notes
    assert "Previous release" not in notes
    assert sha in notes
    assert all(name in notes for name in expected_hashes)
    assert "| `GhidraMCP-next-20260724-184501.zip` | 9 |" in notes


@pytest.mark.parametrize(
    ("timestamp", "sha", "message"),
    [
        ("20260230-120000", "0" * 40, "not a valid UTC"),
        ("20260724T120000Z", "0" * 40, "UTC format"),
        ("20260724-120000", "abc", "40 hexadecimal"),
    ],
)
def test_prepare_release_rejects_invalid_identity(tmp_path: Path, timestamp: str, sha: str, message: str):
    _write_project(tmp_path)
    extension_dir, python_dir = _write_artifacts(tmp_path)

    with pytest.raises(ValueError, match=message):
        prepare_release(
            repo_root=tmp_path,
            extension_dir=extension_dir,
            python_dir=python_dir,
            output_dir=tmp_path / "release",
            build_timestamp=timestamp,
            commit_sha=sha,
            expected_ghidra_version="12.1.2",
        )


def test_prepare_release_rejects_ambiguous_artifacts(tmp_path: Path):
    _write_project(tmp_path)
    extension_dir, python_dir = _write_artifacts(tmp_path)
    (python_dir / "second.whl").write_bytes(b"duplicate")

    with pytest.raises(ValueError, match="exactly one Python wheel.*found 2"):
        prepare_release(
            repo_root=tmp_path,
            extension_dir=extension_dir,
            python_dir=python_dir,
            output_dir=tmp_path / "release",
            build_timestamp="20260724-120000",
            commit_sha="0" * 40,
            expected_ghidra_version="12.1.2",
        )


def test_prepare_release_rejects_mismatched_bridge_versions(tmp_path: Path):
    _write_project(tmp_path)
    extension_dir, python_dir = _write_artifacts(tmp_path)
    sdist = python_dir / "ghidra_mcp_bridge-20260724.173040.tar.gz"
    sdist.rename(python_dir / "ghidra_mcp_bridge-20260724.173041.tar.gz")

    with pytest.raises(ValueError, match="versions do not match"):
        prepare_release(
            repo_root=tmp_path,
            extension_dir=extension_dir,
            python_dir=python_dir,
            output_dir=tmp_path / "release",
            build_timestamp="20260724-184501",
            commit_sha="0" * 40,
            expected_ghidra_version="12.1.2",
        )


def test_prepare_release_rejects_missing_artifact_directory(tmp_path: Path):
    _write_project(tmp_path)
    extension_dir, _ = _write_artifacts(tmp_path)

    with pytest.raises(ValueError, match="directory does not exist"):
        prepare_release(
            repo_root=tmp_path,
            extension_dir=extension_dir,
            python_dir=tmp_path / "missing",
            output_dir=tmp_path / "release",
            build_timestamp="20260724-120000",
            commit_sha="0" * 40,
            expected_ghidra_version="12.1.2",
        )


def test_roll_changelog_moves_unreleased_entries_under_release_name(tmp_path: Path):
    _write_project(tmp_path)
    changelog = tmp_path / "CHANGELOG.md"

    assert roll_changelog(changelog, "20260724-184501")
    assert changelog.read_text(encoding="utf-8") == """\
# Changelog

## Unreleased

## GhidraMCP-next 20260724-184501

### Changed

- Removed semantic versions from release identities.

## v1.2.3

- Previous release.
"""

    assert not roll_changelog(changelog, "20260724-184501")


def test_roll_changelog_rejects_missing_unreleased_heading(tmp_path: Path):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# Changelog\n", encoding="utf-8")

    with pytest.raises(ValueError, match="exactly one"):
        roll_changelog(changelog, "20260724-184501")


def test_classify_cli_reads_null_terminated_git_paths():
    repo_root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.release_automation",
            "classify",
            "--null",
        ],
        cwd=repo_root,
        input=b"docs/TESTING.md\0python/bridge_mcp_ghidra/server.py\0",
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.splitlines() == [b"true"]
    assert result.stderr == b""


def test_timestamp_release_workflow_contract():
    repo_root = Path(__file__).resolve().parents[2]
    workflow_path = repo_root / ".github" / "workflows" / "tests.yml"
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow = yaml.load(workflow_text, Loader=yaml.BaseLoader)

    assert "workflow_dispatch" in workflow["on"]
    assert workflow["permissions"] == {"contents": "read"}

    jobs = workflow["jobs"]
    java = jobs["java-build"]
    assert "strategy" not in java
    assert set(java["outputs"]) == {"build_timestamp", "ghidra_version"}

    release = jobs["automatic-release"]
    assert release["permissions"] == {"contents": "write"}
    assert release["needs"] == ["java-build", "build-status"]
    assert "success()" in release["if"]
    assert release["concurrency"] == {
        "group": "automatic-release-${{ github.repository }}",
        "cancel-in-progress": "false",
    }
    assert all(
        job_name == "automatic-release" or job.get("permissions", {}).get("contents") != "write"
        for job_name, job in jobs.items()
    )

    steps = {step["name"]: step for step in release["steps"]}
    assert steps["Checkout release commit"]["with"]["fetch-depth"] == "0"
    classifier = steps["Check whether distributed artifacts can change"]["run"]
    assert 'git diff --name-only -z "$BEFORE" "$AFTER"' in classifier
    assert "python -m tools.release_automation classify --null" in classifier
    assert "github.event.before" in workflow_text
    prepare = steps["Prepare release metadata"]["run"]
    assert "--project-version" not in prepare
    create = steps["Create timestamp release"]["run"]
    assert '--title "${{ steps.prepare.outputs.name }}"' in create
    roll = steps["Roll released changelog entries"]["run"]
    assert "python -m tools.release_automation roll-changelog" in roll
    assert "git push origin HEAD:main" in roll

    python_steps = {step["name"]: step for step in jobs["python-tests"]["steps"] if "name" in step}
    expected_condition = "matrix.python-version == '3.14' && success()"
    assert python_steps["Build Python distributions"]["if"] == expected_condition
    assert python_steps["Upload release Python distributions"]["if"] == expected_condition
    assert python_steps["Upload release Python distributions"]["with"]["if-no-files-found"] == "error"
