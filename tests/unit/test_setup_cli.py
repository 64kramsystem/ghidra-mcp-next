"""
Unit tests for tools.setup.cli — Maven command routing and helpers.

All tests run without a live Ghidra server or Maven installation.
Subprocess-calling functions are stubbed via monkeypatch.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _args(**kwargs) -> argparse.Namespace:
    defaults = dict(
        dry_run=False,
        ghidra_path=None,
        strict=False,
        force=False,
        test=[],
        new=None,
        old=None,
        tag=False,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ===========================================================================
# cmd_build
# ===========================================================================


def test_cmd_build_routes_to_maven(monkeypatch):
    from tools.setup import cli

    calls = []
    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "run_maven", lambda root, goals, **kw: calls.append((root, goals, kw)) or 0)
    assert cli.cmd_build(_args(dry_run=True)) == 0
    assert calls == [(Path("/repo"), ["clean", "package", "assembly:single", "-DskipTests"], {"dry_run": True})]


# ===========================================================================
# cmd_clean
# ===========================================================================


def test_cmd_clean_routes_to_maven(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_maven",
        lambda root, goals, dry_run=False: recorded.update({"goals": goals}) or 0,
    )

    cli.cmd_clean(_args())
    assert recorded["goals"] == ["clean"]


# ===========================================================================
# cmd_run_tests
# ===========================================================================


def test_cmd_run_tests_routes_to_maven(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_maven",
        lambda root, goals, dry_run=False: recorded.update({"goals": goals}) or 0,
    )

    cli.cmd_run_tests(_args())
    assert recorded["goals"] == ["test"]


# ===========================================================================
# cmd_deploy
# ===========================================================================


def test_cmd_deploy_routes_to_maven(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    called = []
    monkeypatch.setattr(
        cli,
        "deploy_to_ghidra",
        lambda root, path, dry_run=False, test_modes=None: called.append((path, test_modes)) or 0,
    )

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    result = cli.cmd_deploy(_args(ghidra_path=ghidra_path))

    assert result == 0
    assert called
    assert called[0][1] == []


def test_deploy_parser_accepts_release_test_tier():
    from tools.setup import cli

    parser = cli.build_parser()
    args = parser.parse_args(["deploy", "--ghidra-path", "C:/ghidra", "--test", "release"])

    assert args.test == ["release"]


def test_cmd_deploy_raises_when_no_ghidra_path(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    with pytest.raises(ValueError, match="Ghidra path is required"):
        cli.cmd_deploy(_args(ghidra_path=None))


# ===========================================================================
# cmd_start_ghidra
# ===========================================================================


def test_cmd_start_ghidra_routes_to_maven(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    called = []
    monkeypatch.setattr(cli, "start_ghidra", lambda path, dry_run=False: called.append(path) or 0)

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    result = cli.cmd_start_ghidra(_args(ghidra_path=ghidra_path))

    assert result == 0
    assert called


def test_cmd_start_ghidra_requires_ghidra_path(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    with pytest.raises(ValueError, match="Ghidra path is required"):
        cli.cmd_start_ghidra(_args(ghidra_path=None))


# ===========================================================================
# cmd_clean_all
# ===========================================================================


def test_cmd_clean_all_routes_to_maven(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))

    called = []
    monkeypatch.setattr(cli, "clean_all", lambda root, dry_run=False: called.append(root) or 0)

    cli.cmd_clean_all(_args())
    assert called


# ===========================================================================
# cmd_install_ghidra_deps
# ===========================================================================


def test_cmd_install_ghidra_deps_routes_to_maven(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    called = []
    monkeypatch.setattr(
        cli,
        "install_ghidra_dependencies",
        lambda root, path, force=False, dry_run=False: called.append(path) or 0,
    )

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    cli.cmd_install_ghidra_deps(_args(ghidra_path=ghidra_path))
    assert called


# ===========================================================================
# cmd_verify_ghidra
# ===========================================================================


def test_cmd_verify_ghidra_no_ghidra_path(tmp_path, monkeypatch, capsys):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "read_pom_ghidra_version", lambda root: "12.1")

    result = cli.cmd_verify_ghidra(_args(ghidra_path=None))

    assert result == 0
    out = capsys.readouterr().out
    assert "12.1" in out


def test_cmd_verify_ghidra_versions_match(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "read_pom_ghidra_version", lambda root: "12.1")
    monkeypatch.setattr(cli, "infer_ghidra_version_from_path", lambda path: "12.1")

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    result = cli.cmd_verify_ghidra(_args(ghidra_path=ghidra_path))

    assert result == 0


def test_cmd_verify_ghidra_version_mismatch(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "read_pom_ghidra_version", lambda root: "12.1")
    monkeypatch.setattr(cli, "infer_ghidra_version_from_path", lambda path: "11.0.0")

    ghidra_path = tmp_path / "ghidra_11.0.0_PUBLIC"
    ghidra_path.mkdir()
    result = cli.cmd_verify_ghidra(_args(ghidra_path=ghidra_path))

    assert result == 1


def test_cmd_verify_ghidra_uninferrable_path(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "read_pom_ghidra_version", lambda root: "12.1")
    monkeypatch.setattr(cli, "infer_ghidra_version_from_path", lambda path: None)

    ghidra_path = tmp_path / "custom-ghidra-dir"
    ghidra_path.mkdir()
    result = cli.cmd_verify_ghidra(_args(ghidra_path=ghidra_path))

    assert result == 1


# ===========================================================================
# _resolve_ghidra_path / _require_ghidra_path
# ===========================================================================


def test_resolve_ghidra_path_prefers_arg(tmp_path, monkeypatch):
    from tools.setup import cli

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    other_path = tmp_path / "other"
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {"GHIDRA_PATH": str(other_path)})

    resolved = cli._resolve_ghidra_path(tmp_path, ghidra_path)
    assert resolved == ghidra_path.resolve()


def test_resolve_ghidra_path_from_env(tmp_path, monkeypatch):
    from tools.setup import cli

    env_path = tmp_path / "ghidra_12.1_PUBLIC"
    env_path.mkdir()
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {"GHIDRA_PATH": str(env_path)})

    resolved = cli._resolve_ghidra_path(tmp_path, None)
    assert resolved == env_path


def test_resolve_ghidra_path_returns_none_when_missing(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    resolved = cli._resolve_ghidra_path(tmp_path, None)
    assert resolved is None


def test_require_ghidra_path_raises_when_missing(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    with pytest.raises(ValueError, match="Ghidra path is required"):
        cli._require_ghidra_path(tmp_path, None)


def test_require_ghidra_path_returns_path_when_set(tmp_path, monkeypatch):
    from tools.setup import cli

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    result = cli._require_ghidra_path(tmp_path, ghidra_path)
    assert result == ghidra_path.resolve()


# ===========================================================================
# cmd_preflight
# ===========================================================================


def test_cmd_preflight_maven_missing_maven_returns_1(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "find_repo_python", lambda root: Path("python"))

    def raise_not_found():
        raise FileNotFoundError("Maven not found on PATH")

    monkeypatch.setattr(cli, "find_maven_command", raise_not_found)

    result = cli.cmd_preflight(_args())
    assert result == 1


def test_cmd_preflight_maven_missing_java_returns_1(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "find_repo_python", lambda root: Path("python"))
    monkeypatch.setattr(cli, "find_maven_command", lambda: Path("/usr/bin/mvn"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: type("R", (), {"returncode": 0})())
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)

    result = cli.cmd_preflight(_args())
    assert result == 1


def test_cmd_preflight_maven_passes_without_ghidra_path(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "find_repo_python", lambda root: Path("python"))
    monkeypatch.setattr(cli, "find_maven_command", lambda: Path("/usr/bin/mvn"))
    monkeypatch.setattr(cli, "read_pom_ghidra_version", lambda root: "12.1")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: type("R", (), {"returncode": 0})())
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/java" if name == "java" else None)

    result = cli.cmd_preflight(_args(ghidra_path=None))
    assert result == 0


# ===========================================================================
# cmd_ensure_prereqs — dry run
# ===========================================================================


def test_cmd_ensure_prereqs_dry_run_prints_plan(tmp_path, monkeypatch, capsys):
    from tools.setup import cli
    from tools.setup.requirements import InstallPlan

    fake_plan = InstallPlan(
        repo_root=tmp_path,
        groups=("dev",),
    )

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "make_install_plan", lambda *a, **kw: fake_plan)
    monkeypatch.setattr(cli, "execute_install_plan", lambda plan: None)
    monkeypatch.setattr(
        cli,
        "install_ghidra_dependencies",
        lambda root, path, force=False, dry_run=False: 0,
    )

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    result = cli.cmd_ensure_prereqs(_args(ghidra_path=ghidra_path, dry_run=True))

    assert result == 0
    assert "DRY RUN" in capsys.readouterr().out


# ===========================================================================
# argparse
# ===========================================================================


def test_parser_build_subcommand_recognized():
    from tools.setup.cli import build_parser

    args = build_parser().parse_args(["build"])
    assert args.command == "build"


def test_parser_deploy_subcommand_recognized():
    from tools.setup.cli import build_parser

    args = build_parser().parse_args(["deploy"])
    assert args.command == "deploy"


def test_parser_install_python_deps_rejects_obsolete_flags():
    # --requirements / --python were vestiges of the old pip flow; uv sync
    # ignored their values, so they're removed rather than left to silently
    # mask misconfigured automation.
    from tools.setup.cli import build_parser

    parser = build_parser()
    for flag, value in (("--requirements", "requirements.txt"), ("--python", "python3")):
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["install-python-deps", flag, value])
        assert exc_info.value.code != 0


def test_parser_install_python_deps_rejects_removed_debugger_flags():
    from tools.setup.cli import build_parser

    parser = build_parser()
    for flag in ("--with-debugger", "--use-debugger-toggle"):
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["install-python-deps", flag])
        assert exc_info.value.code != 0


def test_parser_install_python_deps_accepts_no_flags():
    from tools.setup.cli import build_parser

    args = build_parser().parse_args(["install-python-deps"])
    assert args.command == "install-python-deps"


def test_parser_verify_ghidra_subcommand_recognized():
    from tools.setup.cli import build_parser

    args = build_parser().parse_args(["verify-ghidra"])
    assert args.command == "verify-ghidra"


# ===========================================================================
# main() integration
# ===========================================================================


def test_main_build_maven(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "run_maven", lambda root, goals, dry_run=False: 0)

    assert cli.main(["build"]) == 0


def test_main_clean_maven(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "run_maven", lambda root, goals, dry_run=False: 0)

    assert cli.main(["clean"]) == 0


def test_main_run_tests_maven(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "run_maven", lambda root, goals, dry_run=False: 0)

    assert cli.main(["run-tests"]) == 0
