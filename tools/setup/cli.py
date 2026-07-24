from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from .envfile import load_env_file
from .ghidra import (
    clean_all,
    collect_preflight_issues,
    deploy_to_ghidra,
    install_ghidra_dependencies,
    start_ghidra,
)
from .python_env import detect_repo_root, find_repo_python
from .maven import find_maven_command, run_maven
from .requirements import (
    ensure_uv_available,
    execute_install_plan,
    make_install_plan,
    uv_sync_command,
)
from .versioning import (
    infer_ghidra_version_from_path,
    is_ghidra_version_compatible,
    read_pom_ghidra_version,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cross-platform repo setup helpers")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser(
        "install-python-deps",
        help="Install the repo's Python dependency groups via uv sync",
    )
    install_parser.set_defaults(func=cmd_install_python_deps)

    verify_parser = subparsers.add_parser(
        "verify-ghidra",
        help="Verify optional Ghidra installation compatibility",
    )
    verify_parser.add_argument(
        "--ghidra-path",
        type=Path,
        help="Optional Ghidra installation path. Defaults to GHIDRA_PATH from .env when set.",
    )
    verify_parser.set_defaults(func=cmd_verify_ghidra)

    preflight_parser = subparsers.add_parser(
        "preflight",
        help="Check Python, build-tool, and optional Ghidra path availability",
    )
    preflight_parser.add_argument(
        "--ghidra-path",
        type=Path,
        help="Optional Ghidra installation path. Defaults to GHIDRA_PATH from .env when set.",
    )
    preflight_parser.add_argument(
        "--strict",
        action="store_true",
        help="Also check network reachability for Maven Central and PyPI.",
    )
    preflight_parser.set_defaults(func=cmd_preflight)

    build_parser = subparsers.add_parser(
        "build",
        help="Build the plugin jar and extension ZIP",
    )
    build_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the build command without running it.",
    )
    build_parser.set_defaults(func=cmd_build)

    clean_parser = subparsers.add_parser(
        "clean",
        help="Remove build outputs",
    )
    clean_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the clean command without running it.",
    )
    clean_parser.set_defaults(func=cmd_clean)

    test_parser = subparsers.add_parser(
        "run-tests",
        help="Run Java tests",
    )
    test_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the test command without running it.",
    )
    test_parser.set_defaults(func=cmd_run_tests)

    ghidra_deps_parser = subparsers.add_parser(
        "install-ghidra-deps",
        help="Install Ghidra jars to the local Maven repository for compilation",
    )
    ghidra_deps_parser.add_argument(
        "--ghidra-path",
        type=Path,
        help="Optional Ghidra installation path. Defaults to GHIDRA_PATH from .env when set.",
    )
    ghidra_deps_parser.add_argument(
        "--force",
        action="store_true",
        help="Reinstall jars even if already present.",
    )
    ghidra_deps_parser.add_argument("--dry-run", action="store_true", help="Print actions without executing them.")
    ghidra_deps_parser.set_defaults(func=cmd_install_ghidra_deps)

    deploy_parser = subparsers.add_parser(
        "deploy",
        help="Copy the built plugin archive and bridge files into a Ghidra installation",
    )
    deploy_parser.add_argument(
        "--ghidra-path",
        type=Path,
        help="Optional Ghidra installation path. Defaults to GHIDRA_PATH from .env when set.",
    )
    deploy_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print copy actions without executing them.",
    )
    deploy_parser.add_argument(
        "--test",
        action="append",
        choices=[
            "benchmark-read",
            "benchmark-write",
            "debugger-live",
            "endpoint-catalog",
            "multi-program",
            "negative-contract",
            "release",
            "selected-contract",
        ],
        default=[],
        help=(
            "Run an optional post-deploy test tier. May be passed multiple times. "
            "A plain deploy only runs MCP health/schema checks and does not import Benchmark.dll. "
            "Use --test release before cutting releases, or set GHIDRA_MCP_DEPLOY_TESTS in local .env."
        ),
    )
    deploy_parser.set_defaults(func=cmd_deploy)

    start_parser = subparsers.add_parser(
        "start-ghidra",
        help="Start the configured Ghidra installation",
    )
    start_parser.add_argument(
        "--ghidra-path",
        type=Path,
        help="Optional Ghidra installation path. Defaults to GHIDRA_PATH from .env when set.",
    )
    start_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the launcher command without starting Ghidra.",
    )
    start_parser.set_defaults(func=cmd_start_ghidra)

    clean_all_parser = subparsers.add_parser(
        "clean-all",
        help="Remove build output and common local cache artifacts",
    )
    clean_all_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print cleanup actions without executing them.",
    )
    clean_all_parser.set_defaults(func=cmd_clean_all)

    ensure_prereqs_parser = subparsers.add_parser(
        "ensure-prereqs",
        help="Install Python dependencies and prepare Ghidra jars for compilation",
    )
    ensure_prereqs_parser.add_argument(
        "--ghidra-path",
        type=Path,
        help="Optional Ghidra installation path. Defaults to GHIDRA_PATH from .env when set.",
    )
    ensure_prereqs_parser.add_argument(
        "--force",
        action="store_true",
        help="Reinstall Ghidra jars even if present in ~/.m2.",
    )
    ensure_prereqs_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print dependency actions without executing them.",
    )
    ensure_prereqs_parser.set_defaults(func=cmd_ensure_prereqs)

    return parser


def cmd_install_python_deps(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    plan = make_install_plan(repo_root)
    execute_install_plan(plan)
    return 0


def _load_repo_env(repo_root: Path) -> dict[str, str]:
    return load_env_file(repo_root / ".env")


def _resolve_ghidra_path(repo_root: Path, ghidra_path: Path | None) -> Path | None:
    if ghidra_path is not None:
        return ghidra_path.resolve()

    env_values = _load_repo_env(repo_root)
    raw_path = env_values.get("GHIDRA_PATH", "").strip()
    if not raw_path:
        return None

    return Path(raw_path)


def _require_ghidra_path(repo_root: Path, ghidra_path: Path | None) -> Path:
    resolved_path = _resolve_ghidra_path(repo_root, ghidra_path)
    if resolved_path is None:
        raise ValueError("A Ghidra path is required. Pass --ghidra-path or set GHIDRA_PATH in .env.")
    return resolved_path


def cmd_verify_ghidra(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    ghidra_path = _resolve_ghidra_path(repo_root, args.ghidra_path)

    ghidra_version = read_pom_ghidra_version(repo_root)
    print(f"Ghidra version from pom.xml: {ghidra_version}")
    if ghidra_path is None:
        print("No Ghidra path configured; pom.xml compatibility target verified.")
        return 0
    inferred_version = infer_ghidra_version_from_path(ghidra_path)
    print(f"Ghidra path: {ghidra_path}")
    if inferred_version is None:
        print("Unable to infer Ghidra version from the provided path.")
        return 1
    print(f"Ghidra version from path: {inferred_version}")
    if not is_ghidra_version_compatible(ghidra_version, inferred_version):
        print(
            "Version mismatch detected between pom.xml and Ghidra path.",
            file=sys.stderr,
        )
        return 1
    if inferred_version != ghidra_version:
        print(
            f"Note: Ghidra path is {inferred_version}, pom.xml pins "
            f"{ghidra_version} — same minor series, treated as compatible."
        )
    print("Version check passed.")
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    python_executable = find_repo_python(repo_root)

    try:
        maven_command = find_maven_command()
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Python: {python_executable}")
    print(f"Maven: {maven_command}")
    try:
        ensure_uv_available()
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("uv: available")
    if shutil.which("java") is None:
        print("Java not found on PATH.", file=sys.stderr)
        return 1
    print("Java: available on PATH")
    ghidra_version = read_pom_ghidra_version(repo_root)
    ghidra_path = _resolve_ghidra_path(repo_root, args.ghidra_path)
    print(f"Ghidra version from pom.xml: {ghidra_version}")
    if ghidra_path is None:
        print("No Ghidra path configured; skipped Ghidra-specific preflight checks.")
        return 0
    inferred_version = infer_ghidra_version_from_path(ghidra_path)
    print(f"Ghidra path: {ghidra_path}")
    if inferred_version is None:
        print("Unable to infer Ghidra version from the provided path.", file=sys.stderr)
        return 1
    print(f"Ghidra version from path: {inferred_version}")
    if not is_ghidra_version_compatible(ghidra_version, inferred_version):
        print(
            "Version mismatch detected between pom.xml and Ghidra path.",
            file=sys.stderr,
        )
        return 1
    if inferred_version != ghidra_version:
        print(
            f"Note: Ghidra path is {inferred_version}, pom.xml pins "
            f"{ghidra_version} — same minor series, treated as compatible."
        )
    issues = collect_preflight_issues(
        repo_root,
        ghidra_path,
        strict=args.strict,
    )
    if issues:
        print("Preflight checks failed:", file=sys.stderr)
        for issue in issues:
            print(f"- {issue}", file=sys.stderr)
        return 1
    print("Preflight checks passed.")
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    return run_maven(
        detect_repo_root(),
        ["clean", "package", "assembly:single", "-DskipTests"],
        dry_run=args.dry_run,
    )


def cmd_clean(args: argparse.Namespace) -> int:
    return run_maven(detect_repo_root(), ["clean"], dry_run=args.dry_run)


def cmd_run_tests(args: argparse.Namespace) -> int:
    return run_maven(detect_repo_root(), ["test"], dry_run=args.dry_run)


def cmd_install_ghidra_deps(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    ghidra_path = _require_ghidra_path(repo_root, args.ghidra_path)
    return install_ghidra_dependencies(repo_root, ghidra_path, force=args.force, dry_run=args.dry_run)


def cmd_deploy(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    ghidra_path = _require_ghidra_path(repo_root, args.ghidra_path)
    return deploy_to_ghidra(repo_root, ghidra_path, dry_run=args.dry_run, test_modes=args.test)


def cmd_start_ghidra(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    ghidra_path = _require_ghidra_path(repo_root, args.ghidra_path)
    return start_ghidra(ghidra_path, dry_run=args.dry_run)


def cmd_clean_all(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    return clean_all(repo_root, dry_run=args.dry_run)


def cmd_ensure_prereqs(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    plan = make_install_plan(repo_root)

    if args.dry_run:
        print(f"DRY RUN: {' '.join(uv_sync_command(plan))}")
    else:
        execute_install_plan(plan)
        print("Python dependencies are ready.")

    ghidra_path = _require_ghidra_path(repo_root, args.ghidra_path)
    return install_ghidra_dependencies(repo_root, ghidra_path, force=args.force, dry_run=args.dry_run)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
