from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

from tools.setup.versioning import read_pom_versions

_RELEASE_FILES = frozenset(
    {
        "LICENSE",
        "README.md",
        "pom.xml",
        "pyproject.toml",
    }
)
_RELEASE_PREFIXES = ("python/", "src/assembly/", "src/main/")
_TIMESTAMP_RE = re.compile(r"^[0-9]{8}-[0-9]{6}$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_UNRELEASED_RE = re.compile(r"(?m)^## Unreleased[ \t]*$")
_LEVEL_TWO_HEADING_RE = re.compile(r"(?m)^## .+$")


def path_affects_release(path: str) -> bool:
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized in _RELEASE_FILES or normalized.startswith(_RELEASE_PREFIXES)


def should_publish(changed_paths: Iterable[str]) -> bool:
    return any(path_affects_release(path) for path in changed_paths)


def decode_changed_paths(payload: bytes, *, nul_terminated: bool) -> list[str]:
    separator = b"\0" if nul_terminated else b"\n"
    return [item.decode("utf-8", errors="surrogateescape") for item in payload.split(separator) if item]


def _validated_timestamp(value: str) -> str:
    if not _TIMESTAMP_RE.fullmatch(value):
        raise ValueError("build timestamp must use UTC format YYYYMMDD-HHMMSS")
    try:
        datetime.strptime(value, "%Y%m%d-%H%M%S")
    except ValueError as exc:
        raise ValueError("build timestamp is not a valid UTC date and time") from exc
    return value


def _validated_sha(value: str) -> str:
    if not _SHA_RE.fullmatch(value):
        raise ValueError("commit SHA must contain exactly 40 hexadecimal characters")
    return value.lower()


def _find_one(directory: Path, pattern: str, label: str) -> Path:
    if not directory.is_dir():
        raise ValueError(f"{label} directory does not exist: {directory}")
    matches = sorted(path for path in directory.glob(pattern) if path.is_file())
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {label} matching {pattern} in {directory}, " f"found {len(matches)}")
    return matches[0]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _unreleased_bounds(text: str) -> tuple[re.Match[str], int]:
    matches = list(_UNRELEASED_RE.finditer(text))
    if len(matches) != 1:
        raise ValueError(f"CHANGELOG.md must contain exactly one ## Unreleased heading; found {len(matches)}")
    heading = matches[0]
    next_heading = _LEVEL_TWO_HEADING_RE.search(text, heading.end())
    return heading, next_heading.start() if next_heading else len(text)


def unreleased_changelog(changelog_path: Path) -> str:
    text = changelog_path.read_text(encoding="utf-8")
    heading, section_end = _unreleased_bounds(text)
    return text[heading.end() : section_end].strip()


def roll_changelog(changelog_path: Path, build_timestamp: str) -> bool:
    timestamp = _validated_timestamp(build_timestamp)
    release_heading = f"## GhidraMCP-next {timestamp}"
    text = changelog_path.read_text(encoding="utf-8")
    unreleased_heading, section_end = _unreleased_bounds(text)
    section = text[unreleased_heading.end() : section_end].strip()

    if re.search(rf"(?m)^{re.escape(release_heading)}[ \t]*$", text):
        if section:
            raise ValueError(f"{release_heading} already exists while ## Unreleased is not empty")
        return False

    suffix = text[section_end:].lstrip("\n")
    parts = [
        text[: unreleased_heading.end()].rstrip(),
        "",
        release_heading,
    ]
    if section:
        parts.extend(["", section])
    if suffix:
        parts.extend(["", suffix.rstrip()])
    changelog_path.write_text("\n".join(parts) + "\n", encoding="utf-8")
    return True


def prepare_release(
    *,
    repo_root: Path,
    extension_dir: Path,
    python_dir: Path,
    output_dir: Path,
    build_timestamp: str,
    commit_sha: str,
    expected_ghidra_version: str,
) -> dict[str, object]:
    timestamp = _validated_timestamp(build_timestamp)
    sha = _validated_sha(commit_sha)

    versions = read_pom_versions(repo_root)
    if versions.ghidra_version != expected_ghidra_version:
        raise ValueError(
            "built Ghidra version does not match checkout: "
            f"build={expected_ghidra_version}, checkout={versions.ghidra_version}"
        )

    artifact_paths = [
        ("ghidra_extension", _find_one(extension_dir, "*.zip", "Ghidra extension ZIP")),
        ("python_wheel", _find_one(python_dir, "*.whl", "Python wheel")),
        ("python_sdist", _find_one(python_dir, "*.tar.gz", "Python source distribution")),
    ]
    artifacts = [
        {
            "kind": kind,
            "name": path.name,
            "size": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for kind, path in artifact_paths
    ]

    name = f"GhidraMCP-next {timestamp}"
    tag = f"build-{timestamp}-{sha[:12]}"
    metadata: dict[str, object] = {
        "schema_version": 1,
        "name": name,
        "tag": tag,
        "ghidra_version": versions.ghidra_version,
        "build_timestamp_utc": timestamp,
        "commit_sha": sha,
        "artifacts": artifacts,
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = output_dir / "release-metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    checksum_lines = sorted(f"{artifact['sha256']}  {artifact['name']}" for artifact in artifacts)
    (output_dir / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    notes = [
        f"# {name}",
        "",
        f"- Ghidra version: `{versions.ghidra_version}`",
        f"- Commit: `{sha}`",
        f"- Tag: `{tag}`",
        "",
        "## Changes",
        "",
        unreleased_changelog(repo_root / "CHANGELOG.md") or "_No curated changes were recorded._",
        "",
        "## Artifacts",
        "",
        "| Artifact | Size (bytes) | SHA-256 |",
        "| --- | ---: | --- |",
    ]
    notes.extend(f"| `{artifact['name']}` | {artifact['size']} | `{artifact['sha256']}` |" for artifact in artifacts)
    (output_dir / "release-notes.md").write_text("\n".join(notes) + "\n", encoding="utf-8")
    return metadata


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GhidraMCP release automation")
    subparsers = parser.add_subparsers(dest="command", required=True)

    classify = subparsers.add_parser("classify", help="decide whether changed paths affect release artifacts")
    classify.add_argument(
        "--null",
        action="store_true",
        help="read NUL-terminated paths instead of newline-terminated paths",
    )

    prepare = subparsers.add_parser("prepare", help="validate artifacts and generate release metadata")
    prepare.add_argument("--repo-root", type=Path, required=True)
    prepare.add_argument("--extension-dir", type=Path, required=True)
    prepare.add_argument("--python-dir", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--build-timestamp", required=True)
    prepare.add_argument("--commit-sha", required=True)
    prepare.add_argument("--ghidra-version", required=True)

    roll = subparsers.add_parser("roll-changelog", help="move Unreleased entries under a timestamp release")
    roll.add_argument("--changelog", type=Path, required=True)
    roll.add_argument("--build-timestamp", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "classify":
            paths = decode_changed_paths(sys.stdin.buffer.read(), nul_terminated=args.null)
            print("true" if should_publish(paths) else "false")
            return 0

        if args.command == "roll-changelog":
            changed = roll_changelog(args.changelog, args.build_timestamp)
            print("changed" if changed else "unchanged")
            return 0

        metadata = prepare_release(
            repo_root=args.repo_root,
            extension_dir=args.extension_dir,
            python_dir=args.python_dir,
            output_dir=args.output_dir,
            build_timestamp=args.build_timestamp,
            commit_sha=args.commit_sha,
            expected_ghidra_version=args.ghidra_version,
        )
        print(metadata["tag"])
        return 0
    except (OSError, ValueError) as exc:
        print(f"release automation error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
