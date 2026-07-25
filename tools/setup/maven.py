from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


def candidate_maven_commands() -> list[Path]:
    candidates: list[Path] = []

    for executable in ("mvn", "mvn.cmd"):
        resolved = shutil.which(executable)
        if resolved:
            candidates.append(Path(resolved))

    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        candidates.append(Path(user_profile) / "tools" / "apache-maven-3.9.6" / "bin" / "mvn.cmd")

    m2_home = os.environ.get("M2_HOME")
    if m2_home:
        if sys.platform == "win32":
            candidates.append(Path(m2_home) / "bin" / "mvn.cmd")
        else:
            candidates.append(Path(m2_home) / "bin" / "mvn")

    candidates.extend(
        [
            Path("/opt/maven/bin/mvn"),
            Path("/usr/local/bin/mvn"),
            Path("/usr/share/maven/bin/mvn"),
        ]
    )

    unique_candidates: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized = str(candidate)
        if normalized in seen:
            continue
        seen.add(normalized)
        unique_candidates.append(candidate)

    return unique_candidates


def find_maven_command() -> Path:
    for candidate in candidate_maven_commands():
        if candidate.is_file():
            return candidate

    raise FileNotFoundError(
        "Unable to locate Maven. Install mvn or configure M2_HOME/USERPROFILE tools path."
    )


def required_java_major(repo_root: Path) -> int | None:
    """The Java release the build targets, read from pom.xml rather than hardcoded."""
    pom = repo_root / "pom.xml"
    try:
        text = pom.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r"<maven\.compiler\.release>\s*(\d+)\s*</maven\.compiler\.release>", text)
    return int(match.group(1)) if match else None


def maven_java_major(maven_command: Path) -> int | None:
    completed = subprocess.run(
        [str(maven_command), "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    output = f"{completed.stdout}\n{completed.stderr}"
    match = re.search(r"(?im)^Java version:\s*(?:1\.)?(\d+)", output)
    return int(match.group(1)) if match else None


def check_maven_java(repo_root: Path, maven_command: Path) -> str | None:
    """Return an error message when Maven's JDK will not build this project.

    The build needs the exact release the pom targets, not merely that or newer. A newer JDK
    fails too: javac emits warnings the build promotes to errors via -Werror, so JDK 26 dies
    with "warnings found and -Werror specified" rather than anything mentioning the version.
    Upstream's equivalent check accepts anything >= 21 and so passes the JDK that fails.
    """
    required = required_java_major(repo_root)
    actual = maven_java_major(maven_command)
    if required is None or actual is None or actual == required:
        return None

    return (
        f"Maven is running on Java {actual}, but this project builds against Java {required}. "
        f"Set JAVA_HOME to a JDK {required} installation and put its bin directory first on PATH."
    )


def run_maven(repo_root: Path, goals: list[str], dry_run: bool = False) -> int:
    maven_command = find_maven_command()
    command = [str(maven_command), *goals]
    if dry_run:
        print("DRY RUN:", " ".join(command))
        return 0

    problem = check_maven_java(repo_root, maven_command)
    if problem:
        print(problem, file=sys.stderr)
        return 1

    completed = subprocess.run(command, cwd=repo_root, check=False)
    return completed.returncode