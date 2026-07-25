from __future__ import annotations

from pathlib import Path

import pytest

from tools.setup import maven


POM = """<project>
  <properties>
    <maven.compiler.release>21</maven.compiler.release>
  </properties>
</project>
"""


def _repo(tmp_path: Path, pom: str | None = POM) -> Path:
    if pom is not None:
        (tmp_path / "pom.xml").write_text(pom, encoding="utf-8")
    return tmp_path


def _maven_reporting(monkeypatch: pytest.MonkeyPatch, java_line: str) -> None:
    def fake_run(*args, **kwargs):
        class Completed:
            stdout = java_line
            stderr = ""

        return Completed()

    monkeypatch.setattr(maven.subprocess, "run", fake_run)


def test_required_major_is_read_from_the_pom(tmp_path: Path):
    assert maven.required_java_major(_repo(tmp_path)) == 21


def test_required_major_is_none_without_a_pom(tmp_path: Path):
    assert maven.required_java_major(_repo(tmp_path, pom=None)) is None


def test_matching_java_is_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _maven_reporting(monkeypatch, "Java version: 21.0.12, vendor: Homebrew")

    assert maven.check_maven_java(_repo(tmp_path), Path("mvn")) is None


def test_newer_java_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The case upstream's `>= required` check lets through: JDK 26 builds fail under -Werror."""
    _maven_reporting(monkeypatch, "Java version: 26.0.1, vendor: Homebrew")

    problem = maven.check_maven_java(_repo(tmp_path), Path("mvn"))

    assert problem is not None
    assert "Java 26" in problem
    assert "Java 21" in problem


def test_older_java_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _maven_reporting(monkeypatch, "Java version: 1.8.0_402, vendor: Oracle")

    problem = maven.check_maven_java(_repo(tmp_path), Path("mvn"))

    assert problem is not None
    assert "Java 8" in problem


def test_unreadable_java_version_does_not_block_the_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _maven_reporting(monkeypatch, "no version line here")

    assert maven.check_maven_java(_repo(tmp_path), Path("mvn")) is None


def test_missing_pom_does_not_block_the_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _maven_reporting(monkeypatch, "Java version: 26.0.1, vendor: Homebrew")

    assert maven.check_maven_java(_repo(tmp_path, pom=None), Path("mvn")) is None
