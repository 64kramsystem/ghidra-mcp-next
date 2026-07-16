from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_removed_build_and_container_paths_are_absent():
    forbidden = [
        "build.gradle", "settings.gradle", "gradlew", "gradlew.bat",
        "gradle", "docker", "tests/unit/test_gradle_tasks.py",
    ]
    assert [path for path in forbidden if (ROOT / path).exists()] == []


def test_setup_cli_is_maven_only():
    cli = (ROOT / "tools/setup/cli.py").read_text(encoding="utf-8")
    maven = (ROOT / "tools/setup/maven.py").read_text(encoding="utf-8")
    assert "TOOLS_SETUP_BACKEND" not in cli
    assert "_get_backend" not in cli
    assert "run_gradle" not in cli
    assert "run_gradle" not in maven
    assert "find_gradle_command" not in maven


def test_workflows_do_not_invoke_removed_build_surfaces():
    workflow_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / ".github/workflows").glob("*.yml"))
    )
    assert "./gradlew" not in workflow_text
    assert "gradlew.bat" not in workflow_text
    assert "docker compose" not in workflow_text
