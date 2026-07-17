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


def test_pom_has_no_docker_build_profile():
    pom = (ROOT / "pom.xml").read_text(encoding="utf-8")
    assert "docker-maven-plugin" not in pom
    assert "docker/Dockerfile" not in pom


def test_maven_enforces_warning_free_java_build():
    pom = (ROOT / "pom.xml").read_text(encoding="utf-8")
    assert "<showWarnings>true</showWarnings>" in pom
    assert "<arg>-Xlint:all</arg>" in pom
    assert "<arg>-Werror</arg>" in pom


def test_mockito_is_loaded_as_a_test_agent():
    pom = (ROOT / "pom.xml").read_text(encoding="utf-8")
    assert "-javaagent:" in pom
    assert "mockito-core" in pom


def test_test_runner_has_no_docker_mode():
    runner = (ROOT / "tests/run_tests.py").read_text(encoding="utf-8")
    assert "--docker" not in runner
    assert 'tests_dir / "docker"' not in runner
    assert "args.docker" not in runner
    assert all(flag in runner for flag in ("--unit", "--integration", "--all"))
    assert all(
        target in runner
        for target in ('tests_dir / "unit"', 'tests_dir / "integration"', "args.extra_args")
    )


def test_env_template_has_no_build_backend_selector():
    env_template = (ROOT / ".env.template").read_text(encoding="utf-8")
    assert "TOOLS_SETUP_BACKEND" not in env_template


def test_version_bump_has_no_docker_tag_rule():
    version_bump = (ROOT / "tools/setup/version_bump.py").read_text(encoding="utf-8")
    assert 'f"v{new_version}:"' not in version_bump
