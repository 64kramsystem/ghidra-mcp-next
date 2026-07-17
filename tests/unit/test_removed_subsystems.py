from pathlib import Path

from tools.setup import ghidra


ROOT = Path(__file__).resolve().parents[2]


def test_fun_doc_and_performance_harness_are_absent():
    assert not (ROOT / "fun-doc").exists()
    assert not (ROOT / "tests/performance").exists()


def test_generic_ghidra_fixture_replaces_fun_doc_fixture():
    fixture = ROOT / "tests/fixtures/ghidra_benchmark"
    assert (fixture / "build.py").is_file()
    assert (fixture / "src/benchmark_debug.c").is_file()
    assert (fixture / "regression/Benchmark.dll.yaml").is_file()
    assert ghidra.DEFAULT_BENCHMARK_DLL == Path(
        "tests/fixtures/ghidra_benchmark/build/Benchmark.dll"
    )
    assert ghidra.DEFAULT_BENCHMARK_DEBUG_EXE == Path(
        "tests/fixtures/ghidra_benchmark/build/BenchmarkDebug.exe"
    )


def test_fun_doc_dependency_group_is_absent():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "fun-doc = [" not in pyproject


def test_standalone_debugger_proxy_is_absent():
    assert not (ROOT / "debugger").exists()
    assert not (ROOT / "python/bridge_mcp_ghidra/debugger.py").exists()
    maintained = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "python/bridge_mcp_ghidra").glob("*.py")
    )
    assert "GHIDRA_DEBUGGER_URL" not in maintained
    assert "DEBUGGER_TOOL_NAMES" not in maintained


def test_removed_subsystems_are_absent_from_tracked_configuration():
    mcp_config = (ROOT / ".mcp.json").read_text(encoding="utf-8")
    env_template = (ROOT / ".env.template").read_text(encoding="utf-8")

    assert "GHIDRA_DEBUGGER_URL" not in mcp_config
    for forbidden in (
        "Fun-Doc",
        "FUNDOC_",
        "Knowledge Database",
        "KNOWLEDGE_DB_",
        "10.0.10.30",
        "store_function_knowledge",
        "query_knowledge_context",
    ):
        assert forbidden not in env_template


def test_removed_documentation_endpoints_are_absent_from_live_tests_and_timeouts():
    maintained = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in (
            "python/bridge_mcp_ghidra/config.py",
            "tests/integration/test_readonly_endpoints.py",
            "tests/integration/test_safe_write_endpoints.py",
        )
    )
    for removed in (
        "compare_programs_documentation",
        "get_function_documentation",
        "apply_function_documentation",
    ):
        assert removed not in maintained


def test_schema_builder_fixtures_use_retained_endpoint_names():
    fixtures = (ROOT / "tests/unit/test_mcp_tool_functions.py").read_text(
        encoding="utf-8"
    )
    assert "archive_ingest_program" not in fixtures
    assert "merge_program_documentation" not in fixtures
