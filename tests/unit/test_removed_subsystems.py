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
