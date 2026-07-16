# Architecture Slimming Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove unused ghidra-mcp subsystems while preserving local FileZilla analysis, Wine/TraceRMI debugging, local BSim assistance, and the concrete seams required by four planned debugger features.

**Architecture:** Cut one dependency cluster at a time, starting at leaf build/tooling systems and ending at high-fan-in Java services. Each slice first adds a behavioral or negative architecture contract, makes the smallest removal that satisfies it, regenerates endpoint/dependency artifacts in the same commit, and runs focused plus repository-wide gates. The plan stays integrated because `GhidraMCPPlugin`, `EndpointRegistry`, headless construction, setup tooling, CI, and `tests/endpoints.json` are shared by several slices.

**Tech Stack:** Java 21, Ghidra 12.1 APIs, Maven, Python 3.10+, FastMCP, pytest, uv/PEP 735, GitHub Actions, Ghidra TraceRMI.

## Global Constraints

- Work only in `/home/saverio/local/ghidra-mcp/.worktrees/remove-unused-subsystems` on `refactor/remove-unused-subsystems` until integration.
- Preserve local `.gpr` project creation/import/persistence/switching in GUI and headless modes.
- Preserve multi-program analysis, schema discovery, TCP/UDS transports, and GUI/headless endpoint parity.
- Preserve the FileZilla workflow tools for strings, xrefs, bytes/operands, decompilation, flow repair, annotations, datatypes, memory blocks, and generic scripts.
- Preserve Java `DebuggerService` and Ghidra TraceRMI/`ghidratrace`; remove only the separate Python dbgeng HTTP proxy.
- Do not add attach, wait-for-stop, process-map, or trace-copy endpoints in this project.
- Preserve the testable seams mapped in the approved specification for all four planned debugger features.
- Keep `SecurityConfig`; remove repository-server authentication and version control only.
- Keep public local hash/signature/fuzzy/diff tools and optional explicitly configured local BSim.
- Maven is the only Java build backend after Task 2.
- Use test-driven changes: observe the new focused test fail before making each behavioral/removal change.
- Regenerate `tests/endpoints.json` in every endpoint-changing task.
- Update affected CI/configuration in the same task as a removal; perform the complete prose-documentation audit in Task 9.
- Request Claude review after the comparison carve, after the debugger cut, and on the final integrated diff. Every mention of an independent reviewer in project artifacts must say Claude, never Codex.
- Commit each numbered task separately; do not squash those commits.
- Integrate through a PR using a merge commit, then verify the resulting remote mainline.

---

### Task 1: Establish Baseline and Protected-Workflow Contracts

**Files:**
- Create: `tests/unit/test_protected_workflows.py`
- Modify: `tools/setup/ghidra.py:66-105`
- Test: `tests/unit/test_protected_workflows.py`

**Interfaces:**
- Consumes: `tests/endpoints.json`, `src/main/java/com/xebyte/core/DebuggerService.java`.
- Produces: `FILEZILLA_ENDPOINTS`, `TRACE_RMI_ENDPOINTS`, and `LOCAL_COMPARISON_ENDPOINTS` as executable preservation contracts; `RELEASE_CONTRACT_TOOLS` aligned with them.

- [ ] **Step 1: Record the clean baseline**

Run:

```bash
pytest tests/unit/ -v --no-cov
mvn test -Dtest='com.xebyte.offline.*Test'
mvn clean compile -q
```

Expected: all three commands exit `0`. If a baseline failure occurs, use `superpowers:systematic-debugging`, determine whether it is environmental or a real regression, and do not start removals with an unexplained failure.

- [ ] **Step 2: Add the protected endpoint contract**

Create `tests/unit/test_protected_workflows.py` with:

```python
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "tests" / "endpoints.json"

FILEZILLA_ENDPOINTS = {
    "/create_project", "/open_project", "/import_file",
    "/list_open_programs", "/switch_program", "/save_program",
    "/search_strings", "/search_functions", "/search_byte_patterns",
    "/search_instructions", "/get_xrefs_to", "/get_xrefs_from",
    "/decompile_function", "/disassemble_bytes", "/clear_flow_and_repair",
    "/rename_function", "/rename_label", "/set_disassembly_comment",
    "/create_struct", "/add_struct_field", "/create_memory_block",
    "/run_ghidra_script", "/run_script_inline",
}

TRACE_RMI_ENDPOINTS = {
    "/debugger/launch_offers", "/debugger/launch", "/debugger/status",
    "/debugger/traces", "/debugger/resume", "/debugger/interrupt",
    "/debugger/step_into", "/debugger/step_over", "/debugger/step_out",
    "/debugger/set_breakpoint", "/debugger/remove_breakpoint",
    "/debugger/list_breakpoints", "/debugger/registers",
    "/debugger/read_memory", "/debugger/stack_trace", "/debugger/modules",
    "/debugger/static_to_dynamic", "/debugger/dynamic_to_static",
}

LOCAL_COMPARISON_ENDPOINTS = {
    "/get_function_hash", "/get_bulk_function_hashes",
    "/get_function_signature", "/find_similar_functions_fuzzy",
    "/bulk_fuzzy_match", "/diff_functions",
}


def _catalog_paths() -> set[str]:
    payload = json.loads(CATALOG.read_text(encoding="utf-8"))
    return {entry["path"] for entry in payload["endpoints"]}


def test_filezilla_workflow_endpoints_are_cataloged():
    assert FILEZILLA_ENDPOINTS <= _catalog_paths()


def test_trace_rmi_workflow_endpoints_are_cataloged():
    assert TRACE_RMI_ENDPOINTS <= _catalog_paths()


def test_local_comparison_endpoints_are_cataloged():
    assert LOCAL_COMPARISON_ENDPOINTS <= _catalog_paths()


def test_debugger_service_owns_the_trace_rmi_group():
    source = (ROOT / "src/main/java/com/xebyte/core/DebuggerService.java").read_text(
        encoding="utf-8"
    )
    assert '@McpToolGroup(value = "debugger"' in source
    for path in TRACE_RMI_ENDPOINTS:
        assert f'path = "{path}"' in source


def test_launch_offers_expose_all_offer_metadata_without_image_filtering():
    source = (ROOT / "src/main/java/com/xebyte/core/DebuggerService.java").read_text(
        encoding="utf-8"
    )
    method = source[source.index("public Response listLaunchOffers(") :]
    assert "launcherSvc.getOffers(program)" in method
    assert 'info.put("supports_image", offer.supportsImage())' in method
    assert 'info.put("requires_image", offer.requiresImage())' in method
    assert ".filter(" not in method.split("return Response.ok(result);", 1)[0]
```

- [ ] **Step 3: Run the new contract**

Run:

```bash
pytest tests/unit/test_protected_workflows.py -v --no-cov
```

Expected: `5 passed`.

- [ ] **Step 4: Align the live release contract**

In `tools/setup/ghidra.py`, align `SMOKE_REQUIRED_TOOLS` and
`RELEASE_CONTRACT_TOOLS` with the protected public surface while retaining
existing generic smoke-only checks such as `analysis_status`, `create_folder`,
`delete_file`, `list_functions`, `list_imports`, and `list_exports`. The live
release contract intentionally uses the 12-tool TraceRMI subset below; the
catalog contract in Step 2 remains responsible for preserving all 18 TraceRMI
tools. Remove `prompt_policy`; it is a naming-policy endpoint scheduled for
deletion.

Use this debugger portion exactly:

```python
TRACE_RMI_CONTRACT_TOOLS = {
    "debugger/launch_offers",
    "debugger/launch",
    "debugger/status",
    "debugger/resume",
    "debugger/interrupt",
    "debugger/set_breakpoint",
    "debugger/read_memory",
    "debugger/registers",
    "debugger/stack_trace",
    "debugger/modules",
    "debugger/static_to_dynamic",
    "debugger/dynamic_to_static",
}
```

- [ ] **Step 5: Run focused and baseline tests**

Run:

```bash
pytest tests/unit/test_protected_workflows.py tests/unit/test_setup_ghidra.py -v --no-cov
mvn test -Dtest='com.xebyte.offline.EndpointsJsonParityTest'
git diff --check
```

Expected: all commands exit `0`.

- [ ] **Step 6: Commit the protection floor**

```bash
git add tests/unit/test_protected_workflows.py tools/setup/ghidra.py
git commit -m "test: protect local analysis and TraceRMI workflows"
```

---

### Task 2: Make Maven the Only Build and Remove Docker

**Files:**
- Create: `tests/unit/test_build_surface.py`
- Modify: `tools/setup/cli.py:15-523`
- Modify: `tools/setup/maven.py:1-105`
- Modify: `tests/unit/test_setup_cli.py`
- Modify: `tests/unit/test_setup_ghidra.py:320-365`
- Modify: `.github/workflows/tests.yml`
- Modify: `.github/workflows/pre-release.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `.github/workflows/release-regression.yml`
- Modify: `.github/dependabot.yml`
- Delete: `build.gradle`, `settings.gradle`, `gradlew`, `gradlew.bat`, `gradle/`
- Delete: `tests/unit/test_gradle_tasks.py`
- Delete: `docker/`
- Test: `tests/unit/test_build_surface.py`, `tests/unit/test_setup_cli.py`, `tests/unit/test_setup_ghidra.py`

**Interfaces:**
- Consumes: existing `run_maven`, `install_ghidra_dependencies`, `deploy_to_ghidra`, `start_ghidra`, and `clean_all` functions.
- Produces: a Maven-only `python -m tools.setup` command surface with no backend selector.

- [ ] **Step 1: Write the failing build-surface test**

Create `tests/unit/test_build_surface.py`:

```python
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
```

- [ ] **Step 2: Verify the new test fails for the intended reasons**

Run:

```bash
pytest tests/unit/test_build_surface.py -v --no-cov
```

Expected: three failures naming existing Gradle/Docker paths, backend symbols, and workflow references.

- [ ] **Step 3: Remove backend branching while retaining Maven behavior**

In `tools/setup/cli.py`:

- change the import to `from .maven import find_maven_command, run_maven`;
- delete `_get_backend`;
- delete every `if _get_backend() == "gradle"` branch;
- leave the existing Maven body of `cmd_verify_version`, `cmd_preflight`, `cmd_build`, `cmd_clean`, `cmd_run_tests`, `cmd_install_ghidra_deps`, `cmd_deploy`, `cmd_start_ghidra`, `cmd_clean_all`, and `cmd_ensure_prereqs` as the unconditional implementation.

The final build/test functions must be:

```python
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
```

Delete the Gradle section from `tools/setup/maven.py`, including `candidate_gradle_commands`, `find_gradle_command`, and `run_gradle`; keep all Maven discovery/execution functions unchanged.

- [ ] **Step 4: Update setup tests to assert Maven directly**

Delete Gradle-routing tests from `tests/unit/test_setup_cli.py`. Keep or add this direct routing test:

```python
def test_cmd_build_routes_to_maven(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(
        cli, "run_maven", lambda root, goals, **kw: calls.append((root, goals, kw)) or 0
    )
    assert cli.cmd_build(_args(dry_run=True)) == 0
    assert calls == [
        (Path("/repo"), ["clean", "package", "assembly:single", "-DskipTests"], {"dry_run": True})
    ]
```

In `tests/unit/test_setup_ghidra.py`, delete Gradle artifact preference/fallback cases and assert Maven ZIP discovery under `target/` only.

- [ ] **Step 5: Remove files and update CI/dependency automation atomically**

Remove the Gradle wrapper/build files, Docker directory, and `tests/unit/test_gradle_tasks.py`. In all four workflows, replace Gradle invocations with the existing Maven command from `AGENTS.md`:

```yaml
- name: Build extension
  run: mvn clean package assembly:single -DskipTests
```

Remove the Gradle and Docker comments/jobs/caches that no longer have inputs. Remove the Gradle ecosystem entry from `.github/dependabot.yml`.

- [ ] **Step 6: Run focused tests and Maven dry-run setup checks**

Run:

```bash
pytest tests/unit/test_build_surface.py tests/unit/test_setup_cli.py tests/unit/test_setup_ghidra.py -v --no-cov
python -m tools.setup build --dry-run
mvn clean compile -q
git diff --check
```

Expected: tests pass; setup prints a Maven `clean package assembly:single -DskipTests` command; Maven compile exits `0`.

- [ ] **Step 7: Commit the build/deployment cut**

```bash
git add -A
git commit -m "build: standardize on Maven and remove Docker"
```

---

### Task 3: Remove Fun-doc While Preserving Generic Live Fixtures

**Files:**
- Create: `tests/unit/test_removed_subsystems.py`
- Move: `fun-doc/benchmark/build.py` to `tests/fixtures/ghidra_benchmark/build.py`
- Move: `fun-doc/benchmark/src/` to `tests/fixtures/ghidra_benchmark/src/`
- Move: `fun-doc/benchmark/regression/` to `tests/fixtures/ghidra_benchmark/regression/`
- Modify: `tools/setup/ghidra.py:57-61, 948-975, 1588-1880`
- Modify: `tests/unit/test_setup_ghidra.py`
- Modify: `pyproject.toml:84-98`
- Modify: `uv.lock`
- Modify: `.github/workflows/tests.yml`
- Modify: `.github/workflows/release-regression.yml`
- Modify: `.github/workflows/codeql.yml`
- Modify: `.github/dependabot.yml`
- Delete: remaining `fun-doc/`
- Delete: `tests/performance/`
- Test: `tests/unit/test_removed_subsystems.py`, `tests/unit/test_setup_ghidra.py`

**Interfaces:**
- Consumes: `reset_benchmark_fixture`, `run_benchmark_yaml_regression`, and `run_debugger_live_test`.
- Produces: a generic functional fixture at `tests/fixtures/ghidra_benchmark` that continues to exercise import, analysis, endpoint contracts, and TraceRMI launch without retaining fun-doc.

- [ ] **Step 1: Write the failing subsystem-absence and fixture test**

Create `tests/unit/test_removed_subsystems.py`:

```python
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
```

- [ ] **Step 2: Verify the new test fails**

Run:

```bash
pytest tests/unit/test_removed_subsystems.py -v --no-cov
```

Expected: failures identify the existing fun-doc/performance trees, missing generic fixture, old constants, and dependency group.

- [ ] **Step 3: Salvage only the generic functional fixture**

Move `build.py`, `src/`, and `regression/` into `tests/fixtures/ghidra_benchmark/`. Update `build.py` so its root is its own directory:

```python
BENCHMARK_DIR = Path(__file__).resolve().parent
SRC_DIR = BENCHMARK_DIR / "src"
BUILD_DIR = BENCHMARK_DIR / "build"
```

Retain only the `msvc2022` toolchain entry and its `vcvars` environment path.
Delete the `vc6sp6` entry, `FUNDOC_VC6_ROOT`/`FUNDOC_VS7_ROOT`, separate-linker
branches, and D2-specific image-base/toolchain commentary from the moved build
script. Move the complete `src/` set because the current regression YAML and
debugger harness depend on its stable exports and addresses; the D2-derived
stat-list names become inert deterministic test data, not retained D2
automation. Do not move scorer, truth-generation, provider, database, VC6, or
benchmark-history assets.

Update `tools/setup/ghidra.py` constants and helpers:

```python
BENCHMARK_FIXTURE_ROOT = Path("tests") / "fixtures" / "ghidra_benchmark"
DEFAULT_BENCHMARK_DLL = BENCHMARK_FIXTURE_ROOT / "build" / "Benchmark.dll"
DEFAULT_BENCHMARK_DEBUG_EXE = BENCHMARK_FIXTURE_ROOT / "build" / "BenchmarkDebug.exe"


def _benchmark_regression_dir(repo_root: Path) -> Path:
    return repo_root / BENCHMARK_FIXTURE_ROOT / "regression"
```

In `reset_benchmark_fixture`, invoke `repo_root / BENCHMARK_FIXTURE_ROOT / "build.py"`. Update the unit tests to construct files at the new constants. Keep `run_debugger_live_test`, `install_ghidratrace_for_debugger`, and their tests.

- [ ] **Step 4: Remove fun-doc and its dependencies/workflows**

Delete the remaining `fun-doc/` tree and `tests/performance/`. Remove the `fun-doc` dependency group from `pyproject.toml`. Remove the fun-doc pytest job and coverage target from `.github/workflows/tests.yml`, update release regression to build `tests/fixtures/ghidra_benchmark/build.py`, remove fun-doc from CodeQL comments, and remove its Dependabot entry.

Regenerate the lockfile:

```bash
uv lock
uv lock --check
```

Expected: both commands exit `0`; `uv.lock` contains no project `fun-doc` dependency-group entry.

- [ ] **Step 5: Run focused and repository Python tests**

Run:

```bash
pytest tests/unit/test_removed_subsystems.py tests/unit/test_setup_ghidra.py -v --no-cov
pytest tests/unit/ -v --no-cov
mvn clean compile -q
git diff --check
```

Expected: all commands exit `0`.

- [ ] **Step 6: Commit the fun-doc cut**

```bash
git add -A
git commit -m "refactor: remove fun-doc and retain generic test fixtures"
```

---

### Task 4: Carve Generic Binary Comparison Out of Documentation Propagation

**Files:**
- Modify: `src/main/java/com/xebyte/core/BinaryComparisonService.java`
- Modify: `src/main/java/com/xebyte/core/EndpointRegistry.java:35-55`
- Modify: `src/main/java/com/xebyte/GhidraMCPPlugin.java:270-305`
- Modify: `src/main/java/com/xebyte/headless/HeadlessEndpointHandler.java`
- Modify: `src/main/java/com/xebyte/headless/GhidraMCPHeadlessServer.java:390-410`
- Modify: `src/test/java/com/xebyte/offline/BinaryComparisonServiceTest.java`
- Delete: `src/main/java/com/xebyte/core/DocumentationHashService.java`
- Delete: `src/test/java/com/xebyte/offline/DocumentationHashServiceValidationTest.java`
- Modify: `tests/endpoints.json`
- Modify: `tests/unit/test_protected_workflows.py`
- Modify: `tests/unit/test_endpoint_catalog.py`
- Modify: `tests/unit/test_project_consistency.py`
- Test: `src/test/java/com/xebyte/offline/BinaryComparisonServiceTest.java`, endpoint parity tests

**Interfaces:**
- Consumes: `ProgramProvider`, `ThreadingStrategy`, and existing static `BinaryComparisonService` signature/scoring/diff helpers.
- Produces: `BinaryComparisonService(ProgramProvider, ThreadingStrategy)` and six unchanged public endpoint paths/parameter names.

- [ ] **Step 1: Add failing endpoint-ownership and validation tests**

Extend `BinaryComparisonServiceTest` with:

```java
private BinaryComparisonService service;

@Override
protected void setUp() {
    service = new BinaryComparisonService(
        ServiceFactory.stubProvider(), new NoopThreadingStrategy());
}

public void testPublicComparisonEndpointsLiveOnBinaryComparisonService() throws Exception {
    assertNotNull(BinaryComparisonService.class.getMethod(
        "getFunctionHash", String.class, String.class));
    assertNotNull(BinaryComparisonService.class.getMethod(
        "getBulkFunctionHashes", int.class, int.class, String.class, String.class));
    assertNotNull(BinaryComparisonService.class.getMethod(
        "getFunctionSignature", String.class, String.class));
    assertNotNull(BinaryComparisonService.class.getMethod(
        "findSimilarFunctionsFuzzy", String.class, String.class, String.class,
        double.class, int.class));
    assertNotNull(BinaryComparisonService.class.getMethod(
        "bulkFuzzyMatch", String.class, String.class, double.class,
        int.class, int.class, String.class));
    assertNotNull(BinaryComparisonService.class.getMethod(
        "diffFunctions", String.class, String.class, String.class, String.class));
}

public void testBulkFuzzyMatchStillValidatesSourceProgramFirst() {
    Response response = service.bulkFuzzyMatch("", "Target.dll", 0.7, 0, 50, "");
    assertTrue(response instanceof Response.Err);
    assertTrue(((Response.Err) response).message().contains(
        "source_program parameter is required"));
}
```

Add the required imports for `Response` and reflection-free direct method calls.

- [ ] **Step 2: Verify the ownership test fails**

Run:

```bash
mvn test -Dtest='com.xebyte.offline.BinaryComparisonServiceTest'
```

Expected: compilation fails because the endpoint-owning constructor and six instance methods are not yet on `BinaryComparisonService`.

- [ ] **Step 3: Move the retained endpoint layer and hash implementation**

Add to `BinaryComparisonService`:

```java
@McpToolGroup(value = "comparison",
        description = "Local function hashing, signatures, fuzzy matching, and diffs")
public class BinaryComparisonService {
    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public BinaryComparisonService(ProgramProvider programProvider,
                                   ThreadingStrategy threadingStrategy) {
        this.programProvider = Objects.requireNonNull(programProvider);
        this.threadingStrategy = Objects.requireNonNull(threadingStrategy);
    }
```

Preserve the six public paths and exact catalog parameters. Transplant the
existing method bodies from `DocumentationHashService` lines 65-296 and
969-1129 into these methods on `BinaryComparisonService`:

- `@McpTool(path = "/get_function_hash", category = "comparison")` on
  `Response getFunctionHash(String address, String program)`;
- `@McpTool(path = "/get_bulk_function_hashes", category = "comparison")` on
  `Response getBulkFunctionHashes(int offset, int limit, String filter, String program)`;
- `@McpTool(path = "/get_function_signature", category = "comparison")` on
  `Response getFunctionSignature(String address, String program)`;
- `@McpTool(path = "/find_similar_functions_fuzzy", category = "comparison")`
  on `Response findSimilarFunctionsFuzzy(String address, String sourceProgram,
  String targetProgram, double threshold, int limit)`;
- `@McpTool(path = "/bulk_fuzzy_match", category = "comparison")` on
  `Response bulkFuzzyMatch(String sourceProgram, String targetProgram, double
  threshold, int offset, int limit, String filter)`; and
- `@McpTool(path = "/diff_functions", category = "comparison")` on `Response
  diffFunctions(String addressA, String addressB, String programA, String
  programB)`.

Use `computeFunctionSignature`, `findSimilarFunctionsJson`,
`bulkFuzzyMatchJson`, and `diffFunctionsJson` for the last four method bodies.
Copy the existing `@Param` annotations so the public parameter names and
defaults remain exactly those recorded in `tests/endpoints.json`.
Move only private helpers reachable from the six methods, notably
`computeNormalizedFunctionHash` and `countFunctionInstructions`; do not move
documentation export/apply/archive helpers. Do not change response keys or
validation messages.

- [ ] **Step 4: Rewire GUI, headless, and manual registry construction**

Construct one endpoint-owning comparison service in both modes:

```java
new BinaryComparisonService(programProvider, threadingStrategy)
```

Replace `DocumentationHashService` fields/constructor parameters/getters with `BinaryComparisonService` in `GhidraMCPPlugin`, `HeadlessEndpointHandler`, `GhidraMCPHeadlessServer`, and `EndpointRegistry`. Keep the existing static comparison algorithms in the same class. Delete `DocumentationHashService` only after `rg "DocumentationHashService" src/main src/test` reports no matches.

- [ ] **Step 5: Regenerate the endpoint catalog and assert the exact delta**

Run:

```bash
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
```

Then extend `test_protected_workflows.py`:

```python
REMOVED_DOCUMENTATION_ENDPOINTS = {
    "/get_function_documentation", "/apply_function_documentation",
    "/compare_programs_documentation", "/find_undocumented_by_string",
    "/batch_string_anchor_report", "/merge_program_documentation",
    "/archive_ingest_function", "/archive_ingest_program",
}


def test_documentation_propagation_endpoints_are_absent():
    assert REMOVED_DOCUMENTATION_ENDPOINTS.isdisjoint(_catalog_paths())
```

Update endpoint/catalog consistency allowlists from `DocumentationHashService` to `BinaryComparisonService`.

- [ ] **Step 6: Run comparison, parity, Python, and compile gates**

Run:

```bash
mvn test -Dtest='com.xebyte.offline.BinaryComparisonServiceTest,com.xebyte.offline.EndpointsJsonParityTest,com.xebyte.offline.AnnotationScannerOfflineTest'
pytest tests/unit/test_protected_workflows.py tests/unit/test_endpoint_catalog.py tests/unit/test_project_consistency.py -v --no-cov
mvn clean compile -q
git diff --check
```

Expected: all commands exit `0`; all six comparison endpoints remain; all eight propagation/archive endpoints are absent.

- [ ] **Step 7: Request Claude review of the high-fan-in carve**

Use the `claude` skill with this focus: verify no generic hash/signature/fuzzy/diff behavior was lost, no documentation/archive helper remains reachable, and GUI/headless construction and endpoint parity agree. Resolve concrete findings and resume the same Claude session until no current findings remain.

- [ ] **Step 8: Commit the comparison boundary**

```bash
git add -A
git commit -m "refactor: retain local comparison without doc propagation"
```

---

### Task 5: Remove Ghidra Repository-Server and Version-Control Paths

**Files:**
- Create: `src/test/java/com/xebyte/offline/ArchitectureBoundaryTest.java`
- Modify: `src/main/java/com/xebyte/GhidraMCPPlugin.java:80, 312-323, 900-1020, 3550-3945`
- Modify: `src/main/java/com/xebyte/headless/GhidraMCPHeadlessServer.java:75-105, 390-570`
- Modify: `src/main/java/com/xebyte/headless/HeadlessManagementService.java:20-220`
- Modify: `src/main/java/com/xebyte/headless/HeadlessProgramProvider.java:430-635, 689-815`
- Modify: `src/test/java/com/xebyte/offline/ProgramLoadResultTest.java`
- Modify: `src/test/java/com/xebyte/offline/OpenProjectGuiEndpointTest.java`
- Delete: `src/main/java/com/xebyte/headless/GhidraServerManager.java`
- Delete: `src/main/java/com/xebyte/core/GhidraMCPAuthenticator.java`
- Delete: `src/main/java/com/xebyte/core/GhidraMCPAuthInitializer.java`
- Delete: `src/test/java/com/xebyte/offline/GhidraServerManagerTest.java`
- Modify: `tests/endpoints.json`
- Modify: `tests/unit/test_protected_workflows.py`
- Test: `ArchitectureBoundaryTest`, local project/provider tests, endpoint parity

**Interfaces:**
- Consumes: `SecurityConfig`, local `ProjectLocator`, `GuiProjectService`, and `HeadlessProgramProvider` local project APIs.
- Produces: local-only headless constructor `HeadlessManagementService(HeadlessProgramProvider)` and project diagnostics without server-binding fields.

- [ ] **Step 1: Add the failing Java architecture boundary**

Create `ArchitectureBoundaryTest.java`:

```java
package com.xebyte.offline;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import junit.framework.TestCase;

public class ArchitectureBoundaryTest extends TestCase {
    private static final Path ROOT = Path.of(System.getProperty("user.dir"));

    private static String maintainedJava() throws IOException {
        StringBuilder out = new StringBuilder();
        try (var paths = Files.walk(ROOT.resolve("src/main/java"))) {
            for (Path path : paths.filter(p -> p.toString().endsWith(".java")).toList()) {
                out.append(Files.readString(path)).append('\n');
            }
        }
        return out.toString();
    }

    public void testRepositoryServerDependenciesAreAbsent() throws Exception {
        String source = maintainedJava();
        for (String forbidden : List.of(
                "GhidraServerManager", "GhidraMCPAuthenticator",
                "GhidraMCPAuthInitializer", "DocumentationHashService",
                "ghidra.framework.client.")) {
            assertFalse("forbidden repository-server dependency: " + forbidden,
                    source.contains(forbidden));
        }
    }

    public void testSecurityConfigRemainsAvailable() throws Exception {
        assertTrue(Files.isRegularFile(ROOT.resolve(
                "src/main/java/com/xebyte/core/SecurityConfig.java")));
        String source = Files.readString(ROOT.resolve(
                "src/main/java/com/xebyte/core/SecurityConfig.java"));
        assertTrue(source.contains("GHIDRA_MCP_ALLOW_SCRIPTS"));
        assertTrue(source.contains("GHIDRA_MCP_FILE_ROOT"));
        assertTrue(source.contains("GHIDRA_MCP_AUTH_TOKEN"));
    }
}
```

- [ ] **Step 2: Verify the boundary test fails only on repository-server dependencies**

Run:

```bash
mvn test -Dtest='com.xebyte.offline.ArchitectureBoundaryTest'
```

Expected: repository-server test fails; `SecurityConfig` test passes.

- [ ] **Step 3: Decouple local headless lifecycle**

Change the constructor to:

```java
public HeadlessManagementService(HeadlessProgramProvider programProvider) {
    this.programProvider = Objects.requireNonNull(programProvider);
}
```

Remove `/checkin_program`. Keep `/load_program_from_project` and `/get_project_info`, but return local fields only: project name/location, requested path, available paths, loaded programs, and local success/error state. Remove `serverHint`, `ServerBindingInfo`, `describeServerBinding`, `getProjectServerInfo`, and `checkinProgram` from `HeadlessProgramProvider`; simplify `ProgramLoadResult` to:

```java
public final boolean success;
public final Program program;
public final String message;
public final List<String> availablePaths;
```

Update `ProgramLoadResultTest` to assert these local diagnostics and no server-binding JSON keys.

- [ ] **Step 4: Remove repository endpoints and auth wiring**

Delete:

- GUI manual contexts from `/server/repository/*`, `/server/version_control/*`, `/server/checkouts`, and `/server/admin/*`;
- their private helpers and `RepositoryAdapter` imports;
- the matching headless `safeContext` registrations and `serverManager` field;
- authenticator initialization in `GhidraMCPPlugin`; and
- the three removed classes and server manager test.

Do not remove transport `ServerManager`, `ServerLifecycle`, `ServerTransport`, `UdsHttpServer`, `SecurityConfig`, bearer-token checks, or local `GuiProjectService` UDS endpoints.

- [ ] **Step 5: Regenerate endpoints and assert server paths are absent**

Run:

```bash
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
```

Add to `test_protected_workflows.py`:

```python
REMOVED_SERVER_ENDPOINTS = {
    "/checkin_program", "/server/connect", "/server/disconnect",
    "/server/authenticate", "/server/repositories",
    "/server/repository/files", "/server/repository/file",
    "/server/repository/create", "/server/version_control/add",
    "/server/version_control/checkout", "/server/version_control/checkin",
    "/server/version_control/undo_checkout", "/server/version_history",
    "/server/checkouts", "/server/admin/users", "/server/admin/set_permissions",
    "/server/admin/terminate_checkout", "/server/admin/terminate_all_checkouts",
}


def test_repository_server_endpoints_are_absent():
    assert REMOVED_SERVER_ENDPOINTS.isdisjoint(_catalog_paths())
```

- [ ] **Step 6: Run local project and architecture gates**

Run:

```bash
mvn test -Dtest='com.xebyte.offline.ArchitectureBoundaryTest,com.xebyte.offline.FrontEndProgramProviderEvictionTest,com.xebyte.offline.HeadlessPathsTest,com.xebyte.offline.OpenProjectGuiEndpointTest,com.xebyte.offline.ProgramLoadResultTest,com.xebyte.offline.EndpointsJsonParityTest'
pytest tests/unit/test_create_project.py tests/unit/test_project_consistency.py tests/unit/test_protected_workflows.py -v --no-cov
mvn clean compile -q
git diff --check
```

Expected: all commands exit `0`; local project endpoints remain in the protection contract.

- [ ] **Step 7: Commit the local-only project boundary**

```bash
git add -A
git commit -m "refactor: remove repository-server workflows"
```

---

### Task 6: Preserve TraceRMI Semantics and Remove the dbgeng Proxy

**Files:**
- Create: `src/main/java/com/xebyte/core/DebuggerTransferSemantics.java`
- Create: `src/test/java/com/xebyte/offline/DebuggerTransferSemanticsTest.java`
- Create: `src/test/java/com/xebyte/offline/DebuggerServiceContractTest.java`
- Modify: `python/bridge_mcp_ghidra/__init__.py`
- Modify: `python/bridge_mcp_ghidra/config.py:44-109`
- Modify: `python/bridge_mcp_ghidra/registry.py:1-25`
- Modify: `python/bridge_mcp_ghidra/schema.py:1-45`
- Modify: `tools/setup/requirements.py`
- Modify: `tools/setup/cli.py`
- Modify: `tools/setup/ghidra.py`
- Modify: `pyproject.toml:75-84`
- Modify: `uv.lock`
- Modify: `tests/unit/test_bridge_utils.py`
- Modify: `tests/unit/test_endpoint_catalog.py`
- Modify: `tests/unit/test_setup_requirements.py`
- Modify: `tests/unit/test_setup_cli.py`
- Modify: `tests/unit/test_setup_ghidra.py`
- Delete: `debugger/`
- Delete: `python/bridge_mcp_ghidra/debugger.py`
- Delete: `tests/unit/test_address_map.py`
- Delete: `tests/unit/test_d2_conventions.py`
- Delete: `tests/unit/test_debugger_engine.py`
- Delete: `tests/unit/test_debugger_server.py`
- Delete: `tests/unit/test_windbg.py`
- Test: Java debugger contracts, Python schema/registration/setup contracts

**Interfaces:**
- Consumes: Java `DebuggerService`, `debugger_launch_offers`, `debugger_status`, `debugger_modules`, `debugger_read_memory`, static/dynamic mapping, `create_memory_block`, and Ghidra-agent `install_ghidratrace_for_debugger`.
- Produces: pure Java `DebuggerTransferSemantics.rebase(long,long,long)` and `planChunks(long,int)` for future trace-copy work; clean schema-discovered TraceRMI names on every host.

- [ ] **Step 1: Write failing engine-neutral semantics tests**

Create `DebuggerTransferSemanticsTest.java`:

```java
package com.xebyte.offline;

import com.xebyte.core.DebuggerTransferSemantics;
import junit.framework.TestCase;

public class DebuggerTransferSemanticsTest extends TestCase {
    public void testRebasePreservesModuleOffset() {
        assertEquals(0x180001234L,
                DebuggerTransferSemantics.rebase(0x7ff612341234L,
                        0x7ff612340000L, 0x180000000L));
    }

    public void testChunkPlanCoversRangeWithoutOverlap() {
        var chunks = DebuggerTransferSemantics.planChunks(9000, 4096);
        assertEquals(3, chunks.size());
        assertEquals(new DebuggerTransferSemantics.Chunk(0, 4096), chunks.get(0));
        assertEquals(new DebuggerTransferSemantics.Chunk(4096, 4096), chunks.get(1));
        assertEquals(new DebuggerTransferSemantics.Chunk(8192, 808), chunks.get(2));
    }

    public void testChunkPlanRejectsInvalidLengths() {
        assertThrows(IllegalArgumentException.class,
                () -> DebuggerTransferSemantics.planChunks(0, 4096));
        assertThrows(IllegalArgumentException.class,
                () -> DebuggerTransferSemantics.planChunks(1, 0));
    }
}
```

- [ ] **Step 2: Verify the semantics tests fail to compile**

Run:

```bash
mvn test -Dtest='com.xebyte.offline.DebuggerTransferSemanticsTest'
```

Expected: compilation fails because `DebuggerTransferSemantics` does not exist.

- [ ] **Step 3: Implement only the reusable semantics, not endpoints**

Create `DebuggerTransferSemantics.java`:

```java
package com.xebyte.core;

import java.util.ArrayList;
import java.util.List;

public final class DebuggerTransferSemantics {
    private DebuggerTransferSemantics() {}

    public record Chunk(long offset, int length) {}

    public static long rebase(long address, long runtimeBase, long staticBase) {
        if (Long.compareUnsigned(address, runtimeBase) < 0) {
            throw new IllegalArgumentException("address precedes runtime base");
        }
        return Math.addExact(staticBase, Math.subtractExact(address, runtimeBase));
    }

    public static List<Chunk> planChunks(long length, int maximumChunkSize) {
        if (length <= 0) throw new IllegalArgumentException("length must be positive");
        if (maximumChunkSize <= 0) {
            throw new IllegalArgumentException("maximum chunk size must be positive");
        }
        List<Chunk> chunks = new ArrayList<>();
        for (long offset = 0; offset < length; ) {
            int chunk = (int) Math.min((long) maximumChunkSize, length - offset);
            chunks.add(new Chunk(offset, chunk));
            offset = Math.addExact(offset, chunk);
        }
        return List.copyOf(chunks);
    }
}
```

Run the focused test again; expected: `3` tests pass.

- [ ] **Step 4: Add the TraceRMI source/endpoint seam contract**

Create `DebuggerServiceContractTest.java`:

```java
package com.xebyte.offline;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import junit.framework.TestCase;

public class DebuggerServiceContractTest extends TestCase {
    public void testTraceRmiSeamEndpointsRemainAnnotated() throws Exception {
        String source = Files.readString(Path.of(System.getProperty("user.dir"),
                "src/main/java/com/xebyte/core/DebuggerService.java"));
        assertTrue(source.contains("@McpToolGroup(value = \"debugger\""));
        for (String path : List.of(
                "/debugger/launch_offers", "/debugger/status",
                "/debugger/modules", "/debugger/read_memory",
                "/debugger/static_to_dynamic", "/debugger/dynamic_to_static")) {
            assertTrue("missing TraceRMI seam " + path,
                    source.contains("path = \"" + path + "\""));
        }
        assertTrue(source.contains("launcherSvc.getOffers(program)"));
        assertTrue(source.contains("offer.supportsImage()"));
        assertTrue(source.contains("offer.requiresImage()"));
    }

    public void testFutureEndpointsAreNotFalselyAdvertised() throws Exception {
        String source = Files.readString(Path.of(System.getProperty("user.dir"),
                "src/main/java/com/xebyte/core/DebuggerService.java"));
        assertFalse(source.contains("/debugger/attach"));
        assertFalse(source.contains("/debugger/wait_for_stop"));
        assertFalse(source.contains("/debugger/memory_maps"));
        assertFalse(source.contains("/debugger/copy_memory_to_program"));
    }
}
```

Run:

```bash
mvn test -Dtest='com.xebyte.offline.DebuggerTransferSemanticsTest,com.xebyte.offline.DebuggerServiceContractTest'
```

Expected: all tests pass before proxy deletion, proving the retained Java side is independently present.

- [ ] **Step 5: Write the failing Python proxy-absence test**

Append to `tests/unit/test_removed_subsystems.py`:

```python
def test_standalone_debugger_proxy_is_absent():
    assert not (ROOT / "debugger").exists()
    assert not (ROOT / "python/bridge_mcp_ghidra/debugger.py").exists()
    maintained = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "python/bridge_mcp_ghidra").glob("*.py")
    )
    assert "GHIDRA_DEBUGGER_URL" not in maintained
    assert "DEBUGGER_TOOL_NAMES" not in maintained
```

Run it and expect failure on the existing proxy tree, client, and configuration names.

- [ ] **Step 6: Remove the proxy client/server without touching TraceRMI setup**

Delete the listed proxy files/tests. Remove debugger imports/registration from `__init__.py`; remove `DEBUGGER_URL`, `DEBUGGER_TOOL_NAMES`, `_ALL_STATIC_TOOL_NAMES` debugger reservations, and the stale `_2` naming comment from `config.py`. Simplify schema normalization to allocate against active management names only:

```python
used_names = set(STATIC_TOOL_NAMES)
name = _allocate_tool_name(sanitize_tool_name(raw_name), used_names)
```

Retain endpoint paths unchanged. Update registry imports accordingly and keep
dynamic schema tools as the only debugger registration mechanism.

Remove `pybag` and `comtypes` from `pyproject.toml`. Remove the root `debugger` dependency group entirely; `protobuf` continues to be installed into the selected Ghidra launcher Python by `install_ghidratrace_for_debugger`, not into the bridge environment.

Simplify `InstallPlan` to:

```python
@dataclass(frozen=True)
class InstallPlan:
    repo_root: Path
    groups: tuple[str, ...]


def make_install_plan(
    repo_root: Path, base_groups: tuple[str, ...] = ("dev",)
) -> InstallPlan:
    return InstallPlan(repo_root=repo_root, groups=base_groups)
```

Remove `--with-debugger`, `--use-debugger-toggle`, `_should_install_debugger`,
`InstallPlan.install_debugger`, and the root-pyproject debugger-group preflight.
Call `make_install_plan(repo_root)` unconditionally. Keep the existing
best-effort `install_ghidratrace_for_debugger` call inside
`install_ghidra_dependencies`, along with its tests and Java TraceRMI live
tests; that installation targets the selected Ghidra launcher Python and is
independent of bridge dependency groups.

Regenerate the lock:

```bash
uv lock
uv lock --check
```

- [ ] **Step 7: Update bridge tests for clean schema-discovered names**

Remove proxy decorator-count and `_debugger_enabled` tests. Retain a generalized test in `test_bridge_utils.py`:

```python
def test_trace_rmi_debugger_endpoint_keeps_clean_name():
    import bridge_mcp_ghidra as bridge
    schema = bridge._parse_schema(
        {"tools": [{"path": "/debugger/status", "method": "GET", "params": []}]}
    )
    assert schema[0]["name"] == "debugger_status"
    assert schema[0]["name_collided"] is False
```

Update `test_endpoint_catalog.py` so static bridge tools count management decorators only. Update setup requirement/CLI tests for the simplified `InstallPlan` while retaining ghidratrace installation tests.

- [ ] **Step 8: Run debugger, schema, setup, and full unit gates**

Run:

```bash
mvn test -Dtest='com.xebyte.offline.DebuggerTransferSemanticsTest,com.xebyte.offline.DebuggerServiceContractTest,com.xebyte.offline.EndpointsJsonParityTest'
pytest tests/unit/test_removed_subsystems.py tests/unit/test_bridge_utils.py tests/unit/test_endpoint_catalog.py tests/unit/test_setup_requirements.py tests/unit/test_setup_cli.py tests/unit/test_setup_ghidra.py tests/unit/test_protected_workflows.py -v --no-cov
pytest tests/unit/ -v --no-cov
mvn clean compile -q
git diff --check
```

Expected: all commands exit `0`; the protected 18 TraceRMI endpoints remain; proxy-only dependencies and names are absent.

- [ ] **Step 9: Request Claude review of the debugger boundary**

Use the `claude` skill to verify that only the standalone proxy was removed, TraceRMI/ghidratrace setup and live tests remain, clean dynamic names are correct, and the pure semantics are useful without pretending the four future endpoints exist. Resolve findings and resume until clear.

- [ ] **Step 10: Commit the debugger cut**

```bash
git add -A
git commit -m "refactor: remove dbgeng proxy and preserve TraceRMI seams"
```

---

### Task 7: Remove Naming Enforcement and Implicit Prefix Mutation

**Files:**
- Create: `src/main/java/com/xebyte/core/GeneratedSymbolNames.java`
- Create: `src/test/java/com/xebyte/offline/UnrestrictedNamingContractTest.java`
- Modify: `src/main/java/com/xebyte/core/FunctionService.java`
- Modify: `src/main/java/com/xebyte/core/SymbolLabelService.java`
- Modify: `src/main/java/com/xebyte/core/DataTypeService.java`
- Modify: `src/main/java/com/xebyte/core/CommentService.java`
- Modify: `src/main/java/com/xebyte/core/ListingService.java`
- Modify: `src/main/java/com/xebyte/core/AnalysisService.java`
- Modify: `src/main/java/com/xebyte/core/ServiceUtils.java`
- Modify: `src/main/java/com/xebyte/GhidraMCPPlugin.java`
- Modify: `src/main/java/com/xebyte/headless/HeadlessEndpointHandler.java`
- Modify: `src/test/java/com/xebyte/offline/ArchitectureBoundaryTest.java`
- Modify: `tools/setup/ghidra.py`
- Delete: `src/main/java/com/xebyte/core/NamingConventions.java`
- Delete: `src/main/java/com/xebyte/core/NamingPolicy.java`
- Delete: `src/main/java/com/xebyte/core/ConventionConfig.java`
- Delete: `src/main/java/com/xebyte/core/ConventionConfigLoader.java`
- Delete: `src/main/java/com/xebyte/core/PromptPolicyService.java`
- Delete: `src/test/java/com/xebyte/offline/NamingConventionsTest.java`
- Delete: `src/test/java/com/xebyte/offline/NamingPolicyTest.java`
- Delete: `src/test/java/com/xebyte/offline/ConventionConfigTest.java`
- Modify: `tests/endpoints.json`
- Test: unrestricted naming contract, datatype/function/symbol validation tests, endpoint parity

**Interfaces:**
- Consumes: existing Ghidra exception handling in rename/label/datatype services.
- Produces: `GeneratedSymbolNames.isGenerated(String)` for listing/filtering only; caller-supplied names pass unchanged to Ghidra.

- [ ] **Step 1: Write the failing unrestricted-naming source contract**

Create `UnrestrictedNamingContractTest.java`:

```java
package com.xebyte.offline;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import junit.framework.TestCase;

public class UnrestrictedNamingContractTest extends TestCase {
    private static final Path ROOT = Path.of(System.getProperty("user.dir"));

    public void testMutationServicesDoNotUseRemovedNamingPolicy() throws Exception {
        for (String file : List.of("FunctionService.java", "SymbolLabelService.java",
                "DataTypeService.java", "CommentService.java")) {
            String source = Files.readString(ROOT.resolve(
                    "src/main/java/com/xebyte/core/" + file));
            assertFalse(file, source.contains("NamingConventions"));
            assertFalse(file, source.contains("NamingPolicy"));
        }
    }

    public void testStructFieldsAreNotImplicitlyPrefixed() throws Exception {
        String source = Files.readString(ROOT.resolve(
                "src/main/java/com/xebyte/core/DataTypeService.java"));
        assertFalse(source.contains("applyStructFieldNamingPolicy"));
    }

    public void testGhidraInvalidInputHandlingRemains() throws Exception {
        String symbols = Files.readString(ROOT.resolve(
                "src/main/java/com/xebyte/core/SymbolLabelService.java"));
        assertTrue(symbols.contains("InvalidInputException"));
        assertTrue(symbols.contains("Response.err"));
    }
}
```

- [ ] **Step 2: Verify the naming contract fails on policy references**

Run:

```bash
mvn test -Dtest='com.xebyte.offline.UnrestrictedNamingContractTest'
```

Expected: policy/prefix tests fail; Ghidra exception-handling test passes.

- [ ] **Step 3: Remove mutation-time policy and preserve generic generated-name detection**

Delete validation, warning, strict-mode, collision-quality, plate-policy, Hungarian-validation, and auto-prefix calls from the four mutation services. Pass the exact supplied name to Ghidra setters. Keep existing `InvalidInputException`, duplicate, parse, and transaction handling.

Create `GeneratedSymbolNames.java` for read-only filtering:

```java
package com.xebyte.core;

public final class GeneratedSymbolNames {
    private GeneratedSymbolNames() {}

    public static boolean isGenerated(String name) {
        if (name == null || name.isBlank()) return true;
        return name.matches("(?i)(FUN|LAB|DAT|PTR|SUB|LOC|BYTE|WORD|DWORD|QWORD)_[0-9a-f]+")
                || name.startsWith("Ordinal_")
                || name.startsWith("thunk_FUN_")
                || name.startsWith("thunk_Ordinal_");
    }
}
```

Replace read-only `isAutoGeneratedGlobalName` checks in `ListingService` and
`DataTypeService` with `GeneratedSymbolNames.isGenerated`. Remove
naming-quality/collision analysis blocks from `AnalysisService`; do not use the
new helper to reject or mutate names.

Move the non-policy type utility used by `FunctionService` into `ServiceUtils`
and update its call site:

```java
public static boolean isUndefinedToUndefined(String oldType, String newType) {
    return oldType != null && newType != null
            && oldType.startsWith("undefined") && newType.startsWith("undefined");
}
```

- [ ] **Step 4: Remove orphaned policy endpoint/classes and strict-mode parameters**

Remove `PromptPolicyService` construction/registration and `/prompt_policy`.
Delete the five policy/config classes and their old tests. Preserve optional
`strict_mode` parameters on retained endpoints as deprecated compatibility
inputs, but do not branch on them or feed them into a policy. Update their
descriptions to say they are ignored because Ghidra validation is authoritative.

Add this method to `ArchitectureBoundaryTest`:

```java
public void testNamingPolicyDependenciesAreAbsent() throws Exception {
    String source = maintainedJava();
    for (String forbidden : List.of(
            "NamingConventions", "NamingPolicy", "ConventionConfig",
            "ConventionConfigLoader", "PromptPolicyService")) {
        assertFalse("forbidden naming-policy dependency: " + forbidden,
                source.contains(forbidden));
    }
}
```

Add this catalog assertion to `test_protected_workflows.py`:

```python
def test_prompt_policy_endpoint_is_absent():
    assert "/prompt_policy" not in _catalog_paths()
```

Update `tools/setup/ghidra.py` required tool sets to contain no `prompt_policy` or naming-policy endpoints.

- [ ] **Step 5: Regenerate endpoints and run focused tests**

Run:

```bash
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
mvn test -Dtest='com.xebyte.offline.UnrestrictedNamingContractTest,com.xebyte.offline.FunctionServicePrototypeTest,com.xebyte.offline.FunctionServiceVariableHintTest,com.xebyte.offline.SymbolLabelServiceValidationTest,com.xebyte.offline.DatatypeMcpToolsHandlerValidationTest,com.xebyte.offline.EndpointsJsonParityTest'
pytest tests/unit/test_endpoint_catalog.py tests/unit/test_project_consistency.py tests/unit/test_protected_workflows.py tests/unit/test_setup_ghidra.py -v --no-cov
mvn clean compile -q
git diff --check
```

Expected: all commands exit `0`; caller names are not policy-mutated; Ghidra errors remain structured.

- [ ] **Step 6: Commit the naming cut**

```bash
git add -A
git commit -m "refactor: remove naming policy enforcement"
```

---

### Task 8: Triage Scripts and Localize BSim

**Files:**
- Create: `tests/unit/test_ghidra_script_inventory.py`
- Rename: `ghidra_scripts/BSimQueryAndPropagate.java` to `ghidra_scripts/BSimQueryFunction.java`
- Modify: `ghidra_scripts/BSimTestConnection.java`
- Modify: `ghidra_scripts/BSimIngestProgram.java`
- Modify: `ghidra_scripts/BSimQueryFunction.java`
- Modify: `ghidra_scripts/BSimBulkQuery.java`
- Modify: `ghidra_scripts/README.md`
- Delete: application-specific and propagation scripts not in the retained allowlist below
- Test: `tests/unit/test_ghidra_script_inventory.py`

**Interfaces:**
- Consumes: generic `run_ghidra_script`/`run_script_inline` and Ghidra stock BSim APIs.
- Produces: a small explicit generic-script allowlist and BSim scripts that require a caller-supplied Ghidra-supported URL.

- [ ] **Step 1: Write the failing exact inventory and BSim-default tests**

Create `tests/unit/test_ghidra_script_inventory.py`:

```python
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "ghidra_scripts"
RETAINED = {
    "ApplyDWORD.java",
    "ArgumentsUnifier.py",
    "BSimBulkQuery.java",
    "BSimIngestProgram.java",
    "BSimQueryFunction.java",
    "BSimTestConnection.java",
    "ClearAllComments.java",
    "ClearAndDisasm.java",
    "ClearCallReturnOverrides.java",
    "ClearFunctionComments.java",
    "ClearPrePostComments.java",
    "ConvertNamespaceToClass.java",
    "CreateFunctionsFromArray.py",
    "DeleteFunctionAt.java",
    "FindFunctionsAfterPadding.java",
    "FindFunctionsAfterPaddingAllPrograms.java",
    "FindFunctionsAtINT3.java",
    "FixIATExternalFunctionAddresses.java",
    "ProperSizeStringsScript.java",
    "RemoveDecompilerComments.java",
    "RemoveOrphanedFunctions.java",
    "RestoreLibraryFunctionNamesFromPlateComments.java",
    "UpgradeAllPrograms.java",
    "namespacer.py",
    "README.md",
}


def test_script_inventory_is_generic_allowlist():
    actual = {path.name for path in SCRIPTS.iterdir() if path.is_file()}
    assert actual == RETAINED


def test_bsim_scripts_have_no_remote_default_or_propagation_language():
    combined = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in SCRIPTS.glob("BSim*.java")
    )
    assert "10.0.10.30" not in combined
    assert "DEFAULT_BSIM_URL" not in combined
    assert "AndPropagate" not in combined
    assert "BSim URL is required" in combined
```

- [ ] **Step 2: Verify the inventory test fails**

Run:

```bash
pytest tests/unit/test_ghidra_script_inventory.py -v --no-cov
```

Expected: failures show extra product-specific scripts, the old BSim filename, and hard-coded PostgreSQL URL.

- [ ] **Step 3: Make BSim configuration explicit**

Rename the query class/file to `BSimQueryFunction`. In each BSim script, resolve a URL with this behavior:

```java
private String requireBsimUrl(String[] args, int index, String dialogTitle)
        throws Exception {
    if (args != null && args.length > index && args[index] != null
            && !args[index].isBlank()) {
        return args[index].trim();
    }
    if (!isRunningHeadless()) {
        String value = askString(dialogTitle, "Enter BSim database URL:");
        if (value != null && !value.isBlank()) return value.trim();
    }
    throw new IllegalArgumentException("BSim URL is required");
}
```

Use argument index `0` for test/ingest/bulk and index `1` for single-function query. Catch `IllegalArgumentException` at the start of `run()` and print the existing JSON error envelope. Update examples to use `file:/absolute/path/to/local-bsim` as an illustrative caller-supplied URL, while stating that any URL must be supported by the installed Ghidra BSim client.

- [ ] **Step 4: Delete scripts outside the allowlist and update the script README**

Remove all files not listed in `RETAINED`. The README must group the survivors as BSim, repair/disassembly, comment cleanup, datatype/symbol utility, and local project maintenance. It must explain script execution remains gated by `GHIDRA_MCP_ALLOW_SCRIPTS` and must not mention D2, propagation, shared check-in, or remote defaults.

- [ ] **Step 5: Run script inventory and generic script security tests**

Run:

```bash
pytest tests/unit/test_ghidra_script_inventory.py tests/unit/test_protected_workflows.py -v --no-cov
mvn test -Dtest='com.xebyte.offline.ProgramScriptServiceValidationTest,com.xebyte.offline.RunGhidraScriptProgramPropagationTest'
mvn clean compile -q
git diff --check
```

Expected: all commands exit `0`.

- [ ] **Step 6: Commit the script/BSim boundary**

```bash
git add -A
git commit -m "refactor: retain generic scripts and local BSim support"
```

---

### Task 9: Update All Maintained Documentation and Remove Obsolete Archives

**Files:**
- Create: `tests/unit/test_documentation_surface.py`
- Modify: `README.md`
- Modify: `CONTRIBUTING.md`
- Modify: `ROADMAP.md`
- Modify: `SECURITY.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/README.md`
- Modify: `docs/PROJECT_STRUCTURE.md`
- Modify: `docs/TESTING.md`
- Modify: `docs/QUICK_REFERENCE_SCRIPTS.md`
- Modify: `docs/MULTI_PROGRAM_SUPPORT_ANALYSIS.md`
- Modify: `docs/prompts/README.md`
- Modify: `docs/prompts/TOOL_USAGE_GUIDE.md`
- Modify: `docs/prompts/CROSS_VERSION_FUNCTION_MATCHING.md`
- Modify: `.github/workflows/README.md`
- Modify: `tools/README.md`
- Modify: `workflows/README.md`
- Delete: naming-policy, propagation, archived legacy-tool, obsolete project-management, and archived release documents describing removed surfaces
- Test: `tests/unit/test_documentation_surface.py`, project consistency tests

**Interfaces:**
- Consumes: final endpoint catalog, script inventory, Maven/setup commands, local project and TraceRMI contracts.
- Produces: one accurate maintained documentation surface and a changelog entry for the removal.

- [ ] **Step 1: Write the failing maintained-doc command/reference test**

Create `tests/unit/test_documentation_surface.py`:

```python
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAINTAINED = [
    "README.md", "CONTRIBUTING.md", "ROADMAP.md", "SECURITY.md",
    "docs/README.md", "docs/PROJECT_STRUCTURE.md", "docs/TESTING.md",
    "docs/QUICK_REFERENCE_SCRIPTS.md", "docs/prompts/README.md",
    "docs/prompts/TOOL_USAGE_GUIDE.md", ".github/workflows/README.md",
    "tools/README.md", "workflows/README.md", "ghidra_scripts/README.md",
]


def _maintained_text() -> str:
    return "\n".join((ROOT / path).read_text(encoding="utf-8") for path in MAINTAINED)


def test_docs_do_not_advertise_removed_commands_or_configuration():
    text = _maintained_text()
    for forbidden in (
        "./gradlew", "gradlew.bat", "TOOLS_SETUP_BACKEND",
        "docker compose", "GHIDRA_DEBUGGER_URL", "--group fun-doc",
        "10.0.10.30", "debugger_continue", "debugger_attach()",
    ):
        assert forbidden not in text


def test_docs_name_the_retained_dynamic_contract():
    text = _maintained_text()
    assert 'load_tool_group("debugger")' in text
    assert "debugger_launch_offers" in text
    assert "debugger_launch" in text
    assert "debugger_set_breakpoint" in text
    assert "debugger_read_memory" in text
    assert "There is no generic TraceRMI attach endpoint" in text


def test_obsolete_document_trees_are_absent():
    assert not (ROOT / "docs/archive/legacy-tools").exists()
    assert not (ROOT / "docs/project-management").exists()
    assert not (ROOT / "docs/releases/archive").exists()
```

- [ ] **Step 2: Verify the documentation test fails on stale references/trees**

Run:

```bash
pytest tests/unit/test_documentation_surface.py -v --no-cov
```

Expected: failures identify stale commands/configuration, missing retained TraceRMI wording, and obsolete document trees.

- [ ] **Step 3: Rewrite maintained user/developer documentation from the final surface**

Document these exact outcomes:

- Maven commands from `AGENTS.md` and `python -m tools.setup build`;
- local GUI/headless projects and multi-program workflows;
- `load_tool_group("debugger")` once, then the 18 schema-discovered TraceRMI tools;
- `debugger_resume`, not removed proxy `debugger_continue`;
- no generic TraceRMI attach/wait/map/copy endpoint yet, plus the four preserved seams;
- generic script gating through `SecurityConfig`;
- explicit local BSim URL and the four retained BSim scripts;
- the retained local comparison endpoint names; and
- supported TCP/UDS transports.

Remove instructions for Ghidra repository server, shared check-in/out, fun-doc, Docker, Gradle, the standalone dbgeng proxy, naming policy configuration, documentation propagation, and the remote BSim host.

- [ ] **Step 4: Remove obsolete documents and update changelog**

Delete:

- `docs/archive/legacy-tools/`;
- `docs/project-management/`;
- `docs/releases/archive/`;
- `docs/HUNGARIAN_NOTATION.md`;
- `docs/NAMING_CONVENTIONS.md`;
- `docs/PLATE_COMMENT_BEST_PRACTICES.md`;
- `docs/SESSION_SUMMARY_DOCUMENTATION_SYSTEM.md`;
- `docs/WORKFLOW_DOCUMENTATION_PROPAGATION.md`;
- `docs/prompts/CUSTOMIZING_CONVENTIONS.md`;
- `docs/prompts/BINARY_DOCUMENTATION_ORDER.md`;
- `docs/prompts/CROSS_VERSION_MATCHING_COMPREHENSIVE.md`;
- `docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md`;

Rewrite `docs/prompts/CROSS_VERSION_FUNCTION_MATCHING.md` around the six retained
local comparison endpoints and optional local BSim. It must not instruct users
to export/apply/merge documentation or build a persistent hash index.

Add an `Unreleased` changelog section summarizing removals, retained local analysis/TraceRMI/BSim surfaces, clean debugger names, Maven-only build, and the fact that the four debugger additions remain planned rather than implemented.

- [ ] **Step 5: Audit the repository for stale references**

Run:

```bash
pytest tests/unit/test_documentation_surface.py tests/unit/test_project_consistency.py tests/unit/test_endpoint_catalog.py -v --no-cov
rg -n 'fun-doc|TOOLS_SETUP_BACKEND|GHIDRA_DEBUGGER_URL|10\.0\.10\.30|gradlew|docker compose|GhidraServerManager|DocumentationHashService|NamingPolicy' README.md CONTRIBUTING.md ROADMAP.md SECURITY.md docs tools workflows .github ghidra_scripts python src/main pyproject.toml
git diff --check
```

Expected: pytest passes. `rg` returns only deliberate historical/specification statements or no matches; every returned line is manually classified and removed if it advertises a deleted surface.

- [ ] **Step 6: Commit documentation**

```bash
git add -A
git commit -m "docs: describe the streamlined local analysis stack"
```

---

### Task 10: Full Verification, Final Claude Review, and Review Fixes

**Files:**
- Modify: only files required by verified failures or concrete Claude findings
- Test: entire supported Java/Python/build/package surface

**Interfaces:**
- Consumes: all prior task commits.
- Produces: a clean, reviewed feature branch ready for PR integration.

- [ ] **Step 1: Regenerate and verify endpoint catalog one final time**

Run:

```bash
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
mvn test -Dtest='com.xebyte.offline.EndpointsJsonParityTest,com.xebyte.offline.AnnotationScannerOfflineTest'
```

Expected: regeneration is idempotent and both parity tests pass.

- [ ] **Step 2: Run the full supported unit suites**

Run:

```bash
pytest tests/unit/ -v --no-cov
mvn test -Dtest='com.xebyte.offline.*Test'
mvn clean compile -q
```

Expected: all commands exit `0`.

- [ ] **Step 3: Build both deliverables and verify setup routing**

Run:

```bash
mvn clean package assembly:single -DskipTests
uv build
uv lock --check
python -m tools.setup build --dry-run
```

Expected: Maven creates the extension ZIP/JAR, uv creates wheel/sdist, lock check passes, and setup prints only Maven.

- [ ] **Step 4: Run optional live checks when the local environment supports them**

Run the existing setup live modes only if a compatible local Ghidra path is configured:

```bash
python -m tools.setup preflight --ghidra-path "$GHIDRA_PATH"
python -m tools.setup deploy --ghidra-path "$GHIDRA_PATH" --test endpoint-catalog --test multi-program --test debugger-live
```

Expected: preflight passes; endpoint and multi-program modes pass; debugger-live either passes or reports its existing explicit environmental skip. Record the exact skip reason in the final handoff rather than treating it as executed coverage.

- [ ] **Step 5: Request final Claude review**

Use the `claude` skill on the complete branch diff. Ask it to check the approved specification, protected FileZilla/Wine workflows, the four future-feature seams, accidental removal of local/headless/TraceRMI/security behavior, stale dependencies/docs, and test adequacy. Resolve each concrete finding with a focused failing test first, rerun the affected gates, and resume the same Claude review until no current findings remain.

- [ ] **Step 6: Commit verified review fixes if the tree changed**

If fixes were required:

```bash
git add -A
git commit -m "fix: address final architecture review findings"
```

If no fixes were required, do not create an empty commit.

- [ ] **Step 7: Re-run final evidence checks**

Run:

```bash
pytest tests/unit/ -v --no-cov
mvn test -Dtest='com.xebyte.offline.*Test'
mvn clean package assembly:single -DskipTests
uv build
git diff --check
git status --short --branch
```

Expected: all verification commands exit `0`; status shows a clean `refactor/remove-unused-subsystems` branch.

---

### Task 11: Push, Review, Merge Commit, and Remote Verification

**Files:**
- No source changes expected

**Interfaces:**
- Consumes: clean verified feature branch.
- Produces: reviewed PR and merge commit on the configured remote mainline.

- [ ] **Step 1: Use the branch-finishing workflow**

Invoke `superpowers:verification-before-completion`, then `superpowers:finishing-a-development-branch`. Do not claim success from earlier output; use Task 10 Step 7 evidence from the current HEAD.

- [ ] **Step 2: Push the feature branch**

```bash
git push -u origin refactor/remove-unused-subsystems
```

Expected: remote branch is created/updated successfully.

- [ ] **Step 3: Create the project-required PR**

```bash
gh pr create --base main --head refactor/remove-unused-subsystems --title "Refactor ghidra-mcp around local analysis and TraceRMI" --body "Removes unused server, propagation, proxy-debugger, naming-policy, build, and curation subsystems while preserving local FileZilla analysis, Wine/TraceRMI debugging, generic comparison, and local BSim. Includes characterization, architecture, parity, packaging, and Claude review gates."
```

Expected: GitHub returns the PR URL. Confirm checks complete successfully before merging.

- [ ] **Step 4: Merge through a merge commit**

```bash
gh pr merge --merge
```

Expected: GitHub reports the PR merged using a merge commit, not squash or rebase.

- [ ] **Step 5: Verify remote main contains the merge commit**

From the original main worktree:

```bash
git fetch origin
git pull --ff-only origin main
git log -1 --merges --oneline origin/main
git status --short --branch
```

Expected: the latest merge commit identifies the architecture-slimming PR; local main matches `origin/main`; working tree is clean.
