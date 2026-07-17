import re
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[2]
MAINTAINED = [
    "AGENTS.md",
    "CLAUDE.md",
    "README.md",
    "CONTRIBUTING.md",
    "ROADMAP.md",
    "SECURITY.md",
    "docs/README.md",
    "docs/PROJECT_STRUCTURE.md",
    "docs/TESTING.md",
    "docs/QUICK_REFERENCE_SCRIPTS.md",
    "docs/MULTI_PROGRAM_SUPPORT_ANALYSIS.md",
    "docs/Context-Window-Analysis.md",
    "docs/GHIDRA_VARIABLE_APIS_EXPLAINED.md",
    "docs/MAVEN_VERSION_MANAGEMENT.md",
    "docs/STRUCT_RESIZE_WORKFLOW.md",
    "docs/THIS_POINTER_TYPING.md",
    "docs/prompts/README.md",
    "docs/prompts/TOOL_USAGE_GUIDE.md",
    "docs/prompts/CROSS_VERSION_FUNCTION_MATCHING.md",
    "docs/prompts/DATA_SECTION_WORKFLOW.md",
    "docs/prompts/DATA_TYPE_INVESTIGATION_QUICK.md",
    "docs/prompts/DATA_TYPE_INVESTIGATION_WORKFLOW.md",
    "docs/prompts/GLOBAL_DATA_ANALYSIS_WORKFLOW.md",
    "docs/prompts/ORPHANED_CODE_DISCOVERY_WORKFLOW.md",
    "docs/prompts/STRING_LABELING_CONVENTION.md",
    "docs/releases/README.md",
    "docs/releases/RELEASE_CHECKLIST.md",
    ".github/workflows/README.md",
    "tools/README.md",
    "tools/context_analysis/README.md",
    "workflows/README.md",
    "ghidra_scripts/README.md",
    "logs/README.md",
    "scripts/ghidra/README.md",
]


def _maintained_text() -> str:
    return "\n".join((ROOT / path).read_text(encoding="utf-8") for path in MAINTAINED)


def test_docs_do_not_advertise_removed_commands_or_configuration():
    text = _maintained_text()
    for forbidden in (
        "./gradlew",
        "gradlew.bat",
        "TOOLS_SETUP_BACKEND",
        "docker compose",
        "GHIDRA_DEBUGGER_URL",
        "--group fun-doc",
        "10.0.10.30",
        "debugger_continue",
        "debugger_attach()",
        "/prompt_policy",
        ".ghidra-mcp/conventions.json",
        "export_function_docs",
        "propagate_documentation",
        "checkout_project",
        "checkin_project",
        "fun-doc",
    ):
        assert forbidden not in text


def test_docs_name_the_retained_dynamic_contract():
    text = _maintained_text()
    assert 'load_tool_group("debugger")' in text
    assert "debugger_launch_offers" in text
    assert "debugger_launch" in text
    assert "debugger_set_breakpoint" in text
    assert "debugger_read_memory" in text
    assert "debugger_resume" in text
    assert "There is no generic TraceRMI attach endpoint" in text


def test_docs_name_all_four_planned_debugger_gaps():
    text = _maintained_text()
    assert "Generic TraceRMI attach using a selected launch offer and PID" in text
    assert "debugger_wait_for_stop(timeout_ms)" in text
    assert "Process memory-map enumeration" in text
    assert "copy_debugger_memory_to_program" in text


def test_docs_describe_optional_explicit_local_bsim():
    text = _maintained_text()
    for script in (
        "BSimTestConnection",
        "BSimIngestProgram",
        "BSimQueryFunction",
        "BSimBulkQuery",
    ):
        assert script in text
    assert "file:/absolute/path/to/local-bsim" in text
    assert "GHIDRA_MCP_ALLOW_SCRIPTS" in text


def test_docs_name_maven_and_local_project_workflows():
    text = _maintained_text()
    assert "mvn clean package assembly:single -DskipTests" in text
    assert "python -m tools.setup build" in text
    assert "local project" in text.lower()


def test_obsolete_document_trees_and_files_are_absent():
    for path in (
        "docs/archive/legacy-tools",
        "docs/project-management",
        "docs/releases/archive",
        "docs/HUNGARIAN_NOTATION.md",
        "docs/NAMING_CONVENTIONS.md",
        "docs/PLATE_COMMENT_BEST_PRACTICES.md",
        "docs/SESSION_SUMMARY_DOCUMENTATION_SYSTEM.md",
        "docs/WORKFLOW_DOCUMENTATION_PROPAGATION.md",
        "docs/prompts/CUSTOMIZING_CONVENTIONS.md",
        "docs/prompts/BINARY_DOCUMENTATION_ORDER.md",
        "docs/prompts/CROSS_VERSION_MATCHING_COMPREHENSIVE.md",
        "docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md",
        "docs/JAVA_HANDLER_REFACTORING.md",
        "docs/MARKDOWN_NAMING.md",
        "docs/ORGANIZATION_SUMMARY.md",
        "docs/releases/v5.7.0-VERIFY.md",
        ".github/MARKDOWN_NAMING_GUIDE.md",
        "tools/scyllahide",
    ):
        assert not (ROOT / path).exists(), path


def test_runtime_guidance_does_not_link_to_deleted_workflow_docs():
    analysis = (ROOT / "src/main/java/com/xebyte/core/AnalysisService.java").read_text(
        encoding="utf-8"
    )
    assert "FUNCTION_DOC_WORKFLOW_V4.md" not in analysis
    assert "docs/HUNGARIAN_NOTATION.md" not in analysis
    assert "KNOWN_ORDINALS.md" not in analysis

    java_source = "\n".join(
        path.read_text(encoding="utf-8")
        for source_root in (ROOT / "src/main/java", ROOT / "scripts/ghidra")
        for path in source_root.rglob("*.java")
    )
    assert "fun-doc" not in java_source


def test_context_analysis_uses_the_live_catalog_count():
    for path in (
        "tools/context_analysis/measure_context.py",
        "tools/context_analysis/advanced_context_analysis.py",
    ):
        source = (ROOT / path).read_text(encoding="utf-8")
        assert "251 endpoints" not in source
        assert "251 tools" not in source
        assert "MISSING:" not in source
        assert "/search_tools endpoint" not in source


def test_relative_links_in_maintained_docs_resolve():
    missing = []
    for relative_path in MAINTAINED:
        document = ROOT / relative_path
        text = document.read_text(encoding="utf-8")
        for raw_target in re.findall(r"\[[^]]*\]\(([^)]+)\)", text):
            target = raw_target.strip().strip("<>").split("#", 1)[0]
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            resolved = (document.parent / unquote(target)).resolve()
            if not resolved.exists():
                missing.append(f"{relative_path}: {raw_target}")
    assert missing == []
