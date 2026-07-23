import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "tests" / "endpoints.json"

FILEZILLA_ENDPOINTS = {
    "/create_project", "/open_project", "/import_file",
    "/list_open_programs", "/switch_program", "/save_program",
    "/search_strings", "/search_functions", "/search_byte_patterns",
    "/search_instructions", "/get_xrefs_to", "/get_xrefs_from",
    "/decompile_function", "/disassemble_flow", "/clear_flow_and_repair",
    "/rename_function", "/rename_label", "/set_disassembly_comment",
    "/create_struct", "/add_struct_field", "/create_memory_block",
    "/run_ghidra_script", "/run_script_inline",
}

TRACE_RMI_ENDPOINTS = {
    "/copy_debugger_memory_to_program",
    "/debugger/launch_offers", "/debugger/launch", "/debugger/attach",
    "/debugger/wait_for_stop",
    "/debugger/memory_maps",
    "/debugger/status",
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

REMOVED_SERVER_ENDPOINTS = {
    "/checkin_program", "/server/connect", "/server/disconnect",
    "/server/status", "/server/authenticate", "/server/repositories",
    "/server/repository/files", "/server/repository/file",
    "/server/repository/create", "/server/version_control/add",
    "/server/version_control/checkout", "/server/version_control/checkin",
    "/server/version_control/undo_checkout", "/server/version_history",
    "/server/checkouts", "/server/admin/users", "/server/admin/set_permissions",
    "/server/admin/terminate_checkout", "/server/admin/terminate_all_checkouts",
}

REMOVED_DOCUMENTATION_ENDPOINTS = {
    "/get_function_documentation", "/apply_function_documentation",
    "/compare_programs_documentation", "/find_undocumented_by_string",
    "/batch_string_anchor_report", "/merge_program_documentation",
    "/archive_ingest_function", "/archive_ingest_program",
}

TRACE_RMI_CONTRACT_TOOLS = {
    "copy_debugger_memory_to_program",
    "debugger/launch_offers",
    "debugger/launch",
    "debugger/attach",
    "debugger/wait_for_stop",
    "debugger/memory_maps",
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

GENERIC_SMOKE_TOOLS = {
    "analysis_status",
    "analyze_function_completeness",
    "batch_set_comments",
    "create_folder",
    "delete_file",
    "get_address_spaces",
    "get_function_variables",
    "get_struct_layout",
    "list_exports",
    "list_functions",
    "list_imports",
    "list_project_files",
    "list_strings",
    "rename_function_by_address",
    "rename_variables",
    "save_all_programs",
    "search_data_types",
    "set_function_prototype",
    "set_local_variable_type",
}


def _catalog_paths() -> set[str]:
    payload = json.loads(CATALOG.read_text(encoding="utf-8"))
    return {entry["path"] for entry in payload["endpoints"]}


def test_filezilla_workflow_endpoints_are_cataloged():
    assert FILEZILLA_ENDPOINTS <= _catalog_paths()


def test_trace_rmi_workflow_endpoints_are_cataloged():
    assert TRACE_RMI_ENDPOINTS <= _catalog_paths()


def test_copy_memory_tool_keeps_exact_public_name():
    from bridge_mcp_ghidra import _parse_schema

    schema = _parse_schema({"tools": [{
        "path": "/copy_debugger_memory_to_program",
        "method": "POST",
        "category": "debugger",
        "params": [],
    }]})
    assert [tool["name"] for tool in schema] == [
        "copy_debugger_memory_to_program"
    ]


def test_local_comparison_endpoints_are_cataloged():
    assert LOCAL_COMPARISON_ENDPOINTS <= _catalog_paths()


def test_repository_server_endpoints_are_absent():
    assert REMOVED_SERVER_ENDPOINTS.isdisjoint(_catalog_paths())


def test_repository_server_configuration_is_absent():
    maintained = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in (".env.template", "ghidra-mcp-setup.ps1")
    )
    for forbidden in (
        "GHIDRA_SERVER_HOST", "GHIDRA_SERVER_PORT",
        "GHIDRA_SERVER_USER", "GHIDRA_SERVER_PASSWORD", "ServerPassword",
    ):
        assert forbidden not in maintained


def test_documentation_propagation_endpoints_are_absent():
    assert REMOVED_DOCUMENTATION_ENDPOINTS.isdisjoint(_catalog_paths())


def test_prompt_policy_endpoint_is_absent():
    assert "/prompt_policy" not in _catalog_paths()


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


def test_live_release_contract_matches_the_protected_public_surface():
    from tools.setup import ghidra

    protected_tools = {
        path.lstrip("/")
        for path in FILEZILLA_ENDPOINTS | LOCAL_COMPARISON_ENDPOINTS
    } | TRACE_RMI_CONTRACT_TOOLS

    assert ghidra.TRACE_RMI_CONTRACT_TOOLS == TRACE_RMI_CONTRACT_TOOLS
    assert ghidra.RELEASE_CONTRACT_TOOLS == protected_tools


def test_live_smoke_contract_preserves_generic_non_policy_checks():
    from tools.setup import ghidra

    assert ghidra.SMOKE_REQUIRED_TOOLS == (
        ghidra.RELEASE_CONTRACT_TOOLS | GENERIC_SMOKE_TOOLS
    )
    assert "prompt_policy" not in ghidra.SMOKE_REQUIRED_TOOLS
    assert "prompt_policy" not in ghidra.RELEASE_CONTRACT_TOOLS
