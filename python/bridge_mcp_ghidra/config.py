"""Configuration constants, timeouts, environment, and logging for the bridge."""

import logging
import os

# ==========================================================================
# Request timeouts
# ==========================================================================

# Per-endpoint timeout overrides for expensive operations
ENDPOINT_TIMEOUTS = {
    "rename_variables": 120,
    "batch_rename_variables": 120,
    "batch_set_comments": 120,
    "analyze_function_complete": 120,
    "batch_rename_function_components": 120,
    "batch_set_variable_types": 90,
    "analyze_data_region": 90,
    "batch_create_labels": 60,
    "batch_delete_labels": 60,
    "disassemble_flow": 120,
    "bulk_fuzzy_match": 180,
    "find_similar_functions_fuzzy": 60,
    "import_file": 300,
    "run_ghidra_script": 1800,
    "run_script_inline": 1800,
    "decompile_function": 45,
    "set_function_prototype": 45,
    "rename_function": 45,
    "rename_function_by_address": 45,
    "consolidate_duplicate_types": 60,
    "batch_analyze_completeness": 120,
    "default": 30,
}

DEFAULT_TCP_URL = "http://127.0.0.1:8089"
DEFAULT_TCP_PORT = 8089
# When set, forwarded to the Ghidra server as `Authorization: Bearer <token>`.
# Same env var the plugin/headless server enforces (v5.4.1+); unset = no header.
AUTH_TOKEN = (os.getenv("GHIDRA_MCP_AUTH_TOKEN") or "").strip()
# Bridge-side TCP port scan range. Mirrors the plugin's
# TCP_PORT_FALLBACK_RANGE so a TCP-only multi-instance setup (e.g. Windows
# 10 pre-1803 where AF_UNIX is unavailable) can still be discovered without
# having to set GHIDRA_MCP_URL per instance. See issue #175 + Copilot review.
TCP_PORT_SCAN_RANGE = 16

# ==========================================================================
# Logging
# ==========================================================================

LOG_LEVEL = os.getenv("GHIDRA_MCP_LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("bridge_mcp_ghidra")

# ==========================================================================
# Tool-group / static-tool catalog constants
# ==========================================================================

MANAGEMENT_TOOL_NAMES = {
    "list_instances",
    "connect_instance",
    "create_and_connect_project",
    "refresh_connection",
    "get_connection_info",
    "list_tool_groups",
    "load_tool_group",
    "unload_tool_group",
    "check_tools",
    "search_tools",
    "import_file_and_notify",
}

# Static management tools registered by the bridge itself. TraceRMI debugger
# tools are discovered dynamically from Ghidra's /mcp/schema endpoint.
STATIC_TOOL_NAMES = set(MANAGEMENT_TOOL_NAMES)

# Core groups always loaded on connect (essential for basic RE workflow)
CORE_GROUPS = {"listing", "function", "program"}
