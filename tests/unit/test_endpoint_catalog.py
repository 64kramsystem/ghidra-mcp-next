"""
Endpoint Catalog Consistency Tests.

Verifies that:
1. Java services have @McpTool annotations that AnnotationScanner discovers
2. endpoints.json catalog stays in sync
3. Bridge dynamically registers from /mcp/schema (no hardcoded tools)
"""

import inspect
import json
import os
import re
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
JAVA_SRC = PROJECT_ROOT / "src" / "main" / "java" / "com" / "xebyte"
CORE_SRC = JAVA_SRC / "core"
ENDPOINTS_JSON = PROJECT_ROOT / "tests" / "endpoints.json"
# The bridge is now a package split across multiple modules under python/.
BRIDGE_PKG = PROJECT_ROOT / "python" / "bridge_mcp_ghidra"


def _bridge_sources() -> list[Path]:
    """All Python source files that make up the bridge package."""
    return sorted(BRIDGE_PKG.glob("*.py"))


def _bridge_source_text() -> str:
    """Concatenated text of every bridge module (for catalog-content checks)."""
    return "\n".join(p.read_text() for p in _bridge_sources())


def count_mcptool_annotations() -> int:
    """Count @McpTool annotations across all service files."""
    count = 0
    for java_file in CORE_SRC.glob("*Service.java"):
        content = java_file.read_text()
        count += len(re.findall(r"@McpTool\(", content))
    return count


def extract_annotated_paths() -> set[str]:
    """Extract all HTTP paths from @McpTool annotations."""
    paths = set()
    pattern = re.compile(r'@McpTool\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']')
    for java_file in CORE_SRC.glob("*Service.java"):
        content = java_file.read_text()
        for match in pattern.finditer(content):
            paths.add(match.group(1))
    return paths


def extract_gui_only_paths() -> set[str]:
    """Extract GUI-only endpoint paths from GhidraMCPPlugin.java."""
    paths = set()
    plugin_file = JAVA_SRC / "GhidraMCPPlugin.java"
    if plugin_file.exists():
        content = plugin_file.read_text()
        for match in re.finditer(r'server\.createContext\("([^"]+)"', content):
            paths.add(match.group(1))
    return paths


class TestAnnotatedEndpoints(unittest.TestCase):
    """Verify annotation-driven endpoint registration."""

    def test_has_annotated_endpoints(self):
        """Services should have @McpTool annotations."""
        count = count_mcptool_annotations()
        self.assertGreater(
            count, 100, f"Expected >100 annotated endpoints, found {count}"
        )

    def test_all_paths_start_with_slash(self):
        """All @McpTool paths should start with /."""
        for path in extract_annotated_paths():
            self.assertTrue(path.startswith("/"), f"Path should start with /: {path}")

    def test_no_duplicate_paths(self):
        """No two @McpTool annotations should have the same path."""
        paths = []
        pattern = re.compile(r'@McpTool\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']')
        for java_file in CORE_SRC.glob("*Service.java"):
            content = java_file.read_text()
            for match in pattern.finditer(content):
                paths.append(match.group(1))
        duplicates = [p for p in paths if paths.count(p) > 1]
        # Some paths may appear twice (with/without program param overload)
        # but should not appear more than twice
        triplicates = [p for p in set(duplicates) if paths.count(p) > 2]
        self.assertEqual(len(triplicates), 0, f"Triplicate paths: {triplicates}")

    def test_services_exist(self):
        """Expected service files should exist."""
        expected_services = [
            "ListingService",
            "FunctionService",
            "CommentService",
            "SymbolLabelService",
            "XrefCallGraphService",
            "DataTypeService",
            "AnalysisService",
            "BinaryComparisonService",
            "MalwareSecurityService",
            "ProgramScriptService",
            "ExportService",
            "FlowDisassemblyService",
            "ListingRangeService",
            "ListingMutationService",
        ]
        for svc in expected_services:
            path = CORE_SRC / f"{svc}.java"
            self.assertTrue(path.exists(), f"Missing service: {path}")


class TestEndpointsJson(unittest.TestCase):
    """Verify endpoints.json catalog validity."""

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_valid_json(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        self.assertIn("endpoints", data)

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_no_duplicate_paths(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        paths = [ep["path"] for ep in data.get("endpoints", [])]
        self.assertEqual(
            len(paths), len(set(paths)), "Duplicate paths in endpoints.json"
        )

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_endpoints_have_required_fields(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        for ep in data.get("endpoints", []):
            self.assertIn("path", ep, f"Missing 'path' in endpoint: {ep}")
            self.assertIn("method", ep, f"Missing 'method' in endpoint: {ep}")

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_export_ascii_listing_contract(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        matches = [
            ep
            for ep in data.get("endpoints", [])
            if ep["path"] == "/export_ascii_listing"
        ]
        self.assertEqual(len(matches), 1)
        endpoint = matches[0]
        self.assertEqual(endpoint["method"], "POST")
        self.assertEqual(endpoint["category"], "export")
        self.assertIs(endpoint["supports_dry_run"], False)
        self.assertEqual(
            endpoint["params"],
            ["output_path", "start", "end", "overwrite", "program"],
        )

        from bridge_mcp_ghidra import _parse_schema
        from bridge_mcp_ghidra.registry import _build_tool_function

        tool = _parse_schema(
            {
                "tools": [
                    {
                        "path": endpoint["path"],
                        "method": endpoint["method"],
                        "supports_dry_run": endpoint["supports_dry_run"],
                        "params": [],
                    }
                ]
            }
        )[0]
        handler = _build_tool_function(
            tool["endpoint"],
            tool["http_method"],
            tool["input_schema"],
            tool["supports_synthetic_dry_run"],
        )
        self.assertNotIn("dry_run", inspect.signature(handler).parameters)

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_listing_range_contract(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        matches = [
            ep
            for ep in data.get("endpoints", [])
            if ep["path"] == "/get_listing_range"
        ]
        self.assertEqual(len(matches), 1)
        endpoint = matches[0]
        self.assertEqual(endpoint["method"], "GET")
        self.assertEqual(endpoint["category"], "listing")
        self.assertEqual(
            endpoint["params"],
            [
                "start",
                "end",
                "max_units",
                "max_bytes",
                "max_incoming_refs_per_unit",
                "cursor",
                "program",
            ],
        )

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_undefine_range_contract_and_bridge_signature(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        matches = [
            ep
            for ep in data.get("endpoints", [])
            if ep["path"] == "/undefine_range"
        ]
        self.assertEqual(len(matches), 1)
        endpoint = matches[0]
        self.assertEqual(endpoint["method"], "POST")
        self.assertEqual(endpoint["category"], "listing")
        self.assertEqual(
            endpoint["params"],
            [
                "start",
                "end",
                "clear_instructions",
                "clear_data",
                "preserve_labels",
                "preserve_comments",
                "preserve_bookmarks",
                "preserve_user_references",
                "remove_intersecting_functions",
                "dry_run",
                "program",
            ],
        )

        from bridge_mcp_ghidra import _parse_schema
        from bridge_mcp_ghidra.registry import _build_tool_function

        raw_tool = {
            "path": endpoint["path"],
            "method": endpoint["method"],
            "supports_dry_run": True,
            "params": [
                {
                    "name": "start",
                    "type": "string",
                    "source": "body",
                    "required": True,
                    "param_type": "address",
                },
                {
                    "name": "end",
                    "type": "string",
                    "source": "body",
                    "required": True,
                    "param_type": "address",
                },
                {
                    "name": "dry_run",
                    "type": "boolean",
                    "source": "body",
                    "required": False,
                    "default": "true",
                },
            ],
        }
        tool = _parse_schema({"tools": [raw_tool]})[0]
        handler = _build_tool_function(
            tool["endpoint"],
            tool["http_method"],
            tool["input_schema"],
            tool["supports_synthetic_dry_run"],
        )
        signature = inspect.signature(handler)
        self.assertIn("start", signature.parameters)
        self.assertIn("end", signature.parameters)
        self.assertIn("dry_run", signature.parameters)

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_analyzer_configuration_contract_and_analysis_group_loading(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        endpoints = {
            ep["path"]: ep
            for ep in data.get("endpoints", [])
            if ep["path"]
            in {
                "/configure_analyzer",
                "/configure_analyzers",
                "/get_analyzer_configuration",
            }
        }
        self.assertEqual(
            set(endpoints),
            {
                "/configure_analyzer",
                "/configure_analyzers",
                "/get_analyzer_configuration",
            },
        )
        self.assertEqual(
            endpoints["/configure_analyzer"]["params"],
            ["analyzer", "enabled", "program"],
        )
        self.assertEqual(
            endpoints["/configure_analyzers"]["params"],
            ["changes", "dry_run", "program"],
        )
        self.assertIs(
            endpoints["/configure_analyzers"]["supports_dry_run"], False
        )
        self.assertEqual(
            endpoints["/get_analyzer_configuration"]["params"], ["program"]
        )
        self.assertTrue(
            all(ep["category"] == "analysis" for ep in endpoints.values())
        )

        import bridge_mcp_ghidra as bridge

        raw_schema = {
            "tools": [
                {
                    "path": "/configure_analyzer",
                    "method": "POST",
                    "category": "analysis",
                    "supports_dry_run": False,
                    "params": [
                        {
                            "name": "analyzer",
                            "type": "string",
                            "source": "body",
                            "required": True,
                        },
                        {
                            "name": "enabled",
                            "type": "boolean",
                            "source": "body",
                            "required": True,
                        },
                        {
                            "name": "program",
                            "type": "string",
                            "source": "query",
                            "required": False,
                        },
                    ],
                },
                {
                    "path": "/configure_analyzers",
                    "method": "POST",
                    "category": "analysis",
                    "supports_dry_run": False,
                    "params": [
                        {
                            "name": "changes",
                            "type": "json",
                            "source": "body",
                            "required": True,
                        },
                        {
                            "name": "dry_run",
                            "type": "boolean",
                            "source": "body",
                            "required": False,
                            "default": "true",
                        },
                        {
                            "name": "program",
                            "type": "string",
                            "source": "query",
                            "required": False,
                        },
                    ],
                },
                {
                    "path": "/get_analyzer_configuration",
                    "method": "GET",
                    "category": "analysis",
                    "params": [
                        {
                            "name": "program",
                            "type": "string",
                            "source": "query",
                            "required": False,
                        }
                    ],
                },
            ]
        }
        try:
            parsed = bridge._parse_schema(raw_schema)
            self.assertEqual(
                bridge.register_tools_from_schema(parsed, groups={"analysis"}), 3
            )
            self.assertTrue(
                {
                    "configure_analyzer",
                    "configure_analyzers",
                    "get_analyzer_configuration",
                }.issubset(bridge.state._dynamic_tool_names)
            )
            handler = bridge.mcp._tool_manager._tools[
                "configure_analyzers"
            ].fn
            self.assertEqual(
                list(inspect.signature(handler).parameters),
                ["changes", "dry_run", "program"],
            )
        finally:
            bridge.register_tools_from_schema([])

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_disassemble_flow_contract_has_separate_safe_controls(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        endpoint = next(
            ep
            for ep in data.get("endpoints", [])
            if ep["path"] == "/disassemble_flow"
        )
        self.assertEqual(endpoint["method"], "POST")
        self.assertEqual(endpoint["category"], "disassembly")
        self.assertEqual(
            endpoint["params"],
            [
                "seeds",
                "restrict_start",
                "restrict_end",
                "dry_run",
                "follow_calls",
                "preserve_defined_data",
                "create_functions",
                "enable_analysis",
                "max_instructions",
                "program",
            ],
        )
        self.assertNotIn("restrict_to_execute_memory", endpoint["params"])
        self.assertNotIn("disassemble_bytes", {
            ep["path"].lstrip("/") for ep in data.get("endpoints", [])
        })

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_catalog_tool_names_are_capi_safe_after_bridge_parsing(self):
        """The generated endpoint catalog should produce valid exposed MCP names."""
        from bridge_mcp_ghidra import _parse_schema

        data = json.loads(ENDPOINTS_JSON.read_text())
        raw_schema = {
            "tools": [
                {
                    "path": ep["path"],
                    "method": ep.get("method", "GET"),
                    "params": [],
                }
                for ep in data.get("endpoints", [])
            ]
        }
        invalid = [
            tool["name"] for tool in _parse_schema(raw_schema)
            if not re.fullmatch(r"^[a-zA-Z0-9_-]+$", tool["name"])
        ]
        self.assertEqual(invalid, [])


class TestBridgeIsDynamic(unittest.TestCase):
    """Verify the bridge uses dynamic registration, not hardcoded tools."""

    def test_bridge_has_few_static_tools(self):
        """Bridge static decorators should match its management allowlist.

        TraceRMI tools are discovered dynamically from Ghidra's schema.
        """
        import bridge_mcp_ghidra as bridge

        content = _bridge_source_text()
        mgmt_count = len(re.findall(r"@mcp\.tool\(\)", content))
        self.assertEqual(
            mgmt_count,
            len(bridge.MANAGEMENT_TOOL_NAMES),
            "management @mcp.tool() decorators should match MANAGEMENT_TOOL_NAMES",
        )
        self.assertEqual(bridge.STATIC_TOOL_NAMES, bridge.MANAGEMENT_TOOL_NAMES)

    def test_bridge_has_schema_registration(self):
        """Bridge should have register_tools_from_schema function."""
        content = _bridge_source_text()
        self.assertIn("register_tools_from_schema", content)
        self.assertIn("/mcp/schema", content)

    def test_bridge_modules_stay_focused(self):
        """No single bridge module should balloon — the split exists to keep
        each module readable. The cap is a soft signal: if it trips, look at
        the diff and confirm the added lines pull weight (real logic /
        regression coverage / docstrings tied to a fix). Split the module or
        bump deliberately rather than papering over bloat.

        History (pre-split, single file): 2100 (2026-05-12) -> 2250 (#170/#175
        socket-dir scan + TCP port-range discovery) -> 2300 (2026-06-14,
        search_tools) -> 2350 (2026-06-18, wildcard-bind DNS-rebinding fix) ->
        2500 (2026-06-26, tier 1+2 security/correctness: CORS header removal,
        IPv6 support, multi-UDS handling, emulation max_steps bounding, plugin
        lifecycle handoff) -> 2550 (2026-06-26, GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS
        strict mode, #339). Split into the python/bridge_mcp_ghidra package on
        2026-06-19 (carrying the accumulated history above forward into the new
        module layout); now enforced per-module.
        """
        per_module_cap = 800
        for module in _bridge_sources():
            lines = len(module.read_text().splitlines())
            self.assertLess(
                lines,
                per_module_cap,
                f"{module.name} is {lines} lines, expected <{per_module_cap}; "
                "split it or bump the cap deliberately.",
            )


class TestAnnotationScannerExists(unittest.TestCase):
    """Verify AnnotationScanner infrastructure."""

    def test_annotation_scanner_exists(self):
        path = CORE_SRC / "AnnotationScanner.java"
        self.assertTrue(path.exists())

    def test_mcptool_annotation_exists(self):
        path = CORE_SRC / "McpTool.java"
        self.assertTrue(path.exists())

    def test_param_annotation_exists(self):
        path = CORE_SRC / "Param.java"
        self.assertTrue(path.exists())

    def test_mcp_tool_group_annotation_exists(self):
        path = CORE_SRC / "McpToolGroup.java"
        self.assertTrue(path.exists())

    def test_scanner_has_schema_method(self):
        content = (CORE_SRC / "AnnotationScanner.java").read_text()
        self.assertIn("generateSchema", content)
        self.assertIn("ToolDescriptor", content)

    def test_all_services_have_tool_group(self):
        """All service files should have @McpToolGroup annotation."""
        expected = [
            "ListingService",
            "FunctionService",
            "CommentService",
            "SymbolLabelService",
            "XrefCallGraphService",
            "DataTypeService",
            "AnalysisService",
            "BinaryComparisonService",
            "MalwareSecurityService",
            "ProgramScriptService",
            "ExportService",
            "FlowDisassemblyService",
        ]
        for name in expected:
            path = CORE_SRC / f"{name}.java"
            if path.exists():
                content = path.read_text()
                self.assertIn(
                    "@McpToolGroup",
                    content,
                    f"{name}.java missing @McpToolGroup annotation",
                )


if __name__ == "__main__":
    unittest.main()
