"""
Project Consistency Tests.

Validates build identity, bridge configuration, and architectural
invariants across the project. All tests run without a server.
"""

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
POM_XML = PROJECT_ROOT / "pom.xml"
PYPROJECT_TOML = PROJECT_ROOT / "pyproject.toml"
# The bridge is now a package split across modules under python/.
BRIDGE_PKG = PROJECT_ROOT / "python" / "bridge_mcp_ghidra"
ENDPOINTS_JSON = PROJECT_ROOT / "tests" / "endpoints.json"


def bridge_source_text() -> str:
    """Concatenated text of every bridge module."""
    return "\n".join(p.read_text() for p in sorted(BRIDGE_PKG.glob("*.py")))


class TestBuildIdentity(unittest.TestCase):
    """Verify the extension and bridge use independent automatic identities."""

    def test_maven_release_artifact_uses_build_timestamp(self):
        pom = POM_XML.read_text(encoding="utf-8")
        self.assertIn("<version>0.0.0</version>", pom)
        self.assertIn(
            "<finalName>${project.artifactId}-${release.timestamp}</finalName>",
            pom,
        )

    def test_bridge_version_is_dynamic_and_git_scoped(self):
        pyproject = PYPROJECT_TOML.read_text(encoding="utf-8")
        self.assertIn('dynamic = ["version"]', pyproject)
        self.assertNotRegex(pyproject, r'(?m)^version = "\d+\.\d+\.\d+"$')
        self.assertIn('path = "tools/bridge_version.py"', pyproject)
        self.assertIn('"/python/bridge_mcp_ghidra"', pyproject)
        self.assertNotIn('    "CHANGELOG.md",', pyproject)

        version_source = (PROJECT_ROOT / "tools" / "bridge_version.py").read_text(encoding="utf-8")
        for bridge_input in (
            "python/bridge_mcp_ghidra",
            "pyproject.toml",
            "tools/bridge_version.py",
            "README.md",
            "LICENSE",
            "NOTICE",
            ".gitignore",
        ):
            self.assertIn(bridge_input, version_source)

    def test_plugin_metadata_uses_build_timestamp(self):
        version_properties = (
            PROJECT_ROOT / "src" / "main" / "resources" / "com" / "xebyte" / "version.properties"
        ).read_text(encoding="utf-8")
        manifest = (PROJECT_ROOT / "src" / "main" / "resources" / "META-INF" / "MANIFEST.MF").read_text(
            encoding="utf-8"
        )
        self.assertIn("app.version=${release.timestamp}", version_properties)
        self.assertIn("Plugin-Version: ${release.timestamp}", manifest)

    def test_user_visible_tool_counts_use_stable_lower_bound(self):
        """User-visible descriptions should not hardcode the exact catalog size."""
        total = json.loads(ENDPOINTS_JSON.read_text())["total_endpoints"]
        self.assertGreater(total, 250)
        checks = {
            "README.md": PROJECT_ROOT / "README.md",
            "CLAUDE.md": PROJECT_ROOT / "CLAUDE.md",
            "AGENTS.md": PROJECT_ROOT / "AGENTS.md",
            "extension.properties": PROJECT_ROOT / "src" / "main" / "resources" / "extension.properties",
            "MANIFEST.MF": PROJECT_ROOT / "src" / "main" / "resources" / "META-INF" / "MANIFEST.MF",
        }
        exact_count = re.compile(r"(?<!more than )\b\d+\s+MCP tools?", re.IGNORECASE)
        exact_claims = []
        for name, path in checks.items():
            if exact_count.search(path.read_text(encoding="utf-8")):
                exact_claims.append(name)
        self.assertEqual(exact_claims, [])

        for path in (
            checks["CLAUDE.md"],
            checks["extension.properties"],
            checks["MANIFEST.MF"],
        ):
            self.assertIn("more than 250", path.read_text(encoding="utf-8"))

    def test_product_branding_is_consistent(self):
        expected = {
            PROJECT_ROOT / "README.md": "# GhidraMCP-next",
            PROJECT_ROOT / "pyproject.toml": 'description = "GhidraMCP-next bridge',
            PROJECT_ROOT / "src" / "main" / "resources" / "extension.properties": "name=GhidraMCP-next",
            PROJECT_ROOT / "src" / "main" / "resources" / "META-INF" / "MANIFEST.MF": "Plugin-Name: GhidraMCP-next",
            PROJECT_ROOT
            / "src"
            / "main"
            / "resources"
            / "com"
            / "xebyte"
            / "version.properties": "app.name=GhidraMCP-next",
        }
        for path, branding in expected.items():
            self.assertIn(branding, path.read_text(encoding="utf-8"))


class TestBridgeConfiguration(unittest.TestCase):
    """Verify bridge configuration and imports."""

    def test_bridge_importable(self):
        """Bridge should be importable without errors."""
        try:
            import bridge_mcp_ghidra
        except ImportError as e:
            self.fail(f"Bridge import failed: {e}")

    def test_bridge_has_uds_support(self):
        """Bridge should support Unix domain sockets."""
        content = bridge_source_text()
        self.assertIn("UnixHTTPConnection", content)
        self.assertIn("AF_UNIX", content)

    def test_bridge_has_tcp_fallback(self):
        """Bridge should support TCP as fallback."""
        content = bridge_source_text()
        self.assertIn("tcp_request", content)
        self.assertIn("DEFAULT_TCP_URL", content)

    def test_bridge_has_auto_connect(self):
        """Bridge should auto-connect on startup."""
        content = bridge_source_text()
        self.assertIn("_auto_connect", content)

    def test_bridge_dependencies_minimal(self):
        """Bridge code should use stdlib http.client, not the requests library."""
        content = bridge_source_text()
        # The thin bridge uses stdlib http.client, not requests
        self.assertNotIn("import requests", content)


class TestJavaArchitecture(unittest.TestCase):
    """Verify Java architectural invariants."""

    def test_annotation_scanner_exists(self):
        self.assertTrue((CORE_SRC / "AnnotationScanner.java").exists())

    def test_endpoint_registry_exists(self):
        """EndpointRegistry.java coexists with AnnotationScanner (upstream keeps both)."""
        self.assertTrue((CORE_SRC / "EndpointRegistry.java").exists())

    def test_endpoint_def_exists(self):
        """EndpointDef.java is used by AnnotationScanner for endpoint handling."""
        self.assertTrue((CORE_SRC / "EndpointDef.java").exists())

    def test_uds_server_exists(self):
        self.assertTrue((CORE_SRC / "UdsHttpServer.java").exists())

    def test_server_manager_exists(self):
        self.assertTrue((CORE_SRC / "ServerManager.java").exists())

    def test_http_exchange_interface_exists(self):
        self.assertTrue((CORE_SRC / "HttpExchange.java").exists())

    def test_services_use_response_type(self):
        """Service methods should return Response type."""
        for svc_file in CORE_SRC.glob("*Service.java"):
            content = svc_file.read_text()
            if "@McpTool" in content:
                # At least some methods should return Response
                self.assertIn("Response", content, f"{svc_file.name} has @McpTool but no Response return type")

    def test_all_services_have_annotations(self):
        """All service files should have at least one @McpTool annotation."""
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
        ]
        for name in expected:
            path = CORE_SRC / f"{name}.java"
            if path.exists():
                content = path.read_text()
                self.assertIn("@McpTool", content, f"{name}.java missing @McpTool annotations")

    def test_manual_gui_headless_shared_endpoints_do_not_drift(self):
        """Manual createContext registrations need explicit GUI/headless parity."""
        gui_file = JAVA_SRC / "GhidraMCPPlugin.java"
        headless_file = JAVA_SRC / "headless" / "GhidraMCPHeadlessServer.java"
        gui = set(re.findall(r'server\.createContext\("([^"]+)"', gui_file.read_text()))
        headless = set(re.findall(r'safeContext\("([^"]+)"', headless_file.read_text()))
        annotated = set()
        for java_file in list(CORE_SRC.glob("*Service.java")) + list((JAVA_SRC / "headless").glob("*Service.java")):
            annotated.update(re.findall(r'@McpTool\(\s*(?:path\s*=\s*)?"([^"]+)"', java_file.read_text()))

        gui_only_expected = {
            "/batch_apply_documentation",
            "/mcp/health",
            "/mcp/instance_info",
            "/project/info",
            "/tool/launch_codebrowser",
            "/tool/running_tools",
        }
        headless_only_expected = {
            "/delete_project",
            "/health",
            "/list_projects",
            "/move_file",
            "/move_folder",
        }

        self.assertEqual(gui - headless - annotated, gui_only_expected)
        self.assertEqual(headless - gui - annotated, headless_only_expected)

    def test_manual_repository_server_endpoints_are_absent(self):
        """Removed repository-server routes must not survive as catalog-only entries."""
        paths = {entry["path"] for entry in json.loads(ENDPOINTS_JSON.read_text())["endpoints"]}
        self.assertFalse(any(path.startswith("/server/") for path in paths))


class TestProjectStructure(unittest.TestCase):
    """Verify key project files exist."""

    def test_pom_xml_exists(self):
        self.assertTrue(POM_XML.exists())

    def test_bridge_exists(self):
        self.assertTrue((BRIDGE_PKG / "__init__.py").exists())

    def test_plugin_exists(self):
        self.assertTrue((JAVA_SRC / "GhidraMCPPlugin.java").exists())

    def test_headless_server_exists(self):
        self.assertTrue((JAVA_SRC / "headless" / "GhidraMCPHeadlessServer.java").exists())


if __name__ == "__main__":
    unittest.main()
