"""Tests for the bridge CLI entry point (python/bridge_mcp_ghidra/cli.py).

cli.py was at 14% coverage: argument parsing, lazy-mode/default-group wiring,
and the DNS-rebinding-protection matrix were exercised only manually. These
tests drive main() with mcp.run and _auto_connect patched out, then assert
the settings that would have governed the real server.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from bridge_mcp_ghidra import cli, state  # noqa: E402
from bridge_mcp_ghidra.server import mcp  # noqa: E402


class _CliHarness(unittest.TestCase):
    """Run cli.main() with side effects stubbed; restore shared state after."""

    def setUp(self):
        self._saved_profile = state._tool_profile
        self._saved_security = getattr(mcp.settings, "transport_security", None)
        self._saved_host = mcp.settings.host
        self._saved_port = mcp.settings.port

    def tearDown(self):
        state._tool_profile = self._saved_profile
        mcp.settings.transport_security = self._saved_security
        mcp.settings.host = self._saved_host
        mcp.settings.port = self._saved_port

    def run_main(self, *argv, env=None):
        """Invoke cli.main() with the given argv; returns the mcp.run mock."""
        patches = [
            patch.object(sys, "argv", ["bridge-mcp-ghidra", *argv]),
            patch.object(cli, "_auto_connect"),
            patch.object(mcp, "run"),
        ]
        profile_env = {"GHIDRA_MCP_TOOL_PROFILE": ""}
        profile_env.update(env or {})
        patches.append(patch.dict(os.environ, profile_env))
        started = []
        for p in patches:
            started.append(p.start())
        try:
            cli.main()
            return started[2]  # the mcp.run mock
        finally:
            for p in patches:
                p.stop()


class TestCliArguments(_CliHarness):
    def test_defaults_stdio_and_core_profile(self):
        run = self.run_main()
        run.assert_called_once_with(transport="stdio")
        self.assertEqual(state._tool_profile.name, "core")
        self.assertTrue(state._tool_profile.lazy)
        self.assertEqual(
            state._tool_profile.groups,
            frozenset({"listing", "function", "program"}),
        )

    def test_named_minimal_profile(self):
        self.run_main("--tool-profile", "minimal")
        self.assertEqual(state._tool_profile.name, "minimal")
        self.assertEqual(state._tool_profile.groups, frozenset())

    def test_named_full_profile(self):
        self.run_main("--tool-profile", "full")
        self.assertEqual(state._tool_profile.name, "full")
        self.assertFalse(state._tool_profile.lazy)

    def test_lazy_flag_selects_core_profile(self):
        self.run_main("--lazy")
        self.assertEqual(state._tool_profile.name, "core")

    def test_no_lazy_selects_full_profile(self):
        self.run_main("--no-lazy")
        self.assertEqual(state._tool_profile.name, "full")

    def test_lazy_and_default_groups_select_custom_profile(self):
        self.run_main("--lazy", "--default-groups", " function , datatype ,")
        self.assertEqual(state._tool_profile.name, "custom")
        self.assertEqual(
            state._tool_profile.groups, frozenset({"function", "datatype"})
        )

    def test_default_groups_alone_selects_custom_profile(self):
        self.run_main("--default-groups", " function , datatype ,")
        self.assertEqual(state._tool_profile.name, "custom")
        self.assertEqual(
            state._tool_profile.groups, frozenset({"function", "datatype"})
        )

    def test_profile_selectors_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            self.run_main("--lazy", "--no-lazy")

    def test_full_and_default_groups_are_rejected(self):
        with self.assertRaises(SystemExit):
            self.run_main("--no-lazy", "--default-groups", "function")

    def test_named_profile_and_default_groups_are_rejected(self):
        with self.assertRaises(SystemExit):
            self.run_main(
                "--tool-profile", "core", "--default-groups", "function"
            )

    def test_empty_default_groups_are_rejected(self):
        with self.assertRaises(SystemExit):
            self.run_main("--default-groups", " , ")

    def test_environment_selects_profile(self):
        self.run_main(env={"GHIDRA_MCP_TOOL_PROFILE": "minimal"})
        self.assertEqual(state._tool_profile.name, "minimal")

    def test_invalid_environment_profile_is_rejected(self):
        with self.assertRaises(SystemExit):
            self.run_main(env={"GHIDRA_MCP_TOOL_PROFILE": "typo"})

    def test_explicit_cli_ignores_invalid_environment_profile(self):
        self.run_main(
            "--tool-profile",
            "full",
            env={"GHIDRA_MCP_TOOL_PROFILE": "typo"},
        )
        self.assertEqual(state._tool_profile.name, "full")

    def test_transport_and_port_applied(self):
        run = self.run_main("--transport", "streamable-http", "--mcp-port", "9905")
        run.assert_called_once_with(transport="streamable-http")
        self.assertEqual(mcp.settings.port, 9905)

    def test_invalid_transport_rejected(self):
        with self.assertRaises(SystemExit):
            self.run_main("--transport", "carrier-pigeon")


class TestCliRebindProtection(_CliHarness):
    def test_loopback_host_leaves_security_untouched(self):
        sentinel = object()
        mcp.settings.transport_security = sentinel
        self.run_main("--mcp-host", "127.0.0.1")
        self.assertIs(mcp.settings.transport_security, sentinel)

    def test_specific_remote_host_enables_protection(self):
        self.run_main("--mcp-host", "192.168.1.50")
        sec = mcp.settings.transport_security
        self.assertTrue(sec.enable_dns_rebinding_protection)
        self.assertIn("192.168.1.50:*", sec.allowed_hosts)
        self.assertIn("localhost:*", sec.allowed_hosts)

    def test_wildcard_bind_keeps_protection_on(self):
        """0.0.0.0 is the most exposed configuration — protection must stay
        ON with the machine's real hostnames allowed (the old behavior of
        disabling protection entirely was the vulnerability)."""
        self.run_main("--mcp-host", "0.0.0.0")
        sec = mcp.settings.transport_security
        self.assertTrue(sec.enable_dns_rebinding_protection)
        self.assertIn("localhost:*", sec.allowed_hosts)
        self.assertIn("127.0.0.1:*", sec.allowed_hosts)

    def test_wildcard_bind_extra_hosts_from_env(self):
        self.run_main(
            "--mcp-host", "0.0.0.0",
            env={"GHIDRA_MCP_ALLOWED_HOSTS": "re-lab.internal, bench01"},
        )
        sec = mcp.settings.transport_security
        self.assertIn("re-lab.internal:*", sec.allowed_hosts)
        self.assertIn("bench01:*", sec.allowed_hosts)

    def test_wildcard_bind_explicit_optout_disables_protection(self):
        self.run_main(
            "--mcp-host", "0.0.0.0",
            env={"GHIDRA_MCP_DISABLE_REBIND_PROTECTION": "1"},
        )
        sec = mcp.settings.transport_security
        self.assertFalse(sec.enable_dns_rebinding_protection)


class TestWildcardAllowedHosts(unittest.TestCase):
    def test_includes_loopbacks_with_port_wildcards(self):
        hosts = cli._wildcard_allowed_hosts()
        self.assertIn("localhost:*", hosts)
        self.assertIn("127.0.0.1:*", hosts)

    def test_ipv6_literals_get_bracketed_forms(self):
        hosts = cli._wildcard_allowed_hosts()
        self.assertIn("::1:*", hosts)
        self.assertIn("[::1]:*", hosts)


if __name__ == "__main__":
    unittest.main()
