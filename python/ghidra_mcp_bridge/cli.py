"""Command-line entry point for the GhidraMCP-next bridge."""

import argparse
import os
import socket

from mcp.server.transport_security import TransportSecuritySettings

from . import state
from .config import DEFAULT_TOOL_PROFILE, TOOL_PROFILES, logger
from .server import mcp
from .static_tools import _auto_connect


def _parse_default_groups(value: str) -> frozenset[str]:
    groups = frozenset(group.strip() for group in value.split(",") if group.strip())
    if not groups:
        raise argparse.ArgumentTypeError(
            "--default-groups must name at least one group; use "
            "--tool-profile minimal for no initially loaded dynamic groups"
        )
    return groups


def _resolve_requested_profile(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> state.ResolvedToolProfile:
    """Resolve CLI and environment selectors with explicit CLI precedence."""
    if args.default_groups is not None:
        if args.tool_profile is not None:
            parser.error("--default-groups cannot be combined with --tool-profile")
        if args.legacy_profile == "full":
            parser.error("--default-groups cannot be combined with --no-lazy")
        return state.resolve_tool_profile("custom", set(args.default_groups))

    selected = args.tool_profile or args.legacy_profile
    if selected is None:
        selected = (
            os.getenv("GHIDRA_MCP_TOOL_PROFILE") or DEFAULT_TOOL_PROFILE
        ).strip()
    try:
        return state.resolve_tool_profile(selected)
    except ValueError as exc:
        parser.error(str(exc))


def _wildcard_allowed_hosts() -> list[str]:
    """Build the allowed-Host list for a 0.0.0.0/:: bind.

    Returns the loopback names plus this machine's hostname, FQDN, and
    every local interface IP, each with a ``:*`` port suffix. This lets
    legitimate remote clients (which use the real hostname/IP in the
    Host header) through while DNS-rebinding attacks (which use an
    attacker-controlled hostname) are rejected.
    """
    hosts: set[str] = {"localhost", "127.0.0.1", "::1"}
    try:
        hn = socket.gethostname()
        if hn:
            hosts.add(hn)
            try:
                hosts.add(socket.getfqdn(hn))
            except OSError:
                pass
            try:
                # All addresses the hostname resolves to (covers multi-NIC).
                for info in socket.getaddrinfo(hn, None):
                    addr = info[4][0]
                    if addr:
                        hosts.add(addr)
            except OSError:
                pass
    except OSError:
        pass
    out: list[str] = []
    for h in sorted(hosts):
        out.append(f"{h}:*")
        # RFC 3986: IPv6 literals are bracketed in Host headers
        # (e.g. "[::1]:8089"); add the bracketed form so they match too.
        if ":" in h and not h.startswith("["):
            out.append(f"[{h}]:*")
    return out


def main():
    parser = argparse.ArgumentParser(
        description="GhidraMCP-next Bridge -- MCP<->HTTP multiplexer"
    )
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host for HTTP transport (streamable-http or sse)",
    )
    parser.add_argument(
        "--mcp-port", type=int, help="Port for HTTP transport (streamable-http or sse)"
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse", "streamable-http"],
        help="MCP transport: stdio (default, recommended for AI tools), "
        "streamable-http (recommended for web/HTTP clients), "
        "sse (deprecated, use streamable-http instead)",
    )
    profile_selectors = parser.add_mutually_exclusive_group()
    profile_selectors.add_argument(
        "--tool-profile",
        choices=sorted(TOOL_PROFILES),
        default=None,
        help="Initial tool visibility: minimal (management only), core "
        "(default), or full (all tools)",
    )
    profile_selectors.add_argument(
        "--lazy",
        dest="legacy_profile",
        action="store_const",
        const="core",
        help="Compatibility alias for --tool-profile core",
    )
    profile_selectors.add_argument(
        "--no-lazy",
        dest="legacy_profile",
        action="store_const",
        const="full",
        help="Compatibility alias for --tool-profile full",
    )
    parser.add_argument(
        "--default-groups",
        type=_parse_default_groups,
        default=None,
        help="Comma-separated custom initial groups; may be combined with "
        "--lazy for compatibility",
    )
    args = parser.parse_args()

    profile = _resolve_requested_profile(parser, args)
    state.configure_tool_profile(
        profile.name,
        set(profile.groups) if profile.name == "custom" else None,
    )

    if not profile.lazy:
        logger.info(
            "Loading all tool groups on startup (clients that don't support tools/list_changed need this)"
        )
    else:
        logger.info(
            "Using %s tool profile with initial groups: %s",
            profile.name,
            ", ".join(sorted(profile.groups or ())) or "(management tools only)",
        )
    _auto_connect()

    mcp.settings.log_level = "INFO"
    mcp.settings.host = args.mcp_host
    if args.mcp_port:
        mcp.settings.port = args.mcp_port

    _host = args.mcp_host
    if _host not in {"127.0.0.1", "localhost", "::1"}:
        if _host in {"0.0.0.0", "::"}:
            # Wildcard bind is the MOST exposed configuration — keep
            # DNS-rebinding protection ON and allow only the machine's
            # actual hostnames/IPs. Previously this branch disabled
            # protection entirely, which is inverted: a malicious page
            # could DNS-rebind to this host and drive every Ghidra tool
            # from the victim's browser.
            #
            # Legitimate remote clients use the real hostname/IP, so
            # they pass the Host-header check. Operators with custom
            # DNS can extend the list via GHIDRA_MCP_ALLOWED_HOSTS
            # (comma-separated), or explicitly opt back into the old
            # unprotected behavior with GHIDRA_MCP_DISABLE_REBIND_PROTECTION=1.
            if os.environ.get("GHIDRA_MCP_DISABLE_REBIND_PROTECTION") == "1":
                logger.warning(
                    "DNS-rebinding protection DISABLED for wildcard bind via "
                    "GHIDRA_MCP_DISABLE_REBIND_PROTECTION=1 — any page in the "
                    "user's browser can drive this server."
                )
                mcp.settings.transport_security = TransportSecuritySettings(
                    enable_dns_rebinding_protection=False
                )
            else:
                allowed = _wildcard_allowed_hosts()
                extra = os.environ.get("GHIDRA_MCP_ALLOWED_HOSTS", "")
                for h in (x.strip() for x in extra.split(",") if x.strip()):
                    allowed.append(f"{h}:*")
                logger.info(
                    "Wildcard bind %s with DNS-rebinding protection ON; "
                    "allowed Host headers: %s. Extend with "
                    "GHIDRA_MCP_ALLOWED_HOSTS=host1,host2 if a remote client "
                    "is rejected.",
                    _host, allowed,
                )
                mcp.settings.transport_security = TransportSecuritySettings(
                    enable_dns_rebinding_protection=True,
                    allowed_hosts=allowed,
                    allowed_origins=[f"http://{h}" for h in allowed],
                )
        else:
            mcp.settings.transport_security = TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=[f"{_host}:*", "localhost:*", "127.0.0.1:*"],
                allowed_origins=[f"http://{_host}:*", "http://localhost:*", "http://127.0.0.1:*"],
            )
    logger.info(f"Starting MCP bridge ({args.transport})")
    if args.transport in ("sse", "streamable-http"):
        host = args.mcp_host
        port = args.mcp_port if args.mcp_port else mcp.settings.port
        path = "/sse" if args.transport == "sse" else "/mcp"
        logger.info(f"MCP endpoint: http://{host}:{port}{path}")
    mcp.run(transport=args.transport)
