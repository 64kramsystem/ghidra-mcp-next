"""Mutable connection and tool-registration state shared across the bridge.

All cross-module readers and writers reference these names through this module
object (e.g. ``state._transport_mode``) so a single source of truth is mutated.
Functions in other modules never use ``global`` on these names — they assign
``state.<name> = ...`` instead.
"""

import os
import inspect
import platform
import threading
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any

from .config import CORE_GROUPS, STATIC_TOOL_NAMES, logger

# --------------------------------------------------------------------------
# Connection state
# --------------------------------------------------------------------------

_active_socket: str | None = None  # UDS socket path
_active_tcp: str | None = None  # TCP base URL (e.g. "http://127.0.0.1:8089")
_transport_mode: str = "none"  # "uds", "tcp", or "none"
_connected_project: str | None = None  # Project name for auto-reconnect

# Serialization lock for Ghidra HTTP calls — prevents stdout corruption when
# multiple MCP tool calls arrive concurrently (see GitHub issue #91).
_ghidra_lock = threading.RLock()


@dataclass(frozen=True)
class ConnectionBundle:
    """One published connection generation and its complete manifest state."""

    connected: bool = False
    generation: int = 0
    project: str | None = None
    transport: str | None = None
    endpoint: str | None = None
    server: dict[str, Any] | None = None
    lazy: bool = False
    manifest_count: int = 0
    callable_dynamic_count: int = 0
    loaded_groups: tuple[str, ...] = ()
    manifest_sha256: str | None = None
    callable_schema_sha256: str | None = None
    full_schema: tuple[dict[str, Any], ...] = ()
    dynamic_names: tuple[str, ...] = ()
    identities: dict[str, tuple[str, str]] = field(default_factory=dict)


_connection = ConnectionBundle()
_last_attempt: dict[str, Any] | None = None


def bridge_identity() -> dict[str, Any]:
    """Return the installed bridge identity without contacting Ghidra."""
    try:
        package_version = metadata.version("ghidra-mcp-bridge")
    except metadata.PackageNotFoundError:
        package_version = "unknown"
    return {
        "bridge_package": "ghidra-mcp-bridge",
        "bridge_version": package_version,
        "bridge_source": os.path.abspath(inspect.getsourcefile(bridge_identity) or __file__),
        "python_version": platform.python_version(),
    }


def connection_summary() -> dict[str, Any]:
    """Snapshot the active published bundle. Caller holds _ghidra_lock."""
    bundle = _connection
    result = {
        **bridge_identity(),
        "connected": bundle.connected,
        "connection_generation": bundle.generation,
        "static_tool_count": len(STATIC_TOOL_NAMES),
        "static_tools": sorted(STATIC_TOOL_NAMES),
    }
    if bundle.connected:
        result.update(
            {
                "project": bundle.project,
                "transport": bundle.transport,
                "endpoint": bundle.endpoint,
                "tool_loading_mode": "lazy" if bundle.lazy else "eager",
                "lazy": bundle.lazy,
                "manifest_count": bundle.manifest_count,
                "callable_dynamic_count": bundle.callable_dynamic_count,
                "loaded_groups": list(bundle.loaded_groups),
                "manifest_sha256": bundle.manifest_sha256,
                "callable_schema_sha256": bundle.callable_schema_sha256,
                **(bundle.server or {}),
            }
        )
    return result


def publish_connection(bundle: ConnectionBundle) -> None:
    """Publish one bundle and update legacy in-module mirrors atomically."""
    global _connection
    global _active_socket, _active_tcp, _transport_mode, _connected_project
    global _full_schema, _lazy_mode
    _connection = bundle
    if bundle.connected:
        _transport_mode = bundle.transport or "none"
        _active_socket = bundle.endpoint if bundle.transport == "uds" else None
        _active_tcp = bundle.endpoint if bundle.transport == "tcp" else None
        _connected_project = bundle.project
        _full_schema = list(bundle.full_schema)
        _lazy_mode = bundle.lazy
        _dynamic_tool_names.clear()
        _dynamic_tool_names.extend(bundle.dynamic_names)
        _loaded_groups.clear()
        _loaded_groups.update(bundle.loaded_groups)
    else:
        _active_socket = None
        _active_tcp = None
        _transport_mode = "none"
        _connected_project = None
        _full_schema = []
        _dynamic_tool_names.clear()
        _loaded_groups.clear()


def disconnected_bundle() -> ConnectionBundle:
    """Disconnect while retaining the last successful generation number."""
    return ConnectionBundle(
        connected=False,
        generation=_connection.generation,
        lazy=_connection.lazy,
    )


# --------------------------------------------------------------------------
# Strict program routing
# --------------------------------------------------------------------------

# When GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1, the bridge refuses any
# program-scoped call that omits a program selector, so a forgotten one fails
# loudly instead of silently running against the server's mutable "current
# program" and hitting the wrong binary. Off by default. (Full rationale in
# commit 6f85c5e / README.)
_require_selectors: bool = False


def _init_require_selectors() -> None:
    """Read GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS once, at import. Set it to 1 to enable."""
    global _require_selectors
    _require_selectors = (os.getenv("GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS") or "").strip() == "1"
    if _require_selectors:
        logger.info(
            "Strict program routing enabled (GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1); "
            "program-scoped calls missing a program selector will be refused"
        )


_init_require_selectors()

# --------------------------------------------------------------------------
# Tool-registration state
# --------------------------------------------------------------------------

# NOTE: _dynamic_tool_names and _loaded_groups are only ever mutated in place
# (clear/append/add/discard) so external references stay valid. _full_schema,
# _lazy_mode, and _default_groups ARE reassigned — always read them through
# this module.
_dynamic_tool_names: list[str] = []
_full_schema: list[dict] = []  # Complete parsed schema
_loaded_groups: set[str] = set()

# CLI-configurable: --lazy keeps only default groups, otherwise load all
_lazy_mode = False  # default: eager (load all groups on connect)
_default_groups: set[str] = set(CORE_GROUPS)
