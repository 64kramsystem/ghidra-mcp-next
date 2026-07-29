"""Thin local MCP-to-Ghidra bridge."""

from importlib.metadata import PackageNotFoundError, version

from .server import Context, mcp
from .static_tools import (
    connect_instance,
    create_and_connect_project,
    get_connection_info,
    list_instances,
    refresh_connection,
)
from .cli import main

try:
    __version__ = version("ghidra-mcp-bridge")
except PackageNotFoundError:
    __version__ = "unknown"

__all__ = [
    "Context",
    "connect_instance",
    "create_and_connect_project",
    "get_connection_info",
    "list_instances",
    "main",
    "mcp",
    "refresh_connection",
]
