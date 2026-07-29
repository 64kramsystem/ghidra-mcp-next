"""The bridge's five management tools."""

import json

from . import connection, discovery, registry, selection, state
from .server import Context, mcp


def _error(error: Exception) -> str:
    available = getattr(error, "available", None)
    result = {"error": str(error)}
    if available is not None:
        result["available"] = available
    return json.dumps(result)


@mcp.tool()
def list_instances() -> str:
    """List reachable local Ghidra instances."""
    instances = discovery.discover_instances()
    with state.lock:
        active = state.connection.socket
    for instance in instances:
        instance["connected"] = instance.get("socket") == active
    return json.dumps({"instances": instances}, indent=2)


@mcp.tool()
async def connect_instance(project: str, ctx: Context | None = None) -> str:
    """Connect by exact project name, PID, or socket and publish all tools."""
    try:
        selected = selection.select(discovery.discover_instances(), project)
        result = connection.connect(
            selected["socket"], selected.get("project") or project
        )
    except Exception as error:
        return _error(error)
    notification_error = await connection.notify(ctx)
    if notification_error:
        result["notification_error"] = notification_error
    return json.dumps(result)


@mcp.tool()
async def create_and_connect_project(
    parent_dir: str,
    name: str,
    instance: str | None = None,
    ctx: Context | None = None,
) -> str:
    """Create a GUI project once, then connect to it."""
    created = False
    try:
        selected = selection.select(discovery.discover_instances(), instance)
        response, _ = connection.create_project(
            selected["socket"], parent_dir, name
        )
        created = True
        result = connection.connect(selected["socket"], response["project"])
        result.update({"created": True, "path": response.get("path")})
    except Exception as error:
        if created:
            registry.clear()
        return json.dumps({"created": created, "error": str(error)})
    notification_error = await connection.notify(ctx)
    if notification_error:
        result["notification_error"] = notification_error
    return json.dumps(result)


@mcp.tool()
def get_connection_info() -> str:
    """Return current bridge state without network I/O."""
    return json.dumps(state.snapshot())


@mcp.tool()
async def refresh_connection(ctx: Context | None = None) -> str:
    """Refetch the active instance schema and replace its dynamic tools."""
    with state.lock:
        socket_path = state.connection.socket
        project = state.connection.project
    if socket_path is None:
        return json.dumps({"error": "No active Ghidra connection."})
    try:
        result = connection.connect(socket_path, project)
    except Exception as first_error:
        try:
            selected = selection.select(discovery.discover_instances(), project)
            result = connection.connect(selected["socket"], project)
        except Exception:
            return _error(first_error)
    notification_error = await connection.notify(ctx)
    if notification_error:
        result["notification_error"] = notification_error
    return json.dumps(result)


def auto_connect() -> None:
    instances = discovery.discover_instances()
    if len(instances) != 1:
        return
    selected = instances[0]
    try:
        connection.connect(selected["socket"], selected.get("project"))
    except Exception:
        pass
