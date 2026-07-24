"""Static MCP tools that are always available, plus startup auto-connect."""

import asyncio
import json
import os

from . import connection
from . import discovery
from . import dispatch
from . import registry
from . import state
from . import transport  # noqa: F401 - retained as the shared transport seam
from .config import DEFAULT_TCP_URL, STATIC_TOOL_NAMES, logger
from .selection import (
    InstanceSelectionError,
    _instance_summary,
    _select_instance,
    _selection_tool_error,
)
from .server import Context, mcp
from .validation import validate_server_url


@mcp.tool()
def get_connection_info() -> str:
    """Return the published connection generation and last attempt, without I/O."""
    return connection.get_connection_info_json()


@mcp.tool()
def list_instances() -> str:
    """
    List running Ghidra instances merged across UDS and TCP discovery.

    Returns JSON with each instance's project name, PID, open programs, and
    socket path or TCP URL. Also shows which instance is currently connected.
    """
    instances = discovery.discover_all_instances()
    with state._ghidra_lock:
        active = state._connection

    if not instances:
        return json.dumps(
            {"instances": [], "note": "No running Ghidra instances found."}
        )

    for inst in instances:
        socket = discovery._normalize_socket_path(inst.get("socket"))
        active_socket = discovery._normalize_socket_path(
            active.endpoint if active.transport == "uds" else None
        )
        url = discovery._normalize_tcp_url(inst.get("url"))
        active_url = discovery._normalize_tcp_url(
            active.endpoint if active.transport == "tcp" else None
        )
        inst["connected"] = (
            active.connected
            and active.transport == "uds"
            and bool(socket)
            and socket == active_socket
        ) or (
            active.connected
            and active.transport == "tcp"
            and bool(url)
            and url == active_url
        )

    return json.dumps({"instances": instances}, indent=2)


@mcp.tool()
async def create_and_connect_project(
    parent_dir: str,
    name: str,
    instance: str | None = None,
    ctx: Context | None = None,
) -> str:
    """Create and connect to a project through a running Ghidra GUI instance.

    With no instance selector, exactly one deduplicated GUI instance must be
    available. A selector matches exact PID text, socket path, TCP URL, or
    project name. On success, the new project's dynamic tools are immediately
    registered and clients are notified that the tool list changed.

    Args:
        parent_dir: Existing parent directory for the new project.
        name: Project name validated by Ghidra's ProjectLocator.
        instance: Optional exact instance selector.
    """
    instances = discovery.discover_all_instances()
    try:
        selected, mode, endpoint = _select_instance(instances, instance)
    except InstanceSelectionError as e:
        connection.record_local_failure(
            "create-and-connect",
            {"project": name, "instance": instance},
            "transport failure",
            str(e),
        )
        raise _selection_tool_error(e) from e

    attempt = {
        "operation": "create-and-connect",
        "candidate": {
            "project": name,
            "transport": mode,
            "endpoint": endpoint,
        },
        "started_at": connection.timestamp(),
        "ended_at": None,
        "success": False,
        "failure": None,
        "server_identity": None,
        "tools_changed": {
            "attempted": False,
            "sent": False,
            "error": None,
        },
    }
    with state._ghidra_lock:
        try:
            text, status = connection.create_project_request(
                mode, endpoint, parent_dir, name
            )
        except Exception as e:
            connection.record_local_failure(
                "create-and-connect",
                {
                    "project": name,
                    "transport": mode,
                    "endpoint": endpoint,
                },
                "transport failure",
                str(e),
            )
            raise RuntimeError(
                "create_project request failed with an uncertain outcome; "
                f"the bridge did not retry another transport: {e}"
            ) from e

        try:
            response = connection.parse_create_project_response(text, status)
        except Exception as exc:
            connection.record_local_failure(
                "create-and-connect",
                {
                    "project": name,
                    "transport": mode,
                    "endpoint": endpoint,
                },
                "project creation failure",
                str(exc),
            )
            raise
        project = str(response["project"])
        path = str(response["path"])
        had_dynamic = bool(state._connection.dynamic_names)
        staged = None
        profile = state._tool_profile
        try:
            staged = connection.fetch_staged_candidate(mode, endpoint, profile)
            attempt["server_identity"] = dict(staged.manifest.version)
            registry.publish_staged(
                staged,
                project=project,
                mode=mode,
                endpoint=endpoint,
                generation=state._connection.generation + 1,
                profile=profile,
            )
            attempt["success"] = True
            result = {
                "created": True,
                "path": path,
                "instance": _instance_summary(selected),
                **state.connection_summary(),
            }
            notify = True
        except Exception as exc:
            identity = (
                dict(staged.manifest.version) if staged is not None else None
            )
            if isinstance(exc, registry.handshake.HandshakeError):
                failure = registry.handshake.HandshakeError(
                    exc.category,
                    str(exc),
                    server_identity=exc.server_identity or identity,
                    failures=exc.failures,
                )
            else:
                failure = registry.handshake.HandshakeError(
                    "registration failure",
                    str(exc),
                    server_identity=identity,
                )
            attempt["server_identity"] = failure.server_identity
            attempt["failure"] = failure.as_dict()
            registry.publish_disconnected()
            result = {
                "created": True,
                "connected": False,
                "project": project,
                "path": path,
                "instance": _instance_summary(selected),
                "error": str(failure),
                "failure": failure.as_dict(),
                **state.connection_summary(),
            }
            notify = had_dynamic
        attempt["ended_at"] = connection.timestamp()
        state._last_attempt = attempt

    diagnostics = await connection.send_tools_changed(ctx, notify)
    with state._ghidra_lock:
        attempt["tools_changed"] = diagnostics
        if state._last_attempt is attempt:
            state._last_attempt = attempt
    result["tools_changed"] = diagnostics
    return json.dumps(result)


@mcp.tool()
async def connect_instance(project: str, ctx: Context | None = None) -> str:
    """Select a running instance and publish its exact capability manifest."""
    with state._ghidra_lock:
        expected = state._connection
        operation = "switch" if expected.connected else "connect"
    instances = discovery.discover_all_instances()
    try:
        selected, mode, endpoint = _select_instance(instances, project)
    except InstanceSelectionError as error:
        project_matches = [
            item for item in instances if item.get("project") == project
        ]
        if (
            instances
            and (
                not any(item.get("project") for item in instances)
                or len(project_matches) == 1
            )
        ):
            scanned = discovery._scan_tcp_for_project(project)
            if scanned and validate_server_url(scanned):
                selected = (
                    {**project_matches[0], "url": scanned}
                    if project_matches
                    else {"project": project, "url": scanned}
                )
                mode, endpoint = "tcp", scanned
            else:
                connection.record_local_failure(
                    operation,
                    {"project": project},
                    "transport failure",
                    str(error),
                )
                return json.dumps(
                    {
                        "error": str(error),
                        "available": error.available,
                        **state.connection_summary(),
                    }
                )
        else:
            available = [
                item.get("project", "unknown") for item in instances
            ]
            connection.record_local_failure(
                operation,
                {"project": project},
                "transport failure",
                f"No instance matching '{project}'.",
            )
            return json.dumps(
                {
                    "error": f"No instance matching '{project}'.",
                    "available": available,
                    **state.connection_summary(),
                }
            )
    result = await connection.handshake_candidate(
        operation,
        mode=mode,
        endpoint=endpoint,
        project=selected.get("project") or project,
        ctx=ctx,
        failure_policy="preserve" if operation == "switch" else "clear",
        expected_connection=expected,
    )
    result["instance"] = _instance_summary(selected)
    return json.dumps(result)


@mcp.tool()
async def refresh_connection(ctx: Context | None = None) -> str:
    """Re-fetch version and manifest from the active endpoint and republish."""
    with state._ghidra_lock:
        active = state._connection
        if not active.connected:
            return json.dumps(
                {
                    **state.connection_summary(),
                    "error": "No active connection to refresh.",
                }
            )
        mode = active.transport
        endpoint = active.endpoint
        project = active.project
    result = await connection.handshake_candidate(
        "refresh",
        mode=mode,
        endpoint=endpoint,
        project=project,
        ctx=ctx,
        failure_policy="clear",
        expected_connection=active,
    )
    return json.dumps(result)


async def _reconnect_active(
    ctx: Context | None, *, cause: str | None = None
) -> dict:
    """Reconnect the last selected project through the same handshake core."""
    with state._ghidra_lock:
        previous = state._connection
        project = previous.project or state._connected_project
        old_mode = previous.transport or state._transport_mode
        old_endpoint = (
            previous.endpoint
            or state._active_socket
            or state._active_tcp
        )
    mode = old_mode
    endpoint = old_endpoint
    if project:
        instances = discovery.discover_all_instances()
        exact = [
            item for item in instances if item.get("project") == project
        ]
        if not exact:
            exact = [
                item
                for item in instances
                if project.lower() in str(item.get("project", "")).lower()
            ]
        if len(exact) == 1:
            try:
                _, mode, endpoint = _select_instance(exact, project)
            except InstanceSelectionError:
                pass
    if mode not in {"uds", "tcp"} or not endpoint:
        mode = "tcp"
        endpoint = DEFAULT_TCP_URL
    result = await connection.handshake_candidate(
        "reconnect",
        mode=mode,
        endpoint=endpoint,
        project=project,
        ctx=ctx,
        failure_policy="clear",
        expected_connection=previous,
    )
    if cause:
        result["reconnect_cause"] = cause
    return result


@mcp.tool()
def list_tool_groups() -> str:
    """
    List all available tool groups with their tool counts and loaded status.

    Returns each category with: tool count, loaded status, and tool names.
    Use load_tool_group(group) to load a group's tools.
    """
    if not state._full_schema:
        return json.dumps(
            {"error": "No instance connected. Use connect_instance() first."}
        )
    groups = registry._get_group_info()
    return json.dumps({"groups": groups, "total_tools": len(state._full_schema)}, indent=2)


@mcp.tool()
async def load_tool_group(group: str, ctx: Context | None = None) -> str:
    """
    Load all tools in a category. Accepts a category name or "all" to load everything.

    Use list_tool_groups() to see available categories.

    Args:
        group: Category name (e.g. "function", "datatype") or "all"
    """
    with state._ghidra_lock:
        active = state._connection
        if not active.connected:
            return json.dumps(
                {"error": "No instance connected. Use connect_instance() first."}
            )
        available = {
            definition.get("category", "unknown")
            for definition in active.full_schema
        }
        requested = available if group == "all" else {group}
        if not requested.issubset(available):
            return json.dumps(
                {
                    "error": f"No tools found for group '{group}'",
                    "available_groups": sorted(available),
                }
            )
        previous = set(active.loaded_groups)
        resulting = previous | requested
        if resulting == previous:
            return json.dumps(
                {
                    "message": f"Group '{group}' is already loaded.",
                    "loaded_groups": sorted(previous),
                    "tools_changed": {
                        "attempted": False,
                        "sent": False,
                        "error": None,
                    },
                }
            )
        try:
            dynamic = registry.stage_active_groups(resulting)
            registry.publish_active_groups(dynamic, resulting)
        except registry.handshake.HandshakeError as exc:
            return json.dumps({"error": str(exc), "failure": exc.as_dict()})
        new_names = sorted(
            set(state._connection.dynamic_names)
            - set(active.dynamic_names)
        )
        result = {
            "loaded": group,
            "new_tools": len(new_names),
            "new_tool_names": new_names,
            "total_loaded": len(dynamic),
            "loaded_groups": sorted(resulting),
        }
    result["tools_changed"] = await connection.send_tools_changed(ctx, True)
    return json.dumps(result)


@mcp.tool()
async def unload_tool_group(group: str, ctx: Context | None = None) -> str:
    """
    Unload a category added after connect. Profile baseline groups are protected.

    Args:
        group: Category name to unload
    """
    with state._ghidra_lock:
        active = state._connection
        if not active.connected:
            return json.dumps(
                {"error": "No instance connected. Use connect_instance() first."}
            )
        if not active.lazy:
            return json.dumps(
                {
                    "error": (
                        "Cannot unload tool groups in eager mode; every "
                        "manifest tool must remain callable."
                    )
                }
            )
        if group in active.profile_groups:
            return json.dumps(
                {
                    "error": f"Cannot unload profile group '{group}'",
                    "tool_profile": active.tool_profile,
                    "profile_groups": list(active.profile_groups),
                }
            )
        previous = set(active.loaded_groups)
        if group not in previous:
            return json.dumps(
                {
                    "message": f"Group '{group}' is not loaded or has no tools.",
                    "tools_changed": {
                        "attempted": False,
                        "sent": False,
                        "error": None,
                    },
                }
            )
        resulting = previous - {group}
        try:
            dynamic = registry.stage_active_groups(resulting)
            registry.publish_active_groups(dynamic, resulting)
        except registry.handshake.HandshakeError as exc:
            return json.dumps({"error": str(exc), "failure": exc.as_dict()})
        removed = len(active.dynamic_names) - len(dynamic)
        result = {
            "unloaded": group,
            "removed_tools": removed,
            "total_loaded": len(dynamic),
            "loaded_groups": sorted(resulting),
        }
    result["tools_changed"] = await connection.send_tools_changed(ctx, True)
    return json.dumps(result)


@mcp.tool()
async def check_tools(tools: str) -> str:
    """
    Check if specific tools are callable right now. Returns status for each tool:
    "callable", "not_loaded" (exists but group not loaded), or "not_found" (doesn't exist).

    Args:
        tools: Comma-separated tool names, e.g. "rename_or_label,batch_set_comments,analyze_function_completeness"
    """
    tool_names = [t.strip() for t in tools.split(",") if t.strip()]
    if not tool_names:
        return json.dumps({"error": "Provide comma-separated tool names"})

    with state._ghidra_lock:
        bundle = state._connection
        all_known = {
            definition["name"]: definition.get("category", "unknown")
            for definition in bundle.full_schema
        }
        dynamic = set(bundle.dynamic_names)
        results: dict[str, dict] = {}
        for name in tool_names:
            if name in STATIC_TOOL_NAMES:
                results[name] = {"status": "callable", "type": "static"}
            elif name in dynamic:
                results[name] = {
                    "status": "callable",
                    "group": all_known.get(name, "unknown"),
                }
            elif name in all_known:
                group = all_known[name]
                results[name] = {
                    "status": "not_loaded",
                    "group": group,
                    "fix": f'load_tool_group("{group}")',
                }
            else:
                results[name] = {"status": "not_found"}
        manifest_sha256 = bundle.manifest_sha256
        generation = bundle.generation

    callable_count = sum(1 for r in results.values() if r["status"] == "callable")
    return json.dumps(
        {
            "results": results,
            "summary": f"{callable_count}/{len(tool_names)} callable",
            "manifest_sha256": manifest_sha256,
            "connection_generation": generation,
        }
    )


@mcp.tool()
async def search_tools(query: str, limit: int = 15) -> str:
    """
    Search the full Ghidra tool catalog by keyword — including tools whose group
    is not currently loaded. Use this to discover the right tool without paying
    the context cost of loading all groups (run the bridge with
    --tool-profile core or minimal and search on demand). Matches against tool
    name, description, and category.

    Each result reports whether the tool is callable right now; if not, it
    includes the exact load_tool_group(...) call needed to make it callable.

    Args:
        query: Space-separated keywords, e.g. "rename function" or "xref struct".
        limit: Maximum number of results to return (default 15).
    """
    terms = [t.lower() for t in query.split() if t.strip()]
    if not terms:
        return json.dumps({"error": "Provide one or more search keywords"})

    scored: list[tuple[int, dict]] = []
    for td in state._full_schema:
        name = td.get("name", "")
        category = td.get("category", "unknown")
        desc = td.get("description", "") or ""
        haystack = f"{name} {category} {desc}".lower()
        score = 0
        for term in terms:
            if term in name.lower():
                score += 3  # name hits rank highest
            elif term in haystack:
                score += 1
        if score == 0:
            continue
        loaded = name in state._dynamic_tool_names or name in STATIC_TOOL_NAMES
        result = {
            "name": name,
            "group": category,
            "status": "callable" if loaded else "not_loaded",
            "description": desc[:160],
        }
        if not loaded:
            result["fix"] = f'load_tool_group("{category}")'
        scored.append((score, result))

    scored.sort(key=lambda x: x[0], reverse=True)
    matches = [r for _, r in scored[: max(1, limit)]]
    return json.dumps(
        {
            "query": query,
            "match_count": len(scored),
            "returned": len(matches),
            "matches": matches,
        }
    )


@mcp.tool()
async def import_file_and_notify(
    file_path: str,
    project_folder: str = "/",
    language: str | None = None,
    compiler_spec: str | None = None,
    auto_analyze: bool = True,
    ctx: Context | None = None,
) -> str:
    """
    Import a binary file from disk into the current Ghidra project.

    Imports the file, opens it in the CodeBrowser, and optionally starts auto-analysis.
    When analysis is enabled, sends a log notification when analysis completes.

    For raw firmware binaries, specify language (e.g. "ARM:LE:32:Cortex") and
    optionally compiler_spec (e.g. "default"). Without language, Ghidra auto-detects
    the format (works for ELF, PE, Mach-O, etc.).

    Args:
        file_path: Absolute path to the binary file on disk
        project_folder: Destination folder in the Ghidra project (default: "/")
        language: Language ID for raw binaries (e.g. "ARM:LE:32:Cortex", "x86:LE:64:default")
        compiler_spec: Compiler spec ID (e.g. "default", "gcc"). Uses language default if omitted.
        auto_analyze: Start auto-analysis after import (default: true)
    """
    payload: dict = {
        "file_path": file_path,
        "project_folder": project_folder,
        "auto_analyze": auto_analyze,
    }
    if language:
        payload["language"] = language
    if compiler_spec:
        payload["compiler_spec"] = compiler_spec

    result = await dispatch.dispatch_dynamic(
        "import_file",
        "POST",
        "/import_file",
        query_params=None,
        body=payload,
        ctx=ctx,
    )

    # Parse result to check if analysis was started
    try:
        data = json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return result

    if data.get("data", {}).get("analyzing") and ctx is not None:
        program_name = data["data"].get("name", "unknown")
        # Capture the session before the tool call returns
        session = ctx.request_context.session

        async def _poll_analysis():
            """Poll analysis_status until analysis completes, then send log notification."""
            await asyncio.sleep(5)  # Initial delay
            for _ in range(360):  # Up to 30 minutes
                try:
                    status_text = dispatch.dispatch_get(
                        "/analysis_status", {"program": program_name}
                    )
                    status = json.loads(status_text)
                    status_data = status.get("data", status)
                    if not status_data.get("analyzing", True):
                        fn_count = status_data.get("function_count", "?")
                        await session.send_log_message(
                            level="info",
                            data=f"Analysis complete for {program_name}: {fn_count} functions found",
                        )
                        return
                except Exception as e:
                    logger.debug(f"Analysis poll error for {program_name}: {e}")
                await asyncio.sleep(5)

        asyncio.create_task(_poll_analysis())

    return result


def _auto_connect():
    """Try to auto-connect to a single running instance on startup."""
    instances = discovery.discover_all_instances()
    if len(instances) > 1:
        logger.info(
            "Multiple Ghidra instances found; use connect_instance() to choose."
        )
        connection.record_local_failure(
            "auto-connect",
            {"instances": len(instances)},
            "transport failure",
            "Multiple Ghidra instances found; explicit selection is required.",
        )
        return
    if len(instances) == 1:
        try:
            selected, mode, endpoint = _select_instance(instances)
        except InstanceSelectionError as exc:
            logger.warning("Auto-connect selection failed: %s", exc)
            connection.record_local_failure(
                "auto-connect",
                {"instances": 1},
                "transport failure",
                str(exc),
            )
            return
        result = asyncio.run(
            connection.handshake_candidate(
                "auto-connect",
                mode=mode,
                endpoint=endpoint,
                project=selected.get("project"),
                ctx=None,
                failure_policy="clear",
            )
        )
        if result.get("connected"):
            logger.info(
                "Auto-connected to %s via %s",
                selected.get("project") or endpoint,
                mode,
            )
        else:
            logger.warning("Auto-connect handshake failed: %s", result.get("error"))
        return

    tcp_url = os.getenv("GHIDRA_MCP_URL", DEFAULT_TCP_URL)
    if not validate_server_url(tcp_url):
        logger.warning("Refusing to auto-connect to non-local URL: %s", tcp_url)
        connection.record_local_failure(
            "auto-connect",
            {"transport": "tcp", "endpoint": tcp_url},
            "transport failure",
            "Refusing to auto-connect to an invalid TCP URL.",
        )
        return
    result = asyncio.run(
        connection.handshake_candidate(
            "auto-connect",
            mode="tcp",
            endpoint=tcp_url,
            project=None,
            ctx=None,
            failure_policy="clear",
        )
    )
    if not result.get("connected"):
        logger.info(
            "No Ghidra instances found. Tools will be registered on connect_instance()."
        )


# Python-level aliases ease source migration without retaining the old MCP names.
create_project = create_and_connect_project
import_file = import_file_and_notify

# All decorators above have now populated the complete static map.
registry.initialize_registry_adapter()
