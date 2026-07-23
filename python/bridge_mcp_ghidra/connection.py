"""Candidate handshake and atomic connection publication."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from . import discovery, registry, state, transport
from .config import STATIC_TOOL_NAMES
from .server import Context


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_project_request(
    mode: str, endpoint: str, parent_dir: str, name: str
) -> tuple[str, int]:
    payload = {"parentDir": parent_dir, "name": name}
    request = (
        transport.uds_request if mode == "uds" else transport.tcp_request
    )
    return request(
        endpoint,
        "POST",
        "/create_project",
        json_data=payload,
        timeout=30,
    )


def parse_create_project_response(text: str, status: int) -> dict:
    try:
        response = discovery._unwrap_response_data(text)
    except Exception as exc:
        raise RuntimeError(
            "create_project returned invalid JSON after the mutating "
            f"request: {exc}"
        ) from exc
    if status != 200 or not isinstance(response, dict):
        raise RuntimeError(
            json.dumps(
                {
                    "error": "GUI project creation failed",
                    "http_status": status,
                    "response": response,
                }
            )
        )
    if response.get("success") is not True:
        raise RuntimeError(
            json.dumps(
                {
                    "error": "GUI project creation failed",
                    "response": response,
                }
            )
        )
    if (
        response.get("active") is not True
        or not response.get("project")
        or not response.get("path")
    ):
        raise RuntimeError(
            json.dumps(
                {
                    "error": "GUI returned an incomplete create_project success",
                    "response": response,
                }
            )
        )
    return response


def fetch_staged_candidate(
    mode: str, endpoint: str
) -> registry.StagedRegistry:
    """Fetch both authoritative documents from an explicit candidate."""
    try:
        version_text, version_status = transport.candidate_request(
            mode, endpoint, "GET", "/get_version", timeout=10
        )
    except Exception as exc:
        raise registry.handshake.HandshakeError(
            "transport failure",
            f"GET /get_version failed via {mode} {endpoint}: {exc}",
        ) from exc
    if version_status != 200:
        raise registry.handshake.HandshakeError(
            "version-response failure",
            f"GET /get_version returned HTTP {version_status}: "
            f"{version_text.strip()}",
        )
    version = registry.handshake.parse_json_strict(version_text, "version")
    identity = version if isinstance(version, dict) else None
    try:
        schema_text, schema_status = transport.candidate_request(
            mode, endpoint, "GET", "/mcp/schema", timeout=10
        )
    except Exception as exc:
        raise registry.handshake.HandshakeError(
            "transport failure",
            f"GET /mcp/schema failed via {mode} {endpoint}: {exc}",
            server_identity=identity,
        ) from exc
    if schema_status != 200:
        raise registry.handshake.HandshakeError(
            "malformed schema",
            f"GET /mcp/schema returned HTTP {schema_status}: "
            f"{schema_text.strip()}",
            server_identity=identity,
        )
    try:
        schema = registry.handshake.parse_json_strict(schema_text, "schema")
        manifest = registry.handshake.validate_handshake(
            version, schema, STATIC_TOOL_NAMES
        )
    except registry.handshake.HandshakeError as exc:
        if exc.server_identity is not None:
            raise
        raise registry.handshake.HandshakeError(
            exc.category,
            str(exc),
            server_identity=identity,
            failures=exc.failures,
        ) from exc
    groups = state._default_groups if state._lazy_mode else None
    return registry.build_staged_registry(manifest, groups)


async def send_tools_changed(
    ctx: Context | None, attempted: bool
) -> dict:
    result = {"attempted": attempted, "sent": False, "error": None}
    if not attempted:
        return result
    if ctx is None or ctx._request_context is None:
        result["attempted"] = False
        return result
    try:
        await ctx.request_context.session.send_tool_list_changed()
        result["sent"] = True
    except Exception as exc:
        result["error"] = str(exc)
    return result


async def handshake_candidate(
    operation: str,
    *,
    mode: str,
    endpoint: str,
    project: str | None,
    ctx: Context | None,
    failure_policy: str,
) -> dict:
    """Build, validate, and atomically publish one candidate connection."""
    started = timestamp()
    with state._ghidra_lock:
        previous = state._connection
        attempt: dict = {
            "operation": operation,
            "candidate": {
                "project": project,
                "transport": mode,
                "endpoint": endpoint,
            },
            "started_at": started,
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
        notify = False
        try:
            staged = fetch_staged_candidate(mode, endpoint)
            attempt["server_identity"] = dict(staged.manifest.version)
            registry.publish_staged(
                staged,
                project=project,
                mode=mode,
                endpoint=endpoint,
                generation=previous.generation + 1,
                lazy=state._lazy_mode,
            )
            attempt["success"] = True
            notify = operation != "auto-connect"
            result = state.connection_summary()
        except registry.handshake.HandshakeError as exc:
            attempt["server_identity"] = exc.server_identity
            attempt["failure"] = exc.as_dict()
            if failure_policy == "clear":
                had_dynamic = bool(previous.dynamic_names)
                registry.publish_disconnected()
                notify = operation in {"refresh", "reconnect"} or (
                    operation == "create-and-connect" and had_dynamic
                )
            elif failure_policy != "preserve":
                raise ValueError(
                    f"unknown handshake failure policy {failure_policy!r}"
                )
            result = {
                **state.connection_summary(),
                "error": str(exc),
                "failure": exc.as_dict(),
            }
        except Exception as exc:
            failure = registry.handshake.HandshakeError(
                "registration failure", str(exc)
            )
            attempt["failure"] = failure.as_dict()
            if failure_policy == "clear":
                had_dynamic = bool(previous.dynamic_names)
                registry.publish_disconnected()
                notify = operation in {"refresh", "reconnect"} or (
                    operation == "create-and-connect" and had_dynamic
                )
            result = {
                **state.connection_summary(),
                "error": str(exc),
                "failure": failure.as_dict(),
            }
        attempt["ended_at"] = timestamp()
        state._last_attempt = attempt

    diagnostics = await send_tools_changed(ctx, notify)
    with state._ghidra_lock:
        attempt["tools_changed"] = diagnostics
        if state._last_attempt is attempt:
            state._last_attempt = attempt
    result["tools_changed"] = diagnostics
    return result


def get_connection_info_json() -> str:
    """Return current state and last attempt without contacting Ghidra."""
    with state._ghidra_lock:
        result = state.connection_summary()
        result["last_attempt"] = (
            dict(state._last_attempt)
            if state._last_attempt is not None
            else None
        )
    return json.dumps(result)


def record_local_failure(
    operation: str,
    candidate: dict,
    category: str,
    message: str,
) -> None:
    """Record selection/preflight failures that never contacted a server."""
    now = timestamp()
    with state._ghidra_lock:
        state._last_attempt = {
            "operation": operation,
            "candidate": candidate,
            "started_at": now,
            "ended_at": now,
            "success": False,
            "failure": {"category": category, "message": message},
            "server_identity": None,
            "tools_changed": {
                "attempted": False,
                "sent": False,
                "error": None,
            },
        }
