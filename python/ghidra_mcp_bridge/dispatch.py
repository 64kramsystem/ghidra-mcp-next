"""One-shot dispatch to the selected Ghidra socket."""

import json

from mcp.types import CallToolResult, TextContent

from . import state, transport
from .config import READ_TIMEOUT, WRITE_TIMEOUT


def dispatch(
    method: str,
    endpoint: str,
    *,
    query: dict | None = None,
    body: dict | None = None,
) -> str:
    with state.lock:
        socket_path = state.connection.socket
        if socket_path is None:
            return json.dumps(
                {"error": "No Ghidra instance connected. Call connect_instance."}
            )
        try:
            text, status = transport.request(
                socket_path,
                method,
                endpoint,
                query=query,
                body=body,
                timeout=WRITE_TIMEOUT if method == "POST" else READ_TIMEOUT,
            )
        except Exception as error:
            state.connection.last_error = str(error)
            return json.dumps(
                {
                    "error": str(error),
                    "hint": "Call refresh_connection after Ghidra is available.",
                }
            )
    if status == 200:
        return text
    return json.dumps({"error": f"HTTP {status}: {text.strip()}"})


def tool_result(text: str) -> CallToolResult:
    """Mark top-level Ghidra failures as MCP errors, preserving their payload."""
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return CallToolResult(content=[TextContent(type="text", text=text)])
    if isinstance(payload, dict) and (
        isinstance(payload.get("error"), str) and payload["error"].strip()
        or payload.get("success") is False
        or payload.get("status") == "rejected"
    ):
        return error_result(text)
    return CallToolResult(content=[TextContent(type="text", text=text)])


def error_result(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)
