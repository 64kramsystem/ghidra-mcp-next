"""Fetch and publish one Ghidra instance's tool schema."""

import json

from . import discovery, registry, schema, state, transport


def connect(socket_path: str, project: str | None) -> dict:
    try:
        version_text, version_status = transport.request(
            socket_path, "GET", "/get_version", timeout=10
        )
        schema_text, schema_status = transport.request(
            socket_path, "GET", "/mcp/schema", timeout=10
        )
        if version_status != 200:
            raise RuntimeError(f"/get_version returned HTTP {version_status}.")
        if schema_status != 200:
            raise RuntimeError(f"/mcp/schema returned HTTP {schema_status}.")
        server = discovery.unwrap(version_text)
        raw_schema = discovery.unwrap(schema_text)
        if not isinstance(server, dict):
            raise ValueError("/get_version did not return an object.")
        definitions = schema.parse(raw_schema)
        tools = registry.build_tools(definitions)
        registry.publish(tools)
    except Exception as error:
        with state.lock:
            state.connection.last_error = str(error)
        raise

    with state.lock:
        state.connection = state.Connection(
            socket=socket_path,
            project=project,
            server=server,
            dynamic_names=set(tools),
        )
        return state.snapshot()


def create_project(
    socket_path: str, parent_dir: str, name: str
) -> tuple[dict, int]:
    text, status = transport.request(
        socket_path,
        "POST",
        "/create_project",
        body={"parentDir": parent_dir, "name": name},
    )
    try:
        result = discovery.unwrap(text)
    except json.JSONDecodeError as error:
        raise RuntimeError("create_project returned invalid JSON.") from error
    if status != 200 or not isinstance(result, dict) or result.get("success") is not True:
        raise RuntimeError(
            json.dumps({"http_status": status, "response": result})
        )
    return result, status


async def notify(ctx) -> str | None:
    if ctx is None or ctx._request_context is None:
        return None
    try:
        await ctx.request_context.session.send_tool_list_changed()
    except Exception as error:
        return str(error)
    return None
