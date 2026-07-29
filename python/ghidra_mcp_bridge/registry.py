"""Generate and publish MCP tools from Ghidra's schema."""

import inspect
import json
from copy import deepcopy

from . import dispatch, state
from .schema import TYPE_MAP
from .server import mcp


def _default(value, kind: str | None):
    if not isinstance(value, str):
        return value
    if kind == "boolean":
        if value.lower() in {"true", "false"}:
            return value.lower() == "true"
        raise ValueError(f"Invalid boolean default {value!r}.")
    if kind == "integer":
        return int(value)
    if kind == "number":
        return float(value)
    if kind in {"array", "object"}:
        return json.loads(value)
    return value


def build_handler(definition: dict):
    properties = definition["input_schema"]["properties"]
    required = set(definition["input_schema"].get("required", []))
    parameters = []
    for name, item in properties.items():
        kind = item.get("type")
        annotation = TYPE_MAP.get(kind, object)
        default = inspect.Parameter.empty
        if "default" in item:
            default = _default(item["default"], kind)
        elif name not in required:
            default = None
            annotation = annotation | None
        parameters.append(
            inspect.Parameter(
                name,
                inspect.Parameter.KEYWORD_ONLY,
                annotation=annotation,
                default=default,
            )
        )
    parameters.sort(key=lambda item: item.default is not inspect.Parameter.empty)

    def handler(**kwargs):
        values = {}
        for key, value in kwargs.items():
            if value is None:
                continue
            item = properties.get(key, {})
            if "default" in item and (
                value == ""
                or value == _default(item["default"], item.get("type"))
            ):
                continue
            values[key] = value
        query = {
            key: value
            for key, value in values.items()
            if properties.get(key, {}).get("source") == "query"
            or definition["method"] == "GET"
        }
        body = (
            {
                key: value
                for key, value in values.items()
                if properties.get(key, {}).get("source") != "query"
            }
            if definition["method"] == "POST"
            else None
        )
        return dispatch.dispatch(
            definition["method"],
            definition["endpoint"],
            query=query or None,
            body=body,
        )

    handler.__name__ = definition["name"]
    handler.__doc__ = definition["description"]
    handler.__signature__ = inspect.Signature(parameters, return_annotation=str)
    handler.__annotations__ = {
        parameter.name: parameter.annotation for parameter in parameters
    }
    handler.__annotations__["return"] = str
    return handler


def build_tools(definitions: list[dict]) -> dict[str, tuple[object, dict, str]]:
    result = {}
    for definition in definitions:
        name = definition["name"]
        result[name] = (
            build_handler(definition),
            definition["input_schema"],
            definition["description"],
        )
    return result


def _add(name: str, value: tuple[object, dict, str]) -> None:
    function, input_schema, description = value
    mcp.add_tool(function, name=name, description=description)
    tool = mcp._tool_manager.get_tool(name)
    if tool is None:
        raise RuntimeError(f"FastMCP did not publish {name!r}.")
    public_schema = deepcopy(input_schema)
    for item in public_schema.get("properties", {}).values():
        item.pop("source", None)
    tool.parameters = public_schema


def publish(tools: dict[str, tuple[object, dict, str]]) -> None:
    """Replace all dynamic tools, restoring the old set if publication fails."""
    with state.lock:
        old = {}
        for name in state.connection.dynamic_names:
            tool = mcp._tool_manager.get_tool(name)
            if tool is not None:
                old[name] = (tool.fn, tool.parameters, tool.description)
        added: set[str] = set()
        try:
            for name in state.connection.dynamic_names:
                mcp.remove_tool(name)
            for name, value in tools.items():
                _add(name, value)
                added.add(name)
        except Exception:
            for name in added:
                mcp.remove_tool(name)
            for name, value in old.items():
                _add(name, value)
            raise


def clear() -> None:
    with state.lock:
        for name in state.connection.dynamic_names:
            mcp.remove_tool(name)
        state.connection = state.Connection()
