"""Parse the plugin's endpoint schema."""

import re

from .config import STATIC_TOOL_NAMES

TYPE_MAP = {
    "string": str,
    "integer": int,
    "boolean": bool,
    "number": float,
    "object": dict,
    "array": list,
}
JSON_SCHEMA_TYPES = set(TYPE_MAP)
TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def parse(raw: dict) -> list[dict]:
    if not isinstance(raw, dict) or not isinstance(raw.get("tools"), list):
        raise ValueError("Schema must contain a tools array.")
    result: list[dict] = []
    names = set(STATIC_TOOL_NAMES)
    for item in raw["tools"]:
        if not isinstance(item, dict):
            raise ValueError("Every schema tool must be an object.")
        endpoint = item.get("path")
        method = str(item.get("method", "GET")).upper()
        name = str(endpoint or "").lstrip("/").replace("/", "_")
        if not endpoint or method not in {"GET", "POST"}:
            raise ValueError(f"Invalid endpoint for tool {name!r}.")
        if not TOOL_NAME.fullmatch(name):
            raise ValueError(f"Invalid MCP tool name {name!r}.")
        if name in names:
            raise ValueError(f"Duplicate MCP tool name {name!r}.")
        names.add(name)
        properties: dict = {}
        required: list[str] = []
        for param in item.get("params", []):
            definition = dict(param.get("schema") or {})
            kind = definition.get("type", param.get("type", "string"))
            if kind in {"json", "any"}:
                definition.pop("type", None)
            elif kind not in JSON_SCHEMA_TYPES:
                raise ValueError(
                    f"Invalid schema type {kind!r} for parameter "
                    f"{param.get('name')!r}."
                )
            else:
                definition["type"] = kind
            if param.get("description"):
                definition["description"] = param["description"]
            if param.get("default") is not None:
                definition["default"] = param["default"]
            if param.get("source"):
                definition["source"] = param["source"]
            properties[param["name"]] = definition
            if param.get("required"):
                required.append(param["name"])
        result.append(
            {
                "name": name,
                "endpoint": endpoint,
                "method": method,
                "description": item.get("description", ""),
                "input_schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            }
        )
    return result
