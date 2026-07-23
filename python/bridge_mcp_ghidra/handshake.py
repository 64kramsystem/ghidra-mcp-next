"""Strict server-manifest validation and atomic FastMCP registry publication."""

from __future__ import annotations

import hashlib
import json
import keyword
import re
from copy import deepcopy
from dataclasses import dataclass
from importlib import metadata
from typing import Any
from urllib.parse import urlsplit

from .schema import _parse_schema
from .validation import sanitize_tool_name

SUPPORTED_MCP_VERSION = "1.28.1"
PARAMETER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
REQUIRED_VERSION_FIELDS = (
    "plugin_name",
    "plugin_version",
    "build_timestamp",
    "build_number",
    "full_version",
    "ghidra_version",
    "java_version",
    "endpoint_count",
    "mode",
)


class HandshakeError(RuntimeError):
    """A categorized capability-handshake failure."""

    def __init__(
        self,
        category: str,
        message: str,
        *,
        server_identity: dict[str, Any] | None = None,
        failures: list[dict[str, Any]] | None = None,
    ):
        super().__init__(message)
        self.category = category
        self.server_identity = server_identity
        self.failures = failures or []

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "category": self.category,
            "message": str(self),
        }
        if self.server_identity is not None:
            result["server_identity"] = self.server_identity
        if self.failures:
            result["failures"] = self.failures
        return result


def _reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HandshakeError(
                "malformed schema", f"duplicate JSON object key: {key!r}"
            )
        result[key] = value
    return result


def _reject_non_finite(value):
    raise HandshakeError(
        "malformed schema", f"non-finite JSON number is not allowed: {value}"
    )


def parse_json_strict(text: str, kind: str) -> Any:
    """Parse server JSON without accepting duplicate keys or NaN/Infinity."""
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_non_finite,
        )
    except HandshakeError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        category = (
            "version-response failure"
            if kind == "version"
            else "malformed schema"
        )
        raise HandshakeError(category, f"invalid {kind} JSON: {exc}") from exc


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HandshakeError(
            "malformed schema", f"manifest is not canonical JSON: {exc}"
        ) from exc


def _canonical_path(value: Any, index: int) -> str:
    if not isinstance(value, str):
        raise HandshakeError(
            "malformed schema", f"tool[{index}].path must be a string"
        )
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise HandshakeError(
            "malformed schema",
            f"tool[{index}].path contains a control character",
        )
    path = "/" + value.lstrip("/")
    parsed = urlsplit(path)
    if parsed.query or parsed.fragment or "?" in path or "#" in path:
        raise HandshakeError(
            "malformed schema",
            f"tool[{index}].path must not contain query or fragment",
        )
    if path == "/":
        raise HandshakeError(
            "malformed schema", f"tool[{index}].path cannot be empty"
        )
    return path


def _server_identity(version: dict[str, Any]) -> dict[str, Any]:
    return {field: version.get(field) for field in REQUIRED_VERSION_FIELDS}


@dataclass(frozen=True)
class ValidatedManifest:
    version: dict[str, Any]
    raw_tools: tuple[dict[str, Any], ...]
    tool_defs: tuple[dict[str, Any], ...]
    manifest_count: int
    manifest_sha256: str
    callable_schema_sha256: str
    manifest_bytes: bytes
    callable_schema_bytes: bytes


def validate_handshake(
    version: Any,
    schema: Any,
    static_names: set[str] | frozenset[str] = frozenset(),
) -> ValidatedManifest:
    """Validate and canonicalize both authoritative server responses."""
    if not isinstance(version, dict):
        raise HandshakeError(
            "version-response failure",
            "/get_version must return a JSON object",
        )
    missing = [
        field
        for field in REQUIRED_VERSION_FIELDS
        if field not in version or version[field] is None
    ]
    if missing:
        raise HandshakeError(
            "version-response failure",
            f"/get_version is missing mandatory fields: {', '.join(missing)}",
            server_identity=_server_identity(version),
        )
    if (
        not isinstance(version["endpoint_count"], int)
        or isinstance(version["endpoint_count"], bool)
        or version["endpoint_count"] < 0
    ):
        raise HandshakeError(
            "version-response failure",
            "/get_version.endpoint_count must be a non-negative integer",
            server_identity=_server_identity(version),
        )
    if version["mode"] not in {"gui", "headless"}:
        raise HandshakeError(
            "version-response failure",
            "/get_version.mode must be 'gui' or 'headless'",
            server_identity=_server_identity(version),
        )
    for field in REQUIRED_VERSION_FIELDS:
        if field not in {"endpoint_count", "mode"} and not isinstance(
            version[field], str
        ):
            raise HandshakeError(
                "version-response failure",
                f"/get_version.{field} must be a string",
                server_identity=_server_identity(version),
            )

    if not isinstance(schema, dict) or not isinstance(schema.get("tools"), list):
        raise HandshakeError(
            "malformed schema",
            "/mcp/schema.tools must be an array",
            server_identity=_server_identity(version),
        )
    raw_count = len(schema["tools"])
    declared_count = schema.get("count")
    if declared_count is not None and (
        not isinstance(declared_count, int)
        or isinstance(declared_count, bool)
        or declared_count != raw_count
    ):
        raise HandshakeError(
            "manifest count mismatch",
            f"/mcp/schema.count={declared_count!r} but tools has {raw_count} entries",
            server_identity=_server_identity(version),
        )
    if version["endpoint_count"] != raw_count:
        raise HandshakeError(
            "manifest count mismatch",
            f"/get_version.endpoint_count={version['endpoint_count']} "
            f"but schema has {raw_count} entries",
            server_identity=_server_identity(version),
        )

    normalized_raw: list[dict[str, Any]] = []
    parsed_defs: list[dict[str, Any]] = []
    used_names: dict[str, int] = {}
    used_identities: dict[tuple[str, str], int] = {}
    for index, original in enumerate(schema["tools"]):
        if not isinstance(original, dict):
            raise HandshakeError(
                "malformed schema",
                f"tool[{index}] must be an object",
                server_identity=_server_identity(version),
            )
        raw = deepcopy(original)
        method = raw.get("method")
        if not isinstance(method, str):
            raise HandshakeError(
                "malformed schema", f"tool[{index}].method must be a string"
            )
        method = method.upper()
        if method not in {"GET", "POST"}:
            raise HandshakeError(
                "malformed schema",
                f"tool[{index}] uses unsupported method {method!r}",
            )
        path = _canonical_path(raw.get("path"), index)
        params = raw.get("params")
        if not isinstance(params, list):
            raise HandshakeError(
                "malformed schema", f"tool[{index}].params must be an array"
            )
        parameter_names: set[str] = set()
        for param_index, parameter in enumerate(params):
            if not isinstance(parameter, dict):
                raise HandshakeError(
                    "malformed schema",
                    f"tool[{index}].params[{param_index}] must be an object",
                )
            name = parameter.get("name")
            if (
                not isinstance(name, str)
                or not PARAMETER_NAME.fullmatch(name)
                or keyword.iskeyword(name)
                or name == "ctx"
            ):
                raise HandshakeError(
                    "malformed schema",
                    f"tool[{index}] has invalid parameter name {name!r}",
                )
            if name in parameter_names:
                raise HandshakeError(
                    "malformed schema",
                    f"tool[{index}] has duplicate parameter {name!r}",
                )
            parameter_names.add(name)

        raw_name = raw.get("name")
        if raw_name is not None and not isinstance(raw_name, str):
            raise HandshakeError(
                "malformed schema", f"tool[{index}].name must be a string"
            )
        try:
            normalized_name = sanitize_tool_name(raw_name or path.lstrip("/"))
        except ValueError as exc:
            raise HandshakeError(
                "malformed schema", f"tool[{index}] name is invalid: {exc}"
            ) from exc
        identity = (method, path)
        if identity in used_identities:
            raise HandshakeError(
                "method/path collision",
                f"tools[{used_identities[identity]}] and [{index}] share "
                f"{method} {path}",
            )
        if normalized_name in static_names:
            raise HandshakeError(
                "normalized-name collision",
                f"manifest tool {normalized_name!r} collides with a static bridge tool",
            )
        if normalized_name in used_names:
            raise HandshakeError(
                "normalized-name collision",
                f"tools[{used_names[normalized_name]}] and [{index}] normalize "
                f"to {normalized_name!r}",
            )
        used_names[normalized_name] = index
        used_identities[identity] = index

        raw["method"] = method
        raw["path"] = path
        normalized_raw.append(raw)
        parsed = _parse_schema({"tools": [raw]})[0]
        parsed["name"] = normalized_name
        parsed["original_name"] = raw_name or path.lstrip("/")
        parsed["sanitized_name"] = normalized_name
        parsed["name_collided"] = False
        parsed_defs.append(parsed)

    sort_key = lambda item: (
        sanitize_tool_name(item.get("name") or item["path"].lstrip("/")),
        item["method"],
        item["path"],
    )
    manifest_value = {"tools": sorted(normalized_raw, key=sort_key)}
    manifest_bytes = canonical_json_bytes(manifest_value)
    callable_value = sorted(
        parsed_defs,
        key=lambda item: (
            item["name"],
            item["http_method"],
            item["endpoint"],
        ),
    )
    callable_schema_bytes = canonical_json_bytes(callable_value)
    return ValidatedManifest(
        version=deepcopy(version),
        raw_tools=tuple(normalized_raw),
        tool_defs=tuple(parsed_defs),
        manifest_count=raw_count,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        callable_schema_sha256=hashlib.sha256(
            callable_schema_bytes
        ).hexdigest(),
        manifest_bytes=manifest_bytes,
        callable_schema_bytes=callable_schema_bytes,
    )


class RegistryAdapter:
    """The only production adapter allowed to touch FastMCP's private tool map."""

    def __init__(self, mcp, static_names: set[str] | frozenset[str]):
        installed = metadata.version("mcp")
        if installed != SUPPORTED_MCP_VERSION:
            raise HandshakeError(
                "unsupported registry-adapter version",
                f"mcp=={SUPPORTED_MCP_VERSION} is required; found {installed}",
            )
        manager = getattr(mcp, "_tool_manager", None)
        tool_map = getattr(manager, "_tools", None)
        if type(tool_map) is not dict:
            raise HandshakeError(
                "unsupported registry-adapter version",
                "FastMCP tool registry shape is not the expected dict",
            )
        self._manager = manager
        self._static_names = frozenset(static_names)
        missing = self._static_names.difference(tool_map)
        if missing:
            raise HandshakeError(
                "unsupported registry-adapter version",
                f"static tools missing from FastMCP registry: {sorted(missing)}",
            )

    def snapshot(self) -> dict[str, Any]:
        return dict(self._manager._tools)

    def replace_dynamic(self, dynamic: dict[str, Any]) -> None:
        collisions = self._static_names.intersection(dynamic)
        if collisions:
            raise HandshakeError(
                "registration failure",
                f"dynamic tools collide with static tool(s): {sorted(collisions)}",
            )
        for name, tool in dynamic.items():
            if getattr(tool, "name", None) != name:
                raise HandshakeError(
                    "registration failure",
                    f"tool map key {name!r} does not match Tool.name "
                    f"{getattr(tool, 'name', None)!r}",
                )
        current = self._manager._tools
        static = {
            name: current[name]
            for name in self._static_names
            if name in current
        }
        staged = {**static, **dynamic}
        self._manager._tools = staged
        published = self._manager._tools
        if (
            type(published) is not dict
            or len(published) != len(staged)
            or set(published) != set(staged)
            or any(published[name] is not tool for name, tool in staged.items())
        ):
            self._manager._tools = current
            raise HandshakeError(
                "registration failure",
                "FastMCP registry did not publish the exact staged tool objects",
            )
