"""Dynamic tool registration from /mcp/schema, plus tool-group management."""

import inspect
import json
import sys
from copy import deepcopy
from dataclasses import dataclass, replace
from typing import Any

from mcp.server.fastmcp.tools.base import Tool

from . import dispatch
from . import handshake
from . import state
from . import transport
from .config import STATIC_TOOL_NAMES
from .schema import _TYPE_MAP, _normalize_tool_def_names, _parse_schema
from .server import Context, mcp
from .validation import sanitize_address, validate_tool_name

# Fail fast at import time if any bridge-defined static tool name is not CAPI-safe.
for _static_tool_name in STATIC_TOOL_NAMES:
    validate_tool_name(_static_tool_name)


@dataclass(frozen=True)
class StagedRegistry:
    """Validated manifest plus concrete dynamic tools, not yet published."""

    manifest: handshake.ValidatedManifest
    dynamic_tools: dict[str, Tool]
    loaded_groups: tuple[str, ...]


_registry_adapter: handshake.RegistryAdapter | None = None


def _adapter() -> handshake.RegistryAdapter:
    global _registry_adapter
    if _registry_adapter is None:
        _registry_adapter = handshake.RegistryAdapter(mcp, STATIC_TOOL_NAMES)
    return _registry_adapter


def initialize_registry_adapter() -> None:
    """Fail bridge startup before serving requests if FastMCP is unsupported."""
    _adapter()


def _coerce_schema_default(value, json_type: str):
    """Convert trusted wire-schema defaults to their declared Python type."""
    if not isinstance(value, str):
        return value
    if json_type == "boolean":
        if value == "true":
            return True
        if value == "false":
            return False
        raise ValueError(f"invalid boolean schema default: {value!r}")
    if json_type == "integer":
        return int(value, 10)
    if json_type == "number":
        return float(value)
    if json_type in {"object", "array"}:
        parsed = json.loads(value)
        expected = dict if json_type == "object" else list
        if not isinstance(parsed, expected):
            raise ValueError(
                f"{json_type} schema default must decode to "
                f"{expected.__name__}"
            )
        return parsed
    return value


def _build_tool_function(
    endpoint: str,
    http_method: str,
    params_schema: dict,
    supports_synthetic_dry_run: bool = True,
):
    """Build a callable that dispatches to the Ghidra HTTP endpoint."""
    properties = params_schema.get("properties", {})
    required = set(params_schema.get("required", []))
    # Program selectors: params that pick which open program a call operates on.
    # Most tools use plain `program=`; the cross-program tools (diff_functions,
    # bulk_fuzzy_match, find_similar_functions_fuzzy) use `source_program`/
    # `target_program` or `program_a`/`program_b`. All match this name pattern.
    # We deliberately do NOT filter by the schema's `required` flag: those
    # selectors are declared required yet the server still falls back to the
    # *current* program when one arrives empty (getProgramOrError), which is the
    # wrong-binary hazard strict mode closes. (open_program/close_program use
    # path/name, so they have no selector here and are unaffected.)
    program_selectors = [
        name for name in properties
        if name == "program" or name.endswith("_program") or name.startswith("program_")
    ]
    is_post = http_method.upper() == "POST"
    has_schema_dry_run = "dry_run" in properties
    use_synthetic_dry_run = (
        supports_synthetic_dry_run and is_post and not has_schema_dry_run
    )

    def is_truthy(value) -> bool:
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def handler(**kwargs):
        # Sanitize address parameters before dispatch
        for pname, pdef in properties.items():
            if (
                pdef.get("param_type") == "address"
                and pname in kwargs
                and kwargs[pname] is not None
            ):
                kwargs[pname] = sanitize_address(str(kwargs[pname]))
        # Synthetic bridge dry-run goes as a query param. Schema-declared
        # dry_run must stay in kwargs so its declared source (query/body) wins.
        dry_run = kwargs.pop("dry_run", None) if use_synthetic_dry_run else None
        # Filter out None AND empty strings. Codex's MCP client passes schema
        # default values (including "") to every call, which the Ghidra
        # handler treats as "present but empty" and fails on params that
        # require a real value (e.g. /get_function_callers rejects empty
        # name/address). minimax avoids this by only sending params the LLM
        # explicitly provided, but the bridge is schema-driven and doesn't
        # know which were defaults. Empty string is not a meaningful value
        # for any current Ghidra endpoint — safe to filter.
        filtered = {
            k: v
            for k, v in kwargs.items()
            if v is not None and not (isinstance(v, str) and v == "")
        }
        # Strict mode: refuse if any program selector is missing, so a forgotten
        # one fails loudly instead of running against the server's current
        # program. filtered has already dropped None and "", so absence is the
        # test (an empty selector counts as omitted).
        if state._require_selectors and program_selectors:
            missing = [p for p in program_selectors if p not in filtered]
            if missing:
                names = ", ".join(f"`{p}=`" for p in missing)
                return json.dumps({
                    "error": (
                        f"Missing required program selector(s): {names} "
                        "(GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS is set). "
                        "Pass each explicitly to target the intended open program(s)."
                    )
                })
        if http_method == "GET":
            str_params = {k: str(v) for k, v in filtered.items()}
            if use_synthetic_dry_run and is_truthy(dry_run):
                str_params["dry_run"] = "true"
            return dispatch.dispatch_get(
                endpoint, params=str_params if str_params else None
            )
        else:
            body_data = {}
            query_params = {}
            for key, value in filtered.items():
                if properties.get(key, {}).get("source") == "query":
                    query_params[key] = str(value)
                else:
                    body_data[key] = value
            if use_synthetic_dry_run and is_truthy(dry_run):
                query_params["dry_run"] = "true"
            return dispatch.dispatch_post(
                endpoint,
                data=body_data,
                query_params=query_params or None,
            )

    # Build function signature with proper types and defaults
    # Params with defaults must come after params without defaults
    required_params = []
    optional_params = []
    for pname, pdef in properties.items():
        json_type = pdef.get("type", "string")
        py_type = _TYPE_MAP.get(json_type, str)
        default = pdef.get("default", inspect.Parameter.empty)
        if default is not inspect.Parameter.empty:
            default = _coerce_schema_default(default, json_type)
        if pname not in required and default is inspect.Parameter.empty:
            default = None
            py_type = py_type | None if py_type != str else str | None

        param = inspect.Parameter(
            pname, inspect.Parameter.KEYWORD_ONLY, default=default, annotation=py_type
        )
        if default is inspect.Parameter.empty:
            required_params.append(param)
        else:
            optional_params.append(param)

    sig_params = required_params + optional_params
    # Add dry_run parameter for POST (write) endpoints
    if use_synthetic_dry_run:
        sig_params.append(
            inspect.Parameter(
                "dry_run",
                inspect.Parameter.KEYWORD_ONLY,
                default=False,
                annotation=bool,
            )
        )
    handler.__signature__ = inspect.Signature(sig_params, return_annotation=str)
    handler.__annotations__ = {p.name: p.annotation for p in sig_params}
    handler.__annotations__["return"] = str

    return handler


def _register_tool_def(tool_def: dict) -> bool:
    """Register a single tool from a schema definition. Returns True if registered."""
    name = tool_def["name"]
    validate_tool_name(name)
    if name in STATIC_TOOL_NAMES:
        raise handshake.HandshakeError(
            "normalized-name collision",
            f"manifest tool {name!r} collides with a static bridge tool",
        )
    current = {
        tool_name: tool
        for tool_name, tool in _adapter().snapshot().items()
        if tool_name not in STATIC_TOOL_NAMES
    }
    if name in current:
        raise handshake.HandshakeError(
            "normalized-name collision",
            f"dynamic tool {name!r} is already registered",
        )
    current[name] = _build_tool_object(tool_def)
    _adapter().replace_dynamic(current)
    state._dynamic_tool_names.clear()
    state._dynamic_tool_names.extend(sorted(current))
    return True


def _restore_structured_parameter_schemas(tool, input_schema: dict) -> None:
    """Restore nested JSON Schema that Python type hints cannot represent.

    FastMCP derives its public schema from the generated callable signature.
    A plain ``list`` annotation necessarily collapses nested ``items`` unions
    to ``items: {}``, so copy trusted structural fragments from Ghidra's
    reviewed schema after registration. Transport-only keywords stay private.
    """
    registered_properties = tool.parameters.setdefault("properties", {})
    for name, definition in input_schema.get("properties", {}).items():
        if not any(
            key in definition
            for key in ("items", "properties", "oneOf", "anyOf", "allOf")
        ):
            continue
        public = deepcopy(definition)
        public.pop("source", None)
        public.pop("param_type", None)
        if "default" in public:
            public["default"] = _coerce_schema_default(
                public["default"], public.get("type", "string")
            )
        registered_properties[name] = public


def _prepare_dynamic_request(
    http_method: str,
    params_schema: dict,
    supports_synthetic_dry_run: bool,
    kwargs: dict[str, Any],
) -> tuple[dict[str, str] | None, dict[str, Any] | None, str | None]:
    """Normalize one generated call into query/body without contacting Ghidra."""
    properties = params_schema.get("properties", {})
    values = dict(kwargs)
    for name, definition in properties.items():
        if (
            definition.get("param_type") == "address"
            and name in values
            and values[name] is not None
        ):
            values[name] = sanitize_address(str(values[name]))
    is_post = http_method == "POST"
    synthetic = (
        is_post
        and supports_synthetic_dry_run
        and "dry_run" not in properties
    )
    dry_run = values.pop("dry_run", None) if synthetic else None
    filtered = {
        key: value
        for key, value in values.items()
        if value is not None
        and not (isinstance(value, str) and value == "")
    }
    selectors = [
        name
        for name in properties
        if name == "program"
        or name.endswith("_program")
        or name.startswith("program_")
    ]
    if state._require_selectors:
        missing = [name for name in selectors if name not in filtered]
        if missing:
            names = ", ".join(f"`{name}=`" for name in missing)
            return None, None, json.dumps(
                {
                    "error": (
                        f"Missing required program selector(s): {names} "
                        "(GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS is set). "
                        "Pass each explicitly to target the intended open program(s)."
                    )
                }
            )
    if http_method == "GET":
        query = {key: str(value) for key, value in filtered.items()}
        if synthetic and (
            dry_run is True
            or isinstance(dry_run, str)
            and dry_run.lower() in {"1", "true", "yes", "on"}
        ):
            query["dry_run"] = "true"
        return query or None, None, None

    body: dict[str, Any] = {}
    query = {}
    for key, value in filtered.items():
        if properties.get(key, {}).get("source") == "query":
            query[key] = str(value)
        else:
            body[key] = value
    if synthetic and (
        dry_run is True
        or isinstance(dry_run, str)
        and dry_run.lower() in {"1", "true", "yes", "on"}
    ):
        query["dry_run"] = "true"
    return query or None, body, None


def _build_tool_object(tool_def: dict) -> Tool:
    """Convert one parsed definition to a concrete hidden-context FastMCP Tool."""
    name = tool_def["name"]
    validate_tool_name(name)
    description = tool_def.get("description", "")
    endpoint = tool_def["endpoint"]
    method = tool_def.get("http_method", "GET").upper()
    input_schema = tool_def.get(
        "input_schema", {"type": "object", "properties": {}}
    )
    signature_source = _build_tool_function(
        endpoint,
        method,
        input_schema,
        tool_def.get("supports_synthetic_dry_run", True),
    )

    async def handler(**kwargs):
        ctx = kwargs.pop("ctx", None)
        # The public register_tools_from_schema helper is retained for focused
        # schema/dispatch tests. Production publication always has a connected
        # bundle; a disconnected bridge cannot retain dynamic names.
        if (
            not state._connection.connected
            and name in state._dynamic_tool_names
        ):
            return signature_source(**kwargs)
        query, body, error = _prepare_dynamic_request(
            method,
            input_schema,
            tool_def.get("supports_synthetic_dry_run", True),
            kwargs,
        )
        if error is not None:
            return error
        return await dispatch.dispatch_dynamic(
            name,
            method,
            endpoint,
            query_params=query,
            body=body,
            ctx=ctx,
        )

    handler.__name__ = name
    handler.__doc__ = description
    parameters = list(inspect.signature(signature_source).parameters.values())
    parameters.append(
        inspect.Parameter(
            "ctx",
            inspect.Parameter.KEYWORD_ONLY,
            default=None,
            annotation=Context | None,
        )
    )
    handler.__signature__ = inspect.Signature(
        parameters, return_annotation=str
    )
    handler.__annotations__ = {
        parameter.name: parameter.annotation for parameter in parameters
    }
    handler.__annotations__["return"] = str
    tool = Tool.from_function(
        handler,
        name=name,
        description=description,
        context_kwarg="ctx",
    )
    _restore_structured_parameter_schemas(tool, input_schema)
    return tool


def build_staged_registry(
    manifest: handshake.ValidatedManifest,
    groups: set[str] | None,
) -> StagedRegistry:
    """Build every selected Tool off-registry or fail with structured details."""
    dynamic: dict[str, Tool] = {}
    loaded_groups: set[str] = set()
    failures: list[dict[str, Any]] = []
    for tool_def in manifest.tool_defs:
        category = tool_def.get("category", "unknown")
        if groups is not None and category not in groups:
            continue
        identity = {
            "name": tool_def["name"],
            "method": tool_def["http_method"],
            "path": tool_def["endpoint"],
        }
        try:
            tool = _build_tool_object(tool_def)
            if tool.name in dynamic:
                raise ValueError("duplicate staged tool name")
            dynamic[tool.name] = tool
            loaded_groups.add(category)
        except Exception as exc:
            failures.append({**identity, "error": str(exc)})
    if failures:
        raise handshake.HandshakeError(
            "registration failure",
            f"{len(failures)} manifest tool(s) failed registration",
            server_identity=manifest.version,
            failures=failures,
        )
    expected = (
        manifest.manifest_count
        if groups is None
        else sum(
            1
            for definition in manifest.tool_defs
            if definition.get("category", "unknown") in groups
        )
    )
    if len(dynamic) != expected:
        raise handshake.HandshakeError(
            "callable-count mismatch",
            f"built {len(dynamic)} callable dynamic tools; expected {expected}",
            server_identity=manifest.version,
        )
    return StagedRegistry(
        manifest=manifest,
        dynamic_tools=dynamic,
        loaded_groups=tuple(sorted(loaded_groups)),
    )


def publish_staged(
    staged: StagedRegistry,
    *,
    project: str | None,
    mode: str,
    endpoint: str,
    generation: int,
    lazy: bool,
) -> state.ConnectionBundle:
    """Commit a staged map and its matching state while the mutation lock is held."""
    identities = {
        definition["name"]: (
            definition["http_method"],
            definition["endpoint"],
        )
        for definition in staged.manifest.tool_defs
    }
    bundle = state.ConnectionBundle(
        connected=True,
        generation=generation,
        project=project,
        transport=mode,
        endpoint=endpoint,
        server=deepcopy(staged.manifest.version),
        lazy=lazy,
        manifest_count=staged.manifest.manifest_count,
        callable_dynamic_count=len(staged.dynamic_tools),
        loaded_groups=staged.loaded_groups,
        manifest_sha256=staged.manifest.manifest_sha256,
        callable_schema_sha256=staged.manifest.callable_schema_sha256,
        full_schema=tuple(deepcopy(staged.manifest.tool_defs)),
        dynamic_names=tuple(sorted(staged.dynamic_tools)),
        identities=identities,
    )
    return _publish_bundle(staged.dynamic_tools, bundle)


def _publish_bundle(
    dynamic: dict[str, Tool], bundle: state.ConnectionBundle
) -> state.ConnectionBundle:
    """Swap tool map and state as one rollback-safe mutation."""
    adapter = _adapter()
    old_map = adapter.snapshot()
    old_bundle = state._connection
    adapter.replace_dynamic(dynamic)
    try:
        state.publish_connection(bundle)
    except Exception as exc:
        adapter.restore(old_map)
        state.publish_connection(old_bundle)
        if isinstance(exc, handshake.HandshakeError):
            raise
        raise handshake.HandshakeError(
            "registration failure",
            f"connection-state publication failed: {exc}",
            server_identity=bundle.server,
        ) from exc
    return bundle


def publish_disconnected() -> state.ConnectionBundle:
    """Atomically remove all dynamic tools and mark the bridge disconnected."""
    bundle = state.disconnected_bundle()
    return _publish_bundle({}, bundle)


def stage_active_groups(groups: set[str]) -> dict[str, Tool]:
    """Rebuild the complete callable map for active lazy-mode groups."""
    dynamic: dict[str, Tool] = {}
    failures: list[dict[str, Any]] = []
    for definition in state._connection.full_schema:
        if definition.get("category", "unknown") not in groups:
            continue
        identity = {
            "name": definition["name"],
            "method": definition["http_method"],
            "path": definition["endpoint"],
        }
        try:
            dynamic[definition["name"]] = _build_tool_object(definition)
        except Exception as exc:
            failures.append({**identity, "error": str(exc)})
    if failures:
        raise handshake.HandshakeError(
            "registration failure",
            f"{len(failures)} tool(s) failed while staging groups",
            server_identity=state._connection.server,
            failures=failures,
        )
    expected = sum(
        1
        for definition in state._connection.full_schema
        if definition.get("category", "unknown") in groups
    )
    if len(dynamic) != expected:
        raise handshake.HandshakeError(
            "callable-count mismatch",
            f"staged {len(dynamic)} tools for groups; expected {expected}",
            server_identity=state._connection.server,
        )
    return dynamic


def publish_active_groups(
    dynamic: dict[str, Tool], groups: set[str]
) -> state.ConnectionBundle:
    """Atomically publish a lazy load/unload map without changing generation."""
    bundle = replace(
        state._connection,
        callable_dynamic_count=len(dynamic),
        loaded_groups=tuple(sorted(groups)),
        dynamic_names=tuple(sorted(dynamic)),
    )
    return _publish_bundle(dynamic, bundle)


def _report_tool_registration_failures(failures: list[str]) -> None:
    """Emit a compact stderr diagnostic for schema tools that could not load."""
    if not failures:
        return

    shown = "; ".join(failures[:8])
    suffix = "..." if len(failures) > 8 else ""
    sys.stderr.write(
        f"[bridge_mcp_ghidra] {len(failures)} tool(s) failed to register: "
        f"{shown}{suffix}\n"
    )
    sys.stderr.flush()


def _clear_dynamic_tools() -> None:
    """Remove dynamic registrations and clear all cached schema state."""
    _adapter().replace_dynamic({})
    state._dynamic_tool_names.clear()
    state._full_schema = []
    state._loaded_groups.clear()


def register_tools_from_schema(
    schema: list[dict], groups: set[str] | None = None
) -> int:
    """Register MCP tools from parsed schema.

    Args:
        schema: List of parsed tool definitions.
        groups: If provided, only register tools in these groups. None = register all.

    Returns: count of registered tools.
    """
    normalized = _normalize_tool_def_names(schema)
    dynamic: dict[str, Tool] = {}
    failures: list[str] = []
    loaded_groups: set[str] = set()
    for tool_def in normalized:
        category = tool_def.get("category", "unknown")
        if groups is not None and category not in groups:
            continue
        try:
            name = tool_def["name"]
            if name in STATIC_TOOL_NAMES or name in dynamic:
                raise handshake.HandshakeError(
                    "normalized-name collision",
                    f"tool {name!r} collides during registration",
                )
            dynamic[name] = _build_tool_object(tool_def)
            loaded_groups.add(category)
        except Exception as e:
            name = tool_def.get("name", "<unnamed>")
            failures.append(f"{name}: {e}")
    _report_tool_registration_failures(failures)
    if failures:
        raise handshake.HandshakeError(
            "registration failure",
            f"{len(failures)} tool(s) failed registration",
        )
    _adapter().replace_dynamic(dynamic)
    state._full_schema = normalized
    state._dynamic_tool_names.clear()
    state._dynamic_tool_names.extend(sorted(dynamic))
    state._loaded_groups.clear()
    state._loaded_groups.update(loaded_groups)
    return len(dynamic)


def _load_group(group_name: str) -> list[str]:
    """Load tools for a specific group from cached schema. Returns list of newly loaded tool names."""
    previous = set(state._dynamic_tool_names)
    groups = set(state._loaded_groups) | {group_name}
    definitions = [
        definition
        for definition in state._full_schema
        if definition.get("category", "unknown") in groups
    ]
    dynamic = {
        definition["name"]: _build_tool_object(definition)
        for definition in definitions
    }
    _adapter().replace_dynamic(dynamic)
    state._dynamic_tool_names.clear()
    state._dynamic_tool_names.extend(sorted(dynamic))
    state._loaded_groups.clear()
    state._loaded_groups.update(groups)
    return sorted(set(dynamic) - previous)


def _unload_group(group_name: str) -> int:
    """Unload tools for a specific group. Returns count of removed tools."""
    if group_name in state._default_groups:
        return 0  # Default groups can't be unloaded

    to_remove = []
    for tool_def in state._full_schema:
        if tool_def.get("category") == group_name:
            name = tool_def["name"]
            if name in state._dynamic_tool_names:
                to_remove.append(name)

    retained_groups = set(state._loaded_groups) - {group_name}
    definitions = [
        definition
        for definition in state._full_schema
        if definition.get("category", "unknown") in retained_groups
    ]
    dynamic = {
        definition["name"]: _build_tool_object(definition)
        for definition in definitions
    }
    _adapter().replace_dynamic(dynamic)
    state._dynamic_tool_names.clear()
    state._dynamic_tool_names.extend(sorted(dynamic))
    if to_remove:
        state._loaded_groups.clear()
        state._loaded_groups.update(retained_groups)
    return len(to_remove)


def _get_group_info() -> list[dict]:
    """Get info about all tool groups from cached schema."""
    groups: dict[str, list[str]] = {}
    descriptions: dict[str, str] = {}
    for tool_def in state._full_schema:
        cat = tool_def.get("category", "unknown")
        groups.setdefault(cat, []).append(tool_def["name"])
        if cat not in descriptions and tool_def.get("category_description"):
            descriptions[cat] = tool_def["category_description"]

    result = []
    for name, tools in sorted(groups.items()):
        info: dict = {
            "group": name,
            "tool_count": len(tools),
            "loaded": name in state._loaded_groups,
            "default": name in state._default_groups,
        }
        if name in descriptions:
            info["description"] = descriptions[name]
        info["tools"] = sorted(tools)
        result.append(info)
    return result


def _fetch_and_register_schema(load_all: bool = False) -> int:
    """Fetch /mcp/schema from connected instance and register tools.

    Args:
        load_all: If True, register all tools. If False, only default groups.

    Returns: count of registered tools.
    """
    if not load_all:
        load_all = not state._lazy_mode
    text, status = transport.do_request("GET", "/mcp/schema", timeout=10)
    if status != 200:
        raise RuntimeError(f"Failed to fetch schema: HTTP {status}")
    raw = json.loads(text)
    schema = _parse_schema(raw)
    groups = None if load_all else state._default_groups
    return register_tools_from_schema(schema, groups=groups)


async def _notify_tools_changed(ctx: Context | None) -> None:
    """Send tools/list_changed notification if context is available."""
    if ctx is not None and ctx._request_context is not None:
        await ctx.request_context.session.send_tool_list_changed()
