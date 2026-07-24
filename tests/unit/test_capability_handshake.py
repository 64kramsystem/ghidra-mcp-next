import json
import asyncio
import threading
import time
from copy import deepcopy
from dataclasses import replace
from http.client import IncompleteRead
from types import SimpleNamespace
from unittest.mock import AsyncMock
from pathlib import Path

import pytest

import tomllib

from bridge_mcp_ghidra import handshake
from bridge_mcp_ghidra import connection, registry, state, static_tools


VERSION = {
    "plugin_name": "GhidraMCP-next",
    "plugin_version": "20260723-201928",
    "build_timestamp": "20260723-201928",
    "build_number": "20260723-201928",
    "full_version": "GhidraMCP-next 20260723-201928",
    "ghidra_version": "12.1.2",
    "java_version": "21.0.11",
    "endpoint_count": 2,
    "mode": "gui",
}

SCHEMA = {
    "count": 2,
    "tools": [
        {
            "path": "alpha",
            "method": "get",
            "description": "alpha",
            "category": "listing",
            "params": [
                {
                    "name": "program",
                    "type": "string",
                    "source": "query",
                    "required": False,
                }
            ],
        },
        {
            "path": "//beta",
            "method": "POST",
            "category": "memory",
            "params": [],
            "future": {"retained": True},
        },
    ],
}


def test_parse_json_rejects_duplicate_keys_and_non_finite_values():
    with pytest.raises(handshake.HandshakeError, match="duplicate JSON object key"):
        handshake.parse_json_strict('{"tools":[],"tools":[]}', "schema")
    with pytest.raises(handshake.HandshakeError, match="non-finite"):
        handshake.parse_json_strict('{"endpoint_count":NaN}', "version")
    with pytest.raises(handshake.HandshakeError, match="non-finite"):
        handshake.parse_json_strict(
            '{"tools":[],"future":1e400}', "schema"
        )


def test_manifest_validation_and_digests_are_canonical():
    candidate = handshake.validate_handshake(
        deepcopy(VERSION), deepcopy(SCHEMA)
    )
    assert [item["endpoint"] for item in candidate.tool_defs] == [
        "/alpha",
        "/beta",
    ]
    assert candidate.manifest_count == 2
    assert len(candidate.manifest_sha256) == 64
    assert len(candidate.callable_schema_sha256) == 64

    reordered = deepcopy(SCHEMA)
    reordered["tools"].reverse()
    for tool in reordered["tools"]:
        tool["method"] = tool["method"].swapcase()
        tool["path"] = "///" + tool["path"].lstrip("/")
    same = handshake.validate_handshake(deepcopy(VERSION), reordered)
    assert same.manifest_sha256 == candidate.manifest_sha256
    assert same.callable_schema_sha256 == candidate.callable_schema_sha256

    key_reordered = {
        "tools": [
            {key: value for key, value in reversed(list(tool.items()))}
            for tool in SCHEMA["tools"]
        ],
        "count": 2,
    }
    same_keys = handshake.validate_handshake(
        deepcopy(VERSION), key_reordered
    )
    assert same_keys.manifest_sha256 == candidate.manifest_sha256

    parameter_order = deepcopy(SCHEMA)
    parameter_order["tools"][0]["params"].append(
        {"name": "limit", "type": "integer", "required": False}
    )
    parameter_order["count"] = 2
    with_parameter = handshake.validate_handshake(
        deepcopy(VERSION), parameter_order
    )
    assert with_parameter.manifest_sha256 != candidate.manifest_sha256
    assert (
        with_parameter.callable_schema_sha256
        != candidate.callable_schema_sha256
    )

    reversed_parameters = deepcopy(parameter_order)
    reversed_parameters["tools"][0]["params"].reverse()
    reversed_digest = handshake.validate_handshake(
        deepcopy(VERSION), reversed_parameters
    )
    assert reversed_digest.manifest_sha256 != with_parameter.manifest_sha256

    unknown = deepcopy(SCHEMA)
    unknown["tools"][0]["future"] = "value"
    unknown_digest = handshake.validate_handshake(deepcopy(VERSION), unknown)
    assert unknown_digest.manifest_sha256 != candidate.manifest_sha256
    assert (
        unknown_digest.callable_schema_sha256
        == candidate.callable_schema_sha256
    )


@pytest.mark.parametrize(
    ("mutation", "category"),
    [
        (lambda s: s["tools"][0].update(method="PUT"), "malformed schema"),
        (
            lambda s: s["tools"][0].update(path="/alpha?x=1"),
            "malformed schema",
        ),
        (
            lambda s: s["tools"][0].update(path="/alpha#frag"),
            "malformed schema",
        ),
        (
            lambda s: s["tools"][0].update(path="/alpha\n"),
            "malformed schema",
        ),
        (
            lambda s: s["tools"][0].update(params={}),
            "malformed schema",
        ),
        (
            lambda s: s["tools"][0]["params"][0].update(name="bad-name"),
            "malformed schema",
        ),
        (
            lambda s: s["tools"][0]["params"][0].update(name="class"),
            "malformed schema",
        ),
        (
            lambda s: s["tools"][0]["params"][0].update(name="ctx"),
            "malformed schema",
        ),
    ],
)
def test_manifest_rejects_invalid_tool_shapes(mutation, category):
    schema = deepcopy(SCHEMA)
    mutation(schema)
    with pytest.raises(handshake.HandshakeError) as exc:
        handshake.validate_handshake(deepcopy(VERSION), schema)
    assert exc.value.category == category


def test_manifest_rejects_counts_and_normalized_collisions():
    bad_version = deepcopy(VERSION)
    bad_version["endpoint_count"] = 3
    with pytest.raises(handshake.HandshakeError) as exc:
        handshake.validate_handshake(bad_version, deepcopy(SCHEMA))
    assert exc.value.category == "manifest count mismatch"

    bad_schema = deepcopy(SCHEMA)
    bad_schema["count"] = 3
    with pytest.raises(handshake.HandshakeError) as exc:
        handshake.validate_handshake(deepcopy(VERSION), bad_schema)
    assert exc.value.category == "manifest count mismatch"

    duplicate_path = deepcopy(SCHEMA)
    duplicate_path["tools"][1]["path"] = "/alpha"
    duplicate_path["tools"][1]["method"] = "GET"
    with pytest.raises(handshake.HandshakeError) as exc:
        handshake.validate_handshake(deepcopy(VERSION), duplicate_path)
    assert exc.value.category == "method/path collision"
    assert "tools[0] and [1] share GET /alpha" in str(exc.value)

    duplicate_name = deepcopy(SCHEMA)
    duplicate_name["tools"][1]["name"] = "alpha"
    with pytest.raises(handshake.HandshakeError) as exc:
        handshake.validate_handshake(deepcopy(VERSION), duplicate_name)
    assert exc.value.category == "normalized-name collision"
    assert "tools[0] and [1] normalize to 'alpha'" in str(exc.value)

    duplicate_parameter = deepcopy(SCHEMA)
    duplicate_parameter["tools"][0]["params"].append(
        deepcopy(duplicate_parameter["tools"][0]["params"][0])
    )
    with pytest.raises(handshake.HandshakeError) as exc:
        handshake.validate_handshake(
            deepcopy(VERSION), duplicate_parameter
        )
    assert exc.value.category == "malformed schema"
    assert "tool[0] has duplicate parameter 'program'" in str(exc.value)


def test_renamed_static_wrappers_leave_server_project_tools_available():
    schema = {
        "count": 2,
        "tools": [
            {
                "path": "/create_project",
                "method": "POST",
                "params": [],
            },
            {
                "path": "/import_file",
                "method": "POST",
                "params": [],
            },
        ],
    }
    manifest = handshake.validate_handshake(
        deepcopy(VERSION),
        schema,
        static_tools.STATIC_TOOL_NAMES,
    )
    staged = registry.build_staged_registry(manifest, None)
    assert set(staged.dynamic_tools) == {"create_project", "import_file"}


def test_real_endpoint_catalog_registers_renamed_project_tools():
    root = Path(__file__).resolve().parents[2]
    catalog = json.loads((root / "tests/endpoints.json").read_text())
    tools = [
        {
            **entry,
            "params": [
                {
                    "name": name,
                    "type": "string",
                    "source": "query",
                    "required": False,
                }
                for name in entry.get("params", [])
            ],
        }
        for entry in catalog["endpoints"]
    ]
    version = {**VERSION, "endpoint_count": len(tools)}
    manifest = handshake.validate_handshake(
        version,
        {"count": len(tools), "tools": tools},
        static_tools.STATIC_TOOL_NAMES,
    )
    staged = registry.build_staged_registry(manifest, None)

    assert manifest.manifest_count == catalog["total_endpoints"]
    assert len(staged.dynamic_tools) == catalog["total_endpoints"]
    assert {"create_project", "import_file"}.issubset(
        staged.dynamic_tools
    )


def test_manifest_serialization_is_exact_utf8_without_unicode_normalization():
    composed = deepcopy(SCHEMA)
    composed["tools"][0]["description"] = "é"
    decomposed = deepcopy(SCHEMA)
    decomposed["tools"][0]["description"] = "e\u0301"

    first = handshake.validate_handshake(deepcopy(VERSION), composed)
    second = handshake.validate_handshake(deepcopy(VERSION), decomposed)
    assert first.manifest_sha256 != second.manifest_sha256
    assert b"\xc3\xa9" in first.manifest_bytes
    assert b"\\\\u" not in first.manifest_bytes


def test_registry_adapter_rejects_wrong_version_and_stages_atomically(monkeypatch):
    class Tool:
        def __init__(self, name):
            self.name = name

    class Manager:
        def __init__(self):
            self._tools = {"static": Tool("static")}

    class Mcp:
        def __init__(self):
            self._tool_manager = Manager()

    mcp = Mcp()
    monkeypatch.setattr(handshake.metadata, "version", lambda _name: "9.9.9")
    with pytest.raises(handshake.HandshakeError) as exc:
        handshake.RegistryAdapter(mcp, {"static"})
    assert exc.value.category == "unsupported registry-adapter version"

    monkeypatch.setattr(handshake.metadata, "version", lambda _name: "1.28.1")
    adapter = handshake.RegistryAdapter(mcp, {"static"})
    old_map = mcp._tool_manager._tools
    dynamic = Tool("dynamic")
    adapter.replace_dynamic({"dynamic": dynamic})
    assert mcp._tool_manager._tools is not old_map
    assert mcp._tool_manager._tools == {"static": old_map["static"], "dynamic": dynamic}

    with pytest.raises(handshake.HandshakeError, match="static tool"):
        adapter.replace_dynamic({"static": Tool("static")})
    assert mcp._tool_manager._tools["dynamic"] is dynamic

    static = mcp._tool_manager._tools.pop("static")
    with pytest.raises(handshake.HandshakeError, match="disappeared"):
        adapter.replace_dynamic({})
    mcp._tool_manager._tools["static"] = static


def test_registry_adapter_rejects_ignored_publication(monkeypatch):
    class Tool:
        def __init__(self, name):
            self.name = name

    class IgnoringManager:
        def __init__(self):
            self.value = {"static": Tool("static")}

        @property
        def _tools(self):
            return self.value

        @_tools.setter
        def _tools(self, _value):
            pass

    manager = IgnoringManager()
    mcp = SimpleNamespace(_tool_manager=manager)
    monkeypatch.setattr(handshake.metadata, "version", lambda _name: "1.28.1")
    adapter = handshake.RegistryAdapter(mcp, {"static"})
    with pytest.raises(handshake.HandshakeError) as exc:
        adapter.replace_dynamic({"dynamic": Tool("dynamic")})
    assert exc.value.category == "registration failure"
    assert set(manager._tools) == {"static"}


def test_runtime_dependency_and_startup_adapter_are_exact():
    root = Path(__file__).resolve().parents[2]
    project = tomllib.loads((root / "pyproject.toml").read_text())
    assert "mcp==1.28.1" in project["project"]["dependencies"]
    assert registry._registry_adapter is not None


def _wire_responses(version=None, schema=None):
    version = deepcopy(version or VERSION)
    schema = deepcopy(schema or SCHEMA)

    def request(_mode, _endpoint, _method, path, **_kwargs):
        if path == "/get_version":
            return json.dumps(version), 200
        if path == "/mcp/schema":
            return json.dumps(schema), 200
        raise AssertionError(path)

    return request


@pytest.fixture
def clean_connection():
    original_profile = state._tool_profile
    with state._ghidra_lock:
        registry._adapter().replace_dynamic({})
        state._connection = state.ConnectionBundle()
        state._last_attempt = None
        state.publish_connection(state._connection)
        state.configure_tool_profile("full")
    yield
    with state._ghidra_lock:
        registry._adapter().replace_dynamic({})
        state._connection = state.ConnectionBundle()
        state._last_attempt = None
        state.publish_connection(state._connection)
        state._tool_profile = original_profile


def test_eager_handshake_publishes_complete_bundle(monkeypatch, clean_connection):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    result = asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="Neverending",
            ctx=None,
            failure_policy="clear",
        )
    )
    assert result["connected"] is True
    assert result["manifest_count"] == 2
    assert result["callable_dynamic_count"] == 2
    assert result["connection_generation"] == 1
    assert result["endpoint_count"] == 2
    assert result["tools_changed"] == {
        "attempted": False,
        "sent": False,
        "error": None,
    }
    assert set(state._dynamic_tool_names) == {"alpha", "beta"}
    assert state._last_attempt["success"] is True


def test_unknown_server_fields_cannot_override_bridge_state(
    monkeypatch, clean_connection
):
    poisoned = {
        **VERSION,
        "connected": False,
        "bridge_version": "server-controlled",
        "connection_generation": 999,
        "manifest_count": 999,
        "manifest_sha256": "server-controlled",
        "project": "server-controlled",
    }
    monkeypatch.setattr(
        static_tools.transport,
        "candidate_request",
        _wire_responses(version=poisoned),
    )
    result = asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    assert result["connected"] is True
    assert result["connection_generation"] == 1
    assert result["manifest_count"] == 2
    assert result["project"] == "A"
    assert result["manifest_sha256"] != "server-controlled"
    assert result["bridge_version"] != "server-controlled"


def test_disconnected_info_reports_bridge_and_static_tools_only(
    clean_connection,
):
    info = json.loads(static_tools.get_connection_info())
    assert info["connected"] is False
    assert info["connection_generation"] == 0
    assert info["bridge_package"] == "ghidra-mcp-bridge"
    assert Path(info["bridge_source"]).is_absolute()
    assert info["static_tool_count"] == len(static_tools.STATIC_TOOL_NAMES)
    assert "plugin_version" not in info
    assert info["last_attempt"] is None


def test_lazy_handshake_and_atomic_group_load(monkeypatch, clean_connection):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    state.configure_tool_profile("custom", {"listing"})
    result = asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="uds",
            endpoint="/tmp/ghidra.sock",
            project="Neverending",
            ctx=None,
            failure_policy="clear",
        )
    )
    assert result["manifest_count"] == 2
    assert result["callable_dynamic_count"] == 1
    assert result["tool_profile"] == "custom"
    assert result["profile_groups"] == ["listing"]
    assert state._connection.dynamic_names == ("alpha",)
    loaded = json.loads(asyncio.run(static_tools.load_tool_group("memory")))
    assert loaded["new_tool_names"] == ["beta"]
    assert state._connection.generation == 1
    assert state._connection.callable_dynamic_count == 2


def test_minimal_profile_keeps_full_catalog_searchable(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    state.configure_tool_profile("minimal")
    result = asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    assert result["tool_profile"] == "minimal"
    assert result["profile_groups"] == []
    assert result["manifest_count"] == 2
    assert result["callable_dynamic_count"] == 0
    assert state._connection.dynamic_names == ()
    assert len(state._connection.full_schema) == 2

    found = json.loads(asyncio.run(static_tools.search_tools("beta")))
    assert found["match_count"] == 1
    assert found["matches"] == [
        {
            "name": "beta",
            "group": "memory",
            "status": "not_loaded",
            "description": "",
            "fix": 'load_tool_group("memory")',
        }
    ]


def test_unknown_custom_profile_group_fails_handshake(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    state.configure_tool_profile("custom", {"typo"})
    result = asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    assert result["connected"] is False
    assert result["failure"]["category"] == "unknown tool group"
    assert "typo" in result["error"]


def test_eager_mode_refuses_partial_unload(monkeypatch, clean_connection):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    before = state._connection
    assert before.tool_profile == "full"
    assert before.profile_groups == ()
    result = json.loads(
        asyncio.run(static_tools.unload_tool_group("memory"))
    )
    assert "eager mode" in result["error"]
    assert state._connection is before
    assert state._connection.callable_dynamic_count == 2
    assert state._connection.manifest_count == 2


def test_failed_switch_preserves_and_failed_refresh_clears(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    previous = state._connection
    bad = deepcopy(SCHEMA)
    bad["count"] = 99
    monkeypatch.setattr(
        static_tools.transport,
        "candidate_request",
        _wire_responses(schema=bad),
    )
    switched = asyncio.run(
        connection.handshake_candidate(
            "switch",
            mode="tcp",
            endpoint="http://127.0.0.1:8090",
            project="B",
            ctx=None,
            failure_policy="preserve",
        )
    )
    assert "error" in switched
    assert state._connection is previous
    assert state._connection.generation == 1
    assert switched["tools_changed"]["attempted"] is False

    refreshed = asyncio.run(
        connection.handshake_candidate(
            "refresh",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    assert refreshed["connected"] is False
    assert state._connection.generation == 1
    assert state._dynamic_tool_names == []
    # No Context means the required post-cleanup notification is observable
    # as not attempted rather than pretending it was sent.
    assert refreshed["tools_changed"]["attempted"] is False
    info = json.loads(static_tools.get_connection_info())
    assert info["connected"] is False
    assert info["connection_generation"] == 1
    assert info["last_attempt"]["operation"] == "refresh"
    assert info["last_attempt"]["success"] is False


def test_check_tools_reports_manifest_generation(monkeypatch, clean_connection):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    state.configure_tool_profile("custom", {"listing"})
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    checked = json.loads(
        asyncio.run(static_tools.check_tools("alpha,beta,missing"))
    )
    assert checked["results"]["alpha"]["status"] == "callable"
    assert checked["results"]["beta"]["status"] == "not_loaded"
    assert checked["results"]["missing"]["status"] == "not_found"
    assert checked["manifest_sha256"] == state._connection.manifest_sha256
    assert checked["connection_generation"] == 1


def test_advertised_disassembly_tools_are_callable_or_return_server_error(
    monkeypatch, clean_connection
):
    schema = {
        "count": 2,
        "tools": [
            {
                "path": "/disassemble_bytes",
                "method": "POST",
                "params": [],
            },
            {
                "path": "/disassemble_flow",
                "method": "POST",
                "params": [],
            },
        ],
    }
    version = {**VERSION, "endpoint_count": 2}
    monkeypatch.setattr(
        static_tools.transport,
        "candidate_request",
        _wire_responses(version=version, schema=schema),
    )
    result = asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    assert result["callable_dynamic_count"] == 2
    tools = registry._adapter().snapshot()
    assert {"disassemble_bytes", "disassemble_flow"}.issubset(tools)
    monkeypatch.setattr(
        static_tools.transport,
        "do_request",
        lambda *_args, **_kwargs: ('{"error":"rejected"}', 404),
    )
    returned = json.loads(asyncio.run(tools["disassemble_bytes"].fn()))
    assert returned["error"] == 'HTTP 404: {"error":"rejected"}'


def test_candidate_build_is_never_observable_as_mixed_state(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    old_digest = state._connection.manifest_sha256
    changed = deepcopy(SCHEMA)
    changed["tools"][0]["description"] = "changed"
    entered = threading.Event()
    release = threading.Event()
    original = connection.fetch_staged_candidate

    def paused(mode, endpoint, profile=None):
        entered.set()
        release.wait(timeout=5)
        return original(mode, endpoint, profile)

    monkeypatch.setattr(connection, "fetch_staged_candidate", paused)
    monkeypatch.setattr(
        static_tools.transport,
        "candidate_request",
        _wire_responses(schema=changed),
    )

    worker = threading.Thread(
        target=lambda: asyncio.run(
            connection.handshake_candidate(
                "refresh",
                mode="tcp",
                endpoint="http://127.0.0.1:8089",
                project="A",
                ctx=None,
                failure_policy="clear",
            )
        )
    )
    worker.start()
    assert entered.wait(timeout=2)
    observed = []

    def read():
        observed.append(json.loads(static_tools.get_connection_info()))

    reader = threading.Thread(target=read)
    reader.start()
    time.sleep(0.05)
    release.set()
    worker.join(timeout=5)
    reader.join(timeout=5)
    assert len(observed) == 1
    assert observed[0]["manifest_sha256"] in {
        old_digest,
        state._connection.manifest_sha256,
    }
    assert observed[0]["callable_dynamic_count"] in {2}


def test_successful_and_failed_publication_are_observed_as_whole_bundles(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    changed = deepcopy(SCHEMA)
    changed["tools"][0]["description"] = "successful publication"
    monkeypatch.setattr(
        static_tools.transport,
        "candidate_request",
        _wire_responses(schema=changed),
    )
    entered = threading.Event()
    release = threading.Event()
    original_publish_bundle = registry._publish_bundle

    def paused_publish(dynamic, bundle):
        entered.set()
        release.wait(timeout=5)
        return original_publish_bundle(dynamic, bundle)

    monkeypatch.setattr(registry, "_publish_bundle", paused_publish)
    worker = threading.Thread(
        target=lambda: asyncio.run(
            connection.handshake_candidate(
                "refresh",
                mode="tcp",
                endpoint="http://127.0.0.1:8089",
                project="A",
                ctx=None,
                failure_policy="clear",
            )
        )
    )
    worker.start()
    assert entered.wait(timeout=2)
    observed = {}

    def observe():
        observed["info"] = json.loads(static_tools.get_connection_info())
        observed["check"] = json.loads(
            asyncio.run(static_tools.check_tools("alpha"))
        )

    reader = threading.Thread(target=observe)
    reader.start()
    time.sleep(0.05)
    release.set()
    worker.join(timeout=5)
    reader.join(timeout=5)
    assert observed["info"]["connection_generation"] == 2
    assert (
        observed["check"]["manifest_sha256"]
        == observed["info"]["manifest_sha256"]
    )
    assert (
        observed["check"]["connection_generation"]
        == observed["info"]["connection_generation"]
    )

    monkeypatch.setattr(
        registry, "_publish_bundle", original_publish_bundle
    )
    old_bundle = state._connection
    old_digest = old_bundle.manifest_sha256
    failed_schema = deepcopy(SCHEMA)
    failed_schema["tools"][0]["description"] = "failed publication"
    monkeypatch.setattr(
        static_tools.transport,
        "candidate_request",
        _wire_responses(schema=failed_schema),
    )
    entered.clear()
    release.clear()
    original_state_publish = state.publish_connection
    calls = 0

    def fail_paused_once(bundle):
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            release.wait(timeout=5)
            raise RuntimeError("injected publication failure")
        return original_state_publish(bundle)

    monkeypatch.setattr(state, "publish_connection", fail_paused_once)
    failed_result = {}

    def failed_switch():
        failed_result.update(
            asyncio.run(
                connection.handshake_candidate(
                    "switch",
                    mode="tcp",
                    endpoint="http://127.0.0.1:8090",
                    project="B",
                    ctx=None,
                    failure_policy="preserve",
                )
            )
        )

    worker = threading.Thread(target=failed_switch)
    worker.start()
    assert entered.wait(timeout=2)
    observed.clear()
    reader = threading.Thread(target=observe)
    reader.start()
    time.sleep(0.05)
    release.set()
    worker.join(timeout=5)
    reader.join(timeout=5)
    assert "error" in failed_result
    assert state._connection is old_bundle
    assert observed["info"]["connection_generation"] == 2
    assert observed["info"]["manifest_sha256"] == old_digest
    assert observed["check"]["manifest_sha256"] == old_digest


def test_stale_handler_identity_and_get_only_replay(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    alpha = registry._adapter().snapshot()["alpha"]
    calls = []

    def request(method, endpoint, **kwargs):
        calls.append((method, endpoint, kwargs))
        if len(calls) == 1:
            raise IncompleteRead(b"", 1)
        return '{"ok":true}', 200

    async def reconnect(_ctx, *, cause=None):
        with state._ghidra_lock:
            state.publish_connection(
                replace(
                    state._connection,
                    generation=state._connection.generation + 1,
                )
            )
        return {"connected": True, "connection_generation": 2}

    monkeypatch.setattr(static_tools.transport, "do_request", request)
    monkeypatch.setattr(static_tools, "_reconnect_active", reconnect)
    assert asyncio.run(alpha.fn()) == '{"ok":true}'
    assert [item[:2] for item in calls] == [
        ("GET", "/alpha"),
        ("GET", "/alpha"),
    ]

    with state._ghidra_lock:
        state.publish_connection(
            replace(
                state._connection,
                identities={**state._connection.identities, "alpha": ("GET", "/moved")},
            )
        )
    stale = json.loads(asyncio.run(alpha.fn()))
    assert stale["category"] == "stale-handler identity"


@pytest.mark.parametrize("replacement", ["changed", "missing"])
def test_actual_reconnect_rejects_changed_or_missing_handler_identity(
    monkeypatch, clean_connection, replacement
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    stale_alpha = registry._adapter().snapshot()["alpha"]
    if replacement == "changed":
        schema = deepcopy(SCHEMA)
        schema["tools"][0]["name"] = "alpha"
        schema["tools"][0]["path"] = "/moved"
        version = deepcopy(VERSION)
    else:
        schema = {"count": 1, "tools": [deepcopy(SCHEMA["tools"][1])]}
        version = {**VERSION, "endpoint_count": 1}
    monkeypatch.setattr(
        static_tools.transport,
        "candidate_request",
        _wire_responses(version=version, schema=schema),
    )
    monkeypatch.setattr(
        static_tools.discovery, "discover_all_instances", lambda: []
    )
    calls = 0

    def interrupted(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise IncompleteRead(b"", 1)

    monkeypatch.setattr(
        static_tools.transport, "do_request", interrupted
    )
    result = json.loads(asyncio.run(stale_alpha.fn()))
    assert result["category"] == "stale-handler identity"
    assert calls == 1
    assert state._connection.generation == 2
    assert state._connection.identities.get("alpha") != ("GET", "/alpha")


def test_post_reconnects_but_never_replays(monkeypatch, clean_connection):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    beta = registry._adapter().snapshot()["beta"]
    calls = 0

    def request(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise IncompleteRead(b"", 1)

    async def reconnect(_ctx, *, cause=None):
        with state._ghidra_lock:
            state.publish_connection(
                replace(
                    state._connection,
                    generation=state._connection.generation + 1,
                )
            )
        return {"connected": True, "connection_generation": 2}

    monkeypatch.setattr(static_tools.transport, "do_request", request)
    monkeypatch.setattr(static_tools, "_reconnect_active", reconnect)
    result = json.loads(asyncio.run(beta.fn()))
    assert result["category"] == "call not replayed"
    assert calls == 1


def test_registration_failure_rolls_back_eager_and_lazy_maps(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    original = registry._build_tool_object

    def fail_beta(definition):
        if definition["name"] == "beta":
            raise ValueError("injected")
        return original(definition)

    monkeypatch.setattr(registry, "_build_tool_object", fail_beta)
    failed = asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    assert failed["connected"] is False
    assert set(registry._adapter().snapshot()) == static_tools.STATIC_TOOL_NAMES

    monkeypatch.setattr(registry, "_build_tool_object", original)
    state.configure_tool_profile("custom", {"listing"})
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    previous_tool = registry._adapter().snapshot()["alpha"]
    monkeypatch.setattr(registry, "_build_tool_object", fail_beta)
    loaded = json.loads(asyncio.run(static_tools.load_tool_group("memory")))
    assert loaded["failure"]["category"] == "registration failure"
    assert registry._adapter().snapshot()["alpha"] is previous_tool
    assert "beta" not in registry._adapter().snapshot()

    monkeypatch.setattr(registry, "_build_tool_object", original)
    loaded = json.loads(asyncio.run(static_tools.load_tool_group("memory")))
    assert loaded["loaded"] == "memory"
    loaded_map = registry._adapter().snapshot()

    def fail_alpha(definition):
        if definition["name"] == "alpha":
            raise ValueError("injected unload failure")
        return original(definition)

    monkeypatch.setattr(registry, "_build_tool_object", fail_alpha)
    unloaded = json.loads(
        asyncio.run(static_tools.unload_tool_group("memory"))
    )
    assert unloaded["failure"]["category"] == "registration failure"
    restored = registry._adapter().snapshot()
    assert set(restored) == set(loaded_map)
    assert all(restored[name] is tool for name, tool in loaded_map.items())


def test_publication_failure_restores_exact_map_and_reports_server_identity(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    old_bundle = state._connection
    old_map = registry._adapter().snapshot()
    manifest = handshake.validate_handshake(
        deepcopy(VERSION), deepcopy(SCHEMA), static_tools.STATIC_TOOL_NAMES
    )
    staged = registry.build_staged_registry(manifest, None)
    original_publish = state.publish_connection
    calls = 0

    def fail_once(bundle):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("injected state publication failure")
        return original_publish(bundle)

    monkeypatch.setattr(state, "publish_connection", fail_once)
    with pytest.raises(handshake.HandshakeError) as exc:
        registry.publish_staged(
            staged,
            project="B",
            mode="tcp",
            endpoint="http://127.0.0.1:8090",
            generation=2,
            profile=state.resolve_tool_profile("full"),
        )
    assert exc.value.category == "registration failure"
    assert exc.value.server_identity == VERSION
    assert state._connection is old_bundle
    restored = registry._adapter().snapshot()
    assert set(restored) == set(old_map)
    assert all(restored[name] is tool for name, tool in old_map.items())


def test_handshake_publication_failure_keeps_candidate_identity(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    old_bundle = state._connection

    def reject_publication(*_args, **_kwargs):
        raise handshake.HandshakeError(
            "registration failure", "adapter rejected publication"
        )

    monkeypatch.setattr(registry, "publish_staged", reject_publication)
    failed = asyncio.run(
        connection.handshake_candidate(
            "switch",
            mode="tcp",
            endpoint="http://127.0.0.1:8090",
            project="B",
            ctx=None,
            failure_policy="preserve",
        )
    )
    assert state._connection is old_bundle
    assert failed["failure"]["server_identity"] == VERSION
    assert state._last_attempt["server_identity"] == VERSION


def test_reconnect_cannot_overwrite_concurrent_switch(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    entered = threading.Event()
    release = threading.Event()

    def paused_discovery():
        entered.set()
        release.wait(timeout=5)
        return [
            {
                "project": "A",
                "url": "http://127.0.0.1:8089",
                "tcp_reachable": True,
            }
        ]

    monkeypatch.setattr(
        static_tools.discovery, "discover_all_instances", paused_discovery
    )
    outcome = {}

    def reconnect():
        outcome.update(asyncio.run(static_tools._reconnect_active(None)))

    worker = threading.Thread(target=reconnect)
    worker.start()
    assert entered.wait(timeout=2)
    switched = asyncio.run(
        connection.handshake_candidate(
            "switch",
            mode="tcp",
            endpoint="http://127.0.0.1:8090",
            project="B",
            ctx=None,
            failure_policy="preserve",
        )
    )
    release.set()
    worker.join(timeout=5)
    assert switched["connected"] is True
    assert outcome["reconnect_aborted"] is True
    assert state._connection.project == "B"
    assert state._connection.generation == 2


def test_group_change_does_not_suppress_required_reconnect(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    state.configure_tool_profile("custom", {"listing"})
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    entered = threading.Event()
    release = threading.Event()

    def paused_discovery():
        entered.set()
        release.wait(timeout=5)
        return []

    monkeypatch.setattr(
        static_tools.discovery, "discover_all_instances", paused_discovery
    )
    outcome = {}

    def reconnect():
        outcome.update(asyncio.run(static_tools._reconnect_active(None)))

    worker = threading.Thread(target=reconnect)
    worker.start()
    assert entered.wait(timeout=2)
    loaded = json.loads(
        asyncio.run(static_tools.load_tool_group("memory"))
    )
    assert loaded["loaded"] == "memory"
    assert state._connection.generation == 1
    release.set()
    worker.join(timeout=5)
    assert outcome["connected"] is True
    assert outcome.get("reconnect_aborted") is not True
    assert state._connection.project == "A"
    assert state._connection.generation == 2
    assert state._last_attempt["operation"] == "reconnect"
    assert state._last_attempt["success"] is True


def test_failed_local_selection_is_recorded_as_switch(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    old_bundle = state._connection
    monkeypatch.setattr(
        static_tools.discovery, "discover_all_instances", lambda: []
    )
    returned = json.loads(
        asyncio.run(static_tools.connect_instance("missing"))
    )
    assert "error" in returned
    assert state._connection is old_bundle
    assert state._last_attempt["operation"] == "switch"


def test_notifications_follow_commits_and_failure_is_post_commit(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    sender = AsyncMock()
    ctx = SimpleNamespace(
        _request_context=object(),
        request_context=SimpleNamespace(
            session=SimpleNamespace(send_tool_list_changed=sender)
        ),
    )
    connected = asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=ctx,
            failure_policy="clear",
        )
    )
    assert connected["tools_changed"]["sent"] is True
    refreshed = asyncio.run(
        connection.handshake_candidate(
            "refresh",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=ctx,
            failure_policy="clear",
        )
    )
    assert refreshed["tools_changed"]["sent"] is True
    assert sender.await_count == 2
    assert state._connection.generation == 2

    sender.side_effect = RuntimeError("client closed")
    post_commit = asyncio.run(
        connection.handshake_candidate(
            "refresh",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=ctx,
            failure_policy="clear",
        )
    )
    assert post_commit["connected"] is True
    assert post_commit["connection_generation"] == 3
    assert post_commit["tools_changed"] == {
        "attempted": True,
        "sent": False,
        "error": "client closed",
    }
    assert state._last_attempt["tools_changed"] == post_commit["tools_changed"]


def test_notification_matrix_for_failures_switch_reconnect_and_groups(
    monkeypatch, clean_connection
):
    sender = AsyncMock()
    ctx = SimpleNamespace(
        _request_context=object(),
        request_context=SimpleNamespace(
            session=SimpleNamespace(send_tool_list_changed=sender)
        ),
    )
    bad = deepcopy(SCHEMA)
    bad["count"] = 99
    monkeypatch.setattr(
        static_tools.transport,
        "candidate_request",
        _wire_responses(schema=bad),
    )
    initial = asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=ctx,
            failure_policy="clear",
        )
    )
    assert initial["tools_changed"]["attempted"] is False
    assert sender.await_count == 0

    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    state.configure_tool_profile("custom", {"listing"})
    connected = asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=ctx,
            failure_policy="clear",
        )
    )
    assert connected["tools_changed"]["sent"] is True
    assert sender.await_count == 1

    loaded = json.loads(
        asyncio.run(static_tools.load_tool_group("memory", ctx))
    )
    assert loaded["tools_changed"]["sent"] is True
    assert sender.await_count == 2
    no_op_load = json.loads(
        asyncio.run(static_tools.load_tool_group("memory", ctx))
    )
    assert no_op_load["tools_changed"]["attempted"] is False
    assert sender.await_count == 2
    unloaded = json.loads(
        asyncio.run(static_tools.unload_tool_group("memory", ctx))
    )
    assert unloaded["tools_changed"]["sent"] is True
    assert sender.await_count == 3
    no_op_unload = json.loads(
        asyncio.run(static_tools.unload_tool_group("memory", ctx))
    )
    assert no_op_unload["tools_changed"]["attempted"] is False
    assert sender.await_count == 3

    monkeypatch.setattr(
        static_tools.transport,
        "candidate_request",
        _wire_responses(schema=bad),
    )
    failed_switch = asyncio.run(
        connection.handshake_candidate(
            "switch",
            mode="tcp",
            endpoint="http://127.0.0.1:8090",
            project="B",
            ctx=ctx,
            failure_policy="preserve",
        )
    )
    assert failed_switch["tools_changed"]["attempted"] is False
    assert sender.await_count == 3
    info = json.loads(static_tools.get_connection_info())
    assert info["project"] == "A"
    assert info["connection_generation"] == 1
    assert info["last_attempt"]["operation"] == "switch"

    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    switched = asyncio.run(
        connection.handshake_candidate(
            "switch",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=ctx,
            failure_policy="preserve",
        )
    )
    assert switched["tools_changed"]["sent"] is True
    assert sender.await_count == 4

    reconnected = asyncio.run(
        connection.handshake_candidate(
            "reconnect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=ctx,
            failure_policy="clear",
        )
    )
    assert reconnected["tools_changed"]["sent"] is True
    assert sender.await_count == 5

    monkeypatch.setattr(
        static_tools.transport,
        "candidate_request",
        _wire_responses(schema=bad),
    )
    failed_reconnect = asyncio.run(
        connection.handshake_candidate(
            "reconnect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=ctx,
            failure_policy="clear",
        )
    )
    assert failed_reconnect["connected"] is False
    assert failed_reconnect["tools_changed"]["sent"] is True
    assert sender.await_count == 6
    info = json.loads(static_tools.get_connection_info())
    assert info["connection_generation"] == 3
    assert info["last_attempt"]["operation"] == "reconnect"
    assert info["last_attempt"]["success"] is False


def test_post_create_handshake_cleanup_notifies_for_removed_active_map(
    monkeypatch, clean_connection
):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    asyncio.run(
        connection.handshake_candidate(
            "connect",
            mode="tcp",
            endpoint="http://127.0.0.1:8089",
            project="A",
            ctx=None,
            failure_policy="clear",
        )
    )
    monkeypatch.setattr(
        static_tools.discovery,
        "discover_all_instances",
        lambda: [
            {
                "project": "A",
                "socket": "/tmp/ghidra-a.sock",
                "uds_reachable": True,
                "tcp_reachable": False,
            }
        ],
    )
    monkeypatch.setattr(
        static_tools.transport,
        "uds_request",
        lambda *_args, **_kwargs: (
            json.dumps(
                {
                    "success": True,
                    "active": True,
                    "project": "New",
                    "path": "/projects/New",
                }
            ),
            200,
        ),
    )

    def fail_fetch(_mode, _endpoint, _profile):
        raise handshake.HandshakeError(
            "malformed schema", "injected post-create failure"
        )

    monkeypatch.setattr(
        static_tools.connection, "fetch_staged_candidate", fail_fetch
    )
    sender = AsyncMock()
    ctx = SimpleNamespace(
        _request_context=object(),
        request_context=SimpleNamespace(
            session=SimpleNamespace(send_tool_list_changed=sender)
        ),
    )
    result = json.loads(
        asyncio.run(
            static_tools.create_and_connect_project(
                "/projects", "New", ctx=ctx
            )
        )
    )
    assert result["created"] is True
    assert result["connected"] is False
    assert result["tools_changed"]["sent"] is True
    assert sender.await_count == 1
    assert state._connection.connected is False
    assert state._last_attempt["operation"] == "create-and-connect"
