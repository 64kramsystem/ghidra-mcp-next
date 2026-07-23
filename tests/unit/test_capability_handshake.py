import json
import asyncio
import threading
import time
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from bridge_mcp_ghidra import handshake
from bridge_mcp_ghidra import connection, registry, state, static_tools


VERSION = {
    "plugin_name": "GhidraMCP",
    "plugin_version": "5.15.0",
    "build_timestamp": "20260723-201928",
    "build_number": "20260723-201928",
    "full_version": "5.15.0 (build 20260723-201928, 20260723-201928)",
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

    duplicate_name = deepcopy(SCHEMA)
    duplicate_name["tools"][1]["name"] = "alpha"
    with pytest.raises(handshake.HandshakeError) as exc:
        handshake.validate_handshake(deepcopy(VERSION), duplicate_name)
    assert exc.value.category == "normalized-name collision"


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
    original_defaults = set(state._default_groups)
    with state._ghidra_lock:
        registry._adapter().replace_dynamic({})
        state._connection = state.ConnectionBundle()
        state._last_attempt = None
        state.publish_connection(state._connection)
        state._lazy_mode = False
        state._default_groups = original_defaults
    yield
    with state._ghidra_lock:
        registry._adapter().replace_dynamic({})
        state._connection = state.ConnectionBundle()
        state._last_attempt = None
        state.publish_connection(state._connection)
        state._lazy_mode = False
        state._default_groups = original_defaults


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


def test_lazy_handshake_and_atomic_group_load(monkeypatch, clean_connection):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    state._lazy_mode = True
    state._default_groups = {"listing"}
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
    assert state._connection.dynamic_names == ("alpha",)
    loaded = json.loads(asyncio.run(static_tools.load_tool_group("memory")))
    assert loaded["new_tool_names"] == ["beta"]
    assert state._connection.generation == 1
    assert state._connection.callable_dynamic_count == 2


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


def test_check_tools_reports_manifest_generation(monkeypatch, clean_connection):
    monkeypatch.setattr(
        static_tools.transport, "candidate_request", _wire_responses()
    )
    state._lazy_mode = True
    state._default_groups = {"listing"}
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

    def paused(mode, endpoint):
        entered.set()
        release.wait(timeout=5)
        return original(mode, endpoint)

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
            raise ConnectionResetError("restart")
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
        raise ConnectionResetError("uncertain")

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
    state._lazy_mode = True
    state._default_groups = {"listing"}
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
