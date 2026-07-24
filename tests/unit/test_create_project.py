"""Discovery, selection, and bootstrap tests for static create_project."""

import asyncio
import json
import os
import threading
from unittest import mock

import pytest

from bridge_mcp_ghidra import (
    config,
    discovery,
    handshake,
    registry,
    state,
    static_tools,
)
from bridge_mcp_ghidra.server import mcp


def _instance(**overrides):
    record = {
        "pid": 123,
        "project": "Example",
        "socket": "/tmp/ghidra-123.sock",
        "url": "http://127.0.0.1:8089",
        "uds_reachable": True,
        "tcp_reachable": True,
    }
    record.update(overrides)
    return record


@pytest.fixture
def clean_bridge_state():
    original_bundle = state._connection
    original_map = registry._adapter().snapshot()
    registry._adapter().replace_dynamic({})
    state.publish_connection(
        state.ConnectionBundle(
            connected=True,
            generation=1,
            project="Previous",
            transport="uds",
            endpoint="/tmp/previous.sock",
        )
    )
    try:
        yield
    finally:
        dynamic = {
            name: tool
            for name, tool in original_map.items()
            if name not in config.STATIC_TOOL_NAMES
        }
        registry._adapter().replace_dynamic(dynamic)
        state.publish_connection(original_bundle)


def _staged_project_manifest():
    version = {
        "plugin_name": "GhidraMCP",
        "plugin_version": "5.15.0",
        "build_timestamp": "dev",
        "build_number": "0",
        "full_version": "5.15.0 (build 0, dev)",
        "ghidra_version": "12.1.2",
        "java_version": "21",
        "endpoint_count": 1,
        "mode": "gui",
    }
    schema = {
        "count": 1,
        "tools": [
            {
                "path": "/create_project",
                "method": "POST",
                "category": "project",
                "params": [],
            }
        ],
    }
    return registry.build_staged_registry(
        handshake.validate_handshake(
            version, schema, config.STATIC_TOOL_NAMES
        ),
        None,
    )


def test_discovery_materializes_tcp_before_uds_and_merges_records(monkeypatch):
    events = []
    tcp_results = [
        ("http://127.0.0.1:8089", {"pid": 123, "project": "Example"})
    ]

    def iter_tcp():
        events.append("tcp")
        yield from tcp_results

    def discover_uds(tcp_instances=None):
        events.append("uds")
        assert tcp_instances == tcp_results
        return [
            {
                "pid": 123,
                "project": "Example",
                "socket": "/tmp/ghidra-123.sock",
                "uds_reachable": True,
            }
        ]

    monkeypatch.setattr(discovery, "_iter_tcp_instances", iter_tcp)
    monkeypatch.setattr(discovery, "discover_instances", discover_uds)
    monkeypatch.setattr(discovery, "discover_active_tcp_instance", lambda: None)

    instances = discovery.discover_all_instances()

    assert events == ["tcp", "uds"]
    assert instances == [
        {
            "pid": 123,
            "project": "Example",
            "url": "http://127.0.0.1:8089",
            "tcp_reachable": True,
            "socket": "/tmp/ghidra-123.sock",
            "uds_reachable": True,
        }
    ]


def test_deduplication_merges_same_pid_and_complementary_transports():
    records = [
        {
            "pid": 123,
            "project": "Example",
            "url": "http://localhost:8089/",
            "tcp_reachable": True,
        },
        {
            "pid": 123,
            "socket": "/tmp/ghidra-123.sock",
            "uds_reachable": True,
        },
    ]

    assert discovery._deduplicate_instances(records) == [
        {
            "pid": 123,
            "project": "Example",
            "url": "http://localhost:8089/",
            "tcp_reachable": True,
            "socket": "/tmp/ghidra-123.sock",
            "uds_reachable": True,
        }
    ]


def test_deduplication_never_merges_conflicting_known_pids():
    records = [
        _instance(pid=111, socket=None),
        _instance(pid=222, socket=None),
    ]

    merged = discovery._deduplicate_instances(records)

    assert [record["pid"] for record in merged] == [111, 222]


def test_deduplication_uses_normalized_endpoint_when_pids_are_compatible(tmp_path):
    socket_path = tmp_path / "ghidra.sock"
    records = [
        {
            "project": "Example",
            "socket": os.path.join(str(tmp_path), ".", "ghidra.sock"),
            "uds_reachable": False,
        },
        {
            "pid": 123,
            "socket": str(socket_path),
            "uds_reachable": True,
        },
        {
            "url": "HTTP://LOCALHOST:8089/",
            "tcp_reachable": False,
        },
        {
            "url": "http://127.0.0.1:8089",
            "tcp_reachable": True,
        },
    ]

    merged = discovery._deduplicate_instances(records)

    assert len(merged) == 2
    assert merged[0]["pid"] == 123
    assert merged[0]["uds_reachable"] is True
    assert merged[1]["tcp_reachable"] is True


def test_uds_discovery_records_probe_reachability(tmp_path, monkeypatch):
    good = tmp_path / "ghidra-101.sock"
    bad = tmp_path / "ghidra-202.sock"
    good.touch()
    bad.touch()

    monkeypatch.setattr(discovery.transport, "get_socket_dir_candidates", lambda: [tmp_path])
    monkeypatch.setattr(discovery.transport, "uds_supported", lambda: True)
    monkeypatch.setattr(discovery.validation, "is_pid_alive", lambda pid: True)

    def uds_request(socket, method, path, timeout):
        if socket == str(good):
            return json.dumps({"data": {"pid": 101, "project": "Good"}}), 200
        raise TimeoutError("probe failed")

    monkeypatch.setattr(discovery.transport, "uds_request", uds_request)

    instances = discovery.discover_instances(tcp_instances=[])

    assert instances == [
        {
            "socket": str(good),
            "pid": 101,
            "uds_reachable": True,
            "project": "Good",
        },
        {"socket": str(bad), "pid": 202, "uds_reachable": False},
    ]


def test_list_instances_uses_merged_discovery_and_preserves_connected_state(
    monkeypatch,
):
    merged = [_instance()]
    monkeypatch.setattr(discovery, "discover_all_instances", lambda: merged)
    monkeypatch.setattr(
        discovery,
        "discover_instances",
        mock.Mock(side_effect=AssertionError("legacy discovery should not run")),
    )
    monkeypatch.setattr(
        discovery,
        "discover_active_tcp_instance",
        mock.Mock(side_effect=AssertionError("active TCP should already be merged")),
    )
    monkeypatch.setattr(
        state,
        "_connection",
        state.ConnectionBundle(
            connected=True,
            transport="tcp",
            endpoint="http://127.0.0.1:8089",
        ),
    )

    result = json.loads(static_tools.list_instances())

    assert result["instances"][0]["connected"] is True


def test_list_instances_matches_connected_tcp_endpoint_after_normalization(
    monkeypatch,
):
    merged = [_instance(url="http://127.0.0.1:8089")]
    monkeypatch.setattr(discovery, "discover_all_instances", lambda: merged)
    monkeypatch.setattr(
        state,
        "_connection",
        state.ConnectionBundle(
            connected=True,
            transport="tcp",
            endpoint="http://localhost:8089/",
        ),
    )

    result = json.loads(static_tools.list_instances())

    assert result["instances"][0]["connected"] is True


def test_selection_automatically_uses_the_only_instance():
    selected, mode, endpoint = static_tools._select_instance([_instance()])

    assert selected["pid"] == 123
    assert mode == "uds"
    assert endpoint == "/tmp/ghidra-123.sock"


@pytest.mark.parametrize(
    "selector",
    [
        "123",
        os.path.join("/tmp", ".", "ghidra-123.sock"),
        "HTTP://LOCALHOST:8089/",
        "Example",
    ],
)
def test_selection_matches_each_exact_instance_identity(selector):
    selected, _, _ = static_tools._select_instance([_instance()], selector)

    assert selected["pid"] == 123


def test_selection_reports_no_running_instance_with_available_records():
    with pytest.raises(static_tools.InstanceSelectionError) as error:
        static_tools._select_instance([])

    assert "No running Ghidra instance" in str(error.value)
    assert error.value.available == []


def test_selection_rejects_omitted_selector_when_instances_are_ambiguous():
    instances = [_instance(pid=1), _instance(pid=2, socket="/tmp/ghidra-2.sock")]

    with pytest.raises(static_tools.InstanceSelectionError) as error:
        static_tools._select_instance(instances)

    assert "Multiple Ghidra instances" in str(error.value)
    assert error.value.available == instances


def test_selection_rejects_ambiguous_exact_project_name():
    instances = [
        _instance(pid=1, project="Same"),
        _instance(pid=2, project="Same", socket="/tmp/ghidra-2.sock"),
    ]

    with pytest.raises(static_tools.InstanceSelectionError) as error:
        static_tools._select_instance(instances, "Same")

    assert "ambiguous" in str(error.value).lower()
    assert error.value.available == instances


def test_selection_reports_requested_instance_not_found():
    instances = [_instance()]

    with pytest.raises(static_tools.InstanceSelectionError) as error:
        static_tools._select_instance(instances, "Missing")

    assert "not found" in str(error.value)
    assert error.value.available == instances


def test_selection_uses_tcp_when_uds_probe_failed():
    instance = _instance(uds_reachable=False, tcp_reachable=True)

    _, mode, endpoint = static_tools._select_instance([instance])

    assert mode == "tcp"
    assert endpoint == "http://127.0.0.1:8089"


def test_selection_rejects_instance_without_reachable_transport():
    instance = _instance(uds_reachable=False, tcp_reachable=False)

    with pytest.raises(static_tools.InstanceSelectionError) as error:
        static_tools._select_instance([instance])

    assert "no reachable transport" in str(error.value).lower()
    assert error.value.available == [instance]


def test_create_project_is_an_always_available_static_management_tool():
    assert "create_and_connect_project" in config.MANAGEMENT_TOOL_NAMES
    assert "create_and_connect_project" in config.STATIC_TOOL_NAMES
    assert "create_and_connect_project" in mcp._tool_manager._tools
    assert "create_project" not in config.STATIC_TOOL_NAMES


def test_schema_create_project_registers_beside_renamed_static_owner(
    clean_bridge_state,
):
    tool_def = {
        "name": "create_project",
        "description": "schema duplicate",
        "endpoint": "/create_project",
        "http_method": "POST",
        "category": "project",
        "input_schema": {"type": "object", "properties": {}},
    }
    assert registry._register_tool_def(tool_def) is True
    assert "create_project" in state._dynamic_tool_names
    assert "create_and_connect_project" in mcp._tool_manager._tools
    assert "create_project" in mcp._tool_manager._tools


def test_ghidra_request_lock_is_reentrant():
    acquired_first = state._ghidra_lock.acquire(timeout=0.1)
    acquired_second = False
    try:
        assert acquired_first
        acquired_second = state._ghidra_lock.acquire(blocking=False)
        assert acquired_second
    finally:
        if acquired_second:
            state._ghidra_lock.release()
        if acquired_first:
            state._ghidra_lock.release()

    assert isinstance(state._ghidra_lock, type(threading.RLock()))


def test_clear_dynamic_tools_removes_registered_and_cached_state():
    name = "create_project_stale_dynamic"
    existing = mcp._tool_manager._tools.get(name)
    original_names = list(state._dynamic_tool_names)
    original_schema = state._full_schema
    original_groups = set(state._loaded_groups)
    try:
        mcp._tool_manager._tools[name] = object()
        state._dynamic_tool_names[:] = [name]
        state._full_schema = [{"name": name}]
        state._loaded_groups.clear()
        state._loaded_groups.add("project")

        registry._clear_dynamic_tools()

        assert name not in mcp._tool_manager._tools
        assert state._dynamic_tool_names == []
        assert state._full_schema == []
        assert state._loaded_groups == set()
    finally:
        if existing is None:
            mcp._tool_manager._tools.pop(name, None)
        else:
            mcp._tool_manager._tools[name] = existing
        state._dynamic_tool_names[:] = original_names
        state._full_schema = original_schema
        state._loaded_groups.clear()
        state._loaded_groups.update(original_groups)


def test_schema_registration_clears_dynamic_state_through_shared_helper(
    clean_bridge_state,
):
    registry.register_tools_from_schema([])
    assert state._full_schema == []
    assert set(registry._adapter().snapshot()) == config.STATIC_TOOL_NAMES


@pytest.mark.parametrize("mode", ["uds", "tcp"])
def test_create_project_posts_directly_to_selected_transport(
    mode, monkeypatch, clean_bridge_state
):
    instance = _instance(
        uds_reachable=mode == "uds",
        tcp_reachable=mode == "tcp",
    )
    response = json.dumps(
        {
            "success": True,
            "project": "NewProject",
            "path": "/projects/NewProject",
            "active": True,
        }
    )
    uds_request = mock.Mock(return_value=(response, 200))
    tcp_request = mock.Mock(return_value=(response, 200))
    monkeypatch.setattr(discovery, "discover_all_instances", lambda: [instance])
    monkeypatch.setattr(static_tools.transport, "uds_request", uds_request)
    monkeypatch.setattr(static_tools.transport, "tcp_request", tcp_request)
    monkeypatch.setattr(
        static_tools.connection,
        "fetch_staged_candidate",
        lambda _mode, _endpoint, _profile: _staged_project_manifest(),
    )
    notify = mock.AsyncMock(
        return_value={"attempted": True, "sent": True, "error": None}
    )
    monkeypatch.setattr(
        static_tools.connection, "send_tools_changed", notify
    )

    result = json.loads(
        asyncio.run(
            static_tools.create_project("/projects", "NewProject")
        )
    )

    assert result["connected"] is True
    assert result["callable_dynamic_count"] == 1
    selected_request = uds_request if mode == "uds" else tcp_request
    other_request = tcp_request if mode == "uds" else uds_request
    args, kwargs = selected_request.call_args
    assert args[:3] == (
        instance["socket"] if mode == "uds" else instance["url"],
        "POST",
        "/create_project",
    )
    assert kwargs["json_data"] == {
        "parentDir": "/projects",
        "name": "NewProject",
    }
    other_request.assert_not_called()
    notify.assert_awaited_once_with(None, True)


def test_create_project_does_not_fallback_after_uncertain_uds_failure(
    monkeypatch, clean_bridge_state
):
    instance = _instance()
    monkeypatch.setattr(discovery, "discover_all_instances", lambda: [instance])
    monkeypatch.setattr(
        static_tools.transport,
        "uds_request",
        mock.Mock(side_effect=TimeoutError("outcome unknown")),
    )
    tcp_request = mock.Mock()
    monkeypatch.setattr(static_tools.transport, "tcp_request", tcp_request)
    clear = mock.Mock()
    monkeypatch.setattr(registry, "_clear_dynamic_tools", clear)

    with pytest.raises(RuntimeError, match="outcome unknown"):
        asyncio.run(static_tools.create_project("/projects", "NewProject"))

    tcp_request.assert_not_called()
    clear.assert_not_called()
    assert state._active_socket == "/tmp/previous.sock"
    assert state._connected_project == "Previous"


def test_create_project_gui_failure_preserves_previous_bridge_state(
    monkeypatch, clean_bridge_state
):
    instance = _instance()
    state._dynamic_tool_names.append("old_dynamic")
    state._full_schema = [{"name": "old_dynamic"}]
    state._loaded_groups.add("old_group")
    response = json.dumps(
        {
            "success": False,
            "category": "destination_exists",
            "message": "already exists",
        }
    )
    monkeypatch.setattr(discovery, "discover_all_instances", lambda: [instance])
    monkeypatch.setattr(
        static_tools.transport,
        "uds_request",
        mock.Mock(return_value=(response, 200)),
    )
    clear = mock.Mock()
    monkeypatch.setattr(registry, "_clear_dynamic_tools", clear)
    notify = mock.AsyncMock(
        return_value={"attempted": True, "sent": True, "error": None}
    )
    monkeypatch.setattr(registry, "_notify_tools_changed", notify)

    with pytest.raises(RuntimeError, match="destination_exists"):
        asyncio.run(static_tools.create_project("/projects", "NewProject"))

    clear.assert_not_called()
    notify.assert_not_awaited()
    assert state._active_socket == "/tmp/previous.sock"
    assert state._transport_mode == "uds"
    assert state._connected_project == "Previous"
    assert state._dynamic_tool_names == ["old_dynamic"]
    assert state._full_schema == [{"name": "old_dynamic"}]
    assert state._loaded_groups == {"old_group"}


def test_create_project_keeps_old_state_until_candidate_publication(
    monkeypatch, clean_bridge_state
):
    instance = _instance(
        uds_reachable=False,
        tcp_reachable=True,
        project="unknown",
    )
    events = []

    def tcp_request(*args, **kwargs):
        assert state._active_socket == "/tmp/previous.sock"
        assert state._connected_project == "Previous"
        events.append("post")
        return (
            json.dumps(
                {
                    "success": True,
                    "project": "NewProject",
                    "path": "/projects/NewProject",
                    "active": True,
                }
            ),
            200,
        )

    def fetch(mode, endpoint, _profile):
        events.append("fetch")
        assert mode == "tcp"
        assert endpoint == instance["url"]
        assert state._transport_mode == "uds"
        assert state._active_socket == "/tmp/previous.sock"
        assert state._connected_project == "Previous"
        return _staged_project_manifest()

    monkeypatch.setattr(discovery, "discover_all_instances", lambda: [instance])
    monkeypatch.setattr(static_tools.transport, "tcp_request", tcp_request)
    monkeypatch.setattr(
        static_tools.connection, "fetch_staged_candidate", fetch
    )
    notify = mock.AsyncMock(
        return_value={"attempted": True, "sent": True, "error": None}
    )
    monkeypatch.setattr(
        static_tools.connection, "send_tools_changed", notify
    )

    result = json.loads(
        asyncio.run(static_tools.create_project("/projects", "NewProject"))
    )

    assert events == ["post", "fetch"]
    assert result["created"] is True
    assert result["connected"] is True
    assert result["project"] == "NewProject"
    assert result["path"] == "/projects/NewProject"
    assert result["callable_dynamic_count"] == 1
    assert state._transport_mode == "tcp"
    assert state._active_tcp == instance["url"]
    notify.assert_awaited_once_with(None, True)


def test_create_project_refresh_failure_clears_partial_state_and_notifies(
    monkeypatch, clean_bridge_state
):
    instance = _instance()
    response = json.dumps(
        {
            "success": True,
            "project": "NewProject",
            "path": "/projects/NewProject",
            "active": True,
        }
    )
    monkeypatch.setattr(discovery, "discover_all_instances", lambda: [instance])
    monkeypatch.setattr(
        static_tools.transport,
        "uds_request",
        mock.Mock(return_value=(response, 200)),
    )

    def failed_fetch(_mode, _endpoint, _profile):
        raise handshake.HandshakeError(
            "malformed schema", "schema exploded"
        )

    monkeypatch.setattr(
        static_tools.connection, "fetch_staged_candidate", failed_fetch
    )
    notify = mock.AsyncMock(
        return_value={"attempted": False, "sent": False, "error": None}
    )
    monkeypatch.setattr(
        static_tools.connection, "send_tools_changed", notify
    )

    result = json.loads(
        asyncio.run(static_tools.create_project("/projects", "NewProject"))
    )

    assert result["created"] is True
    assert result["connected"] is False
    assert "schema exploded" in result["error"]
    assert state._transport_mode == "none"
    assert state._active_socket is None
    assert state._connected_project is None
    assert state._dynamic_tool_names == []
    assert state._full_schema == []
    assert state._loaded_groups == set()
    notify.assert_awaited_once_with(None, False)


def test_create_project_holds_lock_through_refresh_but_not_notification(
    monkeypatch, clean_bridge_state
):
    instance = _instance()
    response = json.dumps(
        {
            "success": True,
            "project": "NewProject",
            "path": "/projects/NewProject",
            "active": True,
        }
    )
    lock = TrackingLock()
    monkeypatch.setattr(state, "_ghidra_lock", lock)
    monkeypatch.setattr(discovery, "discover_all_instances", lambda: [instance])

    def uds_request(*args, **kwargs):
        assert lock.held
        return response, 200

    def fetch(_mode, _endpoint, _profile):
        assert lock.held
        return _staged_project_manifest()

    async def notify(ctx, attempted):
        assert not lock.held
        return {"attempted": attempted, "sent": False, "error": None}

    monkeypatch.setattr(static_tools.transport, "uds_request", uds_request)
    monkeypatch.setattr(
        static_tools.connection, "fetch_staged_candidate", fetch
    )
    monkeypatch.setattr(
        static_tools.connection, "send_tools_changed", notify
    )

    asyncio.run(static_tools.create_project("/projects", "NewProject"))

    assert lock.entries == 2


def test_import_file_dispatches_immediately_through_new_target(
    monkeypatch, clean_bridge_state
):
    instance = _instance()
    response = json.dumps(
        {
            "success": True,
            "project": "NewProject",
            "path": "/projects/NewProject",
            "active": True,
        }
    )
    monkeypatch.setattr(discovery, "discover_all_instances", lambda: [instance])
    monkeypatch.setattr(
        static_tools.transport,
        "uds_request",
        mock.Mock(return_value=(response, 200)),
    )
    monkeypatch.setattr(
        static_tools.connection,
        "fetch_staged_candidate",
        lambda _mode, _endpoint, _profile: _staged_project_manifest(),
    )
    monkeypatch.setattr(
        static_tools.connection,
        "send_tools_changed",
        mock.AsyncMock(
            return_value={"attempted": True, "sent": True, "error": None}
        ),
    )
    asyncio.run(static_tools.create_project("/projects", "NewProject"))

    async def import_post(
        tool_name,
        method,
        endpoint,
        *,
        query_params,
        body,
        ctx,
    ):
        assert state._transport_mode == "uds"
        assert state._active_socket == instance["socket"]
        assert state._connected_project == "NewProject"
        assert tool_name == "import_file"
        assert method == "POST"
        assert endpoint == "/import_file"
        assert body["file_path"] == "/samples/program.exe"
        return json.dumps({"success": True})

    post = mock.AsyncMock(side_effect=import_post)
    monkeypatch.setattr(static_tools.dispatch, "dispatch_dynamic", post)

    result = json.loads(
        asyncio.run(static_tools.import_file("/samples/program.exe"))
    )

    assert result["success"] is True
    post.assert_awaited_once()


class TrackingLock:
    def __init__(self):
        self.held = False
        self.entries = 0

    def __enter__(self):
        assert not self.held
        self.held = True
        self.entries += 1
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.held = False
        return False
