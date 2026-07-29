import asyncio
import json

import pytest

from ghidra_mcp_bridge import (
    config,
    connection,
    registry,
    state,
    static_tools,
    transport,
)


SCHEMA = {
    "tools": [
        {
            "name": "ping_program",
            "path": "/ping_program",
            "method": "GET",
            "params": [],
        }
    ]
}


@pytest.fixture(autouse=True)
def clean_connection():
    registry.clear()
    yield
    registry.clear()


def responses(socket, method, endpoint, **kwargs):
    if endpoint == "/get_version":
        return json.dumps({"plugin_version": "1.0"}), 200
    if endpoint == "/mcp/schema":
        return json.dumps(SCHEMA), 200
    raise AssertionError(endpoint)


def test_connect_publishes_all_schema_tools(monkeypatch):
    monkeypatch.setattr(transport, "request", responses)
    result = connection.connect("/tmp/a.sock", "Project")
    assert result["connected"]
    assert result["tool_count"] == 1
    assert registry.mcp._tool_manager.get_tool("ping_program") is not None


def test_failed_refresh_preserves_old_connection_and_tools(monkeypatch):
    monkeypatch.setattr(transport, "request", responses)
    connection.connect("/tmp/a.sock", "Project")
    monkeypatch.setattr(
        transport,
        "request",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("offline")),
    )
    with pytest.raises(OSError):
        connection.connect("/tmp/a.sock", "Project")
    assert state.connection.socket == "/tmp/a.sock"
    assert registry.mcp._tool_manager.get_tool("ping_program") is not None
    assert state.connection.last_error == "offline"


def test_dispatch_is_one_shot_and_reports_refresh(monkeypatch):
    state.connection = state.Connection(socket="/tmp/a.sock", project="Project")
    calls = 0

    def fail(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise OSError("closed")

    monkeypatch.setattr(transport, "request", fail)
    result = json.loads(registry.dispatch.dispatch("POST", "/write", body={"x": 1}))
    assert calls == 1
    assert "refresh_connection" in result["hint"]


@pytest.mark.parametrize(
    ("method", "expected"),
    [("GET", config.READ_TIMEOUT), ("POST", config.WRITE_TIMEOUT)],
)
def test_dispatch_uses_method_timeout(monkeypatch, method, expected):
    state.connection = state.Connection(socket="/tmp/a.sock", project="Project")
    calls = []
    monkeypatch.setattr(
        transport,
        "request",
        lambda *args, **kwargs: calls.append(kwargs) or ("{}", 200),
    )
    registry.dispatch.dispatch(method, "/operation")
    assert calls[0]["timeout"] == expected


def test_static_surface_is_exact():
    names = set(registry.mcp._tool_manager._tools)
    assert names == {
        "list_instances",
        "connect_instance",
        "create_and_connect_project",
        "get_connection_info",
        "refresh_connection",
    }


def test_list_instances_marks_active(monkeypatch):
    state.connection = state.Connection(socket="/tmp/a.sock", project="P")
    monkeypatch.setattr(
        static_tools.discovery,
        "discover_instances",
        lambda: [{"socket": "/tmp/a.sock", "project": "P"}],
    )
    result = json.loads(static_tools.list_instances())
    assert result["instances"][0]["connected"] is True


def test_connect_instance_selects_exact_project(monkeypatch):
    monkeypatch.setattr(
        static_tools.discovery,
        "discover_instances",
        lambda: [{"socket": "/tmp/a.sock", "project": "P"}],
    )
    monkeypatch.setattr(transport, "request", responses)
    result = json.loads(asyncio.run(static_tools.connect_instance("P")))
    assert result["project"] == "P"
