import asyncio
import json

import pytest

from ghidra_mcp_bridge import connection, registry, state, static_tools


@pytest.fixture(autouse=True)
def clean_connection():
    registry.clear()
    yield
    registry.clear()


def one_instance():
    return [{"socket": "/tmp/ghidra.sock", "project": "Old", "pid": 3}]


def test_create_project_posts_once_then_connects(monkeypatch):
    monkeypatch.setattr(
        static_tools.discovery, "discover_instances", one_instance
    )
    calls = []

    def create(socket, parent, name):
        calls.append((socket, parent, name))
        return {"success": True, "project": name, "path": f"{parent}/{name}"}, 200

    monkeypatch.setattr(connection, "create_project", create)
    monkeypatch.setattr(
        connection,
        "connect",
        lambda socket, project: {
            "connected": True,
            "project": project,
            "socket": socket,
        },
    )
    result = json.loads(
        asyncio.run(
            static_tools.create_and_connect_project("/projects", "New")
        )
    )
    assert calls == [("/tmp/ghidra.sock", "/projects", "New")]
    assert result["created"] is True


def test_create_is_not_retried_when_transport_fails(monkeypatch):
    monkeypatch.setattr(
        static_tools.discovery, "discover_instances", one_instance
    )
    calls = 0

    def fail(*args):
        nonlocal calls
        calls += 1
        raise OSError("uncertain")

    monkeypatch.setattr(connection, "create_project", fail)
    result = json.loads(
        asyncio.run(
            static_tools.create_and_connect_project("/projects", "New")
        )
    )
    assert calls == 1
    assert result == {"created": False, "error": "uncertain"}


def test_successful_create_with_schema_failure_clears_old_tools(monkeypatch):
    monkeypatch.setattr(
        static_tools.discovery, "discover_instances", one_instance
    )
    state.connection = state.Connection(
        socket="/tmp/ghidra.sock",
        project="Old",
        dynamic_names=set(),
    )
    monkeypatch.setattr(
        connection,
        "create_project",
        lambda *args: (
            {"success": True, "project": "New", "path": "/projects/New"},
            200,
        ),
    )
    monkeypatch.setattr(
        connection,
        "connect",
        lambda *args: (_ for _ in ()).throw(ValueError("bad schema")),
    )
    result = json.loads(
        asyncio.run(
            static_tools.create_and_connect_project("/projects", "New")
        )
    )
    assert result["created"] is True
    assert state.connection.connected is False
