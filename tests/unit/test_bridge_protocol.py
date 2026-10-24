import asyncio
import json

import anyio
import pytest
from mcp import Client
from mcp.client.subscriptions import ToolsListChanged

from ghidra_mcp_bridge import (
    config,
    connection,
    registry,
    static_tools,
    transport,
)


def test_current_protocol_refreshes_tool_list_and_calls_dynamic_tool(monkeypatch):
    calls = []

    def request(socket, method, endpoint, **kwargs):
        calls.append((method, endpoint, kwargs))
        if endpoint == "/get_version":
            return json.dumps({"plugin_version": "test"}), 200
        if endpoint == "/mcp/schema":
            return json.dumps(
                {
                    "tools": [
                        {
                            "path": "/read_memory",
                            "method": "GET",
                            "params": [
                                {
                                    "name": "address",
                                    "type": "string",
                                    "required": True,
                                },
                            ],
                        },
                    ],
                }
            ), 200
        assert endpoint == "/read_memory"
        return json.dumps({"hex": "cafe"}), 200

    monkeypatch.setattr(transport, "request", request)
    monkeypatch.setattr(
        static_tools.discovery,
        "discover_instances",
        lambda: [{"socket": "/tmp/test-ghidra.sock", "project": "Test"}],
    )

    async def run():
        async with Client(registry.mcp, mode="2026-07-28") as client:
            listing = await client.list_tools()
            assert len(listing.tools) == 5
            connect_tool = next(t for t in listing.tools if t.name == "connect_instance")
            assert "ctx" not in connect_tool.input_schema["properties"]
            async with client.listen(tools_list_changed=True) as changes:
                connected = await client.call_tool("connect_instance", {"project": "Test"})
                assert not connected.is_error
                assert json.loads(connected.content[0].text)["connected"] is True
                with anyio.fail_after(5):
                    assert isinstance(await anext(changes), ToolsListChanged)

                listing = await client.list_tools()
                dynamic = next(t for t in listing.tools if t.name == "read_memory")
                assert dynamic.input_schema["required"] == ["address"]
                assert "source" not in dynamic.input_schema["properties"]["address"]
                result = await client.call_tool("read_memory", {"address": "c000"})
                assert not result.is_error
                assert json.loads(result.content[0].text) == {"hex": "cafe"}

                refreshed = await client.call_tool("refresh_connection", {})
                assert not refreshed.is_error
                assert "notification_error" not in json.loads(refreshed.content[0].text)
                with anyio.fail_after(5):
                    assert isinstance(await anext(changes), ToolsListChanged)

    registry.clear()
    try:
        asyncio.run(run())
    finally:
        registry.clear()
    assert (
        "GET",
        "/read_memory",
        {"query": {"address": "c000"}, "body": None, "timeout": config.READ_TIMEOUT},
    ) in calls


@pytest.mark.parametrize("failure", ["unavailable_schema", "partial_registration"])
def test_failed_refresh_keeps_previous_tools_callable(monkeypatch, failure):
    tool_names = ["original_tool"]

    def request(socket, method, endpoint, **kwargs):
        if endpoint == "/get_version":
            return json.dumps({"plugin_version": "test"}), 200
        if endpoint == "/mcp/schema":
            return json.dumps(
                {
                    "tools": [
                        {"name": name, "path": f"/{name}", "method": "GET", "params": []}
                        for name in tool_names
                    ]
                }
            ), 200
        assert endpoint == "/original_tool"
        return json.dumps({"original": True}), 200

    monkeypatch.setattr(transport, "request", request)
    monkeypatch.setattr(
        static_tools.discovery,
        "discover_instances",
        lambda: [{"socket": "/tmp/test-ghidra.sock", "project": "Test"}],
    )

    async def run():
        async with Client(registry.mcp, mode="2026-07-28") as client:
            connection.connect("/tmp/test-ghidra.sock", "Test")
            if failure == "unavailable_schema":
                def fail_schema(socket, method, endpoint, **kwargs):
                    if endpoint == "/mcp/schema":
                        raise OSError("schema unavailable")
                    return request(socket, method, endpoint, **kwargs)

                monkeypatch.setattr(transport, "request", fail_schema)
                expected_error = "schema unavailable"
            else:
                original_add_tool = registry.mcp.add_tool

                def reject_second_tool(fn, **kwargs):
                    if kwargs.get("name") == "rejected_tool":
                        raise ValueError("registration rejected")
                    return original_add_tool(fn, **kwargs)

                monkeypatch.setattr(registry.mcp, "add_tool", reject_second_tool)
                tool_names[:] = ["candidate_tool", "rejected_tool"]
                expected_error = "registration rejected"

            refreshed = await client.call_tool("refresh_connection", {})
            assert json.loads(refreshed.content[0].text)["error"] == expected_error
            listing = await client.list_tools()
            names = {tool.name for tool in listing.tools}
            assert "original_tool" in names
            assert "candidate_tool" not in names
            assert "rejected_tool" not in names
            result = await client.call_tool("original_tool", {})
            assert not result.is_error
            assert json.loads(result.content[0].text) == {"original": True}

    registry.clear()
    try:
        asyncio.run(run())
    finally:
        registry.clear()
