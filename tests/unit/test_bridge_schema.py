import inspect
import json

import pytest

from ghidra_mcp_bridge import dispatch, registry, schema


def tool_schema():
    return {
        "tools": [
            {
                "path": "/read_memory",
                "method": "GET",
                "params": [
                    {"name": "address", "type": "string", "required": True},
                    {
                        "name": "length",
                        "type": "integer",
                        "default": "16",
                    },
                ],
            },
            {
                "path": "/add_references",
                "method": "POST",
                "params": [
                    {
                        "name": "program",
                        "type": "string",
                        "source": "query",
                    },
                    {
                        "name": "references",
                        "type": "array",
                        "source": "body",
                        "required": True,
                        "schema": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "from": {"type": "string"},
                                    "to": {"type": "string"},
                                },
                            },
                        },
                    },
                ],
            },
        ]
    }


def test_parse_and_generated_signature():
    definitions = schema.parse(tool_schema())
    function = registry.build_handler(definitions[0])
    signature = inspect.signature(function)
    assert signature.parameters["address"].default is inspect.Parameter.empty
    assert signature.parameters["length"].default == 16


def test_slash_in_server_tool_name_becomes_underscore():
    raw = {
        "tools": [
            {
                "path": "/debugger/attach",
                "method": "POST",
                "params": [],
            }
        ]
    }
    definition = schema.parse(raw)[0]
    assert definition["name"] == "debugger_attach"
    assert definition["endpoint"] == "/debugger/attach"


def test_generated_get_and_post_routing(monkeypatch):
    calls = []
    monkeypatch.setattr(
        dispatch,
        "dispatch",
        lambda method, endpoint, **kwargs: calls.append(
            (method, endpoint, kwargs)
        )
        or "{}",
    )
    get, post = schema.parse(tool_schema())
    registry.build_handler(get)(address="c000", length=8)
    registry.build_handler(post)(
        program="game", references=[{"from": "1000", "to": "2000"}]
    )
    assert calls[0] == (
        "GET",
        "/read_memory",
        {"query": {"address": "c000", "length": 8}, "body": None},
    )
    assert calls[1][2]["query"] == {"program": "game"}
    assert calls[1][2]["body"]["references"][0]["to"] == "2000"


def test_native_nested_schema_is_preserved(monkeypatch):
    definition = schema.parse(tool_schema())[1]
    tools = registry.build_tools([definition])
    monkeypatch.setattr(registry.state.connection, "dynamic_names", set())
    registry.publish(tools)
    try:
        published = registry.mcp._tool_manager.get_tool("add_references")
        items = published.parameters["properties"]["references"]["items"]
        assert items["properties"]["from"]["type"] == "string"
        assert "source" not in published.parameters["properties"]["program"]
    finally:
        registry.mcp.remove_tool("add_references")


def test_json_and_any_publish_as_unrestricted_valid_schemas(monkeypatch):
    raw = {
        "tools": [
            {
                "path": "/accept_values",
                "method": "POST",
                "params": [
                    {"name": "json_value", "type": "json", "source": "body"},
                    {"name": "any_value", "type": "any", "source": "body"},
                ],
            }
        ]
    }
    tools = registry.build_tools(schema.parse(raw))
    monkeypatch.setattr(registry.state.connection, "dynamic_names", set())
    registry.publish(tools)
    try:
        properties = registry.mcp._tool_manager.get_tool(
            "accept_values"
        ).parameters["properties"]
        assert "type" not in properties["json_value"]
        assert "type" not in properties["any_value"]
    finally:
        registry.mcp.remove_tool("accept_values")


def test_empty_client_defaults_are_not_forwarded(monkeypatch):
    calls = []
    monkeypatch.setattr(
        dispatch,
        "dispatch",
        lambda method, endpoint, **kwargs: calls.append(kwargs) or "{}",
    )
    definition = schema.parse(tool_schema())[0]
    registry.build_handler(definition)(address="c000", length="")
    assert calls == [{"query": {"address": "c000"}, "body": None}]


def test_meaningful_empty_string_without_default_is_forwarded(monkeypatch):
    calls = []
    monkeypatch.setattr(
        dispatch,
        "dispatch",
        lambda method, endpoint, **kwargs: calls.append(kwargs) or "{}",
    )
    definition = schema.parse(
        {
            "tools": [
                {
                    "path": "/set_comment",
                    "method": "POST",
                    "params": [
                        {
                            "name": "comment",
                            "type": "string",
                            "source": "body",
                            "required": True,
                        }
                    ],
                }
            ]
        }
    )[0]
    registry.build_handler(definition)(comment="")
    assert calls == [{"query": None, "body": {"comment": ""}}]


@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"tools": [{"path": "/list_instances"}]},
        {
            "tools": [
                {"path": "/same"},
                {"path": "/same"},
            ]
        },
        {"tools": [{"path": "/bad name"}]},
        {"tools": [{"path": "/x", "method": "DELETE"}]},
        {
            "tools": [
                {
                    "path": "/x",
                    "params": [{"name": "value", "type": "address"}],
                }
            ]
        },
    ],
)
def test_invalid_schema_is_rejected(raw):
    with pytest.raises(ValueError):
        schema.parse(raw)
