import json
from copy import deepcopy

import pytest

from bridge_mcp_ghidra import handshake


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

