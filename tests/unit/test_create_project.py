"""Discovery, selection, and bootstrap tests for static create_project."""

import json
import os
from unittest import mock

import pytest

from bridge_mcp_ghidra import discovery, state, static_tools


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
    monkeypatch.setattr(state, "_transport_mode", "tcp")
    monkeypatch.setattr(state, "_active_tcp", "http://127.0.0.1:8089")
    monkeypatch.setattr(state, "_active_socket", None)

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
