"""Selection of one reachable Ghidra instance from discovery records."""

import json

from . import discovery
from . import transport


class InstanceSelectionError(ValueError):
    """Instance selection failed before a mutating request was sent."""

    def __init__(self, message: str, available: list[dict]):
        super().__init__(message)
        self.available = available


def _matches_instance(record: dict, selector: str) -> bool:
    pid = discovery._known_pid(record)
    if pid is not None and str(pid) == selector:
        return True
    if record.get("project") == selector:
        return True

    record_socket = discovery._normalize_socket_path(record.get("socket"))
    selector_socket = discovery._normalize_socket_path(selector)
    if record_socket and record_socket == selector_socket:
        return True

    record_url = discovery._normalize_tcp_url(record.get("url"))
    selector_url = discovery._normalize_tcp_url(selector)
    return bool(record_url and record_url == selector_url)


def _select_instance(
    instances: list[dict], instance: str | None = None
) -> tuple[dict, str, str]:
    """Select exactly one record and its proven reachable transport."""
    if not instances:
        raise InstanceSelectionError(
            "No running Ghidra instance found.", instances
        )

    if instance is None:
        if len(instances) != 1:
            raise InstanceSelectionError(
                "Multiple Ghidra instances are available; specify instance.",
                instances,
            )
        selected = instances[0]
    else:
        selector = str(instance)
        matches = [
            record for record in instances if _matches_instance(record, selector)
        ]
        if not matches:
            matches = [
                record
                for record in instances
                if selector.lower()
                in str(record.get("project", "")).lower()
            ]
        if not matches:
            raise InstanceSelectionError(
                f"Requested instance '{selector}' was not found.", instances
            )
        if len(matches) != 1:
            raise InstanceSelectionError(
                f"Instance selector '{selector}' is ambiguous.", instances
            )
        selected = matches[0]

    uds_reachable = selected.get("uds_reachable")
    if uds_reachable is None:
        uds_reachable = bool(selected.get("socket")) and transport.uds_supported()
    tcp_reachable = selected.get("tcp_reachable")
    if tcp_reachable is None:
        tcp_reachable = bool(selected.get("url"))
    if uds_reachable and selected.get("socket"):
        return selected, "uds", str(selected["socket"])
    if tcp_reachable and selected.get("url"):
        return selected, "tcp", str(selected["url"])
    raise InstanceSelectionError(
        "Selected Ghidra instance has no reachable transport.", instances
    )


def _selection_tool_error(error: InstanceSelectionError) -> RuntimeError:
    return RuntimeError(
        json.dumps({"error": str(error), "available": error.available})
    )


def _instance_summary(instance: dict) -> dict:
    return {
        key: instance[key]
        for key in ("pid", "socket", "url")
        if instance.get(key) is not None
    }
