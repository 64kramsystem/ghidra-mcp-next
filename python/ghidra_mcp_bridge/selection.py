"""Exact instance selection."""

import os


class InstanceSelectionError(ValueError):
    def __init__(self, message: str, available: list[dict]):
        super().__init__(message)
        self.available = available


def select(instances: list[dict], selector: str | None = None) -> dict:
    if selector is None:
        matches = instances
    else:
        wanted = os.path.abspath(os.path.expanduser(selector))
        matches = [
            item
            for item in instances
            if str(item.get("project")) == selector
            or str(item.get("pid")) == selector
            or os.path.abspath(str(item.get("socket", ""))) == wanted
        ]
    if not matches:
        raise InstanceSelectionError("No matching Ghidra instance.", instances)
    if len(matches) != 1:
        raise InstanceSelectionError(
            "Multiple Ghidra instances match; select a project, PID, or socket.",
            instances,
        )
    return matches[0]
