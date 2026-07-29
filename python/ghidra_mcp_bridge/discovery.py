"""Discover local Ghidra plugin sockets."""

import json

from . import transport


def unwrap(text: str):
    value = json.loads(text)
    if isinstance(value, dict) and "data" in value:
        return value["data"]
    return value


def discover_instances() -> list[dict]:
    instances: list[dict] = []
    seen: set[str] = set()
    seen_pids: set[str] = set()
    for directory in transport.socket_dirs():
        try:
            sockets = sorted(directory.glob("*.sock"))
        except OSError:
            continue
        for path in sockets:
            identity = str(path.resolve())
            if identity in seen:
                continue
            try:
                text, status = transport.request(
                    str(path), "GET", "/mcp/instance_info", timeout=2
                )
                info = unwrap(text)
            except Exception:
                continue
            if status != 200 or not isinstance(info, dict):
                continue
            pid = str(info.get("pid", ""))
            if pid and pid in seen_pids:
                continue
            seen.add(identity)
            if pid:
                seen_pids.add(pid)
            instances.append({**info, "socket": str(path)})
    return instances
