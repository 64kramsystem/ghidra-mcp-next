"""Published bridge connection state."""

from dataclasses import dataclass, field
from threading import RLock
from typing import Any


@dataclass
class Connection:
    socket: str | None = None
    project: str | None = None
    server: dict[str, Any] | None = None
    dynamic_names: set[str] = field(default_factory=set)
    last_error: str | None = None

    @property
    def connected(self) -> bool:
        return self.socket is not None


lock = RLock()
connection = Connection()


def snapshot() -> dict[str, Any]:
    with lock:
        return {
            "connected": connection.connected,
            "project": connection.project,
            "socket": connection.socket,
            "server": connection.server,
            "tool_count": len(connection.dynamic_names),
            "last_error": connection.last_error,
        }
