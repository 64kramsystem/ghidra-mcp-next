"""HTTP over local Unix-domain sockets."""

import http.client
import json
import os
import socket
from pathlib import Path
from urllib.parse import urlencode

from .config import READ_TIMEOUT


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: int = READ_TIMEOUT):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def socket_dirs() -> list[Path]:
    user = os.getenv("USER") or "unknown"
    paths: list[Path] = []

    def add(path: Path) -> None:
        if path not in paths:
            paths.append(path)

    if value := os.getenv("XDG_RUNTIME_DIR"):
        add(Path(value) / "ghidra-mcp")
    if value := os.getenv("TMPDIR"):
        add(Path(value) / f"ghidra-mcp-{user}")
    for root in (Path("/var/folders"), Path("/private/var/folders")):
        try:
            for path in root.glob(f"*/*/T/ghidra-mcp-{user}"):
                add(path)
        except OSError:
            pass
    add(Path("/tmp") / f"ghidra-mcp-{user}")
    return paths


def request(
    socket_path: str,
    method: str,
    endpoint: str,
    *,
    query: dict | None = None,
    body: dict | None = None,
    timeout: int = READ_TIMEOUT,
) -> tuple[str, int]:
    path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    if query:
        path = f"{path}?{urlencode(query)}"
    payload = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    connection = UnixHTTPConnection(socket_path, timeout)
    try:
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        return response.read().decode("utf-8"), response.status
    finally:
        connection.close()
