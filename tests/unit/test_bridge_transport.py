import http.server
import json
import socket
import socketserver
import tempfile
import threading
from pathlib import Path

import pytest

from ghidra_mcp_bridge import discovery, transport


class Handler(http.server.BaseHTTPRequestHandler):
    def reply(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(200, {"path": self.path})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.reply(
            200,
            {
                "path": self.path,
                "body": json.loads(self.rfile.read(length)) if length else None,
            },
        )

    def address_string(self):
        return "local"

    def log_message(self, *_):
        pass


class UnixServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name = "uds"
        self.server_port = 0


@pytest.fixture
def uds_server():
    with tempfile.TemporaryDirectory(dir="/tmp") as directory:
        path = str(Path(directory) / "test.sock")
        server = UnixServer(path, Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield path
        finally:
            server.shutdown()
            server.server_close()


def test_request_get_and_post(uds_server):
    text, status = transport.request(
        uds_server, "GET", "/read", query={"address": "1000"}
    )
    assert status == 200
    assert json.loads(text)["path"] == "/read?address=1000"

    text, status = transport.request(
        uds_server, "POST", "/write", body={"value": 7}
    )
    assert status == 200
    assert json.loads(text)["body"] == {"value": 7}


def test_request_missing_socket_raises(tmp_path):
    with pytest.raises(OSError):
        transport.request(str(tmp_path / "missing.sock"), "GET", "/health")


def test_socket_dirs_cover_runtime_locations(monkeypatch):
    monkeypatch.setenv("USER", "tester")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1")
    monkeypatch.setenv("TMPDIR", "/tmp/custom")
    paths = transport.socket_dirs()
    assert Path("/run/user/1/ghidra-mcp") in paths
    assert Path("/tmp/custom/ghidra-mcp-tester") in paths
    assert Path("/tmp/ghidra-mcp-tester") in paths


def test_discovery_queries_and_deduplicates(monkeypatch, tmp_path):
    first = tmp_path / "a.sock"
    second = tmp_path / "b.sock"
    first.touch()
    second.touch()
    monkeypatch.setattr(transport, "socket_dirs", lambda: [tmp_path])
    monkeypatch.setattr(
        transport,
        "request",
        lambda *args, **kwargs: (
            json.dumps({"data": {"pid": 9, "project": "P"}}),
            200,
        ),
    )
    result = discovery.discover_instances()
    assert len(result) == 1
    assert result[0]["project"] == "P"
