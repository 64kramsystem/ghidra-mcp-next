"""One-shot dispatch to the selected Ghidra socket."""

import json

from . import state, transport
from .config import READ_TIMEOUT, WRITE_TIMEOUT


def dispatch(
    method: str,
    endpoint: str,
    *,
    query: dict | None = None,
    body: dict | None = None,
) -> str:
    with state.lock:
        socket_path = state.connection.socket
        if socket_path is None:
            return json.dumps(
                {"error": "No Ghidra instance connected. Call connect_instance."}
            )
        try:
            text, status = transport.request(
                socket_path,
                method,
                endpoint,
                query=query,
                body=body,
                timeout=WRITE_TIMEOUT if method == "POST" else READ_TIMEOUT,
            )
        except Exception as error:
            state.connection.last_error = str(error)
            return json.dumps(
                {
                    "error": str(error),
                    "hint": "Call refresh_connection after Ghidra is available.",
                }
            )
    if status == 200:
        return text
    return json.dumps({"error": f"HTTP {status}: {text.strip()}"})
