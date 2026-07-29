"""Start the local stdio bridge."""

from .server import mcp
from .static_tools import auto_connect


def main() -> None:
    auto_connect()
    mcp.run()
