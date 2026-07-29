"""Small shared configuration for the local bridge."""

import logging

READ_TIMEOUT = 120
WRITE_TIMEOUT = 300
STATIC_TOOL_NAMES = {
    "list_instances",
    "connect_instance",
    "create_and_connect_project",
    "get_connection_info",
    "refresh_connection",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ghidra_mcp_bridge")
