"""FastMCP application instance and entry point."""

import logging

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# The gql aiohttp transport logs full GraphQL requests/responses at INFO, which
# can include Monarch account payloads. Raise its floor to WARNING so those
# payloads are not written to logs. Transport-level errors still surface; drop
# this to INFO/DEBUG temporarily if you need to trace GraphQL traffic.
logging.getLogger("gql.transport.aiohttp").setLevel(logging.WARNING)

# Initialize FastMCP server.  The instructions are intentionally short and
# apply across the whole tool surface; individual selection guidance lives in
# each tool's description.
mcp = FastMCP(
    "Monarch Money MCP Server",
    instructions=(
        "This server exposes read and write tools for one authenticated Monarch Money "
        "account. Use read tools to inspect data first; confirm before consequential "
        "writes. Authentication is completed through the Railway setup page."
    ),
)

# FastMCP 1.x does not expose a public constructor argument for server version,
# but the MCP initialization response supports one. A changing version gives
# clients a reliable signal to refresh cached tool metadata after deployments.
mcp._mcp_server.version = "0.2.0"

# Import tools package to trigger @mcp.tool() registration
import monarch_mcp_server.tools  # noqa: E402, F401

from monarch_mcp_server.tool_metadata import apply_tool_metadata  # noqa: E402

_tool_metadata_applied = False


def configure_tool_metadata() -> None:
    """Apply metadata after all tool modules have finished importing."""
    global _tool_metadata_applied
    if not _tool_metadata_applied:
        apply_tool_metadata(mcp)
        _tool_metadata_applied = True

# Export for `mcp run`
app = mcp


def main() -> None:
    """Main entry point for the server."""
    logger.info("Starting Monarch Money MCP Server...")
    try:
        configure_tool_metadata()
        mcp.run()
    except Exception as e:
        logger.error(f"Failed to run server: {str(e)}")
        raise


if __name__ == "__main__":
    main()
