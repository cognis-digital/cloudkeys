"""CLOUDKEYS MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import sys

from cloudkeys.core import scan, to_json


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-cloudkeys[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "Install the MCP extra: pip install 'cognis-cloudkeys[mcp]'",
            file=sys.stderr,
        )
        return 1
    app = FastMCP("cloudkeys")

    @app.tool()
    def cloudkeys_scan(target: str) -> str:
        """Find leaked cloud keys (AWS/GCP/Azure) + classify blast radius.

        Returns JSON findings.
        """
        if not target or not target.strip():
            return to_json(scan(""))
        return to_json(scan(target))

    app.run()
    return 0
