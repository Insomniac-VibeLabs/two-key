"""An MCP stdio proxy that puts Two-Key in front of an upstream MCP server (``two-key mcp-proxy``).

The agent's host starts the proxy instead of the upstream server. The proxy starts the upstream server as a
child process, shows the agent only the signed tools, and runs every ``tools/call`` through
``TwoKey.authorize`` and the in-process gateway (#45), which calls the upstream tool with the projected
arguments only.

``config`` and ``core`` decide and need no extra dependency. ``sdk`` is the only module that imports the MCP
Python SDK (``pip install "two-key[mcp]"``).
"""
