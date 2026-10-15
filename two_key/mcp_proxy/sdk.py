"""The MCP proxy's only contact with the MCP Python SDK (``pip install "two-key[mcp]"``).

Every SDK import and call is in this module, so an SDK upgrade touches one place. The SDK moves messages; it
decides nothing (``two_key.mcp_proxy.core`` does).

- The upstream server is started as a child process over stdio (``StdioServerParameters``): the program and
  arguments from ``upstream.command``, no shell, and only the variables in ``upstream.env`` plus the SDK's
  minimal set. The SDK's client response cache is off, so ``tools/list`` is what the server says now.
- The proxy serves the agent's host over stdio with ``tools`` only: no resources, prompts, completions, or
  server instructions are forwarded, and the upstream server cannot reach the agent's host (no sampling,
  elicitation, or roots callbacks are given to the upstream client).
- Tools are listed once, at start, and pinned. A later ``tools/list_changed`` from the upstream is ignored;
  restart the proxy to pick up a change, which checks the pin again.
"""

from __future__ import annotations

import sys
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any, AsyncIterator

try:
    _ExceptionGroup = BaseExceptionGroup                  # Python 3.11+
except NameError:  # pragma: no cover - Python 3.10, where anyio depends on the backport
    from exceptiongroup import BaseExceptionGroup as _ExceptionGroup

try:
    import anyio
    import anyio.from_thread
    import anyio.to_thread
    import mcp_types as types
    from mcp import Client, StdioServerParameters
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError('two-key mcp-proxy needs the MCP SDK: pip install "two-key[mcp]"') from e

from .. import __version__
from .config import ProxyConfig, ProxyConfigError
from .core import CallOutcome, ProxyCore, ToolSelection, agent_session, build_two_key, check_tools_signed, \
    identity_refusal, schema_check, select_tools

SERVER_NAME = "two-key-mcp-proxy"
MAX_TOOL_PAGES = 100           # tools/list pages read from the upstream at start
MAX_UPSTREAM_TOOLS = 10_000


def _wire(model: Any) -> dict:
    """An SDK model in MCP wire form (camelCase keys, no unset fields)."""
    return model.model_dump(mode="json", by_alias=True, exclude_none=True)


def upstream_parameters(config: ProxyConfig) -> StdioServerParameters:
    command = config.upstream.command
    return StdioServerParameters(command=command[0], args=list(command[1:]), env=config.upstream.resolved_env(),
                                 cwd=config.upstream.cwd)


async def list_upstream_tools(client: Client) -> list[dict]:
    """Every tool the upstream lists, all pages, bounded."""
    tools: list[dict] = []
    cursor = None
    for _ in range(MAX_TOOL_PAGES):
        result = await client.list_tools(cursor=cursor)
        tools.extend(_wire(t) for t in result.tools)
        if len(tools) > MAX_UPSTREAM_TOOLS:
            raise ProxyConfigError(f"upstream_too_many_tools: more than {MAX_UPSTREAM_TOOLS}")
        cursor = getattr(result, "next_cursor", None)
        if not cursor:
            return tools
    raise ProxyConfigError(f"upstream_too_many_pages: tools/list did not end after {MAX_TOOL_PAGES} pages")


async def connect_upstream(stack: AsyncExitStack, config: ProxyConfig) -> Client:
    client = Client(upstream_parameters(config), cache=None, mode="auto")
    return await stack.enter_async_context(client)


def _error_result(outcome: CallOutcome) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=outcome.deny_text)], is_error=True)


def _result(outcome: CallOutcome) -> types.CallToolResult:
    if not outcome.allowed:
        return _error_result(outcome)
    output = outcome.output
    if isinstance(output, types.CallToolResult):
        # The upstream's result as it is, without its _meta.
        return types.CallToolResult(content=output.content, structured_content=output.structured_content,
                                    is_error=output.is_error)
    return _error_result(CallOutcome(False, "upstream_result_unreadable", stage="gateway"))


def build_server(core: ProxyCore) -> Server:
    """The agent-facing server: ``tools/list`` from the pinned selection, ``tools/call`` through ``core``."""
    listed = types.ListToolsResult(tools=[types.Tool.model_validate(t) for t in core.list_tools()])

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        return listed

    async def on_call_tool(ctx, params) -> types.CallToolResult:
        # authorize and the judges are blocking calls: they run in a worker thread, and the gateway's tool
        # calls back into this event loop for the upstream request.
        outcome = await anyio.to_thread.run_sync(core.call_tool, params.name, params.arguments)
        return _result(outcome)

    return Server(SERVER_NAME, version=__version__, on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def upstream_caller(client: Client, timeout_seconds: float):
    """The gateway's tool for every exposed tool: a blocking call from the worker thread to the upstream."""
    async def call(name: str, arguments: dict) -> Any:
        with anyio.fail_after(timeout_seconds):
            return await client.call_tool(name, arguments)

    def run(name: str, arguments: dict) -> Any:
        return anyio.from_thread.run(call, name, arguments)
    return run


async def start_core(stack: AsyncExitStack, config: ProxyConfig, *, two_key: Any = None,
                     judge_transport: Any = None) -> ProxyCore:
    """Everything before serving: Two-Key, the identity refusal, the upstream child, and the schema pin.

    ``two_key`` is for tests and embedding (an already built ``TwoKey``); the command line builds it from the
    files the config names. Any refusal raises ``ProxyConfigError``.
    """
    session = agent_session(config)
    tk = two_key if two_key is not None else build_two_key(config, judge_transport=judge_transport)
    refusal = identity_refusal(tk.separation, config.allow_unresolved_identity)
    if refusal:
        raise ProxyConfigError(refusal)
    check_tools_signed(config, tk)
    try:
        client = await connect_upstream(stack, config)
        upstream = await list_upstream_tools(client)
    except ProxyConfigError:
        raise
    except Exception as e:      # the child did not start, or did not speak MCP
        raise ProxyConfigError(f"upstream_unavailable: {type(e).__name__}: {str(e)[:200]}") from None
    selection: ToolSelection = select_tools(upstream, tk.compiled.tool_specs, config.tools)
    for line in schema_check(selection, config.upstream.schema_digest, config.upstream.on_schema_change):
        print(line, file=sys.stderr)
    return ProxyCore(tk, config, selection, upstream_caller(client, config.upstream.call_timeout_seconds),
                     agent_session=session)


def _refusal(error: BaseException) -> ProxyConfigError | None:
    """The ``ProxyConfigError`` inside an exception group. A refusal raised while the upstream client is open
    leaves the SDK's task group wrapped in one."""
    if isinstance(error, ProxyConfigError):
        return error
    if isinstance(error, _ExceptionGroup):
        for inner in error.exceptions:
            found = _refusal(inner)
            if found is not None:
                return found
    return None


@asynccontextmanager
async def running_core(config: ProxyConfig, *, two_key: Any = None,
                       judge_transport: Any = None) -> AsyncIterator[ProxyCore]:
    """``start_core`` with the upstream child kept running for the body; a refusal raises ``ProxyConfigError``."""
    try:
        async with AsyncExitStack() as stack:
            yield await start_core(stack, config, two_key=two_key, judge_transport=judge_transport)
    except _ExceptionGroup as group:
        refusal = _refusal(group)
        if refusal is None:
            raise
        raise refusal from None


async def serve(config: ProxyConfig, *, two_key: Any = None) -> None:
    async with running_core(config, two_key=two_key) as core:
        server = build_server(core)
        print(f"two-key: mcp-proxy: serving {len(core.selection.views)} signed tool(s) "
              f"{sorted(core.selection.views)}", file=sys.stderr)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())


def run(config: ProxyConfig) -> int:
    """``two-key mcp-proxy``: serve until the agent's host closes stdin. Nothing but MCP goes to stdout."""
    try:
        anyio.run(serve, config)
    except ProxyConfigError as e:
        print(f"two-key: mcp-proxy refused to start: {e}", file=sys.stderr)
        return 1
    return 0
