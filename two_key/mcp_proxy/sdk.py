# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
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

import io
import json
import sys
from contextlib import AsyncExitStack, asynccontextmanager, suppress
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
from .._platform import resolve_program
from ..strict import DuplicateKeyError, loads_json
from .config import ProxyConfig, ProxyConfigError
from .core import CallOutcome, ProxyCore, ToolSelection, agent_session, build_two_key, check_tools_signed, \
    identity_refusal, schema_check, select_tools, undeclared_file_inputs, undescribed_inputs

SERVER_NAME = "two-key-mcp-proxy"
# Set by mark_repeated_keys in a tools/call's _meta; a call that carries it is refused (an agent setting it is too).
REPEATED_KEY_MARK = "io.github.insomniac-vibelabs.two-key/repeated-key"
MAX_TOOL_PAGES = 100           # tools/list pages read from the upstream at start
MAX_UPSTREAM_TOOLS = 10_000


def mark_repeated_keys(line: str) -> str:
    """One line from the agent's host, as the SDK reads it. A ``tools/call`` whose JSON repeats a key anywhere is
    given ``REPEATED_KEY_MARK`` in its ``_meta``, so ``on_call_tool`` refuses it (run 13, D2): the SDK's parser keeps
    the last key and says nothing. Any other line is passed on unchanged, for the SDK to read or refuse."""
    try:
        loads_json(line)
        return line
    except DuplicateKeyError:
        pass
    except ValueError:      # not JSON, or NaN: the SDK's own error
        return line
    message = json.loads(line)
    if not isinstance(message, dict) or message.get("method") != "tools/call":
        return line
    params = message.get("params")
    if not isinstance(params, dict):
        return line
    meta = params.get("_meta")
    params["_meta"] = {**(meta if isinstance(meta, dict) else {}), REPEATED_KEY_MARK: True}
    return json.dumps(message) + "\n"


class _MarkedLines:
    """The agent's stdin for ``stdio_server``, each line through ``mark_repeated_keys``."""

    def __init__(self, stdin: Any):
        self._stdin = stdin

    def __aiter__(self):
        return self._lines()

    async def _lines(self):
        async for line in self._stdin:
            yield mark_repeated_keys(line)


class _AgentText(io.TextIOWrapper):
    """The agent's stdin as UTF-8 text. Closing it never closes ``sys.stdin``'s buffer, which is not its own."""

    def close(self) -> None:
        with suppress(ValueError):
            self.detach()


def agent_stdin() -> _MarkedLines:
    """The agent's stdin for ``stdio_server``: ``sys.stdin``'s buffer as UTF-8 lines, each through
    ``mark_repeated_keys``. The upstream server is a child with its own pipes, so it never reads this stdin."""
    return _MarkedLines(anyio.wrap_file(_AgentText(sys.stdin.buffer, encoding="utf-8", errors="replace")))


def _wire(model: Any) -> dict:
    """An SDK model in MCP wire form (camelCase keys, no unset fields)."""
    return model.model_dump(mode="json", by_alias=True, exclude_none=True)


def upstream_parameters(config: ProxyConfig) -> StdioServerParameters:
    command = config.upstream.command
    return StdioServerParameters(command=resolve_program(command[0]), args=list(command[1:]),
                                 env=config.upstream.resolved_env(),
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
        if (params.meta or {}).get(REPEATED_KEY_MARK):
            return _result(await anyio.to_thread.run_sync(core.refuse_duplicate_keys, params.name))
        # authorize and the judges are blocking calls: they run in a worker thread, and the gateway's tool
        # calls back into this event loop for the upstream request.
        outcome = await anyio.to_thread.run_sync(core.call_tool, params.name, params.arguments)
        return _result(outcome)

    return Server(SERVER_NAME, version=__version__, on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def upstream_caller(client: Client, timeout_seconds: float):
    """The gateway's tool for every exposed tool: a blocking call from the worker thread to the upstream."""
    async def call(name: str, arguments: dict, meta: dict | None) -> Any:
        with anyio.fail_after(timeout_seconds):
            if meta is None:
                return await client.call_tool(name, arguments)
            return await client.call_tool(name, arguments, meta=meta)      # a checked tool (#28)

    def run(name: str, arguments: dict, meta: dict | None = None) -> Any:
        return anyio.from_thread.run(call, name, arguments, meta)
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
    for line in undescribed_inputs(selection, tk.compiled.tool_specs):      # advice; it still starts
        print(f"two-key: WARNING: mcp-proxy: {line}", file=sys.stderr)
    for line in undeclared_file_inputs(selection, tk.compiled.tool_specs, getattr(tk, "scanner", None)):
        print(f"two-key: WARNING: mcp-proxy: {line}", file=sys.stderr)
    core = ProxyCore(tk, config, selection, upstream_caller(client, config.upstream.call_timeout_seconds),
                     agent_session=session)
    try:
        core.record_start()
    except Exception as e:      # a proxy that cannot write its own start to the ledger does not serve
        raise ProxyConfigError(f"ledger_failed: could not record mcp_proxy_started ({type(e).__name__})") from None
    return core


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
        try:
            async with stdio_server(stdin=agent_stdin()) as (read, write):
                await server.run(read, write, server.create_initialization_options())
        finally:
            # Give the SIEM sender its last pass (0.7.0). What has not gone out is still in the ledger,
            # and the next start sends it from the cursor.
            getattr(core.two_key, "close", lambda: None)()


def run(config: ProxyConfig) -> int:
    """``two-key mcp-proxy``: serve until the agent's host closes stdin. Nothing but MCP goes to stdout."""
    try:
        anyio.run(serve, config)
    except ProxyConfigError as e:
        print(f"two-key: mcp-proxy refused to start: {e}", file=sys.stderr)
        return 1
    return 0


async def fetch_upstream_tools(command: list[str], env: dict[str, str]) -> list[dict]:
    """``two-key mcp-draft-specs``: start the server once, list its tools, and stop it."""
    params = StdioServerParameters(command=resolve_program(command[0]), args=list(command[1:]), env=env)
    async with Client(params, cache=None, mode="auto") as client:
        return await list_upstream_tools(client)


def draft_tools(command: list[str], env: dict[str, str]) -> list[dict]:
    try:
        return anyio.run(fetch_upstream_tools, command, env)
    except ProxyConfigError:
        raise
    except Exception as e:
        found = _refusal(e)
        if found is not None:
            raise found from None
        raise ProxyConfigError(f"upstream_unavailable: {type(e).__name__}: {str(e)[:200]}") from None
