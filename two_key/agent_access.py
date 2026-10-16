"""The account that started the MCP proxy, checked before the proxy opens its ledger (``on_agent_access``).

``two-key mcp-proxy`` is started by the agent's host: directly, through the ``run-proxy`` sudo rule, or by a
forced command after SSH. The real account of that parent process is the agent's (or the SSH login account
an agent on another machine signs in as). Two-Key refuses to start when that account:

- is Two-Key's own (``agent_same_account``): it can read every key and change everything Two-Key trusts;
- is root (``agent_account_root``): it can change anything;
- cannot be told (``agent_account_unknown``): unknown is never a different account;
- can change a path the proxy runs or reads (``agent_can_write``): its program, import path, config, keys,
  ledger, hook modules, and the rest of the start-up writable-path check (two_key/writable.py).

``on_agent_access: refuse`` is the default; ``warn`` names the problem on stderr and starts (for a test on one
machine under one account); ``high_assurance`` always refuses and does not accept ``warn``. Other accounts that
could change those paths are still only the writable-path check's business, under ``on_writable_paths``.

The proxy calls :func:`check` from ``build_two_key``, before it opens the ledger. It cannot see the agent's
own machine, a parent that ran under another account than the agent's tools, or an agent that reaches Two-Key's
files some other way (a second login, a shared folder); docs/CONNECTING.md is the checklist.
"""

from __future__ import annotations

import os
import sys
from typing import Iterable

from . import _platform, writable

MODES = ("refuse", "warn")
GUIDE = "docs/CONNECTING.md"


class AgentAccessError(ValueError):
    """Two-Key refuses to start: the account that started it is, or can change, Two-Key."""


def resolve_mode(mode: str | None, high_assurance: bool) -> str:
    """``refuse`` or ``warn`` from ``on_agent_access`` and the quorum profile. Raises ``ValueError``."""
    if mode is not None and mode not in MODES:
        raise ValueError(f"on_agent_access: expected one of {list(MODES)}")
    if high_assurance:
        if mode == "warn":
            raise ValueError("on_agent_access: high_assurance refuses to start when the agent's account is "
                             "Two-Key's own or can change what it runs; remove on_agent_access: warn")
        return "refuse"
    return mode or "refuse"


def problems(paths: Iterable[tuple[object, str]], *, parent=None, own_uid: int | None = None) -> list[str]:
    """What is wrong with the account that started this process, one line each; empty when nothing is.

    ``paths`` are ``(path, rule)`` pairs, as for ``writable.check``. ``parent`` and ``own_uid`` are for tests.
    """
    if _platform.WINDOWS:  # pragma: no cover
        uid, label = None, _platform.parent_account()[1]
    else:
        uid, label = parent if parent is not None else _platform.parent_account()
        own_uid = os.geteuid() if own_uid is None else own_uid
    if uid is None:
        return [f"agent_account_unknown: cannot tell which account started the proxy: {label}"]
    if uid == own_uid:
        return [f"agent_same_account: the proxy was started by {label}, Two-Key's own account, so the agent "
                "could read Two-Key's keys and change its settings; run the agent as another account"]
    if uid == 0:
        return [f"agent_account_root: the proxy was started by {label}, which can change anything Two-Key "
                "runs or reads; run the agent as an ordinary account"]
    out = []
    for path, _ in writable.check(paths, runtime=True):
        try:
            how = _platform.account_can_write(path, uid)
        except OSError as e:
            how = f"it cannot be checked ({e.strerror or type(e).__name__})"
        if how:
            out.append(f"agent_can_write: {path}: the account that started the proxy, {label}, could change it "
                       f"({how})")
    return out


def check(paths: Iterable[tuple[object, str]], mode: str, *, why: str, stream=None, **kw) -> list[str]:
    """Name each problem on stderr; under ``refuse``, raise ``AgentAccessError`` with the first."""
    found = problems(paths, **kw)
    if not found:
        return found
    stream = sys.stderr if stream is None else stream
    if mode == "refuse":
        more = f" (and {len(found) - 1} more)" if len(found) > 1 else ""
        for line in found[1:writable.MAX_LINES]:
            print(f"two-key: {line} ({GUIDE})", file=stream)
        raise AgentAccessError(f"{found[0]}{more}; {why} refuses to start ({GUIDE})")
    for line in found[:writable.MAX_LINES]:
        print(f"two-key: WARNING: {line}; on_agent_access: warn starts anyway ({GUIDE})", file=stream)
    return found


__all__ = ["AgentAccessError", "MODES", "check", "problems", "resolve_mode"]
