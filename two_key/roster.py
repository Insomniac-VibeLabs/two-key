# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The signed agent roster (0.9.0): which agents may connect, the account each one runs as, and which tools each
may use.

The roster is part of the constitution, signed by the principal key (``agents:`` in the rules file), so an agent
cannot add itself or change its own account. Each entry names one agent and the account it runs as: a local
account, or the SSH login account for an agent on another machine (under a forced command the login account is
the account that starts the proxy). No two entries share an account, because two agents on one account cannot be
told apart. An entry marked ``shared: true`` is a group of callers Two-Key cannot tell apart (for example public
agents reaching it through one gateway account): it is judged as one agent, and ``one_proxy_per_agent`` does not
apply to it.

Each tool may say which agents may use it (``tool_specs.<tool>.agents``): ``any`` (every listed agent, the
default) or a list of roster ids. Under ``high_assurance`` the roster is required and every tool names its
agents.

At start the MCP proxy reads the account that started it (two_key/agent_access.py) and serves the roster entry
for that account. It refuses when no entry has that account (``agent_account_unlisted``) or when its
``agent_id`` names another entry (``agent_account_mismatch``). Accounts are compared by number: a name is looked
up when the proxy starts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .policy_vm import ConstitutionError

AGENT_KEYS = ("id", "account", "shared", "hosting")
# An agent id: what the ledger, the judges, and ledger-view show; ``unnamed`` is the id of a proxy with no name.
AGENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
RESERVED_IDS = ("unnamed", "any")
# A POSIX account name (useradd's rules, a little wider): letters, digits, '.', '_', '-', at most 64 characters.
ACCOUNT = re.compile(r"[A-Za-z_][A-Za-z0-9._-]{0,63}")
MAX_HOSTING = 256
MAX_AGENTS = 256
ANY = "any"


class RosterError(ValueError):
    """A proxy refuses to start: the account that started it is not the account of the agent it would serve."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class RosterAgent:
    id: str
    account: str
    shared: bool = False
    hosting: str | None = None

    def to_record(self) -> dict:
        out: dict[str, Any] = {"id": self.id, "account": self.account}
        if self.shared:
            out["shared"] = True
        if self.hosting:
            out["hosting"] = self.hosting
        return out


def _entry(i: int, entry: Any) -> RosterAgent:
    """One roster entry, checked on its own."""
    where = f"agents[{i}]"
    if not isinstance(entry, Mapping):
        raise ConstitutionError(f"{where}: expected a mapping with id and account")
    extra = set(entry) - set(AGENT_KEYS)
    if extra:
        raise ConstitutionError(f"{where}: unknown key(s) {sorted(map(str, extra))}")
    aid, account = entry.get("id"), entry.get("account")
    if not isinstance(aid, str) or not AGENT_ID.fullmatch(aid):
        raise ConstitutionError(f"{where}.id: expected letters, digits, '.', '_' or '-' (at most 128, starting "
                                "with a letter or digit)")
    if aid.casefold() in RESERVED_IDS:
        raise ConstitutionError(f"{where}.id: {aid!r} is reserved")
    if not isinstance(account, str) or not ACCOUNT.fullmatch(account):
        raise ConstitutionError(f"{where}.account: expected an account name (the local account, or the SSH login, "
                                "the agent runs as)")
    shared = entry.get("shared", False)
    if not isinstance(shared, bool):
        raise ConstitutionError(f"{where}.shared: expected true or false")
    hosting = entry.get("hosting")
    if hosting is not None and (not isinstance(hosting, str) or not hosting.strip() or len(hosting) > MAX_HOSTING):
        raise ConstitutionError(f"{where}.hosting: expected a non-empty string of at most {MAX_HOSTING} characters")
    return RosterAgent(aid, account, shared, hosting.strip() if hosting else None)


def validate_agents(value: Any) -> list[dict]:
    """The canonical roster: a list of ``{id, account, shared?, hosting?}``, sorted by id. ``shared`` appears only
    when true and ``hosting`` only when set, so an entry hashes the same however it was written."""
    if not isinstance(value, list) or not value:
        raise ConstitutionError("agents: expected a non-empty list of {id, account}")
    if len(value) > MAX_AGENTS:
        raise ConstitutionError(f"agents: at most {MAX_AGENTS} agents")
    out: dict[str, dict] = {}
    accounts: dict[str, str] = {}
    for i, raw in enumerate(value):
        agent = _entry(i, raw)
        if agent.id in out:
            raise ConstitutionError(f"agents: duplicate id {agent.id!r}")
        if agent.account in accounts:
            raise ConstitutionError(f"agents: {agent.id!r} and {accounts[agent.account]!r} share the account "
                                    f"{agent.account!r}; two agents on one account cannot be told apart, so give each "
                                    "its own account, or list them once as a shared group (shared: true)")
        accounts[agent.account] = agent.id
        out[agent.id] = agent.to_record()
    return [out[k] for k in sorted(out)]


def validate_tool_agents(tool: str, value: Any, roster: Iterable[str] | None) -> str | list[str]:
    """A tool's ``agents``: ``any`` or a sorted list of roster ids. Needs a roster."""
    ids = None if roster is None else set(roster)
    if ids is None:
        raise ConstitutionError(f"tool_specs.{tool}.agents: needs an agents: roster in the rules file")
    if value == ANY:
        return ANY
    if not isinstance(value, list) or not value or not all(isinstance(a, str) for a in value):
        raise ConstitutionError(f"tool_specs.{tool}.agents: expected any, or a non-empty list of agent ids")
    if len(set(value)) != len(value):
        raise ConstitutionError(f"tool_specs.{tool}.agents: an agent is listed twice")
    unknown = sorted(set(value) - ids)
    if unknown:
        raise ConstitutionError(f"tool_specs.{tool}.agents: not on the roster: {unknown}")
    return sorted(value)


def roster_of(agents: Any) -> tuple[RosterAgent, ...]:
    """The roster entries of a canonical ``agents`` list (empty without one)."""
    return tuple(RosterAgent(a["id"], a["account"], bool(a.get("shared")), a.get("hosting"))
                 for a in agents or ())


def tool_allows(spec: Mapping, agent_id: str | None) -> bool:
    """Whether a tool's spec lets this agent call it. A tool with no ``agents`` (or ``any``) allows every caller."""
    allowed = spec.get("agents", ANY)
    return allowed == ANY or (agent_id is not None and agent_id in allowed)


def uid_of(account: str) -> int | None:
    """The number of a local account, or None when this machine has no such account (or no account database)."""
    try:
        import pwd
        return pwd.getpwnam(account).pw_uid
    except (ImportError, KeyError):
        return None


def account_name(uid: int | None) -> str | None:
    """The name of local account ``uid``, or None when it has none (or it cannot be told)."""
    if uid is None:
        return None
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        return None


@dataclass(frozen=True)
class ServedAgent:
    """The agent a running MCP proxy serves, and how it knows (``source``: ``roster`` or ``proxy_yaml``)."""
    id: str | None
    uid: int | None
    account: str | None
    source: str
    shared: bool = False
    hosting: str | None = None

    def account_record(self) -> dict:
        return {"uid": self.uid, "name": self.account}


def resolve(roster: Iterable[RosterAgent], uid: int | None, label: str, configured_id: str | None,
            *, lookup=uid_of) -> RosterAgent:
    """The roster entry for the account that started the proxy. Raises ``RosterError``."""
    entries = list(roster)
    match = [a for a in entries if uid is not None and lookup(a.account) == uid]
    if not match:
        raise RosterError("agent_account_unlisted",
                          f"the proxy was started by {label}, which is not the account of any agent on the signed "
                          "roster (agents: in the rules file); add it, or start the proxy as the agent's own account "
                          "(docs/CONNECTING.md)")
    agent = match[0]      # one at most: signing refuses two entries on one account, and uids are compared
    if len(match) > 1:
        raise RosterError("agent_account_mismatch",
                          f"roster entries {sorted(a.id for a in match)} name accounts with the same number as "
                          f"{label}; give each agent its own account")
    if configured_id is not None and configured_id != agent.id:
        raise RosterError("agent_account_mismatch",
                          f"this proxy's agent_id is {configured_id!r}, but it was started by {label}, the account of "
                          f"roster agent {agent.id!r}; remove agent_id from proxy.yaml or start the proxy as "
                          f"{configured_id!r}'s account")
    return agent


__all__ = ["ANY", "AGENT_KEYS", "RosterAgent", "RosterError", "ServedAgent", "account_name", "resolve", "roster_of",
           "tool_allows", "uid_of", "validate_agents", "validate_tool_agents"]
