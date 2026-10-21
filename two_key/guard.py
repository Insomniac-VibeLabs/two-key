# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Guard: one call that authorizes and runs a tool through both keys, with caller-supplied facts.

Usable from any agent loop (LangChain, the OpenAI Agents SDK, custom code) and used by the MCP proxy. For each
call it:

1. copies the arguments once;
2. runs the tool's fact hooks on a copy (one per ``source: caller`` field the tool maps);
3. calls ``TwoKey.authorize`` with a fixed claim and proposal (never the agent's) and those facts;
4. on an allow, runs the hooks again and redeems the token with ``gateway.invoke(..., facts=...)`` in this
   process (#45), so a fact that changed in between is ``fact_mismatch``;
5. returns reason codes only.

Fact hooks are trusted operator code, like ``judges.yaml`` auth callbacks, but they receive agent-written
arguments: a hook must look a fact up by an id in the system of record and never echo an argument. A hook that
raises or returns nothing leaves its fact out, so the call denies (``field_missing``); its type goes to stderr.

The claim is ``floor`` (the tool's signed ``data_class_floor``), a data class, or ``none`` (omitted, so
``classified``). Amount, counterparty, and irreversible are never claimed: they come from the argument bytes and
the signed spec.
"""

from __future__ import annotations

import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from .action import DATA_CLASS_SEP, DATA_CLASSES
from .agent_meta import type_tag
from .canonical import MAX_INPUT_DEPTH, EncodingError, OversizeError, to_plain
from .derive import MAX_ARGS_BYTES, caller_fields

CLAIM_POLICIES = ("floor", "none")
FactHook = Callable[[str, Mapping[str, Any]], Any]


class GuardConfigError(ValueError):
    """The guard refuses this tool configuration."""


class GuardDenied(Exception):
    """Raised by a ``@guard.tool`` function when a key does not turn. ``reason`` is the reason code."""

    def __init__(self, reason: str, stage: str):
        super().__init__(reason)
        self.reason, self.stage = reason, stage


def valid_claim(value: Any) -> str:
    """``floor``, ``none``, or a data class (``financial+medical`` too), in canonical form."""
    if not isinstance(value, str):
        raise GuardConfigError("claim: expected floor, none, or a data class")
    claim = value.strip().casefold()
    if claim in CLAIM_POLICIES:
        return claim
    parts = claim.split(DATA_CLASS_SEP)
    if not parts or any(p not in DATA_CLASSES for p in parts) or len(set(parts)) != len(parts):
        raise GuardConfigError(f"claim: expected floor, none, or one of {list(DATA_CLASSES)}")
    if len(parts) > 1 and set(parts) != {"financial", "medical"}:
        raise GuardConfigError("claim: only financial+medical combines")
    return DATA_CLASS_SEP.join(sorted(parts))


@dataclass(frozen=True)
class GuardedTool:
    """A signed tool, the function that does its work, and how it is authorized."""
    name: str
    fn: Callable[[dict], Any]
    claim: str = "none"
    facts: Mapping[str, FactHook] = field(default_factory=dict)
    proposal: str | None = None


@dataclass(frozen=True)
class GuardResult:
    """One call. ``output`` is the tool's result, only when it ran. ``stage``: guard | authorize | gateway."""
    allowed: bool
    reason: str
    output: Any = None
    stage: str = "authorize"


class Guard:
    """Authorize and redeem calls to guarded tools in the ``TwoKey`` process, one call at a time."""

    def __init__(self, two_key: Any, tools: Iterable[GuardedTool] = (), *, origin: str = "guard",
                 agent_id: str | None = None, hosting: str | None = None):
        self.two_key = two_key
        self.origin, self.agent_id, self.hosting = origin, agent_id, hosting
        self.gateway = two_key.gateway(tools={})
        self._tools: dict[str, GuardedTool] = {}
        # TwoKey and the ledger are used by one call at a time; a judge round ends by the quorum deadline.
        self._lock = threading.Lock()
        for tool in tools:
            self.add(tool)

    @property
    def tools(self) -> Mapping[str, GuardedTool]:
        return dict(self._tools)

    def add(self, tool: GuardedTool) -> GuardedTool:
        """Register a tool. Refused: an unsigned tool, a bad claim, a caller field with no hook, a hook for a
        field that is not a caller field of this tool, or a name already guarded."""
        specs = self.two_key.compiled.tool_specs
        if tool.name not in specs:
            raise GuardConfigError(f"{tool.name!r} is not a tool in the signed constitution")
        if tool.name in self._tools:
            raise GuardConfigError(f"{tool.name!r} is already guarded")
        if not callable(tool.fn):
            raise GuardConfigError(f"{tool.name!r}: fn must be callable")
        claim = valid_claim(tool.claim)
        needed = set(caller_fields(specs[tool.name]))
        scanner = getattr(self.two_key, "scanner", None)
        if scanner is not None and scanner.scans(specs[tool.name]):
            needed.discard(scanner.field)       # Two-Key fills the scan verdict itself; no hook may supply it
        given = set(tool.facts)
        if needed - given:
            raise GuardConfigError(f"{tool.name!r}: no fact hook for caller-supplied field(s) {sorted(needed - given)}")
        if given - needed:
            raise GuardConfigError(f"{tool.name!r}: hook(s) for {sorted(given - needed)}, which this tool does not "
                                   "map as caller-supplied fields")
        if any(not callable(h) for h in tool.facts.values()):
            raise GuardConfigError(f"{tool.name!r}: every fact hook must be callable")
        tool = GuardedTool(tool.name, tool.fn, claim, dict(tool.facts), tool.proposal)
        self._tools[tool.name] = tool
        self.gateway.tools[tool.name] = tool.fn
        return tool

    def record(self, kind: str, body: dict) -> None:
        """Append one ledger entry (an integration's own record, such as ``mcp_proxy_started``) under the
        guard's lock, so it never interleaves with a call."""
        with self._lock:
            self.two_key.ledger.append_bounded(kind, body)
            self.two_key.ledger.checkpoint()

    def tool(self, name: str, *, claim: str = "none", facts: Mapping[str, FactHook] | None = None,
             proposal: str | None = None):
        """Decorator: ``@guard.tool("pay_vendor", claim="floor", facts={"po_matched": hook})``. The decorated
        function does the work; calling the returned function goes through both keys and raises
        ``GuardDenied`` when a key does not turn."""
        def wrap(fn: Callable[[dict], Any]):
            self.add(GuardedTool(name, fn, claim, facts or {}, proposal))

            def guarded(arguments: Mapping[str, Any], *, agent_session: str | None = None) -> Any:
                result = self.call(name, arguments, agent_session=agent_session)
                if not result.allowed:
                    raise GuardDenied(result.reason, result.stage)
                return result.output
            guarded.__name__ = getattr(fn, "__name__", name)
            guarded.__doc__ = fn.__doc__
            return guarded
        return wrap

    def claim(self, name: str) -> dict:
        tool = self._tools[name]
        if tool.claim == "none":
            return {"tool": name}                       # an omitted data class is classified
        if tool.claim == "floor":
            return {"tool": name, "data_class": self.two_key.compiled.tool_specs[name]["data_class_floor"]}
        return {"tool": name, "data_class": tool.claim}

    def proposal(self, name: str) -> str:
        return self._tools[name].proposal or f"call {name}"

    @staticmethod
    def _copy(arguments: Any) -> Any:
        try:
            return to_plain(arguments, max_depth=MAX_INPUT_DEPTH, what="tool args are", max_items=MAX_ARGS_BYTES // 2)
        except (OversizeError, EncodingError):
            return None                                 # authorize denies these arguments on its own

    def resolve_facts(self, name: str, arguments: Any) -> dict:
        """Run the tool's fact hooks. A hook that raises or returns None leaves its fact out."""
        facts: dict[str, Any] = {}
        hooks = self._tools[name].facts
        if not hooks or not isinstance(arguments, Mapping):
            return facts
        for fact, hook in sorted(hooks.items()):
            try:
                value = hook(name, self._copy(arguments))
            except Exception as e:      # trusted code that failed: the fact is missing, so the call denies
                print(f"two-key: fact hook for {name}.{fact} failed: {type_tag(e)}", file=sys.stderr)
                continue
            if value is not None:
                facts[fact] = value
        return facts

    def call(self, name: Any, arguments: Any, *, agent_session: str | None = None) -> GuardResult:
        if not isinstance(name, str) or name not in self._tools:
            return GuardResult(False, "tool_not_guarded", stage="guard")
        if arguments is None:
            arguments = {}
        plain = self._copy(arguments)
        with self._lock:
            decision = self.two_key.authorize(
                self.claim(name), arguments, self.proposal(name), agent_id=self.agent_id, hosting=self.hosting,
                agent_session=agent_session, origin=self.origin, facts=self.resolve_facts(name, plain))
            if not decision.allowed or not decision.token:
                return GuardResult(False, decision.reason, stage="authorize")
            # The facts are looked up again just before the tool runs: one that changed is fact_mismatch.
            result = self.gateway.invoke(decision.token, name, arguments, facts=self.resolve_facts(name, plain))
        if not result.allowed:
            return GuardResult(False, result.reason, stage="gateway")
        return GuardResult(True, result.reason, result.output, stage="gateway")
