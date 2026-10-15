"""What the MCP proxy decides, without the MCP SDK.

The SDK module (``two_key.mcp_proxy.sdk``) moves messages; everything that decides is here, so it is tested
without the SDK installed:

- which upstream tools the agent sees (signed tools only) and the schema digest that pins them;
- the fixed claim and proposal text each call is authorized with;
- the refusal of an unresolved judge or agent identity;
- one ``tools/call``: ``TwoKey.authorize``, then ``ToolGateway.invoke`` in this process (#45), which calls
  the upstream tool with the projected arguments only. A deny is a reason code, never a value.
"""

from __future__ import annotations

import os
import sys
import threading
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

from ..canonical import canonical_hash
from .config import ProxyConfig, ProxyConfigError, ToolPolicy

# The parts of an upstream tool the agent sees, by their MCP wire names. Everything else (``_meta``,
# ``icons``, ``execution``, unknown keys) is dropped, so the digest covers all the agent is shown.
AGENT_TOOL_KEYS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
ORIGIN = "mcp-proxy"
MAX_REASON_CHARS = 200
DENY_PREFIX = "two-key denied this call: "


def pinned_view(tool: Mapping[str, Any]) -> dict:
    """The part of one upstream tool (MCP wire form) that is pinned and shown to the agent."""
    return {k: tool[k] for k in AGENT_TOOL_KEYS if k in tool and tool[k] is not None}


def schema_digest(views: Iterable[Mapping[str, Any]]) -> str:
    """``sha256:`` of the canonical JSON of the pinned views, sorted by upstream name."""
    return "sha256:" + canonical_hash(sorted((dict(v) for v in views), key=lambda v: str(v.get("name"))))


@dataclass(frozen=True)
class ToolSelection:
    """Signed tools matched to upstream tools. ``views`` are keyed by signed tool id."""
    views: Mapping[str, dict]
    upstream_names: Mapping[str, str]
    missing: tuple[str, ...]
    digest: str


def upstream_name(tool_id: str, policy: ToolPolicy) -> str:
    return policy.upstream_name or tool_id


def select_tools(upstream_tools: Iterable[Mapping[str, Any]], signed: Iterable[str],
                 policies: Mapping[str, ToolPolicy]) -> ToolSelection:
    """Each signed tool's upstream tool, by exact name (``upstream_name`` or the signed id).

    An upstream tool that no signed tool names is never shown and never called. Two upstream tools with one
    name are refused: which one runs would depend on the server. The digest covers the matched tools only,
    so a signed tool that disappears changes it too.
    """
    by_name: dict[str, Mapping[str, Any]] = {}
    for tool in upstream_tools:
        name = tool.get("name") if isinstance(tool, Mapping) else None
        if not isinstance(name, str):
            raise ProxyConfigError("upstream_tool_unreadable: the upstream listed a tool with no name")
        if name in by_name:
            raise ProxyConfigError(f"upstream_duplicate_tool: the upstream lists {name[:80]!r} twice")
        by_name[name] = tool
    views, names, missing = {}, {}, []
    seen: dict[str, str] = {}
    for tool_id in sorted(signed):
        name = upstream_name(tool_id, policies.get(tool_id) or ToolPolicy())
        if name in seen:
            raise ProxyConfigError(f"upstream_name_collision: signed tools {seen[name]!r} and {tool_id!r} "
                                   f"both map to upstream tool {name!r}")
        seen[name] = tool_id
        if name not in by_name:
            missing.append(tool_id)
            continue
        views[tool_id] = pinned_view(by_name[name])
        names[tool_id] = name
    return ToolSelection(views, names, tuple(missing), schema_digest(views.values()))


def agent_tools(selection: ToolSelection) -> list[dict]:
    """``tools/list`` for the agent: each exposed tool under its signed id."""
    return [dict(view, name=tool_id) for tool_id, view in sorted(selection.views.items())]


def schema_check(selection: ToolSelection, pinned: str, on_change: str) -> list[str]:
    """Messages for stderr when the upstream schema differs from the pin. Raises when it must refuse."""
    if selection.digest == pinned:
        return []
    detail = (f"the upstream tool schemas do not match upstream.schema_digest (pinned {pinned}, "
              f"now {selection.digest})")
    if selection.missing:
        detail += f"; signed tools the upstream does not list: {list(selection.missing)}"
    hint = ("re-run two-key mcp-draft-specs, review the diff, re-sign if a tool's meaning changed, and update "
            "schema_digest")
    if on_change == "refuse":
        raise ProxyConfigError(f"upstream_schema_changed: {detail}. {hint}, or pin the upstream server version")
    return [f"two-key: WARNING: upstream_schema_changed: {detail}; starting anyway (on_schema_change: warn). {hint}"]


def identity_refusal(separation: Any, allow_unresolved: bool) -> str | None:
    """The proxy refuses an unresolved judge or agent identity unless ``allow_unresolved_identity: true``.

    The library only warns (``unresolved_identity``): behind a local proxy or an unrecognized host, Two-Key
    cannot tell who serves the model, so it cannot rule out a judge that is the agent. Declaring
    ``upstream:`` for that side in ``judges.yaml`` resolves it.
    """
    hits = [w for w in getattr(separation, "warnings", ()) if w.get("check") == "unresolved_identity"]
    if not hits or allow_unresolved:
        return None
    sides = sorted({f"{w.get('side')} {w.get(w.get('side'))!r}" for w in hits if w.get("side")})
    return ("unresolved_identity: Two-Key cannot resolve who serves " + ", ".join(sides or ["a judge or the agent"])
            + "; declare upstream: for it in the judges file, or set allow_unresolved_identity: true in the "
              "proxy config to accept the risk")


def claim_for(tool_id: str, policy: ToolPolicy, spec: Mapping[str, Any]) -> dict:
    """The fixed claim for one call. The agent writes none of it; amount, counterparty, and irreversible
    are left out, so they come from the argument bytes and the signed spec."""
    if policy.claim == "none":
        return {"tool": tool_id}                        # an omitted data class is classified
    if policy.claim == "floor":
        return {"tool": tool_id, "data_class": spec["data_class_floor"]}
    return {"tool": tool_id, "data_class": policy.claim}


def proposal_for(tool_id: str, policy: ToolPolicy) -> str:
    """Fixed per tool, never agent text. Judges see it only with ``judge_inputs: record_and_proposal``."""
    return policy.proposal or f"MCP tools/call {tool_id}"


def safe_reason(reason: Any) -> str:
    """A reason code for the agent: printable ASCII, at most ``MAX_REASON_CHARS``."""
    text = reason if isinstance(reason, str) else "internal_error"
    text = "".join(c for c in text if 0x20 <= ord(c) < 0x7F)
    return text[:MAX_REASON_CHARS] or "denied"


@dataclass(frozen=True)
class CallOutcome:
    """One ``tools/call``. ``output`` is the upstream result, only when the tool ran."""
    allowed: bool
    reason: str
    output: Any = None
    stage: str = "authorize"          # authorize | gateway | proxy

    @property
    def deny_text(self) -> str:
        return DENY_PREFIX + safe_reason(self.reason)


UpstreamCall = Callable[[str, dict], Any]


class ProxyCore:
    """Authorize and redeem each call, in this process, one at a time.

    ``upstream_call(upstream_name, arguments)`` runs the upstream tool and returns its result; it is the
    gateway's registered tool, so it runs only for a redeemed token, with the projected arguments.
    """

    def __init__(self, two_key: Any, config: ProxyConfig, selection: ToolSelection, upstream_call: UpstreamCall,
                 *, agent_session: str | None = None):
        self.two_key = two_key
        self.config = config
        self.selection = selection
        self._agent_session = agent_session
        specs = two_key.compiled.tool_specs
        self._specs = {tool_id: specs[tool_id] for tool_id in selection.views}
        tools = {tool_id: self._tool(upstream_call, name) for tool_id, name in selection.upstream_names.items()}
        self.gateway = two_key.gateway(tools=tools)
        # TwoKey and the ledger are used by one call at a time; a judge round is bounded by the quorum deadline.
        self._lock = threading.Lock()

    @staticmethod
    def _tool(upstream_call: UpstreamCall, name: str) -> Callable[[dict], Any]:
        def run(arguments: dict) -> Any:
            return upstream_call(name, arguments)
        return run

    def list_tools(self) -> list[dict]:
        return agent_tools(self.selection)

    def call_tool(self, name: Any, arguments: Any) -> CallOutcome:
        if not isinstance(name, str) or name not in self._specs:
            # Not a tool this proxy offers. No token can exist for it, so nothing is authorized or ledgered.
            shown = safe_reason(name)[:80] if isinstance(name, str) else type(name).__name__
            print(f"two-key: mcp-proxy: refused a call to a tool it does not offer: {shown!r}", file=sys.stderr)
            return CallOutcome(False, "tool_not_offered", stage="proxy")
        policy = self.config.tool_policy(name)
        if arguments is None:
            arguments = {}
        with self._lock:
            decision = self.two_key.authorize(
                claim_for(name, policy, self._specs[name]), arguments, proposal_for(name, policy),
                agent_id=self.config.agent_id, hosting=self.config.hosting,
                agent_session=self._agent_session, origin=ORIGIN)
            if not decision.allowed or not decision.token:
                return CallOutcome(False, decision.reason, stage="authorize")
            result = self.gateway.invoke(decision.token, name, arguments)
        if not result.allowed:
            return CallOutcome(False, result.reason, stage="gateway")
        return CallOutcome(True, result.reason, result.output, stage="gateway")


def build_two_key(config: ProxyConfig, *, judge_transport: Any = None) -> Any:
    """``TwoKey`` from the files the config names, the same way ``two-key authorize`` loads them."""
    from ..constitution import ConstitutionError, ConstitutionSignatureError, load_envelope
    from ..core import TwoKey, TwoKeyConfigError
    from ..identity import IdentityError, load_monitored_agent_file
    from ..judges.config import JudgeConfigError, load_config_file
    from ..keys import load_private_key_file, load_public_key
    from ..ledger import Ledger, LedgerError
    try:
        key = load_private_key_file(config.principal_key)
        judges, policy = load_config_file(config.judges, judge_transport)
        agent = load_monitored_agent_file(config.judges)
        witness = load_public_key(config.witness_public_key) if config.witness_public_key else None
        ledger = Ledger(config.ledger, key, witness_public_key=witness, anchor_path=config.head_anchor)
        return TwoKey.load(ledger, key.public_key(), load_envelope(config.constitution), judges,
                           private_key=key, quorum=policy, monitored_agent=agent, ttl_seconds=config.ttl_seconds)
    except (OSError, ValueError, JudgeConfigError, IdentityError, LedgerError, ConstitutionError,
            ConstitutionSignatureError, TwoKeyConfigError) as e:
        raise ProxyConfigError(f"{type(e).__name__}: {e}") from None


def check_tools_signed(config: ProxyConfig, two_key: Any) -> None:
    """Every ``tools:`` entry names a tool in the signed constitution."""
    signed = two_key.compiled.tool_specs
    unknown = sorted(set(config.tools) - set(signed))
    if unknown:
        raise ProxyConfigError(f"tools: {unknown} are not tools in the signed constitution")


def agent_session(config: ProxyConfig, environ: Mapping[str, str] | None = None) -> str | None:
    """The agent session secret from ``agent_session_env``, read once at start. Unset or empty refuses."""
    if config.agent_session_env is None:
        return None
    environ = os.environ if environ is None else environ
    value = environ.get(config.agent_session_env)
    if not value:
        raise ProxyConfigError(f"agent_session_env: the environment variable {config.agent_session_env} "
                               "is unset or empty")
    return value
