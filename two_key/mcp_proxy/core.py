# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
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

import copy
import importlib
import importlib.util
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from ..action import MAX_TOOL_NAME_CHARS
from ..canonical import canonical_hash
from ..derive import size_record
from ..fields import field_mappings
from ..guard import Guard, GuardConfigError, GuardedTool
from .config import ProxyConfig, ProxyConfigError, ToolPolicy, UpstreamConfig

_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,127}")

# The parts of an upstream tool the agent sees, by their MCP wire names. Everything else (``_meta``,
# ``icons``, ``execution``, unknown keys) is dropped, so the digest covers all the agent is shown.
AGENT_TOOL_KEYS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
ORIGIN = "mcp-proxy"
MAX_REASON_CHARS = 200
DENY_PREFIX = "two-key denied this call: "
# Programs that start another program named in their arguments (#13). With one as upstream.command[0], the
# start-up checks see the launcher, not the server, unless an absolute argument or upstream.check_paths
# names the server's files. Compared by name, ignoring case and a Windows program extension.
LAUNCHERS = frozenset({"sudo", "doas", "env", "npx", "uvx", "pipx", "cmd", "powershell", "pwsh"})
_PROGRAM_EXTENSIONS = (".exe", ".cmd", ".bat", ".com")


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


def _schema_at(schema: Any, path: str) -> Mapping[str, Any] | None:
    """The JSON Schema of one dotted argument path, through nested ``properties``; None when it is not declared."""
    node = schema
    for segment in path.split("."):
        props = node.get("properties") if isinstance(node, Mapping) else None
        if not isinstance(props, Mapping) or not isinstance(props.get(segment), Mapping):
            return None
        node = props[segment]
    return node


def _read_paths(spec: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Every argument path Path A reads for a tool, with what it is: the amount and currency, each counterparty,
    and each argument-mapped custom field. Payload paths are copied unread, and a caller-supplied fact is hidden
    from the agent, so neither is listed."""
    out = []
    amount = spec.get("amount") or {}
    for key, what in (("json_path", "the amount"), ("currency_path", "the currency")):
        if isinstance(amount.get(key), str):
            out.append((amount[key], what))
    out += [(p["json_path"], "a counterparty") for p in spec.get("counterparties") or [] if isinstance(p, Mapping)]
    out += [(entry["json_path"], f"the field {name}") for name, entry in sorted(field_mappings(spec).items())
            if entry.get("source") != "caller" and isinstance(entry.get("json_path"), str)]
    return out


_ADVICE = {
    "the amount": ("the agent may write words, another currency, or cents. Describe the unit in the server, e.g. "
                   "'Amount in US dollars, a number such as 271.85'"),
    "a counterparty": ("the agent may write a display name instead of the exact id the allow list needs. Describe "
                       "the format in the server, e.g. 'Vendor id: the bare domain, such as vendor.example'"),
}
_GENERIC_ADVICE = ("the agent sees only its name and type and guesses the format. Describe it in the server: the exact "
                   "form Two-Key compares, e.g. 'Folder id, exactly as the directory shows it'")


def undescribed_advice(what: str) -> str:
    """The text after "<path> (<what>)": the same at draft time, at ``--constitution``, and at proxy start."""
    return "has no description in the upstream schema; " + _ADVICE.get(what, _GENERIC_ADVICE)


def undescribed_inputs(selection: ToolSelection, specs: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """One line per argument Path A reads that the upstream schema shows the agent with no ``description`` and no
    ``enum``. Behind the proxy that schema is the agent's only format guide, whatever the data: a payee, a folder
    id, an environment, a ticket. With nothing to go on the agent guesses, and an exact match then fails (live run
    6: payees written as display names; run 6x: a folder id's letter case). Advice, never a refusal."""
    out = []
    for tool in sorted(selection.views):
        schema = selection.views[tool].get("inputSchema")
        for path, what in _read_paths(specs.get(tool) or {}):
            node = _schema_at(schema, path)
            if node is None:
                out.append(f"{tool}: {path} ({what}) is not declared in the upstream input schema, so the agent is "
                           "not told it exists or how to write it")
                continue
            text = node.get("description")
            if (isinstance(text, str) and text.strip()) or (isinstance(node.get("enum"), list) and node["enum"]):
                continue
            out.append(f"{tool}: {path} ({what}) {undescribed_advice(what)}")
    return out


# Names that suggest an input holds a file. A hint for the operator, never a decision: what is a file is declared.
FILE_LIKE_NAME = re.compile(r"(^|_)(file|files|path|filepath|attachment|attachments|blob|base64|b64|upload|uploads)$")
_CONTENT_NAMES = ("content", "data", "bytes", "body")
MAX_SCHEMA_DEPTH = 8


def _file_like(name: str, node: Mapping[str, Any], in_file_container: bool) -> bool:
    if node.get("contentEncoding") in ("base64", "base64url") or node.get("format") in ("byte", "binary") \
            or isinstance(node.get("contentMediaType"), str):
        return True
    if node.get("type") not in ("string", None):
        return False
    low = name.casefold()
    return bool(FILE_LIKE_NAME.search(low)) or (in_file_container and low in _CONTENT_NAMES)


def file_like_inputs(schema: Any) -> list[tuple[str, str]]:
    """Inputs the upstream schema suggests hold a file, as (path, kind guess). ``[]`` marks each item of a list.
    The kind is ``path`` for a path-like name, ``base64url`` or ``base64`` from ``contentEncoding``, else
    ``base64``. A hint for the drafter and the start-up warning only."""
    out: list[tuple[str, str]] = []
    _walk_file_inputs(schema, "", 0, False, out)
    return out


def _file_kind_guess(name: str, node: Mapping[str, Any]) -> str:
    if node.get("contentEncoding") == "base64url":
        return "base64url"
    if node.get("contentEncoding") == "base64" or node.get("format") in ("byte", "binary"):
        return "base64"
    return "path" if "path" in name.casefold() else "base64"


def _walk_file_inputs(node: Any, prefix: str, depth: int, container: bool, out: list[tuple[str, str]]) -> None:
    props = node.get("properties") if isinstance(node, Mapping) else None
    if not isinstance(props, Mapping) or depth > MAX_SCHEMA_DEPTH:
        return
    for name, sub in sorted(props.items()):
        if isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) and isinstance(sub, Mapping):
            _file_input(name, sub, prefix, depth, container, out)


def _file_input(name: str, sub: Mapping[str, Any], prefix: str, depth: int, container: bool,
                out: list[tuple[str, str]]) -> None:
    """One property: walk into an object or a list of objects; otherwise note it if it looks like a file. A
    file-like name makes its objects a file container."""
    path = f"{prefix}.{name}" if prefix else name
    inner = container or bool(FILE_LIKE_NAME.search(name.casefold()))
    items = sub.get("items")
    if sub.get("type") == "array" and isinstance(items, Mapping):
        if items.get("type") == "object" or "properties" in items:
            _walk_file_inputs(items, f"{path}[]", depth + 1, inner, out)
        elif _file_like(name, items, container):
            out.append((f"{path}[]", _file_kind_guess(name, items)))
    elif sub.get("type") == "object" or "properties" in sub:
        _walk_file_inputs(sub, path, depth + 1, inner, out)
    elif _file_like(name, sub, container):
        out.append((path, _file_kind_guess(name, sub)))


def undeclared_file_inputs(selection: ToolSelection, specs: Mapping[str, Mapping[str, Any]], scanner: Any) -> list[str]:
    """One line per input of a scanned tool that looks like a file in the upstream schema but is not declared under
    ``tools.<id>.files``: it is scanned as text, not as a file. Advice, never a refusal."""
    if scanner is None:
        return []
    out = []
    for tool in sorted(selection.views):
        if not scanner.scans(specs.get(tool)):
            continue
        declared = {f.path for f in scanner.files.get(tool, ())}
        for path, kind in file_like_inputs(selection.views[tool].get("inputSchema")):
            if path not in declared:
                out.append(f"{tool}: {path} looks like a file in the upstream schema but is not declared under "
                           f"tools.{tool}.files (kind: {kind}?), so it is scanned as text, not as a file")
    return out


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


def load_hooks(config: ProxyConfig) -> dict[str, dict[str, Callable]]:
    """Import each ``tools.<id>.facts.<field>.hook`` (``module:function``): trusted operator code, like a
    ``judges.yaml`` callback. A hook that cannot be imported refuses to start."""
    out: dict[str, dict[str, Callable]] = {}
    for tool_id, policy in config.tools.items():
        for name, spec in policy.facts.items():
            module, fn = spec.split(":", 1)
            try:
                # The module named in the operator's proxy.yaml, checked by config.HOOK: trusted configuration.
                hook = getattr(importlib.import_module(module), fn)  # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
            except (ImportError, AttributeError) as e:
                raise ProxyConfigError(f"tools.{tool_id}.facts.{name}.hook: cannot import {spec!r} "
                                       f"({type(e).__name__})") from None
            if not callable(hook):
                raise ProxyConfigError(f"tools.{tool_id}.facts.{name}.hook: {spec!r} is not callable")
            out.setdefault(tool_id, {})[name] = hook
    return out


def _hide(schema: Any, paths: Iterable[str]) -> Any:
    """``schema`` without the properties at ``paths`` (dotted), also dropped from ``required``."""
    schema = copy.deepcopy(schema)
    for path in paths:
        node, parts = schema, path.split(".")
        for part in parts[:-1]:
            props = node.get("properties") if isinstance(node, dict) else None
            node = props.get(part) if isinstance(props, dict) else None
            if not isinstance(node, dict):
                break
        else:
            props = node.get("properties") if isinstance(node, dict) else None
            if isinstance(props, dict):
                props.pop(parts[-1], None)
            if isinstance(node, dict) and isinstance(node.get("required"), list):
                node["required"] = [r for r in node["required"] if r != parts[-1]]
    return schema


def caller_paths(spec: Mapping[str, Any]) -> list[str]:
    """Where an agent might write a caller-supplied fact: its delivery path, or its name at the top level."""
    out = []
    for name, entry in (spec.get("fields") or {}).items():
        if isinstance(entry, Mapping) and entry.get("source") == "caller":
            out.append(entry.get("json_path") or name)
    return sorted(out)


def _ledger_name(name: Any) -> dict:
    """A refused tool name for the ledger: the name only if it is a short identifier, else its size and digest."""
    if isinstance(name, str) and len(name) <= MAX_TOOL_NAME_CHARS and _NAME.fullmatch(name):
        return {"tool": name}
    return {"tool": None, **size_record(name if isinstance(name, str) else type(name).__name__, "tool")}


UpstreamCall = Callable[[str, dict], Any]


class ProxyCore:
    """Authorize and redeem each call through a ``Guard``, in this process, one at a time.

    ``upstream_call(upstream_name, arguments)`` runs the upstream tool and returns its result; it is the
    gateway's registered tool, so it runs only for a redeemed token, with the projected arguments (and any
    caller-supplied fact delivered at its path).
    """

    def __init__(self, two_key: Any, config: ProxyConfig, selection: ToolSelection, upstream_call: UpstreamCall,
                 *, agent_session: str | None = None, hooks: Mapping[str, Mapping[str, Callable]] | None = None):
        self.two_key = two_key
        self.config = config
        self.selection = selection
        self._agent_session = agent_session
        hooks = load_hooks(config) if hooks is None else hooks
        unused = sorted(set(hooks) - set(selection.views))
        if unused:
            raise ProxyConfigError(f"tools: fact hooks for {unused}, which the proxy does not offer")
        specs = two_key.compiled.tool_specs
        self._specs = {tool_id: specs[tool_id] for tool_id in selection.views}
        self.guard = Guard(two_key, origin=ORIGIN, agent_id=config.agent_id, hosting=config.hosting)
        self.gateway = self.guard.gateway
        for tool_id, name in selection.upstream_names.items():
            policy = config.tool_policy(tool_id)
            try:
                self.guard.add(GuardedTool(tool_id, self._tool(upstream_call, name), policy.claim,
                                           hooks.get(tool_id, {}), proposal_for(tool_id, policy)))
            except GuardConfigError as e:
                raise ProxyConfigError(f"tools.{tool_id}: {e}") from None

    @staticmethod
    def _tool(upstream_call: UpstreamCall, name: str) -> Callable[[dict], Any]:
        def run(arguments: dict) -> Any:
            return upstream_call(name, arguments)
        return run

    def list_tools(self) -> list[dict]:
        """The signed tools, with every caller-supplied field hidden from the input schema the agent sees."""
        out = []
        for tool in agent_tools(self.selection):
            hidden = caller_paths(self._specs[tool["name"]])
            if hidden and isinstance(tool.get("inputSchema"), dict):
                tool = dict(tool, inputSchema=_hide(tool["inputSchema"], hidden))
            out.append(tool)
        return out

    def record_start(self) -> None:
        """Ledger ``mcp_proxy_started``: what this proxy serves, so an audit can tie decisions to a setup."""
        command = list(self.config.upstream.command)
        body = {"upstream_program": Path(command[0]).name[:128],
                "upstream_command_digest": "sha256:" + canonical_hash(command),
                "schema_digest_pinned": self.config.upstream.schema_digest,
                "schema_digest_seen": self.selection.digest,
                "on_schema_change": self.config.upstream.on_schema_change,
                "allow_unresolved_identity": self.config.allow_unresolved_identity,
                "tools": {tool_id: {"claim": tool.claim, "facts": sorted(tool.facts)}
                          for tool_id, tool in sorted(self.guard.tools.items())},
                "signed_tools_not_listed": list(self.selection.missing)}
        self.guard.record("mcp_proxy_started", body)

    def _record_not_offered(self, name: Any) -> None:
        try:
            self.guard.record("tool_not_offered", {"origin": ORIGIN, **_ledger_name(name)})
        except Exception as e:      # still refused; the ledger write failing is reported, never an allow
            print(f"two-key: mcp-proxy: could not record tool_not_offered: {type(e).__name__}", file=sys.stderr)

    def call_tool(self, name: Any, arguments: Any) -> CallOutcome:
        if not isinstance(name, str) or name not in self._specs:
            # Not a tool this proxy offers. No token can exist for it: nothing is authorized; the attempt is ledgered.
            shown = safe_reason(name)[:80] if isinstance(name, str) else type(name).__name__
            print(f"two-key: mcp-proxy: refused a call to a tool it does not offer: {shown!r}", file=sys.stderr)
            self._record_not_offered(name)
            return CallOutcome(False, "tool_not_offered", stage="proxy")
        result = self.guard.call(name, arguments, agent_session=self._agent_session)
        return CallOutcome(result.allowed, result.reason, result.output, stage=result.stage)


def build_two_key(config: ProxyConfig, *, judge_transport: Any = None) -> Any:
    """``TwoKey`` from the files the config names, the same way ``two-key authorize`` loads them."""
    from .. import agent_access
    from ..constitution import ConstitutionError, ConstitutionSignatureError, load_envelope
    from ..core import TwoKey, TwoKeyConfigError
    from ..identity import IdentityError, load_monitored_agent_file
    from ..judges.config import JudgeConfigError, load_config_file
    from ..keys import load_public_key
    from ..ledger import Ledger, LedgerError
    from ..scan import ScanConfigError
    from ..scanners import scanner_from_config
    from ..siem import SiemConfigError
    from ..siem_sinks import siem_from_config
    try:
        scanner = None
        if config.scan is not None:
            scanner = scanner_from_config(config.scan, {tool: policy.files for tool, policy in config.tools.items()
                                                        if policy.files})
        key = config.load_principal_key(prompt=False)
        judges, policy = load_config_file(config.judges, judge_transport)
        missing = cloud_session_missing(config, judges)
        if missing:
            raise ProxyConfigError(f"{missing}; the proxy refuses to start")
        high = bool(getattr(policy, "is_high_assurance", False))
        check_upstream_paths(config.upstream, high)
        paths = startup_paths(config)
        agent_access.check(paths, agent_access.resolve_mode(config.on_agent_access, high),
                           why="high_assurance" if high else
                           f"on_agent_access: {config.on_agent_access or 'refuse (the default)'}")
        agent = load_monitored_agent_file(config.judges)
        witness = load_public_key(config.witness_public_key) if config.witness_public_key else None
        siem = siem_from_config(config.siem, config.path.parent) if config.siem is not None else None
        ledger = Ledger(config.ledger, key, witness_public_key=witness, anchor_path=config.head_anchor)
        tk = TwoKey.load(ledger, key.public_key(), load_envelope(config.constitution), judges,
                         private_key=key, quorum=policy, monitored_agent=agent, ttl_seconds=config.ttl_seconds,
                         scanner=scanner, on_writable_paths=config.on_writable_paths,
                         check_paths=paths, siem=siem, known_agent_ids=[config.agent_id] if config.agent_id else ())
        hold_agent_lock(tk, config)
        return tk
    except ProxyConfigError:
        raise
    except (OSError, ValueError, JudgeConfigError, IdentityError, LedgerError, ConstitutionError,
            ConstitutionSignatureError, TwoKeyConfigError, ScanConfigError, SiemConfigError) as e:
        raise ProxyConfigError(f"{type(e).__name__}: {e}") from None


def cloud_session_missing(config: ProxyConfig, judges: Any) -> str | None:
    """Why a proxy with these judges could approve nothing, or None. A cloud judge (one not on this machine's
    loopback address, or a ``:cloud`` model) votes only on a call that comes with the agent's session, and the
    proxy has that session only through ``agent_session_env``. Without it, every call that reaches the judges
    is denied ``cloud_judge_session_required``, so ``mcp-proxy`` refuses to start and ``config check`` fails."""
    if config.agent_session_env:
        return None
    cloud = sorted(str(j.judge_id) for j in judges if getattr(j, "is_cloud", lambda: False)())
    if not cloud:
        return None
    return (f"cloud_judge_session_required: judge(s) {', '.join(cloud)} are not on this machine, and "
            "agent_session_env is not set, so every call they judge would be denied; set agent_session_env to the "
            "name of the variable that holds the agent's session (docs/CONNECTING.md)")


def hold_agent_lock(tk: Any, config: ProxyConfig) -> None:
    """One proxy per agent on a ledger (0.8.0, D10). Take this agent's lock and keep it for the life of the
    process; if another running proxy holds it, ledger ``agent_already_connected`` (sent to the SIEM) and refuse.

    The lock goes when the process exits, however it exits. A proxy with no ``agent_id`` counts as one agent,
    ``unnamed``. With ``one_proxy_per_agent: false`` nothing is taken and a warning says so."""
    from .. import _platform
    agent = config.agent_id or "unnamed"
    if not config.one_proxy_per_agent:
        print("two-key: WARNING: one_proxy_per_agent: false: more than one proxy may serve this agent on this "
              "ledger at once; only the re-check at mint (history_changed) keeps their judges' history in step",
              file=sys.stderr)
        return
    fd = _platform.open_lock_file(tk.ledger.agent_lock_path(agent))
    if _platform.try_lock(fd):
        tk.agent_lock_fd = fd       # held until the process exits
        return
    os.close(fd)
    try:
        tk.ledger.record("agent_already_connected", {"agent_id": agent, "origin": ORIGIN})
    finally:
        tk.close()
    raise ProxyConfigError(f"agent_already_connected: another two-key mcp-proxy is serving agent {agent!r} on this "
                           "ledger; stop it first (a dead SSH session's proxy goes with sshd ClientAliveInterval), "
                           "or give each session its own agent_id, or set one_proxy_per_agent: false")


def _program(name: str) -> str | None:
    return shutil.which(name) or (name if os.path.isabs(name) else None)


def _module_origin(module: str) -> str | None:
    """The file a hook module would be imported from, found without running it (its parent packages do run,
    as they would when the hook is imported)."""
    try:
        spec = importlib.util.find_spec(module)
    except Exception:       # loading the hooks refuses to start with the reason
        return None
    origin = getattr(spec, "origin", None)
    return origin if isinstance(origin, str) and os.path.isabs(origin) else None


def launcher(program: str) -> str | None:
    """The launcher ``program`` names (``sudo`` for ``/usr/bin/sudo``, ``npx`` for ``NPX.CMD``), or None."""
    name = os.path.basename(program).casefold()
    for extension in _PROGRAM_EXTENSIONS:
        if name.endswith(extension):
            name = name[:-len(extension)]
            break
    return name if name in LAUNCHERS else None


def _rule(path: Path | str) -> str:
    return "folder" if os.path.isdir(path) else "file"


def upstream_paths(upstream: UpstreamConfig) -> list[tuple[Path | str, str]]:
    """The upstream server's own files beyond its program (#13): each argument of ``upstream.command`` after
    the first that is an absolute path to something that exists, and each ``upstream.check_paths`` entry.
    A file comes with its folder, checked as a folder: a script's folder is where Python, Node, and most
    others look for what it imports. Options and relative arguments are not read as paths, and a launcher is
    not followed to its target. A ``check_paths`` entry that does not exist refuses
    (``check_path_missing``): the operator named it so that it would be checked."""
    paths: list[tuple[Path | str, str]] = []
    named = [arg for arg in upstream.command[1:] if os.path.isabs(arg) and os.path.lexists(arg)]
    for i, entry in enumerate(upstream.check_paths):
        if not os.path.exists(entry):
            raise ProxyConfigError(f"check_path_missing: upstream.check_paths[{i}]: {entry} does not exist; "
                                   "fix the path or remove the entry")
        named.append(entry)
    for path in named:
        rule = _rule(path)
        paths.append((path, rule))
        if rule == "file":
            paths.append((os.path.dirname(os.path.abspath(path)), "folder"))
    return paths


def check_upstream_paths(upstream: UpstreamConfig, high_assurance: bool, *, stream=None) -> str | None:
    """``upstream_paths_unchecked`` when ``upstream.command`` starts with a launcher and nothing names the
    server's files: a warning on stderr, or under ``high_assurance`` a refusal. Returns the line, or None."""
    name = launcher(upstream.command[0])
    if name is None or upstream_paths(upstream):
        return None
    line = (f"upstream_paths_unchecked: upstream.command starts with {name}, so the start-up checks see {name} "
            "and not the server it starts; name the server's files and folders in upstream.check_paths, or "
            "give them as absolute arguments (docs/CONNECTING.md)")
    if high_assurance:
        raise ProxyConfigError(f"{line}; high_assurance refuses to start")
    print(f"two-key: WARNING: {line}", file=sys.stderr if stream is None else stream)
    return line


def startup_paths(config: ProxyConfig) -> list[tuple[Path | str, str]]:
    """What the proxy reads or starts, for the writable-path check at start (two_key/writable.py): its
    config and the files it names, the ledger, the upstream program and the folder it starts in (the
    proxy's own when ``upstream.cwd`` is unset, which under sudo is the caller's), the upstream's own files
    (``upstream_paths``), each fact hook's module, the folders of files sent by path, and a command
    scanner's program. (clamd's socket belongs to clamd's own account, so it is left to the checklist in
    docs/CONNECTING.md.)"""
    paths: list[tuple[Path | str, str]] = [(config.path, "file"), (config.constitution, "file"),
                                           (config.principal_key, "file"), (config.judges, "file"),
                                           (config.ledger, "folder")]
    for extra in (config.witness_public_key, config.head_anchor, config.principal_passphrase_file):
        if extra is not None:
            paths.append((extra, "file"))
    paths.append((config.upstream.cwd or Path.cwd(), "folder"))
    program = _program(config.upstream.command[0])
    if program:
        paths.append((program, "file"))
    paths.extend(upstream_paths(config.upstream))
    for policy in config.tools.values():
        paths.extend(_tool_paths(policy))
    paths.extend(_scanner_paths(config.scan or {}))
    paths.extend(_siem_paths(config.siem or {}, config.path.parent, config.ledger))
    return paths


def _siem_paths(siem: Mapping[str, Any], base: Path, ledger: Path | str) -> list[tuple[Path | str, str]]:
    """The files a SIEM sink reads: a CA bundle, a client certificate and its key, a webhook token, and an
    HMAC key. Whoever can change one of them can redirect or read the copy. The delivery cursor too: whoever
    can change it can make the copy repeat or skip entries (live run 8x, C40; docs/CONNECTING.md says it is
    checked)."""
    from ..siem import default_cursor_path
    out: list[tuple[Path | str, str]] = [(default_cursor_path(ledger), "file")]
    for sink in siem.get("sinks") or ():
        if not isinstance(sink, Mapping):
            continue
        for name in ("ca_file", "cert_file", "key_file", "auth_value_file", "hmac_key_file"):
            value = sink.get(name)
            if isinstance(value, str) and value:
                path = Path(value).expanduser()
                out.append((path if path.is_absolute() else base / path, "file"))
    return out


def _tool_paths(policy: ToolPolicy) -> list[tuple[Path | str, str]]:
    """A tool's fact hook modules, and the folders of the files it takes by path."""
    paths: list[tuple[Path | str, str]] = []
    for spec in policy.facts.values():
        origin = _module_origin(spec.split(":", 1)[0])
        if origin:
            paths.append((origin, "file"))
    for arg in policy.files:
        if arg.kind == "path" and arg.folder:
            paths.append((arg.folder, "folder"))
    return paths


def _scanner_paths(scan: Mapping[str, Any]) -> list[tuple[Path | str, str]]:
    """A command scanner's program."""
    command = scan.get("command")
    if scan.get("type") == "command" and isinstance(command, list) and command and isinstance(command[0], str):
        program = _program(command[0])
        if program:
            return [(program, "file")]
    return []


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
