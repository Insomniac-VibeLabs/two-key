"""Draft ``tool_specs`` from an upstream server's tool schemas (``two-key mcp-draft-specs``). No MCP SDK here.

A draft is a starting point for the principal to review and sign, never a signed policy. It fails closed:
whatever the principal must decide is written so that ``two-key sign-constitution`` refuses it until they
do:

- ``data_class_floor: REPLACE_WITH_DATA_CLASS`` for every tool;
- an amount-like property (``amount``, ``price``, ``total``, ...) becomes ``amount`` with
  ``unit: REPLACE_WITH_usd_OR_cents``;
- a payee-like property (``vendor``, ``recipient``, ``to``, ...) becomes a counterparty with an empty
  ``allow`` list.

``irreversible`` is ``false`` only for a tool the server marks ``readOnlyHint: true``; otherwise ``true``.
A server's hints are claims too: review them.

A fact-like property (``*_matched``, ``*_verified``, ``*_approved``, ``*_confirmed``, ``*_validated``) is a
claim about the world the agent would write. The draft leaves it out of the spec, so the tool never receives
the agent's value, and lists it as a candidate for a caller-supplied fact (``source: caller``, HOWTO "Caller-
supplied facts"). The proxy then hides it from the agent and delivers the hook's value instead.

Behind the proxy, the upstream schema is the agent's only format guide. A property the draft maps as a
counterparty or an amount with no ``description`` gets a WARNING: the agent then guesses the format, and a
display name ("Alpine MedSupply (alpine-medsupply.example)") is not on an exact allow list (live run 6, C25).

Only top-level properties are read. A nested object is one payload path, copied unread; review it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..action import MAX_TOOL_NAME_CHARS, TOOL_NAME
from .core import pinned_view, schema_digest, undescribed_advice

FACT_LIKE = re.compile(r"(^|_)(matched|verified|approved|confirmed|validated)$")
AMOUNT_LIKE = re.compile(r"^(amount|amount_usd|amount_cents|price|total|cost|sum|value_usd|usd|cents)$")
PARTY_LIKE = re.compile(r"^(vendor|payee|recipient|recipients|to|cc|bcc|email|counterparty|customer|account|"
                        r"account_id|beneficiary|destination|dest|target_user)$")
PATH_SEGMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
MAX_DESCRIPTION_IN_COMMENT = 160


@dataclass
class ToolDraft:
    tool_id: str
    upstream_name: str
    spec: dict
    notes: list[str] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class Draft:
    tools: list[ToolDraft]
    skipped: list[str]
    digest: str
    views: list[dict]

    @property
    def fact_candidates(self) -> dict[str, list[str]]:
        return {t.tool_id: t.facts for t in self.tools if t.facts}

    @property
    def warnings(self) -> dict[str, list[str]]:
        return {t.tool_id: t.warnings for t in self.tools if t.warnings}


def _described(schema: Mapping[str, Any]) -> bool:
    text = schema.get("description")
    return isinstance(text, str) and bool(text.strip())


def _comment(text: str) -> str:
    """One comment line: printable ASCII only, so server text cannot end the comment or hide characters."""
    clean = "".join(c if 0x20 <= ord(c) < 0x7F else "?" for c in text)
    return clean[:MAX_DESCRIPTION_IN_COMMENT] + ("..." if len(clean) > MAX_DESCRIPTION_IN_COMMENT else "")


def _wrapped(text: str, width: int = 100) -> list[str]:
    """Our own note as comment lines: each made ASCII-safe like server text, wrapped instead of cut."""
    words, lines, line = text.split(), [], ""
    for word in words:
        if line and len(line) + 1 + len(word) > width:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}" if line else word
    lines.append(line)
    return [f"  # - {_comment(lines[0])}"] + [f"  #   {_comment(rest)}" for rest in lines[1:]]


def _payload(path: str, schema: Mapping[str, Any]) -> dict:
    kind = schema.get("type")
    entry: dict[str, Any] = {"json_path": path}
    if kind == "string":
        entry["shape"] = "string"
        if isinstance(schema.get("maxLength"), int) and schema["maxLength"] >= 1:
            entry["max_length"] = schema["maxLength"]
    elif kind in ("number", "integer"):
        entry["shape"] = "number"
    elif kind == "array" and isinstance(schema.get("items"), Mapping) and schema["items"].get("type") == "string":
        entry["shape"] = "list"
        if isinstance(schema.get("maxItems"), int) and schema["maxItems"] >= 1:
            entry["max_length"] = schema["maxItems"]
    return entry


def draft_tool(view: Mapping[str, Any]) -> ToolDraft | str:
    """A draft spec for one tool, or the reason it was skipped."""
    name = view.get("name")
    tool_id = name.casefold() if isinstance(name, str) else ""
    if not tool_id or len(tool_id) > MAX_TOOL_NAME_CHARS or not TOOL_NAME.fullmatch(tool_id):
        return f"{str(name)[:80]!r}: not usable as a signed tool id (a-z, 0-9, _ . : / -)"
    annotations = view.get("annotations") or {}
    read_only = annotations.get("readOnlyHint") is True
    spec: dict[str, Any] = {"irreversible": not read_only, "data_class_floor": "REPLACE_WITH_DATA_CLASS"}
    draft = ToolDraft(tool_id, name, spec)
    if read_only:
        draft.notes.append("irreversible: false because the server says readOnlyHint: true (a claim; review it)")
    else:
        draft.notes.append("irreversible: true (the server does not say readOnlyHint: true)")
    schema = view.get("inputSchema") or {}
    props = schema.get("properties") if isinstance(schema, Mapping) else None
    parties, payload = [], []
    for prop, sub in sorted((props or {}).items()):
        sub = sub if isinstance(sub, Mapping) else {}
        if not isinstance(prop, str) or not PATH_SEGMENT.fullmatch(prop):
            draft.notes.append(f"property {_comment(str(prop))!r} is not a dotted-identifier path; it is left "
                               "out, so the tool never receives it")
            continue
        low = prop.casefold()
        if FACT_LIKE.search(low):
            draft.facts.append(prop)
            draft.notes.append(f"{prop}: fact-like, left out (the agent would assert it); make it a caller-supplied "
                               f"fact (fields: {prop}: {{type: ..., default: ..., source: caller}}; map it as "
                               f"{{source: caller, json_path: {prop}}}; add a hook under tools.<id>.facts in "
                               "proxy.yaml), or have the tool check it")
        elif AMOUNT_LIKE.fullmatch(low) and "amount" not in spec and sub.get("type") in ("number", "integer", None):
            unit = "cents" if "cents" in low else "REPLACE_WITH_usd_OR_cents"
            spec["amount"] = {"json_path": prop, "unit": unit}
            draft.notes.append(f"{prop}: amount-like, mapped as the amount; set unit (usd or cents)")
            if not _described(sub):
                draft.warnings.append(f"{prop} (the amount) {undescribed_advice('the amount')}")
        elif PARTY_LIKE.fullmatch(low) and sub.get("type") in ("string", "array", None):
            parties.append({"json_path": prop, "allow": []})
            draft.notes.append(f"{prop}: payee-like, mapped as a counterparty; fill its allow list")
            if not _described(sub):
                draft.warnings.append(f"{prop} (a counterparty) {undescribed_advice('a counterparty')}")
        else:
            payload.append(_payload(prop, sub))
    if parties:
        spec["counterparties"] = parties
    if payload:
        spec["payload"] = payload
    return draft


def draft_specs(upstream_tools: list[Mapping[str, Any]], only: list[str] | None = None) -> Draft:
    """Drafts for the upstream tools (all, or the upstream names in ``only``)."""
    wanted = None if not only else set(only)
    tools, skipped, views, seen = [], [], [], set()
    for tool in sorted(upstream_tools, key=lambda t: str(t.get("name"))):
        view = pinned_view(tool)
        seen.add(view.get("name"))
        if wanted is not None and view.get("name") not in wanted:
            continue
        result = draft_tool(view)
        if isinstance(result, str):
            skipped.append(result)
            continue
        tools.append(result)
        views.append(view)
    skipped.extend(f"{name!r}: the upstream does not list it" for name in sorted((wanted or set()) - seen))
    ids = [t.tool_id for t in tools]
    if len(set(ids)) != len(ids):
        raise ValueError("two upstream tools differ only in case; pick one with --tool")
    return Draft(tools, skipped, schema_digest(views), views)


def _yaml_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True)   # JSON is valid YAML; ASCII keeps server text visible


def render_rules(draft: Draft, command: list[str]) -> str:
    """The draft rules file: YAML with review comments. Signing refuses it until every placeholder is gone."""
    lines = [
        "# DRAFT tool specs from two-key mcp-draft-specs. Review every line before signing.",
        f"# Upstream: {_comment(' '.join(command))}",
        f"# schema_digest of these tools: {draft.digest}",
        "# sign-constitution refuses this file until you replace every REPLACE_WITH_* value and fill every",
        "# empty allow list. Remove the tools the agent should not have; the digest changes if you do (the",
        "# proxy prints the digest it sees). A server's descriptions and hints are its claims, not facts.",
        "hard_rules:",
        f"  - {{id: tools, allow_only_tools: {_yaml_value([t.tool_id for t in draft.tools])}}}",
        "tool_specs:",
    ]
    if not draft.tools:
        lines[-1] = "tool_specs: {}"
    for t in draft.tools:
        view = next(v for v in draft.views if v.get("name") == t.upstream_name)
        lines.append(f"  # {t.tool_id}: {_comment(str(view.get('description') or '(no description)'))}")
        if t.upstream_name != t.tool_id:
            lines.append(f"  # upstream name {_comment(t.upstream_name)!r}: set tools.{t.tool_id}.upstream_name "
                         "in proxy.yaml")
        for note in t.notes:
            lines.append(f"  # - {_comment(note)}")
        for warning in t.warnings:
            lines.extend(_wrapped(f"WARNING: {warning}"))
        lines.append(f"  {_yaml_value(t.tool_id)}:")
        for key in ("irreversible", "data_class_floor", "amount", "counterparties", "payload"):
            if key in t.spec:
                lines.append(f"    {key}: {_yaml_value(t.spec[key])}")
    if draft.skipped:
        lines.append("# Not drafted:")
        lines.extend(f"# - {_comment(s)}" for s in draft.skipped)
    return "\n".join(lines) + "\n"


def render_proxy_tools(draft: Draft) -> str:
    """A ``tools:`` block for proxy.yaml with the conservative default claim."""
    lines = ["# For proxy.yaml. claim: none (classified) is the default; floor uses the signed data_class_floor.",
             "tools:"]
    if not draft.tools:
        return lines[0] + "\ntools: {}\n"
    for t in draft.tools:
        lines.append(f"  {_yaml_value(t.tool_id)}:")
        lines.append("    claim: none")
        if t.upstream_name != t.tool_id:
            lines.append(f"    upstream_name: {_yaml_value(t.upstream_name)}")
    return "\n".join(lines) + "\n"


def signed_digest(upstream_tools: list[Mapping[str, Any]], envelope: Mapping[str, Any],
                  upstream_names: Mapping[str, str] | None = None) -> tuple[str, tuple[str, ...]]:
    """The ``schema_digest`` the proxy will compute for a signed constitution's tools, and the signed tools the
    upstream does not list. The constitution is read, not verified: this only prints a digest, and the proxy
    verifies the signature when it starts."""
    digest, missing, _ = signed_check(upstream_tools, envelope, upstream_names)
    return digest, missing


def signed_check(upstream_tools: list[Mapping[str, Any]], envelope: Mapping[str, Any],
                 upstream_names: Mapping[str, str] | None = None) -> tuple[str, tuple[str, ...], list[str]]:
    """``signed_digest`` plus the arguments the signed specs read that the upstream schema leaves undescribed
    (``core.undescribed_inputs``): any custom field, counterparty, or amount, not only what a draft maps."""
    from .config import ToolPolicy
    from .core import select_tools, undescribed_inputs
    signed = envelope.get("signed") if isinstance(envelope, Mapping) else None
    specs = signed.get("tool_specs") if isinstance(signed, Mapping) else None
    if not isinstance(specs, Mapping):
        raise ValueError("not a signed constitution (no signed.tool_specs)")
    policies = {tool: ToolPolicy(upstream_name=name) for tool, name in (upstream_names or {}).items()}
    selection = select_tools(upstream_tools, specs, policies)
    return selection.digest, selection.missing, undescribed_inputs(selection, specs)
