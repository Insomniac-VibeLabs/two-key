# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Signed constitution: prose for Path B, hard rules for Path A, and tool specs."""

from __future__ import annotations

import json
import os
import re

from .strict import StrictParseError, load_file_strict, loads_json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from . import _platform
from .action import DATA_CLASSES, DEFAULT_DATA_CLASS, DEFAULT_IRREVERSIBLE
from .canonical import canonical_bytes, canonical_hash
from .fields import (MAX_FIELDS_PER_TOOL, NOT_APPLICABLE, FieldError, check_path, has_caller_fields,
                     has_exact_fields, has_path_fields, is_caller, rule_fields, validate_fields)
from .derive import DOMAIN, is_domain_entry
from .keys import classical_half, fingerprint, is_hybrid, sign, verify
from .policy_vm import ConstitutionError, validate_rules
from .roster import roster_of, validate_agents, validate_tool_agents

FORMAT_V1 = "two-key-constitution-v1"
# v2 may carry a custom-field registry (``fields``) and refuses any other unknown signed key.
FORMAT_V2 = "two-key-constitution-v2"
# v3 may also declare caller-supplied fields (``source: caller``) and ``case: exact`` string fields, and mark a
# field ``not_applicable`` for a tool. The format label is outside the signed bytes, so the meaning comes from
# the signed bytes only: a v1 or v2 label on a constitution that uses any of them is refused, never read as an
# argument field, a case-insensitive field, or a mapping.
FORMAT_V3 = "two-key-constitution-v3"
ENVELOPE_FORMATS = ("auto", "v2", "v3")
_V2_SIGNED_KEYS = {"prose", "hard_rules", "tool_specs", "fields"}
# The principal's ordering of constitutions (live run 9x, C44): a positive integer, signed, v3 only. A ledger that has
# run serial N refuses a lower one and refuses N again with other bytes (two_key.core).
# The signed agent roster (0.9.0, two_key/roster.py) is v3 only too: an older install refuses it as an unknown key.
_V3_SIGNED_KEYS = _V2_SIGNED_KEYS | {"serial", "agents"}
# The keys the loaders accept in a rules file and in a tool spec. Named here so docs/SETTINGS.md and its test
# (two_key/settings.py) read the same sets the validators use.
RULES_FILE_KEYS = ("hard_rules", "tool_specs", "fields", "serial", "agents")
TOOL_SPEC_KEYS = ("irreversible", "data_class_floor", "amount", "counterparties", "payload", "deny_unmapped",
                  "fields", "tool_check", "agents")
# A tool's check (#28, docs/TOOL_CHECK.md): the fingerprint of the tool's receipt key, or "exempt".
# Hybrid only (0.9.0): the tool check has no classical keys to stay compatible with.
TOOL_CHECK_KEY = re.compile(r"hybrid-sha256:[0-9a-f]{64}")
TOOL_CHECK_KEYS = ("key",)
AMOUNT_KEYS = ("json_path", "unit", "currency_path")
COUNTERPARTY_KEYS = ("json_path", "allow")
PAYLOAD_KEYS = ("json_path", "shape", "max_length")
FIELD_MAPPING_KEYS = ("json_path", "source", "encrypted")


def _tool_check(tool: str, spec: Mapping) -> dict:
    """``{"tool_check": ...}`` when the spec sets it, else ``{}``. The value is ``exempt``, or
    ``{key: "hybrid-sha256:<64 hex>"}``: the fingerprint of the hybrid key that signs the tool's receipts."""
    if "tool_check" not in spec:
        return {}
    value = spec["tool_check"]
    if value == "exempt":
        return {"tool_check": value}
    if isinstance(value, Mapping) and set(value) == set(TOOL_CHECK_KEYS) and isinstance(value["key"], str) \
            and TOOL_CHECK_KEY.fullmatch(value["key"]):
        return {"tool_check": {"key": value["key"]}}
    raise ConstitutionError(f"tool_specs.{tool}.tool_check: expected exempt or {{key: hybrid-sha256:<64 hex digits>}} "
                            "(two-key tool-key new prints the fingerprint)")


class ConstitutionSignatureError(ValueError):
    pass


@dataclass(frozen=True)
class Constitution:
    prose: str
    hard_rules: list[dict]
    document: dict
    tool_specs: dict
    specs_enforced: bool
    fields: dict = field(default_factory=dict)   # canonical custom-field registry; empty without one

    @property
    def serial(self) -> int | None:
        """The signed serial, or None for a constitution signed without one."""
        return self.document["signed"].get("serial")

    @property
    def digest(self) -> str:
        return canonical_hash(self.document["signed"])

    @property
    def agents(self) -> tuple:
        """The signed agent roster (two_key/roster.py) as ``RosterAgent`` entries; empty without one."""
        return roster_of(self.document["signed"].get("agents"))


_PATH = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")


def _json_path(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _PATH.fullmatch(value):
        raise ConstitutionError(f"{where}: json_path must be dotted identifiers")
    return value


def _allow_listed(rules: list) -> list[str]:
    found: list[str] = []
    for rule in rules:
        if not isinstance(rule, Mapping) or "allow_only_tools" not in rule:
            continue
        body = rule["allow_only_tools"]
        if not isinstance(body, list):
            continue
        for item in body:
            if isinstance(item, str) and item.strip():
                name = item.strip().casefold()
                if name not in found:
                    found.append(name)
    return found


def _field_error(e: FieldError) -> ConstitutionError:
    return ConstitutionError(str(e))


def _overlaps(a: str, b: str) -> bool:
    """Equal, ancestor, or descendant, without regard to case."""
    a, b = a.casefold(), b.casefold()
    return a == b or a.startswith(b + ".") or b.startswith(a + ".")


# The scan verdict for an encrypted file the principal lets a tool pass (scan.py). Only an enum caller field
# with this value may carry ``encrypted: pass``; Two-Key checks at start that it is the scan field.
ENCRYPTED = "encrypted"


def _field_mapping(where: str, defn: Mapping, entry: Any) -> dict:
    """One field's mapping: ``{json_path}`` for an argument field; ``{source: caller}`` or
    ``{source: caller, json_path}`` for a caller-supplied fact (the path is where the tool receives it). The scan
    field may add ``encrypted: pass``."""
    if is_caller(defn):
        _check_caller_mapping(where, defn, entry)
        return dict(entry)
    if not isinstance(entry, Mapping) or set(entry) != {"json_path"}:
        if isinstance(entry, Mapping) and "source" in entry:
            raise ConstitutionError(f"{where}: source: caller needs the field declared source: caller under fields:")
        raise ConstitutionError(f"{where}: expected json_path only, or not_applicable")
    return dict(entry)


def _check_caller_mapping(where: str, defn: Mapping, entry: Any) -> None:
    if not isinstance(entry, Mapping) or entry.get("source") != "caller" or \
            set(entry) - set(FIELD_MAPPING_KEYS):
        raise ConstitutionError(f"{where}: a caller-supplied field maps as {{source: caller}} or "
                                "{source: caller, json_path: ...}")
    if "encrypted" not in entry:
        return
    if entry["encrypted"] != "pass":
        raise ConstitutionError(f"{where}.encrypted: expected pass (omit it and an encrypted file is "
                                "flagged)")
    if defn.get("type") != "enum" or ENCRYPTED not in (defn.get("values") or ()):
        raise ConstitutionError(f"{where}.encrypted: only the scan field takes encrypted: pass, an enum "
                                "whose values include encrypted")


V3_FEATURES = ("caller-supplied fields (source: caller), case: exact fields, path fields, not_applicable marks, "
               "and @domain allow entries")


def validate_serial(value: Any) -> int | None:
    """A constitution serial: absent (None) or a positive integer. ``true`` and ``1.0`` are not serials."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2 ** 53:
        raise ConstitutionError("serial must be a positive integer (the principal's order of constitutions)")
    return value


def uses_v3(registry: Mapping, specs: Mapping) -> bool:
    """True when the signed bytes need a 0.5.0 reader: a caller-supplied, ``case: exact`` or path field, a
    ``not_applicable`` mark, or an @domain entry. (A path field needs 0.9.0; earlier v3 readers refuse its type.)"""
    return has_caller_fields(registry) or has_exact_fields(registry) or has_path_fields(registry) or any(
        entry == NOT_APPLICABLE for spec in specs.values() for entry in (spec.get("fields") or {}).values()) or any(
        is_domain_entry(item) for spec in specs.values() for party in spec.get("counterparties") or []
        for item in party.get("allow") or [])


def domain_allow_notes(specs: Mapping) -> list[tuple[bool, str]]:
    """What each @domain allow entry admits, for the signer. Takes canonical tool specs.

    ``warn`` is true when the tool also passes text Path A does not read (a payload that is not a number): anyone at
    that domain can receive it, and only the judges check what it says (live run 6x, X31)."""
    out: list[tuple[bool, str]] = []
    for tool in sorted(specs):
        spec = specs[tool]
        unread = [p["json_path"] for p in spec.get("payload") or [] if p.get("shape") != "number"]
        for party in spec.get("counterparties") or []:
            domains = [item for item in party.get("allow") or [] if is_domain_entry(item)]
            if not domains:
                continue
            text = f"tool {tool!r}: {party['json_path']} allows any address at {', '.join(domains)}"
            if unread:
                text += (f"; Path A does not read {', '.join(unread)}, so anyone there can receive what it carries, "
                         "and only the judges check it")
            out.append((bool(unread), text))
    return out


def encrypted_pass_notes(specs: Mapping) -> list[str]:
    """Each tool signed to pass encrypted files, for the signer. Takes canonical tool specs.

    The scanner cannot see inside them, so on that tool encryption is a way past it; the tool's allow lists and
    the judges are what still check where they go."""
    out = []
    for tool in sorted(specs):
        marked = [name for name, entry in sorted((specs[tool].get("fields") or {}).items())
                  if isinstance(entry, Mapping) and entry.get("encrypted") == "pass"]
        if marked:
            out.append(f"tool {tool!r}: {', '.join(marked)} has encrypted: pass, so encrypted files reach it without "
                       "a look inside; only the receiving side can scan them")
    return out


MAX_MISSING_SHOWN = 100


def _require_field_decisions(specs: Mapping, rules: list) -> None:
    """Every tool decides each field a deny_if_fields rule reads: it maps the field, or marks it not_applicable.

    A forgotten mapping would hand the tool the field's default, which can switch the rule off for it without
    a word. It is refused here, at signing and on load, for argument and caller-supplied fields alike.
    """
    read = rule_fields(rules)
    missing = [f"tool_specs.{tool}.fields.{name} ({'rule' if len(ids) == 1 else 'rules'} "
               f"{', '.join(repr(i) for i in ids)})"
               for tool in sorted(specs) for name, ids in sorted(read.items())
               if name not in (specs[tool].get("fields") or {})]
    if missing:
        # Every one, so a principal fixes them in one pass (live run 6z: eight of eleven were shown); bounded only
        # against a pathological file.
        shown = "; ".join(missing[:MAX_MISSING_SHOWN]) + (
            f"; and {len(missing) - MAX_MISSING_SHOWN} more" if len(missing) > MAX_MISSING_SHOWN else "")
        raise ConstitutionError(
            "each tool must map every field a deny_if_fields rule reads, or mark it not_applicable "
            f"(name: not_applicable under the tool's fields:): {shown}")


class _PathSet:
    """The paths one tool spec declares. A path given twice is refused."""

    def __init__(self) -> None:
        self.seen: set[str] = set()

    def take(self, path: str, where: str) -> str:
        if path in self.seen:
            raise ConstitutionError(f"{where}: duplicate path")
        self.seen.add(path)
        return path


def _field_mappings(tool: str, mapped: Any, registry: Mapping, control_paths: list, take) -> dict:
    """``tool_specs.<tool>.fields``: declared field name -> mapping, or ``not_applicable`` for a field this tool
    does not carry (it gets the signed default). Adds each path to ``control_paths``.

    A path must not equal, contain, or sit under another declared path, compared without regard to case. A
    caller-supplied field may have no path (the tool does not receive it).
    """
    out: dict[str, dict] = {}
    if mapped is None:
        return out
    if not isinstance(mapped, Mapping) or not mapped:
        raise ConstitutionError(f"tool_specs.{tool}.fields: expected a non-empty mapping")
    if len(mapped) > MAX_FIELDS_PER_TOOL:
        raise ConstitutionError(f"tool_specs.{tool}.fields: more than {MAX_FIELDS_PER_TOOL} fields")
    for fname, entry in mapped.items():
        where = f"tool_specs.{tool}.fields.{fname}"
        if not isinstance(fname, str) or fname not in registry:
            raise ConstitutionError(f"{where}: not a declared field (add it under fields:)")
        if entry == NOT_APPLICABLE:
            out[fname] = NOT_APPLICABLE
            continue
        entry = _field_mapping(where, registry[fname], entry)
        passes = {"encrypted": entry["encrypted"]} if "encrypted" in entry else {}
        if "json_path" not in entry:
            out[fname] = {"source": "caller", **passes}
            continue
        try:
            path = check_path(_json_path(entry["json_path"], where), where)
        except FieldError as e:
            raise _field_error(e) from None
        path = take(path, where)
        for other in control_paths:
            if _overlaps(path, other):
                raise ConstitutionError(f"{where}: field path {path!r} overlaps the path {other!r}")
        control_paths.append(path)
        out[fname] = {"json_path": path, **({"source": "caller"} if is_caller(registry[fname]) else {}), **passes}
    return out


def _tool_agents(tool: str, spec: Mapping, agents: list | None) -> dict:
    """A tool's ``agents`` (two_key/roster.py), canonical; empty when the spec sets none."""
    if "agents" not in spec:
        return {}
    roster_ids = None if agents is None else [a["id"] for a in agents]
    return {"agents": validate_tool_agents(tool, spec["agents"], roster_ids)}


def _spec_tool_name(name: Any, seen: Mapping) -> str:
    """A tool spec's name, canonical (trimmed, case-folded), refused when empty or already used."""
    if not isinstance(name, str) or not name.strip():
        raise ConstitutionError("tool_specs: tool name must be a non-empty string")
    tool = name.strip().casefold()
    if tool in seen:
        raise ConstitutionError(f"tool_specs: duplicate tool {tool}")
    return tool


def _spec_basics(tool: str, spec: Any) -> tuple[bool, str]:
    """The spec's own keys checked, and its ``irreversible`` and canonical ``data_class_floor``.

    Both are optional. Left out, they take the fail-closed defaults, written into the signed spec, so a spec
    that leaves them out signs as if it had written them."""
    if not isinstance(spec, Mapping):
        raise ConstitutionError(f"tool_specs.{tool}: expected a mapping")
    extra = set(spec) - set(TOOL_SPEC_KEYS)
    if extra:
        raise ConstitutionError(f"tool_specs.{tool}: unknown key(s) {sorted(extra)}")
    irreversible = spec.get("irreversible", DEFAULT_IRREVERSIBLE)
    if not isinstance(irreversible, bool):
        raise ConstitutionError(f"tool_specs.{tool}.irreversible: expected a boolean")
    floor = spec.get("data_class_floor", DEFAULT_DATA_CLASS)
    if not isinstance(floor, str) or floor.strip().casefold() not in DATA_CLASSES:
        raise ConstitutionError(f"tool_specs.{tool}.data_class_floor: expected one of {list(DATA_CLASSES)}")
    if "deny_unmapped" in spec and not isinstance(spec["deny_unmapped"], bool):
        raise ConstitutionError(f"tool_specs.{tool}.deny_unmapped: expected a boolean")
    return irreversible, floor.strip().casefold()


def _amount_spec(tool: str, amount: Any, take) -> dict | None:
    """A spec's ``amount``, canonical; None when it has none."""
    if amount is None:
        return None
    where = f"tool_specs.{tool}.amount"
    if not isinstance(amount, Mapping):
        raise ConstitutionError(f"{where}: expected a mapping")
    if set(amount) - set(AMOUNT_KEYS) or "json_path" not in amount or "unit" not in amount:
        raise ConstitutionError(f"{where}: requires json_path and unit (usd or cents)")
    if amount["unit"] not in ("usd", "cents"):
        raise ConstitutionError(f"{where}.unit: expected usd or cents")
    out = {"json_path": take(_json_path(amount["json_path"], where), where), "unit": amount["unit"]}
    if "currency_path" in amount:
        out["currency_path"] = take(_json_path(amount["currency_path"], where), f"{where}.currency_path")
    return out


def _allow_entries(where: str, allow: Any) -> list[str]:
    """A counterparty ``allow`` list, canonical: trimmed, case-folded, sorted, no wildcards."""
    if not isinstance(allow, list) or not allow or any(not isinstance(item, str) or not item.strip() for item in allow):
        raise ConstitutionError(f"{where}.allow: expected a non-empty list of strings")
    canonical = sorted({item.strip().casefold() for item in allow})
    for item in canonical:
        if "*" in item:
            raise ConstitutionError(f"{where}.allow: {item!r}: wildcards are not supported; list each party, or "
                                    "use @domain for every address at one domain")
        if is_domain_entry(item) and not DOMAIN.fullmatch(item[1:]):
            raise ConstitutionError(f"{where}.allow: {item!r} is not a domain entry: @ and an ASCII host name such "
                                    "as @example.org (no subdomain patterns)")
    return canonical


def _counterparty_specs(tool: str, parties: Any, take) -> list[dict]:
    """A spec's ``counterparties``, canonical."""
    if not isinstance(parties, list):
        raise ConstitutionError(f"tool_specs.{tool}.counterparties: expected a list")
    out = []
    for index, entry in enumerate(parties):
        where = f"tool_specs.{tool}.counterparties[{index}]"
        if not isinstance(entry, Mapping) or set(entry) != set(COUNTERPARTY_KEYS):
            raise ConstitutionError(f"{where}: expected json_path and allow")
        path = take(_json_path(entry["json_path"], where), where)
        out.append({"json_path": path, "allow": _allow_entries(where, entry["allow"])})
    return out


def _control_overlap(path: str, control_paths: list[str]) -> str | None:
    """The first path Path A reads that ``path`` equals, covers, or sits under, compared case-folded (a tool
    that reads keys case-insensitively must not see ``TO.name`` as payload)."""
    folded = path.casefold()
    for control in control_paths:
        c = control.casefold()
        if folded == c or c.startswith(folded + ".") or folded.startswith(c + "."):
            return control
    return None


def _payload_entry(where: str, entry: Any, control_paths: list[str], take) -> dict:
    """One ``payload`` entry, canonical."""
    if not isinstance(entry, Mapping) or "json_path" not in entry:
        raise ConstitutionError(f"{where}: expected json_path")
    extra = set(entry) - set(PAYLOAD_KEYS)
    if extra:
        raise ConstitutionError(f"{where}: unknown key(s) {sorted(extra)}")
    path = take(_json_path(entry["json_path"], where), where)
    control = _control_overlap(path, control_paths)
    if control is not None:
        raise ConstitutionError(f"{where}: payload path {path!r} overlaps the field path {control!r}")
    shape = entry.get("shape")
    if shape is not None and shape not in ("string", "number", "list"):
        raise ConstitutionError(f"{where}.shape: expected string, number, or list")
    limit = entry.get("max_length")
    if limit is not None:
        if shape not in ("string", "list"):
            raise ConstitutionError(f"{where}.max_length: only valid for string or list")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ConstitutionError(f"{where}.max_length: expected a positive integer")
    return {"json_path": path, "shape": shape, "max_length": limit}


def _payload_specs(tool: str, payload: Any, control_paths: list[str], take) -> list[dict]:
    """A spec's ``payload``: paths copied unread, none of which may cover or sit under a path Path A reads."""
    if not isinstance(payload, list):
        raise ConstitutionError(f"tool_specs.{tool}.payload: expected a list")
    return [_payload_entry(f"tool_specs.{tool}.payload[{index}]", entry, control_paths, take)
            for index, entry in enumerate(payload)]


def _tool_spec(tool: str, spec: Any, registry: Mapping, agents: list | None) -> dict:
    """One tool's canonical spec."""
    irreversible, floor = _spec_basics(tool, spec)
    take = _PathSet().take
    amount_out = _amount_spec(tool, spec.get("amount"), take)
    party_out = _counterparty_specs(tool, spec.get("counterparties", []), take)
    control_paths = [p for p in ((amount_out or {}).get("json_path"), (amount_out or {}).get("currency_path"))
                     if p] + [entry["json_path"] for entry in party_out]
    fields_out = _field_mappings(tool, spec.get("fields"), registry, control_paths, take)
    out = {
        "irreversible": irreversible,
        "data_class_floor": floor,
        "amount": amount_out,
        "counterparties": party_out,
        "payload": _payload_specs(tool, spec.get("payload", []), control_paths, take),
        "deny_unmapped": spec.get("deny_unmapped", False) is True,
    }
    if fields_out:      # absent for a tool with no custom fields, so its spec hashes as before
        out["fields"] = fields_out
    out.update(_tool_check(tool, spec))      # absent unless set, for the same reason
    out.update(_tool_agents(tool, spec, agents))      # absent unless set: no roster means any caller
    return out


def validate_tool_specs(specs: Any, rules: list, fields: Mapping | None = None,
                        agents: list | None = None) -> dict:
    """Canonical tool specs. Every allow-listed tool must have one.

    A spec says which argument paths Path A may read. It is not an English
    scanner. Only the tool's name is required. ``irreversible`` defaults to
    true and ``data_class_floor`` to ``classified``. ``amount.unit`` is ``usd`` or ``cents``. A currency path, when
    set, must be the string ``usd`` at authorization time or the call is
    denied. A counterparty path copies only values on its ``allow`` list.
    The tool receives that canonical value, not the raw spelling.
    ``deny_unmapped`` defaults to false: a key the spec does not name
    does not reach the tool. Set it true to deny that key instead.
    ``payload`` names paths that may be present and are not interpreted. With
    no ``shape``, a named path covers that value and its children. A payload
    path that equals, is an ancestor of, or sits under an amount, currency, or
    counterparty path is refused, so a payload never carries a field Path A reads. ``shape``
    is ``string``, ``number``, or ``list`` (a list of strings). ``max_length``
    bounds a string or a list. A shape does not classify the contents.
    ``fields`` maps custom fields declared in the registry (``fields``) to argument paths. A mapped
    field is required at authorization time. A field path may not equal, contain, or sit under any
    other declared path, compared without regard to case.
    ``agents`` says which roster agents may call the tool: ``any`` or a list of ids (two_key/roster.py); it
    needs the canonical roster, passed as ``agents``.
    """
    registry = fields or {}
    if not isinstance(specs, Mapping):
        raise ConstitutionError("tool_specs must be a mapping")
    out: dict[str, dict] = {}
    for name, spec in specs.items():
        tool = _spec_tool_name(name, out)
        out[tool] = _tool_spec(tool, spec, registry, agents)
    allow = _allow_listed(rules)
    missing = [tool for tool in allow if tool not in out]
    if missing:
        raise ConstitutionError(f"tool_specs missing for allow-listed tool(s) {missing}")
    extra_tools = [tool for tool in out if allow and tool not in allow]
    if extra_tools:
        raise ConstitutionError(f"tool_specs for tool(s) not in the allow list: {extra_tools}")
    _require_field_decisions(out, rules)
    return out


def load_unsigned(prose_path: Path | str, rules_path: Path | str) -> tuple[str, list, Mapping]:
    """Return prose, hard rules, and tool specs.

    ``tool_specs`` is required. A bare rule list, a missing key, and ``null``
    are refused. An empty mapping is refused when an allow-listed tool has
    no spec. There is no path that trusts the agent's form. A rules file
    that declares custom ``fields`` is refused here, so they are never
    dropped silently: use ``load_unsigned_with_fields``.
    """
    prose, rules, specs, fields = load_unsigned_with_fields(prose_path, rules_path)
    if fields:
        raise ConstitutionError("the rules file declares custom fields: use load_unsigned_with_fields")
    return prose, rules, specs


def load_unsigned_with_fields(prose_path: Path | str, rules_path: Path | str) -> tuple[str, list, Mapping, dict]:
    """Return prose, hard rules, tool specs, and the canonical custom-field registry (empty if none). A
    ``serial`` in the rules file is read by ``load_serial``."""
    prose = Path(prose_path).read_text(encoding="utf-8")
    rules, specs, fields, _, _ = _load_rules_document(Path(rules_path))
    try:
        registry = validate_fields(fields)
    except FieldError as e:
        raise _field_error(e) from None
    return prose, validate_rules(rules, fields=registry), specs, registry


def load_serial(rules_path: Path | str) -> int | None:
    """The ``serial`` a rules file declares, validated; None when it declares none."""
    return validate_serial(_load_rules_document(Path(rules_path))[3])


def load_agents(rules_path: Path | str) -> list | None:
    """The agent roster a rules file declares (``agents:``), canonical; None when it declares none."""
    value = _load_rules_document(Path(rules_path))[4]
    return None if value is None else validate_agents(value)


def _load_rules_document(path: Path) -> tuple[list, Mapping, Any, Any, Any]:
    if path.suffix.lower() != ".json":
        try:
            import yaml  # noqa: F401
        except ImportError as e:
            raise ConstitutionError("reading YAML rules needs the yaml extra (pip install pyyaml)") from e
    try:
        data = load_file_strict(path)
    except StrictParseError as e:
        raise ConstitutionError(f"rules file {path}: {e}") from None
    if isinstance(data, list):
        raise ConstitutionError("tool_specs required: a bare rule list cannot be signed")
    if isinstance(data, dict) and "hard_rules" in data:
        extra = set(data) - set(RULES_FILE_KEYS)
        if extra:
            raise ConstitutionError(f"unknown rules-file key(s) {sorted(extra)}")
        rules = data["hard_rules"]
        if not isinstance(rules, list):
            raise ConstitutionError("hard rules must be a list")
        if "tool_specs" not in data:
            raise ConstitutionError("tool_specs required")
        specs = data["tool_specs"]
        if not isinstance(specs, Mapping):
            raise ConstitutionError("tool_specs must be a mapping")
        return rules, specs, data.get("fields"), data.get("serial"), data.get("agents")
    raise ConstitutionError("hard rules must be a list")


def signed_body(prose: str, rules: list, tool_specs: Any = None, *, fields: Any = None,
                envelope_format: str = "auto", serial: int | None = None,
                agents: Any = None) -> tuple[str, dict]:
    """The envelope format and the body ``sign_constitution`` signs, checked the same way and not signed: what
    ``two-key constitution-editor`` shows before it signs."""
    if envelope_format not in ENVELOPE_FORMATS:
        raise ConstitutionError(f"envelope_format must be one of {list(ENVELOPE_FORMATS)}")
    try:
        registry = validate_fields(fields)
    except FieldError as e:
        raise _field_error(e) from None
    rules = validate_rules(rules, fields=registry)
    if tool_specs is None:
        raise ConstitutionError(
            "tool_specs required: every allow-listed tool needs a spec"
        )
    roster = None if agents is None else validate_agents(agents)
    signed: dict[str, Any] = {
        "prose": prose,
        "hard_rules": rules,
        "tool_specs": validate_tool_specs(tool_specs, rules, registry, roster),
    }
    if roster is not None:
        signed["agents"] = roster
    if registry:
        signed["fields"] = registry
    serial = validate_serial(serial)
    if serial is not None:
        signed["serial"] = serial
    return _body_format(signed, envelope_format), signed


def _body_format(signed: Mapping, envelope_format: str) -> str:
    """The envelope format a checked body signs as."""
    registry = signed.get("fields")
    v3 = uses_v3(registry or {}, signed["tool_specs"]) or "serial" in signed or "agents" in signed
    if v3 and envelope_format == "v2":
        raise ConstitutionError(f"{V3_FEATURES}, a serial, and an agent roster need a v3 constitution")
    if v3 or envelope_format == "v3":
        return FORMAT_V3
    if registry or envelope_format == "v2":
        return FORMAT_V2
    return FORMAT_V1


def sign_constitution(prose: str, rules: list, private_key, tool_specs: Any = None, *,
                      fields: Any = None, envelope_format: str = "auto", serial: int | None = None,
                      agents: Any = None) -> dict:
    """Sign prose, hard rules, tool specs, and the optional custom-field registry.

    ``envelope_format`` is the principal's choice at signing time. ``auto`` (the default) writes
    ``v1``, byte for byte as before, when there are no custom fields, ``v2`` when there are, and ``v3`` when
    a field is caller-supplied (``source: caller``) or ``case: exact``, or a tool marks one
    ``not_applicable``, or the constitution has a ``serial``. ``v2`` always writes at least ``v2``, and ``v3``
    always writes ``v3``. None of those can be signed as ``v2``. An install older than custom fields refuses a ``v2`` envelope; one before 0.5.0
    refuses ``v3``.
    """
    fmt, signed = signed_body(prose, rules, tool_specs, fields=fields, envelope_format=envelope_format, serial=serial,
                              agents=agents)
    signature = sign(private_key, canonical_bytes(signed))
    return {
        "format": fmt,
        "signed": signed,
        "signature": signature,
        "fingerprint": fingerprint(private_key.public_key()),
    }


def save_envelope(path: Path | str, envelope: dict, *, owner_only: bool = False) -> None:
    """Write a signed constitution to a new file beside ``path``, then rename it over ``path``: a reader never
    sees half a constitution, and a link at ``path`` is replaced, not written through. ``owner_only`` makes the
    new file readable by its owner only (mode 0600), as ``two-key setup`` writes it."""
    target = Path(path)
    tmp = target.parent / f".{target.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
    try:
        with os.fdopen(_platform.create_new(tmp, owner_only=owner_only), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(envelope, indent=2) + "\n")
        _platform.replace(tmp, target)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def load_envelope(path: Path | str) -> dict:
    """Read a signed constitution. A duplicate key is refused: the signature covers one reading only."""
    try:
        return loads_json(Path(path).read_text(encoding="utf-8"))
    except StrictParseError as e:
        raise ConstitutionError(f"constitution {path}: {e}") from None


def _signature_failed(public_key, message: bytes, signature) -> str:
    """Why a constitution's signature failed. One by the hybrid principal's own Ed25519 half is the 0.8.0 key's,
    from before the key upgrade: refused, not signed again, since an Ed25519-only signature is not enough."""
    if is_hybrid(public_key) and verify(classical_half(public_key), message, signature):
        return ("constitution signature failed: it is signed by this principal's 0.8.0 Ed25519 key, from before "
                "the key upgrade; sign it again (two-key keys upgrade --key KEY --ledger DIR --constitution FILE, "
                "or two-key sign-constitution; docs/UPGRADING.md)")
    return "constitution signature failed"


def verify_signed(envelope: dict, public_key) -> Constitution:
    fmt = envelope.get("format") if isinstance(envelope, dict) else None
    if fmt not in (FORMAT_V1, FORMAT_V2, FORMAT_V3):
        if isinstance(fmt, str) and fmt.startswith("two-key-concept-constitution"):
            raise ConstitutionSignatureError(
                "constitution signed by two-key-concept (before two-key 0.4.0); re-sign it with "
                "two-key sign-constitution")
        raise ConstitutionSignatureError("unsupported constitution format")
    signed = envelope.get("signed")
    if not isinstance(signed, dict):
        raise ConstitutionSignatureError("missing signed body")
    signature = envelope.get("signature") or ""
    if not verify(public_key, canonical_bytes(signed), signature):
        raise ConstitutionSignatureError(_signature_failed(public_key, canonical_bytes(signed), signature))
    if fmt in (FORMAT_V2, FORMAT_V3):
        extra = set(signed) - (_V3_SIGNED_KEYS if fmt == FORMAT_V3 else _V2_SIGNED_KEYS)
        if extra:
            raise ConstitutionError(f"unknown signed key(s) {sorted(map(str, extra))} in a {fmt[-2:]} constitution")
    elif "fields" in signed:
        raise ConstitutionError("custom fields need a v2 constitution")
    if "serial" in signed:
        if fmt != FORMAT_V3:
            raise ConstitutionError("a serial needs a v3 constitution")
        validate_serial(signed["serial"])
    roster = None
    if "agents" in signed:
        if fmt != FORMAT_V3:
            raise ConstitutionError("an agent roster needs a v3 constitution")
        roster = validate_agents(signed["agents"])
        if roster != signed["agents"]:
            raise ConstitutionError("agents: the signed roster is not in canonical form")
    prose = signed.get("prose")
    rules = signed.get("hard_rules")
    if not isinstance(prose, str) or not prose.strip():
        raise ConstitutionError("constitution prose is empty")
    try:
        registry = validate_fields(signed.get("fields"))
    except FieldError as e:
        raise _field_error(e) from None
    if has_caller_fields(registry) and fmt != FORMAT_V3:
        raise ConstitutionError("caller-supplied fields (source: caller) need a v3 constitution")
    rules = validate_rules(rules, fields=registry)
    if "tool_specs" not in signed:
        raise ConstitutionError("tool_specs required")
    specs = validate_tool_specs(signed["tool_specs"], rules, registry, roster)
    if uses_v3(registry, specs) and fmt != FORMAT_V3:
        raise ConstitutionError(f"{V3_FEATURES} need a v3 constitution")
    return Constitution(prose, rules, envelope, specs, True, registry)
