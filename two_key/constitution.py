"""Signed constitution: prose for Path B, hard rules for Path A, and tool specs."""

from __future__ import annotations

import json
import re

from .strict import StrictParseError, load_file_strict, loads_json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .action import DATA_CLASSES
from .canonical import canonical_bytes, canonical_hash
from .fields import MAX_FIELDS_PER_TOOL, FieldError, check_path, validate_fields
from .keys import fingerprint, sign, verify
from .policy_vm import ConstitutionError, validate_rules

FORMAT_V1 = "two-key-concept-constitution-v1"
# v2 may carry a custom-field registry (``fields``) and refuses any other unknown signed key.
FORMAT_V2 = "two-key-concept-constitution-v2"
ENVELOPE_FORMATS = ("auto", "v2")
_V2_SIGNED_KEYS = {"prose", "hard_rules", "tool_specs", "fields"}


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
    def digest(self) -> str:
        return canonical_hash(self.document["signed"])


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


def validate_tool_specs(specs: Any, rules: list, fields: Mapping | None = None) -> dict:
    """Canonical tool specs. Every allow-listed tool must have one.

    A spec says which argument paths Path A may read. It is not an English
    scanner. ``amount.unit`` is ``usd`` or ``cents``. A currency path, when
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
    """
    registry = fields or {}
    if not isinstance(specs, Mapping):
        raise ConstitutionError("tool_specs must be a mapping")
    allowed_keys = {
        "irreversible", "data_class_floor", "amount", "counterparties",
        "payload", "deny_unmapped", "fields",
    }
    out: dict[str, dict] = {}
    for name, spec in specs.items():
        if not isinstance(name, str) or not name.strip():
            raise ConstitutionError("tool_specs: tool name must be a non-empty string")
        tool = name.strip().casefold()
        if tool in out:
            raise ConstitutionError(f"tool_specs: duplicate tool {tool}")
        if not isinstance(spec, Mapping):
            raise ConstitutionError(f"tool_specs.{tool}: expected a mapping")
        extra = set(spec) - allowed_keys
        if extra:
            raise ConstitutionError(f"tool_specs.{tool}: unknown key(s) {sorted(extra)}")
        if "irreversible" not in spec or not isinstance(spec["irreversible"], bool):
            raise ConstitutionError(f"tool_specs.{tool}.irreversible: expected a boolean")
        floor = spec.get("data_class_floor")
        if not isinstance(floor, str) or floor.strip().casefold() not in DATA_CLASSES:
            raise ConstitutionError(
                f"tool_specs.{tool}.data_class_floor: expected one of {list(DATA_CLASSES)}"
            )
        if "deny_unmapped" in spec and not isinstance(spec["deny_unmapped"], bool):
            raise ConstitutionError(f"tool_specs.{tool}.deny_unmapped: expected a boolean")
        seen_paths: set[str] = set()

        def take(path: str, where: str) -> str:
            if path in seen_paths:
                raise ConstitutionError(f"{where}: duplicate path")
            seen_paths.add(path)
            return path

        amount = spec.get("amount")
        amount_out = None
        if amount is not None:
            if not isinstance(amount, Mapping):
                raise ConstitutionError(f"tool_specs.{tool}.amount: expected a mapping")
            amount_extra = set(amount) - {"json_path", "unit", "currency_path"}
            if amount_extra or "json_path" not in amount or "unit" not in amount:
                raise ConstitutionError(
                    f"tool_specs.{tool}.amount: requires json_path and unit (usd or cents)"
                )
            if amount["unit"] not in ("usd", "cents"):
                raise ConstitutionError(f"tool_specs.{tool}.amount.unit: expected usd or cents")
            amount_out = {
                "json_path": take(
                    _json_path(amount["json_path"], f"tool_specs.{tool}.amount"),
                    f"tool_specs.{tool}.amount",
                ),
                "unit": amount["unit"],
            }
            if "currency_path" in amount:
                amount_out["currency_path"] = take(
                    _json_path(amount["currency_path"], f"tool_specs.{tool}.amount"),
                    f"tool_specs.{tool}.amount.currency_path",
                )
        parties = spec.get("counterparties", [])
        if not isinstance(parties, list):
            raise ConstitutionError(f"tool_specs.{tool}.counterparties: expected a list")
        party_out = []
        for index, entry in enumerate(parties):
            where = f"tool_specs.{tool}.counterparties[{index}]"
            if not isinstance(entry, Mapping) or set(entry) != {"json_path", "allow"}:
                raise ConstitutionError(f"{where}: expected json_path and allow")
            path = take(_json_path(entry["json_path"], where), where)
            allow = entry["allow"]
            if not isinstance(allow, list) or not allow or any(not isinstance(item, str) or not item.strip() for item in allow):
                raise ConstitutionError(f"{where}.allow: expected a non-empty list of strings")
            canonical = sorted({item.strip().casefold() for item in allow})
            party_out.append({"json_path": path, "allow": canonical})
        # A payload path is copied unread. It must not cover, or sit under, a path Path A reads,
        # compared without regard to case.
        control_paths = [p for p in ((amount_out or {}).get("json_path"), (amount_out or {}).get("currency_path"))
                         if p] + [entry["json_path"] for entry in party_out]
        mapped = spec.get("fields")
        fields_out: dict[str, dict] = {}
        if mapped is not None:
            if not isinstance(mapped, Mapping) or not mapped:
                raise ConstitutionError(f"tool_specs.{tool}.fields: expected a non-empty mapping")
            if len(mapped) > MAX_FIELDS_PER_TOOL:
                raise ConstitutionError(f"tool_specs.{tool}.fields: more than {MAX_FIELDS_PER_TOOL} fields")
            for fname, entry in mapped.items():
                where = f"tool_specs.{tool}.fields.{fname}"
                if not isinstance(fname, str) or fname not in registry:
                    raise ConstitutionError(f"{where}: not a declared field (add it under fields:)")
                if not isinstance(entry, Mapping) or set(entry) != {"json_path"}:
                    raise ConstitutionError(f"{where}: expected json_path only")
                try:
                    path = check_path(_json_path(entry["json_path"], where), where)
                except FieldError as e:
                    raise _field_error(e) from None
                path = take(path, where)
                for other in control_paths:
                    if _overlaps(path, other):
                        raise ConstitutionError(f"{where}: field path {path!r} overlaps the path {other!r}")
                control_paths.append(path)
                fields_out[fname] = {"json_path": path}
        payload = spec.get("payload", [])
        if not isinstance(payload, list):
            raise ConstitutionError(f"tool_specs.{tool}.payload: expected a list")
        payload_out = []
        for index, entry in enumerate(payload):
            where = f"tool_specs.{tool}.payload[{index}]"
            if not isinstance(entry, Mapping) or "json_path" not in entry:
                raise ConstitutionError(f"{where}: expected json_path")
            extra = set(entry) - {"json_path", "shape", "max_length"}
            if extra:
                raise ConstitutionError(f"{where}: unknown key(s) {sorted(extra)}")
            path = take(_json_path(entry["json_path"], where), where)
            # Casefolded: a tool that reads keys case-insensitively must not see `TO.name` as payload.
            folded = path.casefold()
            for control in control_paths:
                c = control.casefold()
                if folded == c or c.startswith(folded + ".") or folded.startswith(c + "."):
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
            payload_out.append({"json_path": path, "shape": shape, "max_length": limit})
        out[tool] = {
            "irreversible": spec["irreversible"],
            "data_class_floor": floor.strip().casefold(),
            "amount": amount_out,
            "counterparties": party_out,
            "payload": payload_out,
            "deny_unmapped": spec.get("deny_unmapped", False) is True,
        }
        if fields_out:      # absent for a tool with no custom fields, so its spec hashes as before
            out[tool]["fields"] = fields_out
    allow = _allow_listed(rules)
    missing = [tool for tool in allow if tool not in out]
    if missing:
        raise ConstitutionError(f"tool_specs missing for allow-listed tool(s) {missing}")
    extra_tools = [tool for tool in out if allow and tool not in allow]
    if extra_tools:
        raise ConstitutionError(f"tool_specs for tool(s) not in the allow list: {extra_tools}")
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
    """Return prose, hard rules, tool specs, and the canonical custom-field registry (empty if none)."""
    prose = Path(prose_path).read_text(encoding="utf-8")
    rules, specs, fields = _load_rules_document(Path(rules_path))
    try:
        registry = validate_fields(fields)
    except FieldError as e:
        raise _field_error(e) from None
    return prose, validate_rules(rules, fields=registry), specs, registry


def _load_rules_document(path: Path) -> tuple[list, Mapping, Any]:
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
        extra = set(data) - {"hard_rules", "tool_specs", "fields"}
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
        return rules, specs, data.get("fields")
    raise ConstitutionError("hard rules must be a list")


def sign_constitution(prose: str, rules: list, private_key, tool_specs: Any = None, *,
                      fields: Any = None, envelope_format: str = "auto") -> dict:
    """Sign prose, hard rules, tool specs, and the optional custom-field registry.

    ``envelope_format`` is the principal's choice at signing time. ``auto`` (the default) writes
    ``v1``, byte for byte as before, when there are no custom fields, and ``v2`` when there are.
    ``v2`` always writes ``v2``. An install older than custom fields refuses a ``v2`` envelope.
    """
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
    signed: dict[str, Any] = {
        "prose": prose,
        "hard_rules": rules,
        "tool_specs": validate_tool_specs(tool_specs, rules, registry),
    }
    if registry:
        signed["fields"] = registry
    signature = sign(private_key, canonical_bytes(signed))
    return {
        "format": FORMAT_V2 if registry or envelope_format == "v2" else FORMAT_V1,
        "signed": signed,
        "signature": signature,
        "fingerprint": fingerprint(private_key.public_key()),
    }


def save_envelope(path: Path | str, envelope: dict) -> None:
    Path(path).write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")


def load_envelope(path: Path | str) -> dict:
    """Read a signed constitution. A duplicate key is refused: the signature covers one reading only."""
    try:
        return loads_json(Path(path).read_text(encoding="utf-8"))
    except StrictParseError as e:
        raise ConstitutionError(f"constitution {path}: {e}") from None


def verify_signed(envelope: dict, public_key) -> Constitution:
    fmt = envelope.get("format") if isinstance(envelope, dict) else None
    if fmt not in (FORMAT_V1, FORMAT_V2):
        raise ConstitutionSignatureError("unsupported constitution format")
    signed = envelope.get("signed")
    if not isinstance(signed, dict):
        raise ConstitutionSignatureError("missing signed body")
    if not verify(public_key, canonical_bytes(signed), envelope.get("signature") or ""):
        raise ConstitutionSignatureError("constitution signature failed")
    if fmt == FORMAT_V2:
        extra = set(signed) - _V2_SIGNED_KEYS
        if extra:
            raise ConstitutionError(f"unknown signed key(s) {sorted(map(str, extra))} in a v2 constitution")
    elif "fields" in signed:
        raise ConstitutionError("custom fields need a v2 constitution")
    prose = signed.get("prose")
    rules = signed.get("hard_rules")
    if not isinstance(prose, str) or not prose.strip():
        raise ConstitutionError("constitution prose is empty")
    try:
        registry = validate_fields(signed.get("fields"))
    except FieldError as e:
        raise _field_error(e) from None
    rules = validate_rules(rules, fields=registry)
    if "tool_specs" not in signed:
        raise ConstitutionError("tool_specs required")
    specs = validate_tool_specs(signed["tool_specs"], rules, registry)
    return Constitution(prose, rules, envelope, specs, True, registry)
