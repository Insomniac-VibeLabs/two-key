"""Derive Path A's form from the argument bytes and a signed tool spec.

The agent may still send amount, data class, counterparty, and irreversible.
Those are claims. When the signed constitution has a spec for the tool, the
values Path A sees come from the spec and the arguments. A claim that
disagrees is a deny. This module does not read English and it does not
classify free text.

Keys the spec does not name do not reach the tool. ``deny_unmapped`` defaults
off: those keys are dropped at the gateway. Their names (never their values)
are written to the ledger (``dropped_keys``). When a spec sets it, an unnamed
key is a deny instead. A declared path covers that value and everything
under it. A counterparty path copies only values on its allow list, and the
tool receives the canonical value. A payload path is not interpreted.
``shape``, when set, only checks the kind of value: string, number, or a
list of strings. It does not read the contents. Omit ``shape`` and the
value, including its children, is copied unread.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .action import DATA_CLASS_SEP, DATA_CLASSES, MAX_AMOUNT_USD, SPECIFIC_DATA_CLASSES
from .agent_meta import type_tag
from .canonical import canonical_bytes
from .fields import FieldValueError, coerce_value, defaults


# Size cap on tool arguments and on the proposal text, in UTF-8 bytes of their compact JSON.
# Checked before anything is derived, judged, hashed for a token, or ledgered.
MAX_ARGS_BYTES = 256 * 1024
# The structured action claim is small; its cap is lower. Measured before normalize_action.
MAX_ACTION_BYTES = 64 * 1024


def _json_bytes(value: Any) -> bytes | None:
    """Compact UTF-8 JSON of a plain value (``canonical.to_plain``). Anything JSON has no form for is not
    measured through ``str()`` or ``repr()``, which a custom type controls: it is ``None``, too large."""
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "surrogatepass")
    except (RecursionError, ValueError, TypeError):
        return None  # cannot be measured: treated as too large


def args_size(value: Any) -> int:
    """UTF-8 bytes of ``value`` as JSON (``repr`` if that fails). -1 if it cannot be measured."""
    data = _json_bytes(value)
    return -1 if data is None else len(data)


def args_too_large(value: Any) -> bool:
    size = args_size(value)
    return size < 0 or size > MAX_ARGS_BYTES


def canonical_too_large(canonical: bytes, value: Any) -> bool:
    """``args_too_large(value)``, measured once in the common case.

    ``canonical`` is ``canonical_bytes(value)``: compact JSON with non-ASCII escaped, so it is never
    shorter than the UTF-8 compact JSON this cap measures. At or under the cap it settles the
    question without a second encoding; only a longer one is measured exactly.
    """
    return len(canonical) > MAX_ARGS_BYTES and args_too_large(value)


def size_record(value: Any, name: str) -> dict:
    """What the ledger keeps for an oversized value: its size and digest, never the bytes."""
    data = _json_bytes(value)
    return {f"{name}_size": -1 if data is None else len(data),
            f"{name}_digest": None if data is None else "sha256:" + hashlib.sha256(data).hexdigest(),
            f"{name}_omitted": True}


class DeriveError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


_SEGMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class Derived:
    amount_usd: float | None
    counterparties: tuple[str, ...]
    irreversible: bool
    data_class_floor: str
    # Custom field values, sorted by name: read from the bytes for mapped fields, the signed default otherwise.
    fields: tuple[tuple[str, Any], ...] = ()


def _cents(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DeriveError("amount_unreadable")
    try:
        number = float(value)  # an int such as 10**400 raises OverflowError here
    except (OverflowError, ValueError):
        raise DeriveError("amount_unreadable") from None
    if math.isnan(number) or math.isinf(number) or number < 0 or math.isinf(number * 100):
        raise DeriveError("amount_unreadable")
    cents = round(number * 100)
    if abs(number * 100 - cents) > 1e-6:
        raise DeriveError("amount_unreadable")
    return int(cents)


def lookup(document: Mapping[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = document
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _parties_at(raw: Any) -> list[str]:
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, list) and raw and all(isinstance(item, str) for item in raw):
        values = list(raw)
    else:
        raise DeriveError("counterparty_unreadable")
    parties: list[str] = []
    for value in values:
        party = value.strip().casefold()
        if not party:
            raise DeriveError("counterparty_missing")
        parties.append(party)
    return parties


def _clone(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _clone(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clone(item) for item in value]
    return value


def _assign(dest: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    current = dest
    for part in parts[:-1]:
        nxt = current.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            current[part] = nxt
        current = nxt
    current[parts[-1]] = value


def _payload_shape(entry: Mapping[str, Any], raw: Any) -> None:
    """Refuse a payload value whose kind is not the declared shape.

    This does not interpret the value. ``string`` is any string. ``number``
    is a finite int or float, not a boolean. ``list`` is a list of strings.
    ``max_length`` bounds characters or list items. No shape means no check.
    """
    shape = entry.get("shape")
    if not shape:
        return
    limit = entry.get("max_length")
    if shape == "string":
        if not isinstance(raw, str) or (isinstance(limit, int) and len(raw) > limit):
            raise DeriveError("payload_shape")
        return
    if shape == "number":
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise DeriveError("payload_shape")
        if math.isnan(float(raw)) or math.isinf(float(raw)):
            raise DeriveError("payload_shape")
        return
    if shape == "list":
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            raise DeriveError("payload_shape")
        if isinstance(limit, int) and len(raw) > limit:
            raise DeriveError("payload_shape")
        return
    raise DeriveError("payload_shape")


def disallowed_party(spec: Mapping[str, Any], arguments: Mapping[str, Any]) -> bool:
    """True when a copied party is not on that path's allow list."""
    for entry in spec.get("counterparties") or []:
        if not isinstance(entry, Mapping):
            continue
        found, raw = lookup(arguments, entry["json_path"])
        if not found:
            continue
        allow = set(entry.get("allow") or [])
        if any(party not in allow for party in _parties_at(raw)):
            return True
    return False


def _project_fields(out: dict, spec: Mapping[str, Any], derived_fields: Mapping[str, Any] | None) -> None:
    """Each mapped custom field gets the normalized value Path A checked, at its path."""
    if derived_fields is None:
        return
    for name, entry in (spec.get("fields") or {}).items():
        if name in derived_fields and isinstance(entry, Mapping):
            _assign(out, entry["json_path"], derived_fields[name])


def project_arguments(spec: Mapping[str, Any], arguments: Mapping[str, Any],
                      derived_fields: Mapping[str, Any] | None = None) -> dict:
    """Arguments the tool may see.

    Unnamed keys are dropped. A counterparty path is the canonical party
    Path A checked, not the raw spelling. A payload path with no shape is
    copied whole, including its children, and is not interpreted. A shaped
    payload is that value only, still unread. A custom field path is the
    normalized value Path A checked (``derived_fields``), not the raw spelling.
    """
    if not isinstance(arguments, Mapping):
        return {}
    out: dict[str, Any] = {}
    _project_fields(out, spec, derived_fields)
    for entry in spec.get("payload") or []:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("json_path"), str):
            continue
        found, raw = lookup(arguments, entry["json_path"])
        if found:
            _assign(out, entry["json_path"], _clone(raw))
    amount = spec.get("amount")
    if isinstance(amount, Mapping):
        path = amount.get("json_path")
        if isinstance(path, str):
            found, raw = lookup(arguments, path)
            if found:
                _assign(out, path, _clone(raw))
        currency_path = amount.get("currency_path")
        if isinstance(currency_path, str):
            found, raw = lookup(arguments, currency_path)
            if found:
                _assign(out, currency_path, raw.strip().casefold() if isinstance(raw, str) else _clone(raw))
    for entry in spec.get("counterparties") or []:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("json_path"), str):
            continue
        path = entry["json_path"]
        found, raw = lookup(arguments, path)
        if not found:
            continue
        parties = _parties_at(raw)
        if isinstance(raw, str):
            _assign(out, path, parties[0])
        else:
            _assign(out, path, list(dict.fromkeys(parties)))
    return out


def _declared_paths(spec: Mapping[str, Any]) -> tuple[str, ...]:
    paths: list[str] = []
    amount = spec.get("amount")
    if isinstance(amount, Mapping):
        for key in ("json_path", "currency_path"):
            value = amount.get(key)
            if isinstance(value, str):
                paths.append(value)
    for key in ("counterparties", "payload"):
        for entry in spec.get(key) or []:
            if isinstance(entry, Mapping) and isinstance(entry.get("json_path"), str):
                paths.append(entry["json_path"])
    for entry in (spec.get("fields") or {}).values():
        if isinstance(entry, Mapping) and isinstance(entry.get("json_path"), str):
            paths.append(entry["json_path"])
    return tuple(paths)


def _unmapped(arguments: Mapping[str, Any], declared: tuple[str, ...]) -> bool:
    """True when an argument key is outside every declared path.

    A declared path covers itself and its children. Ancestors of a declared
    path are walked. Lists and scalars are not walked, so a named value does
    not require a key list for every nested level.
    """
    declared_set = set(declared)

    def is_prefix(path: str) -> bool:
        needle = path + "."
        return any(item.startswith(needle) for item in declared_set)

    def walk(node: Mapping[str, Any], prefix: str) -> bool:
        for key, value in node.items():
            if not isinstance(key, str) or not _SEGMENT.fullmatch(key):
                return True
            path = f"{prefix}.{key}" if prefix else key
            if path in declared_set:
                continue
            if is_prefix(path):
                if isinstance(value, Mapping) and walk(value, path):
                    return True
                continue
            return True
        return False

    return walk(arguments, "")


MAX_DROPPED_NAMES = 64
MAX_DROPPED_NAME_CHARS = 128


def dropped_keys(spec: Mapping[str, Any], arguments: Mapping[str, Any]) -> list[str]:
    """Dotted names of argument keys the tool will not receive. Names only, never values.

    A declared path covers itself and its children. The list is sorted, capped at
    ``MAX_DROPPED_NAMES`` names of at most ``MAX_DROPPED_NAME_CHARS`` characters each.
    """
    if not isinstance(arguments, Mapping):
        return []
    declared = set(_declared_paths(spec))
    found: list[str] = []

    def walk(node: Mapping[str, Any], prefix: str) -> None:
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if path in declared:
                continue
            if isinstance(key, str) and any(item.startswith(path + ".") for item in declared) \
                    and isinstance(value, Mapping):
                walk(value, path)
                continue
            found.append(path[:MAX_DROPPED_NAME_CHARS])

    walk(arguments, "")
    return sorted(set(found))[:MAX_DROPPED_NAMES]


def derive(spec: Mapping[str, Any], arguments: Mapping[str, Any],
           registry: Mapping[str, Mapping[str, Any]] | None = None) -> Derived:
    """Read the derived fields from ``arguments`` using ``spec`` paths.

    Any value this cannot read is a ``DeriveError``, never another exception.
    An amount that cannot be read (for example 10**400) is
    ``DeriveError("amount_unreadable")``. Any other ``OverflowError``,
    ``TypeError``, ``ValueError``, or ``RecursionError`` (a value nested too
    deeply) becomes ``DeriveError("value_unreadable:<type_tag>")`` (bounded type label,
    never raw unbounded ``__name__``), which ``TwoKey`` turns into a
    ``derive_failed:`` deny (``cap_ledger_text`` on the reason).
    """
    try:
        return _derive(spec, arguments, registry or {})
    except DeriveError:
        raise
    except (OverflowError, TypeError, ValueError, RecursionError) as exc:
        # RecursionError: a value nested too deeply to read is a deny, never a crash.
        raise DeriveError(f"value_unreadable:{type_tag(exc)}") from None


def _custom_fields(spec: Mapping[str, Any], arguments: Mapping[str, Any],
                   registry: Mapping[str, Mapping[str, Any]]) -> tuple[tuple[str, Any], ...]:
    """Every registry field: a mapped field from the bytes (required), any other its signed default."""
    values = defaults(registry)
    for name, entry in (spec.get("fields") or {}).items():
        if name not in registry:
            raise DeriveError(f"field_unreadable:{name}")
        found, raw = lookup(arguments, entry["json_path"])
        if not found:
            raise DeriveError(f"field_missing:{name}")
        try:
            values[name] = coerce_value(registry[name], raw)
        except FieldValueError as e:
            raise DeriveError(f"{e.kind}:{name}") from None
    return tuple(sorted(values.items()))


def _derive(spec: Mapping[str, Any], arguments: Mapping[str, Any],
            registry: Mapping[str, Mapping[str, Any]]) -> Derived:
    if not isinstance(arguments, Mapping):
        raise DeriveError("arguments_not_object")
    amount_spec = spec.get("amount")
    amount: float | None = None
    if amount_spec:
        found, raw = lookup(arguments, amount_spec["json_path"])
        if not found:
            raise DeriveError("amount_missing")
        if amount_spec["unit"] == "cents":
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise DeriveError("amount_unreadable")
            if isinstance(raw, float) and (math.isnan(raw) or math.isinf(raw) or not raw.is_integer()):
                raise DeriveError("amount_unreadable")
            cents = int(raw)
            if cents < 0 or cents > int(MAX_AMOUNT_USD * 100):
                raise DeriveError("amount_unreadable")
            amount = cents / 100.0
        else:
            amount = _cents(raw) / 100.0
        if math.isnan(amount) or math.isinf(amount) or amount > MAX_AMOUNT_USD:
            raise DeriveError("amount_unreadable")
        currency_path = amount_spec.get("currency_path")
        if currency_path:
            seen, currency = lookup(arguments, currency_path)
            if not seen or not isinstance(currency, str) or currency.strip().casefold() != "usd":
                raise DeriveError("amount_unit_rejected")
    parties: list[str] = []
    for entry in spec.get("counterparties") or []:
        found, raw = lookup(arguments, entry["json_path"])
        if not found:
            raise DeriveError("counterparty_missing")
        parties.extend(_parties_at(raw))
    for entry in spec.get("payload") or []:
        if not isinstance(entry, Mapping) or not entry.get("shape"):
            continue
        found, raw = lookup(arguments, entry["json_path"])
        if found:
            _payload_shape(entry, raw)
    custom = _custom_fields(spec, arguments, registry) if registry else ()
    if spec.get("deny_unmapped") is True and _unmapped(arguments, _declared_paths(spec)):
        raise DeriveError("unmapped_field")
    return Derived(
        amount_usd=amount,
        counterparties=tuple(sorted(set(parties))),
        irreversible=bool(spec["irreversible"]),
        data_class_floor=str(spec["data_class_floor"]),
        fields=custom,
    )


def join_data_class(claimed: str, floor: str) -> str:
    """The classes the call carries: the claim's and the floor's, the more specific kept.

    Order: public < personal < {financial, medical} < classified. financial and medical are kinds of
    personal data, so either replaces personal; together they are "financial+medical" (Path A's
    data_class_in matches either), not classified. classified absorbs everything. A floor never
    lowers a claim, and a claim never lowers a floor. ``claimed`` may itself be "financial+medical".
    """
    parts = set(claimed.split(DATA_CLASS_SEP)) | {floor}
    if not parts <= set(DATA_CLASSES):
        raise DeriveError("data_class_unreadable")
    if "classified" in parts:
        return "classified"
    specific = parts & set(SPECIFIC_DATA_CLASSES)
    if specific:
        return DATA_CLASS_SEP.join(sorted(specific))
    return "personal" if "personal" in parts else "public"


def blocked_from_rules(rules: list) -> set[str]:
    found: set[str] = set()
    for rule in rules:
        parties = rule.get("deny_counterparties") if isinstance(rule, Mapping) else None
        if parties:
            found.update(parties)
    return found


def vm_counterparty(parties: tuple[str, ...], blocked: set[str]) -> str:
    """One string for the policy VM. Prefer a blocked party so Path A can deny it."""
    if not parties:
        return ""
    hits = sorted(set(parties) & blocked)
    if hits:
        return hits[0]
    return parties[0]


def disagreement(proposed: Mapping[str, Any], derived: Derived) -> str | None:
    """A present claim that is not what the bytes say. Omission is not a lie."""
    if not isinstance(proposed, Mapping):
        return "malformed_action"
    if "amount_usd" in proposed:
        try:
            claimed_cents = _cents(proposed["amount_usd"])
            derived_cents = 0 if derived.amount_usd is None else _cents(derived.amount_usd)
        except DeriveError as exc:
            return exc.reason
        if claimed_cents != derived_cents:
            return "amount_mismatch"
    elif derived.amount_usd is not None:
        pass
    if "counterparty" in proposed and str(proposed.get("counterparty") or "").strip():
        claimed = str(proposed["counterparty"]).strip().casefold()
        if set(derived.counterparties) != {claimed}:
            return "counterparty_mismatch"
    if "irreversible" in proposed and proposed["irreversible"] is not derived.irreversible:
        return "irreversible_mismatch"
    return None


def form_for(derived: Derived, claimed_data_class: str, blocked: set[str]) -> dict[str, Any]:
    """The form Path A saw. Amount and parties come from the bytes, not the claim."""
    if derived.counterparties:
        party = vm_counterparty(derived.counterparties, blocked)
    else:
        party = ""
    amount = 0.0 if derived.amount_usd is None else derived.amount_usd
    form = {
        "amount_usd": amount,
        "data_class": join_data_class(claimed_data_class, derived.data_class_floor),
        "counterparty": party,
        "irreversible": derived.irreversible,
        "counterparties": list(derived.counterparties),
    }
    if derived.fields:     # only with a registry, so a form without custom fields keeps its shape
        form["fields"] = dict(derived.fields)
    return form


def forms_match(signed: Mapping[str, Any], fresh: Mapping[str, Any]) -> bool:
    if set(signed) != set(fresh):
        return False
    if _cents(signed["amount_usd"]) != _cents(fresh["amount_usd"]):
        return False
    for key in ("data_class", "counterparty", "irreversible"):
        if signed[key] != fresh[key]:
            return False
    if list(signed["counterparties"]) != list(fresh["counterparties"]):
        return False
    if "fields" in signed:
        # Compared as canonical bytes, so the types must match too (true is not 1).
        try:
            return canonical_bytes(signed["fields"]) == canonical_bytes(fresh["fields"])
        except (TypeError, ValueError):
            return False
    return True
