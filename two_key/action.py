"""Normalized action record (disclosure section 5.2) and its validation.

``normalize_action`` validates and canonicalizes a proposed action before
the Policy VM sees it. Any validation failure raises ``ActionValidationError``,
and Two-Key turns that into an explicit, logged DENY.

Missing-field defaults follow disclosure section 5.2 and the missing-field rule: a missing
``irreversible`` means ``True`` and a missing ``data_class`` means
``"classified"``.

Open design question, not decided here: *who* produces the action record
(the proposing model, the gateway working from the literal tool-call
arguments, or a separate classifier). See DESIGN_OPTIONS.md section 1.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

DATA_CLASSES = ("public", "personal", "medical", "financial", "classified")

# Conservative defaults for missing high-impact fields (spec 5.2 / the missing-field rule).
DEFAULT_IRREVERSIBLE = True
DEFAULT_DATA_CLASS = "classified"
MAX_AMOUNT_USD = 1e12  # sanity bound; larger values are rejected as malformed

KNOWN_FIELDS = {
    "tool", "amount_usd", "currency", "counterparty", "data_class",
    "destination", "duration_hours", "irreversible", "tags", "raw",
}


class ActionValidationError(ValueError):
    """Raised when a proposed action record is malformed. Always a DENY."""


def canon_str(value: Any, name: str) -> str:
    """Trim and case-fold a string field. Non-strings are rejected."""
    if not isinstance(value, str):
        raise ActionValidationError(f"{name}: expected string, got {type(value).__name__}")
    return value.strip().casefold()


def _number(value: Any, name: str, *, lo: float = 0.0, hi: float = MAX_AMOUNT_USD) -> float:
    # bool is a subclass of int; reject it explicitly. Numeric strings are rejected.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ActionValidationError(f"{name}: expected a number, got {type(value).__name__}")
    f = float(value)
    if math.isnan(f) or math.isinf(f):
        raise ActionValidationError(f"{name}: must be finite")
    if f < lo:
        raise ActionValidationError(f"{name}: must be >= {lo}")
    if f > hi:
        raise ActionValidationError(f"{name}: exceeds maximum {hi}")
    return f


@dataclass(frozen=True)
class Action:
    """A normalized proposed tool invocation. Build it with ``normalize_action``."""

    tool: str
    amount_usd: float = 0.0
    currency: str = "usd"
    counterparty: str = ""
    data_class: str = DEFAULT_DATA_CLASS
    destination: str = ""
    duration_hours: float = 0.0
    irreversible: bool = DEFAULT_IRREVERSIBLE
    tags: tuple[str, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)

    def field_value(self, name: str) -> Any:
        if name in KNOWN_FIELDS:
            return getattr(self, name)
        return self.raw.get(name)

    def to_record(self) -> dict[str, Any]:
        d = asdict(self)
        d["tags"] = list(self.tags)
        d["raw"] = dict(self.raw)
        return d


def normalize_action(proposed: Action | Mapping[str, Any]) -> Action:
    """Validate and canonicalize a proposed action. Raises ActionValidationError."""
    if isinstance(proposed, Action):
        src: dict[str, Any] = proposed.to_record()
    elif isinstance(proposed, Mapping):
        src = dict(proposed)
    else:
        raise ActionValidationError("action must be an Action or a mapping")

    unknown = set(src) - KNOWN_FIELDS
    if unknown:
        raise ActionValidationError(f"unknown action fields: {sorted(unknown)}")

    if "tool" not in src:
        raise ActionValidationError("tool: required")
    tool = canon_str(src["tool"], "tool")
    if not tool:
        raise ActionValidationError("tool: must be non-empty")

    amount = _number(src.get("amount_usd", 0.0), "amount_usd")
    duration = _number(src.get("duration_hours", 0.0), "duration_hours", hi=1e6)

    currency = canon_str(src.get("currency", "usd"), "currency")
    counterparty = canon_str(src.get("counterparty", ""), "counterparty")
    destination = canon_str(src.get("destination", ""), "destination")

    data_class = canon_str(src.get("data_class", DEFAULT_DATA_CLASS), "data_class")
    if data_class not in DATA_CLASSES:
        raise ActionValidationError(f"data_class: {data_class!r} not in {list(DATA_CLASSES)}")

    irreversible = src.get("irreversible", DEFAULT_IRREVERSIBLE)
    if not isinstance(irreversible, bool):
        raise ActionValidationError("irreversible: expected a boolean")

    tags_in = src.get("tags", ())
    if isinstance(tags_in, (str, bytes)) or not isinstance(tags_in, (list, tuple)):
        raise ActionValidationError("tags: expected a list of strings")
    tags = tuple(canon_str(t, "tags[]") for t in tags_in)

    raw = src.get("raw", {}) or {}
    if not isinstance(raw, Mapping):
        raise ActionValidationError("raw: expected a mapping")

    return Action(
        tool=tool, amount_usd=amount, currency=currency, counterparty=counterparty,
        data_class=data_class, destination=destination, duration_hours=duration,
        irreversible=irreversible, tags=tags, raw=dict(raw),
    )
