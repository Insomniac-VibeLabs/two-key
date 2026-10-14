"""Normalized action record and its validation.

``normalize_action`` validates and canonicalizes a proposed action before
the Policy VM sees it. Any validation failure raises ``ActionValidationError``,
and Two-Key turns that into an explicit, logged DENY.

Missing-field defaults follow the missing-field rule: a missing
``irreversible`` means ``True`` and a missing ``data_class`` means
``"classified"``. A signed constitution must include ``tool_specs``.
``derive.py`` then fills the form from the argument bytes. A disagreeing
claim is a deny. The missing-field defaults still apply before that fill:
omitted ``data_class`` stays ``classified``, and the floor cannot lower it.
Omitted ``irreversible`` is replaced by the spec. Free text is not classified.
``deny_unmapped`` defaults off. An unnamed argument key does not reach the
tool. Setting the flag denies that key instead. A counterparty path copies
only values on its allow list, canonicalized. A payload path is not
interpreted. Optional ``shape`` locks it to a string, a number, or a list
of strings. It does not read the contents.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping
from .agent_meta import type_tag

DATA_CLASSES = ("public", "personal", "medical", "financial", "classified")
# A call may carry both specific kinds of personal data: "financial+medical" (sorted, joined by "+").
DATA_CLASS_SEP = "+"
SPECIFIC_DATA_CLASSES = ("financial", "medical")


def data_class_parts(value: str) -> tuple[str, ...]:
    """The classes in a data_class value: "medical" -> ("medical",), "financial+medical" -> both."""
    return tuple(value.split(DATA_CLASS_SEP))


def canonical_data_class(value: str) -> str:
    """Validate a claim: one known class, or financial and medical joined by "+" (returned sorted)."""
    parts = set(data_class_parts(value))
    if len(parts) == 1 and parts <= set(DATA_CLASSES):
        return next(iter(parts))
    if parts == set(SPECIFIC_DATA_CLASSES):
        return DATA_CLASS_SEP.join(sorted(parts))
    raise ActionValidationError("data_class: not a known class")

# Conservative defaults for missing high-impact fields (the missing-field rule).
DEFAULT_IRREVERSIBLE = True
DEFAULT_DATA_CLASS = "classified"
MAX_AMOUNT_USD = 1e12  # sanity bound; larger values are rejected as malformed
# A tool name is an identifier: lower case after case folding, at most MAX_TOOL_NAME_CHARS.
MAX_TOOL_NAME_CHARS = 128
TOOL_NAME = re.compile(r"[a-z0-9][a-z0-9_.:/-]{0,%d}" % (MAX_TOOL_NAME_CHARS - 1))

KNOWN_FIELDS = {
    "tool", "amount_usd", "currency", "counterparty", "data_class",
    "destination", "duration_hours", "irreversible", "tags", "raw",
}
# What the policy VM's LOAD may read. Not ``raw``, and never a custom field (those use LOAD_FIELD).
LOADABLE_FIELDS = frozenset(KNOWN_FIELDS - {"raw"})


class ActionValidationError(ValueError):
    """Raised when a proposed action record is malformed. Always a DENY."""


def canon_str(value: Any, name: str) -> str:
    """Trim and case-fold a string field. Non-strings are rejected."""
    if not isinstance(value, str):
        raise ActionValidationError(f"{name}: expected string, got {type_tag(value)}")
    return value.strip().casefold()


def _number(value: Any, name: str, *, lo: float = 0.0, hi: float = MAX_AMOUNT_USD) -> float:
    # bool is a subclass of int; reject it explicitly. Numeric strings are rejected.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ActionValidationError(f"{name}: expected a number, got {type_tag(value)}")
    try:
        f = float(value)
    except OverflowError:  # an int such as 10**400
        raise ActionValidationError(f"{name}: exceeds maximum {hi}") from None
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
    # Custom field values derived from the argument bytes (fields.py). Never from the claim: a claim
    # that names ``fields`` is an unknown action field.
    fields: Mapping[str, Any] = field(default_factory=dict)

    def field_value(self, name: str) -> Any:
        """A built-in field. Any other name is a ``KeyError``: ``raw`` is the agent's, never a field."""
        if name == "data_class":     # Path A sees each class the call carries (data_class_in matches any)
            return data_class_parts(self.data_class)
        if name in LOADABLE_FIELDS:
            return getattr(self, name)
        raise KeyError("not a built-in field")

    def to_record(self) -> dict[str, Any]:
        d = asdict(self)
        d["tags"] = list(self.tags)
        d["raw"] = dict(self.raw)
        # Present only when the constitution declares custom fields, so a record without them hashes as before.
        if self.fields:
            d["fields"] = dict(self.fields)
        else:
            del d["fields"]
        return d


def normalize_action(proposed: Action | Mapping[str, Any]) -> Action:
    """Validate and canonicalize a proposed action. Raises ActionValidationError."""
    if isinstance(proposed, Action):
        src: dict[str, Any] = proposed.to_record()
    elif isinstance(proposed, Mapping):
        src = dict(proposed)
    else:
        raise ActionValidationError("action must be an Action or a mapping")

    # Reasons name the field only. A value or an unknown key name is never copied into a reason
    # (reasons go to the ledger, stderr, and Decision.reason).
    unknown = set(src) - KNOWN_FIELDS
    if unknown:
        raise ActionValidationError(f"unknown action fields ({len(unknown)})")

    if "tool" not in src:
        raise ActionValidationError("tool: required")
    tool = canon_str(src["tool"], "tool")
    if not tool:
        raise ActionValidationError("tool: must be non-empty")
    if len(tool) > MAX_TOOL_NAME_CHARS:
        raise ActionValidationError(f"tool: longer than {MAX_TOOL_NAME_CHARS} characters")
    if not TOOL_NAME.fullmatch(tool):
        raise ActionValidationError("tool: not an identifier (a-z, 0-9, and _ . : / -)")

    amount = _number(src.get("amount_usd", 0.0), "amount_usd")
    duration = _number(src.get("duration_hours", 0.0), "duration_hours", hi=1e6)

    currency = canon_str(src.get("currency", "usd"), "currency")
    counterparty = canon_str(src.get("counterparty", ""), "counterparty")
    destination = canon_str(src.get("destination", ""), "destination")

    data_class = canonical_data_class(canon_str(src.get("data_class", DEFAULT_DATA_CLASS), "data_class"))

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
