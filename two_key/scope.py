"""Scope taken from the frozen tool arguments, not from the agent's summary.

The action record is a claim. The arguments are what the gateway will run.
A claim that is quieter than the arguments is a mismatch, not a judgment.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Mapping

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "Α": "a", "Β": "b", "Ε": "e", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n",
    "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
})
_MONEY = re.compile(
    r"(?:\$\s*([0-9][0-9,]*(?:\.[0-9]+)?)|([0-9][0-9,]*(?:\.[0-9]+)?)\s*(?:usd|dollars?|bucks)"
    r"|(?:usd|dollars?)\s*([0-9][0-9,]*(?:\.[0-9]+)?))",
    re.I,
)
_SENSITIVE = ("patient", "diagnosis", "ssn", "social security", "classified", "top secret",
              "medical record", "phi", "hipaa")
_PAY = ("wire", "ach ", "sepa", "usdt", "gift card", "giftcard", "remit")
_QUIET_TOOLS = {"search", "notes", "draft", "summarize", "read"}


def fold(text: str) -> str:
    """NFKC, drop zero-width characters, fold the homoglyphs a phrase list misses."""
    folded = unicodedata.normalize("NFKC", text or "").translate(_ZERO_WIDTH).translate(_HOMOGLYPHS)
    return folded


def _walk(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        out = []
        for key, item in value.items():
            out.append(str(key))
            out.extend(_walk(item))
        return out
    if isinstance(value, (list, tuple)):
        return [part for item in value for part in _walk(item)]
    if value is None or isinstance(value, (int, float, bool)):
        return [str(value)]
    return []


def argument_text(args: Mapping[str, Any]) -> str:
    try:
        blob = json.dumps(args, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        blob = repr(args)
    return fold("\n".join(_walk(args) + [blob]))


def amounts_in(text: str) -> list[float]:
    found = []
    for match in _MONEY.finditer(text):
        raw = next(group for group in match.groups() if group)
        found.append(float(raw.replace(",", "")))
    return found


def derive(tool: str, args: Mapping[str, Any]) -> dict[str, Any]:
    text = argument_text(args)
    low = text.lower()
    amounts = amounts_in(low)
    return {
        "tool": tool,
        "amount_usd": max(amounts) if amounts else None,
        "sensitive": any(mark in low for mark in _SENSITIVE),
        "payment": any(mark in low for mark in _PAY),
    }


def disagreement(record: Mapping[str, Any], args: Mapping[str, Any]) -> str | None:
    """None when the frozen arguments do not contradict the action record."""
    if not args:
        return None
    derived = derive(str(record.get("tool", "")), args)
    claimed = float(record.get("amount_usd") or 0)
    if derived["amount_usd"] is not None and derived["amount_usd"] - claimed > 0.01:
        return "amount_mismatch"
    if str(record.get("data_class", "")) == "public" and derived["sensitive"]:
        return "sensitive_labeled_public"
    if derived["payment"] and str(record.get("tool", "")) in _QUIET_TOOLS:
        return "tool_hides_payment"
    nested = args.get("tool")
    if isinstance(nested, str) and nested and nested != record.get("tool"):
        return "tool_mismatch"
    return None
