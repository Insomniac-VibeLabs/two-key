"""Canonical encoding for the ledger, tokens, and judge bindings.

JSON with sorted keys and no insignificant whitespace. Non-finite numbers
are rejected so two encoders cannot disagree on NaN. Containers nested more
than ``MAX_DEPTH`` levels are an ``EncodingError``. The walk is iterative, so
the limit does not depend on the Python version or on how deep the caller's
stack is.

Inputs (tool args, the action claim, a non-text proposal) are held to
``MAX_INPUT_DEPTH``, which is ``WRAP_DEPTH`` levels under ``MAX_DEPTH``. That
leaves room for the two levels an input gains when it is wrapped. A ledger
entry's hash covers ``{"body": {field: value}}``, and a judge's action record
carries the args as ``{"raw": {"tool_args": args}}``. So an input that is
accepted can always be encoded again inside its wrapper.

``to_plain`` copies an input once, without recursion, into built-in ``dict``,
``list``, ``str``, ``int``, ``float``, ``bool`` and ``None``. Any
``collections.abc.Mapping`` becomes a dict and a tuple becomes a list.
Everything after that is measured, hashed, judged, ledgered and handed to
the tool from the copy. A custom mapping's ``__str__``, ``__repr__`` or
``__iter__`` is read once, during the copy, and never again.

An integer with more than ``MAX_INT_DIGITS`` (4300) decimal digits is an
``EncodingError`` (``integer too large``), on every Python version, in the
copy and in the encoder: Python 3.11+ cannot write one as text, and the
answer must not depend on the interpreter (#51).
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from typing import Any


class EncodingError(ValueError):
    pass


# Containers (objects and arrays) nested more than this many levels are not encoded.
MAX_DEPTH = 64
# Levels an input gains when it is wrapped: a ledger body field, or raw.tool_args in a judge's record.
WRAP_DEPTH = 2
# The limit on tool args, the action claim, and a non-text proposal.
MAX_INPUT_DEPTH = MAX_DEPTH - WRAP_DEPTH


# Python 3.11+ refuses int<->str conversions past 4300 digits (sys.int_info.default_max_str_digits).
MAX_INT_DIGITS = 4300
_INT_LIMIT = 10 ** MAX_INT_DIGITS
INTEGER_TOO_LARGE = "integer too large"


def _int_too_large(value: int) -> bool:
    return int.__abs__(value) >= _INT_LIMIT       # never a subclass's own __abs__


def nested_too_deeply(what: str = "value is") -> str:
    return f"{what} nested too deeply"


class OversizeError(EncodingError):
    """``to_plain`` met more elements than fit under the caller's byte cap and stopped copying."""


def _scalar(value: Any) -> Any:
    if value is None or value is True or value is False:
        return value
    if isinstance(value, str):     # a subclass is copied to its str value; its __str__ is not called
        return value if type(value) is str else str.__str__(value)
    if isinstance(value, int):
        value = value if type(value) is int else int.__int__(value)
        if _int_too_large(value):
            raise EncodingError(INTEGER_TOO_LARGE)
        return value
    if isinstance(value, float):
        return value if type(value) is float else float.__float__(value)
    raise EncodingError("unsupported_type")


def to_plain(value: Any, *, max_depth: int = MAX_INPUT_DEPTH, what: str = "value is",
             max_items: int | None = None) -> Any:
    """Copy ``value`` once into built-in types, without recursion.

    Any ``Mapping`` (string keys only) becomes a ``dict``, and a ``list`` or ``tuple`` becomes a ``list``.
    A ``str``, ``int`` or ``float`` subclass becomes its base value. Anything else is an ``EncodingError``.
    A container more than ``max_depth`` levels down is ``EncodingError("<what> nested too deeply")``.
    With ``max_items``, copying stops with ``OversizeError`` after that many values, so a mapping
    that never stops iterating cannot hang the caller. Every value takes at least two bytes of JSON,
    so ``cap // 2`` items is a safe bound for a ``cap``-byte limit."""
    root: list = [None]
    stack = [(value, root, 0, 1)]
    count = 1

    def push(child, parent, slot, level):
        nonlocal count
        count += 1
        if max_items is not None and count > max_items:
            raise OversizeError(f"{what} too large")
        stack.append((child, parent, slot, level))

    while stack:
        item, parent, slot, level = stack.pop()
        if isinstance(item, Mapping):
            if level > max_depth:
                raise EncodingError(nested_too_deeply(what))
            out: dict = {}
            parent[slot] = out
            for key, child in item.items():
                if not isinstance(key, str):
                    raise EncodingError("canonical object keys must be strings")
                key = _scalar(key)
                if key in out:
                    raise EncodingError("duplicate object key")
                out[key] = None
                push(child, out, key, level + 1)
        elif isinstance(item, (list, tuple)):
            if level > max_depth:
                raise EncodingError(nested_too_deeply(what))
            seq: list = []
            parent[slot] = seq
            for child in item:
                seq.append(None)
                push(child, seq, len(seq) - 1, level + 1)
        else:
            parent[slot] = _scalar(item)
    return root[0]


def _check(value: Any, max_depth: int, what: str) -> None:
    """Walk ``value`` without recursion. The outermost container is level 1."""
    stack = [(value, 1)]
    while stack:
        item, level = stack.pop()
        if isinstance(item, bool) or item is None or isinstance(item, str):
            continue
        if isinstance(item, int):
            if _int_too_large(item):
                raise EncodingError(INTEGER_TOO_LARGE)
            continue
        if isinstance(item, float):
            if math.isnan(item) or math.isinf(item):
                raise EncodingError("non-finite number")
            continue
        if isinstance(item, (list, tuple, dict)):
            if level > max_depth:
                raise EncodingError(nested_too_deeply(what))
            if isinstance(item, dict):
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise EncodingError("canonical object keys must be strings")
                    stack.append((child, level + 1))
            else:
                stack.extend((child, level + 1) for child in item)
            continue
        raise EncodingError("unsupported_type")


def canonical_bytes(value: Any, *, max_depth: int = MAX_DEPTH, what: str = "value is") -> bytes:
    """Canonical JSON of ``value``. ``EncodingError`` if it nests more than ``max_depth`` levels, holds a
    non-finite number, a non-string key, or a type JSON has no form for. ``what`` names the value in the
    nesting error (``"tool args are"`` gives ``tool args are nested too deeply``)."""
    try:
        _check(value, max_depth, what)
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except RecursionError:  # not expected under MAX_DEPTH; kept so a crash is never the answer
        raise EncodingError(nested_too_deeply(what)) from None
    except EncodingError:
        raise
    except ValueError as e:  # an interpreter whose int limit is under MAX_INT_DIGITS (PYTHONINTMAXSTRDIGITS)
        raise EncodingError(INTEGER_TOO_LARGE if "digits" in str(e) else "value cannot be encoded") from None


def digest_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value: Any) -> str:
    return digest_hex(canonical_bytes(value))
