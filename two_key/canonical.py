"""Canonical JSON encoding and hashing, shared by every component.

Hashes and signatures are computed over these bytes, so the encoding
must be deterministic. Keys are sorted, separators are fixed, output is
ASCII-only, and NaN/Infinity are rejected.

All hashing goes through the crypto provider (two_key.crypto), so the
FIPS-mode algorithm policy applies. ``digest_hex``/``canonical_hash``
default to SHA-384 (F_REVIEW; CONCEPTION_NOTES Entry 10) and take any
approved algorithm; ``sha256_hex`` remains for reading legacy records.

Two encodings
-------------
``canonical_bytes`` is canonical JSON. It is used for JSON-native records
(ledger entries, signed constitutions, signed heads, token payloads), whose
values come from JSON or from Two-Key itself. Since F_REVIEW finding 2, it
refuses non-string mapping keys instead of coercing them; no record that
already verifies changes bytes.

``typed_bytes`` (``two-key-enc/2``) is the injective, typed, versioned
encoding for values the agent supplies and a tool receives (F_REVIEW §7.2,
finding 2; approved by Stephan, CONCEPTION_NOTES Entry 10). Every value
carries a type tag, so a tuple and a list, ``1`` and ``"1"``, ``1`` and
``1.0``, and ``True`` and ``1`` all encode differently. Mapping keys must
be strings. The output is a canonical JSON object with the encoding
version and a domain-separation label:
``{"domain": <label>, "enc": "two-key-enc/2", "value": <tagged>}``.
``typed_loads`` decodes it back to the same types (tuples stay tuples).

``freeze_call`` serializes a tool call once into immutable bytes. The
gateway hashes those bytes, scans them, and runs the tool with arguments
decoded from them (F_REVIEW §7.1, finding 1). No Unicode normalization is
applied: differently normalized strings stay different (a false mismatch,
never a false match).
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Mapping

from .crypto.provider import CryptoProvider, default_provider


class EncodingError(TypeError):
    """A value can't be encoded injectively (non-string key, unsupported type, NaN, too deep)."""


def _check_keys(obj: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise EncodingError("value nested too deeply")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise EncodingError(f"mapping keys must be strings (got {type(k).__name__})")
            _check_keys(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _check_keys(v, depth + 1)


def canonical_bytes(obj: Any) -> bytes:
    """Canonical JSON. Non-string mapping keys are refused, not coerced (F_REVIEW finding 2)."""
    _check_keys(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


# ---------------------------------------------------------------------------
# two-key-enc/2: typed, injective, versioned, domain-separated
# ---------------------------------------------------------------------------
ENCODING = "two-key-enc/2"
DOMAIN_TOOL_CALL = "two-key/tool-call"
DOMAIN_ACTION_RECORD = "two-key/action-record"
DOMAIN_TOOL_RESULT = "two-key/tool-result"
MAX_DEPTH = 64


def _tag(obj: Any, depth: int) -> list:
    if depth > MAX_DEPTH:
        raise EncodingError("value nested too deeply")
    if obj is None:
        return ["z"]
    if isinstance(obj, bool):
        return ["b", obj is True]
    if isinstance(obj, int):
        return ["i", int.__repr__(obj)]
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise EncodingError("NaN and infinity are not allowed")
        return ["f", float.__repr__(obj)]
    if isinstance(obj, str):
        return ["s", str.__str__(obj)]
    if isinstance(obj, tuple):
        return ["t", [_tag(v, depth + 1) for v in tuple(obj)]]
    if isinstance(obj, list):
        return ["l", [_tag(v, depth + 1) for v in list(obj)]]
    if isinstance(obj, Mapping):
        out, seen = [], set()
        for k, v in list(obj.items()):  # one read of the caller's mapping
            if not isinstance(k, str):
                raise EncodingError(f"mapping keys must be strings (got {type(k).__name__})")
            k = str.__str__(k)
            if k in seen:
                raise EncodingError("duplicate mapping key")
            seen.add(k)
            out.append([k, _tag(v, depth + 1)])
        out.sort(key=lambda kv: kv[0])
        return ["m", out]
    raise EncodingError(f"unsupported value type {type(obj).__name__}")


def _untag(t: Any, depth: int = 0) -> Any:
    if depth > MAX_DEPTH or not isinstance(t, list) or not t or not isinstance(t[0], str):
        raise EncodingError("malformed two-key-enc/2 value")
    tag, rest = t[0], t[1:]
    if tag == "z" and not rest:
        return None
    if len(rest) != 1:
        raise EncodingError("malformed two-key-enc/2 value")
    v = rest[0]
    if tag == "b" and isinstance(v, bool):
        return v
    if tag == "i" and isinstance(v, str):
        return int(v)
    if tag == "f" and isinstance(v, str):
        return float(v)
    if tag == "s" and isinstance(v, str):
        return v
    if tag in ("l", "t") and isinstance(v, list):
        items = [_untag(x, depth + 1) for x in v]
        return tuple(items) if tag == "t" else items
    if tag == "m" and isinstance(v, list):
        out = {}
        for kv in v:
            if not (isinstance(kv, list) and len(kv) == 2 and isinstance(kv[0], str)):
                raise EncodingError("malformed two-key-enc/2 mapping")
            out[kv[0]] = _untag(kv[1], depth + 1)
        return out
    raise EncodingError(f"malformed two-key-enc/2 value (tag {tag!r})")


def typed_bytes(obj: Any, domain: str) -> bytes:
    """The two-key-enc/2 encoding of ``obj`` under ``domain`` (see the module docstring)."""
    if not isinstance(domain, str) or not domain:
        raise ValueError("a domain-separation label is required")
    return json.dumps({"domain": domain, "enc": ENCODING, "value": _tag(obj, 0)}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def typed_loads(data: bytes, domain: str) -> Any:
    """Decode two-key-enc/2 bytes. The label must equal ``domain`` and the bytes must be canonical."""
    try:
        env = json.loads(bytes(data).decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise EncodingError("not two-key-enc/2 bytes") from None
    if not isinstance(env, dict) or set(env) != {"domain", "enc", "value"} or env["enc"] != ENCODING:
        raise EncodingError("not two-key-enc/2 bytes")
    if env["domain"] != domain:
        raise EncodingError(f"domain is {env['domain']!r}, not {domain!r}")
    value = _untag(env["value"])
    if typed_bytes(value, domain) != bytes(data):
        raise EncodingError("non-canonical two-key-enc/2 bytes")
    return value


def typed_hash(obj: Any, domain: str, alg: str = "sha384", provider: CryptoProvider | None = None) -> str:
    return digest_hex(typed_bytes(obj, domain), alg, provider)


@dataclass(frozen=True)
class FrozenCall:
    """A tool call serialized once (F_REVIEW §7.1). ``data`` is what is hashed, scanned, and executed."""
    tool: str
    data: bytes

    def args(self) -> dict:
        """A fresh copy of the arguments decoded from ``data`` (each caller gets its own)."""
        return typed_loads(self.data, DOMAIN_TOOL_CALL)["args"]

    def digest(self, alg: str = "sha384", provider: CryptoProvider | None = None) -> str:
        return digest_hex(self.data, alg, provider)


def freeze_call(tool: str, args: Any) -> FrozenCall:
    """Serialize ``{tool, args}`` once with two-key-enc/2. Raises TypeError/EncodingError if it can't."""
    if not isinstance(args, Mapping):
        raise TypeError("tool args must be a mapping")
    if not isinstance(tool, str):
        raise TypeError("tool name must be a string")
    return FrozenCall(tool, typed_bytes({"tool": tool, "args": args}, DOMAIN_TOOL_CALL))


def digest_hex(data: bytes, alg: str = "sha384", provider: CryptoProvider | None = None) -> str:
    return (provider or default_provider()).hash_hex(alg, data)


def sha256_hex(data: bytes) -> str:
    return default_provider().hash_hex("sha256", data)


def canonical_hash(obj: Any, alg: str = "sha384", provider: CryptoProvider | None = None) -> str:
    return digest_hex(canonical_bytes(obj), alg, provider)
