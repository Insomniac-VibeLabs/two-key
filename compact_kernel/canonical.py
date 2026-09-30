"""Canonical JSON encoding and hashing, shared by every component.

Hashes and signatures are computed over these bytes, so the encoding
must be deterministic. Keys are sorted, separators are fixed, output is
ASCII-only, and NaN/Infinity are rejected.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(obj: Any) -> str:
    return sha256_hex(canonical_bytes(obj))
