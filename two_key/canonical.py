"""Canonical JSON encoding and hashing, shared by every component.

Hashes and signatures are computed over these bytes, so the encoding
must be deterministic. Keys are sorted, separators are fixed, output is
ASCII-only, and NaN/Infinity are rejected.

All hashing goes through the crypto provider (two_key.crypto), so the
FIPS-mode algorithm policy applies. ``sha256_hex`` keeps the legacy
SHA-256 behaviour; ``digest_hex``/``canonical_hash`` take an algorithm
(e.g. "sha384" for the post-quantum profiles).
"""

from __future__ import annotations

import json
from typing import Any

from .crypto.provider import CryptoProvider, default_provider


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def digest_hex(data: bytes, alg: str = "sha256", provider: CryptoProvider | None = None) -> str:
    return (provider or default_provider()).hash_hex(alg, data)


def sha256_hex(data: bytes) -> str:
    return default_provider().hash_hex("sha256", data)


def canonical_hash(obj: Any, alg: str = "sha256", provider: CryptoProvider | None = None) -> str:
    return digest_hex(canonical_bytes(obj), alg, provider)
