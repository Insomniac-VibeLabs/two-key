"""A minimal RFC 6962-style Merkle tree over ledger entry digests.

leaf hash = SHA-256(0x00 || leaf), node hash = SHA-256(0x01 || left || right).
The tree splits at the largest power of two below n, as in Certificate
Transparency. The root of an empty tree is SHA-256(b"").
"""

from __future__ import annotations

import hashlib
from typing import Sequence


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf_hash(leaf: bytes) -> bytes:
    return _h(b"\x00" + leaf)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01" + left + right)


def _split(n: int) -> int:
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root(leaves: Sequence[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return _h(b"")
    if n == 1:
        return leaf_hash(leaves[0])
    k = _split(n)
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def inclusion_proof(leaves: Sequence[bytes], index: int) -> list[bytes]:
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError("leaf index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(leaves[:k], index) + [root(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [root(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, size: int, proof: Sequence[bytes], expected_root: bytes) -> bool:
    def rec(idx: int, n: int, path: list[bytes]) -> bytes | None:
        if n == 1:
            return leaf_hash(leaf) if not path else None
        if not path:
            return None
        k = _split(n)
        sibling = path[-1]
        if idx < k:
            sub = rec(idx, k, path[:-1])
            return None if sub is None else node_hash(sub, sibling)
        sub = rec(idx - k, n - k, path[:-1])
        return None if sub is None else node_hash(sibling, sub)

    if not 0 <= index < size:
        return False
    got = rec(index, size, list(proof))
    return got is not None and got == expected_root
