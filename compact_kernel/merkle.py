"""A minimal RFC 6962-style Merkle tree over ledger entry digests.

leaf hash = H(0x00 || leaf), node hash = H(0x01 || left || right), where H is
SHA-256 by default (legacy) or SHA-384 in the post-quantum profile. The tree
splits at the largest power of two below n, as in Certificate Transparency.
The root of an empty tree is H(b"").

``MerkleFrontier`` keeps the roots of the perfect subtrees along the right
edge, so appending a leaf and reading the root cost O(log n) instead of
rebuilding the whole tree (needed for signed-head updates on long ledgers).
"""

from __future__ import annotations

import hashlib
from typing import Callable, Sequence

HashFn = Callable[[bytes], bytes]


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf_hash(leaf: bytes, h: HashFn = _sha256) -> bytes:
    return h(b"\x00" + leaf)


def node_hash(left: bytes, right: bytes, h: HashFn = _sha256) -> bytes:
    return h(b"\x01" + left + right)


def _split(n: int) -> int:
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root(leaves: Sequence[bytes], h: HashFn = _sha256) -> bytes:
    n = len(leaves)
    if n == 0:
        return h(b"")
    if n == 1:
        return leaf_hash(leaves[0], h)
    k = _split(n)
    return node_hash(root(leaves[:k], h), root(leaves[k:], h), h)


def inclusion_proof(leaves: Sequence[bytes], index: int, h: HashFn = _sha256) -> list[bytes]:
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError("leaf index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(leaves[:k], index, h) + [root(leaves[k:], h)]
    return inclusion_proof(leaves[k:], index - k, h) + [root(leaves[:k], h)]


def verify_inclusion(leaf: bytes, index: int, size: int, proof: Sequence[bytes], expected_root: bytes,
                     h: HashFn = _sha256) -> bool:
    def rec(idx: int, n: int, path: list[bytes]) -> bytes | None:
        if n == 1:
            return leaf_hash(leaf, h) if not path else None
        if not path:
            return None
        k = _split(n)
        sibling = path[-1]
        if idx < k:
            sub = rec(idx, k, path[:-1])
            return None if sub is None else node_hash(sub, sibling, h)
        sub = rec(idx - k, n - k, path[:-1])
        return None if sub is None else node_hash(sibling, sub, h)

    if not 0 <= index < size:
        return False
    got = rec(index, size, list(proof))
    return got is not None and got == expected_root


class MerkleFrontier:
    """Incremental RFC 6962 root: O(log n) per append and per root()."""

    def __init__(self, h: HashFn = _sha256):
        self.h = h
        self.size = 0
        self._stack: list[tuple[int, bytes]] = []  # (subtree size, subtree root), sizes strictly decreasing

    def append(self, leaf: bytes) -> None:
        node, size = leaf_hash(leaf, self.h), 1
        while self._stack and self._stack[-1][0] == size:
            left_size, left = self._stack.pop()
            node, size = node_hash(left, node, self.h), size + left_size
        self._stack.append((size, node))
        self.size += 1

    def root(self) -> bytes:
        if not self._stack:
            return self.h(b"")
        acc = self._stack[-1][1]
        for _, sub in reversed(self._stack[:-1]):
            acc = node_hash(sub, acc, self.h)
        return acc
