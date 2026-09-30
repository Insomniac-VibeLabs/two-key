"""A minimal RFC 6962-style Merkle tree over ledger entry digests.

leaf hash = H(0x00 || leaf), node hash = H(0x01 || left || right), where H is
SHA-256 by default (legacy) or SHA-384 in the post-quantum profile. The tree
splits at the largest power of two below n, as in Certificate Transparency.
The root of an empty tree is H(b"").

``MerkleFrontier`` keeps the roots of the perfect subtrees along the right
edge, so appending a leaf and reading the root cost O(log n) instead of
rebuilding the whole tree (needed for signed-head updates on long ledgers).

``MerkleTree`` also keeps every completed perfect subtree root (about 2n
hashes in total). It can then answer, in O(log n) to O(log^2 n) hash
operations:
* the root of any earlier tree size (``root(size)``),
* inclusion proofs (RFC 9162 section 2.1.3),
* consistency proofs between two tree sizes (RFC 9162 section 2.1.4).
``verify_consistency`` implements the RFC 9162 section 2.1.4.2 verifier. The
tool gateway uses it to check that the ledger root bound into a token is an
ancestor of (a prefix of) the ledger it currently knows (PRIOR_ART.md §4 (i)).
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


class MerkleTree:
    """Append-only RFC 6962/9162 tree that stores all perfect-subtree roots."""

    def __init__(self, h: HashFn = _sha256):
        self.h = h
        self.size = 0
        # levels[j][i] = root of leaves [i * 2**j, (i + 1) * 2**j)
        self.levels: list[list[bytes]] = [[]]
        self._root_cache: tuple[int, bytes] | None = None

    def append(self, leaf: bytes) -> None:
        node = leaf_hash(leaf, self.h)
        idx = self.size
        self.levels[0].append(node)
        self.size += 1
        j = 0
        while idx & 1:  # this node completes a pair at level j
            node = node_hash(self.levels[j][idx - 1], node, self.h)
            j += 1
            idx >>= 1
            if len(self.levels) <= j:
                self.levels.append([])
            self.levels[j].append(node)

    def _mth(self, start: int, n: int) -> bytes:
        """Root of leaves [start, start + n), n >= 1."""
        if n & (n - 1) == 0 and start % n == 0:
            j = n.bit_length() - 1
            return self.levels[j][start >> j]
        k = _split(n)
        return node_hash(self._mth(start, k), self._mth(start + k, n - k), self.h)

    def root(self, size: int | None = None) -> bytes:
        size = self.size if size is None else size
        if not 0 <= size <= self.size:
            raise IndexError("tree size out of range")
        if size == 0:
            return self.h(b"")
        if size == self.size:
            if self._root_cache is None or self._root_cache[0] != size:
                self._root_cache = (size, self._mth(0, size))
            return self._root_cache[1]
        return self._mth(0, size)

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        size = self.size if size is None else size
        if not 0 <= index < size <= self.size:
            raise IndexError("leaf index or tree size out of range")

        def path(m: int, start: int, n: int) -> list[bytes]:
            if n == 1:
                return []
            k = _split(n)
            if m < k:
                return path(m, start, k) + [self._mth(start + k, n - k)]
            return path(m - k, start + k, n - k) + [self._mth(start, k)]
        return path(index, 0, size)

    def consistency_proof(self, first: int, second: int | None = None) -> list[bytes]:
        """RFC 9162 PROOF(first, D[second])."""
        second = self.size if second is None else second
        if not 0 <= first <= second <= self.size:
            raise IndexError("tree sizes out of range")
        if first == 0 or first == second:
            return []

        def sub(m: int, start: int, n: int, whole: bool) -> list[bytes]:
            if m == n:
                return [] if whole else [self._mth(start, n)]
            k = _split(n)
            if m <= k:
                return sub(m, start, k, whole) + [self._mth(start + k, n - k)]
            return sub(m - k, start + k, n - k, False) + [self._mth(start, k)]
        return sub(first, 0, second, True)


def consistency_proof(leaves: Sequence[bytes], first: int, h: HashFn = _sha256) -> list[bytes]:
    """Reference (non-cached) RFC 9162 consistency proof, used to cross-check MerkleTree."""
    second = len(leaves)
    if not 0 <= first <= second:
        raise IndexError("tree sizes out of range")
    if first == 0 or first == second:
        return []

    def sub(m: int, d: Sequence[bytes], whole: bool) -> list[bytes]:
        n = len(d)
        if m == n:
            return [] if whole else [root(d, h)]
        k = _split(n)
        if m <= k:
            return sub(m, d[:k], whole) + [root(d[k:], h)]
        return sub(m - k, d[k:], False) + [root(d[:k], h)]
    return sub(first, leaves, True)


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes,
                       proof: Sequence[bytes], h: HashFn = _sha256) -> bool:
    """RFC 9162 section 2.1.4.2: is the tree of size ``first`` a prefix of the tree of size ``second``?"""
    proof = list(proof)
    if first < 0 or second < 0 or first > second:
        return False
    if first == second:
        return not proof and first_root == second_root
    if first == 0:
        return not proof and first_root == h(b"")
    if not proof:
        return False
    if first & (first - 1) == 0:  # exact power of two
        proof = [first_root] + proof
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr, h)
            sr = node_hash(c, sr, h)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c, h)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
