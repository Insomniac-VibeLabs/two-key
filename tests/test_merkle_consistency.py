"""RFC 9162 consistency proofs and the cached MerkleTree (groundwork for PRIOR_ART.md §4 (i))."""
import hashlib
import os
import random
import tempfile
import unittest
from pathlib import Path

from compact_kernel import keys, merkle
from compact_kernel.ledger import PersonalLedger


def sha384(b):
    return hashlib.sha384(b).digest()


class MerkleTreeMatchesReference(unittest.TestCase):
    def test_roots_inclusion_and_consistency_brute_force(self):
        rnd = random.Random(7)
        for h in (merkle._sha256, sha384):
            leaves = [os.urandom(32) for _ in range(65)]
            t = merkle.MerkleTree(h)
            for n in range(66):
                self.assertEqual(t.root(), merkle.root(leaves[:n], h))
                for m in range(n + 1):
                    self.assertEqual(t.root(m), merkle.root(leaves[:m], h))
                    p = t.consistency_proof(m)
                    self.assertEqual(p, merkle.consistency_proof(leaves[:n], m, h))
                    self.assertTrue(merkle.verify_consistency(m, n, t.root(m), t.root(), p, h), (m, n))
                    if 0 < m < n:
                        bad = list(p)
                        bad[rnd.randrange(len(bad))] = os.urandom(len(bad[0]))
                        self.assertFalse(merkle.verify_consistency(m, n, t.root(m), t.root(), bad, h))
                        self.assertFalse(merkle.verify_consistency(m, n, os.urandom(32), t.root(), p, h))
                        self.assertFalse(merkle.verify_consistency(m, n, t.root(m), os.urandom(32), p, h))
                        self.assertFalse(merkle.verify_consistency(m, n, t.root(m), t.root(), p[:-1], h))
                        self.assertFalse(merkle.verify_consistency(m, n, t.root(m), t.root(), p + [p[0]], h))
                        self.assertFalse(merkle.verify_consistency(n, m, t.root(), t.root(m), p, h))
                for i in range(n):
                    ip = t.inclusion_proof(i)
                    self.assertEqual(ip, merkle.inclusion_proof(leaves[:n], i, h))
                    self.assertTrue(merkle.verify_inclusion(leaves[i], i, n, ip, t.root(), h))
                if n < 65:
                    t.append(leaves[n])

    def test_edge_cases(self):
        t = merkle.MerkleTree()
        empty = t.root()
        self.assertEqual(empty, hashlib.sha256(b"").digest())
        for x in (b"a", b"b", b"c"):
            t.append(x)
        self.assertTrue(merkle.verify_consistency(0, 3, empty, t.root(), []))
        self.assertFalse(merkle.verify_consistency(0, 3, b"x" * 32, t.root(), []))
        self.assertTrue(merkle.verify_consistency(3, 3, t.root(), t.root(), []))
        self.assertFalse(merkle.verify_consistency(3, 3, t.root(), t.root(), [t.root()]))
        self.assertFalse(merkle.verify_consistency(2, 3, t.root(2), t.root(), []))
        self.assertFalse(merkle.verify_consistency(-1, 3, t.root(2), t.root(), []))
        with self.assertRaises(IndexError):
            t.root(4)
        with self.assertRaises(IndexError):
            t.consistency_proof(2, 4)
        with self.assertRaises(IndexError):
            t.inclusion_proof(3)


class LedgerConsistency(unittest.TestCase):
    def test_ledger_proofs_historical_roots_and_reload(self):
        with tempfile.TemporaryDirectory() as d:
            key = keys.generate_private_key()
            led = PersonalLedger(Path(d) / "l.jsonl", key, auto_sign_every=0, fsync=False)
            roots = [led.merkle_root()]
            for i in range(40):
                led.append("x", {"i": i})
                roots.append(led.merkle_root())
            for m in (1, 5, 16, 17, 33):
                self.assertEqual(led.merkle_root(m), roots[m])
                p = led.consistency_proof(m)
                self.assertTrue(PersonalLedger.verify_consistency_proof(p, roots[m], roots[40]))
                # The verifier uses the roots it holds, not the roots inside the proof.
                self.assertFalse(PersonalLedger.verify_consistency_proof(p, roots[m - 1], roots[40]))
                self.assertFalse(PersonalLedger.verify_consistency_proof(dict(p, proof=["zz"]), roots[m], roots[40]))
                self.assertFalse(PersonalLedger.verify_consistency_proof({"first": m}, roots[m], roots[40]))
            led.checkpoint()
            again = PersonalLedger(Path(d) / "l.jsonl", key, auto_sign_every=0, fsync=False)
            self.assertEqual(again.merkle_root(), roots[40])
            self.assertEqual(again.consistency_proof(9), led.consistency_proof(9))
            self.assertTrue(again.verify(key.public_key()).ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
