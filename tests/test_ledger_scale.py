# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""#49 torn last line, #50 Merkle prefix roots and the size check staying honest."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from two_key.keys import generate_private_key
from two_key.ledger import Ledger, LedgerError, merkle_root, merkle_root_incremental


class MerkleIncremental(unittest.TestCase):
    def test_matches_full_root_including_awkward_sizes(self):
        for n in list(range(0, 65)) + [127, 128, 129, 255, 256, 511, 512, 1000]:
            leaves = [hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(n)]
            self.assertEqual(merkle_root_incremental(leaves), merkle_root(leaves), n)

    def test_ledger_prefix_roots_match_the_full_function(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            led = Ledger(Path(tmp, "ledger"), key)
            for i in range(6):
                led.append("note", {"n": i})
            led.checkpoint()
            leaves = [bytes.fromhex(e.entry_hash) for e in led.entries]
            self.assertEqual(led.merkle_root(), merkle_root(leaves).hex())
            for size in range(0, len(leaves) + 1):
                self.assertEqual(led.merkle_root(size), merkle_root(leaves[:size]).hex(), size)
            reopened = Ledger(Path(tmp, "ledger"), key)
            self.assertEqual(reopened.merkle_root(), led.merkle_root())
            self.assertEqual(reopened.merkle_root(3), led.merkle_root(3))


class KindIndex(unittest.TestCase):
    def test_lookups_match_a_full_walk_and_survive_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            path = Path(tmp, "ledger")
            led = Ledger(path, key)
            led.append("constitution_loaded", {"capability_key_fingerprint": "sha256:first"})
            for i in range(30):
                led.append("note", {"n": i})
            led.append("constitution_loaded", {"capability_key_fingerprint": "sha256:second"})
            for i in range(10):
                led.append("note", {"n": 100 + i})
            led.append("revocation", {"reason": "stop"})
            led.checkpoint()
            second = next(e.seq for e in led.entries if e.body.get("capability_key_fingerprint") == "sha256:second")
            self.assertEqual(led.last_before(second, "constitution_loaded").body["capability_key_fingerprint"],
                             "sha256:first")
            self.assertEqual(led.last_before(second + 1, "constitution_loaded").body["capability_key_fingerprint"],
                             "sha256:second")
            self.assertIsNone(led.last_before(0, "constitution_loaded"))
            naive = [e for e in led.entries[second:] if e.kind in {"constitution_loaded", "revocation", "note"}]
            self.assertEqual([e.seq for e in led.kinds_after(second, {"constitution_loaded", "revocation", "note"})],
                             [e.seq for e in naive])
            self.assertEqual(led.kinds_after(len(led.entries), {"revocation"}), [])
            reopened = Ledger(path, key)
            self.assertEqual(
                reopened.last_before(second + 1, "constitution_loaded").body["capability_key_fingerprint"],
                "sha256:second")
            self.assertEqual(
                [e.seq for e in reopened.kinds_after(second, {"revocation"})],
                [e.seq for e in led.kinds_after(second, {"revocation"})])


class TornLastRecord(unittest.TestCase):
    def test_last_line_names_a_crash_and_a_middle_line_names_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            path = Path(tmp, "ledger")
            led = Ledger(path, key)
            led.append("note", {"n": 1})
            led.checkpoint()
            led.append("note", {"n": 2})
            entries = path / "entries.jsonl"
            entries.write_bytes(entries.read_bytes()[:-8])
            with self.assertRaises(LedgerError) as raised:
                Ledger(path, key)
            self.assertIn("last record does not decrypt", str(raised.exception))
            self.assertNotIn("tampered ciphertext", str(raised.exception))

            path2 = Path(tmp, "ledger2")
            led = Ledger(path2, key)
            led.append("note", {"n": 1})
            led.checkpoint()
            led.append("note", {"n": 2})
            led.checkpoint()
            raw = (path2 / "entries.jsonl").read_bytes().splitlines()
            raw[0] = raw[0][:-4] + b"zzzz"
            (path2 / "entries.jsonl").write_bytes(b"\n".join(raw) + b"\n")
            with self.assertRaises(LedgerError) as raised:
                Ledger(path2, key)
            self.assertIn("tampered ciphertext", str(raised.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
