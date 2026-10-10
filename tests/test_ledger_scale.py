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
