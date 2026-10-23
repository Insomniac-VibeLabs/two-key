# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Two processes on one ledger (two MCP proxies, say): the one that did not write catches up under the lock.

Each Ledger object here stands for a process: it keeps its own copy of the ledger's state, as a second proxy
does. The new entries are verified like an open verifies them; a shorter file, a partial line, or a forged
line is still refused."""

import tempfile
import threading
import unittest
from pathlib import Path

from two_key.keys import generate_private_key
from two_key.ledger import Ledger, LedgerError


class SharedLedger(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name, "ledger")
        self.key = generate_private_key()
        self.a = Ledger(self.path, self.key)
        self.b = Ledger(self.path, self.key)

    def write(self, ledger, n):  # skipcq: PYL-R0201 - test only
        ledger.append("note", {"n": n})
        ledger.checkpoint()

    def test_writers_take_turns(self):
        for n in range(6):
            self.write(self.a if n % 2 == 0 else self.b, n)
        self.assertEqual(self.a.size(), 6)          # a has not read b's last entry yet
        self.write(self.a, 6)
        self.assertEqual([e.body.get("n") for e in self.a.entries], [None, 0, 1, 2, 3, 4, 5, 6])
        reopened = Ledger(self.path, self.key)
        self.assertEqual([e.entry_hash for e in reopened.entries], [e.entry_hash for e in self.a.entries])

    def test_a_redemption_by_one_is_seen_by_the_other(self):
        self.a.append("redemption", {"jti": "t1"})
        self.a.checkpoint()
        self.assertFalse(self.b.is_redeemed("t1"))  # not read yet
        self.write(self.b, 1)
        self.assertTrue(self.b.is_redeemed("t1"))

    def test_observers_get_only_their_own_entries(self):
        seen = []
        self.b.observe(seen.append)
        self.write(self.a, 1)
        self.write(self.b, 2)
        self.assertEqual(seen, [2])                 # the SIEM copy of entry 1 is a's to send

    def test_a_rotation_by_one_is_followed_by_the_other(self):
        self.a.rotate_witness(reason="test")
        self.write(self.b, 1)
        self.assertEqual(self.b.entries[-2].kind, "witness_rotated")
        self.assertEqual(Ledger(self.path, self.key).size(), self.b.size())

    def test_a_shorter_file_is_refused(self):
        self.write(self.a, 1)
        self.write(self.b, 2)
        data = self.b.entries_path.read_bytes()
        self.b.entries_path.write_bytes(data[:data.rindex(b"\n", 0, len(data) - 1) + 1])
        with self.assertRaisesRegex(LedgerError, "changed by another writer; reopen"):
            self.write(self.b, 3)

    def test_a_partial_line_is_refused(self):
        self.write(self.a, 1)
        with self.b.entries_path.open("ab") as fh:
            fh.write(b"half a record")
        with self.assertRaisesRegex(LedgerError, "changed by another writer; reopen"):
            self.write(self.b, 2)

    def test_a_forged_line_is_refused(self):
        self.write(self.a, 1)
        lines = self.a.entries_path.read_bytes().splitlines(keepends=True)
        with self.a.entries_path.open("ab") as fh:
            fh.write(lines[-1])                     # a replayed record: the chain does not continue
        with self.assertRaises(LedgerError):
            self.write(self.b, 2)

    def test_one_hold_writes_the_entries_and_their_checkpoint(self):
        """Run 9y, S6c: the other process waits for the checkpoint instead of reading entries it does not cover."""
        done = []

        def other():
            self.write(self.b, 3)
            done.append(self.b.size())

        with self.a.exclusive():
            self.a.append("note", {"n": 1})
            self.a.append("note", {"n": 2})
            worker = threading.Thread(target=other)
            worker.start()
            worker.join(0.3)
            self.assertTrue(worker.is_alive(), "the other writer did not wait for the lock")
            self.a.checkpoint()
        worker.join(10)
        self.assertEqual(done, [4])
        self.assertEqual(Ledger(self.path, self.key).size(), 4)

    def test_record_is_an_entry_and_its_checkpoint(self):
        self.a.record("note", {"n": 1})
        self.write(self.b, 2)
        self.assertEqual([e.body.get("n") for e in self.b.entries], [None, 1, 2])

    def test_the_hold_is_reentrant_and_released_once(self):
        with self.a.exclusive():
            with self.a.exclusive():
                self.a.append("note", {"n": 1})
            self.a.checkpoint()
        self.write(self.b, 2)                       # b gets the lock: nothing is left held
        self.assertEqual(self.b.size(), 3)

    def test_entries_the_head_does_not_cover_are_refused(self):
        self.a.append("note", {"n": 1})             # appended, then a crash before the checkpoint
        with self.assertRaisesRegex(LedgerError, "signed head does not match the chain"):
            self.write(self.b, 2)


if __name__ == "__main__":
    unittest.main()
