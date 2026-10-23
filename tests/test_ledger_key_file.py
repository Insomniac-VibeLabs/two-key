# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The ledger key and the wrapped data key are created with O_EXCL at 0600 and checked on read."""

import tempfile
import unittest
from pathlib import Path

from two_key.keys import generate_private_key
from two_key.ledger import Ledger, LedgerError
from perm import chmod, private


class LedgerKeyFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ledger_dir = self.root / "ledger"
        self.key = generate_private_key()

    def open(self):
        return Ledger(self.ledger_dir, self.key)

    def test_created_0600_in_a_0700_directory_and_reused(self):
        led = self.open()
        path = led.ledger_key_path
        self.assertTrue(private(path))
        self.assertTrue(private(path.parent))
        self.assertTrue(private(led.wrap_path))
        first = path.read_bytes()
        led.append("note", {"n": 1})
        led.checkpoint()
        self.open()
        self.assertEqual(path.read_bytes(), first, "an existing ledger key is read, never regenerated")

    def test_no_temporary_keywrap_left_behind(self):
        self.open()
        self.assertEqual(sorted(p.name for p in self.ledger_dir.iterdir() if p.name.startswith(".keywrap")), [])

    def test_group_readable_ledger_key_is_refused(self):
        led = self.open()
        chmod(led.ledger_key_path, 0o640)
        with self.assertRaisesRegex(LedgerError, "ledger_key_insecure"):
            self.open()

    def test_symlinked_ledger_key_is_refused(self):
        key_dir = self.root / "ledger.ledger-key"
        key_dir.mkdir(mode=0o700)
        target = self.root / "elsewhere"
        target.write_bytes(b"x" * 32)
        chmod(target, 0o600)
        (key_dir / "ledger.key").symlink_to(target)
        with self.assertRaisesRegex(LedgerError, "ledger_key_unreadable"):
            self.open()

    def test_dangling_symlink_is_not_followed_on_create(self):
        key_dir = self.root / "ledger.ledger-key"
        key_dir.mkdir(mode=0o700)
        target = self.root / "planted"
        (key_dir / "ledger.key").symlink_to(target)
        with self.assertRaises(LedgerError):
            self.open()
        self.assertFalse(target.exists(), "a planted symlink must not receive the key")

    def test_wrong_length_ledger_key_is_refused(self):
        led = self.open()
        chmod(led.ledger_key_path, 0o600)
        with open(led.ledger_key_path, "ab") as fh:
            fh.write(b"x")
        with self.assertRaisesRegex(LedgerError, "ledger_key_unreadable"):
            self.open()

    def test_symlinked_keywrap_is_refused(self):
        led = self.open()
        real = self.root / "wrap-copy.json"
        real.write_bytes(led.wrap_path.read_bytes())
        led.wrap_path.unlink()
        led.wrap_path.symlink_to(real)
        with self.assertRaisesRegex(LedgerError, "ledger key file"):
            self.open()


if __name__ == "__main__":
    unittest.main()
