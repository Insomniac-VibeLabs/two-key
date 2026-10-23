# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""save_envelope (sign-constitution --out) writes a new file and renames it over the target (0.6.0): a reader
never sees half a constitution, and a link at the target is replaced, not written through."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from two_key.constitution import load_envelope, save_envelope, sign_constitution, verify_signed
from two_key.keys import generate_private_key

from test_cli_tokens import PROSE, RULES, SPECS


class SaveEnvelope(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.key = generate_private_key()
        self.envelope = sign_constitution(PROSE, RULES, self.key, SPECS)

    def test_writes_then_replaces_and_leaves_no_temporary_file(self):
        out = self.dir / "c.json"
        save_envelope(out, {"old": True})
        save_envelope(out, self.envelope)
        verify_signed(load_envelope(out), self.key.public_key())
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["c.json"])
        self.assertTrue(out.read_bytes().endswith(b"}\n"))
        self.assertNotIn(b"\r\n", out.read_bytes())

    def test_a_link_at_the_target_is_replaced_not_written_through(self):
        elsewhere = self.dir / "elsewhere.txt"
        elsewhere.write_text("not a constitution\n", encoding="utf-8", newline="\n")
        out = self.dir / "c.json"
        try:
            os.symlink(elsewhere, out)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create a symlink here")
        save_envelope(out, self.envelope)
        self.assertFalse(out.is_symlink())
        self.assertEqual(elsewhere.read_text(encoding="utf-8"), "not a constitution\n")
        verify_signed(load_envelope(out), self.key.public_key())

    def test_a_failed_write_keeps_the_old_file_and_removes_the_temporary_one(self):
        out = self.dir / "c.json"
        save_envelope(out, self.envelope)
        before = out.read_bytes()
        with mock.patch("two_key.constitution._platform.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                save_envelope(out, {"new": True})
        self.assertEqual(out.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["c.json"])


if __name__ == "__main__":
    unittest.main()
