# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Files written by the two-key-concept repository (before 0.4.0) are refused with a clear message.

0.4.0 renamed every format identifier from "two-key-concept-..." to "two-key-...". Old constitutions,
ledgers, head anchors, and key backups are not read; each says what made it and what to do.
"""

import json
import tempfile
import unittest
from pathlib import Path

from two_key import backup
from two_key.backup import BackupError
from two_key.constitution import ConstitutionSignatureError, sign_constitution, verify_signed
from two_key.keys import generate_private_key
from two_key.ledger import Ledger, LedgerError

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}


def _set_format(path: Path, fmt: str) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    data["format"] = fmt
    path.write_text(json.dumps(data), encoding="utf-8")


class NewNames(unittest.TestCase):
    def test_no_identifier_keeps_the_concept_prefix(self):
        from two_key import constitution, ledger
        names = [constitution.FORMAT_V1, constitution.FORMAT_V2, ledger.WRAP_FORMAT, ledger.RECORD_FORMAT,
                 ledger.ANCHOR_FORMAT, ledger.WITNESS_ROTATION_FORMAT, backup.FORMAT, backup.PAYLOAD_FORMAT]
        for name in names:
            self.assertTrue(name.startswith("two-key-"), name)
            self.assertNotIn("concept", name)


class LegacyFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = generate_private_key()

    def test_concept_constitution_is_refused_with_advice(self):
        env = sign_constitution("Searching is fine.", RULES, self.key, SPECS)
        env["format"] = "two-key-concept-constitution-v1"
        with self.assertRaisesRegex(ConstitutionSignatureError, "two-key-concept.*re-sign"):
            verify_signed(env, self.key.public_key())

    def _ledger(self):
        path = Path(self.tmp.name, "ledger")
        led = Ledger(path, self.key)
        led.append("note", {"x": 1})
        led.checkpoint()
        return path, led

    def test_concept_ledger_key_wrap_is_refused_with_advice(self):
        path, led = self._ledger()
        _set_format(led.path / "keywrap.json", "two-key-concept-ledger-wrap/1")
        with self.assertRaisesRegex(LedgerError, "two-key-concept.*start a new ledger"):
            Ledger(path, self.key)

    def test_concept_head_anchor_is_refused_with_advice(self):
        path, led = self._ledger()
        _set_format(led.ledger_key_path.parent / "head.anchor", "two-key-concept-head-anchor/1")
        with self.assertRaisesRegex(LedgerError, "two-key-concept.*start a new ledger"):
            Ledger(path, self.key)

    def test_concept_backup_bundle_is_refused_with_advice(self):
        payload = {"format": backup.PAYLOAD_FORMAT, "version": backup.BACKUP_VERSION, "role": "witness"}
        bundle = json.loads(backup._encrypt("witness", payload, "a long test passphrase", backup.MIN_ITERATIONS))
        bundle["format"] = "two-key-concept-key-backup/1"
        with self.assertRaisesRegex(BackupError, "two-key-concept.*new backup"):
            backup._decrypt(json.dumps(bundle).encode("ascii"), "a long test passphrase", "witness")


if __name__ == "__main__":
    unittest.main()
