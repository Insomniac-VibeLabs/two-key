"""Ledger at rest is encrypted in both modes. A missing key fails closed."""

import json
import tempfile
import unittest
from pathlib import Path

from two_key import keys
from two_key.ledger import LedgerError, PersonalLedger


class EncryptedLedger(unittest.TestCase):
    def test_file_is_ciphertext_and_wrong_key_fails(self):
        key = keys.generate_private_key()
        other = keys.generate_private_key()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "l.jsonl"
            led = PersonalLedger(path, signing_key=key)
            led.append("event", {"tool": "pay_bill", "secret": "do-not-store-in-clear"})
            raw = path.read_text()
            self.assertNotIn("pay_bill", raw)
            self.assertNotIn("do-not-store-in-clear", raw)
            self.assertEqual(PersonalLedger(path, signing_key=key).verify(key.public_key()).reason, "ok")
            with self.assertRaises(LedgerError):
                PersonalLedger(path)
            with self.assertRaises(LedgerError):
                PersonalLedger(path, signing_key=other)
            blob = json.loads((Path(str(path) + ".key.json")).read_text())
            self.assertEqual(blob["format"], "two-key-ledger-wrap/1")
