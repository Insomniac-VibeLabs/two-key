# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The constitution serial (live run 9x, C44): a ledger never goes back to an older constitution.

An older constitution signed with the same key is still validly signed, so the signature cannot tell it from
the current one. The principal's signed ``serial`` can: once a ledger has run serial N, a lower serial, N again
with other rules, and a constitution with no serial all refuse to start, before anything is written.
"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from two_key.constitution import (FORMAT_V1, FORMAT_V3, ConstitutionError, load_serial, sign_constitution,
                                  verify_signed)
from two_key.core import TwoKey, TwoKeyConfigError, check_constitution_order
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

PROSE = "Searching is fine."
RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}
STRICTER = RULES + [{"id": "no-classified", "deny_if": {"data_class_in": ["classified"]}}]


class Signing(unittest.TestCase):
    def setUp(self):
        self.key = generate_private_key()

    def test_no_serial_stays_v1_byte_for_byte(self):
        envelope = sign_constitution(PROSE, RULES, self.key, SPECS)
        self.assertEqual(envelope["format"], FORMAT_V1)
        self.assertNotIn("serial", envelope["signed"])
        self.assertIsNone(verify_signed(envelope, self.key.public_key()).serial)

    def test_a_serial_signs_as_v3_and_is_covered_by_the_signature(self):
        envelope = sign_constitution(PROSE, RULES, self.key, SPECS, serial=3)
        self.assertEqual(envelope["format"], FORMAT_V3)
        self.assertEqual(verify_signed(envelope, self.key.public_key()).serial, 3)
        changed = json.loads(json.dumps(envelope))
        changed["signed"]["serial"] = 4
        with self.assertRaisesRegex(ValueError, "signature failed"):
            verify_signed(changed, self.key.public_key())

    def test_a_serial_is_a_positive_integer(self):
        for bad in (0, -1, True, 1.0, "2"):
            with self.subTest(bad=bad), self.assertRaisesRegex(ConstitutionError, "serial must be a positive"):
                sign_constitution(PROSE, RULES, self.key, SPECS, serial=bad)

    def test_a_serial_cannot_be_signed_as_v2(self):
        with self.assertRaisesRegex(ConstitutionError, "need a v3 constitution"):
            sign_constitution(PROSE, RULES, self.key, SPECS, serial=1, envelope_format="v2")

    def test_a_serial_under_a_v1_or_v2_label_is_refused(self):
        from two_key.constitution import FORMAT_V2
        from two_key.keys import sign
        from two_key.canonical import canonical_bytes
        signed = {"prose": PROSE, "hard_rules": RULES, "tool_specs": SPECS, "serial": 2}
        for fmt in (FORMAT_V1, FORMAT_V2):
            envelope = {"format": fmt, "signed": signed, "signature": sign(self.key, canonical_bytes(signed))}
            with self.subTest(fmt=fmt), self.assertRaisesRegex(ConstitutionError, "serial|unknown signed key"):
                verify_signed(envelope, self.key.public_key())

    def test_the_rules_file_carries_the_serial(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(json.dumps({"serial": 7, "hard_rules": RULES, "tool_specs": SPECS}), encoding="utf-8")
            self.assertEqual(load_serial(path), 7)
            path.write_text(json.dumps({"hard_rules": RULES, "tool_specs": SPECS}), encoding="utf-8")
            self.assertIsNone(load_serial(path))


class Order(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.key = generate_private_key()

    def constitution(self, serial=None, rules=RULES):
        return verify_signed(sign_constitution(PROSE, rules, self.key, SPECS, serial=serial), self.key.public_key())

    def start(self, constitution):
        with contextlib.redirect_stderr(io.StringIO()):
            tk = TwoKey(Ledger(self.dir / "ledger", self.key), self.key.public_key(), constitution,
                        [FixedJudge("a", "yes")], private_key=self.key, quorum=QuorumPolicy(required_yes=1),
                        allow_test_doubles=True, monitored_agent=TEST_AGENT)
        self.addCleanup(tk.close)
        return tk

    def refused(self, constitution, code):
        size = Ledger(self.dir / "ledger", self.key).size()
        with self.assertRaisesRegex(TwoKeyConfigError, f"^{code}:"):
            self.start(constitution)
        self.assertEqual(Ledger(self.dir / "ledger", self.key).size(), size, "a refused start wrote to the ledger")

    def loaded(self):
        return [e.body for e in Ledger(self.dir / "ledger", self.key).entries if e.kind == "constitution_loaded"]

    def test_c44_an_older_serial_is_refused(self):
        self.start(self.constitution(2, STRICTER))
        self.refused(self.constitution(1), "constitution_rollback")

    def test_the_same_serial_with_other_rules_is_refused(self):
        self.start(self.constitution(2, STRICTER))
        self.refused(self.constitution(2), "constitution_serial_reused")

    def test_no_serial_after_a_serial_is_refused(self):
        self.start(self.constitution(2))
        self.refused(self.constitution(None), "constitution_serial_missing")

    def test_the_same_constitution_restarts_and_a_higher_serial_starts(self):
        first = self.constitution(1)
        self.start(first)
        self.start(first)
        newer = self.constitution(2, STRICTER)
        self.start(newer)
        bodies = self.loaded()
        self.assertEqual([b["serial"] for b in bodies], [1, 1, 2])
        self.assertEqual(bodies[-1]["previous_digest"], first.digest)

    def test_a_rollback_is_refused_even_after_restarts_of_the_newer_one(self):
        self.start(self.constitution(1))
        self.start(self.constitution(5, STRICTER))
        self.start(self.constitution(5, STRICTER))
        self.refused(self.constitution(4), "constitution_rollback")
        self.refused(self.constitution(1), "constitution_rollback")

    def test_older_rules_come_back_only_with_a_higher_serial(self):
        self.start(self.constitution(1))
        self.start(self.constitution(2, STRICTER))
        self.start(self.constitution(3))
        self.assertEqual([b["serial"] for b in self.loaded()], [1, 2, 3])

    def test_a_ledger_without_serials_accepts_any_and_records_nothing_new(self):
        self.start(self.constitution(None, STRICTER))
        self.start(self.constitution(None))
        self.assertTrue(all("serial" not in b and "previous_digest" not in b for b in self.loaded()))
        self.start(self.constitution(1))
        self.assertEqual(self.loaded()[-1]["serial"], 1)

    def test_the_check_on_its_own(self):
        with contextlib.redirect_stderr(io.StringIO()):
            empty = Ledger(self.dir / "empty", self.key)
        self.assertIsNone(check_constitution_order(empty, self.constitution(1)))


if __name__ == "__main__":
    unittest.main()
