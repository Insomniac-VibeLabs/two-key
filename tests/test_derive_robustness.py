# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Fix 10: an unreadable value is a derive_failed deny, and any exception in authorize is a ledgered deny."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import DeriveError, derive
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["pay"]}]
SPECS = {"pay": {"irreversible": False, "data_class_floor": "public",
                 "amount": {"json_path": "amt", "unit": "usd"},
                 "counterparties": [{"json_path": "to", "allow": ["ada"]}]}}
CENTS = {"pay": dict(SPECS["pay"], amount={"json_path": "amt", "unit": "cents"})}
PAY = {"tool": "pay", "data_class": "public", "irreversible": False}


def engine(tmp, specs=None):
    specs = SPECS if specs is None else specs
    key = generate_private_key()
    env = sign_constitution("Pay ada small amounts.", RULES, key, specs)
    return TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                  [FixedJudge("a", "yes")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                  allow_test_doubles=True, monitored_agent=TEST_AGENT)


class Unreadable(unittest.TestCase):
    def test_derive_raises_only_derive_error(self):
        for value in (10**400, -(10**400), float("nan"), float("inf"), 1e308):
            for spec in (SPECS["pay"], CENTS["pay"]):
                with self.assertRaises(DeriveError):
                    derive(spec, {"amt": value, "to": "ada"})

    def test_huge_amount_is_a_derive_failed_deny(self):
        for specs in (SPECS, CENTS):
            with tempfile.TemporaryDirectory() as tmp:
                tk = engine(tmp, specs)
                d = tk.authorize(PAY, {"amt": 10**400, "to": "ada"}, "x")
                self.assertFalse(d.allowed)
                self.assertEqual(d.reason, "derive_failed:amount_unreadable")   # the reason CHANGES.md gives
                self.assertEqual([e.kind for e in tk.ledger.entries][-1], "decision")

    def test_huge_claimed_amount_is_a_malformed_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(tmp)
            d = tk.authorize(dict(PAY, amount_usd=10**400), {"amt": 1, "to": "ada"}, "x")
            self.assertFalse(d.allowed)
            self.assertTrue(d.reason.startswith("malformed_action:"), d.reason)

    def test_any_exception_in_authorize_is_a_ledgered_deny(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(tmp)
            with patch("two_key.core.convene", side_effect=RuntimeError("boom")):
                d = tk.authorize(PAY, {"amt": 1, "to": "ada"}, "x", agent_id="ag")
            self.assertFalse(d.allowed)
            self.assertIsNone(d.token)
            self.assertEqual(d.reason, "internal_error:RuntimeError")
            last = tk.ledger.entries[-1]
            self.assertEqual((last.kind, last.body["reason"], last.body["agent"]["id"]),
                             ("decision", "internal_error:RuntimeError", "ag"))
            tk.ledger.verify()
            self.assertTrue(tk.authorize(PAY, {"amt": 1, "to": "ada"}, "x").allowed)

    def test_deny_that_cannot_be_ledgered_is_still_a_deny_and_reported(self):
        import io
        from contextlib import redirect_stderr
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(tmp)
            err = io.StringIO()
            with patch("two_key.core.convene", side_effect=RuntimeError("boom")), \
                 patch.object(tk.ledger, "append", side_effect=OSError("disk full")), redirect_stderr(err):
                d = tk.authorize(PAY, {"amt": 1, "to": "ada"}, "x")
            self.assertFalse(d.allowed)
            self.assertIsNone(d.token)
            self.assertEqual(d.reason, "ledger_failed:OSError")
            self.assertIn("two-key: could not record deny decision", err.getvalue())

    def test_ledger_error_reason_carries_its_message(self):
        import io
        from contextlib import redirect_stderr
        from two_key.ledger import LedgerError
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(tmp)
            with patch("two_key.core.convene", side_effect=RuntimeError("boom")), \
                 patch.object(tk.ledger, "append", side_effect=LedgerError("ledger file changed")), \
                 redirect_stderr(io.StringIO()):
                d = tk.authorize(PAY, {"amt": 1, "to": "ada"}, "x")
            self.assertEqual(d.reason, "ledger_failed:ledger file changed")

    def test_huge_ledger_error_reason_is_capped(self):
        """#21: core _deny ledger_failed message is capped."""
        import io
        from contextlib import redirect_stderr
        from two_key.agent_meta import MAX_LEDGER_ERROR_CHARS
        from two_key.ledger import LedgerError
        mark = "ZQXLED"
        huge = mark + "L" * (5 << 20)
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(tmp)
            with patch("two_key.core.convene", side_effect=RuntimeError("boom")), \
                 patch.object(tk.ledger, "append", side_effect=LedgerError(huge)), \
                 redirect_stderr(io.StringIO()):
                d = tk.authorize(PAY, {"amt": 1, "to": "ada"}, "x")
            self.assertTrue(d.reason.startswith("ledger_failed:"), d.reason)
            self.assertIn(mark, d.reason)
            self.assertIn("…sha256:", d.reason)
            self.assertLess(len(d.reason), len("ledger_failed:") + MAX_LEDGER_ERROR_CHARS + 80)
            self.assertNotIn("L" * 1000, d.reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
