# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Arguments nested too deeply to walk are a deny, never a RecursionError reaching the caller."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from two_key import derive as derive_mod
from two_key.canonical import EncodingError, canonical_bytes
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import DeriveError, derive
from two_key.gateway import ToolGateway
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["pay"]}]
SPECS = {"pay": {"irreversible": False, "data_class_floor": "public", "amount": {"json_path": "amount", "unit": "usd"},
                 "counterparties": [{"json_path": "to", "allow": ["bob"]}], "payload": [{"json_path": "memo"}]}}
PAY = {"tool": "pay", "amount_usd": 1, "data_class": "public", "irreversible": False}


def nest(n):
    v = 1
    for _ in range(n):
        v = {"x": v}
    return v


class DeepArgs(unittest.TestCase):
    def setUp(self):
        key = generate_private_key()
        env = sign_constitution("Paying bob is fine.", RULES, key, SPECS)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                         [FixedJudge("a", "yes")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                         allow_test_doubles=True, monitored_agent=TEST_AGENT)

    def test_canonical_encoding_raises_encoding_error(self):
        with self.assertRaisesRegex(EncodingError, "^value is nested too deeply$"):
            canonical_bytes(nest(5000))
        with self.assertRaisesRegex(EncodingError, "^tool args are nested too deeply$"):
            canonical_bytes(nest(5000), what="tool args are")

    def test_authorize_denies(self):
        d = self.tk.authorize(PAY, {"amount": 1, "to": "bob", "memo": nest(5000)}, "pay bob")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "invalid_call:tool args are nested too deeply")
        body = self.tk.ledger.entries[-1].body
        self.assertTrue(body.get("tool_args_omitted"))
        self.assertEqual(body.get("tool_args_error"), "tool args are nested too deeply")

    def test_shallow_nesting_still_allowed(self):
        self.assertTrue(self.tk.authorize(PAY, {"amount": 1, "to": "bob", "memo": nest(50)}, "pay bob").allowed)

    def test_derive_recursion_error_is_a_derive_error(self):
        with mock.patch.object(derive_mod, "_derive", side_effect=RecursionError):
            with self.assertRaisesRegex(DeriveError, "value_unreadable:RecursionError"):
                derive(SPECS["pay"], {"amount": 1, "to": "bob"})

    def test_derive_recursion_in_authorize_is_a_derive_deny(self):
        with mock.patch("two_key.core.derive", side_effect=DeriveError("value_unreadable:RecursionError")):
            d = self.tk.authorize(PAY, {"amount": 1, "to": "bob"}, "pay bob")
        self.assertEqual(d.reason, "derive_failed:value_unreadable:RecursionError")

    def test_gateway_denies_deep_args_instead_of_raising(self):
        d = self.tk.authorize(PAY, {"amount": 1, "to": "bob"}, "pay bob")
        self.assertTrue(d.allowed)
        gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled, tools={"pay": lambda a: "paid"})
        r = gw.invoke(d.token, "pay", {"amount": 1, "to": "bob", "memo": nest(5000)})
        self.assertFalse(r.allowed)
        self.assertEqual(r.reason, "invalid_call:tool args are nested too deeply")


if __name__ == "__main__":
    unittest.main(verbosity=2)
