# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Only the tool's name is required in a tool spec.

``irreversible`` left out is true and ``data_class_floor`` left out is
``classified``: the fail-closed defaults. They are written into the signed
spec, so a spec that leaves them out signs exactly as one that writes them.
"""

import tempfile
import unittest
from pathlib import Path

from two_key.canonical import canonical_bytes
from two_key.constitution import ConstitutionError, sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

PROSE = "Only summarize. Nothing that cannot be undone."
TOOLS = {"id": "tools", "allow_only_tools": ["summarize"]}
CALL = {"tool": "summarize", "amount_usd": 0}
ARGS = {"text": "hello"}


def _sign(specs, rules=None):
    key = generate_private_key()
    return key, sign_constitution(PROSE, rules or [TOOLS], key, specs)


def _engine(tmp, specs, rules=None):
    key, env = _sign(specs, rules)
    judges = [FixedJudge("j0", "yes", provider="p0", maker="v0", local_weights=True)]
    return TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                  judges, private_key=key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                  monitored_agent=TEST_AGENT)


class OptionalToolSpecFieldsTests(unittest.TestCase):
    def test_an_empty_spec_signs_with_the_defaults(self):
        _, env = _sign({"summarize": {}})
        spec = env["signed"]["tool_specs"]["summarize"]
        self.assertIs(spec["irreversible"], True)
        self.assertEqual(spec["data_class_floor"], "classified")

    def test_left_out_signs_as_written_out(self):
        _, left_out = _sign({"summarize": {}})
        _, written = _sign({"summarize": {"irreversible": True, "data_class_floor": "classified"}})
        self.assertEqual(canonical_bytes(left_out["signed"]), canonical_bytes(written["signed"]))

    def test_a_wrong_type_still_does_not_sign(self):
        for spec in ({"irreversible": "no"}, {"irreversible": None}, {"data_class_floor": "secret"},
                     {"data_class_floor": None}):
            with self.subTest(spec=spec), self.assertRaises(ConstitutionError):
                _sign({"summarize": spec})

    def test_left_out_irreversible_is_irreversible(self):
        rules = [TOOLS, {"id": "no-irreversible", "deny_if": {"irreversible": True}}]
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp, {"summarize": {"data_class_floor": "public"}}, rules)
            denied = tk.authorize(dict(CALL, data_class="public"), ARGS, "summarize")
            understated = tk.authorize(dict(CALL, data_class="public", irreversible=False), ARGS, "summarize")
            self.assertFalse(denied.allowed)
            self.assertEqual(denied.path_a["denied_by"], "no-irreversible")
            self.assertEqual(understated.reason, "irreversible_mismatch")

    def test_left_out_floor_is_classified(self):
        rules = [TOOLS, {"id": "sensitive", "deny_if": {"data_class_in": ["classified"]}}]
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp, {"summarize": {"irreversible": False}}, rules)
            decision = tk.authorize(dict(CALL, data_class="public", irreversible=False), ARGS, "summarize")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.path_a["denied_by"], "sensitive")

    def test_written_values_still_apply(self):
        rules = [TOOLS, {"id": "no-irreversible", "deny_if": {"irreversible": True}},
                 {"id": "sensitive", "deny_if": {"data_class_in": ["classified"]}}]
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp, {"summarize": {"irreversible": False, "data_class_floor": "public"}}, rules)
            decision = tk.authorize(dict(CALL, data_class="public", irreversible=False), ARGS, "summarize")
            self.assertTrue(decision.allowed, decision.reason)


if __name__ == "__main__":
    unittest.main()
