# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Fix 11: payload paths may not overlap field paths; dropped keys are logged by name, never by value."""

import json
import tempfile
import unittest
from pathlib import Path

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import dropped_keys
from two_key.gateway import ToolGateway
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.policy_vm import ConstitutionError
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["pay"]}]


def spec(payload):
    return {"pay": {"irreversible": False, "data_class_floor": "public",
                    "amount": {"json_path": "meta.amt", "unit": "usd", "currency_path": "cur"},
                    "counterparties": [{"json_path": "to.name", "allow": ["ada"]}],
                    "payload": payload}}


class Overlap(unittest.TestCase):
    def test_overlapping_payload_paths_are_refused(self):
        key = generate_private_key()
        for path in ("meta", "meta.amt", "meta.amt.x", "to", "to.name", "to.name.first", "cur", "cur.code"):
            with self.assertRaisesRegex(ConstitutionError, "overlaps the field path|duplicate path"):
                sign_constitution("p", RULES, key, spec([{"json_path": path}]))
        env = sign_constitution("p", RULES, key, spec([{"json_path": "memo"}, {"json_path": "meta2"},
                                                         {"json_path": "to_name"}]))
        self.assertTrue(verify_signed(env, key.public_key()).tool_specs["pay"]["payload"])

    def test_overlap_check_ignores_case(self):
        key = generate_private_key()
        for path in ("TO.name", "To", "to.NAME.first", "META", "Meta.Amt", "CUR", "Cur.code"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ConstitutionError, "overlaps the field path"):
                    sign_constitution("p", RULES, key, spec([{"json_path": path}]))

    def test_a_signed_case_variant_overlap_does_not_load(self):
        from two_key.canonical import canonical_bytes
        from two_key.keys import sign
        key = generate_private_key()
        env = sign_constitution("p", RULES, key, spec([{"json_path": "memo"}]))
        env["signed"]["tool_specs"]["pay"]["payload"] = [{"json_path": "TO.name", "shape": None, "max_length": None}]
        env["signature"] = sign(key, canonical_bytes(env["signed"]))
        with self.assertRaisesRegex(ConstitutionError, "overlaps the field path"):
            verify_signed(env, key.public_key())

    def test_a_signed_overlap_does_not_load(self):
        from two_key.canonical import canonical_bytes
        from two_key.keys import sign
        key = generate_private_key()
        env = sign_constitution("p", RULES, key, spec([{"json_path": "memo"}]))
        env["signed"]["tool_specs"]["pay"]["payload"] = [{"json_path": "to", "shape": None, "max_length": None}]
        env["signature"] = sign(key, canonical_bytes(env["signed"]))
        with self.assertRaises(ConstitutionError):
            verify_signed(env, key.public_key())


class DroppedKeys(unittest.TestCase):
    def test_names_only(self):
        s = spec([{"json_path": "memo"}])["pay"]
        args = {"meta": {"amt": 5, "secret_note": "VALUE-1"}, "cur": "usd", "to": {"name": "ada", "x": "VALUE-2"},
                "memo": {"deep": "kept"}, "extra": "VALUE-3", "to2": ["VALUE-4"]}
        self.assertEqual(dropped_keys(s, args), ["extra", "meta.secret_note", "to.x", "to2"])

    def test_ledger_has_names_not_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            env = sign_constitution("p", RULES, key, spec([{"json_path": "memo"}]))
            tk = TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                        [FixedJudge("a", "yes")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                        allow_test_doubles=True, monitored_agent=TEST_AGENT)
            args = {"meta": {"amt": 5}, "cur": "usd", "to": {"name": "ada"}, "memo": "m", "hidden": "SECRET-VALUE"}
            d = tk.authorize({"tool": "pay", "data_class": "public", "irreversible": False}, args, "pay")
            self.assertTrue(d.allowed, d.reason)
            seen = []
            gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled, tools={"pay": seen.append})
            self.assertTrue(gw.invoke(d.token, "pay", args).allowed)
            self.assertNotIn("hidden", seen[0])
            bodies = {e.kind: e.body for e in tk.ledger.entries}
            self.assertEqual(bodies["action_normalized"]["dropped_keys"], ["hidden"])
            self.assertEqual(bodies["redemption_started"]["dropped_keys"], ["hidden"])
            ledger_text = json.dumps([e.body for e in tk.ledger.entries if e.kind != "proposal"])
            self.assertNotIn("SECRET-VALUE", ledger_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
