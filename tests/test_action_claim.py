# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""B-1: the raw action claim is size-capped, the tool name is an identifier, and reasons carry no values."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from two_key.action import MAX_TOOL_NAME_CHARS, ActionValidationError, normalize_action
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import MAX_ACTION_BYTES
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}
BIG = "A" * (1 << 20)


class Claim(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, key, SPECS)
        self.tk = TwoKey(Ledger(Path(self.tmp.name) / "ledger", key), key.public_key(),
                         verify_signed(env, key.public_key()), [FixedJudge("a", "yes")], private_key=key,
                         quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)

    def ledger_text(self):
        return json.dumps([e.body for e in self.tk.ledger.entries])

    def deny(self, action):
        err = io.StringIO()
        with redirect_stderr(err):
            d = self.tk.authorize(action, {}, "look it up")
        self.assertFalse(d.allowed)
        self.assertNotIn("AAAA", d.reason)
        self.assertNotIn("AAAA", err.getvalue())
        self.assertNotIn("AAAA", self.ledger_text())
        self.assertLess(len(self.ledger_text()), 64 * 1024)
        return d

    def test_huge_tool_name(self):
        d = self.deny({**SEARCH, "tool": BIG})
        self.assertEqual(d.reason, "action_too_large")
        body = self.tk.ledger.entries[-1].body
        self.assertTrue(body["action_omitted"])
        self.assertGreater(body["action_size"], MAX_ACTION_BYTES)
        self.assertTrue(body["action_digest"].startswith("sha256:"))

    def test_huge_data_class_and_unknown_key(self):
        self.assertEqual(self.deny({**SEARCH, "data_class": BIG}).reason, "action_too_large")
        self.assertEqual(self.deny({**SEARCH, BIG: 1}).reason, "action_too_large")

    def test_small_bad_values_name_the_field_only(self):
        d = self.deny({**SEARCH, "data_class": "AAAA-secret"})
        self.assertEqual(d.reason, "malformed_action:data_class: not a known class")
        d = self.deny({**SEARCH, "AAAA_field": 1, "AAAA_other": 2})
        self.assertEqual(d.reason, "malformed_action:unknown action fields (2)")

    def test_tool_name_length_and_pattern(self):
        self.assertEqual(normalize_action({"tool": "a" * MAX_TOOL_NAME_CHARS}).tool, "a" * MAX_TOOL_NAME_CHARS)
        for bad, why in (("a" * (MAX_TOOL_NAME_CHARS + 1), "longer than 128"), ("pay bill", "not an identifier"),
                         ("pay\nbill", "not an identifier"), ("-x", "not an identifier"), ("tool\u200b", "not an identifier")):
            with self.assertRaisesRegex(ActionValidationError, "^tool: " + why, msg=repr(bad)):
                normalize_action({"tool": bad})
        for good in ("search", "pay_bill", "mcp.server:tool", "fs/read-file", "Email_Draft"):
            normalize_action({"tool": good})
        d = self.deny({**SEARCH, "tool": "AAAA" + " x" * 10})
        self.assertEqual(d.reason, "malformed_action:tool: not an identifier (a-z, 0-9, and _ . : / -)")

    def test_normal_claim_still_allowed(self):
        self.assertTrue(self.tk.authorize(SEARCH, {}, "look it up").allowed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
