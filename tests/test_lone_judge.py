# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""A start-up warning when one judge can approve a call alone while the others are down (live run 6x, X03).

With two judges, required_yes 1 and min_responding unset (so 1), judge A's yes passed with judge B on a dead
port. That is what the policy says, and it may be meant; the warning makes sure it is not an accident.
"""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy, lone_judge_warning
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["lookup"]}]
SPECS = {"lookup": {"irreversible": False, "data_class_floor": "public"}}
TWO = [FixedJudge("a", "yes", provider="p0", maker="m0"), FixedJudge("b", "abstain", provider="p1", maker="m1")]


class LoneJudge(unittest.TestCase):
    def test_when_it_warns(self):
        cases = ((TWO, QuorumPolicy(required_yes=1), True),
                 (TWO, QuorumPolicy(required_yes=1, min_responding=1), True),
                 (TWO, QuorumPolicy(required_yes=1, min_responding=2), False),
                 (TWO, QuorumPolicy(required_yes=2), False),
                 (TWO, QuorumPolicy(), False),                       # default: min(2, judges) = 2
                 (TWO[:1], QuorumPolicy(required_yes=1), False))     # one judge is the whole of Path B
        for judges, policy, warns in cases:
            with self.subTest(judges=len(judges), policy=policy.to_record()):
                got = lone_judge_warning(judges, policy.resolved(len(judges)))
                self.assertEqual(got is not None, warns)
        text = lone_judge_warning(TWO, QuorumPolicy(required_yes=1).resolved(2))
        self.assertIn("one judge approves a call alone", text)
        self.assertIn("min_responding: 2", text)

    def test_start_prints_it_and_the_call_still_passes(self):
        key = generate_private_key()
        con = verify_signed(sign_constitution("p", RULES, key, SPECS), key.public_key())
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(err):
            tk = TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), con, TWO, private_key=key,
                        quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)
            d = tk.authorize({"tool": "lookup", "data_class": "public"}, {}, "look up")
        self.assertIn("two-key: WARNING: quorum: required_yes 1 with 2 judges and min_responding 1", err.getvalue())
        self.assertTrue(d.allowed, d.reason)            # a warning, not a refusal
        self.assertEqual((d.path_b["yes"], d.path_b["abstain"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
