# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""two_key.audit recomputes identities_digest and policy_digest and catches a decision that does not match."""

import tempfile
import unittest
from pathlib import Path

from two_key.audit import check_decision_digests, identities_digest, policy_digest
from two_key.canonical import canonical_hash
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


class Audit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = generate_private_key()
        self.path = Path(self.tmp.name, "ledger")
        self.tk = self.engine(QuorumPolicy(required_yes=1))

    def engine(self, policy):
        env = sign_constitution("Searching is fine.", RULES, self.key, SPECS)
        return TwoKey(Ledger(self.path, self.key), self.key.public_key(), verify_signed(env, self.key.public_key()),
                      [FixedJudge("a", "yes")], private_key=self.key, quorum=policy, allow_test_doubles=True,
                      monitored_agent=TEST_AGENT)

    def test_clean_ledger_has_no_problems(self):
        self.tk.authorize(SEARCH, {"q": "x"}, "look")
        self.tk.authorize({"tool": "nope"}, {}, "x")
        self.assertEqual(check_decision_digests(self.tk.ledger), [])

    def test_recipe_matches_the_helpers(self):
        loaded = [e.body for e in self.tk.ledger.entries if e.kind == "constitution_loaded"][-1]
        sep = loaded["judge_agent_separation"]
        self.assertEqual(identities_digest(sep), canonical_hash({"agents": sep["agents"], "judges": sep["judges"]}))
        self.assertEqual(policy_digest(loaded["quorum_policy"]), loaded["policy_digest"])

    def test_a_reload_with_a_new_policy_is_tracked(self):
        self.tk.authorize(SEARCH, {"q": "x"}, "look")
        tk2 = self.engine(QuorumPolicy(required_yes=1, tool_args_on_derive_deny=True))
        tk2.authorize(SEARCH, {"q": "x"}, "look")
        self.assertEqual(check_decision_digests(tk2.ledger), [])
        digests = {e.body["policy_digest"] for e in tk2.ledger.entries if e.kind == "decision"}
        self.assertEqual(len(digests), 2)

    def test_mismatched_decision_is_reported(self):
        self.tk.ledger.append("decision", {"allowed": False, "reason": "x", "policy_digest": "0" * 64,
                                           "identities_digest": "f" * 64})
        problems = check_decision_digests(self.tk.ledger)
        self.assertEqual(len(problems), 2)
        self.assertIn("policy_digest", problems[0] + problems[1])
        self.assertIn("identities_digest", problems[0] + problems[1])


if __name__ == "__main__":
    unittest.main()
