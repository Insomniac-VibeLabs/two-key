# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Re-review: required_yes defaults to None and resolves to min(2, n) in TwoKey and the loader,
so one judge plus a timeout starts. parallel stays True."""

import tempfile
import unittest
from pathlib import Path

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.judges.config import load_config
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}
J1 = [{"id": "a", "type": "ollama", "model": "llama3"}]


class RequiredYesDefault(unittest.TestCase):
    def test_dataclass_default_is_none_and_resolves(self):
        p = QuorumPolicy()
        self.assertIsNone(p.required_yes)
        self.assertTrue(p.parallel)
        self.assertEqual([p.resolved(n).required_yes for n in (1, 2, 5)], [1, 2, 2])
        self.assertEqual(QuorumPolicy(required_yes=3).resolved(5).required_yes, 3)

    def test_loader_one_judge_with_timeout(self):
        _, policy = load_config({"judges": J1, "quorum": {"timeout_seconds": 30}})
        self.assertEqual((policy.required_yes, policy.timeout_seconds, policy.parallel), (1, 30, True))
        _, policy = load_config({"judges": J1 + [{"id": "b", "type": "ollama", "model": "qwen2.5:7b"}],
                                 "quorum": {"timeout_seconds": 30}})
        self.assertEqual(policy.required_yes, 2)

    def test_twokey_one_judge_with_timeout(self):
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, key, SPECS)
        with tempfile.TemporaryDirectory() as tmp:
            tk = TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                        [FixedJudge("a", "yes", provider="p")], private_key=key,
                        quorum=QuorumPolicy(timeout_seconds=30), allow_test_doubles=True, monitored_agent=TEST_AGENT)
            self.assertEqual(tk.quorum.required_yes, 1)
            d = tk.authorize({"tool": "search", "data_class": "public", "irreversible": False}, {}, "s")
            self.assertTrue(d.allowed, d.reason)
            loaded = [e for e in tk.ledger.entries if e.kind == "constitution_loaded"][-1].body
            self.assertEqual(loaded["quorum_policy"]["required_yes"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
