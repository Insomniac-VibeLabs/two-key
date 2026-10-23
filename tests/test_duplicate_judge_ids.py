# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Regression: a local 'a' voting no plus a cloud 'a' voting yes was quorum_pass (ballots keyed by id)."""

import tempfile
import unittest
from pathlib import Path

from two_key.action import normalize_action
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.judges.config import JudgeConfigError, load_config
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy, convene
from two_key.testing import TEST_AGENT, FixedJudge

A = normalize_action({"tool": "pay"})


def dup():
    return [FixedJudge("a", "no", provider="l", maker="local", local_weights=True),
            FixedJudge("a", "yes", provider="c1", maker="v1"),
            FixedJudge("c", "yes", provider="c2", maker="v2")]


class DuplicateJudgeIds(unittest.TestCase):
    def test_convene_denies_without_calling_judges(self):
        for policy in (QuorumPolicy(), QuorumPolicy.high_assurance()):
            q = convene(dup(), "c", A, "p", policy)
            self.assertFalse(q.passed)
            self.assertEqual(q.reason, "duplicate_judge_id")
            self.assertEqual(q.ballots, ())

    def test_twokey_refuses_to_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            env = sign_constitution("c", [{"id": "t", "allow_only_tools": ["search"]}], key,
                                    {"search": {"irreversible": False, "data_class_floor": "public"}})
            for judges in (dup(), [FixedJudge("", "yes")]):
                with self.assertRaises(TwoKeyConfigError) as raised:
                    TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()), judges,
                           private_key=key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)
                self.assertTrue(str(raised.exception).startswith("duplicate_judge_id:"))

    def test_config_loader_refuses(self):
        j = {"id": "a", "type": "ollama", "model": "m"}
        with self.assertRaises(JudgeConfigError) as raised:
            load_config({"judges": [j, dict(j)]})
        self.assertTrue(str(raised.exception).startswith("duplicate_judge_id:"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
