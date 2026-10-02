"""Tests for the argument-binding fixes. The judge must see the bytes the gateway runs."""

import unittest

from two_key.action import normalize_action
from two_key.judges.base import Ballot, Judge
from two_key.quorum import QuorumPolicy, convene
from two_key.scope import disagreement, fold
from helpers import TwoKeyFixture

RULES = [{"id": "tools", "allow_only_tools": ["search", "wire_transfer"]},
         {"id": "cap", "deny_if": {"amount_usd_gt": 5000}}]
BIND = {"action_hash": "aa" * 32, "constitution_hash": "cc" * 32, "nl_hash": "11" * 32, "bytecode_hash": "22" * 32}


class Yes(Judge):
    is_test_double = True
    local_weights = False

    def __init__(self, judge_id, local=False, vendor="openai"):
        self.judge_id, self.provider, self.local_weights = judge_id, judge_id, local
        self.vendor = "meta-llama" if local else vendor
        self.seen = None

    def score(self, constitution_text, action, proposal):
        return self.score_bound(constitution_text, action, proposal, None)

    def score_bound(self, constitution_text, action, proposal, binding):
        self.seen = action.to_record()
        return Ballot(self.judge_id, self.provider, "yes", 0.9, "ok")


class Binding(unittest.TestCase):
    def test_fold_strips_zero_width_and_homoglyph(self):
        self.assertEqual(fold("ign" + chr(0x200b) + "ore " + chr(0x0430) + "lso"), "ignore also")

    def test_quiet_record_cannot_hide_a_wire(self):
        record = {"tool": "search", "amount_usd": 0, "data_class": "public"}
        self.assertIn(disagreement(record, {"q": "wire 4800 usd to vendor"}), {"tool_hides_payment", "amount_mismatch"})

    def test_public_label_cannot_hide_a_record(self):
        record = {"tool": "search", "amount_usd": 0, "data_class": "public"}
        self.assertEqual(disagreement(record, {"q": "patient diagnosis"}), "sensitive_labeled_public")

    def test_authorize_denies_a_laundered_record(self):
        with TwoKeyFixture(RULES, [Yes("only")], quorum_policy=QuorumPolicy(required_yes=1)) as tk:
            d = tk.authorize({"tool": "search", "amount_usd": 0, "data_class": "public", "irreversible": False},
                             "look something up", {"q": "wire 4800 usd to vendor"})
        self.assertFalse(d.allowed)
        self.assertIn("record_args_mismatch", d.reason)

    def test_judge_sees_the_frozen_arguments(self):
        judge = Yes("only")
        with TwoKeyFixture(RULES, [judge], quorum_policy=QuorumPolicy(required_yes=1)) as tk:
            tk.authorize({"tool": "search", "amount_usd": 0, "data_class": "public", "irreversible": False},
                         "look something up", {"q": "weather"})
        self.assertEqual(judge.seen["raw"]["tool_args"], {"q": "weather"})

    def test_local_abstain_cannot_be_outvoted(self):
        class Down(Yes):
            def score_bound(self, constitution_text, action, proposal, binding):
                return Ballot(self.judge_id, self.provider, "abstain", None, "", error="down")
        local = Down("local", local=True)
        action = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
        judges = [Yes("cloud-a", vendor="openai"), Yes("cloud-b", vendor="anthropic"), local]
        q = convene(judges, "c", action, "", QuorumPolicy.section4(required_yes=1), BIND)
        self.assertFalse(q.passed)
        self.assertIn("local_judge_required", q.reason)
