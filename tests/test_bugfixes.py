"""Regression tests for every defect found in the 2026-09-30 review (REVIEW.md 4.2)."""
import math
import tempfile
import unittest
from pathlib import Path

from two_key.action import ActionValidationError, normalize_action
from two_key.judges.base import Ballot
from two_key.core import TwoKey
from helpers import TwoKeyFixture, signed
from two_key.policy_vm import ConstitutionError, Op, PolicyVM, compile_constitution
from two_key.quorum import QuorumPolicy, convene
from two_key.testing import FixedJudge, HeuristicJudge, RaisingJudge

DEMO_RULES = [
    {"id": "tool-allowlist", "allow_only_tools": ["search", "calendar", "email_draft", "email_send",
                                                  "pay_bill", "wire_transfer", "summarize"]},
    {"id": "no-wires", "deny_if": {"tool": "wire_transfer"}},
    {"id": "no-sensitive-data", "deny_if": {"data_class_in": ["medical", "classified"]}},
    {"id": "spend-cap", "deny_if": {"amount_usd_gt": 200}},
    {"id": "irreversible-cap", "deny_if_irreversible_over": 200},
    {"id": "blocked-parties", "deny_counterparties": ["offshore-mule.example", "acme-scam.example"]},
]


def vm(rules=DEMO_RULES):
    return PolicyVM(compile_constitution(rules))


class AmountValidation(unittest.TestCase):
    def test_negative_amount_rejected(self):
        with self.assertRaises(ActionValidationError):
            normalize_action({"tool": "wire_transfer", "amount_usd": -4800})

    def test_nan_inf_rejected(self):
        for v in (math.nan, math.inf, -math.inf):
            with self.assertRaises(ActionValidationError):
                normalize_action({"tool": "pay_bill", "amount_usd": v})

    def test_non_numeric_rejected(self):
        for v in ("5000", None, True, [1]):
            with self.assertRaises(ActionValidationError):
                normalize_action({"tool": "pay_bill", "amount_usd": v})

    def test_original_negative_wire_exploit_denied_end_to_end(self):
        with TwoKeyFixture(DEMO_RULES, [HeuristicJudge("a", .3), HeuristicJudge("b", .6),
                                        HeuristicJudge("c", .9)]) as tk:
            dec = tk.authorize({"tool": "wire_transfer", "amount_usd": -4800, "counterparty": "new-payee.example",
                               "irreversible": True, "data_class": "financial"}, "Process the refund.")
            self.assertFalse(dec.allowed)
            self.assertTrue(dec.reason.startswith("invalid_action:"))
            self.assertIsNone(dec.capability)
            self.assertEqual(tk.ledger.entries[-1].kind, "decision")

    def test_zero_amount_wire_denied_by_tool_ban(self):
        r = vm().eval(normalize_action({"tool": "wire_transfer", "amount_usd": 0, "data_class": "financial",
                                        "irreversible": False}))
        self.assertFalse(r.allowed)
        self.assertEqual(r.denied_by, "no-wires")


class Defaults(unittest.TestCase):
    def test_missing_fields_are_conservative(self):
        a = normalize_action({"tool": "email_send"})
        self.assertTrue(a.irreversible)
        self.assertEqual(a.data_class, "classified")

    def test_missing_fields_denied_by_vm(self):
        r = vm().eval(normalize_action({"tool": "email_send", "amount_usd": 10000}))
        self.assertFalse(r.allowed)

    def test_unknown_action_field_rejected(self):
        with self.assertRaises(ActionValidationError):
            normalize_action({"tool": "search", "amount": 5})

    def test_irreversible_must_be_bool(self):
        with self.assertRaises(ActionValidationError):
            normalize_action({"tool": "search", "irreversible": "false"})


class Canonicalization(unittest.TestCase):
    def test_medical_case_and_whitespace(self):
        a = normalize_action({"tool": "search", "data_class": "  Medical ", "irreversible": False})
        self.assertEqual(a.data_class, "medical")
        self.assertFalse(vm().eval(a).allowed)

    def test_unknown_data_class_rejected(self):
        with self.assertRaises(ActionValidationError):
            normalize_action({"tool": "search", "data_class": "health"})

    def test_counterparty_case_folded(self):
        a = normalize_action({"tool": "email_send", "counterparty": " OFFSHORE-MULE.example",
                              "data_class": "public", "irreversible": False})
        r = vm().eval(a)
        self.assertFalse(r.allowed)
        self.assertEqual(r.denied_by, "blocked-parties")

    def test_tool_case_folded(self):
        a = normalize_action({"tool": "Wire_Transfer", "data_class": "public", "irreversible": False})
        self.assertEqual(vm().eval(a).denied_by, "no-wires")


class CompilerStrictness(unittest.TestCase):
    def test_typo_rule_type_rejected(self):
        with self.assertRaises(ConstitutionError):
            compile_constitution([{"allow_only_tools": ["search"]}, {"deny_iff": {"tool": "search"}}])

    def test_unknown_deny_if_key_rejected(self):
        with self.assertRaises(ConstitutionError):
            compile_constitution([{"allow_only_tools": ["search"]}, {"deny_if": {"counterparty": "x"}}])

    def test_empty_constitution_rejected(self):
        with self.assertRaises(ConstitutionError):
            compile_constitution([])

    def test_allow_list_required_by_default(self):
        with self.assertRaises(ConstitutionError):
            compile_constitution([{"deny_if": {"tool": "x"}}])
        compile_constitution([{"deny_if": {"tool": "x"}}], require_allow_list=False)

    def test_bad_value_types_rejected(self):
        for bad in ([{"allow_only_tools": "search"}],
                    [{"allow_only_tools": ["s"]}, {"deny_if": {"amount_usd_gt": "200"}}],
                    [{"allow_only_tools": ["s"]}, {"deny_if": {"data_class_in": ["health"]}}],
                    [{"allow_only_tools": ["s"]}, {"deny_if_irreversible_over": -1}],
                    [{"allow_only_tools": ["s"], "deny_if": {"tool": "x"}}]):
            with self.assertRaises(ConstitutionError, msg=str(bad)):
                compile_constitution(bad)

    def test_large_constitution_fits_default_step_limit(self):
        rules = [{"allow_only_tools": ["search"]}] + [{"deny_counterparties": [f"c{i}"]} for i in range(60)]
        r = PolicyVM(compile_constitution(rules)).eval(
            normalize_action({"tool": "search", "data_class": "public", "irreversible": False}))
        self.assertTrue(r.allowed, r.reason)

    def test_program_over_step_limit_rejected_at_compile_time(self):
        rules = [{"allow_only_tools": ["search"]}] + [{"deny_counterparties": [f"c{i}"]} for i in range(60)]
        with self.assertRaises(ConstitutionError):
            compile_constitution(rules, max_steps=100)


class VMFaults(unittest.TestCase):
    def test_type_fault_is_explicit_deny(self):
        prog = [(Op.PUSH, "x"), (Op.PUSH, 1.0), (Op.GT,), (Op.ASSERT, "r"), (Op.PASS,)]
        r = PolicyVM(prog).eval(normalize_action({"tool": "search"}))
        self.assertFalse(r.allowed)
        self.assertTrue(r.reason.startswith("vm_fault:"))

    def test_stack_underflow_is_deny(self):
        r = PolicyVM([(Op.AND,), (Op.PASS,)]).eval(normalize_action({"tool": "search"}))
        self.assertFalse(r.allowed)

    def test_no_pass_is_deny(self):
        r = PolicyVM([(Op.PUSH, True)]).eval(normalize_action({"tool": "search"}))
        self.assertEqual(r.reason, "no_pass")

    def test_vm_fault_logged_as_decision(self):
        with TwoKeyFixture(DEMO_RULES, [FixedJudge("a", "yes")], quorum_policy=QuorumPolicy(required_yes=1)) as tk:
            tk.vm = PolicyVM([(Op.PUSH, None), (Op.PUSH, 1.0), (Op.GT,), (Op.PASS,)])
            dec = tk.authorize({"tool": "search", "data_class": "public", "irreversible": False}, "x")
            self.assertFalse(dec.allowed)
            self.assertIn("vm_fault", dec.reason)
            self.assertEqual(tk.ledger.entries[-1].kind, "decision")


class Quorum(unittest.TestCase):
    A = normalize_action({"tool": "search"})

    def test_two_of_three_passes(self):
        q = convene([FixedJudge("a", "yes"), FixedJudge("b", "yes"), FixedJudge("c", "no")], "c", self.A, "p",
                    QuorumPolicy(required_yes=2))
        self.assertTrue(q.passed, q.reason)

    def test_one_of_three_fails(self):
        q = convene([FixedJudge("a", "yes"), FixedJudge("b", "no"), FixedJudge("c", "no")], "c", self.A, "p",
                    QuorumPolicy(required_yes=2))
        self.assertFalse(q.passed)

    def test_zero_judges_fails(self):
        q = convene([], "c", self.A, "p", QuorumPolicy(required_yes=1))
        self.assertFalse(q.passed)
        self.assertEqual(q.reason, "no_judges")

    def test_min_responding_enforced(self):
        q = convene([FixedJudge("a", "yes"), RaisingJudge("b"), RaisingJudge("c")], "c", self.A, "p",
                    QuorumPolicy(required_yes=1, min_responding=2))
        self.assertFalse(q.passed)
        self.assertTrue(q.reason.startswith("insufficient_responses"))

    def test_raising_judge_is_abstain_not_yes(self):
        q = convene([FixedJudge("a", "yes"), RaisingJudge("b")], "c", self.A, "p", QuorumPolicy(required_yes=2))
        self.assertFalse(q.passed)
        self.assertEqual(q.abstain, 1)

    def test_invalid_ballot_object_is_abstain(self):
        class Bad(FixedJudge):
            def score(self, *a):
                return {"consistent": True}
        q = convene([Bad("x", "yes")], "c", self.A, "p", QuorumPolicy(required_yes=1))
        self.assertFalse(q.passed)

    def test_invalid_policy_rejected(self):
        for kw in ({"required_yes": 0}, {"required_yes": 1, "min_responding": 0}):
            with self.assertRaises(ValueError):
                QuorumPolicy(**kw)

    def test_distinct_provider_option(self):
        js = [FixedJudge("a", "yes", provider="x"), FixedJudge("b", "yes", provider="x")]
        self.assertTrue(convene(js, "c", self.A, "p", QuorumPolicy(required_yes=2)).passed)
        self.assertFalse(convene(js, "c", self.A, "p", QuorumPolicy(required_yes=2, min_distinct_providers=2)).passed)


class TwoKeyGuards(unittest.TestCase):
    def test_test_doubles_refused_by_default(self):
        with self.assertRaises(ValueError):
            with TwoKeyFixture(DEMO_RULES, [FixedJudge("a", "yes")], allow_test_doubles=False):
                pass

    def test_no_judges_refused(self):
        with self.assertRaises(ValueError):
            with TwoKeyFixture(DEMO_RULES, []):
                pass



class AnchorReceiptSize(unittest.TestCase):
    """LocalFileAnchor read 'size' from the top of the signed head, which is {"head": {...}, "sig": ...},
    so every receipt said 'size': None. It now reads head['size'] (engineering fix, Stephan's instruction)."""

    def test_receipt_reports_signed_head_size(self):
        import json
        from two_key import keys
        from two_key.anchoring import LocalFileAnchor
        from two_key.ledger import PersonalLedger
        with tempfile.TemporaryDirectory() as tmp:
            led = PersonalLedger(Path(tmp) / "l.jsonl", keys.generate_private_key())
            for i in range(3):
                led.append("note", {"i": i})
            r = led.anchor(LocalFileAnchor(Path(tmp) / "anchor.jsonl"))
            self.assertEqual(r["size"], 3)  # the head that was anchored covered 3 entries
            self.assertEqual(led.entries[-1].body["receipt"]["size"], 3)
            rec = json.loads((Path(tmp) / "anchor.jsonl").read_text().splitlines()[-1])
            self.assertEqual(rec["signed_head"]["head"]["size"], r["size"])
            led.append("note", {"i": 3})
            self.assertEqual(led.anchor(LocalFileAnchor(Path(tmp) / "anchor.jsonl"))["size"], 5)

    def test_flat_head_dict_still_accepted(self):
        from two_key.anchoring import LocalFileAnchor
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(LocalFileAnchor(Path(tmp) / "a.jsonl").publish({"size": 7})["size"], 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)
