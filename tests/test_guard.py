"""two_key.guard: one call through both keys, with caller-supplied facts looked up before authorize and again
before the tool runs."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.guard import Guard, GuardConfigError, GuardDenied, GuardedTool, valid_claim
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

FIELDS = {"po_matched": {"type": "boolean", "default": True, "source": "caller"}}
RULES = [{"id": "tools", "allow_only_tools": ["pay_vendor", "lookup"]},
         {"id": "require-po-match", "deny_if_fields": {"po_matched": {"eq": False}}}]
SPECS = {"pay_vendor": {"irreversible": True, "data_class_floor": "financial",
                        "amount": {"json_path": "amount", "unit": "usd"},
                        "counterparties": [{"json_path": "payee", "allow": ["alpine"]}],
                        "payload": [{"json_path": "invoice", "shape": "string"}],
                        "fields": {"po_matched": {"source": "caller"}}},
         "lookup": {"irreversible": False, "data_class_floor": "public",
                    "payload": [{"json_path": "query", "shape": "string"}]}}
ARGS = {"payee": "alpine", "amount": 50, "invoice": "AMS-1"}


class GuardTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        key = generate_private_key()
        env = sign_constitution("Pay matched invoices.", RULES, key, SPECS, fields=FIELDS)
        self.tk = TwoKey(Ledger(Path(tmp.name, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                         [FixedJudge("a", "yes")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                         allow_test_doubles=True, monitored_agent=TEST_AGENT)
        self.paid, self.lookups = [], []

    def hook(self, answers):
        answers = list(answers)

        def po(tool, arguments):
            self.lookups.append((tool, arguments))
            return answers.pop(0) if answers else None
        return po

    def guard(self, answers=(True, True), **kw):
        return Guard(self.tk, [GuardedTool("pay_vendor", self.paid.append, "floor",
                                           {"po_matched": self.hook(answers)}, "Pay an invoice"),
                               GuardedTool("lookup", lambda a: {"hits": 1})], **kw)

    def test_allowed_call_looks_the_fact_up_twice(self):
        g = self.guard()
        r = g.call("pay_vendor", ARGS)
        self.assertEqual((r.allowed, r.reason, r.stage), (True, "redeemed", "gateway"))
        self.assertEqual(self.paid, [ARGS])
        self.assertEqual(len(self.lookups), 2)                  # before authorize, and before the tool runs
        self.assertEqual(self.lookups[0], ("pay_vendor", ARGS))
        self.assertIsNot(self.lookups[0][1], self.lookups[1][1])  # each hook gets its own copy
        decision = [e.body for e in self.tk.ledger.entries if e.kind == "decision"][-1]
        self.assertEqual(decision["origin"], "guard")
        normalized = [e.body for e in self.tk.ledger.entries if e.kind == "action_normalized"][-1]
        self.assertEqual((normalized["claimed_data_class"], normalized["fact_fields"]), ("financial", ["po_matched"]))

    def test_denies(self):
        for answers, reason, stage in (((False,), "rule_denied:require-po-match", "authorize"),
                                       ((), "derive_failed:field_missing:po_matched", "authorize"),
                                       ((True, False), "fact_mismatch", "gateway")):
            with self.subTest(reason=reason):
                r = self.guard(answers).call("pay_vendor", ARGS)
                self.assertEqual((r.allowed, r.reason, r.stage), (False, reason, stage))
        self.assertEqual(self.paid, [])

    def test_a_hook_that_raises_leaves_the_fact_out(self):
        def broken(tool, arguments):
            raise TimeoutError("billing down")
        g = Guard(self.tk, [GuardedTool("pay_vendor", self.paid.append, facts={"po_matched": broken})])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            r = g.call("pay_vendor", ARGS)
        self.assertEqual(r.reason, "derive_failed:field_missing:po_matched")
        self.assertIn("fact hook for pay_vendor.po_matched failed: TimeoutError", err.getvalue())

    def test_a_tool_without_facts_and_the_default_claim(self):
        g = self.guard()
        self.assertEqual(g.claim("lookup"), {"tool": "lookup"})
        r = g.call("lookup", {"query": "q"})
        self.assertEqual((r.allowed, r.output), (True, {"hits": 1}))
        normalized = [e.body for e in self.tk.ledger.entries if e.kind == "action_normalized"][-1]
        self.assertEqual(normalized["claimed_data_class"], "classified")
        self.assertNotIn("fact_fields", normalized)
        self.assertEqual(g.call("nope", {}).reason, "tool_not_guarded")

    def test_refusals(self):
        bad = [(GuardedTool("wire", print), "not a tool in the signed constitution"),
               (GuardedTool("pay_vendor", print), r"no fact hook for caller-supplied field\(s\) \['po_matched'\]"),
               (GuardedTool("lookup", print, facts={"po_matched": print}), "does not map as caller-supplied"),
               (GuardedTool("lookup", print, claim="secret"), "claim"),
               (GuardedTool("lookup", "not callable"), "fn must be callable"),
               (GuardedTool("pay_vendor", print, facts={"po_matched": "x"}), "hook must be callable")]
        for tool, pattern in bad:
            with self.subTest(pattern=pattern), self.assertRaisesRegex(GuardConfigError, pattern):
                Guard(self.tk, [tool])
        g = Guard(self.tk, [GuardedTool("lookup", print)])
        with self.assertRaisesRegex(GuardConfigError, "already guarded"):
            g.add(GuardedTool("lookup", print))
        self.assertEqual(valid_claim("Medical+Financial"), "financial+medical")

    def test_decorator(self):
        g = Guard(self.tk, agent_id="loop-agent")

        @g.tool("pay_vendor", claim="floor", facts={"po_matched": lambda tool, args: args["invoice"] == "AMS-1"})
        def pay_vendor(args):
            """Pay an invoice."""
            return {"paid": args["amount"]}
        self.assertEqual(pay_vendor(ARGS), {"paid": 50})
        self.assertEqual(pay_vendor.__doc__, "Pay an invoice.")
        with self.assertRaises(GuardDenied) as cm:
            pay_vendor(dict(ARGS, invoice="AMS-2"))
        self.assertEqual((cm.exception.reason, cm.exception.stage), ("rule_denied:require-po-match", "authorize"))
        decision = [e.body for e in self.tk.ledger.entries if e.kind == "decision"][-1]
        self.assertEqual(decision["agent"]["id"], "loop-agent")

    def test_record(self):
        g = self.guard()
        g.record("integration_note", {"what": "started"})
        self.assertEqual(self.tk.ledger.entries[-1].kind, "integration_note")


if __name__ == "__main__":
    unittest.main()
