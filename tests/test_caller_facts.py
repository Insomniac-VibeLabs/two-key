"""Caller-supplied facts (#2 P1): a `source: caller` field takes its value from the integration only.

The agent writing it is refused, a missing fact denies, the token binds the fact, the gateway recomputes with the
facts at redemption (fact_mismatch), judges see which fields are facts, and such a constitution signs as v3."""

import tempfile
import unittest
from pathlib import Path

from two_key.agents import tool_vocabulary
from two_key.canonical import canonical_bytes
from two_key.constitution import (FORMAT_V1, FORMAT_V2, FORMAT_V3, ConstitutionError, sign_constitution,
                                  verify_signed)
from two_key.core import TwoKey
from two_key.derive import DeriveError, derive, project_arguments
from two_key.keys import generate_private_key, sign
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

FIELDS = {"po_matched": {"type": "boolean", "default": True, "source": "caller"},
          "risk_tier": {"type": "enum", "values": ["low", "high"], "default": "low"}}
RULES = [{"id": "tools", "allow_only_tools": ["pay_vendor", "lookup"]},
         {"id": "require-po-match", "deny_if_fields": {"po_matched": {"eq": False}}}]
SPECS = {"pay_vendor": {"irreversible": True, "data_class_floor": "financial",
                        "amount": {"json_path": "amount", "unit": "usd"},
                        "counterparties": [{"json_path": "payee", "allow": ["alpine"]}],
                        "payload": [{"json_path": "invoice", "shape": "string"}],
                        "fields": {"po_matched": {"source": "caller", "json_path": "po_matched"},
                                   "risk_tier": {"json_path": "tier"}}},
         "lookup": {"irreversible": False, "data_class_floor": "public",
                    "payload": [{"json_path": "query", "shape": "string"}],
                    "fields": {"po_matched": "not_applicable"}}}
NO_PATH = dict(SPECS, pay_vendor=dict(SPECS["pay_vendor"], fields={"po_matched": {"source": "caller"},
                                                                   "risk_tier": {"json_path": "tier"}}))
CLAIM = {"tool": "pay_vendor", "data_class": "financial"}
ARGS = {"payee": "Alpine", "amount": 120, "invoice": "AMS-1", "tier": "low"}


class RecordingJudge(FixedJudge):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.records = []

    def score(self, constitution_text, action, proposal):
        self.records.append(action.to_record())
        return super().score(constitution_text, action, proposal)


def signed(specs=None, fields=None, **kw):
    key = generate_private_key()
    env = sign_constitution("Pay only matched invoices.", RULES, key, specs or SPECS,
                            fields=FIELDS if fields is None else fields, **kw)
    return key, env


class Signing(unittest.TestCase):
    def test_caller_field_signs_as_v3(self):
        key, env = signed()
        self.assertEqual(env["format"], FORMAT_V3)
        self.assertEqual(env["signed"]["fields"]["po_matched"]["source"], "caller")
        self.assertEqual(env["signed"]["tool_specs"]["pay_vendor"]["fields"]["po_matched"],
                         {"json_path": "po_matched", "source": "caller"})
        c = verify_signed(env, key.public_key())
        self.assertEqual(c.fields["po_matched"]["source"], "caller")
        _, env2 = signed(NO_PATH)
        self.assertEqual(env2["signed"]["tool_specs"]["pay_vendor"]["fields"]["po_matched"], {"source": "caller"})

    def test_without_caller_fields_formats_do_not_change(self):
        fields = {"risk_tier": FIELDS["risk_tier"]}
        specs = dict(SPECS, pay_vendor=dict(SPECS["pay_vendor"], fields={"risk_tier": {"json_path": "tier"}}),
                     lookup={k: v for k, v in SPECS["lookup"].items() if k != "fields"})
        key = generate_private_key()
        rules = [RULES[0]]
        self.assertEqual(sign_constitution("p", rules, key, specs, fields=fields)["format"], FORMAT_V2)
        plain = dict(specs, pay_vendor={k: v for k, v in specs["pay_vendor"].items() if k != "fields"})
        self.assertEqual(sign_constitution("p", rules, key, plain)["format"], FORMAT_V1)
        self.assertNotIn("source", sign_constitution("p", rules, key, specs, fields=fields)["signed"]["fields"]
                         ["risk_tier"])

    def test_v2_cannot_carry_a_caller_field(self):
        with self.assertRaisesRegex(ConstitutionError, "need a v3 constitution"):
            signed(envelope_format="v2")
        key, env = signed()
        for fmt in (FORMAT_V2, FORMAT_V1):     # a relabeled envelope is refused, never read as an argument field
            with self.subTest(fmt=fmt), self.assertRaises(ConstitutionError):
                verify_signed(dict(env, format=fmt), key.public_key())

    def test_mixed_mappings_are_refused(self):
        bad_specs = [
            ({"po_matched": {"json_path": "po_matched"}}, "caller-supplied field maps as"),
            ({"po_matched": {"source": "caller", "json_path": "po", "x": 1}}, "caller-supplied field maps as"),
            ({"risk_tier": {"source": "caller"}}, "needs the field declared source: caller"),
            ({"po_matched": {"source": "caller", "json_path": "amount"}}, "duplicate path|overlaps"),
        ]
        for fields, pattern in bad_specs:
            specs = dict(SPECS, pay_vendor=dict(SPECS["pay_vendor"], fields=fields))
            with self.subTest(fields=fields), self.assertRaisesRegex(ConstitutionError, pattern):
                signed(specs)
        with self.assertRaisesRegex(ConstitutionError, "source: expected caller"):
            signed(fields=dict(FIELDS, po_matched=dict(FIELDS["po_matched"], source="arguments")))

    def test_the_signature_covers_the_source(self):
        key, env = signed()
        body = dict(env["signed"], fields=dict(env["signed"]["fields"],
                                               po_matched={"type": "boolean", "default": True}))
        with self.assertRaises(Exception):
            verify_signed(dict(env, signed=body), key.public_key())
        # Re-signed without the source, the tool mapping no longer fits: the constitution does not load.
        forged = dict(env, signed=body, signature=sign(key, canonical_bytes(body)))
        with self.assertRaises(ConstitutionError):
            verify_signed(forged, key.public_key())


class Derive(unittest.TestCase):
    def setUp(self):
        key, env = signed()
        self.c = verify_signed(env, key.public_key())
        self.spec = self.c.tool_specs["pay_vendor"]

    def derive(self, args, facts, spec=None):
        return derive(spec or self.spec, args, self.c.fields, facts)

    def test_fact_from_the_caller(self):
        d = self.derive(ARGS, {"po_matched": False})
        self.assertEqual(dict(d.fields), {"po_matched": False, "risk_tier": "low"})
        self.assertEqual(d.fact_fields, ("po_matched",))
        projected = project_arguments(self.spec, ARGS, dict(d.fields))
        self.assertEqual(projected["po_matched"], False)            # delivered to the tool at its json_path

    def test_refusals(self):
        cases = [
            (dict(ARGS, po_matched=True), {"po_matched": False}, "caller_field_in_arguments:po_matched"),
            (ARGS, None, "field_missing:po_matched"),
            (ARGS, {}, "field_missing:po_matched"),
            (ARGS, {"po_matched": "yes"}, "field_unreadable:po_matched"),
            (ARGS, ["po_matched"], "facts_not_object"),
            (ARGS, {"po_matched": True, "risk_tier": "high"}, "fact_not_mapped:risk_tier"),
            (ARGS, {"po_matched": True, "Bad Name": 1}, "fact_not_mapped"),
        ]
        for args, facts, reason in cases:
            with self.subTest(reason=reason), self.assertRaises(DeriveError) as cm:
                self.derive(args, facts)
            self.assertEqual(cm.exception.reason, reason)

    def test_no_path_means_the_field_name_is_refused_at_the_top_level(self):
        key, env = signed(NO_PATH)
        c = verify_signed(env, key.public_key())
        spec = c.tool_specs["pay_vendor"]
        with self.assertRaises(DeriveError) as cm:
            derive(spec, dict(ARGS, po_matched=True), c.fields, {"po_matched": True})
        self.assertEqual(cm.exception.reason, "caller_field_in_arguments:po_matched")
        d = derive(spec, ARGS, c.fields, {"po_matched": True})
        self.assertNotIn("po_matched", project_arguments(spec, ARGS, dict(d.fields)))   # not delivered

    def test_a_tool_without_caller_fields_takes_no_facts(self):
        lookup = self.c.tool_specs["lookup"]
        self.assertEqual(derive(lookup, {"query": "q"}, self.c.fields, None).fact_fields, ())
        with self.assertRaises(DeriveError) as cm:
            derive(lookup, {"query": "q"}, self.c.fields, {"po_matched": True})
        self.assertEqual(cm.exception.reason, "fact_not_mapped:po_matched")


class Authorize(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        key, env = signed()
        self.judge = RecordingJudge("a", "yes")
        self.tk = TwoKey(Ledger(Path(tmp.name, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                         [self.judge], private_key=key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                         monitored_agent=TEST_AGENT)
        self.ran = []
        self.gw = self.tk.gateway(tools={"pay_vendor": self.ran.append})

    def entries(self, kind):
        return [e.body for e in self.tk.ledger.entries if e.kind == kind]

    def test_allowed_with_the_fact_and_redeemed_with_the_same_fact(self):
        d = self.tk.authorize(CLAIM, ARGS, "pay", facts={"po_matched": True})
        self.assertTrue(d.allowed, d.reason)
        self.assertEqual(self.entries("action_normalized")[-1]["fact_fields"], ["po_matched"])
        self.assertEqual(self.judge.records[-1]["fact_fields"], ["po_matched"])
        self.assertIs(self.judge.records[-1]["fields"]["po_matched"], True)
        r = self.gw.invoke(d.token, "pay_vendor", ARGS, facts={"po_matched": True})
        self.assertEqual((r.allowed, r.reason), (True, "redeemed"))
        self.assertEqual(self.ran, [{"payee": "alpine", "amount": 120, "invoice": "AMS-1", "tier": "low",
                                     "po_matched": True}])

    def test_a_false_fact_is_a_path_a_deny(self):
        d = self.tk.authorize(CLAIM, ARGS, "pay", facts={"po_matched": False})
        self.assertEqual((d.allowed, d.reason), (False, "rule_denied:require-po-match"))

    def test_fact_denies_run_both_paths_and_issue_no_token(self):
        for args, facts, reason in (
                (dict(ARGS, po_matched=True), {"po_matched": True}, "derive_failed:caller_field_in_arguments:po_matched"),
                (ARGS, None, "derive_failed:field_missing:po_matched"),
                (ARGS, {"po_matched": 1}, "derive_failed:field_unreadable:po_matched"),
                (ARGS, {"po_matched": True, "x" * 10: 1}, "derive_failed:fact_not_mapped:xxxxxxxxxx"),
                (ARGS, "po_matched", "derive_failed:facts_not_object")):
            with self.subTest(reason=reason):
                before = len(self.judge.records)
                d = self.tk.authorize(CLAIM, args, "pay", facts=facts)
                self.assertEqual((d.allowed, d.reason, d.token), (False, reason, None))
                self.assertEqual(len(self.judge.records), before + 1)       # Path B still ran
                self.assertIn("allowed", d.path_a)

    def test_a_fact_in_the_claim_is_refused(self):
        for claim in (dict(CLAIM, po_matched=True), dict(CLAIM, fields={"po_matched": True}),
                      dict(CLAIM, fact_fields=["po_matched"])):
            d = self.tk.authorize(claim, ARGS, "pay", facts={"po_matched": True})
            self.assertTrue(d.reason.startswith("malformed_action:unknown action fields"), d.reason)

    def test_the_gateway_recomputes_with_the_facts_at_redemption(self):
        for facts, reason in (({"po_matched": False}, "fact_mismatch"), (None, "fact_mismatch"),
                              ({}, "fact_mismatch"), ({"po_matched": "true"}, "fact_mismatch")):
            with self.subTest(facts=facts):
                d = self.tk.authorize(CLAIM, ARGS, "pay", facts={"po_matched": True})
                r = self.gw.invoke(d.token, "pay_vendor", ARGS, facts=facts)
                self.assertEqual((r.allowed, r.reason), (False, reason))
        d = self.tk.authorize(CLAIM, ARGS, "pay", facts={"po_matched": True})
        r = self.gw.invoke(d.token, "pay_vendor", dict(ARGS, amount=121), facts={"po_matched": True})
        self.assertEqual(r.reason, "args_mismatch")
        self.assertEqual(self.ran, [])
        self.assertEqual({e["reason"] for e in self.entries("gateway_denied")}, {"fact_mismatch", "args_mismatch"})

    def test_facts_are_copied_under_the_caps(self):
        d = self.tk.authorize(CLAIM, ARGS, "pay", facts={"po_matched": "x" * (300 * 1024)})
        self.assertEqual(d.reason, "derive_failed:facts_too_large")
        nested = {"k": 1}
        for _ in range(70):
            nested = {"k": nested}
        self.assertEqual(self.tk.authorize(CLAIM, ARGS, "pay", facts={"po_matched": nested}).reason,
                         "derive_failed:facts_unreadable")

    def test_authorize_from_agent_takes_a_resolver(self):
        class Agent:
            agent_id, hosting = "a", "local"
        text = '{"tool": "pay_vendor", "arguments": {"payee": "alpine", "amount": 120, "invoice": "AMS-1", ' \
               '"tier": "low"}, "proposal": "pay"}'
        seen = []

        def resolver(tool, arguments):
            seen.append((tool, arguments))
            return {"po_matched": arguments["invoice"] == "AMS-1"}
        d = self.tk.authorize_from_agent(Agent(), text, facts=resolver)
        self.assertTrue(d.allowed, d.reason)
        self.assertEqual(seen[0][0], "pay_vendor")

        def broken(tool, arguments):
            raise RuntimeError("billing down")
        d = self.tk.authorize_from_agent(Agent(), text, facts=broken)
        self.assertEqual(d.reason, "derive_failed:field_missing:po_matched")

    def test_the_vocabulary_never_lists_a_caller_field(self):
        text = self.tk.agent_vocabulary()
        self.assertNotIn("po_matched", text)
        self.assertIn("risk_tier", text)
        self.assertEqual(text, tool_vocabulary(self.tk.constitution))


if __name__ == "__main__":
    unittest.main()
