"""An agent may decline. A decline is a ledgered deny: never a call, never a token, neither path runs."""

import json
import tempfile
import unittest
from pathlib import Path

from two_key.agents import (MAX_DECLINE_CHARS, SYSTEM, AgentConfigError, AgentDeclined, MonitoredAgent,
                            parse_proposal)
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}
# What a strict-schema host (OpenAI, xAI) returns: every key present.
SCHEMA_DECLINE = {"tool": "", "arguments": "{}", "proposal": "", "amount_usd": None, "counterparty": None,
                  "data_class": None, "irreversible": None, "decline": "The request asks me to wire money."}


class ParseDecline(unittest.TestCase):
    def reason(self, obj):
        with self.assertRaises(AgentDeclined) as cm:
            parse_proposal(json.dumps(obj))
        return cm.exception.reason

    def test_bare_decline(self):
        self.assertEqual(self.reason({"decline": "  not allowed  "}), "not allowed")

    def test_schema_forced_decline(self):
        self.assertEqual(self.reason(SCHEMA_DECLINE), "The request asks me to wire money.")
        self.assertEqual(self.reason({**SCHEMA_DECLINE, "tool": None, "arguments": {}, "proposal": "why"}),
                         "The request asks me to wire money.")

    def test_a_decline_is_an_agent_config_error(self):
        # A caller written before declines existed, catching AgentConfigError, still fails closed.
        self.assertTrue(issubclass(AgentDeclined, AgentConfigError))

    def test_decline_mixed_with_a_call_is_malformed_not_a_decline(self):
        bad = [
            {"decline": "no", "tool": "search", "arguments": {}, "proposal": "x"},
            {"decline": "no", "tool": "", "arguments": {"query": "x"}, "proposal": ""},
            {"decline": "no", "arguments": "{\"query\": \"x\"}"},
            {"decline": "no", "data_class": "public"},
            {"decline": "no", "amount_usd": 0},
            {"decline": "no", "extra": 1},
            {"decline": ""}, {"decline": "   "}, {"decline": 5}, {"decline": ["no"]},
            {"decline": "x" * (MAX_DECLINE_CHARS + 1)},
        ]
        for obj in bad:
            with self.subTest(obj=str(obj)[:80]), self.assertRaises(AgentConfigError) as cm:
                parse_proposal(json.dumps(obj))
            self.assertNotIsInstance(cm.exception, AgentDeclined)

    def test_null_decline_is_an_ordinary_call(self):
        action, args, proposal = parse_proposal(json.dumps({"tool": "search", "arguments": {"q": "x"},
                                                            "proposal": "look", "decline": None}))
        self.assertEqual((action["tool"], args, proposal), ("search", {"q": "x"}, "look"))

    def test_system_prompt_says_how_to_decline(self):
        self.assertIn('{"decline": "<short reason>"}', SYSTEM)


class AuthorizeDecline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        con = verify_signed(sign_constitution("Searching is fine.", RULES, key, SPECS), key.public_key())
        self.judge = FixedJudge("a", "yes")
        self.tk = TwoKey(Ledger(Path(self.tmp.name) / "ledger", key), key.public_key(), con, [self.judge],
                         private_key=key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                         monitored_agent=TEST_AGENT)
        self.agent = MonitoredAgent("grok", "xai", "grok", "https://api.x.ai/v1", "cloud", kind="openai_compatible")

    def kinds(self):
        return [e.kind for e in self.tk.ledger.entries]

    def test_decline_is_a_ledgered_deny_with_no_path_and_no_token(self):
        before = len(self.tk.ledger.entries)
        d = self.tk.authorize_from_agent(self.agent, json.dumps(SCHEMA_DECLINE))
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "agent_declined")
        self.assertIsNone(d.token)
        self.assertEqual((d.path_a, d.path_b), ({}, {}))
        new = self.tk.ledger.entries[before:]
        self.assertNotIn("capability_issued", [e.kind for e in new])
        self.assertNotIn("action_normalized", [e.kind for e in new])
        body = [e.body for e in new if e.kind == "decision"][-1]
        self.assertEqual(body["reason"], "agent_declined")
        self.assertEqual(body["decline"], "The request asks me to wire money.")
        self.assertIn("proposal_text_digest", body)

    def test_judges_are_not_asked(self):
        calls = []
        for name in ("score", "score_bound"):
            real = getattr(self.judge, name)
            setattr(self.judge, name, lambda *a, _real=real, **k: calls.append(a) or _real(*a, **k))
        self.tk.authorize_from_agent(self.agent, json.dumps({"decline": "no"}))
        self.assertEqual(calls, [])
        # The spy works: an ordinary call reaches the judge.
        self.tk.authorize_from_agent(self.agent, json.dumps({"tool": "search", "arguments": {}, "proposal": "x",
                                                             "data_class": "public"}))
        self.assertTrue(calls)

    def test_mixed_reply_is_malformed_proposal(self):
        d = self.tk.authorize_from_agent(self.agent, json.dumps({"decline": "no", "tool": "search",
                                                                  "arguments": {}, "proposal": "x"}))
        self.assertEqual(d.reason, "malformed_proposal")
        self.assertIsNone(d.token)

    def test_complete_raises_agent_declined(self):
        def transport(url, headers, body, timeout):
            return {"choices": [{"message": {"content": json.dumps({"decline": "outside my constitution"})}}]}
        agent = MonitoredAgent("a", "p", "m", "https://api.example.test/v1", "cloud", kind="openai_compatible",
                               transport=transport)
        with self.assertRaises(AgentDeclined) as cm:
            agent.complete("wire $3,500", "Never wire money.")
        self.assertEqual(cm.exception.reason, "outside my constitution")


if __name__ == "__main__":
    unittest.main()
