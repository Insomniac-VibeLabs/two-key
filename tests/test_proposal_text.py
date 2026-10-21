# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""An agent proposal is measured before it is parsed, and a bad one is a ledgered deny, not an exception."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from two_key.agents import MAX_PROPOSAL_TEXT_CHARS, AgentConfigError, MonitoredAgent, parse_proposal
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import MAX_ARGS_BYTES
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}
SECRET_KEY = "zz_secret_key_name_zz"


class ProposalText(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, key, SPECS)
        self.tk = TwoKey(Ledger(Path(self.tmp.name) / "ledger", key), key.public_key(),
                         verify_signed(env, key.public_key()), [FixedJudge("a", "yes")], private_key=key,
                         quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)
        self.agent = MonitoredAgent("grok", "xai", "grok", "https://api.x.ai/v1", "cloud", kind="openai_compatible")

    def last_decision(self):
        return [e.body for e in self.tk.ledger.entries if e.kind == "decision"][-1]

    def test_cap_is_four_times_the_args_cap(self):
        self.assertEqual(MAX_PROPOSAL_TEXT_CHARS, 4 * MAX_ARGS_BYTES)

    def test_oversized_text_is_denied_with_size_and_digest_only(self):
        text = '{"tool": "search", "arguments": {}, "proposal": "' + "Q" * MAX_PROPOSAL_TEXT_CHARS + '"}'
        d = self.tk.authorize_from_agent(self.agent, text)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "proposal_too_large")
        body = self.last_decision()
        self.assertEqual(body["reason"], "proposal_too_large")
        self.assertEqual(body["proposal_text_size"], len(json.dumps(text)))
        self.assertTrue(body["proposal_text_digest"].startswith("sha256:"))
        self.assertTrue(body["proposal_text_omitted"])
        self.assertNotIn("QQQQ", json.dumps([e.body for e in self.tk.ledger.entries]))
        self.assertEqual(body["agent"]["id"], "grok")

    def test_parse_proposal_refuses_oversized_text_before_parsing(self):
        with self.assertRaisesRegex(AgentConfigError, "longer than"):
            parse_proposal("x" * (MAX_PROPOSAL_TEXT_CHARS + 1))

    def test_none_is_a_deny_not_attribute_error(self):
        d = self.tk.authorize_from_agent(self.agent, None)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "malformed_proposal")
        self.assertEqual(self.last_decision()["proposal_text_type"], "NoneType")

    def test_no_agent_and_none_is_still_a_deny(self):
        d = self.tk.authorize_from_agent(None, None)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "malformed_proposal")

    def test_unparseable_text_is_a_ledgered_deny(self):
        for text in ("not json", "[]", '{"tool": "search"}', ""):
            with self.subTest(text=text):
                d = self.tk.authorize_from_agent(self.agent, text)
                self.assertFalse(d.allowed)
                self.assertEqual(d.reason, "malformed_proposal")
                body = self.last_decision()
                self.assertIn("proposal_text_digest", body)
                self.assertIn("proposal_text_size", body)

    def test_reason_and_ledger_never_carry_a_key_name(self):
        dup = '{"tool": "search", "arguments": {"%s": 1, "%s": 2}, "proposal": "x"}' % (SECRET_KEY, SECRET_KEY)
        extra = '{"tool": "search", "arguments": {}, "proposal": "x", "%s": 1}' % SECRET_KEY
        for text in (dup, extra):
            with self.subTest(text=text[:40]):
                d = self.tk.authorize_from_agent(self.agent, text)
                self.assertEqual(d.reason, "malformed_proposal")
                self.assertNotIn(SECRET_KEY, json.dumps([e.body for e in self.tk.ledger.entries]))

    def test_reply_too_deep_to_parse_is_malformed_proposal(self):
        # Deep enough that json recurses out on every supported Python version.
        for text in ('{"tool": "search", "arguments": {"q": ' + "[" * 200_000 + "]" * 200_000 + '}, "proposal": "x"}',
                     "[" * 200_000 + "]" * 200_000):
            with self.subTest(size=len(text)):
                d = self.tk.authorize_from_agent(self.agent, text)
                self.assertEqual((d.allowed, d.reason), (False, "malformed_proposal"))
                self.assertIn("proposal_text_digest", self.last_decision())

    def test_recursion_error_while_parsing_is_malformed_proposal_not_internal_error(self):
        with mock.patch("two_key.core.parse_proposal", side_effect=RecursionError):
            d = self.tk.authorize_from_agent(self.agent, '{"tool": "search", "arguments": {}, "proposal": "x"}')
        self.assertEqual((d.allowed, d.reason), (False, "malformed_proposal"))
        body = self.last_decision()
        self.assertEqual(body["reason"], "malformed_proposal")
        self.assertIn("proposal_text_digest", body)

    def test_good_text_still_runs_both_paths(self):
        text = json.dumps({"tool": "search", "arguments": {"q": "x"}, "proposal": "look it up",
                           "data_class": "public", "irreversible": False})
        d = self.tk.authorize_from_agent(self.agent, text)
        self.assertTrue(d.allowed, d.reason)


if __name__ == "__main__":
    unittest.main()
