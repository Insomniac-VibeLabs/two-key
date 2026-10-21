# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Depth boundary: tool args, the action claim, and a structured proposal are held to MAX_INPUT_DEPTH, two
levels under the encoder's MAX_DEPTH, so an accepted input still encodes inside a judge's record and a
ledger entry. One level past the limit is a ledgered deny, never internal_error. A ledger body that cannot be
encoded is recorded by size and digest."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from two_key.canonical import MAX_DEPTH, MAX_INPUT_DEPTH, WRAP_DEPTH, EncodingError, canonical_bytes
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.gateway import ToolGateway
from two_key.judges.llm import build_user_prompt
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


def deep(depth):
    """A value with exactly ``depth`` nested containers (objects and arrays alternate)."""
    v = "leaf"
    for i in range(depth):
        v = {"x": v} if i % 2 else [v]
    return v


def depth_of(value):
    stack, best = [(value, 1)], 0
    while stack:
        item, level = stack.pop()
        if isinstance(item, dict):
            best = max(best, level)
            stack.extend((c, level + 1) for c in item.values())
        elif isinstance(item, list):
            best = max(best, level)
            stack.extend((c, level + 1) for c in item)
    return best


class PromptJudge(FixedJudge):
    """Encodes the record a real LLM judge would send, so a record that cannot be encoded fails the test."""
    prompts: list

    def score(self, constitution_text, action, proposal):
        PromptJudge.prompts.append(build_user_prompt(constitution_text, action, proposal))
        return super().score(constitution_text, action, proposal)


class Boundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, self.key, SPECS)
        PromptJudge.prompts = []
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), self.key), self.key.public_key(),
                         verify_signed(env, self.key.public_key()), [PromptJudge("a", "yes")], private_key=self.key,
                         quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)
        self.ran = []
        self.gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled,
                              tools={"search": lambda a: self.ran.append(a) or "ok"})

    def reload(self):
        Ledger(Path(self.tmp.name, "ledger"), self.key).verify()

    def args_at(self, depth):
        args = {"q": deep(depth - 1)}
        self.assertEqual(depth_of(args), depth)
        return args

    def test_limits(self):
        self.assertEqual(MAX_DEPTH, 64)
        self.assertEqual(WRAP_DEPTH, 2)
        self.assertEqual(MAX_INPUT_DEPTH, MAX_DEPTH - WRAP_DEPTH)
        canonical_bytes(deep(MAX_DEPTH))
        with self.assertRaisesRegex(EncodingError, "^value is nested too deeply$"):
            canonical_bytes(deep(MAX_DEPTH + 1))

    def test_args_under_and_at_the_limit_get_a_token_and_redeem(self):
        for depth in (MAX_INPUT_DEPTH - 1, MAX_INPUT_DEPTH):
            with self.subTest(depth=depth):
                args = self.args_at(depth)
                d = self.tk.authorize(SEARCH, args, "look it up")
                self.assertTrue(d.allowed, d.reason)
                # The judge's record wraps the args two levels down: {"raw": {"tool_args": args}}.
                record = json.loads(PromptJudge.prompts[-1].split("<untrusted_action_record>\n")[1].split("\n")[0])
                self.assertEqual(record["raw"]["tool_args"], args)
                self.assertEqual(depth_of(record), depth + WRAP_DEPTH)
                r = self.gw.invoke(d.token, "search", args)
                self.assertTrue(r.allowed, r.reason)
                self.assertEqual(self.ran[-1], args)
        self.reload()

    def test_args_one_past_the_limit_are_invalid_call_and_ledgered(self):
        before = self.tk.ledger.size()
        d = self.tk.authorize(SEARCH, self.args_at(MAX_INPUT_DEPTH + 1), "look it up")
        self.assertEqual((d.allowed, d.reason), (False, "invalid_call:tool args are nested too deeply"))
        self.assertEqual(self.tk.ledger.size(), before + 1)
        body = self.tk.ledger.entries[-1].body
        self.assertEqual(body["reason"], d.reason)
        self.assertTrue(body["tool_args_omitted"])
        self.assertEqual(PromptJudge.prompts, [])
        self.reload()

    def test_gateway_args_one_past_the_limit(self):
        d = self.tk.authorize(SEARCH, {"q": "x"}, "look it up")
        r = self.gw.invoke(d.token, "search", self.args_at(MAX_INPUT_DEPTH + 1))
        self.assertEqual((r.allowed, r.reason), (False, "invalid_call:tool args are nested too deeply"))
        body = self.tk.ledger.entries[-1].body
        self.assertEqual((self.tk.ledger.entries[-1].kind, body["reason"]), ("gateway_denied", r.reason))
        self.assertEqual(self.ran, [])
        self.reload()

    def claim_at(self, depth):
        claim = {**SEARCH, "raw": {"x": deep(depth - 2)}}
        self.assertEqual(depth_of(claim), depth)
        return claim

    def test_claim_under_and_at_the_limit(self):
        for depth in (MAX_INPUT_DEPTH - 1, MAX_INPUT_DEPTH):
            with self.subTest(depth=depth):
                d = self.tk.authorize(self.claim_at(depth), {"q": "x"}, "look it up")
                self.assertTrue(d.allowed, d.reason)
        self.reload()

    def test_claim_one_past_the_limit_is_malformed_action_and_ledgered(self):
        before = self.tk.ledger.size()
        d = self.tk.authorize(self.claim_at(MAX_INPUT_DEPTH + 1), {"q": "x"}, "look it up")
        self.assertEqual((d.allowed, d.reason), (False, "malformed_action:action claim is nested too deeply"))
        self.assertEqual(self.tk.ledger.size(), before + 1)
        body = self.tk.ledger.entries[-1].body
        self.assertEqual(body["reason"], d.reason)
        self.assertTrue(body["action_omitted"])
        self.reload()

    def test_claim_with_args_at_the_limit_still_encodes_for_the_judge(self):
        d = self.tk.authorize(self.claim_at(MAX_INPUT_DEPTH), self.args_at(MAX_INPUT_DEPTH), "look it up")
        self.assertTrue(d.allowed, d.reason)

    def test_structured_proposal_at_and_past_the_limit(self):
        d = self.tk.authorize(SEARCH, {"q": "x"}, deep(MAX_INPUT_DEPTH))
        self.assertTrue(d.allowed, d.reason)
        proposal_entry = [e for e in self.tk.ledger.entries if e.kind == "proposal"][-1]
        self.assertEqual(proposal_entry.body["proposal"], deep(MAX_INPUT_DEPTH))   # stored whole, not omitted
        d = self.tk.authorize(SEARCH, {"q": "x"}, deep(MAX_INPUT_DEPTH + 1))
        self.assertEqual((d.allowed, d.reason), (False, "malformed_proposal"))
        self.assertEqual(self.tk.ledger.entries[-1].body["proposal_error"], "proposal is nested too deeply")
        self.reload()


class AppendBounded(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = generate_private_key()
        self.ledger = Ledger(Path(self.tmp.name, "ledger"), self.key)

    def test_too_deep_body_is_kept_as_size_and_digest(self):
        body = {"reason": "why", "jti": "j1", "allowed": False, "secret": deep(MAX_DEPTH)}
        with self.assertRaisesRegex(EncodingError, "nested too deeply"):
            self.ledger.append("x", body)
        self.assertEqual(self.ledger.size(), 1)     # only the new ledger's witness_pinned entry
        entry = self.ledger.append_bounded("x", body)
        self.assertEqual(entry.body["reason"], "why")
        self.assertEqual(entry.body["jti"], "j1")
        self.assertIs(entry.body["allowed"], False)
        self.assertNotIn("secret", entry.body)
        self.assertTrue(entry.body["body_omitted"])
        self.assertEqual(entry.body["body_error"], "value is nested too deeply")
        self.assertGreater(entry.body["body_size"], 0)
        self.assertRegex(entry.body["body_digest"], "^sha256:[0-9a-f]{64}$")
        self.ledger.checkpoint()
        Ledger(Path(self.tmp.name, "ledger"), self.key).verify()

    def test_unencodable_value_and_long_string_are_dropped(self):
        entry = self.ledger.append_bounded("x", {"reason": "r" * 500, "obj": object(), "n": 3})
        self.assertEqual(set(entry.body) - {"body_size", "body_digest", "body_omitted", "body_error"}, {"n"})
        self.assertEqual(entry.body["body_error"], "unsupported_type")

    def test_body_omitted_retains_policy_and_identity_digests(self):
        """Auditors can still bind a truncated decision to the loaded policy/identities (#11)."""
        body = {"allowed": False, "reason": "x", "policy_digest": "a" * 64,
                "identities_digest": "b" * 64, "secret": deep(MAX_DEPTH)}
        entry = self.ledger.append_bounded("decision", body)
        self.assertTrue(entry.body["body_omitted"])
        self.assertEqual(entry.body["policy_digest"], "a" * 64)
        self.assertEqual(entry.body["identities_digest"], "b" * 64)
        self.assertNotIn("secret", entry.body)

    def test_a_body_that_encodes_is_unchanged(self):
        self.assertEqual(self.ledger.append_bounded("x", {"a": [1, 2]}).body, {"a": [1, 2]})

    def test_authorize_records_a_body_the_encoder_refuses(self):
        # body_omitted on a path that would issue a token is fail-closed (B1 / Cyber):
        # ledger the omitted proposal for audit, but do not allow or mint a token.
        from two_key.agent_meta import REASON_LEDGER_BODY
        env = sign_constitution("Searching is fine.", RULES, self.key, SPECS)
        tk = TwoKey(self.ledger, self.key.public_key(), verify_signed(env, self.key.public_key()),
                    [FixedJudge("a", "yes")], private_key=self.key, quorum=QuorumPolicy(required_yes=1),
                    allow_test_doubles=True, monitored_agent=TEST_AGENT)
        real = Ledger.append

        def refuse_proposal(ledger, kind, body):
            if kind == "proposal" and not body.get("body_omitted"):
                raise EncodingError("value is nested too deeply")
            return real(ledger, kind, body)
        with mock.patch.object(Ledger, "append", refuse_proposal):
            d = tk.authorize(SEARCH, {"q": "x"}, "look it up " * 30)   # over the 200 characters a fallback keeps
        self.assertEqual((d.allowed, d.token, d.reason), (False, None, REASON_LEDGER_BODY))
        [entry] = [e for e in tk.ledger.entries if e.kind == "proposal"]
        self.assertTrue(entry.body["body_omitted"])
        self.assertEqual(entry.body["tool"], "search")
        self.assertNotIn("proposal", entry.body)
        Ledger(Path(self.tmp.name, "ledger"), self.key).verify()


if __name__ == "__main__":
    unittest.main()
