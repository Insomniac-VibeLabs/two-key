# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Run 14 Z5: an argument string the tool would not get as written is denied before either path. A lone surrogate
is always refused (``invalid_call:text_not_unicode``); a NUL is refused (``invalid_call:nul_in_arguments``) unless
the tool's signed spec says ``nul_in_arguments: allow``, which is weaker."""

import tempfile
import unittest
from pathlib import Path

from two_key import config_set, setup_cmd
from two_key.constitution import ConstitutionError, sign_constitution, verify_signed
from two_key.core import TwoKey, args_text_problem
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search", "raw"]}]
PAYLOAD = {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}
SPECS = {"search": PAYLOAD, "raw": dict(PAYLOAD, nul_in_arguments="allow")}


def call(tool):
    return {"tool": tool, "data_class": "public", "irreversible": False}


class Counting(FixedJudge):
    calls = 0

    def score(self, *a, **kw):
        Counting.calls += 1
        return super().score(*a, **kw)


def engine(tmp):
    key = generate_private_key()
    env = sign_constitution("Searching is fine.", RULES, key, SPECS)
    return TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                  [Counting("a", "yes", provider="p1")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                  allow_test_doubles=True, monitored_agent=TEST_AGENT)


class Walk(unittest.TestCase):
    def test_keys_values_and_nesting_are_read(self):
        self.assertIsNone(args_text_problem({"q": ["a", {"b": "c"}]}))
        self.assertEqual(args_text_problem({"q": ["a", {"b": "c\x00d"}]}), "nul_in_arguments")
        self.assertEqual(args_text_problem({"q\x00": 1}), "nul_in_arguments")
        self.assertIsNone(args_text_problem({"q": "c\x00d"}, nul_allowed=True))
        self.assertEqual(args_text_problem({"q": "\ud800"}, nul_allowed=True), "text_not_unicode")
        self.assertEqual(args_text_problem({"\udfff": "x"}), "text_not_unicode")
        self.assertIsNone(args_text_problem({"q": "\U0001F600 café"}))     # a pair written as one is fine


class Authorize(unittest.TestCase):
    def test_a_nul_is_denied_before_the_judges_unless_the_spec_allows_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(tmp)
            Counting.calls = 0
            denied = tk.authorize(call("search"), {"q": "/notes/a\x00../../etc"}, "look")
            self.assertEqual((denied.allowed, denied.reason, denied.token),
                             (False, "invalid_call:nul_in_arguments", None))
            self.assertEqual(Counting.calls, 0)
            body = tk.ledger.entries[-1].body
            self.assertEqual((body["tool_args_omitted"], body["tool_args_error"]), (True, "nul_in_arguments"))
            self.assertTrue(tk.authorize(call("raw"), {"q": "a\x00b"}, "look").allowed)

    def test_a_lone_surrogate_is_denied_even_where_a_nul_is_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(tmp)
            for tool in ("search", "raw"):
                with self.subTest(tool):
                    denied = tk.authorize(call(tool), {"q": "x\ud800"}, "look")
                    self.assertEqual((denied.allowed, denied.reason), (False, "invalid_call:text_not_unicode"))


class Settings(unittest.TestCase):
    def test_only_allow_signs_and_leaving_it_out_signs_the_same_bytes(self):
        key = generate_private_key()
        bad = dict(SPECS, raw=dict(PAYLOAD, nul_in_arguments="yes"))
        with self.assertRaisesRegex(ConstitutionError, "nul_in_arguments: expected allow"):
            sign_constitution("x", RULES, key, bad)
        plain = verify_signed(sign_constitution("x", RULES, key, SPECS), key.public_key())
        self.assertNotIn("nul_in_arguments", plain.tool_specs["search"])
        self.assertEqual(plain.tool_specs["raw"]["nul_in_arguments"], "allow")

    def test_allowing_a_nul_is_weaker_and_refusing_it_again_is_not(self):
        self.assertIs(config_set._same_or_tighter("nul_in_arguments", None, "allow"), False)
        self.assertIs(config_set._same_or_tighter("nul_in_arguments", "allow", None), True)

    def test_setup_names_it_as_weaker(self):
        answers = {"profile": "default", "tools": [{"id": "raw", "nul_in_arguments": "allow"}, {"id": "search"}]}
        self.assertEqual(setup_cmd.weaker_reasons(answers),
                         ["tool_specs.raw.nul_in_arguments: allow (a NUL reaches the tool)"])
        spec = setup_cmd._starter_spec({"id": "raw", "nul_in_arguments": "allow"}, None, False)
        self.assertEqual(spec["nul_in_arguments"], "allow")

    def test_the_interview_asks_per_tool_and_defaults_to_refusing(self):
        def ask_with(nul):
            given = {"tool ids": "raw search", "NUL character": nul}
            return lambda prompt: next((v for k, v in given.items() if k in prompt), "")
        tools = setup_cmd._ask_tools(ask_with(""), "default")
        self.assertFalse([t for t in tools if "nul_in_arguments" in t], tools)
        tools = setup_cmd._ask_tools(ask_with("yes"), "default")
        self.assertEqual([t.get("nul_in_arguments") for t in tools], ["allow", "allow"])


if __name__ == "__main__":
    unittest.main()
