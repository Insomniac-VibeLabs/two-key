# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""A non-dict Mapping (top level or nested) in the tool args, the action claim, or the proposal is copied
once into built-in types and sized, hashed, judged, ledgered, and handed to the tool from that copy. Its
str() or repr() never stands in for its size, so a 5 MB custom Mapping cannot get a token."""

import json
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path

from two_key.action import Action
from two_key.canonical import EncodingError, OversizeError, to_plain
from two_key.capability import args_hash
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import MAX_ACTION_BYTES, MAX_ARGS_BYTES, args_too_large
from two_key.gateway import ToolGateway
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}
BIG = "A" * (5 << 20)


class Small(Mapping):
    """A Mapping whose str() and repr() claim it is tiny."""

    def __init__(self, data):
        self._data = dict(data)

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return 1

    def __str__(self):
        return "{}"

    __repr__ = __str__


class Endless(Mapping):
    """A Mapping that never stops iterating."""

    def __getitem__(self, key):
        return 1

    def __iter__(self):
        n = 0
        while True:
            n += 1
            yield f"k{n}"

    def __len__(self):
        return 1


class Text(str):
    def __str__(self):
        return "other"


class Counting(FixedJudge):
    calls = 0

    def score(self, *a, **kw):
        Counting.calls += 1
        return super().score(*a, **kw)


class ToPlain(unittest.TestCase):
    def test_copies_into_builtin_types(self):
        out = to_plain(Small({"a": (1, Small({"b": [Text("t"), 2.5, None, True]}))}))
        self.assertEqual(out, {"a": [1, {"b": ["t", 2.5, None, True]}]})
        self.assertIs(type(out), dict)
        self.assertIs(type(out["a"]), list)
        self.assertIs(type(out["a"][1]["b"][0]), str)

    def test_refusals(self):
        with self.assertRaisesRegex(EncodingError, "^canonical object keys must be strings$"):
            to_plain(Small({1: "x"}))
        with self.assertRaisesRegex(EncodingError, "^unsupported_type$"):
            to_plain({"a": object()})
        with self.assertRaisesRegex(EncodingError, "^tool args are nested too deeply$"):
            to_plain({"a": {"b": 1}}, max_depth=1, what="tool args are")
        with self.assertRaisesRegex(OversizeError, "^value is too large$"):
            to_plain(Endless(), max_items=1000)

    def test_sizer_never_measures_str_or_repr(self):
        self.assertTrue(args_too_large(Small({"q": "x"})))   # not JSON: unmeasurable, so too large
        self.assertFalse(args_too_large(to_plain(Small({"q": "x"}))))


class Inputs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, key, SPECS)
        Counting.calls = 0
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), key), key.public_key(),
                         verify_signed(env, key.public_key()), [Counting("a", "yes")], private_key=key,
                         quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)
        self.received = []
        self.gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled,
                              tools={"search": lambda a: self.received.append(a) or "ok"})

    def ledger_text(self):
        return json.dumps([e.body for e in self.tk.ledger.entries])

    def assert_denied(self, d, reason, name, cap):
        self.assertEqual((d.allowed, d.reason, d.token), (False, reason, None))
        body = self.tk.ledger.entries[-1].body
        self.assertEqual(body["reason"], reason)
        self.assertTrue(body[f"{name}_omitted"])
        self.assertGreater(body[f"{name}_size"], cap)
        self.assertRegex(body[f"{name}_digest"], "^sha256:")
        self.assertNotIn("AAAA", self.ledger_text())
        self.assertEqual(Counting.calls, 0)

    def test_big_mapping_args_top_level_and_nested(self):
        for args in (Small({"q": BIG}), {"q": Small({"x": BIG})}, {"q": [Small({"x": BIG})]}):
            with self.subTest(kind=type(args).__name__):
                self.assert_denied(self.tk.authorize(SEARCH, args, "look it up"), "args_too_large", "tool_args",
                                   MAX_ARGS_BYTES)

    def test_big_mapping_claim_top_level_and_nested(self):
        for claim in (Small({**SEARCH, "destination": BIG}), {**SEARCH, "raw": Small({"x": BIG})},
                      {**SEARCH, "raw": {"y": Small({"x": BIG})}},
                      Action(tool="search", data_class="public", raw=Small({"y": Small({"x": BIG})}))):
            with self.subTest(kind=type(claim).__name__):
                self.assert_denied(self.tk.authorize(claim, {"q": "x"}, "look it up"), "action_too_large", "action",
                                   MAX_ACTION_BYTES)

    def test_big_mapping_proposal(self):
        self.assert_denied(self.tk.authorize(SEARCH, {"q": "x"}, Small({"p": BIG})), "proposal_too_large",
                           "proposal", MAX_ARGS_BYTES)

    def test_endless_mapping_is_too_large_not_a_hang(self):
        d = self.tk.authorize(SEARCH, {"q": Endless()}, "look it up")
        self.assertEqual((d.allowed, d.reason), (False, "args_too_large"))
        self.assertEqual(self.tk.ledger.entries[-1].body["tool_args_size"], -1)
        d = self.tk.authorize({**SEARCH, "raw": Endless()}, {"q": "x"}, "look it up")
        self.assertEqual((d.allowed, d.reason), (False, "action_too_large"))

    def test_small_mapping_args_are_bound_and_delivered_as_the_copy(self):
        for args in (Small({"q": "weather"}), {"q": Small({"city": Text("oslo")})}):
            with self.subTest(kind=type(args).__name__):
                plain = to_plain(args)
                d = self.tk.authorize(SEARCH, args, "look it up")
                self.assertTrue(d.allowed, d.reason)
                self.assertEqual(self.tk.issuer.verify(d.token)["args_hash"], args_hash(plain))
                r = self.gw.invoke(d.token, "search", args)
                self.assertTrue(r.allowed, r.reason)
                self.assertEqual(self.received[-1], plain)
                self.assertIs(type(self.received[-1]), dict)
        # The same token cannot be redeemed with a Mapping that reads differently: its copy is hashed.
        d = self.tk.authorize(SEARCH, {"q": Small({"city": "oslo"})}, "look it up")
        self.assertEqual(self.gw.invoke(d.token, "search", {"q": Small({"city": "bergen"})}).reason, "args_mismatch")

    def test_gateway_big_mapping_args_top_level_and_nested(self):
        for args in (Small({"q": BIG}), {"q": Small({"x": BIG})}):
            with self.subTest(kind=type(args).__name__):
                d = self.tk.authorize(SEARCH, {"q": "x"}, "look it up")
                r = self.gw.invoke(d.token, "search", args)
                self.assertEqual((r.allowed, r.reason), (False, "args_too_large"))
                entry = self.tk.ledger.entries[-1]
                self.assertEqual(entry.kind, "gateway_denied")
                self.assertGreater(entry.body["tool_args_size"], MAX_ARGS_BYTES)
                self.assertNotIn("AAAA", self.ledger_text())
        self.assertEqual(self.received, [])

    def test_gateway_endless_mapping(self):
        d = self.tk.authorize(SEARCH, {"q": "x"}, "look it up")
        r = self.gw.invoke(d.token, "search", {"q": Endless()})
        self.assertEqual((r.allowed, r.reason), (False, "args_too_large"))
        body = self.tk.ledger.entries[-1].body
        self.assertEqual((body["tool_args_size"], body["tool_args_digest"]), (-1, None))


if __name__ == "__main__":
    unittest.main()
