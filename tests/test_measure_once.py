# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Arguments are encoded once per authorize and once per gateway call; the cap still measures UTF-8 compact JSON."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from two_key import canonical as canonical_mod
from two_key import derive as derive_mod
from two_key.canonical import canonical_bytes, canonical_hash
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import MAX_ARGS_BYTES, args_too_large, canonical_too_large
from two_key.gateway import ToolGateway
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


class Shortcut(unittest.TestCase):
    def test_agrees_with_the_exact_measure(self):
        for value in ({"q": "x" * (MAX_ARGS_BYTES - 8)}, {"q": "x" * MAX_ARGS_BYTES},
                      {"q": "\u00e9" * (MAX_ARGS_BYTES // 3)}, {"q": "\u00e9" * (MAX_ARGS_BYTES // 2)},
                      {"q": "\U0001F600" * (MAX_ARGS_BYTES // 5)}, {}):
            with self.subTest(size=len(json.dumps(value))):
                self.assertEqual(canonical_too_large(canonical_bytes(value), value), args_too_large(value))

    def test_no_second_encoding_under_the_cap(self):
        value = {"q": "\u00e9" * 1000}
        with mock.patch.object(derive_mod, "_json_bytes", side_effect=AssertionError("measured twice")):
            self.assertFalse(canonical_too_large(canonical_bytes(value), value))


class EncodedOnce(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, key, SPECS)
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), key), key.public_key(),
                         verify_signed(env, key.public_key()), [FixedJudge("a", "yes")], private_key=key,
                         quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)

    def count_arg_encodings(self, fn, args):  # skipcq: PYL-R0201 - test only
        real = canonical_mod.canonical_bytes
        seen = []

        def spy(value, **kw):
            if value == args:   # the plain copy of args, not the caller's object
                seen.append(1)
            return real(value, **kw)
        real_size = derive_mod._json_bytes
        sized, hashed = [], []

        def size_spy(value):
            if value == args:   # the plain copy of args, not the caller's object
                sized.append(1)
            return real_size(value)

        def hash_spy(value):
            if value == args:   # the plain copy of args, not the caller's object
                hashed.append(1)
            return canonical_hash(value)
        with mock.patch("two_key.core.canonical_bytes", spy), mock.patch("two_key.gateway.canonical_bytes", spy), \
                mock.patch("two_key.capability.canonical_hash", hash_spy), \
                mock.patch.object(derive_mod, "_json_bytes", size_spy):
            result = fn()
        return result, len(seen), len(hashed) + len(sized)

    def test_authorize_encodes_the_arguments_once(self):
        args = {"q": "weather"}
        d, encodes, rehashes = self.count_arg_encodings(lambda: self.tk.authorize(SEARCH, args, "look"), args)
        self.assertTrue(d.allowed, d.reason)
        self.assertEqual((encodes, rehashes), (1, 0))

    def test_gateway_encodes_the_arguments_once(self):
        args = {"q": "weather"}
        d = self.tk.authorize(SEARCH, args, "look")
        gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled, tools={"search": lambda a: "ok"})
        r, encodes, _ = self.count_arg_encodings(lambda: gw.invoke(d.token, "search", args), args)
        self.assertTrue(r.allowed, r.reason)
        self.assertEqual(encodes, 1)


if __name__ == "__main__":
    unittest.main()
