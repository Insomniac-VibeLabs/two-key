# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Re-review: tool arguments and the proposal over MAX_ARGS_BYTES (UTF-8 bytes of their JSON) are denied
before anything is derived, judged, or ledgered; the ledger keeps only the size and digest."""

import json
import tempfile
import time
import unittest
from pathlib import Path

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import MAX_ARGS_BYTES, args_size, args_too_large
from two_key.gateway import ToolGateway
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


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


class Size(unittest.TestCase):
    def test_measure_is_utf8_bytes(self):
        self.assertEqual(MAX_ARGS_BYTES, 262144)
        self.assertEqual(args_size({"q": "\U0001F600"}), len('{"q":"\U0001F600"}'.encode()))  # compact JSON
        self.assertTrue(args_too_large({"q": "\U0001F600" * (MAX_ARGS_BYTES // 4)}))  # under the cap in chars
        self.assertFalse(args_too_large({"q": "x" * (MAX_ARGS_BYTES - 20)}))

        class Unmeasurable:
            def __repr__(self):
                raise RecursionError

        self.assertTrue(args_too_large({"q": Unmeasurable()}))  # cannot be measured: fail closed

    def test_oversized_args_denied_before_judges_and_only_size_ledgered(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(tmp)
            Counting.calls = 0
            big = {"q": "\ufdfa" * 100_000}  # 300,000 bytes, 100,000 chars
            start = time.time()
            d = tk.authorize(SEARCH, big, "look")
            self.assertLess(time.time() - start, 1.0)
            self.assertEqual((d.allowed, d.reason, d.token), (False, "args_too_large", None))
            self.assertEqual(Counting.calls, 0)
            body = tk.ledger.entries[-1].body
            self.assertEqual(tk.ledger.entries[-1].kind, "decision")
            self.assertTrue(body["tool_args_omitted"])
            self.assertEqual(body["tool_args_size"], args_size(big))
            self.assertTrue(body["tool_args_digest"].startswith("sha256:"))
            self.assertNotIn("\ufdfa", json.dumps([e.body for e in tk.ledger.entries], ensure_ascii=False))
            self.assertNotIn("proposal", [e.kind for e in tk.ledger.entries])
            self.assertTrue(tk.authorize(SEARCH, {"q": "x"}, "look").allowed)
            deep = "x"
            for _ in range(5000):
                deep = {"a": deep}
            self.assertFalse(tk.authorize(SEARCH, {"q": deep}, "look").allowed)  # a deny, never an exception

    def test_oversized_proposal_is_denied_and_not_ledgered(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(tmp)
            d = tk.authorize(SEARCH, {"q": "x"}, "p" * (MAX_ARGS_BYTES + 1))
            self.assertEqual(d.reason, "proposal_too_large")
            body = tk.ledger.entries[-1].body
            self.assertTrue(body["proposal_omitted"])
            self.assertNotIn("p" * 1000, json.dumps([e.body for e in tk.ledger.entries]))

    def test_gateway_refuses_oversized_args_before_hashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(tmp)
            d = tk.authorize(SEARCH, {"q": "x"}, "look")
            gw = ToolGateway(tk.ledger, tk.issuer.verifier(), tk.compiled, tools={"search": lambda a: a})
            self.assertEqual(gw.invoke(d.token, "search", {"q": "x" * (MAX_ARGS_BYTES + 1)}).reason, "args_too_large")
            self.assertTrue(gw.invoke(d.token, "search", {"q": "x"}).allowed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
