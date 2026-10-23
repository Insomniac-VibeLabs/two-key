# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""#42: the gateway's per-jti lock map holds only jtis in flight; each entry is removed after redemption."""

import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.gateway import ToolGateway
from two_key.keys import generate_private_key
from two_key.ledger import Ledger, LedgerError
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


class GatewayLocks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, key, SPECS)
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), key), key.public_key(),
                         verify_signed(env, key.public_key()), [FixedJudge("a", "yes")], private_key=key,
                         quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)

    def token(self, q="weather"):
        d = self.tk.authorize(SEARCH, {"q": q}, "look")
        self.assertTrue(d.allowed, d.reason)
        return d.token

    def gateway(self, fn=lambda a: "ok"):
        return ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled, tools={"search": fn})

    def assert_empty(self, gw):
        self.assertEqual(len(gw._locks), 0)
        self.assertEqual(len(gw._lock_refs), 0)

    def test_sequential_redemptions_leave_no_entries(self):
        tokens = [(self.token(f"q{i}"), f"q{i}") for i in range(5)]
        gw = self.gateway()
        for token, q in tokens:
            self.assertEqual(gw.invoke(token, "search", {"q": q}).reason, "redeemed")
        self.assert_empty(gw)

    def test_replay_and_mismatch_leave_no_entries(self):
        token = self.token()
        gw = self.gateway()
        self.assertEqual(gw.invoke(token, "search", {"q": "weather"}).reason, "redeemed")
        self.assertEqual(gw.invoke(token, "search", {"q": "weather"}).reason, "already_redeemed")
        self.assertEqual(gw.invoke(token, "search", {"q": "other"}).reason, "args_mismatch")
        self.assert_empty(gw)

    def test_concurrent_same_jti(self):
        token = self.token()
        entered = threading.Event()
        release = threading.Event()

        def slow(args):
            entered.set()
            release.wait(5)
            return "ok"

        gw = self.gateway(slow)
        start = threading.Barrier(8)
        reasons = []
        guard = threading.Lock()

        def run():
            start.wait()
            r = gw.invoke(token, "search", {"q": "weather"})
            with guard:
                reasons.append(r.reason)

        threads = [threading.Thread(target=run) for _ in range(8)]
        for t in threads:
            t.start()
        self.assertTrue(entered.wait(5))
        release.set()
        for t in threads:
            t.join(10)
        self.assertEqual(len(reasons), 8)
        self.assertEqual(reasons.count("redeemed"), 1, reasons)
        self.assertTrue(all(r in ("redeemed", "already_redeemed", "already_attempted") for r in reasons), reasons)
        self.assert_empty(gw)

    def test_entry_is_shared_while_held(self):
        token = self.token()
        seen = {}

        def tool(args):
            seen["locks"], seen["refs"] = len(gw._locks), dict(gw._lock_refs)
            return "ok"

        gw = self.gateway(tool)
        self.assertEqual(gw.invoke(token, "search", {"q": "weather"}).reason, "redeemed")
        self.assertEqual(seen["locks"], 1)
        self.assertEqual(list(seen["refs"].values()), [1])
        self.assert_empty(gw)

    def test_tool_that_raises_still_removes_the_entry(self):
        token = self.token()

        def boom(args):
            raise RuntimeError("tool failed")

        gw = self.gateway(boom)
        self.assertEqual(gw.invoke(token, "search", {"q": "weather"}).reason, "tool_error:RuntimeError")
        self.assert_empty(gw)
        gw.tools["search"] = lambda a: "ok"
        self.assertEqual(gw.invoke(token, "search", {"q": "weather"}).reason, "redeemed")
        self.assert_empty(gw)

    def test_lock_file_failure_removes_the_entry(self):
        token = self.token()
        gw = self.gateway()
        with mock.patch.object(type(self.tk.ledger), "redeem_lock_path", side_effect=LedgerError("no lock dir")):
            with self.assertRaises(LedgerError):
                gw.invoke(token, "search", {"q": "weather"})
        self.assert_empty(gw)
        self.assertEqual(gw.invoke(token, "search", {"q": "weather"}).reason, "redeemed")
        self.assert_empty(gw)


if __name__ == "__main__":
    unittest.main()
