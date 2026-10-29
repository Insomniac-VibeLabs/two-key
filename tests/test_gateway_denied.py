# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Gateway refusals of an authenticated token are ledgered as gateway_denied: reason, jti, tool, size, digest."""

import json
import tempfile
import threading
import unittest
from unittest import mock
from pathlib import Path

from two_key.agent_meta import MAX_LEDGER_ERROR_CHARS
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import MAX_ARGS_BYTES
from two_key.gateway import ToolGateway
from two_key.keys import generate_private_key
from two_key.ledger import Ledger, LedgerError
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}
SECRET = "zz-secret-argument-value-zz"


def nest(n):
    v = 1
    for _ in range(n):
        v = {"x": v}
    return v


class GatewayDenied(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, key, SPECS)
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), key), key.public_key(),
                         verify_signed(env, key.public_key()), [FixedJudge("a", "yes")], private_key=key,
                         quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)
        self.gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled, tools={"search": lambda a: "ok"})
        d = self.tk.authorize(SEARCH, {"q": "weather"}, "look")
        self.assertTrue(d.allowed, d.reason)
        self.token = d.token

    def denied(self):
        return [e.body for e in self.tk.ledger.entries if e.kind == "gateway_denied"]

    def ledger_text(self):
        return json.dumps([e.body for e in self.tk.ledger.entries])

    def test_unauthenticated_tokens_write_nothing(self):
        before = self.tk.ledger.size()
        for token in ("garbage", "tk2.e30.AAAA", self.token[:-4] + "AAAA", None):
            self.assertFalse(self.gw.invoke(token, "search", {"q": "x"}).allowed)
        self.assertEqual(self.tk.ledger.size(), before)

    def test_args_mismatch_is_ledgered_without_values(self):
        r = self.gw.invoke(self.token, "search", {"q": SECRET})
        self.assertEqual(r.reason, "args_mismatch")
        [body] = self.denied()
        self.assertEqual(body["reason"], "args_mismatch")
        self.assertEqual(body["tool"], "search")
        self.assertEqual(len(body["jti"]), 32)
        self.assertTrue(body["tool_args_digest"].startswith("sha256:"))
        self.assertGreater(body["tool_args_size"], 0)
        self.assertNotIn(SECRET, self.ledger_text())

    def test_huge_tool_name_is_recorded_by_size_and_digest(self):
        big = "t" * (1 << 20)
        r = self.gw.invoke(self.token, big, {"q": "weather"})
        self.assertEqual(r.reason, "tool_mismatch")
        [body] = self.denied()
        self.assertIsNone(body["tool"])
        self.assertGreater(body["tool_size"], 1 << 20)
        self.assertLess(len(self.ledger_text()), 100_000)

    def test_oversized_and_deep_arguments(self):
        self.assertEqual(self.gw.invoke(self.token, "search", {"q": SECRET * (MAX_ARGS_BYTES // 10)}).reason,
                         "args_too_large")
        # Same jti: second deny still refuses but does not append another gateway_denied (#12).
        self.assertEqual(self.gw.invoke(self.token, "search", {"q": nest(5000)}).reason,
                         "invalid_call:tool args are nested too deeply")
        [big] = self.denied()
        self.assertEqual(big["reason"], "args_too_large")
        self.assertGreater(big["tool_args_size"], MAX_ARGS_BYTES)
        self.assertNotIn(SECRET, self.ledger_text())

    def test_replay_is_ledgered_and_success_is_not_a_deny(self):
        self.assertTrue(self.gw.invoke(self.token, "search", {"q": "weather"}).allowed)
        self.assertEqual(self.denied(), [])
        self.assertEqual(self.gw.invoke(self.token, "search", {"q": "weather"}).reason, "already_redeemed")
        self.assertEqual([b["reason"] for b in self.denied()], ["already_redeemed"])
        # Further replays of the same jti still deny but do not flood the ledger (#12).
        self.assertEqual(self.gw.invoke(self.token, "search", {"q": "weather"}).reason, "already_redeemed")
        self.assertEqual(len(self.denied()), 1)
        self.tk.ledger.verify()

    def test_per_jti_throttle_stops_repeat_appends(self):
        r1 = self.gw.invoke(self.token, "search", {"q": SECRET})
        r2 = self.gw.invoke(self.token, "search", {"q": SECRET})
        self.assertEqual(r1.reason, r2.reason)
        self.assertEqual(len(self.denied()), 1)

    def test_append_failure_does_not_mark_jti_so_retry_can_ledger(self):
        """#16: mark-after-append — a failed deny ledger write leaves jti unmarked."""
        real_append = self.tk.ledger.append_bounded
        calls = {"n": 0}

        def flaky(kind, body):
            calls["n"] += 1
            if calls["n"] == 1 and kind == "gateway_denied":
                raise OSError("disk full")
            return real_append(kind, body)

        with mock.patch.object(self.tk.ledger, "append_bounded", side_effect=flaky):
            r1 = self.gw.invoke(self.token, "search", {"q": SECRET})
        self.assertTrue(r1.reason.startswith("ledger_failed:"))
        self.assertEqual(self.denied(), [])  # first append failed
        # Later deny with working ledger can append.
        r2 = self.gw.invoke(self.token, "search", {"q": SECRET})
        self.assertEqual(r2.reason, "args_mismatch")
        self.assertEqual(len(self.denied()), 1)

    def test_denied_jtis_hard_cap(self):
        """#16: remembered denied jtis do not grow past the configured cap."""
        # Rebuild gateway with a tiny cap; mint many tokens with distinct jtis.
        gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled,
                         tools={"search": lambda a: "ok"}, max_denied_jtis=3)
        tokens = []
        for i in range(5):
            d = self.tk.authorize(SEARCH, {"q": f"weather-{i}"}, "look")
            self.assertTrue(d.allowed, d.reason)
            tokens.append(d.token)
        for tok in tokens:
            r = gw.invoke(tok, "search", {"q": SECRET})
            self.assertEqual(r.reason, "args_mismatch")
        self.assertLessEqual(len(gw._denied_jtis), 3)
        # Cap is hard: exactly at most 3 remembered after 5 distinct denies.
        self.assertEqual(len(gw._denied_jtis), 3)

    def test_max_denied_jtis_zero_clamped_no_keyerror(self):
        """#22: max_denied_jtis=0 clamps to 1; deny succeeds without KeyError."""
        gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled,
                         tools={"search": lambda a: "ok"}, max_denied_jtis=0)
        self.assertEqual(gw._max_denied_jtis, 1)
        r = gw.invoke(self.token, "search", {"q": SECRET})
        self.assertEqual(r.reason, "args_mismatch")
        self.assertEqual(len(self.denied()), 1)
        self.assertEqual(len(gw._denied_jtis), 1)
        # Second distinct jti: LRU drops the first (cap 1), no KeyError.
        d2 = self.tk.authorize(SEARCH, {"q": "other"}, "look")
        self.assertTrue(d2.allowed, d2.reason)
        r2 = gw.invoke(d2.token, "search", {"q": SECRET})
        self.assertEqual(r2.reason, "args_mismatch")
        self.assertEqual(len(gw._denied_jtis), 1)

    def test_max_denied_jtis_negative_clamped(self):
        """#22: negative max_denied_jtis also clamps to 1."""
        gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled,
                         tools={"search": lambda a: "ok"}, max_denied_jtis=-5)
        self.assertEqual(gw._max_denied_jtis, 1)

    def test_same_jti_concurrent_denies_single_gateway_denied(self):
        """#23: concurrent same-jti denies yield at most one gateway_denied row."""
        barrier = threading.Barrier(8)
        results = []
        errors = []

        def worker():
            try:
                barrier.wait(timeout=5)
                results.append(self.gw.invoke(self.token, "search", {"q": SECRET}))
            except Exception as e:  # noqa: BLE001 — collect for assertion
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        for r in results:
            self.assertEqual(r.reason, "args_mismatch")
        self.assertEqual(len(self.denied()), 1)

    def test_huge_redemption_ledger_failed_is_capped(self):
        """#21: gateway redemption ledger_failed:{e} message is capped."""
        mark = "ZQXGW"
        huge = mark + "G" * (5 << 20)
        real_append = self.tk.ledger.append_bounded

        def boom(kind, body):
            if kind == "redemption_started":
                raise LedgerError(huge)
            return real_append(kind, body)

        with mock.patch.object(self.tk.ledger, "append_bounded", side_effect=boom):
            r = self.gw.invoke(self.token, "search", {"q": "weather"})
        self.assertTrue(r.reason.startswith("ledger_failed:"), r.reason)
        self.assertIn(mark, r.reason)
        self.assertIn("…sha256:", r.reason)
        self.assertLess(len(r.reason), len("ledger_failed:") + MAX_LEDGER_ERROR_CHARS + 80)
        self.assertNotIn("G" * 1000, r.reason)


    def test_deny_inflight_wait_timeout_fail_closed(self):
        """#25: if append hangs, same-jti waiter times out; still deny, no mark, no fail-open."""
        entered = threading.Event()
        release = threading.Event()
        real_append = self.tk.ledger.append_bounded
        results_first = []

        def slow(kind, body):
            if kind == "gateway_denied":
                entered.set()
                if not release.wait(timeout=10):
                    raise TimeoutError("release never set")
            return real_append(kind, body)

        gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled,
                         tools={"search": lambda a: "ok"},
                         deny_inflight_wait_seconds=0.15)

        def first():
            with mock.patch.object(self.tk.ledger, "append_bounded", side_effect=slow):
                results_first.append(gw.invoke(self.token, "search", {"q": SECRET}))

        t = threading.Thread(target=first)
        t.start()
        self.assertTrue(entered.wait(timeout=5), "first deny never entered append")
        # Waiter must return quickly (timeout), still deny, and must not mark jti.
        r2 = gw.invoke(self.token, "search", {"q": SECRET})
        self.assertFalse(r2.allowed)
        self.assertEqual(r2.reason, "args_mismatch")
        self.assertEqual(len(gw._denied_jtis), 0)
        self.assertEqual(self.denied(), [])  # first append still blocked
        release.set()
        t.join(timeout=5)
        self.assertFalse(t.is_alive())
        self.assertEqual(len(results_first), 1)
        self.assertEqual(results_first[0].reason, "args_mismatch")
        # After the hung append completes, jti is marked and one gateway_denied exists.
        self.assertEqual(len(self.denied()), 1)
        self.assertEqual(len(gw._denied_jtis), 1)



    def test_deny_inflight_wait_nonfinite_falls_back_to_default(self):
        """#28: inf/nan (and <=0) for deny_inflight_wait_seconds fall back to 30s."""
        from two_key.gateway import _DENY_INFLIGHT_WAIT_SECONDS

        for bad in (float("inf"), float("-inf"), float("nan"), 0, -1, -0.5):
            gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled,
                             tools={"search": lambda a: "ok"},
                             deny_inflight_wait_seconds=bad)
            self.assertEqual(gw._deny_inflight_wait_seconds, _DENY_INFLIGHT_WAIT_SECONDS)
            self.assertEqual(gw._deny_inflight_wait_seconds, 30.0)

    def test_deny_inflight_wait_finite_positive_is_kept(self):
        """#28: a finite positive wait is accepted as-is."""
        gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled,
                         tools={"search": lambda a: "ok"},
                         deny_inflight_wait_seconds=12.5)
        self.assertEqual(gw._deny_inflight_wait_seconds, 12.5)


if __name__ == "__main__":
    unittest.main()
