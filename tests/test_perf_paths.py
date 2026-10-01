"""Hot-path properties: parallel judges with a deadline, no network in the gateway path,
incremental Merkle root, and configurable / per-decision signed-head checkpoints."""
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from two_key import merkle
from two_key.action import normalize_action
from two_key.judges.base import Ballot, Judge
from two_key.judges.config import load_config
from two_key.ledger import PersonalLedger
from two_key.quorum import QuorumConfigError, QuorumPolicy, convene
from two_key.testing import FixedJudge
from two_key import keys
from helpers import TwoKeyFixture

A = normalize_action({"tool": "search"})
RULES = [{"id": "tools", "allow_only_tools": ["pay_bill"]}]
YES = [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2")]
PAY = {"tool": "pay_bill", "amount_usd": 10, "counterparty": "power-co.example", "data_class": "financial"}
PAY_ARGS = {"payee": "power-co.example", "amount": 10}
PAY_FIELDS = {"amount_usd": 10, "counterparty": "power-co.example", "data_class": "financial"}


class SlowJudge(Judge):
    is_test_double = True

    def __init__(self, judge_id, delay, vote="yes", provider="slow"):
        self.judge_id, self.delay, self.vote, self.provider = judge_id, delay, vote, provider
        self.threads = []

    def score(self, constitution_text, action, proposal):
        self.threads.append(threading.current_thread().name)
        time.sleep(self.delay)
        return Ballot(self.judge_id, self.provider, self.vote, 0.9, "slow")


class ParallelJudges(unittest.TestCase):
    def test_judges_run_in_parallel(self):
        js = [SlowJudge(f"j{i}", 0.3, provider=f"p{i}") for i in range(3)]
        t0 = time.perf_counter()
        q = convene(js, "c", A, "p", QuorumPolicy(required_yes=3, timeout_seconds=5))
        elapsed = time.perf_counter() - t0
        self.assertTrue(q.passed, q.reason)
        self.assertLess(elapsed, 0.75, "3 x 0.3 s judges should overlap, not run back to back")
        self.assertEqual([b.judge_id for b in q.ballots], ["j0", "j1", "j2"])  # order preserved
        self.assertTrue(all(j.threads[0].startswith("twokey-judge") for j in js))

    def test_timeout_counts_as_abstain_and_returns_promptly(self):
        js = [FixedJudge("fast", "yes"), SlowJudge("hung", 3.0)]
        t0 = time.perf_counter()
        q = convene(js, "c", A, "p", QuorumPolicy(required_yes=2, timeout_seconds=0.2))
        self.assertLess(time.perf_counter() - t0, 1.0)
        self.assertFalse(q.passed)
        hung = q.ballots[1]
        self.assertEqual(hung.vote, "abstain")
        self.assertTrue(hung.error.startswith("timeout"))
        self.assertEqual(q.reason, "insufficient_responses:1<2")

    def test_timeout_with_enough_other_judges_passes(self):
        js = [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2"), SlowJudge("hung", 3.0)]
        q = convene(js, "c", A, "p", QuorumPolicy(required_yes=2, timeout_seconds=0.2))
        self.assertTrue(q.passed)
        self.assertEqual((q.yes, q.abstain), (2, 1))

    def test_sequential_mode_still_available(self):
        q = convene(YES, "c", A, "p", QuorumPolicy(required_yes=2, timeout_seconds=None, parallel=False))
        self.assertTrue(q.passed)

    def test_policy_validation_and_config(self):
        for bad in (0, -1, "5", True):
            with self.assertRaises(QuorumConfigError):
                QuorumPolicy(timeout_seconds=bad)
        _, pol = load_config({"judges": [{"id": "l", "type": "ollama", "model": "m"}],
                              "quorum": {"required_yes": 1, "timeout_seconds": 12.5}})
        self.assertEqual(pol.timeout_seconds, 12.5)


class NoNetworkInGatewayPath(unittest.TestCase):
    def test_authorize_and_invoke_make_no_network_calls(self):
        def boom(*a, **kw):
            raise AssertionError("network access attempted in the Two-Key/gateway hot path")

        with TwoKeyFixture(RULES, YES) as tk:
            gw = tk.gateway(tools={"pay_bill": lambda **a: "paid"})
            with mock.patch.object(socket, "socket", boom), mock.patch.object(socket, "create_connection", boom), \
                    mock.patch.object(socket, "getaddrinfo", boom):
                d = tk.authorize(PAY, "Pay.", PAY_ARGS)
                self.assertTrue(d.allowed, d.reason)
                self.assertEqual(gw.invoke(d.capability, "pay_bill", PAY_ARGS, PAY_FIELDS).reason, "executed")


class MerkleAndCheckpoints(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_frontier_matches_recursive_root(self):
        import hashlib
        for h in (merkle._sha256, lambda b: hashlib.sha384(b).digest()):
            f = merkle.MerkleFrontier(h)
            leaves = []
            for n in range(0, 70):
                self.assertEqual(f.root(), merkle.root(leaves, h), n)
                leaf = os.urandom(32)
                leaves.append(leaf)
                f.append(leaf)

    def test_auto_sign_every_and_checkpoint(self):
        key = keys.generate_private_key()
        L = PersonalLedger(self.d / "l.jsonl", signing_key=key, auto_sign_every=0, fsync=False)
        for i in range(4):
            L.append("e", {"i": i})
        self.assertFalse(L.head_path.exists())
        self.assertEqual(L.unsigned_entries, 4)
        self.assertTrue(L.checkpoint())
        self.assertFalse(L.checkpoint())  # nothing new to cover
        self.assertEqual(PersonalLedger(self.d / "l.jsonl").verify(key.public_key()).reason, "ok")

        L3 = PersonalLedger(self.d / "l3.jsonl", signing_key=key, auto_sign_every=3)
        with mock.patch.object(L3, "_write_head", wraps=L3._write_head) as w:
            for i in range(7):
                L3.append("e", {"i": i})
            self.assertEqual(w.call_count, 2)
        with self.assertRaises(ValueError):
            PersonalLedger(self.d / "x.jsonl", auto_sign_every=-1)

    def test_two_key_signs_one_head_per_decision(self):
        with TwoKeyFixture(RULES, YES) as tk:
            with mock.patch.object(tk.ledger, "_write_head", wraps=tk.ledger._write_head) as w:
                d = tk.authorize(PAY, "Pay.", PAY_ARGS)
                self.assertTrue(d.allowed)
                self.assertEqual(w.call_count, 1)
                tk.gateway().invoke(d.capability, "pay_bill", PAY_ARGS, PAY_FIELDS)
                self.assertEqual(w.call_count, 2)
            self.assertEqual(tk.ledger.unsigned_entries, 0)
            self.assertEqual(tk.ledger.verify(tk.trusted_public_key).reason, "ok")

    def test_gateway_checkpoint_every(self):
        with TwoKeyFixture(RULES, YES) as tk:
            gw = tk.gateway(checkpoint_every=0)
            decs = [tk.authorize(PAY, "Pay.", PAY_ARGS) for _ in range(3)]
            for d in decs:
                gw.invoke(d.capability, "pay_bill", PAY_ARGS, PAY_FIELDS)
            self.assertEqual(tk.ledger.unsigned_entries, 3)  # one capability_redeemed per call, unsigned
            self.assertTrue(tk.ledger.verify(tk.trusted_public_key).reason.startswith("size_mismatch"))
            tk.ledger.checkpoint()
            self.assertEqual(tk.ledger.verify(tk.trusted_public_key).reason, "ok")
            with self.assertRaises(ValueError):
                tk.gateway(checkpoint_every=-1)

    def test_two_key_per_append_mode(self):
        with TwoKeyFixture(RULES, YES, head_signing="append") as tk:
            with mock.patch.object(tk.ledger, "_write_head", wraps=tk.ledger._write_head) as w:
                n0 = len(tk.ledger.entries)
                tk.authorize(PAY, "Pay.", PAY_ARGS)
                self.assertEqual(w.call_count, len(tk.ledger.entries) - n0)

    def test_checkpoint_failure_denies_and_withholds_token(self):
        with TwoKeyFixture(RULES, YES) as tk:
            with mock.patch.object(tk.ledger, "checkpoint", side_effect=OSError("disk full")):
                d = tk.authorize(PAY, "Pay.", PAY_ARGS)
            self.assertFalse(d.allowed)
            self.assertIsNone(d.capability)
            self.assertIn("ledger_checkpoint", d.reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
