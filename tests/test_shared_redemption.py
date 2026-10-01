"""Single use is shared by every gateway on one kernel/ledger (Stephan's instruction, 2026-09-30 evening).

Before this fix each ToolGateway kept its own used-token set, rebuilt from the ledger only when the gateway
was created, so two live gateways on one kernel would each accept the same token once. The used-token record
now lives in PersonalLedger (``redeem``), under the ledger's lock, and on POSIX also under an flock on the
ledger file. These tests cover: two gateways, concurrent threads, restart persistence, and a second ledger
instance / second process on the same file.
"""
import multiprocessing
import os
import tempfile
import threading
import unittest
from pathlib import Path

from compact_kernel.gateway import ToolGateway
from compact_kernel.ledger import LedgerError, PersonalLedger
from compact_kernel.quorum import QuorumPolicy
from compact_kernel.testing import FixedJudge
from helpers import KernelFixture

try:
    import fcntl  # noqa: F401
except ImportError:  # pragma: no cover
    fcntl = None

RULES = [{"id": "tools", "allow_only_tools": ["pay_bill"]}, {"id": "cap", "deny_if": {"amount_usd_gt": 200}}]
YES = [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2")]
PAY = {"tool": "pay_bill", "amount_usd": 42.5, "counterparty": "power-co.example", "data_class": "financial",
       "irreversible": False}
ARGS = {"payee": "power-co.example", "amount": 42.5, "invoice": "INV-7"}
FIELDS = {"amount_usd": 42.5, "counterparty": "power-co.example", "data_class": "financial"}


def redemptions(ledger, jti):
    return [e for e in ledger.entries if e.kind == "capability_redeemed" and e.body.get("jti") == jti]


class Base(unittest.TestCase):
    def setUp(self):
        self.fx = KernelFixture(RULES, YES, quorum_policy=QuorumPolicy(required_yes=2))
        self.k = self.fx.__enter__()
        self.calls = []
        self._calls_lock = threading.Lock()

    def tearDown(self):
        self.fx.__exit__(None, None, None)

    def tool(self, **a):
        with self._calls_lock:
            self.calls.append(a)
        return "paid"

    def token(self, invoice="INV-7"):
        args = dict(ARGS, invoice=invoice)
        d = self.k.authorize(PAY, "Pay the electric bill.", args)
        self.assertTrue(d.allowed, d.reason)
        return d, args


class TwoGateways(Base):
    def test_two_gateways_same_token_only_first_accepted(self):
        g1, g2 = self.k.gateway(tools={"pay_bill": self.tool}), self.k.gateway(tools={"pay_bill": self.tool})
        d, args = self.token()  # both gateways exist before the token is issued or redeemed
        r1 = g1.invoke(d.capability, "pay_bill", args, FIELDS)
        r2 = g2.invoke(d.capability, "pay_bill", args, FIELDS)
        self.assertEqual((r1.allowed, r1.reason), (True, "executed"))
        self.assertEqual((r2.allowed, r2.reason), (False, "replayed"))
        self.assertEqual(len(self.calls), 1)
        jti = d.token_payload["jti"]
        self.assertEqual(len(redemptions(self.k.ledger, jti)), 1)
        self.assertEqual(self.k.ledger.entries[-1].kind, "gateway_denied")
        self.assertEqual(self.k.ledger.entries[-1].body["reason"], "replayed")
        self.assertTrue(self.k.ledger.verify(self.fx.key.public_key()).ok)

    def test_order_does_not_matter_and_new_gateway_sees_it(self):
        d, args = self.token()
        g2 = self.k.gateway(tools={"pay_bill": self.tool})
        self.assertEqual(g2.invoke(d.capability, "pay_bill", args, FIELDS).reason, "executed")
        for g in (self.k.gateway(tools={"pay_bill": self.tool}), g2):
            self.assertEqual(g.invoke(d.capability, "pay_bill", args, FIELDS).reason, "replayed")
        self.assertEqual(len(self.calls), 1)

    def test_gateway_without_executor_also_consumes_token(self):
        d, args = self.token()
        self.assertEqual(self.k.gateway().invoke(d.capability, "pay_bill", args, FIELDS).reason,
                         "authorized_no_executor")
        self.assertEqual(self.k.gateway(tools={"pay_bill": self.tool}).invoke(
            d.capability, "pay_bill", args, FIELDS).reason, "replayed")
        self.assertEqual(self.calls, [])

    def test_ledger_redeem_api(self):
        led = self.k.ledger
        e, why = led.redeem("jti-x", {"note": "direct"})
        self.assertEqual((e.kind, e.body["jti"], why), ("capability_redeemed", "jti-x", "ok"))
        self.assertTrue(led.is_redeemed("jti-x"))
        self.assertEqual(led.redemption_for("jti-x").seq, e.seq)
        self.assertEqual(led.redeem("jti-x", {}), (None, "replayed"))
        self.assertEqual(led.redeem("", {}), (None, "replayed"))
        self.assertEqual(len(redemptions(led, "jti-x")), 1)

    def test_failed_redemption_write_still_burns_token(self):
        d, args = self.token()
        g = self.k.gateway(tools={"pay_bill": self.tool})
        real = self.k.ledger.append

        def failing(kind, body):
            if kind == "capability_redeemed":
                raise OSError("disk full")
            return real(kind, body)
        self.k.ledger.append = failing
        with self.assertRaises(OSError):
            g.invoke(d.capability, "pay_bill", args, FIELDS)
        self.k.ledger.append = real
        self.assertTrue(self.k.ledger.is_redeemed(d.token_payload["jti"]))
        self.assertIsNone(self.k.ledger.redemption_for(d.token_payload["jti"]))
        self.assertEqual(g.invoke(d.capability, "pay_bill", args, FIELDS).reason, "replayed")
        self.assertEqual(self.calls, [])


class Concurrent(Base):
    N = 16

    def _race(self, gateways, d, args):
        barrier = threading.Barrier(len(gateways))
        out, errs = [], []

        def run(g):
            try:
                barrier.wait()
                out.append(g.invoke(d.capability, "pay_bill", args, FIELDS).reason)
            except Exception as e:  # pragma: no cover - reported below
                errs.append(e)
        ts = [threading.Thread(target=run, args=(g,)) for g in gateways]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        self.assertEqual(errs, [])
        return out

    def test_concurrent_attempts_many_gateways(self):
        d, args = self.token()
        out = self._race([self.k.gateway(tools={"pay_bill": self.tool}) for _ in range(self.N)], d, args)
        self.assertEqual(sorted(out), ["executed"] + ["replayed"] * (self.N - 1))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(redemptions(self.k.ledger, d.token_payload["jti"])), 1)
        self.k.ledger.checkpoint()
        self.assertTrue(self.k.ledger.verify(self.fx.key.public_key()).ok)

    def test_concurrent_attempts_one_shared_gateway(self):
        d, args = self.token()
        g = self.k.gateway(tools={"pay_bill": self.tool})
        out = self._race([g] * self.N, d, args)
        self.assertEqual(sorted(out), ["executed"] + ["replayed"] * (self.N - 1))
        self.assertEqual(len(self.calls), 1)

    def test_many_tokens_many_threads_chain_stays_valid(self):
        toks = [self.token(f"INV-{i}") for i in range(6)]
        gws = [self.k.gateway(tools={"pay_bill": self.tool}) for _ in range(4)]
        barrier = threading.Barrier(len(toks) * len(gws))
        out, errs = [], []

        def run(g, d, args):
            try:
                barrier.wait()
                out.append((d.token_payload["jti"], g.invoke(d.capability, "pay_bill", args, FIELDS).reason))
            except Exception as e:  # pragma: no cover
                errs.append(e)
        ts = [threading.Thread(target=run, args=(g, d, a)) for d, a in toks for g in gws]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        self.assertEqual(errs, [])
        for d, _ in toks:
            jti = d.token_payload["jti"]
            self.assertEqual(sorted(r for j, r in out if j == jti), ["executed"] + ["replayed"] * (len(gws) - 1))
            self.assertEqual(len(redemptions(self.k.ledger, jti)), 1)
        self.assertEqual(len(self.calls), len(toks))
        self.k.ledger.checkpoint()
        self.assertTrue(self.k.ledger.verify(self.fx.key.public_key()).ok)
        reloaded = PersonalLedger(self.k.ledger.path, self.fx.key)
        self.assertTrue(reloaded.verify(self.fx.key.public_key()).ok)


class Restart(Base):
    def test_replay_rejected_after_restart(self):
        d, args = self.token()
        self.assertEqual(self.k.gateway(tools={"pay_bill": self.tool}).invoke(
            d.capability, "pay_bill", args, FIELDS).reason, "executed")
        led2 = PersonalLedger(self.k.ledger.path, self.fx.key)  # the process restarts and reopens the ledger
        self.assertTrue(led2.is_redeemed(d.token_payload["jti"]))
        gws = [ToolGateway(self.k.issuer, led2, self.k.principal, {"pay_bill": self.tool}) for _ in range(2)]
        for g in gws:
            self.assertEqual(g.invoke(d.capability, "pay_bill", args, FIELDS).reason, "replayed")
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(PersonalLedger(led2.path, self.fx.key).verify(self.fx.key.public_key()).ok)

    def test_unused_token_still_redeemable_once_after_restart(self):
        d, args = self.token()
        led2 = PersonalLedger(self.k.ledger.path, self.fx.key)
        g = ToolGateway(self.k.issuer, led2, self.k.principal, {"pay_bill": self.tool})
        self.assertEqual(g.invoke(d.capability, "pay_bill", args, FIELDS).reason, "executed")
        self.assertEqual(g.invoke(d.capability, "pay_bill", args, FIELDS).reason, "replayed")


@unittest.skipIf(fcntl is None, "cross-process redemption guard needs POSIX flock")
class OtherWriter(Base):
    """A second PersonalLedger on the same file (another process, or a second kernel) cannot redeem twice."""

    def test_second_instance_cannot_redeem_again(self):
        d, args = self.token()
        other = PersonalLedger(self.k.ledger.path, self.fx.key)  # opened before the redemption
        g_other = ToolGateway(self.k.issuer, other, self.k.principal, {"pay_bill": self.tool})
        self.assertEqual(self.k.gateway(tools={"pay_bill": self.tool}).invoke(
            d.capability, "pay_bill", args, FIELDS).reason, "executed")
        size, head = self.k.ledger.path.stat().st_size, self.k.ledger.head_path.read_bytes()
        r = g_other.invoke(d.capability, "pay_bill", args, FIELDS)
        self.assertEqual((r.allowed, r.reason), (False, "replayed"))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.k.ledger.path.stat().st_size, size)  # the stale instance wrote nothing
        self.assertEqual(self.k.ledger.head_path.read_bytes(), head)  # nor re-signed the owner's head
        with self.assertRaises(LedgerError):
            other.append("note", {})
        with self.assertRaises(LedgerError):
            other._write_head()
        self.assertTrue(PersonalLedger(self.k.ledger.path, self.fx.key).verify(self.fx.key.public_key()).ok)

    def test_unrelated_foreign_write_fails_closed(self):
        d, args = self.token()
        other = PersonalLedger(self.k.ledger.path, self.fx.key)
        self.k.ledger.append("note", {"by": "owner"})  # the owner writes something else
        r = ToolGateway(self.k.issuer, other, self.k.principal, {"pay_bill": self.tool}).invoke(
            d.capability, "pay_bill", args, FIELDS)
        self.assertEqual((r.allowed, r.reason), (False, "ledger_concurrent_writer"))
        self.assertEqual(self.calls, [])
        # The owner, whose view of the file is current, still redeems normally.
        self.assertEqual(self.k.gateway(tools={"pay_bill": self.tool}).invoke(
            d.capability, "pay_bill", args, FIELDS).reason, "executed")


def _child(issuer, path, key, principal, marker, start, q):
    led = PersonalLedger(path, key)

    def tool(**a):
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.write(fd, b"x\n")
        os.close(fd)
        return "paid"
    g = ToolGateway(issuer, led, principal, {"pay_bill": tool})
    q.put("ready")  # every child has loaded the ledger (and sees the unused token) before any invokes
    start.wait(30)
    q.put(g.invoke(TOKEN[0], "pay_bill", ARGS, FIELDS).reason)


TOKEN = [None]


@unittest.skipIf(fcntl is None or "fork" not in multiprocessing.get_all_start_methods(),
                 "needs POSIX flock and the fork start method")
class Processes(Base):
    def test_concurrent_processes_accept_token_once(self):
        d, _ = self.token()
        TOKEN[0] = d.capability
        ctx = multiprocessing.get_context("fork")
        q, start = ctx.Queue(), ctx.Event()
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "executions"
            ps = [ctx.Process(target=_child, args=(self.k.issuer, self.k.ledger.path, self.fx.key, self.k.principal,
                                                   marker, start, q)) for _ in range(4)]
            for p in ps:
                p.start()
            self.assertEqual([q.get(timeout=60) for _ in ps], ["ready"] * len(ps))
            start.set()
            out = sorted(q.get(timeout=60) for _ in ps)
            for p in ps:
                p.join(30)
            self.assertEqual(out, ["executed", "replayed", "replayed", "replayed"])
            self.assertEqual(marker.read_text(), "x\n")
        reloaded = PersonalLedger(self.k.ledger.path, self.fx.key)
        self.assertEqual(len(redemptions(reloaded, d.token_payload["jti"])), 1)
        self.assertTrue(reloaded.verify(self.fx.key.public_key()).ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
