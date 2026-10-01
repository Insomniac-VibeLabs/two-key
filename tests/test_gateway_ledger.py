"""Tool gateway (all spec 5.5 checks plus single-use) and the signed, Merkle-backed ledger."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from two_key import keys
from two_key.anchoring import LocalFileAnchor, NullAnchor
from two_key.capability import CapabilityIssuer, _b64u, _b64u_dec
from two_key.core import TwoKey
from two_key.ledger import LedgerError, PersonalLedger
from two_key.quorum import QuorumPolicy
from two_key.testing import FixedJudge
from helpers import TwoKeyFixture, signed

RULES = [
    {"id": "tools", "allow_only_tools": ["email_send", "pay_bill", "search"]},
    {"id": "sensitive", "deny_if": {"data_class_in": ["medical", "classified"]}},
    {"id": "cap", "deny_if": {"amount_usd_gt": 200}},
]
YES = [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2")]
PAY = {"tool": "pay_bill", "amount_usd": 42.5, "counterparty": "Power-Co.example", "data_class": "financial",
       "irreversible": False}
PAY_ARGS = {"payee": "power-co.example", "amount": 42.5, "invoice": "INV-7"}
PAY_FIELDS = {"amount_usd": 42.5, "counterparty": "power-co.example", "data_class": "financial"}


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class GatewayChecks(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.fx = TwoKeyFixture(RULES, YES, quorum_policy=QuorumPolicy(required_yes=2), clock=self.clock,
                                ttl_seconds=30)
        self.tk = self.fx.__enter__()
        self.calls = []
        self.gw = self.tk.gateway(tools={"pay_bill": lambda **a: self.calls.append(a) or "paid",
                                        "email_send": lambda **a: "sent"})
        self.d = self.tk.authorize(PAY, "Pay the electric bill.", PAY_ARGS)
        self.assertTrue(self.d.allowed, self.d.reason)

    def tearDown(self):
        self.fx.__exit__(None, None, None)

    def test_full_token_returned_and_redeemable_once(self):
        self.assertTrue(self.d.capability.startswith("tk1.") and self.d.capability.count(".") == 2)
        r = self.gw.invoke(self.d.capability, "pay_bill", PAY_ARGS, PAY_FIELDS)
        self.assertEqual((r.allowed, r.reason, r.result), (True, "executed", "paid"))
        self.assertEqual(self.calls, [PAY_ARGS])
        r2 = self.gw.invoke(self.d.capability, "pay_bill", PAY_ARGS, PAY_FIELDS)
        self.assertEqual((r2.allowed, r2.reason), (False, "replayed"))
        self.assertEqual(len(self.calls), 1)

    def test_replay_across_tools_fails(self):
        r = self.gw.invoke(self.d.capability, "email_send", PAY_ARGS, PAY_FIELDS)
        self.assertEqual(r.reason, "tool_mismatch")

    def test_expiry(self):
        self.clock.t += 31
        self.assertEqual(self.gw.invoke(self.d.capability, "pay_bill", PAY_ARGS, PAY_FIELDS).reason, "expired")

    def test_args_binding(self):
        evil = dict(PAY_ARGS, payee="offshore-mule.example")
        self.assertEqual(self.gw.invoke(self.d.capability, "pay_bill", evil, PAY_FIELDS).reason, "args_mismatch")

    def test_amount_scope(self):
        r = self.gw.invoke(self.d.capability, "pay_bill", PAY_ARGS, dict(PAY_FIELDS, amount_usd=43))
        self.assertEqual(r.reason, "amount_exceeds_scope")

    def test_counterparty_scope(self):
        r = self.gw.invoke(self.d.capability, "pay_bill", PAY_ARGS, dict(PAY_FIELDS, counterparty="other.example"))
        self.assertEqual(r.reason, "counterparty_mismatch")

    def test_counterparty_canonicalized(self):
        r = self.gw.invoke(self.d.capability, "pay_bill", PAY_ARGS, dict(PAY_FIELDS, counterparty=" POWER-CO.example"))
        self.assertTrue(r.allowed, r.reason)

    def test_data_class_scope_and_conservative_default(self):
        r = self.gw.invoke(self.d.capability, "pay_bill", PAY_ARGS, dict(PAY_FIELDS, data_class="personal"))
        self.assertEqual(r.reason, "data_class_mismatch")
        fields = {k: v for k, v in PAY_FIELDS.items() if k != "data_class"}  # missing -> classified
        self.assertEqual(self.gw.invoke(self.d.capability, "pay_bill", PAY_ARGS, fields).reason, "data_class_mismatch")

    def test_call_fields_required_without_extractor(self):
        self.assertTrue(self.gw.invoke(self.d.capability, "pay_bill", PAY_ARGS).reason.startswith("invalid_call"))

    def test_extractor_hook(self):
        gw = self.tk.gateway(extractors={"pay_bill": lambda a: {"amount_usd": a["amount"], "counterparty": a["payee"],
                                                               "data_class": "financial"}})
        self.assertTrue(gw.invoke(self.d.capability, "pay_bill", PAY_ARGS).allowed)

    def test_extractor_disagreement_denied(self):
        gw = self.tk.gateway(extractors={"pay_bill": lambda a: {"amount_usd": a["amount"], "counterparty": a["payee"],
                                                               "data_class": "financial"}})
        r = gw.invoke(self.d.capability, "pay_bill", PAY_ARGS, dict(PAY_FIELDS, amount_usd=1))
        self.assertTrue(r.reason.startswith("invalid_call"))

    def test_signature_tampering(self):
        prefix, body, mac = self.d.capability.split(".")
        p = json.loads(_b64u_dec(body))
        p["scope"]["amount_usd"] = 1e6
        forged = f"{prefix}.{_b64u(json.dumps(p).encode())}.{mac}"
        self.assertEqual(self.gw.invoke(forged, "pay_bill", PAY_ARGS, PAY_FIELDS).reason, "bad_signature")
        self.assertEqual(self.gw.invoke(self.d.capability[:-2] + "AA", "pay_bill", PAY_ARGS, PAY_FIELDS).reason,
                         "bad_signature")
        self.assertEqual(self.gw.invoke("garbage", "pay_bill", PAY_ARGS, PAY_FIELDS).reason, "malformed_token")
        self.assertEqual(self.gw.invoke(None, "pay_bill", PAY_ARGS, PAY_FIELDS).reason, "malformed_token")

    def test_token_from_other_issuer_rejected(self):
        other = CapabilityIssuer(clock=self.clock).issue(
            principal=self.tk.principal, tool="pay_bill", scope=self.d.token_payload["scope"],
            args_digest=self.d.token_payload["args_hash"], ledger_root=self.tk.ledger.root(),
            constitution_digest="x", ttl_seconds=30)
        self.assertEqual(self.gw.invoke(other.token, "pay_bill", PAY_ARGS, PAY_FIELDS).reason, "bad_signature")

    def test_ledger_root_must_be_known_ancestor(self):
        tok = self.tk.issuer.issue(principal=self.tk.principal, tool="pay_bill", scope=self.d.token_payload["scope"],
                                  args_digest=self.d.token_payload["args_hash"], ledger_root="ab" * 32,
                                  constitution_digest="x", ttl_seconds=30)
        self.assertEqual(self.gw.invoke(tok.token, "pay_bill", PAY_ARGS, PAY_FIELDS).reason, "unknown_ledger_root")

    def test_ancestor_root_accepted(self):
        # Later ledger activity doesn't invalidate the token: its root is an ancestor of the current head.
        self.tk.authorize({"tool": "search", "data_class": "public", "irreversible": False}, "look something up")
        self.assertNotEqual(self.tk.ledger.root(), self.d.token_payload["ledger_root"])
        self.assertTrue(self.gw.invoke(self.d.capability, "pay_bill", PAY_ARGS, PAY_FIELDS).allowed)

    def test_wrong_principal(self):
        gw = type(self.gw)(self.tk.issuer, self.tk.ledger, "did:twokey:someone-else")
        self.assertEqual(gw.invoke(self.d.capability, "pay_bill", PAY_ARGS, PAY_FIELDS).reason, "wrong_principal")

    def test_constitution_reload_invalidates_old_tokens(self):
        secret = os.urandom(32)
        with tempfile.TemporaryDirectory() as d:
            env, key = signed(RULES)
            k1 = TwoKey(env, key.public_key(), Path(d) / "l.jsonl", YES, ledger_signing_key=key,
                               capability_secret=secret, allow_test_doubles=True)
            dec = k1.authorize(PAY, "Pay.", PAY_ARGS)
            k2 = TwoKey(env, key.public_key(), Path(d) / "l.jsonl", YES, ledger_signing_key=key,
                               capability_secret=secret, allow_test_doubles=True)
            r = k2.gateway().invoke(dec.capability, "pay_bill", PAY_ARGS, PAY_FIELDS)
            self.assertEqual(r.reason, "constitution_changed_since_issue")

    def test_replay_protection_survives_restart(self):
        self.assertTrue(self.gw.invoke(self.d.capability, "pay_bill", PAY_ARGS, PAY_FIELDS).allowed)
        gw2 = self.tk.gateway()  # rebuilt from ledger
        self.assertEqual(gw2.invoke(self.d.capability, "pay_bill", PAY_ARGS, PAY_FIELDS).reason, "replayed")

    def test_ledger_records_full_action_token_hash_and_reasons_not_token(self):
        self.gw.invoke(self.d.capability, "email_send", PAY_ARGS, PAY_FIELDS)
        kinds = [e.kind for e in self.tk.ledger.entries]
        for k in ("proposal", "action_normalized", "vm_result", "quorum_result", "capability_issued", "decision",
                  "gateway_denied"):
            self.assertIn(k, kinds)
        norm = next(e for e in self.tk.ledger.entries if e.kind == "action_normalized").body["action"]
        self.assertEqual(norm["counterparty"], "power-co.example")
        self.assertEqual(set(norm), {"tool", "amount_usd", "currency", "counterparty", "data_class", "destination",
                                     "duration_hours", "irreversible", "tags", "raw"})
        issued = next(e for e in self.tk.ledger.entries if e.kind == "capability_issued").body
        self.assertEqual(len(issued["token_sha256"]), 64)
        self.assertNotIn(self.d.capability, self.tk.ledger.path.read_text())
        self.assertNotIn(self.d.capability.split(".")[2], self.tk.ledger.path.read_text())
        denied = [e for e in self.tk.ledger.entries if e.kind == "gateway_denied"][-1].body
        self.assertEqual(denied["reason"], "tool_mismatch")

    def test_path_a_deny_reason_logged(self):
        d = self.tk.authorize(dict(PAY, amount_usd=500), "Pay a lot.", PAY_ARGS)
        self.assertEqual(d.denied_by_rule, "cap")
        last = self.tk.ledger.entries[-1]
        self.assertEqual((last.kind, last.body["denied_by_rule"]), ("decision", "cap"))


class LedgerIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "ledger.jsonl"
        self.key = keys.generate_private_key()
        self.L = PersonalLedger(self.path, signing_key=self.key)
        for i in range(7):
            self.L.append("event", {"i": i})

    def tearDown(self):
        self.tmp.cleanup()

    def reload(self):
        return PersonalLedger(self.path)

    def test_valid(self):
        self.assertEqual(self.reload().verify(self.key.public_key()).reason, "ok")
        self.assertEqual(oct(self.path.stat().st_mode & 0o777), "0o600")

    def test_full_rewrite_detected(self):
        # The attacker rewrites every entry and recomputes the hash chain (the original prototype accepted this).
        self.path.unlink()
        forged = PersonalLedger(self.path)  # no key
        for i in range(7):
            forged.append("event", {"i": i * 100})
        L = self.reload()
        self.assertTrue(L.verify_chain())  # the hash chain alone is fooled...
        self.assertFalse(L.verify(self.key.public_key()).ok)  # ...the signed head is not

    def test_full_rewrite_with_attacker_key_detected(self):
        self.path.unlink()
        self.L.head_path.unlink()
        forged = PersonalLedger(self.path, signing_key=keys.generate_private_key())
        forged.append("event", {"i": 0})
        self.assertEqual(self.reload().verify(self.key.public_key()).reason, "head_signed_by_untrusted_key")

    def test_single_edit_detected(self):
        lines = self.path.read_text().splitlines()
        d = json.loads(lines[3]); d["body"] = {"i": 999}; lines[3] = json.dumps(d)
        self.path.write_text("\n".join(lines) + "\n")
        self.assertEqual(self.reload().verify(self.key.public_key()).reason, "hash_chain_broken")

    def test_truncation_detected(self):
        lines = self.path.read_text().splitlines()
        self.path.write_text("\n".join(lines[:5]) + "\n")
        self.assertTrue(self.reload().verify(self.key.public_key()).reason.startswith("size_mismatch"))

    def test_unsigned_append_detected(self):
        PersonalLedger(self.path).append("event", {"sneaky": True})  # appended without the key
        self.assertTrue(self.reload().verify(self.key.public_key()).reason.startswith("size_mismatch"))

    def test_head_signature_tamper_detected(self):
        h = json.loads(self.L.head_path.read_text())
        h["head"]["size"] = 99
        self.L.head_path.write_text(json.dumps(h))
        self.assertEqual(self.reload().verify(self.key.public_key()).reason, "head_signature_invalid")

    def test_merkle_inclusion_proofs(self):
        for n in range(1, 8):
            L = PersonalLedger(Path(self.tmp.name) / f"m{n}.jsonl")
            for i in range(n):
                L.append("e", {"i": i})
            for s in range(n):
                p = L.inclusion_proof(s)
                self.assertTrue(PersonalLedger.verify_inclusion_proof(p))
                bad = dict(p, leaf="00" * 32)
                self.assertFalse(PersonalLedger.verify_inclusion_proof(bad))

    def test_anchoring_stub(self):
        self.assertFalse(self.L.anchor(NullAnchor())["published"])
        r = self.L.anchor(LocalFileAnchor(Path(self.tmp.name) / "anchor.jsonl"))
        self.assertEqual(r["anchor"], "local-file")
        self.assertEqual(self.L.entries[-1].kind, "anchored")
        self.assertTrue(self.reload().verify(self.key.public_key()).ok)

    def test_two_key_refuses_tampered_existing_ledger(self):
        env, key = signed(RULES)
        p = Path(self.tmp.name) / "k.jsonl"
        TwoKey(env, key.public_key(), p, YES, ledger_signing_key=key, allow_test_doubles=True)
        p.write_text(p.read_text().replace('"bytecode_len"', '"bytecode_LEN"'))
        with self.assertRaises(LedgerError):
            TwoKey(env, key.public_key(), p, YES, ledger_signing_key=key, allow_test_doubles=True)

    def test_ledger_append_failure_denies(self):
        env, key = signed(RULES)
        p = Path(self.tmp.name) / "k2.jsonl"
        tk = TwoKey(env, key.public_key(), p, YES, ledger_signing_key=key, allow_test_doubles=True)

        def boom(*a, **kw):
            raise OSError("disk full")
        tk.ledger.append = boom
        d = tk.authorize(PAY, "Pay.", PAY_ARGS)
        self.assertFalse(d.allowed)
        self.assertIsNone(d.capability)
        self.assertTrue(d.reason.startswith("internal_error"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
