"""PRIOR_ART.md §4 (i): ledger-root-bound token (selected by the author, 2026-09-30, Entry 2 "A").

Token carries R (ledger_merkle_root at ledger_size), H(bytecode), H(NL constitution). Before executing, the
gateway (1) checks R equals or is an ancestor of its last-known root via a consistency proof, (2) checks the
hashes against the latest constitution_loaded entry, (3) rejects tokens issued before a later reload or
revocation, and (4) links the execution record to the token's ledger entry.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from two_key import merkle
from two_key.canonical import DOMAIN_TOOL_RESULT, typed_hash
from two_key.constitution import sign_document
from two_key.crypto.signatures import PrivateKeySet
from two_key.core import TwoKey
from two_key.ledger import PersonalLedger, _entry_digest
from two_key.quorum import QuorumPolicy
from two_key.testing import FixedJudge
from helpers import TwoKeyFixture, signed

RULES = [
    {"id": "tools", "allow_only_tools": ["email_send", "pay_bill", "search"]},
    {"id": "cap", "deny_if": {"amount_usd_gt": 200}},
]
YES = [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2")]
PAY = {"tool": "pay_bill", "amount_usd": 42.5, "counterparty": "power-co.example", "data_class": "financial",
       "irreversible": False}
ARGS = {"payee": "power-co.example", "amount": 42.5}
FIELDS = {"amount_usd": 42.5, "counterparty": "power-co.example", "data_class": "financial"}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


class Base(unittest.TestCase):
    def setUp(self):
        self.fx = TwoKeyFixture(RULES, YES, quorum_policy=QuorumPolicy(required_yes=2), ledger_fsync=False)
        self.tk = self.fx.__enter__()
        self.addCleanup(self.fx.__exit__, None, None, None)
        self.gw = self.tk.gateway({"pay_bill": lambda **a: {"paid": a["amount"]}})
        self.d = self.tk.authorize(PAY, "Pay the power bill.", ARGS)
        self.assertTrue(self.d.allowed, self.d.reason)

    def issue(self, **over):
        """Mint a token with Two-Key's own issuer (valid MAC) but chosen binding fields."""
        p = self.d.token_payload
        kw = dict(principal=p["principal"], tool=p["tool"], scope=p["scope"], args_digest=p["args_hash"],
                  ledger_root=p["ledger_root"], constitution_digest=p["constitution_digest"], ttl_seconds=30,
                  ledger_size=p["ledger_size"], ledger_merkle_root=p["ledger_merkle_root"],
                  bytecode_hash=p["bytecode_hash"], nl_hash=p["nl_hash"])
        kw.update(over)
        return self.tk.issuer.issue(**kw).token

    def invoke(self, token):
        return self.gw.invoke(token, "pay_bill", ARGS, FIELDS)


class TokenCarriesBinding(Base):
    def test_payload_fields(self):
        p, led = self.d.token_payload, self.tk.ledger
        cap = led.capability_entry(p["jti"])
        self.assertEqual(cap.kind, "capability_issued")
        self.assertEqual(p["ledger_size"], cap.seq)            # R is the root just before the token's entry
        self.assertEqual(p["ledger_merkle_root"], led.merkle_root(cap.seq))
        self.assertEqual(p["ledger_root"], led.entries[cap.seq - 1].digest)
        loaded = led.latest_constitution().body
        self.assertEqual((p["bytecode_hash"], p["nl_hash"]), (loaded["bytecode_hash"], loaded["nl_hash"]))
        self.assertEqual((p["bytecode_hash"], p["nl_hash"]), (self.tk.compiled.bytecode_hash, self.tk.compiled.nl_hash))
        for k in ("ledger_size", "ledger_merkle_root", "bytecode_hash", "nl_hash"):
            self.assertEqual(cap.body[k], p[k])


class AncestorCheck(Base):
    def test_equal_root_and_ancestor_via_consistency_proof(self):
        for _ in range(5):  # later ledger activity: R becomes a strict ancestor
            self.tk.authorize(SEARCH, "look something up")
        size0 = self.gw.view[0]
        r = self.invoke(self.d.capability)
        self.assertEqual(r.reason, "executed")
        self.assertGreater(self.gw.view[0], size0)  # the gateway's view advanced by consistency proof

    def test_forged_root_or_size_rejected(self):
        self.assertEqual(self.invoke(self.issue(ledger_merkle_root="ab" * 32)).reason, "ledger_root_not_ancestor")
        self.assertEqual(self.invoke(self.issue(ledger_size=10_000)).reason, "ledger_root_not_ancestor")
        self.assertEqual(self.invoke(self.issue(ledger_size=0)).reason, "ledger_root_not_ancestor")
        # R and size from a different point in history than the chain digest in the token
        p = self.d.token_payload
        other = self.issue(ledger_size=p["ledger_size"] - 1,
                           ledger_merkle_root=self.tk.ledger.merkle_root(p["ledger_size"] - 1))
        self.assertEqual(self.invoke(other).reason, "ledger_root_not_ancestor")

    def test_missing_binding_rejected(self):
        p = self.d.token_payload
        legacy = self.tk.issuer.issue(principal=p["principal"], tool=p["tool"], scope=p["scope"],
                                     args_digest=p["args_hash"], ledger_root=p["ledger_root"],
                                     constitution_digest=p["constitution_digest"], ttl_seconds=30).token
        self.assertEqual(self.invoke(legacy).reason, "token_missing_ledger_binding")
        self.assertEqual(self.invoke(self.issue(ledger_merkle_root="not-hex")).reason,
                         "token_missing_ledger_binding")
        self.assertEqual(self.invoke(self.issue(ledger_size=True)).reason, "token_missing_ledger_binding")

    def _copy_external_keys(self, src, dst):
        for suffix in (".ledger-key", ".witness"):
            source = src.parent.parent / f"{src.parent.name}{suffix}"
            dest = dst.parent.parent / f"{dst.parent.name}{suffix}"
            if source.is_dir():
                shutil.copytree(source, dest)
                self.addCleanup(shutil.rmtree, dest, True)

    def _rewritten_ledger(self, mutate_seq):
        """Copy the ledger file and rewrite history from ``mutate_seq`` on with a consistent hash chain."""
        src = self.tk.ledger.path
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        dst = tmp / "l.jsonl"
        from two_key import ledger_at_rest
        shutil.copy(src, dst)
        shutil.copy(src.with_name(src.name + ".key.json"), dst.with_name(dst.name + ".key.json"))
        self._copy_external_keys(src, dst)
        data_key = self.tk.ledger._data_key
        rows = [json.loads(ledger_at_rest.open_record(data_key, x)) for x in dst.read_text().splitlines()]
        rows[mutate_seq]["body"] = {"rewritten": True}
        prev = rows[mutate_seq - 1]["digest"] if mutate_seq else "0" * 64
        for r in rows[mutate_seq:]:
            r["prev"] = prev
            r["digest"] = _entry_digest(r["seq"], r["ts"], r["kind"], r["body"], r["prev"], r.get("alg", "sha256"))
            prev = r["digest"]
        sealed = [ledger_at_rest.seal(data_key, json.dumps(r, sort_keys=True)) for r in rows]
        dst.write_text("\n".join(sealed) + "\n")
        return PersonalLedger(dst, self.tk.ledger.signing_key, fsync=False)

    def test_rewrite_outside_view_is_an_extension(self):
        # The view taken at gateway construction covers only entry 0; rewriting later entries is,
        # from this gateway's point of view, a legitimate extension. The token check still fails
        # because the token's chain digest no longer exists.
        self.assertEqual(self.gw.view[0], 1)
        self.gw.ledger = self._rewritten_ledger(1)
        self.assertEqual(self.invoke(self.d.capability).reason, "unknown_ledger_root")

    def test_fork_detected_in_every_call_mode(self):
        gw = self.tk.gateway(view_refresh="every_call")
        self.assertTrue(gw.refresh_view())
        gw.ledger = self._rewritten_ledger(2)
        self.assertEqual(gw.invoke(self.d.capability, "pay_bill", ARGS, FIELDS).reason, "ledger_fork_detected")

    def test_fork_detected_against_last_known_view(self):
        d2 = self.tk.authorize(PAY, "Pay again.", ARGS)
        self.assertEqual(self.invoke(d2.capability).reason, "executed")  # view now covers the token's entry
        forged = self._rewritten_ledger(1)
        self.assertTrue(forged.verify_chain())         # a well-formed chain, but not an extension of the view
        forged.append("filler", {})                    # and even longer than the view
        self.gw.ledger = forged
        self.assertEqual(self.invoke(self.d.capability).reason, "ledger_fork_detected")

    def test_truncation_detected(self):
        d2 = self.tk.authorize(PAY, "Pay again.", ARGS)
        self.assertEqual(self.invoke(d2.capability).reason, "executed")  # the view is now the current ledger
        before = self.gw.view
        n = before[0]
        self.assertGreater(n, 10)
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        src = self.tk.ledger.path
        lines = src.read_text().splitlines()[: n - 2]
        (tmp / "l.jsonl").write_text("\n".join(lines) + "\n")
        shutil.copy(src.with_name(src.name + ".key.json"), tmp / "l.jsonl.key.json")
        self._copy_external_keys(src, tmp / "l.jsonl")
        self.gw.ledger = PersonalLedger(tmp / "l.jsonl", self.tk.ledger.signing_key, fsync=False)
        self.assertEqual(self.invoke(self.d.capability).reason, "ledger_fork_detected")
        self.assertEqual(self.gw.view, before)          # the view never moves to a non-extension

    def test_view_consistency_uses_merkle_proof(self):
        size, root = self.gw.view
        self.tk.authorize(SEARCH, "look something up")
        n = self.tk.ledger.size
        proof = self.tk.ledger.consistency_path(size, n)
        self.assertTrue(merkle.verify_consistency(size, n, bytes.fromhex(root), self.tk.ledger.root_bytes(),
                                                  proof, self.tk.ledger.hash_fn()))
        self.assertTrue(self.gw.refresh_view())
        self.assertEqual(self.gw.view, (n, self.tk.ledger.merkle_root()))

    def test_view_advances_only_to_token_roots_by_default(self):
        self.assertEqual(self.invoke(self.d.capability).reason, "executed")
        self.assertEqual(self.gw.view, (self.d.token_payload["ledger_size"], self.d.token_payload["ledger_merkle_root"]))

    def test_every_call_refresh_mode(self):
        gw = self.tk.gateway(view_refresh="every_call")
        self.tk.authorize(SEARCH, "look")
        self.assertEqual(gw.invoke(self.d.capability, "pay_bill", ARGS, FIELDS).reason, "tool_not_registered")
        self.assertGreater(gw.view[0], self.d.token_payload["ledger_size"])
        with self.assertRaises(ValueError):
            self.tk.gateway(view_refresh="sometimes")


class ConstitutionHashesAndRevocation(Base):
    def test_hash_mismatch(self):
        self.assertEqual(self.invoke(self.issue(bytecode_hash="00" * 32)).reason, "constitution_hash_mismatch")
        self.assertEqual(self.invoke(self.issue(nl_hash="00" * 32)).reason, "constitution_hash_mismatch")
        self.assertEqual(self.invoke(self.issue(constitution_digest="00" * 32)).reason,
                         "constitution_hash_mismatch")

    def test_reload_with_new_constitution_invalidates_old_tokens(self):
        new_rules = RULES + [{"id": "no-irrev", "deny_if": {"irreversible": True}}]
        env, _ = signed(new_rules, key=self.fx.key)
        self.tk.reload_constitution(env, acknowledge=True)
        self.assertEqual(self.invoke(self.d.capability).reason, "constitution_hash_mismatch")
        d2 = self.tk.authorize(PAY, "Pay the power bill.", ARGS)
        self.assertTrue(d2.allowed, d2.reason)
        self.assertEqual(self.invoke(d2.capability).reason, "executed")
        loaded = self.tk.ledger.latest_constitution().body
        self.assertEqual(loaded["bytecode_hash"], d2.token_payload["bytecode_hash"])
        self.assertIn("previous_constitution_digest", loaded)

    def test_reload_of_same_constitution_still_invalidates(self):
        self.tk.reload_constitution(signed(RULES, key=self.fx.key)[0])  # same rules and text, new created_at
        r = self.invoke(self.d.capability)
        self.assertIn(r.reason, ("constitution_hash_mismatch", "constitution_changed_since_issue"))
        self.assertFalse(r.allowed)

    def test_identical_reload_is_changed_since_issue(self):
        # Byte-identical document: all hashes match, but the reload entry postdates the token.
        self.tk.reload_constitution(sign_document(self.tk.constitution.document, self.fx.key))
        self.assertEqual(self.invoke(self.d.capability).reason, "constitution_changed_since_issue")

    def test_revoke_one_token(self):
        d2 = self.tk.authorize(PAY, "Pay again.", ARGS)
        self.tk.revoke(self.d.token_payload["jti"], reason="lost device")
        self.assertEqual(self.invoke(self.d.capability).reason, "revoked")
        self.assertEqual(self.invoke(d2.capability).reason, "executed")
        rev = [e for e in self.tk.ledger.entries if e.kind == "revocation"][-1].body
        self.assertEqual((rev["jti"], rev["scope"], rev["reason"]), (self.d.token_payload["jti"], "token", "lost device"))

    def test_revoke_all_issued_so_far(self):
        d2 = self.tk.authorize(PAY, "Pay again.", ARGS)
        self.tk.revoke()
        self.assertEqual(self.invoke(self.d.capability).reason, "revoked")
        self.assertEqual(self.invoke(d2.capability).reason, "revoked")
        d3 = self.tk.authorize(PAY, "Pay after revocation.", ARGS)
        self.assertEqual(self.invoke(d3.capability).reason, "executed")
        with self.assertRaises(ValueError):
            self.tk.revoke("")

    def test_token_without_its_ledger_entry(self):
        # A valid-MAC token whose capability_issued entry does not exist (issuer bypassed Two-Key).
        led = self.tk.ledger
        self.tk.authorize(SEARCH, "look")
        tok = self.issue(ledger_size=led.size, ledger_merkle_root=led.merkle_root(), ledger_root=led.root())
        led.append("filler", {})
        self.assertEqual(self.invoke(tok).reason, "capability_not_recorded")

    def test_token_hash_must_match_recorded_entry(self):
        # Same jti and binding as a recorded token, but a different token string.
        forged = self.issue()
        import base64
        p = json.loads(base64.urlsafe_b64decode(forged.split(".")[1] + "=="))
        self.assertNotEqual(p["jti"], self.d.token_payload["jti"])  # issuer always mints a fresh jti
        self.assertEqual(self.invoke(forged).reason, "capability_not_recorded")


class ExecutionLinkedToTokenEntry(Base):
    def test_links_and_result_hash(self):
        r = self.invoke(self.d.capability)
        self.assertEqual(r.reason, "executed")
        led = self.tk.ledger
        cap = led.capability_entry(self.d.token_payload["jti"])
        red = [e for e in led.entries if e.kind == "capability_redeemed"][-1].body
        ex = [e for e in led.entries if e.kind == "tool_executed"][-1].body
        for b in (red, ex):
            self.assertEqual((b["capability_entry_seq"], b["capability_entry_digest"]), (cap.seq, cap.digest))
        self.assertEqual(ex["result_hash"], typed_hash({"paid": 42.5}, DOMAIN_TOOL_RESULT, led.digest_alg))
        self.assertNotIn("paid", json.dumps(ex))  # only the hash of the result is stored
        self.assertEqual(self.invoke(self.d.capability).reason, "replayed")
        self.assertTrue(led.verify(self.fx.key.public_key()).ok)

    def test_tool_error_linked(self):
        gw = self.tk.gateway({"pay_bill": lambda **a: 1 / 0})
        self.assertEqual(gw.invoke(self.d.capability, "pay_bill", ARGS, FIELDS).reason, "tool_error:ZeroDivisionError")
        err = [e for e in self.tk.ledger.entries if e.kind == "tool_error"][-1].body
        self.assertEqual(err["capability_entry_seq"], self.tk.ledger.capability_entry(self.d.token_payload["jti"]).seq)
        self.assertFalse(self.tk.ledger.is_redeemed(self.d.token_payload["jti"]))

    def test_tool_error_can_be_retried(self):
        calls = {"n": 0}

        def flaky(**_a):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("down")
            return {"paid": 1}

        gw = self.tk.gateway({"pay_bill": flaky})
        first = gw.invoke(self.d.capability, "pay_bill", ARGS, FIELDS)
        second = gw.invoke(self.d.capability, "pay_bill", ARGS, FIELDS)
        self.assertEqual(first.reason, "tool_error:RuntimeError")
        self.assertEqual(second.reason, "executed")
        self.assertEqual(calls["n"], 2)

    def test_open_intent_does_not_run_the_tool_again(self):
        jti = self.d.token_payload["jti"]
        started, why = self.tk.ledger.begin_attempt(jti, {"tool": "pay_bill"})
        self.assertEqual(why, "ok")
        self.assertIsNotNone(started)
        calls = {"n": 0}
        gw = self.tk.gateway({"pay_bill": lambda **a: calls.__setitem__("n", 1)})
        result = gw.invoke(self.d.capability, "pay_bill", ARGS, FIELDS)
        self.assertEqual(result.reason, "already_attempted")
        self.assertEqual(calls["n"], 0)

    def test_non_json_result_is_hashed(self):
        gw = self.tk.gateway({"pay_bill": lambda **a: object()})
        self.assertEqual(gw.invoke(self.d.capability, "pay_bill", ARGS, FIELDS).reason, "executed")
        self.assertEqual(len([e for e in self.tk.ledger.entries if e.kind == "tool_executed"][-1].body["result_hash"]),
                         96)


class NonLegacyProfile(unittest.TestCase):
    def test_sha384_profile_end_to_end(self):
        ks = PrivateKeySet.generate("ecdsa-p384")
        env, _ = signed(RULES, key=ks)
        with tempfile.TemporaryDirectory() as d:
            tk = TwoKey(env, ks.public(), Path(d) / "l.jsonl", YES, ledger_signing_key=ks,
                              allow_test_doubles=True, ledger_fsync=False)
            dec = tk.authorize(PAY, "Pay.", ARGS)
            p = dec.token_payload
            self.assertEqual((len(p["ledger_merkle_root"]), len(p["bytecode_hash"]), len(p["nl_hash"])), (96, 96, 96))
            tk.authorize(SEARCH, "look")
            self.assertEqual(tk.gateway().invoke(dec.capability, "pay_bill", ARGS, FIELDS).reason,
                             "tool_not_registered")
            self.assertTrue(tk.ledger.verify(ks.public()).ok)

    def test_fips_mode_end_to_end(self):
        from two_key.crypto import CryptoProvider
        fips = CryptoProvider(fips_mode=True)
        ks = PrivateKeySet.generate("ecdsa-p384", fips)
        env, _ = signed(RULES, key=ks)
        with tempfile.TemporaryDirectory() as d:
            tk = TwoKey(env, ks.public(), Path(d) / "l.jsonl", YES, ledger_signing_key=ks, crypto=fips,
                              allow_test_doubles=True, ledger_fsync=False)
            self.assertTrue(tk.crypto_profile()["fips_mode"])
            dec = tk.authorize(PAY, "Pay.", ARGS)
            tk.authorize(SEARCH, "look")
            self.assertEqual(tk.gateway().invoke(dec.capability, "pay_bill", ARGS, FIELDS).reason,
                             "tool_not_registered")
            tk.revoke()
            self.assertEqual(tk.ledger.latest_constitution().body["crypto"]["digest_alg"], "sha384")


if __name__ == "__main__":
    unittest.main(verbosity=2)
