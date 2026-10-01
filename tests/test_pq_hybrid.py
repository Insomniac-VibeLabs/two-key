"""Hybrid post-quantum signatures (ML-DSA-65 + Ed25519 / ECDSA P-384) with a REAL ML-DSA backend.

Rule under test: both halves must verify. If either half is altered, stripped,
reordered, relabelled, or replaced, the signature is rejected. These tests are
skipped when no ML-DSA backend is installed (e.g. cryptography < ML-DSA
support); MissingPQ below runs only in that case and checks the failure is clear.
"""
import base64
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from two_key.capability import CapabilityIssuer, TokenError
from two_key.cli import main as cli_main
from two_key.constitution import ConstitutionSignatureError, build_document, sign_document, verify_signed
from two_key.crypto import PQUnavailableError, PrivateKeySet, PublicKeySet
from two_key.crypto.signatures import _Ed25519, public_keyset_from_encoded
from two_key.core import TwoKey
from two_key.ledger import PersonalLedger
from two_key.testing import FixedJudge
from crypto_helpers import PQ, decode_sig, encode_sig, flip_component
from helpers import DEFAULT_TEXT

RULES = [{"id": "tools", "allow_only_tools": ["pay_bill"]}]
YES = [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2")]
PAY = {"tool": "pay_bill", "amount_usd": 10, "counterparty": "power-co.example", "data_class": "financial"}
PAY_ARGS = {"payee": "power-co.example", "amount": 10}
PAY_FIELDS = {"amount_usd": 10, "counterparty": "power-co.example", "data_class": "financial"}
HYBRIDS = ("hybrid-mldsa65-ed25519", "hybrid-mldsa65-p384")


@unittest.skipUnless(PQ, "no ML-DSA backend available")
class HybridSignatureTamper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = {s: PrivateKeySet.generate(s) for s in HYBRIDS}

    def test_valid_hybrid_verifies(self):
        for s, ks in self.keys.items():
            sig = ks.sign(b"msg")
            self.assertTrue(ks.public().verify(b"msg", sig), s)
            self.assertFalse(ks.public().verify(b"other", sig), s)
            self.assertEqual(len(base64.b64decode(decode_sig(sig)["sigs"][0][1])), 3309)  # ML-DSA-65

    def test_either_half_tampered_rejects(self):
        for s, ks in self.keys.items():
            sig = ks.sign(b"msg")
            self.assertFalse(ks.public().verify(b"msg", flip_component(sig, 0)), f"{s}: ML-DSA half")
            self.assertFalse(ks.public().verify(b"msg", flip_component(sig, 1)), f"{s}: classical half")

    def test_stripped_component_rejects(self):
        for s, ks in self.keys.items():
            obj = decode_sig(ks.sign(b"msg"))
            for keep in (0, 1):
                self.assertFalse(ks.public().verify(b"msg", encode_sig(dict(obj, sigs=[obj["sigs"][keep]]))))
            self.assertFalse(ks.public().verify(b"msg", encode_sig(dict(obj, sigs=obj["sigs"] * 2))))

    def test_reordered_or_relabelled_rejects(self):
        for s, ks in self.keys.items():
            obj = decode_sig(ks.sign(b"msg"))
            self.assertFalse(ks.public().verify(b"msg", encode_sig(dict(obj, sigs=obj["sigs"][::-1]))))
            other = [x for x in HYBRIDS if x != s][0]
            self.assertFalse(ks.public().verify(b"msg", encode_sig(dict(obj, suite=other))))

    def test_half_replaced_with_valid_signature_from_other_key_rejects(self):
        a, b = PrivateKeySet.generate(HYBRIDS[0]), PrivateKeySet.generate(HYBRIDS[0])
        sa, sb = decode_sig(a.sign(b"msg")), decode_sig(b.sign(b"msg"))
        self.assertFalse(a.public().verify(b"msg", encode_sig(dict(sa, sigs=[sb["sigs"][0], sa["sigs"][1]]))))
        self.assertFalse(a.public().verify(b"msg", encode_sig(dict(sa, sigs=[sa["sigs"][0], sb["sigs"][1]]))))

    def test_classical_component_cannot_be_lifted_out(self):
        """Components sign a domain-separated message naming the suite, so the Ed25519 half of a
        hybrid signature is not a valid standalone Ed25519 signature over the message."""
        ks = self.keys["hybrid-mldsa65-ed25519"]
        comp_sig = decode_sig(ks.sign(b"msg"))["sigs"][1][1]
        ed_raw = json.loads(base64.b64decode(ks.public().encoded))["keys"][1][1]
        legacy = public_keyset_from_encoded(ed_raw)
        self.assertEqual(legacy.suite, "ed25519")
        self.assertFalse(legacy.verify(b"msg", comp_sig))

    def test_garbage_signatures_rejected(self):
        pub = self.keys[HYBRIDS[0]].public()
        for bad in (None, "", "!!!", base64.b64encode(b"{}").decode(), base64.b64encode(b"[1]").decode(),
                    encode_sig({"suite": HYBRIDS[0], "sigs": "x"})):
            self.assertFalse(pub.verify(b"msg", bad))

    def test_public_key_roundtrip(self):
        for ks in self.keys.values():
            self.assertEqual(public_keyset_from_encoded(ks.public().encoded), ks.public())


@unittest.skipUnless(PQ, "no ML-DSA backend available")
class HybridConstitutionLedgerTokens(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.ks = PrivateKeySet.generate("hybrid-mldsa65-ed25519")
        self.env = sign_document(build_document("did:twokey:t", DEFAULT_TEXT, RULES), self.ks)

    def tearDown(self):
        self.tmp.cleanup()

    def test_constitution_either_half_tampered(self):
        c = verify_signed(self.env, self.ks.public())
        self.assertEqual((c.signer_suite, c.digest_alg), ("hybrid-mldsa65-ed25519", "sha384"))
        for i in (0, 1):
            env = json.loads(json.dumps(self.env))
            env["signature"]["sig"] = flip_component(env["signature"]["sig"], i)
            with self.assertRaises(ConstitutionSignatureError):
                verify_signed(env, self.ks.public())

    def test_constitution_downgrade_to_classical_refused(self):
        ed_half = self.ks._privs[1]  # the principal's own Ed25519 component key
        legacy_env = sign_document(self.env["constitution"], ed_half)
        with self.assertRaises(ConstitutionSignatureError) as cm:
            verify_signed(legacy_env, self.ks.public())
        self.assertIn("downgrade refused", str(cm.exception))
        forged = json.loads(json.dumps(legacy_env))
        forged["signature"]["alg"] = "hybrid-mldsa65-ed25519"
        forged["signature"]["public_key"] = self.ks.public().encoded
        with self.assertRaises(ConstitutionSignatureError):
            verify_signed(forged, self.ks.public())

    def test_ledger_head_hybrid_and_tamper(self):
        L = PersonalLedger(self.d / "l.jsonl", signing_key=self.ks)
        for i in range(5):
            L.append("e", {"i": i})
        self.assertEqual((L.digest_alg, len(L.tip())), ("sha384", 96))
        self.assertEqual(PersonalLedger(self.d / "l.jsonl").verify(self.ks.public()).reason, "ok")
        good = L.head_path.read_text()
        for i in (0, 1):
            h = json.loads(good)
            h["sig"] = flip_component(h["sig"], i)
            L.head_path.write_text(json.dumps(h))
            self.assertEqual(PersonalLedger(self.d / "l.jsonl").verify(self.ks.public()).reason,
                             "head_signature_invalid")
        L.head_path.write_text(good)
        p = L.inclusion_proof(2)
        self.assertEqual(p["alg"], "sha384")
        self.assertTrue(PersonalLedger.verify_inclusion_proof(p))

    def test_ledger_head_suite_downgrade_refused(self):
        L = PersonalLedger(self.d / "l.jsonl", signing_key=self.ks)
        L.append("e", {})
        h = json.loads(L.head_path.read_text())
        h["head"].pop("suite")
        L.head_path.write_text(json.dumps(h))
        self.assertEqual(PersonalLedger(self.d / "l.jsonl").verify(self.ks.public()).reason, "head_suite_mismatch")

    def test_two_key_end_to_end_require_pq(self):
        tk = TwoKey(self.env, self.ks.public(), self.d / "k.jsonl", YES, ledger_signing_key=self.ks,
                          allow_test_doubles=True, require_pq=True)
        self.assertEqual(tk.crypto_profile()["pq_backend"]["backend"], "pyca-cryptography")
        dec = tk.authorize(PAY, "Pay.", PAY_ARGS)
        self.assertTrue(dec.allowed, dec.reason)
        self.assertEqual(len(dec.token_payload["args_hash"]), 96)
        self.assertEqual(len(dec.token_payload["constitution_digest"]), 96)
        r = tk.gateway().invoke(dec.capability, "pay_bill", PAY_ARGS, PAY_FIELDS)
        self.assertEqual(r.reason, "authorized_no_executor")
        self.assertEqual(PersonalLedger(self.d / "k.jsonl").verify(self.ks.public()).reason, "ok")

    def test_signed_capability_tokens(self):
        tk = PrivateKeySet.generate("hybrid-mldsa65-ed25519")
        issuer = CapabilityIssuer(mode="tk1-sig", signing_key=tk)
        verifier = CapabilityIssuer(mode="tk1-sig", verify_key=tk.public())  # gateway side: no signing key
        cap = issuer.issue(principal="p", tool="t", scope={}, args_digest="h", ledger_root="r",
                           constitution_digest="c", ttl_seconds=30)
        self.assertTrue(cap.token.startswith("tk1-sig."))
        self.assertEqual(verifier.verify(cap.token)["jti"], cap.payload["jti"])
        prefix, body, tag = cap.token.split(".")
        raw = bytearray(base64.urlsafe_b64decode(tag + "=" * (-len(tag) % 4)))
        raw[len(raw) // 3] ^= 1
        bad = f"{prefix}.{body}." + base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
        with self.assertRaises(TokenError) as cm:
            verifier.verify(bad)
        self.assertEqual(cm.exception.reason, "bad_signature")
        mac_tok = CapabilityIssuer(os.urandom(32)).issue(principal="p", tool="t", scope={}, args_digest="h",
                                                         ledger_root="r", constitution_digest="c", ttl_seconds=30)
        with self.assertRaises(TokenError) as cm:
            verifier.verify(mac_tok.token)
        self.assertEqual(cm.exception.reason, "unsupported_token_version")

    def test_two_key_with_signed_tokens(self):
        tk = PrivateKeySet.generate("hybrid-mldsa65-ed25519")
        tk = TwoKey(self.env, self.ks.public(), self.d / "k.jsonl", YES, ledger_signing_key=self.ks,
                          allow_test_doubles=True, token_mode="tk1-sig", token_signing_key=tk)
        dec = tk.authorize(PAY, "Pay.", PAY_ARGS)
        self.assertTrue(dec.capability.startswith("tk1-sig."))
        self.assertEqual(tk.gateway().invoke(dec.capability, "pay_bill", PAY_ARGS, PAY_FIELDS).reason,
                         "authorized_no_executor")

    def test_cli_hybrid_keygen_sign_verify(self):
        os.environ["TWOKEY_TEST_PASS"] = "test-only passphrase"
        try:
            ex = Path(__file__).resolve().parent.parent / "examples"
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(cli_main(["keygen", "--out", str(self.d / "k"), "--suite", "hybrid-mldsa65-p384",
                                           "--passphrase-env", "TWOKEY_TEST_PASS"]), 0)
                self.assertEqual(cli_main(["sign-constitution", "--text", str(ex / "constitution.md"),
                                           "--rules", str(ex / "hard_rules.json"), "--principal", "did:twokey:t",
                                           "--key", str(self.d / "k" / "principal.keys.json"),
                                           "--out", str(self.d / "s.json"), "--passphrase-env", "TWOKEY_TEST_PASS"]), 0)
                self.assertEqual(cli_main(["verify-constitution", "--signed", str(self.d / "s.json"),
                                           "--pub", str(self.d / "k" / "principal.pub.json")]), 0)
            self.assertIn("digest=sha384:", out.getvalue())
        finally:
            del os.environ["TWOKEY_TEST_PASS"]


@unittest.skipIf(PQ, "an ML-DSA backend is installed")
class MissingPQRealEnvironment(unittest.TestCase):
    """Runs only where no ML-DSA backend exists (e.g. system cryptography 43)."""

    def test_hybrid_keygen_fails_clearly(self):
        with self.assertRaises(PQUnavailableError) as cm:
            PrivateKeySet.generate("hybrid-mldsa65-ed25519")
        self.assertIn("Refusing to downgrade", str(cm.exception))

    def test_cli_selftest_require_pq_fails(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli_main(["selftest", "--require-pq"]), 1)
        self.assertIn("no ML-DSA backend", out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
