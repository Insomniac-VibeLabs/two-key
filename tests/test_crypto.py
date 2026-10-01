"""Crypto provider: FIPS-mode rejection, self-test, backend selection, missing-PQ behaviour,
ECDSA P-384 suite, encrypted key bundles. These run on every interpreter (no ML-DSA needed)."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from two_key import keys
from two_key.capability import CapabilityIssuer, TokenError
from two_key.cli import main as cli_main
from two_key.constitution import (ConstitutionSignatureError, build_document, sign_document,
                                         verify_signed)
from two_key.crypto import (CryptoPolicyError, CryptoProvider, PQUnavailableError, PrivateKeySet,
                                   SelfTestError, openssl_fips_status, public_keyset_from_encoded)
from two_key.crypto import selftest as st
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.ledger import PersonalLedger
from two_key.testing import FixedJudge
from crypto_helpers import PQ, fake_oqs, flip_component, no_oqs, pyca_without_mldsa
from helpers import DEFAULT_TEXT, signed

RULES = [{"id": "tools", "allow_only_tools": ["pay_bill"]}, {"id": "cap", "deny_if": {"amount_usd_gt": 200}}]
YES = [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2")]
PAY = {"tool": "pay_bill", "amount_usd": 42.5, "counterparty": "power-co.example", "data_class": "financial"}
PAY_ARGS = {"payee": "power-co.example", "amount": 42.5}
PAY_FIELDS = {"amount_usd": 42.5, "counterparty": "power-co.example", "data_class": "financial"}


class FipsModeRejection(unittest.TestCase):
    def setUp(self):
        self.fips = CryptoProvider(fips_mode=True)
        self.lax = CryptoProvider(fips_mode=False)

    def test_approved_algorithms_work_in_fips_mode(self):
        for alg in ("sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"):
            self.assertTrue(self.fips.hash_hex(alg, b"x"))
        self.assertEqual(len(self.fips.hmac("hmac-sha384", b"k" * 48, b"m")), 48)
        for alg in ("ed25519", "ecdsa-p384", "ml-dsa-65"):
            self.fips.check("sig", alg)

    def test_non_approved_hashes_refused(self):
        for alg in ("blake2b", "md5", "sha1"):
            with self.assertRaises(CryptoPolicyError):
                self.fips.hash(alg, b"x")
            self.lax.hash(alg, b"x")  # known but non-approved: only allowed outside fips_mode

    def test_non_approved_macs_and_rng_refused(self):
        for alg in ("hmac-md5", "hmac-sha1", "hmac-blake2b"):
            with self.assertRaises(CryptoPolicyError):
                self.fips.hmac_factory(alg, b"k" * 32)
        with self.assertRaises(CryptoPolicyError):
            self.fips.check("rng", "random")

    def test_unknown_algorithms_refused_in_any_mode(self):
        for p in (self.fips, self.lax):
            with self.assertRaises(CryptoPolicyError):
                p.hash("sha224", b"x")
            with self.assertRaises(CryptoPolicyError):
                p.check("sig", "rsa-1024")

    def test_short_hmac_key_refused(self):
        with self.assertRaises(CryptoPolicyError):
            self.lax.hmac_factory("hmac-sha256", b"k" * 31)
        with self.assertRaises(ValueError):
            CapabilityIssuer(b"k" * 16, mode="tk1-hs384")

    def test_ledger_and_two_key_refuse_non_approved_digest_in_fips_mode(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(CryptoPolicyError):
                PersonalLedger(Path(d) / "l.jsonl", digest_alg="blake2b", crypto=self.fips)
            env, key = signed(RULES)
            with self.assertRaises(CryptoPolicyError):
                TwoKey(env, key.public_key(), Path(d) / "k.jsonl", YES, ledger_signing_key=key,
                              allow_test_doubles=True, crypto=self.fips, digest_alg="blake2b")
            # The same TwoKey setup runs in fips_mode with approved algorithms.
            tk = TwoKey(env, key.public_key(), Path(d) / "k2.jsonl", YES, ledger_signing_key=key,
                              allow_test_doubles=True, crypto=self.fips)
            self.assertTrue(tk.authorize(PAY, "Pay.", PAY_ARGS).allowed)
            self.assertTrue(tk.crypto_profile()["fips_mode"])

    def test_liboqs_refused_in_fips_mode(self):
        with self.assertRaises(CryptoPolicyError):
            CryptoProvider(fips_mode=True, pq_backend="liboqs")
        with fake_oqs(), pyca_without_mldsa():
            self.assertIsNotNone(CryptoProvider(pq_backend="auto").pq_backend())            # lax: liboqs ok
            self.assertIsNone(CryptoProvider(fips_mode=True, pq_backend="auto").pq_backend())  # fips: never

    @unittest.skipIf(openssl_fips_status()["cryptography_fips"] and openssl_fips_status()["hashlib_fips"],
                     "a FIPS provider is active on this machine")
    def test_require_fips_module_refuses_without_validated_module(self):
        with self.assertRaises(CryptoPolicyError) as cm:
            CryptoProvider(fips_mode=True, require_fips_module=True)
        self.assertIn("validated module", str(cm.exception))

    def test_cli_refuses_fips_with_liboqs(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli_main(["--fips", "--pq-backend", "liboqs", "selftest"]), 2)
        self.assertIn("REFUSED", out.getvalue())

    def test_describe_never_claims_validation(self):
        claim = CryptoProvider(fips_mode=True).describe()["claim"]
        self.assertIn("not FIPS certified/validated", claim)


class SelfTest(unittest.TestCase):
    def test_selftest_passes_and_is_cached(self):
        p = CryptoProvider()
        r = p.ensure_selftest()
        self.assertTrue(r["ok"])
        for name in ("KAT sha256", "KAT sha384", "KAT sha3-256", "KAT hmac-sha256 (RFC 4231 TC2)",
                     "KAT hmac-sha384 (RFC 4231 TC2)", "KAT Ed25519 (RFC 8032 TEST 1)", "PCT ECDSA P-384"):
            self.assertIn(name, r["passed"])
        if PQ:
            self.assertIn("PCT ML-DSA-65 (pyca)", r["passed"])
        with mock.patch.object(st, "run_selftest", side_effect=AssertionError("must not rerun")):
            self.assertIs(p.ensure_selftest(), r)

    def test_forced_hash_kat_failure(self):
        with mock.patch.dict(st.KATS, {"sha256": (b"abc", "00" * 32)}):
            with self.assertRaises(SelfTestError) as cm:
                CryptoProvider().ensure_selftest()
        self.assertIn("KAT sha256", str(cm.exception))

    def test_forced_ed25519_kat_failure(self):
        with mock.patch.dict(st.ED25519_KAT, {"sig": "00" * 64}):
            with self.assertRaises(SelfTestError):
                CryptoProvider().ensure_selftest()

    def test_broken_provider_fails_selftest_and_two_key_refuses_to_start(self):
        class Broken(CryptoProvider):
            def hash_hex(self, alg, data):
                return "f" * 96 if alg == "sha384" else super().hash_hex(alg, data)

        with self.assertRaises(SelfTestError):
            Broken().ensure_selftest()
        env, key = signed(RULES)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SelfTestError):
                TwoKey(env, key.public_key(), Path(d) / "l.jsonl", YES, ledger_signing_key=key,
                              allow_test_doubles=True, crypto=Broken())
            self.assertFalse((Path(d) / "l.jsonl").exists())  # nothing was written

    def test_two_key_records_selftest_and_profile(self):
        env, key = signed(RULES)
        with tempfile.TemporaryDirectory() as d:
            tk = TwoKey(env, key.public_key(), Path(d) / "l.jsonl", YES, ledger_signing_key=key,
                              allow_test_doubles=True)
            prof = tk.ledger.entries[0].body["crypto"]
            self.assertEqual((prof["signature_suite"], prof["digest_alg"], prof["token_mode"]),
                             ("ed25519", "sha256", "tk1"))
            self.assertTrue(prof["selftest"]["ok"])

    def test_cli_selftest(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli_main(["selftest"]), 0)
        self.assertIn("KAT Ed25519", out.getvalue())


class MissingPQLibrary(unittest.TestCase):
    """Hybrid is required but ML-DSA is unavailable: fail clearly, never downgrade."""

    def _hybrid_under_fake(self):
        with fake_oqs():
            p = CryptoProvider(pq_backend="liboqs")
            return p, PrivateKeySet.generate("hybrid-mldsa65-ed25519", p)

    def test_backend_none_refuses_hybrid_keygen(self):
        with self.assertRaises(PQUnavailableError) as cm:
            PrivateKeySet.generate("hybrid-mldsa65-p384", CryptoProvider(pq_backend="none"))
        self.assertIn("Refusing to downgrade", str(cm.exception))

    def test_pyca_without_mldsa_and_no_liboqs(self):
        with pyca_without_mldsa(), no_oqs():
            for choice in ("auto", "pyca", "liboqs"):
                p = CryptoProvider(pq_backend=choice)
                self.assertIsNone(p.pq_backend())
                with self.assertRaises(PQUnavailableError):
                    p.require_pq()
            # Classic suites still work without any PQ library.
            k = PrivateKeySet.generate("ecdsa-p384", CryptoProvider(pq_backend="auto"))
            self.assertTrue(k.public().verify(b"m", k.sign(b"m")))

    def test_liboqs_without_mldsa65_mechanism(self):
        with fake_oqs(mechs=("Falcon-512",)):
            self.assertIsNone(CryptoProvider(pq_backend="liboqs").pq_backend())

    def test_verifying_hybrid_without_backend_raises_not_downgrades(self):
        p, ks = self._hybrid_under_fake()
        env = sign_document(build_document("did:twokey:t", DEFAULT_TEXT, RULES), ks, p)
        self.assertEqual(verify_signed(env, ks.public(), p).signer_suite, "hybrid-mldsa65-ed25519")
        none = CryptoProvider(pq_backend="none")
        with self.assertRaises(PQUnavailableError):
            public_keyset_from_encoded(ks.public().encoded, none)
        with self.assertRaises(PQUnavailableError):
            verify_signed(env, public_keyset_from_encoded(ks.public().encoded, none), none)

    def test_two_key_with_hybrid_key_and_no_backend_refuses_to_start(self):
        p, ks = self._hybrid_under_fake()
        env = sign_document(build_document("did:twokey:t", DEFAULT_TEXT, RULES), ks, p)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(PQUnavailableError):
                TwoKey(env, ks.public(), Path(d) / "l.jsonl", YES,
                              ledger_signing_key=ks, allow_test_doubles=True,
                              crypto=CryptoProvider(pq_backend="none"))

    def test_require_pq_with_classic_key_refused(self):
        env, key = signed(RULES)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(TwoKeyConfigError):
                TwoKey(env, key.public_key(), Path(d) / "l.jsonl", YES, ledger_signing_key=key,
                              allow_test_doubles=True, require_pq=True)

    def test_fake_liboqs_backend_end_to_end(self):
        """The liboqs adapter plumbing (hybrid sign/verify/tamper, Two-Key start) with a fake oqs module."""
        p, ks = self._hybrid_under_fake()
        self.assertEqual(p.pq_backend().describe()["backend"], "liboqs-python")
        sig = ks.sign(b"msg")
        self.assertTrue(ks.public().verify(b"msg", sig))
        self.assertFalse(ks.public().verify(b"msg", flip_component(sig, 0)))
        self.assertFalse(ks.public().verify(b"msg", flip_component(sig, 1)))
        env = sign_document(build_document("did:twokey:t", DEFAULT_TEXT, RULES), ks, p)
        with tempfile.TemporaryDirectory() as d:
            tk = TwoKey(env, ks.public(), Path(d) / "l.jsonl", YES, ledger_signing_key=ks,
                              allow_test_doubles=True, crypto=p, require_pq=True)
            dec = tk.authorize(PAY, "Pay.", PAY_ARGS)
            self.assertTrue(dec.allowed, dec.reason)
            self.assertTrue(dec.capability.startswith("tk1-hs384."))
            self.assertEqual(tk.gateway().invoke(dec.capability, "pay_bill", PAY_ARGS, PAY_FIELDS).reason,
                             "authorized_no_executor")
            self.assertEqual(tk.ledger.verify(ks.public()).reason, "ok")


class ClassicSuites(unittest.TestCase):
    def test_ecdsa_p384_constitution_and_two_key(self):
        ks = PrivateKeySet.generate("ecdsa-p384")
        env = sign_document(build_document("did:twokey:t", DEFAULT_TEXT, RULES), ks)
        c = verify_signed(env, ks.public())
        self.assertEqual((c.signer_suite, c.digest_alg, len(c.digest)), ("ecdsa-p384", "sha384", 96))
        bad = dict(env, constitution=dict(env["constitution"], principal="did:twokey:mallory"))
        with self.assertRaises(ConstitutionSignatureError):
            verify_signed(bad, ks.public())
        with tempfile.TemporaryDirectory() as d:
            tk = TwoKey(env, ks.public(), Path(d) / "l.jsonl", YES, ledger_signing_key=ks,
                              allow_test_doubles=True)
            dec = tk.authorize(PAY, "Pay.", PAY_ARGS)
            self.assertTrue(dec.allowed and dec.capability.startswith("tk1-hs384."))
            self.assertEqual(len(tk.ledger.tip()), 96)
            self.assertEqual(tk.gateway().invoke(dec.capability, "pay_bill", PAY_ARGS, PAY_FIELDS).reason,
                             "authorized_no_executor")
            self.assertEqual(PersonalLedger(Path(d) / "l.jsonl").verify(ks.public()).reason, "ok")

    def test_legacy_signature_refused_for_p384_trusted_key(self):
        ks = PrivateKeySet.generate("ecdsa-p384")
        legacy_env, _ = signed(RULES)
        with self.assertRaises(ConstitutionSignatureError) as cm:
            verify_signed(legacy_env, ks.public())
        self.assertIn("downgrade refused", str(cm.exception))

    def test_hs384_issuer_refuses_ck1_tokens(self):
        a = CapabilityIssuer(b"k" * 48, mode="tk1")
        b = CapabilityIssuer(b"k" * 48, mode="tk1-hs384")
        tok = a.issue(principal="p", tool="t", scope={}, args_digest="h", ledger_root="r",
                      constitution_digest="c", ttl_seconds=5).token
        with self.assertRaises(TokenError) as cm:
            b.verify(tok)
        self.assertEqual(cm.exception.reason, "unsupported_token_version")
        # Relabelled prefix: the MAC no longer matches.
        with self.assertRaises(TokenError) as cm:
            b.verify("tk1-hs384." + tok.split(".", 1)[1])
        self.assertEqual(cm.exception.reason, "bad_signature")

    def test_public_key_parsing_is_cached(self):
        ks = PrivateKeySet.generate("ecdsa-p384")
        self.assertIs(public_keyset_from_encoded(ks.public().encoded),
                      public_keyset_from_encoded(ks.public().encoded))


class KeyBundles(unittest.TestCase):
    def test_encrypted_bundle_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            ks = PrivateKeySet.generate("ecdsa-p384")
            path = Path(d) / "k.keys.json"
            keys.save_keyset(path, ks, b"correct horse battery")
            self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
            self.assertNotIn(ks.export_components()[0]["raw"], path.read_text())
            ks2 = keys.load_private_any(path, b"correct horse battery")
            self.assertEqual(ks2.public().encoded, ks.public().encoded)
            with self.assertRaises(ValueError):
                keys.load_keyset(path, b"wrong")
            with self.assertRaises(ValueError):
                keys.load_keyset(path, None)
            keys.save_public_keyset(Path(d) / "k.pub.json", ks.public())
            self.assertEqual(keys.load_public_any(Path(d) / "k.pub.json"), ks.public())


if __name__ == "__main__":
    unittest.main(verbosity=2)
