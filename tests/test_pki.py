"""Enterprise PKI identities (pki.py; CONCEPTION_NOTES.md Entry 11): chain, expiry, revocation (CRL, OCSP,
fail-closed), key usage, role mapping, the ML-DSA-65 binding extension, PKCS#11 keys, and TwoKey enterprise mode."""

import datetime as dt
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from two_key import pki
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.crypto import CryptoProvider
from two_key.crypto.signatures import pq_available
from two_key.pki import CertificateRejected, Credential, PkiConfig, PkiVerifier
from two_key.pki_testing import SoftwareToken, TestPki
from two_key.quorum import QuorumPolicy
from two_key.testing import FixedJudge
from helpers import AGENT_URI, PRINCIPAL_EMAIL, ROLE_MAP, TwoKeyFixture, enterprise_pki, signed

PQ = pq_available()
RULES = [{"id": "tools", "allow_only_tools": ["email_send"]}]
YES = [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2")]
QP = QuorumPolicy(required_yes=2)
ACTION = {"tool": "email_send", "counterparty": "a@example.com", "data_class": "public", "irreversible": False}
ARGS = {"to": "a@example.com", "body": "hi"}


class FakeAnchorGateway:
    def __init__(self):
        self.state, self.txs = {}, {}

    def submit_transaction(self, channel, chaincode, function, args):
        tx = f"tx{len(self.txs)}"
        self.state.setdefault(args[0], args[1])
        self.txs[tx] = {"tx_id": tx, "block_number": len(self.txs), "validation_code": "VALID",
                        "endorsing_orgs": ["Org1MSP"]}
        return dict(self.txs[tx])

    def evaluate_transaction(self, channel, chaincode, function, args):
        return self.state.get(args[0], "").encode()

    def get_transaction(self, channel, tx_id):
        return self.txs.get(tx_id)


def fabric():
    from two_key.anchoring import FabricAnchor
    return FabricAnchor(FakeAnchorGateway(), channel="audit", chaincode="twokey-anchor")


class Chain(unittest.TestCase):
    def setUp(self):
        self.t = TestPki()
        self.cred, self.ks = self.t.identity("Alice", email=PRINCIPAL_EMAIL)

    def v(self, **kw):
        return PkiVerifier(self.t.config(ROLE_MAP, **kw))

    def test_valid_leaf_chain_and_identity_record(self):
        ident = self.v().verify(self.cred, "principal")
        self.assertEqual((ident.role, ident.roles, ident.public_keyset.suite), ("principal", ("principal",), "ecdsa-p384"))
        self.assertEqual(ident.public_keyset.encoded, self.ks.public().encoded)
        rec = ident.to_record()
        self.assertIn(f"email:{PRINCIPAL_EMAIL}", rec["names"])
        self.assertEqual([r["status"] for r in rec["revocation"]], ["good", "good"])  # leaf and intermediate
        json.dumps(rec)

    def test_ed25519_leaf(self):
        cert, _ = self.t.issue("Ed", email=PRINCIPAL_EMAIL, key=ed25519.Ed25519PrivateKey.generate())
        self.assertEqual(self.v().verify(self.t.credential(cert), "principal").public_keyset.suite, "ed25519")

    def test_expired_and_not_yet_valid(self):
        with self.assertRaises(CertificateRejected) as cm:
            self.v().verify(self.cred, "principal", at=self.t.now + dt.timedelta(days=31))
        self.assertEqual(cm.exception.reason, "expired")
        future, _ = self.t.issue("Later", email=PRINCIPAL_EMAIL, not_before=self.t.now + dt.timedelta(days=2))
        with self.assertRaises(CertificateRejected) as cm:
            self.v().verify(self.t.credential(future), "principal")
        self.assertEqual(cm.exception.reason, "not_yet_valid")
        clocked = PkiVerifier(self.t.config(ROLE_MAP), clock=lambda: (self.t.now + dt.timedelta(days=60)).timestamp())
        with self.assertRaises(CertificateRejected):
            clocked.verify(self.cred, "principal")

    def test_wrong_chain(self):
        other = TestPki()
        with self.assertRaises(CertificateRejected) as cm:
            PkiVerifier(other.config(ROLE_MAP)).verify(self.cred, "principal")
        self.assertEqual(cm.exception.reason, "chain")
        # Missing intermediate: the leaf alone does not chain to the root.
        with self.assertRaises(CertificateRejected) as cm:
            self.v().verify(Credential(self.cred.certificate, []), "principal")
        self.assertEqual(cm.exception.reason, "chain")
        # A leaf issued by another PKI's intermediate presented with ours.
        foreign, _ = other.issue("Mallory", email=PRINCIPAL_EMAIL)
        with self.assertRaises(CertificateRejected):
            self.v().verify(Credential(foreign, [self.t.intermediate]), "principal")
        # Configured intermediates are used for path building.
        cfg = self.t.config(ROLE_MAP, intermediates=[self.t.intermediate])
        PkiVerifier(cfg).verify(Credential(self.cred.certificate, []), "principal")

    def test_key_usage(self):
        cert, _ = self.t.issue("NoSign", email=PRINCIPAL_EMAIL, digital_signature=False)
        with self.assertRaises(CertificateRejected) as cm:
            self.v().verify(self.t.credential(cert), "principal")
        self.assertEqual(cm.exception.reason, "key_usage")

    def test_unsupported_key_type(self):
        cert, _ = self.t.issue("P256", email=PRINCIPAL_EMAIL, key=ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaises(CertificateRejected) as cm:
            self.v().verify(self.t.credential(cert), "principal")
        self.assertEqual(cm.exception.reason, "key_type")


class Revocation(unittest.TestCase):
    def setUp(self):
        self.t = TestPki()
        self.cred, _ = self.t.identity("Alice", email=PRINCIPAL_EMAIL)

    def reason(self, **kw):
        try:
            PkiVerifier(self.t.config(ROLE_MAP, **kw)).verify(self.cred, "principal")
        except CertificateRejected as e:
            return e.reason
        return "ok"

    def test_revoked_leaf_by_crl_and_by_ocsp(self):
        self.t.revoke(self.cred.certificate)
        self.assertEqual(self.reason(), "revoked")                                   # CRL
        self.assertEqual(self.reason(ocsp=True, crl=False), "revoked")               # OCSP
        self.assertEqual(self.reason(ocsp=True, crl=False, revocation="ocsp"), "revoked")

    def test_revoked_intermediate(self):
        self.t.revoke(self.t.intermediate)
        self.assertEqual(self.reason(), "revoked")
        self.assertEqual(self.reason(ocsp=True, crl=False), "revoked")

    def test_fail_closed_is_the_default_when_unreachable(self):
        self.assertEqual(pki.DEFAULT_REVOCATION_UNREACHABLE, "fail_closed")
        self.assertEqual(self.reason(crl=False), "revocation_unreachable")           # nothing configured
        cfg = self.t.config(ROLE_MAP, crl=False)
        cfg.ocsp_fetcher = self.t.ocsp_fetcher(unreachable=True)
        with self.assertRaisesRegex(CertificateRejected, "placeholder pending Stephan"):
            PkiVerifier(cfg).verify(self.cred, "principal")

    def test_fail_open_setting_records_unreachable(self):
        ident = PkiVerifier(self.t.config(ROLE_MAP, crl=False, revocation_unreachable="fail_open")).verify(
            self.cred, "principal")
        self.assertEqual({r[2] for r in ident.revocation}, {"unreachable"})
        self.t.revoke(self.cred.certificate)  # fail_open never overrides a definite "revoked"
        self.assertEqual(self.reason(revocation_unreachable="fail_open"), "revoked")

    def test_ocsp_unreachable_falls_back_to_crl(self):
        cfg = self.t.config(ROLE_MAP)
        cfg.ocsp_fetcher = self.t.ocsp_fetcher(unreachable=True)
        ident = PkiVerifier(cfg).verify(self.cred, "principal")
        self.assertEqual({r[1] for r in ident.revocation}, {"crl"})

    def test_stale_or_forged_crl_is_no_answer(self):
        stale = self.t.crl(next_update_days=1, last_update=self.t.now - dt.timedelta(days=3))
        cfg = PkiConfig(trust_anchors=[self.t.root], crls=[stale, self.t.crl(by_root=True)], role_map=ROLE_MAP)
        with self.assertRaises(CertificateRejected) as cm:
            PkiVerifier(cfg).verify(self.cred, "principal")
        self.assertEqual(cm.exception.reason, "revocation_unreachable")
        other = TestPki()
        forged = (x509.CertificateRevocationListBuilder().issuer_name(self.t.intermediate.subject)
                  .last_update(self.t.now - dt.timedelta(hours=1)).next_update(self.t.now + dt.timedelta(days=1))
                  .sign(other.intermediate_key, hashes.SHA384()))
        cfg = PkiConfig(trust_anchors=[self.t.root], crls=[forged, self.t.crl(by_root=True)], role_map=ROLE_MAP)
        with self.assertRaises(CertificateRejected):
            PkiVerifier(cfg).verify(self.cred, "principal")

    def test_ocsp_response_from_wrong_signer_is_no_answer(self):
        other = TestPki()
        good = self.t.ocsp_fetcher()

        def forged(url, req):  # a valid-looking response, signed by another CA
            other.issued.update({s: (c, i, other.intermediate_key) for s, (c, i, _) in self.t.issued.items()})
            return other.ocsp_fetcher()(url, req)
        cfg = self.t.config(ROLE_MAP, crl=False)
        cfg.ocsp_fetcher = forged
        with self.assertRaises(CertificateRejected) as cm:
            PkiVerifier(cfg).verify(self.cred, "principal")
        self.assertEqual(cm.exception.reason, "revocation_unreachable")
        cfg.ocsp_fetcher = good
        PkiVerifier(cfg).verify(self.cred, "principal")

    def test_crl_fetched_from_distribution_point(self):
        fetched = []

        def fetch(url):
            fetched.append(url)
            crl = self.t.crl(by_root="root" in url)
            return crl.public_bytes(serialization.Encoding.DER)
        cfg = PkiConfig(trust_anchors=[self.t.root], crl_fetcher=fetch, role_map=ROLE_MAP, revocation="crl")
        PkiVerifier(cfg).verify(self.cred, "principal")
        self.assertEqual(len(fetched), 2)


class Roles(unittest.TestCase):
    def setUp(self):
        self.t = TestPki()

    def test_san_and_subject_mapping(self):
        agent, _ = self.t.identity("Agent 7", uri=AGENT_URI)
        judge, _ = self.t.identity("Judge", dns="judge.two-key.test.invalid")
        by_dn, _ = self.t.identity("Bob")
        rm = dict(ROLE_MAP, **{"subject:CN=Bob,O=Two-Key Test PKI": ["principal", "agent"]})
        v = PkiVerifier(self.t.config(rm))
        self.assertEqual(v.verify(agent, "agent").roles, ("agent",))
        self.assertEqual(v.verify(judge, "judge").role, "judge")
        self.assertEqual(v.verify(by_dn, "agent").roles, ("agent", "principal"))
        for cred, role in ((agent, "principal"), (judge, "agent")):
            with self.assertRaises(CertificateRejected) as cm:
                v.verify(cred, role)
            self.assertEqual(cm.exception.reason, "role")
        unmapped, _ = self.t.identity("Nobody", email="nobody@example.com")
        with self.assertRaises(CertificateRejected):
            v.verify(unmapped, "agent")

    def test_role_map_validation(self):
        for bad in ({"alice": ["principal"]}, {"email:a@b": ["admin"]}):
            with self.assertRaises(pki.PkiConfigError):
                self.t.config(bad)
        with self.assertRaises(pki.PkiConfigError):
            PkiConfig(trust_anchors=[], role_map={})
        with self.assertRaises(pki.PkiConfigError):
            self.t.config(ROLE_MAP, revocation_unreachable="ignore")


@unittest.skipUnless(PQ, "needs an ML-DSA-65 backend (cryptography>=50)")
class HybridBinding(unittest.TestCase):
    def setUp(self):
        self.t = TestPki()
        self.v = PkiVerifier(self.t.config(ROLE_MAP))

    def test_extension_binds_the_mldsa_key(self):
        cred, ks = self.t.identity("Alice", email=PRINCIPAL_EMAIL, pq=True)
        ident = self.v.verify(cred, "principal")
        self.assertEqual((ident.public_keyset.suite, ident.mldsa_bound), ("hybrid-mldsa65-p384", True))
        self.assertTrue(ident.public_keyset.verify(b"m", ks.sign(b"m")))
        ext = cred.certificate.extensions.get_extension_for_oid(pki.MLDSA_BINDING_OID)
        self.assertFalse(ext.critical)

    def test_wrong_missing_or_unbound_mldsa_key(self):
        cred, _ = self.t.identity("Alice", email=PRINCIPAL_EMAIL, pq=True)
        other, _ = self.t.identity("Other", email=PRINCIPAL_EMAIL, pq=True)
        for c in (Credential(cred.certificate, cred.chain, other.mldsa_public),     # wrong key
                  Credential(cred.certificate, cred.chain, None)):                  # downgrade
            with self.assertRaises(CertificateRejected) as cm:
                self.v.verify(c, "principal")
            self.assertEqual(cm.exception.reason, "mldsa_binding")
        classical, _ = self.t.identity("Classic", email=PRINCIPAL_EMAIL)
        with self.assertRaises(CertificateRejected):
            self.v.verify(Credential(classical.certificate, classical.chain, cred.mldsa_public), "principal")

    def test_ed25519_hybrid(self):
        cred, ks = self.t.identity("Ed", email=PRINCIPAL_EMAIL, pq=True, key=ed25519.Ed25519PrivateKey.generate())
        self.assertEqual(self.v.verify(cred, "principal").public_keyset.suite, "hybrid-mldsa65-ed25519")


class Pkcs11(unittest.TestCase):
    def test_software_token_keys_sign_through_the_token(self):
        tok = SoftwareToken()
        for kind, suite in (("p384", "ecdsa-p384"), ("ed25519", "ed25519")):
            k = tok.generate(f"k-{kind}", kind)
            ks = pki.signing_keyset(k)
            self.assertEqual(ks.suite, suite)
            self.assertTrue(ks.public().verify(b"msg", ks.sign(b"msg")))
            with self.assertRaises(TypeError):
                k.private_bytes()
        self.assertEqual([m for _, m in tok.calls], ["ECDSA", "EDDSA"])
        from two_key.crypto.signatures import as_private_keyset
        moved = as_private_keyset(pki.signing_keyset(tok.generate("x")), CryptoProvider(fips_mode=True))
        self.assertTrue(moved.public().verify(b"m", moved.sign(b"m")))

    def test_token_key_certified_and_used_as_principal(self):
        t = TestPki()
        tok = SoftwareToken()
        cred, ks = t.identity("HSM Principal", email=PRINCIPAL_EMAIL, key=tok.generate("principal"))
        self.assertEqual(PkiVerifier(t.config(ROLE_MAP)).verify(cred, "principal").public_keyset.encoded,
                         ks.public().encoded)

    def test_missing_python_pkcs11_degrades_gracefully(self):
        with mock.patch.dict("sys.modules", {"pkcs11": None}):
            with self.assertRaisesRegex(pki.Pkcs11Unavailable, "pip install python-pkcs11"):
                pki.PythonPkcs11Token("/nonexistent.so", "t", "0000")

    @unittest.skipUnless(shutil.which("softhsm2-util") and Path("/usr/lib/softhsm/libsofthsm2.so").exists(),
                         "SoftHSM 2 not installed")
    def test_softhsm_token(self):
        try:
            import pkcs11
            from pkcs11.util.ec import encode_named_curve_parameters
        except ImportError:
            self.skipTest("python-pkcs11 not installed")
        lib_path = "/usr/lib/softhsm/libsofthsm2.so"
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "tokens").mkdir()
            conf = Path(d) / "softhsm2.conf"
            conf.write_text(f"directories.tokendir = {d}/tokens\nobjectstore.backend = file\nlog.level = ERROR\n")
            env = dict(os.environ, SOFTHSM2_CONF=str(conf))
            subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "tktest", "--pin", "1234",
                            "--so-pin", "5678"], env=env, check=True, capture_output=True)
            with mock.patch.dict("os.environ", {"SOFTHSM2_CONF": str(conf)}):
                lib = pkcs11.lib(lib_path)
                lib.reinitialize()
                with lib.get_token(token_label="tktest").open(user_pin="1234", rw=True) as s:
                    s.create_domain_parameters(pkcs11.KeyType.EC, {
                        pkcs11.Attribute.EC_PARAMS: encode_named_curve_parameters("secp384r1")},
                        local=True).generate_keypair(store=True, label="p384")
                tok = pki.PythonPkcs11Token(lib_path, "tktest", "1234")
                key = pki.Pkcs11PrivateKey(tok, "p384")
                t = TestPki()
                cred, ks = t.identity("SoftHSM", email=PRINCIPAL_EMAIL, key=key)
                ident = PkiVerifier(t.config(ROLE_MAP)).verify(cred, "principal")
                self.assertTrue(ident.public_keyset.verify(b"constitution", ks.sign(b"constitution")))


class Enterprise(unittest.TestCase):
    def test_refuses_to_start_without_pki_or_principal_certificate(self):
        env, key = signed(RULES)
        with tempfile.TemporaryDirectory() as d:
            base = dict(ledger_signing_key=key, quorum_policy=QP, allow_test_doubles=True,
                        deployment_mode="enterprise", anchor=fabric())
            with self.assertRaisesRegex(TwoKeyConfigError, "requires PKI identities.*placeholder"):
                TwoKey(env, key.public_key(), Path(d) / "l.jsonl", YES, **base)
            extra, _ = enterprise_pki(key)
            with self.assertRaisesRegex(TwoKeyConfigError, "requires principal_credential"):
                TwoKey(env, key.public_key(), Path(d) / "l.jsonl", YES, pki=extra["pki"], **base)
            other_key = ed25519.Ed25519PrivateKey.generate()
            wrong, t = enterprise_pki(other_key)
            with self.assertRaisesRegex(TwoKeyConfigError, "does not certify the trusted principal key"):
                TwoKey(env, key.public_key(), Path(d) / "l.jsonl", YES, **wrong, **base)
            extra, t = enterprise_pki(key)
            t.revoke(extra["principal_credential"].certificate)
            extra["pki"] = t.config(ROLE_MAP)
            with self.assertRaisesRegex(TwoKeyConfigError, "principal certificate rejected: revoked"):
                TwoKey(env, key.public_key(), Path(d) / "l.jsonl", YES, **extra, **base)
            extra, t = enterprise_pki(key, crl=False)
            with self.assertRaisesRegex(TwoKeyConfigError, "revocation_unreachable"):
                TwoKey(env, key.public_key(), Path(d) / "l.jsonl", YES, **extra, **base)
            self.assertFalse((Path(d) / "l.jsonl").exists())

    def test_personal_mode_unchanged_without_pki(self):
        with TwoKeyFixture(RULES, YES, quorum_policy=QP) as tk:
            self.assertIsNone(tk.pki)
            self.assertNotIn("identity", tk.ledger.entries[0].body)
            self.assertTrue(tk.authorize(ACTION, "Send it.", ARGS).allowed)

    def make(self, **kw):
        env, key = signed(RULES)
        extra, t = enterprise_pki(key, **kw.pop("config", {}))
        self.principal_credential = extra["principal_credential"]
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        tk = TwoKey(env, key.public_key(), Path(self.tmp.name) / "l.jsonl", YES, ledger_signing_key=key,
                    quorum_policy=QP, allow_test_doubles=True, deployment_mode="enterprise", anchor=fabric(),
                    **extra, **kw)
        return tk, t

    def test_agent_assertion_required_and_verified(self):
        tk, t = self.make()
        loaded = tk.ledger.entries[0].body["identity"]
        self.assertEqual(loaded["principal"]["role"], "principal")
        d = tk.authorize(ACTION, "Send it.", ARGS)
        self.assertEqual((d.allowed, d.reason), (False, "agent_identity_required"))
        agent, agent_key = t.identity("Agent", uri=AGENT_URI)
        a = pki.sign_agent_request(agent, agent_key, ACTION, "Send it.", ARGS)
        d = tk.authorize(ACTION, "Send it.", ARGS, agent_assertion=a)
        self.assertTrue(d.allowed, d.reason)
        rec = [e for e in tk.ledger.entries if e.kind == "agent_identity"][-1].body
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["identity"]["role"], "agent")
        # Replay of the same assertion is refused.
        self.assertEqual(tk.authorize(ACTION, "Send it.", ARGS, agent_assertion=a).reason,
                         "agent_identity_rejected:assertion_replay")
        # Bound to the request: other args, other proposal text.
        a2 = pki.sign_agent_request(agent, agent_key, ACTION, "Send it.", ARGS)
        self.assertEqual(tk.authorize(ACTION, "Send it.", dict(ARGS, body="other"), agent_assertion=a2).reason,
                         "agent_identity_rejected:assertion_binding")
        # Signed by a key other than the certified one.
        _, stranger = t.identity("Stranger", uri=AGENT_URI)
        a3 = pki.sign_agent_request(agent, stranger, ACTION, "Send it.", ARGS)
        self.assertEqual(tk.authorize(ACTION, "Send it.", ARGS, agent_assertion=a3).reason,
                         "agent_identity_rejected:assertion_signature")
        # A principal certificate is not an agent certificate.
        a4 = pki.sign_agent_request(self.principal_credential, agent_key, ACTION, "Send it.", ARGS)
        self.assertEqual(tk.authorize(ACTION, "Send it.", ARGS, agent_assertion=a4).reason,
                         "agent_identity_rejected:role")
        # Stale.
        old = pki.sign_agent_request(agent, agent_key, ACTION, "Send it.", ARGS, clock=lambda: 1_000_000)
        self.assertEqual(tk.authorize(ACTION, "Send it.", ARGS, agent_assertion=old).reason,
                         "agent_identity_rejected:assertion_stale")
        # Revoked agent.
        t.revoke(agent.certificate)
        tk.pki.config.crls = t.crls()
        a5 = pki.sign_agent_request(agent, agent_key, ACTION, "Send it.", ARGS)
        self.assertEqual(tk.authorize(ACTION, "Send it.", ARGS, agent_assertion=a5).reason,
                         "agent_identity_rejected:revoked")
        self.assertTrue(tk.ledger.verify(tk.trusted_keyset).ok)

    def test_judge_credentials(self):
        env, key = signed(RULES)
        extra, t = enterprise_pki(key)
        jcred, _ = t.identity("Judge A", dns="judge.two-key.test.invalid")
        with tempfile.TemporaryDirectory() as d:
            base = dict(ledger_signing_key=key, quorum_policy=QP, allow_test_doubles=True,
                        deployment_mode="enterprise", anchor=fabric(), **extra)
            tk = TwoKey(env, key.public_key(), Path(d) / "a.jsonl", YES, judge_credentials={"a": jcred}, **base)
            self.assertEqual(tk.ledger.entries[0].body["identity"]["judges"]["a"]["role"], "judge")
            with self.assertRaisesRegex(TwoKeyConfigError, "unknown judges"):
                TwoKey(env, key.public_key(), Path(d) / "b.jsonl", YES, judge_credentials={"zz": jcred}, **base)
            principal_as_judge = extra["principal_credential"]
            with self.assertRaisesRegex(TwoKeyConfigError, "judge 'a' certificate rejected: role"):
                TwoKey(env, key.public_key(), Path(d) / "c.jsonl", YES, judge_credentials={"a": principal_as_judge},
                       **base)
            base["pki"] = t.config(ROLE_MAP, require_judge_identities=True)
            with self.assertRaisesRegex(TwoKeyConfigError, "missing certificates for"):
                TwoKey(env, key.public_key(), Path(d) / "d.jsonl", YES, judge_credentials={"a": jcred}, **base)

    def test_pki_from_the_deployment_config_file(self):
        env, key = signed(RULES)
        t = TestPki()
        cert, _ = t.issue("Principal", email=PRINCIPAL_EMAIL, key=key)
        with tempfile.TemporaryDirectory() as d:
            pem = lambda c: c.public_bytes(serialization.Encoding.PEM)  # noqa: E731
            (Path(d) / "root.pem").write_bytes(pem(t.root))
            (Path(d) / "inter.pem").write_bytes(pem(t.intermediate))
            (Path(d) / "inter.crl").write_bytes(t.crl().public_bytes(serialization.Encoding.PEM))
            (Path(d) / "root.crl").write_bytes(t.crl(by_root=True).public_bytes(serialization.Encoding.DER))
            cfg = {"deployment_mode": "enterprise",
                   "pki": {"trust_anchors": ["root.pem"], "intermediates": ["inter.pem"],
                           "crls": ["inter.crl", "root.crl"], "role_map": ROLE_MAP}}
            (Path(d) / "two-key.json").write_text(json.dumps(cfg))
            tk = TwoKey(env, key.public_key(), Path(d) / "l.jsonl", YES, ledger_signing_key=key, quorum_policy=QP,
                        allow_test_doubles=True, deployment_config=Path(d) / "two-key.json", anchor=fabric(),
                        principal_credential=Credential(cert, []))
            self.assertEqual(tk.principal_identity.role, "principal")
            cfg["pki"]["bogus"] = 1
            (Path(d) / "bad.json").write_text(json.dumps(cfg))
            with self.assertRaisesRegex(TwoKeyConfigError, "unknown pki settings"):
                TwoKey(env, key.public_key(), Path(d) / "m.jsonl", YES, ledger_signing_key=key, quorum_policy=QP,
                       allow_test_doubles=True, deployment_config=Path(d) / "bad.json", anchor=fabric(),
                       principal_credential=Credential(cert, []))

    def test_fips_mode_enterprise_with_p384_principal(self):
        from two_key.constitution import build_document, sign_document
        from two_key.crypto.signatures import PrivateKeySet
        p = CryptoProvider(fips_mode=True)
        t = TestPki()
        cred, ks = t.identity("Principal", email=PRINCIPAL_EMAIL, provider=p)
        env = sign_document(build_document("did:twokey:acme", "No wires.", RULES), ks)
        with tempfile.TemporaryDirectory() as d:
            tk = TwoKey(env, ks.public(), Path(d) / "l.jsonl", YES, ledger_signing_key=ks, quorum_policy=QP,
                        allow_test_doubles=True, crypto=p, deployment_mode="enterprise", anchor=fabric(),
                        pki=t.config(ROLE_MAP), principal_credential=cred)
            agent, akey = t.identity("Agent", uri=AGENT_URI, provider=p)
            d1 = tk.authorize(ACTION, "Send it.", ARGS,
                              agent_assertion=pki.sign_agent_request(agent, akey, ACTION, "Send it.", ARGS, provider=p))
            self.assertTrue(d1.allowed, d1.reason)
            self.assertIsInstance(ks, PrivateKeySet)


if __name__ == "__main__":
    unittest.main()
