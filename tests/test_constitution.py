"""Constitution upload, Ed25519 signing, and verification."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from compact_kernel import keys
from compact_kernel.constitution import (ConstitutionSignatureError, build_document, load_rules_file,
                                         load_text_file, sign_document, sign_files, verify_signed)
from compact_kernel.kernel import CompactKernel
from compact_kernel.policy_vm import ConstitutionError
from compact_kernel.testing import FixedJudge

RULES = [{"allow_only_tools": ["search"]}, {"deny_if": {"data_class_in": ["medical"]}}]


class SignVerify(unittest.TestCase):
    def setUp(self):
        self.key = keys.generate_private_key()
        self.env = sign_document(build_document("did:ck:p", "Never share medical data.", RULES), self.key)

    def test_roundtrip(self):
        c = verify_signed(self.env, self.key.public_key())
        self.assertEqual(c.principal, "did:ck:p")
        self.assertEqual(c.text, "Never share medical data.")

    def test_modified_text_rejected(self):
        env = copy.deepcopy(self.env)
        env["constitution"]["constitution_text"] = "Share everything."
        with self.assertRaises(ConstitutionSignatureError):
            verify_signed(env, self.key.public_key())

    def test_modified_rules_rejected(self):
        env = copy.deepcopy(self.env)
        env["constitution"]["hard_rules"][0]["allow_only_tools"].append("wire_transfer")
        with self.assertRaises(ConstitutionSignatureError):
            verify_signed(env, self.key.public_key())

    def test_unsigned_rejected(self):
        for env in ({"constitution": self.env["constitution"]},
                    {"constitution": self.env["constitution"], "signature": {"alg": "Ed25519"}},
                    self.env["constitution"]):
            with self.assertRaises(ConstitutionSignatureError):
                verify_signed(env, self.key.public_key())

    def test_foreign_key_rejected(self):
        attacker = keys.generate_private_key()
        forged = sign_document(self.env["constitution"], attacker)  # validly signed, wrong signer
        with self.assertRaises(ConstitutionSignatureError):
            verify_signed(forged, self.key.public_key())

    def test_embedded_key_swap_rejected(self):
        env = copy.deepcopy(self.env)
        env["signature"]["public_key"] = keys.b64e(keys.public_key_raw(keys.generate_private_key()))
        with self.assertRaises(ConstitutionSignatureError):
            verify_signed(env, self.key.public_key())

    def test_bad_signature_bytes_rejected(self):
        env = copy.deepcopy(self.env)
        env["signature"]["sig"] = keys.b64e(b"\x00" * 64)
        with self.assertRaises(ConstitutionSignatureError):
            verify_signed(env, self.key.public_key())

    def test_invalid_rules_cannot_be_signed(self):
        with self.assertRaises(ConstitutionError):
            build_document("p", "text", [{"deny_iff": {}}])

    def test_kernel_refuses_unsigned_and_tampered(self):
        with tempfile.TemporaryDirectory() as d:
            env = copy.deepcopy(self.env)
            env["constitution"]["constitution_text"] += " (edited by vendor)"
            with self.assertRaises(ConstitutionSignatureError):
                CompactKernel(env, self.key.public_key(), Path(d) / "l", [FixedJudge("a", "yes")], ledger_signing_key=self.key,
                              allow_test_doubles=True)
            with self.assertRaises(ConstitutionSignatureError):
                CompactKernel({"constitution": self.env["constitution"]}, self.key.public_key(),
                              Path(d) / "l", [FixedJudge("a", "yes")], allow_test_doubles=True, ledger_signing_key=self.key)


class FileUpload(unittest.TestCase):
    def test_md_and_json(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d) / "c.md"; t.write_text("# My constitution\nNo wires.\n")
            r = Path(d) / "r.json"; r.write_text(json.dumps({"hard_rules": RULES}))
            key = keys.generate_private_key()
            env = sign_files(t, r, "did:ck:p", key)
            self.assertIn("No wires.", verify_signed(env, key.public_key()).text)

    def test_yaml_rules(self):
        with tempfile.TemporaryDirectory() as d:
            r = Path(d) / "r.yaml"
            r.write_text("- allow_only_tools: [search, Email_Draft]\n- deny_if: {data_class_in: [medical]}\n")
            self.assertEqual(len(load_rules_file(r)), 2)

    def test_bad_suffix_and_empty(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.pdf"; p.write_text("x")
            with self.assertRaises(ConstitutionError):
                load_text_file(p)
            e = Path(d) / "c.txt"; e.write_text("   \n")
            with self.assertRaises(ConstitutionError):
                load_text_file(e)

    def test_key_files_roundtrip_with_passphrase(self):
        with tempfile.TemporaryDirectory() as d:
            k = keys.generate_private_key()
            keys.save_private_key(Path(d) / "p.pem", k, b"correct horse")
            keys.save_public_key(Path(d) / "p.pub.pem", k)
            self.assertEqual(oct((Path(d) / "p.pem").stat().st_mode & 0o777), "0o600")
            k2 = keys.load_private_key(Path(d) / "p.pem", b"correct horse")
            self.assertEqual(keys.public_key_raw(k2), keys.public_key_raw(keys.load_public_key(Path(d) / "p.pub.pem")))
            with self.assertRaises(Exception):
                keys.load_private_key(Path(d) / "p.pem", b"wrong")


if __name__ == "__main__":
    unittest.main(verbosity=2)
