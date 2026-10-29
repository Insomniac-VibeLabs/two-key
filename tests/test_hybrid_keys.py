# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Hybrid Ed25519 + ML-DSA-65 keys (0.9.0): a signature needs both halves, a half or a classical signature is
refused, the key files round trip, and where ML-DSA-65 is missing Two-Key refuses instead of falling back."""

import base64
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from two_key import keys
from two_key.capability import CapabilityIssuer, CapabilityVerifier, TokenError, _b64u
from two_key.canonical import canonical_bytes
from two_key.keys import (ED_SIG_BYTES, HybridPrivateKey, add_ml_dsa, classical_half, generate_private_key,
                          hybrid_message, key_fingerprint, load_private_key_file, load_public_key, public_from_raw,
                          public_raw, save_private_key, save_public_key, sign, verify)

MESSAGE = b"two-key hybrid test"


def signature_parts(signature: str) -> tuple[bytes, bytes]:
    data = base64.b64decode(signature)
    return data[:ED_SIG_BYTES], data[ED_SIG_BYTES:]


class Signatures(unittest.TestCase):
    def setUp(self):
        self.key = generate_private_key()
        self.public = self.key.public_key()

    def test_a_hybrid_signature_verifies_and_names_its_message(self):
        signature = sign(self.key, MESSAGE)
        self.assertTrue(verify(self.public, MESSAGE, signature))
        self.assertFalse(verify(self.public, MESSAGE + b"!", signature))
        self.assertEqual(len(base64.b64decode(signature)), 64 + 3309)

    def test_either_half_alone_is_refused(self):
        ed, ml = signature_parts(sign(self.key, MESSAGE))
        for data in (ed, ml, ed + bytes(len(ml)), bytes(len(ed)) + ml, ed + ml[:-1]):
            self.assertFalse(verify(self.public, MESSAGE, base64.b64encode(data).decode()))

    def test_a_classical_signature_by_the_same_ed25519_key_is_refused(self):
        """The downgrade: an Ed25519 signature, even by the hybrid key's own Ed25519 half, is not a hybrid one."""
        classical = sign(classical_half(self.key), MESSAGE)
        self.assertTrue(verify(classical_half(self.public), MESSAGE, classical))
        self.assertFalse(verify(self.public, MESSAGE, classical))

    def test_the_ed25519_half_of_a_hybrid_signature_is_not_a_classical_signature(self):
        ed, _ = signature_parts(sign(self.key, MESSAGE))
        self.assertFalse(verify(classical_half(self.public), MESSAGE, base64.b64encode(ed).decode()))
        classical_half(self.public).verify(ed, hybrid_message(MESSAGE))       # it signed the labelled message

    def test_another_hybrid_key_is_refused(self):
        self.assertFalse(verify(generate_private_key().public_key(), MESSAGE, sign(self.key, MESSAGE)))

    def test_fingerprints_say_which_kind_of_key(self):
        self.assertTrue(key_fingerprint(self.public).startswith("hybrid-sha256:"))
        self.assertTrue(key_fingerprint(classical_half(self.public)).startswith("sha256:"))
        self.assertNotEqual(key_fingerprint(self.public).split(":")[1],
                            key_fingerprint(classical_half(self.public)).split(":")[1])

    def test_raw_public_keys_round_trip_by_length(self):
        self.assertEqual(public_from_raw(public_raw(self.public)), self.public)
        ed = classical_half(self.public)
        self.assertEqual(public_raw(public_from_raw(public_raw(ed))), public_raw(ed))
        odd = base64.b64encode(bytes(33)).decode()
        with self.assertRaisesRegex(ValueError, "public_key_invalid"):
            public_from_raw(odd)

    def test_add_ml_dsa_keeps_the_ed25519_key(self):
        old = Ed25519PrivateKey.generate()
        new = add_ml_dsa(old)
        self.assertIsInstance(new, HybridPrivateKey)
        self.assertEqual(public_raw(classical_half(new.public_key())), public_raw(old.public_key()))
        self.assertIs(add_ml_dsa(new), new)


class Files(unittest.TestCase):
    def test_plain_encrypted_and_public_files_round_trip(self):
        key = generate_private_key()
        with tempfile.TemporaryDirectory() as tmp:
            plain, locked, public = Path(tmp, "k.pem"), Path(tmp, "locked.pem"), Path(tmp, "k.pub.pem")
            save_private_key(plain, key)
            save_private_key(locked, key, passphrase=b"a long enough passphrase")
            save_public_key(public, key.public_key())
            self.assertEqual(plain.read_bytes().count(b"-----BEGIN PRIVATE KEY-----"), 2)
            for loaded in (load_private_key_file(plain),
                           load_private_key_file(locked, b"a long enough passphrase")):
                self.assertEqual(public_raw(loaded.public_key()), public_raw(key.public_key()))
            self.assertIn(b"two-key-encrypted-key/2", base64.decodebytes(b"".join(
                locked.read_bytes().splitlines()[1:-1])))
            self.assertEqual(load_public_key(public), key.public_key())

    def test_a_0_8_0_ed25519_key_file_still_loads(self):
        old = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "old.pem")
            save_private_key(path, old)
            self.assertIsInstance(load_private_key_file(path), Ed25519PrivateKey)

    def test_a_file_with_the_halves_swapped_or_doubled_is_refused(self):
        key = generate_private_key()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "k.pem")
            save_private_key(path, key)
            blocks = path.read_bytes().split(b"-----END PRIVATE KEY-----\n")
            for name, data in (("swapped", blocks[1] + b"-----END PRIVATE KEY-----\n" + blocks[0]
                                + b"-----END PRIVATE KEY-----\n"),
                               ("tripled", path.read_bytes() + blocks[0] + b"-----END PRIVATE KEY-----\n")):
                bad = Path(tmp, f"{name}.pem")
                save_private_key(bad, key)
                bad.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "key_file_invalid", msg=name):
                    load_private_key_file(bad)


class Tokens(unittest.TestCase):
    def test_a_hybrid_issuer_makes_tk2_tokens_with_the_suite(self):
        issuer = CapabilityIssuer(generate_private_key())
        issued = issuer.issue(tool="t", arguments={}, ledger_root="r", ledger_size=0, bytecode_hash="b",
                              nl_hash="n")
        self.assertTrue(issued.token.startswith("tk2."))
        self.assertEqual((issued.payload["v"], issued.payload["alg"]), (2, "ed25519+ml-dsa-65"))
        self.assertEqual(issuer.verifier().verify(issued.token)["jti"], issued.payload["jti"])

    def test_a_tk1_token_from_the_ed25519_half_is_refused(self):
        key = generate_private_key()
        issuer = CapabilityIssuer(key)
        payload = dict(issuer.issue(tool="t", arguments={}, ledger_root="r", ledger_size=0, bytecode_hash="b",
                                    nl_hash="n").payload, v=1)
        payload.pop("alg")
        body = _b64u(canonical_bytes(payload))
        downgraded = f"tk1.{body}.{sign(classical_half(key), body.encode('ascii'))}"
        verifier = CapabilityVerifier(key.public_key())
        # Run 12, X6: named, so an operator knows to ask for a new token rather than look for a corrupt one.
        with self.assertRaisesRegex(TokenError, "^token_before_upgrade$"):
            verifier.verify(downgraded)


class WithoutMlDsa(unittest.TestCase):
    """A cryptography without ML-DSA-65 (too old, or built against an OpenSSL before 3.5): Two-Key refuses."""

    def test_new_keys_and_hybrid_files_are_refused_never_classical(self):
        key = generate_private_key()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "k.pem")
            save_private_key(path, key)
            with mock.patch.object(keys, "ml_dsa_available", return_value=False):
                for call in (generate_private_key, lambda: add_ml_dsa(Ed25519PrivateKey.generate()),
                             lambda: load_private_key_file(path),
                             lambda: public_from_raw(public_raw(key.public_key()))):
                    with self.assertRaisesRegex(ValueError, "^ml_dsa_unavailable"):
                        call()


if __name__ == "__main__":
    unittest.main()
