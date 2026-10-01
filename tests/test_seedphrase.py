"""Seed-phrase backup (seedphrase.py; CONCEPTION_NOTES.md Entry 11): BIP-39 vectors, round trip,
checksum rejection, passphrase, per-algorithm labels, determinism, policy refusals, CLI."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from two_key import cli, keys, seedphrase as sp
from two_key.crypto import CryptoProvider, default_provider, set_default_provider
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from two_key.crypto.signatures import as_private_keyset, as_public_keyset, pq_available
from two_key.deployment import resolve

# trezor/python-mnemonic vectors.json, English, 256-bit entropy; seed uses passphrase "TREZOR".
VECTORS = [
    ("00" * 32, "abandon " * 23 + "art",
     "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"),
    ("ff" * 32, "zoo " * 23 + "vote",
     "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"),
    ("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
     "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol "
     "group space point ten exist slush involve unfold",
     "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998"),
]
PQ = pq_available()
SUITES = ["ed25519", "ecdsa-p384"] + (["hybrid-mldsa65-ed25519", "hybrid-mldsa65-p384"] if PQ else [])


class TestBip39(unittest.TestCase):
    def test_wordlist_is_the_bip39_english_list(self):
        wl = sp.wordlist()
        self.assertEqual((len(wl), wl[0], wl[-1]), (2048, "abandon", "zoo"))

    def test_reference_vectors(self):
        for ent, words, seed in VECTORS:
            self.assertEqual(sp.entropy_to_phrase(bytes.fromhex(ent)).reveal(), words.strip())
            self.assertEqual(sp.phrase_to_entropy(words).hex(), ent)
            self.assertEqual(sp.bip39_seed(words, "TREZOR").hex(), seed)

    def test_new_phrase_is_24_words_with_valid_checksum(self):
        p = sp.new_phrase()
        self.assertEqual(len(p.reveal().split()), 24)
        sp.validate(p)
        self.assertNotEqual(p.reveal(), sp.new_phrase().reveal())

    def test_checksum_rejection(self):
        words = VECTORS[2][1].split()
        for i in (0, 11, 23):
            bad = list(words)
            bad[i] = "abandon" if words[i] != "abandon" else "ability"
            with self.assertRaisesRegex(sp.SeedPhraseError, "checksum"):
                sp.phrase_to_entropy(" ".join(bad))
        swapped = list(words); swapped[0], swapped[1] = swapped[1], swapped[0]
        with self.assertRaisesRegex(sp.SeedPhraseError, "checksum"):
            sp.phrase_to_entropy(" ".join(swapped))
        with self.assertRaisesRegex(sp.SeedPhraseError, "24 words"):
            sp.phrase_to_entropy(" ".join(words[:12]))

    def test_errors_never_contain_the_words(self):
        words = VECTORS[2][1].split()
        bad = list(words); bad[4] = "notaword"
        with self.assertRaises(sp.SeedPhraseError) as cm:
            sp.phrase_to_entropy(" ".join(bad))
        msg = str(cm.exception)
        self.assertIn("position 5", msg)
        for w in set(bad):
            self.assertNotIn(w, msg.split())
        p = sp.new_phrase()
        for w in p.reveal().split():
            self.assertNotIn(w, repr(p).split())
            self.assertNotIn(w, str(p).split())
            self.assertNotIn(w, f"{p}".split())

    def test_normalization(self):
        w = VECTORS[2][1]
        self.assertEqual(sp.phrase_to_entropy("  " + w.upper().replace(" ", "\n ") + " "),
                         bytes.fromhex(VECTORS[2][0]))


class TestDerivation(unittest.TestCase):
    phrase = VECTORS[2][1]

    def pub(self, suite, passphrase=""):
        return as_public_keyset(sp.derive_key(self.phrase, suite, passphrase)).encoded

    def test_round_trip_every_suite(self):
        for suite in SUITES:
            with self.subTest(suite=suite):
                phrase, k = sp.generate(suite)
                self.assertTrue(sp.matches(phrase, as_public_keyset(k)))
                rebuilt = sp.derive_key(phrase.reveal(), suite)
                self.assertEqual(as_public_keyset(rebuilt).encoded, as_public_keyset(k).encoded)
                msg = b"constitution"
                self.assertTrue(as_public_keyset(k).verify(msg, as_private_keyset(rebuilt).sign(msg)))

    def test_determinism(self):
        for suite in SUITES:
            self.assertEqual(self.pub(suite), self.pub(suite))
        self.assertEqual(sp.component_seed(sp.bip39_seed(self.phrase), "ed25519").hex(),
                         sp.component_seed(sp.bip39_seed(self.phrase), "ed25519").hex())

    def test_passphrase_changes_the_keys(self):
        for suite in SUITES:
            self.assertNotEqual(self.pub(suite), self.pub(suite, "correct horse"))
            self.assertNotEqual(self.pub(suite, "a"), self.pub(suite, "b"))
        self.assertFalse(sp.matches(self.phrase, sp.derive_key(self.phrase, "ed25519", "x"), ""))

    def test_labels_give_independent_keys(self):
        seed = sp.bip39_seed(self.phrase)
        a, b, c = (sp.component_seed(seed, alg, length=32) for alg in ("ed25519", "ml-dsa-65", "ecdsa-p384"))
        self.assertEqual(len({a, b, c}), 3)
        self.assertEqual(len(set(sp.LABELS.values())), len(sp.LABELS))
        # Same label, same key in every suite that uses that algorithm.
        legacy = as_public_keyset(sp.derive_key(self.phrase, "ed25519")).legacy_raw
        if PQ:
            hybrid = sp.derive_key(self.phrase, "hybrid-mldsa65-ed25519")
            self.assertEqual(hybrid.public()._raws[1], legacy)
            self.assertNotEqual(hybrid.public()._raws[0][:32], legacy)

    def test_derivation_chain_is_bip39_seed_then_hkdf_sha384(self):
        seed = sp.bip39_seed(VECTORS[0][1])
        self.assertEqual(seed.hex(), sp.bip39_seed("abandon " * 23 + "art").hex())
        want = HKDF(hashes.SHA384(), 32, b"two-key/seed/v1/hkdf-salt", b"two-key/seed/v1/ed25519").derive(seed)
        self.assertEqual(sp.component_seed(seed, "ed25519"), want)
        self.assertEqual(as_public_keyset(sp.derive_key(VECTORS[0][1], "ed25519")).legacy_raw,
                         as_public_keyset(Ed25519PrivateKey.from_private_bytes(want)).legacy_raw)


class TestPolicy(unittest.TestCase):
    def test_refused_in_fips_mode(self):
        p = CryptoProvider(fips_mode=True)
        with self.assertRaisesRegex(sp.SeedPhrasePolicyError, "disabled in fips_mode"):
            sp.new_phrase(p)
        with self.assertRaisesRegex(sp.SeedPhrasePolicyError, "fips_mode"):
            sp.derive_key(VECTORS[0][1], "ed25519", provider=p)

    def test_refused_in_enterprise_mode(self):
        with self.assertRaisesRegex(sp.SeedPhrasePolicyError, "personal mode only"):
            sp.generate("ed25519", deployment=resolve("enterprise", env={}))
        sp.generate("ed25519", deployment=resolve("personal", env={}))


class TestCli(unittest.TestCase):
    def run_cli(self, argv, stdin=""):
        out = io.StringIO()
        prev = default_provider()  # --fips replaces the process-wide default provider
        with mock.patch.object(sys, "stdin", io.StringIO(stdin)), contextlib.redirect_stdout(out):
            try:
                rc = cli.main(argv)
            except SystemExit as e:
                rc = e.code
            finally:
                set_default_provider(prev)
        return rc, out.getvalue()

    def test_generate_verify_recover(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out = self.run_cli(["keygen", "--out", f"{d}/a", "--seed-phrase", "--no-passphrase"])
            self.assertEqual(rc, 0, out)
            lines = [l for l in out.splitlines() if l.startswith("  ") and ". " in l]
            words = [tok for l in lines for tok in l.split() if not tok.rstrip(".").isdigit()]
            self.assertEqual(len(words), 24)
            phrase = " ".join(words)
            pub = f"{d}/a/principal.pub.pem"
            before = sorted(p.name for p in Path(d).rglob("*"))
            rc, out = self.run_cli(["verify-seed-phrase", "--pub", pub], phrase + "\n")
            self.assertEqual(rc, 0, out)
            self.assertIn("OK: the phrase re-derives", out)
            self.assertEqual(before, sorted(p.name for p in Path(d).rglob("*")))  # wrote nothing
            self.assertNotIn(phrase, out)
            fixed_message = {"the", "phrase", "re-derives", "nothing", "was", "written"}  # BIP-39 has "phrase", "nothing"
            for w in words:
                if w not in fixed_message:
                    self.assertNotIn(w, out.split())
            words2 = list(words); words2[0], words2[1] = words2[1], words2[0]
            rc, out = self.run_cli(["verify-seed-phrase"], " ".join(words2) + "\n")
            self.assertEqual(rc, 1)
            rc, out = self.run_cli(["recover-key", "--out", f"{d}/b", "--no-passphrase", "--expect-pub", pub],
                                   phrase + "\n")
            self.assertEqual(rc, 0, out)
            self.assertEqual(keys.load_public_key(Path(f"{d}/b/principal.pub.pem")).public_bytes_raw(),
                             keys.load_public_key(Path(pub)).public_bytes_raw())
            with mock.patch.dict("os.environ", {"SEEDPW": "other"}):
                rc, out = self.run_cli(["recover-key", "--out", f"{d}/c", "--no-passphrase", "--expect-pub", pub,
                                        "--seed-passphrase-env", "SEEDPW"], phrase + "\n")
            self.assertNotEqual(rc, 0)
            self.assertFalse(Path(f"{d}/c").exists())

    def test_cli_refusals(self):
        rc, out = self.run_cli(["--fips", "keygen", "--out", "/nonexistent/x", "--seed-phrase", "--no-passphrase"])
        self.assertIn("fips_mode", str(rc) + out)
        rc, out = self.run_cli(["verify-seed-phrase", "--deployment-mode", "enterprise"], VECTORS[0][1])
        self.assertIn("personal mode only", str(rc) + out)


if __name__ == "__main__":
    unittest.main()
