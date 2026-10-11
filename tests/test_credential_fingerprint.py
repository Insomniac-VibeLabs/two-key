"""Credential fingerprints: whitespace is stripped first, and the hash is an HMAC under a per-install key."""

import hashlib
import hmac
import os
import stat
import tempfile
import unittest
from pathlib import Path

from two_key.identity import (FINGERPRINT_DOMAIN, IdentityError, credential_fingerprint, fingerprint_key_id,
                              load_fingerprint_key)
from two_key.keys import generate_private_key
from two_key.judges.credentials import StaticToken
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.ledger import Ledger, LedgerError
from test_judge_agent_separation import Env, claude


class KeyFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "l.ledger-key", "fingerprint.key")

    def test_created_once_0600_in_a_0700_directory(self):
        key = load_fingerprint_key(self.path)
        self.assertEqual(len(key), 32)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.path)).st_mode), 0o700)
        self.assertEqual(load_fingerprint_key(self.path), key, "an existing key is read, never regenerated")

    def test_group_readable_key_is_refused(self):
        load_fingerprint_key(self.path)
        os.chmod(self.path, 0o640)
        with self.assertRaisesRegex(IdentityError, "fingerprint_key_insecure"):
            load_fingerprint_key(self.path)

    def test_symlink_is_refused(self):
        os.makedirs(os.path.dirname(self.path))
        target = Path(self.tmp.name) / "elsewhere"
        target.write_bytes(b"x" * 32)
        os.chmod(target, 0o600)
        os.symlink(target, self.path)
        with self.assertRaisesRegex(IdentityError, "fingerprint_key_unreadable"):
            load_fingerprint_key(self.path)

    def test_wrong_length_is_refused(self):
        os.makedirs(os.path.dirname(self.path))
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, b"short")
        os.close(fd)
        with self.assertRaisesRegex(IdentityError, "fingerprint_key_unreadable: .* 32-byte key"):
            load_fingerprint_key(self.path)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can write anywhere")
    def test_uncreatable_key_fails_closed(self):
        ro = Path(self.tmp.name) / "ro"
        ro.mkdir(mode=0o500)
        self.addCleanup(os.chmod, ro, 0o700)
        with self.assertRaisesRegex(IdentityError, "fingerprint_key_unavailable"):
            load_fingerprint_key(ro / "sub" / "fingerprint.key")

    def test_ledger_keeps_it_beside_the_ledger_key(self):
        led = Ledger(Path(self.tmp.name) / "ledger", generate_private_key())
        path = led.fingerprint_key_path()
        self.assertEqual(path, led.ledger_key_path.parent / "fingerprint.key")
        self.assertFalse(path.resolve().is_relative_to(led.path.resolve()))
        key = led.fingerprint_key()
        self.assertEqual(led.fingerprint_key(), key)
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(LedgerError, "fingerprint_key_insecure"):
            led.fingerprint_key()


class Fingerprint(unittest.TestCase):
    KEY = b"k" * 32

    def test_hmac_of_stripped_secret(self):
        want = "hmac-sha256:" + hmac.new(self.KEY, FINGERPRINT_DOMAIN + b"sk-abc", hashlib.sha256).hexdigest()
        self.assertEqual(credential_fingerprint("sk-abc", self.KEY), want)
        self.assertNotEqual(credential_fingerprint("sk-abc", self.KEY).split(":", 1)[1],
                            credential_fingerprint("sk-abc").split(":", 1)[1])

    def test_whitespace_is_stripped_first(self):
        for key in (self.KEY, None):
            fp = credential_fingerprint("sk-abc", key)
            for variant in ("sk-abc\n", "  sk-abc", "\tsk-abc \r\n"):
                self.assertEqual(credential_fingerprint(variant, key), fp, repr(variant))
            self.assertEqual(credential_fingerprint(" \n\t", key), "none")
            self.assertNotEqual(credential_fingerprint("sk-a bc", key), fp)

    def test_a_password_pair_is_pbkdf2_hmac_sha256(self):
        """An approved function (SP 800-132), so a FIPS-only OpenSSL can compute it; scrypt is neither."""
        from two_key.identity import PASSWORD_KDF, password_fingerprint
        derived = hashlib.pbkdf2_hmac("sha256", FINGERPRINT_DOMAIN + b"alice:s3cret", self.KEY, 600_000, 32)
        self.assertEqual(password_fingerprint(" alice:s3cret\n", self.KEY), "pbkdf2-sha256-600000:" + derived.hex())
        # The floors OpenSSL's FIPS provider enforces for PBKDF2: salt >= 128 bits, >= 1000 iterations, key >= 112 bits.
        self.assertEqual(PASSWORD_KDF["alg"], "pbkdf2-hmac-sha256")
        self.assertGreaterEqual(len(self.KEY) * 8, 128)
        self.assertGreaterEqual(PASSWORD_KDF["iterations"], 600_000)
        self.assertGreaterEqual(PASSWORD_KDF["dklen"] * 8, 112)

    def test_another_install_gets_other_fingerprints(self):
        self.assertNotEqual(credential_fingerprint("sk-abc", b"a" * 32), credential_fingerprint("sk-abc", b"b" * 32))
        self.assertNotEqual(fingerprint_key_id(b"a" * 32), fingerprint_key_id(b"b" * 32))


class Separation(Env):
    def test_agent_key_with_a_trailing_newline_still_matches_the_judge(self):
        os.environ["SEP_AGENT_KEY"] = "agent-secret-key\n"
        # The same key, whitespace aside, is the same agent, on its address or any other.
        same_address = OpenAICompatibleJudge("x", "xai", "grok-3-mini", "https://api.x.ai/v1",
                                             StaticToken("  agent-secret-key"))
        self.refused([same_address], "the same credential on the same address api.x.ai:443")
        self.refused([claude(key="  agent-secret-key")], r"the same credential \(agent at api.x.ai:443")

    def test_ledger_records_hmac_fingerprints_and_the_key_id(self):
        tk = self.started([claude()])
        key = tk.ledger.fingerprint_key()
        loaded = [e for e in tk.ledger.entries if e.kind == "constitution_loaded"][-1].body["judge_agent_separation"]
        self.assertEqual(loaded["credential_fingerprint"]["alg"], "hmac-sha256")
        self.assertEqual(loaded["credential_fingerprint"]["key_id"], fingerprint_key_id(key))
        self.assertEqual(loaded["judges"][0]["credential_fingerprint"],
                         [credential_fingerprint("judge-anthropic-key", key)])
        self.assertNotIn(key.hex(), str(loaded))


if __name__ == "__main__":
    unittest.main(verbosity=2)
