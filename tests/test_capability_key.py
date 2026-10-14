"""Fix 9: the capability key file, its directory, its fingerprint pin, and the principal-key split."""

import os
import stat
import tempfile
import unittest
from pathlib import Path

from two_key.capability import CapabilityIssuer, CapabilityVerifier, TokenError, capability_key_fingerprint
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.gateway import ToolGateway
from two_key.keys import generate_private_key, load_private_key, save_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "t", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


def engine(path, key):
    env = sign_constitution("c", RULES, key, SPECS)
    return TwoKey(Ledger(path, key), key.public_key(), verify_signed(env, key.public_key()),
                  [FixedJudge("a", "yes")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                  allow_test_doubles=True, monitored_agent=TEST_AGENT)


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


class KeyFile(unittest.TestCase):
    def test_created_exclusive_0600_in_0700_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(Path(tmp, "l"), generate_private_key())
            cap = tk.ledger.capability_key_path()
            self.assertEqual(mode(cap), 0o600)
            self.assertEqual(mode(cap.parent), 0o700)

    def test_save_private_key_never_overwrites_or_follows_a_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp, "k", "key.pem")
            save_private_key(p, generate_private_key())
            self.assertEqual(mode(p.parent), 0o700)
            with self.assertRaises(FileExistsError):
                save_private_key(p, generate_private_key())
            target = Path(tmp, "elsewhere")
            link = Path(tmp, "k", "link.pem")
            link.symlink_to(target)
            with self.assertRaises(OSError):
                save_private_key(link, generate_private_key())
            self.assertFalse(target.exists())

    def test_an_existing_loose_capability_dir_is_tightened(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(Path(tmp, "l"), generate_private_key())
            cap_dir = tk.ledger.capability_key_path().parent
            os.chmod(cap_dir, 0o755)  # skipcq: BAN-B103 -- the test loosens the mode to check it is tightened to 0o700
            engine(Path(tmp, "l"), tk.ledger.private_key)
            self.assertEqual(mode(cap_dir), 0o700)


class NoSilentRegeneration(unittest.TestCase):
    def test_missing_key_after_issuance_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            tk = engine(Path(tmp, "l"), key)
            self.assertTrue(tk.authorize(SEARCH, {}, "s").allowed)
            os.remove(tk.ledger.capability_key_path())
            with self.assertRaisesRegex(TwoKeyConfigError, "^capability_key_missing"):
                engine(Path(tmp, "l"), key)

    def test_swapped_key_after_issuance_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            tk = engine(Path(tmp, "l"), key)
            self.assertTrue(tk.authorize(SEARCH, {}, "s").allowed)
            cap = tk.ledger.capability_key_path()
            os.remove(cap)
            save_private_key(cap, generate_private_key())
            with self.assertRaisesRegex(TwoKeyConfigError, "^capability_key_changed"):
                engine(Path(tmp, "l"), key)

    def test_missing_key_before_any_issuance_is_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            tk = engine(Path(tmp, "l"), key)
            os.remove(tk.ledger.capability_key_path())
            again = engine(Path(tmp, "l"), key)
            self.assertNotEqual(capability_key_fingerprint(again.issuer.public_key),
                                capability_key_fingerprint(tk.issuer.public_key))

    def test_issued_tokens_without_a_pin_fail_closed(self):
        # A ledger from before pinning, or one whose last constitution_loaded lacks the pin.
        for pin in (None, ""):
            with self.subTest(pin=pin), tempfile.TemporaryDirectory() as tmp:
                key = generate_private_key()
                tk = engine(Path(tmp, "l"), key)
                self.assertTrue(tk.authorize(SEARCH, {}, "s").allowed)
                body = {"constitution_hash": "x"}
                if pin is not None:
                    body["capability_key_fingerprint"] = pin
                tk.ledger.append("constitution_loaded", body)
                tk.ledger.checkpoint()
                with self.assertRaisesRegex(TwoKeyConfigError, "^capability_key_unpinned"):
                    engine(Path(tmp, "l"), key)

    def test_no_pin_needed_before_any_issuance(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            tk = engine(Path(tmp, "l"), key)
            tk.ledger.append("constitution_loaded", {"constitution_hash": "x"})
            tk.ledger.checkpoint()
            engine(Path(tmp, "l"), key)


class PinAndPrincipalSplit(unittest.TestCase):
    def test_fingerprint_recorded_and_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(Path(tmp, "l"), generate_private_key())
            loaded = [e for e in tk.ledger.entries if e.kind == "constitution_loaded"][-1].body
            self.assertEqual(loaded["capability_key_fingerprint"], capability_key_fingerprint(tk.issuer.public_key))
            d = tk.authorize(SEARCH, {}, "s")
            # A gateway handed some other verifying key refuses the (validly signed) token by its pin.
            other = CapabilityIssuer(generate_private_key(), clock=tk.issuer.clock, max_ttl_seconds=120)
            gw_other = ToolGateway(tk.ledger, other.verifier(), tk.compiled, tools={"search": lambda a: a})
            payload = tk.issuer.verify(d.token)
            forged = other.issue(tool="search", arguments={}, ledger_root=payload["ledger_root"],
                                 ledger_size=payload["ledger_size"], bytecode_hash=payload["bytecode_hash"],
                                 nl_hash=payload["nl_hash"], spec_hash=payload["spec_hash"],
                                 form=payload["form"], claimed_data_class=payload["claimed_data_class"])
            self.assertEqual(gw_other.invoke(forged.token, "search", {}).reason, "capability_key_mismatch")
            gw = ToolGateway(tk.ledger, tk.issuer.verifier(), tk.compiled, tools={"search": lambda a: a})
            self.assertTrue(gw.invoke(d.token, "search", {}).allowed)

    def test_principal_signed_token_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(Path(tmp, "l"), generate_private_key())
            d = tk.authorize(SEARCH, {}, "s")
            payload = tk.issuer.verify(d.token)
            forged = CapabilityIssuer(tk.ledger.private_key, clock=tk.issuer.clock).issue(
                tool="search", arguments={}, ledger_root=payload["ledger_root"], ledger_size=payload["ledger_size"],
                bytecode_hash=payload["bytecode_hash"], nl_hash=payload["nl_hash"], spec_hash=payload["spec_hash"],
                form=payload["form"], claimed_data_class=payload["claimed_data_class"])
            gw = ToolGateway(tk.ledger, tk.issuer.verifier(), tk.compiled, tools={"search": lambda a: a})
            self.assertEqual(gw.invoke(forged.token, "search", {}).reason, "bad_signature")
            with self.assertRaisesRegex(TokenError, "capability_key_is_principal_key"):
                ToolGateway(tk.ledger, CapabilityVerifier(tk.ledger.public_key), tk.compiled)

    def test_capability_key_equal_to_principal_key_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            path = Path(tmp, "l")
            ledger = Ledger(path, key)
            save_private_key(ledger.capability_key_path(), key)  # an operator copied principal.pem here
            with self.assertRaisesRegex(TwoKeyConfigError, "^capability_key_is_principal_key"):
                engine(path, key)
            self.assertEqual(load_private_key(ledger.capability_key_path()).public_key().public_bytes_raw(),
                             key.public_key().public_bytes_raw())


if __name__ == "__main__":
    unittest.main(verbosity=2)
