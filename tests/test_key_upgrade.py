# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The key upgrade (0.9.0, two_key/upgrade.py): a 0.8.0 deployment's Ed25519 keys become hybrid at the first
start, once, recorded as keys_upgraded; a stop at any step goes on at the next start; a 0.8.0 key is refused
afterwards; where it cannot do it all alone, or ML-DSA-65 is missing, it refuses and changes nothing."""

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from two_key import core, keys, ledger as ledger_mod
from two_key.backup import export_backup, restore_backup, verify_backup
from two_key.cli import main
from two_key.constitution import (ConstitutionSignatureError, load_envelope, save_envelope, sign_constitution,
                                  verify_signed)
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.keys import (add_ml_dsa, classical_half, is_hybrid, key_file_is_encrypted, load_private_key_file,
                          load_public_key, public_raw, save_private_key, save_public_key)
from two_key.ledger import Ledger, LedgerError
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge
from two_key.upgrade import BACKUP_DUE, UpgradeError, backup_made, open_upgraded

RULES = [{"id": "t", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}
PASSPHRASE = b"a long enough passphrase"
PHRASES = {"principal": "principal-passphrase-one", "ledger": "ledger-passphrase-two-ok",
           "witness": "witness-passphrase-three"}


def start(ledger, key, constitution: Path) -> TwoKey:
    return TwoKey(ledger, key.public_key(), verify_signed(load_envelope(constitution), key.public_key()),
                  [FixedJudge("a", "yes")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                  allow_test_doubles=True, monitored_agent=TEST_AGENT)


class Deployment08:
    """A deployment as 0.8.0 left it: Ed25519 principal, witness and capability keys, an Ed25519-signed
    constitution, and a ledger with a decision and a witness rotation in it."""

    def __init__(self, root: Path, *, encrypted: bool = False):
        self.root = root
        self.principal_path = root / "principal.pem"
        self.ledger_path = root / "ledger"
        self.constitution = root / "constitution.signed.json"
        self.old = Ed25519PrivateKey.generate()
        save_private_key(self.principal_path, self.old, passphrase=PASSPHRASE if encrypted else None)
        save_public_key(root / "principal.pub.pem", self.old.public_key())
        witness = root / "ledger.witness" / "witness.pem"
        save_private_key(witness, Ed25519PrivateKey.generate(), private_dir=True)
        save_public_key(witness.with_suffix(".pub.pem"), load_private_key_file(witness).public_key())
        save_private_key(root / "ledger.capability" / "capability.pem", Ed25519PrivateKey.generate(),
                         private_dir=True)
        save_envelope(self.constitution, sign_constitution("c", RULES, self.old, SPECS))
        self.digest = verify_signed(load_envelope(self.constitution), self.old.public_key()).digest
        # 0.8.0 ran on these keys; 0.9.0's TwoKey refuses them (keys_upgrade_needed), so the check is off here.
        with contextlib.redirect_stderr(io.StringIO()), mock.patch.object(core, "is_hybrid", return_value=True):
            tk = start(Ledger(self.ledger_path, self.old), self.old, self.constitution)
        self.decision = tk.authorize(SEARCH, {}, "look something up")
        with mock.patch.object(ledger_mod, "HybridPrivateKey", (keys.HybridPrivateKey, Ed25519PrivateKey)):
            tk.ledger.rotate_witness(Ed25519PrivateKey.generate(), reason="0.8.0 rotation")
        self.size = tk.ledger.size()

    def files(self) -> dict:
        return {p: p.read_bytes() for p in sorted(self.root.rglob("*")) if p.is_file()}

    def upgrade(self, **kw):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            result = open_upgraded(self.principal_path, kw.pop("passphrase", None), self.ledger_path,
                                   constitution=self.constitution, **kw)
        return result, err.getvalue()


class FreshInstall(unittest.TestCase):
    def test_a_fresh_install_never_runs_the_upgrade_or_asks_for_a_backup(self):
        """A 0.9.0 deployment is hybrid from its first key: no keys_upgraded, no upgrade message, no reminder."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = keys.generate_private_key()
            save_private_key(root / "principal.pem", key)
            constitution = root / "constitution.signed.json"
            save_envelope(constitution, sign_constitution("c", RULES, key, SPECS))
            for _ in range(2):          # the first start makes the ledger; the second opens it
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    result = open_upgraded(root / "principal.pem", None, root / "ledger", constitution=constitution)
                    start(result.ledger, result.principal, constitution)
                self.assertFalse(result.upgraded)
                self.assertEqual(result.replaced, [])
                self.assertNotIn("keys upgraded", err.getvalue())
                self.assertNotIn("back up now", err.getvalue())
            self.assertNotIn("keys_upgraded", [e.kind for e in result.ledger.entries])
            self.assertFalse((root / "ledger.ledger-key" / BACKUP_DUE).exists())


class Upgrade(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dep = Deployment08(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_the_first_start_upgrades_every_key_once_and_records_it(self):
        result, said = self.dep.upgrade()
        self.assertTrue(result.upgraded)
        self.assertIn("keys upgraded to hybrid ed25519+ml-dsa-65", said)
        self.assertIn("back up now", said)
        principal = load_private_key_file(self.dep.principal_path)
        self.assertTrue(is_hybrid(principal))
        self.assertEqual(public_raw(classical_half(principal.public_key())), public_raw(self.dep.old.public_key()))
        for path in (self.dep.root / "ledger.witness" / "witness.pem",
                     self.dep.root / "ledger.capability" / "capability.pem"):
            self.assertTrue(is_hybrid(load_private_key_file(path)), path)
        self.assertEqual(load_public_key(self.dep.root / "principal.pub.pem"), principal.public_key())
        entry = result.ledger.last_before(result.ledger.size(), "keys_upgraded")
        self.assertEqual(entry.seq, self.dep.size)
        self.assertEqual((entry.body["from_alg"], entry.body["to_alg"]), ("ed25519", "ed25519+ml-dsa-65"))
        self.assertTrue(entry.body["capability_key_fingerprint"].startswith("hybrid-sha256:"))
        self.assertTrue((self.dep.root / "ledger.ledger-key" / BACKUP_DUE).exists())
        # The constitution is signed again with the same body: same digest, so the serial checks still hold.
        self.assertEqual(verify_signed(load_envelope(self.dep.constitution), principal.public_key()).digest,
                         self.dep.digest)
        # It runs: the history before the upgrade still verifies, and a new decision is hybrid.
        reopened = Ledger(self.dep.ledger_path, principal)
        self.assertEqual(reopened.witness_report()["in_ledger"]["source"], "upgraded")
        with contextlib.redirect_stderr(io.StringIO()):
            tk = start(reopened, principal, self.dep.constitution)
        decision = tk.authorize(SEARCH, {}, "look again")
        self.assertTrue(decision.allowed, decision.reason)
        self.assertTrue(decision.token.startswith("tk2."))
        # Once: the next start does nothing, and still says to back up until a backup is made.
        again_result, said = self.dep.upgrade()
        self.assertFalse(again_result.upgraded)
        self.assertIn("back up now", said)
        backup_made(again_result.ledger.ledger_key_path)
        self.assertNotIn("back up now", self.dep.upgrade()[1])

    def test_an_encrypted_principal_key_stays_encrypted_under_its_passphrase(self):
        self._tmp.cleanup()
        self._tmp = tempfile.TemporaryDirectory()
        self.dep = Deployment08(Path(self._tmp.name), encrypted=True)
        self.dep.upgrade(passphrase=PASSPHRASE)
        self.assertTrue(key_file_is_encrypted(self.dep.principal_path))
        self.assertTrue(is_hybrid(load_private_key_file(self.dep.principal_path, PASSPHRASE)))

    def test_the_0_8_0_key_is_refused_afterwards(self):
        self.dep.upgrade()
        with self.assertRaisesRegex(LedgerError, "^keys_upgraded: .*0.8.0 principal key is refused"):
            Ledger(self.dep.ledger_path, self.dep.old)

    def test_an_out_of_ledger_witness_pin_stops_the_automatic_upgrade_and_nothing_changes(self):
        pin = self.dep.root / "pin.pub.pem"
        pin.write_bytes((self.dep.root / "ledger.witness" / "witness.pub.pem").read_bytes())
        before = self.dep.files()
        with self.assertRaisesRegex(UpgradeError, "^keys_upgrade_needed: .*two-key keys upgrade"):
            self.dep.upgrade(witness_public_key=pin)
        self.assertEqual(self.dep.files(), before)
        result, said = self.dep.upgrade(witness_public_key=pin, automatic=False)
        self.assertTrue(result.upgraded)
        self.assertIn(f"replace the out-of-ledger witness pin {pin}", said)
        principal, old_pin = load_private_key_file(self.dep.principal_path), load_public_key(pin)
        with self.assertRaisesRegex(LedgerError, "witness_key_changed"):
            Ledger(self.dep.ledger_path, principal, witness_public_key=old_pin)

    def test_a_stop_after_the_principal_key_file_goes_on_at_the_next_start(self):
        principal = add_ml_dsa(self.dep.old)
        self.dep.principal_path.unlink()
        save_private_key(self.dep.principal_path, principal)
        pending = Ledger(self.dep.ledger_path, principal)
        self.assertTrue(pending.upgrade_pending)
        with self.assertRaisesRegex(LedgerError, "^keys_upgrade_pending"):
            pending.append("note", {})
        with self.assertRaisesRegex(LedgerError, "^keys_upgrade_pending"):
            pending.rotate_witness()
        result, _ = self.dep.upgrade()
        self.assertTrue(result.upgraded)
        self.assertFalse(Ledger(self.dep.ledger_path, principal).upgrade_pending)

    def test_a_stop_after_every_file_but_before_the_entry_goes_on_at_the_next_start(self):
        with mock.patch.object(Ledger, "upgrade_keys", side_effect=LedgerError("stopped")):
            with self.assertRaisesRegex(UpgradeError, "keys_upgrade_stopped"):
                self.dep.upgrade()
        principal = load_private_key_file(self.dep.principal_path)
        self.assertTrue(is_hybrid(principal))
        self.assertTrue(Ledger(self.dep.ledger_path, principal).upgrade_pending)
        result, _ = self.dep.upgrade()
        self.assertTrue(result.upgraded)
        self.assertEqual(result.ledger.size(), self.dep.size + 1)

    def test_a_stop_between_the_entry_and_its_head_is_recovered_then_finished(self):
        real = Ledger._checkpoint_unlocked

        def fail_once(ledger, witness=None):
            if ledger.entries[-1].kind == "keys_upgraded" and not getattr(fail_once, "done", False):
                fail_once.done = True
                raise OSError("disk full")
            return real(ledger, witness)
        with mock.patch.object(Ledger, "_checkpoint_unlocked", fail_once):
            with self.assertRaisesRegex(UpgradeError, "keys_upgraded was written but no head covers it"):
                self.dep.upgrade()
        principal = load_private_key_file(self.dep.principal_path)
        with self.assertRaisesRegex(LedgerError, "signed head does not match the chain"):
            Ledger(self.dep.ledger_path, principal)
        with contextlib.redirect_stderr(io.StringIO()):
            recovered = Ledger.recover_tail(self.dep.ledger_path, principal)
        self.assertTrue(recovered["changed"])
        result, _ = self.dep.upgrade()
        self.assertTrue(result.upgraded)
        kinds = [e.kind for e in result.ledger.entries[self.dep.size:]]
        self.assertEqual(kinds, ["ledger_recovered", "keys_upgraded"])

    def test_it_says_it_is_upgrading_before_it_starts(self):
        """Run 12: the only line came after the work, so a slow upgrade looked like a hang."""
        _, said = self.dep.upgrade()
        self.assertLess(said.index("upgrading the keys"), said.index("keys upgraded"))

    def test_a_temporary_key_file_a_stop_left_is_removed(self):
        """Run 12, B7b: a kill during the principal write left half a private key beside it, for good."""
        stale = self.dep.root / ".principal.pem.4242.0a1b2c3d.tmp"
        stale.write_bytes(b"-----BEGIN PRIVATE KEY-----\nhalf")
        other = self.dep.root / ".notes.txt.4242.0a1b2c3d.tmp"
        other.write_bytes(b"not ours")
        self.dep.upgrade()
        self.assertFalse(stale.exists())
        self.assertTrue(other.exists())

    @unittest.skipIf(os.name == "nt", "POSIX modes")
    def test_a_public_key_file_keeps_its_mode(self):
        """Run 12: the operator's 0600 principal.pub.pem came back 0644."""
        public = self.dep.root / "principal.pub.pem"
        os.chmod(public, 0o600)
        self.dep.upgrade()
        self.assertEqual(stat.S_IMODE(os.stat(public).st_mode), 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX modes")
    def test_the_constitution_signed_again_keeps_its_mode(self):
        """Setup writes constitution.signed.json 0600; signing it again must not leave it 0644."""
        os.chmod(self.dep.constitution, 0o600)
        self.dep.upgrade()
        self.assertEqual(stat.S_IMODE(os.stat(self.dep.constitution).st_mode), 0o600)

    def test_a_folder_it_cannot_write_is_named_not_a_raw_error(self):
        """Run 12, X5: a read-only deployment folder gave a raw PermissionError naming a temporary file."""
        denied = PermissionError(13, "Permission denied")
        denied.filename = str(self.dep.root / ".principal.pem.1.0a1b2c3d.tmp")
        before = self.dep.files()
        with mock.patch("two_key.upgrade._platform.create_new", side_effect=denied):
            with self.assertRaisesRegex(UpgradeError, "^keys_upgrade_stopped: this account cannot write .*writable"):
                self.dep.upgrade()
        self.assertEqual(self.dep.files(), before)

    def test_a_second_first_start_that_lost_the_race_says_so(self):
        """Run 12, X3: the start that waited for the lock said keys_upgraded "names a principal key other than this
        ledger's". Safe, but it read like damage."""
        old_ledger = Ledger(self.dep.ledger_path, self.dep.old)
        self.dep.upgrade()                              # the other process wins while this one has the ledger open
        late, said = mock.patch("two_key.upgrade.Ledger", return_value=old_ledger), io.StringIO()
        with late, self.assertRaisesRegex(UpgradeError, "^keys_upgraded_elsewhere: .*start again"):
            open_upgraded(self.dep.principal_path, None, self.dep.ledger_path, principal=self.dep.old, out=said)

    def test_a_new_principal_that_is_not_the_old_one_made_hybrid_is_refused(self):
        led, stranger = Ledger(self.dep.ledger_path, self.dep.old), keys.generate_private_key()
        with self.assertRaisesRegex(LedgerError, "^keys_upgrade_refused"):
            led.upgrade_keys(stranger)
        self.assertEqual(led.size(), self.dep.size)

    def test_without_ml_dsa_it_refuses_and_changes_nothing(self):
        before = self.dep.files()
        with mock.patch.object(keys, "ml_dsa_available", return_value=False):
            with self.assertRaisesRegex(ValueError, "^ml_dsa_unavailable"):
                self.dep.upgrade()
        self.assertEqual(self.dep.files(), before)

    def test_the_python_library_route_refuses_a_0_8_0_key_instead_of_running_on_it(self):
        ledger = Ledger(self.dep.ledger_path, self.dep.old)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(TwoKeyConfigError, "^keys_upgrade_needed: .*two-key keys upgrade"):
                start(ledger, self.dep.old, self.dep.constitution)

    def test_another_constitution_signed_by_the_0_8_0_key_is_refused_until_signed_again_by_hand(self):
        other = self.dep.root / "other.signed.json"
        save_envelope(other, sign_constitution("other", RULES, self.dep.old, SPECS))
        self.dep.upgrade()
        public = load_private_key_file(self.dep.principal_path).public_key()
        envelope = load_envelope(other)
        with self.assertRaisesRegex(ConstitutionSignatureError, "0.8.0 Ed25519 key.*keys upgrade"):
            verify_signed(envelope, public)
        # A start does not sign it again (an Ed25519 forger could pass one off); the operator does, by hand.
        self.dep.upgrade()
        envelope = load_envelope(other)
        with self.assertRaisesRegex(ConstitutionSignatureError, "0.8.0 Ed25519 key"):
            verify_signed(envelope, public)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            main(["keys", "upgrade", "--key", str(self.dep.principal_path), "--ledger", str(self.dep.ledger_path),
                  "--constitution", str(other)])
        self.assertIn(f"signed again with the hybrid key: {other}", json.loads(out.getvalue())["note"])
        self.assertEqual(verify_signed(load_envelope(other), public).prose, "other")

    def test_a_backup_right_after_the_upgrade_exports_verifies_and_restores(self):
        """Before the next start writes constitution_loaded, keys_upgraded is what pins the capability key."""
        self.dep.upgrade()
        out = self.dep.root / "backups"
        with contextlib.redirect_stderr(io.StringIO()):
            exported = export_backup(self.dep.ledger_path, self.dep.principal_path, out, PHRASES, iterations=1000)
            verified = verify_backup(out, PHRASES)
        self.assertTrue(exported["fingerprints"]["capability"].startswith("hybrid-sha256:"))
        self.assertTrue(verified["ok"])
        self.assertFalse((self.dep.root / "ledger.ledger-key" / BACKUP_DUE).exists())
        capability = self.dep.root / "ledger.capability" / "capability.pem"
        capability.unlink()
        with contextlib.redirect_stderr(io.StringIO()):
            restored = restore_backup(self.dep.ledger_path, self.dep.principal_path, out, PHRASES)
        self.assertEqual(restored["actions"]["capability.pem"], "created")
        self.assertTrue(is_hybrid(load_private_key_file(capability)))

    def test_keys_upgrade_on_the_command_line(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main(["keys", "upgrade", "--key", str(self.dep.principal_path), "--ledger",
                         str(self.dep.ledger_path), "--constitution", str(self.dep.constitution)])
        self.assertEqual(code, 0)
        report = json.loads(out.getvalue())
        self.assertTrue(report["upgraded"])
        self.assertEqual(report["keys_upgraded"]["seq"], self.dep.size)
        self.assertIn("back up now", report["next"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            main(["keys", "upgrade", "--key", str(self.dep.principal_path), "--ledger", str(self.dep.ledger_path)])
        self.assertFalse(json.loads(out.getvalue())["upgraded"])


if __name__ == "__main__":
    unittest.main()
