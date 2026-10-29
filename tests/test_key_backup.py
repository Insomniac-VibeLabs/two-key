# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""0.3 key backup: three passphrase bundles, restore, wrong passphrase, tampered bundle.

The ledger key and the witness key are never in the same bundle. A restore writes
head.anchor from the same moment as the ledger and does not delete it.
"""

import io
import json
import os
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from two_key.backup import (
    ALG, BUNDLE_NAMES, FORMAT, KDF_NAME, MAX_ITERATIONS, MIN_ITERATIONS, PBKDF2_ITERATIONS,
    BackupError, _decrypt, export_backup, restore_backup, verify_backup,
)
from two_key.capability import capability_key_fingerprint, open_capability_key
from two_key.cli import main
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.keys import (generate_private_key, key_fingerprint, load_private_key_file, load_public_key,
                          save_private_key)
from two_key.ledger import Ledger, LedgerError
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge
from two_key.toolcheck import open_stamp_key, stamp_key_path
from perm import chmod, private

RULES = [{"id": "t", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}
PHRASES = {
    "principal": "principal-passphrase-one",
    "ledger": "ledger-passphrase-two-ok",
    "witness": "witness-passphrase-three",
}
FAST = 1000


def _engine(path, key):
    env = sign_constitution("c", RULES, key, SPECS)
    err = io.StringIO()
    with redirect_stderr(err):
        return TwoKey(Ledger(path, key), key.public_key(), verify_signed(env, key.public_key()),
                      [FixedJudge("a", "yes")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                      allow_test_doubles=True, monitored_agent=TEST_AGENT)


class BackupFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ledger = self.root / "ledger"
        self.key = generate_private_key()
        self.key_path = self.root / "keys" / "principal.pem"
        save_private_key(self.key_path, self.key)
        self.tk = _engine(self.ledger, self.key)
        self.out = self.root / "backups"

    def export(self, phrases=None, **kwargs):
        err = io.StringIO()
        with redirect_stderr(err):
            result = export_backup(self.ledger, self.key_path, self.out, phrases or PHRASES,
                                   iterations=kwargs.pop("iterations", FAST), **kwargs)
        return result, err.getvalue()

    def bundles(self):
        return {role: _decrypt((self.out / name).read_bytes(), PHRASES[role], role)
                for role, name in BUNDLE_NAMES.items()}


class ExportShape(BackupFixture):
    def test_three_bundles_split_the_keys_and_name_the_kdf(self):
        result, _ = self.export()
        self.assertEqual(result["kdf"], KDF_NAME)
        self.assertEqual(result["alg"], ALG)
        self.assertEqual(result["format"], FORMAT)
        self.assertEqual(result["iterations"], FAST)
        opened = self.bundles()
        self.assertEqual(set(opened["principal"]["files"]), {"principal.pem", "capability.pem"})
        self.assertEqual(set(opened["witness"]["files"]), {"witness.pem"})
        self.assertIn("ledger.key", opened["ledger"]["files"])
        self.assertIn("head.anchor", opened["ledger"]["files"])
        self.assertNotIn("witness.pem", opened["ledger"]["files"])
        self.assertNotIn("principal.pem", opened["ledger"]["files"])
        self.assertNotIn("ledger.key", opened["witness"]["files"])
        self.assertNotIn("ledger.key", opened["principal"]["files"])
        for name in BUNDLE_NAMES.values():
            path = self.out / name
            self.assertTrue(private(path))
            header = json.loads(path.read_text())
            self.assertEqual(header["format"], FORMAT)
            self.assertEqual(header["version"], 1)
            self.assertEqual(header["alg"], ALG)
            self.assertEqual(header["kdf"]["name"], KDF_NAME)
        anchor = (self.ledger.parent / "ledger.ledger-key" / "head.anchor").read_bytes()
        self.assertEqual(opened["ledger"]["files"]["head.anchor"], anchor)

    def test_default_iterations_are_pbkdf2_600000(self):
        self.assertEqual(PBKDF2_ITERATIONS, 600_000)
        self.assertGreaterEqual(PBKDF2_ITERATIONS, MIN_ITERATIONS)
        self.assertLessEqual(PBKDF2_ITERATIONS, MAX_ITERATIONS)

    def test_export_refuses_a_missing_capability_key_and_low_iterations(self):
        bare = self.root / "bare"
        err = io.StringIO()
        with redirect_stderr(err):
            Ledger(bare, self.key)
        with self.assertRaisesRegex(BackupError, "capability key or the fingerprint key is missing"):
            export_backup(bare, self.key_path, self.root / "nope", PHRASES, iterations=FAST)
        with self.assertRaisesRegex(BackupError, "iterations"):
            self.export(iterations=MIN_ITERATIONS - 1)

    def test_shared_passphrase_warns(self):
        same = {role: "same-passphrase-value" for role in PHRASES}
        _, text = self.export(same)
        self.assertIn("share one passphrase", text)

    def test_refuses_to_overwrite_a_bundle(self):
        self.export()
        with self.assertRaisesRegex(BackupError, "refusing to overwrite"):
            self.export()

    def test_two_matching_passphrases_warn(self):
        phrases = dict(PHRASES)
        phrases["witness"] = phrases["principal"]
        _, text = self.export(phrases)
        self.assertIn("principal and witness", text)
        self.assertIn("passphrases match", text)

    def test_export_refuses_a_snapshot_that_would_not_open(self):
        cap = self.tk.ledger.capability_key_path()
        cap.unlink()
        save_private_key(cap, generate_private_key())
        with self.assertRaisesRegex(BackupError, "would not open"):
            self.export()
        self.assertFalse((self.out / "principal.bundle.json").exists())

    def test_refuses_a_symlink_or_a_group_writable_output_directory(self):
        real = self.root / "real-out"
        real.mkdir()
        chmod(real, 0o777)  # skipcq: BAN-B103 -- deliberately world-writable; export must refuse it
        link = self.root / "out-link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(BackupError, "symlink"):
            export_backup(self.ledger, self.key_path, link, PHRASES, iterations=FAST)
        self.assertEqual(list(real.iterdir()), [])
        wide = self.root / "wide-out"
        wide.mkdir()
        chmod(wide, 0o775)  # skipcq: BAN-B103 -- deliberately group-writable; export must refuse it
        with self.assertRaisesRegex(BackupError, "writable"):
            export_backup(self.ledger, self.key_path, wide, PHRASES, iterations=FAST)
        self.assertEqual(list(wide.iterdir()), [])
        private_out = self.root / "private-out"
        private_out.mkdir()
        chmod(private_out, 0o755)  # skipcq: BAN-B103 -- an ordinary directory; export must accept it
        err = io.StringIO()
        with redirect_stderr(err):
            export_backup(self.ledger, self.key_path, private_out, PHRASES, iterations=FAST)
        self.assertTrue((private_out / "principal.bundle.json").is_file())


class VerifyAndPassphrase(BackupFixture):
    def test_verify_checks_fingerprints_in_a_temporary_ledger(self):
        self.export()
        before = {p: p.stat().st_mtime_ns for p in self.ledger.rglob("*") if p.is_file()}
        err = io.StringIO()
        with redirect_stderr(err):
            report = verify_backup(self.out, PHRASES)
        self.assertTrue(report["ok"])
        self.assertEqual(report["capability_key_fingerprint"],
                         capability_key_fingerprint(self.tk.issuer.public_key))
        self.assertEqual(report["ledger_size"], self.tk.ledger.size())
        after = {p: p.stat().st_mtime_ns for p in self.ledger.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertFalse(self.root.joinpath("two-key-backup-").exists())

    def test_wrong_passphrase_and_tamper_are_rejected(self):
        self.export()
        bad = dict(PHRASES)
        bad["ledger"] = PHRASES["ledger"] + " "
        with self.assertRaisesRegex(BackupError, "wrong passphrase or tampered bundle"):
            verify_backup(self.out, bad)
        path = self.out / BUNDLE_NAMES["witness"]
        header = json.loads(path.read_text())
        body = header["ciphertext"]
        idx = 10
        swap = "A" if body[idx] != "A" else "B"
        header["ciphertext"] = body[:idx] + swap + body[idx + 1:]
        path.write_text(json.dumps(header) + "\n")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(BackupError, "wrong passphrase or tampered bundle"):
            verify_backup(self.out, PHRASES)

    def test_illegal_iterations_are_refused_without_running_the_kdf(self):
        self.export()
        path = self.out / BUNDLE_NAMES["principal"]
        header = json.loads(path.read_text())
        header["kdf"]["iterations"] = MAX_ITERATIONS + 1
        path.write_bytes((json.dumps(header) + "\n").encode())
        os.chmod(path, 0o600)
        started = time.monotonic()
        with self.assertRaisesRegex(BackupError, "iterations"):
            verify_backup(self.out, PHRASES)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_duplicate_key_in_the_bundle_is_refused(self):
        self.export()
        path = self.out / BUNDLE_NAMES["ledger"]
        text = path.read_text().replace('"format"', '"format": "x", "format"', 1)
        path.write_text(text)
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(BackupError, "duplicate key"):
            verify_backup(self.out, PHRASES)

    def test_empty_passphrase_is_refused_not_reported_as_tamper(self):
        self.export()
        blob = (self.out / BUNDLE_NAMES["witness"]).read_bytes()
        with self.assertRaisesRegex(BackupError, "passphrase is empty"):
            _decrypt(blob, "", "witness")

    def test_payload_rejects_an_extra_field_and_a_boolean_version(self):
        from two_key.backup import BACKUP_VERSION, PAYLOAD_FORMAT, _check_payload
        self.export()
        opened = self.bundles()["witness"]
        pem = opened["files"]["witness.pem"]
        payload = {
            "format": PAYLOAD_FORMAT,
            "version": BACKUP_VERSION,
            "role": "witness",
            "files": {"witness.pem": {"encoding": "pem", "alg": "ed25519+ml-dsa-65", "data": pem.decode("ascii")}},
            "fingerprints": {"witness.pem": opened["fingerprints"]["witness.pem"]},
        }
        self.assertEqual(_check_payload(payload, "witness")["files"]["witness.pem"], pem)
        # The alg is the key's own: a hybrid key named as an Ed25519 key is refused.
        mislabelled = dict(payload, files={"witness.pem": dict(payload["files"]["witness.pem"], alg="ed25519")})
        with self.assertRaisesRegex(BackupError, "witness.pem is not a witness backup field"):
            _check_payload(mislabelled, "witness")
        extra = dict(payload, note="x")
        with self.assertRaisesRegex(BackupError, "payload"):
            _check_payload(extra, "witness")
        boolean = dict(payload, version=True)
        with self.assertRaisesRegex(BackupError, "payload"):
            _check_payload(boolean, "witness")


class Restore(BackupFixture):
    def _anchor(self):
        return self.ledger.parent / "ledger.ledger-key" / "head.anchor"

    def test_restore_missing_keys_and_a_deleted_ledger(self):
        self.tk.ledger.append("note", {"n": 1})
        self.tk.ledger.checkpoint()
        size = self.tk.ledger.size()
        self.export()
        cap = self.tk.ledger.capability_key_path()
        fingerprint = capability_key_fingerprint(load_private_key_file(cap).public_key())
        cap.unlink()
        self.key_path.unlink()
        err = io.StringIO()
        with redirect_stderr(err):
            result = restore_backup(self.ledger, self.key_path, self.out, PHRASES)
        self.assertEqual(result["actions"]["capability.pem"], "created")
        self.assertEqual(result["actions"]["principal.pem"], "created")
        self.assertNotIn("entries.jsonl", result["actions"])
        self.assertEqual(capability_key_fingerprint(open_capability_key(Ledger(self.ledger, self.key)).public_key()),
                         fingerprint)
        # Total loss: remove the ledger directory and the sibling key dirs, then restore.
        import shutil
        for name in ("ledger", "ledger.ledger-key", "ledger.witness", "ledger.capability"):
            shutil.rmtree(self.root / name)
        self.key_path.unlink()
        with redirect_stderr(io.StringIO()):
            full = restore_backup(self.ledger, self.key_path, self.out, PHRASES)
        self.assertEqual(full["actions"]["head.anchor"], "created")
        self.assertEqual(full["actions"]["entries.jsonl"], "created")
        self.assertTrue(self._anchor().is_file())
        restored = Ledger(self.ledger, load_private_key_file(self.key_path))
        self.assertEqual(restored.size(), size)

    def test_newer_ledger_is_kept_and_replace_writes_the_anchor_with_the_ledger(self):
        self.export()
        old_anchor = self._anchor().read_bytes()
        self.tk.ledger.append("note", {"later": True})
        self.tk.ledger.checkpoint()
        newer = Ledger(self.ledger, self.key).size()
        newer_anchor = self._anchor().read_bytes()
        self.assertNotEqual(old_anchor, newer_anchor)
        with redirect_stderr(io.StringIO()):
            kept = restore_backup(self.ledger, self.key_path, self.out, PHRASES)
        self.assertFalse(kept["replaced_ledger"])
        self.assertNotIn("entries.jsonl", kept["actions"])
        self.assertNotIn("head.anchor", kept["actions"])
        self.assertEqual(self._anchor().read_bytes(), newer_anchor)
        self.assertEqual(Ledger(self.ledger, self.key).size(), newer)
        # Roll the directory back by hand and leave the current anchor. That must not open,
        # and restore must not fix it by deleting the anchor.
        opened = self.bundles()
        for name in ("entries.jsonl", "head.json", "keywrap.json"):
            (self.ledger / name).write_bytes(opened["ledger"]["files"][name])
        with self.assertRaisesRegex(LedgerError, "ledger_rolled_back") as raised:
            Ledger(self.ledger, self.key)
        self.assertIn("do not delete it", str(raised.exception))
        self.assertEqual(self._anchor().read_bytes(), newer_anchor)
        # The files now match the backup, and the anchor does not. Restore writes that
        # anchor back. It does not delete it, and it does not need the files to stay ahead.
        with redirect_stderr(io.StringIO()):
            fixed = restore_backup(self.ledger, self.key_path, self.out, PHRASES)
        self.assertEqual(fixed["actions"]["head.anchor"], "replaced")
        self.assertEqual(self._anchor().read_bytes(), old_anchor)
        self.assertLess(Ledger(self.ledger, self.key).size(), newer)

    def test_replace_ledger_overwrites_a_newer_ledger_without_deleting_the_anchor(self):
        self.export()
        old_anchor = self._anchor().read_bytes()
        self.tk.ledger.append("note", {"later": True})
        self.tk.ledger.checkpoint()
        newer = Ledger(self.ledger, self.key).size()
        err = io.StringIO()
        with redirect_stderr(err):
            result = restore_backup(self.ledger, self.key_path, self.out, PHRASES, replace_ledger=True)
        self.assertTrue(result["replaced_ledger"])
        self.assertIn("replace_ledger", err.getvalue())
        self.assertTrue(self._anchor().is_file())
        self.assertEqual(self._anchor().read_bytes(), old_anchor)
        self.assertLess(Ledger(self.ledger, self.key).size(), newer)

    def test_wrong_passphrase_writes_nothing(self):
        self.export()
        cap = self.tk.ledger.capability_key_path()
        cap.unlink()
        anchor = self._anchor().read_bytes()
        bad = dict(PHRASES)
        bad["witness"] = "not-the-witness-passphrase"
        with self.assertRaisesRegex(BackupError, "wrong passphrase or tampered"):
            restore_backup(self.ledger, self.key_path, self.out, bad)
        self.assertFalse(cap.exists())
        self.assertEqual(self._anchor().read_bytes(), anchor)

    def test_conflicting_key_is_not_overwritten(self):
        self.export()
        cap = self.tk.ledger.capability_key_path()
        original = cap.read_bytes()
        other = generate_private_key()
        cap.unlink()
        save_private_key(cap, other)
        written = cap.read_bytes()
        with self.assertRaisesRegex(BackupError, "backup_conflict"):
            restore_backup(self.ledger, self.key_path, self.out, PHRASES)
        self.assertEqual(cap.read_bytes(), written)
        self.assertNotEqual(written, original)

    def test_wiped_ledger_beside_a_newer_anchor_needs_replace_ledger(self):
        import shutil
        self.export()
        self.tk.ledger.append("note", {"later": True})
        self.tk.ledger.checkpoint()
        newer = self.tk.ledger.size()
        newer_anchor = self._anchor().read_bytes()
        shutil.rmtree(self.ledger)
        with self.assertRaisesRegex(BackupError, "replace_ledger"):
            restore_backup(self.ledger, self.key_path, self.out, PHRASES)
        self.assertFalse((self.ledger / "entries.jsonl").exists())
        self.assertEqual(self._anchor().read_bytes(), newer_anchor)
        with redirect_stderr(io.StringIO()):
            result = restore_backup(self.ledger, self.key_path, self.out, PHRASES, replace_ledger=True)
        self.assertEqual(result["actions"]["entries.jsonl"], "created")
        self.assertEqual(result["actions"]["head.anchor"], "replaced")
        self.assertTrue(self._anchor().is_file())
        self.assertNotEqual(self._anchor().read_bytes(), newer_anchor)
        self.assertLess(Ledger(self.ledger, self.key).size(), newer)

    def test_missing_anchor_on_a_newer_ledger_does_not_take_the_older_one(self):
        self.export()
        old_anchor = self._anchor().read_bytes()
        self.tk.ledger.append("note", {"later": True})
        self.tk.ledger.checkpoint()
        newer = Ledger(self.ledger, self.key).size()
        cap = self.tk.ledger.capability_key_path()
        cap.unlink()
        self._anchor().unlink()
        with redirect_stderr(io.StringIO()):
            result = restore_backup(self.ledger, self.key_path, self.out, PHRASES)
        self.assertEqual(result["actions"].get("capability.pem"), "created")
        self.assertNotIn("head.anchor", result["actions"])
        self.assertNotIn("entries.jsonl", result["actions"])
        self.assertFalse(self._anchor().exists())
        opened = Ledger(self.ledger, self.key)
        self.assertEqual(opened.size(), newer)
        self.assertNotEqual(self._anchor().read_bytes(), old_anchor)

    def test_missing_keys_after_witness_rotation_keep_the_new_witness(self):
        self.export()
        self.tk.ledger.rotate_witness(reason="yearly")
        newer = Ledger(self.ledger, self.key).size()
        witness = self.ledger.parent / "ledger.witness" / "witness.pem"
        new_witness = witness.read_bytes()
        anchor = self._anchor().read_bytes()
        self.key_path.unlink()
        cap = self.tk.ledger.capability_key_path()
        cap.unlink()
        err = io.StringIO()
        with redirect_stderr(err):
            result = restore_backup(self.ledger, self.key_path, self.out, PHRASES)
        self.assertEqual(result["actions"]["principal.pem"], "created")
        self.assertEqual(result["actions"]["capability.pem"], "created")
        self.assertEqual(result["actions"]["witness.pem"], "kept")
        self.assertNotIn("entries.jsonl", result["actions"])
        self.assertNotIn("head.anchor", result["actions"])
        self.assertEqual(witness.read_bytes(), new_witness)
        self.assertEqual(self._anchor().read_bytes(), anchor)
        self.assertIn("left in place", err.getvalue())
        opened = Ledger(self.ledger, load_private_key_file(self.key_path))
        self.assertEqual(opened.size(), newer)
        self.assertTrue(cap.is_file())


class StampKey(BackupFixture):
    """The tool check's stamp key (0.9.0) is in the principal bundle where the deployment has one: the checking
    tools pin its public key, so a restore that lost it would leave every checked tool refusing."""

    def setUp(self):
        super().setUp()
        self.stamp = stamp_key_path(self.tk.ledger)
        self.fingerprint = key_fingerprint(open_stamp_key(self.tk.ledger).public_key())

    def test_export_carries_it_and_restore_puts_it_and_its_public_file_back(self):
        result, _ = self.export()
        self.assertEqual(result["fingerprints"]["stamp"], self.fingerprint)
        principal = self.bundles()["principal"]["files"]
        self.assertEqual(principal["stamp.pem"], self.stamp.read_bytes())
        public = self.stamp.with_name("stamp.pub.pem")
        self.stamp.unlink()
        public.unlink()
        with redirect_stderr(io.StringIO()):
            restored = restore_backup(self.ledger, self.key_path, self.out, PHRASES)
        self.assertEqual((restored["actions"]["stamp.pem"], restored["actions"]["stamp.pub.pem"]),
                         ("created", "created"))
        self.assertEqual(key_fingerprint(load_private_key_file(self.stamp).public_key()), self.fingerprint)
        self.assertEqual(key_fingerprint(load_public_key(public)), self.fingerprint)

    def test_a_deployment_without_one_backs_up_as_before(self):
        self.stamp.unlink()
        self.export()
        self.assertNotIn("stamp.pem", self.bundles()["principal"]["files"])

    def test_a_stamp_key_that_is_not_the_pinned_one_or_is_missing_is_rejected(self):
        self.export()
        with patch("two_key.core._pinned_stamp_key", return_value=self.fingerprint), redirect_stderr(io.StringIO()):
            self.assertTrue(verify_backup(self.out, PHRASES)["ok"])
        with patch("two_key.core._pinned_stamp_key", return_value="hybrid-sha256:" + "0" * 64), \
                redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(BackupError, "stamp key does not match the fingerprint pinned"):
                verify_backup(self.out, PHRASES)
        self.stamp.unlink()
        other = self.root / "nostamp"
        with redirect_stderr(io.StringIO()):
            export_backup(self.ledger, self.key_path, other, PHRASES, iterations=FAST)
        with patch("two_key.core._pinned_stamp_key", return_value=self.fingerprint), redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(BackupError, "pins a stamp key .* stamp.pem is missing"):
                verify_backup(other, PHRASES)


class CommandLine(BackupFixture):
    def test_cli_round_trip_uses_the_default_kdf(self):
        env_names = {
            "principal": "TWO_KEY_TEST_PRINCIPAL_PP",
            "ledger": "TWO_KEY_TEST_LEDGER_PP",
            "witness": "TWO_KEY_TEST_WITNESS_PP",
        }
        for role, name in env_names.items():
            os.environ[name] = PHRASES[role]
        self.addCleanup(lambda: [os.environ.pop(name, None) for name in env_names.values()])
        args = ["backup-export", "--key", str(self.key_path), "--ledger", str(self.ledger),
                "--out", str(self.out),
                "--principal-passphrase-env", env_names["principal"],
                "--ledger-passphrase-env", env_names["ledger"],
                "--witness-passphrase-env", env_names["witness"]]
        err = io.StringIO()
        out = io.StringIO()
        with redirect_stderr(err), redirect_stdout(out):
            self.assertEqual(main(args), 0)
        header = json.loads((self.out / "principal.bundle.json").read_text())
        self.assertEqual(header["kdf"]["iterations"], PBKDF2_ITERATIONS)
        self.assertEqual(header["kdf"]["name"], KDF_NAME)
        cap = self.tk.ledger.capability_key_path()
        cap.unlink()
        restore_args = ["backup-restore", "--key", str(self.key_path), "--ledger", str(self.ledger),
                        "--bundles", str(self.out),
                        "--principal-passphrase-env", env_names["principal"],
                        "--ledger-passphrase-env", env_names["ledger"],
                        "--witness-passphrase-env", env_names["witness"]]
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            self.assertEqual(main(restore_args), 0)
        self.assertTrue(cap.is_file())
        verify_args = ["backup-verify", "--bundles", str(self.out),
                       "--principal-passphrase-env", env_names["principal"],
                       "--ledger-passphrase-env", env_names["ledger"],
                       "--witness-passphrase-env", env_names["witness"]]
        buf = io.StringIO()
        with redirect_stderr(io.StringIO()), redirect_stdout(buf):
            self.assertEqual(main(verify_args), 0)
        report = json.loads(buf.getvalue())
        self.assertTrue(report["ok"])
        self.assertEqual(report["capability_key_fingerprint"],
                         capability_key_fingerprint(load_private_key_file(cap).public_key()))


if __name__ == "__main__":
    unittest.main()
