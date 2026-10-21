# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""#58: the ledger's witness public key is pinned in the ledger and, optionally, outside it.

A new ledger's first entry is ``witness_pinned``. A ledger made before 0.2.3 pins the key that signed its
head on first open (trust on first use). A head signed by another witness key, and a ``witness.pem`` that
does not match, are refused (``witness_key_changed``). The key changes only by ``rotate_witness``.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from two_key.audit import witness_pins
from two_key.canonical import canonical_bytes
from two_key.keys import generate_private_key, public_raw, save_private_key, sign
from two_key.ledger import Ledger, LedgerError, _seal, witness_key_fingerprint
from perm import chmod, private

from test_two_key import _engine


def fp(key) -> str:
    return witness_key_fingerprint(public_raw(key.public_key()))


def swap_witness(ledger: Ledger, key=None):
    """Replace witness.pem with another key, as #58 reproduced it."""
    key = key or generate_private_key()
    ledger.witness_path.unlink()
    save_private_key(ledger.witness_path, key)
    return key


class NewLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name, "ledger")
        self.key = generate_private_key()

    def test_first_entry_pins_the_witness_key(self):
        led = Ledger(self.path, self.key)
        witness = led._witness
        self.assertEqual([e.kind for e in led.entries], ["witness_pinned"])
        self.assertEqual(led.entries[0].body, {"witness_public_key": public_raw(witness.public_key()),
                                               "source": "new_ledger"})
        report = Ledger(self.path, self.key).verify()
        self.assertEqual(report["head"], fp(witness))
        self.assertEqual(report["in_ledger"], {"fingerprint": fp(witness), "seq": 0, "source": "new_ledger"})
        self.assertIsNone(report["configured"])
        self.assertEqual(report["history"], [{"seq": 0, "kind": "witness_pinned", "source": "new_ledger",
                                              "fingerprint": fp(witness)}])

    def test_reopening_does_not_pin_again(self):
        led = Ledger(self.path, self.key)
        led.append("note", {"n": 1})
        led.checkpoint()
        led = Ledger(self.path, self.key)
        self.assertEqual([e.kind for e in led.entries], ["witness_pinned", "note"])

    def test_pin_entries_are_written_only_by_the_ledger(self):
        led = Ledger(self.path, self.key)
        for kind in ("witness_pinned", "witness_rotated"):
            with self.assertRaisesRegex(LedgerError, "rotate_witness"):
                led.append(kind, {"witness_public_key": public_raw(generate_private_key().public_key())})
            with self.assertRaisesRegex(LedgerError, "rotate_witness"):
                led.append_bounded(kind, {})
        self.assertEqual(led.size(), 1)


class SwappedWitness(unittest.TestCase):
    """The #58 reproduction: replace witness.pem, then reopen. 0.2.2 accepted it silently."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name, "ledger")
        self.key = generate_private_key()
        self.led = Ledger(self.path, self.key)
        self.led.append("note", {"n": 1})
        self.led.checkpoint()

    def test_swapped_witness_pem_is_refused_on_open(self):
        swap_witness(self.led)
        with self.assertRaisesRegex(LedgerError, "witness_key_changed: .*witness.pem does not match the witness "
                                                 "key pinned in the ledger"):
            Ledger(self.path, self.key)

    def test_swapped_witness_pem_is_refused_before_an_append_is_written(self):
        swap_witness(self.led)
        with self.assertRaisesRegex(LedgerError, "witness_key_changed"):
            self.led.append("note", {"n": 2})
        with self.assertRaisesRegex(LedgerError, "witness_key_changed"):
            self.led.checkpoint()
        self.assertEqual(self.led.size(), 2)

    def test_restoring_the_pinned_key_reopens(self):
        original = self.led.witness_path.read_bytes()
        swap_witness(self.led)
        self.led.witness_path.unlink()
        self.led.witness_path.write_bytes(original)
        chmod(self.led.witness_path, 0o600)
        Ledger(self.path, self.key).verify()

    def test_head_signed_by_another_witness_key_is_refused(self):
        # Someone with the principal key and the ledger key writes a head that another witness key signs.
        other = generate_private_key()
        led = self.led
        head = {"size": led.size(), "tip": led.entries[-1].entry_hash, "merkle_root": led.merkle_root(),
                "public_key": public_raw(self.key.public_key()), "witness_public_key": public_raw(other.public_key())}
        stored = {**head, "signature": sign(self.key, canonical_bytes(head)),
                  "witness_signature": sign(other, canonical_bytes(head))}
        led.head_path.write_text(_seal(led._data_key, json.dumps(stored)) + "\n", encoding="utf-8")
        swap_witness(led, other)
        with self.assertRaisesRegex(LedgerError, "witness_key_changed: the head is signed by a witness key other "
                                                 "than the witness key pinned in the ledger"):
            Ledger(self.path, self.key)


class ConfiguredPin(unittest.TestCase):
    """The pin outside the ledger: a rewritten chain under a new witness key is refused."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name, "ledger")
        self.key = generate_private_key()
        led = Ledger(self.path, self.key)
        led.append("note", {"n": 1})
        led.checkpoint()
        self.witness = led._witness.public_key()

    def test_matching_pin_opens_and_is_reported(self):
        report = Ledger(self.path, self.key, witness_public_key=self.witness).verify()
        self.assertEqual(report["configured"], report["head"])
        self.assertEqual(report["configured"], report["in_ledger"]["fingerprint"])

    def test_other_configured_key_is_refused(self):
        with self.assertRaisesRegex(LedgerError, "witness_key_changed: the head is signed by a witness key other "
                                                 "than the configured witness public key"):
            Ledger(self.path, self.key, witness_public_key=generate_private_key().public_key())

    def test_rewritten_ledger_passes_the_in_ledger_pin_but_not_the_configured_one(self):
        # Wiping the ledger directory alone is refused: the head anchor sits outside it (#62).
        for name in ("entries.jsonl", "head.json"):
            (self.path / name).unlink()
        with self.assertRaisesRegex(LedgerError, "ledger_rolled_back"):
            Ledger(self.path, self.key)
        # Principal key and ledger key in hand: this attacker can also remove the anchor (it sits
        # beside the ledger key) and the witness key, then start over. The in-ledger pin is rewritten
        # with the new chain, so it cannot tell. The configured pin can.
        shutil.rmtree(self.path.parent / "ledger.witness")
        (self.path.parent / "ledger.ledger-key" / "head.anchor").unlink()
        forged = Ledger(self.path, self.key)          # pins a new witness key of the writer's choosing
        forged.append("note", {"n": "forged"})
        forged.checkpoint()
        Ledger(self.path, self.key).verify()         # the in-ledger pin alone cannot tell
        with self.assertRaisesRegex(LedgerError, "witness_key_changed"):
            Ledger(self.path, self.key, witness_public_key=self.witness)

    def test_new_ledger_with_a_configured_pin_needs_that_witness_key(self):
        other = Path(self.tmp.name, "other")
        with self.assertRaisesRegex(LedgerError, "witness_key_missing"):
            Ledger(other, self.key, witness_public_key=self.witness)
        self.assertFalse(Path(self.tmp.name, "other.witness", "witness.pem").exists())
        witness = generate_private_key()
        save_private_key(Path(self.tmp.name, "other.witness", "witness.pem"), witness)
        with self.assertRaisesRegex(LedgerError, "witness_key_changed"):
            Ledger(other, self.key, witness_public_key=self.witness)
        led = Ledger(other, self.key, witness_public_key=witness.public_key())
        self.assertEqual(led.entries[0].body["source"], "new_ledger")

    def test_configured_pin_must_be_a_public_key(self):
        with self.assertRaisesRegex(LedgerError, "Ed25519 public key"):
            Ledger(self.path, self.key, witness_public_key=public_raw(self.witness))


def _old_ledger(path: Path, key, notes: int = 2) -> Ledger:
    """A ledger as 0.2.2 wrote it: no witness_pinned entry."""
    with patch.object(Ledger, "_pin_witness", lambda self: None):
        led = Ledger(path, key)
        for n in range(notes):
            led.append("note", {"n": n})
        led.checkpoint()
    return led


class TrustOnFirstUse(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name, "ledger")
        self.key = generate_private_key()

    def test_old_ledger_pins_its_head_witness_on_first_open(self):
        old = _old_ledger(self.path, self.key)
        witness = old._witness
        led = Ledger(self.path, self.key)
        self.assertEqual([e.kind for e in led.entries], ["note", "note", "witness_pinned"])
        self.assertEqual(led.entries[-1].body, {"witness_public_key": public_raw(witness.public_key()),
                                                "source": "first_use", "head_size": 2})
        report = Ledger(self.path, self.key).verify()
        self.assertEqual(report["in_ledger"], {"fingerprint": fp(witness), "seq": 2, "source": "first_use"})
        self.assertEqual(report["history"][0]["head_size"], 2)
        self.assertEqual(Ledger(self.path, self.key).size(), 3)    # pinned once

    def test_old_ledger_with_a_witness_pem_that_did_not_sign_the_head_is_refused(self):
        old = _old_ledger(self.path, self.key)
        swap_witness(old)
        with self.assertRaisesRegex(LedgerError, "witness_key_changed: .*does not match the witness key that "
                                                 "signed the head"):
            Ledger(self.path, self.key)
        self.assertEqual(len((self.path / "entries.jsonl").read_text().splitlines()), 2)

    def test_old_ledger_with_a_configured_pin(self):
        old = _old_ledger(self.path, self.key)
        with self.assertRaisesRegex(LedgerError, "witness_key_changed"):
            Ledger(self.path, self.key, witness_public_key=generate_private_key().public_key())
        led = Ledger(self.path, self.key, witness_public_key=old._witness.public_key())
        self.assertEqual(led.entries[-1].body["source"], "first_use")

    def test_a_key_swapped_before_the_upgrade_is_not_detected(self):
        # The stated limit of trust on first use: 0.2.2 signs with whatever witness.pem holds.
        old = _old_ledger(self.path, self.key)
        swapped = swap_witness(old)
        with patch.object(Ledger, "_pin_witness", lambda self: None):
            led = Ledger(self.path, self.key)
            led.append("note", {"n": 2})
            led.checkpoint()
        led = Ledger(self.path, self.key)
        self.assertEqual(led.verify()["in_ledger"]["fingerprint"], fp(swapped))


class Rotation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name, "ledger")
        self.key = generate_private_key()
        self.led = Ledger(self.path, self.key)
        self.led.append("note", {"n": 1})
        self.led.checkpoint()
        self.old = self.led._witness

    def test_rotation_is_ledgered_and_reopens(self):
        new = generate_private_key()
        result = self.led.rotate_witness(new, reason="scheduled")
        self.assertEqual(result["seq"], 2)
        self.assertEqual(result["old_witness_key_fingerprint"], fp(self.old))
        self.assertEqual(result["new_witness_key_fingerprint"], fp(new))
        entry = self.led.entries[-1]
        self.assertEqual(entry.kind, "witness_rotated")
        self.assertEqual(entry.body["reason"], "scheduled")
        self.assertLessEqual({"principal_signature", "old_witness_signature", "new_witness_signature"},
                             set(entry.body))
        self.assertFalse(Path(str(self.led.witness_path) + ".new").exists())
        self.assertTrue(private(self.led.witness_path))
        self.assertIn(b"PUBLIC KEY", self.led.witness_path.with_suffix(".pub.pem").read_bytes())
        self.led.append("note", {"n": 2})
        self.led.checkpoint()
        report = Ledger(self.path, self.key).verify()
        self.assertEqual(report["head"], fp(new))
        self.assertEqual(report["in_ledger"], {"fingerprint": fp(new), "seq": 2, "source": "rotated"})
        self.assertEqual([p["kind"] for p in report["history"]], ["witness_pinned", "witness_rotated"])
        self.assertEqual(report["history"][1]["old_fingerprint"], fp(self.old))
        self.assertEqual(witness_pins(Ledger(self.path, self.key)), report["history"])

    def test_old_key_after_rotation_is_refused(self):
        old_pem = self.led.witness_path.read_bytes()
        self.led.rotate_witness()
        self.led.witness_path.unlink()
        self.led.witness_path.write_bytes(old_pem)
        chmod(self.led.witness_path, 0o600)
        with self.assertRaisesRegex(LedgerError, "witness_key_changed"):
            Ledger(self.path, self.key)

    def test_two_rotations(self):
        self.led.rotate_witness()
        last = generate_private_key()
        self.led.rotate_witness(last)
        report = Ledger(self.path, self.key).verify()
        self.assertEqual(report["in_ledger"]["fingerprint"], fp(last))
        self.assertEqual(len(report["history"]), 3)

    def test_rotation_refusals(self):
        with self.assertRaisesRegex(LedgerError, "is the current one"):
            self.led.rotate_witness(self.old)
        with self.assertRaisesRegex(LedgerError, "must not be the principal key"):
            self.led.rotate_witness(self.key)
        with self.assertRaisesRegex(LedgerError, "Ed25519 private key"):
            self.led.rotate_witness(self.key.public_key())
        with self.assertRaisesRegex(LedgerError, "at most 200"):
            self.led.rotate_witness(reason="x" * 201)
        with self.assertRaisesRegex(LedgerError, "principal key mismatch"):
            Ledger(self.path, generate_private_key(), self.key.public_key())
        other = Ledger(self.path, self.key)
        other.private_key = generate_private_key()          # changed after the open
        with self.assertRaisesRegex(LedgerError, "principal private key does not match"):
            other.rotate_witness()
        swap_witness(self.led)
        with self.assertRaisesRegex(LedgerError, "witness_key_changed"):
            self.led.rotate_witness()
        self.assertEqual(self.led.size(), 2)
        self.assertFalse(Path(str(self.led.witness_path) + ".new").exists())

    def test_rotation_with_a_configured_pin(self):
        led = Ledger(self.path, self.key, witness_public_key=self.old.public_key())
        new = generate_private_key()
        led.rotate_witness(new)
        led.append("note", {"n": 2})
        led.checkpoint()
        self.assertEqual(led.verify()["configured"], fp(new))
        with self.assertRaisesRegex(LedgerError, "witness_key_changed"):
            Ledger(self.path, self.key, witness_public_key=self.old.public_key())
        Ledger(self.path, self.key, witness_public_key=new.public_key()).verify()

    def test_forged_rotation_without_the_old_witness_key_is_refused(self):
        # The principal key and the ledger key, but not the old witness key: sign "old" with a stand-in.
        led, new, stand_in = self.led, generate_private_key(), generate_private_key()
        statement = {"format": "two-key-witness-rotation/1", "seq": led.size(),
                     "prev": led.entries[-1].entry_hash, "old_witness_public_key": public_raw(self.old.public_key()),
                     "new_witness_public_key": public_raw(new.public_key()), "reason": ""}
        message = canonical_bytes(statement)
        with led._exclusive():
            led._append_unlocked("witness_rotated", {**statement, "principal_signature": sign(self.key, message),
                                                     "old_witness_signature": sign(stand_in, message),
                                                     "new_witness_signature": sign(new, message)})
            led._checkpoint_unlocked(new)
        swap_witness(led, new)
        with self.assertRaisesRegex(LedgerError, "old_witness_signature failed"):
            Ledger(self.path, self.key)

    def test_interrupted_after_the_head_is_written(self):
        staged = Path(str(self.led.witness_path) + ".new")
        real_replace = os.replace

        def replace(src, dst):
            if str(src) == str(staged):
                raise OSError(5, "Input/output error")
            return real_replace(src, dst)
        with patch("two_key.ledger.os.replace", replace):
            with self.assertRaisesRegex(LedgerError, "move it by hand"):
                self.led.rotate_witness()
        self.assertTrue(staged.exists())
        with self.assertRaisesRegex(LedgerError, "witness_key_changed"):
            Ledger(self.path, self.key)
        os.replace(staged, self.led.witness_path)              # the documented repair
        led = Ledger(self.path, self.key)
        led.verify()
        # witness.pub.pem was never rewritten by the interrupted rotation; the open brings it in step.
        from two_key.keys import load_public_key
        pub = load_public_key(self.led.witness_path.with_suffix(".pub.pem"))
        self.assertEqual(public_raw(pub), public_raw(led._witness.public_key()))

    def test_a_staged_key_left_before_the_entry_was_written_blocks_rotation(self):
        staged = Path(str(self.led.witness_path) + ".new")
        save_private_key(staged, generate_private_key())
        with self.assertRaisesRegex(LedgerError, "interrupted rotation"):
            self.led.rotate_witness()
        self.assertEqual(Ledger(self.path, self.key).size(), 2)   # the ledger is unchanged; delete the file
        staged.unlink()
        self.led.rotate_witness()

    def test_failed_checkpoint_after_the_entry_recovers_as_after_a_crash(self):
        staged = Path(str(self.led.witness_path) + ".new")
        old_pem = self.led.witness_path.read_bytes()
        with patch.object(Ledger, "_checkpoint_unlocked", side_effect=OSError(28, "No space left on device")):
            with self.assertRaisesRegex(LedgerError, "witness_rotated was written but no head covers it"):
                self.led.rotate_witness()
        self.assertTrue(staged.exists())
        self.assertEqual(self.led.witness_path.read_bytes(), old_pem)
        with self.assertRaisesRegex(LedgerError, "witness_key_changed"):
            self.led.append("note", {"n": 2})               # the instance refuses to write on
        # The open reports the uncovered entry, not a witness change, so HOWTO's crash recovery applies.
        with self.assertRaisesRegex(LedgerError, "signed head does not match the chain"):
            Ledger(self.path, self.key)
        entries = self.path / "entries.jsonl"
        entries.write_text("".join(entries.read_text().splitlines(keepends=True)[:-1]))
        staged.unlink()
        led = Ledger(self.path, self.key)
        self.assertEqual(led.verify()["in_ledger"]["fingerprint"], fp(self.old))
        led.rotate_witness()


class OpenWrites(unittest.TestCase):
    """Opening a new or pre-0.2.3 ledger writes; it must not write with a mismatched principal key pair."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name, "ledger")
        self.key = generate_private_key()

    def test_first_open_with_the_wrong_principal_private_key_writes_nothing(self):
        _old_ledger(self.path, self.key)
        before = (self.path / "entries.jsonl").read_bytes(), (self.path / "head.json").read_bytes()
        with self.assertRaisesRegex(LedgerError, "principal key mismatch"):
            Ledger(self.path, generate_private_key(), self.key.public_key())
        self.assertEqual(((self.path / "entries.jsonl").read_bytes(), (self.path / "head.json").read_bytes()), before)
        self.assertEqual(Ledger(self.path, self.key).entries[-1].kind, "witness_pinned")

    def test_new_ledger_with_the_wrong_principal_private_key(self):
        with self.assertRaisesRegex(LedgerError, "principal key mismatch"):
            Ledger(self.path, generate_private_key(), self.key.public_key())
        self.assertFalse((self.path / "entries.jsonl").exists())

    def test_witness_read_before_another_process_rotated_it(self):
        led = Ledger(self.path, self.key)
        stale = led._witness
        Ledger(self.path, self.key).rotate_witness()
        with patch.object(Ledger, "_open_witness", lambda self: stale):
            Ledger(self.path, self.key).verify()       # reloaded under the lock, not refused

    def test_witness_pub_pem_is_kept_in_step(self):
        led = Ledger(self.path, self.key)
        pub = led.witness_path.with_suffix(".pub.pem")
        pub.write_bytes(b"not a key")
        Ledger(self.path, self.key)
        from two_key.keys import load_public_key
        self.assertEqual(public_raw(load_public_key(pub)), public_raw(led._witness.public_key()))


class EngineAfterRotation(unittest.TestCase):
    def test_authorize_and_redeem_after_a_rotation(self):
        from two_key.gateway import ToolGateway
        with tempfile.TemporaryDirectory() as tmp:
            key, tk = _engine(tmp)
            self.assertEqual(tk.ledger.entries[0].kind, "witness_pinned")
            tk.ledger.rotate_witness(reason="test")
            decision = tk.authorize({"tool": "search", "amount_usd": 0, "data_class": "public",
                                     "irreversible": False}, {}, "look it up")
            self.assertTrue(decision.allowed, decision.reason)
            gateway = ToolGateway(tk.ledger, tk.issuer, tk.compiled, tools={"search": lambda a: "ok"})
            self.assertTrue(gateway.invoke(decision.token, "search", {}).allowed)
            Ledger(Path(tmp, "ledger"), key).verify()


if __name__ == "__main__":
    unittest.main(verbosity=2)
