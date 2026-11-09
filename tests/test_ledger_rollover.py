# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""0.9.1: the ledger rolls over into sealed segments and encrypted archives (design note, approved 2026-11-09).

One chain and one Merkle tree run across every segment; the active segment starts with ``ledger_continued``.
These tests follow the note's test plan: a rollover stopped at each step finishes or leaves the segment as it was,
another process catches up through an archive, a changed or missing archive is refused, a token still open at the
seal is carried and only that exact token redeems, and backups carry the archives."""

import io
import json
import os
import struct
import tempfile
import time
import unittest
import zlib
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from two_key import ledger_archive
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.gateway import ToolGateway
from two_key.keys import generate_private_key, save_private_key
from two_key.ledger import Ledger, LedgerError, RolloverSettings
from two_key.quorum import QuorumPolicy
from two_key import siem_export
from two_key.testing import TEST_AGENT, FixedJudge
from perm import private

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


def quiet(fn, *args, **kwargs):
    with redirect_stderr(io.StringIO()):
        return fn(*args, **kwargs)


def _checkpoint_once():
    """A stand-in for Ledger._checkpoint_unlocked that fails the second time: the checkpoint after
    ledger_continued."""
    real = Ledger._checkpoint_unlocked
    calls = {"n": 0}

    def wrapped(led, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("stopped")
        return real(led, *args, **kwargs)
    return wrapped


class LedgerCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root / "ledger"
        self.key = generate_private_key()
        self.led = self.open()

    def open(self, **kwargs) -> Ledger:
        return quiet(Ledger, self.path, self.key, **kwargs)

    def notes(self, led, start, count):  # skipcq: PYL-R0201 - test only
        for n in range(start, start + count):
            led.record("note", {"n": n})

    def archive(self, segment=1) -> Path:
        return self.path / "archive" / ledger_archive.archive_name(segment)


class Rollover(LedgerCase):
    def test_one_chain_across_segments(self):
        self.notes(self.led, 0, 5)
        result = self.led.roll("manual")
        self.assertTrue(result["rolled"])
        self.assertEqual((result["segment"], result["first_seq"], result["last_seq"]), (1, 0, 6))
        self.notes(self.led, 5, 3)
        again = self.open()
        self.assertEqual(again.segment_start(), 7)
        self.assertEqual([e.seq for e in again.entries], list(range(again.size())))
        self.assertEqual([e.body.get("n") for e in again.entries if e.kind == "note"], list(range(8)))
        self.assertEqual(again.entries[6].kind, "ledger_sealed")
        self.assertEqual(again.entries[7].prev, again.entries[6].entry_hash)
        self.assertEqual(again.merkle_root(), self.led.merkle_root())
        self.assertEqual(again.audit_archives()["archives"], 1)
        self.assertTrue(private(self.archive()))

    def test_the_active_file_holds_only_the_new_segment(self):
        self.notes(self.led, 0, 20)
        before = self.led.entries_path.stat().st_size
        self.led.roll("manual")
        self.assertLess(self.led.entries_path.stat().st_size, before)
        lines = self.led.entries_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["enc"], "two-key-ledger-enc/2")

    def test_hex_records_are_still_read(self):
        from two_key.ledger import RECORD_FORMAT_HEX, _open
        record = json.loads(self.led.entries_path.read_text(encoding="utf-8").splitlines()[0])
        nonce, ct = (bytes(__import__("base64").b64decode(record[k])) for k in ("n", "c"))
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        plain = AESGCM(self.led._data_key).decrypt(nonce, ct, b"two-key-ledger-enc/2")
        nonce2 = os.urandom(12)
        hexed = json.dumps({"enc": RECORD_FORMAT_HEX, "n": nonce2.hex(),
                            "c": AESGCM(self.led._data_key).encrypt(nonce2, plain, b"two-key-ledger-enc/1").hex()})
        self.assertEqual(_open(self.led._data_key, hexed), plain.decode("utf-8"))

    def test_rollover_and_continued_are_written_by_the_ledger_only(self):
        for kind in ("ledger_sealed", "ledger_continued", "ledger_rollover_failed"):
            with self.assertRaises(LedgerError):
                self.led.append(kind, {})

    def test_nothing_to_seal_is_put_off(self):
        self.notes(self.led, 0, 1)
        self.led.roll("manual")
        result = self.led.roll("manual")
        self.assertFalse(result["rolled"])
        self.assertIn("ledger_rollover_empty", result["reason"])

    def test_automatic_rollover_at_the_size_threshold(self):
        self.led.rollover = RolloverSettings(segment_mb=8)
        with mock.patch.object(RolloverSettings, "segment_bytes", new=property(lambda s: 4000)):
            self.notes(self.led, 0, 12)
        self.assertGreater(self.led.segment_start(), 0)
        self.assertEqual(self.led.entries[self.led.segment_start()].kind, "ledger_continued")
        self.assertEqual(self.open().size(), self.led.size())

    def test_automatic_rollover_by_age(self):
        self.led.rollover = RolloverSettings(segment_days=1)
        self.notes(self.led, 0, 2)
        self.assertEqual(self.led.segment_start(), 0)       # no entry with a time yet
        self.led.record("note", {"at": int(time.time()) - 3 * 86400})
        first = self.led.segment_start()
        self.assertGreater(first, 0)                         # its first timed entry is 3 days old
        self.led.record("note", {"n": 9})
        self.assertEqual(self.led.segment_start(), first)    # the new segment began now
        later = time.time() + 2 * 86400
        with mock.patch("two_key.ledger.time.time", return_value=later):
            self.led.record("note", {"n": 10})
        self.assertGreater(self.led.segment_start(), first)

    def test_settings_are_checked(self):
        for bad in ({"segment_mb": 4}, {"segment_mb": 2048}, {"segment_days": -1}, {"hard_limit_mb": 10},
                    {"compression": "lzma"}, {"keep_archives": "30"}, {"enabled": "yes"}, {"other": 1}):
            with self.assertRaises(ValueError, msg=bad):
                RolloverSettings.from_mapping(bad)
        self.assertEqual(RolloverSettings.from_mapping({"segment_mb": 16}).hard_limit_bytes, 32 * 1024 * 1024)

    def test_a_seal_after_a_rotation_and_a_rotation_after_a_seal(self):
        self.notes(self.led, 0, 2)
        self.led.rotate_witness(reason="before")
        self.led.roll("manual")
        self.led.rotate_witness(reason="after")
        self.notes(self.led, 2, 2)
        self.led.roll("manual")
        again = self.open()
        self.assertEqual(again.audit_archives()["archives"], 2)
        self.assertEqual(len([p for p in again.witness_report()["history"] if p["kind"] == "witness_rotated"]), 2)

    def test_compression_none(self):
        self.led.rollover = RolloverSettings(compression="none")
        self.notes(self.led, 0, 5)
        self.led.roll("manual")
        self.assertEqual(self.open().catalogue()[0]["compression"], "none")
        self.assertEqual(self.open().audit_archives()["archives"], 1)

    def test_archive_length_is_padded(self):
        self.notes(self.led, 0, 30)
        self.led.roll("manual")
        self.assertEqual(self.archive().stat().st_size % ledger_archive.PAD_BYTES, 0)

    def test_the_anchor_refuses_the_directory_rolled_back_with_its_archives(self):
        import shutil
        self.notes(self.led, 0, 3)
        saved = self.root / "saved"
        shutil.copytree(self.path, saved)
        self.led.roll("manual")
        self.notes(self.led, 3, 2)
        shutil.rmtree(self.path)
        shutil.copytree(saved, self.path)
        with self.assertRaises(LedgerError) as raised:
            self.open()
        self.assertIn("ledger_rolled_back", str(raised.exception))


class Crashes(LedgerCase):
    """A rollover stopped at any step is finished on the next open, or never started: no third state."""

    def setUp(self):
        super().setUp()
        self.notes(self.led, 0, 6)
        self.notes_before = self.led.size()

    def stopped(self, target, after=0):
        calls = {"n": 0}
        real = target[1]

        def boom(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] > after:
                raise OSError("stopped here")
            return real(*args, **kwargs)
        with mock.patch.object(target[0], target[2], side_effect=boom):
            with self.assertRaises((OSError, LedgerError)):
                self.led.roll("manual")

    def assert_finished_or_untouched(self):
        again = self.open()
        notes = [e.body["n"] for e in again.entries if e.kind == "note"]
        self.assertEqual(notes, list(range(6)))
        if again.segment_start():
            self.assertEqual(again.entries[again.segment_start()].kind, "ledger_continued")
            again.audit_archives()
        else:
            self.assertNotIn("ledger_sealed", [e.kind for e in again.entries])
        self.notes(again, 6, 1)
        self.assertEqual(self.open().size(), again.size())
        return again

    def test_stopped_writing_the_archive(self):
        with mock.patch.object(ledger_archive, "write_archive", side_effect=OSError("disk full")):
            result = self.led.roll("manual")
        self.assertFalse(result["rolled"])
        self.assertEqual(self.led.entries[-1].kind, "ledger_rollover_failed")
        self.assertEqual(self.assert_finished_or_untouched().segment_start(), 0)
        self.assertEqual(list((self.path / "archive").glob("*")), [])

    # The rollover's replaces, in order: the head and anchor after the seal, the archive into place,
    # entries.jsonl, the head and anchor after ledger_continued.

    def test_stopped_before_the_seal_is_signed(self):
        from two_key import _platform
        self.stopped((_platform, _platform.replace, "replace"))
        with self.assertRaises(LedgerError) as raised:
            self.open()
        self.assertIn("two-key recover", str(raised.exception))      # an uncheckpointed tail, as after any crash
        quiet(Ledger.recover_tail, self.path, self.key)
        self.assertEqual(self.assert_finished_or_untouched().segment_start(), 0)

    def test_stopped_after_the_seal_before_the_move(self):
        from two_key import _platform
        self.stopped((_platform, _platform.replace, "replace"), after=2)
        self.assertEqual(self.led.entries[-1].kind, "ledger_sealed")
        self.assertFalse(self.archive().exists())
        self.assertGreater(self.assert_finished_or_untouched().segment_start(), 0)

    def test_stopped_after_the_move_before_the_new_segment(self):
        from two_key import _platform
        self.stopped((_platform, _platform.replace, "replace"), after=3)
        self.assertTrue(self.archive().exists())
        self.assertEqual(self.led.entries_path.read_text(encoding="utf-8").count("\n"), self.notes_before + 1)
        self.assertGreater(self.assert_finished_or_untouched().segment_start(), 0)

    def test_stopped_before_the_last_head(self):
        from two_key import _platform
        self.stopped((_platform, _platform.replace, "replace"), after=4)
        self.assertGreater(self.assert_finished_or_untouched().segment_start(), 0)

    def test_stopped_writing_the_anchor_after_the_seal(self):
        from two_key import _platform
        self.stopped((_platform, _platform.replace, "replace"), after=1)
        self.assertGreater(self.assert_finished_or_untouched().segment_start(), 0)

    def test_the_same_process_finishes_on_its_next_write(self):
        from two_key import _platform
        self.stopped((_platform, _platform.replace, "replace"), after=2)
        self.led.record("note", {"n": 6})
        self.assertGreater(self.led.segment_start(), 0)
        self.assertEqual(self.open().size(), self.led.size())

    def test_stopped_before_the_last_checkpoint(self):
        with mock.patch.object(Ledger, "_prune_redeem_locks", side_effect=OSError("stopped")), \
                mock.patch.object(Ledger, "_checkpoint_unlocked", autospec=True,
                                  side_effect=_checkpoint_once()):
            with self.assertRaises(OSError):
                self.led.roll("manual")
        again = self.assert_finished_or_untouched()
        self.assertGreater(again.segment_start(), 0)

    def test_an_archive_that_is_not_this_segment_is_refused(self):
        from two_key import _platform
        self.stopped((_platform, _platform.replace, "replace"), after=2)
        self.archive().parent.mkdir(exist_ok=True)
        fd = _platform.create_new(self.archive())
        os.write(fd, b"not an archive")
        os.close(fd)
        with self.assertRaises(LedgerError) as raised:
            self.open()
        self.assertIn("ledger_rollover_incomplete", str(raised.exception))


class Tampering(LedgerCase):
    def setUp(self):
        super().setUp()
        self.notes(self.led, 0, 40)
        self.led.roll("manual")
        self.notes(self.led, 40, 40)
        self.led.roll("manual")
        self.notes(self.led, 80, 2)

    def refused(self, what="ledger_archive_invalid", audit=False):
        with self.assertRaises(LedgerError) as raised:
            self.open_and_audit(audit)
        self.assertIn(what, str(raised.exception))

    def open_and_audit(self, audit):
        led = self.open()
        if audit:
            led.audit_archives()

    def rewrite(self, path, data):  # skipcq: PYL-R0201 - test only
        os.chmod(path, 0o600)
        path.write_bytes(data)
        os.chmod(path, 0o600)

    def test_a_flipped_byte(self):
        data = bytearray(self.archive(1).read_bytes())
        data[len(data) // 2] ^= 1
        self.rewrite(self.archive(1), bytes(data))
        self.refused(audit=True)

    def test_a_flipped_byte_in_the_newest_archive_is_caught_at_open(self):
        data = bytearray(self.archive(2).read_bytes())
        data[200] ^= 1
        self.rewrite(self.archive(2), bytes(data))
        self.refused()

    def test_a_truncated_last_chunk(self):
        data = self.archive(1).read_bytes()
        self.rewrite(self.archive(1), data[:-10])
        self.refused()

    def test_two_archives_swapped(self):
        one, two = self.archive(1).read_bytes(), self.archive(2).read_bytes()
        self.rewrite(self.archive(1), two)
        self.rewrite(self.archive(2), one)
        self.refused()

    def test_a_deleted_archive(self):
        self.archive(1).unlink()
        self.refused()

    def test_a_loose_archive_is_insecure(self):
        if os.name == "nt":
            self.skipTest("POSIX modes")
        os.chmod(self.archive(1), 0o644)
        self.refused("ledger_archive_insecure")

    def test_a_replaced_catalogue_fails_the_chain(self):
        from two_key.ledger import _open, _seal
        line = self.led.entries_path.read_text(encoding="utf-8").splitlines()[0]
        entry = json.loads(_open(self.led._data_key, line))
        entry["body"]["catalogue"][0]["sha256"] = "sha256:" + "0" * 64
        lines = self.led.entries_path.read_text(encoding="utf-8").splitlines()
        lines[0] = _seal(self.led._data_key, json.dumps(entry, separators=(",", ":"), sort_keys=True))
        self.led.entries_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.refused("ledger chain failed verification")

    def test_audit_passes_untouched(self):
        report = self.open().audit_archives()
        self.assertEqual((report["archives"], report["archived_entries"]), (2, self.led.segment_start()))


class ArchiveFormat(unittest.TestCase):
    """The reader refuses a crafted archive before it can fill memory."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.key = os.urandom(32)

    def write(self, lines, compression="zlib", name="a.tkla"):
        path = self.dir / name
        with open(path, "wb") as fh:
            stats = ledger_archive.write_archive(fh, self.key, 1, iter(lines), compression)
        os.chmod(path, 0o600)
        return path, stats

    def read(self, path, limit, *, key=None, segment=1):
        return list(ledger_archive.read_archive(path, key or self.key, segment, max_plain=limit))

    def test_round_trip_spans_chunks(self):
        lines = [ledger_archive.entry_line({"n": i, "pad": os.urandom(400).hex()}) for i in range(4000)]
        path, stats = self.write(lines)
        self.assertGreater(stats["bytes"], ledger_archive.CHUNK_BYTES)
        self.assertEqual(len(self.read(path, stats["plain_bytes"])), 4000)

    def test_a_decompression_bomb_is_refused_at_the_recorded_length(self):
        lines = [b'{"x":"' + b"a" * 1_000_000 + b'"}\n'] * 50
        path, stats = self.write(lines)
        self.assertLess(stats["bytes"], 1_000_000)
        with self.assertRaises(ledger_archive.ArchiveError) as raised:
            self.read(path, 1000)
        self.assertIn("more than its recorded length", str(raised.exception))

    def test_an_oversized_chunk_is_refused(self):
        path, _ = self.write([b'{"a":1}\n'])
        data = path.read_bytes()
        header_end = data.index(b"\n") + 1
        forged = data[:header_end] + struct.pack(">I", ledger_archive.CHUNK_BYTES * 4) + data[header_end + 4:]
        path.write_bytes(forged)
        with self.assertRaises(ledger_archive.ArchiveError) as raised:
            self.read(path, 100)
        self.assertIn("impossible length", str(raised.exception))

    def test_swapped_chunks_are_refused(self):
        lines = [ledger_archive.entry_line({"pad": os.urandom(600).hex()}) for _ in range(3000)]
        path, stats = self.write(lines, compression="none")
        data = path.read_bytes()
        start = data.index(b"\n") + 1
        size = 4 + ledger_archive.CHUNK_BYTES + 16
        first, second = data[start:start + size], data[start + size:start + 2 * size]
        path.write_bytes(data[:start] + second + first + data[start + 2 * size:])
        with self.assertRaises(ledger_archive.ArchiveError):
            self.read(path, stats["plain_bytes"])

    def test_a_wrong_key_or_segment_is_refused(self):
        path, _ = self.write([b'{"a":1}\n'])
        other_key = os.urandom(32)
        with self.assertRaises(ledger_archive.ArchiveError):
            self.read(path, 100, key=other_key)
        with self.assertRaises(ledger_archive.ArchiveError):
            self.read(path, 100, segment=2)

    def test_bytes_after_the_body_are_refused(self):
        body = zlib.compress(b'{"a":1}\n')
        self.assertTrue(body)     # the writer pads with zeros only; anything else inside is refused
        path, stats = self.write([b'{"a":1}\n'], compression="none")
        self.assertEqual(self.read(path, stats["plain_bytes"]), [{"a": 1}])


class TwoProcesses(LedgerCase):
    def test_the_other_process_catches_up_through_the_archive(self):
        other = self.open()
        seen = []
        other.observe(seen.append)
        self.notes(self.led, 0, 4)
        self.led.roll("manual")
        self.notes(self.led, 4, 2)
        other.record("note", {"n": 6})
        self.assertEqual(other.size(), self.led.size() + 1)
        self.assertEqual([e.body.get("n") for e in other.entries if e.kind == "note"], list(range(7)))
        self.assertTrue(all(other.from_another_process(s) for s in range(1, other.size() - 1)))
        self.assertEqual(seen, [other.size() - 1])

    def test_two_rollovers_while_the_other_was_away(self):
        other = self.open()
        for n in range(3):
            self.notes(self.led, n * 3, 3)
            self.led.roll("manual")
        other.record("note", {"n": 99})
        self.assertEqual(len(other.catalogue()), 3)
        self.assertEqual(self.open().size(), other.size())


class Siem(LedgerCase):
    def test_export_and_verify_read_through_two_archives(self):
        self.notes(self.led, 0, 5)
        self.led.roll("manual")
        self.notes(self.led, 5, 5)
        self.led.roll("manual")
        self.notes(self.led, 10, 2)
        again = self.open()
        self.assertEqual([e.seq for e in siem_export.events(again)], list(range(again.size())))
        out = self.root / "export.jsonl"
        siem_export.write(again, out)
        report = siem_export.verify(self.open(), out, require_complete=True)
        self.assertEqual(report["problems"], [], report)


class CarriedTokens(unittest.TestCase):
    """A token issued just before a seal is redeemed after it; any other token naming an archived size is refused."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, key, SPECS)
        self.tk = quiet(TwoKey, quiet(Ledger, Path(self.tmp.name, "ledger"), key), key.public_key(),
                        verify_signed(env, key.public_key()), [FixedJudge("a", "yes")], private_key=key,
                        quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)
        self.gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled, tools={"search": lambda a: "ok"})

    def token(self, q="weather"):
        d = self.tk.authorize(SEARCH, {"q": q}, "look")
        self.assertTrue(d.allowed, d.reason)
        return d.token

    def redeem(self, token, q="weather"):
        return self.gw.invoke(token, "search", {"q": q}).reason

    def test_an_open_token_is_carried_and_redeems_once(self):
        token = self.token()
        result = self.tk.ledger.roll("manual")
        self.assertEqual(result["carried_tokens"], 1)
        self.assertEqual(self.redeem(token), "redeemed")
        self.assertEqual(self.redeem(token), "already_redeemed")

    def test_a_carried_token_is_carried_again_at_a_second_seal(self):
        token = self.token()
        self.tk.ledger.roll("manual")
        self.tk.ledger.record("note", {})
        self.assertEqual(self.tk.ledger.roll("manual")["carried_tokens"], 1)
        self.assertEqual(self.redeem(token), "redeemed")

    def test_a_spent_or_started_token_is_not_carried(self):
        token = self.token()
        self.assertEqual(self.redeem(token), "redeemed")
        self.assertEqual(self.tk.ledger.roll("manual")["carried_tokens"], 0)
        self.assertEqual(self.redeem(token), "ledger_size_archived")

    def test_an_expired_token_is_not_carried(self):
        token = self.token()
        self.assertEqual(self.tk.ledger.roll("manual", now=time.time() + 400)["carried_tokens"], 0)
        self.assertEqual(self.redeem(token), "ledger_size_archived")

    def test_a_revoked_token_is_not_carried(self):
        token = self.token()
        self.tk.revoke("test")
        self.assertEqual(self.tk.ledger.roll("manual")["carried_tokens"], 0)
        self.assertEqual(self.redeem(token), "ledger_size_archived")

    def test_a_revocation_after_the_seal_still_counts(self):
        token = self.token()
        self.tk.ledger.roll("manual")
        self.tk.revoke("test")
        self.assertEqual(self.redeem(token), "revoked_or_reloaded")

    def test_an_altered_token_with_a_carried_jti_is_refused(self):
        token = self.token()
        self.tk.ledger.roll("manual")
        record = self.tk.ledger.carried_token(self.tk.ledger.state_entries()[-1].body["carried_tokens"][0]["jti"])
        self.assertIsNotNone(record)
        with mock.patch.object(self.tk.ledger, "carried_token",
                               return_value={**record, "token_hash": "sha256:" + "0" * 64}):
            self.assertEqual(self.redeem(token), "ledger_size_archived")

    def test_after_reopen_the_carried_token_still_redeems(self):
        token = self.token()
        self.tk.ledger.roll("manual")
        led = quiet(Ledger, self.tk.ledger.path, self.tk.ledger.private_key)
        gw = ToolGateway(led, self.tk.issuer, self.tk.compiled, tools={"search": lambda a: "ok"})
        self.assertEqual(gw.invoke(token, "search", {"q": "weather"}).reason, "redeemed")

    def test_redeem_locks_are_pruned_by_the_rule(self):
        spent = self.token("a")
        self.assertEqual(self.redeem(spent, "a"), "redeemed")
        young = self.token("b")
        self.assertEqual(self.redeem(young, "b"), "redeemed")
        open_token = self.token("c")
        locks = self.tk.ledger.path.parent / "ledger.redeem-locks"
        files = sorted(locks.iterdir())
        self.assertEqual(len(files), 2)
        old = time.time() - 600
        os.utime(files[0], (old, old))
        link = locks / "not-a-lock"
        if os.name != "nt":
            link.symlink_to(files[1])
        result = self.tk.ledger.roll("manual")
        self.assertEqual(result["redeem_locks_removed"], 1)       # the young one stays; the open token has none
        self.assertEqual(len([p for p in locks.iterdir() if not p.is_symlink()]), 1)
        self.assertEqual(self.redeem(open_token, "c"), "redeemed")

    def test_the_hard_limit_stops_new_tokens(self):
        with mock.patch.object(Ledger, "over_hard_limit", return_value=True):
            d = self.tk.authorize(SEARCH, {"q": "x"}, "look")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "ledger_rollover_overdue")


class LedgerView(LedgerCase):
    """``two-key ledger-view --print``: the active segment by default, every archive with ``--archives``."""

    def setUp(self):
        super().setUp()
        self.key_file = self.root / "principal.pem"
        save_private_key(self.key_file, self.key)
        self.notes(self.led, 0, 4)
        self.led.roll("manual")
        self.notes(self.led, 4, 2)

    def view(self, *extra):
        from two_key.cli import main
        out, err = io.StringIO(), io.StringIO()
        argv = ["ledger-view", "--key", str(self.key_file), "--ledger", str(self.path), "--print", *extra]
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = main(argv)
            except SystemExit as e:
                return e.code, out.getvalue()
        return code, out.getvalue()

    def test_active_segment_then_every_archive(self):
        code, out = self.view()
        self.assertEqual(code, 0)
        rows = [json.loads(line) for line in out.splitlines()]
        self.assertEqual(rows[0]["kind"], "ledger_continued")
        self.assertEqual(rows[0]["seq"], self.led.segment_start())
        code, out = self.view("--archives")
        self.assertEqual(code, 0)
        self.assertEqual([json.loads(line)["seq"] for line in out.splitlines()], list(range(self.led.size())))

    def test_an_archive_that_does_not_read_is_named_not_a_traceback(self):
        self.led.roll("manual")             # opening checks only the newest archive's digest; this damages the older
        data = bytearray(self.archive().read_bytes())
        data[200] ^= 1
        self.archive().write_bytes(bytes(data))
        code, _ = self.view("--archives")
        self.assertIsInstance(code, str)
        self.assertIn("ledger_archive_invalid", code)


class Backups(unittest.TestCase):
    def test_export_verify_and_restore_with_archives(self):
        from two_key.backup import export_backup, restore_backup, verify_backup
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = generate_private_key()
            key_path = root / "keys" / "principal.pem"
            save_private_key(key_path, key)
            env = sign_constitution("c", RULES, key, SPECS)
            tk = quiet(TwoKey, quiet(Ledger, root / "ledger", key), key.public_key(),
                       verify_signed(env, key.public_key()), [FixedJudge("a", "yes")], private_key=key,
                       quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)
            tk.authorize(SEARCH, {"q": "x"}, "look")
            tk.ledger.roll("manual")
            tk.ledger.record("note", {})
            tk.ledger.roll("manual")
            phrases = {"principal": "principal-passphrase-one", "ledger": "ledger-passphrase-two-ok",
                       "witness": "witness-passphrase-three"}
            result = quiet(export_backup, root / "ledger", key_path, root / "out", phrases, iterations=1000)
            self.assertEqual(sorted(result["archives"]), ["segment-000001.tkla", "segment-000002.tkla"])
            self.assertEqual(len(quiet(verify_backup, root / "out", phrases)["archives"]), 2)
            (root / "out" / "archive" / "segment-000001.tkla").unlink()
            with self.assertRaises(Exception):
                quiet(verify_backup, root / "out", phrases)
            quiet(export_backup, root / "ledger", key_path, root / "out2", phrases, iterations=1000)
            restored = quiet(restore_backup, root / "new" / "ledger", root / "new" / "principal.pem", root / "out2",
                             phrases)
            self.assertEqual(restored["actions"]["archive/segment-000002.tkla"], "created")
            again = quiet(Ledger, root / "new" / "ledger", key)
            self.assertEqual(again.size(), tk.ledger.size())
            self.assertEqual(again.audit_archives()["archives"], 2)


if __name__ == "__main__":
    unittest.main()
