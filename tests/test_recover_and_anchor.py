"""#49 recovery command and #62 head anchor. Neither truncates on open."""

import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from two_key.cli import main
from two_key.keys import generate_private_key, save_private_key
from two_key.ledger import ANCHOR_FORMAT, Ledger, LedgerError
from perm import chmod, private


class CreateWarning(unittest.TestCase):
    def test_warns_once_on_a_new_path_and_not_on_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            path = Path(tmp, "ledger")
            err = io.StringIO()
            with redirect_stderr(err):
                led = Ledger(path, key)
            text = err.getvalue()
            self.assertIn("creating a new ledger", text)
            self.assertIn(str(path), text)
            self.assertTrue(led.created)
            err2 = io.StringIO()
            with redirect_stderr(err2):
                again = Ledger(path, key)
            self.assertEqual(err2.getvalue(), "")
            self.assertFalse(again.created)
            anchor = path.parent / f"{path.name}.ledger-key" / "head.anchor"
            self.assertTrue(anchor.is_file())
            self.assertFalse(str(anchor.resolve()).startswith(str(path.resolve()) + os.sep))
            self.assertTrue(private(anchor))

    def test_anchor_inside_the_ledger_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            path = Path(tmp, "ledger")
            path.mkdir()
            with self.assertRaises(LedgerError) as raised:
                Ledger(path, key, anchor_path=path / "head.anchor")
            self.assertIn("outside the ledger directory", str(raised.exception))


class AnchorRollback(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key = generate_private_key()
        self.path = Path(self.tmp.name, "ledger")
        err = io.StringIO()
        with redirect_stderr(err):
            self.led = Ledger(self.path, self.key)
        self.led.append("note", {"n": 1})
        self.led.checkpoint()

    def tearDown(self):
        self.tmp.cleanup()

    def _snapshot(self):
        return (self.path / "entries.jsonl").read_bytes(), (self.path / "head.json").read_bytes()

    def test_older_signed_head_is_refused_and_deleting_the_anchor_accepts_it(self):
        entries, head = self._snapshot()
        self.led.append("note", {"n": 2})
        self.led.checkpoint()
        newer = self.led.size()
        (self.path / "entries.jsonl").write_bytes(entries)
        (self.path / "head.json").write_bytes(head)
        with self.assertRaises(LedgerError) as raised:
            Ledger(self.path, self.key)
        self.assertIn("ledger_rolled_back", str(raised.exception))
        self.assertIn("do not delete it", str(raised.exception))
        # The documented hole: no anchor file means the current head is adopted.
        self.led._anchor_path.unlink()
        rolled = Ledger(self.path, self.key)
        self.assertLess(rolled.size(), newer)
        self.assertTrue(self.led._anchor_path.is_file())

    def test_wipe_does_not_open_as_a_new_ledger(self):
        anchor = self.led._anchor_path
        keywrap = self.path / "keywrap.json"
        for name in ("entries.jsonl", "head.json", "keywrap.json"):
            (self.path / name).unlink()
        with self.assertRaises(LedgerError) as raised:
            Ledger(self.path, self.key)
        self.assertIn("ledger_rolled_back", str(raised.exception))
        self.assertFalse(keywrap.exists())
        self.assertTrue(anchor.is_file())

    def test_same_size_different_tip_is_refused(self):
        from two_key.canonical import canonical_bytes
        from two_key.keys import sign
        anchor = json.loads(self.led._anchor_path.read_text())
        body = {k: anchor[k] for k in ("format", "size", "tip", "merkle_root", "public_key", "witness_public_key")}
        self.assertEqual(body["format"], ANCHOR_FORMAT)
        body["tip"] = "ab" * 32
        message = canonical_bytes(body)
        stored = dict(body)
        stored["signature"] = sign(self.key, message)
        stored["witness_signature"] = sign(self.led._witness, message)
        self.led._anchor_path.write_bytes((json.dumps(stored) + "\n").encode())
        chmod(self.led._anchor_path, 0o600)
        with self.assertRaises(LedgerError) as raised:
            Ledger(self.path, self.key)
        self.assertIn("differs from", str(raised.exception))

    def test_ledger_ahead_of_a_stale_anchor_advances_it(self):
        stale = self.led._anchor_path.read_bytes()
        self.led.append("note", {"n": 2})
        self.led.checkpoint()
        self.led._anchor_path.write_bytes(stale)
        chmod(self.led._anchor_path, 0o600)
        reopened = Ledger(self.path, self.key)
        self.assertEqual(reopened.size(), self.led.size())
        fresh = json.loads(reopened._anchor_path.read_text())
        self.assertEqual(fresh["size"], reopened.size())
        self.assertEqual(fresh["tip"], reopened.entries[-1].entry_hash)


class RecoverTail(unittest.TestCase):
    def test_clean_ledger_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            path = Path(tmp, "ledger")
            with redirect_stderr(io.StringIO()):
                led = Ledger(path, key)
            led.append("note", {"n": 1})
            led.checkpoint()
            before = (path / "entries.jsonl").read_bytes()
            result = Ledger.recover_tail(path, key)
            self.assertFalse(result["changed"])
            self.assertEqual((path / "entries.jsonl").read_bytes(), before)
            self.assertFalse(any(e.kind == "ledger_recovered" for e in Ledger(path, key).entries))

    def test_uncheckpointed_tail_is_dropped_and_recorded_without_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            path = Path(tmp, "ledger")
            with redirect_stderr(io.StringIO()):
                led = Ledger(path, key)
            led.append("note", {"n": 1, "secret": "do-not-ledger-this"})
            led.checkpoint()
            covered = led.size()
            led.append("note", {"n": 2, "secret": "do-not-ledger-this"})
            led.append("note", {"n": 3, "secret": "do-not-ledger-this"})
            with self.assertRaises(LedgerError) as raised:
                Ledger(path, key)
            self.assertIn("signed head does not match", str(raised.exception))
            result = Ledger.recover_tail(path, key)
            self.assertTrue(result["changed"])
            self.assertEqual(result["head_size"], covered)
            self.assertGreater(result["dropped_bytes"], 0)
            self.assertTrue(result["dropped_sha256"].startswith("sha256:"))
            self.assertNotIn("do-not-ledger-this", json.dumps(result))
            opened = Ledger(path, key)
            self.assertEqual(opened.size(), covered + 1)
            note = opened.entries[-1]
            self.assertEqual(note.kind, "ledger_recovered")
            self.assertNotIn("do-not-ledger-this", json.dumps(note.body))
            tail = Path(result["tail_file"]).read_bytes()
            self.assertEqual("sha256:" + hashlib.sha256(tail).hexdigest(), result["dropped_sha256"])
            self.assertFalse(str(Path(result["tail_file"]).resolve()).startswith(str(path.resolve()) + os.sep))
            opened.verify()
            with self.assertRaises(LedgerError):
                opened.append("ledger_recovered", {"dropped_bytes": 0})

    def test_torn_last_line_is_a_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            path = Path(tmp, "ledger")
            with redirect_stderr(io.StringIO()):
                led = Ledger(path, key)
            led.append("note", {"n": 1})
            led.checkpoint()
            led.append("note", {"n": 2})
            entries = path / "entries.jsonl"
            entries.write_bytes(entries.read_bytes()[:-8])
            result = Ledger.recover_tail(path, key)
            self.assertTrue(result["tail_torn"])
            self.assertTrue(Ledger(path, key).verify())

    def test_damage_inside_the_signed_prefix_is_not_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            path = Path(tmp, "ledger")
            with redirect_stderr(io.StringIO()):
                led = Ledger(path, key)
            led.append("note", {"n": 1})
            led.checkpoint()
            led.append("note", {"n": 2})
            led.checkpoint()
            raw = (path / "entries.jsonl").read_bytes().splitlines()
            raw[0] = raw[0][:-4] + b"zzzz"
            original = b"\n".join(raw) + b"\n"
            (path / "entries.jsonl").write_bytes(original)
            with self.assertRaises(LedgerError) as raised:
                Ledger.recover_tail(path, key)
            self.assertIn("not a trailing tail", str(raised.exception))
            self.assertEqual((path / "entries.jsonl").read_bytes(), original)

    def test_recover_refuses_a_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            path = Path(tmp, "ledger")
            with redirect_stderr(io.StringIO()):
                led = Ledger(path, key)
            led.append("note", {"n": 1})
            led.checkpoint()
            entries, head = (path / "entries.jsonl").read_bytes(), (path / "head.json").read_bytes()
            led.append("note", {"n": 2})
            led.checkpoint()
            (path / "entries.jsonl").write_bytes(entries)
            (path / "head.json").write_bytes(head)
            with self.assertRaises(LedgerError) as raised:
                Ledger.recover_tail(path, key)
            self.assertIn("ledger_rolled_back", str(raised.exception))
            self.assertEqual((path / "entries.jsonl").read_bytes(), entries)

    def test_cli_recover(self):
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            directory = Path(tmp)
            save_private_key(directory / "principal.pem", key)
            path = directory / "ledger"
            with redirect_stderr(io.StringIO()):
                led = Ledger(path, key)
            led.append("note", {"n": 1})
            led.checkpoint()
            led.append("note", {"n": 2})
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main(["recover", "--key", str(directory / "principal.pem"), "--ledger", str(path)])
            self.assertEqual(code, 0, out.getvalue() + err.getvalue())
            rec = json.loads(out.getvalue())
            self.assertTrue(rec["ok"])
            self.assertTrue(rec["changed"])
            self.assertTrue(Ledger(path, key).verify())


if __name__ == "__main__":
    unittest.main(verbosity=2)
