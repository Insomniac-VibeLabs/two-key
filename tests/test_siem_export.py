# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""``two-key siem-export`` and ``two-key siem-verify`` (0.7.0): the file export and the offline check.

The export is the same projection the live sinks use, so the allowlist tests in ``tests/test_siem.py``
cover what may leave; here the subject is the file: it verifies the ledger first, writes a line per event
and a summary, refuses to overwrite, and the check catches a gap, a repeat, and an edited event.
"""

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from two_key import _platform
from two_key.cli import main
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.keys import generate_private_key, save_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.siem_export import EXPORT_FORMAT, SUMMARY_KIND, ExportError, lines, verify, write
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public"}
SECRET = "zz-secret-argument-zz"
POSIX = not _platform.WINDOWS


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.key = generate_private_key()
        self.key_file = self.dir / "principal.pem"
        save_private_key(self.key_file, self.key)
        env = sign_constitution("Searching is fine.", RULES, self.key, SPECS)
        con = verify_signed(env, self.key.public_key())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.tk = TwoKey(Ledger(self.dir / "ledger", self.key), self.key.public_key(), con,
                             [FixedJudge("a", "yes")], private_key=self.key,
                             quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                             monitored_agent=TEST_AGENT)
        self.addCleanup(self.tk.close)
        allowed = self.tk.authorize(SEARCH, {"q": SECRET}, f"look up {SECRET}")
        self.assertTrue(allowed.allowed, allowed.reason)
        self.ledger = self.tk.ledger

    def exported(self, out="events.jsonl", **kw):
        path = self.dir / out
        result = write(self.ledger, path, **kw)
        return path, result

    def events_of(self, path):  # skipcq: PYL-R0201 - test only
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
        self.out, self.err = out.getvalue(), err.getvalue()
        return code


class Export(Fixture):
    def test_every_entry_is_a_line_and_the_last_line_is_the_summary(self):
        path, result = self.exported()
        events = self.events_of(path)
        self.assertEqual(result["lines"], self.ledger.size() + 1)
        self.assertEqual([e["seq"] for e in events[:-1]], list(range(self.ledger.size())))
        summary = events[-1]
        self.assertEqual((summary["kind"], summary["format"]), (SUMMARY_KIND, EXPORT_FORMAT))
        self.assertEqual(summary["ledger_size"], self.ledger.size())
        self.assertEqual(summary["merkle_root"], self.ledger.merkle_root())
        self.assertTrue(summary["signature"])

    def test_no_argument_value_or_proposal_text_is_in_the_file(self):
        path, _ = self.exported()
        self.assertNotIn(SECRET, path.read_text(encoding="utf-8"))

    def test_a_range_can_be_exported(self):
        path, _ = self.exported(from_seq=2, to_seq=4)
        events = self.events_of(path)
        self.assertEqual([e["seq"] for e in events[:-1]], [2, 3, 4])
        self.assertEqual(events[-1]["first_seq"], 2)

    def test_an_export_is_marked_a_replay(self):
        path, _ = self.exported()
        self.assertTrue(all(e.get("replay") for e in self.events_of(path)[:-1]))

    def test_it_refuses_to_overwrite(self):
        self.exported()
        with self.assertRaisesRegex(ExportError, "refusing to overwrite"):
            self.exported()

    @unittest.skipUnless(POSIX, "POSIX file modes")
    def test_the_file_is_owner_only(self):
        path, _ = self.exported()
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o077, 0)

    def test_the_other_schemas_and_cef_export_too(self):
        path, _ = self.exported("ecs.jsonl", schema="ecs")
        self.assertEqual(self.events_of(path)[0]["observer"]["product"], "Two-Key")
        path, _ = self.exported("events.cef", fmt="cef")
        first = path.read_text(encoding="utf-8").splitlines()[0]
        self.assertTrue(first.startswith("CEF:0|"))

    def test_the_lines_are_a_generator_that_does_not_hold_the_ledger(self):
        produced = lines(self.ledger)
        self.assertTrue(next(produced).startswith("{"))  # skipcq: PTC-W0063 - test only


class Verify(Fixture):
    def test_an_export_matches_the_ledger(self):
        path, _ = self.exported()
        result = verify(self.ledger, path, require_complete=True)
        self.assertTrue(result["ok"], result["problems"])
        self.assertEqual(result["events"], self.ledger.size())
        self.assertEqual(result["summary"]["kind"], SUMMARY_KIND)

    def test_an_edited_field_is_caught(self):
        path, _ = self.exported()
        events = self.events_of(path)
        decision = next(e for e in events if e["kind"] == "decision")  # skipcq: PTC-W0063 - test only
        decision["reason"] = "forged_allow"
        self.rewrite(path, events)
        problems = verify(self.ledger, path)["problems"]
        self.assertEqual([p["problem"] for p in problems], ["fields were changed"])
        self.assertEqual(problems[0]["seq"], decision["seq"])
        self.assertEqual(problems[0]["fields"], ["reason"])

    def test_the_rest_of_the_envelope_is_checked_against_the_ledger(self):
        """prev, severity, replay, ledgered and sent_at: the ledger decides all but the last, and an
        export writes one time on every line (live run 8x, C49, C58, C83)."""
        cases = {"prev": ("sha256:" + "0" * 64, "prev does not match the ledger"),
                 "severity": (0, "severity does not match the ledger"),
                 "replay": ("yes", "replay is written only when it is true"),
                 "ledgered": (False, None),      # counted as unledgered, and the summary's count is then off
                 "sent_at": ("whenever", "sent_at is not a timestamp")}
        for name, (value, want) in cases.items():
            with self.subTest(field=name):
                path, _ = self.exported(f"envelope-{name}.jsonl")
                events = self.events_of(path)
                events[2][name] = value
                self.rewrite(path, events)
                problems = [p["problem"] for p in verify(self.ledger, path)["problems"]]
                self.assertIn(want or "the summary counts a different number of events", problems)

    def test_a_changed_summary_is_caught(self):
        """The last line counts the lines it closes and names the head they were taken from."""
        for name, value in (("count", 3), ("first_seq", 2), ("last_seq", 99),
                            ("ledger_size", 9999), ("merkle_root", "sha256:" + "0" * 64),
                            ("exported_at", "2020-01-01T00:00:00.000Z")):
            with self.subTest(field=name):
                path, _ = self.exported(f"summary-{name}.jsonl")
                events = self.events_of(path)       # the summary is the last of them
                events[-1][name] = value
                self.rewrite(path, events)
                self.assertFalse(verify(self.ledger, path)["ok"])

    def test_a_changed_hash_is_caught(self):
        path, _ = self.exported()
        events = self.events_of(path)
        events[1]["entry_hash"] = "0" * 64
        self.rewrite(path, events)
        self.assertEqual(verify(self.ledger, path)["problems"][0]["problem"],
                         "entry_hash does not match the ledger")

    def test_an_added_field_is_caught(self):
        path, _ = self.exported()
        events = self.events_of(path)
        events[0]["counterparty"] = "attacker@example.net"
        self.rewrite(path, events)
        self.assertFalse(verify(self.ledger, path)["ok"])

    def test_a_gap_and_a_repeat_are_reported(self):
        path, _ = self.exported()
        events = self.events_of(path)
        missing = events.pop(3)
        events.append(dict(events[0]))
        self.rewrite(path, events)
        result = verify(self.ledger, path)
        problems = {p["problem"] for p in result["problems"]}
        self.assertIn("gap in the exported range", problems)
        self.assertIn("repeated sequence numbers", problems)
        self.assertEqual(result["missing"], 1)
        self.assertNotIn(missing["seq"], [e["seq"] for e in events if "seq" in e])

    def test_an_event_from_another_ledger_is_not_in_this_one(self):
        path, _ = self.exported()
        events = self.events_of(path)
        events[0]["seq"] = 9999
        self.rewrite(path, events)
        self.assertEqual(verify(self.ledger, path)["problems"][0]["problem"], "not in the ledger")

    def test_require_complete_wants_the_whole_ledger(self):
        path, _ = self.exported("part.jsonl", from_seq=2)
        self.assertTrue(verify(self.ledger, path)["ok"])
        problems = [p["problem"] for p in verify(self.ledger, path, require_complete=True)["problems"]]
        self.assertIn("does not start at the first entry", problems)

    def test_events_pulled_back_without_the_summary_still_check(self):
        path, _ = self.exported()
        events = [e for e in self.events_of(path) if e.get("kind") != SUMMARY_KIND]
        self.rewrite(path, events)
        result = verify(self.ledger, path, require_complete=True)
        self.assertTrue(result["ok"], result["problems"])
        self.assertIsNone(result["summary"])

    def test_an_unledgered_count_is_counted_not_checked(self):
        path, _ = self.exported()
        events = self.events_of(path)
        events.insert(0, {"schema": "two-key-siem-v1", "kind": "gateway_token_refused", "seq": -1,
                          "ledgered": False, "entry_hash": "", "total": 3})
        self.rewrite(path, events)
        result = verify(self.ledger, path, require_complete=True)
        self.assertTrue(result["ok"], result["problems"])
        self.assertEqual(result["unledgered_events"], 1)

    def test_another_schema_or_unreadable_text_is_a_problem(self):
        path = self.dir / "other.jsonl"
        path.write_text('{"event":{"action":"decision"},"seq":1}\nnot json\n', encoding="utf-8")
        problems = [p["problem"] for p in verify(self.ledger, path)["problems"]]
        self.assertTrue(any("native JSON schema" in p for p in problems))
        self.assertTrue(any("not readable JSON" in p for p in problems))

    def test_a_missing_file_is_an_export_error(self):
        with self.assertRaises(ExportError):
            verify(self.ledger, self.dir / "nope.jsonl")

    def rewrite(self, path, events):  # skipcq: PYL-R0201 - test only
        path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8", newline="\n")


class Cli(Fixture):
    def test_export_then_verify_from_the_command_line(self):
        out = self.dir / "cli.jsonl"
        self.assertEqual(self.cli("siem-export", "--key", str(self.key_file), "--ledger",
                                  str(self.ledger.path), "--out", str(out)), 0)
        self.assertIn('"ok": true', self.out)
        self.assertEqual(self.cli("siem-verify", "--key", str(self.key_file), "--ledger",
                                  str(self.ledger.path), "--events", str(out), "--require-complete"), 0)
        self.assertIn('"ok": true', self.out)

    def test_export_to_stdout_keeps_the_report_on_stderr(self):
        self.assertEqual(self.cli("siem-export", "--key", str(self.key_file), "--ledger",
                                  str(self.ledger.path)), 0)
        self.assertIn('"schema":"two-key-siem-v1"', self.out)
        self.assertIn('"lines"', self.err)

    def test_verify_reports_a_changed_event_and_exits_one(self):
        out = self.dir / "cli2.jsonl"
        self.cli("siem-export", "--key", str(self.key_file), "--ledger", str(self.ledger.path),
                 "--out", str(out))
        events = self.events_of(out)
        events[2]["reason"] = "forged"
        out.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8", newline="\n")
        self.assertEqual(self.cli("siem-verify", "--key", str(self.key_file), "--ledger",
                                  str(self.ledger.path), "--events", str(out)), 1)
        self.assertIn("fields were changed", self.out)

    def test_a_path_with_no_ledger_is_refused(self):
        self.assertEqual(self.cli("siem-export", "--key", str(self.key_file),
                                  "--ledger", str(self.dir / "nothing")), 1)
        self.assertIn("no ledger at", self.out)

    def test_export_refuses_to_overwrite_from_the_command_line(self):
        out = self.dir / "cli3.jsonl"
        self.cli("siem-export", "--key", str(self.key_file), "--ledger", str(self.ledger.path),
                 "--out", str(out))
        self.assertEqual(self.cli("siem-export", "--key", str(self.key_file), "--ledger",
                                  str(self.ledger.path), "--out", str(out)), 1)
        self.assertIn("refusing to overwrite", self.err)


if __name__ == "__main__":
    unittest.main()
