# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""``two-key ledger-view``: every field searchable, filterable, and sortable, alone and together; read-only.

The rows, tests, and sort are two_key/ledger_view.py's and need no display. The window itself is in
``tests/test_ledger_gui.py``; here ``--print`` and ``--fields`` drive the same code from the command line, and
a stand-in window checks what the command hands it.
"""

import contextlib
import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from two_key import cli
from two_key.cli import main
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.keys import generate_private_key, save_private_key
from two_key.ledger import Ledger
from two_key.ledger_view import (ANY_FIELD, OPS, Filter, Query, ViewError, default_columns, field_names, flatten,
                                 integrity, parse_sort, parse_where, rows_from_entries, select, sort_rows, text_of)
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search", "email_draft"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]},
         "email_draft": {"irreversible": False, "data_class_floor": "public",
                         "counterparties": [{"json_path": "to", "allow": ["ada@example"]}]}}


def entry(number, kind, **body):
    return {"seq": number, "prev": "0" * 64, "kind": kind, "body": body, "entry_hash": f"{number:064x}"}


ENTRIES = [
    entry(0, "proposal", tool="search", proposal="Look up Ada", agent=None),
    entry(1, "path_b", passed=True, reason="quorum_pass", yes=2, no=0,
          ballots=[{"judge_id": "a", "vote": "yes", "confidence": 0.9},
                   {"judge_id": "b", "vote": "yes", "confidence": 0.4}]),
    entry(2, "decision", allowed=True, reason="both_paths_allow", at="2026-10-27T02:00:00Z",
          subject={"tool": "search", "counterparties": [], "amount_usd": None}, agent="buyer"),
    entry(3, "path_b", passed=False, reason="quorum_fail", yes=1, no=1,
          ballots=[{"judge_id": "a", "vote": "yes", "confidence": 0.8},
                   {"judge_id": "c", "vote": "no", "confidence": 0.95}]),
    entry(4, "decision", allowed=False, reason="quorum_fail", at="2026-10-27T03:00:00Z",
          subject={"tool": "wire", "counterparties": ["eve@example", "ada@example"], "amount_usd": 250},
          agent="seller"),
    entry(5, "gateway_denied", reason="already_redeemed", jti="j1", tool_args_size=20, seq="shadowed"),
]


def seqs(rows):
    return [r.seq for r in rows]


class Rows(unittest.TestCase):
    def setUp(self):
        self.rows = rows_from_entries(ENTRIES)

    def test_every_body_value_is_a_field_under_its_dotted_path(self):
        row = self.rows[4]
        self.assertEqual(row.values["subject.tool"], ("wire",))
        self.assertEqual(row.values["subject.counterparties[]"], ("eve@example", "ada@example"))
        self.assertEqual(row.text("subject.counterparties[]"), "eve@example, ada@example")
        self.assertEqual(row.values["seq"], (4,))
        self.assertEqual(row.values["entry_hash"], (f"{4:064x}",))

    def test_list_of_records_keeps_every_element(self):
        self.assertEqual(self.rows[3].values["ballots[].judge_id"], ("a", "c"))
        self.assertEqual(self.rows[3].values["ballots[].confidence"], (0.8, 0.95))
        self.assertNotIn("ballots[]", self.rows[3].values)

    def test_empty_list_and_record_are_fields_with_no_value(self):
        self.assertEqual(self.rows[2].values["subject.counterparties[]"], ())
        self.assertEqual(flatten(entry(9, "x", extra={})).values["extra"], ())

    def test_body_key_named_like_an_entry_field_is_prefixed(self):
        row = self.rows[5]
        self.assertEqual(row.values["seq"], (5,))
        self.assertEqual(row.values["body.seq"], ("shadowed",))

    def test_entry_without_a_body(self):
        row = flatten({"seq": 7, "kind": "odd", "prev": "", "entry_hash": "h"})
        self.assertEqual(sorted(row.values), sorted(["seq", "kind", "prev", "entry_hash"]))

    def test_field_names_and_default_columns(self):
        names = field_names(self.rows)
        self.assertEqual(names[:2], ["seq", "kind"])
        self.assertEqual(names[2:], sorted(names[2:]))
        self.assertIn("ballots[].vote", names)
        self.assertEqual(default_columns(names)[:3], ["seq", "kind", "at"])
        self.assertNotIn("jti" + "x", default_columns(names))

    def test_text_of(self):
        self.assertEqual([text_of(v) for v in (None, True, False, 3, 0.5, "x")],
                         ["null", "true", "false", "3", "0.5", "x"])


class Filters(unittest.TestCase):
    def setUp(self):
        self.rows = rows_from_entries(ENTRIES)

    def keep(self, *filters, match_any=False, search=""):
        return seqs(select(self.rows, Query(search=search, filters=filters, match_any=match_any)))

    def test_each_text_test(self):
        self.assertEqual(self.keep(Filter("reason", "contains", "QUORUM")), [1, 3, 4])
        self.assertEqual(self.keep(Filter("reason", "equals", "quorum_fail")), [3, 4])
        self.assertEqual(self.keep(Filter("reason", "starts-with", "both")), [2])
        self.assertEqual(self.keep(Filter("reason", "ends-with", "_PASS")), [1])
        self.assertEqual(self.keep(Filter("reason", "regex", r"^quorum_(pass|fail)$")), [1, 3, 4])

    def test_negated_tests_keep_rows_without_the_field(self):
        self.assertEqual(self.keep(Filter("reason", "not-contains", "quorum")), [0, 2, 5])
        self.assertEqual(self.keep(Filter("agent", "not-equals", "buyer")), [0, 1, 3, 4, 5])

    def test_empty_and_not_empty(self):
        self.assertEqual(self.keep(Filter("agent", "empty")), [0, 1, 3, 5])
        self.assertEqual(self.keep(Filter("agent", "not-empty")), [2, 4])
        self.assertEqual(self.keep(Filter("subject.counterparties[]", "empty")), [0, 1, 2, 3, 5])

    def test_numbers_compare_as_numbers(self):
        self.assertEqual(self.keep(Filter("subject.amount_usd", "gt", "99")), [4])
        self.assertEqual(self.keep(Filter("seq", "ge", "4")), [4, 5])
        self.assertEqual(self.keep(Filter("seq", "lt", "2")), [0, 1])
        self.assertEqual(self.keep(Filter("seq", "le", "1")), [0, 1])
        # null is never greater or smaller than anything
        self.assertEqual(self.keep(Filter("subject.amount_usd", "lt", "1000")), [4])

    def test_text_compares_as_text_so_times_order(self):
        self.assertEqual(self.keep(Filter("at", "gt", "2026-10-27T02:30:00Z")), [4])
        self.assertEqual(self.keep(Filter("kind", "lt", "e")), [2, 4])

    def test_symbols_are_aliases(self):
        self.assertEqual(self.keep(Filter("seq", ">", "3")), self.keep(Filter("seq", "gt", "3")))
        self.assertEqual(self.keep(Filter("kind", "=", "decision")), [2, 4])
        self.assertEqual(self.keep(Filter("kind", "!~", "path")), [0, 2, 4, 5])

    def test_any_element_of_a_list_matches(self):
        self.assertEqual(self.keep(Filter("ballots[].judge_id", "equals", "c")), [3])
        self.assertEqual(self.keep(Filter("ballots[].confidence", "lt", "0.5")), [1])
        self.assertEqual(self.keep(Filter("subject.counterparties[]", "equals", "ada@example")), [4])

    def test_any_field(self):
        self.assertEqual(self.keep(Filter(ANY_FIELD, "equals", "seller")), [4])

    def test_filters_combine_with_all_or_any(self):
        both = (Filter("kind", "equals", "decision"), Filter("allowed", "equals", "false"))
        self.assertEqual(self.keep(*both), [4])
        self.assertEqual(self.keep(*both, match_any=True), [2, 4])
        either = (Filter("kind", "equals", "decision"), Filter("passed", "equals", "false"))
        self.assertEqual(self.keep(*either, match_any=True), [2, 3, 4])

    def test_search_applies_with_either_combination(self):
        self.assertEqual(self.keep(search="ada"), [0, 4])
        either = (Filter("kind", "equals", "proposal"), Filter("kind", "equals", "decision"))
        self.assertEqual(self.keep(*either, match_any=True, search="ADA"), [0, 4])

    def test_search_names_also_matches_field_names(self):
        self.assertEqual(self.keep(search="confidence"), [])
        names = Query(search="CONFIDENCE", search_names=True)
        self.assertEqual(seqs(select(self.rows, names)), [1, 3])
        either = Query(search="ada", search_names=True)
        self.assertEqual(seqs(select(self.rows, either)), [0, 4], "values still match")

    def test_booleans_and_null_match_their_json_spelling(self):
        self.assertEqual(self.keep(Filter("passed", "equals", "true")), [1])
        self.assertEqual(self.keep(Filter("agent", "equals", "null")), [0])

    def test_a_bad_filter_is_refused_in_words(self):
        unknown = Filter("kind", "like", "x")
        with self.assertRaisesRegex(ViewError, "unknown test"):
            unknown.compiled()
        broken = Filter("kind", "regex", "(")
        with self.assertRaisesRegex(ViewError, "regex"):
            broken.compiled()
        huge = Filter("kind", "regex", "a" * 501)
        with self.assertRaisesRegex(ViewError, "longer than"):
            huge.compiled()

    def test_every_listed_test_compiles(self):
        for op in OPS:
            self.assertEqual(Filter("kind", op, "x").compiled().op, op)


class Sorting(unittest.TestCase):
    def setUp(self):
        self.rows = rows_from_entries(ENTRIES)

    def test_default_is_ledger_order(self):
        self.assertEqual(seqs(select(list(reversed(self.rows)), Query())), [0, 1, 2, 3, 4, 5])

    def test_numbers_sort_as_numbers_and_missing_go_last_both_ways(self):
        self.assertEqual(seqs(sort_rows(self.rows, [("yes", False)])), [3, 1, 0, 2, 4, 5])
        self.assertEqual(seqs(sort_rows(self.rows, [("yes", True)])), [1, 3, 0, 2, 4, 5])

    def test_text_sort_ignores_case(self):
        rows = rows_from_entries([entry(0, "x", name="b"), entry(1, "x", name="A"), entry(2, "x", name="c")])
        self.assertEqual(seqs(sort_rows(rows, [("name", False)])), [1, 0, 2])

    def test_several_keys_first_decides_first(self):
        order = sort_rows(self.rows, [("kind", False), ("seq", True)])
        self.assertEqual(seqs(order), [4, 2, 5, 3, 1, 0])

    def test_numbers_before_text_in_one_column(self):
        rows = rows_from_entries([entry(0, "x", v="abc"), entry(1, "x", v=10), entry(2, "x", v=2)])
        self.assertEqual(seqs(sort_rows(rows, [("v", False)])), [2, 1, 0])

    def test_booleans_sort_as_their_text(self):
        self.assertEqual(seqs(sort_rows(self.rows, [("passed", False)])), [3, 1, 0, 2, 4, 5])

    def test_null_counts_as_missing(self):
        self.assertEqual(seqs(sort_rows(self.rows, [("agent", False)]))[:2], [2, 4])


class Arguments(unittest.TestCase):
    def test_parse_where(self):
        self.assertEqual(parse_where(["kind", "=", "decision"]), Filter("kind", "equals", "decision"))
        self.assertEqual(parse_where(["proposal", "contains", "two", "words"]),
                         Filter("proposal", "contains", "two words"))
        self.assertEqual(parse_where(["agent", "empty"]), Filter("agent", "empty", ""))
        for bad in (["kind"], ["kind", "like", "x"], ["kind", "equals"]):
            with self.subTest(bad=bad), self.assertRaises(ViewError):
                parse_where(bad)

    def test_parse_sort(self):
        self.assertEqual(parse_sort("seq"), ("seq", False))
        self.assertEqual(parse_sort("seq:desc"), ("seq", True))
        self.assertEqual(parse_sort("at:asc"), ("at", False))
        self.assertEqual(parse_sort("history_basis.now:desc"), ("history_basis.now", True))
        with self.assertRaises(ViewError):
            parse_sort(":desc")


class Command(unittest.TestCase):
    """``two-key ledger-view`` on a real ledger."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        cls.key = generate_private_key()
        cls.key_file = cls.dir / "principal.pem"
        save_private_key(cls.key_file, cls.key)
        env = sign_constitution("Searching and drafts to Ada are fine.", RULES, cls.key, SPECS)
        con = verify_signed(env, cls.key.public_key())
        with contextlib.redirect_stderr(io.StringIO()):
            tk = TwoKey(Ledger(cls.dir / "ledger", cls.key), cls.key.public_key(), con,
                        [FixedJudge("a", "yes", provider="p-a", maker="m-a"),
                         FixedJudge("b", "no", provider="p-b", maker="m-b")],
                        private_key=cls.key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                        monitored_agent=TEST_AGENT)
            tk.authorize({"tool": "search", "data_class": "public"}, {"q": "find ada"}, "look up ada", agent_id="buyer")
            tk.authorize({"tool": "wire_transfer", "data_class": "public"}, {}, "wire it")
            tk.close()
        cls.size = len(tk.ledger.entries)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_cli(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        argv = ["ledger-view", "--key", str(self.key_file), "--ledger", str(self.dir / "ledger"), *extra]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def printed(self, *extra):
        code, out, _ = self.run_cli("--print", *extra)
        self.assertEqual(code, 0)
        return [json.loads(line) for line in out.splitlines()]

    def test_print_lists_every_entry_in_order(self):
        entries = self.printed()
        self.assertEqual([e["seq"] for e in entries], list(range(self.size)))
        self.assertEqual(list(entries[0]), ["seq", "prev", "kind", "body", "entry_hash"])

    def test_print_filters_and_sorts(self):
        decisions = self.printed("--where", "kind", "equals", "decision", "--sort", "seq:desc")
        self.assertEqual([e["body"]["allowed"] for e in decisions], [False, True])
        denied = self.printed("--where", "kind", "=", "decision", "--where", "allowed", "=", "false")
        self.assertEqual([e["body"]["reason"] for e in denied], ["rule_denied:tools"])

    def test_print_by_judge_ballot(self):
        noes = self.printed("--where", "ballots[].vote", "equals", "no")
        self.assertTrue(noes)
        self.assertTrue(all(e["kind"] == "path_b" for e in noes))

    def test_print_any_and_search(self):
        either = self.printed("--any", "--where", "kind", "=", "proposal", "--where", "kind", "=", "decision")
        self.assertEqual({e["kind"] for e in either}, {"proposal", "decision"})
        searched = self.printed("--search", "wire it")
        self.assertEqual([e["kind"] for e in searched], ["proposal"])

    def test_print_search_names(self):
        self.assertEqual(self.printed("--search", "required_yes"), [])
        named = self.printed("--search", "required_yes", "--search-names")
        self.assertTrue(named)
        self.assertTrue(all("quorum_policy" in e["body"] for e in named))

    def test_print_by_agent(self):
        """The ledger records the agent as a mapping, so its id is the field ``agent.id``."""
        mine = self.printed("--where", "agent.id", "equals", "buyer")
        self.assertEqual([e["kind"] for e in mine], ["proposal", "decision"])
        self.assertIn("agent.id", default_columns(field_names(rows_from_entries(self.printed()))))

    def test_fields_lists_every_name(self):
        code, out, _ = self.run_cli("--fields")
        self.assertEqual(code, 0)
        names = out.split()
        self.assertEqual(names[:2], ["seq", "kind"])
        for name in ("ballots[].judge_id", "history_digest", "subject.tool", "quorum_policy.required_yes"):
            self.assertIn(name, names)

    def test_bad_arguments_are_refused_before_the_ledger_opens(self):
        for extra in (["--where", "kind", "like", "x"], ["--sort", ":desc"], ["--max-rows", "0"]):
            with self.subTest(extra=extra), self.assertRaises(SystemExit):
                self.run_cli("--print", *extra)

    def test_bad_regex_is_refused(self):
        with self.assertRaises(SystemExit) as caught:
            self.run_cli("--print", "--where", "reason", "regex", "(")
        self.assertIn("regex", str(caught.exception))

    def test_no_ledger(self):
        out = io.StringIO()
        argv = ["ledger-view", "--key", str(self.key_file), "--ledger", str(self.dir / "missing"), "--print"]
        with contextlib.redirect_stdout(out):
            code = main(argv)
        self.assertEqual(code, 1)
        self.assertIn("no ledger", out.getvalue())
        self.assertFalse((self.dir / "missing").exists())

    def test_viewing_does_not_change_the_ledger(self):
        files = sorted(p for p in self.dir.rglob("*") if p.is_file())
        before = {p: p.read_bytes() for p in files}
        self.printed()
        self.run_cli("--fields")
        self.assertEqual({p: p.read_bytes() for p in files}, before)
        self.assertEqual(sorted(p for p in self.dir.rglob("*") if p.is_file()), files)

    def window(self, show, *extra):
        fake = types.ModuleType("two_key.ledger_gui")
        fake.show = show
        with mock.patch.dict(sys.modules, {"two_key.ledger_gui": fake}):
            return self.run_cli(*extra)

    def test_window_gets_the_rows_report_and_query(self):
        seen = {}

        def show(rows, **kwargs):
            seen.update(kwargs, rows=rows)
            return 0
        code, _, _ = self.window(show, "--where", "kind", "=", "decision", "--max-rows", "5")
        self.assertEqual(code, 0)
        self.assertEqual(len(seen["rows"]), self.size)
        self.assertIs(seen["report"]["ok"], True)
        self.assertEqual(seen["query"].filters, (Filter("kind", "equals", "decision"),))
        self.assertEqual(seen["max_rows"], 5)
        rows, report = seen["reload"]()
        self.assertEqual(len(rows), self.size)
        self.assertEqual(report["size"], self.size)

    def test_reload_that_cannot_open_says_so(self):
        seen = {}

        def show(_rows, **kwargs):
            seen.update(kwargs)
            return 0
        self.window(show)
        reload = seen["reload"]
        entries = self.dir / "ledger" / "entries.jsonl"
        with mock.patch.object(Path, "is_file", return_value=False), self.assertRaisesRegex(ViewError, "no ledger"):
            reload()
        with mock.patch.object(Path, "read_text", side_effect=PermissionError(13, "Permission denied")), \
                self.assertRaisesRegex(ViewError, "Permission denied"):
            reload()
        original = entries.read_bytes()
        self.addCleanup(entries.write_bytes, original)
        lines = original.splitlines(keepends=True)
        entries.write_bytes(b"".join(lines[:-1]))
        with self.assertRaisesRegex(ViewError, "."):
            reload()

    def test_without_tkinter_the_command_says_what_to_do(self):
        with mock.patch.dict(sys.modules, {"two_key.ledger_gui": None}):
            code, _, err = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("tkinter", err)
        self.assertIn("--print", err)

    def test_integrity_reports_decision_digest_problems(self):
        ledger = types.SimpleNamespace(entries=[], size=lambda: 0)
        self.assertEqual(integrity(ledger), {"ok": True, "size": 0, "decision_digest_problems": []})
        with mock.patch("two_key.audit.check_decision_digests", return_value=["seq 3: bad"]):
            self.assertIs(integrity(ledger)["ok"], False)


if __name__ == "__main__":
    unittest.main()
