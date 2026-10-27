# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The ``two-key ledger-view`` window (two_key/ledger_gui.py), driven the way a person uses it.

Each test builds the window on a real Tk display, changes the search, filters, sort, or columns through the
same methods the controls call, and reads the table back. Skipped where Python has no tkinter or there is no
display to open a window on (a Linux job without ``xvfb-run``). A child process first opens and closes a
window the same way; where Tk ends that process (a CI runner without a usable window server, where Tk stops
the whole interpreter instead of raising ``TclError``), the window tests are skipped with its exit code.
"""

import functools
import subprocess  # nosec B404 - runs this Python with a fixed script
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

try:
    import tkinter as tk
    from tkinter import ttk

    from two_key import ledger_gui
    from two_key.ledger_gui import REFRESH_MS, LedgerViewer, details_text, report_text, show
except ImportError:                 # this Python was built without tkinter
    tk = None

from two_key.ledger_view import Filter, Query, ViewError, rows_from_entries


def entry(number, kind, **body):
    return {"seq": number, "prev": "0" * 64, "kind": kind, "body": body, "entry_hash": f"{number:064x}"}


ENTRIES = [
    entry(0, "proposal", tool="search", proposal="Look up Ada\non two lines", agent=None),
    entry(1, "path_b", passed=True, reason="quorum_pass",
          ballots=[{"judge_id": "a", "vote": "yes"}, {"judge_id": "b", "vote": "yes"}]),
    entry(2, "decision", allowed=True, reason="both_paths_allow", agent="buyer", at="2026-10-27T02:00:00Z"),
    entry(3, "path_b", passed=False, reason="quorum_fail",
          ballots=[{"judge_id": "a", "vote": "yes"}, {"judge_id": "c", "vote": "no"}]),
    entry(4, "decision", allowed=False, reason="quorum_fail", agent="seller", at="2026-10-27T03:00:00Z",
          note="x" * 300),
]
OK = {"ok": True, "size": 5, "decision_digest_problems": []}
ROOT = Path(__file__).resolve().parent.parent
# What the tests below do with Tk, in a child process: a hidden root, a viewer in a Toplevel, a menu, the
# clipboard, the Columns window, then a second root that runs its main loop until closed.
PROBE = """
import tkinter as tk
from two_key.ledger_gui import LedgerViewer
from two_key.ledger_view import rows_from_entries
root = tk.Tk()
root.withdraw()
top = tk.Toplevel(root)
view = LedgerViewer(top, rows_from_entries([{"seq": 0, "prev": "", "kind": "k", "body": {"a": [1, 2]},
                                             "entry_hash": "h"}]), reload=lambda: None)
top.update()
view.menu_for("0", "a")
view.copy("x")
top.clipboard_get()
view.choose_columns().destroy()
top.destroy()
root.destroy()
again = tk.Tk()
again.after(50, again.destroy)
again.mainloop()
"""


@functools.lru_cache(maxsize=None)
def tk_problem():
    """None when a child process can open and close windows as the tests do; otherwise why not."""
    try:
        done = subprocess.run([sys.executable, "-c", PROBE], cwd=ROOT, capture_output=True, text=True,
                              timeout=120, check=False)  # nosec B603 - this Python, a fixed script
    except subprocess.TimeoutExpired:
        return "opening a window did not finish in 120 seconds"
    if done.returncode != 0:
        last = (done.stderr.strip().splitlines() or ["no message"])[-1]
        return f"Tk cannot open windows here (exit code {done.returncode}: {last})"
    return None


def _find(widget, kind, text):
    """The first descendant of ``widget`` of ``kind`` whose text is ``text``."""
    for child in widget.winfo_children():
        if isinstance(child, kind) and str(child.cget("text")) == text:
            return child
        found = _find(child, kind, text)
        if found is not None:
            return found
    return None


@unittest.skipIf(tk is None, "this Python has no tkinter")
class Window(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if tk_problem():
            raise unittest.SkipTest(tk_problem())
        try:
            cls.root = tk.Tk()
        except tk.TclError as e:
            raise unittest.SkipTest(f"no display: {e}") from None
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        self.top = tk.Toplevel(self.root)
        self.addCleanup(self.top.destroy)
        self.rows = rows_from_entries(ENTRIES)

    def viewer(self, **kwargs):
        kwargs.setdefault("report", OK)
        view = LedgerViewer(self.top, self.rows, title="ledger", **kwargs)
        self.top.update_idletasks()
        return view

    def test_opens_with_every_entry_in_ledger_order(self):
        view = self.viewer()
        self.assertEqual(view.shown_seqs(), [0, 1, 2, 3, 4])
        self.assertEqual(view.status.cget("text"), "Showing 5 of 5 entries. Sorted by seq ascending.")
        self.assertEqual(self.top.title(), "Two-Key ledger: ledger")
        self.assertEqual(list(view.tree["columns"]), ["seq", "kind", "at", "agent", "tool", "allowed", "passed",
                                                      "reason", "ballots[].judge_id", "ballots[].vote"])

    def test_cells_are_one_line_and_cut(self):
        view = self.viewer()
        view.set_columns(["seq", "proposal", "note"])
        self.assertEqual(view.tree.set("0", "proposal"), "Look up Ada on two lines")
        note = view.tree.set("4", "note")
        self.assertEqual(len(note), ledger_gui.CELL_CHARS)
        self.assertTrue(note.endswith("…"))

    def test_search_and_filters_alone_and_together(self):
        view = self.viewer()
        view.search.set("ada")
        view.refresh()
        self.assertEqual(view.shown_seqs(), [0])
        view.search.set("")
        view.add_filter("kind", "equals", "decision")
        view.refresh()
        self.assertEqual(view.shown_seqs(), [2, 4])
        view.add_filter("ballots[].vote", "equals", "no")
        view.refresh()
        self.assertEqual(view.shown_seqs(), [])
        view.match_any.set(True)
        view.refresh()
        self.assertEqual(view.shown_seqs(), [2, 3, 4])
        view.search.set("quorum")
        view.refresh()
        self.assertEqual(view.shown_seqs(), [3, 4])

    def test_a_filter_line_without_a_value_does_nothing_yet(self):
        view = self.viewer()
        line = view.add_filter("reason")
        view.refresh()
        self.assertEqual(view.shown_seqs(), [0, 1, 2, 3, 4])
        self.assertIsNone(line.filter())
        line.op.set("empty")
        self.assertEqual(line.filter(), Filter("reason", "empty", ""))
        view.refresh()
        self.assertEqual(view.shown_seqs(), [0])
        line.name.set(" ")
        self.assertIsNone(line.filter())

    def test_remove_and_clear(self):
        view = self.viewer()
        first = view.add_filter("kind", "equals", "decision")
        view.add_filter("agent", "equals", "buyer")
        view.search.set("both")
        view.refresh()
        self.assertEqual(view.shown_seqs(), [2])
        view.remove_filter(first)
        view.refresh()
        self.assertEqual(view.shown_seqs(), [2])
        view.clear()
        view.refresh()
        self.assertEqual(view.filters, [])
        self.assertEqual(view.search.get(), "")
        self.assertEqual(view.shown_seqs(), [0, 1, 2, 3, 4])

    def test_query_given_on_the_command_line_is_shown(self):
        query = Query(search="quorum", filters=(Filter("kind", "equals", "path_b"),), sort=(("seq", True),))
        view = self.viewer(query=query)
        self.assertEqual(view.search.get(), "quorum")
        self.assertEqual([f.filter() for f in view.filters], [Filter("kind", "equals", "path_b")])
        self.assertEqual(view.shown_seqs(), [3, 1])

    def test_a_bad_filter_is_reported_and_the_table_stays(self):
        view = self.viewer()
        view.add_filter("reason", "regex", "(")
        view.refresh()
        self.assertIn("regex", view.status.cget("text"))
        self.assertEqual(view.shown_seqs(), [0, 1, 2, 3, 4])

    def test_typing_waits_then_filters_once(self):
        view = self.viewer()
        view.search.set("a")
        first = view.pending
        view.search.set("ad")
        self.assertIsNotNone(view.pending)
        self.assertNotEqual(view.pending, first)
        deadline = time.monotonic() + 5
        while view.pending is not None and time.monotonic() < deadline:
            time.sleep(REFRESH_MS / 4000)
            self.top.update()
        self.assertEqual(view.shown_seqs(), [0])

    def test_sort_by_heading_reverses_and_adds_keys(self):
        view = self.viewer()
        view.sort_by("reason")
        self.assertEqual(view.shown_seqs(), [2, 3, 4, 1, 0])
        self.assertEqual(view.tree.heading("reason", "text"), "reason ▲")
        view.sort_by("reason")
        self.assertEqual(view.shown_seqs(), [1, 3, 4, 2, 0])
        view.sort_by("seq", add=True)
        self.assertEqual(view.sort, [("reason", True), ("seq", False)])
        self.assertEqual(view.tree.heading("seq", "text"), "seq ▲2")
        view.sort_by("seq", add=True)
        self.assertEqual(view.shown_seqs(), [1, 4, 3, 2, 0])
        self.assertEqual(view.tree.heading("reason", "text"), "reason ▼1")
        self.assertIn("Sorted by reason descending, seq descending.", view.status.cget("text"))
        view.sort_by("kind")
        self.assertEqual(view.sort, [("kind", False)])

    def test_shift_click_on_a_heading_adds_a_sort_key(self):
        self.top.geometry("1200x600")
        view = self.viewer()
        self.top.update()
        x, y = view.tree.bbox("0", "kind")[0] + 5, 5
        if view.tree.identify_region(x, y) != "heading":
            self.skipTest("the window manager did not lay the table out")
        self.assertEqual(view.shift_click(SimpleNamespace(x=x, y=y)), "break")
        self.assertEqual(view.sort, [("seq", False), ("kind", False)])
        row_y = view.tree.bbox("0")[1] + 2
        self.assertIsNone(view.shift_click(SimpleNamespace(x=x, y=row_y)))

    def test_selecting_a_row_shows_every_field_and_the_entry(self):
        view = self.viewer()
        view.tree.selection_set("3")
        self.top.update()
        text = view.details_now()
        self.assertIn("ballots[].judge_id = a, c", text)
        self.assertIn('"reason": "quorum_fail"', text)
        view.tree.selection_set(())
        self.top.update()
        self.assertEqual(view.details_now(), "")
        self.assertEqual(details_text(self.rows[0]).splitlines()[0], "agent = null")

    def test_selection_stays_while_the_entry_is_listed(self):
        view = self.viewer()
        view.tree.selection_set("3")
        self.top.update()
        view.add_filter("kind", "equals", "path_b")
        view.refresh()
        self.assertEqual(view.tree.selection(), ("3",))
        self.assertIsNone(view.pending)
        view.search.set("quorum_pass")
        view.refresh()
        self.assertEqual(view.tree.selection(), ())
        self.top.update()
        self.assertEqual(view.details_now(), "")

    def test_right_click_menu_filters_on_a_value_or_copies_it(self):
        view = self.viewer()
        self.assertIsNone(view.menu_for("", "kind"))
        self.assertIsNone(view.menu_for("3", None))
        menu = view.menu_for("3", "ballots[].judge_id")
        labels = [menu.entrycget(i, "label") for i in range(menu.index("end") + 1)]
        self.assertEqual(labels, ["Show only ballots[].judge_id = a", "Hide ballots[].judge_id = a",
                                  "Show only ballots[].judge_id = c", "Hide ballots[].judge_id = c", "Copy value"])
        menu.invoke(2)
        view.refresh()
        self.assertEqual(view.shown_seqs(), [3])
        menu.invoke(1)
        view.refresh()
        self.assertEqual(view.shown_seqs(), [])
        menu.invoke(4)
        self.assertEqual(self.top.clipboard_get(), "a, c")

    def test_right_click_outside_the_rows_shows_no_menu(self):
        view = self.viewer()
        with mock.patch.object(tk.Menu, "tk_popup") as popup:
            view.context_menu(SimpleNamespace(x=-50, y=-50, x_root=0, y_root=0))
        popup.assert_not_called()
        with mock.patch.object(view, "menu_for") as menu_for:
            view.context_menu(SimpleNamespace(x=1, y=1, x_root=3, y_root=4))
        menu_for.return_value.tk_popup.assert_called_once_with(3, 4)

    def test_columns_window(self):
        view = self.viewer()
        top = view.choose_columns()
        box = next(w for w in top.winfo_children() if isinstance(w, tk.Listbox))
        box.selection_clear(0, "end")
        for i, name in enumerate(view.fields):
            if name in ("seq", "proposal", "ballots[].vote"):
                box.selection_set(i)
        _find(top, ttk.Button, "Apply").invoke()
        self.assertEqual(view.columns, ["seq", "ballots[].vote", "proposal"])
        self.assertEqual(view.tree.set("3", "ballots[].vote"), "yes, no")
        top = view.choose_columns()
        _find(top, ttk.Button, "Defaults").invoke()
        self.assertEqual(view.columns[:2], ["seq", "kind"])
        view.set_columns([])
        self.assertEqual(view.columns, ["seq"])

    def test_max_rows_lists_the_first_and_counts_all(self):
        view = self.viewer(max_rows=2)
        self.assertEqual(view.shown_seqs(), [0, 1])
        self.assertIn("Showing 5 of 5 entries (the first 2 are listed", view.status.cget("text"))

    def test_report_banner(self):
        view = self.viewer()
        self.assertIn("verified when opened", view.banner.cget("text"))
        self.assertFalse(view.problems_button.winfo_ismapped())
        bad = {"ok": False, "size": 5, "decision_digest_problems": ["seq 2: one", "seq 4: two"]}
        view.show_report(bad)
        self.top.update()
        self.assertIn("seq 2: one (and 1 more", view.banner.cget("text"))
        self.assertTrue(view.problems_button.winfo_ismapped())
        view.show_problems()
        self.assertEqual(view.details_now(), "seq 2: one\nseq 4: two")
        self.assertEqual(report_text({"ok": False, "size": 1, "decision_digest_problems": ["x"]})[0],
                         "1 entries. Decision digest problem: x")

    def test_reload_keeps_the_view_and_reports_a_failure(self):
        more = rows_from_entries([*ENTRIES, entry(5, "decision", allowed=True, reason="both_paths_allow",
                                                   extra_field="new")])
        results = [(more, OK)]

        def reload():
            if not results:
                raise ViewError("ledger gone")
            return results.pop()
        view = self.viewer(reload=reload)
        line = view.add_filter("kind", "equals", "decision")
        view.sort_by("seq")
        self.assertEqual(view.shown_seqs(), [4, 2])
        _find(self.top, ttk.Button, "Reload").invoke()
        self.assertEqual(view.shown_seqs(), [5, 4, 2])
        self.assertIn("extra_field", line.name_box.cget("values"))
        view.reload()
        self.assertIn("did not open again: ledger gone", view.banner.cget("text"))
        self.assertEqual(view.shown_seqs(), [5, 4, 2])

    def test_no_reload_button_without_a_reload(self):
        self.viewer()
        self.assertIsNone(_find(self.top, ttk.Button, "Reload"))


@unittest.skipIf(tk is None, "this Python has no tkinter")
class Show(unittest.TestCase):
    def test_no_display_says_to_use_print(self):
        with mock.patch.object(ledger_gui.tk, "Tk", side_effect=tk.TclError("no display name")), \
                mock.patch("builtins.print") as printed:
            self.assertEqual(show([]), 1)
        self.assertIn("--print", printed.call_args[0][0])

    def test_opens_and_returns_when_closed(self):
        if tk_problem():
            self.skipTest(tk_problem())
        real = tk.Tk

        def closing_soon():
            root = real()
            root.after(50, root.destroy)
            return root
        with mock.patch.object(ledger_gui.tk, "Tk", side_effect=closing_soon):
            self.assertEqual(show(rows_from_entries(ENTRIES), title="t", report=OK), 0)


if __name__ == "__main__":
    unittest.main()
