# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The ``two-key ledger-view`` window: ledger entries in a table to search, filter, and sort for an audit.

It uses tkinter from Python's standard library, so it adds no dependency, opens no network port, and writes
no file. It only reads: the rows come from a ledger that ``two-key ledger-view`` opened and verified the way
``two-key audit`` does, and the filtering and sorting are two_key/ledger_view.py's.

- The search box matches any field's value, and field names too when "Also match field names" is ticked.
  Each filter row tests one field (or ``*``, any field) and the filters combine with "all" or "any"; the
  search always applies too.
- Click a column heading to sort by it, again to reverse it; Shift-click adds it as the next sort key.
- Select a row to see every field and the whole entry below the table. Right-click a cell to filter on its
  value or copy it. "Columns" picks which fields the table shows; every field can be filtered either way.
- "Reload" opens the ledger again, verifies it again, and keeps the search, filters, and sort.
"""

from __future__ import annotations

import json
import sys
import tkinter as tk
from tkinter import ttk
from typing import Callable, Sequence

from .ledger_view import (ANY_FIELD, OPS, Filter, Query, Row, ViewError, default_columns, field_names, select,
                          text_of)

CELL_CHARS = 200            # longer cell text is cut in the table; the details pane shows all of it
REFRESH_MS = 250            # typing waits this long before the table is filtered again
MAX_MENU_VALUES = 10
UNARY = ("empty", "not-empty")


def _cell(text: str) -> str:
    """One line of at most ``CELL_CHARS`` characters for a table cell."""
    line = " ".join(text.split())
    return line if len(line) <= CELL_CHARS else line[:CELL_CHARS - 1] + "…"


def details_text(row: Row) -> str:
    """What the details pane shows for a row: each field and its values, then the entry as JSON."""
    lines = [f"{name} = {row.text(name)}" for name in sorted(row.values)]
    return "\n".join([*lines, "", "Entry as JSON:", json.dumps(row.entry, indent=2, sort_keys=True)])


def report_text(report: dict) -> tuple[str, bool]:
    """The integrity line above the table, and whether it reports a problem."""
    if report.get("error"):
        return (f"The ledger did not open again: {report['error']}. The table still shows the entries from when "
                "it last opened."), True
    problems = report.get("decision_digest_problems") or []
    if problems:
        more = f" (and {len(problems) - 1} more; press Show problems)" if len(problems) > 1 else ""
        return f"{report.get('size', 0)} entries. Decision digest problem: {problems[0]}{more}", True
    return (f"{report.get('size', 0)} entries, verified when opened: hash chain, signed head and witness pins "
            "check out, and every decision's digests match its constitution_loaded."), False


class FilterRow:
    """One filter line: a field, a test, a value, and a Remove button."""

    def __init__(self, viewer: "LedgerViewer", parent, name: str = ANY_FIELD, op: str = "contains",
                 value: str = "") -> None:
        self.frame = ttk.Frame(parent)
        self.name, self.op, self.value = tk.StringVar(value=name), tk.StringVar(value=op), tk.StringVar(value=value)
        self.name_box = ttk.Combobox(self.frame, textvariable=self.name, values=[ANY_FIELD, *viewer.fields],
                                     width=36)
        self.name_box.pack(side="left", padx=(0, 4))
        ttk.Combobox(self.frame, textvariable=self.op, values=OPS, state="readonly", width=12).pack(side="left")
        ttk.Entry(self.frame, textvariable=self.value, width=40).pack(side="left", padx=4, fill="x", expand=True)
        ttk.Button(self.frame, text="Remove", command=lambda: viewer.remove_filter(self)).pack(side="left")
        for var in (self.name, self.op, self.value):
            var.trace_add("write", viewer.changed)
        self.frame.pack(fill="x", pady=1)

    def filter(self) -> Filter | None:
        """The filter this line describes, or None while it has no field or no value yet."""
        name, op, value = self.name.get().strip(), self.op.get(), self.value.get()
        if not name or (op not in UNARY and value == ""):
            return None
        return Filter(name, op, value)


class LedgerViewer:
    """The window's contents. ``reload`` returns fresh rows and a report, or raises ``ViewError``."""

    def __init__(self, root, rows: Sequence[Row], *, title: str = "", report: dict | None = None,
                 reload: Callable[[], tuple[Sequence[Row], dict]] | None = None, query: Query | None = None,
                 max_rows: int = 10000) -> None:
        query = query or Query()
        self.root, self.rows, self.reload_rows, self.max_rows = root, list(rows), reload, max_rows
        self.fields = field_names(self.rows)
        self.columns = default_columns(self.fields)
        self.sort: list[tuple[str, bool]] = list(query.sort)
        self.filters: list[FilterRow] = []
        self.shown: list[Row] = []
        self.by_seq: dict[str, Row] = {}
        self.problems: list[str] = []
        self.pending = None
        self.search = tk.StringVar(value=query.search)
        self.match_any = tk.BooleanVar(value=query.match_any)
        self.search_names = tk.BooleanVar(value=query.search_names)
        root.title(f"Two-Key ledger: {title}" if title else "Two-Key ledger")
        self._build_toolbar()
        self.filter_frame = ttk.Frame(root, padding=(8, 0))
        self.filter_frame.pack(fill="x")
        self._build_banner()
        self._build_panes()
        self.status = ttk.Label(root, anchor="w", padding=(8, 2))
        self.status.pack(fill="x", side="bottom")
        for f in query.filters:
            self.add_filter(f.name, f.op, f.value)
        self.search.trace_add("write", self.changed)
        self.match_any.trace_add("write", self.changed)
        self.search_names.trace_add("write", self.changed)
        root.bind("<Control-f>", lambda _e: self.search_entry.focus_set())
        self.show_report(report or {})
        self.refresh()

    # -- building the window -------------------------------------------------------------------------------

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, padding=8)
        bar.pack(fill="x")
        ttk.Label(bar, text="Search all fields:").pack(side="left")
        self.search_entry = ttk.Entry(bar, textvariable=self.search, width=40)
        self.search_entry.pack(side="left", padx=4, fill="x", expand=True)
        ttk.Checkbutton(bar, text="Also match field names", variable=self.search_names).pack(
            side="left", padx=(0, 8))
        ttk.Radiobutton(bar, text="Match all filters", variable=self.match_any, value=False).pack(side="left")
        ttk.Radiobutton(bar, text="Match any filter", variable=self.match_any, value=True).pack(side="left", padx=4)
        ttk.Button(bar, text="Add filter", command=self.add_filter).pack(side="left")
        ttk.Button(bar, text="Clear", command=self.clear).pack(side="left", padx=4)
        ttk.Button(bar, text="Columns", command=self.choose_columns).pack(side="left")
        if self.reload_rows is not None:
            ttk.Button(bar, text="Reload", command=self.reload).pack(side="left", padx=4)

    def _build_banner(self) -> None:
        line = ttk.Frame(self.root, padding=(8, 4))
        line.pack(fill="x")
        self.banner = tk.Label(line, anchor="w", justify="left")
        self.banner.pack(side="left", fill="x", expand=True)
        self.problems_button = ttk.Button(line, text="Show problems", command=self.show_problems)

    def _build_panes(self) -> None:
        panes = ttk.PanedWindow(self.root, orient="vertical")
        panes.pack(fill="both", expand=True, padx=8)
        table = ttk.Frame(panes)
        self.tree = ttk.Treeview(table, show="headings", selectmode="browse")
        ysb = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        xsb = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self._selected)
        self.tree.bind("<Shift-Button-1>", self.shift_click)
        for button in ("<Button-3>", "<Button-2>"):
            self.tree.bind(button, self.context_menu)
        details = ttk.Frame(panes)
        self.details = tk.Text(details, height=12, wrap="none", state="disabled")
        dsb = ttk.Scrollbar(details, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=dsb.set)
        self.details.pack(side="left", fill="both", expand=True)
        dsb.pack(side="left", fill="y")
        panes.add(table, weight=3)
        panes.add(details, weight=1)
        self._set_columns()

    def _set_columns(self) -> None:
        self.tree["columns"] = self.columns
        for name in self.columns:
            self.tree.heading(name, text=name, command=lambda n=name: self.sort_by(n))
            self.tree.column(name, width=70 if name == "seq" else 170, stretch=False, anchor="w")

    # -- what to show ----------------------------------------------------------------------------------------

    def query(self) -> Query:
        filters = tuple(f for f in (row.filter() for row in self.filters) if f is not None)
        return Query(search=self.search.get(), filters=filters, match_any=self.match_any.get(),
                     sort=tuple(self.sort), search_names=self.search_names.get())

    def changed(self, *_args) -> None:
        """Filter again shortly after the last change, so typing is not slowed by each key."""
        if self.pending is not None:
            self.root.after_cancel(self.pending)
        self.pending = self.root.after(REFRESH_MS, self.refresh)

    def refresh(self) -> None:
        """Filter and sort again now. The selected entry stays selected while it is still listed."""
        if self.pending is not None:
            self.root.after_cancel(self.pending)
            self.pending = None
        try:
            shown = select(self.rows, self.query())
        except ViewError as e:
            self._set_status(str(e), error=True)
            return
        selected = self.tree.selection()
        self.shown = shown
        self.by_seq = {str(row.seq): row for row in shown[:self.max_rows]}
        self.tree.delete(*self.tree.get_children())
        for row in shown[:self.max_rows]:
            self.tree.insert("", "end", iid=str(row.seq), values=[_cell(row.text(c)) for c in self.columns])
        kept = [iid for iid in selected if iid in self.by_seq]
        if kept:
            self.tree.selection_set(kept)
            self.tree.see(kept[0])
        self._update_headings()
        self._set_status(self._summary())

    def _summary(self) -> str:
        text = f"Showing {len(self.shown)} of {len(self.rows)} entries"
        if len(self.shown) > self.max_rows:
            text += f" (the first {self.max_rows} are listed; narrow the search to see the rest)"
        order = ", ".join(f"{name} {'descending' if desc else 'ascending'}" for name, desc in self.sort)
        return f"{text}. Sorted by {order}." if order else f"{text}."

    def _set_status(self, text: str, *, error: bool = False) -> None:
        self.status.configure(text=text, foreground="#b00020" if error else "")

    def _update_headings(self) -> None:
        keys = [name for name, _ in self.sort]
        for name in self.columns:
            label = name
            if name in keys:
                arrow = "▼" if dict(self.sort)[name] else "▲"
                label = f"{name} {arrow}{keys.index(name) + 1 if len(keys) > 1 else ''}"
            self.tree.heading(name, text=label)

    def shown_seqs(self) -> list[int]:
        """The ``seq`` of each row in the table, top to bottom."""
        return [int(iid) for iid in self.tree.get_children()]

    # -- sorting -----------------------------------------------------------------------------------------------

    def sort_by(self, name: str, *, add: bool = False) -> None:
        """Sort by ``name``; again reverses it. ``add`` keeps the current keys and adds or flips this one."""
        current = dict(self.sort)
        if add:
            if name in current:
                self.sort = [(n, not d if n == name else d) for n, d in self.sort]
            else:
                self.sort.append((name, False))
        else:
            first = self.sort[0] if self.sort else None
            self.sort = [(name, not first[1] if first and first[0] == name else False)]
        self.refresh()

    def _column_at(self, x: int) -> str | None:
        column = self.tree.identify_column(x)
        index = int(column.lstrip("#") or 0) - 1
        return self.columns[index] if 0 <= index < len(self.columns) else None

    def shift_click(self, event):
        if self.tree.identify_region(event.x, event.y) != "heading":
            return None
        name = self._column_at(event.x)
        if name is not None:
            self.sort_by(name, add=True)
        return "break"

    # -- filters -----------------------------------------------------------------------------------------------

    def add_filter(self, name: str = ANY_FIELD, op: str = "contains", value: str = "") -> FilterRow:
        row = FilterRow(self, self.filter_frame, name, op, value)
        self.filters.append(row)
        self.changed()
        return row

    def remove_filter(self, row: FilterRow) -> None:
        self.filters.remove(row)
        row.frame.destroy()
        self.changed()

    def clear(self) -> None:
        """Remove every filter and empty the search box; the sort stays."""
        for row in self.filters:
            row.frame.destroy()
        self.filters.clear()
        self.search.set("")
        self.changed()

    def context_menu(self, event) -> None:
        menu = self.menu_for(self.tree.identify_row(event.y), self._column_at(event.x))
        if menu is not None:
            menu.tk_popup(event.x_root, event.y_root)

    def menu_for(self, iid: str, name: str | None):
        """The right-click menu for one cell: filter on each of its values, or copy it. None off the rows."""
        row = self.by_seq.get(iid)
        if row is None or name is None:
            return None
        menu = tk.Menu(self.root, tearoff=False)
        for value in list(dict.fromkeys(text_of(v) for v in row.values.get(name, ())))[:MAX_MENU_VALUES]:
            menu.add_command(label=f"Show only {name} = {_cell(value)[:60]}",
                             command=lambda v=value: self.add_filter(name, "equals", v))
            menu.add_command(label=f"Hide {name} = {_cell(value)[:60]}",
                             command=lambda v=value: self.add_filter(name, "not-equals", v))
        menu.add_command(label="Copy value", command=lambda: self.copy(row.text(name)))
        return menu

    def copy(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    # -- columns, details, reload -----------------------------------------------------------------------------

    def set_columns(self, names: Sequence[str]) -> None:
        """Show these fields as columns: those already shown keep their place, the others follow in the order
        ``field_names`` lists them. An empty choice keeps ``seq``."""
        chosen = set(names) or {"seq"}
        kept = [name for name in self.columns if name in chosen]
        self.columns = kept + [name for name in self.fields if name in chosen and name not in kept]
        self._set_columns()
        self.refresh()

    def reset_columns(self) -> None:
        """The columns a new window starts with, in their order."""
        self.columns = default_columns(self.fields)
        self._set_columns()
        self.refresh()

    def choose_columns(self):
        """The Columns window: pick fields from a list, then Apply (or Defaults)."""
        top = tk.Toplevel(self.root)
        top.title("Columns")
        ttk.Label(top, text="Fields shown as columns (every field can be searched and filtered either way):",
                  padding=8).pack(fill="x")
        box = tk.Listbox(top, selectmode="multiple", height=24, width=60, exportselection=False)
        box.pack(fill="both", expand=True, padx=8)
        for i, name in enumerate(self.fields):
            box.insert("end", name)
            if name in self.columns:
                box.selection_set(i)
        buttons = ttk.Frame(top, padding=8)
        buttons.pack(fill="x")

        def apply() -> None:
            self.set_columns([self.fields[i] for i in box.curselection()])
            top.destroy()
        ttk.Button(buttons, text="Apply", command=apply).pack(side="right")
        ttk.Button(buttons, text="Defaults", command=lambda: (self.reset_columns(),
                                                              top.destroy())).pack(side="right", padx=4)
        return top

    def _selected(self, _event=None) -> None:
        selection = self.tree.selection()
        row = self.by_seq.get(selection[0]) if selection else None
        self.show_details("" if row is None else details_text(row))

    def show_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def details_now(self) -> str:
        return self.details.get("1.0", "end-1c")

    def show_report(self, report: dict) -> None:
        text, bad = report_text(report)
        self.problems = list(report.get("decision_digest_problems") or [])
        self.banner.configure(text=text, foreground="#b00020" if bad else "#1b5e20")
        if self.problems:
            self.problems_button.pack(side="right")
        else:
            self.problems_button.pack_forget()

    def show_problems(self) -> None:
        self.show_details("\n".join(self.problems))

    def reload(self) -> None:
        """Open and verify the ledger again; the search, filters, sort, and columns stay."""
        try:
            rows, report = self.reload_rows()
        except ViewError as e:
            self.show_report({"error": str(e)})
            return
        self.rows = list(rows)
        self.fields = field_names(self.rows)
        for row in self.filters:
            row.name_box.configure(values=[ANY_FIELD, *self.fields])
        self.show_report(report)
        self.refresh()


def show(rows: Sequence[Row], **kwargs) -> int:
    """Open the window and wait until it is closed. 1 when there is no display to open it on."""
    try:
        root = tk.Tk()
    except tk.TclError as e:
        print(f"two-key ledger-view: cannot open a window ({e}); use --print to list the entries instead",
              file=sys.stderr)
        return 1
    root.geometry("1400x800")
    LedgerViewer(root, rows, **kwargs)
    root.mainloop()
    return 0
