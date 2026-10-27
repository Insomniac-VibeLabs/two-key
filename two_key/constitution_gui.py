# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The ``two-key constitution-editor`` window: write, check, try, and sign a constitution.

It uses tkinter from Python's standard library, so it adds no dependency and opens no network port. The checks,
the trial call, and the signing are two_key/constitution_editor.py's; this file only lays them out.

- **Judges' text**: the prose every judge reads in full.
- **Tools**: the allow list and each tool's spec (irreversible, lowest data class, argument mappings).
- **Rules**: Path A's hard rules, in order, each with an id, a type, and a body.
- **Custom fields**: the field registry the rules and specs can name.
- **Try a call**: one call through the draft, with what Path A decides and the prompt a judge is sent.
- **Review and sign**: the serial, the envelope format, every check and note, the rules file as it will be
  written, and Sign and save, which needs the principal key.

The status line under the tabs always says whether the draft signs, and if not, why not.
"""

from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Any, Callable

from .action import DEFAULT_DATA_CLASS
from .constitution import ENVELOPE_FORMATS
from .constitution_editor import (CLAIMS, DATA_CLASSES, FIELDS_EXAMPLE, FILE_NAMES, RULE_TEMPLATES, WARNING, Draft,
                                  EditorError, build_rule, build_spec, check, dump_value, move_rule, new_draft,
                                  open_signed, open_sources, parse_value, remove_tool, rule_summary, rule_type,
                                  rules_text, save_sources, set_tool, sign_and_save, spec_form, tool_names,
                                  try_call)
from .policy_vm import RULE_TYPES

REFRESH_MS = 300            # typing waits this long before the draft is checked again
GOOD, BAD = "#1b5e20", "#b00020"
READ_ONLY = "readonly"       # a combobox that offers only its list
SHOWN_ONLY = "disabled"      # a text box the window writes and the user only reads
APPLY = "Apply"
PROSE_HELP = ("What every judge reads, in full, before each call it votes on. It is signed with the rules: "
              "write what the principal wants and does not want, in plain words.")
TOOLS_HELP = ("Only the tools listed here can be called. Each needs a spec: whether a call can be undone, its "
              "lowest data class, and which argument paths Path A reads (amount, counterparties, payload, fields).")
RULES_HELP = ("Path A runs these in order and reports the first that denies. The allow list (allow_only_tools) "
              "comes from the Tools tab; edit the others here.")
FIELDS_HELP = ("Custom fields Path A derives from a call's arguments (type, default, values). Tools map them in "
               "their spec; deny_if_fields rules test them.")
TRY_HELP = ("Runs one call through this draft on a throwaway key and a temporary ledger, with a stand-in judge "
            "that votes yes. Nothing real is touched.")


def _text(parent, height: int, **kw) -> tk.Text:
    kw.setdefault("wrap", "word")
    return tk.Text(parent, height=height, undo=True, **kw)


def _set_text(box: tk.Text, text: str, *, read_only: bool = False) -> None:
    box.configure(state="normal")
    box.delete("1.0", "end")
    box.insert("1.0", text)
    if read_only:
        box.configure(state=SHOWN_ONLY)


def _get_text(box: tk.Text) -> str:
    return box.get("1.0", "end-1c")


def _help(parent, text: str) -> None:
    ttk.Label(parent, text=text, wraplength=1000, justify="left", padding=(0, 0, 0, 6)).pack(fill="x")


class ConstitutionEditor:
    """The editor in ``root`` (a Tk or a Toplevel). ``draft`` is the constitution to start from."""

    def __init__(self, root, draft: Draft | None = None, *, title: str = "new constitution", key_path: str = "",
                 folder: str = "", opened: str = "") -> None:
        self.root = root
        self.draft = draft if draft is not None else new_draft()
        self._pending: str | None = None
        self.tool_selected: str | None = None
        self.rule_selected: int | None = None
        # The Review and sign tab's boxes, read when it signs. The passphrase box is emptied after each try.
        self.key_path, self.folder = tk.StringVar(master=root), tk.StringVar(master=root)
        self.passphrase, self.passphrase_file = tk.StringVar(master=root), tk.StringVar(master=root)
        self.names = {role: tk.StringVar(master=root, value=name) for role, name in FILE_NAMES.items()}
        self.overwrite = tk.BooleanVar(master=root, value=False)
        self._menu(root)
        self.status = ttk.Label(root, padding=8, anchor="w")
        self.status.pack(side="bottom", fill="x")       # first, so a small window never hides it
        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=8, pady=(8, 0))
        self.notebook = notebook
        self._build_prose(self._tab("Judges' text"))
        self._build_tools(self._tab("Tools"))
        self._build_rules(self._tab("Rules"))
        self._build_fields(self._tab("Custom fields"))
        self._build_try(self._tab("Try a call"))
        self._build_sign(self._tab("Review and sign"), key_path, folder)
        self.load(self.draft, title, opened)
        root.bind("<Destroy>", self._closed, add="+")

    def _closed(self, event) -> None:
        """Drop a pending check when the window goes, so it never runs on destroyed widgets."""
        if str(event.widget) == str(self.root) and self._pending is not None:
            self.root.after_cancel(self._pending)
            self._pending = None

    def _tab(self, name: str) -> ttk.Frame:
        frame = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(frame, text=name)
        return frame

    def _menu(self, root) -> None:
        bar = tk.Menu(root)
        files = tk.Menu(bar, tearoff=False)
        files.add_command(label="New", command=lambda: self.load(new_draft(), "new constitution"))
        files.add_command(label="Open prose and rules…", command=self.ask_open_sources)
        files.add_command(label="Open a signed constitution…", command=self.ask_open_signed)
        files.add_separator()
        files.add_command(label="Close", command=root.destroy)
        bar.add_cascade(label="File", menu=files)
        root.configure(menu=bar)

    # -- loading and the status line ------------------------------------------------------------------------

    def load(self, draft: Draft, title: str, opened: str = "") -> None:
        """Show ``draft`` in every tab. ``opened`` is a line about where it came from."""
        self.draft = draft
        self.root.title(f"Two-Key constitution: {title}")
        _set_text(self.prose, draft.prose)
        self.prose.edit_modified(False)
        _set_text(self.fields_box, dump_value(draft.fields))
        self.serial_var.set("" if draft.serial is None else str(draft.serial))
        self.format_var.set(draft.envelope_format)
        self.tool_selected, self.rule_selected = None, None
        self.refresh_tools()
        self.refresh_rules()
        self.try_tool.configure(values=tool_names(draft))
        self.edit_tool(None)
        self.edit_rule(None)
        self.say(self.sign_note, opened)
        self.recheck()

    @staticmethod
    def say(label: ttk.Label, text: str, bad: bool = False) -> None:
        label.configure(text=text, foreground=BAD if bad else GOOD)

    def changed(self, *_args) -> None:
        """Check the draft again a moment after typing stops."""
        if self._pending is not None:
            self.root.after_cancel(self._pending)
        self._pending = self.root.after(REFRESH_MS, self._due)

    @property
    def check_waiting(self) -> bool:
        """Whether a check is waiting for typing to stop."""
        return self._pending is not None

    def _due(self) -> None:
        self._pending = None
        self.recheck()

    def recheck(self) -> None:
        """Read the prose, serial, and format into the draft, check it, and show the result."""
        if self._pending is not None:       # called directly while a check was waiting: that one is not needed
            self.root.after_cancel(self._pending)
            self._pending = None
        self.draft.prose = _get_text(self.prose)
        self._read_serial()
        self.draft.envelope_format = self.format_var.get()
        report = check(self.draft)
        if report.ok:
            warnings = sum(1 for level, _ in report.notes if level == WARNING)
            extra = f" {warnings} warning(s) on Review and sign." if warnings else ""
            self.say(self.status, f"Ready to sign: {report.envelope_format}, digest {report.digest}.{extra}")
        else:
            self.say(self.status, f"Does not sign yet: {report.error}", bad=True)
        self.show_review(report)

    def _read_serial(self) -> None:
        text = self.serial_var.get().strip()
        if not text:
            self.draft.serial = None
            return
        try:
            self.draft.serial = int(text)
        except ValueError:
            self.draft.serial = text        # check() refuses it and says why

    def status_text(self) -> str:
        return str(self.status.cget("text"))

    # -- judges' text ----------------------------------------------------------------------------------------

    def _build_prose(self, tab) -> None:
        _help(tab, PROSE_HELP)
        self.prose = _text(tab, 16)
        self.prose.pack(fill="both", expand=True)
        self.prose.bind("<<Modified>>", self._prose_modified)
        row = ttk.Frame(tab, padding=(0, 6, 0, 0))
        row.pack(fill="x")
        ttk.Button(row, text="Use the starter text", command=self.use_starter).pack(side="left")

    def _prose_modified(self, _event=None) -> None:
        if self.prose.edit_modified():
            self.prose.edit_modified(False)
            self.changed()

    def use_starter(self) -> None:
        _set_text(self.prose, new_draft().prose)
        self.recheck()

    # -- tools ------------------------------------------------------------------------------------------------

    def _build_tools(self, tab) -> None:
        _help(tab, TOOLS_HELP)
        self.tools = ttk.Treeview(tab, columns=("tool", "irreversible", "floor", "maps"), show="headings",
                                  height=8, selectmode="browse")
        for name, text, width in (("tool", "Tool", 220), ("irreversible", "Irreversible", 100),
                                  ("floor", "Lowest data class", 140), ("maps", "Argument mappings", 520)):
            self.tools.heading(name, text=text)
            self.tools.column(name, width=width, stretch=name == "maps")
        self.tools.pack(fill="x")
        self.tools.bind("<<TreeviewSelect>>", lambda _e: self._tool_clicked())
        form = ttk.Frame(tab, padding=(0, 8, 0, 0))
        form.pack(fill="both", expand=True)
        self.tool_id = tk.StringVar()
        self.irreversible = tk.BooleanVar(value=True)
        self.floor = tk.StringVar(value=DEFAULT_DATA_CLASS)
        self.deny_unmapped = tk.BooleanVar(value=False)
        line = ttk.Frame(form)
        line.pack(fill="x")
        ttk.Label(line, text="Tool id").pack(side="left")
        ttk.Entry(line, textvariable=self.tool_id, width=32).pack(side="left", padx=(4, 12))
        ttk.Checkbutton(line, text="A call cannot be undone", variable=self.irreversible).pack(side="left")
        ttk.Label(line, text="Lowest data class").pack(side="left", padx=(12, 4))
        ttk.Combobox(line, textvariable=self.floor, values=DATA_CLASSES, state=READ_ONLY, width=12).pack(side="left")
        ttk.Checkbutton(line, text="Deny an argument no path names", variable=self.deny_unmapped).pack(
            side="left", padx=12)
        ttk.Label(form, text="Argument mappings (YAML: amount, counterparties, payload, fields)",
                  padding=(0, 6, 0, 2)).pack(fill="x")
        self.mappings = _text(form, 6)
        self.mappings.pack(fill="both", expand=True)
        buttons = ttk.Frame(form, padding=(0, 6, 0, 0))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="New tool", command=lambda: self.edit_tool(None)).pack(side="left")
        ttk.Button(buttons, text=APPLY, command=self.apply_tool).pack(side="left", padx=4)
        ttk.Button(buttons, text="Remove", command=self.remove_selected_tool).pack(side="left")
        self.tool_note = ttk.Label(buttons, padding=(12, 0))
        self.tool_note.pack(side="left", fill="x")

    def _selected_tool(self) -> str | None:
        chosen = self.tools.selection()
        return chosen[0] if chosen else None

    def _tool_clicked(self) -> None:
        # refresh_tools selects the row being edited again; that is no new choice, and keeps its note.
        if self._selected_tool() != self.tool_selected:
            self.edit_tool(self._selected_tool())

    def refresh_tools(self) -> None:
        self.tools.delete(*self.tools.get_children())
        for name in tool_names(self.draft):
            spec = self.draft.tool_specs.get(name)
            if not isinstance(spec, dict):
                self.tools.insert("", "end", iid=name, values=(name, "", "", "no spec yet"))
                continue
            known, rest = spec_form(spec)
            floor = known.get("data_class_floor", DEFAULT_DATA_CLASS)
            irreversible = "yes" if known.get("irreversible", True) else "no"
            self.tools.insert("", "end", iid=name, values=(name, irreversible, floor, ", ".join(rest) or "none"))
        if self.tool_selected in self.tools.get_children():
            self.tools.selection_set(self.tool_selected)

    def edit_tool(self, name: str | None) -> None:
        """Fill the form with a tool's spec, or clear it for a new tool."""
        self.tool_selected = name
        spec = self.draft.tool_specs.get(name) if name else None
        known, rest = spec_form(spec if isinstance(spec, dict) else {})
        self.tool_id.set(name or "")
        self.irreversible.set(bool(known.get("irreversible", True)))
        self.floor.set(known.get("data_class_floor", DEFAULT_DATA_CLASS))
        self.deny_unmapped.set(bool(known.get("deny_unmapped", False)))
        _set_text(self.mappings, dump_value(rest))
        if name is None:            # a new tool: no row stays selected, so a click on any row edits it
            self.tools.selection_remove(*self.tools.selection())
        self.say(self.tool_note, "")

    def apply_tool(self) -> None:
        """Add the tool in the form, or change the selected one."""
        try:
            mappings = parse_value(_get_text(self.mappings), "argument mappings")
            if not isinstance(mappings, dict):
                raise EditorError("argument mappings: expected a mapping (amount:, counterparties:, ...)")
            spec = build_spec(self.irreversible.get(), self.floor.get(), self.deny_unmapped.get(), mappings)
            set_tool(self.draft, self.tool_id.get(), spec, self.tool_selected)
        except EditorError as e:
            self.say(self.tool_note, str(e), bad=True)
            return
        self.tool_selected = self.tool_id.get().strip()
        self.after_edit()
        self.say(self.tool_note, f"{self.tool_selected} applied")

    def remove_selected_tool(self) -> None:
        if self.tool_selected:
            remove_tool(self.draft, self.tool_selected)
        self.after_edit()
        self.edit_tool(None)

    def after_edit(self) -> None:
        self.refresh_tools()
        self.refresh_rules()
        self.try_tool.configure(values=tool_names(self.draft))
        self.recheck()

    # -- rules ------------------------------------------------------------------------------------------------

    def _build_rules(self, tab) -> None:
        _help(tab, RULES_HELP)
        self.rules = ttk.Treeview(tab, columns=("n", "id", "type", "body"), show="headings", height=8,
                                  selectmode="browse")
        for name, text, width in (("n", "#", 40), ("id", "Id", 180), ("type", "Type", 200), ("body", "Rule", 560)):
            self.rules.heading(name, text=text)
            self.rules.column(name, width=width, stretch=name == "body")
        self.rules.pack(fill="x")
        self.rules.bind("<<TreeviewSelect>>", lambda _e: self._rule_clicked())
        form = ttk.Frame(tab, padding=(0, 8, 0, 0))
        form.pack(fill="both", expand=True)
        self.rule_id, self.rule_kind = tk.StringVar(), tk.StringVar(value="deny_if")
        line = ttk.Frame(form)
        line.pack(fill="x")
        ttk.Label(line, text="Id").pack(side="left")
        ttk.Entry(line, textvariable=self.rule_id, width=28).pack(side="left", padx=(4, 12))
        ttk.Label(line, text="Type").pack(side="left")
        ttk.Combobox(line, textvariable=self.rule_kind, values=RULE_TYPES, state=READ_ONLY, width=28).pack(
            side="left", padx=4)
        ttk.Button(line, text="Template", command=self.rule_template).pack(side="left")
        ttk.Label(form, text="Rule (YAML)", padding=(0, 6, 0, 2)).pack(fill="x")
        self.rule_body = _text(form, 8)
        self.rule_body.pack(fill="both", expand=True)
        buttons = ttk.Frame(form, padding=(0, 6, 0, 0))
        buttons.pack(fill="x")
        for text, command in (("New rule", lambda: self.edit_rule(None)), (APPLY, self.apply_rule),
                              ("Remove", self.remove_rule), ("Up", lambda: self.move(-1)),
                              ("Down", lambda: self.move(1))):
            ttk.Button(buttons, text=text, command=command).pack(side="left", padx=(0, 4))
        self.rule_note = ttk.Label(buttons, padding=(12, 0))
        self.rule_note.pack(side="left", fill="x")

    def _selected_rule(self) -> int | None:
        chosen = self.rules.selection()
        return int(chosen[0]) if chosen else None

    def _rule_clicked(self) -> None:
        if self._selected_rule() != self.rule_selected:
            self.edit_rule(self._selected_rule())

    def refresh_rules(self) -> None:
        self.rules.delete(*self.rules.get_children())
        for i, rule in enumerate(self.draft.rules):
            rule_id = rule.get("id", "") if isinstance(rule, dict) else ""
            self.rules.insert("", "end", iid=str(i), values=(i + 1, rule_id, rule_type(rule), rule_summary(rule)))
        if self.rule_selected is not None and str(self.rule_selected) in self.rules.get_children():
            self.rules.selection_set(str(self.rule_selected))

    def edit_rule(self, index: int | None) -> None:
        """Fill the form with a rule, or clear it for a new one."""
        self.rule_selected = index
        rule = self.draft.rules[index] if index is not None else None
        if isinstance(rule, dict) and rule_type(rule) != "?":
            self.rule_id.set(str(rule.get("id", "")))
            self.rule_kind.set(rule_type(rule))
            _set_text(self.rule_body, dump_value(rule[rule_type(rule)]))
        else:
            self.rule_id.set("")
            self.rule_kind.set("deny_if")
            _set_text(self.rule_body, "")
        if index is None:
            self.rules.selection_remove(*self.rules.selection())
        self.say(self.rule_note, "")

    def rule_template(self) -> None:
        _set_text(self.rule_body, dump_value(RULE_TEMPLATES[self.rule_kind.get()]))

    def apply_rule(self) -> None:
        """Add the rule in the form at the end, or change the selected one."""
        try:
            rule = build_rule(self.rule_id.get(), self.rule_kind.get(),
                              parse_value(_get_text(self.rule_body), "rule"))
        except EditorError as e:
            self.say(self.rule_note, str(e), bad=True)
            return
        if self.rule_selected is None:
            self.draft.rules.append(rule)
            self.rule_selected = len(self.draft.rules) - 1
        else:
            self.draft.rules[self.rule_selected] = rule
        self.after_edit()
        self.say(self.rule_note, f"rule {self.rule_selected + 1} applied")

    def remove_rule(self) -> None:
        if self.rule_selected is not None:
            del self.draft.rules[self.rule_selected]
        self.after_edit()
        self.edit_rule(None)

    def move(self, step: int) -> None:
        if self.rule_selected is None:
            return
        self.rule_selected = move_rule(self.draft, self.rule_selected, step)
        self.after_edit()

    # -- custom fields ----------------------------------------------------------------------------------------

    def _build_fields(self, tab) -> None:
        _help(tab, FIELDS_HELP)
        self.fields_box = _text(tab, 16)
        self.fields_box.pack(fill="both", expand=True)
        buttons = ttk.Frame(tab, padding=(0, 6, 0, 0))
        buttons.pack(fill="x")
        ttk.Button(buttons, text=APPLY, command=self.apply_fields).pack(side="left")
        ttk.Button(buttons, text="Insert an example", command=self.fields_example).pack(side="left", padx=4)
        self.fields_note = ttk.Label(buttons, padding=(12, 0))
        self.fields_note.pack(side="left", fill="x")

    def fields_example(self) -> None:
        current = _get_text(self.fields_box).rstrip()
        _set_text(self.fields_box, (current + "\n" if current else "") + dump_value(FIELDS_EXAMPLE))

    def apply_fields(self) -> None:
        try:
            fields = parse_value(_get_text(self.fields_box), "custom fields")
            if not isinstance(fields, dict):
                raise EditorError("custom fields: expected a mapping of field names")
        except EditorError as e:
            self.say(self.fields_note, str(e), bad=True)
            return
        self.draft.fields = fields
        self.after_edit()
        self.say(self.fields_note, f"{len(fields)} field(s) applied")

    # -- try a call -------------------------------------------------------------------------------------------

    def _build_try(self, tab) -> None:
        _help(tab, TRY_HELP)
        self.try_tool_var, self.claim = tk.StringVar(), tk.StringVar(value="none")
        self.proposal = tk.StringVar()
        line = ttk.Frame(tab)
        line.pack(fill="x")
        ttk.Label(line, text="Tool").pack(side="left")
        self.try_tool = ttk.Combobox(line, textvariable=self.try_tool_var, width=28)
        self.try_tool.pack(side="left", padx=(4, 12))
        ttk.Label(line, text="Claimed data class").pack(side="left")
        ttk.Combobox(line, textvariable=self.claim, values=CLAIMS, state=READ_ONLY, width=18).pack(side="left",
                                                                                                    padx=4)
        ttk.Label(line, text="Proposal (sent only to a judge set to receive it)").pack(side="left", padx=(12, 4))
        ttk.Entry(line, textvariable=self.proposal, width=40).pack(side="left", fill="x", expand=True)
        boxes = ttk.Frame(tab, padding=(0, 6, 0, 0))
        boxes.pack(fill="x")
        ttk.Label(boxes, text="Arguments (JSON or YAML)").grid(row=0, column=0, sticky="w")
        ttk.Label(boxes, text="Caller facts, for source: caller fields (optional)").grid(row=0, column=1, sticky="w")
        self.arguments, self.facts = _text(boxes, 6), _text(boxes, 6)
        self.arguments.grid(row=1, column=0, sticky="nsew", padx=(0, 4))
        self.facts.grid(row=1, column=1, sticky="nsew")
        boxes.columnconfigure(0, weight=1)
        boxes.columnconfigure(1, weight=1)
        ttk.Button(tab, text="Run", command=self.run_trial).pack(anchor="w", pady=6)
        self.trial = _text(tab, 12, state=SHOWN_ONLY)
        self.trial.pack(fill="both", expand=True)

    def run_trial(self) -> None:
        """Run the call in the form through the draft and show the result."""
        self.recheck()
        try:
            arguments = parse_value(_get_text(self.arguments), "arguments")
            facts = parse_value(_get_text(self.facts), "caller facts") or None
            result = try_call(self.draft, self.try_tool_var.get().strip(), arguments, claim=self.claim.get(),
                              proposal=self.proposal.get(), facts=facts).text()
        except EditorError as e:
            result = str(e)
        _set_text(self.trial, result, read_only=True)

    def trial_text(self) -> str:
        return _get_text(self.trial)

    # -- review and sign --------------------------------------------------------------------------------------

    def _build_sign(self, tab, key_path: str, folder: str) -> None:
        self.serial_var, self.format_var = tk.StringVar(), tk.StringVar(value="auto")
        line = ttk.Frame(tab)
        line.pack(fill="x")
        ttk.Label(line, text="Serial (each new version gets a higher one; blank: none)").pack(side="left")
        ttk.Entry(line, textvariable=self.serial_var, width=10).pack(side="left", padx=(4, 12))
        ttk.Label(line, text="Envelope format").pack(side="left")
        ttk.Combobox(line, textvariable=self.format_var, values=ENVELOPE_FORMATS, state=READ_ONLY,
                     width=6).pack(side="left", padx=4)
        for var in (self.serial_var, self.format_var):
            var.trace_add("write", self.changed)
        keys = ttk.Frame(tab)
        keys.pack(side="bottom", fill="x")      # before the panes, so they give up room first
        self._build_key_rows(keys, key_path, folder)
        # Under the buttons, and a child of the tab, so the notebook never draws over it.
        self.sign_note = ttk.Label(keys, padding=(0, 6), wraplength=1000, justify="left")
        self.sign_note.pack(fill="x")
        panes = ttk.Panedwindow(tab, orient="horizontal")
        panes.pack(fill="both", expand=True, pady=6)
        self.review = _text(panes, 10, state=SHOWN_ONLY)
        self.preview = _text(panes, 10, state=SHOWN_ONLY, wrap="none")
        panes.add(self.review, weight=1)
        panes.add(self.preview, weight=1)

    @staticmethod
    def _row(parent, label: str, var: tk.StringVar, browse: Callable[[], Any] | None = None, **entry) -> None:
        line = ttk.Frame(parent)
        line.pack(fill="x", pady=1)
        ttk.Label(line, text=label, width=30).pack(side="left")
        ttk.Entry(line, textvariable=var, **entry).pack(side="left", fill="x", expand=True)
        if browse is not None:
            ttk.Button(line, text="Browse…", command=browse).pack(side="left", padx=4)

    def _build_key_rows(self, tab, key_path: str, folder: str) -> None:
        self.key_path.set(key_path)
        self.folder.set(folder)
        self._row(tab, "Principal key (principal.pem)", self.key_path, self.ask_key)
        self._row(tab, "Key passphrase (if encrypted)", self.passphrase, show="•")
        self._row(tab, "…or a passphrase file", self.passphrase_file)
        self._row(tab, "Folder to write into", self.folder, self.ask_folder)
        names = ttk.Frame(tab)
        names.pack(fill="x", pady=1)
        ttk.Label(names, text="File names", width=30).pack(side="left")
        for role in FILE_NAMES:
            ttk.Entry(names, textvariable=self.names[role], width=26).pack(side="left", padx=(0, 4))
        buttons = ttk.Frame(tab, padding=(0, 6, 0, 0))
        buttons.pack(fill="x")
        ttk.Checkbutton(buttons, text="Replace files that are there", variable=self.overwrite).pack(side="left")
        ttk.Button(buttons, text="Sign and save", command=self.sign).pack(side="left", padx=8)
        ttk.Button(buttons, text="Save prose and rules only (unsigned)", command=self.save_unsigned).pack(side="left")

    def show_review(self, report) -> None:
        if report.ok:
            lines = [f"Signs as {report.envelope_format}.", f"Digest: {report.digest}",
                     f"Tools: {len(report.body['tool_specs'])}, rules: {len(report.body['hard_rules'])}, "
                     f"custom fields: {len(report.body.get('fields') or {})}, serial: "
                     f"{report.body.get('serial', 'none')}", ""]
            lines += [f"{level}: {text}" for level, text in report.notes] or ["No warnings or notes."]
        else:
            lines = [f"Does not sign yet: {report.error}"]
        _set_text(self.review, "\n".join(lines), read_only=True)
        try:
            preview = rules_text(self.draft, self.names["rules"].get().lower().endswith(".json"))
        except ImportError:
            preview = "(a YAML rules file needs the yaml extra; name the rules file .json to write JSON)"
        _set_text(self.preview, preview, read_only=True)

    def review_text(self) -> str:
        return _get_text(self.review)

    def _key(self):
        from .keys import load_private_key_file, read_passphrase_file
        typed, file = self.passphrase.get(), self.passphrase_file.get().strip()
        source = typed.encode("utf-8") if typed else (lambda _p: read_passphrase_file(file)) if file else None
        try:
            return load_private_key_file(self.key_path.get().strip(), source)
        except (OSError, ValueError) as e:
            raise EditorError(f"principal key: {e}") from None

    def _names(self) -> dict[str, str]:
        return {role: var.get().strip() for role, var in self.names.items()}

    def sign(self) -> None:
        """Sign the draft with the principal key and write the three files."""
        self.recheck()
        try:
            saved = sign_and_save(self.draft, self._key(), self.folder.get().strip(), self._names(),
                                  overwrite=self.overwrite.get())
        except EditorError as e:
            self.say(self.sign_note, str(e), bad=True)
            return
        finally:
            self.passphrase.set("")
        self.say(self.sign_note, f"Signed ({saved.envelope_format}, digest {saved.digest}, key {saved.fingerprint}). "
                                 f"Wrote {saved.signed}, {saved.rules}, and {saved.prose}.")

    def save_unsigned(self) -> None:
        self.recheck()
        try:
            written = save_sources(self.draft, self.folder.get().strip(), self._names(),
                                   overwrite=self.overwrite.get())
        except (EditorError, OSError) as e:
            self.say(self.sign_note, str(e), bad=True)
            return
        self.say(self.sign_note, f"Wrote {' and '.join(written)}, not signed.")

    def sign_text(self) -> str:
        return str(self.sign_note.cget("text"))

    # -- file dialogs -----------------------------------------------------------------------------------------

    def ask_key(self) -> None:
        path = filedialog.askopenfilename(parent=self.root, title="Principal key")
        if path:
            self.key_path.set(path)

    def ask_folder(self) -> None:
        path = filedialog.askdirectory(parent=self.root, title="Folder to write into")
        if path:
            self.folder.set(path)

    def ask_open_sources(self) -> None:
        prose = filedialog.askopenfilename(parent=self.root, title="Prose (constitution.md)")
        rules = prose and filedialog.askopenfilename(parent=self.root, title="Rules (hard_rules.yaml)")
        if prose and rules:
            self.open_sources(prose, rules)

    def ask_open_signed(self) -> None:
        path = filedialog.askopenfilename(parent=self.root, title="Signed constitution")
        if path:
            public = filedialog.askopenfilename(parent=self.root, title="Its public key, to check the signature "
                                                                       "(Cancel: do not check)")
            self.open_signed(path, public or None)

    def open_sources(self, prose: str, rules: str) -> None:
        try:
            draft = open_sources(prose, rules)
        except EditorError as e:
            self.say(self.status, f"Not opened: {e}", bad=True)
            return
        self.folder.set(str(Path(rules).parent))
        self.load(draft, rules, f"Opened {prose} and {rules}.")

    def open_signed(self, path: str, public_path: str | None = None) -> None:
        from .keys import load_public_key
        try:
            public = load_public_key(public_path) if public_path else None
            draft, said = open_signed(path, public)
        except (EditorError, OSError, ValueError) as e:
            self.say(self.status, f"Not opened: {e}", bad=True)
            return
        self.folder.set(str(Path(path).parent))
        self.load(draft, path, f"Opened {path}: {said}.")


def show(draft: Draft | None = None, **kwargs) -> int:
    """Open the window and wait until it is closed. 1 when there is no display to open it on."""
    try:
        root = tk.Tk()
    except tk.TclError as e:
        print(f"two-key constitution-editor: cannot open a window ({e}); use --check, or two-key sign-constitution",
              file=sys.stderr)
        return 1
    root.geometry("1200x860")
    ConstitutionEditor(root, draft, **kwargs)
    root.mainloop()
    return 0
