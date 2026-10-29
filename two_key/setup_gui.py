# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The ``two-key setup --window`` window: the same questions as the terminal setup, on one screen.

It uses tkinter from Python's standard library, so it adds no dependency and opens no network port. It is a
choice beside the terminal interview, never a replacement: both collect the same answers and hand them to the
same ``build`` (two_key/setup_cmd.py), so the files, the refusals and the ledger entry are the same. The checks
it shows between the pages are two_key/setup_form.py's; this file only lays them out.

- **Deployment**: the new folder, the route, the **High assurance** switch, and the key's passphrase file. With
  the switch on, the settings the profile sets are shown grayed out, and each quorum number can only go up.
- **Judges**, **Quorum**, **Agent and history**, **Rules and prose**, **Proxy**: one page per group of
  questions, in the interview's order.
- **Review and set up**: every answer, every problem, warning and weaker setting, the typed ``yes`` a weaker
  setting needs, **Save answers file** (for ``two-key setup --answers`` on a machine with no screen) and
  **Set up**. When it is done, buttons open ``constitution-editor`` and ``ledger-view`` on the new folder.

It never asks for a secret: a judge's key, the agent's credential and its session are named by environment
variable, and the key's passphrase is a file path.
"""

from __future__ import annotations

import io
import json
import shlex
import subprocess  # nosec B404 - starts this Python's own two-key windows with fixed arguments
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Any

from .config_set import ConfigChangeError
from .setup_cmd import (DATA_CLASSES, FILES, JUDGE_TYPES, QUORUM_COUNTS, QUORUM_QUESTIONS, ROUTES, SetupError,
                        profile_quorum)
from .setup_form import (HIGH_ASSURANCE, HIGH_ASSURANCE_SETTINGS, clean, open_answers, quorum_minimums, review,
                         run_setup, save_answers)

REFRESH_MS = 300            # typing waits this long before the answers are checked again
GOOD, BAD = "#1b5e20", "#b00020"
READ_ONLY = "readonly"
SHOWN_ONLY = "disabled"
JUDGE_KEYS = ("id", "type", "model", "base_url", "maker", "upstream", "auth_env")
AGENT_KEYS = ("id", "model", "provider", "base_url", "upstream", "credential_env")
TOOL_COLUMNS = ("id", "irreversible", "data_class_floor", "tool_check")
ON_FAILURE = ("deny", "judge_without_history")
HA_HELP = ("High assurance: two judges from two different model makers, at least one on this machine, and a yes "
           "from a judge on this machine. Each quorum number can be raised, never lowered below the profile's.")


def _check_text(value) -> str:
    """A tool's tool check as the table and the entry show it: the fingerprint, ``exempt``, or blank (off)."""
    if isinstance(value, dict):
        return str(value.get("key", ""))
    return "" if value is None else str(value)


def _help(parent, text: str) -> None:
    ttk.Label(parent, text=text, wraplength=1000, justify="left", padding=(0, 0, 0, 6)).pack(fill="x")


def _row(parent, label: str, var: tk.Variable, row: int, *, width: int = 60, choices: tuple[str, ...] = (),
         browse=None) -> ttk.Widget:
    """A labelled box on a grid: an entry, or a read-only combobox when ``choices`` are given."""
    ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=2)
    if choices:
        box = ttk.Combobox(parent, textvariable=var, values=choices, state=READ_ONLY, width=width - 2)
    else:
        box = ttk.Entry(parent, textvariable=var, width=width)
    box.grid(row=row, column=1, sticky="we", pady=2)
    if browse is not None:
        ttk.Button(parent, text="Browse...", command=browse).grid(row=row, column=2, padx=(6, 0))
    return box


def _set_text(box: tk.Text, text: str) -> None:
    box.configure(state="normal")
    box.delete("1.0", "end")
    box.insert("1.0", text)
    box.configure(state=SHOWN_ONLY)


def _int(var: tk.Variable, default: int) -> int:
    try:
        return int(var.get())
    except (tk.TclError, ValueError):
        return default


class SetupWindow:
    """The setup window in ``root`` (a Tk or a Toplevel), filled from ``answers`` when given."""

    def __init__(self, root, answers: dict | None = None, *, folder: str = "") -> None:
        self.root = root
        self._pending: str | None = None
        self._quorum_touched = False
        self._filling = False
        self.judges: list[dict] = []
        self.tools: list[dict] = []
        self.result: dict | None = None
        self.var = {name: tk.StringVar(master=root) for name in (
            "dir", "route", "key_passphrase_file", "rules_file", "prose_file", "command", "schema_digest",
            "agent_session_env", "on_failure", "burst_denies", "burst_minutes", "typed_yes")}
        self.var["dir"].set(folder)
        self.high = tk.BooleanVar(master=root, value=False)
        self.history = tk.BooleanVar(master=root, value=True)
        self.one_proxy = tk.BooleanVar(master=root, value=True)
        self.judge_var = {k: tk.StringVar(master=root) for k in JUDGE_KEYS}
        self.agent_var = {k: tk.StringVar(master=root) for k in AGENT_KEYS}
        self.tool_var = {"id": tk.StringVar(master=root), "data_class_floor": tk.StringVar(master=root),
                         "tool_check": tk.StringVar(master=root)}
        self.tool_irreversible = tk.BooleanVar(master=root, value=True)
        self.quorum = {name: tk.IntVar(master=root, value=1) for name in QUORUM_COUNTS}
        self.status = ttk.Label(root, padding=8, anchor="w")
        self.status.pack(side="bottom", fill="x")       # first, so a small window never hides it
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(8, 0))
        self._build_deployment(self._tab("Deployment"))
        self._build_judges(self._tab("Judges"))
        self._build_quorum(self._tab("Quorum"))
        self._build_agent(self._tab("Agent and history"))
        self._build_rules(self._tab("Rules and prose"))
        self.proxy_tab = self._tab("Proxy")
        self._build_proxy(self.proxy_tab)
        self._build_review(self._tab("Review and set up"))
        self.load(answers or {})
        for v in [*self.var.values(), *self.agent_var.values(), self.history, self.one_proxy]:
            v.trace_add("write", self._changed)
        for v in self.quorum.values():
            v.trace_add("write", self._quorum_changed)
        self.high.trace_add("write", self._high_changed)
        root.bind("<Destroy>", self._closed, add="+")

    # -- layout --------------------------------------------------------------------------------------------

    def _tab(self, name: str) -> ttk.Frame:
        frame = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(frame, text=name)
        return frame

    def _build_deployment(self, tab) -> None:
        _help(tab, "Every answer can be changed later with two-key config set (docs/SETUP.md). Secrets are never "
                   "asked for: give the NAME of the environment variable that will hold each one.")
        form = ttk.Frame(tab)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        _row(form, "New folder for the files", self.var["dir"], 0, browse=self._browse_dir)
        _row(form, "Route", self.var["route"], 1, choices=ROUTES)
        _row(form, "Key passphrase file (blank: not encrypted)", self.var["key_passphrase_file"], 2,
             browse=lambda: self._browse_file("key_passphrase_file"))
        switch = ttk.Checkbutton(tab, text="High assurance", variable=self.high)
        switch.pack(anchor="w", pady=(12, 2))
        _help(tab, HA_HELP)
        # Shown, grayed out, only while the switch is on: what the profile sets and the window does not let change.
        self.ha_box = ttk.LabelFrame(tab, text="Set and locked by high assurance", padding=8)
        for name, what in HIGH_ASSURANCE_SETTINGS:
            ttk.Label(self.ha_box, text=f"{name}: {what}", state="disabled").pack(anchor="w")

    def _build_judges(self, tab) -> None:
        _help(tab, "The judges that vote on each call. Name each judge's API key by its environment variable. "
                   "Upstream is asked only when the address and model do not say who serves the judge.")
        self.judge_table = self._table(tab, JUDGE_KEYS, self._judge_clicked)
        form = ttk.Frame(tab)
        form.pack(fill="x", pady=6)
        form.columnconfigure(1, weight=1)
        for n, key in enumerate(JUDGE_KEYS):
            _row(form, key.replace("_", " "), self.judge_var[key], n, choices=JUDGE_TYPES if key == "type" else ())
        self._buttons(tab, ("Add", self.add_judge), ("Apply", self.apply_judge), ("Remove", self.remove_judge))

    def _build_quorum(self, tab) -> None:
        _help(tab, "The profile's numbers for these judges are filled in. A lower number is weaker and needs the "
                   "typed yes on the Review page; under high assurance a number can only be raised.")
        form = ttk.Frame(tab)
        form.pack(fill="x")
        self.spin = {}
        for n, name in enumerate(QUORUM_COUNTS):
            ttk.Label(form, text=f"{name}: {QUORUM_QUESTIONS[name]}").grid(row=n, column=0, sticky="w", pady=2)
            box = ttk.Spinbox(form, from_=0, to=99, textvariable=self.quorum[name], width=6)
            box.grid(row=n, column=1, sticky="w", padx=8)
            self.spin[name] = box
        self._buttons(tab, ("Use the profile's numbers", self.reset_quorum))
        self.quorum_note = ttk.Label(tab, wraplength=1000, justify="left")
        self.quorum_note.pack(fill="x", pady=6)

    def _build_agent(self, tab) -> None:
        _help(tab, "The agent Two-Key watches. Its credential is named by environment variable, never typed here.")
        form = ttk.Frame(tab)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        labels = {"credential_env": "credential (environment variable; blank: none)"}
        for n, key in enumerate(AGENT_KEYS):
            _row(form, labels.get(key, key.replace("_", " ")), self.agent_var[key], n)
        ttk.Checkbutton(tab, text="Show the judges a summary of recent decisions (off is weaker)",
                        variable=self.history).pack(anchor="w", pady=(12, 2))
        history = ttk.Frame(tab)
        history.pack(fill="x")
        history.columnconfigure(1, weight=1)
        _row(history, "If the summary cannot be built", self.var["on_failure"], 0, choices=ON_FAILURE)
        _row(history, "Attempt episode: denied calls", self.var["burst_denies"], 1, width=8)
        _row(history, "Attempt episode: within minutes", self.var["burst_minutes"], 2, width=8)

    def _build_rules(self, tab) -> None:
        form = ttk.Frame(tab)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        _row(form, "Reviewed rules file (blank: starter rules below)", self.var["rules_file"], 0,
             browse=lambda: self._browse_file("rules_file"))
        _row(form, "Prose file (blank: the starter, edit it later)", self.var["prose_file"], 1,
             browse=lambda: self._browse_file("prose_file"))
        _help(tab, "Starter rules: the tools to allow, whether a call can be undone, and each tool's lowest data "
                   "class. Ignored when a rules file is given. Behind the proxy, a tool's check (docs/TOOL_CHECK.md) "
                   "is its receipt key's fingerprint from two-key tool-key new, or exempt; high assurance needs one "
                   "or the other.")
        self.tool_table = self._table(tab, TOOL_COLUMNS, self._tool_clicked, height=6)
        form = ttk.Frame(tab)
        form.pack(fill="x", pady=6)
        form.columnconfigure(1, weight=1)
        _row(form, "tool id", self.tool_var["id"], 0)
        _row(form, "lowest data class", self.tool_var["data_class_floor"], 1, choices=DATA_CLASSES)
        _row(form, "tool check (hybrid-sha256:..., exempt, or blank: off)", self.tool_var["tool_check"], 2)
        ttk.Checkbutton(form, text="a call cannot be undone", variable=self.tool_irreversible).grid(
            row=3, column=1, sticky="w")
        self._buttons(tab, ("Add", self.add_tool), ("Remove", self.remove_tool))

    def _build_proxy(self, tab) -> None:
        _help(tab, "Only for the proxy route: the MCP server two-key mcp-proxy starts and forwards signed calls to.")
        form = ttk.Frame(tab)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        _row(form, "Command that starts the server", self.var["command"], 0)
        _row(form, "Schema digest (blank: read it from the server)", self.var["schema_digest"], 1)
        _row(form, "Agent session (environment variable)", self.var["agent_session_env"], 2)
        ttk.Checkbutton(tab, text="Only one proxy at a time serves this agent on this ledger (off is weaker)",
                        variable=self.one_proxy).pack(anchor="w", pady=8)

    def _build_review(self, tab) -> None:
        self.review_box = tk.Text(tab, height=22, wrap="word", state=SHOWN_ONLY)
        self.review_box.pack(fill="both", expand=True)
        row = ttk.Frame(tab)
        row.pack(fill="x", pady=6)
        self.yes_label = ttk.Label(row, text="Weaker than the profile: type yes to go ahead")
        self.yes_label.pack(side="left")
        ttk.Entry(row, textvariable=self.var["typed_yes"], width=8).pack(side="left", padx=6)
        self.setup_button = ttk.Button(row, text="Set up", command=self.set_up)
        self.setup_button.pack(side="right")
        ttk.Button(row, text="Save answers file...", command=self.ask_save).pack(side="right", padx=6)
        after = ttk.Frame(tab)
        after.pack(fill="x")
        self.open_editor = ttk.Button(after, text="Open the constitution editor", state="disabled",
                                      command=lambda: self._launch("constitution-editor"))
        self.open_ledger = ttk.Button(after, text="Open the ledger view", state="disabled",
                                      command=lambda: self._launch("ledger-view"))
        self.open_editor.pack(side="left")
        self.open_ledger.pack(side="left", padx=6)

    @staticmethod
    def _table(parent, columns: tuple[str, ...], clicked, *, height: int = 5) -> ttk.Treeview:
        table = ttk.Treeview(parent, columns=columns, show="headings", height=height, selectmode="browse")
        for col in columns:
            table.heading(col, text=col.replace("_", " "))
            table.column(col, width=140, stretch=True)
        table.pack(fill="x")
        table.bind("<<TreeviewSelect>>", lambda _e: clicked())
        return table

    @staticmethod
    def _buttons(parent, *buttons) -> None:
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=4)
        for text, command in buttons:
            ttk.Button(row, text=text, command=command).pack(side="left", padx=(0, 6))

    # -- answers -------------------------------------------------------------------------------------------

    def answers(self) -> dict:
        """The answers as the window shows them, in the shape ``--answers`` takes."""
        out: dict[str, Any] = {"route": self.var["route"].get() or "proxy",
                               "profile": HIGH_ASSURANCE if self.high.get() else "default",
                               "judges": [dict(j) for j in self.judges],
                               "quorum": {name: _int(var, 0) for name, var in self.quorum.items()},
                               "monitored_agent": self._agent(),
                               "judge_history": self._history()}
        for key in ("key_passphrase_file", "rules_file", "prose_file"):
            out[key] = self.var[key].get().strip()
        if not out["rules_file"]:
            out["tools"] = [dict(t) for t in self.tools]
        if out["route"] == "proxy":
            out["upstream"] = {"command": self._command(), "schema_digest": self.var["schema_digest"].get().strip()}
            out["agent_session_env"] = self.var["agent_session_env"].get().strip()
            out["one_proxy_per_agent"] = bool(self.one_proxy.get())
        return clean(out)

    def _agent(self) -> dict:
        agent = {k: v.get().strip() for k, v in self.agent_var.items() if v.get().strip()}
        env = agent.pop("credential_env", "")
        agent["credential_env" if env else "credential"] = env or "none"
        return agent

    def _history(self) -> dict:
        if not self.history.get():
            return {"enabled": False}
        return {"enabled": True, "on_failure": self.var["on_failure"].get() or "deny",
                "burst_denies": _int(self.var["burst_denies"], 5), "burst_minutes": _int(self.var["burst_minutes"], 10)}

    def _command(self) -> list[str]:
        try:
            return shlex.split(self.var["command"].get())
        except ValueError:
            return []

    def load(self, answers: dict) -> None:
        """Fill every page from ``answers`` (a file's, or none for a new deployment)."""
        self._filling = True
        try:
            self.var["route"].set(answers.get("route", "proxy"))
            self.high.set(answers.get("profile") == HIGH_ASSURANCE)
            self.judges = [dict(j) for j in answers.get("judges") or [] if isinstance(j, dict)]
            self.tools = [dict(t) for t in answers.get("tools") or [] if isinstance(t, dict)]
            for key in ("key_passphrase_file", "rules_file", "prose_file", "agent_session_env"):
                self.var[key].set(str(answers.get(key) or ""))
            self._load_agent(answers.get("monitored_agent") or {})
            self._load_history(answers.get("judge_history") or {})
            self._load_proxy(answers)
            self._quorum_touched = bool(answers.get("quorum"))
            self._fill_quorum(answers.get("quorum") or {})
            self._show_tables()
        finally:
            self._filling = False
        self.refresh()

    def _load_agent(self, agent: dict) -> None:
        for key, var in self.agent_var.items():
            var.set(str(agent.get(key) or ""))
        if agent.get("credential") == "none":
            self.agent_var["credential_env"].set("")

    def _load_history(self, history: dict) -> None:
        self.history.set(history.get("enabled", True) is not False)
        self.var["on_failure"].set(history.get("on_failure", "deny"))
        self.var["burst_denies"].set(str(history.get("burst_denies", 5)))
        self.var["burst_minutes"].set(str(history.get("burst_minutes", 10)))

    def _load_proxy(self, answers: dict) -> None:
        upstream = answers.get("upstream") if isinstance(answers.get("upstream"), dict) else {}
        command = upstream.get("command") or []
        self.var["command"].set(shlex.join(command))
        self.var["schema_digest"].set(upstream.get("schema_digest") or "")
        self.one_proxy.set(answers.get("one_proxy_per_agent", True) is not False)

    def _profile(self) -> str:
        return HIGH_ASSURANCE if self.high.get() else "default"

    def _fill_quorum(self, given: dict) -> None:
        try:
            numbers = profile_quorum(self._profile(), max(1, len(self.judges)))
        except SetupError:
            numbers = dict.fromkeys(QUORUM_COUNTS, 1)
        numbers.update({k: v for k, v in given.items() if k in numbers and isinstance(v, int)})
        lowest = quorum_minimums(self._profile(), len(self.judges))
        for name, var in self.quorum.items():
            var.set(max(numbers[name], lowest[name]))
            self.spin[name].configure(from_=lowest[name])

    # -- the pages' buttons --------------------------------------------------------------------------------

    def _judge_form(self) -> dict:
        return {k: v.get().strip() for k, v in self.judge_var.items() if v.get().strip()}

    def add_judge(self) -> None:
        self.judges.append(self._judge_form())
        self._judges_changed()

    def apply_judge(self) -> None:
        index = self._selected(self.judge_table)
        if index is not None:
            self.judges[index] = self._judge_form()
            self._judges_changed()

    def remove_judge(self) -> None:
        index = self._selected(self.judge_table)
        if index is not None:
            del self.judges[index]
            self._judges_changed()

    def _judge_clicked(self) -> None:
        index = self._selected(self.judge_table)
        if index is not None:
            for key, var in self.judge_var.items():
                var.set(str(self.judges[index].get(key) or ""))

    def add_tool(self) -> None:
        tool_id = self.tool_var["id"].get().strip()
        if not tool_id:
            return
        self.tools = [t for t in self.tools if t["id"] != tool_id]
        tool = {"id": tool_id, "irreversible": bool(self.tool_irreversible.get()),
                "data_class_floor": self.tool_var["data_class_floor"].get() or "classified"}
        check = self.tool_var["tool_check"].get().strip()
        if check:
            tool["tool_check"] = check if check == "exempt" else {"key": check}
        self.tools.append(tool)
        self._show_tables()
        self.refresh()

    def remove_tool(self) -> None:
        index = self._selected(self.tool_table)
        if index is not None:
            del self.tools[index]
            self._show_tables()
            self.refresh()

    def _tool_clicked(self) -> None:
        index = self._selected(self.tool_table)
        if index is not None:
            tool = self.tools[index]
            self.tool_var["id"].set(tool["id"])
            self.tool_var["data_class_floor"].set(tool.get("data_class_floor", "classified"))
            self.tool_irreversible.set(bool(tool.get("irreversible", True)))
            self.tool_var["tool_check"].set(_check_text(tool.get("tool_check")))

    def reset_quorum(self) -> None:
        self._quorum_touched = False
        self._filling = True
        try:
            self._fill_quorum({})
        finally:
            self._filling = False
        self.refresh()

    @staticmethod
    def _selected(table: ttk.Treeview) -> int | None:
        chosen = table.selection()
        return table.index(chosen[0]) if chosen else None

    def _show_tables(self) -> None:
        for table, rows, columns in ((self.judge_table, self.judges, JUDGE_KEYS),
                                     (self.tool_table, self.tools, TOOL_COLUMNS)):
            table.delete(*table.get_children())
            for row in rows:
                table.insert("", "end", values=[_check_text(row.get(c)) if c == "tool_check" else str(row.get(c, ""))
                                                for c in columns])

    # -- keeping the pages current -------------------------------------------------------------------------

    def _judges_changed(self) -> None:
        self._show_tables()
        if not self._quorum_touched:
            self._filling = True
            try:
                self._fill_quorum({})
            finally:
                self._filling = False
        self.refresh()

    def _high_changed(self, *_args) -> None:
        if self._filling:
            return
        self._filling = True
        try:
            self._fill_quorum({} if not self._quorum_touched else self.answers().get("quorum", {}))
        finally:
            self._filling = False
        self.refresh()

    def _quorum_changed(self, *_args) -> None:
        if not self._filling:
            self._quorum_touched = True
            self._changed()

    def _changed(self, *_args) -> None:
        if self._filling:
            return
        if self._pending is not None:
            self.root.after_cancel(self._pending)
        self._pending = self.root.after(REFRESH_MS, self.refresh)

    def _closed(self, event) -> None:
        if str(event.widget) == str(self.root) and self._pending is not None:
            self.root.after_cancel(self._pending)
            self._pending = None

    def refresh(self) -> None:
        """Check the answers again and show the result on the Review page and the status line."""
        self._pending = None
        answers = self.answers()
        found = review(answers)
        if self.high.get():
            self.ha_box.pack(fill="x")
        else:
            self.ha_box.pack_forget()
        self.notebook.tab(self.proxy_tab, state="normal" if answers.get("route") == "proxy" else "disabled")
        self.quorum_note.configure(text="\n".join([*(f"WARN  {w}" for w in found.warnings),
                                                   *(f"weaker: {w}" for w in found.weaker)]))
        self.yes_label.configure(foreground=BAD if found.weaker else "")
        _set_text(self.review_box, self._review_text(answers, found))
        ready = found.ready and bool(self.var["dir"].get().strip()) and self.result is None
        self.setup_button.configure(state="normal" if ready else "disabled")
        if self.result is not None:
            self._status_after_setup(found)
            return
        if found.ready:
            note = "Ready to set up." + (" Weaker settings need the typed yes." if found.weaker else "")
            self.status.configure(text=note, foreground=GOOD)
        else:
            self.status.configure(text=f"Not ready: {found.problems[0]}", foreground=BAD)

    def _status_after_setup(self, found) -> None:
        """The window sets up once. Answers changed after that keep the result on the status line, and say what
        is wrong with them now (run 12: it went on saying only "Set up in ..." beside a list of problems)."""
        done = f"Set up in {self.result['dir']}."
        if found.ready:
            self.status.configure(text=done, foreground=GOOD)
        else:
            self.status.configure(text=f"{done} The answers changed since, and now: {found.problems[0]}",
                                  foreground=BAD)

    @staticmethod
    def _review_text(answers: dict, found) -> str:
        parts = []
        for title, lines in (("Problems (setup refuses)", found.problems), ("Warnings", found.warnings),
                             ("Weaker than the profile", found.weaker)):
            if lines:
                parts.append(f"{title}:\n" + "\n".join(f"  - {line}" for line in lines))
        parts.append("Answers:\n" + json.dumps(answers, indent=2, sort_keys=True))
        return "\n\n".join(parts)

    # -- files and setup -----------------------------------------------------------------------------------

    def _browse_dir(self) -> None:
        chosen = filedialog.asksaveasfilename(parent=self.root, title="New folder for the deployment")
        if chosen:
            self.var["dir"].set(chosen)

    def _browse_file(self, key: str) -> None:
        chosen = filedialog.askopenfilename(parent=self.root)
        if chosen:
            self.var[key].set(chosen)

    def ask_save(self) -> None:
        chosen = filedialog.asksaveasfilename(parent=self.root, title="Save answers file",
                                              defaultextension=".json", filetypes=[("JSON", "*.json")])
        if chosen:
            self.save(chosen, overwrite=True)

    def save(self, path: str, *, overwrite: bool = False) -> bool:
        try:
            saved = save_answers(self.answers(), path, overwrite=overwrite)
        except (SetupError, OSError) as e:
            self.status.configure(text=f"Not saved: {e}", foreground=BAD)
            return False
        self.status.configure(text=f"Saved {saved}. On the server: two-key setup --dir DIR --answers {saved.name}",
                              foreground=GOOD)
        return True

    def set_up(self) -> dict | None:
        """Run setup with the answers on screen. The result, or None when it was refused (the status says why)."""
        found = review(self.answers())
        if not found.ready:
            self.status.configure(text=f"Not ready: {found.problems[0]}", foreground=BAD)
            return None
        log = io.StringIO()
        try:
            result = run_setup(self.answers(), self.var["dir"].get().strip(), typed_yes=self.var["typed_yes"].get(),
                               out=log)
        except (SetupError, ConfigChangeError, OSError) as e:
            self.status.configure(text=f"Refused: {e}", foreground=BAD)
            _set_text(self.review_box, f"Setup refused: {e}\n\n{log.getvalue()}")
            return None
        finally:
            self.var["typed_yes"].set("")
        self.result = result
        steps = "\n".join(f"  - {step}" for step in result.get("next", []))
        _set_text(self.review_box, f"{log.getvalue()}\nSet up in {result['dir']}.\n\nNext steps:\n{steps}")
        self.status.configure(text=f"Set up in {result['dir']}.", foreground=GOOD)
        self.setup_button.configure(state="disabled")
        self.open_editor.configure(state="normal")
        self.open_ledger.configure(state="normal")
        return result

    def launch_arguments(self, command: str) -> list[str]:
        """The command line that opens another two-key window on the new folder."""
        folder = Path(self.result["dir"]) if self.result else Path(self.var["dir"].get())
        if command == "constitution-editor":
            return [sys.executable, "-m", "two_key", command, "--signed", str(folder / FILES["constitution"]),
                    "--key", str(folder / FILES["key"])]
        return [sys.executable, "-m", "two_key", command, "--key", str(folder / FILES["key"]),
                "--ledger", str(folder / FILES["ledger"])]

    def _launch(self, command: str) -> None:
        subprocess.Popen(self.launch_arguments(command))  # nosec B603 - this Python, two-key's own command


def show(answers: dict | None = None, *, folder: str = "") -> int:
    """Open the window and wait until it is closed. 1 when there is no display to open it on."""
    try:
        root = tk.Tk()
    except tk.TclError as e:
        print(f"two-key setup: cannot open a window ({e}); answer on the terminal, or give --answers FILE",
              file=sys.stderr)
        return 1
    root.title("two-key setup")
    root.geometry("1100x820")
    SetupWindow(root, answers, folder=folder)
    root.mainloop()
    return 0


def load_for_window(path: str | None) -> dict:
    """The answers file to start from, or none."""
    return open_answers(path) if path else {}


__all__ = ["SetupWindow", "load_for_window", "show"]
