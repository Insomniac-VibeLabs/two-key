# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The ``two-key constitution-editor`` window (two_key/constitution_gui.py), driven the way a person uses it.

Each test builds the window on a real Tk display, fills its forms through the same variables and methods the
controls use, and reads the tables, status line, and files back. Skipped where Python has no tkinter or no
display can be opened (as for tests/test_ledger_gui.py: a child process opens and closes a window first).
"""

import functools
import json
import subprocess  # nosec B404 - runs this Python with a fixed script
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import tkinter as tk

    from two_key import constitution_gui
    from two_key.constitution_gui import ConstitutionEditor, _set_text, show
except ImportError:                 # this Python was built without tkinter
    tk = None

from two_key.constitution import load_envelope, sign_constitution, verify_signed
from two_key.constitution_editor import new_draft
from two_key.keys import encrypt_private_key, generate_private_key, save_private_key, save_public_key

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
PROBE = """
import tkinter as tk
from two_key.constitution_gui import ConstitutionEditor
root = tk.Tk()
root.withdraw()
top = tk.Toplevel(root)
ConstitutionEditor(top)
top.update()
top.destroy()
root.destroy()
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
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.key = generate_private_key()
        save_private_key(self.dir / "principal.pem", self.key)
        save_public_key(self.dir / "principal.pub.pem", self.key.public_key())
        (self.dir / "out").mkdir()

    def editor(self, **kwargs):
        kwargs.setdefault("key_path", str(self.dir / "principal.pem"))
        kwargs.setdefault("folder", str(self.dir / "out"))
        editor = ConstitutionEditor(self.top, **kwargs)
        self.top.update_idletasks()
        return editor

    @staticmethod
    def add_tools(editor):
        editor.tool_id.set("search")
        editor.irreversible.set(False)
        editor.floor.set("public")
        editor.apply_tool()
        editor.edit_tool(None)
        editor.tool_id.set("pay_vendor")
        editor.floor.set("financial")
        _set_text(editor.mappings, "amount:\n  json_path: amount\n  unit: usd\n")
        editor.apply_tool()
        editor.edit_rule(None)
        editor.rule_id.set("spend-cap")
        editor.rule_kind.set("deny_if")
        _set_text(editor.rule_body, "amount_usd_gt: 200\n")
        editor.apply_rule()

    def test_a_new_constitution_says_why_it_does_not_sign(self):
        editor = self.editor()
        self.assertEqual(self.top.title(), "Two-Key constitution: new constitution")
        self.assertIn("Does not sign yet", editor.status_text())
        self.assertIn("allow_only_tools", editor.review_text())
        self.assertEqual(len(editor.notebook.tabs()), 6)

    def test_tools_and_rules_make_it_sign(self):
        editor = self.editor()
        self.add_tools(editor)
        self.assertIn("Ready to sign: two-key-constitution-v3", editor.status_text())
        self.assertEqual(list(editor.tools.get_children()), ["search", "pay_vendor"])
        self.assertEqual(editor.tools.set("pay_vendor", "maps"), "amount")
        self.assertEqual(editor.tools.set("search", "irreversible"), "no")
        self.assertEqual([editor.rules.set(i, "type") for i in editor.rules.get_children()],
                         ["allow_only_tools", "deny_if"])
        self.assertIn("serial: 1", editor.review_text())
        self.assertIn("spend-cap", _get(editor.preview))
        self.assertEqual(list(editor.try_tool.cget("values")), ["search", "pay_vendor"])

    def test_bad_input_is_reported_where_it_was_typed(self):
        editor = self.editor()
        _set_text(editor.mappings, "a: 1\na: 2\n")
        editor.tool_id.set("x")
        editor.apply_tool()
        self.assertIn("argument mappings", editor.tool_note.cget("text"))
        _set_text(editor.mappings, "- a list\n")
        editor.apply_tool()
        self.assertIn("expected a mapping", editor.tool_note.cget("text"))
        _set_text(editor.mappings, "irreversible: false\n")
        editor.apply_tool()
        self.assertIn("controls above", editor.tool_note.cget("text"))
        _set_text(editor.rule_body, "a: [\n")
        editor.apply_rule()
        self.assertIn("rule", editor.rule_note.cget("text"))
        _set_text(editor.fields_box, "- x\n")
        editor.apply_fields()
        self.assertIn("expected a mapping", editor.fields_note.cget("text"))

    def test_edit_rename_and_remove_a_tool(self):
        editor = self.editor()
        self.add_tools(editor)
        editor.tools.selection_set("search")
        editor.edit_tool("search")
        self.assertEqual(editor.floor.get(), "public")
        self.assertIs(editor.irreversible.get(), False)
        editor.tool_id.set("find")
        editor.apply_tool()
        self.assertEqual(list(editor.tools.get_children()), ["find", "pay_vendor"])
        editor.remove_selected_tool()
        self.assertEqual(list(editor.tools.get_children()), ["pay_vendor"])
        self.assertEqual(editor.tool_id.get(), "")

    def test_the_applied_note_stays_and_new_clears_the_selection(self):
        editor = self.editor()
        self.add_tools(editor)
        self.top.update()       # the select events that refresh_tools and refresh_rules queue
        self.assertEqual(editor.tool_note.cget("text"), "pay_vendor applied")
        self.assertEqual(editor.rule_note.cget("text"), "rule 2 applied")
        editor.edit_tool(None)
        editor.edit_rule(None)
        self.assertEqual(editor.tools.selection(), ())
        self.assertEqual(editor.rules.selection(), ())
        editor.tools.selection_set("pay_vendor")
        editor.rules.selection_set("1")
        self.top.update()       # a click on the row it was editing before still opens it
        self.assertEqual(editor.tool_id.get(), "pay_vendor")
        self.assertEqual(editor.rule_id.get(), "spend-cap")

    def test_rules_change_move_and_go(self):
        editor = self.editor()
        self.add_tools(editor)
        editor.edit_rule(1)
        self.assertEqual(editor.rule_id.get(), "spend-cap")
        editor.move(-1)
        self.assertEqual(editor.rules.set("0", "id"), "spend-cap")
        editor.move(1)
        self.assertEqual(editor.rules.set("1", "id"), "spend-cap")
        _set_text(editor.rule_body, "amount_usd_gt: 50\n")
        editor.apply_rule()
        self.assertEqual(editor.draft.rules[1]["deny_if"], {"amount_usd_gt": 50})
        editor.rule_kind.set("deny_if_irreversible_over")
        editor.rule_template()
        self.assertEqual(_get(editor.rule_body).strip(), "100")
        editor.remove_rule()
        self.assertEqual(len(editor.draft.rules), 1)
        editor.move(1)          # nothing selected: nothing moves
        editor.remove_rule()
        self.assertEqual(len(editor.draft.rules), 1)

    def test_custom_fields(self):
        editor = self.editor()
        self.add_tools(editor)
        editor.fields_example()
        editor.apply_fields()
        self.assertIn("1 field(s) applied", editor.fields_note.cget("text"))
        self.assertIn("environment", editor.draft.fields)
        self.assertIn("Ready to sign", editor.status_text())
        _set_text(editor.fields_box, "")
        editor.apply_fields()
        self.assertEqual(editor.draft.fields, {})

    def test_try_a_call_shows_path_a_and_the_prompt(self):
        editor = self.editor()
        self.add_tools(editor)
        editor.try_tool_var.set("pay_vendor")
        _set_text(editor.arguments, '{"amount": 500}')
        editor.run_trial()
        text = editor.trial_text()
        self.assertIn("Path A denies the call: rule_denied:spend-cap", text)
        self.assertIn("<principal_constitution>", text)
        _set_text(editor.arguments, "a: [\n")
        editor.run_trial()
        self.assertIn("arguments", editor.trial_text())

    def test_prose_edits_are_checked(self):
        editor = self.editor()
        self.add_tools(editor)
        _set_text(editor.prose, "")
        editor.recheck()
        self.assertIn("prose is empty", editor.status_text())
        editor.use_starter()
        self.assertIn("Ready to sign", editor.status_text())
        editor.prose.insert("end", "More.")
        editor.prose.event_generate("<<Modified>>")
        self.top.update()
        self.assertTrue(editor.check_waiting)
        editor.changed()
        editor.recheck()
        self.assertIn("More.", editor.draft.prose)

    def test_serial_and_format(self):
        editor = self.editor()
        self.add_tools(editor)
        editor.serial_var.set("")
        editor.recheck()
        self.assertIn("1 warning(s)", editor.status_text())
        self.assertIsNone(editor.draft.serial)
        editor.serial_var.set("two")
        editor.recheck()
        self.assertIn("Does not sign yet", editor.status_text())
        editor.serial_var.set("3")
        editor.format_var.set("v2")
        editor.recheck()
        self.assertIn("Does not sign yet", editor.status_text())

    def test_sign_and_save_writes_a_constitution_that_verifies(self):
        editor = self.editor()
        self.add_tools(editor)
        editor.sign()
        self.assertIn("Signed (two-key-constitution-v3", editor.sign_text())
        # The note lives in the Review and sign tab, so the notebook does not draw over it.
        self.assertTrue(editor.sign_note.winfo_parent().startswith(str(editor.notebook.tabs()[-1])))
        envelope = load_envelope(self.dir / "out" / "constitution.signed.json")
        self.assertEqual(verify_signed(envelope, self.key.public_key()).serial, 1)
        editor.sign()
        self.assertIn("already there", editor.sign_text())
        editor.overwrite.set(True)
        editor.serial_var.set("2")
        editor.sign()
        self.assertEqual(load_envelope(self.dir / "out" / "constitution.signed.json")["signed"]["serial"], 2)

    def test_an_encrypted_key_needs_its_passphrase_and_the_box_is_cleared(self):
        (self.dir / "locked.pem").write_bytes(encrypt_private_key(self.key, b"correct horse battery"))
        (self.dir / "locked.pem").chmod(0o600)
        editor = self.editor(key_path=str(self.dir / "locked.pem"))
        self.add_tools(editor)
        editor.sign()
        self.assertIn("key_passphrase_needed", editor.sign_text())
        editor.passphrase.set("wrong passphrase!")
        editor.sign()
        self.assertIn("principal key", editor.sign_text())
        self.assertEqual(editor.passphrase.get(), "")
        editor.passphrase.set("correct horse battery")
        editor.sign()
        self.assertIn("Signed", editor.sign_text())
        self.assertEqual(editor.passphrase.get(), "")

    def test_a_passphrase_file(self):
        (self.dir / "locked.pem").write_bytes(encrypt_private_key(self.key, b"correct horse battery"))
        (self.dir / "locked.pem").chmod(0o600)
        (self.dir / "pass").write_text("correct horse battery\n")
        (self.dir / "pass").chmod(0o600)
        editor = self.editor(key_path=str(self.dir / "locked.pem"))
        self.add_tools(editor)
        editor.passphrase_file.set(str(self.dir / "pass"))
        editor.sign()
        self.assertIn("Signed", editor.sign_text())

    def test_save_unsigned(self):
        editor = self.editor()
        editor.save_unsigned()
        self.assertIn("not signed", editor.sign_text())
        self.assertTrue((self.dir / "out" / "hard_rules.yaml").exists())
        self.assertFalse((self.dir / "out" / "constitution.signed.json").exists())
        editor.save_unsigned()
        self.assertIn("already there", editor.sign_text())

    def test_open_sources_and_signed(self):
        editor = self.editor()
        editor.open_sources(str(EXAMPLES / "constitution.md"), str(EXAMPLES / "hard_rules.yaml"))
        self.assertIn("hard_rules.yaml", self.top.title())
        self.assertIn("search", editor.tools.get_children())
        self.assertEqual(editor.folder.get(), str(EXAMPLES))
        editor.open_sources(str(EXAMPLES / "constitution.md"), str(self.dir / "missing.yaml"))
        self.assertIn("Not opened", editor.status_text())
        draft = new_draft()
        envelope = sign_constitution(draft.prose, [{"allow_only_tools": ["a"]}], self.key, {"a": {}}, serial=3)
        signed = self.dir / "c.json"
        signed.write_text(json.dumps(envelope))
        editor.open_signed(str(signed), str(self.dir / "principal.pub.pem"))
        self.assertEqual(editor.serial_var.get(), "4")
        self.assertIn("signature checked", editor.sign_text())
        editor.open_signed(str(self.dir / "missing.json"))
        self.assertIn("Not opened", editor.status_text())

    def test_file_dialogs_fill_the_boxes(self):
        editor = self.editor(key_path="", folder="")
        with mock.patch.object(constitution_gui.filedialog, "askopenfilename", return_value="/k.pem"):
            editor.ask_key()
        with mock.patch.object(constitution_gui.filedialog, "askdirectory", return_value="/out"):
            editor.ask_folder()
        self.assertEqual((editor.key_path.get(), editor.folder.get()), ("/k.pem", "/out"))
        answers = [str(EXAMPLES / "constitution.md"), str(EXAMPLES / "hard_rules.yaml")]
        with mock.patch.object(constitution_gui.filedialog, "askopenfilename", side_effect=answers):
            editor.ask_open_sources()
        self.assertIn("search", editor.tools.get_children())
        with mock.patch.object(constitution_gui.filedialog, "askopenfilename", side_effect=["/nope.json", ""]):
            editor.ask_open_signed()
        self.assertIn("Not opened", editor.status_text())
        with mock.patch.object(constitution_gui.filedialog, "askopenfilename", return_value=""):
            editor.ask_open_sources()
            editor.ask_open_signed()
            editor.ask_key()


@unittest.skipIf(tk is None, "this Python has no tkinter")
class Show(unittest.TestCase):
    def test_show_without_a_display(self):
        with mock.patch.object(constitution_gui.tk, "Tk", side_effect=tk.TclError("no display name")), \
                mock.patch("builtins.print") as printed:
            self.assertEqual(show(), 1)
        self.assertIn("--check", printed.call_args.args[0])
        self.assertIs(printed.call_args.kwargs.get("file"), sys.stderr, "the message goes to stderr")

    def test_the_command_opens_the_window_on_the_files_given(self):
        from two_key import cli
        with mock.patch.object(constitution_gui, "show", return_value=0) as shown:
            code = cli.main(["constitution-editor", "--prose", str(EXAMPLES / "constitution.md"),
                             "--rules", str(EXAMPLES / "hard_rules.yaml"), "--key", "k.pem"])
        self.assertEqual(code, 0)
        kwargs = shown.call_args.kwargs
        self.assertEqual((kwargs["folder"], kwargs["key_path"]), (str(EXAMPLES), "k.pem"))
        self.assertIn("Opened", kwargs["opened"])
        with mock.patch.object(constitution_gui, "show", return_value=0) as shown:
            cli.main(["constitution-editor", "--dir", "/somewhere"])
        self.assertEqual(shown.call_args.kwargs["folder"], "/somewhere")

    def test_show_opens_and_closes(self):
        if tk_problem():
            self.skipTest(tk_problem())
        real = tk.Tk

        def closing_soon():
            window = real()
            window.after(100, window.destroy)
            return window
        with mock.patch.object(constitution_gui.tk, "Tk", side_effect=closing_soon):
            self.assertEqual(show(new_draft(), title="t"), 0)



def _get(box) -> str:
    return box.get("1.0", "end-1c")


if __name__ == "__main__":
    unittest.main()
