# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The ``two-key setup --window`` window (two_key/setup_gui.py), driven the way a person uses it.

Each test builds the window on a real Tk display, fills its pages through the same variables and buttons the
controls use, and reads the status line, the Review page and the files back. Skipped where Python has no tkinter
or no display can be opened (a child process opens and closes a window first, as tests/test_ledger_gui.py does).
"""

import functools
import io
import os
import subprocess  # nosec B404 - runs this Python with a fixed script
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import tkinter as tk

    from two_key.setup_gui import SetupWindow
except ImportError:                 # this Python was built without tkinter
    tk = None

try:
    import yaml
except ImportError:                 # installed without the yaml extra
    yaml = None

from two_key import _platform, cli, config_set, setup_cmd, setup_form

ROOT = Path(__file__).resolve().parent.parent
DIGEST = "sha256:" + "0" * 64
PROBE = """
import tkinter as tk
from two_key.setup_gui import SetupWindow
root = tk.Tk()
root.withdraw()
top = tk.Toplevel(root)
SetupWindow(top)
top.update()
top.destroy()
root.destroy()
"""
JUDGE = {"id": "j1", "type": "openai_compatible", "model": "m", "base_url": "http://127.0.0.1:11434/v1",
         "maker": "local-maker", "upstream": "api.example"}
LOCAL = {"id": "local", "type": "ollama", "model": "qwen2.5:7b-instruct", "base_url": "http://127.0.0.1:11434",
         "maker": "alibaba"}
AGENT = {"id": "agent", "model": "some-model", "provider": "other", "base_url": "https://agent.example/v1",
         "upstream": "agent.example", "credential_env": "AGENT_KEY_VAR"}


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
        self.base = Path(os.path.realpath(tmp.name))
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.base)
        for patch in (mock.patch.object(config_set, "_euid", return_value=None if _platform.WINDOWS else 1000),
                      mock.patch("two_key.writable.runtime_targets", return_value=[])):
            patch.start()
            self.addCleanup(patch.stop)

    def window(self, answers=None):
        window = SetupWindow(self.top, answers, folder=str(self.base / "deployment"))
        self.top.update_idletasks()
        return window

    @staticmethod
    def fill(window, judges=(JUDGE,), check=""):
        for judge in judges:
            for key, var in window.judge_var.items():
                var.set(judge.get(key, ""))
            window.add_judge()
        for key, var in window.agent_var.items():
            var.set(AGENT.get(key, ""))
        window.tool_var["id"].set("tool_a")
        window.tool_var["data_class_floor"].set("personal")
        window.tool_var["tool_check"].set(check)
        window.tool_irreversible.set(False)
        window.add_tool()
        window.var["command"].set("server --flag")
        window.var["schema_digest"].set(DIGEST)
        window.refresh()

    def test_empty_window_is_not_ready_and_says_why(self):
        window = self.window()
        self.assertIn("Not ready: judges: at least one judge", window.status.cget("text"))
        self.assertEqual(str(window.setup_button.cget("state")), "disabled")

    def test_filled_window_gives_the_interview_answers(self):
        window = self.window()
        self.fill(window)
        answers = window.answers()
        self.assertEqual(answers["upstream"], {"command": ["server", "--flag"], "schema_digest": DIGEST})
        self.assertEqual(answers["monitored_agent"]["credential_env"], "AGENT_KEY_VAR")
        self.assertEqual(answers["tools"], [{"id": "tool_a", "irreversible": False, "data_class_floor": "personal"}])
        self.assertEqual(answers["quorum"], setup_cmd.profile_quorum("default", 1))
        self.assertIn("Ready to set up", window.status.cget("text"))
        self.assertEqual(str(window.setup_button.cget("state")), "normal")

    def test_set_up_writes_the_deployment_and_offers_the_other_windows(self):
        window = self.window()
        self.fill(window)
        result = window.set_up()
        self.assertIsNotNone(result, window.status.cget("text"))
        self.assertTrue((self.base / "deployment" / "proxy.yaml").is_file())
        self.assertEqual(str(window.open_ledger.cget("state")), "normal")
        args = window.launch_arguments("constitution-editor")
        self.assertEqual(args[1:4], ["-m", "two_key", "constitution-editor"])
        self.assertIn(str(self.base / "deployment" / "constitution.signed.json"), args)
        # GUI guide run: without the public key the editor said the signature was not checked.
        self.assertEqual(args[args.index("--public-key") + 1], str(self.base / "deployment" / "principal.pub.pem"))
        args = window.launch_arguments("ledger-view")
        witness = self.base / "deployment" / "ledger.witness" / "witness.pub.pem"
        self.assertEqual(args[args.index("--witness-public-key") + 1], str(witness))
        # Run 12, E3c: answers changed after the setup say what is wrong now, beside the result.
        window.high.set(True)
        window.refresh()
        self.assertRegex(window.status.cget("text"), r"^Set up in .*The answers changed since, and now: ")

    def test_high_assurance_switch_raises_the_numbers_and_locks_them_as_minimums(self):
        window = self.window()
        self.fill(window, judges=(LOCAL, dict(JUDGE, id="j2")), check="hybrid-sha256:" + "1" * 64)
        window.high.set(True)
        self.top.update()
        lowest = setup_form.quorum_minimums("high_assurance", 2)
        self.assertEqual({k: v.get() for k, v in window.quorum.items()}, lowest)
        self.assertEqual(int(float(window.spin["min_makers"].cget("from"))), 2)
        self.assertTrue(window.ha_box.winfo_manager())
        window.quorum["required_yes"].set(1)
        window.refresh()
        self.assertIn("required_yes is at least 2", window.status.cget("text"))
        window.quorum["required_yes"].set(2)
        window.refresh()
        self.assertEqual(window.answers()["profile"], "high_assurance")
        window.high.set(False)
        self.top.update()
        self.assertFalse(window.ha_box.winfo_manager())

    def test_high_assurance_needs_each_tools_check(self):
        window = self.window()
        self.fill(window, judges=(LOCAL, dict(JUDGE, id="j2")))
        window.high.set(True)
        self.top.update()
        window.refresh()
        self.assertIn("tool tool_a: high_assurance needs the tool check", window.status.cget("text"))
        window.tool_table.selection_set(window.tool_table.get_children()[0])
        window._tool_clicked()
        window.tool_var["tool_check"].set("exempt")
        window.add_tool()
        self.assertEqual(window.answers()["tools"][0]["tool_check"], "exempt")
        self.assertIn("tool_specs.tool_a.tool_check: exempt", window.review_box.get("1.0", "end"))

    def test_weaker_needs_the_typed_yes(self):
        window = self.window()
        self.fill(window, judges=(JUDGE, dict(JUDGE, id="j2")))
        window.quorum["required_yes"].set(1)
        window.quorum["min_responding"].set(1)
        window.refresh()
        self.assertIsNone(window.set_up())
        self.assertIn("not_confirmed", window.status.cget("text"))
        self.assertFalse((self.base / "deployment").exists())
        window.var["typed_yes"].set("yes")
        self.assertIsNotNone(window.set_up())

    def test_save_and_open_an_answers_file(self):
        window = self.window()
        self.fill(window)
        path = self.base / "answers.json"
        self.assertTrue(window.save(str(path)))
        reopened = self.window(setup_form.open_answers(path))
        self.assertEqual(reopened.answers(), window.answers())

    def test_guard_route_turns_the_proxy_page_off(self):
        window = self.window()
        self.fill(window)
        window.var["route"].set("guard")
        window.refresh()
        self.assertEqual(window.notebook.tab(window.proxy_tab, "state"), "disabled")
        self.assertNotIn("upstream", window.answers())

    @unittest.skipIf(yaml is None, "the quickstart's answers file is YAML")
    def test_the_quickstart_answers_set_up_in_the_window(self):
        # docs/QUICKSTART.md step 3 offers the window beside the terminal; CI runs the terminal half.
        page = (ROOT / "docs" / "QUICKSTART.md").read_text(encoding="utf-8")
        answers_file = self.base / "answers.yaml"
        answers_file.write_text(page.split("cat > answers.yaml <<'EOF'\n", 1)[1].split("\nEOF\n", 1)[0] + "\n",
                                encoding="utf-8")
        window = self.window(setup_form.open_answers(answers_file))
        window.refresh()
        self.assertIn("Ready to set up", window.status.cget("text"))
        self.assertEqual(window.notebook.tab(window.proxy_tab, "state"), "disabled")
        self.assertIsNotNone(window.set_up(), window.status.cget("text"))
        for name in ("constitution.signed.json", "judges.yaml", "ledger"):
            self.assertTrue((self.base / "deployment" / name).exists(), name)
        self.assertEqual(str(window.open_ledger.cget("state")), "normal")


class CommandLine(unittest.TestCase):
    def test_without_tkinter_it_says_how_to_go_on(self):
        with mock.patch.dict(sys.modules, {"two_key.setup_gui": None}), \
                mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            code = cli.main(["setup", "--dir", "unused", "--window"])
        self.assertEqual(code, 1)
        self.assertIn("needs tkinter", err.getvalue())


if __name__ == "__main__":
    unittest.main()
