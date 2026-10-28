# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""What the setup window checks and does (two_key/setup_form.py), without a window.

The window must reach the same result as the terminal interview: the same answers give the same files, and
what the interview refuses the window refuses. Under ``high_assurance`` a quorum number can only go up.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from perm import private
from two_key import _platform, config_set, setup_cmd, setup_form
from two_key.setup_cmd import SetupError

DIGEST = "sha256:" + "0" * 64
JUDGE = {"id": "j1", "type": "openai_compatible", "model": "m", "base_url": "http://127.0.0.1:11434/v1",
         "maker": "local-maker", "upstream": "api.example"}
LOCAL = {"id": "local", "type": "ollama", "model": "qwen2.5:7b-instruct", "base_url": "http://127.0.0.1:11434",
         "maker": "alibaba"}
CLOUD = {"id": "cloud", "type": "openai_compatible", "model": "m", "base_url": "https://judge.example/v1",
         "maker": "other-maker", "auth_env": "JUDGE_KEY_VAR", "upstream": "judge.example"}
AGENT = {"id": "agent", "model": "some-model", "provider": "other", "base_url": "https://agent.example/v1",
         "upstream": "agent.example", "credential_env": "AGENT_KEY_VAR"}
ANSWERS = {"route": "proxy", "profile": "default", "judges": [JUDGE],
           "quorum": {"required_yes": 1, "min_responding": 1, "min_distinct_providers": 1, "min_makers": 1,
                      "min_local_judges": 0},
           "monitored_agent": AGENT,
           "judge_history": {"enabled": True, "on_failure": "deny", "burst_denies": 5, "burst_minutes": 10},
           "tools": [{"id": "tool_a", "irreversible": False, "data_class_floor": "personal"}],
           "upstream": {"command": ["server"], "schema_digest": DIGEST}, "one_proxy_per_agent": True}
CHECK = {"key": "sha256:" + "1" * 64}
NO_RUNTIME = mock.patch("two_key.writable.runtime_targets", return_value=[])


def quiet(fn, *a, **kw):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*a, **kw)


def scripted(replies):
    """An ``ask`` for the interview: the reply whose key starts the question, else blank (the default)."""
    def ask(question):
        for start, reply in replies:
            if question.startswith(start):
                return reply
        return ""
    return ask


class Review(unittest.TestCase):
    def test_complete_answers_are_ready(self):
        found = setup_form.review(ANSWERS)
        self.assertEqual(found.problems, [])
        self.assertTrue(found.ready)

    def test_what_stops_setup(self):
        cases = [({"judges": []}, "at least one judge"),
                 ({"judges": [JUDGE, JUDGE]}, "its own id"),
                 ({"monitored_agent": {"id": "a"}}, "monitored agent: model is needed"),
                 ({"tools": []}, "rules: give a reviewed rules file"),
                 ({"upstream": {"command": [], "schema_digest": ""}}, "upstream: the command"),
                 ({"upstream": {"command": ["s"], "schema_digest": "md5:1"}}, "starts with sha256:"),
                 ({"key_passphrase_file": "relative.txt"}, "absolute path"),
                 ({"judges": [CLOUD]}, "agent session")]
        for change, why in cases:
            with self.subTest(why=why):
                found = setup_form.review(dict(ANSWERS, **change))
                self.assertFalse(found.ready)
                self.assertTrue(any(why in p for p in found.problems), found.problems)

    def test_an_unresolvable_server_is_a_warning_as_in_config_check(self):
        judge = {k: v for k, v in JUDGE.items() if k != "upstream"}
        found = setup_form.review(dict(ANSWERS, judges=[judge]))
        self.assertTrue(found.ready)
        self.assertTrue(any("unresolved_identity" in w for w in found.warnings), found.warnings)

    def test_a_lower_quorum_number_is_weaker(self):
        answers = dict(ANSWERS, judges=[JUDGE, dict(JUDGE, id="j2")],
                       quorum=dict(ANSWERS["quorum"], required_yes=1, min_responding=1))
        found = setup_form.review(answers)
        self.assertTrue(found.ready)
        self.assertTrue(found.weaker)

    def test_high_assurance_numbers_only_go_up(self):
        lowest = setup_form.quorum_minimums("high_assurance", 2)
        self.assertEqual((lowest["required_yes"], lowest["min_makers"], lowest["min_local_judges"]), (2, 2, 1))
        self.assertEqual(setup_form.quorum_minimums("default", 2)["min_local_judges"], 0)
        answers = dict(ANSWERS, profile="high_assurance", judges=[LOCAL, CLOUD], agent_session_env="SESSION_VAR",
                       quorum=dict(lowest, required_yes=1), tools=[dict(ANSWERS["tools"][0], tool_check=CHECK)])
        found = setup_form.review(answers)
        self.assertIn("quorum: required_yes is at least 2 under high_assurance", found.problems)
        found = setup_form.review(dict(answers, quorum=dict(lowest, required_yes=2)))
        self.assertTrue(found.ready, found.problems)

    def test_high_assurance_needs_the_tool_check_and_exempt_is_weaker(self):
        answers = dict(ANSWERS, profile="high_assurance", judges=[LOCAL, CLOUD], agent_session_env="SESSION_VAR",
                       quorum=setup_form.quorum_minimums("high_assurance", 2))
        self.assertTrue(any("needs the tool check" in p for p in setup_form.review(answers).problems))
        exempt = setup_form.review(dict(answers, tools=[dict(ANSWERS["tools"][0], tool_check="exempt")]))
        self.assertTrue(exempt.ready, exempt.problems)
        self.assertEqual(exempt.weaker, ["tool_specs.tool_a.tool_check: exempt"])

    def test_high_assurance_needs_two_judges(self):
        found = setup_form.review(dict(ANSWERS, profile="high_assurance",
                                       quorum=setup_form.quorum_minimums("high_assurance", 1)))
        self.assertFalse(found.ready)

    def test_clean_drops_blanks_and_unknown_keys(self):
        self.assertEqual(setup_form.clean({"route": "proxy", "rules_file": "", "tools": [], "x": 1}),
                         {"route": "proxy"})


class Files(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.base)
        for patch in (mock.patch.object(config_set, "_euid", return_value=None if _platform.WINDOWS else 1000),
                      NO_RUNTIME):
            patch.start()
            self.addCleanup(patch.stop)

    def test_saved_answers_are_owner_only_and_setup_reads_them(self):
        path = setup_form.save_answers(ANSWERS, self.base / "answers.json")
        self.assertTrue(private(path))
        self.assertEqual(setup_cmd.load_answers(str(path)), setup_form.clean(ANSWERS))
        with self.assertRaisesRegex(SetupError, "exists"):
            setup_form.save_answers(ANSWERS, path)
        setup_form.save_answers(dict(ANSWERS, route="guard"), path, overwrite=True)
        self.assertEqual(setup_form.open_answers(path)["route"], "guard")

    def test_saved_answers_hold_no_secret_values(self):
        path = setup_form.save_answers(dict(ANSWERS, judges=[CLOUD], agent_session_env="SESSION_VAR"),
                                       self.base / "answers.json")
        text = path.read_text(encoding="utf-8")
        self.assertIn("JUDGE_KEY_VAR", text)
        self.assertNotIn("secret", text.lower())

    def test_the_window_and_the_interview_write_the_same_deployment(self):
        replies = [("Route", "proxy"), ("Profile", "default"), ("Judge 1: type", "openai_compatible"),
                   ("Judge 1: id", "j1"), ("Judge 1: model", "m"), ("Judge 1: base URL", JUDGE["base_url"]),
                   ("Judge 1: who made", "local-maker"), ("Judge 1: Two-Key cannot tell", "api.example"),
                   ("Add another judge", "no"), ("Monitored agent: id", "agent"),
                   ("Monitored agent: model", "some-model"), ("Monitored agent: provider", "other"),
                   ("Monitored agent: base URL", AGENT["base_url"]),
                   ("Monitored agent: Two-Key cannot tell", "agent.example"),
                   ("Monitored agent: name of", "AGENT_KEY_VAR"), ("Starter: the tool ids", "tool_a"),
                   ("Tool tool_a: can a call", "no"), ("Tool tool_a: lowest", "personal"),
                   ("Upstream MCP server", "server"), ("Upstream schema digest", DIGEST)]
        interviewed = quiet(setup_cmd.interview, scripted(replies))
        self.assertEqual(setup_form.clean(interviewed), setup_form.clean(ANSWERS))
        quiet(setup_cmd.build, interviewed, self.base / "terminal", confirm_weaker=True, confirm=lambda _p: True,
              environ={})
        quiet(setup_form.run_setup, ANSWERS, self.base / "window", typed_yes="", environ={})
        for name in ("judges.yaml", "proxy.yaml", "hard_rules.yaml", "constitution.md"):
            with self.subTest(file=name):
                self.assertEqual((self.base / "terminal" / name).read_bytes(),
                                 (self.base / "window" / name).read_bytes())

    def test_weaker_answers_need_the_typed_yes(self):
        answers = dict(ANSWERS, judges=[JUDGE, dict(JUDGE, id="j2")])
        with self.assertRaisesRegex(SetupError, "not_confirmed"):
            quiet(setup_form.run_setup, answers, self.base / "no", typed_yes="y", environ={})
        self.assertFalse((self.base / "no").exists())
        result = quiet(setup_form.run_setup, answers, self.base / "yes", typed_yes="yes", environ={})
        self.assertTrue(result["weaker"])
        self.assertEqual(json.loads(json.dumps(result))["dir"], str(self.base / "yes"))


if __name__ == "__main__":
    unittest.main()
