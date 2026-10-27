# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""``two-key config show`` and ``config check`` (two_key/config_cmd.py): read-only, and no secret in the output."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from two_key import cli, config_cmd
from two_key.constitution import save_envelope, sign_constitution
from two_key.keys import generate_private_key, save_private_key

DIGEST = "sha256:" + "0" * 64
JUDGES = """\
monitored_agent: {id: agent, model: some-model, provider: other, base_url: "https://agent.example/v1",
                  credential_env: AGENT_KEY_VAR}
judges:
  - {id: j1, type: openai_compatible, model: m, base_url: "http://127.0.0.1:11434/v1", maker: local-maker}
  - {id: j2, type: openai_compatible, model: m2, base_url: "https://judge.example/v1", maker: other-maker,
     auth: {type: env, var: JUDGE_KEY_VAR}}
quorum: {required_yes: 1}
"""


SET = {"UPSTREAM_SECRET_VAR": "x", "AGENT_KEY_VAR": "y", "JUDGE_KEY_VAR": "z", "AGENT_SESSION_VAR": "s"}


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Workspace(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        os.chmod(self.dir, 0o700)
        key = generate_private_key()
        save_private_key(self.dir / "k.pem", key)
        save_envelope(self.dir / "c.json", sign_constitution(
            "Approve small, routine requests.", [{"id": "tools", "allow_only_tools": ["tool_a"]}], key,
            {"tool_a": {"irreversible": False, "data_class_floor": "public"}}))
        (self.dir / "judges.yaml").write_text(JUDGES, encoding="utf-8")
        self.write_proxy()

    def write_proxy(self, extra=""):
        (self.dir / "proxy.yaml").write_text(
            "constitution: c.json\nkeys: {principal: k.pem}\nledger: ledger\njudges: judges.yaml\n"
            "agent_session_env: AGENT_SESSION_VAR\n"
            f"upstream:\n  command: [server]\n  schema_digest: {DIGEST}\n"
            "  env: {TOKEN: {env: UPSTREAM_SECRET_VAR}, LEVEL: info-literal-value}\n" + extra, encoding="utf-8")

    def _files(self):
        return sorted(p.name for p in self.dir.iterdir())

    @property
    def proxy(self):
        return str(self.dir / "proxy.yaml")


class Show(Workspace):
    def test_shows_the_effective_settings_without_values_that_could_be_secret(self):
        before = self._files()
        code, out, _ = run("config", "show", "--config", self.proxy)
        self.assertEqual(code, 0)
        shown = json.loads(out)
        self.assertEqual(shown["ttl_seconds"], 120)
        self.assertEqual(shown["on_agent_access"], "refuse")
        self.assertEqual(shown["on_writable_paths"], "warn")
        self.assertEqual(shown["upstream"]["env"], {"LEVEL": "<literal>", "TOKEN": {"env": "UPSTREAM_SECRET_VAR"}})
        self.assertNotIn("info-literal-value", out)
        self.assertEqual(shown["upstream"]["check_paths"], [])
        self.assertEqual(shown["judges"][0]["id"], "j1")
        # Live run 9, finding 1: where each judge is, and the name of each variable it reads; never a value.
        self.assertEqual({k: shown["judges"][1][k] for k in ("type", "base_url", "auth", "variables")},
                         {"type": "openai_compatible", "base_url": "https://judge.example/v1", "auth": "env",
                          "variables": {"auth.var": "JUDGE_KEY_VAR"}})
        self.assertEqual(self._files(), before, "show wrote a file, or opened the ledger")

    def test_a_scanner_variable_is_never_shown(self):
        self.write_proxy("scan: {type: command, command: [/bin/true], env: {SCAN_PW: scanner-secret-value}}\n")
        code, out, _ = run("config", "show", "--config", self.proxy)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["scan"]["env"], {"SCAN_PW": "<literal>"})
        self.assertNotIn("scanner-secret-value", out)

    def test_a_bad_file_is_one_line_and_exit_1(self):
        self.write_proxy("surprise: 1\n")
        code, out, err = run("config", "show", "--config", self.proxy)
        self.assertEqual((code, out), (1, ""))
        self.assertIn("unknown key", err)


class Check(Workspace):
    def check(self, environ=None):
        return config_cmd.check(self.proxy, dict(SET) if environ is None else environ)

    @staticmethod
    def levels(found):
        return {level for level, _ in found}

    def test_a_good_setup_has_no_failure_and_writes_nothing(self):
        before = self._files()
        found = self.check()
        self.assertNotIn(config_cmd.FAIL, self.levels(found), found)
        self.assertTrue(any("signed by the principal key" in text for _, text in found))
        self.assertEqual(self._files(), before, "check wrote a file, or opened the ledger")

    def test_an_unset_variable_fails_and_the_value_is_never_printed(self):
        found = self.check({})
        self.assertTrue(any(level == config_cmd.FAIL and "upstream_env_missing" in text for level, text in found))
        found = self.check({**SET, "UPSTREAM_SECRET_VAR": "hunter2-secret"})
        self.assertNotIn("hunter2-secret", json.dumps(found))

    def test_every_variable_set_is_named_in_the_ok_line(self):
        [line] = [text for _, text in self.check() if text.startswith("environment")]
        self.assertEqual(line, "environment: set here: AGENT_KEY_VAR, AGENT_SESSION_VAR, JUDGE_KEY_VAR, "
                               "UPSTREAM_SECRET_VAR")

    def test_an_unset_agent_credential_fails(self):
        """Live run 9, finding 1: the proxy refuses to start without it, so check must not say all is set."""
        found = self.check({**SET, "AGENT_KEY_VAR": ""})
        self.assertIn((config_cmd.FAIL, "agent_credential_missing: monitored_agent.credential_env names "
                       "AGENT_KEY_VAR, which is unset or empty here (the proxy's own environment may differ)"),
                      found)
        self.assertFalse(any(text.startswith("environment:") for _, text in found))

    def test_an_unset_judge_key_warns_by_name(self):
        """The proxy starts, and that judge abstains on every call: a warning, with the variable's name only."""
        found = self.check({**SET, "JUDGE_KEY_VAR": ""})
        warned = [text for level, text in found if level == config_cmd.WARN and "judge_env_missing" in text]
        self.assertEqual(warned, ["judge_env_missing: judge j2 auth.var names JUDGE_KEY_VAR, which is unset or "
                                  "empty here (the proxy's own environment may differ); the judge will abstain"])
        self.assertNotIn(config_cmd.FAIL, self.levels(found), found)

    def test_a_cloud_judge_without_the_agent_session_fails(self):
        """Live setup run, 2026-10-27: a cloud judge abstains on a call without the agent's session, so with no
        agent_session_env every call it would judge is denied cloud_judge_session_required."""
        text = (self.dir / "proxy.yaml").read_text(encoding="utf-8")
        (self.dir / "proxy.yaml").write_text(text.replace("agent_session_env: AGENT_SESSION_VAR\n", ""),
                                             encoding="utf-8")
        failed = [text for level, text in self.check() if level == config_cmd.FAIL]
        self.assertEqual(len(failed), 1, failed)
        self.assertTrue(failed[0].startswith("cloud_judge_session_required: judge(s) j2 are not on this machine"))
        local = JUDGES.replace("https://judge.example/v1", "http://127.0.0.1:11435/v1")
        (self.dir / "judges.yaml").write_text(local, encoding="utf-8")
        self.assertNotIn(config_cmd.FAIL, self.levels(self.check()))

    def test_a_quorum_that_could_be_too_lenient_warns(self):
        warned = [text for level, text in self.check() if level == config_cmd.WARN and text.startswith("quorum:")]
        self.assertTrue(any("one judge approves a call alone" in text for text in warned), warned)
        self.assertTrue(any("every judge comes from one provider" in text for text in warned), warned)

    def test_a_constitution_signed_by_another_key_fails(self):
        other = generate_private_key()
        save_envelope(self.dir / "c.json", sign_constitution(
            "Approve small, routine requests.", [{"id": "tools", "allow_only_tools": ["tool_a"]}], other,
            {"tool_a": {"irreversible": False, "data_class_floor": "public"}}))
        self.assertTrue(any(level == config_cmd.FAIL and "constitution" in text for level, text in self.check()))

    def test_a_tool_the_constitution_does_not_sign_fails(self):
        self.write_proxy("tools:\n  tool_b: {claim: floor}\n")
        self.assertTrue(any(level == config_cmd.FAIL and "tool_b" in text for level, text in self.check()))

    def test_a_missing_judges_file_fails(self):
        (self.dir / "judges.yaml").unlink()
        self.assertTrue(any(level == config_cmd.FAIL and "judges_invalid" in text for level, text in self.check()))

    def test_plaintext_siem_warns_here(self):
        self.write_proxy("siem:\n  sinks:\n    - {type: syslog, host: 127.0.0.1, transport: udp}\n")
        found = self.check()
        self.assertTrue(any(level == config_cmd.WARN and "in the clear" in text for level, text in found), found)

    def test_the_upstream_servers_files(self):
        # #13: a check_paths entry that does not exist fails here as it refuses in the proxy.
        self.write_proxy(f"  check_paths: [{json.dumps(str(self.dir / 'gone'))}]\n")
        found = self.check()
        self.assertIn((config_cmd.FAIL, f"check_path_missing: upstream.check_paths[0]: {self.dir / 'gone'} does "
                                        "not exist; fix the path or remove the entry"), found)
        self.write_proxy(f"  check_paths: [{json.dumps(str(self.dir / 'k.pem'))}]\n")
        self.assertFalse([t for _, t in self.check() if "check_path" in t or "upstream_paths" in t])
        # A launcher with nothing named: a warning, as at start.
        self.write_proxy()
        text = (self.dir / "proxy.yaml").read_text(encoding="utf-8")
        (self.dir / "proxy.yaml").write_text(text.replace("command: [server]", "command: [npx, -y, example-server]"),
                                             encoding="utf-8")
        self.assertTrue(any(level == config_cmd.WARN and text.startswith("upstream_paths_unchecked: ")
                            for level, text in self.check()))

    def test_cli_exit_code_follows_failures(self):
        code, out, _ = run("config", "check", "--config", str(self.dir / "missing.yaml"))
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)


if __name__ == "__main__":
    unittest.main()
