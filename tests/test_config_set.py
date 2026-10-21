"""``two-key config set``, ``get`` and ``undo`` (two_key/config_set.py), and ``two-key setup`` (two_key/setup_cmd.py).

What is refused writes nothing: no file changes, no ``.prev``, no ledger entry. What is written is owner-only,
checked as a whole first, recorded as ``config_changed`` with names and digests but never a value, and can be
put back with ``undo``.
"""

import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from perm import chmod, private
from two_key import _platform, cli, config_set, setup_cmd
from two_key.config_set import ConfigChangeError
from two_key.constitution import load_envelope, verify_signed
from two_key.keys import generate_private_key, load_private_key_file, save_private_key
from two_key.ledger import Ledger
from two_key.siem import project

POSIX = not _platform.WINDOWS
DIGEST = "sha256:" + "0" * 64
VALUE_CANARY = "canary-agent-id-7f3a"
SECRET_CANARY = "hunter2-upstream-token-9c1d"
LOCAL = {"id": "local", "type": "ollama", "model": "qwen2.5:7b-instruct", "base_url": "http://127.0.0.1:11434",
         "maker": "alibaba"}
CLOUD = {"id": "cloud", "type": "openai_compatible", "model": "m", "base_url": "https://judge.example/v1",
         "maker": "other-maker", "auth_env": "JUDGE_KEY_VAR"}
ANSWERS = {
    "route": "proxy", "profile": "default",
    "judges": [{"id": "j1", "type": "openai_compatible", "model": "m", "base_url": "http://127.0.0.1:11434/v1",
                "maker": "local-maker"}],
    "monitored_agent": {"id": "agent", "model": "some-model", "provider": "other",
                        "base_url": "https://agent.example/v1", "credential_env": "AGENT_KEY_VAR"},
    "tools": [{"id": "tool_a", "irreversible": False, "data_class_floor": "personal"}],
    "upstream": {"command": ["server"], "schema_digest": DIGEST},
}
NO_RUNTIME = mock.patch("two_key.writable.runtime_targets", return_value=[])


def quiet(fn, *a, **kw):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        result = fn(*a, **kw)
    return result, out.getvalue(), err.getvalue()


class Deployment(unittest.TestCase):
    """A deployment written by ``setup``, run as an ordinary account (the suite may run as root)."""
    answers = ANSWERS

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        for patch in (mock.patch.object(config_set, "_euid", return_value=None if _platform.WINDOWS else 1000),
                      NO_RUNTIME):
            patch.start()
            self.addCleanup(patch.stop)
        self.dir = self.base / "deployment"
        self.result, self.setup_out, _ = quiet(setup_cmd.build, dict(self.answers), self.dir, environ={})
        self.proxy = self.dir / "proxy.yaml"
        self.key = self.dir / "principal.pem"
        self.rules = self.dir / "hard_rules.yaml"
        self.answered: list[str] = []

    def ledger(self):
        return Ledger(self.dir / "ledger", load_private_key_file(self.key))

    def changes(self):
        return [e for e in self.ledger().entries if e.kind == "config_changed"]

    def snapshot(self):
        return {p.name: p.read_bytes() for p in sorted(self.dir.iterdir()) if p.is_file()
                and not p.name.endswith(".lock")}

    def confirm(self, answer=True):
        def ask(prompt):
            self.answered.append(prompt)
            return answer
        return ask

    def set(self, name, value=None, **kw):
        kw.setdefault("confirm", self.confirm())
        kw.setdefault("environ", {})
        return quiet(config_set.set_setting, self.proxy, name, value, **kw)

    def refused(self, pattern, name, value=None, **kw):
        before, entries = self.snapshot(), len(self.ledger().entries)
        with self.assertRaisesRegex(ConfigChangeError, pattern):
            self.set(name, value, **kw)
        self.assertEqual(self.snapshot(), before, "a refused change wrote a file")
        self.assertEqual(len(self.ledger().entries), entries, "a refused change was ledgered")


class Setup(Deployment):
    def test_writes_every_file_owner_only_and_records_their_digests(self):
        names = {p.name for p in self.dir.iterdir()}
        for name in ("principal.pem", "constitution.md", "hard_rules.yaml", "constitution.signed.json",
                     "judges.yaml", "proxy.yaml", "ledger"):
            self.assertIn(name, names)
        for name in ("principal.pem", "constitution.md", "hard_rules.yaml", "constitution.signed.json",
                     "judges.yaml", "proxy.yaml"):
            self.assertTrue(private(self.dir / name), name)
        [entry] = self.changes()
        self.assertEqual(entry.body["command"], "setup")
        recorded = {f["file"]: f["new_sha256"] for f in entry.body["files"]}
        self.assertNotIn("principal.pem", recorded, "a private key's digest is not recorded")
        self.assertEqual(recorded["proxy.yaml"], config_set.sha256(self.proxy.read_bytes()))
        self.assertFalse(list(self.base.glob(".deployment.setup-*")), "the staging folder was left behind")

    def test_the_result_passes_config_check(self):
        from two_key import config_cmd
        found = config_cmd.check(self.proxy, {})
        self.assertNotIn(config_cmd.FAIL, {level for level, _ in found}, found)
        self.assertEqual(json.loads(self.proxy.read_text(encoding="utf-8").split("\n", 2)[2] or "{}")
                         if self.proxy.suffix == ".json" else 0, 0)

    def test_no_secret_is_asked_for_or_written(self):
        text = "".join(p.read_text(encoding="utf-8") for p in self.dir.glob("*.yaml"))
        self.assertIn("credential_env: AGENT_KEY_VAR", text)
        self.assertIn("AGENT_KEY_VAR", " ".join(self.result["next"]))

    def test_an_existing_folder_is_refused(self):
        with self.assertRaisesRegex(setup_cmd.SetupError, "setup_target_exists"):
            quiet(setup_cmd.build, dict(ANSWERS), self.dir, environ={})

    def test_a_refused_setup_leaves_nothing(self):
        bad = dict(ANSWERS, judges=[dict(ANSWERS["judges"][0], type="no_such_type")])
        with self.assertRaisesRegex(setup_cmd.SetupError, "config_check_failed"):
            quiet(setup_cmd.build, bad, self.base / "other", environ={})
        self.assertEqual(sorted(p.name for p in self.base.iterdir()), ["deployment"])

    def test_high_assurance_with_one_judge_is_refused(self):
        with self.assertRaisesRegex(setup_cmd.SetupError, "too_few_judges"):
            quiet(setup_cmd.build, dict(ANSWERS, profile="high_assurance"), self.base / "ha", environ={})
        self.assertFalse((self.base / "ha").exists())

    def test_high_assurance_writes_refuse_for_the_writable_path_check(self):
        answers = dict(ANSWERS, profile="high_assurance", judges=[LOCAL, CLOUD])
        quiet(setup_cmd.build, answers, self.base / "ha", environ={})
        text = (self.base / "ha" / "proxy.yaml").read_text(encoding="utf-8")
        self.assertIn("on_writable_paths: refuse", text)
        self.assertIn("var: JUDGE_KEY_VAR", (self.base / "ha" / "judges.yaml").read_text(encoding="utf-8"))

    def test_the_library_route_writes_no_proxy_config(self):
        quiet(setup_cmd.build, dict(ANSWERS, route="library"), self.base / "lib", environ={})
        self.assertFalse((self.base / "lib" / "proxy.yaml").exists())
        self.assertTrue((self.base / "lib" / "constitution.signed.json").exists())

    def test_root_is_refused(self):
        with mock.patch.object(config_set, "_euid", return_value=0):
            with self.assertRaisesRegex(setup_cmd.SetupError, "config_as_root"):
                quiet(setup_cmd.build, dict(ANSWERS), self.base / "root", environ={})

    def test_an_answers_file_with_an_unknown_key_is_refused(self):
        path = self.base / "answers.json"
        path.write_text(json.dumps(dict(ANSWERS, judge_api_key="x")), encoding="utf-8", newline="\n")
        with self.assertRaisesRegex(setup_cmd.SetupError, "unknown key"):
            setup_cmd.load_answers(str(path))

    def test_the_interview_asks_for_names_never_secrets(self):
        replies = ["proxy", "default", "openai_compatible", "j1", "m", "http://127.0.0.1:11434/v1", "", "",
                   "no", "agent", "some-model", "other", "https://agent.example/v1", "AGENT_KEY_VAR", "", "",
                   "tool_a", "no", "public", "", "server --stdio", DIGEST, ""]
        asked = []

        def ask(prompt):
            asked.append(prompt)
            self.assertTrue(replies, f"the interview asked more than the test answers: {prompt}")
            return replies.pop(0)
        answers, _, _ = quiet(setup_cmd.interview, ask)
        self.assertEqual(answers["upstream"], {"command": ["server", "--stdio"], "schema_digest": DIGEST})
        self.assertEqual(answers["tools"], [{"id": "tool_a", "irreversible": False, "data_class_floor": "public"}])
        for q in asked:
            self.assertNotRegex(q.lower(), r"password|token|secret", q)
            if "passphrase" in q.lower():
                self.assertIn("path of a file", q.lower())
            if re.search(r"api key|credential|session", q.lower()):
                self.assertIn("name of the environment variable", q.lower())
        quiet(setup_cmd.build, answers, self.base / "asked", environ={})


class Names(unittest.TestCase):
    def test_brackets_hold_list_items_and_keys_with_dots(self):
        self.assertEqual(config_set.parse_name("siem.sinks[0].port"), ["siem", "sinks", 0, "port"])
        self.assertEqual(config_set.parse_name("tools[fs.read].claim"), ["tools", "fs.read", "claim"])
        self.assertEqual(config_set.format_name(["tools", "fs.read", "claim"]), "tools[fs.read].claim")

    def test_the_file_comes_from_the_name(self):
        role = config_set.role_for
        self.assertEqual(role(["ttl_seconds"]), "proxy")
        self.assertEqual(role(["judges", 0, "timeout"]), "judges")
        self.assertEqual(role(["quorum", "profile"]), "judges")
        self.assertEqual(role(["tool_specs", "x", "irreversible"]), "rules")
        for name in ("ledger", "keys", "constitution", "judges", "witness_public_key", "head_anchor"):
            with self.assertRaisesRegex(ConfigChangeError, "not_settable"):
                role([name])

    def test_a_name_is_short_printable_ascii(self):
        for bad in ("", "a..b", "a[0", "tté", "x" * 201, "a\nb"):
            with self.assertRaises(ConfigChangeError):
                config_set.parse_name(bad)

    def test_values_are_json_or_text(self):
        self.assertEqual(config_set.parse_value("120"), 120)
        self.assertEqual(config_set.parse_value('"120"'), "120")
        self.assertEqual(config_set.parse_value("high_assurance"), "high_assurance")
        self.assertEqual(config_set.parse_value('{"env": "X"}'), {"env": "X"})


class Get(Deployment):
    def test_a_value_its_file_and_its_default(self):
        got, _, _ = quiet(config_set.get, self.proxy, "ttl_seconds")
        self.assertEqual((got["value"], got["default"], got["tier"], got["set"]), (120, "120", "operator", True))
        got, _, _ = quiet(config_set.get, self.proxy, "quorum.min_makers")
        self.assertEqual((got["value"], got["set"], got["high_assurance"]), (None, False, "2"))
        got, _, _ = quiet(config_set.get, self.proxy, "tool_specs.tool_a.data_class_floor")
        self.assertEqual((got["value"], got["tier"]), ("personal", "signed"))

    def test_an_env_literal_is_never_printed(self):
        self.set("upstream.env.TOKEN", SECRET_CANARY, value_from="file")
        for name in ("upstream.env.TOKEN", "upstream.env", "upstream"):
            got, _, _ = quiet(config_set.get, self.proxy, name)
            self.assertNotIn(SECRET_CANARY, json.dumps(got))
        self.assertIn("<literal>", json.dumps(got))


class Set(Deployment):
    def test_a_change_is_owner_only_kept_for_undo_and_ledgered_without_its_value(self):
        before = self.proxy.read_bytes()
        result, out, _ = self.set("agent_id", VALUE_CANARY)
        self.assertEqual((result["settings"], result["weaker"], result["signed"]), (["agent_id"], [], False))
        self.assertIn("restart", result["next"])
        self.assertIn(VALUE_CANARY, self.proxy.read_text(encoding="utf-8"))
        self.assertTrue(private(self.proxy))
        self.assertEqual((self.dir / "proxy.yaml.prev").read_bytes(), before)
        entry = self.changes()[-1]
        self.assertEqual(entry.body["settings"], ["agent_id"])
        self.assertEqual(entry.body["files"][0]["old_sha256"], config_set.sha256(before))
        self.assertEqual(entry.body["files"][0]["new_sha256"], config_set.sha256(self.proxy.read_bytes()))
        self.assertNotIn(VALUE_CANARY, json.dumps(entry.body))
        self.assertEqual(self.answered, [], "a change that weakens nothing asks nothing")

    def test_the_siem_copy_has_names_and_digests_but_not_the_account(self):
        self.set("agent_id", VALUE_CANARY)
        entry = self.changes()[-1]
        event = project(entry.kind, entry.body)
        self.assertEqual(event["settings"], ["agent_id"])
        self.assertEqual(set(event["files"][0]), {"role", "file", "old_sha256", "new_sha256"})
        self.assertNotIn("account", event)
        self.assertNotIn(entry.body["account"], json.dumps(event))

    def test_a_judges_setting_goes_to_judges_yaml(self):
        self.set("judges[0].timeout", 20)
        self.assertIn("timeout: 20", (self.dir / "judges.yaml").read_text(encoding="utf-8"))
        self.assertEqual(self.changes()[-1].body["files"][0]["role"], "judges")

    def test_unset_brings_back_the_default(self):
        self.set("ttl_seconds", 60)
        self.set("ttl_seconds", unset=True, confirm_weaker=True)
        got, _, _ = quiet(config_set.get, self.proxy, "ttl_seconds")
        self.assertFalse(got["set"])

    def test_an_unknown_or_untouchable_setting_is_refused(self):
        self.refused("unknown_setting", "ttl_second", 5)
        self.refused("not_settable", "ledger", "elsewhere")
        self.refused("not_settable", "keys.principal", "other.pem")

    def test_a_config_that_would_not_start_is_refused_and_named(self):
        self.refused("config_check_failed: tools: \\['tool_b'\\]", "tools.tool_b.claim", "floor")
        code, _, err = quiet(cli.main, ["config", "set", "--config", str(self.proxy), "tools.tool_b.claim", "floor"])
        self.assertEqual(code, 1)
        self.assertIn("FAIL  tools: ['tool_b'] are not tools in the signed constitution", err)

    def test_an_invalid_value_is_refused_by_the_loader(self):
        self.refused("config_invalid: .*ttl_seconds", "ttl_seconds", 9999)
        self.refused("config_invalid", "on_agent_access", "sometimes")

    def test_root_is_refused(self):
        with mock.patch.object(config_set, "_euid", return_value=0):
            self.refused("config_as_root", "ttl_seconds", 60)

    @unittest.skipUnless(POSIX, "mode bits")
    def test_a_file_another_account_can_change_is_refused(self):
        chmod(self.proxy, 0o666)
        self.addCleanup(chmod, self.proxy, 0o600)
        self.refused("config_target_unsafe", "ttl_seconds", 60)

    @unittest.skipUnless(POSIX, "mode bits")
    def test_a_folder_another_account_can_change_is_refused(self):
        chmod(self.dir, 0o777)
        self.addCleanup(chmod, self.dir, 0o700)
        self.refused("config_target_unsafe", "judges[0].timeout", 20)

    @unittest.skipUnless(POSIX, "symlinks")
    def test_a_link_is_refused(self):
        real = self.dir / "judges.real.yaml"
        os.replace(self.dir / "judges.yaml", real)
        os.symlink(real, self.dir / "judges.yaml")
        self.refused("config_target_link", "judges[0].timeout", 20)

    def test_no_ledger_no_change(self):
        os.replace(self.dir / "ledger", self.base / "moved-ledger")
        with self.assertRaisesRegex(ConfigChangeError, "ledger_missing"):
            self.set("ttl_seconds", 60)
        self.assertFalse((self.dir / "proxy.yaml.prev").exists())


class Secrets(Deployment):
    def test_a_literal_on_the_command_line_is_refused(self):
        self.refused("secret_on_command_line", "upstream.env.TOKEN", SECRET_CANARY)
        self.refused("secret_on_command_line", "upstream.env", {"TOKEN": SECRET_CANARY})

    def test_a_variable_name_is_fine_on_the_command_line(self):
        self.set("upstream.env.TOKEN", {"env": "UPSTREAM_TOKEN"})
        self.assertIn("UPSTREAM_TOKEN", self.proxy.read_text(encoding="utf-8"))

    def test_a_value_file_must_be_owner_only_and_the_value_is_never_shown(self):
        path = self.base / "token.txt"
        fd = _platform.create_new(path)
        os.write(fd, (SECRET_CANARY + "\n").encode("ascii"))
        os.close(fd)
        code, out, err = quiet(cli.main, ["config", "set", "--config", str(self.proxy), "upstream.env.TOKEN",
                                          "--value-file", str(path)])
        self.assertEqual(code, 0, err)
        self.assertNotIn(SECRET_CANARY, out + err)
        self.assertIn(f"TOKEN: {SECRET_CANARY}\n", self.proxy.read_text(encoding="utf-8"))
        self.assertNotIn(SECRET_CANARY, json.dumps([e.body for e in self.ledger().entries]))
        if POSIX:
            chmod(path, 0o644)
            with self.assertRaisesRegex(ConfigChangeError, "value_file_insecure"):
                config_set.read_value_file(str(path))

    def test_the_command_line_takes_one_source_of_value(self):
        code, _, err = quiet(cli.main, ["config", "set", "--config", str(self.proxy), "ttl_seconds", "60",
                                        "--unset"])
        self.assertEqual(code, 1)
        self.assertIn("exactly one", err)


class Weaker(Deployment):
    def test_weaker_needs_the_flag(self):
        self.refused("weaker: ttl_seconds: tokens live longer.*--confirm-weaker", "ttl_seconds", 300)
        self.assertEqual(self.answered, [])

    def test_weaker_needs_a_typed_yes(self):
        self.refused("not_confirmed", "on_agent_access", "warn", confirm_weaker=True, confirm=self.confirm(False))

    def test_weaker_with_the_flag_and_a_yes_is_written_and_says_why(self):
        result, _, _ = self.set("on_agent_access", "warn", confirm_weaker=True)
        self.assertEqual(result["weaker"], ["on_agent_access: refuse to warn"])
        self.assertEqual(len(self.answered), 1)
        body = self.changes()[-1].body
        self.assertEqual((body["weaker"], body["confirmed"]), (["on_agent_access: refuse to warn"], True))

    def test_without_a_terminal_the_answer_is_no(self):
        with mock.patch("sys.stdin", io.StringIO("yes\n")):
            self.refused("not_confirmed", "ttl_seconds", 300, confirm_weaker=True,
                         confirm=config_set.terminal_confirm)

    def test_what_counts_as_weaker(self):
        cases = [("allow_unresolved_identity", True, "allow_unresolved_identity"),
                 ("upstream.on_schema_change", "warn", "on_schema_change"),
                 ("tools.tool_a.claim", "public", "lower data class"),
                 ("upstream.check_paths", None, "no longer checked"),
                 ("quorum.judge_inputs", "record_and_proposal", "judges see the proposal"),
                 ("quorum.tool_args_on_derive_deny", True, "judges see more"),
                 ("judges[0].model", "another-model", r"judges\[j1\]: model"),
                 ("monitored_agent.model", "another-agent-model", "monitored_agent: changed"),
                 ("siem", {"sinks": [{"type": "syslog", "host": "127.0.0.1", "transport": "udp"}]}, "in the clear")]
        self.set("upstream.check_paths", [str(self.dir)])
        for name, value, why in cases:
            with self.subTest(name=name):
                self.refused(f"weaker: .*{why}", name, value, unset=value is None)

    def test_stronger_is_not_weaker(self):
        self.set("tools.tool_a.claim", "public", confirm_weaker=True)
        self.answered.clear()
        self.set("tools.tool_a.claim", "personal")
        self.set("tools.tool_a.claim", "floor")
        self.set("ttl_seconds", 30)
        self.set("judges[0].timeout", 10)
        self.assertEqual(self.answered, [])


class HighAssurance(Deployment):
    answers = dict(ANSWERS, profile="high_assurance", judges=[LOCAL, CLOUD])

    def test_what_the_profile_forbids_stays_forbidden(self):
        self.refused("config_check_failed: on_agent_access: high_assurance", "on_agent_access", "warn",
                     confirm_weaker=True)
        self.refused("config_check_failed: on_writable_paths", "on_writable_paths", "warn", confirm_weaker=True)
        self.refused("config_check_failed: siem_plaintext_refused", "siem",
                     {"sinks": [{"type": "syslog", "host": "127.0.0.1", "transport": "tcp"}]}, confirm_weaker=True)

    def test_turning_it_off_is_weaker(self):
        self.refused("weaker: quorum: high_assurance turned off", "quorum.profile", "default")
        result, _, _ = self.set("quorum.profile", "default", confirm_weaker=True)
        self.assertIn("quorum: high_assurance turned off", result["weaker"])


class Signed(Deployment):
    def signed(self, name, value, **kw):
        kw.setdefault("key_path", str(self.key))
        kw.setdefault("rules_path", str(self.rules))
        return self.set(name, value, **kw)

    def test_needs_the_principal_key_and_the_rules_file(self):
        self.refused("principal_key_needed", "tool_specs.tool_a.irreversible", True, rules_path=str(self.rules))
        self.refused("rules_file_needed", "tool_specs.tool_a.irreversible", True, key_path=str(self.key))

    def test_another_key_is_refused(self):
        other = self.base / "other.pem"
        save_private_key(other, generate_private_key())
        self.refused("principal_key_mismatch", "tool_specs.tool_a.irreversible", True, key_path=str(other),
                     rules_path=str(self.rules))

    def test_a_rules_file_that_is_not_what_was_signed_is_refused(self):
        text = self.rules.read_text(encoding="utf-8").replace("data_class_floor: personal",
                                                               "data_class_floor: public")
        self.rules.write_bytes(text.encode("utf-8"))
        self.refused("rules_source_differs", "tool_specs.tool_a.irreversible", True, key_path=str(self.key),
                     rules_path=str(self.rules))

    def test_a_signed_change_is_shown_confirmed_signed_and_verified(self):
        result, out, _ = self.signed("tool_specs.tool_a.irreversible", True)
        self.assertTrue(result["signed"])
        self.assertIn('-  "irreversible": false', out)
        self.assertIn('+  "irreversible": true', out)
        self.assertEqual(len(self.answered), 1)
        self.assertIn("signs a new constitution", self.answered[0])
        envelope = load_envelope(self.dir / "constitution.signed.json")
        signed = verify_signed(envelope, load_private_key_file(self.key).public_key())
        self.assertTrue(signed.tool_specs["tool_a"]["irreversible"])
        self.assertTrue(private(self.dir / "constitution.signed.json"))
        body = self.changes()[-1].body
        self.assertEqual((body["signed"], body["constitution_hash"]), (True, signed.digest))
        self.assertEqual({f["role"] for f in body["files"]}, {"rules", "constitution"})

    def test_no_typed_yes_no_signature(self):
        self.refused("not_confirmed", "tool_specs.tool_a.irreversible", True, key_path=str(self.key),
                     rules_path=str(self.rules), confirm=self.confirm(False))

    def test_a_looser_rule_is_weaker(self):
        self.refused("weaker: tool_specs.tool_a.data_class_floor", "tool_specs.tool_a.data_class_floor", "public",
                     key_path=str(self.key), rules_path=str(self.rules))
        result, _, _ = self.signed("hard_rules[1]", {"id": "cap", "deny_if": {"amount_usd_gt": 100}})
        self.assertEqual(result["weaker"], [], "a new rule only adds a deny")
        self.refused("weaker: hard_rules: a rule was changed or removed", "hard_rules[1].deny_if.amount_usd_gt", 500,
                     key_path=str(self.key), rules_path=str(self.rules))

    def test_a_rule_that_does_not_sign_is_refused(self):
        self.refused("constitution_refused", "tool_specs.tool_a.data_class_floor", "secret-ish",
                     key_path=str(self.key), rules_path=str(self.rules))

    def test_undo_of_a_signed_change_needs_the_key(self):
        before = (self.dir / "constitution.signed.json").read_bytes()
        self.signed("tool_specs.tool_a.irreversible", True)
        with self.assertRaisesRegex(ConfigChangeError, "principal_key_needed"):
            quiet(config_set.undo, self.proxy, confirm=self.confirm(), environ={})
        quiet(config_set.undo, self.proxy, key_path=str(self.key), confirm=self.confirm(), confirm_weaker=True,
              environ={})
        self.assertEqual((self.dir / "constitution.signed.json").read_bytes(), before)


class Undo(Deployment):
    def undo(self, **kw):
        kw.setdefault("confirm", self.confirm())
        kw.setdefault("environ", {})
        return quiet(config_set.undo, self.proxy, **kw)

    def test_undo_puts_it_back_and_undo_again_puts_the_change_back(self):
        first = self.proxy.read_bytes()
        self.set("ttl_seconds", 60)
        changed = self.proxy.read_bytes()
        self.undo(confirm_weaker=True)
        self.assertEqual(self.proxy.read_bytes(), first)
        self.undo()
        self.assertEqual(self.proxy.read_bytes(), changed)
        self.assertEqual([e.body["command"] for e in self.changes()], ["setup", "set", "undo", "undo"])

    def test_undo_that_weakens_needs_the_flag(self):
        self.set("ttl_seconds", 60)
        with self.assertRaisesRegex(ConfigChangeError, "weaker: ttl_seconds"):
            self.undo()

    def test_a_file_changed_since_is_not_overwritten(self):
        self.set("ttl_seconds", 60)
        self.proxy.write_bytes(self.proxy.read_bytes() + b"agent_id: by-hand\n")
        with self.assertRaisesRegex(ConfigChangeError, "undo_stale"):
            self.undo()

    def test_nothing_to_undo(self):
        with self.assertRaisesRegex(ConfigChangeError, "nothing_to_undo"):
            self.undo()


class CommandLine(Deployment):
    def test_get_and_a_refusal_are_one_line_each(self):
        code, out, _ = quiet(cli.main, ["config", "get", "--config", str(self.proxy), "on_agent_access"])
        self.assertEqual((code, json.loads(out)["value"]), (0, "refuse"))
        code, out, err = quiet(cli.main, ["config", "set", "--config", str(self.proxy), "ttl_seconds", "300"])
        self.assertEqual(code, 1)
        self.assertIn("two-key: config set: refused: weaker", err)

    def test_setup_without_a_terminal_needs_answers(self):
        with mock.patch("sys.stdin", io.StringIO("")):
            code, _, err = quiet(cli.main, ["setup", "--dir", str(self.base / "x")])
        self.assertEqual(code, 1)
        self.assertIn("--answers", err)


if __name__ == "__main__":
    unittest.main()
