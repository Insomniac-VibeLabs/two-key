# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""``two-key constitution-editor`` without a window (two_key/constitution_editor.py, and its ``--check`` mode).

What the editor checks is what ``sign_constitution`` checks, what it signs is what ``two-key sign-constitution``
signs from the files it writes, and a trial call goes through ``TwoKey.authorize`` on a throwaway ledger.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from two_key import cli
from two_key import constitution_editor as ce
from two_key.canonical import canonical_hash
from two_key.constitution import (load_envelope, load_serial, load_unsigned_with_fields, sign_constitution,
                                  verify_signed)
from two_key.keys import generate_private_key, save_private_key, save_public_key
from two_key.strict import load_file_strict

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def draft_with_tools() -> ce.Draft:
    draft = ce.new_draft()
    ce.set_tool(draft, "search", ce.build_spec(False, "public", False, {}))
    ce.set_tool(draft, "pay_vendor", ce.build_spec(True, "financial", False, {
        "amount": {"json_path": "amount", "unit": "usd"},
        "counterparties": [{"json_path": "to", "allow": ["power-co.example"]}]}))
    draft.rules.append(ce.build_rule("spend-cap", "deny_if", {"amount_usd_gt": 200}))
    return draft


class Drafts(unittest.TestCase):
    def test_a_new_draft_has_the_starter_prose_and_needs_a_tool(self):
        draft = ce.new_draft()
        self.assertIn("Vote yes only when", draft.prose)
        self.assertEqual(draft.serial, 1)
        report = ce.check(draft)
        self.assertFalse(report.ok)
        self.assertIn("allow_only_tools", report.error)

    def test_a_draft_with_tools_signs_as_v3_with_its_serial(self):
        report = ce.check(draft_with_tools())
        self.assertTrue(report.ok, report.error)
        self.assertEqual(report.envelope_format, "two-key-constitution-v3")
        self.assertEqual(report.body["serial"], 1)
        self.assertEqual(report.digest, canonical_hash(report.body))
        # The signed allow list is sorted.
        self.assertEqual(report.body["hard_rules"][0], {"id": "tools", "allow_only_tools": ["pay_vendor", "search"]})

    def test_the_check_signs_the_same_body_as_sign_constitution(self):
        draft = draft_with_tools()
        envelope = sign_constitution(draft.prose, draft.rules, generate_private_key(), draft.tool_specs,
                                     serial=draft.serial)
        self.assertEqual(ce.check(draft).body, envelope["signed"])

    def test_without_a_serial_it_warns(self):
        draft = draft_with_tools()
        draft.serial = None
        report = ce.check(draft)
        self.assertTrue(report.ok)
        self.assertEqual(report.envelope_format, "two-key-constitution-v1")
        self.assertEqual(report.notes[0][0], "WARNING")
        self.assertIn("no serial", report.notes[0][1])

    def test_refusals(self):
        draft = draft_with_tools()
        draft.prose = "  \n"
        self.assertIn("prose is empty", ce.check(draft).error)
        draft = draft_with_tools()
        draft.envelope_format = "v9"
        self.assertIn("envelope format", ce.check(draft).error)
        draft = draft_with_tools()
        draft.serial = "two"
        self.assertFalse(ce.check(draft).ok)
        draft = draft_with_tools()
        draft.tool_specs["search"]["data_class_floor"] = "secret"
        self.assertFalse(ce.check(draft).ok)

    def test_notes_are_the_ones_sign_constitution_prints(self):
        draft = ce.open_sources(EXAMPLES / "constitution.md", EXAMPLES / "custom_fields.yaml")
        notes = ce.check(draft).notes
        self.assertTrue(any("not_applicable" in text for _, text in notes))

    def test_a_copy_is_independent(self):
        draft = draft_with_tools()
        other = draft.copy()
        other.tool_specs["search"]["irreversible"] = True
        self.assertIs(draft.tool_specs["search"]["irreversible"], False)


class ToolsAndRules(unittest.TestCase):
    def test_add_rename_and_remove_a_tool(self):
        draft = draft_with_tools()
        ce.set_tool(draft, "find", {"irreversible": False, "data_class_floor": "public"}, "search")
        self.assertEqual(ce.tool_names(draft), ["find", "pay_vendor"])
        self.assertIn("find", draft.tool_specs)
        self.assertNotIn("search", draft.tool_specs)
        ce.remove_tool(draft, "find")
        self.assertEqual(ce.tool_names(draft), ["pay_vendor"])
        self.assertTrue(ce.check(draft).ok)

    def test_a_tool_needs_a_new_id(self):
        draft = draft_with_tools()
        spec = {"irreversible": True, "data_class_floor": "public"}
        with self.assertRaises(ce.EditorError):
            ce.set_tool(draft, "search", spec)
        with self.assertRaises(ce.EditorError):
            ce.set_tool(draft, "  ", spec)
        ce.set_tool(draft, "search", spec, "search")
        self.assertIs(draft.tool_specs["search"]["irreversible"], True)

    def test_an_allow_list_is_added_when_there_is_none(self):
        draft = ce.Draft(prose="p")
        ce.set_tool(draft, "search", {"irreversible": False, "data_class_floor": "public"})
        self.assertEqual(draft.rules, [{"id": "tools", "allow_only_tools": ["search"]}])

    def test_a_spec_with_no_allow_list_entry_is_still_listed(self):
        draft = ce.Draft(prose="p", rules=[{"allow_only_tools": ["a"]}], tool_specs={"a": {}, "b": {}})
        self.assertEqual(ce.tool_names(draft), ["a", "b"])
        self.assertFalse(ce.check(draft).ok)

    def test_spec_form_and_build_spec(self):
        spec = ce.build_spec(True, "personal", True, {"payload": [{"json_path": "body"}]})
        self.assertEqual(spec, {"irreversible": True, "data_class_floor": "personal", "deny_unmapped": True,
                                "payload": [{"json_path": "body"}]})
        known, rest = ce.spec_form(spec)
        self.assertEqual(set(known), {"irreversible", "data_class_floor", "deny_unmapped"})
        self.assertEqual(rest, {"payload": [{"json_path": "body"}]})
        self.assertNotIn("deny_unmapped", ce.build_spec(False, "public", False, {}))
        mappings = {"irreversible": False}
        with self.assertRaises(ce.EditorError):
            ce.build_spec(True, "public", False, mappings)

    def test_rules_build_summarise_and_move(self):
        rule = ce.build_rule(" cap ", "deny_if", {"amount_usd_gt": 5})
        self.assertEqual(rule, {"id": "cap", "deny_if": {"amount_usd_gt": 5}})
        self.assertEqual(ce.build_rule("", "deny_if_irreversible_over", 3), {"deny_if_irreversible_over": 3})
        self.assertEqual(ce.rule_type(rule), "deny_if")
        self.assertEqual(ce.rule_summary(rule), "amount_usd_gt: 5")
        self.assertEqual(ce.rule_type({"deny_if": {}, "allow_only_tools": []}), "?")
        self.assertIn("odd", ce.rule_summary({"odd": 1}))
        with self.assertRaises(ce.EditorError):
            ce.build_rule("x", "allow_everything", {})
        draft = draft_with_tools()
        self.assertEqual(ce.move_rule(draft, 1, -1), 0)
        self.assertEqual(draft.rules[0]["id"], "spend-cap")
        self.assertEqual(ce.move_rule(draft, 0, -1), 0)
        self.assertEqual(ce.move_rule(draft, 5, 1), 5)

    def test_every_rule_type_has_a_template(self):
        from two_key.policy_vm import RULE_TYPES
        self.assertEqual(set(ce.RULE_TEMPLATES), set(RULE_TYPES))

    def test_values_are_read_strictly(self):
        self.assertEqual(ce.parse_value("a: 1\nb: [x]\n", "v"), {"a": 1, "b": ["x"]})
        self.assertEqual(ce.parse_value('{"a": 1}', "v"), {"a": 1})
        self.assertEqual(ce.parse_value("  ", "v"), {})
        with self.assertRaises(ce.EditorError):
            ce.parse_value("a: 1\na: 2\n", "v")
        self.assertEqual(ce.dump_value({}), "")
        self.assertEqual(ce.dump_value(None), "")
        self.assertEqual(ce.dump_value({"a": 1}), "a: 1\n")


class Opening(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.key = generate_private_key()
        save_public_key(self.dir / "principal.pub.pem", self.key.public_key())

    def test_open_the_examples(self):
        draft = ce.open_sources(EXAMPLES / "constitution.md", EXAMPLES / "hard_rules.yaml")
        document = load_file_strict(EXAMPLES / "hard_rules.yaml")
        self.assertEqual(draft.prose, (EXAMPLES / "constitution.md").read_text(encoding="utf-8"))
        self.assertEqual(draft.rules, document["hard_rules"])
        self.assertEqual(draft.tool_specs, document["tool_specs"])
        self.assertIsNone(draft.serial)

    def test_unreadable_sources_are_refused(self):
        missing = self.dir / "missing.yaml"
        with self.assertRaises(ce.EditorError):
            ce.open_sources(EXAMPLES / "constitution.md", missing)
        for doc in ([1], {"hard_rules": [], "tool_specs": {}, "extra": 1}, {"hard_rules": {}, "tool_specs": {}},
                    {"hard_rules": [], "tool_specs": []}, {"hard_rules": [], "tool_specs": {}, "fields": []}):
            with self.subTest(doc=doc), self.assertRaises(ce.EditorError):
                ce.draft_from("p", doc)

    def test_open_a_signed_constitution_as_its_next_version(self):
        draft = draft_with_tools()
        draft.serial = 4
        path = self.dir / "c.json"
        path.write_text(json.dumps(sign_constitution(draft.prose, draft.rules, self.key, draft.tool_specs,
                                                     serial=4)))
        opened, said = ce.open_signed(path, self.key.public_key())
        self.assertEqual(opened.serial, 5)
        self.assertEqual(opened.tool_specs, draft.tool_specs)       # without the defaults signing fills in
        self.assertIn("signature checked", said)
        self.assertIn("serial 4, the new version gets 5", said)
        _, said = ce.open_signed(path)
        self.assertIn("not checked", said)
        other = generate_private_key().public_key()
        with self.assertRaises(ce.EditorError):
            ce.open_signed(path, other)

    def test_a_reopened_constitution_signs_the_same_body_again(self):
        for rules in ("hard_rules.yaml", "custom_fields.yaml"):
            with self.subTest(rules=rules):
                prose, hard, specs, fields = load_unsigned_with_fields(EXAMPLES / "constitution.md", EXAMPLES / rules)
                envelope = sign_constitution(prose, hard, self.key, specs, fields=fields, serial=7)
                path = self.dir / "c.json"
                path.write_text(json.dumps(envelope))
                opened, _ = ce.open_signed(path)
                opened.serial = 7
                self.assertEqual(ce.check(opened).body, envelope["signed"])

    def test_tidy_spec_keeps_what_is_not_a_default(self):
        self.assertEqual(ce.tidy_spec({"irreversible": True, "data_class_floor": "public", "amount": None,
                                       "counterparties": [], "payload": [{"json_path": "b", "shape": None}],
                                       "deny_unmapped": True}),
                         {"irreversible": True, "data_class_floor": "public", "payload": [{"json_path": "b"}],
                          "deny_unmapped": True})
        self.assertEqual(ce.tidy_spec("odd"), "odd")

    def test_a_signed_constitution_without_a_serial_opens_as_serial_1(self):
        draft = draft_with_tools()
        path = self.dir / "c.json"
        path.write_text(json.dumps(sign_constitution(draft.prose, draft.rules, self.key, draft.tool_specs)))
        opened, said = ce.open_signed(path)
        self.assertEqual(opened.serial, 1)
        self.assertIn("serial none", said)

    def test_a_file_that_is_not_a_signed_constitution_is_refused(self):
        path = self.dir / "c.json"
        path.write_text('{"format": "x"}')
        with self.assertRaises(ce.EditorError):
            ce.open_signed(path)
        path.write_text('{"a": 1, "a": 2}')
        with self.assertRaises(ce.EditorError):
            ce.open_signed(path)


class Signing(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.key = generate_private_key()

    def test_sign_and_save_writes_three_files_that_sign_again_the_same(self):
        saved = ce.sign_and_save(draft_with_tools(), self.key, self.dir)
        envelope = load_envelope(saved.signed)
        signed = verify_signed(envelope, self.key.public_key())
        self.assertEqual(signed.digest, saved.digest)
        self.assertEqual(saved.envelope_format, "two-key-constitution-v3")
        prose, rules, specs, fields = load_unsigned_with_fields(saved.prose, saved.rules)
        again = sign_constitution(prose, rules, self.key, specs, fields=fields, serial=load_serial(saved.rules))
        self.assertEqual(canonical_hash(again["signed"]), saved.digest)
        self.assertEqual(Path(saved.prose).name, "constitution.md")
        self.assertEqual(Path(saved.rules).name, "hard_rules.yaml")
        written = Path(saved.rules).read_text(encoding="utf-8")
        self.assertTrue(written.startswith("# Written by two-key constitution-editor"))
        if os.name == "posix":
            self.assertEqual(os.stat(saved.rules).st_mode & 0o077, 0)

    def test_a_json_rules_file(self):
        saved = ce.sign_and_save(draft_with_tools(), self.key, self.dir, {"rules": "rules.json"})
        self.assertEqual(json.loads(Path(saved.rules).read_text(encoding="utf-8"))["serial"], 1)

    def test_existing_files_need_overwrite(self):
        ce.sign_and_save(draft_with_tools(), self.key, self.dir)
        draft = draft_with_tools()
        draft.serial = 2
        with self.assertRaises(ce.EditorError) as caught:
            ce.sign_and_save(draft, self.key, self.dir)
        self.assertIn("already there", str(caught.exception))
        self.assertEqual(load_envelope(self.dir / "constitution.signed.json")["signed"]["serial"], 1)
        ce.sign_and_save(draft, self.key, self.dir, overwrite=True)
        self.assertEqual(load_envelope(self.dir / "constitution.signed.json")["signed"]["serial"], 2)

    def test_nothing_is_written_for_a_draft_that_does_not_sign(self):
        draft = ce.new_draft()
        with self.assertRaises(ce.EditorError):
            ce.sign_and_save(draft, self.key, self.dir)
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_folder_and_names_are_checked(self):
        draft = draft_with_tools()
        missing = self.dir / "missing"
        with self.assertRaises(ce.EditorError):
            ce.sign_and_save(draft, self.key, missing)
        same = {"rules": "x", "signed": "x"}
        with self.assertRaises(ce.EditorError):
            ce.sign_and_save(draft, self.key, self.dir, same)
        unknown = {"other": "x"}
        with self.assertRaises(ce.EditorError):
            ce.target_paths(self.dir, unknown)
        self.assertEqual(ce.target_paths(self.dir, {"prose": ""})["prose"].name, "constitution.md")

    def test_a_folder_that_cannot_be_written_is_refused_in_words(self):
        draft = draft_with_tools()
        denied = PermissionError(13, "Permission denied")
        with mock.patch.object(ce, "_write_text", side_effect=denied), \
                self.assertRaisesRegex(ce.EditorError, "not signed: .*Permission denied"):
            ce.sign_and_save(draft, self.key, self.dir)
        with mock.patch.object(ce, "_write_text", side_effect=denied), \
                self.assertRaisesRegex(ce.EditorError, "not saved: .*Permission denied"):
            ce.save_sources(draft, self.dir)
        with mock.patch.object(ce, "save_envelope", side_effect=denied), \
                self.assertRaisesRegex(ce.EditorError, "not signed: .*Permission denied"):
            ce.sign_and_save(draft, self.key, self.dir, overwrite=True)
        self.assertFalse((self.dir / "constitution.signed.json").exists())

    def test_files_that_do_not_read_back_are_refused_in_words(self):
        paths = ce.target_paths(self.dir)
        with self.assertRaisesRegex(ce.EditorError, "do not read back"):
            ce.same_from_files(paths, {"prose": "x"})

    def test_rules_that_do_not_read_back_the_same_are_refused_before_the_signed_file(self):
        draft = draft_with_tools()
        paths = ce.target_paths(self.dir)
        paths["prose"].write_text(draft.prose)
        paths["rules"].write_text(ce.rules_text(draft))
        other = {"prose": "something else"}
        with self.assertRaises(ce.EditorError):
            ce.same_from_files(paths, other)

    def test_save_sources_writes_prose_and_rules_unsigned(self):
        written = ce.save_sources(ce.new_draft(), self.dir)
        self.assertEqual(sorted(Path(p).name for p in written), ["constitution.md", "hard_rules.yaml"])
        self.assertFalse((self.dir / "constitution.signed.json").exists())
        again = ce.new_draft()
        with self.assertRaises(ce.EditorError):
            ce.save_sources(again, self.dir)
        self.assertEqual(len(ce.save_sources(ce.new_draft(), self.dir, overwrite=True)), 2)


class TryingACall(unittest.TestCase):
    def test_path_a_denies_and_the_judge_prompt_is_shown(self):
        trial = ce.try_call(draft_with_tools(), "pay_vendor", {"amount": 500, "to": "power-co.example"})
        self.assertIs(trial.path_a_allowed, False)
        self.assertEqual(trial.path_a_reason, "rule_denied:spend-cap")
        self.assertIn("<principal_constitution>\nVote yes only when", trial.user_prompt)
        self.assertIn('"amount_usd":500.0', trial.user_prompt)
        self.assertIn("Path B judge", trial.system_prompt)
        text = trial.text()
        self.assertIn("Path A denies the call: rule_denied:spend-cap", text)
        self.assertIn("System prompt:", text)

    def test_an_allowed_call(self):
        trial = ce.try_call(draft_with_tools(), "pay_vendor", {"amount": 50, "to": "power-co.example"},
                            proposal="pay the power bill")
        self.assertIs(trial.path_a_allowed, True)
        self.assertEqual(trial.decision_reason, "both_paths_allow")
        # Record-only judge inputs by default: the proposal reaches only a judge set to receive it.
        self.assertNotIn("pay the power bill", trial.user_prompt)

    def test_a_call_refused_before_the_judges(self):
        trial = ce.try_call(draft_with_tools(), "pay_vendor", {"amount": "lots", "to": "power-co.example"})
        self.assertIn("derive_failed", trial.decision_reason)
        self.assertEqual(trial.user_prompt, "")
        self.assertIn("No judge was asked", trial.text())

    def test_a_draft_that_does_not_sign_is_not_tried(self):
        draft = ce.new_draft()
        with self.assertRaises(ce.EditorError):
            ce.try_call(draft, "x", {})

    def test_claims(self):
        specs = {"t": {"data_class_floor": "personal"}}
        self.assertEqual(ce.claim_for("t", "none", specs), {"tool": "t"})
        self.assertEqual(ce.claim_for("t", "floor", specs), {"tool": "t", "data_class": "personal"})
        self.assertEqual(ce.claim_for("u", "floor", specs), {"tool": "u", "data_class": "classified"})
        self.assertEqual(ce.claim_for("t", "medical", specs), {"tool": "t", "data_class": "medical"})


class CheckCommand(unittest.TestCase):
    @staticmethod
    def run_cli(*argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["constitution-editor", *argv])
        return code, out.getvalue()

    def test_check_the_examples(self):
        code, out = self.run_cli("--check", "--prose", str(EXAMPLES / "constitution.md"),
                                 "--rules", str(EXAMPLES / "custom_fields.yaml"))
        self.assertEqual(code, 0)
        self.assertIn("signs as two-key-constitution-v3, digest ", out)
        self.assertIn("WARNING: no serial", out)

    def test_check_a_new_draft_does_not_sign(self):
        code, out = self.run_cli("--check")
        self.assertEqual(code, 1)
        self.assertIn("does not sign", out)

    def test_check_a_signed_constitution_with_its_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            save_public_key(Path(tmp) / "p.pub.pem", key.public_key())
            save_private_key(Path(tmp) / "p.pem", key)
            saved = ce.sign_and_save(draft_with_tools(), key, tmp)
            code, out = self.run_cli("--check", "--signed", saved.signed, "--public-key", str(Path(tmp) / "p.pub.pem"))
        self.assertEqual(code, 0)
        self.assertIn("signs as", out)

    def test_without_tkinter_it_says_what_to_use(self):
        err = io.StringIO()
        with mock.patch.dict(sys.modules, {"two_key.constitution_gui": None}), contextlib.redirect_stderr(err):
            code, _ = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("--check", err.getvalue())

    def test_wrong_combinations_are_refused(self):
        prose = str(EXAMPLES / "constitution.md")
        for argv in (["--prose", prose], ["--signed", "x", "--prose", prose, "--rules", prose],
                     ["--prose", prose, "--rules", str(EXAMPLES / "missing.yaml")]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit):
                self.run_cli(*argv)


if __name__ == "__main__":
    unittest.main()
