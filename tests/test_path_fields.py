# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""``path`` fields: any file inside a signed folder (0.9.0).

Path A cleans a path up as text only and refuses what it cannot clean up safely (``..``, relative paths, a
backslash, non-ASCII). The tool receives the cleaned path. Just before the tool runs, the gateway refuses a path
that reaches through a link below its folder. The table in docs/HOWTO.md is checked here row by row.
"""

import json
import os
import posixpath
import random
import re
import tempfile
import unittest
from pathlib import Path

from two_key.agents import tool_vocabulary
from two_key.canonical import canonical_bytes
from two_key.constitution import FORMAT_V2, sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.fields import (FieldError, FieldValueError, case_warnings, clean_path, coerce_value, path_inside,
                            path_notes, validate_fields)
from two_key.gateway import linked_path
from two_key.keys import generate_private_key, sign
from two_key.ledger import Ledger
from two_key.policy_vm import ConstitutionError
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

ROOT = Path(__file__).resolve().parent.parent
HOWTO = ROOT / "docs" / "HOWTO.md"
V3 = "two-key-constitution-v3"
NOTES = "/home/agent/notes"
FIELDS = {"note_path": {"type": "path", "under": [NOTES], "default": NOTES}}
RULES = [{"id": "tools", "allow_only_tools": ["write_file", "search"]},
         {"id": "no-private", "deny_if_fields": {"note_path": {"under": NOTES + "/private"}}}]
SPECS = {"write_file": {"irreversible": False, "data_class_floor": "personal",
                        "fields": {"note_path": {"json_path": "path"}},
                        "payload": [{"json_path": "content", "shape": "string"}]},
         "search": {"irreversible": False, "data_class_floor": "public",
                    "fields": {"note_path": "not_applicable"},
                    "payload": [{"json_path": "q", "shape": "string"}]}}
WRITE = {"tool": "write_file", "data_class": "personal", "irreversible": False}


def signed(fields=FIELDS, rules=RULES, specs=SPECS, **kw):  # skipcq: PYL-W0102 - test only
    return sign_constitution("p", rules, generate_private_key(), specs, fields=fields, **kw)


def vectors() -> list[tuple[str, str]]:
    text = HOWTO.read_text(encoding="utf-8")
    block = text.split("<!-- path-vectors -->", 1)[1].split("<!-- /path-vectors -->", 1)[0]
    rows = re.findall(r"^\| `(.*)` \| `(.*)` \|$", block, re.MULTILINE)
    return [(re.sub(r"\\u([0-9a-f]{4})", lambda m: chr(int(m.group(1), 16)), value), result)
            for value, result in rows]


def outcome(value: str, defn: dict) -> str:
    try:
        return coerce_value(defn, value)
    except FieldValueError as e:
        return e.kind


class Vectors(unittest.TestCase):
    def test_every_row_of_the_howto_table(self):
        rows = vectors()
        self.assertGreaterEqual(len(rows), 20)
        defn = validate_fields(FIELDS)["note_path"]
        for value, result in rows:
            with self.subTest(value=value):
                self.assertEqual(outcome(value, defn), result)

    def test_more_than_a_string_or_a_long_path(self):
        defn = validate_fields(FIELDS)["note_path"]
        cases = [42, None, True, [NOTES + "/a"], {"p": NOTES}, NOTES + "/" + "a" * 256,
                 NOTES + "/a" * 70, NOTES + "/" + "a/" * 2100]
        for value in cases:
            with self.subTest(value=str(value)[:40]):
                self.assertEqual(outcome(value, defn), "field_unreadable")


class Cleanup(unittest.TestCase):
    PARTS = ("/", "//", ".", "..", "notes", "home", "agent", "a", "A", "~", " ", "\\", "x.txt", "...")

    def test_randomized_cleanup_is_the_os_normal_form_and_stays_inside(self):
        rng = random.Random(20261030)
        accepted = 0
        for _ in range(5000):
            raw = "".join(rng.choice(self.PARTS) for _ in range(rng.randint(1, 10)))
            if rng.random() < 0.5:
                raw = NOTES + "/" + raw
            try:
                got = clean_path(raw)
            except FieldValueError:
                continue
            accepted += 1
            self.assertEqual(posixpath.normpath(got), got)
            self.assertNotIn("..", got.split("/"))
            self.assertEqual(clean_path(got), got)
            self.assertEqual(got, "/" + posixpath.normpath(raw).lstrip("/"))
            if path_inside(got, NOTES):
                self.assertEqual(posixpath.commonpath([got, NOTES]), NOTES)
        self.assertGreater(accepted, 500)

    def test_inside_is_whole_segments(self):
        self.assertTrue(path_inside(NOTES, NOTES))
        self.assertTrue(path_inside(NOTES + "/a/b", NOTES))
        self.assertIs(path_inside(NOTES + "2/a", NOTES), False)
        self.assertIs(path_inside("/home/agent", NOTES), False)


class Definition(unittest.TestCase):
    def test_refused_definitions(self):
        bad = [({"type": "path", "default": NOTES}, "under: expected a non-empty list"),
               ({"type": "path", "under": [], "default": NOTES}, "under: expected a non-empty list"),
               ({"type": "path", "under": ["/"], "default": "/"}, "/ admits every path"),
               ({"type": "path", "under": [NOTES + "/"], "default": NOTES}, "clean form"),
               ({"type": "path", "under": ["notes"], "default": NOTES}, "not a path this field can hold"),
               ({"type": "path", "under": [NOTES, NOTES + "/a"], "default": NOTES}, "inside another"),
               ({"type": "path", "under": [NOTES, NOTES], "default": NOTES}, "listed twice"),
               ({"type": "path", "under": [NOTES], "default": "/etc"}, "default: not a valid value"),
               ({"type": "path", "under": [NOTES], "default": NOTES, "case": "exact"}, "expected insensitive"),
               ({"type": "path", "under": ["/Home"], "default": "/home", "case": "insensitive"}, "clean form"),
               ({"type": "path", "under": [NOTES], "default": NOTES, "max_length": 9}, "unknown key"),
               ({"type": "path", "under": ["/a"] * 17, "default": "/a"}, "more than 16 folders")]
        for defn, msg in bad:
            with self.subTest(defn=defn), self.assertRaisesRegex(FieldError, msg):
                validate_fields({"p": defn})

    def test_refused_rule_paths(self):
        bad = [({"under": "/etc"}, "could never apply"),
               ({"under": NOTES + "/private/"}, "clean form"),
               ({"in": [NOTES + "/a", "/tmp/a"]}, "could never apply"),
               ({"under": NOTES + "/../x"}, "not a path"),
               ({"gt": NOTES}, "not valid for path")]
        for ops, msg in bad:
            rules = [RULES[0], {"id": "r", "deny_if_fields": {"note_path": ops}}]
            with self.subTest(ops=ops), self.assertRaisesRegex(ConstitutionError, msg):
                signed(rules=rules)

    def test_signs_as_v3_only(self):
        env = signed()
        self.assertEqual(env["format"], V3)
        self.assertEqual(env["signed"]["fields"]["note_path"]["under"], [NOTES])
        with self.assertRaisesRegex(ConstitutionError, "need a v3"):
            signed(envelope_format="v2")
        key = generate_private_key()
        relabelled = {"format": FORMAT_V2, "signed": env["signed"], "fingerprint": "x",
                      "signature": sign(key, canonical_bytes(env["signed"]))}
        pub = key.public_key()
        with self.assertRaisesRegex(ConstitutionError, "need a v3"):
            verify_signed(relabelled, pub)


class Calls(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.got = []

    def two_key(self, fields=FIELDS, rules=RULES):  # skipcq: PYL-W0102 - test only
        key = generate_private_key()
        con = verify_signed(sign_constitution("p", rules, key, SPECS, fields=fields), key.public_key())
        tk = TwoKey(Ledger(self.tmp / f"ledger{len(self.got)}{id(fields)}", key), key.public_key(), con,
                    [FixedJudge("a", "yes")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                    allow_test_doubles=True, monitored_agent=TEST_AGENT)
        return tk, tk.gateway(tools={"write_file": self.got.append, "search": self.got.append})

    def test_the_tool_gets_the_cleaned_path(self):
        tk, gw = self.two_key()
        args = {"path": "/home//agent/./notes/todo.txt", "content": "milk"}
        d = tk.authorize(WRITE, args, "write a note")
        self.assertTrue(d.allowed, d.reason)
        self.assertTrue(gw.invoke(d.token, "write_file", args).allowed)
        self.assertEqual(self.got, [{"path": NOTES + "/todo.txt", "content": "milk"}])

    def test_outside_the_folder_tricks_and_the_denied_subfolder(self):
        tk, _ = self.two_key()
        cases = {NOTES + "/../.ssh/authorized_keys": "derive_failed:field_unreadable:note_path",
                 "todo.txt": "derive_failed:field_unreadable:note_path",
                 NOTES + "2/todo.txt": "derive_failed:field_not_allowed:note_path",
                 NOTES + "/private/diary.txt": "rule_denied:no-private",
                 NOTES + "/private": "rule_denied:no-private"}
        for path, reason in cases.items():
            with self.subTest(path=path):
                self.assertEqual(tk.authorize(WRITE, {"path": path, "content": "x"}, "write").reason, reason)
        self.assertTrue(tk.authorize(WRITE, {"path": NOTES + "/privately.txt", "content": "x"}, "write").allowed)
        self.assertEqual(self.got, [])

    def test_a_tool_that_marks_the_field_not_applicable_is_not_denied(self):
        tk, _ = self.two_key()
        d = tk.authorize({"tool": "search", "data_class": "public", "irreversible": False}, {"q": "milk"}, "find")
        self.assertTrue(d.allowed, d.reason)

    def test_not_under_and_in(self):
        rules = [RULES[0], {"id": "only-inbox", "deny_if_fields": {"note_path": {"not_under": NOTES + "/inbox"}}},
                 {"id": "not-these", "deny_if_fields": {"note_path": {"in": [NOTES + "/inbox/keep.txt"]}}}]
        tk, _ = self.two_key(rules=rules)
        cases = {NOTES + "/inbox/a.txt": "both_paths_allow", NOTES + "/a.txt": "rule_denied:only-inbox",
                 NOTES + "/inbox/keep.txt": "rule_denied:not-these"}
        for path, reason in cases.items():
            with self.subTest(path=path):
                self.assertEqual(tk.authorize(WRITE, {"path": path, "content": "x"}, "write").reason, reason)

    def test_case_insensitive(self):
        fields = {"note_path": dict(FIELDS["note_path"], case="insensitive")}
        tk, gw = self.two_key(fields=fields)
        args = {"path": "/Home/Agent/Notes/ToDo.txt", "content": "x"}
        d = tk.authorize(WRITE, args, "write")
        self.assertTrue(d.allowed, d.reason)
        self.assertTrue(gw.invoke(d.token, "write_file", args).allowed)
        self.assertEqual(self.got[0]["path"], NOTES + "/todo.txt")
        d = tk.authorize(WRITE, {"path": NOTES + "/PRIVATE/a", "content": "x"}, "write")
        self.assertEqual(d.reason, "rule_denied:no-private")


@unittest.skipUnless(hasattr(os, "symlink") and os.name == "posix", "needs POSIX symlinks")
class Links(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(os.path.realpath(tmp.name))
        self.notes = base / "notes"
        (self.notes / "sub").mkdir(parents=True)
        (base / "outside").mkdir()
        os.symlink(base / "outside", self.notes / "out")
        os.symlink(base / "missing", self.notes / "dangling")
        os.symlink(self.notes, base / "notes-link")
        self.base = base
        self.got = []

    def test_linked_path(self):
        folder = [str(self.notes)]
        self.assertIs(linked_path(str(self.notes / "sub" / "a.txt"), folder), False)
        self.assertIs(linked_path(str(self.notes / "new" / "a.txt"), folder), False)
        self.assertIs(linked_path(str(self.notes), folder), False)
        self.assertIs(linked_path(str(self.notes / "out" / "a.txt"), folder), True)
        self.assertIs(linked_path(str(self.notes / "out"), folder), True)
        self.assertIs(linked_path(str(self.notes / "dangling"), folder), True)
        self.assertIs(linked_path("/elsewhere/a", folder), True)
        linked_folder = [str(self.base / "notes-link")]      # the folder itself may be a link
        self.assertIs(linked_path(str(self.base / "notes-link" / "sub" / "a.txt"), linked_folder), False)

    def test_the_tool_does_not_run_through_a_link(self):
        fields = {"note_path": {"type": "path", "under": [str(self.notes)], "default": str(self.notes)}}
        key = generate_private_key()
        con = verify_signed(sign_constitution("p", RULES[:1], key, SPECS, fields=fields), key.public_key())
        tk = TwoKey(Ledger(self.base / "ledger", key), key.public_key(), con, [FixedJudge("a", "yes")],
                    private_key=key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                    monitored_agent=TEST_AGENT)
        gw = tk.gateway(tools={"write_file": self.got.append, "search": self.got.append})
        args = {"path": str(self.notes / "out" / "a.txt"), "content": "x"}
        d = tk.authorize(WRITE, args, "write")
        self.assertTrue(d.allowed, d.reason)           # Path A reads text only
        result = gw.invoke(d.token, "write_file", args)
        self.assertEqual(result.reason, "path_symlink:note_path")
        args = {"path": str(self.notes / "sub" / "a.txt"), "content": "x"}
        d = tk.authorize(WRITE, args, "write")
        self.assertTrue(gw.invoke(d.token, "write_file", args).allowed)
        self.assertEqual(self.got, [args])


class Notes(unittest.TestCase):
    def test_signing_names_the_folders_and_warns_about_case(self):
        s = signed()["signed"]
        notes = path_notes(s["tool_specs"], s["fields"])
        self.assertEqual(len(notes), 1)
        self.assertIn(f"tool 'write_file': note_path admits any path inside {NOTES}", notes[0])
        warned = case_warnings(s["hard_rules"], s["tool_specs"], s["fields"])
        self.assertEqual(len(warned), 1)
        self.assertIn("rule 'no-private': the path field note_path is compared exactly", warned[0])
        fields = {"note_path": dict(FIELDS["note_path"], case="insensitive")}
        s = signed(fields=fields)["signed"]
        self.assertEqual(case_warnings(s["hard_rules"], s["tool_specs"], s["fields"]), [])

    def test_the_agent_vocabulary_gives_the_syntax_not_the_folder(self):
        key = generate_private_key()
        con = verify_signed(sign_constitution("p", RULES, key, SPECS, fields=FIELDS), key.public_key())
        text = tool_vocabulary(con)
        entry = json.loads(text.split("\n", 1)[1])["tools"]["write_file"]["fields"]["note_path"]
        self.assertIn("absolute file path", entry["value"])
        self.assertNotIn(NOTES, text)


if __name__ == "__main__":
    unittest.main()
