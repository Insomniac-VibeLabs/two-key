# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""``case: exact`` string fields: compared, and passed to the tool, exactly as written (live run 6x, X19).

A case-insensitive ASCII field is lower-cased, and the tool receives the value Path A checked, so a
case-sensitive system of record refused a correct folder id. An exact field keeps the value as written. Signing
warns about the two mistakes around it: an exact field in a deny-list rule, and a lower-cased field mapped to an
identifier.
"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from two_key.agents import tool_vocabulary
from two_key.canonical import canonical_bytes
from two_key.cli import main
from two_key.constitution import FORMAT_V2, sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.fields import case_warnings
from two_key.keys import generate_private_key, sign
from two_key.ledger import Ledger
from two_key.policy_vm import ConstitutionError
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

V3 = "two-key-constitution-v3"
EXACT = {"folder": {"type": "string", "max_length": 64, "default": "", "case": "exact"}}
RULES = [{"id": "tools", "allow_only_tools": ["share_folder"]},
         {"id": "known-folders", "deny_if_fields": {"folder": {"not_in": ["FLD-WM-G5-Science", "FLD-WM-G5-Math"]}}}]
SPECS = {"share_folder": {"irreversible": False, "data_class_floor": "personal",
                          "fields": {"folder": {"json_path": "folder_id"}},
                          "payload": [{"json_path": "grantee", "shape": "string"}]}}
CLAIM = {"tool": "share_folder", "data_class": "personal", "irreversible": False}


def signed(fields=EXACT, rules=RULES, specs=SPECS, **kw):
    return sign_constitution("p", rules, generate_private_key(), specs, fields=fields, **kw)


class Definition(unittest.TestCase):
    def test_only_an_ascii_string_may_be_exact(self):
        bad = [({"type": "string", "max_length": 8, "default": "", "case": "Exact"}, "expected exact"),
               ({"type": "string", "max_length": 8, "default": "", "case": "insensitive"}, "expected exact"),
               ({"type": "string", "max_length": 8, "default": "", "case": "exact", "charset": "unicode",
                 "scripts": "latin"}, "only valid with charset: ascii"),
               ({"type": "enum", "values": ["a"], "default": "a", "case": "exact"}, "unknown key")]
        for defn, msg in bad:
            with self.subTest(defn=defn), self.assertRaisesRegex(ConstitutionError, msg):
                signed({"folder": defn})

    def test_rule_values_and_the_default_keep_their_case(self):
        env = signed(dict(EXACT, folder=dict(EXACT["folder"], default="FLD-None")))
        self.assertEqual(env["signed"]["fields"]["folder"]["default"], "FLD-None")
        self.assertEqual(env["signed"]["hard_rules"][1]["deny_if_fields"]["folder"]["not_in"],
                         ["FLD-WM-G5-Math", "FLD-WM-G5-Science"])

    def test_signs_as_v3_only(self):
        self.assertEqual(signed()["format"], V3)
        with self.assertRaisesRegex(ConstitutionError, "need a v3"):
            signed(envelope_format="v2")
        env = signed()
        key = generate_private_key()
        relabelled = {"format": FORMAT_V2, "signed": env["signed"], "fingerprint": "x",
                      "signature": sign(key, canonical_bytes(env["signed"]))}
        pub = key.public_key()
        with self.assertRaisesRegex(ConstitutionError, "need a v3"):
            verify_signed(relabelled, pub)
        insensitive = {"folder": {k: v for k, v in EXACT["folder"].items() if k != "case"}}
        rules = [RULES[0], {"id": "k", "deny_if_fields": {"folder": {"not_in": ["fld-a"]}}}]
        self.assertEqual(signed(insensitive, rules)["format"], FORMAT_V2)


class Calls(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        key = generate_private_key()
        con = verify_signed(sign_constitution("p", RULES, key, SPECS, fields=EXACT), key.public_key())
        self.tk = TwoKey(Ledger(Path(tmp.name, "ledger"), key), key.public_key(), con, [FixedJudge("a", "yes")],
                         private_key=key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                         monitored_agent=TEST_AGENT)
        self.got = []
        self.gw = self.tk.gateway(tools={"share_folder": self.got.append})

    def test_the_tool_gets_the_id_as_written(self):
        args = {"folder_id": "FLD-WM-G5-Science", "grantee": "j.ortiz"}
        d = self.tk.authorize(CLAIM, args, "share")
        self.assertTrue(d.allowed, d.reason)
        self.assertTrue(self.gw.invoke(d.token, "share_folder", args).allowed)
        self.assertEqual(self.got, [{"folder_id": "FLD-WM-G5-Science", "grantee": "j.ortiz"}])

    def test_a_case_variant_or_padding_is_another_value(self):
        for folder in ("fld-wm-g5-science", "FLD-WM-G5-SCIENCE", " FLD-WM-G5-Science"):
            with self.subTest(folder=folder):
                d = self.tk.authorize(CLAIM, {"folder_id": folder, "grantee": "j"}, "share")
                self.assertEqual(d.reason, "rule_denied:known-folders")
        d = self.tk.authorize(CLAIM, {"folder_id": "FLD\tX", "grantee": "j"}, "share")
        self.assertEqual(d.reason, "derive_failed:field_unreadable:folder")
        self.assertEqual(self.got, [])


class Warnings(unittest.TestCase):
    def warnings(self, fields, rules):
        s = signed(fields, rules)["signed"]
        return case_warnings(s["hard_rules"], s["tool_specs"], s["fields"])

    def test_an_exact_field_in_a_deny_list(self):
        got = self.warnings(EXACT, [RULES[0], {"id": "blocked", "deny_if_fields": {"folder": {"in": ["FLD-HR"]}}}])
        self.assertEqual(len(got), 1)
        self.assertIn("rule 'blocked': folder is case: exact and the rule lists values to deny", got[0])
        self.assertEqual(self.warnings(EXACT, RULES), [])          # not_in is an allow list

    def test_a_lower_cased_field_mapped_to_an_identifier(self):
        insensitive = {"folder": {k: v for k, v in EXACT["folder"].items() if k != "case"}}
        got = self.warnings(insensitive, [RULES[0], {"id": "k", "deny_if_fields": {"folder": {"not_in": ["a"]}}}])
        self.assertEqual(len(got), 1)
        self.assertIn("tool 'share_folder': the string field folder maps 'folder_id', which looks like an "
                      "identifier", got[0])

    def test_cli_prints_them_and_signs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "p.md").write_text("Share known folders only.", encoding="utf-8")
            rules = [RULES[0], {"id": "blocked", "deny_if_fields": {"folder": {"eq": "FLD-HR"}}}]
            (root / "r.json").write_text(json.dumps({"fields": EXACT, "hard_rules": rules, "tool_specs": SPECS}))
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["init-key", str(root / "keys")]), 0)
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc = main(["sign-constitution", "--key", str(root / "keys" / "principal.pem"), "--prose",
                           str(root / "p.md"), "--rules", str(root / "r.json"), "--out", str(root / "c.json")])
            self.assertEqual(rc, 0)
            self.assertIn("two-key: WARNING: rule 'blocked': folder is case: exact", err.getvalue())


class Vocabulary(unittest.TestCase):
    def test_the_agent_is_told_case_matters(self):
        key = generate_private_key()
        con = verify_signed(sign_constitution("p", RULES, key, SPECS, fields=EXACT), key.public_key())
        entry = json.loads(tool_vocabulary(con).split("\n", 1)[1])["tools"]["share_folder"]["fields"]["folder"]
        self.assertIn("letter case matters", entry["value"])
        self.assertNotIn("FLD-WM", tool_vocabulary(con))          # syntax only, never a value


if __name__ == "__main__":
    unittest.main()
