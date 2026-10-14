"""Signing warns when a tool does not map a field a deny_if_fields rule reads (live run 5, attempt 1).

An unmapped tool gets the field's signed default. A strict default denies that tool on every call; a
permissive one silently turns the rule off for it. The warning says which, and never changes the result.
"""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from two_key.cli import main
from two_key.constitution import sign_constitution
from two_key.fields import unmapped_rule_field_warnings
from two_key.keys import generate_private_key

FIELDS = {"po_matched": {"type": "boolean", "default": False},
          "env": {"type": "enum", "values": ["dev", "prod"], "default": "dev"}}
RULE = {"id": "po-mismatch", "deny_if_fields": {"po_matched": {"eq": False}}}


def warnings_for(rules, specs, fields=FIELDS):
    allow = {"id": "tools", "allow_only_tools": sorted(specs)}
    signed = sign_constitution("p", [allow, *rules], generate_private_key(), specs, fields=fields)["signed"]
    return unmapped_rule_field_warnings(signed["hard_rules"], signed["tool_specs"], signed["fields"])


class Warnings(unittest.TestCase):
    def test_strict_default_always_denies_an_unmapped_tool(self):
        specs = {"pay_vendor": {"irreversible": True, "data_class_floor": "financial",
                                "fields": {"po_matched": {"json_path": "po_matched"}}},
                 "lookup": {"irreversible": False, "data_class_floor": "public"}}
        got = warnings_for([RULE], specs)
        self.assertEqual(len(got), 1)
        self.assertIn("tool 'lookup' does not map po_matched (default po_matched=false)", got[0])
        self.assertIn("always denies it", got[0])

    def test_permissive_default_never_denies_an_unmapped_tool(self):
        specs = {"pay_vendor": {"irreversible": True, "data_class_floor": "financial"}}
        got = warnings_for([RULE], specs, {**FIELDS, "po_matched": {"type": "boolean", "default": True}})
        self.assertEqual(len(got), 1)
        self.assertIn("never denies it", got[0])

    def test_partly_mapped_rule_reads_the_default(self):
        rule = {"id": "r", "deny_if_fields": {"po_matched": {"eq": False}, "env": {"in": ["prod"]}}}
        specs = {"deploy": {"irreversible": True, "data_class_floor": "public",
                            "fields": {"env": {"json_path": "env"}}}}
        got = warnings_for([rule], specs)
        self.assertEqual(len(got), 1)
        self.assertIn("reads that default", got[0])

    def test_mapped_everywhere_or_no_field_rule_is_silent(self):
        specs = {"pay_vendor": {"irreversible": True, "data_class_floor": "financial",
                                "fields": {"po_matched": {"json_path": "po_matched"}}}}
        self.assertEqual(warnings_for([RULE], specs), [])
        self.assertEqual(warnings_for([], specs), [])

    def test_cli_prints_to_stderr_and_still_signs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "p.md").write_text("Pay vendors with a matched PO.", encoding="utf-8")
            (root / "r.json").write_text(
                '{"fields": {"po_matched": {"type": "boolean", "default": false}},'
                ' "hard_rules": [{"id": "tools", "allow_only_tools": ["pay_vendor", "lookup"]},'
                ' {"id": "po-mismatch", "deny_if_fields": {"po_matched": {"eq": false}}}],'
                ' "tool_specs": {"pay_vendor": {"irreversible": true, "data_class_floor": "financial",'
                ' "fields": {"po_matched": {"json_path": "po_matched"}}},'
                ' "lookup": {"irreversible": false, "data_class_floor": "public"}}}', encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["init-key", str(root / "keys")]), 0)
            err, out = io.StringIO(), io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
                rc = main(["sign-constitution", "--key", str(root / "keys" / "principal.pem"), "--prose",
                           str(root / "p.md"), "--rules", str(root / "r.json"), "--out", str(root / "c.json")])
            self.assertEqual(rc, 0)
            self.assertTrue((root / "c.json").exists())
            self.assertIn("two-key: WARNING: rule 'po-mismatch': tool 'lookup'", err.getvalue())


if __name__ == "__main__":
    unittest.main()
