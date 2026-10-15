"""Every tool decides each field a deny_if_fields rule reads: it maps it, or marks it not_applicable (#10).

A forgotten mapping used to hand the tool the field's signed default, with only a warning at signing: a
permissive default switched the rule off for that tool. It is refused now, at signing and on load, for argument
and caller-supplied fields alike. A not_applicable mark gets the default, as an unmapped tool did, and needs a v3
constitution (live run 6x, X02/X04).
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
from two_key.fields import not_applicable_notes
from two_key.keys import generate_private_key, sign
from two_key.ledger import Ledger
from two_key.policy_vm import ConstitutionError
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

V3 = "two-key-constitution-v3"
FIELDS = {"ticket_verified": {"type": "boolean", "default": True},
          "env": {"type": "enum", "values": ["dev", "prod"], "default": "dev"}}
CALLER = {"ticket_verified": {"type": "boolean", "default": True, "source": "caller"}}
RULES = [{"id": "tools", "allow_only_tools": ["reset_password", "lookup_kb"]},
         {"id": "require-verified-ticket", "deny_if_fields": {"ticket_verified": {"eq": False}}}]
RESET = {"irreversible": True, "data_class_floor": "personal", "payload": [{"json_path": "user", "shape": "string"}],
         "fields": {"ticket_verified": {"json_path": "ticket_verified"}}}
LOOKUP = {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q", "shape": "string"}]}
MARKED = dict(LOOKUP, fields={"ticket_verified": "not_applicable"})


def sign_with(specs, fields=FIELDS, rules=RULES, **kw):
    return sign_constitution("p", rules, generate_private_key(), specs, fields=fields, **kw)


class Refusal(unittest.TestCase):
    def test_a_forgotten_mapping_does_not_sign(self):
        for fields, reset in ((FIELDS, RESET),
                              (CALLER, dict(RESET, fields={"ticket_verified": {"source": "caller"}}))):
            with self.subTest(caller="source" in fields["ticket_verified"]):
                with self.assertRaises(ConstitutionError) as cm:
                    sign_with({"reset_password": reset, "lookup_kb": LOOKUP}, fields)
                msg = str(cm.exception)
                self.assertIn("tool_specs.lookup_kb.fields.ticket_verified (rule 'require-verified-ticket')", msg)
                self.assertIn("not_applicable", msg)

    def test_a_field_no_rule_reads_needs_no_decision(self):
        env = sign_with({"reset_password": dict(RESET, fields={"env": {"json_path": "env"},
                                                                **RESET["fields"]}), "lookup_kb": MARKED})
        self.assertNotIn("env", env["signed"]["tool_specs"]["lookup_kb"]["fields"])
        rules = [RULES[0]]
        self.assertEqual(sign_with({"reset_password": RESET, "lookup_kb": LOOKUP}, rules=rules)["format"], FORMAT_V2)

    def test_many_missing_are_summarised(self):
        fields = {f"f{i}": {"type": "boolean", "default": False} for i in range(12)}
        rules = [{"id": "tools", "allow_only_tools": ["x"]},
                 {"id": "r", "deny_if_fields": {name: {"eq": True} for name in fields}}]
        with self.assertRaisesRegex(ConstitutionError, "and 4 more"):
            sign_with({"x": {"irreversible": False, "data_class_floor": "public"}}, fields, rules)

    def test_the_mark_is_exact(self):
        for bad in ("Not_Applicable", "n/a", True, None, {"not_applicable": True}):
            with self.subTest(bad=bad), self.assertRaises(ConstitutionError):
                sign_with({"reset_password": RESET, "lookup_kb": dict(LOOKUP, fields={"ticket_verified": bad})})
        with self.assertRaisesRegex(ConstitutionError, "not a declared field"):
            sign_with({"reset_password": RESET, "lookup_kb": dict(LOOKUP, fields={"nope": "not_applicable"})})


class Format(unittest.TestCase):
    def test_a_mark_signs_as_v3_and_only_v3(self):
        env = sign_with({"reset_password": RESET, "lookup_kb": MARKED})
        self.assertEqual(env["format"], V3)
        self.assertEqual(env["signed"]["tool_specs"]["lookup_kb"]["fields"], {"ticket_verified": "not_applicable"})
        with self.assertRaisesRegex(ConstitutionError, "need a v3"):
            sign_with({"reset_password": RESET, "lookup_kb": MARKED}, envelope_format="v2")

    def _resigned(self, signed, fmt):
        key = generate_private_key()
        return key, {"format": fmt, "signed": signed, "signature": sign(key, canonical_bytes(signed)),
                     "fingerprint": "x"}

    def test_load_refuses_a_v2_label_on_a_mark(self):
        signed = sign_with({"reset_password": RESET, "lookup_kb": MARKED})["signed"]
        key, env = self._resigned(signed, FORMAT_V2)
        with self.assertRaisesRegex(ConstitutionError, "need a v3"):
            verify_signed(env, key.public_key())

    def test_load_refuses_a_constitution_signed_before_the_rule(self):
        # What 0.3.0 to 0.4.0 signed: lookup_kb neither maps nor marks the field the rule reads.
        signed = {"prose": "p", "hard_rules": RULES, "fields": FIELDS,
                  "tool_specs": {"reset_password": RESET, "lookup_kb": LOOKUP}}
        key, env = self._resigned(signed, FORMAT_V2)
        with self.assertRaisesRegex(ConstitutionError, "tool_specs.lookup_kb.fields.ticket_verified"):
            verify_signed(env, key.public_key())


class Behaviour(unittest.TestCase):
    def tk(self, default):
        fields = {"ticket_verified": dict(FIELDS["ticket_verified"], default=default)}
        key = generate_private_key()
        con = verify_signed(sign_constitution("p", RULES, key, {"reset_password": RESET, "lookup_kb": MARKED},
                                              fields=fields), key.public_key())
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return TwoKey(Ledger(Path(tmp.name, "ledger"), key), key.public_key(), con, [FixedJudge("a", "yes")],
                      private_key=key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                      monitored_agent=TEST_AGENT)

    def test_a_marked_tool_gets_the_default(self):
        claim = {"tool": "lookup_kb", "data_class": "public", "irreversible": False}
        self.assertTrue(self.tk(True).authorize(claim, {"q": "vpn"}, "look up").allowed)
        d = self.tk(False).authorize(claim, {"q": "vpn"}, "look up")
        self.assertEqual(d.reason, "rule_denied:require-verified-ticket")

    def test_the_mapped_tool_still_reads_its_value(self):
        tk = self.tk(True)
        claim = {"tool": "reset_password", "data_class": "personal", "irreversible": True}
        self.assertEqual(tk.authorize(claim, {"user": "u1", "ticket_verified": False}, "reset").reason,
                         "rule_denied:require-verified-ticket")
        self.assertEqual(tk.authorize(claim, {"user": "u1"}, "reset").reason,
                         "derive_failed:field_missing:ticket_verified")

    def test_the_vocabulary_leaves_a_marked_field_out(self):
        key = generate_private_key()
        con = verify_signed(sign_constitution("p", RULES, key, {"reset_password": RESET, "lookup_kb": MARKED},
                                              fields=FIELDS), key.public_key())
        tools = json.loads(tool_vocabulary(con).split("\n", 1)[1])["tools"]
        self.assertNotIn("fields", tools["lookup_kb"])
        self.assertIn("ticket_verified", tools["reset_password"]["fields"])


class Notes(unittest.TestCase):
    def test_what_each_mark_does(self):
        for default, warn, effect in ((True, False, "never denies it"), (False, True, "always denies it")):
            with self.subTest(default=default):
                fields = {"ticket_verified": dict(FIELDS["ticket_verified"], default=default)}
                signed = sign_with({"reset_password": RESET, "lookup_kb": MARKED}, fields)["signed"]
                got = not_applicable_notes(signed["hard_rules"], signed["tool_specs"], signed["fields"])
                self.assertEqual(len(got), 1)
                self.assertEqual(got[0][0], warn)
                self.assertIn("tool 'lookup_kb' marks ticket_verified not_applicable", got[0][1])
                self.assertIn(effect, got[0][1])

    def test_cli_refuses_or_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "p.md").write_text("Reset passwords for verified tickets only.", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["init-key", str(root / "keys")]), 0)

            def run(lookup):
                (root / "r.json").write_text(json.dumps({"fields": FIELDS, "hard_rules": RULES, "tool_specs": {
                    "reset_password": RESET, "lookup_kb": lookup}}), encoding="utf-8")
                err = io.StringIO()
                with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                    rc = main(["sign-constitution", "--key", str(root / "keys" / "principal.pem"), "--prose",
                               str(root / "p.md"), "--rules", str(root / "r.json"), "--out", str(root / "c.json")])
                return rc, err.getvalue()
            with self.assertRaises((ConstitutionError, SystemExit)):
                run(LOOKUP)
            self.assertFalse((root / "c.json").exists())
            rc, err = run(MARKED)
            self.assertEqual(rc, 0)
            self.assertIn("two-key: note: rule 'require-verified-ticket': tool 'lookup_kb' marks", err)


if __name__ == "__main__":
    unittest.main()
