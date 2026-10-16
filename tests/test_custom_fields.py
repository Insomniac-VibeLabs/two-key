"""Custom Path A fields: typed, signed, read from argument bytes only, and bound into the token.

Each test class is one invariant from the plan. Negative and bypass attempts are the point.
"""

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from two_key import constitution as constitution_mod
from two_key import fields as F
from two_key.action import LOADABLE_FIELDS, Action
from two_key.compiler import compile_both
from two_key.constitution import (FORMAT_V1, FORMAT_V2, ConstitutionError, ConstitutionSignatureError,
                                  load_unsigned, load_unsigned_with_fields, sign_constitution, verify_signed)
from two_key.core import TwoKey
from two_key.gateway import ToolGateway
from two_key.judges.llm import build_user_prompt
from two_key.keys import generate_private_key, sign
from two_key.canonical import canonical_bytes
from two_key.ledger import Ledger
from two_key.policy_vm import Op, PolicyVM
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

MARK = "ZZ-ANNOTATION-MARK-ZZ"

FIELDS = {
    "environment": {"type": "enum", "values": ["dev", "staging", "prod"], "default": "dev",
                    "description": f"Target environment. {MARK}"},
    "replicas": {"type": "integer", "min": 0, "max": 1000, "default": 0},
    "dry_run": {"type": "boolean", "default": True},
    "team": {"type": "string", "max_length": 32, "default": "", "charset": "unicode", "scripts": "latin"},
}
RULES = [
    {"id": "tools", "allow_only_tools": ["deploy", "search"]},
    {"id": "no-prod", "deny_if_fields": {"environment": {"in": ["prod"]}}},
    {"id": "replica-cap", "deny_if_fields": {"replicas": {"gt": 10}}},
    {"id": "no-blocked-team", "deny_if_fields": {"team": {"eq": "blocked"}}},
]
SPECS = {
    "deploy": {"irreversible": True, "data_class_floor": "public",
               "fields": {"environment": {"json_path": "target.env"},
                          "replicas": {"json_path": "target.replicas"},
                          "dry_run": {"json_path": "dry_run"},
                          "team": {"json_path": "team"}},
               "payload": [{"json_path": "note", "shape": "string"}]},
    "search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}],
               # Every tool decides each field a rule reads: search does not carry them, so it says so.
               "fields": {"environment": "not_applicable", "replicas": "not_applicable", "team": "not_applicable"}},
}
DEPLOY = {"tool": "deploy", "data_class": "public", "irreversible": True}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


def good_args(**over):
    args = {"target": {"env": "Staging", "replicas": 3}, "dry_run": False, "team": "Ops", "note": "x"}
    args.update(over)
    return args


class RecordingJudge(FixedJudge):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.seen = []

    def score(self, constitution_text, action, proposal):
        self.seen.append((constitution_text, action.to_record()))
        return super().score(constitution_text, action, proposal)


class Harness:
    """Shared set-up: a signed constitution with custom fields, a TwoKey, and its gateway. A mixin."""

    fields, rules, specs = FIELDS, RULES, SPECS

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = generate_private_key()
        self.env = sign_constitution("Deploy carefully.", self.rules, self.key, self.specs, fields=self.fields)
        self.con = verify_signed(self.env, self.key.public_key())
        self.judge = RecordingJudge("a", "yes")
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), self.key), self.key.public_key(), self.con,
                         [self.judge], private_key=self.key, quorum=QuorumPolicy(required_yes=1),
                         allow_test_doubles=True, monitored_agent=TEST_AGENT)
        self.received = []
        self.gw = self.tk.gateway(tools={"deploy": self._tool, "search": self._tool})

    def _tool(self, args):
        self.received.append(args)
        return "ok"

    def entries(self, kind):
        return [e.body for e in self.tk.ledger.entries if e.kind == kind]


class HappyPath(Harness, unittest.TestCase):
    def test_allows_and_redeems(self):
        args = good_args()
        d = self.tk.authorize(DEPLOY, args, "deploy to staging")
        self.assertTrue(d.allowed, d.reason)
        form = self.entries("action_normalized")[-1]["form"]
        self.assertEqual(form["fields"], {"environment": "staging", "replicas": 3, "dry_run": False, "team": "ops"})
        self.assertTrue(self.gw.invoke(d.token, "deploy", args).allowed)
        self.assertEqual(self.env["format"], "two-key-constitution-v3")     # search marks not_applicable


class A1ValuesOnlyFromBytes(Harness, unittest.TestCase):
    def test_raw_claim_cannot_supply_a_value(self):
        claim = dict(DEPLOY, raw={"environment": "dev", "replicas": 0})
        d = self.tk.authorize(claim, good_args(target={"env": "prod", "replicas": 3}), "deploy")
        self.assertFalse(d.allowed)
        self.assertEqual(d.path_a["denied_by"], "no-prod")

    def test_claiming_a_custom_field_is_malformed(self):
        for claim in (dict(DEPLOY, environment="dev"), dict(DEPLOY, fields={"environment": "dev"})):
            d = self.tk.authorize(claim, good_args(target={"env": "prod", "replicas": 3}), "deploy")
            self.assertFalse(d.allowed)
            self.assertTrue(d.reason.startswith("malformed_action:"), d.reason)

    def test_prefilled_action_object_is_refused(self):
        action = Action(tool="deploy", data_class="public", irreversible=True, fields={"environment": "dev"})
        d = self.tk.authorize(action, good_args(target={"env": "prod", "replicas": 3}), "deploy")
        self.assertFalse(d.allowed)
        self.assertTrue(d.reason.startswith("malformed_action:"), d.reason)

    def test_vm_load_never_reads_raw(self):
        action = Action(tool="x", raw={"environment": "dev"})
        for name in ("environment", "raw"):
            r = PolicyVM([(Op.LOAD, name), (Op.PUSH, "dev"), (Op.EQ,), (Op.ASSERT, "r"), (Op.PASS,)]).eval(action)
            self.assertFalse(r.allowed)
            self.assertTrue(r.reason.startswith("vm_fault:"), r.reason)
        r = PolicyVM([(Op.LOAD_FIELD, "environment"), (Op.PASS,)]).eval(action)
        self.assertTrue(r.reason.startswith("vm_fault:"), r.reason)

    def test_compiler_loads_custom_fields_only_with_load_field(self):
        for op, *args in self.tk.compiled.bytecode:
            if op == Op.LOAD:
                self.assertIn(args[0], LOADABLE_FIELDS)
        loaded = {args[0] for op, *args in self.tk.compiled.bytecode if op == Op.LOAD_FIELD}
        self.assertEqual(loaded, {"environment", "replicas", "team"})


class A2FailClosed(Harness, unittest.TestCase):
    CASES = [
        ({"target": {"replicas": 3}}, "derive_failed:field_missing:environment"),
        ({"target": {"env": "dev"}}, "derive_failed:field_missing:replicas"),
        ({"target": {"env": "dev", "replicas": True}}, "derive_failed:field_unreadable:replicas"),
        ({"target": {"env": "dev", "replicas": "5"}}, "derive_failed:field_unreadable:replicas"),
        ({"target": {"env": "dev", "replicas": 5.0}}, "derive_failed:field_unreadable:replicas"),
        ({"target": {"env": "dev", "replicas": None}}, "derive_failed:field_unreadable:replicas"),
        ({"target": {"env": "dev", "replicas": [1]}}, "derive_failed:field_unreadable:replicas"),
        ({"target": {"env": "dev", "replicas": 1001}}, "derive_failed:field_not_allowed:replicas"),
        ({"target": {"env": "dev", "replicas": 10 ** 20}}, "derive_failed:field_not_allowed:replicas"),
        ({"target": {"env": "dev", "replicas": -1}}, "derive_failed:field_not_allowed:replicas"),
        ({"target": {"env": "qa", "replicas": 3}}, "derive_failed:field_not_allowed:environment"),
        ({"target": {"env": "pr\u043ed", "replicas": 3}}, "derive_failed:field_unreadable:environment"),
        ({"target": {"env": {"x": 1}, "replicas": 3}}, "derive_failed:field_unreadable:environment"),
        ({"dry_run": "false"}, "derive_failed:field_unreadable:dry_run"),
        ({"dry_run": 0}, "derive_failed:field_unreadable:dry_run"),
        ({"team": "x" * 33}, "derive_failed:field_not_allowed:team"),
        ({"team": "\u041e\u043f\u0441"}, "derive_failed:field_unreadable:team"),
        ({"team": "o\u202eps"}, "derive_failed:field_unreadable:team"),
        ({"team": "o\u200bps"}, "derive_failed:field_unreadable:team"),
    ]

    def test_each_bad_value_denies_without_judges_and_no_token(self):
        for over, reason in self.CASES:
            with self.subTest(over=over):
                before = len(self.judge.seen)
                args = good_args(**over)
                d = self.tk.authorize(DEPLOY, args, "deploy")
                self.assertFalse(d.allowed)
                self.assertIsNone(d.token)
                self.assertEqual(d.reason, reason)
                self.assertEqual(len(self.judge.seen), before)                # unreadable: no judge is asked
                self.assertEqual(self.entries("path_b")[-1], {"passed": False, "reason": "skipped:derive_failed",
                                                              "yes": 0, "no": 0, "abstain": 0, "skipped": True})
                self.assertEqual(self.entries("action_normalized")[-1]["deny_reason"], reason)

    def test_huge_integer_is_invalid_call(self):
        d = self.tk.authorize(DEPLOY, good_args(target={"env": "dev", "replicas": 10 ** 5000}), "deploy")
        self.assertFalse(d.allowed)
        self.assertTrue(d.reason.startswith("invalid_call:"), d.reason)


class A3TokenBindsFields(Harness, unittest.TestCase):
    def _issue(self, form):
        args = good_args()
        frozen = canonical_bytes(args)
        from two_key.canonical import digest_hex
        issued = self.tk.issuer.issue(
            tool="deploy", arguments=args, args_digest=digest_hex(frozen),
            ledger_root=self.tk.ledger.merkle_root(), ledger_size=self.tk.ledger.size(),
            bytecode_hash=self.tk.compiled.bytecode_hash, nl_hash=self.tk.compiled.nl_hash,
            spec_hash=self.tk.compiled.spec_hash, form=form, claimed_data_class="public", ttl_seconds=60)
        return issued.token, args

    def _form(self):
        d = self.tk.authorize(DEPLOY, good_args(), "deploy")
        self.assertTrue(d.allowed, d.reason)
        return copy.deepcopy(self.entries("action_normalized")[-1]["form"])

    def test_tampered_field_value(self):
        form = self._form()
        form["fields"]["environment"] = "dev"
        token, args = self._issue(form)
        self.assertEqual(self.gw.invoke(token, "deploy", args).reason, "derived_mismatch")
        self.assertEqual(self.received, [])

    def test_true_is_not_one(self):
        form = self._form()
        form["fields"]["dry_run"] = 0
        token, args = self._issue(form)
        self.assertEqual(self.gw.invoke(token, "deploy", args).reason, "derived_mismatch")

    def test_missing_fields_key(self):
        form = self._form()
        del form["fields"]
        token, args = self._issue(form)
        self.assertEqual(self.gw.invoke(token, "deploy", args).reason, "derived_mismatch")

    def test_changed_args(self):
        d = self.tk.authorize(DEPLOY, good_args(), "deploy")
        r = self.gw.invoke(d.token, "deploy", good_args(target={"env": "prod", "replicas": 3}))
        self.assertEqual(r.reason, "args_mismatch")

    def test_registry_change_is_constitution_mismatch(self):
        d = self.tk.authorize(DEPLOY, good_args(), "deploy")
        changed = copy.deepcopy(FIELDS)
        changed["replicas"]["default"] = 1
        other = compile_both("Deploy carefully.", self.con.hard_rules, SPECS, specs_enforced=True, fields=changed)
        self.assertNotEqual(other.spec_hash, self.tk.compiled.spec_hash)
        gw = ToolGateway(self.tk.ledger, self.tk.issuer.verifier(), other, tools={"deploy": self._tool})
        self.assertEqual(gw.invoke(d.token, "deploy", good_args()).reason, "constitution_mismatch")


class A4ToolSeesCheckedValues(Harness, unittest.TestCase):
    def test_normalized_values_and_dropped_keys(self):
        args = good_args(target={"env": " STAGING ", "replicas": 3, "secret": "s"}, extra="e")
        d = self.tk.authorize(DEPLOY, args, "deploy")
        self.assertTrue(d.allowed, d.reason)
        self.assertTrue(self.gw.invoke(d.token, "deploy", args).allowed)
        self.assertEqual(self.received[-1], {"target": {"env": "staging", "replicas": 3}, "dry_run": False,
                                             "team": "ops", "note": "x"})

    def test_deny_unmapped_still_denies(self):
        specs = copy.deepcopy(SPECS)
        specs["deploy"]["deny_unmapped"] = True
        env = sign_constitution("p", RULES, self.key, specs, fields=FIELDS)
        con = verify_signed(env, self.key.public_key())
        with tempfile.TemporaryDirectory() as tmp:
            tk = TwoKey(Ledger(Path(tmp, "ledger"), self.key), self.key.public_key(), con, [FixedJudge("a", "yes")],
                        private_key=self.key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                        monitored_agent=TEST_AGENT)
            self.assertTrue(tk.authorize(DEPLOY, good_args(), "d").allowed)
            self.assertEqual(tk.authorize(DEPLOY, good_args(extra=1), "d").reason, "derive_failed:unmapped_field")


def _refused(test, fields=None, rules=None, specs=None, contains=None):
    with test.assertRaises(ConstitutionError) as raised:
        sign_constitution("p", RULES if rules is None else rules, test.key,
                          SPECS if specs is None else specs, fields=FIELDS if fields is None else fields)
    if contains:
        test.assertIn(contains, str(raised.exception))


class A5NoOverridesOrOverlaps(unittest.TestCase):
    def setUp(self):
        self.key = generate_private_key()

    def test_reserved_and_malformed_names(self):
        names = sorted(F.RESERVED_NAMES) + ["Tool", "Environment", "two_key_x", "_x", "1x", "a-b", "a.b", ""]
        for name in names:
            with self.subTest(name=name):
                _refused(self, fields={name: {"type": "boolean", "default": False}}, rules=RULES[:1],
                         specs={k: {kk: vv for kk, vv in v.items() if kk != "fields"} for k, v in SPECS.items()})

    def test_definition_cannot_carry_security_settings(self):
        for key in ("irreversible", "data_class_floor", "deny_unmapped", "allow", "json_path", "id"):
            with self.subTest(key=key):
                bad = copy.deepcopy(FIELDS)
                bad["dry_run"][key] = True
                _refused(self, fields=bad, contains="unknown key")

    def test_bad_definitions(self):
        cases = {
            "no default": {"type": "boolean"},
            "bad type": {"type": "decimal", "default": 1},
            "enum default not member": {"type": "enum", "values": ["a"], "default": "b"},
            "enum duplicate after normalization": {"type": "enum", "values": ["Prod", "prod"], "default": "prod"},
            "enum empty": {"type": "enum", "values": [], "default": "a"},
            "enum empty member": {"type": "enum", "values": [" "], "default": " "},
            "int no bounds": {"type": "integer", "default": 0},
            "int min > max": {"type": "integer", "min": 2, "max": 1, "default": 1},
            "int bool bound": {"type": "integer", "min": False, "max": 1, "default": 0},
            "int default out": {"type": "integer", "min": 0, "max": 1, "default": 2},
            "string no max": {"type": "string", "default": ""},
            "scripts without unicode": {"type": "enum", "values": ["a"], "default": "a", "scripts": "latin"},
            "unicode without scripts": {"type": "enum", "values": ["a"], "default": "a", "charset": "unicode"},
            "unknown script": {"type": "enum", "values": ["a"], "default": "a", "charset": "unicode",
                               "scripts": "klingon"},
            "values on boolean": {"type": "boolean", "default": True, "values": [True]},
        }
        for label, defn in cases.items():
            with self.subTest(label):
                bad = copy.deepcopy(FIELDS)
                bad["extra_field"] = defn
                _refused(self, fields=bad)

    def test_path_overlaps(self):
        def with_paths(**paths):
            specs = copy.deepcopy(SPECS)
            for name, path in paths.items():
                specs["deploy"]["fields"][name] = {"json_path": path}
            return specs
        cases = [
            with_paths(team="note"),                       # equal to a payload path
            with_paths(team="target"),                     # ancestor of other field paths
            with_paths(team="note.sub"),                   # under a payload path
            with_paths(team="TARGET.ENV"),                 # case variant of another field path
            with_paths(team="target.env"),                 # duplicate path
        ]
        specs = copy.deepcopy(SPECS)
        specs["deploy"]["counterparties"] = [{"json_path": "to", "allow": ["a"]}]
        specs["deploy"]["fields"]["team"] = {"json_path": "TO"}
        cases.append(specs)
        specs = copy.deepcopy(SPECS)
        specs["deploy"]["amount"] = {"json_path": "cost", "unit": "usd"}
        specs["deploy"]["fields"]["team"] = {"json_path": "cost.x"}
        cases.append(specs)
        specs = copy.deepcopy(SPECS)
        specs["deploy"]["payload"].append({"json_path": "Target"})     # payload over field paths
        cases.append(specs)
        for i, specs in enumerate(cases):
            with self.subTest(i=i):
                with self.assertRaises(ConstitutionError) as raised:
                    sign_constitution("p", RULES, self.key, specs, fields=FIELDS)
                self.assertRegex(str(raised.exception), "overlap|duplicate")

    def test_mapping_errors(self):
        specs = copy.deepcopy(SPECS)
        specs["deploy"]["fields"]["undeclared"] = {"json_path": "u"}
        _refused(self, specs=specs, contains="not a declared field")
        specs = copy.deepcopy(SPECS)
        specs["deploy"]["fields"]["team"] = {"json_path": "team", "default": "x"}
        _refused(self, specs=specs)
        specs = copy.deepcopy(SPECS)
        specs["deploy"]["fields"]["team"] = {"json_path": "bad path"}
        _refused(self, specs=specs)
        specs = copy.deepcopy(SPECS)
        specs["deploy"]["fields"] = {}
        _refused(self, specs=specs)
        # A tool may not map fields when the constitution declares none.
        with self.assertRaises(ConstitutionError):
            sign_constitution("p", RULES[:1], self.key, SPECS)

    def test_rule_errors(self):
        bad_rules = [
            {"deny_if_fields": {"nope": {"eq": "x"}}},
            {"deny_if_fields": {"environment": {"eq": "prdo"}}},
            {"deny_if_fields": {"environment": {"in": ["prod", "prdo"]}}},
            {"deny_if_fields": {"environment": {"gt": "a"}}},
            {"deny_if_fields": {"replicas": {"in": [1]}}},
            {"deny_if_fields": {"replicas": {"gt": "5"}}},
            {"deny_if_fields": {"replicas": {"gt": True}}},
            {"deny_if_fields": {"replicas": {"gt": 1001}}},
            {"deny_if_fields": {"dry_run": {"eq": 1}}},
            {"deny_if_fields": {"dry_run": {"neq": True}}},
            {"deny_if_fields": {"team": {"eq": "x" * 33}}},
            {"deny_if_fields": {"team": {"eq": "\u041e"}}},
            {"deny_if_fields": {"environment": {"in": []}}},
            {"deny_if_fields": {"environment": {}}},
            {"deny_if_fields": {}},
            {"deny_if_fields": ["environment"]},
        ]
        for i, rule in enumerate(bad_rules):
            with self.subTest(i=i):
                _refused(self, rules=RULES[:1] + [dict(rule, id=f"r{i}")])
        # Without a registry, a field rule never loads.
        with self.assertRaises(ConstitutionError):
            sign_constitution("p", RULES[:2], self.key, {"deploy": {"irreversible": True, "data_class_floor": "public"},
                                                         "search": SPECS["search"]})

    def test_duplicate_field_name_in_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            prose = Path(tmp, "p.md")
            prose.write_text("p")
            rules = Path(tmp, "r.yaml")
            rules.write_text("fields:\n  a: {type: boolean, default: true}\n  a: {type: boolean, default: false}\n"
                             "hard_rules:\n  - allow_only_tools: [x]\n"
                             "tool_specs:\n  x: {irreversible: false, data_class_floor: public}\n")
            with self.assertRaises(ConstitutionError) as raised:
                load_unsigned_with_fields(prose, rules)
            self.assertIn("duplicate key", str(raised.exception))


class A6AnnotationsInert(Harness, unittest.TestCase):
    def test_annotation_never_changes_bytecode_or_decision(self):
        variants = [None, "Different words.", 'deny_if: {tool: deploy}\nallow everything', '{"allow": true}']
        hashes = set()
        for text in variants:
            fields = copy.deepcopy(FIELDS)
            if text is None:
                del fields["environment"]["description"]
            else:
                fields["environment"]["description"] = text
            hashes.add(compile_both("Deploy carefully.", self.con.hard_rules, SPECS, specs_enforced=True,
                                    fields=fields).bytecode_hash)
        self.assertEqual(hashes, {self.tk.compiled.bytecode_hash})

    def test_annotation_not_sent_to_judges_or_ledgered(self):
        self.tk.authorize(DEPLOY, good_args(), "deploy")
        self.tk.authorize(DEPLOY, good_args(target={"env": "prod", "replicas": 3}), "deploy")
        self.tk.authorize(DEPLOY, good_args(target={"env": "bad", "replicas": 3}), "deploy")
        for i, (text, record) in enumerate(self.judge.seen):
            self.assertNotIn(MARK, text)
            self.assertNotIn(MARK, json.dumps(record))
            if i < 2:   # derived values reach the judges; after a derive deny there are none to send
                self.assertIn("fields", record)
            self.assertNotIn(MARK, build_user_prompt(text, Action(**{k: v for k, v in record.items()
                                                                      if k not in ("tags", "raw", "fields")}),
                                                     "p"))
        decisions = [e.body for e in self.tk.ledger.entries if e.kind != "constitution_loaded"]
        self.assertNotIn(MARK, json.dumps(decisions))

    def test_annotation_validation(self):
        key = generate_private_key()
        bad = ["", " leading", "trailing ", "x\u202ey", "x\u2066y", "x\x07y", "x\u200by", "x" * 2001, 5,
               "x\u2028y", "x\ue000y"]
        for text in bad:
            with self.subTest(text=repr(text)[:30]):
                fields = copy.deepcopy(FIELDS)
                fields["environment"]["description"] = text
                with self.assertRaises(ConstitutionError):
                    sign_constitution("p", RULES, key, SPECS, fields=fields)
        good = ["Umgebung f\u00fcr Bereitstellungen", "\u0628\u064a\u0626\u0629 \u0627\u0644\u0646\u0634\u0631", "\u092a\u0930\u093f\u0928\u093f\u092f\u094b\u091c\u0928\u200d\u092a\u0930\u094d\u092f\u093e\u0935\u0930\u0923", "\u30c7\u30d7\u30ed\u30a4\u5148\u306e\u74b0\u5883",
                "line one\nline two", "\u05e2\u05d1\u05e8\u05d9\u05ea\u200f text", "x" * 2000]
        for text in good:
            with self.subTest(text=text[:20]):
                fields = copy.deepcopy(FIELDS)
                fields["environment"]["description"] = text
                sign_constitution("p", RULES, key, SPECS, fields=fields)

    def test_editing_an_annotation_breaks_the_signature(self):
        env = copy.deepcopy(self.env)
        env["signed"]["fields"]["environment"]["description"] = "Edited."
        with self.assertRaises(ConstitutionSignatureError):
            verify_signed(env, self.key.public_key())


class A7Unicode(Harness, unittest.TestCase):
    def test_fullwidth_folds_to_the_rule_value_in_a_unicode_field(self):
        d = self.tk.authorize(DEPLOY, good_args(team="\uff42\uff4c\uff4f\uff43\uff4b\uff45\uff44"), "deploy")
        self.assertFalse(d.allowed)
        self.assertEqual(d.path_a["denied_by"], "no-blocked-team")

    def test_fullwidth_is_refused_in_an_ascii_field(self):
        d = self.tk.authorize(DEPLOY, good_args(target={"env": "\uff50\uff52\uff4f\uff44", "replicas": 3}), "d")
        self.assertEqual(d.reason, "derive_failed:field_unreadable:environment")

    def test_normalization(self):
        n = F.normalize_text
        self.assertEqual(n("Caf\u00e9", "unicode", "latin"), n("Cafe\u0301", "unicode", "latin"))
        self.assertEqual(n("\u0130stanbul", "unicode", "latin"), "i\u0307stanbul")   # Turkish dotted I
        self.assertEqual(n("  PROD ", "ascii"), "prod")
        accepted = [("\u7d4c\u7406", "japanese"), ("\u3072\u3089\u304c\u306a\u30ab\u30bf\u30ab\u30ca\u6f22\u5b57abc",
                                                   "japanese"),
                    ("\uc11c\uc6b8", "korean"), ("\u0645\u0627\u0644\u064a\u0629", "arabic"),
                    ("\u0641\u0627\u0631\u0633\u06cc\u200c\u0647\u0627", "arabic"),
                    ("\u0939\u093f\u0928\u094d\u0926\u0940", "devanagari"),
                    ("\u0915\u094d\u200d\u0937", "devanagari"),
                    ("\u041c\u043e\u0441\u043a\u0432\u0430", "cyrillic"), ("\u0e01\u0e23\u0e38\u0e07", "thai")]
        for text, scripts in accepted:
            with self.subTest(text=text):
                n(text, "unicode", scripts)
        refused = [
            ("pr\u043ed", "latin"),                 # Cyrillic o inside Latin
            ("prod", "cyrillic"),                   # Latin inside Cyrillic
            ("\uc11c\uc6b8", "japanese"),           # Hangul inside Japanese
            ("\u041c", "japanese"),
            ("ab\u200dc", "latin"),                 # joiner where the script does not use one
            ("\u200d\u0939", "devanagari"),         # joiner first
            ("a\u202eb", "latin"),                  # bidi override
            ("a\u2066b", "latin"),                  # bidi isolate
            ("a\u00adb", "latin"),                  # soft hyphen (format)
            ("a\u0378b", "latin"),                  # unassigned
            ("a\ue000b", "latin"),                  # private use
            ("a\x00b", "latin"),                    # control
            ("\u0301a", "latin"),                   # combining mark with no base
            ("x\u0301\u0301\u0301\u0301", "latin"),  # combining run longer than 3
            ("pr\u20acd", "latin"),                 # non-ASCII symbol of no declared script
            ("pr\u2010d", "latin"),                 # Unicode hyphen that looks like '-'
            ("caf\u00e9", None),                    # unknown scripts
        ]
        for text, scripts in refused:
            with self.subTest(text=repr(text)), self.assertRaises(F.FieldValueError):
                n(text, "unicode", scripts)
        for text in ("caf\u00e9", "a\tb", "a\x7fb"):
            with self.assertRaises(F.FieldValueError):
                n(text, "ascii")

    def test_unicode_enum(self):
        fields = {"abteilung": {"type": "enum", "charset": "unicode", "scripts": "japanese",
                                "values": ["\u7d4c\u7406", "\u55b6\u696d"], "default": "\u55b6\u696d"}}
        rules = [{"id": "tools", "allow_only_tools": ["x"]},
                 {"id": "no-keiri", "deny_if_fields": {"abteilung": {"eq": "\u7d4c\u7406"}}}]
        specs = {"x": {"irreversible": False, "data_class_floor": "public",
                       "fields": {"abteilung": {"json_path": "d"}}}}
        env = sign_constitution("p", rules, self.key, specs, fields=fields)
        con = verify_signed(env, self.key.public_key())
        with tempfile.TemporaryDirectory() as tmp:
            tk = TwoKey(Ledger(Path(tmp, "ledger"), self.key), self.key.public_key(), con, [FixedJudge("a", "yes")],
                        private_key=self.key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                        monitored_agent=TEST_AGENT)
            claim = {"tool": "x", "data_class": "public", "irreversible": False}
            self.assertTrue(tk.authorize(claim, {"d": "\u55b6\u696d"}, "p").allowed)
            self.assertEqual(tk.authorize(claim, {"d": "\u7d4c\u7406"}, "p").path_a["denied_by"], "no-keiri")
            self.assertEqual(tk.authorize(claim, {"d": "\uc11c\uc6b8"}, "p").reason,
                             "derive_failed:field_unreadable:abteilung")


class A9EnvelopeFormat(unittest.TestCase):
    def setUp(self):
        self.key = generate_private_key()
        self.plain_rules = [{"id": "tools", "allow_only_tools": ["search"]}]
        self.plain_specs = {"search": {k: v for k, v in SPECS["search"].items() if k != "fields"}}

    def test_auto_and_forced(self):
        v1 = sign_constitution("p", self.plain_rules, self.key, self.plain_specs)
        self.assertEqual(v1["format"], FORMAT_V1)
        self.assertNotIn("fields", v1["signed"])
        v2 = sign_constitution("p", self.plain_rules, self.key, self.plain_specs, envelope_format="v2")
        self.assertEqual(v2["format"], FORMAT_V2)
        self.assertEqual(v1["signed"], v2["signed"])
        a, b = verify_signed(v1, self.key.public_key()), verify_signed(v2, self.key.public_key())
        self.assertEqual((a.hard_rules, a.tool_specs, a.fields), (b.hard_rules, b.tool_specs, b.fields))
        # Every tool maps every rule-read field: v2. A not_applicable mark (search, in SPECS) needs v3.
        deploy_only = [{"id": "tools", "allow_only_tools": ["deploy"]}, *RULES[1:]]
        self.assertEqual(sign_constitution("p", deploy_only, self.key, {"deploy": SPECS["deploy"]},
                                           fields=FIELDS)["format"], FORMAT_V2)
        self.assertEqual(sign_constitution("p", RULES, self.key, SPECS, fields=FIELDS)["format"],
                         "two-key-constitution-v3")
        with self.assertRaisesRegex(ConstitutionError, "need a v3"):
            sign_constitution("p", RULES, self.key, SPECS, fields=FIELDS, envelope_format="v2")
        # v3 (0.5.0, caller-supplied fields) can be forced; the signed body is the same.
        v3 = sign_constitution("p", self.plain_rules, self.key, self.plain_specs, envelope_format="v3")
        self.assertEqual((v3["format"], v3["signed"]), ("two-key-constitution-v3", v1["signed"]))
        with self.assertRaises(ConstitutionError):
            sign_constitution("p", self.plain_rules, self.key, self.plain_specs, envelope_format="v4")

    def _resign(self, env, signed):
        env = dict(env, signed=signed)
        env["signature"] = sign(self.key, canonical_bytes(signed))
        return env

    def test_v2_refuses_unknown_signed_keys(self):
        env = sign_constitution("p", self.plain_rules, self.key, self.plain_specs, envelope_format="v2")
        env = self._resign(env, dict(env["signed"], extra=1))
        with self.assertRaises(ConstitutionError):
            verify_signed(env, self.key.public_key())

    def test_v1_refuses_fields(self):
        env = sign_constitution("p", RULES, self.key, SPECS, fields=FIELDS)
        env = self._resign(dict(env, format=FORMAT_V1), env["signed"])
        with self.assertRaises(ConstitutionError):
            verify_signed(env, self.key.public_key())

    def test_unknown_format_refused(self):
        env = sign_constitution("p", self.plain_rules, self.key, self.plain_specs)
        with self.assertRaises(ConstitutionSignatureError):
            verify_signed(dict(env, format="two-key-constitution-v4"), self.key.public_key())

    def test_cli_and_loaders(self):
        from two_key.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            prose = Path(tmp, "p.md")
            prose.write_text("Deploy carefully.")
            rules = Path(tmp, "r.json")
            rules.write_text(json.dumps({"fields": FIELDS, "hard_rules": RULES, "tool_specs": SPECS}))
            plain = Path(tmp, "plain.json")
            plain.write_text(json.dumps({"hard_rules": self.plain_rules, "tool_specs": self.plain_specs}))
            with self.assertRaises(ConstitutionError):
                load_unsigned(prose, rules)          # never drops fields silently
            keyfile = Path(tmp, "k.pem")
            from two_key.keys import save_private_key
            save_private_key(keyfile, self.key)
            out = Path(tmp, "c.json")
            for rules_file, flag, fmt in ((rules, [], "two-key-constitution-v3"), (plain, [], FORMAT_V1),
                                          (plain, ["--envelope-format", "v2"], FORMAT_V2)):
                with self.subTest(rules=rules_file.name, flag=flag):
                    with mock.patch("sys.stdout"):
                        # --force: signing over an existing file is deliberate (live run 8x, finding 3)
                        self.assertEqual(main(["sign-constitution", "--key", str(keyfile), "--prose", str(prose),
                                               "--rules", str(rules_file), "--out", str(out), "--force"] + flag), 0)
                    env = json.loads(out.read_text())
                    self.assertEqual(env["format"], fmt)
                    verify_signed(env, self.key.public_key())
            before = out.read_text()
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(main(["sign-constitution", "--key", str(keyfile), "--prose", str(prose),
                                       "--rules", str(rules), "--out", str(out)]), 1)
            self.assertIn("exists; move it aside, or pass --force", err.getvalue())
            self.assertEqual(out.read_text(), before)


class A10Limits(unittest.TestCase):
    def setUp(self):
        self.key = generate_private_key()

    def _sign(self, fields, rules=None, specs=None):
        rules = rules or [{"id": "tools", "allow_only_tools": ["x"]}]
        specs = specs or {"x": {"irreversible": False, "data_class_floor": "public"}}
        return sign_constitution("p", rules, self.key, specs, fields=fields)

    def assert_limit(self, make, at, over):
        """``make(value)`` returns the keyword arguments for ``_sign``: ``at`` signs, ``over`` is refused."""
        self._sign(**make(at))
        with self.assertRaises(ConstitutionError):
            self._sign(**make(over))

    def test_field_count(self):
        def make(n):
            return {"fields": {f"f{i}": {"type": "boolean", "default": False} for i in range(n)}}
        self.assert_limit(make, F.MAX_FIELDS, F.MAX_FIELDS + 1)

    def test_name_length(self):
        def make(n):
            return {"fields": {"a" * n: {"type": "boolean", "default": False}}}
        self.assert_limit(make, F.MAX_FIELD_NAME_CHARS, F.MAX_FIELD_NAME_CHARS + 1)

    def test_enum_values_and_lengths(self):
        def many(n):
            return {"fields": {"e": {"type": "enum", "values": [f"{i:04d}" for i in range(n)], "default": "0000"}}}

        def long(size):
            return {"fields": {"e": {"type": "enum", "values": ["0" * size], "default": "0" * size}}}
        self.assert_limit(many, F.MAX_ENUM_VALUES, F.MAX_ENUM_VALUES + 1)
        self.assert_limit(long, F.MAX_VALUE_CHARS, F.MAX_VALUE_CHARS + 1)

    def test_description_length(self):
        def make(n):
            return {"fields": {"b": {"type": "boolean", "default": False, "description": "x" * n}}}
        self.assert_limit(make, F.MAX_DESCRIPTION_CHARS, F.MAX_DESCRIPTION_CHARS + 1)

    def test_string_max_length(self):
        def make(n):
            return {"fields": {"s": {"type": "string", "max_length": n, "default": ""}}}
        self.assert_limit(make, F.MAX_STRING_LENGTH, F.MAX_STRING_LENGTH + 1)

    def test_integer_bounds(self):
        def make(lo):
            return {"fields": {"i": {"type": "integer", "min": lo, "max": F.MAX_SAFE_INT, "default": F.MAX_SAFE_INT}}}
        self.assert_limit(make, -F.MAX_SAFE_INT, -F.MAX_SAFE_INT - 1)

    def test_conditions_and_list_items(self):
        ints = {f"i{n}": {"type": "integer", "min": 0, "max": 2000, "default": 0} for n in range(F.MAX_CONDITIONS + 1)}

        def x_marks(names):
            return {"x": {"irreversible": False, "data_class_floor": "public",
                          "fields": {name: "not_applicable" for name in names}}}

        def conditions(n):
            return {"fields": ints, "specs": x_marks(ints),
                    "rules": [{"id": "tools", "allow_only_tools": ["x"]},
                              {"id": "c", "deny_if_fields": {f"i{k}": {"gt": 1} for k in range(n)}}]}

        def items(n):
            return {"fields": {"s": {"type": "string", "max_length": 8, "default": ""}}, "specs": x_marks(["s"]),
                    "rules": [{"id": "tools", "allow_only_tools": ["x"]},
                              {"id": "c", "deny_if_fields": {"s": {"in": [f"v{k}" for k in range(n)]}}}]}
        self.assert_limit(conditions, F.MAX_CONDITIONS, F.MAX_CONDITIONS + 1)
        self.assert_limit(items, F.MAX_LIST_ITEMS, F.MAX_LIST_ITEMS + 1)

    def test_path_limits(self):
        def make(path):
            return {"fields": {"b": {"type": "boolean", "default": False}},
                    "specs": {"x": {"irreversible": False, "data_class_floor": "public",
                                    "fields": {"b": {"json_path": path}}}}}
        self.assert_limit(make, ".".join(["a"] * F.MAX_PATH_SEGMENTS), ".".join(["a"] * (F.MAX_PATH_SEGMENTS + 1)))
        self.assert_limit(make, "a" * F.MAX_PATH_CHARS, "a" * (F.MAX_PATH_CHARS + 1))

    def test_fields_per_tool(self):
        def make(n):
            return {"fields": {f"f{i}": {"type": "boolean", "default": False} for i in range(3)},
                    "specs": {"x": {"irreversible": False, "data_class_floor": "public",
                                    "fields": {f"f{i}": {"json_path": f"p{i}"} for i in range(n)}}}}
        with mock.patch.object(constitution_mod, "MAX_FIELDS_PER_TOOL", 2):
            self.assert_limit(make, 2, 3)


class A11UnrelatedTools(Harness, unittest.TestCase):
    def test_unmapped_tool_gets_defaults_without_a_fault(self):
        d = self.tk.authorize(SEARCH, {"q": "weather"}, "look")
        self.assertTrue(d.allowed, d.reason)
        self.assertEqual(self.judge.seen[-1][1]["fields"],
                         {"environment": "dev", "replicas": 0, "dry_run": True, "team": ""})
        self.assertTrue(self.gw.invoke(d.token, "search", {"q": "weather"}).allowed)

    def test_tool_off_the_allow_list_is_denied_by_the_rule(self):
        d = self.tk.authorize({"tool": "wire", "data_class": "public", "irreversible": True}, {}, "wire")
        self.assertFalse(d.allowed)
        self.assertEqual(d.path_a["denied_by"], "tools")


class ExampleFile(unittest.TestCase):
    def test_examples_custom_fields_yaml(self):
        root = Path(__file__).resolve().parent.parent
        prose, rules, specs, fields = load_unsigned_with_fields(root / "examples" / "constitution.md",
                                                               root / "examples" / "custom_fields.yaml")
        key = generate_private_key()
        env = sign_constitution(prose, rules, key, specs, fields=fields)
        self.assertEqual(env["format"], "two-key-constitution-v3")      # search marks fields not_applicable
        con = verify_signed(env, key.public_key())
        claim = {"tool": "deploy", "data_class": "public", "irreversible": True}

        def args(env_name, dry, abteilung="Entwicklung", replicas=2):
            return {"target": {"env": env_name, "replicas": replicas}, "dry_run": dry, "ticket": "CHG-1",
                    "requested_by": {"abteilung": abteilung}}
        with tempfile.TemporaryDirectory() as tmp:
            tk = TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), con, [FixedJudge("a", "yes")],
                        private_key=key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                        monitored_agent=TEST_AGENT)
            self.assertTrue(tk.authorize(claim, args("staging", False), "p").allowed)
            self.assertTrue(tk.authorize(claim, args("prod", True), "p").allowed)
            self.assertEqual(tk.authorize(claim, args("prod", False), "p").path_a["denied_by"],
                             "only-dev-or-staging-unless-dry-run")
            self.assertEqual(tk.authorize(claim, args("dev", False, replicas=21), "p").path_a["denied_by"],
                             "replica-cap")
            self.assertEqual(tk.authorize(claim, args("dev", False, "BUCHHALTUNG"), "p").path_a["denied_by"],
                             "no-buchhaltung-deploys")
            self.assertEqual(tk.authorize(claim, args("dev", False, "Marketing"), "p").reason,
                             "derive_failed:field_not_allowed:abteilung")
            search = {"tool": "search", "data_class": "public", "irreversible": False}
            self.assertTrue(tk.authorize(search, {}, "p").allowed)


if __name__ == "__main__":
    unittest.main()
