# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Encrypted files (0.6.0): a tool passes them only when the principal signs ``encrypted: pass`` on its scan field,
and only when encryption is the scanner's sole finding. Every other tool treats an encrypted file as flagged.

The scanners here are in-process fakes (no network). The adapters' mapping is in test_scanners.py."""

import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from two_key.constitution import ConstitutionError, encrypted_pass_notes, sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.judges.llm import SCAN_ENCRYPTED_NOTE, build_user_prompt
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.scan import ScanResult, Scanner, combine
from two_key.testing import TEST_AGENT, FixedJudge

VALUES = ["clean", "flagged", "unavailable", "encrypted"]
FIELDS = {"scan": {"type": "enum", "values": VALUES, "default": "clean", "source": "caller"}}
RULES = {
    "default": [{"id": "scan", "deny_if_fields": {"scan": {"eq": "flagged"}}}],
    "strict": [{"id": "scan", "deny_if_fields": {"scan": {"in": ["flagged", "unavailable"]}}}],
    "monitor": [],
}
SPECS = {
    "vault_upload": {"irreversible": False, "data_class_floor": "personal",
                     "payload": [{"json_path": "file", "shape": "string"}],
                     "fields": {"scan": {"source": "caller", "encrypted": "pass"}}},
    "send_email": {"irreversible": True, "data_class_floor": "personal",
                   "counterparties": [{"json_path": "to", "allow": ["ops@example.org"]}],
                   "payload": [{"json_path": "attachment", "shape": "string"}],
                   "fields": {"scan": {"source": "caller"}}},
}
TOOLS = [{"id": "tools", "allow_only_tools": sorted(SPECS)}]
FILES = {"vault_upload": [{"path": "file", "kind": "base64", "max_bytes": 4096}],
         "send_email": [{"path": "attachment", "kind": "base64", "max_bytes": 4096}]}
LOCKED = base64.b64encode(b"PK\x03\x04 a zip with a password").decode()


class Fixed:
    label = "fixed"

    def __init__(self, result):
        self.result = result
        self.requests = []

    def inspect(self, request):
        self.requests.append(request)
        return self.result


class Recording(FixedJudge):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.prompts = []

    def score(self, constitution_text, action, proposal):
        self.prompts.append(build_user_prompt(constitution_text, action, proposal))
        return super().score(constitution_text, action, proposal)


def quiet():
    return contextlib.redirect_stderr(io.StringIO())


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.key = generate_private_key()
        self.n = 0

    def make(self, result, *, stance="default", specs=None, fields=None, rules=None):
        self.n += 1
        env = sign_constitution("Upload to the vault; mail only ops.", TOOLS + (rules or RULES[stance]), self.key,
                                specs or SPECS, fields=fields or FIELDS)
        self.inspector = Fixed(result)
        self.judge = Recording("a", "yes")
        self.startup = io.StringIO()
        with contextlib.redirect_stderr(self.startup):
            self.tk = TwoKey(Ledger(self.dir / f"ledger{self.n}", self.key), self.key.public_key(),
                             verify_signed(env, self.key.public_key()), [self.judge], private_key=self.key,
                             quorum=QuorumPolicy(required_yes=1, timeout_seconds=10), allow_test_doubles=True,
                             monitored_agent=TEST_AGENT, scanner=Scanner(self.inspector, files=FILES))
        self.ran = []
        self.gw = self.tk.gateway(tools={t: self.ran.append for t in SPECS})
        return self.tk

    def call(self, tool, **args):
        args = args or ({"file": LOCKED} if tool == "vault_upload" else
                        {"to": "ops@example.org", "attachment": LOCKED})
        with quiet():
            return self.tk.authorize({"tool": tool, "data_class": "personal"}, args, "store the file"), args

    def scans(self):
        return [e.body for e in self.tk.ledger.entries if e.kind == "scan"]


class Verdicts(Base):
    def test_encrypted_alone_passes_only_on_the_tool_that_signs_it(self):
        for stance in ("default", "strict", "monitor"):
            with self.subTest(stance=stance):
                self.make(ScanResult.flagged("encrypted", scanner="av"), stance=stance)
                d, args = self.call("vault_upload")
                self.assertTrue(d.allowed, d.reason)
                self.assertEqual((self.scans()[-1]["verdict"], self.scans()[-1]["categories"]),
                                 ("encrypted", ["encrypted"]))
                r = self.gw.invoke(d.token, "vault_upload", args)
                self.assertTrue(r.allowed, r.reason)
                d, _ = self.call("send_email")
                self.assertEqual(self.scans()[-1]["verdict"], "flagged")
                self.assertEqual(self.scans()[-1]["categories"], ["encrypted"])
                self.assertEqual(d.allowed, stance == "monitor", d.reason)

    def test_encrypted_with_any_other_finding_is_flagged(self):
        for other in ("malware", "secret", "limits_exceeded", "unreadable", "policy"):
            with self.subTest(other=other):
                self.make(ScanResult.flagged("encrypted", other))
                d, _ = self.call("vault_upload")
                self.assertFalse(d.allowed)
                self.assertEqual(self.scans()[-1]["verdict"], "flagged")
        self.make(combine([ScanResult.flagged("encrypted"), ScanResult.flagged()]))
        self.assertEqual(self.call("vault_upload")[0].allowed, False)

    def test_a_part_that_could_not_be_scanned_is_still_unavailable(self):
        result = combine([ScanResult.flagged("encrypted"), ScanResult.unavailable()])
        self.assertEqual((result.verdict, result.categories), ("unavailable", ("encrypted",)))
        for stance, allowed in (("default", True), ("strict", False)):
            with self.subTest(stance=stance):
                self.make(result, stance=stance)
                d, _ = self.call("vault_upload")
                self.assertEqual(d.allowed, allowed, d.reason)
                self.assertEqual((self.scans()[-1]["verdict"], self.scans()[-1]["categories"]), ("unavailable", []))
                d, _ = self.call("send_email")
                self.assertFalse(d.allowed)
                self.assertEqual(self.scans()[-1]["verdict"], "flagged")

    def test_a_scanner_cannot_answer_the_verdict_encrypted_itself(self):
        self.make(ScanResult("encrypted"))
        d, _ = self.call("vault_upload")
        self.assertEqual((self.scans()[-1]["verdict"], self.scans()[-1]["error"]), ("unavailable", "invalid_result"))

    def test_the_judges_see_the_verdict_with_the_arguments(self):
        self.make(ScanResult.flagged("encrypted"))
        self.call("vault_upload")
        prompt = self.judge.prompts[-1]
        self.assertIn(SCAN_ENCRYPTED_NOTE, prompt)
        self.assertIn('"verdict":"encrypted"', prompt)
        self.assertIn('"arguments_withheld":false', prompt)
        self.make(ScanResult.clean())
        self.call("vault_upload")
        self.assertNotIn(SCAN_ENCRYPTED_NOTE, self.judge.prompts[-1])

    def test_the_gateway_takes_the_verdict_only_for_a_tool_that_passes(self):
        self.make(ScanResult.flagged("encrypted"))
        d, args = self.call("vault_upload")
        body = json.loads(base64.urlsafe_b64decode(d.token.split(".")[1] + "=="))
        self.assertEqual(body["scan"]["verdict"], "encrypted")
        with mock.patch.object(self.tk.scanner, "passes_encrypted", return_value=False):
            r = self.gw.invoke(d.token, "vault_upload", args)
        self.assertEqual((r.allowed, r.reason), (False, "scan_mismatch"))
        self.assertEqual(self.ran, [])

    def test_a_principal_can_still_rule_on_encrypted(self):
        rules = [{"id": "scan", "deny_if_fields": {"scan": {"in": ["flagged", "encrypted"]}}}]
        self.make(ScanResult.flagged("encrypted"), rules=rules)
        self.assertIn("lets nothing more through", self.startup.getvalue())
        d, _ = self.call("vault_upload")
        self.assertFalse(d.allowed)


class Configuration(Base):
    def refused(self, specs, fields, pattern):
        env = sign_constitution("p", TOOLS, self.key, specs, fields=fields)
        with quiet(), self.assertRaisesRegex(TwoKeyConfigError, pattern):
            TwoKey(Ledger(self.dir / f"refused{id(specs)}", self.key), self.key.public_key(),
                   verify_signed(env, self.key.public_key()), [FixedJudge("a", "yes")], allow_test_doubles=True,
                   monitored_agent=TEST_AGENT, scanner=Scanner(Fixed(ScanResult.clean())))

    def test_the_fourth_value_comes_with_a_tool_that_passes_and_only_then(self):
        three = {"scan": {**FIELDS["scan"], "values": ["clean", "flagged", "unavailable"]}}
        with self.assertRaisesRegex(ConstitutionError, "values include encrypted"):
            sign_constitution("p", TOOLS, self.key, SPECS, fields=three)
        no_pass = {**SPECS, "vault_upload": {**SPECS["vault_upload"], "fields": {"scan": {"source": "caller"}}}}
        self.refused(no_pass, FIELDS, "only for a tool that passes encrypted files")

    def test_encrypted_pass_belongs_on_the_scan_field_only(self):
        fields = {**FIELDS, "zone": {"type": "enum", "values": ["inside", "encrypted"], "default": "inside",
                                     "source": "caller"}}
        specs = {**SPECS, "vault_upload": {**SPECS["vault_upload"],
                                           "fields": {"scan": {"source": "caller", "encrypted": "pass"},
                                                      "zone": {"source": "caller", "encrypted": "pass"}}},
                 "send_email": {**SPECS["send_email"], "fields": {"scan": {"source": "caller"},
                                                                  "zone": "not_applicable"}}}
        self.refused(specs, fields, "only valid on the scan field 'scan'")

    def test_the_signed_mark_is_checked(self):
        def spec(mapping):
            return {**SPECS, "vault_upload": {**SPECS["vault_upload"], "fields": mapping}}
        bad = {"not pass": ({"scan": {"source": "caller", "encrypted": "yes"}}, FIELDS, "expected pass"),
               "argument field": ({"scan": {"json_path": "s", "encrypted": "pass"}},
                                  {"scan": {k: v for k, v in FIELDS["scan"].items() if k != "source"}},
                                  "expected json_path only"),
               "string field": ({"scan": {"source": "caller", "encrypted": "pass"}},
                                {"scan": {"type": "string", "max_length": 20, "default": "clean",
                                          "source": "caller"}}, "only the scan field takes encrypted")}
        for name, (mapping, fields, pattern) in bad.items():
            with self.subTest(name), self.assertRaisesRegex(ConstitutionError, pattern):
                sign_constitution("p", TOOLS, self.key, spec(mapping), fields=fields)

    def test_the_mark_is_signed_kept_and_reported(self):
        env = sign_constitution("p", TOOLS, self.key, SPECS, fields=FIELDS)
        signed = verify_signed(env, self.key.public_key()).tool_specs
        self.assertEqual(signed["vault_upload"]["fields"]["scan"], {"encrypted": "pass", "source": "caller"})
        self.assertEqual(signed["send_email"]["fields"]["scan"], {"source": "caller"})
        path = {**SPECS, "vault_upload": {**SPECS["vault_upload"], "fields": {
            "scan": {"source": "caller", "encrypted": "pass", "json_path": "verdict"}}}}
        env = sign_constitution("p", TOOLS, self.key, path, fields=FIELDS)
        self.assertEqual(env["signed"]["tool_specs"]["vault_upload"]["fields"]["scan"],
                         {"encrypted": "pass", "json_path": "verdict", "source": "caller"})
        self.assertEqual(len(encrypted_pass_notes(env["signed"]["tool_specs"])), 1)
        self.assertIn("vault_upload", encrypted_pass_notes(env["signed"]["tool_specs"])[0])

    def test_start_up_says_which_tools_pass_and_the_ledger_records_it(self):
        self.make(ScanResult.clean())
        self.assertIn("encrypted files pass without a look inside (encrypted: pass): vault_upload",
                      self.startup.getvalue())
        loaded = [e.body for e in self.tk.ledger.entries if e.kind == "constitution_loaded"][-1]
        self.assertEqual(loaded["scanner"]["encrypted_pass"], ["vault_upload"])

    def test_the_agent_never_sees_the_mark(self):
        self.make(ScanResult.clean())
        self.assertNotIn("encrypted", self.tk.agent_vocabulary())


if __name__ == "__main__":
    unittest.main(verbosity=2)
