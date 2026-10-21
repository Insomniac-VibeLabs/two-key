# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""``@domain`` allow entries: every email address at exactly one domain, as the principal's signed choice (run 6x).

The school constitution had to list every staff address, and one it forgot stopped a leak only by luck (X31).
A domain entry admits any plain address at that exact domain; signing says so, and warns when the tool also
passes text Path A does not read. Exact entries stay the default, and nothing else is widened: no subdomains, no
lookalike letters, no wildcards, and no address whose local part could carry a header.
"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from two_key.canonical import canonical_bytes
from two_key.cli import main
from two_key.constitution import FORMAT_V1, domain_allow_notes, sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import party_allowed
from two_key.keys import generate_private_key, sign
from two_key.ledger import Ledger
from two_key.policy_vm import ConstitutionError
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

V3 = "two-key-constitution-v3"
RULES = [{"id": "tools", "allow_only_tools": ["send_notice", "pay_vendor"]}]
SPECS = {"send_notice": {"irreversible": False, "data_class_floor": "personal",
                         "counterparties": [{"json_path": "to", "allow": ["@LarkspurValley.example",
                                                                          "board@district.example"]}],
                         "payload": [{"json_path": "body", "shape": "string"}]},
         "pay_vendor": {"irreversible": True, "data_class_floor": "financial",
                        "amount": {"json_path": "amount", "unit": "usd"},
                        "counterparties": [{"json_path": "payee", "allow": ["acme.example"]}],
                        "payload": [{"json_path": "invoice_total", "shape": "number"}]}}
NOTICE = {"tool": "send_notice", "data_class": "personal", "irreversible": False}


def signed(specs=SPECS, rules=RULES, **kw):
    return sign_constitution("p", rules, generate_private_key(), specs, **kw)


class Matching(unittest.TestCase):
    ALLOW = {"@larkspurvalley.example", "board@district.example"}

    def test_any_plain_address_at_exactly_that_domain(self):
        for party in ("helpdesk@larkspurvalley.example", "a.b+notice@larkspurvalley.example", "board@district.example"):
            with self.subTest(party=party):
                self.assertTrue(party_allowed(party, self.ALLOW))

    def test_nothing_wider(self):
        for party in ("x@mail.larkspurvalley.example",          # a subdomain
                      "x@larkspurvalley.example.evil.example",  # the domain as a prefix
                      "x@evil-larkspurvalley.example",
                      "x@larkspurvalley.example.",              # a trailing dot
                      "x@lаrkspurvalley.example",               # Cyrillic а
                      "x@larkspurvalley.example\n",
                      "a\r\nbcc: e\r\n@larkspurvalley.example",  # header injection in the local part
                      "a b@larkspurvalley.example", '"a@b"@larkspurvalley.example', "a@b@larkspurvalley.example",
                      "@larkspurvalley.example", "larkspurvalley.example", "other@district.example"):
            with self.subTest(party=party):
                self.assertFalse(party_allowed(party, self.ALLOW))


class Signing(unittest.TestCase):
    def test_canonical_and_v3(self):
        env = signed()
        self.assertEqual(env["format"], V3)
        self.assertEqual(env["signed"]["tool_specs"]["send_notice"]["counterparties"][0]["allow"],
                         ["@larkspurvalley.example", "board@district.example"])
        with self.assertRaisesRegex(ConstitutionError, "need a v3"):
            signed(envelope_format="v2")
        exact = dict(SPECS, send_notice=dict(SPECS["send_notice"], counterparties=[
            {"json_path": "to", "allow": ["board@district.example"]}]))
        self.assertEqual(signed(exact)["format"], FORMAT_V1)

    def test_a_v1_label_on_a_domain_entry_is_refused(self):
        env = signed()
        key = generate_private_key()
        relabelled = {"format": FORMAT_V1, "signed": env["signed"], "fingerprint": "x",
                      "signature": sign(key, canonical_bytes(env["signed"]))}
        pub = key.public_key()
        with self.assertRaisesRegex(ConstitutionError, "need a v3"):
            verify_signed(relabelled, pub)

    def test_bad_entries(self):
        for item, msg in (("*@larkspurvalley.example", "wildcards"), ("@*.larkspurvalley.example", "wildcards"),
                          ("@larkspurvalley", "not a domain entry"), ("@.example", "not a domain entry"),
                          ("@larkspurvalley.example.", "not a domain entry"), ("@", "not a domain entry"),
                          ("@lаrkspurvalley.example", "not a domain entry"), ("@a_b.example", "not a domain entry")):
            with self.subTest(item=item), self.assertRaisesRegex(ConstitutionError, msg):
                signed(dict(SPECS, send_notice=dict(SPECS["send_notice"], counterparties=[
                    {"json_path": "to", "allow": [item]}])))

    def test_a_block_list_stays_exact(self):
        with self.assertRaisesRegex(ConstitutionError, "only for a tool spec's allow list"):
            signed(rules=RULES + [{"id": "no-evil", "deny_counterparties": ["@evil.example"]}])

    def test_notes(self):
        notes = domain_allow_notes(signed()["signed"]["tool_specs"])
        self.assertEqual(len(notes), 1)
        warn, text = notes[0]
        self.assertTrue(warn)          # body is free text Path A does not read
        self.assertIn("tool 'send_notice': to allows any address at @larkspurvalley.example", text)
        self.assertIn("Path A does not read body", text)
        quiet = dict(SPECS, send_notice=dict(SPECS["send_notice"], payload=[]))
        self.assertIs(domain_allow_notes(signed(quiet)["signed"]["tool_specs"])[0][0], False)

    def test_cli_warns_and_signs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "p.md").write_text("Send notices to staff.", encoding="utf-8")
            (root / "r.json").write_text(json.dumps({"hard_rules": RULES, "tool_specs": SPECS}), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["init-key", str(root / "keys")]), 0)
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc = main(["sign-constitution", "--key", str(root / "keys" / "principal.pem"), "--prose",
                           str(root / "p.md"), "--rules", str(root / "r.json"), "--out", str(root / "c.json")])
            self.assertEqual(rc, 0)
            self.assertIn("two-key: WARNING: tool 'send_notice': to allows any address at @larkspurvalley.example",
                          err.getvalue())


class Calls(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        key = generate_private_key()
        con = verify_signed(sign_constitution("p", RULES, key, SPECS), key.public_key())
        self.tk = TwoKey(Ledger(Path(tmp.name, "ledger"), key), key.public_key(), con, [FixedJudge("a", "yes")],
                         private_key=key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                         monitored_agent=TEST_AGENT)
        self.sent = []
        self.gw = self.tk.gateway(tools={"send_notice": self.sent.append})

    def test_an_address_at_the_domain_redeems_and_the_tool_gets_it_canonical(self):
        args = {"to": "  Helpdesk@LarkspurValley.example ", "body": "Room 4 is closed today."}
        d = self.tk.authorize(NOTICE, args, "notice")
        self.assertTrue(d.allowed, d.reason)
        self.assertTrue(self.gw.invoke(d.token, "send_notice", args).allowed)
        self.assertEqual(self.sent[0]["to"], "helpdesk@larkspurvalley.example")

    def test_anything_else_is_not_allowed(self):
        for to in ("x@mail.larkspurvalley.example", "a\r\nbcc: e@evil.example\r\n@larkspurvalley.example",
                   ["ok@larkspurvalley.example", "x@evil.example"]):
            with self.subTest(to=to):
                d = self.tk.authorize(NOTICE, {"to": to, "body": "hi"}, "notice")
                self.assertEqual(d.reason, "counterparty_not_allowed")
        self.assertEqual(self.sent, [])


if __name__ == "__main__":
    unittest.main()
