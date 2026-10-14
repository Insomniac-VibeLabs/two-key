"""A call carries a set of data classes, not an invented one.

public < personal < {financial, medical} < classified. financial and medical are kinds of personal data;
together they are "financial+medical", which a data_class_in rule naming either one matches. Only a
claim or floor of classified (or an omitted claim) is classified. A floor never lowers a claim.
"""

import itertools
import tempfile
import unittest
from pathlib import Path

from two_key.action import DATA_CLASSES, ActionValidationError, normalize_action
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import join_data_class
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

LEVEL = {"public": 0, "personal": 1, "financial": 2, "medical": 2, "classified": 3}


class Join(unittest.TestCase):
    def test_table(self):
        cases = {
            ("medical", "personal"): "medical",          # dentist entry on a personal calendar (run 3, C05)
            ("financial", "personal"): "financial",      # CPA email (run 3, C18)
            ("medical", "financial"): "financial+medical",   # a medical bill paid with pay_bill
            ("financial", "medical"): "financial+medical",
            ("personal", "medical"): "medical",
            ("public", "financial"): "financial",
            ("public", "public"): "public",
            ("personal", "public"): "personal",
            ("classified", "public"): "classified",
            ("medical", "classified"): "classified",
            ("financial+medical", "personal"): "financial+medical",
            ("financial+medical", "classified"): "classified",
        }
        for (claim, floor), want in cases.items():
            with self.subTest(claim=claim, floor=floor):
                self.assertEqual(join_data_class(claim, floor), want)

    def test_never_lower_than_the_claim_or_the_floor(self):
        for claim, floor in itertools.product(DATA_CLASSES, repeat=2):
            got = join_data_class(claim, floor).split("+")
            for side in (claim, floor):
                with self.subTest(claim=claim, floor=floor, side=side):
                    self.assertGreaterEqual(max(LEVEL[g] for g in got), LEVEL[side])
            for specific in {"financial", "medical"} & {claim, floor}:
                if "classified" not in (claim, floor):     # a specific class is never dropped
                    self.assertIn(specific, got, (claim, floor))

    def test_classified_only_when_someone_says_so(self):
        for claim, floor in itertools.product(DATA_CLASSES, repeat=2):
            if "classified" not in (claim, floor):
                self.assertNotEqual(join_data_class(claim, floor), "classified", (claim, floor))


class Claim(unittest.TestCase):
    def test_combined_claim_is_canonical(self):
        self.assertEqual(normalize_action({"tool": "t", "data_class": "Medical+Financial"}).data_class,
                         "financial+medical")
        self.assertEqual(normalize_action({"tool": "t", "data_class": "financial+medical"}).data_class,
                         "financial+medical")

    def test_repeated_class_is_refused(self):
        # Live run 5 (C36): "financial+financial" was accepted as financial, contrary to the docs.
        for bad in ("financial+financial", "medical+medical", "personal+personal", "public+public",
                    "classified+classified", "financial+medical+financial", "medical+financial+medical"):
            with self.subTest(bad=bad), self.assertRaises(ActionValidationError):
                normalize_action({"tool": "t", "data_class": bad})

    def test_unknown_part_is_refused(self):
        for bad in ("medical+secret", "+medical", "medical+", "", "medical,financial", "personal+medical",
                    "public+personal", "classified+medical", "financial+medical+personal"):
            with self.subTest(bad=bad), self.assertRaises(ActionValidationError):
                normalize_action({"tool": "t", "data_class": bad})

    def test_omitted_claim_is_still_classified(self):
        self.assertEqual(normalize_action({"tool": "t"}).data_class, "classified")


SPECS = {"pay_bill": {"irreversible": True, "data_class_floor": "financial",
                      "amount": {"json_path": "amount", "unit": "usd", "currency_path": "currency"},
                      "counterparties": [{"json_path": "to", "allow": ["clinic.example"]}]}}
ARGS = {"amount": 40, "currency": "USD", "to": "clinic.example"}


class MedicalBill(unittest.TestCase):
    def tk(self, denied):
        rules = [{"id": "tools", "allow_only_tools": ["pay_bill"]},
                 {"id": "sensitive", "deny_if": {"data_class_in": denied}}]
        key = generate_private_key()
        con = verify_signed(sign_constitution("Pay the clinic (`clinic.example`).", rules, key, SPECS),
                            key.public_key())
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return TwoKey(Ledger(Path(tmp.name, "ledger"), key), key.public_key(), con, [FixedJudge("a", "yes")],
                      private_key=key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                      monitored_agent=TEST_AGENT)

    def test_allowed_when_only_classified_is_denied_and_the_gateway_agrees(self):
        tk = self.tk(["classified"])
        d = tk.authorize({"tool": "pay_bill", "data_class": "medical"}, ARGS, "pay the clinic bill")
        self.assertTrue(d.allowed, d.reason)
        form = [e.body for e in tk.ledger.entries if e.kind == "action_normalized"][-1]["form"]
        self.assertEqual(form["data_class"], "financial+medical")
        red = tk.gateway(tools={"pay_bill": lambda a: "paid"}).invoke(d.token, "pay_bill", ARGS)
        self.assertTrue(red.allowed, red.reason)

    def test_a_rule_naming_either_class_still_denies(self):
        for denied in (["medical"], ["financial"]):
            with self.subTest(denied=denied):
                d = self.tk(denied).authorize({"tool": "pay_bill", "data_class": "medical"}, ARGS, "pay")
                self.assertFalse(d.allowed)
                self.assertEqual(d.reason, "rule_denied:sensitive")

    def test_omitted_claim_still_denied_by_a_classified_rule(self):
        d = self.tk(["classified"]).authorize({"tool": "pay_bill"}, ARGS, "pay")
        self.assertEqual(d.reason, "rule_denied:sensitive")


if __name__ == "__main__":
    unittest.main()
