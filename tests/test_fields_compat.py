"""A constitution without custom fields signs, hashes, and binds exactly as it did before they existed.

The hashes below were recorded from the code before custom fields were added. If one changes, every
existing signed constitution, outstanding token, and ledger audit would see a different value.
"""

import tempfile
import unittest
from pathlib import Path

from two_key.action import normalize_action
from two_key.canonical import canonical_hash
from two_key.compiler import compile_both
from two_key.constitution import load_unsigned, sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

ROOT = Path(__file__).resolve().parent.parent

GOLDEN = {
    "format": "two-key-concept-constitution-v1",
    "digest": "b14f4ae309ba6aceb1cce794f40144f3d69e78a9dbb39569fb4d16b74cadb114",
    "bytecode_hash": "6ee63736003bf94f4bc5fdb9e65d4406e63f3cbc6127081bddf5fe15ea83bb6c",
    "spec_hash": "5ba4019be1bdcdbd1e7eed9e43c8d5e7b99b813eac85890479b6d64cc2c7b161",
    "nl_hash": "0599cb862497009213bbdbc6b20c85cb5c82c6c53e09f21eb2798e1ef233ebc7",
    "action_hash": "5a4be54f77f0f3914c768deaf4db0baf01bb3f4006a72036cbb023c880f23a54",
}


class ExampleConstitutionUnchanged(unittest.TestCase):
    def setUp(self):
        # A frozen copy of the 0.2 example prose: the example itself may change, the golden input may not.
        self.prose, rules, specs = load_unsigned(ROOT / "tests" / "fixtures" / "v1_constitution.md",
                                                 ROOT / "examples" / "hard_rules.yaml")
        self.key = generate_private_key()
        self.rules, self.specs = rules, specs
        self.env = sign_constitution(self.prose, rules, self.key, specs)
        self.con = verify_signed(self.env, self.key.public_key())

    def test_hashes(self):
        comp = compile_both(self.con.prose, self.con.hard_rules, self.con.tool_specs, specs_enforced=True)
        self.assertEqual(self.env["format"], GOLDEN["format"])
        self.assertEqual(set(self.env["signed"]), {"prose", "hard_rules", "tool_specs"})
        self.assertEqual(self.con.digest, GOLDEN["digest"])
        self.assertEqual(comp.bytecode_hash, GOLDEN["bytecode_hash"])
        self.assertEqual(comp.spec_hash, GOLDEN["spec_hash"])
        self.assertEqual(comp.nl_hash, GOLDEN["nl_hash"])

    def test_action_record_shape(self):
        record = normalize_action({"tool": "pay_bill", "amount_usd": 12.5, "counterparty": "power-co.example",
                                   "data_class": "financial", "irreversible": True}).to_record()
        self.assertNotIn("fields", record)
        self.assertEqual(canonical_hash(record), GOLDEN["action_hash"])

    def test_token_form_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = TwoKey(Ledger(Path(tmp, "ledger"), self.key), self.key.public_key(), self.con,
                        [FixedJudge("a", "yes")], private_key=self.key, quorum=QuorumPolicy(required_yes=1),
                        allow_test_doubles=True, monitored_agent=TEST_AGENT)
            d = tk.authorize({"tool": "pay_bill", "data_class": "financial", "irreversible": True},
                             {"amount": 12.5, "currency": "USD", "to": "power-co.example"}, "pay it")
            self.assertTrue(d.allowed, d.reason)
            form = [e.body for e in tk.ledger.entries if e.kind == "action_normalized"][-1]["form"]
            self.assertEqual(set(form), {"amount_usd", "data_class", "counterparty", "irreversible",
                                         "counterparties"})
            self.assertTrue(tk.gateway(tools={"pay_bill": lambda a: a}).invoke(
                d.token, "pay_bill", {"amount": 12.5, "currency": "USD", "to": "power-co.example"}).allowed)


if __name__ == "__main__":
    unittest.main()
