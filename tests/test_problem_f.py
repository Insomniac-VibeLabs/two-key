"""Problem F: a signed tool spec fills the form. A disagreeing claim denies.

A constitution cannot omit tool_specs. There is no English scanner: a
public tool may mention "classified ads", and medical text is denied only
because the tool's floor is medical.
"""

import tempfile
import unittest
from pathlib import Path

from two_key.constitution import ConstitutionError, load_unsigned, sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import DeriveError, derive, join_data_class
from two_key.gateway import ToolGateway
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

try:
    import yaml  # noqa: F401  (PyYAML is the optional [yaml] extra)
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False
NEEDS_YAML = unittest.skipUnless(HAVE_YAML, "PyYAML is not installed (pip install two-key-concept[yaml])")


PROSE = "Never wire money. Cap spend at 200. No medical or classified data."
RULES = [
    {"id": "tools", "allow_only_tools": ["email_draft", "pay_bill", "summarize", "read_chart"]},
    {"id": "cap", "deny_if": {"amount_usd_gt": 200}},
    {"id": "sensitive", "deny_if": {"data_class_in": ["medical", "classified"]}},
    {"id": "blocked", "deny_counterparties": ["offshore-mule.example", "acme-scam.example"]},
]
SPECS = {
    "email_draft": {
        "irreversible": False,
        "data_class_floor": "public",
        "counterparties": [{"json_path": "to", "allow": ["ada@example"]}],
    },
    "pay_bill": {
        "irreversible": True,
        "data_class_floor": "financial",
        "amount": {"json_path": "amount", "unit": "usd", "currency_path": "currency"},
        "counterparties": [{"json_path": "to", "allow": ["power-co.example", "aaa-good.example"]}],
    },
    "summarize": {
        "irreversible": False,
        "data_class_floor": "public",
    },
    "read_chart": {
        "irreversible": False,
        "data_class_floor": "medical",
    },
}


def _engine(tmp, specs=SPECS, rules=RULES):
    key = generate_private_key()
    env = sign_constitution(PROSE, rules, key, specs)
    ledger = Ledger(Path(tmp, "ledger"), key)
    judges = [FixedJudge("j0", "yes", provider="p0", maker="v0", local_weights=True),
              FixedJudge("j1", "yes", provider="p1", maker="v1")]
    constitution = verify_signed(env, key.public_key())
    tk = TwoKey(ledger, key.public_key(), constitution, judges, private_key=key,
                quorum=QuorumPolicy(required_yes=2), allow_test_doubles=True, monitored_agent=TEST_AGENT)
    return key, tk


class ProblemFTests(unittest.TestCase):
    def test_declared_zero_cannot_hide_a_bare_amount(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 0, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                {"amount": 4800, "currency": "usd", "to": "power-co.example", "memo": "4800"},
                "pay the bill")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, "amount_mismatch")
            self.assertIn("path_b", [entry.kind for entry in tk.ledger.entries])

    def test_eur_string_and_eur_currency_deny(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            as_text = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 0, "data_class": "financial", "irreversible": True},
                {"amount": "EUR 4800", "currency": "usd", "to": "power-co.example"},
                "pay")
            as_code = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 4800, "data_class": "financial", "irreversible": True},
                {"amount": 4800, "currency": "EUR", "to": "power-co.example"},
                "pay")
            self.assertEqual(as_text.reason, "derive_failed:amount_unreadable")
            self.assertEqual(as_code.reason, "derive_failed:amount_unit_rejected")
            self.assertIn("path_a", [entry.kind for entry in tk.ledger.entries])

    def test_counterparty_lie_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                {"amount": 10, "currency": "usd", "to": "offshore-mule.example"},
                "pay")
            self.assertEqual(decision.reason, "counterparty_mismatch")
            self.assertFalse(decision.allowed)

    def test_omitted_counterparty_is_filled_and_the_block_list_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True},
                {"amount": 10, "currency": "usd", "to": "offshore-mule.example"},
                "pay")
            self.assertFalse(decision.allowed)
            self.assertNotEqual(decision.reason, "counterparty_mismatch")
            self.assertEqual(decision.path_a["denied_by"], "blocked")

    def test_memo_dollars_do_not_raise_the_amount(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                {"amount": 10, "currency": "usd", "to": "power-co.example",
                 "memo": "prior balance was $5,000"},
                "pay the small bill")
            self.assertTrue(decision.allowed, decision.reason)
            self.assertEqual(decision.reason, "both_paths_allow")

    def test_classified_ads_on_a_public_tool_are_not_a_sensitive_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"text": "see the classified ads in the paper"},
                "summarize")
            self.assertTrue(decision.allowed, decision.reason)

    def test_medical_floor_raises_a_public_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "read_chart", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"note": "Pt dx: HIV+, Rx listed"},
                "read")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.path_a["denied_by"], "sensitive")
            normalized = [entry for entry in tk.ledger.entries if entry.kind == "action_normalized"][-1]
            self.assertEqual(normalized.body["form"]["data_class"], "medical")

    def test_irreversible_claim_cannot_understate_the_spec(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": False,
                 "counterparty": "power-co.example"},
                {"amount": 10, "currency": "usd", "to": "power-co.example"},
                "pay")
            self.assertEqual(decision.reason, "irreversible_mismatch")

    def test_missing_amount_path_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "data_class": "financial", "irreversible": True},
                {"currency": "usd", "to": "power-co.example"},
                "pay")
            self.assertEqual(decision.reason, "derive_failed:amount_missing")

    def test_gateway_recomputes_the_form(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            args = {"amount": 10, "currency": "usd", "to": "power-co.example"}
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                args, "pay")
            self.assertTrue(decision.allowed, decision.reason)
            gateway = ToolGateway(tk.ledger, tk.issuer, tk.compiled,
                                  tools={"pay_bill": lambda a: {"paid": a["to"]}})
            redeemed = gateway.invoke(decision.token, "pay_bill", args)
            self.assertTrue(redeemed.allowed, redeemed.reason)

    def test_spec_change_invalidates_the_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            key, tk = _engine(tmp)
            args = {"to": "ada@example"}
            decision = tk.authorize(
                {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False,
                 "counterparty": "ada@example"},
                args, "draft")
            self.assertTrue(decision.allowed, decision.reason)
            other = dict(SPECS)
            other["email_draft"] = dict(SPECS["email_draft"], data_class_floor="personal")
            envelope = sign_constitution(PROSE, RULES, key, other)
            other_tk = TwoKey(tk.ledger, key.public_key(), verify_signed(envelope, key.public_key()),
                              tk.judges, private_key=key, quorum=tk.quorum, allow_test_doubles=True, monitored_agent=TEST_AGENT)
            gateway = ToolGateway(tk.ledger, tk.issuer, other_tk.compiled,
                                  tools={"email_draft": lambda a: a})
            result = gateway.invoke(decision.token, "email_draft", args)
            self.assertEqual(result.reason, "constitution_mismatch")

    def test_allow_list_without_a_spec_is_refused(self):
        key = generate_private_key()
        with self.assertRaises(ConstitutionError):
            sign_constitution(PROSE, RULES, key, {})

    @NEEDS_YAML
    def test_example_rules_file_enforces_specs(self):
        root = Path(__file__).resolve().parents[1]
        _prose, rules, specs = load_unsigned(root / "examples" / "constitution.md",
                                             root / "examples" / "hard_rules.yaml")
        self.assertIn("pay_bill", specs)
        key = generate_private_key()
        envelope = sign_constitution(_prose, rules, key, specs)
        constitution = verify_signed(envelope, key.public_key())
        self.assertTrue(constitution.specs_enforced)
        self.assertEqual(constitution.tool_specs["pay_bill"]["amount"]["unit"], "usd")
        self.assertFalse(constitution.tool_specs["pay_bill"]["deny_unmapped"])
        self.assertEqual(constitution.tool_specs["summarize"]["payload"], [])

    def test_join_never_lowers_the_floor(self):
        self.assertEqual(join_data_class("public", "medical"), "medical")
        self.assertEqual(join_data_class("classified", "public"), "classified")
        self.assertEqual(join_data_class("personal", "medical"), "medical")   # was classified before class sets
        self.assertEqual(join_data_class("financial", "financial"), "financial")

    def test_omitted_tool_specs_are_refused(self):
        """There is no legacy path that trusts the agent's form."""
        key = generate_private_key()
        with self.assertRaises(ConstitutionError):
            sign_constitution(PROSE, RULES, key)
        from two_key.canonical import canonical_bytes
        from two_key.keys import fingerprint, sign
        from two_key.policy_vm import validate_rules
        rules = validate_rules(RULES)
        signed = {"prose": PROSE, "hard_rules": rules}
        envelope = {
            "format": "two-key-concept-constitution-v1",
            "signed": signed,
            "signature": sign(key, canonical_bytes(signed)),
            "fingerprint": fingerprint(key.public_key()),
        }
        with self.assertRaises(ConstitutionError):
            verify_signed(envelope, key.public_key())
        with tempfile.TemporaryDirectory() as tmp:
            rules_path = Path(tmp, "rules.yaml")
            prose_path = Path(tmp, "prose.md")
            prose_path.write_text(PROSE, encoding="utf-8")
            rules_path.write_text(
                "hard_rules:\n  - id: tools\n    allow_only_tools: [search]\n",
                encoding="utf-8")
            with self.assertRaises(ConstitutionError):
                load_unsigned(prose_path, rules_path)
            rules_path.write_text("- id: tools\n  allow_only_tools: [search]\n", encoding="utf-8")
            with self.assertRaises(ConstitutionError):
                load_unsigned(prose_path, rules_path)

    def test_cents_unit_accepts_an_integral_float_only(self):
        spec = {
            "irreversible": True,
            "data_class_floor": "financial",
            "amount": {"json_path": "amount", "unit": "cents"},
            "counterparties": [],
        }
        got = derive(spec, {"amount": 1050.0})
        self.assertEqual(got.amount_usd, 10.5)
        with self.assertRaises(DeriveError) as fractional:
            derive(spec, {"amount": 10.5})
        self.assertEqual(fractional.exception.reason, "amount_unreadable")
        with self.assertRaises(DeriveError) as huge:
            derive(spec, {"amount": 10**20})
        self.assertEqual(huge.exception.reason, "amount_unreadable")

    def test_derived_amount_above_the_sanity_cap_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 0, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                {"amount": 10**13, "currency": "usd", "to": "power-co.example"},
                "pay")
            self.assertEqual(decision.reason, "derive_failed:amount_unreadable")
            self.assertFalse(decision.allowed)

    def test_null_tool_specs_is_not_the_legacy_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.yaml"
            prose = Path(tmp) / "prose.md"
            prose.write_text("Do not wire money.\n", encoding="utf-8")
            rules.write_text(
                "hard_rules:\n"
                "  - id: tools\n"
                "    allow_only_tools: [search]\n"
                "tool_specs: null\n",
                encoding="utf-8")
            with self.assertRaises(ConstitutionError):
                load_unsigned(prose, rules)

    def test_blocked_party_is_not_hidden_behind_an_allowed_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True},
                {"amount": 10, "currency": "usd",
                 "to": ["aaa-good.example", "offshore-mule.example"]},
                "pay")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.path_a["denied_by"], "blocked")

    def test_omitted_irreversible_follows_the_spec(self):
        rules = RULES + [{"id": "no-irreversible", "deny_if": {"irreversible": True}}]
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp, rules=rules)
            omitted = tk.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public"},
                {"text": "hello"}, "summarize")
            claimed = tk.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": True},
                {"text": "hello"}, "summarize")
            self.assertTrue(omitted.allowed, omitted.reason)
            self.assertEqual(claimed.reason, "irreversible_mismatch")

    def test_unnamed_keys_stay_payload_unless_the_spec_opts_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            allowed = tk.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"text": "hello", "extra": {"n": 5}},
                "summarize")
            self.assertTrue(allowed.allowed, allowed.reason)
        specs = {name: dict(spec) for name, spec in SPECS.items()}
        specs["summarize"] = dict(SPECS["summarize"], deny_unmapped=True)
        with tempfile.TemporaryDirectory() as tmp:
            _, strict = _engine(tmp, specs=specs)
            denied = strict.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"text": "hello"},
                "summarize")
            self.assertEqual(denied.reason, "derive_failed:unmapped_field")
        specs["summarize"] = dict(
            SPECS["summarize"], deny_unmapped=True, payload=[{"json_path": "note"}],
        )
        with tempfile.TemporaryDirectory() as tmp:
            _, named = _engine(tmp, specs=specs)
            decision = named.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"note": {"n": 5000, "text": "hello"}},
                "summarize")
            self.assertTrue(decision.allowed, decision.reason)
            form = [entry for entry in named.ledger.entries if entry.kind == "action_normalized"][-1]
            self.assertEqual(form.body["form"]["amount_usd"], 0.0)
            sibling = named.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"note": "hello", "other": 1},
                "summarize")
            self.assertEqual(sibling.reason, "derive_failed:unmapped_field")

    def test_deny_unmapped_walks_only_to_declared_paths(self):
        specs = {name: dict(spec) for name, spec in SPECS.items()}
        specs["pay_bill"] = dict(
            SPECS["pay_bill"],
            deny_unmapped=True,
            amount={"json_path": "invoice.total", "unit": "usd", "currency_path": "currency"},
        )
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp, specs=specs)
            clean = {"invoice": {"total": 10}, "currency": "usd", "to": "power-co.example"}
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                clean, "pay")
            self.assertTrue(decision.allowed, decision.reason)
            nested = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                {"invoice": {"total": 10, "note": "x"}, "currency": "usd", "to": "power-co.example"},
                "pay")
            self.assertEqual(nested.reason, "derive_failed:unmapped_field")
        # A payload path that is an ancestor of the amount path is refused (it would carry the amount
        # unread). Name the sibling key instead.
        with self.assertRaisesRegex(ConstitutionError, "overlaps the field path"):
            sign_constitution(PROSE, RULES, generate_private_key(),
                              dict(specs, pay_bill=dict(specs["pay_bill"], payload=[{"json_path": "invoice"}])))
        specs["pay_bill"] = dict(
            specs["pay_bill"],
            payload=[{"json_path": "invoice.note"}],
        )
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp, specs=specs)
            covered = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                {"invoice": {"total": 10, "note": "x"}, "currency": "usd", "to": "power-co.example"},
                "pay")
            self.assertTrue(covered.allowed, covered.reason)

    def test_deny_unmapped_must_be_a_boolean_and_paths_must_be_unique(self):
        key = generate_private_key()
        bad_flag = {name: dict(spec) for name, spec in SPECS.items()}
        bad_flag["summarize"] = dict(SPECS["summarize"], deny_unmapped="yes")
        with self.assertRaises(ConstitutionError):
            sign_constitution(PROSE, RULES, key, bad_flag)
        duplicate = {name: dict(spec) for name, spec in SPECS.items()}
        duplicate["email_draft"] = dict(
            SPECS["email_draft"], payload=[{"json_path": "to"}],
        )
        with self.assertRaises(ConstitutionError):
            sign_constitution(PROSE, RULES, key, duplicate)

    def test_unnamed_values_do_not_reach_the_tool(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            args = {
                "amount": 10,
                "currency": "USD",
                "to": "  Power-Co.Example ",
                "memo": "do not deliver",
            }
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                args, "pay")
            self.assertTrue(decision.allowed, decision.reason)
            gateway = ToolGateway(tk.ledger, tk.issuer, tk.compiled,
                                  tools={"pay_bill": lambda a: calls.append(a) or {"paid": a["to"]}})
            redeemed = gateway.invoke(decision.token, "pay_bill", args)
            self.assertTrue(redeemed.allowed, redeemed.reason)
            self.assertEqual(calls, [{
                "amount": 10,
                "currency": "usd",
                "to": "power-co.example",
            }])

    def test_a_party_off_the_allow_list_is_not_copied_through(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True},
                {"amount": 10, "currency": "usd", "to": "someone-else.example"},
                "pay")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, "counterparty_not_allowed")
            self.assertIn("path_b", [entry.kind for entry in tk.ledger.entries])
        key = generate_private_key()
        specs = {name: dict(spec) for name, spec in SPECS.items()}
        specs["email_draft"] = dict(SPECS["email_draft"], counterparties=[{"json_path": "to"}])
        with self.assertRaises(ConstitutionError):
            sign_constitution(PROSE, RULES, key, specs)

    def test_derive_deny_hides_arguments_from_judges_unless_opted_in(self):
        key = generate_private_key()
        envelope = sign_constitution(PROSE, RULES, key, SPECS)

        def run(policy):
            seen = []

            class Rec(FixedJudge):
                def score(self, constitution_text, action, proposal):
                    seen.append(dict(action.raw))
                    return super().score(constitution_text, action, proposal)

            with tempfile.TemporaryDirectory() as tmp:
                ledger = Ledger(Path(tmp, "ledger"), key)
                judges = [Rec("j0", "yes", provider="p0", maker="v0", local_weights=True),
                          Rec("j1", "yes", provider="p1", maker="v1")]
                tk = TwoKey(ledger, key.public_key(), verify_signed(envelope, key.public_key()), judges,
                            private_key=key, quorum=policy, allow_test_doubles=True, monitored_agent=TEST_AGENT)
                denied = tk.authorize(
                    {"tool": "pay_bill", "data_class": "financial", "irreversible": True},
                    {"currency": "usd", "to": "power-co.example", "secret": "hide-me"},
                    "pay")
                self.assertEqual(denied.reason, "derive_failed:amount_missing")
                self.assertIn("path_b", [entry.kind for entry in tk.ledger.entries])
                allowed = tk.authorize(
                    {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                     "counterparty": "power-co.example"},
                    {"amount": 10, "currency": "usd", "to": "power-co.example", "memo": "visible-on-allow"},
                    "pay")
                self.assertTrue(allowed.allowed, allowed.reason)
            return seen

        hidden = run(QuorumPolicy(required_yes=2, parallel=False))
        self.assertTrue(hidden)
        self.assertNotIn("tool_args", hidden[0])
        self.assertEqual(hidden[-1]["tool_args"]["memo"], "visible-on-allow")
        shown = run(QuorumPolicy(required_yes=2, parallel=False, tool_args_on_derive_deny=True))
        self.assertEqual(shown[0]["tool_args"]["secret"], "hide-me")

    def test_payload_shape_locks_kind_and_does_not_read_contents(self):
        specs = {name: dict(spec) for name, spec in SPECS.items()}
        specs["summarize"] = dict(SPECS["summarize"], payload=[
            {"json_path": "note", "shape": "string", "max_length": 20},
            {"json_path": "count", "shape": "number"},
            {"json_path": "tags", "shape": "list", "max_length": 3},
        ])
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp, specs=specs)
            args = {"note": "classified ads", "count": 2, "tags": ["a", "b"]}
            decision = tk.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                args, "summarize")
            self.assertTrue(decision.allowed, decision.reason)
            form = [entry for entry in tk.ledger.entries if entry.kind == "action_normalized"][-1]
            self.assertEqual(form.body["form"]["data_class"], "public")
            calls = []
            gateway = ToolGateway(tk.ledger, tk.issuer, tk.compiled,
                                  tools={"summarize": lambda a: calls.append(a) or a})
            redeemed = gateway.invoke(decision.token, "summarize", args)
            self.assertTrue(redeemed.allowed, redeemed.reason)
            self.assertEqual(calls, [{"note": "classified ads", "count": 2, "tags": ["a", "b"]}])
            nested = tk.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"note": {"text": "hello"}, "count": 1, "tags": []},
                "summarize")
            self.assertEqual(nested.reason, "derive_failed:payload_shape")
            self.assertIn("path_b", [entry.kind for entry in tk.ledger.entries])
            too_long = tk.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"note": "x" * 21, "count": 1, "tags": []},
                "summarize")
            self.assertEqual(too_long.reason, "derive_failed:payload_shape")
            flagged = tk.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"note": "ok", "count": True, "tags": []},
                "summarize")
            self.assertEqual(flagged.reason, "derive_failed:payload_shape")
            mixed = tk.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"note": "ok", "count": 1, "tags": ["a", {"x": 1}]},
                "summarize")
            self.assertEqual(mixed.reason, "derive_failed:payload_shape")
        key = generate_private_key()
        bad_shape = {name: dict(spec) for name, spec in SPECS.items()}
        bad_shape["summarize"] = dict(SPECS["summarize"], payload=[{"json_path": "note", "shape": "object"}])
        with self.assertRaises(ConstitutionError):
            sign_constitution(PROSE, RULES, key, bad_shape)
        bad_limit = {name: dict(spec) for name, spec in SPECS.items()}
        bad_limit["summarize"] = dict(
            SPECS["summarize"], payload=[{"json_path": "count", "shape": "number", "max_length": 4}],
        )
        with self.assertRaises(ConstitutionError):
            sign_constitution(PROSE, RULES, key, bad_limit)


if __name__ == "__main__":
    unittest.main()
