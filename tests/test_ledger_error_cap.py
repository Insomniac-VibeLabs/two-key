# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Ballot / VM ledger error strings are capped; type labels never use raw __name__."""
from __future__ import annotations

import unittest

from two_key.action import normalize_action
from two_key.agent_meta import (MAX_LEDGER_ERROR_CHARS, MAX_TYPE_TAG_CHARS, cap_ledger_text,
                                exception_ledger_error, type_tag)
from two_key.judges.base import Judge
from two_key.policy_vm import Op, PolicyVM
from two_key.quorum import QuorumPolicy, convene

SEARCH = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})


class CapLedgerText(unittest.TestCase):
    def test_short_unchanged(self):
        self.assertEqual(cap_ledger_text("ok"), "ok")

    def test_oversize_keeps_prefix_and_digest_of_remainder(self):
        huge = "A" * (MAX_LEDGER_ERROR_CHARS + 5000)
        out = cap_ledger_text(huge)
        self.assertTrue(out.startswith("A" * MAX_LEDGER_ERROR_CHARS))
        self.assertIn("…sha256:", out)
        self.assertNotIn("A" * (MAX_LEDGER_ERROR_CHARS + 1), out)
        self.assertLess(len(out), MAX_LEDGER_ERROR_CHARS + 80)


class QuorumExceptionCap(unittest.TestCase):
    def test_huge_judge_exception_is_capped_in_ballot(self):
        mark = "ZQXERR"

        class Boom(Judge):
            is_test_double = True
            judge_id = "boom"
            provider = "test"

            def score(self, constitution_text, action, proposal):
                raise RuntimeError(mark + "x" * (5 << 20))

        q = convene([Boom()], "Fine.", SEARCH, "look", QuorumPolicy(required_yes=1))
        err = q.ballots[0].error
        self.assertEqual(q.ballots[0].vote, "abstain")
        self.assertTrue(err.startswith("RuntimeError:"))
        self.assertIn(mark, err)
        self.assertIn("…sha256:", err)
        self.assertLess(len(err), MAX_LEDGER_ERROR_CHARS + 80)
        self.assertNotIn("x" * 1000, err)

    def test_huge_type_name_uses_type_tag_not_raw(self):
        huge = "H" * (2 << 20)
        cls = type(huge, (Exception,), {})

        class Boom(Judge):
            is_test_double = True
            judge_id = "boom"
            provider = "test"

            def score(self, constitution_text, action, proposal):
                raise cls("nope")

        q = convene([Boom()], "Fine.", SEARCH, "look", QuorumPolicy(required_yes=1))
        err = q.ballots[0].error
        tag = type_tag(cls("x"))
        self.assertLessEqual(len(tag), MAX_TYPE_TAG_CHARS)
        self.assertNotIn(huge, err)
        self.assertTrue(err.startswith(tag + ":"))


class VmFaultExceptionCap(unittest.TestCase):
    def test_huge_exception_in_vm_fault_reason_is_capped(self):
        mark = "ZQXVM"

        class BoomAction:
            def field_value(self, name):  # skipcq: PYL-R0201 - test only
                raise RuntimeError(mark + "y" * (5 << 20))

        vm = PolicyVM([(Op.LOAD, "tool"), (Op.PASS,)])
        r = vm.eval(BoomAction())  # type: ignore[arg-type]
        self.assertFalse(r.allowed)
        self.assertTrue(r.reason.startswith("vm_fault:"))
        self.assertIn(mark, r.reason)
        self.assertIn("…sha256:", r.reason)
        self.assertLess(len(r.reason), len("vm_fault:") + MAX_LEDGER_ERROR_CHARS + 80)
        self.assertNotIn("y" * 1000, r.reason)

    def test_vmfault_branch_reason_is_capped(self):
        """#20: dedicated VMFault path (not generic Exception) also caps reason text."""
        mark = "ZQXVMF"

        class HugeOp:
            def __repr__(self):
                return mark + "z" * (5 << 20)

        vm = PolicyVM([(HugeOp(),)])  # type: ignore[arg-type]
        r = vm.eval(object())  # type: ignore[arg-type]
        self.assertFalse(r.allowed)
        self.assertTrue(r.reason.startswith("vm_fault:"))
        self.assertIn(mark, r.reason)
        self.assertIn("…sha256:", r.reason)
        self.assertLess(len(r.reason), len("vm_fault:") + MAX_LEDGER_ERROR_CHARS + 80)
        self.assertNotIn("z" * 1000, r.reason)
        self.assertIn("VMFault", r.reason)


class ExceptionLedgerErrorHelper(unittest.TestCase):
    def test_exception_ledger_error_uses_type_tag(self):
        class WeirdName(Exception):
            pass
        WeirdName.__name__ = "W" * 500
        e = WeirdName("msg")
        out = exception_ledger_error(e)
        self.assertTrue(out.startswith(type_tag(e) + ":"))
        self.assertNotIn("W" * 100, out)


class EncodingErrorReasonCap(unittest.TestCase):
    """#24: EncodingError / invalid_call reasons never carry raw unbounded __name__."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        from two_key.constitution import sign_constitution, verify_signed
        from two_key.core import TwoKey
        from two_key.gateway import ToolGateway
        from two_key.keys import generate_private_key
        from two_key.ledger import Ledger
        from two_key.testing import TEST_AGENT, FixedJudge

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        rules = [{"id": "tools", "allow_only_tools": ["search"]}]
        specs = {"search": {"irreversible": False, "data_class_floor": "public",
                            "payload": [{"json_path": "q"}]}}
        env = sign_constitution("Searching is fine.", rules, key, specs)
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), key), key.public_key(),
                         verify_signed(env, key.public_key()), [FixedJudge("a", "yes")],
                         private_key=key, quorum=QuorumPolicy(required_yes=1),
                         allow_test_doubles=True, monitored_agent=TEST_AGENT)
        self.gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled,
                              tools={"search": lambda a: "ok"})
        self.search = normalize_action({"tool": "search", "data_class": "public",
                                        "irreversible": False})

    def test_to_plain_pathological_type_name_is_fixed_label(self):
        from two_key.canonical import EncodingError, to_plain
        huge = "X" * 200_000
        bad = type(huge, (), {})()
        with self.assertRaises(EncodingError) as cm:
            to_plain({"q": bad})
        self.assertEqual(str(cm.exception), "unsupported_type")
        self.assertNotIn(huge, str(cm.exception))
        self.assertLess(len(str(cm.exception)), 40)

    def test_authorize_invalid_call_reason_bounded_for_huge_type_name(self):
        huge = "X" * 200_000
        bad = type(huge, (), {})()
        d = self.tk.authorize(self.search, {"q": bad}, "look")
        self.assertFalse(d.allowed)
        self.assertTrue(d.reason.startswith("invalid_call:"), d.reason)
        self.assertEqual(d.reason, "invalid_call:unsupported_type")
        self.assertNotIn(huge, d.reason)
        self.assertLess(len(d.reason), 80)
        # Ledger decision reason must stay bounded too.
        decisions = [e.body for e in self.tk.ledger.entries if e.kind == "decision"]
        self.assertTrue(decisions)
        self.assertEqual(decisions[-1]["reason"], "invalid_call:unsupported_type")
        self.assertEqual(decisions[-1].get("tool_args_error"), "unsupported_type")
        self.assertLess(len(str(decisions[-1])), 5000)

    def test_gateway_invalid_call_reason_bounded_for_huge_type_name(self):
        d = self.tk.authorize(self.search, {"q": "weather"}, "look")
        self.assertTrue(d.allowed, d.reason)
        huge = "Y" * 200_000
        bad = type(huge, (), {})()
        r = self.gw.invoke(d.token, "search", {"q": bad})
        self.assertFalse(r.allowed)
        self.assertEqual(r.reason, "invalid_call:unsupported_type")
        self.assertNotIn(huge, r.reason)
        self.assertLess(len(r.reason), 80)




class DeriveValueUnreadableBounded(unittest.TestCase):
    """#26: value_unreadable / derive_failed never carry raw unbounded __name__."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        from two_key.constitution import sign_constitution, verify_signed
        from two_key.core import TwoKey
        from two_key.keys import generate_private_key
        from two_key.ledger import Ledger
        from two_key.testing import TEST_AGENT, FixedJudge

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        rules = [{"id": "tools", "allow_only_tools": ["pay"]}]
        specs = {"pay": {"irreversible": False, "data_class_floor": "public",
                         "amount": {"json_path": "amt", "unit": "usd"},
                         "counterparties": [{"json_path": "to", "allow": ["ada"]}]}}
        env = sign_constitution("Pay ada.", rules, key, specs)
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), key), key.public_key(),
                         verify_signed(env, key.public_key()), [FixedJudge("a", "yes")],
                         private_key=key, quorum=QuorumPolicy(required_yes=1),
                         allow_test_doubles=True, monitored_agent=TEST_AGENT)
        self.pay = normalize_action({"tool": "pay", "data_class": "public", "irreversible": False})

    def test_pathological_type_name_in_value_unreadable_is_type_tag(self):
        from unittest import mock
        from two_key.derive import DeriveError, derive

        huge = "P" * 200_000
        cls = type(huge, (ValueError,), {})
        with mock.patch("two_key.derive._derive", side_effect=cls("boom")):
            with self.assertRaises(DeriveError) as cm:
                derive({"amount": {"json_path": "amt", "unit": "usd"}}, {"amt": 1})
        reason = str(cm.exception)
        tag = type_tag(cls("x"))
        self.assertEqual(reason, f"value_unreadable:{tag}")
        self.assertLessEqual(len(tag), MAX_TYPE_TAG_CHARS)
        self.assertNotIn(huge, reason)
        self.assertLess(len(reason), 80)

    def test_authorize_derive_failed_reason_bounded_for_huge_type_name(self):
        """Even a pre-capped DeriveError reason is cap_ledger_text'd into the decision."""
        from unittest import mock
        from two_key.derive import DeriveError

        huge = "Q" * 200_000
        with mock.patch("two_key.core.derive",
                        side_effect=DeriveError("value_unreadable:" + huge)):
            d = self.tk.authorize(self.pay, {"amt": 1, "to": "ada"}, "pay")
        self.assertFalse(d.allowed)
        self.assertTrue(d.reason.startswith("derive_failed:"), d.reason)
        self.assertNotIn(huge, d.reason)
        self.assertLess(len(d.reason), len("derive_failed:") + MAX_LEDGER_ERROR_CHARS + 80)
        self.assertIn("…sha256:", d.reason)
        decisions = [e.body for e in self.tk.ledger.entries if e.kind == "decision"]
        self.assertTrue(decisions)
        self.assertEqual(decisions[-1]["reason"], d.reason)
        self.assertLess(len(str(decisions[-1]["reason"])),
                        len("derive_failed:") + MAX_LEDGER_ERROR_CHARS + 80)

    def test_derive_raises_type_tag_then_authorize_is_bounded(self):
        from unittest import mock

        huge = "R" * 200_000
        cls = type(huge, (OverflowError,), {})
        with mock.patch("two_key.derive._derive", side_effect=cls("x")):
            d = self.tk.authorize(self.pay, {"amt": 1, "to": "ada"}, "pay")
        tag = type_tag(cls("x"))
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, f"derive_failed:value_unreadable:{tag}")
        self.assertLessEqual(len(tag), MAX_TYPE_TAG_CHARS)
        self.assertNotIn(huge, d.reason)
        self.assertLess(len(d.reason), 80)


class LedgerOmitDefaultBounded(unittest.TestCase):
    """#26: omitted_body JSON default uses type_tag, not raw __name__."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        from two_key.keys import generate_private_key
        from two_key.ledger import Ledger

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = generate_private_key()
        self.ledger = Ledger(Path(self.tmp.name, "ledger"), self.key)

    def test_pathological_type_name_does_not_inflate_omit_digest_allocation(self):

        huge = "O" * 200_000
        bad = type(huge, (), {})()
        entry = self.ledger.append_bounded("x", {"n": 3, "obj": bad})
        self.assertTrue(entry.body["body_omitted"])
        # Temporary dump uses <type_tag>, so body_size stays small (not ~200k).
        self.assertLess(entry.body["body_size"], 500)
        self.assertNotIn(huge, str(entry.body))
        tag = type_tag(bad)
        self.assertLessEqual(len(tag), MAX_TYPE_TAG_CHARS)
        # Digest still present and well-formed.
        self.assertRegex(entry.body["body_digest"], r"^sha256:[0-9a-f]{64}$")


class LlmAbstainTypeTag(unittest.TestCase):
    """#27: transport / malformed_response abstain errors use type_tag."""

    def test_transport_pathological_type_name_is_type_tag(self):
        from two_key.judges.ollama import OllamaJudge

        huge = "T" * 200_000
        cls = type(huge, (OSError,), {})

        def transport(url, headers, body, timeout):
            raise cls("boom")

        j = OllamaJudge("local", "ollama", "qwen2.5:7b", transport=transport)
        action = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
        b = j.score_bound("Searching is fine.", action, "look", None)
        self.assertEqual(b.vote, "abstain")
        tag = type_tag(cls("x"))
        self.assertEqual(b.error, f"transport: {tag}")
        self.assertLessEqual(len(tag), MAX_TYPE_TAG_CHARS)
        self.assertNotIn(huge, b.error)
        self.assertLess(len(b.error), 80)

    def test_malformed_response_pathological_type_name_is_type_tag(self):
        from two_key.judges.ollama import OllamaJudge

        huge = "M" * 200_000
        cls = type(huge, (RuntimeError,), {})

        def transport(url, headers, body, timeout):
            return {"message": {"content": '{"consistent": true, "confidence": 0.9, "rationale": "ok"}'}}

        j = OllamaJudge("local", "ollama", "qwen2.5:7b", transport=transport)

        def boom_extract(resp):
            raise cls("bad")

        j._extract_text = boom_extract  # type: ignore[method-assign]
        action = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
        b = j.score_bound("Searching is fine.", action, "look", None)
        self.assertEqual(b.vote, "abstain")
        tag = type_tag(cls("x"))
        self.assertEqual(b.error, f"malformed_response: {tag}")
        self.assertLessEqual(len(tag), MAX_TYPE_TAG_CHARS)
        self.assertNotIn(huge, b.error)
        self.assertLess(len(b.error), 80)


class CredentialErrorTypeName(unittest.TestCase):
    """#29: credential and start-up identity errors use type_tag, and the LLM credential abstain is capped."""

    HUGE = "C" * 5000

    def _raiser(self, cls):  # skipcq: PYL-R0201 - test only
        def fn():
            raise cls("secret-free message")
        return fn

    def test_token_callback_huge_class_name_is_bounded(self):
        from two_key.judges.credentials import CallbackTokenProvider, CredentialError

        cls = type(self.HUGE, (RuntimeError,), {})
        with self.assertRaises(CredentialError) as cm:
            CallbackTokenProvider(self._raiser(cls)).get_token()
        msg = str(cm.exception)
        label = msg.removeprefix("token callback failed: ")
        self.assertLessEqual(len(label), MAX_TYPE_TAG_CHARS)
        self.assertNotIn(self.HUGE, msg)

    def test_secret_from_huge_class_name_is_bounded(self):
        from two_key.identity import IdentityError, _secret_from
        from two_key.judges.credentials import CredentialProvider

        cls = type(self.HUGE, (RuntimeError,), {})

        class Bad(CredentialProvider):
            kind = "custom"

            def get_token(self):
                raise cls("nope")

        with self.assertRaises(IdentityError) as cm:
            _secret_from(Bad())
        msg = str(cm.exception)
        self.assertNotIn(self.HUGE, msg)
        self.assertIn("(" + "C" * MAX_TYPE_TAG_CHARS + ")", msg)
        self.assertLess(len(msg), 200)

    def test_ordinary_names_unchanged(self):
        from two_key.identity import IdentityError, _secret_from
        from two_key.judges.credentials import CallbackTokenProvider, CredentialError

        with self.assertRaises(CredentialError) as cm:
            CallbackTokenProvider(self._raiser(ValueError)).get_token()
        self.assertEqual(str(cm.exception), "token callback failed: ValueError")
        with self.assertRaises(IdentityError) as cm:
            _secret_from(CallbackTokenProvider(self._raiser(ValueError)))
        self.assertIn("(CredentialError)", str(cm.exception))

    def test_llm_credential_abstain_is_capped(self):
        from two_key.judges.credentials import CredentialError, CredentialProvider
        from two_key.judges.ollama import OllamaJudge

        class Huge(CredentialProvider):
            kind = "custom"

            def get_token(self):
                raise CredentialError("x" * 10000)

        def transport(url, headers, body, timeout):  # never reached
            raise AssertionError("no network")

        j = OllamaJudge("local", "ollama", "qwen2.5:7b", credential=Huge(), transport=transport)
        j.auth_header = "bearer"
        b = j.score_bound("Searching is fine.", SEARCH, "look", None)
        self.assertEqual(b.vote, "abstain")
        self.assertTrue(b.error.startswith("credential: xxx"))
        self.assertIn("…sha256:", b.error)
        self.assertNotIn("x" * (MAX_LEDGER_ERROR_CHARS + 1), b.error)
        self.assertEqual(b.error, cap_ledger_text("credential: " + "x" * 10000))
        self.assertLess(len(b.error), MAX_LEDGER_ERROR_CHARS + 80)


if __name__ == "__main__":
    unittest.main()
