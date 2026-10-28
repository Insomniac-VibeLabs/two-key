# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The tool check (#28, two_key/toolcheck.py): the token field, the redeem stamp, the tool's checks in order, the
receipt, and what the gateway does with a missing or bad one, in both profiles."""

import copy
import os
import tempfile
import unittest
from pathlib import Path

from two_key.capability import _b64u, _b64u_dec
from two_key.canonical import canonical_bytes
from two_key.constitution import ConstitutionError, sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.keys import generate_private_key, save_public_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.strict import loads_json
from two_key.testing import TEST_AGENT, FixedJudge
from two_key.toolcheck import (META_KEY, RECEIPT_LABEL, RECEIPT_PREFIX, STAMP_LABEL, STAMP_PREFIX, SeenRecord, ToolCheckConfig, ToolCheckError,
                               ToolChecker, key_fingerprint, mcp_receipt, new_tool_key, open_sealed, open_stamp_key,
                               peek, seal, stamp_key_path, text_hash, tool_args_hash, verify_receipt)
from perm import private

RULES = [{"id": "tools", "allow_only_tools": ["send", "plain"]}]
PROSE = "Only send to ada."
ARGS = {"to": "ada", "note": "hello", "extra": "dropped"}
PROJECTED = {"to": "ada", "note": "hello"}


def specs(check):
    send = {"irreversible": False, "data_class_floor": "public",
            "counterparties": [{"json_path": "to", "allow": ["ada"]}],
            "payload": [{"json_path": "note", "shape": "string"}]}
    if check is not None:
        send["tool_check"] = check
    return {"send": send, "plain": {"irreversible": False, "data_class_floor": "public"}}


CLAIM = {"tool": "send", "amount_usd": 0, "data_class": "public", "irreversible": False}


def result(text="sent"):
    return {"content": [{"type": "text", "text": text}], "isError": False}


class Deployment(unittest.TestCase):
    """A TwoKey whose ``send`` tool pins a receipt key, and the tool's own checker."""

    check = True

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.key = generate_private_key()
        self.tool_key_path = self.base / "tool.pem"
        fingerprint = new_tool_key(self.tool_key_path)
        self.fingerprint = fingerprint
        self.tk = self.two_key({"key": fingerprint} if self.check else None)
        self.calls = []

    def two_key(self, check, ledger_dir="ledger"):
        env = sign_constitution(PROSE, RULES, self.key, specs(check))
        ledger = Ledger(self.base / ledger_dir, self.key)
        judges = [FixedJudge("j0", "yes", provider="p0", maker="v0", local_weights=True),
                  FixedJudge("j1", "yes", provider="p1", maker="v1")]
        tk = TwoKey(ledger, self.key.public_key(), verify_signed(env, self.key.public_key()), judges,
                    private_key=self.key, quorum=QuorumPolicy(required_yes=2), allow_test_doubles=True,
                    monitored_agent=TEST_AGENT)
        self.addCleanup(tk.close)
        return tk

    def checker(self, tool="send", clock=None):
        loaded = self.tk.ledger.last_before(self.tk.ledger.size(), "constitution_loaded").body
        self.assertEqual(loaded["stamp_key_fingerprint"], self.tk.stamp_signer.fingerprint)
        config = ToolCheckConfig(tool, self.tk.issuer.public_key, self.tk.stamp_signer.public_key,
                                 _load(self.tool_key_path), self.base / "seen.sqlite")
        return ToolChecker(config, clock=clock)

    def upstream(self, checker, *, tamper=None):
        """The gateway's tool for ``send``: what an MCP server using the helper sends back."""
        def run(arguments, check=None):
            self.calls.append((copy.deepcopy(arguments), check))
            meta = {META_KEY: check} if check is not None else {}
            try:
                call = checker.check(arguments, meta)
            except ToolCheckError as e:
                out = dict(result("refused"), isError=True)
                return dict(out, _meta={META_KEY: {"receipt": checker.refusal(e.reason, meta)}})
            out = result()
            receipt = checker.receipt(call, out)
            out = dict(out, _meta={META_KEY: {"receipt": receipt}})
            return tamper(out) if tamper else out
        return run

    def gateway(self, run, **kw):
        gw = self.tk.gateway(tools={"send": run, "plain": lambda a: "plain ran"}, **kw)
        gw.receipt_reader = mcp_receipt
        return gw

    def token(self, args=None):
        decision = self.tk.authorize(CLAIM, ARGS if args is None else args, "send a note")
        self.assertTrue(decision.allowed, decision.reason)
        return decision.token


def _load(path):
    from two_key.keys import load_private_key_file
    return load_private_key_file(path)


class Formats(Deployment):
    def test_token_binds_the_arguments_the_tool_receives(self):
        payload = self.tk.issuer.verify(self.token())
        self.assertEqual(payload["tool_args_hash"], tool_args_hash(PROJECTED))
        plain = self.tk.authorize(dict(CLAIM, tool="plain"), {}, "plain")
        self.assertNotIn("tool_args_hash", self.tk.issuer.verify(plain.token))

    def test_constitution_loaded_pins_the_stamp_key_and_each_tool_key(self):
        body = self.tk.ledger.last_before(self.tk.ledger.size(), "constitution_loaded").body
        self.assertEqual(body["tool_check_keys"], {"send": self.fingerprint})
        self.assertTrue(private(stamp_key_path(self.tk.ledger)))

    def test_a_label_keeps_a_stamp_from_passing_as_anything_else(self):
        key = generate_private_key()
        stamp = seal(STAMP_PREFIX, STAMP_LABEL, key, {"v": 1, "alg": "ed25519", "jti": "a"})
        self.assertEqual(peek(STAMP_PREFIX, stamp, "stamp")[0]["jti"], "a")
        public, as_receipt = key.public_key(), RECEIPT_PREFIX + stamp[len(STAMP_PREFIX):]
        with self.assertRaisesRegex(ToolCheckError, "receipt_invalid"):
            open_sealed(RECEIPT_PREFIX, RECEIPT_LABEL, public, as_receipt, "receipt")
        token = self.token()
        with self.assertRaisesRegex(ToolCheckError, "stamp_invalid"):
            peek(STAMP_PREFIX, token, "stamp")

    def test_spec_tool_check_must_be_a_fingerprint_or_exempt(self):
        for bad in ({"key": "md5:1"}, {"key": "sha256:" + "0" * 64, "x": 1}, "yes", True):
            spec = specs(bad)
            with self.subTest(bad=bad), self.assertRaisesRegex(ConstitutionError, "tool_check"):
                sign_constitution(PROSE, RULES, self.key, spec)
        sign_constitution(PROSE, RULES, self.key, specs("exempt"))

    def test_a_tool_without_the_check_keeps_its_spec_hash(self):
        without = sign_constitution(PROSE, RULES, self.key, specs(None))
        self.assertNotIn("tool_check", without["signed"]["tool_specs"]["send"])


class Gateway(Deployment):
    def test_a_checked_call_runs_and_ledgers_the_receipt(self):
        gw = self.gateway(self.upstream(self.checker()))
        result_ = gw.invoke(self.token(), "send", ARGS)
        self.assertTrue(result_.allowed, result_.reason)
        arguments, check = self.calls[0]
        self.assertEqual(arguments, PROJECTED)
        self.assertEqual(set(check), {"token", "stamp"})
        redemption = [e for e in self.tk.ledger.entries if e.kind == "redemption"][-1].body
        self.assertEqual(redemption["receipt_outcome"], "ran")
        self.assertEqual(redemption["stamp_hash"], text_hash(check["stamp"]))
        started = [e for e in self.tk.ledger.entries if e.kind == "redemption_started"][-1]
        stamp = loads_json(_b64u_dec(check["stamp"].split(".")[1]))
        self.assertEqual(stamp["seq"], started.seq)

    def test_a_replayed_call_to_the_tool_is_refused_by_the_tool(self):
        checker = self.checker()
        gw = self.gateway(self.upstream(checker))
        self.assertTrue(gw.invoke(self.token(), "send", ARGS).allowed)
        _, check = self.calls[0]
        with self.assertRaisesRegex(ToolCheckError, "replayed"):
            checker.check(PROJECTED, {META_KEY: check})

    def test_a_direct_call_without_the_check_is_refused(self):
        checker = self.checker()
        with self.assertRaisesRegex(ToolCheckError, "check_missing"):
            checker.check(PROJECTED, {})

    def test_without_the_proxy_a_checked_tool_is_refused(self):
        gw = self.tk.gateway(tools={"send": lambda a: "ran"})
        self.assertEqual(gw.invoke(self.token(), "send", ARGS).reason, "tool_check_needs_proxy")

    def test_changed_arguments_are_refused_before_the_tool_runs(self):
        gw = self.gateway(self.upstream(self.checker()))
        token = self.token()
        payload = self.tk.issuer.verify(token)
        self.assertEqual(gw._check_ready("sha256:" + "1" * 64, dict(payload, tool_args_hash="sha256:" + "0" * 64),
                                         "send", PROJECTED),
                         "tool_args_mismatch")

    def test_a_bad_receipt_returns_the_output_and_alerts_in_the_default_profile(self):
        def forged(out):
            return dict(out, content=[{"type": "text", "text": "swapped"}])
        gw = self.gateway(self.upstream(self.checker(), tamper=forged))
        got = gw.invoke(self.token(), "send", ARGS)
        self.assertTrue(got.allowed)
        bad = [e.body for e in self.tk.ledger.entries if e.kind == "tool_receipt_invalid"]
        self.assertEqual(bad[-1]["why"], "mismatch")
        self.assertNotIn("tool_held", [e.kind for e in self.tk.ledger.entries])

    def test_high_assurance_withholds_the_output_and_holds_the_tool(self):
        def dropped(out):
            return {k: v for k, v in out.items() if k != "_meta"}
        gw = self.gateway(self.upstream(self.checker(), tamper=dropped), high_assurance=True)
        got = gw.invoke(self.token(), "send", ARGS)
        self.assertFalse(got.allowed)
        self.assertEqual(got.reason, "tool_receipt_invalid:missing")
        self.assertIsNone(got.output)
        self.assertTrue(self.tk.ledger.tool_held("send"))
        self.assertEqual(gw.invoke(self.token(), "send", ARGS).reason, "tool_held")
        reopened = Ledger(self.base / "ledger", self.key)       # a restart does not release it
        self.assertTrue(reopened.tool_held("send"))
        reopened.record("tool_released", {"tool": "send", "reason": "key fixed"})
        self.assertFalse(Ledger(self.base / "ledger", self.key).tool_held("send"))

    def test_a_refusal_receipt_counts_as_bad(self):
        later = self.checker(clock=lambda: 10 ** 10)          # the tool's clock is far ahead: expired
        gw = self.gateway(self.upstream(later), high_assurance=True)
        self.assertEqual(gw.invoke(self.token(), "send", ARGS).reason, "tool_receipt_invalid:refused:expired")

    def test_a_tool_error_spends_a_checked_token_too(self):
        def boom(arguments, check=None):
            raise RuntimeError("down")
        gw = self.gateway(boom)
        token = self.token()
        self.assertEqual(gw.invoke(token, "send", ARGS).reason, "tool_error:RuntimeError")
        self.assertEqual(gw.invoke(token, "send", ARGS).reason, "already_attempted")


class ToolChecks(Deployment):
    """Each of the tool's checks refuses on its own failure."""

    def call(self):
        captured = {}

        def run(_arguments, check=None):
            captured["meta"] = {META_KEY: dict(check)}
            return {"content": [], "isError": False}
        gw = self.gateway(run)
        gw.invoke(self.token(), "send", ARGS)
        return captured["meta"]

    def test_each_check(self):
        meta = self.call()
        token, stamp = meta[META_KEY]["token"], meta[META_KEY]["stamp"]
        other_token = self.call()[META_KEY]["token"]
        wrong_stamp_key = seal(STAMP_PREFIX, STAMP_LABEL, generate_private_key(),
                               loads_json(_b64u_dec(stamp.split(".")[1])))
        body, sig = token.split(".")[1:]
        forged_token = "tk1." + _b64u(canonical_bytes(dict(loads_json(_b64u_dec(body)), tool="plain"))) + "." + sig
        cases = [({}, PROJECTED, "check_missing"),
                 ({META_KEY: {"token": token}}, PROJECTED, "check_missing"),
                 ({META_KEY: {"token": token, "stamp": wrong_stamp_key}}, PROJECTED, "stamp_invalid"),
                 ({META_KEY: {"token": forged_token, "stamp": stamp}}, PROJECTED, "token_invalid"),
                 ({META_KEY: {"token": other_token, "stamp": stamp}}, PROJECTED, "stamp_mismatch"),
                 (meta, dict(PROJECTED, note="changed"), "args_mismatch")]
        checker = self.checker()
        for given, arguments, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(ToolCheckError, f"^{reason}$"):
                checker.check(arguments, given)
        other_tool, much_later = self.checker(tool="plain"), self.checker(clock=lambda: 10 ** 10)
        with self.assertRaisesRegex(ToolCheckError, "^tool_mismatch$"):
            other_tool.check(PROJECTED, meta)
        with self.assertRaisesRegex(ToolCheckError, "^expired$"):
            much_later.check(PROJECTED, meta)
        self.assertEqual(checker.check(PROJECTED, meta).tool, "send")
        with self.assertRaisesRegex(ToolCheckError, "^replayed$"):
            checker.check(PROJECTED, meta)

    def test_the_clock_allowance_is_five_seconds(self):
        meta = self.call()
        exp = loads_json(_b64u_dec(meta[META_KEY]["token"].split(".")[1]))["exp"]
        self.assertEqual(self.checker(clock=lambda: exp + 5).check(PROJECTED, meta).tool, "send")
        later = self.call()
        exp = loads_json(_b64u_dec(later[META_KEY]["token"].split(".")[1]))["exp"]
        late = self.checker(clock=lambda: exp + 5.5)
        with self.assertRaisesRegex(ToolCheckError, "^expired$"):
            late.check(PROJECTED, later)


class Receipts(Deployment):
    def test_verify_receipt_reasons(self):
        meta = ToolChecks.call(self)
        checker = self.checker()
        call = checker.check(PROJECTED, meta)
        stamp = meta[META_KEY]["stamp"]
        good = checker.receipt(call, result())
        digest = mcp_receipt(dict(result(), _meta={META_KEY: {"receipt": good}}))[1]
        args = dict(pinned=self.fingerprint, jti=call.jti, tool="send", stamp=stamp, result=digest)
        self.assertEqual(verify_receipt(good, **args)["outcome"], "ran")
        other = ToolChecker(ToolCheckConfig("send", self.tk.issuer.public_key, self.tk.stamp_signer.public_key,
                                            generate_private_key(), self.base / "other.sqlite"))
        cases = [(None, "missing"), ("tkr1.x.y", "bad_signature"),
                 (other.receipt(call, result()), "bad_signature"),
                 (checker.receipt(call, result("other")), "mismatch"),
                 (checker.refusal("replayed", meta), "refused:replayed")]
        for receipt, why in cases:
            with self.subTest(why=why), self.assertRaisesRegex(ToolCheckError, f"^{why}$"):
                verify_receipt(receipt, **args)
        with self.assertRaisesRegex(ToolCheckError, "^mismatch$"):
            verify_receipt(good, **{**args, "jti": "other"})


class StampKey(Deployment):
    def test_a_changed_stamp_key_is_refused(self):
        path = stamp_key_path(self.tk.ledger)
        pinned = self.tk.stamp_signer.fingerprint
        self.tk.close()
        path.unlink()
        with self.assertRaisesRegex(ToolCheckError, "stamp_key_missing"):
            open_stamp_key(self.tk.ledger, pinned)
        with self.assertRaisesRegex(TwoKeyConfigError, "stamp_key_missing"):
            self.two_key({"key": self.fingerprint})


class NoCheck(Deployment):
    check = False

    def test_no_stamp_key_and_no_new_fields(self):
        self.assertIsNone(self.tk.stamp_signer)
        self.assertFalse(stamp_key_path(self.tk.ledger).exists())
        body = self.tk.ledger.last_before(self.tk.ledger.size(), "constitution_loaded").body
        self.assertNotIn("stamp_key_fingerprint", body)
        self.assertNotIn("tool_args_hash", self.tk.issuer.verify(self.token()))


class Seen(unittest.TestCase):
    def test_owner_only_and_pruned(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = SeenRecord(Path(tmp, "seen.sqlite"))
            self.assertTrue(record.add("a", until=10, now=0))
            self.assertFalse(record.add("a", until=10, now=5))
            self.assertTrue(SeenRecord(Path(tmp, "seen.sqlite")).add("b", until=10, now=5))
            self.assertTrue(record.add("a", until=30, now=20))      # pruned once its token could not be valid
            self.assertTrue(private(Path(tmp, "seen.sqlite")))

    def test_a_record_others_can_read_is_refused(self):
        if os.name == "nt":
            self.skipTest("mode bits")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "seen.sqlite")
            path.write_bytes(b"")
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(ToolCheckError, "seen record"):
                SeenRecord(path)


class Config(Deployment):
    def test_load_checks_the_pinned_fingerprints(self):
        cap, stamp = self.base / "cap.pub.pem", self.base / "stamp.pub.pem"
        save_public_key(cap, self.tk.issuer.public_key)
        save_public_key(stamp, self.tk.stamp_signer.public_key)
        data = {"tool": "send", "capability_public_key": "cap.pub.pem",
                "capability_key_fingerprint": key_fingerprint(self.tk.issuer.public_key),
                "stamp_public_key": "stamp.pub.pem", "stamp_key_fingerprint": self.tk.stamp_signer.fingerprint,
                "tool_private_key": "tool.pem", "seen_record": "seen.sqlite"}
        path = self.base / "check.json"
        import json
        path.write_text(json.dumps(data))
        self.assertEqual(ToolCheckConfig.load(path).tool, "send")
        path.write_text(json.dumps(dict(data, stamp_key_fingerprint="sha256:" + "0" * 64)))
        with self.assertRaisesRegex(ToolCheckError, "pinned fingerprint"):
            ToolCheckConfig.load(path)


if __name__ == "__main__":
    unittest.main()
