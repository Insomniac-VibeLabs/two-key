"""Concept invariants: both paths, ledger, token, agent hook, no execution."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from two_key.agents import AgentConfigError, MonitoredAgent, parse_proposal
from two_key.constitution import ConstitutionSignatureError, sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.gateway import ToolGateway
from two_key.judges.config import JudgeConfigError, build_credential
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.ledger import LedgerError, merkle_root
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumConfigError, QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge


RULES = [
    {"id": "tools", "allow_only_tools": ["search", "email_draft"]},
    {"id": "no-wires", "deny_if": {"tool": "wire_transfer"}},
    {"id": "cap", "deny_if": {"amount_usd_gt": 200}},
    {"id": "sensitive", "deny_if": {"data_class_in": ["medical", "classified"]}},
]
SPECS = {
    "search": {"irreversible": False, "data_class_floor": "public"},
    "email_draft": {
        "irreversible": False,
        "data_class_floor": "public",
        "counterparties": [{"json_path": "to", "allow": ["ada", "ada@example"]}],
    },
}
PROSE = "Never wire money. Cap spend at 200. No medical or classified data."


def _engine(tmp, votes=("yes", "yes"), quorum=None):
    key = generate_private_key()
    env = sign_constitution(PROSE, RULES, key, SPECS)
    ledger = Ledger(Path(tmp, "ledger"), key)
    judges = [FixedJudge(f"j{i}", vote, provider=f"p{i}", maker=f"v{i}", local_weights=(i == 0))
              for i, vote in enumerate(votes)]
    tk = TwoKey(ledger, key.public_key(), verify_signed(env, key.public_key()), judges,
                private_key=key, quorum=quorum or QuorumPolicy(required_yes=len(votes)),
                allow_test_doubles=True, monitored_agent=TEST_AGENT)
    return key, tk


class ConceptTests(unittest.TestCase):
    def test_both_paths_required_and_ledger_records_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp, ("yes", "no"))
            decision = tk.authorize(
                {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"to": "ada"}, "draft a note")
            self.assertFalse(decision.allowed)
            self.assertIsNone(decision.token)
            self.assertTrue(decision.path_a["allowed"])
            self.assertFalse(decision.path_b["passed"])
            kinds = [e.kind for e in tk.ledger.entries]
            self.assertIn("path_a", kinds)
            self.assertIn("path_b", kinds)
            tk.ledger.verify()

    def test_path_a_deny_still_runs_path_b(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "wire_transfer", "amount_usd": 10, "data_class": "public", "irreversible": True},
                {"to": "bob"}, "wire it")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.path_a["denied_by"], "tools")
            self.assertIn("path_b", [e.kind for e in tk.ledger.entries])

    def test_token_single_use_and_bound_to_args(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"to": "ada"}, "draft")
            self.assertTrue(decision.allowed)
            gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled,
                             tools={"email_draft": lambda a: calls.append(a) or {"ok": True}})
            first = gw.invoke(decision.token, "email_draft", {"to": "ada"})
            replay = gw.invoke(decision.token, "email_draft", {"to": "ada"})
            mismatch = gw.invoke(decision.token, "email_draft", {"to": "eve"})
            self.assertTrue(first.allowed)
            self.assertEqual(calls, [{"to": "ada"}])
            self.assertFalse(any(p.name.startswith(".redeem-") for p in Path(tmp, "ledger").iterdir()))
            self.assertTrue((Path(tmp) / "ledger.redeem-locks").is_dir())
            self.assertTrue((Path(tmp) / "ledger.lock").is_file())
            self.assertEqual(replay.reason, "already_redeemed")
            self.assertFalse(mismatch.allowed)

    def test_agent_hook_does_not_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            agent = MonitoredAgent("grok", "xai", "grok", "https://api.x.ai/v1", "cloud", kind="openai_compatible")
            raw = json.dumps({"tool": "email_draft", "arguments": {"to": "ada"}, "proposal": "draft a note",
                              "amount_usd": 0, "data_class": "public", "irreversible": False})
            decision = tk.authorize_from_agent(agent, raw, agent_session="sess")
            self.assertTrue(decision.allowed)
            self.assertFalse(decision.agent["trusted"])
            self.assertEqual(decision.agent["hosting"], "cloud")
            self.assertFalse(hasattr(decision, "tool_output"))

    def test_revoke_blocks_outstanding_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "search", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"q": "weather"}, "search")
            tk.revoke("principal stop")
            gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled, tools={"search": lambda a: a})
            result = gw.invoke(decision.token, "search", {"q": "weather"})
            self.assertEqual(result.reason, "revoked_or_reloaded")

    def test_unsigned_constitution_refused(self):
        key = generate_private_key()
        env = sign_constitution(PROSE, RULES, key, SPECS)
        env["signature"] = "aa"
        with self.assertRaisesRegex(ConstitutionSignatureError, "^constitution signature failed"):
            verify_signed(env, key.public_key())

    def test_schema_400_falls_back_once(self):
        class Rec:
            def __init__(self):
                self.calls = []
            def __call__(self, url, headers, body, timeout):
                self.calls.append(body)
                if len(self.calls) == 1:
                    raise urllib.error.HTTPError("u", 400, "schema", {}, None)
                return {"choices": [{"message": {"content": json.dumps(
                    {"consistent": True, "confidence": 0.9, "rationale": "ok"})}}]}
        rec = Rec()
        judge = OpenAICompatibleJudge("x", "xai", "grok", "https://api.x.ai/v1", transport=rec)
        from two_key.action import normalize_action
        ballot = judge.score_bound(PROSE, normalize_action({"tool": "search", "data_class": "public", "irreversible": False}), "search", None, agent_session="principal-session")
        self.assertEqual(ballot.vote, "yes")
        self.assertEqual(rec.calls[0]["response_format"]["type"], "json_schema")
        self.assertEqual(rec.calls[0]["reasoning_effort"], "low")
        self.assertNotIn("reasoning_effort", rec.calls[1])
        self.assertEqual(rec.calls[1]["response_format"]["type"], "json_object")

    def test_proposal_parser_rejects_extra_keys(self):
        with self.assertRaisesRegex(AgentConfigError, "no other keys"):
            parse_proposal(json.dumps({"tool": "search", "arguments": {}, "proposal": "x", "exec": True}))



    def test_tool_error_does_not_consume_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"to": "ada"}, "draft")
            calls = {"n": 0}
            def flaky(args):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise RuntimeError("backend down")
                return {"ok": True}
            gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled, tools={"email_draft": flaky})
            first = gw.invoke(decision.token, "email_draft", {"to": "ada"})
            second = gw.invoke(decision.token, "email_draft", {"to": "ada"})
            self.assertFalse(first.allowed)
            self.assertTrue(first.reason.startswith("tool_error:"))
            self.assertTrue(second.allowed)
            self.assertEqual(calls["n"], 2)

    def test_crash_after_intent_does_not_run_tool_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"to": "ada"}, "draft")
            payload = tk.issuer.verify(decision.token)
            tk.ledger.append("redemption_started", {"jti": payload["jti"], "tool": "email_draft"})
            tk.ledger.checkpoint()
            calls = {"n": 0}
            def tool(args):
                calls["n"] += 1
                return {"ok": True}
            gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled, tools={"email_draft": tool})
            result = gw.invoke(decision.token, "email_draft", {"to": "ada"})
            self.assertFalse(result.allowed)
            self.assertEqual(result.reason, "already_attempted")
            self.assertEqual(calls["n"], 0)

    def test_merkle_does_not_duplicate_odd_leaf(self):
        leaves = [hashlib.sha256(str(i).encode()).digest() for i in range(3)]
        root = merkle_root(leaves)
        duplicated = hashlib.sha256(b"\x01" + hashlib.sha256(b"\x01" + hashlib.sha256(b"\x00" + leaves[0]).digest() + hashlib.sha256(b"\x00" + leaves[1]).digest()).digest() + hashlib.sha256(b"\x01" + hashlib.sha256(b"\x00" + leaves[2]).digest() + hashlib.sha256(b"\x00" + leaves[2]).digest()).digest()).digest()
        self.assertNotEqual(root, duplicated)
        self.assertEqual(len(root), 32)

    def test_ledger_ciphertext_and_witness(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            raw = Path(tmp, "ledger", "entries.jsonl").read_text()
            self.assertNotIn("constitution_loaded", raw)
            self.assertIn("two-key-concept-ledger-enc/1", raw)
            self.assertFalse(any(p.name == "witness.pem" for p in Path(tmp, "ledger").iterdir()))
            self.assertTrue(tk.ledger.witness_path.exists())
            self.assertFalse(str(tk.ledger.witness_path).startswith(str(Path(tmp, "ledger")) + "/"))
            key = tk.ledger.private_key
            Ledger(Path(tmp, "ledger"), key).verify()
            with self.assertRaises(LedgerError):
                Ledger(Path(tmp, "ledger"), key, ledger_key_path=Path(tmp, "missing.key"))
            with self.assertRaises(LedgerError):
                Ledger(Path(tmp, "ledger"), generate_private_key())

    def test_missing_witness_refuses_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            witness = tk.ledger.witness_path
            witness.unlink()
            with self.assertRaises(LedgerError):
                tk.ledger.append("revocation", {"reason": "stop"})
                tk.ledger.checkpoint()

    def test_encrypted_ledger_reloads_in_second_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            from two_key.keys import save_private_key
            save_private_key(Path(tmp, "principal.pem"), key)
            ledger = Path(tmp, "ledger")
            led = Ledger(ledger, key)
            led.append("note", {"ok": True})
            led.checkpoint()
            script = "from two_key.ledger import Ledger; from two_key.keys import load_private_key; " \
                     "led = Ledger(%r, load_private_key(%r)); led.verify(); print(led.size())" % (str(ledger), str(Path(tmp, "principal.pem")))
            root = Path(__file__).resolve().parents[1]
            env = dict(os.environ)
            env["PYTHONPATH"] = str(root)
            proc = subprocess.run([sys.executable, "-c", script], cwd=str(root), env=env,
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), "2")      # witness_pinned, then the note

    def test_stub_auth_rejected(self):
        with self.assertRaises(JudgeConfigError):
            build_credential({"type": "username_password", "username": "me", "password_env": "PW"})
        with self.assertRaises(JudgeConfigError):
            build_credential({"type": "oauth_device_code", "client_id": "x",
                              "device_authorization_endpoint": "https://example/device",
                              "token_endpoint": "https://example/token"})

    def test_cli_authorize_does_not_execute(self):
        from two_key.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            from two_key.keys import save_private_key
            from two_key.constitution import save_envelope
            save_private_key(Path(tmp, "principal.pem"), key)
            save_envelope(Path(tmp, "c.json"), sign_constitution(PROSE, RULES, key, SPECS))
            judges = [FixedJudge("a", "yes", provider="p0", maker="v0", local_weights=True),
                      FixedJudge("b", "yes", provider="p1", maker="v1")]
            with self.assertRaises(SystemExit):
                main(["authorize", "--allow-test-doubles"])
            buf = io.StringIO()
            with patch("two_key.judges.config.load_config_file", return_value=(judges, QuorumPolicy(required_yes=2))), \
                 patch("two_key.identity.load_monitored_agent_file", return_value=TEST_AGENT):
                with redirect_stdout(buf):
                    with self.assertRaises(ValueError) as raised:
                        main(["authorize", "--key", str(Path(tmp, "principal.pem")),
                              "--ledger", str(Path(tmp, "ledger")),
                              "--constitution", str(Path(tmp, "c.json")),
                              "--judges", str(Path(tmp, "unused.yaml")),
                              "--tool", "email_draft", "--args", '{"to":"ada"}',
                              "--proposal", "draft"])
            self.assertIn("test-double", str(raised.exception))
            self.assertNotIn("both_paths_allow", buf.getvalue())

    def test_cli_authorize_defaults_match_library(self):
        from two_key.cli import main
        from two_key.core import Decision
        captured = {}

        class _Stopped:
            def authorize(self, action, arguments, proposal, agent_session=None, origin=None):
                captured["action"] = action
                return Decision(False, "stopped", None, {}, {}, 0, None)

        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            from two_key.keys import save_private_key
            from two_key.constitution import save_envelope
            save_private_key(Path(tmp, "principal.pem"), key)
            save_envelope(Path(tmp, "c.json"), sign_constitution(PROSE, RULES, key, SPECS))
            judges = [FixedJudge("a", "yes", provider="p0")]
            buf = io.StringIO()
            with patch("two_key.judges.config.load_config_file", return_value=(judges, QuorumPolicy(required_yes=1))), \
                 patch("two_key.identity.load_monitored_agent_file", return_value=TEST_AGENT), \
                 patch("two_key.ledger.Ledger", return_value=object()), \
                 patch("two_key.core.TwoKey.load", return_value=_Stopped()), \
                 redirect_stdout(buf):
                code = main(["authorize", "--key", str(Path(tmp, "principal.pem")),
                             "--ledger", str(Path(tmp, "ledger")),
                             "--constitution", str(Path(tmp, "c.json")),
                             "--judges", str(Path(tmp, "unused.yaml")),
                             "--tool", "email_draft", "--args", "{}",
                             "--proposal", "draft"])
            self.assertEqual(code, 2)
            self.assertEqual(captured["action"], {"tool": "email_draft"})
            self.assertNotIn("amount_usd", captured["action"])
            self.assertNotIn("data_class", captured["action"])
            self.assertNotIn("irreversible", captured["action"])
            with patch("two_key.judges.config.load_config_file", return_value=(judges, QuorumPolicy(required_yes=1))), \
                 patch("two_key.identity.load_monitored_agent_file", return_value=TEST_AGENT), \
                 patch("two_key.ledger.Ledger", return_value=object()), \
                 patch("two_key.core.TwoKey.load", return_value=_Stopped()), \
                 redirect_stdout(buf):
                main(["authorize", "--key", str(Path(tmp, "principal.pem")),
                      "--ledger", str(Path(tmp, "ledger")),
                      "--constitution", str(Path(tmp, "c.json")),
                      "--judges", str(Path(tmp, "unused.yaml")),
                      "--tool", "email_draft", "--args", "{}",
                      "--proposal", "draft", "--data-class", "public",
                      "--no-irreversible"])
            self.assertEqual(captured["action"]["data_class"], "public")
            self.assertIs(captured["action"]["irreversible"], False)

    def test_stale_ledger_refuses_to_append(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            path = Path(tmp, "ledger")
            first = Ledger(path, key)
            first.append("note", {"n": 1})
            first.checkpoint()
            second = Ledger(path, key)
            first.append("note", {"n": 2})
            first.checkpoint()
            with self.assertRaises(LedgerError) as raised:
                second.append("note", {"n": 3})
            self.assertIn("another writer", str(raised.exception))
            reopened = Ledger(path, key)
            self.assertEqual(reopened.size(), 3)            # witness_pinned and two notes
            reopened.append("note", {"n": 3})
            self.assertEqual(reopened.size(), 4)
            self.assertFalse((path / ".redeem-abc.lock").exists())
            self.assertTrue(first.lock_path().is_file())
            self.assertFalse(str(first.lock_path()).startswith(str(path) + os.sep))

    def test_one_judge_default_and_high_assurance_opt_in(self):
        policy = QuorumPolicy()
        self.assertEqual(policy.min_makers, 1)
        self.assertEqual(policy.min_local_judges, 0)
        self.assertFalse(policy.require_local_yes)
        self.assertFalse(policy.require_path_a_first)
        self.assertEqual(QuorumPolicy.without_diversity_floors(required_yes=2), QuorumPolicy(required_yes=2))
        strict = QuorumPolicy.high_assurance()
        self.assertEqual((strict.min_makers, strict.min_local_judges, strict.require_local_yes), (2, 1, True))
        same = [FixedJudge("a", "yes", provider="p", maker="v"),
                FixedJudge("b", "yes", provider="p", maker="v")]
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            env = sign_constitution(PROSE, RULES, key, SPECS)
            ledger = Ledger(Path(tmp, "ledger"), key)
            constitution = verify_signed(env, key.public_key())
            with self.assertRaises(QuorumConfigError):
                TwoKey(ledger, key.public_key(), constitution, same, private_key=key,
                       quorum=QuorumPolicy.high_assurance(required_yes=2), allow_test_doubles=True, monitored_agent=TEST_AGENT)
            tk = TwoKey(ledger, key.public_key(), constitution, same, private_key=key,
                        quorum=QuorumPolicy(required_yes=2), allow_test_doubles=True, monitored_agent=TEST_AGENT)
            decision = tk.authorize(
                {"tool": "search", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"q": "weather"}, "search")
            self.assertTrue(decision.allowed, decision.reason)
        with tempfile.TemporaryDirectory() as tmp:
            _, one = _engine(tmp, ("yes",), quorum=QuorumPolicy(required_yes=1))
            decision = one.authorize(
                {"tool": "search", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"q": "weather"}, "search")
            self.assertTrue(decision.allowed, decision.reason)

    def test_quorum_profile_in_yaml(self):
        from two_key.judges.config import load_config
        judge = {"id": "l", "type": "ollama", "model": "qwen2.5:7b"}
        _, policy = load_config({"judges": [judge]})
        self.assertEqual((policy.required_yes, policy.min_makers, policy.require_local_yes), (1, 1, False))
        with self.assertRaisesRegex(JudgeConfigError, "insufficient_makers:1<2"):
            load_config({"judges": [judge], "quorum": {"profile": "high_assurance", "required_yes": 1}})
        with self.assertRaisesRegex(JudgeConfigError, "quorum profile must be one of"):
            load_config({"judges": [judge], "quorum": {"profile": "paranoid"}})

    def test_unmeetable_quorum_in_config_names_the_documented_reason(self):
        # Live run 5 (C45): the loader said "required_yes=3 exceeds number of judges 2", not the
        # documented too_few_judges_configured reason.
        from two_key.judges.config import load_config
        judges = [{"id": "a", "type": "ollama", "model": "qwen2.5:7b"},
                  {"id": "b", "type": "ollama", "model": "llama3.1:8b", "base_url": "http://localhost:11435"}]
        with self.assertRaisesRegex(JudgeConfigError, r"^too_few_judges_configured:2<3 "):
            load_config({"judges": judges, "quorum": {"required_yes": 3}})
        with self.assertRaisesRegex(JudgeConfigError, r"^too_few_judges_configured:2<3 "):
            load_config({"judges": judges, "quorum": {"required_yes": 1, "min_responding": 3}})

    def test_section4_does_not_skip_path_b(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp, quorum=QuorumPolicy.section4(required_yes=2))
            decision = tk.authorize(
                {"tool": "wire_transfer", "amount_usd": 10, "data_class": "public", "irreversible": True},
                {"to": "bob"}, "wire it")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.path_a["denied_by"], "tools")
            self.assertIn("path_b", [e.kind for e in tk.ledger.entries])
            self.assertTrue(tk.quorum.require_path_a_first)

    def test_gateway_cannot_mint(self):
        from two_key.capability import CapabilityIssuer, TokenError
        from two_key.keys import fingerprint
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            self.assertIsNotNone(tk.issuer.private_key)
            self.assertNotEqual(fingerprint(tk.issuer.public_key), fingerprint(tk.public_key))
            cap = tk.ledger.capability_key_path()
            self.assertTrue(cap.is_file())
            self.assertFalse(str(cap).startswith(str(Path(tmp, "ledger")) + os.sep))
            decision = tk.authorize(
                {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False,
                 "counterparty": "ada"},
                {"to": "ada"}, "draft")
            self.assertTrue(decision.allowed, decision.reason)
            gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled,
                             tools={"email_draft": lambda a: {"ok": True}})
            self.assertIsNone(gw.issuer.private_key)
            with self.assertRaises(TokenError):
                gw.issuer.issue(tool="email_draft", arguments={"to": "ada"}, ledger_root="x",
                                ledger_size=0, bytecode_hash="x", nl_hash="x")
            forged = CapabilityIssuer(tk.ledger.private_key, clock=tk.issuer.clock)
            bad = forged.issue(tool="email_draft", arguments={"to": "ada"},
                               ledger_root=tk.ledger.merkle_root(), ledger_size=tk.ledger.size(),
                               bytecode_hash=tk.compiled.bytecode_hash, nl_hash=tk.compiled.nl_hash,
                               spec_hash=tk.compiled.spec_hash)
            self.assertEqual(gw.invoke(bad.token, "email_draft", {"to": "ada"}).reason, "bad_signature")
            self.assertTrue(gw.invoke(decision.token, "email_draft", {"to": "ada"}).allowed)




if __name__ == "__main__":
    unittest.main()
