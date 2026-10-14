"""Open issues fixed in 0.2.3: #47, #48, #51, #52 (auth keys), #54, #57, #60 items 1 and 5.

#52's merge keys are in test_strict_parsing.py; #56 is a workflow change.
"""

import http.server
import os
import stat
import sys
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from two_key.action import normalize_action
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.gateway import ToolGateway
from two_key.judges.config import JudgeConfigError, build_credential
from two_key.judges.transport import pooled_transport
from two_key.keys import generate_private_key, save_private_key
from two_key.ledger import Ledger, LedgerError
from two_key.quorum import QuorumPolicy, convene
from two_key.strict import StrictParseError, load_yaml, loads_json
from two_key.testing import TEST_AGENT, FixedJudge

from test_concept import PROSE, RULES, SPECS, _engine

DRAFT = {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False}
BIG = 10 ** 4400


class _Redirect(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:9/elsewhere")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class NoRedirectSwitch(unittest.TestCase):
    """#47: TWOKEY_DOCCHECK_FAKE_LLM no longer switches the transport to one that follows redirects."""

    def test_a_redirect_is_refused_whatever_the_environment(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), _Redirect)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{server.server_port}/v1/chat"
        with patch.dict(os.environ, {"TWOKEY_DOCCHECK_FAKE_LLM": "1"}):
            with self.assertRaisesRegex(urllib.error.HTTPError, "redirect refused"):
                pooled_transport(url, {"Authorization": "Bearer k"}, {}, 5)


class KeylessStart(unittest.TestCase):
    """#48: a TwoKey without private_key= is refused once a keyed TwoKey has run on the ledger, so it cannot leave
    an unpinned constitution_loaded that blocks every later keyed start."""

    def test_refused_once_a_keyed_twokey_has_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            env = sign_constitution(PROSE, RULES, key, SPECS)
            ledger = Ledger(Path(tmp, "ledger"), key)
            judges = [FixedJudge("a", "yes", provider="p0", maker="m0"), FixedJudge("b", "yes", provider="p1")]

            def start(**kw):
                return TwoKey(ledger, key.public_key(), verify_signed(env, key.public_key()), judges,
                              quorum=QuorumPolicy(required_yes=2), allow_test_doubles=True,
                              monitored_agent=TEST_AGENT, **kw)
            self.assertIsNone(start().issuer)              # a fresh ledger: a keyless start is fine
            keyed = start(private_key=key)
            for issue_first in (False, True):             # refused with or without tokens issued
                if issue_first:
                    self.assertTrue(keyed.authorize(DRAFT, {"to": "ada"}, "x").allowed)
                size = ledger.size()
                with self.assertRaisesRegex(TwoKeyConfigError, "^keyless_start_refused:"):
                    start()
                self.assertEqual(ledger.size(), size)     # nothing written
            self.assertTrue(keyed.authorize(DRAFT, {"to": "ada"}, "x").allowed)
            self.assertIsNotNone(start(private_key=key).issuer)


class LargeIntegers(unittest.TestCase):
    """#51: an integer over 4300 digits is a clean refusal on every path, never a ValueError."""

    def test_strict_parsers(self):
        for parse, text in ((loads_json, '{"a": ' + "9" * 4301 + "}"), (load_yaml, "a: -" + "9" * 4301 + "\n"),
                            (load_yaml, "a: 0x" + "F" * 3600 + "\n")):
            with self.subTest(parse=parse.__name__, text=text[:12]):
                with self.assertRaisesRegex(StrictParseError, "integer too large"):
                    parse(text)
        self.assertEqual(loads_json('{"a": ' + "9" * 4300 + "}")["a"], 10 ** 4300 - 1)
        self.assertEqual(load_yaml("a: 0x1F\nb: 1_000\n"), {"a": 31, "b": 1000})

    def test_authorize_and_gateway(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            self.assertEqual(tk.authorize(DRAFT, {"to": "ada", "n": BIG}, "x").reason,
                             "invalid_call:integer too large")
            self.assertEqual(tk.authorize({**DRAFT, "extra": BIG}, {"to": "ada"}, "x").reason,
                             "malformed_action:integer too large")
            self.assertEqual(tk.authorize(DRAFT, {"to": "ada"}, {"text": "x", "n": BIG}).reason, "malformed_proposal")
            agent = type("Agent", (), {"agent_id": "a", "hosting": "local"})()
            text = '{"tool": "email_draft", "arguments": {"n": ' + "9" * 4400 + '}, "proposal": "x"}'
            self.assertEqual(tk.authorize_from_agent(agent, text).reason, "malformed_proposal")
            ok = tk.authorize(DRAFT, {"to": "ada"}, "x")
            gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled, tools={"email_draft": lambda a: "ok"})
            size = tk.ledger.size()
            self.assertEqual(gw.invoke(ok.token, "email_draft", {"to": "ada", "n": BIG}).reason,
                             "invalid_call:integer too large")
            self.assertEqual([e.kind for e in tk.ledger.entries[size:]], ["gateway_denied"])
            self.assertTrue(gw.invoke(ok.token, "email_draft", {"to": "ada"}).allowed)


class LargeIntegersAtALowerLimit(unittest.TestCase):
    """#51 when the interpreter's own limit is lower (PYTHONINTMAXSTRDIGITS), and for int subclasses."""

    @unittest.skipUnless(hasattr(sys, "set_int_max_str_digits"), "no int string limit on this Python")
    def test_a_lower_runtime_limit_is_still_a_clean_refusal(self):
        from two_key.canonical import EncodingError, canonical_bytes
        old = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(640)
        self.addCleanup(sys.set_int_max_str_digits, old)
        with self.assertRaisesRegex(StrictParseError, "integer too large"):
            loads_json('{"a": ' + "9" * 1000 + "}")
        with self.assertRaisesRegex(StrictParseError, "integer too large"):
            load_yaml("a: " + "9" * 1000 + "\n")
        with self.assertRaisesRegex(EncodingError, "integer too large"):
            canonical_bytes({"a": 10 ** 1000})

    def test_an_int_subclass_cannot_hide_its_size(self):
        from two_key.canonical import EncodingError, canonical_bytes, to_plain

        class Small(int):
            def __abs__(self):
                return 0
        for fn in (canonical_bytes, to_plain):
            with self.subTest(fn=fn.__name__):
                with self.assertRaisesRegex(EncodingError, "integer too large"):
                    fn({"a": Small(BIG)})


class AuthKeys(unittest.TestCase):
    """#52: an unknown key inside an auth mapping is refused, not dropped."""

    def test_unknown_keys_are_refused(self):
        for auth in ({"type": "env", "var": "X", "vars": "Y"}, {"type": "none", "var": "X"},
                     {"type": "keyring", "service": "s", "username": "u", "servce": "t"},
                     {"type": "callback", "callback": "m:f", "timeout": 3}):
            with self.subTest(auth=auth):
                with self.assertRaisesRegex(JudgeConfigError, f"auth type {auth['type']} takes"):
                    build_credential(auth)
        self.assertEqual(build_credential({"type": "env", "var": "X"}).var, "X")
        with self.assertRaisesRegex(JudgeConfigError, r"auth type basic takes only \['password_env', 'username_env'\]"):
            build_credential({"type": "basic", "username_env": "U", "password_env": "P", "user": "x"})
        for bad in (["env"], {"a": 1}):
            with self.assertRaisesRegex(JudgeConfigError, "unknown auth type"):
                build_credential({"type": bad, "var": "X"})


class TooFewJudges(unittest.TestCase):
    """#54: a threshold above the judge count refuses at start-up, and convene calls no judge."""

    def test_twokey_refuses(self):
        key = generate_private_key()
        env = sign_constitution(PROSE, RULES, key, SPECS)
        for policy, reason in ((QuorumPolicy(required_yes=2), "too_few_judges_configured:1<2"),
                               (QuorumPolicy.without_diversity_floors(), "too_few_judges_configured:1<2"),
                               (QuorumPolicy(required_yes=1, min_responding=2), "too_few_judges_configured:1<2"),
                               (QuorumPolicy(required_yes=1, min_distinct_providers=2),
                                "insufficient_distinct_providers:1<2")):
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(TwoKeyConfigError, f"^{reason}: the quorum policy"):
                    TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                           [FixedJudge("a", "yes")], private_key=key, quorum=policy, allow_test_doubles=True,
                           monitored_agent=TEST_AGENT)

    def test_convene_calls_no_judge(self):
        calls = []

        class Counting(FixedJudge):
            def score(self, *a):
                calls.append(self.judge_id)
                return super().score(*a)
        act = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
        r = convene([Counting("a", "yes")], "Be careful.", act, "look", QuorumPolicy(required_yes=2))
        self.assertEqual((r.passed, r.reason, calls), (False, "too_few_judges_configured:1<2", []))


class KeyFiles(unittest.TestCase):
    """#57: the witness and capability keys load like the ledger key: no symlink, a regular file, mode 0600."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key, self.tk = _engine(self.tmp.name)
        self.path = Path(self.tmp.name, "ledger")

    def test_new_witness_directory_is_private(self):
        self.assertEqual(stat.S_IMODE(self.tk.ledger.witness_path.parent.stat().st_mode), 0o700)
        os.chmod(self.tk.ledger.witness_path.parent, 0o755)  # skipcq: BAN-B103 -- the test loosens the mode to check it is tightened to 0o700
        Ledger(self.path, self.key)                         # the default directory is set back to 0700
        self.assertEqual(stat.S_IMODE(self.tk.ledger.witness_path.parent.stat().st_mode), 0o700)

    def test_a_witness_directory_it_cannot_chmod_still_opens(self):
        real = os.chmod

        def chmod(path, mode, *a, **kw):
            if Path(path) == self.tk.ledger.witness_path.parent:
                raise PermissionError(1, "Operation not permitted")
            return real(path, mode, *a, **kw)
        with patch("two_key.ledger.os.chmod", chmod):
            Ledger(self.path, self.key).verify()

    def test_lax_or_linked_witness_key_is_refused(self):
        witness = self.tk.ledger.witness_path
        os.chmod(witness, 0o644)
        with self.assertRaisesRegex(LedgerError, "witness key: key_file_insecure"):
            Ledger(self.path, self.key)
        os.chmod(witness, 0o600)
        real = witness.with_name("real.pem")
        witness.rename(real)
        witness.symlink_to(real)
        with self.assertRaisesRegex(LedgerError, "witness key: key_file_unreadable"):
            Ledger(self.path, self.key)

    def test_lax_capability_key_is_refused(self):
        cap = self.tk.ledger.capability_key_path()
        os.chmod(cap, 0o644)
        env = sign_constitution(PROSE, RULES, self.key, SPECS)
        with self.assertRaisesRegex(TwoKeyConfigError, "capability key: key_file_insecure"):
            TwoKey(Ledger(self.path, self.key), self.key.public_key(), verify_signed(env, self.key.public_key()),
                   [FixedJudge("a", "yes"), FixedJudge("b", "yes", provider="p1")], private_key=self.key,
                   quorum=QuorumPolicy(required_yes=2), allow_test_doubles=True, monitored_agent=TEST_AGENT)


class GatewayAndLedger(unittest.TestCase):
    def test_a_non_ledger_error_after_the_intent_returns_a_result(self):
        """#60 item 1: an OSError (a full disk) while recording does not escape invoke."""
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            ok = tk.authorize(DRAFT, {"to": "ada"}, "x")
            gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled, tools={"email_draft": lambda a: "ok"})
            with patch.object(Ledger, "checkpoint", side_effect=OSError(28, "No space left on device")):
                r = gw.invoke(ok.token, "email_draft", {"to": "ada"})
            self.assertEqual((r.allowed, r.reason), (False, "ledger_failed:OSError"))

    def test_a_mismatched_principal_key_pair_is_refused_before_anything_is_written(self):
        """#60 item 5: every head it signed would fail on the next open."""
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            save_private_key(Path(tmp, "principal.pem"), key)
            with self.assertRaisesRegex(LedgerError, "^principal key mismatch"):
                Ledger(Path(tmp, "ledger"), generate_private_key(), key.public_key())
            self.assertFalse(Path(tmp, "ledger").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
