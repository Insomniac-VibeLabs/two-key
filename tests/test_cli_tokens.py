"""Fix 13: the CLI never prints the bearer token, never takes the session secret on argv,
loads the principal key through the safe loader, uses the configured TTL, and ledgers origin: cli."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from two_key.capability import _b64u_dec
from two_key.cli import main
from two_key.constitution import save_envelope, sign_constitution
from two_key.core import TwoKey
from two_key.keys import generate_private_key, load_private_key_file, save_private_key, save_public_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge
from perm import chmod, private

PROSE = "Drafts to ada are allowed."
RULES = [{"id": "tools", "allow_only_tools": ["email_draft"]}]
SPECS = {"email_draft": {"irreversible": False, "data_class_floor": "public",
                         "counterparties": [{"json_path": "to", "allow": ["ada"]}]}}

_real_load = TwoKey.load.__func__


def _load_with_doubles(cls, *a, **kw):
    return _real_load(cls, *a, allow_test_doubles=True, **kw)


class CliTokens(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.key = generate_private_key()
        save_private_key(self.dir / "principal.pem", self.key)
        save_envelope(self.dir / "c.json", sign_constitution(PROSE, RULES, self.key, SPECS))

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *extra, judges=None, env=None):
        judges = judges or [FixedJudge("a", "yes", provider="p0"), FixedJudge("b", "yes", provider="p1")]
        out, err = io.StringIO(), io.StringIO()
        argv = ["authorize", "--key", str(self.dir / "principal.pem"), "--ledger", str(self.dir / "ledger"),
                "--constitution", str(self.dir / "c.json"), "--judges", str(self.dir / "unused.yaml"),
                "--tool", "email_draft", "--args", '{"to":"ada"}', "--proposal", "draft",
                "--data-class", "public", "--no-irreversible", *extra]
        with patch("two_key.judges.config.load_config_file", return_value=(judges, QuorumPolicy(required_yes=2))), \
             patch("two_key.identity.load_monitored_agent_file", return_value=TEST_AGENT), \
             patch.object(TwoKey, "load", classmethod(_load_with_doubles)), \
             patch.dict(os.environ, env or {}), redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_token_never_printed_jti_and_digest_are(self):
        code, out, _ = self.run_cli()
        self.assertEqual(code, 0)
        rec = json.loads(out)
        self.assertNotIn("token", rec)
        self.assertNotIn("tk1.", out)
        self.assertTrue(rec["token_digest"].startswith("sha256:") or len(rec["token_digest"]) >= 32)
        issued = [e for e in Ledger(self.dir / "ledger", self.key).entries if e.kind == "capability_issued"]
        self.assertEqual(issued[-1].body["jti"], rec["token_jti"])
        self.assertEqual(issued[-1].body["token_hash"], rec["token_digest"])

    def test_emit_token_writes_0600_file_and_never_overwrites(self):
        path = self.dir / "token.txt"
        code, out, _ = self.run_cli("--emit-token", str(path))
        self.assertEqual(code, 0)
        self.assertTrue(private(path))
        token = path.read_text().strip()
        self.assertTrue(token.startswith("tk1."))
        self.assertNotIn(token, out)
        self.assertEqual(json.loads(out)["token_file"], str(path))
        code, _, err = self.run_cli("--emit-token", str(path))
        self.assertEqual(code, 1)
        self.assertIn("refusing to overwrite", err)
        self.assertEqual(path.read_text().strip(), token)

    def test_emit_token_on_deny_writes_nothing(self):
        path = self.dir / "token.txt"
        code, _, _ = self.run_cli("--emit-token", str(path),
                                  judges=[FixedJudge("a", "no", provider="p0"), FixedJudge("b", "yes", provider="p1")])
        self.assertEqual(code, 2)
        self.assertFalse(path.exists())

    def test_session_secret_on_argv_refused(self):
        code, out, err = self.run_cli("--agent-session", "s3cret-on-argv")
        self.assertEqual(code, 1)
        self.assertIn("--agent-session-env", err)
        self.assertNotIn("s3cret-on-argv", out + err)
        self.assertFalse((self.dir / "ledger").exists())

    def test_session_from_named_env_var(self):
        seen = {}
        real = TwoKey.authorize

        def spy(tk, *a, **kw):
            seen["session"] = kw.get("agent_session")
            return real(tk, *a, **kw)

        with patch.object(TwoKey, "authorize", spy):
            code, out, _ = self.run_cli("--agent-session-env", "TK_TEST_SESSION",
                                        env={"TK_TEST_SESSION": "from-env"})
        self.assertEqual(code, 0)
        self.assertEqual(seen["session"], "from-env")
        self.assertNotIn("from-env", out)
        code, _, err = self.run_cli("--agent-session-env", "TK_TEST_UNSET_VAR")
        self.assertEqual(code, 1)
        self.assertIn("TK_TEST_UNSET_VAR is not set", err)

    def test_configured_ttl_is_used(self):
        code, _, _ = self.run_cli("--ttl-seconds", "30", "--emit-token", str(self.dir / "t"))
        self.assertEqual(code, 0)
        payload = json.loads(_b64u_dec((self.dir / "t").read_text().strip().split(".")[1]))
        self.assertEqual(payload["exp"] - payload["iat"], 30)

    def test_origin_cli_ledgered(self):
        self.run_cli()
        decisions = [e for e in Ledger(self.dir / "ledger", self.key).entries if e.kind == "decision"]
        self.assertEqual(decisions[-1].body["origin"], "cli")

    def test_safe_loader_refuses_group_or_world_readable_key(self):
        path = self.dir / "principal.pem"
        chmod(path, 0o644)
        with self.assertRaisesRegex(ValueError, "key_file_insecure"):
            load_private_key_file(path)
        with self.assertRaisesRegex(SystemExit, "^--key: key_file_insecure"):    # one line, no traceback
            self.run_cli()
        chmod(path, 0o600)
        link = self.dir / "link.pem"
        link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, "key_file_unreadable"):
            load_private_key_file(link)
        load_private_key_file(path)

    def test_public_key_named_as_such(self):
        """Live run 7: audit --key given principal.pub.pem said 'run chmod 600', which would not help."""
        public = self.dir / "principal.pub.pem"
        save_public_key(public, self.key.public_key())
        chmod(public, 0o644)
        with self.assertRaisesRegex(ValueError, "^key_file_public: .*principal.pub.pem is a public key"):
            load_private_key_file(public)
        chmod(public, 0o600)        # whatever its mode
        with self.assertRaisesRegex(ValueError, "^key_file_public:"):
            load_private_key_file(public)
        with self.assertRaisesRegex(SystemExit, "^--key: key_file_public:"):
            main(["audit", "--key", str(public), "--ledger", str(self.dir / "ledger")])

    def test_not_a_private_key(self):
        junk = self.dir / "junk.pem"
        junk.write_text("not a key\n", encoding="ascii")
        chmod(junk, 0o600)
        with self.assertRaisesRegex(ValueError, "^key_file_invalid: .*not an unencrypted PEM private key"):
            load_private_key_file(junk)

    def test_key_help_names_the_private_key(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit):
            main(["audit", "--help"])
        text = " ".join(out.getvalue().split())     # argparse wraps to the terminal width
        self.assertIn("the principal private key (principal.pem", text)
        self.assertIn("not principal.pub.pem", text)


class CliOmittedClaims(unittest.TestCase):
    """#53: a flag the operator did not pass is not a claim."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.key = generate_private_key()
        save_private_key(self.dir / "principal.pem", self.key)
        save_envelope(self.dir / "c.json", sign_constitution(PROSE, RULES, self.key, SPECS))

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, argv):
        judges = [FixedJudge("a", "yes", provider="p0"), FixedJudge("b", "yes", provider="p1")]
        out, err = io.StringIO(), io.StringIO()
        with patch("two_key.judges.config.load_config_file", return_value=(judges, QuorumPolicy(required_yes=2))), \
             patch("two_key.identity.load_monitored_agent_file", return_value=TEST_AGENT), \
             patch.object(TwoKey, "load", classmethod(_load_with_doubles)), \
             redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_omitted_irreversible_follows_the_spec(self):
        code, out, err = self._run([
            "authorize", "--key", str(self.dir / "principal.pem"), "--ledger", str(self.dir / "ledger"),
            "--constitution", str(self.dir / "c.json"), "--judges", str(self.dir / "unused.yaml"),
            "--tool", "email_draft", "--args", '{"to":"ada"}', "--proposal", "draft",
            "--data-class", "public"])
        self.assertEqual(code, 0, out + err)
        self.assertEqual(json.loads(out)["reason"], "both_paths_allow")

    def test_omitted_amount_is_read_from_the_bytes(self):
        rules = [{"id": "tools", "allow_only_tools": ["pay_bill"]}]
        specs = {"pay_bill": {"irreversible": True, "data_class_floor": "financial",
                              "amount": {"json_path": "amount", "unit": "usd", "currency_path": "currency"},
                              "counterparties": [{"json_path": "to", "allow": ["power-co.example"]}]}}
        save_envelope(self.dir / "pay.json", sign_constitution(PROSE, rules, self.key, specs))
        base = ["authorize", "--key", str(self.dir / "principal.pem"), "--ledger", str(self.dir / "pay"),
                "--constitution", str(self.dir / "pay.json"), "--judges", str(self.dir / "unused.yaml"),
                "--tool", "pay_bill", "--args",
                '{"amount": 12.5, "currency": "usd", "to": "power-co.example"}',
                "--proposal", "pay", "--data-class", "financial"]
        code, out, err = self._run(base)
        self.assertEqual(code, 0, out + err)
        code, out, err = self._run([*base, "--amount-usd", "1"])
        self.assertEqual(code, 2, out + err)
        self.assertEqual(json.loads(out)["reason"], "amount_mismatch")


class LibraryRecord(unittest.TestCase):
    def test_to_record_has_no_bearer_token(self):
        from two_key.core import Decision
        d = Decision(True, "both_paths_allow", "tk1.eyJqdGkiOiJ4In0.sig", {}, {}, 3, None)
        rec = d.to_record()
        self.assertNotIn("token", rec)
        self.assertEqual(rec["token_jti"], "x")
        self.assertEqual(d.token, "tk1.eyJqdGkiOiJ4In0.sig")
        self.assertIsNone(Decision(False, "no", None, {}, {}, 3, None).to_record()["token_digest"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
