# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""#58 on the command line: --witness-public-key on authorize, rotate-witness, and audit."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from two_key.cli import main
from two_key.constitution import save_envelope, sign_constitution
from two_key.core import TwoKey
from two_key.keys import generate_private_key, public_raw, save_private_key, save_public_key
from two_key.ledger import witness_key_fingerprint
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

from test_cli_tokens import PROSE, RULES, SPECS, _load_with_doubles


class CliWitness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.key = generate_private_key()
        save_private_key(self.dir / "principal.pem", self.key)
        save_envelope(self.dir / "c.json", sign_constitution(PROSE, RULES, self.key, SPECS))
        self.witness_pub = self.dir / "ledger.witness" / "witness.pub.pem"
        self.pin = self.dir / "pins" / "witness.pub.pem"     # the operator's copy, outside the ledger's reach

    def cli(self, *argv):  # skipcq: PYL-R0201 - test only
        judges = [FixedJudge("a", "yes", provider="p0"), FixedJudge("b", "yes", provider="p1")]
        out, err = io.StringIO(), io.StringIO()
        with patch("two_key.judges.config.load_config_file", return_value=(judges, QuorumPolicy(required_yes=2))), \
             patch("two_key.identity.load_monitored_agent_file", return_value=TEST_AGENT), \
             patch.object(TwoKey, "load", classmethod(_load_with_doubles)), \
             redirect_stdout(out), redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def authorize(self, *extra):
        return self.cli("authorize", "--key", str(self.dir / "principal.pem"), "--ledger", str(self.dir / "ledger"),
                        "--constitution", str(self.dir / "c.json"), "--judges", str(self.dir / "unused.yaml"),
                        "--tool", "email_draft", "--args", '{"to":"ada"}', "--proposal", "draft",
                        "--data-class", "public", "--no-irreversible", *extra)

    def ledger_cmd(self, cmd, *extra):
        return self.cli(cmd, "--key", str(self.dir / "principal.pem"), "--ledger", str(self.dir / "ledger"), *extra)

    def keep_pin(self):
        self.pin.parent.mkdir(exist_ok=True)
        self.pin.write_bytes(self.witness_pub.read_bytes())

    def test_authorize_with_the_pin(self):
        self.assertEqual(self.authorize()[0], 0)
        self.keep_pin()
        self.assertEqual(self.authorize("--witness-public-key", str(self.pin))[0], 0)
        other = self.dir / "other.pub.pem"
        save_public_key(other, generate_private_key().public_key())
        code, out, err = self.authorize("--witness-public-key", str(other))
        self.assertEqual((code, out), (1, ""))
        self.assertIn("ledger refused: witness_key_changed", err)
        with self.assertRaisesRegex(SystemExit, "--witness-public-key"):
            self.authorize("--witness-public-key", str(self.dir / "missing.pem"))
        with self.assertRaisesRegex(SystemExit, "empty path"):
            self.authorize("--witness-public-key", "")      # an unset $VAR must not turn the pin off

    def test_audit_reports_both_pins(self):
        self.assertEqual(self.authorize()[0], 0)
        self.keep_pin()
        code, out, _ = self.ledger_cmd("audit", "--witness-public-key", str(self.pin))
        self.assertEqual(code, 0, out)
        rec = json.loads(out)
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["decision_digest_problems"], [])
        w = rec["witness"]
        self.assertEqual(w["in_ledger"]["source"], "new_ledger")
        self.assertEqual(w["head"], w["configured"])
        self.assertEqual(w["head"], w["in_ledger"]["fingerprint"])
        code, out, _ = self.ledger_cmd("audit")
        self.assertEqual(code, 0)
        self.assertIsNone(json.loads(out)["witness"]["configured"])

    def test_audit_refusal_is_printed(self):
        self.assertEqual(self.authorize()[0], 0)
        other = self.dir / "other.pub.pem"
        save_public_key(other, generate_private_key().public_key())
        code, out, _ = self.ledger_cmd("audit", "--witness-public-key", str(other))
        self.assertEqual(code, 1)
        rec = json.loads(out)
        self.assertFalse(rec["ok"])
        self.assertIn("witness_key_changed", rec["error"])

    def test_rotate_witness_then_update_the_pin(self):
        self.assertEqual(self.authorize()[0], 0)
        self.keep_pin()
        code, out, _ = self.ledger_cmd("rotate-witness", "--witness-public-key", str(self.pin), "--reason", "yearly")
        self.assertEqual(code, 0, out)
        rec = json.loads(out)
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["witness_public_key_path"], str(self.witness_pub))
        from two_key.keys import load_public_key
        new = load_public_key(self.witness_pub)
        self.assertEqual(rec["new_witness_key_fingerprint"], witness_key_fingerprint(public_raw(new)))
        # The stored pin is the old key until the operator updates it.
        code, _, err = self.authorize("--witness-public-key", str(self.pin))
        self.assertEqual(code, 1)
        self.assertIn("witness_key_changed", err)
        self.keep_pin()
        self.assertEqual(self.authorize("--witness-public-key", str(self.pin))[0], 0)
        code, out, _ = self.ledger_cmd("audit", "--witness-public-key", str(self.pin))
        w = json.loads(out)["witness"]
        self.assertEqual(code, 0)
        self.assertEqual(w["in_ledger"]["source"], "rotated")
        self.assertEqual(w["history"][-1]["reason"], "yearly")

    def test_audit_and_rotate_refuse_a_path_with_no_ledger(self):
        for cmd in ("audit", "rotate-witness"):
            code, out, _ = self.cli(cmd, "--key", str(self.dir / "principal.pem"), "--ledger", str(self.dir / "typo"))
            self.assertEqual(code, 1)
            self.assertIn("no ledger at", json.loads(out)["error"])
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["c.json", "principal.pem"])

    def test_a_ledger_this_account_may_not_read_is_not_called_missing(self):
        self.assertEqual(self.authorize()[0], 0)
        real_stat = Path.stat

        def stat(path, *args, **kwargs):
            if path.name == "entries.jsonl":
                raise PermissionError(13, "Permission denied", str(path))
            return real_stat(path, *args, **kwargs)
        with patch.object(Path, "stat", stat):
            code, out, _ = self.ledger_cmd("audit")
        error = json.loads(out)["error"]
        self.assertEqual(code, 1)
        self.assertIn("permission denied", error)
        self.assertNotIn("no ledger at", error)

    def test_rotate_witness_refusal_is_printed(self):
        self.assertEqual(self.authorize()[0], 0)
        staged = self.dir / "ledger.witness" / "witness.pem.new"
        save_private_key(staged, generate_private_key())
        code, out, _ = self.ledger_cmd("rotate-witness")
        self.assertEqual(code, 1)
        self.assertIn("interrupted rotation", json.loads(out)["error"])
        os.unlink(staged)
        code, out, _ = self.ledger_cmd("rotate-witness", "--reason", "x" * 201)
        self.assertEqual(code, 1)
        self.assertIn("at most 200", json.loads(out)["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
