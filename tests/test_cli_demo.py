"""CLI end-to-end (keygen, sign, verify, tamper), check-judges, and the demo."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from compact_kernel import cli

EX = Path(__file__).parent.parent / "examples"


def run(*argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli.main(list(argv))
    return code, buf.getvalue()


class CLI(unittest.TestCase):
    def test_keygen_sign_verify_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run("keygen", "--out", f"{d}/k", "--no-passphrase")[0], 0)
            for rules in ("hard_rules.json", "hard_rules.yaml"):
                out = f"{d}/signed-{rules}.json"
                code, _ = run("sign-constitution", "--text", str(EX / "constitution.md"), "--rules", str(EX / rules),
                              "--principal", "did:ck:t", "--key", f"{d}/k/principal.pem", "--no-passphrase",
                              "--out", out)
                self.assertEqual(code, 0)
                code, txt = run("verify-constitution", "--signed", out, "--pub", f"{d}/k/principal.pub.pem")
                self.assertEqual(code, 0, txt)
                env = json.loads(Path(out).read_text())
                env["constitution"]["hard_rules"].pop()
                Path(out).write_text(json.dumps(env))
                code, txt = run("verify-constitution", "--signed", out, "--pub", f"{d}/k/principal.pub.pem")
                self.assertEqual(code, 1)
                self.assertIn("REJECTED", txt)

    def test_keygen_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            run("keygen", "--out", d, "--no-passphrase")
            with self.assertRaises(SystemExit):
                run("keygen", "--out", d, "--no-passphrase")

    def test_check_judges_rejects_placeholders(self):
        code, txt = run("check-judges", "--config", str(EX / "judges.yaml"))
        self.assertEqual(code, 1)
        self.assertIn("model", txt)

    def test_demo_runs(self):
        code, txt = run("demo")
        self.assertEqual(code, 0)
        self.assertIn("[ALLOW] Draft an email", txt)
        self.assertIn("rule_denied:no-wires", txt)
        self.assertIn("rule_denied:no-sensitive-data", txt)
        self.assertIn("invalid_action:amount_usd", txt)
        self.assertIn("replay        : replayed", txt)
        self.assertIn("verify: ok", txt)
        self.assertIn("signed verify=", txt)
        self.assertNotIn("signed verify=ok", txt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
