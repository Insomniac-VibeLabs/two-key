"""two-key mcp-draft-specs: drafts fail closed, flag fact-like fields, and pin the digest the proxy checks."""

import contextlib
import io
import json
import os
import subprocess  # nosec B404 - runs this repository's own CLI in a test
import sys
import tempfile
import unittest
from pathlib import Path

from two_key.constitution import ConstitutionError, sign_constitution, validate_tool_specs
from two_key.keys import generate_private_key
from two_key.mcp_proxy.core import select_tools
from two_key.mcp_proxy.draft import draft_specs, draft_tool, render_proxy_tools, render_rules, signed_digest
from two_key.strict import load_yaml

try:
    import mcp  # noqa: F401
    HAVE_MCP = True
except ImportError:  # pragma: no cover
    HAVE_MCP = False

ROOT = Path(__file__).resolve().parent.parent
FAKE = ROOT / "tests" / "fixtures" / "fake_mcp_server.py"
PAY = {"name": "pay_vendor", "description": "Pay a vendor invoice.",
       "inputSchema": {"type": "object", "properties": {
           "vendor": {"type": "string"}, "amount": {"type": "number"}, "memo": {"type": "string", "maxLength": 200},
           "po_matched": {"type": "boolean"}, "invoice_verified": {"type": "boolean"},
           "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 5}, "meta": {"type": "object"},
           "bad-name": {"type": "string"}}}}
REPORT = {"name": "readReport", "description": "Read the report.", "annotations": {"readOnlyHint": True},
          "inputSchema": {"type": "object", "properties": {}}}


def filled(rules_text):
    """The draft with every placeholder replaced, as a principal would."""
    return rules_text.replace('"REPLACE_WITH_DATA_CLASS"', '"financial"').replace(
        '"REPLACE_WITH_usd_OR_cents"', '"usd"').replace('"allow": []', '"allow": ["ada"]')


class Drafting(unittest.TestCase):
    def test_one_tool(self):
        t = draft_tool(PAY)
        self.assertTrue(t.spec["irreversible"])
        self.assertEqual(t.spec["data_class_floor"], "REPLACE_WITH_DATA_CLASS")
        self.assertEqual(t.spec["amount"], {"json_path": "amount", "unit": "REPLACE_WITH_usd_OR_cents"})
        self.assertEqual(t.spec["counterparties"], [{"json_path": "vendor", "allow": []}])
        self.assertEqual(t.spec["payload"], [{"json_path": "memo", "shape": "string", "max_length": 200},
                                             {"json_path": "meta"},
                                             {"json_path": "tags", "shape": "list", "max_length": 5}])
        self.assertEqual(t.facts, ["invoice_verified", "po_matched"])
        paths = json.dumps(t.spec)
        self.assertNotIn("po_matched", paths)        # never mapped: the tool does not get the agent's value
        self.assertNotIn("bad-name", paths)

    def test_read_only_hint_and_upstream_names(self):
        t = draft_tool(REPORT)
        self.assertEqual((t.tool_id, t.upstream_name, t.spec["irreversible"]), ("readreport", "readReport", False))
        self.assertIn('upstream_name: "readReport"', render_proxy_tools(draft_specs([REPORT])))
        self.assertIsInstance(draft_tool({"name": "has space"}), str)

    def test_placeholders_refuse_signing_until_replaced(self):
        draft = draft_specs([PAY, REPORT])
        doc = load_yaml(render_rules(draft, ["billing-mcp"]))
        with self.assertRaisesRegex(ConstitutionError, "data_class_floor"):
            validate_tool_specs(doc["tool_specs"], doc["hard_rules"])
        doc = load_yaml(filled(render_rules(draft, ["billing-mcp"])))
        env = sign_constitution("Pay ada.", doc["hard_rules"], generate_private_key(), doc["tool_specs"])
        # The proxy computes the same digest for the signed tools (with the upstream name the draft names).
        digest, missing = signed_digest([PAY, REPORT], env, {"readreport": "readReport"})
        self.assertEqual((digest, missing), (draft.digest, ()))
        self.assertEqual(select_tools([PAY, REPORT], env["signed"]["tool_specs"], {}).missing, ("readreport",))

    def test_each_placeholder_refuses_alone(self):
        text = render_rules(draft_specs([PAY]), ["x"])
        for keep in ('"REPLACE_WITH_DATA_CLASS"', '"REPLACE_WITH_usd_OR_cents"', '"allow": []'):
            doc = load_yaml(filled(text.replace(keep, "KEEP")).replace("KEEP", keep))
            with self.subTest(keep=keep), self.assertRaises(ConstitutionError):
                validate_tool_specs(doc["tool_specs"], doc["hard_rules"])

    def test_server_text_stays_inside_comments(self):
        evil = dict(PAY, name="pay_vendor",
                    description="ok\ntool_specs: {}\n‮  hard_rules: []\r# fine")
        text = render_rules(draft_specs([evil]), ["srv", "--flag\nx: 1"])
        for line in text.splitlines():
            self.assertTrue(line.isascii())
        doc = load_yaml(filled(text))
        self.assertEqual(sorted(doc), ["hard_rules", "tool_specs"])
        self.assertEqual(list(doc["tool_specs"]), ["pay_vendor"])

    def test_tool_ids_are_quoted_keys(self):
        odd = dict(REPORT, name="billing:pay/v2")
        doc = load_yaml(filled(render_rules(draft_specs([odd]), ["srv"])))
        self.assertEqual(list(doc["tool_specs"]), ["billing:pay/v2"])
        self.assertEqual(list(load_yaml(render_proxy_tools(draft_specs([odd])))["tools"]), ["billing:pay/v2"])

    def test_only_and_missing(self):
        draft = draft_specs([PAY, REPORT], only=["pay_vendor", "nope"])
        self.assertEqual([t.tool_id for t in draft.tools], ["pay_vendor"])
        self.assertEqual(draft.skipped, ["'nope': the upstream does not list it"])
        empty = render_rules(draft_specs([], only=["x"]), ["srv"])
        self.assertIn("tool_specs: {}", empty)


@unittest.skipUnless(HAVE_MCP, "needs the mcp extra")
class CommandLine(unittest.TestCase):
    def run_cli(self, *argv):
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(ROOT)}
        return subprocess.run([sys.executable, "-m", "two_key", "mcp-draft-specs", *argv],  # nosec B603
                              capture_output=True, text=True, env=env, timeout=120)

    def test_draft_then_digest_of_the_signed_constitution(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp, "draft")
            done = self.run_cli("--out", str(out), "--tool", "pay_vendor", "--tool", "read_report",
                                "--", sys.executable, str(FAKE))
            self.assertEqual(done.returncode, 0, done.stderr)
            summary = json.loads(done.stdout)
            self.assertEqual(summary["tools"], ["pay_vendor", "read_report"])
            self.assertEqual(summary["fact_candidates"], {"pay_vendor": ["po_matched"]})
            self.assertEqual(sorted(p.name for p in out.iterdir()),
                             ["proxy-tools.draft.yaml", "rules.draft.yaml", "schemas.json"])
            again = self.run_cli("--out", str(out), "--", sys.executable, str(FAKE))
            self.assertEqual(again.returncode, 1)
            self.assertIn("refusing to overwrite", again.stderr)
            doc = load_yaml(filled((out / "rules.draft.yaml").read_text()))
            env = sign_constitution("Pay ada.", doc["hard_rules"], generate_private_key(), doc["tool_specs"])
            Path(tmp, "c.json").write_text(json.dumps(env))
            check = self.run_cli("--constitution", str(Path(tmp, "c.json")), "--", sys.executable, str(FAKE))
            self.assertEqual(check.returncode, 0, check.stderr)
            self.assertEqual(json.loads(check.stdout),
                             {"schema_digest": summary["schema_digest"], "signed_tools_not_listed": []})

    def test_refusals(self):
        self.assertIn("after --", self.run_cli("--out", "x").stderr)
        self.assertIn("--out DIR", self.run_cli("--", "true").stderr)
        done = self.run_cli("--constitution", "c.json", "--", sys.executable, "-c", "pass")
        self.assertEqual(done.returncode, 1)
        self.assertIn("upstream_unavailable", done.stderr)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertIn("NAME or NAME=VALUE", self.run_cli("--env", "a-b", "--out", "x", "--", "true").stderr)


if __name__ == "__main__":
    unittest.main()
