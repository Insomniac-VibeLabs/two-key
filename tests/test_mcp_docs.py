"""The MCP proxy's worked example in docs/HOWTO.md stays true: its proxy.yaml parses, its rules sign."""

import os
import re
import unittest
from pathlib import Path

from two_key.constitution import sign_constitution
from two_key.keys import generate_private_key
from two_key.mcp_proxy.config import ProxyConfigError, parse_proxy_config
from two_key.mcp_proxy.draft import draft_specs, render_rules
from two_key.strict import load_yaml

ROOT = Path(__file__).resolve().parent.parent
HOWTO = (ROOT / "docs" / "HOWTO.md").read_text(encoding="utf-8")
SECTION = HOWTO[HOWTO.index("## Put Two-Key in front of an MCP server"):HOWTO.index("## If the ledger will not open")]
YAML_BLOCKS = re.findall(r"```yaml\n(.*?)```", SECTION, re.S)


class WorkedExample(unittest.TestCase):
    def test_rules_example_signs(self):
        doc = load_yaml(next(b for b in YAML_BLOCKS if "tool_specs:" in b))
        env = sign_constitution("Pay approved vendors.", doc["hard_rules"], generate_private_key(), doc["tool_specs"],
                                fields=doc.get("fields"))
        self.assertEqual(sorted(env["signed"]["tool_specs"]), ["pay_vendor", "read_report"])
        self.assertEqual(env["format"], "two-key-constitution-v3")        # po_matched is a caller-supplied fact

    def test_proxy_example_parses(self):
        text = next(b for b in YAML_BLOCKS if "upstream:" in b).replace('"sha256:..."', '"sha256:' + "a" * 64 + '"')
        data = load_yaml(text)
        windows = os.name == "nt"
        if windows:
            # The example is a Linux one. On Windows, /opt/... has no drive, and check_paths refuses it rather
            # than read it against whichever drive is current.
            with self.assertRaisesRegex(ProxyConfigError, r"upstream.check_paths\[0\]: expected an absolute path"):
                parse_proxy_config(data, Path("/etc/two-key/proxy.yaml"))
            del data["upstream"]["check_paths"]
        cfg = parse_proxy_config(data, Path("/etc/two-key/proxy.yaml"))
        if not windows:
            self.assertEqual(cfg.upstream.check_paths, (Path("/opt/billing-mcp/node_modules/@example/billing-mcp"),))
        self.assertEqual(cfg.upstream.command[:4], ("sudo", "-n", "-u", "mcp-billing"))
        self.assertEqual(cfg.tool_policy("pay_vendor").claim, "floor")
        self.assertEqual(cfg.tool_policy("pay_vendor").facts, {"po_matched": "billing_facts:po_matches"})
        self.assertFalse(cfg.allow_unresolved_identity)

    def test_the_config_table_lists_every_key(self):
        table = SECTION[SECTION.index("### `proxy.yaml`"):SECTION.index("### What the proxy does")]
        documented = set()
        for row in re.findall(r"^\| (`[^|]+`) \|", table, re.M):
            documented |= set(re.findall(r"`([a-z_.<>]+)`", row))
        from two_key.mcp_proxy import config
        known = (config._TOP_KEYS - {"keys", "upstream", "tools"}) | {"keys.principal"} \
            | {f"upstream.{k}" for k in config._UPSTREAM_KEYS} | {f"tools.<id>.{k}" for k in config._TOOL_KEYS}
        self.assertEqual(documented, known)

    def test_draft_placeholders_match_the_text(self):
        text = render_rules(draft_specs([{"name": "pay_vendor", "inputSchema": {
            "type": "object", "properties": {"amount": {"type": "number"}, "vendor": {"type": "string"}}}}]), ["x"])
        for placeholder in ("REPLACE_WITH_DATA_CLASS", "REPLACE_WITH_usd_OR_cents"):
            self.assertIn(placeholder, text)
            self.assertIn(placeholder, SECTION)


if __name__ == "__main__":
    unittest.main()
