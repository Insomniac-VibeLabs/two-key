# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The tool check (#28) through the MCP SDK: a fake upstream server (tests/fixtures/fake_mcp_server.py) runs
``pay_vendor`` only through ``ToolChecker.mcp_call``. A call through the proxy passes and its receipt is ledgered;
the same call sent to the server directly is refused. Skipped without the mcp extra."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import AsyncExitStack
from pathlib import Path

try:
    import anyio
    from mcp import Client
    from two_key.mcp_proxy import sdk
except ImportError:  # pragma: no cover - the suite runs without the extra too
    sdk = None

from two_key.keys import save_public_key
from two_key.mcp_proxy.config import ProxyConfigError, parse_proxy_config
from two_key.mcp_proxy.core import select_tools
from two_key.toolcheck import META_KEY, key_fingerprint, new_tool_key

from test_mcp_proxy import SPECS, two_key

ROOT = Path(__file__).resolve().parent.parent
FAKE = ROOT / "tests" / "fixtures" / "fake_mcp_server.py"
CALL = {"vendor": "ada", "amount": 12.5}


def checked_specs(fingerprint):
    return {**SPECS, "pay_vendor": {**SPECS["pay_vendor"], "tool_check": {"key": fingerprint}}}


@unittest.skipIf(sdk is None, "needs the mcp extra")
class ThroughTheProxy(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.tool_key = self.tmp / "tool.pem"
        self.tk = two_key(self.tmp, specs=checked_specs(new_tool_key(self.tool_key)))
        self.addCleanup(self.tk.close)
        save_public_key(self.tmp / "cap.pub.pem", self.tk.issuer.public_key)
        save_public_key(self.tmp / "stamp.pub.pem", self.tk.stamp_signer.public_key)
        self.check_config = self.tmp / "check.json"
        self.check_config.write_text(json.dumps({
            "tool": "pay_vendor", "capability_public_key": "cap.pub.pem",
            "capability_key_fingerprint": key_fingerprint(self.tk.issuer.public_key),
            "stamp_public_key": "stamp.pub.pem", "stamp_key_fingerprint": self.tk.stamp_signer.fingerprint,
            "tool_private_key": "tool.pem", "seen_record": "seen.sqlite"}))

    def config(self, digest="sha256:" + "0" * 64):
        upstream = {"command": [sys.executable, str(FAKE)], "schema_digest": digest,
                    "env": {"FAKE_MCP_TOOL_CHECK": str(self.check_config), "PYTHONPATH": str(ROOT)}}
        return parse_proxy_config({"constitution": "c.json", "keys": {"principal": "k.pem"}, "ledger": "ledger",
                                   "judges": "judges.yaml", "upstream": upstream,
                                   "tools": {"pay_vendor": {"claim": "floor"}}}, self.tmp / "proxy.yaml")

    def digest(self):
        async def main():
            async with AsyncExitStack() as stack:
                client = await sdk.connect_upstream(stack, self.config())
                return select_tools(await sdk.list_upstream_tools(client), SPECS, {}).digest
        return anyio.run(main)

    def run_client(self, body):
        cfg = self.config(self.digest())

        async def main():
            async with sdk.running_core(cfg, two_key=self.tk) as core:
                async with Client(sdk.build_server(core)) as client:
                    return await body(client)
        with contextlib.redirect_stderr(io.StringIO()):
            return anyio.run(main)

    def test_a_call_through_the_proxy_runs_and_its_receipt_is_ledgered(self):
        async def body(client):
            return await client.call_tool("pay_vendor", CALL)
        result = self.run_client(body)
        self.assertFalse(result.is_error, result)
        self.assertNotIn(META_KEY, result.meta or {})          # the receipt never reaches the agent
        redemption = [e.body for e in self.tk.ledger.entries if e.kind == "redemption"][-1]
        self.assertEqual(redemption["receipt_outcome"], "ran")
        self.assertNotIn("tool_receipt_invalid", [e.kind for e in self.tk.ledger.entries])

    def test_the_same_call_sent_to_the_server_directly_is_refused(self):
        async def main():
            async with AsyncExitStack() as stack:
                client = await sdk.connect_upstream(stack, self.config())
                return await client.call_tool("pay_vendor", CALL)
        result = anyio.run(main)
        self.assertTrue(result.is_error)
        self.assertIn("check_missing", result.content[0].text)

    def test_high_assurance_refuses_to_start_with_an_unchecked_tool(self):
        tk = two_key(self.tmp / "ha", specs=SPECS)
        self.addCleanup(tk.close)
        tk.quorum = _HighAssurance()       # only the profile matters to this refusal
        cfg = self.config(self.digest())

        async def main():
            async with sdk.running_core(cfg, two_key=tk):
                pass
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ProxyConfigError,
                                                                               "tool_check_required"):
            anyio.run(main)


class _HighAssurance:
    is_high_assurance = True


if __name__ == "__main__":
    unittest.main()
