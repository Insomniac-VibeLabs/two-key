"""The MCP proxy through the MCP SDK, against a fake upstream server started as a child process over stdio
(tests/fixtures/fake_mcp_server.py). Network-free. Skipped without the mcp extra."""

import contextlib
import io
import json
import os
import subprocess  # nosec B404 - runs this repository's own CLI in a test
import sys
import tempfile
import textwrap
import unittest
from contextlib import AsyncExitStack
from pathlib import Path

try:
    import anyio
    from mcp import Client
    from mcp.client.stdio import DEFAULT_INHERITED_ENV_VARS
    from two_key.mcp_proxy import sdk
except ImportError:  # pragma: no cover - the suite runs without the extra too
    sdk = None

from two_key.mcp_proxy.config import ProxyConfigError, parse_proxy_config
from two_key.mcp_proxy.core import DENY_PREFIX, select_tools

from child_env import child_env
from test_mcp_proxy import DIGEST, SPECS, two_key

ROOT = Path(__file__).resolve().parent.parent
FAKE = ROOT / "tests" / "fixtures" / "fake_mcp_server.py"


def proxy_config(tmp, digest=DIGEST, variant="", **over):
    upstream = {"command": [sys.executable, str(FAKE)], "schema_digest": digest,
                "env": {"FAKE_MCP_LOG": str(Path(tmp, "calls.jsonl")), "FAKE_MCP_VARIANT": variant}}
    upstream.update(over.pop("upstream", {}))
    data = {"constitution": "c.json", "keys": {"principal": "k.pem"}, "ledger": "ledger", "judges": "judges.yaml",
            "upstream": upstream, **over}
    return parse_proxy_config(data, Path(tmp, "proxy.yaml"))


def upstream_calls(tmp):
    path = Path(tmp, "calls.jsonl")
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


async def pinned_digest(tmp, variant=""):
    """The digest the fake server's signed tools have now, as mcp-draft-specs would print it."""
    async with AsyncExitStack() as stack:
        client = await sdk.connect_upstream(stack, proxy_config(tmp, variant=variant))
        return select_tools(await sdk.list_upstream_tools(client), SPECS, {}).digest


@unittest.skipIf(sdk is None, "needs the mcp extra")
class ThroughTheSdk(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.digest = anyio.run(pinned_digest, self.tmp)
        self.dirs = 0

    def fresh_dir(self) -> str:
        """A new ledger directory under the test's temporary directory (one principal key per ledger)."""
        self.dirs += 1
        path = Path(self.tmp, f"run{self.dirs}")
        path.mkdir()
        return str(path)

    def run_client(self, body, cfg=None, judges=None, mode="auto"):
        """Start the proxy core in this process and talk to its server with an MCP client."""
        tk = two_key(self.fresh_dir(), judges)
        cfg = cfg or proxy_config(self.tmp, self.digest, tools={"pay_vendor": {"claim": "floor"}})

        async def main():
            async with sdk.running_core(cfg, two_key=tk) as core:
                async with Client(sdk.build_server(core), mode=mode) as client:
                    return await body(client), tk
        with contextlib.redirect_stderr(io.StringIO()):
            return anyio.run(main)

    def test_lists_only_signed_tools_and_calls_through_both_keys(self):
        async def body(client):
            listed = await client.list_tools()
            ok = await client.call_tool("pay_vendor", {"vendor": "Ada", "amount": 12.5, "po_matched": True})
            capped = await client.call_tool("pay_vendor", {"vendor": "ada", "amount": 5000})
            hidden = await client.call_tool("delete_all", {})
            return listed, ok, capped, hidden
        for mode in ("auto", "legacy"):
            with self.subTest(mode=mode):
                (listed, ok, capped, hidden), tk = self.run_client(body, mode=mode)
                self.assertEqual(sorted(t.name for t in listed.tools), ["env_names", "pay_vendor", "read_report"])
                pay = next(t for t in listed.tools if t.name == "pay_vendor")
                self.assertEqual(pay.description, "Pay a vendor invoice.")
                self.assertTrue(pay.annotations.destructive_hint)
                self.assertFalse(ok.is_error, ok)
                self.assertEqual(json.loads(ok.content[0].text)["arguments"], {"vendor": "ada", "amount": 12.5})
                self.assertTrue(capped.is_error)
                self.assertEqual(capped.content[0].text, DENY_PREFIX + "rule_denied:cap")
                self.assertTrue(hidden.is_error)
                self.assertEqual(hidden.content[0].text, DENY_PREFIX + "tool_not_offered")
                # The upstream saw one call: the allowed one, with the projected arguments.
                self.assertEqual(upstream_calls(self.tmp)[-1],
                                 {"tool": "pay_vendor", "arguments": {"vendor": "ada", "amount": 12.5}})
                self.assertNotIn("delete_all", [c["tool"] for c in upstream_calls(self.tmp)])
                self.assertEqual([e.kind for e in tk.ledger.entries].count("redemption"), 1)
                Path(self.tmp, "calls.jsonl").unlink()

    def test_the_upstream_gets_only_its_declared_environment(self):
        os.environ["TWO_KEY_TEST_JUDGE_SECRET"] = "judge-key"
        self.addCleanup(os.environ.pop, "TWO_KEY_TEST_JUDGE_SECRET", None)

        async def body(client):
            return await client.call_tool("env_names", {})
        result, _ = self.run_client(body)
        names = set(json.loads(result.content[0].text))
        self.assertNotIn("TWO_KEY_TEST_JUDGE_SECRET", names)
        self.assertIn("FAKE_MCP_LOG", names)
        self.assertLessEqual(names - {"FAKE_MCP_LOG", "FAKE_MCP_VARIANT"},
                             {"HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER", "LC_CTYPE",
                              "__CF_USER_TEXT_ENCODING",    # macOS sets it in every process: a text encoding code
                              *DEFAULT_INHERITED_ENV_VARS})  # the SDK's own minimal list (Windows has its own)

    def test_paged_tools_list(self):
        cfg = proxy_config(self.tmp, anyio.run(pinned_digest, self.tmp, "paged"), variant="paged")

        async def body(client):
            return await client.list_tools()
        listed, _ = self.run_client(body, cfg)
        self.assertEqual(sorted(t.name for t in listed.tools), ["env_names", "pay_vendor", "read_report"])

    def test_upstream_tool_error_is_a_tool_error(self):
        cfg = proxy_config(self.tmp, anyio.run(pinned_digest, self.tmp, "fail"), variant="fail")

        async def body(client):
            return await client.call_tool("pay_vendor", {"vendor": "ada", "amount": 1})
        result, tk = self.run_client(body, cfg)
        self.assertTrue(result.is_error)
        self.assertIn(result.content[0].text, (DENY_PREFIX + "tool_error:MCPError",))
        self.assertIn("redemption_aborted", [e.kind for e in tk.ledger.entries])

    def start(self, cfg):
        tk = two_key(self.fresh_dir())

        async def main():
            async with sdk.running_core(cfg, two_key=tk):
                pass
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            anyio.run(main)
        return err.getvalue()

    def test_a_changed_schema_refuses_to_start(self):
        cfg = proxy_config(self.tmp, self.digest, variant="changed")
        with self.assertRaisesRegex(ProxyConfigError, "^upstream_schema_changed: .*" + self.digest):
            self.start(cfg)
        self.assertEqual(upstream_calls(self.tmp), [])

    def test_on_schema_change_warn_starts_with_a_warning(self):
        cfg = proxy_config(self.tmp, self.digest, variant="changed", upstream={"on_schema_change": "warn"})
        self.assertIn("WARNING: upstream_schema_changed", self.start(cfg))

    def test_start_warns_for_each_undescribed_input_path_a_reads(self):
        # Advice, never a refusal: the fake server describes neither input (live run 6z did not exercise this).
        err = self.start(proxy_config(self.tmp, self.digest, tools={"pay_vendor": {"claim": "floor"}}))
        self.assertIn("two-key: WARNING: mcp-proxy: pay_vendor: amount (the amount) has no description", err)
        self.assertIn("two-key: WARNING: mcp-proxy: pay_vendor: vendor (a counterparty) has no description", err)

    def test_a_duplicate_upstream_tool_refuses_to_start(self):
        with self.assertRaisesRegex(ProxyConfigError, "upstream_duplicate_tool"):
            self.start(proxy_config(self.tmp, self.digest, variant="dupe"))

    def test_an_upstream_that_does_not_start(self):
        cfg = proxy_config(self.tmp, self.digest, upstream={"command": [sys.executable, "-c", "pass"]})
        with self.assertRaisesRegex(ProxyConfigError, "^upstream_unavailable: "):
            self.start(cfg)


@unittest.skipIf(sdk is None, "needs the mcp extra")
class CommandLine(unittest.TestCase):
    """``two-key mcp-proxy`` refuses before it serves anything; nothing but MCP may go to stdout."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        from two_key.cli import main
        with contextlib.redirect_stdout(io.StringIO()):
            main(["init-key", str(self.dir / "keys")])
        key = self.dir / "keys" / "principal.pem"
        rules = self.dir / "rules.json"
        rules.write_text(json.dumps({"hard_rules": [{"id": "tools", "allow_only_tools": ["read_report"]}],
                                     "tool_specs": {"read_report": SPECS["read_report"]}}))
        (self.dir / "prose.md").write_text("Reading reports is fine.")
        with contextlib.redirect_stdout(io.StringIO()):
            main(["sign-constitution", "--key", str(key), "--prose", str(self.dir / "prose.md"),
                  "--rules", str(rules), "--out", str(self.dir / "constitution.json")])

    def judges(self, judge_url, judge_model):
        (self.dir / "judges.yaml").write_text(textwrap.dedent(f"""\
            monitored_agent:
              id: agent
              model: gpt-4o
              provider: openai
              base_url: https://api.openai.com/v1
              credential_env: TK_TEST_AGENT_KEY
            quorum: {{required_yes: 1, timeout_seconds: 10}}
            judges:
              - id: local
                type: openai_compatible
                provider: litellm
                base_url: {judge_url}
                model: {judge_model}
                auth: {{type: env, var: TK_TEST_JUDGE_KEY}}
            """))

    def config(self, **over):
        # The test runner starts the proxy as its own account; tests/test_agent_access.py covers that refusal.
        data = {"constitution": "constitution.json", "keys": {"principal": "keys/principal.pem"},
                "ledger": "ledger", "judges": "judges.yaml", "on_agent_access": "warn",
                "upstream": {"command": [sys.executable, str(FAKE)], "schema_digest": DIGEST}, **over}
        (self.dir / "proxy.json").write_text(json.dumps(data))
        return self.dir / "proxy.json"

    def run_proxy(self, config):
        env = child_env(TK_TEST_AGENT_KEY="agent-key", TK_TEST_JUDGE_KEY="judge-key", PYTHONPATH=str(ROOT))
        return subprocess.run([sys.executable, "-m", "two_key", "mcp-proxy", "--config", str(config)],  # nosec B603
                              capture_output=True, text=True, env=env, timeout=120, stdin=subprocess.DEVNULL)

    def test_unresolved_identity_refuses_to_start(self):
        # A local proxy serving an alias: Two-Key cannot tell who serves it (the library only warns).
        self.judges("http://localhost:4000/v1", "house-model")
        done = self.run_proxy(self.config())
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertEqual(done.stdout, "")
        self.assertIn("mcp-proxy refused to start: unresolved_identity", done.stderr)
        self.assertIn("allow_unresolved_identity: true", done.stderr)

    def test_allow_unresolved_identity_reaches_the_schema_pin(self):
        self.judges("http://localhost:4000/v1", "house-model")
        done = self.run_proxy(self.config(allow_unresolved_identity=True))
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertEqual(done.stdout, "")
        self.assertIn("mcp-proxy refused to start: upstream_schema_changed", done.stderr)

    def test_the_test_runners_own_account_refuses_to_start_by_default(self):
        # The runner starts the proxy as its own account: the case on_agent_access exists for.
        self.judges("http://localhost:4000/v1", "house-model")
        path = self.config(allow_unresolved_identity=True)
        data = json.loads(path.read_text())
        del data["on_agent_access"]
        path.write_text(json.dumps(data))
        done = self.run_proxy(path)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertEqual(done.stdout, "")
        code = "agent_account_unknown" if os.name == "nt" else "agent_same_account"
        self.assertIn(f"mcp-proxy refused to start: AgentAccessError: {code}: ", done.stderr)
        self.assertIn("on_agent_access: refuse (the default) refuses to start (docs/CONNECTING.md)", done.stderr)
        self.assertFalse((self.dir / "ledger").exists())        # refused before the ledger is opened

    def test_a_config_error(self):
        done = self.run_proxy(self.config(upstream={"command": "python server.py", "schema_digest": DIGEST}))
        self.assertEqual(done.returncode, 1)
        self.assertEqual(done.stdout, "")
        self.assertIn("without a shell", done.stderr)


if __name__ == "__main__":
    unittest.main()
