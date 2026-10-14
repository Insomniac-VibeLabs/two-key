"""B5: a local proxy or daemon serving the agent's exact model.

Owner rule (2026-10-08): a judge is refused as the monitored agent when it holds the agent's credential, at any address,
or when neither side has a credential on the same address. A loopback or private endpoint serving the agent's model, a shared declared
upstream, or a shared tenant is therefore allowed, and each is a likely accident that is warned and recorded
(``identity.separation_warnings``). Tenants are still scoped by the family a proxy reaches (not its address),
upstream labels are normalized, and every local alias of this machine is one address, so two keyless sides on
it are refused.
"""

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.identity import (AgentDeclaration, _own_addresses, check_separation, compare, endpoint_key,
                              judge_identity, local_alias, normalize_upstream, separation_warnings, IdentityError)
from two_key.judges.credentials import StaticToken
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy

OPENAI_AGENT = {"id": "agent", "model": "gpt-4o", "provider": "openai", "base_url": "https://api.openai.com/v1",
                "credential_env": "B5_AGENT_KEY"}
OLLAMA_AGENT = {"id": "agent", "model": "gpt-oss:120b-cloud", "provider": "ollama",
                "base_url": "https://ollama.com", "credential_env": "B5_AGENT_KEY"}
FP = b"k" * 32
UNKNOWN = "same_model_unknown_proxy"
SAME_UPSTREAM = "same_model_shared_route"
NO_CREDENTIAL = "no credential on either side"


def judge(model, base_url, key=None, tenant=None, upstream=None, jid="j"):
    return SimpleNamespace(judge_id=jid, model=model, base_url=base_url, provider="x",
                           credential=StaticToken(key) if key else None, tenant=tenant, upstream=upstream)


class B5(unittest.TestCase):
    def setUp(self):
        os.environ["B5_AGENT_KEY"] = "agent-key-K"
        self.addCleanup(os.environ.pop, "B5_AGENT_KEY", None)

    def resolved(self, agent: dict, j):
        return AgentDeclaration.from_mapping(agent).resolve(fp_key=FP), judge_identity(j, FP)

    def verdict(self, agent: dict, j) -> str | None:
        return compare(*self.resolved(agent, j))

    def checks(self, agent: dict, j) -> list[str]:
        return [w["check"] for w in separation_warnings(*self.resolved(agent, j))]

    def denied(self, agent, j, pattern):
        reason = self.verdict(agent, j)
        self.assertIsNotNone(reason, "expected a refusal")
        self.assertRegex(reason, pattern)

    def warned(self, agent, j, *checks):
        self.assertIsNone(self.verdict(agent, j), "expected the pairing to be allowed")
        got = self.checks(agent, j)
        for check in checks:
            self.assertIn(check, got)

    def allowed(self, agent, j):
        self.assertIsNone(self.verdict(agent, j))

    # ------------------------------------------------------------ the reported gaps, now warned
    def test_keyless_local_proxy_with_the_agents_model(self):
        for model in ("gpt-4o", "openai/gpt-4o", "gpt-4o-2024-08-06"):
            with self.subTest(model=model):
                self.warned(OPENAI_AGENT, judge(model, "http://localhost:4000"), UNKNOWN)

    def test_private_address_proxy(self):
        self.warned(OPENAI_AGENT, judge("gpt-4o", "https://192.168.1.9:4000"), UNKNOWN)
        self.warned(OPENAI_AGENT, judge("gpt-4o", "https://192.168.1.9:4000", key="other-key"), UNKNOWN)

    def test_declared_upstream_is_compared(self):
        for up in ("api.openai.com", "https://API.OpenAI.com:443/v1", "api.openai.com.", ["api.openai.com"]):
            with self.subTest(upstream=up):
                self.warned(OPENAI_AGENT, judge("gpt-4o", "http://localhost:4000", upstream=up), SAME_UPSTREAM)
                self.assertNotIn(UNKNOWN, self.checks(OPENAI_AGENT, judge("gpt-4o", "http://localhost:4000",
                                                                          upstream=up)))

    def test_shared_declared_tenant_behind_a_proxy(self):
        agent = dict(OPENAI_AGENT, tenant={"project": "p1"})
        self.warned(agent, judge("gpt-4o", "http://localhost:4000", tenant={"project": "p1"}), UNKNOWN, "shared_tenant")
        self.warned(agent, judge("gpt-4o", "http://localhost:4000", tenant={"project": "P1"},
                                 upstream="api.openai.com"), SAME_UPSTREAM, "shared_tenant")
        # Tenant ids are scoped by provider family, so a proxy's p1 is OpenAI's p1 even on another model.
        j = judge("gpt-4o-mini", "http://localhost:4000", tenant={"project": "P1"}, upstream="api.openai.com")
        self.warned(agent, j, "shared_tenant")
        [w] = separation_warnings(*self.resolved(agent, j))
        self.assertEqual(w["detail"], "a shared tenant openai:project:p1")

    def test_declared_upstream_on_a_remote_router_counts_as_an_endpoint(self):
        agent = dict(OPENAI_AGENT, base_url="https://llm-router.example.com/v1", upstream="api.openai.com")
        self.warned(agent, judge("gpt-4o", "https://api.openai.com/v1", key="judge-key"), SAME_UPSTREAM)

    def test_ollama_cloud_model_through_a_local_daemon(self):
        j = judge("gpt-oss:120b-cloud", "http://localhost:11434")
        self.warned(OLLAMA_AGENT, j, UNKNOWN, SAME_UPSTREAM)
        self.warned(OLLAMA_AGENT, judge("gpt-oss:120b-cloud", "http://localhost:11434", upstream="ollama.com"),
                    SAME_UPSTREAM)
        same_account = dict(OLLAMA_AGENT, tenant={"account": "acct-a"})
        self.warned(same_account, judge("gpt-oss:120b-cloud", "http://localhost:11434", upstream="ollama.com",
                                        tenant={"account": "acct-a"}), SAME_UPSTREAM, "shared_tenant")
        self.warned(same_account, judge("qwen3-coder:480b-cloud", "http://localhost:11434", upstream="ollama.com",
                                        tenant={"account": "acct-a"}), "shared_tenant")
        # The agent's model without the -cloud suffix is the same model.
        self.warned(dict(OLLAMA_AGENT, model="gpt-oss:120b"), j, UNKNOWN)

    def test_local_aliases_are_one_endpoint(self):
        agent = {"id": "agent", "model": "llama3.1:8b", "provider": "ollama", "base_url": "http://localhost:11434",
                 "credential": "none", "upstream": "localhost:11434"}
        hosts = ["0.0.0.0", "127.1", "127.0.0.2", "localhost.localdomain", "[::1]", "[::]", "LOCALHOST"]  # skipcq: BAN-B104 -- hostname fixture for the address classifier, not a bind
        own = sorted(a for a in _own_addresses() if ":" not in a and not a.startswith("127."))
        hosts += own[:1]
        for host in hosts:
            with self.subTest(host=host):
                self.assertTrue(local_alias(host.strip("[]")), host)
                self.assertEqual(endpoint_key(f"http://{host}:11434"), "localhost:11434")
                # Every alias is the one address, and neither side has a credential: refused.
                self.denied(agent, judge("llama3.1:8b", f"http://{host}:11434", upstream=f"{host}:11434"),
                            "the same address localhost:11434 and " + NO_CREDENTIAL)

    def test_this_machines_own_address_is_a_local_alias(self):
        from unittest import mock
        agent = {"id": "agent", "model": "llama3.1:8b", "provider": "ollama", "base_url": "http://localhost:11434",
                 "credential": "none", "upstream": "localhost:11434"}
        with mock.patch("two_key.identity._own_addresses", return_value=frozenset({"10.20.30.40", "box-name"})):
            for host in ("10.20.30.40", "box-name"):
                with self.subTest(host=host):
                    self.assertEqual(endpoint_key(f"http://{host}:11434"), "localhost:11434")
                    self.denied(agent, judge("llama3.1:8b", f"http://{host}:11434", upstream=f"{host}:11434"),
                                "the same address localhost:11434")
            self.assertFalse(local_alias("10.20.30.41"))

    def test_upstream_normalization(self):
        self.assertEqual(normalize_upstream("https://API.OpenAI.com:443/v1"), "api.openai.com")
        self.assertEqual(normalize_upstream("api.openai.com:80"), "api.openai.com")
        self.assertEqual(normalize_upstream("Gateway.example:8443"), "gateway.example:8443")
        self.assertEqual(normalize_upstream("127.0.0.1:11434"), "localhost:11434")
        self.assertEqual(normalize_upstream("maker:meta"), "maker:meta")
        for public in ("8.8.8.8", "api.openai.com", "192.168.1.9", "example.com"):
            self.assertFalse(local_alias(public), public)

    # ------------------------------------------------------------ still allowed
    def test_a_different_model_is_allowed(self):
        self.allowed(OPENAI_AGENT, judge("gpt-4o-mini", "http://localhost:4000"))
        self.allowed(OLLAMA_AGENT, judge("qwen3-coder:480b-cloud", "http://localhost:11434"))

    def test_a_different_provider_upstream_is_allowed(self):
        self.allowed(OPENAI_AGENT, judge("gpt-4o", "http://localhost:4000", upstream="api.groq.com"))
        agent = dict(OPENAI_AGENT, tenant={"project": "p1"})
        self.allowed(agent, judge("gpt-4o", "http://localhost:4000", upstream="api.groq.com",
                                  tenant={"project": "p1"}))      # p1 at Groq is not p1 at OpenAI

    def test_a_different_daemon_is_allowed(self):
        agent = {"id": "agent", "model": "llama3.1:8b", "provider": "ollama", "base_url": "http://localhost:11434",
                 "credential": "none", "upstream": "localhost:11434"}
        self.allowed(agent, judge("llama3.1:8b", "http://192.168.1.9:11434", upstream="192.168.1.9:11434"))
        remote = dict(OPENAI_AGENT, model="llama3.1:8b", base_url="https://api.together.xyz/v1")
        self.allowed(remote, judge("llama3.1:8b", "http://localhost:11434", upstream="localhost:11434"))

    def test_different_declared_tenants_on_a_shared_upstream_are_warned(self):
        # One model from one upstream on different accounts: allowed, and the shared route is recorded.
        agent = dict(OLLAMA_AGENT, tenant={"account": "acct-a"})
        j = judge("gpt-oss:120b-cloud", "http://localhost:11434", upstream="ollama.com", tenant={"account": "acct-b"})
        self.warned(agent, j, SAME_UPSTREAM)
        self.assertNotIn("shared_tenant", self.checks(agent, j))
        agent = dict(OPENAI_AGENT, tenant={"project": "p1"})
        self.warned(agent, judge("gpt-4o", "http://localhost:4000", upstream="api.openai.com",
                                 tenant={"project": "p2"}), SAME_UPSTREAM)

    def test_same_provider_on_a_different_model_or_endpoint_is_allowed(self):
        self.allowed(OPENAI_AGENT, judge("gpt-4o-mini", "https://api.openai.com/v1", key="judge-key"))
        self.allowed(OPENAI_AGENT, judge("openai/gpt-4o", "https://openrouter.ai/api/v1", key="judge-key"))
        self.allowed(OPENAI_AGENT, judge("gpt-4o", "https://my-res.openai.azure.com/openai/deployments/gpt4o",
                                         key="judge-key"))

    def test_records_show_routes_and_declared_upstream(self):
        rec = judge_identity(judge("gpt-oss:120b-cloud", "http://127.0.0.1:11434", upstream="https://ollama.com"),
                             FP).to_record()
        self.assertEqual(rec["upstream_declared"], ["ollama.com"])
        self.assertTrue(rec["local_endpoint"])
        self.assertEqual(rec["routes"], ["localhost:11434", "ollama.com"])


class UnrecognizedHost(unittest.TestCase):
    """A maker/ prefix does not identify a host. A keyless judge on a non-vendor host serving the agent's
    model is a proxy whose upstream and tenant are unknown, unless it declares a non-overlapping upstream."""
    HOSTS = ("http://litellm:4000", "http://litellm.internal:4000", "http://host.docker.internal:4000",
             "https://proxy.corp.example", "http://100.64.1.2:4000", "http://169.254.10.20:4000")

    def setUp(self):
        os.environ["B5_AGENT_KEY"] = "agent-key-K"
        self.addCleanup(os.environ.pop, "B5_AGENT_KEY", None)
        self.agent = AgentDeclaration.from_mapping(OPENAI_AGENT).resolve(fp_key=FP)

    def verdict(self, j):
        return compare(self.agent, judge_identity(j, FP))

    def checks(self, j):
        return [w["check"] for w in separation_warnings(self.agent, judge_identity(j, FP))]

    def check(self, base_url):
        for j in (judge("openai/gpt-4o", base_url), judge("openai/gpt-4o", base_url, upstream="api.openai.com"),
                  judge("openai/gpt-4o", base_url, upstream="api.groq.com"), judge("openai/gpt-4o-mini", base_url)):
            self.assertIsNone(self.verdict(j), base_url)        # another address: never the same agent
        self.assertIn(UNKNOWN, self.checks(judge("openai/gpt-4o", base_url)))
        self.assertEqual(self.checks(judge("openai/gpt-4o", base_url, upstream="api.openai.com")), [SAME_UPSTREAM])
        self.assertEqual(self.checks(judge("openai/gpt-4o", base_url, upstream="api.groq.com")), [])
        self.assertEqual(self.checks(judge("openai/gpt-4o-mini", base_url)), [])     # a different model

    def test_litellm(self):
        self.check(self.HOSTS[0])

    def test_litellm_internal(self):
        self.check(self.HOSTS[1])

    def test_host_docker_internal(self):
        self.check(self.HOSTS[2])

    def test_proxy_corp_example(self):
        self.check(self.HOSTS[3])

    def test_cgnat_100_64(self):
        self.check(self.HOSTS[4])

    def test_link_local_169_254(self):
        self.check(self.HOSTS[5])

    def test_recognized_vendor_hosts_are_not_proxies(self):
        for url in ("https://api.together.xyz/v1", "https://openrouter.ai/api/v1"):
            with self.subTest(url=url):
                self.assertIsNone(self.verdict(judge("openai/gpt-4o", url, key="judge-key")))


class EndToEnd(unittest.TestCase):
    def test_twokey_starts_with_a_keyless_local_proxy_and_records_the_warning(self):
        import contextlib
        import io
        os.environ["B5_AGENT_KEY"] = "agent-key-K"
        self.addCleanup(os.environ.pop, "B5_AGENT_KEY", None)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", [{"id": "t", "allow_only_tools": ["search"]}], key,
                                {"search": {"irreversible": False, "data_class_floor": "public"}})
        proxy = OpenAICompatibleJudge("proxy", "litellm", "gpt-4o", "http://localhost:4000/v1")
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(err):
            tk = TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                        [proxy], private_key=key, quorum=QuorumPolicy(required_yes=1), monitored_agent=OPENAI_AGENT)
            [loaded] = [e.body for e in tk.ledger.entries if e.kind == "constitution_loaded"]
        self.assertIn("two-key: WARNING: judge 'proxy' vs agent 'agent'", err.getvalue())
        self.assertIn(UNKNOWN, [w["check"] for w in loaded["judge_agent_separation"]["warnings"]])


if __name__ == "__main__":
    unittest.main()
