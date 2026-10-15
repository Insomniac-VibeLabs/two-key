"""A judge must not be the monitored agent. Checked at start-up from operator config only.

Owner rule (2026-10-08, restated 2026-10-09): a judge may run any model from any vendor. A judge must not be the
monitored agent: TwoKey refuses to start when a judge holds the agent's credential (the same API token, or the
same username and password), at any address, or when neither side sends a credential on the same address.
Everything else starts; likely accidents (the same model on the same address, a shared tenant, a proxy, an
unresolved identity) are warned on stderr and recorded in constitution_loaded.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from two_key.action import normalize_action
from two_key.agents import load_agents
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.identity import (AgentDeclaration, credential_fingerprint, load_monitored_agent, resolve_tenants, resolve_upstream_info,
                              model_maker, normalize_model, resolve_upstreams)
from two_key.judges.anthropic import AnthropicJudge
from two_key.judges.credentials import BasicAuthCredential, EnvApiKey, StaticToken
from two_key.judges.ollama import OllamaJudge
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}
AGENT = {"id": "grok-agent", "model": "grok-4-0709", "provider": "xai", "base_url": "https://api.x.ai/v1",
         "credential_env": "SEP_AGENT_KEY"}
# Default for the ``agent`` parameters below. ``None`` is a test value (no monitored agent), so the default is a sentinel.
DEFAULT_AGENT = object()


def claude(key="judge-anthropic-key", model="claude-sonnet-4-20250514"):
    return AnthropicJudge("claude", "anthropic", model, credential=StaticToken(key))


def oai(jid, model, base_url, key):
    return OpenAICompatibleJudge(jid, "x", model, base_url, StaticToken(key))


def start(tmp, judges, agent=DEFAULT_AGENT, quorum=None, allow_test_doubles=True):
    agent = AGENT if agent is DEFAULT_AGENT else agent
    key = generate_private_key()
    env = sign_constitution("Searching is fine.", RULES, key, SPECS)
    return TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()), judges,
                  private_key=key, quorum=quorum or QuorumPolicy(required_yes=1),
                  allow_test_doubles=allow_test_doubles, monitored_agent=agent)


class Env(unittest.TestCase):
    def setUp(self):
        os.environ["SEP_AGENT_KEY"] = "agent-secret-key"
        self.addCleanup(os.environ.pop, "SEP_AGENT_KEY", None)

    def refused(self, judges, pattern, agent=DEFAULT_AGENT, **kw):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(TwoKeyConfigError, pattern):
                start(tmp, judges, agent, **kw)

    def started(self, judges, agent=DEFAULT_AGENT, **kw):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with contextlib.redirect_stderr(io.StringIO()):
            return start(tmp.name, judges, agent, **kw)

    def warned(self, judges, check, agent=DEFAULT_AGENT, **kw):
        """Starts, prints a warning, and records ``check`` in constitution_loaded."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            tk = start(tmp.name, judges, agent, **kw)
        rec = [e for e in tk.ledger.entries if e.kind == "constitution_loaded"][-1].body["judge_agent_separation"]
        self.assertIn(check, [w["check"] for w in rec["warnings"]], rec["warnings"])
        self.assertIn(f"({check})", err.getvalue())
        return tk


class Normalization(unittest.TestCase):
    def test_model_ids(self):
        same = [("gpt-4o-2024-08-06", "openai/gpt-4o", "chatgpt-4o-latest", "gpt-4o"),
                ("claude-3-5-sonnet-20241022", "anthropic/claude-3.5-sonnet",
                 "us.anthropic.claude-3-5-sonnet-20241022-v2:0", "claude-3-5-sonnet@20241022",
                 "publishers/anthropic/models/claude-3-5-sonnet@20241022"),
                ("claude-opus-4-0", "claude-opus-4-20250514"),
                ("qwen2.5:7b", "Qwen/Qwen2.5-7B-Instruct", "qwen2.5:7b-instruct"),
                ("models/gemini-1.5-pro", "gemini-1.5-pro-002")]
        for group in same:
            self.assertEqual(len({normalize_model(m) for m in group}), 1, group)
        self.assertNotEqual(normalize_model("gpt-4o"), normalize_model("gpt-4o-mini"))
        self.assertNotEqual(normalize_model("qwen2.5:7b"), normalize_model("qwen2.5:14b"))
        self.assertEqual(model_maker("meta-llama/Llama-3.1-8B-Instruct"), "meta")

    def test_routers_resolve_to_the_real_upstream(self):
        cases = {("https://api.openai.com/v1", "gpt-4o"): {"api.openai.com"},
                 ("https://openrouter.ai/api/v1", "anthropic/claude-3.5-sonnet"): {"api.anthropic.com"},
                 ("https://res.openai.azure.com", "my-deployment"): {"api.openai.com"},
                 ("https://bedrock-runtime.us-east-1.amazonaws.com", "anthropic.claude-3-haiku-20240307-v1:0"):
                     {"api.anthropic.com"},
                 ("https://us-central1-aiplatform.googleapis.com/v1", "gemini-1.5-pro"):
                     {"generativelanguage.googleapis.com"},
                 ("http://localhost:4000", "openai/gpt-4o"): {"api.openai.com", "localhost:4000"},
                 ("https://llm.corp.example/v1", "anthropic/claude-3-5-sonnet"): {"api.anthropic.com"}}
        for (url, model), want in cases.items():
            self.assertEqual(set(resolve_upstreams(url, model)[0]), want, (url, model))
        for url, model in (("https://openrouter.ai/api/v1", "mystery-model"), ("https://llm.corp.example/v1", "gpt-4o")):
            self.assertEqual(resolve_upstreams(url, model)[0], frozenset(), (url, model))
        self.assertIn("ollama.com", resolve_upstreams("http://localhost:11434", "gpt-oss:120b-cloud")[0])

    def test_tenants_from_the_url_and_the_declaration(self):
        self.assertEqual(resolve_tenants("https://acme.openai.azure.com/openai/deployments/d"),
                         {"azure:resource:acme", "azure:deployment:acme/d"})
        self.assertEqual(resolve_tenants("https://us-central1-aiplatform.googleapis.com/v1/projects/p1/locations/x"),
                         {"gcp:project:p1"})
        self.assertEqual(resolve_tenants("https://api.openai.com/v1", {"organization": "Org-1"}),
                         {"openai:organization:org-1"})
        self.assertEqual(resolve_tenants("https://api.openai.com/v1"), frozenset())

    def test_fingerprint_never_contains_the_key(self):
        fp = credential_fingerprint("sk-very-secret")
        self.assertTrue(fp.startswith("sha256:"))          # no key: offline use only
        self.assertTrue(credential_fingerprint("sk-very-secret", b"k" * 32).startswith("hmac-sha256:"))
        self.assertNotIn("very-secret", fp)
        self.assertEqual(credential_fingerprint(""), "none")


class Declaration(Env):
    def test_agent_must_be_declared(self):
        self.refused([FixedJudge("a", "yes")], "^monitored_agent_required: declare the monitored agent", agent=None)

    def test_every_field_is_required_and_readable(self):
        for drop in ("model", "provider", "base_url", "credential_env"):
            self.refused([claude()], "monitored_agent", agent={k: v for k, v in AGENT.items() if k != drop})
        os.environ.pop("SEP_AGENT_KEY")
        self.refused([claude()], "SEP_AGENT_KEY is not set")

    def test_credential_none_only_for_loopback_and_in_process_only_in_tests(self):
        cloud_none = dict(AGENT, credential="none")
        cloud_none.pop("credential_env")
        self.refused([claude()], "credential: none is only for", agent=cloud_none)
        self.refused([claude()], "tests only", agent=TEST_AGENT, allow_test_doubles=False)

    def test_yaml_block(self):
        d = load_monitored_agent({"judges": [], "monitored_agent": AGENT})
        self.assertEqual(d, AgentDeclaration(**AGENT))
        self.assertIsNone(load_monitored_agent({"judges": []}))


class Refusals(Env):
    def test_same_model_through_a_router_is_a_different_endpoint(self):
        self.assertTrue(self.started([oai("or", "x-ai/grok-4", "https://openrouter.ai/api/v1",
                                          "openrouter-key")]).separation.ok)

    def test_same_endpoint_and_model_with_another_key_is_warned(self):
        tk = self.warned([oai("direct", "grok-4", "https://api.x.ai/v1", "other-key")], "same_model_same_address")
        self.assertTrue(tk.separation.ok)

    def test_same_credential_on_the_same_address(self):
        self.refused([oai("direct", "grok-3-mini", "https://api.x.ai/v1", "agent-secret-key")],
                     "^judge_matches_agent: .*the same credential on the same address api.x.ai:443")
        os.environ["SEP_JUDGE_KEY"] = "agent-secret-key"
        self.addCleanup(os.environ.pop, "SEP_JUDGE_KEY", None)
        j = OpenAICompatibleJudge("x2", "xai", "grok-4", "https://API.x.ai:443/v1", EnvApiKey("SEP_JUDGE_KEY"))
        self.refused([j], "the same credential on the same address")

    def test_same_credential_on_another_address_is_refused(self):
        # A credential identifies its holder wherever it is sent.
        self.refused([claude(key="agent-secret-key")],
                     r"^judge_matches_agent: .*the same credential \(agent at api.x.ai:443, judge at "
                     r"api.anthropic.com:443\); a credential identifies its holder")
        self.refused([oai("proxy", "grok-4", "http://localhost:4000", "agent-secret-key")],
                     r"the same credential \(agent at api.x.ai:443, judge at localhost:4000\)")

    def test_unresolved_router_is_warned(self):
        self.warned([oai("gw", "judge-model", "https://llm.corp.example/v1", "gw-key")], "unresolved_identity")
        agent = dict(AGENT, base_url="https://llm.corp.example/v1", model="agent-model")
        self.warned([claude()], "unresolved_identity", agent=agent)

    def test_unreadable_judge_credential(self):
        j = AnthropicJudge("c3", "anthropic", "claude-3-haiku", credential=EnvApiKey("SEP_UNSET"))
        self.refused([j], "credential could not be read")

    def test_judge_without_identity(self):
        class Custom(FixedJudge):
            is_test_double = False
        self.refused([Custom("c", "yes")], "declares no model and base_url", allow_test_doubles=False)

    def test_provider_labels_are_not_compared(self):
        # Same free-text label, different real upstream: accepted. Different label, same model and address: warned.
        tk = self.started([AnthropicJudge("c", "xai", "claude-3-haiku", credential=StaticToken("k"))])
        self.assertTrue(tk.separation.ok)
        j = OpenAICompatibleJudge("g", "some-label", "grok-4", "https://api.x.ai/v1", StaticToken("judge-key"))
        tk = self.warned([j], "same_model_same_address")
        [w] = [w for w in tk.separation.warnings if w["check"] == "same_model_same_address"]
        self.assertIn("the same model 'grok4' on the same address api.x.ai:443", w["detail"])

    def test_same_tenant_declared_or_derived_is_warned(self):
        agent = dict(AGENT, model="gpt-4o", base_url="https://api.openai.com/v1", tenant={"organization": "org-acme"})
        j = oai("o", "gpt-4o-mini", "https://api.openai.com/v1", "judge-openai-key")
        j.tenant = {"organization": "ORG-acme"}
        tk = self.warned([j], "shared_tenant", agent=agent)
        self.assertIn("openai:organization:org-acme", tk.separation.warnings[0]["detail"])
        agent = dict(AGENT, model="gpt-4o", base_url="https://acme.openai.azure.com/openai/deployments/agent")
        judge = oai("az", "judge-deployment", "https://acme.openai.azure.com/openai/deployments/judge", "az-key")
        self.warned([judge], "shared_tenant", agent=agent)
        other = oai("az2", "judge-deployment", "https://other.openai.azure.com/openai/deployments/j", "az-key2")
        self.assertEqual(self.started([other], agent).separation.warnings, ())

    def test_tenant_yaml_keys(self):
        from two_key.judges.config import JudgeConfigError, load_config
        judges, _ = load_config({"judges": [{"id": "l", "type": "ollama", "model": "llama3",
                                             "tenant": {"account": "t1"}}], "quorum": {"required_yes": 1}})
        self.assertEqual(judges[0].tenant, {"account": "t1"})
        for bad in ("t1", {"tenant_id": "x"}, {"account": ""}):
            with self.assertRaisesRegex(JudgeConfigError, "tenant"):
                load_config({"judges": [{"id": "l", "type": "ollama", "model": "m", "tenant": bad}]})
        self.assertEqual(load_monitored_agent({"monitored_agent": dict(AGENT, tenant={"project": "p"})}).tenant,
                         {"project": "p"})

    def test_configured_agent_object_is_checked(self):
        os.environ["SEP_OTHER"] = "other-agent-key"
        self.addCleanup(os.environ.pop, "SEP_OTHER", None)
        agents = load_agents({"agents": [{"id": "claude-agent", "type": "anthropic", "provider": "anthropic",
                                          "model": "claude-sonnet-4-0", "auth": {"type": "env", "var": "SEP_OTHER"}}]})
        self.warned([claude()], "same_model_same_address", agent=agents)
        self.refused([claude(key="other-agent-key")], "the same credential on the same address", agent=agents)
        self.refused([oai("or", "anthropic/claude-sonnet-4", "https://openrouter.ai/api/v1", " other-agent-key\n")],
                     r"the same credential \(agent at api.anthropic.com:443, judge at openrouter.ai:443\)",
                     agent=agents)
        # A mixed list: a declaration and an agents.yaml agent; the second one's key is found.
        self.refused([oai("or", "m", "https://openrouter.ai/api/v1", "other-agent-key")],
                     "judge 'or' vs agent 'claude-agent': the same credential", agent=[AGENT, *agents])


class SameProvider(Env):
    """The same provider is allowed by default. allow_same_provider_judge is a deprecated no-op."""

    def test_same_provider_different_model_is_allowed(self):
        agent = dict(AGENT, model="gpt-4o", base_url="https://api.openai.com/v1")
        tk = self.started([oai("mini", "gpt-4o-mini", "https://api.openai.com/v1", "judge-openai-key")], agent)
        rec = [e for e in tk.ledger.entries if e.kind == "constitution_loaded"][-1].body["judge_agent_separation"]
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["same_provider"], "allowed")
        self.assertEqual(rec["same_agent"], "same_held_credential_or_keyless_same_address")
        self.assertEqual(rec["checks"], ["same_credential", "same_address_no_credential"])
        self.assertNotIn("same_credential_other_address", rec["warning_checks"])
        self.assertEqual(rec["warnings"], [])
        self.warned([oai("same", "gpt-4o-2024-08-06", "https://api.openai.com/v1", "k2")],
                    "same_model_same_address", agent=agent)

    def test_same_model_on_a_different_endpoint_is_allowed(self):
        agent = dict(AGENT, model="gpt-4o", base_url="https://api.openai.com/v1")
        self.assertTrue(self.started([oai("or", "openai/gpt-4o", "https://openrouter.ai/api/v1", "k3")],
                                     agent).separation.ok)
        agent = dict(AGENT, model="llama3.1:8b", base_url="https://api.together.xyz/v1")
        # A local daemon with the same model and no declared upstream: allowed, with a warning.
        self.warned([OllamaJudge("q", "ollama", "llama3.1:8b")], "same_model_unknown_proxy", agent=agent)
        local_weights = OllamaJudge("q", "ollama", "llama3.1:8b")
        local_weights.upstream = ["localhost:11434"]
        self.assertEqual(self.started([local_weights], agent).separation.warnings, ())

    def test_same_local_endpoint_with_no_credential_is_refused(self):
        agent = {"id": "local-agent", "model": "llama3.1:8b", "provider": "ollama",
                 "base_url": "http://localhost:11434", "credential": "none"}
        # Two keyless sides on one daemon: nothing tells them apart, whatever the model.
        self.refused([OllamaJudge("q", "ollama", "qwen2.5:7b")],
                     "the same address localhost:11434 and no credential on either side", agent=agent)
        self.refused([OllamaJudge("q", "ollama", "llama3.1:8b", base_url="http://127.0.0.1:11434")],
                     "the same address localhost:11434", agent=agent)
        # Another daemon is another address.
        self.assertTrue(self.started([OllamaJudge("q", "ollama", "qwen2.5:7b", base_url="http://localhost:11435")],
                                     agent).separation.ok)

    def test_allow_same_provider_judge_is_a_deprecated_no_op(self):
        from two_key.judges.config import load_config
        _, policy = load_config({"judges": [{"id": "l", "type": "ollama", "model": "llama3"}],
                                 "quorum": {"required_yes": 1, "allow_same_provider_judge": True}})
        self.assertTrue(policy.allow_same_provider_judge)
        agent = dict(AGENT, model="gpt-4o", base_url="https://api.openai.com/v1")
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(err):
            start(tmp, [oai("mini", "gpt-4o-mini", "https://api.openai.com/v1", "jk")], agent,
                  quorum=QuorumPolicy(required_yes=1, allow_same_provider_judge=True))
        self.assertIn("deprecated and has no effect", err.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            self.refused([oai("same", "gpt-4o", "https://api.openai.com/v1", "agent-secret-key")],
                         "the same credential on the same address", agent=agent,
                         quorum=QuorumPolicy(required_yes=1, allow_same_provider_judge=True))


class ResolutionRereview(Env):
    """Re-review: a local proxy is not trusted to be local; unknown is unresolved; ids are NFKC-folded."""

    def test_local_endpoint_without_a_known_maker_is_unresolved_and_warned(self):
        for url in ("http://127.0.0.1:4000", "http://[::1]:4000", "http://10.0.0.5:4000"):
            j = OpenAICompatibleJudge("p", "x", "judge-alias", url, None, allow_insecure_http=True)
            tk = self.warned([j], "unresolved_identity")
            self.assertIn("judge upstream is unresolved", tk.separation.warnings[0]["detail"])
        agent = {"id": "proxy-agent", "model": "agent-alias", "provider": "x", "base_url": "http://127.0.0.1:4000",
                 "credential": "none"}
        self.warned([claude()], "unresolved_identity", agent=agent)

    def test_declared_upstream_resolves_and_is_ledgered(self):
        j = OpenAICompatibleJudge("p", "x", "judge-alias", "http://127.0.0.1:4000", None, allow_insecure_http=True)
        j.upstream = "api.anthropic.com"
        tk = self.started([j])
        rec = [e for e in tk.ledger.entries if e.kind == "constitution_loaded"][-1].body["judge_agent_separation"]
        judge = rec["judges"][0]
        self.assertEqual((judge["resolved_by"], judge["upstream"]), ("declared_upstream", ["api.anthropic.com"]))
        agent = {"id": "proxy-agent", "model": "agent-alias", "provider": "x", "base_url": "http://127.0.0.1:4000",
                 "credential": "none", "upstream": "https://api.x.ai/v1"}
        tk = self.started([claude()], agent=agent)
        self.assertEqual(tk.separation.agents[0].resolved_by, "declared_upstream")

    def test_resolved_by(self):
        self.assertEqual(resolve_upstream_info("https://api.openai.com/v1", "gpt-4o")[2], "endpoint")
        self.assertEqual(resolve_upstream_info("https://api.openai.com/v1", "gpt-4o")[2], "endpoint")
        self.assertEqual(resolve_upstream_info("https://openrouter.ai/api/v1", "openai/gpt-4o")[2], "model_prefix")
        self.assertEqual(resolve_upstream_info("https://llm.corp.example/v1", "openai/gpt-4o")[2], "model_prefix")
        self.assertEqual(resolve_upstream_info("http://localhost:4000", "qwen2.5:7b")[2], "model_prefix")
        self.assertIsNone(resolve_upstream_info("http://localhost:4000", "alias")[2])

    def test_unicode_model_ids_fold(self):
        for m in ("gpt\u20104o", "\uff47\uff50\uff54-4o", "gpt\u200b-4o", "GPT\u22124o"):
            self.assertEqual(normalize_model(m), normalize_model("gpt-4o"), repr(m))
        agent = dict(AGENT, model="gpt-4o", base_url="https://api.openai.com/v1")
        self.warned([oai("u", "gpt\u20104o", "https://api.openai.com/v1", "jk")], "same_model_same_address", agent=agent)

    def test_upstream_yaml_key(self):
        from two_key.judges.config import JudgeConfigError, load_config
        judges, _ = load_config({"judges": [{"id": "l", "type": "openai_compatible", "model": "alias",
                                             "base_url": "http://localhost:4000", "upstream": "api.openai.com"}],
                                 "quorum": {"required_yes": 1}})
        self.assertEqual(judges[0].upstream, ["api.openai.com"])
        with self.assertRaisesRegex(JudgeConfigError, "upstream entries must be non-empty strings"):
            load_config({"judges": [{"id": "l", "type": "ollama", "model": "m", "upstream": [""]}]})


class Accepted(Env):
    def test_distinct_judges_start_and_the_check_is_recorded(self):
        tk = self.started([claude(), OllamaJudge("q", "ollama", "qwen2.5:7b")])
        rec = [e for e in tk.ledger.entries if e.kind == "constitution_loaded"][-1].body["judge_agent_separation"]
        ledger_text = json.dumps([e.body for e in tk.ledger.entries])
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["rule"], "judge_is_not_monitored_agent")
        self.assertEqual([a["id"] for a in rec["agents"]], ["grok-agent"])
        self.assertEqual(rec["agents"][0]["upstream"], ["api.x.ai"])
        self.assertEqual({j["id"]: j["upstream"] for j in rec["judges"]},
                         {"claude": ["api.anthropic.com"], "q": ["localhost:11434", "maker:alibaba"]})
        self.assertIn(credential_fingerprint("judge-anthropic-key", tk.ledger.fingerprint_key()),
                      rec["judges"][0]["credential_fingerprint"])
        for raw in ("agent-secret-key", "judge-anthropic-key"):
            self.assertNotIn(raw, ledger_text)


class RuntimeSessionCheckForEveryJudge(unittest.TestCase):
    def test_local_judge_reusing_the_agent_session_abstains(self):
        def never(*a):
            raise AssertionError("must not call the model")
        j = OllamaJudge("q", "ollama", "qwen2.5:7b", credential=StaticToken("shared"), auth_header="bearer",
                        transport=never)
        a = normalize_action({"tool": "search"})
        self.assertEqual(j.score_bound("c", a, "", None, agent_session="shared").error,
                         "cloud_judge_reused_agent_session")

    def test_the_runtime_check_ignores_the_address(self):
        calls = []

        def transport(url, headers, body, timeout):
            calls.append(url)
            return {"message": {"content": '{"consistent": true, "confidence": 0.9, "rationale": "ok"}'}}
        j = OllamaJudge("q", "ollama", "qwen2.5:7b", credential=StaticToken("shared"), auth_header="bearer",
                        transport=transport)
        a = normalize_action({"tool": "search"})
        # A judge presenting the agent session is the agent, wherever it connects: it abstains without a call.
        self.assertEqual(j.score_bound("c", a, "", None, agent_session="shared").error,
                         "cloud_judge_reused_agent_session")
        self.assertEqual(calls, [])
        # Another session: the judge votes.
        self.assertEqual(j.score_bound("c", a, "", None, agent_session="other").vote, "yes")
        self.assertEqual(len(calls), 1)


def _yes_transport(calls, bodies):
    def transport(url, headers, body, timeout):
        calls.append(url)
        bodies.append(json.dumps(body))
        return {"choices": [{"message": {"content":
                '{"consistent": true, "confidence": 0.9, "rationale": "ok"}'}}]}
    return transport


class ConfiguredCredentialIsCompared(Env):
    """A placeholder ``agent_session`` must not hide the key named in the config."""

    def cloud(self, calls, bodies, key_var="SEP_JUDGE_KEY"):
        return OpenAICompatibleJudge(
            "c", "openai", "gpt-4o", "https://api.openai.com/v1", EnvApiKey(key_var),
            transport=_yes_transport(calls, bodies))

    def test_a_placeholder_does_not_hide_the_configured_key(self):
        os.environ["SEP_JUDGE_KEY"] = "judge-other-key"
        self.addCleanup(os.environ.pop, "SEP_JUDGE_KEY", None)
        calls, bodies = [], []
        tk = self.started([self.cloud(calls, bodies)])
        os.environ["SEP_AGENT_KEY"] = "judge-other-key"   # rotated onto the judge's key after startup
        decision = tk.authorize({"tool": "search"}, {}, "look", agent_session="x")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "cloud_judge_reused_agent_session")
        self.assertEqual(calls, [])
        ledger_text = json.dumps([e.body for e in tk.ledger.entries])
        self.assertNotIn("judge-other-key", ledger_text)
        self.assertNotIn("agent-secret-key", ledger_text)

    def test_a_placeholder_still_allows_a_judge_with_its_own_key(self):
        os.environ["SEP_JUDGE_KEY"] = "judge-other-key"
        self.addCleanup(os.environ.pop, "SEP_JUDGE_KEY", None)
        calls, bodies = [], []
        tk = self.started([self.cloud(calls, bodies)])
        decision = tk.authorize({"tool": "search"}, {}, "look", agent_session="x")
        self.assertTrue(decision.allowed)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("agent-secret-key", bodies[0])
        self.assertNotIn("judge-other-key", bodies[0])

    def test_omitting_the_session_still_denies_a_cloud_judge(self):
        os.environ["SEP_JUDGE_KEY"] = "judge-other-key"
        self.addCleanup(os.environ.pop, "SEP_JUDGE_KEY", None)
        tk = self.started([self.cloud([], [])])
        decision = tk.authorize({"tool": "search"}, {}, "look")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.path_b["reason"], "cloud_judge_session_required")

    def test_an_unreadable_configured_key_denies_before_the_judge_is_called(self):
        os.environ["SEP_JUDGE_KEY"] = "judge-other-key"
        self.addCleanup(os.environ.pop, "SEP_JUDGE_KEY", None)
        calls, bodies = [], []
        tk = self.started([self.cloud(calls, bodies)])
        os.environ.pop("SEP_AGENT_KEY")
        decision = tk.authorize({"tool": "search"}, {}, "look", agent_session="x")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "agent_credential_unreadable")
        self.assertEqual(calls, [])
        self.assertNotIn("agent-secret-key", json.dumps([e.body for e in tk.ledger.entries]))

    def test_the_configured_key_is_not_a_judge_argument(self):
        from two_key.judges.base import Ballot

        class Grab(FixedJudge):
            def __init__(self):
                super().__init__("g", "yes")
                self.seen = None

            def score_bound(self, constitution_text, action, proposal, binding, **kwargs):
                self.seen = dict(kwargs)
                return Ballot(self.judge_id, self.provider, "yes", 0.9, "fixed")

        judge = Grab()
        tk = self.started([judge])
        decision = tk.authorize({"tool": "search"}, {}, "look", agent_session="x")
        self.assertTrue(decision.allowed)
        self.assertEqual(judge.seen, {"agent_session": "x"})
        self.assertNotIn("agent-secret-key", json.dumps(judge.seen))

    def test_a_keyless_agent_still_has_nothing_to_add(self):
        """Residual: a second secret, or a keyless agent, is still only what the caller passes."""
        os.environ["SEP_JUDGE_KEY"] = "judge-other-key"
        self.addCleanup(os.environ.pop, "SEP_JUDGE_KEY", None)
        calls, bodies = [], []
        agent = {"id": "local-agent", "model": "m", "provider": "local",
                 "base_url": "http://127.0.0.1:9/v1", "credential": "none"}
        tk = self.started([self.cloud(calls, bodies)], agent=agent)
        decision = tk.authorize({"tool": "search"}, {}, "look", agent_session="x")
        self.assertTrue(decision.allowed)
        self.assertEqual(len(calls), 1)

    def test_a_username_and_password_are_the_named_key(self):
        os.environ["SEP_AGENT_USER"] = "alice"
        os.environ["SEP_AGENT_PASS"] = "start-secret"
        os.environ["SEP_JUDGE_USER"] = "carol"
        os.environ["SEP_JUDGE_PASS"] = "judge-secret"
        for name in ("SEP_AGENT_USER", "SEP_AGENT_PASS", "SEP_JUDGE_USER", "SEP_JUDGE_PASS"):
            self.addCleanup(os.environ.pop, name, None)
        calls, bodies = [], []
        judge = OpenAICompatibleJudge(
            "c", "openai", "gpt-4o", "https://api.openai.com/v1",
            BasicAuthCredential("SEP_JUDGE_USER", "SEP_JUDGE_PASS"),
            auth_header="basic", transport=_yes_transport(calls, bodies))
        agent = {"id": "a", "model": "m", "provider": "p", "base_url": "https://api.example.com/v1",
                 "username_env": "SEP_AGENT_USER", "password_env": "SEP_AGENT_PASS"}
        tk = self.started([judge], agent=agent)
        os.environ["SEP_AGENT_USER"] = "carol"
        os.environ["SEP_AGENT_PASS"] = "judge-secret"
        decision = tk.authorize({"tool": "search"}, {}, "look", agent_session="x")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "cloud_judge_reused_agent_session")
        self.assertEqual(calls, [])
        ledger_text = json.dumps([e.body for e in tk.ledger.entries])
        self.assertNotIn("judge-secret", ledger_text)
        self.assertNotIn("carol", ledger_text)

    def test_a_key_the_judge_holds_but_does_not_send_still_matches(self):
        calls = []

        def transport(url, headers, body, timeout):
            calls.append(json.dumps(body))
            return {"message": {"content": '{"consistent": true, "confidence": 0.9, "rationale": "ok"}'}}

        judge = OllamaJudge("q", "ollama", "qwen2.5:7b", "http://127.0.0.1:11434",
                            credential=StaticToken("judge-held"), auth_header="none", transport=transport)
        tk = self.started([judge])
        judge.credential._t = os.environ["SEP_AGENT_KEY"]
        decision = tk.authorize({"tool": "search"}, {}, "look", agent_session="x")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "cloud_judge_reused_agent_session")
        self.assertEqual(calls, [])
        self.assertNotIn(os.environ["SEP_AGENT_KEY"], json.dumps([e.body for e in tk.ledger.entries]))

    def test_whitespace_around_the_named_key_still_matches(self):
        os.environ["SEP_JUDGE_KEY"] = "judge-other-key"
        self.addCleanup(os.environ.pop, "SEP_JUDGE_KEY", None)
        calls, bodies = [], []
        tk = self.started([self.cloud(calls, bodies)])
        os.environ["SEP_AGENT_KEY"] = "  judge-other-key\n"
        decision = tk.authorize({"tool": "search"}, {}, "look", agent_session="x")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "cloud_judge_reused_agent_session")
        self.assertEqual(calls, [])

    def test_one_matching_judge_means_nobody_is_called(self):
        os.environ["SEP_JUDGE_KEY"] = "judge-a"
        os.environ["SEP_JUDGE_KEY_B"] = "judge-b"
        self.addCleanup(os.environ.pop, "SEP_JUDGE_KEY", None)
        self.addCleanup(os.environ.pop, "SEP_JUDGE_KEY_B", None)
        calls, bodies = [], []
        first = self.cloud(calls, bodies, "SEP_JUDGE_KEY")
        second = OpenAICompatibleJudge(
            "b", "other", "claude-sonnet-4-20250514", "https://api.anthropic.com/v1",
            EnvApiKey("SEP_JUDGE_KEY_B"), transport=_yes_transport(calls, bodies))
        tk = self.started([first, second], quorum=QuorumPolicy(required_yes=1))
        os.environ["SEP_JUDGE_KEY_B"] = os.environ["SEP_AGENT_KEY"]
        decision = tk.authorize({"tool": "search"}, {}, "look", agent_session="x")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "cloud_judge_reused_agent_session")
        self.assertEqual(calls, [])


class ModelFolding(unittest.TestCase):
    def test_azure_gpt_35_and_unicode_forms(self):
        from two_key.netloc import fold_model_id
        self.assertEqual(normalize_model("gpt-35-turbo"), normalize_model("gpt-3.5-turbo"))
        self.assertEqual(fold_model_id("\uff27PT\u2011\u200b4o "), "gpt-4o")
        self.assertEqual(normalize_model("gpt\u20134o"), normalize_model("gpt-4o"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
