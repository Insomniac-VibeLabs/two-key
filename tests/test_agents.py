"""Monitored agents may be local or vendor-hosted. Hosting is not trust."""
import json
import os
import unittest

from two_key.action import normalize_action
from two_key.agents import AgentConfigError, hosting_of, load_agents, parse_proposal
from two_key.judges import OpenAICompatibleJudge
from two_key.judges.credentials import StaticToken
from two_key.testing import HeuristicJudge

from helpers import TwoKeyFixture

GOOD = json.dumps({"tool": "search", "arguments": {"q": "weather"}, "proposal": "look up the weather",
                    "data_class": "personal", "irreversible": False})


class Recorder:
    def __init__(self, response):
        self.response, self.calls = response, []

    def __call__(self, url, headers, body, timeout):
        self.calls.append((url, headers, body))
        return self.response


def chat(text):
    return {"choices": [{"message": {"content": text}}]}


class Agents(unittest.TestCase):
    def test_vendor_host_cannot_be_labeled_local(self):
        self.assertEqual(hosting_of("https://api.x.ai/v1", "local"), "cloud")
        self.assertEqual(hosting_of("https://api.anthropic.com", None), "cloud")
        self.assertEqual(hosting_of("http://localhost:11434", None, local_default=True), "local")

    def test_proposal_parser_rejects_extra_keys(self):
        action, args, text = parse_proposal(GOOD)
        self.assertEqual(action["tool"], "search")
        self.assertEqual(args, {"q": "weather"})
        self.assertEqual(text, "look up the weather")
        with self.assertRaises(AgentConfigError):
            parse_proposal('{"tool": "search", "arguments": {}, "proposal": "x", "execute": true}')

    def test_several_providers_load(self):
        agents = load_agents({"agents": [
            {"id": "grok", "type": "openai_compatible", "provider": "xai", "base_url": "https://api.x.ai/v1",
             "model": "grok-test", "auth": {"type": "env", "var": "XAI_AGENT_API_KEY"}},
            {"id": "claude", "type": "anthropic", "provider": "anthropic", "model": "claude-test",
             "auth": {"type": "env", "var": "ANTHROPIC_AGENT_API_KEY"}},
            {"id": "local", "type": "ollama", "provider": "local", "model": "llama-test"},
        ]}, transport=Recorder(chat(GOOD)))
        self.assertEqual([a.hosting for a in agents], ["cloud", "cloud", "local"])

    def test_authorize_from_agent_still_checks_the_constitution(self):
        transport = Recorder(chat(GOOD))
        agents = load_agents({"agents": [
            {"id": "local", "type": "openai_compatible", "provider": "local", "hosting": "local",
             "base_url": "http://127.0.0.1:9/v1", "model": "m"},
        ]}, transport=transport)
        with TwoKeyFixture([{"allow_only_tools": ["search"]}], [HeuristicJudge("h")], agents=agents) as tk:
            allowed = tk.authorize_from_agent("local", "weather")
            self.assertTrue(allowed.allowed, allowed.reason)
            denied = tk.authorize_from_agent("local", "weather")
            # second call proposes search again; single-use is at the gateway, so authorize may allow again
            self.assertTrue(denied.allowed)
            missing = tk.authorize_from_agent("nope", "weather")
            self.assertEqual(missing.reason, "unknown_agent")
            self.assertIsNone(missing.capability)
        system = transport.calls[0][2]["messages"][0]["content"]
        self.assertIn("PROPOSE", system)
        self.assertNotIn("execute a tool", system.lower())

    def test_cloud_agent_credential_cannot_be_the_judge_credential(self):
        os.environ["AGENT_KEY"] = "shared-secret"
        try:
            agents = load_agents({"agents": [
                {"id": "grok", "type": "openai_compatible", "provider": "xai", "base_url": "https://api.x.ai/v1",
                 "model": "grok-test", "auth": {"type": "env", "var": "AGENT_KEY"}},
            ]}, transport=Recorder(chat(GOOD)))
            judge = OpenAICompatibleJudge(judge_id="j", provider="xai", model="m", base_url="https://api.x.ai/v1",
                                          credential=StaticToken("shared-secret"),
                                          transport=Recorder(chat('{"consistent": true, "confidence": 1, "rationale": "ok"}')))
            with TwoKeyFixture([{"allow_only_tools": ["search"]}], [judge], agents=agents) as tk:
                d = tk.authorize_from_agent("grok", "weather")
            self.assertFalse(d.allowed)
            self.assertIn("cloud_judge_reused_agent_session", d.reason)
        finally:
            os.environ.pop("AGENT_KEY", None)




if __name__ == "__main__":
    unittest.main()
