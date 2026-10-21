# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""A judge is local only from its endpoint host, never from the declared local_weights flag."""

import unittest

from two_key.action import normalize_action
from two_key.judges.credentials import StaticToken
from two_key.judges.ollama import OllamaJudge
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.netloc import host_is_local, host_is_loopback
from two_key.quorum import QuorumConfigError, QuorumPolicy, check_judge_set
from two_key.testing import TEST_AGENT, FixedJudge

A = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})


def _never(*a):
    raise AssertionError("judge must not call its model")


class Locality(unittest.TestCase):
    def test_hosts(self):
        for h in ("localhost", "127.0.0.1", "::1", "[::1]"):
            self.assertTrue(host_is_loopback(h), h)
        for h in ("10.0.0.5", "192.168.1.9", "172.16.0.1", "fd00::1"):
            self.assertTrue(host_is_local(h), h)
            self.assertFalse(host_is_loopback(h), h)
        for h in ("ollama.com", "api.openai.com", "169.254.169.254", "8.8.8.8", "intranet.example", ""):
            self.assertFalse(host_is_local(h), h)

    def test_ollama_default_follows_the_host(self):
        self.assertTrue(OllamaJudge("l", "ollama", "qwen2.5:7b").is_local())
        lan = OllamaJudge("lan", "ollama", "qwen2.5:7b", base_url="http://192.168.1.9:11434", allow_insecure_http=True)
        self.assertTrue(lan.is_local())
        self.assertTrue(lan.is_cloud())  # not loopback: it needs the agent session check
        cloud = OllamaJudge("c", "ollama", "gpt-oss:120b-cloud", base_url="https://ollama.com")
        self.assertFalse(cloud.local_weights)
        self.assertFalse(cloud.is_local())
        self.assertTrue(cloud.is_cloud())

    def test_declared_flag_never_makes_a_remote_judge_local(self):
        for j in (OllamaJudge("c", "ollama", "m", base_url="https://ollama.com", local_weights=True),
                  OpenAICompatibleJudge("o", "openai", "gpt-4o", "https://api.openai.com/v1", local_weights=True)):
            self.assertFalse(j.is_local())
            self.assertTrue(j.is_cloud())
        floor = QuorumPolicy.high_assurance(required_yes=2)
        remote = [OllamaJudge("c", "ollama", "m", base_url="https://ollama.com", local_weights=True, maker="x"),
                  FixedJudge("b", "yes", provider="p", maker="y")]
        with self.assertRaisesRegex(QuorumConfigError, "insufficient_local_judges:0<1"):
            check_judge_set(remote, floor)

    def test_declared_local_cloud_judge_still_checks_the_agent_credential(self):
        j = OllamaJudge("c", "ollama", "m", base_url="https://ollama.com", local_weights=True,
                        credential=StaticToken("shared-key"), auth_header="bearer", transport=_never)
        self.assertEqual(j.score_bound("c", A, "", None).error, "cloud_judge_session_required")
        self.assertEqual(j.score_bound("c", A, "", None, agent_session="shared-key").error,
                         "cloud_judge_reused_agent_session")


class RequireLocalYesNeedsALocalJudge(unittest.TestCase):
    def test_config_error_everywhere(self):
        import tempfile
        from pathlib import Path
        from two_key.constitution import sign_constitution, verify_signed
        from two_key.core import TwoKey
        from two_key.judges.config import JudgeConfigError, load_config
        from two_key.keys import generate_private_key
        from two_key.ledger import Ledger
        from two_key.quorum import convene
        js = [FixedJudge("a", "yes", provider="p1", maker="v1"), FixedJudge("b", "yes", provider="p2", maker="v2")]
        p = QuorumPolicy(required_yes=2, require_local_yes=True)
        with self.assertRaisesRegex(QuorumConfigError, "require_local_yes_without_local_judge"):
            check_judge_set(js, p)
        q = convene(js, "c", A, "", p)
        self.assertFalse(q.passed)
        self.assertEqual(q.reason, "judge_set_not_heterogeneous:require_local_yes_without_local_judge")
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            env = sign_constitution("c", [{"id": "t", "allow_only_tools": ["search"]}], key,
                                    {"search": {"irreversible": False, "data_class_floor": "public"}})
            with self.assertRaisesRegex(QuorumConfigError, "require_local_yes_without_local_judge"):
                TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()), js,
                       private_key=key, quorum=p, allow_test_doubles=True, monitored_agent=TEST_AGENT)
        with self.assertRaisesRegex(JudgeConfigError, "require_local_yes_without_local_judge"):
            load_config({"judges": [{"id": "x", "type": "openai_compatible", "base_url": "https://api.x.ai/v1",
                                     "model": "m", "auth": {"type": "env", "var": "X"}}],
                         "quorum": {"required_yes": 1, "require_local_yes": True}})

    def test_local_judge_must_say_yes(self):
        from two_key.quorum import convene
        js = [FixedJudge("l", "no", provider="pl", maker="vl", local_weights=True),
              FixedJudge("b", "yes", provider="p2", maker="v2"), FixedJudge("c", "yes", provider="p3", maker="v3")]
        q = convene(js, "c", A, "", QuorumPolicy(required_yes=2, require_local_yes=True))
        self.assertEqual((q.passed, q.reason), (False, "local_judge_required"))


class OllamaCloudModels(unittest.TestCase):
    """Re-review: an Ollama model named *:cloud or *-cloud runs at ollama.com, so it is never local."""

    def test_cloud_model_on_loopback_is_cloud_and_not_local(self):
        for model in ("gpt-oss:120b-cloud", "deepseek-v3.1:671b-cloud", "qwen3-coder:cloud", "GPT-OSS:20B-CLOUD"):
            for kw in ({}, {"local_weights": True}):
                j = OllamaJudge("o", "ollama", model, base_url="http://127.0.0.1:11434", **kw)
                self.assertTrue(j.is_cloud(), model)
                self.assertFalse(j.is_local(), (model, kw))
        positional = OllamaJudge("o", "ollama", "gpt-oss:120b-cloud", "http://localhost:11434")
        self.assertFalse(positional.is_local())
        plain = OllamaJudge("p", "ollama", "llama3", base_url="http://127.0.0.1:11434")
        self.assertTrue(plain.is_local())
        self.assertFalse(plain.is_cloud())

    def test_cloud_model_does_not_meet_high_assurance(self):
        o = OllamaJudge("o", "ollama", "gpt-oss:120b-cloud", base_url="http://127.0.0.1:11434")
        with self.assertRaisesRegex(QuorumConfigError, "insufficient_local_judges|require_local_yes_without_local_judge"):
            check_judge_set([o, FixedJudge("b", "yes", provider="openai", maker="openai")],
                            QuorumPolicy.high_assurance())


if __name__ == "__main__":
    unittest.main(verbosity=2)
