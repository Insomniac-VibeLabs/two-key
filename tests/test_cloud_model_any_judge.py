# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""B-2: a :cloud / -cloud model is cloud and never local for every judge class, not only OllamaJudge."""

import unittest

from two_key.agents import hosting_of
from two_key.judges.ollama import OllamaJudge
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.quorum import QuorumPolicy, heterogeneity_shortfall


def oai(model, url="http://localhost:11434/v1"):
    return OpenAICompatibleJudge("j", "ollama", model, url, local_weights=True)


class CloudModelAnyJudge(unittest.TestCase):
    def test_openai_compatible_on_loopback(self):
        for model in ("gpt-oss:120b-cloud", "gpt-oss:120b:cloud", "qwen3-coder:480B-CLOUD", "deepseek\u2011v3.1:671b\u2010cloud"):
            j = oai(model)
            self.assertFalse(j.is_local(), model)
            self.assertTrue(j.is_cloud(), model)
        j = oai("qwen2.5:7b")
        self.assertTrue(j.is_local())
        self.assertFalse(j.is_cloud())

    def test_private_address_too(self):
        j = OpenAICompatibleJudge("j", "x", "gpt-oss:120b-cloud", "http://10.0.0.5:11434/v1", local_weights=True,
                                  allow_insecure_http=True)
        self.assertFalse(j.is_local())
        self.assertTrue(j.is_cloud())

    def test_ollama_unchanged(self):
        self.assertFalse(OllamaJudge("o", "ollama", "gpt-oss:120b-cloud").is_local())
        self.assertTrue(OllamaJudge("o", "ollama", "gpt-oss:120b-cloud").is_cloud())
        self.assertTrue(OllamaJudge("o", "ollama", "qwen2.5:7b").is_local())

    def test_does_not_satisfy_the_local_floor(self):
        policy = QuorumPolicy(required_yes=1, min_makers=1, min_local_judges=1, require_local_yes=False)
        self.assertEqual(heterogeneity_shortfall([oai("gpt-oss:120b-cloud")], policy), "insufficient_local_judges:0<1")

    def test_monitored_agent_hosting(self):
        self.assertEqual(hosting_of("http://localhost:11434", "local", model="gpt-oss:120b-cloud"), "cloud")
        self.assertEqual(hosting_of("http://localhost:11434", None, local_default=True, model="qwen2.5:7b"), "local")


if __name__ == "__main__":
    unittest.main(verbosity=2)
