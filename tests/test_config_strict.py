# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Re-review: the judges config loader refuses unknown top-level keys."""

import unittest

from two_key.judges.config import JudgeConfigError, load_config

J2 = [{"id": "a", "type": "ollama", "model": "llama3"}, {"id": "b", "type": "ollama", "model": "qwen2.5:7b"}]


class TopLevel(unittest.TestCase):
    def test_typo_is_refused(self):
        with self.assertRaisesRegex(JudgeConfigError, r"unknown top-level key\(s\) \['quorm'\]"):
            load_config({"judges": J2, "quorm": {"profile": "high_assurance"}})

    def test_agents_config_typo_is_refused(self):
        from two_key.agents import AgentConfigError, load_agents
        with self.assertRaisesRegex(AgentConfigError, r"unknown top-level key\(s\) \['agnets'\]; allowed: \['agents'\]"):
            load_agents({"agents": [{"id": "a", "type": "ollama", "model": "llama3"}], "agnets": []})

    def test_known_keys_load(self):
        _, policy = load_config({"judges": J2, "quorum": {"required_yes": 1},
                                 "monitored_agent": {"model": "m", "provider": "p", "base_url": "http://localhost:1",
                                                     "credential": "none"}})
        self.assertEqual(policy.required_yes, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
