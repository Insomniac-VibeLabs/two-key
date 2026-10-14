"""What the monitored agent is told. It must learn the data classes and that omitting one means classified."""

import unittest

from two_key.action import DATA_CLASSES, DEFAULT_DATA_CLASS
from two_key.agents import SYSTEM, user_prompt


class AgentSystemPrompt(unittest.TestCase):
    def test_lists_every_data_class(self):
        for name in DATA_CLASSES:
            self.assertIn(name, SYSTEM)

    def test_says_an_omitted_class_is_the_default(self):
        self.assertEqual(DEFAULT_DATA_CLASS, "classified")
        self.assertIn('Omitting "data_class" means classified', SYSTEM)

    def test_user_prompt_still_carries_only_prose_and_instruction(self):
        text = user_prompt("Pay power-co.example.", "pay the bill")
        self.assertIn("<principal_constitution>", text)
        self.assertIn("<untrusted_instruction>", text)
        self.assertNotIn("tool_specs", text)


if __name__ == "__main__":
    unittest.main()
