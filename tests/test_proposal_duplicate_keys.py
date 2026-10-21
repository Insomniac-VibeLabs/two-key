# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Fix 12: a repeated JSON key in an agent proposal is refused, at any depth, not last-one-wins."""

import json
import unittest

from two_key.agents import AgentConfigError, parse_proposal


class DuplicateKeys(unittest.TestCase):
    def test_refused_everywhere(self):
        for text in ('{"tool":"pay","arguments":{"to":"ada","to":"mallory"},"proposal":"p"}',
                     '{"tool":"pay","tool":"wire","arguments":{},"proposal":"p"}',
                     '{"tool":"pay","arguments":{"a":{"b":1,"b":2}},"proposal":"p"}',
                     json.dumps({"tool": "pay", "arguments": '{"to":"ada","to":"mallory"}', "proposal": "p"})):
            with self.assertRaisesRegex(AgentConfigError, "duplicate key"):
                parse_proposal(text)

    def test_clean_proposal_unchanged(self):
        action, args, proposal = parse_proposal(
            '{"tool":"pay","arguments":{"to":"ada","a":{"b":1}},"proposal":"p","amount_usd":3}')
        self.assertEqual((action, args, proposal), ({"tool": "pay", "amount_usd": 3}, {"to": "ada", "a": {"b": 1}}, "p"))
        with self.assertRaisesRegex(AgentConfigError, "is not JSON"):
            parse_proposal("not json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
