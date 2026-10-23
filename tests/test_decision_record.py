# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Fix 7: the ledger records the quorum policy in effect and each judge's resolved identity.

The identities are written once, in constitution_loaded; each decision references them by digest.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from two_key.canonical import canonical_hash
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.identity import credential_fingerprint, normalize_model
from two_key.judges.anthropic import AnthropicJudge
from two_key.judges.credentials import StaticToken
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}
AGENT = {"id": "grok-agent", "model": "grok-4", "provider": "xai", "base_url": "https://api.x.ai/v1",
         "credential_env": "REC_AGENT_KEY"}


def yes(url, headers, body, timeout):
    return {"content": [{"type": "text", "text": json.dumps({"consistent": True, "confidence": 0.9, "rationale": "ok"})}]}


class DecisionRecord(unittest.TestCase):
    def test_every_decision_carries_policy_and_identities_digests(self):
        os.environ["REC_AGENT_KEY"] = "agent-secret"
        self.addCleanup(os.environ.pop, "REC_AGENT_KEY", None)
        judge = AnthropicJudge("claude", "anthropic", "claude-3-haiku-20240307", credential=StaticToken("judge-key"),
                               transport=yes)
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            env = sign_constitution("Searching is fine.", RULES, key, SPECS)
            policy = QuorumPolicy(required_yes=1, tool_args_on_derive_deny=True)
            tk = TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()), [judge],
                        private_key=key, quorum=policy, monitored_agent=AGENT)
            allowed = tk.authorize({"tool": "search", "data_class": "public", "irreversible": False}, {}, "s",
                                   agent_session="agent-secret")
            denied = tk.authorize({"tool": "nope"}, {}, "s", agent_session="agent-secret")
            malformed = tk.authorize({"tool": 5}, {}, "s", agent_session="agent-secret")
            self.assertTrue(allowed.allowed, allowed.reason)
            self.assertFalse(denied.allowed)
            self.assertTrue(malformed.reason.startswith("malformed_action"))
            loaded = [e for e in tk.ledger.entries if e.kind == "constitution_loaded"][-1].body
            self.assertEqual(loaded["quorum_policy"], policy.to_record())
            self.assertTrue(loaded["quorum_policy"]["tool_args_on_derive_deny"])
            decisions = [e.body for e in tk.ledger.entries if e.kind == "decision"]
            self.assertEqual(len(decisions), 3)
            sep = loaded["judge_agent_separation"]
            self.assertEqual(sep["identities_digest"],
                             canonical_hash({"agents": sep["agents"], "judges": sep["judges"]}))
            fp_key = tk.ledger.fingerprint_key()
            self.assertEqual(loaded["policy_digest"], canonical_hash(policy.to_record()))
            for d in decisions:
                self.assertNotIn("policy", d)          # the full policy is in constitution_loaded only
                self.assertEqual(d["policy_digest"], canonical_hash(loaded["quorum_policy"]))
                self.assertNotIn("judges", d)          # identities are written once, referenced by digest
                self.assertEqual(d["identities_digest"], sep["identities_digest"])
            (j,) = sep["judges"]
            self.assertEqual(j["id"], "claude")
            self.assertEqual(j["model"], normalize_model("claude-3-haiku"))
            self.assertEqual(j["model_declared"], "claude-3-haiku-20240307")
            self.assertEqual(j["upstream"], ["api.anthropic.com"])
            self.assertEqual(j["credential_fingerprint"], [credential_fingerprint("judge-key", fp_key)])
            self.assertTrue(j["credential_fingerprint"][0].startswith("hmac-sha256:"))
            self.assertEqual(sep["agents"][0]["upstream"], ["api.x.ai"])
            text = json.dumps([e.body for e in tk.ledger.entries])
            self.assertNotIn('"judge-key"', text)
            self.assertNotIn("agent-secret", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
