# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Each behaviour change the "Upgrading from 0.1.12" section lists, checked."""

import tempfile
import unittest
from pathlib import Path

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.gateway import ToolGateway
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


class UpgradeNotes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, key, SPECS)
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), key), key.public_key(),
                         verify_signed(env, key.public_key()), [FixedJudge("a", "yes")], private_key=key,
                         quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)

    def test_decision_record_has_no_token(self):
        d = self.tk.authorize(SEARCH, {"q": "x"}, "look")
        rec = d.to_record()
        self.assertNotIn("token", rec)
        self.assertEqual(rec["token_jti"], d.token_jti)
        self.assertTrue(d.token)

    def test_required_yes_is_unresolved_by_default(self):
        self.assertIsNone(QuorumPolicy().required_yes)

    def test_lan_judge_with_local_weights_is_cloud(self):
        lan = OpenAICompatibleJudge("o", "llama", "llama3", "http://192.168.1.9:8000/v1", local_weights=True,
                                    allow_insecure_http=True)
        self.assertTrue(lan.is_cloud())     # needs agent_session
        self.assertTrue(lan.is_local())     # still counts toward local-judge floors

    def test_token_issued_without_a_pinned_key_is_refused(self):
        # A ledger whose latest constitution_loaded has no pin, as a 0.1.12 ledger does.
        self.tk.ledger.append("constitution_loaded", {"constitution_hash": "old"})
        self.tk.ledger.checkpoint()
        d = self.tk.authorize(SEARCH, {"q": "x"}, "look")
        gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled, tools={"search": lambda a: "ok"})
        self.assertEqual(gw.invoke(d.token, "search", {"q": "x"}).reason, "capability_key_mismatch")


if __name__ == "__main__":
    unittest.main()
