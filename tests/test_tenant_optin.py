# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""allow_same_model_distinct_tenant: deprecated, no effect (2026-10-08).

A judge is refused when it uses the monitored agent's credential, at any address, so nothing is left for the
flag to lift. It is still accepted, recorded in constitution_loaded (same_model_tenant_optin, with
an always-empty pairs list), part of the policy digest, and it prints a deprecation note. A misspelled flag is
still refused.
"""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.identity import TENANT_OPTIN_DEPRECATED, AgentDeclaration, compare, judge_identity
from two_key.judges.config import JudgeConfigError, load_config
from two_key.judges.credentials import StaticToken
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.audit import policy_digest
from two_key.quorum import QuorumConfigError, QuorumPolicy

AGENT = {"id": "agent", "model": "gpt-4o", "provider": "openai", "base_url": "https://api.openai.com/v1",
         "credential_env": "OPTIN_AGENT_KEY", "tenant": {"project": "p1"}}
FP = b"k" * 32


def judge(model="gpt-4o", base_url="https://api.openai.com/v1", key="judge-key", tenant=None, upstream=None):
    return SimpleNamespace(judge_id="j", model=model, base_url=base_url, provider="x",
                           credential=StaticToken(key) if key else None, tenant=tenant, upstream=upstream)


class Compare(unittest.TestCase):
    def setUp(self):
        os.environ["OPTIN_AGENT_KEY"] = "agent-key-K"
        self.addCleanup(os.environ.pop, "OPTIN_AGENT_KEY", None)

    def verdict(self, agent, j, flag):
        a = AgentDeclaration.from_mapping(agent).resolve(fp_key=FP)
        return compare(a, judge_identity(j, FP), allow_same_model_distinct_tenant=flag)

    def test_the_flag_changes_nothing(self):
        cases = [judge(tenant={"project": "p2"}), judge(), judge(tenant={"project": "P1"}),
                 judge(base_url="http://localhost:4000", upstream="api.openai.com", tenant={"project": "p2"}),
                 judge(key="agent-key-K"), judge(key="agent-key-K", base_url="http://localhost:4000")]
        for j in cases:
            with self.subTest(base_url=j.base_url, tenant=j.tenant):
                self.assertEqual(self.verdict(AGENT, j, True), self.verdict(AGENT, j, False))

    def test_same_credential_on_the_same_address_is_still_refused(self):
        self.assertRegex(self.verdict(AGENT, judge(key="agent-key-K", tenant={"project": "p2"}), True),
                         "the same credential on the same address api.openai.com:443")


class Config(unittest.TestCase):
    def test_default_off_and_strict(self):
        self.assertFalse(QuorumPolicy().allow_same_model_distinct_tenant)
        self.assertIn("allow_same_model_distinct_tenant", QuorumPolicy().to_record())
        with self.assertRaisesRegex(QuorumConfigError, "allow_same_model_distinct_tenant must be a boolean"):
            QuorumPolicy(allow_same_model_distinct_tenant="yes")

    def test_misspelled_flag_is_rejected(self):
        for name in ("allow_same_model_distinct_tenants", "allow_same_model_different_tenant"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(JudgeConfigError, f"unknown quorum keys \\['{name}'\\]"):
                    load_config({"judges": [{"id": "l", "type": "ollama", "model": "m"}], "quorum": {name: True}})
        with self.assertRaises(TypeError):
            QuorumPolicy(allow_same_model_distinct_tenants=True)
        _, policy = load_config({"judges": [{"id": "l", "type": "ollama", "model": "m"}],
                                 "quorum": {"allow_same_model_distinct_tenant": True}})
        self.assertTrue(policy.allow_same_model_distinct_tenant)

    def test_policy_digest_still_covers_the_flag(self):
        self.assertNotEqual(policy_digest(QuorumPolicy(required_yes=1).to_record()),
                            policy_digest(QuorumPolicy(required_yes=1,
                                                       allow_same_model_distinct_tenant=True).to_record()))


class EndToEnd(unittest.TestCase):
    def setUp(self):
        os.environ["OPTIN_AGENT_KEY"] = "agent-key-K"
        self.addCleanup(os.environ.pop, "OPTIN_AGENT_KEY", None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = generate_private_key()
        self.env = sign_constitution("Searching is fine.", [{"id": "t", "allow_only_tools": ["search"]}], self.key,
                                     {"search": {"irreversible": False, "data_class_floor": "public"}})

    def start(self, flag, tenant, key="judge-key", model="gpt-4o"):
        j = OpenAICompatibleJudge("j", "openai", model, "https://api.openai.com/v1", StaticToken(key))
        j.tenant = tenant
        err = io.StringIO()
        with redirect_stderr(err):
            tk = TwoKey(Ledger(Path(self.tmp.name, f"ledger-{flag}-{bool(tenant)}-{key}"), self.key),
                        self.key.public_key(), verify_signed(self.env, self.key.public_key()), [j],
                        private_key=self.key, quorum=QuorumPolicy(required_yes=1, allow_same_model_distinct_tenant=flag),
                        monitored_agent=AGENT)
        return tk, err.getvalue()

    def test_flag_set_is_recorded_and_noted_as_deprecated(self):
        tk, err = self.start(True, {"project": "p2"})
        self.assertIn(TENANT_OPTIN_DEPRECATED, err)
        [loaded] = [e.body for e in tk.ledger.entries if e.kind == "constitution_loaded"]
        self.assertIs(loaded["same_model_tenant_optin"], True)
        self.assertEqual(loaded["same_model_tenant_optin_pairs"], [])
        self.assertTrue(loaded["quorum_policy"]["allow_same_model_distinct_tenant"])
        self.assertEqual(loaded["policy_digest"], policy_digest(loaded["quorum_policy"]))
        self.assertIs(loaded["judge_agent_separation"]["same_model_tenant_optin"], True)

    def test_same_model_same_address_starts_either_way_with_a_warning(self):
        for flag in (False, True):
            with self.subTest(flag=flag):
                tk, err = self.start(flag, {"project": "p2"})
                self.assertIn("(same_model_same_address)", err)
                self.assertTrue(tk.separation.ok)

    def test_the_agents_key_on_the_agents_address_is_refused_either_way(self):
        for flag in (False, True):
            with self.subTest(flag=flag):
                with self.assertRaisesRegex(TwoKeyConfigError, "judge_matches_agent: .*the same credential"):
                    self.start(flag, {"project": "p2"}, key="agent-key-K")

    def test_default_records_the_flag_as_off(self):
        tk, err = self.start(False, None, model="gpt-4o-mini")
        self.assertNotIn("allow_same_model_distinct_tenant", err)
        [loaded] = [e.body for e in tk.ledger.entries if e.kind == "constitution_loaded"]
        self.assertIs(loaded["same_model_tenant_optin"], False)
        self.assertEqual(loaded["same_model_tenant_optin_pairs"], [])


if __name__ == "__main__":
    unittest.main()
