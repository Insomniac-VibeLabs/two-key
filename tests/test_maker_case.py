# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The maker-diversity floor compares maker names case-insensitively (and NFKC, trimmed).

``maker`` / ``min_makers`` were ``vendor`` / ``min_vendors`` through 0.2.1; 0.2.3 refuses the old names.
"""

import dataclasses
import unittest

from two_key.judges.config import JudgeConfigError, load_config
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.quorum import QuorumConfigError, QuorumPolicy, check_judge_set, convene, heterogeneity_shortfall
from two_key.testing import FixedJudge

POLICY = QuorumPolicy(required_yes=2, min_makers=2, min_local_judges=0, require_local_yes=False)


class MakerCase(unittest.TestCase):
    def test_case_variants_are_one_maker(self):
        for a, b in (("OpenAI", "openai"), ("openai", "OPENAI "), ("Anthropic", "ａｎｔｈｒｏｐｉｃ")):
            judges = [FixedJudge("a", "yes", maker=a), FixedJudge("b", "yes", maker=b)]
            self.assertEqual(heterogeneity_shortfall(judges, POLICY), "insufficient_makers:1<2", (a, b))
            with self.assertRaisesRegex(QuorumConfigError, "insufficient_makers:1<2"):
                check_judge_set(judges, POLICY)

    def test_provider_fallback_is_folded_too(self):
        judges = [FixedJudge("a", "yes", "XAI"), FixedJudge("b", "yes", "xai")]
        self.assertEqual(heterogeneity_shortfall(judges, POLICY), "insufficient_makers:1<2")

    def test_distinct_makers_still_count(self):
        judges = [FixedJudge("a", "yes", maker="OpenAI"), FixedJudge("b", "yes", maker="Anthropic")]
        self.assertIsNone(heterogeneity_shortfall(judges, POLICY))

    def test_convene_denies_case_variants(self):
        from two_key.action import normalize_action
        judges = [FixedJudge("a", "yes", maker="OpenAI"), FixedJudge("b", "yes", maker="openai")]
        act = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
        r = convene(judges, "Be careful.", act, "look it up", POLICY)
        self.assertFalse(r.passed)
        self.assertEqual(r.reason, "judge_set_not_heterogeneous:insufficient_makers:1<2")


class ProviderCase(unittest.TestCase):
    def test_distinct_provider_count_folds_case(self):
        from two_key.action import normalize_action
        judges = [FixedJudge("a", "yes", "OpenAI"), FixedJudge("b", "yes", "openai ")]
        act = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
        r = convene(judges, "Be careful.", act, "look it up", QuorumPolicy(required_yes=2, min_distinct_providers=2))
        self.assertEqual(r.reason, "insufficient_distinct_providers:1<2")


def judge_spec(jid, **extra):
    return {"id": jid, "type": "openai_compatible", "base_url": "https://api.example.com/v1", "model": "m",
            "auth": {"type": "none"}, **extra}


class OldNames(unittest.TestCase):
    """vendor and min_vendors (through 0.2.1, deprecated in 0.2.2) are removed in 0.2.3: refused, not read."""

    def test_policy_record_uses_the_new_key(self):
        rec = QuorumPolicy.high_assurance().to_record()
        self.assertEqual(rec["min_makers"], 2)
        self.assertNotIn("min_vendors", rec)
        self.assertFalse(hasattr(QuorumPolicy(), "min_vendors"))

    def test_min_vendors_keyword_is_refused(self):
        for build in (QuorumPolicy, QuorumPolicy.high_assurance, QuorumPolicy.section4,
                      QuorumPolicy.without_diversity_floors):
            with self.assertRaisesRegex(TypeError, "min_vendors", msg=build):
                build(min_vendors=3)

    def test_replace_keeps_a_new_min_makers(self):
        p = QuorumPolicy(min_makers=3)
        self.assertEqual(dataclasses.replace(p, min_makers=1).min_makers, 1)
        self.assertEqual(p.resolved(4).min_makers, 3)

    def test_vendor_keyword_is_refused(self):
        with self.assertRaisesRegex(TypeError, "vendor"):
            FixedJudge("a", "yes", vendor="OpenAI")  # skipcq: PYL-E1123 - test only
        with self.assertRaisesRegex(TypeError, "vendor"):
            OpenAICompatibleJudge("o", "p", "m", "https://api.example.com/v1", vendor="xai")
        self.assertFalse(hasattr(FixedJudge("a", "yes", maker="OpenAI"), "vendor"))

    def test_an_old_vendor_label_is_not_read(self):
        from two_key.judges.base import Ballot, Judge

        class Old(Judge):
            vendor = "same-maker"

            def __init__(self, jid, provider):
                self.judge_id, self.provider, self._vendor = jid, provider, "same-maker"

            def score(self, constitution_text, action, proposal):
                return Ballot(self.judge_id, self.provider, "yes", 0.9, "")
        judges = [Old("a", "p1"), Old("b", "p2")]
        self.assertEqual([j.maker for j in judges], ["p1", "p2"])
        self.assertIsNone(heterogeneity_shortfall(judges, POLICY))

    def test_config_refuses_old_keys(self):
        with self.assertRaisesRegex(JudgeConfigError, r"unknown key\(s\) \['vendor'\]"):
            load_config({"judges": [judge_spec("a", vendor="openai")]})
        with self.assertRaisesRegex(JudgeConfigError, r"unknown quorum keys \['min_vendors'\]"):
            load_config({"judges": [judge_spec("a")], "quorum": {"min_vendors": 1}})

    def test_config_new_keys(self):
        cfg = {"judges": [judge_spec("a", maker="openai"), judge_spec("b", maker="openai")],
               "quorum": {"min_makers": 2, "required_yes": 2}}
        with self.assertRaisesRegex(JudgeConfigError, "insufficient_makers:1<2"):
            load_config(cfg)
        cfg["judges"][1]["maker"] = "anthropic"
        judges, policy = load_config(cfg)
        self.assertEqual(([j.maker for j in judges], policy.min_makers), (["openai", "anthropic"], 2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
