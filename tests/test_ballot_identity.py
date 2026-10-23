# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Re-review: a ballot cannot claim another judge's identity. Ballots are paired with judges by
position, judge_id and provider come from the judge object, and a mismatched judge_id abstains."""

import unittest

from two_key.action import normalize_action
from two_key.judges.base import Ballot, Judge
from two_key.quorum import QuorumPolicy, convene
from two_key.testing import FixedJudge, RaisingJudge

SEARCH = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})


class Liar(Judge):
    judge_id, provider, is_test_double = "cloud", "openai", True

    def score(self, c, a, p):
        return Ballot("local", "ollama", "yes", 0.9, "")


class ProviderLiar(Judge):
    judge_id, provider, is_test_double = "c2", "openai", True

    def score(self, c, a, p):
        return Ballot("c2", "some-other-vendor", "yes", 0.9, "")


class Impersonation(unittest.TestCase):
    def test_ballot_naming_the_local_judge_does_not_count_as_its_yes(self):
        loc = FixedJudge("local", "no", provider="ollama", local_weights=True)
        q = convene([loc, Liar(), FixedJudge("c", "yes", provider="anthropic")], "c", SEARCH, "p",
                    QuorumPolicy.high_assurance(required_yes=2))
        self.assertFalse(q.passed)
        liar = q.ballots[1]
        self.assertEqual((liar.judge_id, liar.provider, liar.vote, liar.error), ("cloud", "openai", "abstain",
                                                                                   "judge_id_mismatch"))
        self.assertEqual([b.judge_id for b in q.ballots], ["local", "cloud", "c"])

    def test_provider_comes_from_the_judge(self):
        # Two providers are configured, but the anthropic judge abstains: only the liar's claimed
        # "some-other-vendor" could make a second responding provider, and it is not used.
        q = convene([ProviderLiar(), FixedJudge("c", "yes", provider="openai"), RaisingJudge("r", "anthropic")],
                    "c", SEARCH, "p", QuorumPolicy(required_yes=2, min_distinct_providers=2))
        self.assertEqual(q.ballots[0].provider, "openai")
        self.assertEqual((q.passed, q.reason), (False, "insufficient_distinct_providers:1<2"))

    def test_too_few_configured_providers_calls_no_judge(self):
        q = convene([ProviderLiar(), FixedJudge("c", "yes", provider="openai")], "c", SEARCH, "p",
                    QuorumPolicy(required_yes=2, min_distinct_providers=2))
        self.assertEqual((q.passed, q.reason, q.ballots), (False, "insufficient_distinct_providers:1<2", ()))

    def test_honest_judges_still_pass(self):
        loc = FixedJudge("local", "yes", provider="ollama", maker="ollama", local_weights=True)
        q = convene([loc, FixedJudge("c", "yes", provider="anthropic", maker="anthropic")], "c", SEARCH, "p",
                    QuorumPolicy.high_assurance(required_yes=2))
        self.assertTrue(q.passed, q.reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
