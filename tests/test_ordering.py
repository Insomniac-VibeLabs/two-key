"""Configurable Path A / Path B ordering."""
import unittest

from compact_kernel.quorum import QuorumPolicy
from compact_kernel.testing import FixedJudge
from helpers import KernelFixture

RULES = [{"allow_only_tools": ["search"]}]


class CountingJudge(FixedJudge):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.calls = 0

    def score(self, *a):
        self.calls += 1
        return super().score(*a)


class Ordering(unittest.TestCase):
    def run_case(self, short_circuit):
        j = CountingJudge("a", "yes")
        with KernelFixture(RULES, [j], quorum_policy=QuorumPolicy(required_yes=1),
                           short_circuit_path_b=short_circuit) as k:
            d = k.authorize({"tool": "wire_transfer", "data_class": "public", "irreversible": False}, "wire it")
            kinds = [e.kind for e in k.ledger.entries]
        return d, j.calls, kinds

    def test_default_short_circuits_after_path_a_deny(self):
        d, calls, kinds = self.run_case(True)
        self.assertFalse(d.allowed)
        self.assertEqual(calls, 0)
        self.assertIsNone(d.quorum_passed)
        self.assertIn("quorum_skipped", kinds)

    def test_run_both_option(self):
        d, calls, kinds = self.run_case(False)
        self.assertFalse(d.allowed)
        self.assertEqual(calls, 1)
        self.assertTrue(d.quorum_passed)
        self.assertIn("quorum_result", kinds)
        self.assertTrue(d.reason.startswith("path_a_denied"))

    def test_path_b_still_runs_when_path_a_allows(self):
        j = CountingJudge("a", "no")
        with KernelFixture(RULES, [j], quorum_policy=QuorumPolicy(required_yes=1)) as k:
            d = k.authorize({"tool": "search", "data_class": "public", "irreversible": False}, "search")
        self.assertEqual(j.calls, 1)
        self.assertFalse(d.allowed)
        self.assertTrue(d.reason.startswith("path_b_denied"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
