"""Offline TEST DOUBLES only. They are not real judges.

``HeuristicJudge`` is the original prototype's keyword heuristic. It is kept
only so the demo and tests run without network access. Unlike a real judge it
does not consult the constitution meaningfully, so never use it in
deployment. ``kernel.CompactKernel`` refuses test doubles unless
``allow_test_doubles=True``.
"""

from __future__ import annotations

from .action import Action
from .judges.base import Ballot, Judge


class HeuristicJudge(Judge):
    is_test_double = True

    def __init__(self, judge_id: str, strictness: float = 0.5, provider: str = "test-double"):
        self.judge_id = judge_id
        self.provider = provider
        self.strictness = strictness

    def score(self, constitution_text: str, action: Action, proposal: str) -> Ballot:
        text = (proposal + " " + action.tool).lower()
        flags, why = 0, []
        if action.amount_usd > 250:
            flags += 2; why.append("large outbound value")
        if action.irreversible and action.amount_usd > 20:
            flags += 1; why.append("irreversible value transfer")
        if action.data_class in {"medical", "classified"}:
            flags += 2; why.append("sensitive data class")
        if any(w in text for w in ("ignore previous", "jailbreak", "do anything now")):
            flags += 5; why.append("injection language")
        if action.tool in {"wire_transfer", "sign_contract", "delete_account"}:
            flags += 1; why.append("high-impact tool")
        ok = flags + self.strictness < 2.4
        conf = max(0.55, min(0.97, 0.9 - 0.08 * flags))
        return Ballot(self.judge_id, self.provider, "yes" if ok else "no", conf,
                      "; ".join(why) or "no material conflict (heuristic test double)")


class FixedJudge(Judge):
    """Always returns the given vote. Useful for quorum tests."""

    is_test_double = True

    def __init__(self, judge_id: str, vote: str, provider: str = "test-double"):
        self.judge_id, self.vote, self.provider = judge_id, vote, provider

    def score(self, constitution_text: str, action: Action, proposal: str) -> Ballot:
        return Ballot(self.judge_id, self.provider, self.vote, 0.9, "fixed")  # type: ignore[arg-type]


class RaisingJudge(Judge):
    is_test_double = True

    def __init__(self, judge_id: str = "raiser", provider: str = "test-double"):
        self.judge_id, self.provider = judge_id, provider

    def score(self, constitution_text: str, action: Action, proposal: str) -> Ballot:
        raise RuntimeError("simulated judge outage")
