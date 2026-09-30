"""
Compact Kernel — Multi-Model Intent Quorum
==========================================
Path B of dual-path enforcement.

A single LLM can be prompt-injected, sycophantic, or vendor-aligned.
This module requires N independent judges to agree that a proposed
action is consistent with the principal's stated constitution.

In production the judges are different model vendors / local weights.
This prototype uses deterministic stub judges so the method can be
demonstrated and unit-tested without network calls. Swap Judge.score()
for real model calls without changing the quorum protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from policy_vm import Action


@dataclass
class JudgeBallot:
    judge_id: str
    consistent: bool
    confidence: float
    rationale: str


@dataclass
class QuorumResult:
    passed: bool
    yes: int
    no: int
    threshold: float
    ballots: list[JudgeBallot]


class Judge(Protocol):
    judge_id: str

    def score(self, constitution_text: str, action: Action, proposal: str) -> JudgeBallot:
        ...


class HeuristicJudge:
    """
    Stand-in for an independent model.

    Each judge has a slightly different temperament so the quorum is
    meaningful even in the offline demo. A production judge would send
    constitution + proposal to a distinct model endpoint and parse a
    structured yes/no + confidence.
    """

    def __init__(self, judge_id: str, strictness: float = 0.5):
        self.judge_id = judge_id
        self.strictness = strictness  # 0 liberal, 1 harsh

    def score(self, constitution_text: str, action: Action, proposal: str) -> JudgeBallot:
        proposal_l = (proposal + " " + action.tool).lower()
        red_flags = 0
        rationale_bits = []

        if action.amount_usd > 250:
            red_flags += 2
            rationale_bits.append("large outbound value")
        if action.irreversible and action.amount_usd > 20:
            red_flags += 1
            rationale_bits.append("irreversible value transfer")
        if action.data_class in {"medical", "classified"}:
            red_flags += 2
            rationale_bits.append("sensitive data class")
        # Score injection phrases on the proposal only. The constitution may
        # name the attacks it forbids; that must not poison the judges.
        if any(w in proposal_l for w in ("ignore previous", "jailbreak", "do anything now")):
            red_flags += 5
            rationale_bits.append("injection language")
        if action.tool in {"wire_transfer", "sign_contract", "delete_account"}:
            red_flags += 1
            rationale_bits.append("high-impact tool")

        score = red_flags + self.strictness
        consistent = score < 2.4
        confidence = max(0.55, min(0.97, 0.9 - 0.08 * red_flags))
        rationale = "; ".join(rationale_bits) or "no material conflict with constitution"
        return JudgeBallot(self.judge_id, consistent, confidence, rationale)


def convene(
    judges: list[HeuristicJudge],
    constitution_text: str,
    action: Action,
    proposal: str,
    threshold: float = 0.67,
) -> QuorumResult:
    ballots = [j.score(constitution_text, action, proposal) for j in judges]
    yes = sum(1 for b in ballots if b.consistent)
    no = len(ballots) - yes
    passed = (yes / max(len(ballots), 1)) >= threshold
    return QuorumResult(passed, yes, no, threshold, ballots)
