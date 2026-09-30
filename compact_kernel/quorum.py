"""
Compact Kernel: Path B, the multi-model intent quorum
=====================================================
N judges, each connected to whichever AI the principal chooses, vote on
whether a proposal is consistent with the principal's natural-language
constitution (spec 5.4). The convenor counts booleans. It never averages prose.

Fixes from the original prototype (see CHANGES.md):
- An exact integer k-of-n threshold (``required_yes``) replaces the
  fractional threshold. With the old 0.67 default, 2-of-3 failed.
- A minimum number of responding judges (``min_responding``, spec 5.4 "K").
  Zero judges, or too few valid responses, is a deny.
- A judge that raises, or returns a malformed ballot, is an abstention and
  never counts as "yes".
- ``min_distinct_providers`` is an optional, configurable independence
  check. It defaults to 1, meaning not enforced. How independence should be
  ensured is an open design question; see DESIGN_OPTIONS.md section 2.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Sequence

from .action import Action
from .judges.base import Ballot, Judge


class QuorumConfigError(ValueError):
    pass


@dataclass(frozen=True)
class QuorumPolicy:
    required_yes: int = 2            # k in k-of-n
    min_responding: int | None = None  # K in spec 5.4; defaults to required_yes
    min_distinct_providers: int = 1  # 1 = not enforced (open design question)

    def __post_init__(self):
        if isinstance(self.required_yes, bool) or not isinstance(self.required_yes, int) or self.required_yes < 1:
            raise QuorumConfigError("required_yes must be an integer >= 1")
        mr = self.effective_min_responding
        if not isinstance(mr, int) or mr < 1:
            raise QuorumConfigError("min_responding must be an integer >= 1")
        if not isinstance(self.min_distinct_providers, int) or self.min_distinct_providers < 1:
            raise QuorumConfigError("min_distinct_providers must be an integer >= 1")

    @property
    def effective_min_responding(self) -> int:
        return self.required_yes if self.min_responding is None else self.min_responding


@dataclass(frozen=True)
class QuorumResult:
    passed: bool
    reason: str
    yes: int
    no: int
    abstain: int
    required_yes: int
    ballots: tuple[Ballot, ...]

    def to_record(self) -> dict:
        return {
            "passed": self.passed, "reason": self.reason, "yes": self.yes, "no": self.no,
            "abstain": self.abstain, "required_yes": self.required_yes,
            "ballots": [asdict(b) for b in self.ballots],
        }


def convene(
    judges: Sequence[Judge],
    constitution_text: str,
    action: Action,
    proposal: str,
    policy: QuorumPolicy | None = None,
) -> QuorumResult:
    policy = policy or QuorumPolicy()
    ballots: list[Ballot] = []
    for j in judges:
        try:
            b = j.score(constitution_text, action, proposal)
            if not isinstance(b, Ballot) or b.vote not in ("yes", "no", "abstain"):
                b = Ballot(getattr(j, "judge_id", "?"), getattr(j, "provider", "?"), "abstain",
                           None, "", error="judge returned an invalid ballot object")
        except Exception as e:  # a failing judge is an abstention, never a yes
            b = Ballot(getattr(j, "judge_id", "?"), getattr(j, "provider", "?"), "abstain",
                       None, "", error=f"{type(e).__name__}: {e}")
        ballots.append(b)

    yes = sum(1 for b in ballots if b.vote == "yes")
    no = sum(1 for b in ballots if b.vote == "no")
    abstain = len(ballots) - yes - no
    responding = [b for b in ballots if b.responded]
    providers = {b.provider for b in responding}

    def result(passed: bool, reason: str) -> QuorumResult:
        return QuorumResult(passed, reason, yes, no, abstain, policy.required_yes, tuple(ballots))

    if not judges:
        return result(False, "no_judges")
    if len(judges) < policy.required_yes:
        return result(False, f"too_few_judges_configured:{len(judges)}<{policy.required_yes}")
    if len(responding) < policy.effective_min_responding:
        return result(False, f"insufficient_responses:{len(responding)}<{policy.effective_min_responding}")
    if len(providers) < policy.min_distinct_providers:
        return result(False, f"insufficient_distinct_providers:{len(providers)}<{policy.min_distinct_providers}")
    if yes < policy.required_yes:
        return result(False, f"insufficient_yes:{yes}<{policy.required_yes}")
    return result(True, "quorum_pass")
