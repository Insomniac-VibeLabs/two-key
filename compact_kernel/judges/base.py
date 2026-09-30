"""Path B judge interface (engineering; the protocol follows spec 5.4).

A judge receives the principal's natural-language constitution, the
normalized action record, and the proposal text. It returns a structured
ballot. Implementations must never raise into the quorum: any failure is
reported as an ``abstain`` ballot with ``error`` set, and abstentions never
count toward "yes" (fail closed).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Literal

from ..action import Action

Vote = Literal["yes", "no", "abstain"]


@dataclass(frozen=True)
class Ballot:
    judge_id: str
    provider: str
    vote: Vote
    confidence: float | None
    rationale: str
    error: str | None = None

    @property
    def consistent(self) -> bool:
        return self.vote == "yes"

    @property
    def responded(self) -> bool:
        """True if the judge returned a valid yes/no ballot."""
        return self.vote in ("yes", "no")


class Judge(abc.ABC):
    """Abstract Path B judge."""

    judge_id: str
    provider: str  # e.g. "openai", "xai", "anthropic", "google", "ollama", "local", "test-double"

    @abc.abstractmethod
    def score(self, constitution_text: str, action: Action, proposal: str) -> Ballot:
        ...

    def abstain(self, error: str) -> Ballot:
        return Ballot(self.judge_id, self.provider, "abstain", None, "", error=error)
