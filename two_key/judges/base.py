"""Path B judge interface (engineering; the protocol follows spec 5.4).

A judge receives the principal's natural-language constitution, the
normalized action record, and the proposal text. It returns a structured
ballot. Implementations must never raise into the quorum: any failure is
reported as an ``abstain`` ballot with ``error`` set, and abstentions never
count toward "yes" (fail closed).

Quorum protocol specifics (PRIOR_ART.md §4 (iii), selected by Stephan Busch on
2026-09-30, CONCEPTION_NOTES.md Entry 2 "C"):
* ``vendor`` and ``local_weights`` describe the judge so that the judge set
  can be checked for vendor heterogeneity (quorum.check_judge_set);
* ballots are bound to H(action record) and H(constitution). The convenor
  passes a ``binding`` mapping to ``score_bound``. A judge that reports hashes
  (echo) is checked against it; the convenor stamps the hashes on every ballot.
  See quorum.py.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Literal, Mapping

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
    # §4 (iii) binding: H(action record), H(constitution) and the two compilation hashes.
    action_hash: str | None = None
    constitution_hash: str | None = None
    nl_hash: str | None = None
    bytecode_hash: str | None = None
    binding: str | None = None   # "echo" (reported by the judge) | "stamp" (added by the convenor) | None

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
    local_weights: bool = False      # True if the model runs from a local weight file under the principal's control
    weights_sha256: str | None = None  # optional identifier of that weight file (recorded, not verified)

    @property
    def vendor(self) -> str:
        """Model vendor used for heterogeneity checks. Defaults to ``provider``."""
        return getattr(self, "_vendor", None) or self.provider

    @vendor.setter
    def vendor(self, value: str) -> None:
        self._vendor = value

    @abc.abstractmethod
    def score(self, constitution_text: str, action: Action, proposal: str) -> Ballot:
        ...

    def score_bound(self, constitution_text: str, action: Action, proposal: str,
                    binding: Mapping[str, str] | None) -> Ballot:
        """Score with the ballot binding available. The default ignores it (the convenor stamps it)."""
        return self.score(constitution_text, action, proposal)

    def describe(self) -> dict:
        d = {"id": self.judge_id, "provider": self.provider, "vendor": self.vendor,
             "local_weights": bool(self.local_weights)}
        if self.weights_sha256:
            d["weights_sha256"] = self.weights_sha256
        return d

    def abstain(self, error: str) -> Ballot:
        return Ballot(self.judge_id, self.provider, "abstain", None, "", error=error)
