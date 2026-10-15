"""Path B judge interface.

A judge receives the principal's natural-language constitution, the
normalized action record, and the proposal text. It returns a structured
ballot. Implementations must never raise into the quorum: any failure is
reported as an ``abstain`` ballot with ``error`` set, and abstentions never
count toward "yes" (fail closed).

Quorum protocol specifics (the section-4 profile):
* ``maker`` and ``local_weights`` describe the judge so that the judge set
  can be checked for maker heterogeneity (quorum.check_judge_set). ``maker``
  is who made the judge's model, as the operator labels it (default:
  ``provider``). It is not verified, and the judge-is-not-the-agent check
  never compares it. Whether a judge is local is ``is_local()``: the declared flag AND a loopback or
  private endpoint host. The flag alone never makes a judge local;
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
    # Ballot binding: H(action record), H(constitution) and the two compilation hashes.
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
    def maker(self) -> str:
        """Who made the judge's model, for the ``min_makers`` floor. Operator label, not verified.
        Defaults to ``provider``."""
        return getattr(self, "_maker", None) or self.provider

    @maker.setter
    def maker(self, value: str) -> None:
        self._maker = value

    @abc.abstractmethod
    def score(self, constitution_text: str, action: Action, proposal: str) -> Ballot:
        ...

    def score_bound(self, constitution_text: str, action: Action, proposal: str,
                    binding: Mapping[str, str] | None) -> Ballot:
        """Score with the ballot binding available. The default ignores it (the convenor stamps it)."""
        return self.score(constitution_text, action, proposal)

    def is_local(self) -> bool:
        """Whether this judge counts toward ``min_local_judges`` and ``require_local_yes``.

        A self-declared flag never relaxes a check: a network judge must also have a
        loopback or private host (LLMJudge.is_local). Only in-process test doubles
        are taken at their ``local_weights`` word; any other judge without an
        endpoint is not local.
        """
        return bool(getattr(self, "is_test_double", False)) and bool(self.local_weights)

    def describe(self) -> dict:
        d = {"id": self.judge_id, "provider": self.provider, "maker": self.maker,
             "local_weights": bool(self.local_weights), "local": bool(self.is_local())}
        if self.weights_sha256:
            d["weights_sha256"] = self.weights_sha256
        return d

    def abstain(self, error: str) -> Ballot:
        return Ballot(self.judge_id, self.provider, "abstain", None, "", error=error)
