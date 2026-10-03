"""
Two-Key: Path B, the multi-model intent quorum
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
- Judges run in parallel (one thread per judge) under an overall deadline
  ``timeout_seconds`` (default 45 s). A judge that has not answered by the
  deadline is recorded as an abstention (``error="timeout..."``), so a slow or
  hung provider can never produce a "yes" and cannot stall Two-Key beyond
  the deadline. Per-request HTTP timeouts are still set on each LLM judge.

Quorum protocol specifics (PRIOR_ART.md §4 (iii), selected by the author on
2026-09-30, CONCEPTION_NOTES.md Entry 2 "C"):
- Vendor heterogeneity in judge-set selection: ``min_vendors`` distinct
  vendors and ``min_local_judges`` judges on local weight files
  (check_judge_set; Two-Key refuses to start otherwise). §4's figures are
  >= 2 vendors including >= 1 local weight file (``QuorumPolicy.section4``).
  With ``heterogeneity_scope="responding"`` the same floor also applies to the
  judges that actually returned valid ballots.
- Availability floor K (``min_responding``) distinct from the approval
  threshold T (``required_yes``): fewer than K valid ballots is a deny
  *without counting*. The result then has ``counted=False`` and no yes/no
  tally (yes/no are None).
- Ballots are bound to H(action record) and H(constitution), plus the two
  compilation hashes (nl_hash, bytecode_hash; §4 (ii)). The convenor stamps
  the binding on every ballot. A judge that reports hashes that differ is an
  abstention (``binding_mismatch``). With ``ballot_binding="echo"`` a yes/no
  ballot that the judge itself did not bind is an abstention too. Malformed
  ballots are abstentions, which count as deny.
- Judge inputs: ``judge_inputs="record_only"`` (default) gives judges only the
  normalized action record and the constitution, never the agent's proposal
  text (transcript) or tool outputs. "record_and_proposal" restores the
  earlier behaviour.
- Both paths always answer. ``short_circuit_path_b`` is ignored.
  ``require_path_a_first`` is recorded and does not skip Path B.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, fields, replace
from typing import Mapping, Sequence

from .action import Action
from .judges.base import Ballot, Judge


class QuorumConfigError(ValueError):
    pass


@dataclass(frozen=True)
class QuorumPolicy:
    required_yes: int = 2            # k in k-of-n
    min_responding: int | None = None  # K in spec 5.4; defaults to required_yes
    min_distinct_providers: int = 1  # 1 = not enforced (open design question)
    timeout_seconds: float | None = 45.0  # overall deadline for all judges; None = no deadline
    parallel: bool = True
    # PRIOR_ART.md §4 (iii). The defaults are permissive, so earlier configurations keep working;
    # QuorumPolicy.section4() gives §4's figures. Which should be the default is open (DESIGN_OPTIONS §7).
    min_vendors: int = 1
    min_local_judges: int = 0
    heterogeneity_scope: str = "selection"      # selection | responding
    judge_inputs: str = "record_only"           # record_only | record_and_proposal
    ballot_binding: str = "stamp"               # stamp | echo
    require_path_a_first: bool = False
    require_local_yes: bool = False         # a local judge in the set must itself vote yes


    def __post_init__(self):
        if isinstance(self.required_yes, bool) or not isinstance(self.required_yes, int) or self.required_yes < 1:
            raise QuorumConfigError("required_yes must be an integer >= 1")
        mr = self.effective_min_responding
        if not isinstance(mr, int) or mr < 1:
            raise QuorumConfigError("min_responding must be an integer >= 1")
        if not isinstance(self.min_distinct_providers, int) or self.min_distinct_providers < 1:
            raise QuorumConfigError("min_distinct_providers must be an integer >= 1")
        t = self.timeout_seconds
        if t is not None and (isinstance(t, bool) or not isinstance(t, (int, float)) or not t > 0):
            raise QuorumConfigError("timeout_seconds must be a positive number or None")
        if not isinstance(self.parallel, bool):
            raise QuorumConfigError("parallel must be a boolean")
        for name in ("min_vendors", "min_local_judges"):
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int) or v < (1 if name == "min_vendors" else 0):
                raise QuorumConfigError(f"{name} must be an integer >= {1 if name == 'min_vendors' else 0}")
        if self.heterogeneity_scope not in ("selection", "responding"):
            raise QuorumConfigError("heterogeneity_scope must be 'selection' or 'responding'")
        if self.judge_inputs not in ("record_only", "record_and_proposal"):
            raise QuorumConfigError("judge_inputs must be 'record_only' or 'record_and_proposal'")
        if self.ballot_binding not in ("stamp", "echo"):
            raise QuorumConfigError("ballot_binding must be 'stamp' or 'echo'")
        if not isinstance(self.require_path_a_first, bool):
            raise QuorumConfigError("require_path_a_first must be a boolean")

    @classmethod
    def section4(cls, required_yes: int = 2, min_responding: int | None = None, **kw) -> "QuorumPolicy":
        """Reference profile with PRIOR_ART.md §4 (iii)'s figures: >= 2 vendors, >= 1 local weight file,
        record-only judge inputs, Path A first. K and T remain the principal's choice."""
        base = {"min_vendors": 2, "min_local_judges": 1, "judge_inputs": "record_only",
                "require_path_a_first": True, "require_local_yes": True}
        base.update(kw)
        return cls(required_yes=required_yes, min_responding=min_responding, **base)

    def to_record(self) -> dict:
        return {"required_yes": self.required_yes, "min_responding": self.effective_min_responding,
                "min_distinct_providers": self.min_distinct_providers, "timeout_seconds": self.timeout_seconds,
                "min_vendors": self.min_vendors, "min_local_judges": self.min_local_judges,
                "heterogeneity_scope": self.heterogeneity_scope, "judge_inputs": self.judge_inputs,
                "ballot_binding": self.ballot_binding, "require_path_a_first": self.require_path_a_first}

    @property
    def effective_min_responding(self) -> int:
        return self.required_yes if self.min_responding is None else self.min_responding


@dataclass(frozen=True)
class QuorumResult:
    passed: bool
    reason: str
    yes: int | None          # None when the availability floor failed (not counted)
    no: int | None
    abstain: int
    required_yes: int
    ballots: tuple[Ballot, ...]
    counted: bool = True
    valid: int = 0           # valid ballots (the availability measure compared with K)
    min_responding: int = 0
    binding: dict | None = None  # the round's ballot binding (§4 (iii)), shared by every ballot

    def to_record(self) -> dict:
        """Ledger record. The binding is written once. A ballot's hash fields appear only where they
        differ from it (a judge that reported a different binding); ``ballot.binding`` says how each
        ballot was bound."""
        return {
            "passed": self.passed, "reason": self.reason, "counted": self.counted, "yes": self.yes,
            "no": self.no, "abstain": self.abstain, "valid": self.valid, "required_yes": self.required_yes,
            "min_responding": self.min_responding, "binding": self.binding,
            "ballots": [_ballot_record(b, self.binding) for b in self.ballots],
        }


_BALLOT_FIELDS = tuple(f.name for f in fields(Ballot))
_BINDING_SET = frozenset(("action_hash", "constitution_hash", "nl_hash", "bytecode_hash"))


def _ballot_record(b: Ballot, binding: Mapping[str, str] | None = None) -> dict:
    """Like dataclasses.asdict(b) (all fields are scalars), minus hash fields equal to the round binding."""
    out = {}
    for f in _BALLOT_FIELDS:
        v = getattr(b, f)
        if f in _BINDING_SET and (v is None or (binding is not None and binding.get(f) == v)):
            continue
        out[f] = v
    return out


def _local(j) -> bool:
    return bool(getattr(j, "local_weights", False))


def _vendor(j) -> str:
    return str(getattr(j, "vendor", None) or getattr(j, "provider", "?"))


def heterogeneity_shortfall(judges: Sequence, policy: QuorumPolicy) -> str | None:
    vendors = {_vendor(j) for j in judges}
    local = sum(1 for j in judges if _local(j))
    if len(vendors) < policy.min_vendors:
        return f"insufficient_vendors:{len(vendors)}<{policy.min_vendors}"
    if local < policy.min_local_judges:
        return f"insufficient_local_judges:{local}<{policy.min_local_judges}"
    return None


def check_judge_set(judges: Sequence, policy: QuorumPolicy) -> None:
    """Judge-set selection check (§4 (iii)). Raises QuorumConfigError."""
    short = heterogeneity_shortfall(judges, policy)
    if short:
        raise QuorumConfigError(f"judge set is not heterogeneous enough: {short}")


BINDING_FIELDS = ("action_hash", "constitution_hash", "nl_hash", "bytecode_hash")


def _bind(b: Ballot, binding: Mapping[str, str] | None, policy: QuorumPolicy) -> Ballot:
    """Check a judge-reported binding and stamp the expected one (§4 (iii))."""
    if binding is None:
        return b
    ah, ch, nh, bh = (binding.get(k) for k in BINDING_FIELDS)
    reported = (b.action_hash, b.constitution_hash, b.nl_hash, b.bytecode_hash)
    if any(r is not None and r != e for r, e in zip(reported, (ah, ch, nh, bh))):
        # Keep what the judge reported, for the audit record; the vote becomes an abstention.
        return replace(b, vote="abstain", binding="mismatch",
                       error="binding_mismatch: ballot bound to a different action record or constitution")
    echoed = b.binding == "echo" and reported[0] == ah and reported[1] == ch
    vote, error = b.vote, b.error
    if policy.ballot_binding == "echo" and b.responded and not echoed:
        vote, error = "abstain", "unbound_ballot: judge did not echo the ballot binding"
    return Ballot(b.judge_id, b.provider, vote, b.confidence, b.rationale, error, ah, ch, nh, bh,
                  "echo" if echoed else "stamp")


def _proposal_for(j: Judge, proposal: str, policy: QuorumPolicy) -> str:
    """The user annotates a judge with receives_proposal to send it the proposal."""
    if policy.judge_inputs == "record_and_proposal" or getattr(j, "receives_proposal", False):
        return proposal
    return ""


def _score_one(j: Judge, constitution_text: str, action: Action, proposal: str,
               binding: Mapping[str, str] | None = None, agent_session: str | None = None) -> Ballot:
    try:
        sb = getattr(j, "score_bound", None)
        if sb is not None:
            try:
                b = sb(constitution_text, action, proposal, binding, agent_session=agent_session)
            except TypeError:
                b = sb(constitution_text, action, proposal, binding)
        else:
            b = j.score(constitution_text, action, proposal)
        if not isinstance(b, Ballot) or b.vote not in ("yes", "no", "abstain"):
            b = Ballot(getattr(j, "judge_id", "?"), getattr(j, "provider", "?"), "abstain",
                       None, "", error="judge returned an invalid ballot object")
    except Exception as e:  # a failing judge is an abstention, never a yes
        b = Ballot(getattr(j, "judge_id", "?"), getattr(j, "provider", "?"), "abstain",
                   None, "", error=f"{type(e).__name__}: {e}")
    return b


def _collect(judges: Sequence[Judge], constitution_text: str, action: Action, proposal: str,
             policy: QuorumPolicy, binding: Mapping[str, str] | None = None,
             agent_session: str | None = None) -> list[Ballot]:
    if not judges:
        return []
    if not policy.parallel and policy.timeout_seconds is None:
        return [_score_one(j, constitution_text, action, _proposal_for(j, proposal, policy), binding, agent_session)
                for j in judges]
    # One daemon thread per judge: a hung judge can neither delay the decision past the deadline
    # nor keep the process alive at exit (its HTTP timeout ends the thread eventually).
    results: list[Ballot | None] = [None] * len(judges)
    done = [threading.Event() for _ in judges]

    def run(i: int, j: Judge) -> None:
        results[i] = _score_one(j, constitution_text, action, _proposal_for(j, proposal, policy), binding, agent_session)
        done[i].set()

    deadline = None if policy.timeout_seconds is None else time.monotonic() + policy.timeout_seconds
    if policy.parallel:
        for i, j in enumerate(judges):
            threading.Thread(target=run, args=(i, j), name=f"twokey-judge-{i}", daemon=True).start()
    else:  # sequential, but still under the overall deadline
        def run_all() -> None:
            for i, j in enumerate(judges):
                run(i, j)
        threading.Thread(target=run_all, name="twokey-judge-seq", daemon=True).start()
    ballots = []
    for i, j in enumerate(judges):
        remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
        if done[i].wait(remaining) and results[i] is not None:
            ballots.append(results[i])
        else:
            ballots.append(Ballot(getattr(j, "judge_id", "?"), getattr(j, "provider", "?"), "abstain",
                                  None, "", error=f"timeout: no ballot within {policy.timeout_seconds}s"))
    return ballots


def convene(
    judges: Sequence[Judge],
    constitution_text: str,
    action: Action,
    proposal: str,
    policy: QuorumPolicy | None = None,
    binding: Mapping[str, str] | None = None,
    tool_args: Mapping | None = None,
    agent_session: str | None = None,
) -> QuorumResult:
    """Convene the judges.

    ``binding`` = {action_hash, constitution_hash, nl_hash, bytecode_hash} (Two-Key always passes it).
    """
    policy = policy or QuorumPolicy()
    k_floor = policy.effective_min_responding
    judge_action = action
    if tool_args:
        raw = dict(action.raw)
        raw["tool_args"] = dict(tool_args)
        judge_action = replace(action, raw=raw)
    ballots: list[Ballot] = []
    selection = heterogeneity_shortfall(judges, policy) if judges else None
    if judges and selection is None:
        ballots = [_bind(b, binding, policy)
                   for b in _collect(judges, constitution_text, judge_action, proposal, policy, binding, agent_session)]
    responding = [b for b in ballots if b.responded]
    abstain = len(ballots) - len(responding)

    def result(passed: bool, reason: str, counted: bool = True) -> QuorumResult:
        yes = sum(1 for b in ballots if b.vote == "yes") if counted else None
        no = sum(1 for b in ballots if b.vote == "no") if counted else None
        return QuorumResult(passed, reason, yes, no, abstain, policy.required_yes, tuple(ballots),
                            counted, len(responding), k_floor,
                            None if binding is None else {k: binding.get(k) for k in BINDING_FIELDS})

    if not judges:
        return result(False, "no_judges", counted=False)
    if selection is not None:
        return result(False, f"judge_set_not_heterogeneous:{selection}", counted=False)
    if len(judges) < policy.required_yes:
        return result(False, f"too_few_judges_configured:{len(judges)}<{policy.required_yes}", counted=False)
    if any(getattr(j, "is_cloud", lambda: False)() for j in judges) and not agent_session:
        return result(False, "cloud_judge_session_required")
    if any((b.error or "").startswith("cloud_judge_") for b in ballots):
        return result(False, next(b.error for b in ballots if (b.error or "").startswith("cloud_judge_")))
    # Availability floor K: below it, deny WITHOUT counting (§4 (iii)).
    if len(responding) < k_floor:
        return result(False, f"insufficient_responses:{len(responding)}<{k_floor}", counted=False)
    if policy.heterogeneity_scope == "responding":
        by_id = {getattr(j, "judge_id", None): j for j in judges}
        short = heterogeneity_shortfall([by_id.get(b.judge_id) for b in responding if b.judge_id in by_id],
                                        policy)
        if short:
            return result(False, f"responding_not_heterogeneous:{short}", counted=False)
    providers = {b.provider for b in responding}
    if len(providers) < policy.min_distinct_providers:
        return result(False, f"insufficient_distinct_providers:{len(providers)}<{policy.min_distinct_providers}")
    yes = sum(1 for b in responding if b.vote == "yes")
    if yes < policy.required_yes:
        return result(False, f"insufficient_yes:{yes}<{policy.required_yes}")
    if policy.require_local_yes:
        local_ids = {getattr(j, "judge_id", None) for j in judges if _local(j)}
        if local_ids and not any(b.vote == "yes" and b.judge_id in local_ids for b in responding):
            return result(False, "local_judge_required")
    return result(True, "quorum_pass")
