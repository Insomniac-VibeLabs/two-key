"""
Two-Key: Path B, the multi-model intent quorum
=====================================================
N judges, each connected to whichever AI the principal chooses, vote on
whether a proposal is consistent with the principal's natural-language
constitution. The convenor counts booleans. It never averages prose.

Fixes from the original prototype (see CHANGES.md):
- An exact integer k-of-n threshold (``required_yes``) replaces the
  fractional threshold. With the old 0.67 default, 2-of-3 failed.
- A minimum number of responding judges (``min_responding``, "K").
  Zero judges, or too few valid responses, is a deny.
- A judge that raises, or returns a malformed ballot, is an abstention and
  never counts as "yes".
- ``min_distinct_providers`` counts providers among responding ballots.
  It still defaults to 1, so that check is not a floor by itself.
- The default needs one judge: ``min_makers=1``, ``min_local_judges=0``,
  ``require_local_yes=False``. The owner's rule is at least one judge, and
  that judge must not be the monitored agent. The diversity floors are
  opt-in: ``QuorumPolicy.high_assurance()`` (or ``profile: high_assurance``
  in judges.yaml) needs judges from at least two model makers, at least one
  local judge, and a yes from a local judge (``require_local_yes``). It is
  recommended for destructive, irreversible, financial, or external-send
  tools. A judge's maker is the operator's ``maker:`` label for who made its
  model (default: its ``provider``). It is not verified, and it is never
  compared with the monitored agent (identity.py does that).
  ``require_local_yes`` with no local judge in the set is a configuration
  error at start-up and a deny in ``convene``.
  ``QuorumPolicy.without_diversity_floors`` still works and now builds the
  default. ``require_path_a_first`` is not part of the floor and is not a
  skip.
- Judges run in parallel (one thread per judge) under an overall deadline
  ``timeout_seconds`` (default 45 s). A judge that has not answered by the
  deadline is recorded as an abstention (``error="timeout..."``), so a slow or
  hung provider can never produce a "yes" and cannot stall Two-Key beyond
  the deadline. ``TwoKey`` and the judges.yaml loader refuse
  ``timeout_seconds=None``, so a deployment always has a hard deadline. Per-request
  HTTP timeouts are still set on each LLM judge.

Quorum protocol specifics:
- Maker heterogeneity: ``check_judge_set`` runs when ``TwoKey`` starts, and
  again inside ``convene``. The default floor is one maker and no local
  judge. ``QuorumPolicy.high_assurance`` is >= 2 makers, >= 1 local judge,
  and ``require_local_yes``. ``QuorumPolicy.section4`` is that floor plus
  ``require_path_a_first``, which ``TwoKey.authorize`` still does not read.
  With ``heterogeneity_scope="responding"`` the same floor also applies to the
  judges that actually returned valid ballots.
- Availability floor K (``min_responding``) distinct from the approval
  threshold T (``required_yes``): fewer than K valid ballots is a deny
  *without counting*. The result then has ``counted=False`` and no yes/no
  tally (yes/no are None).
- Ballots are bound to H(action record) and H(constitution), plus the two
  compilation hashes (nl_hash, bytecode_hash). The convenor stamps
  the binding on every ballot. A judge that reports hashes that differ is an
  abstention (``binding_mismatch``). With ``ballot_binding="echo"`` a yes/no
  ballot that the judge itself did not bind is an abstention too. Malformed
  ballots are abstentions, which count as deny.
- Judge inputs: ``judge_inputs="record_only"`` (default) gives judges only the
  normalized action record and the constitution, never the agent's proposal
  text (transcript) or tool outputs. "record_and_proposal" restores the
  earlier behaviour. After a derive deny, ``tool_args`` is omitted unless
  ``tool_args_on_derive_deny`` is set; a ``derive_failed:`` call is then not sent to the judges at all.
- Both paths run once the call is well-formed and within limits. A Path A deny does not skip Path B, except
  for a ``derive_failed:`` call without ``tool_args_on_derive_deny``, which has nothing to judge.
  ``require_path_a_first`` is stored on the policy and copied into
  ``to_record``. ``TwoKey.authorize`` does not read it. There is no
  ``short_circuit_path_b`` setting in this package.
"""

from __future__ import annotations

import inspect
import threading
import time
import unicodedata
from dataclasses import dataclass, fields, replace
from typing import Mapping, Sequence

from .action import Action
from .agent_meta import exception_ledger_error
from .judges.base import Ballot, Judge


class QuorumConfigError(ValueError):
    pass


@dataclass(frozen=True)
class QuorumPolicy:
    required_yes: int | None = None  # k in k-of-n; None = min(2, number of judges), resolved at start-up
    min_responding: int | None = None  # K, the availability floor; defaults to required_yes
    min_distinct_providers: int = 1  # responding providers; 1 means this check is not a floor
    timeout_seconds: float | None = 45.0  # overall deadline; None (no deadline) is refused by TwoKey
    parallel: bool = True
    # One judge is enough by default. QuorumPolicy.high_assurance() opts in to the diversity floors.
    min_makers: int = 1                         # distinct judge model makers (Judge.maker labels)
    min_local_judges: int = 0
    heterogeneity_scope: str = "selection"      # selection | responding
    judge_inputs: str = "record_only"           # record_only | record_and_proposal
    ballot_binding: str = "stamp"               # stamp | echo
    require_path_a_first: bool = False          # stored, not a skip
    require_local_yes: bool = False             # a local judge in the set must itself vote yes
                                                # (a config error if no judge is local)
    # Deprecated, no effect: the same provider with a different model is allowed (identity.py).
    # Still accepted and recorded so older configurations load.
    allow_same_provider_judge: bool = False
    # After a derive deny, do not attach tool arguments to the judge record, and do not ask the judges about a
    # derive_failed call at all (it has nothing to judge). Set true to send those bytes and ask them anyway.
    tool_args_on_derive_deny: bool = False
    # When the content scanner flags a call, the judges get the record without the arguments and the proposal
    # text, so a detected secret is not sent to a judge vendor (scan.py). Set true (a local judge set) to send them.
    tool_args_on_scan_flag: bool = False
    # Deprecated, no effect (2026-10-08): a judge is refused when it uses the monitored agent's credential, or is
    # keyless on a keyless agent's address (identity.compare), so there is nothing left for this flag to lift.
    # Still accepted, recorded and part of the policy digest, with a note on stderr, so older configurations load.
    allow_same_model_distinct_tenant: bool = False


    def __post_init__(self):
        if self.required_yes is not None and (isinstance(self.required_yes, bool)
                                              or not isinstance(self.required_yes, int) or self.required_yes < 1):
            raise QuorumConfigError("required_yes must be an integer >= 1")
        mr = self.effective_min_responding
        if mr is not None and (isinstance(mr, bool) or not isinstance(mr, int) or mr < 1):
            raise QuorumConfigError("min_responding must be an integer >= 1")
        if not isinstance(self.min_distinct_providers, int) or self.min_distinct_providers < 1:
            raise QuorumConfigError("min_distinct_providers must be an integer >= 1")
        t = self.timeout_seconds
        if t is not None and (isinstance(t, bool) or not isinstance(t, (int, float)) or not t > 0):
            raise QuorumConfigError("timeout_seconds must be a positive number or None")
        if not isinstance(self.parallel, bool):
            raise QuorumConfigError("parallel must be a boolean")
        for name in ("min_makers", "min_local_judges"):
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int) or v < (1 if name == "min_makers" else 0):
                raise QuorumConfigError(f"{name} must be an integer >= {1 if name == 'min_makers' else 0}")
        if self.heterogeneity_scope not in ("selection", "responding"):
            raise QuorumConfigError("heterogeneity_scope must be 'selection' or 'responding'")
        if self.judge_inputs not in ("record_only", "record_and_proposal"):
            raise QuorumConfigError("judge_inputs must be 'record_only' or 'record_and_proposal'")
        if self.ballot_binding not in ("stamp", "echo"):
            raise QuorumConfigError("ballot_binding must be 'stamp' or 'echo'")
        if not isinstance(self.require_path_a_first, bool):
            raise QuorumConfigError("require_path_a_first must be a boolean")
        if not isinstance(self.require_local_yes, bool):
            raise QuorumConfigError("require_local_yes must be a boolean")
        if not isinstance(self.tool_args_on_derive_deny, bool):
            raise QuorumConfigError("tool_args_on_derive_deny must be a boolean")
        if not isinstance(self.tool_args_on_scan_flag, bool):
            raise QuorumConfigError("tool_args_on_scan_flag must be a boolean")
        if not isinstance(self.allow_same_model_distinct_tenant, bool):
            raise QuorumConfigError("allow_same_model_distinct_tenant must be a boolean")
        if not isinstance(self.allow_same_provider_judge, bool):
            raise QuorumConfigError("allow_same_provider_judge must be a boolean")

    @classmethod
    def high_assurance(cls, required_yes: int = 2, min_responding: int | None = None, **kw) -> "QuorumPolicy":
        """Opt-in diversity floors: >= 2 makers, >= 1 local judge, and a yes from a local judge.

        Recommended for destructive, irreversible, financial, or external-send tools.
        This was the default in 0.1.12. The default is now one judge.
        """
        base = {"min_makers": 2, "min_local_judges": 1, "require_local_yes": True}
        base.update(kw)
        return cls(required_yes=required_yes, min_responding=min_responding, **base)

    @classmethod
    def without_diversity_floors(cls, required_yes: int = 2, min_responding: int | None = None,
                                 **kw) -> "QuorumPolicy":
        """Compatibility name for the default floors: one maker, no local judge required."""
        base = {"min_makers": 1, "min_local_judges": 0, "require_local_yes": False}
        base.update(kw)
        return cls(required_yes=required_yes, min_responding=min_responding, **base)

    @classmethod
    def section4(cls, required_yes: int = 2, min_responding: int | None = None, **kw) -> "QuorumPolicy":
        """``high_assurance`` floors, plus ``require_path_a_first``.

        ``TwoKey.authorize`` still runs both paths; it does not read that flag.
        K and T remain the principal's choice.
        """
        base = {"min_makers": 2, "min_local_judges": 1, "judge_inputs": "record_only",
                "require_path_a_first": True, "require_local_yes": True}
        base.update(kw)
        return cls(required_yes=required_yes, min_responding=min_responding, **base)

    def to_record(self) -> dict:
        return {"required_yes": self.required_yes, "min_responding": self.effective_min_responding,
                "min_distinct_providers": self.min_distinct_providers, "timeout_seconds": self.timeout_seconds,
                "min_makers": self.min_makers, "min_local_judges": self.min_local_judges,
                "heterogeneity_scope": self.heterogeneity_scope, "judge_inputs": self.judge_inputs,
                "ballot_binding": self.ballot_binding, "require_path_a_first": self.require_path_a_first,
                "require_local_yes": self.require_local_yes,
                "tool_args_on_derive_deny": self.tool_args_on_derive_deny,
                "allow_same_provider_judge": self.allow_same_provider_judge,
                "allow_same_model_distinct_tenant": self.allow_same_model_distinct_tenant,
                # Present only when set, so a policy without it records and digests as before.
                **({"tool_args_on_scan_flag": True} if self.tool_args_on_scan_flag else {})}

    @property
    def is_high_assurance(self) -> bool:
        """The ``high_assurance`` floors: two makers, a local judge, and a local yes."""
        return self.min_makers >= 2 and self.min_local_judges >= 1 and self.require_local_yes

    @property
    def effective_min_responding(self) -> int | None:
        return self.required_yes if self.min_responding is None else self.min_responding

    def resolved(self, n_judges: int) -> "QuorumPolicy":
        """``required_yes=None`` becomes min(2, n_judges) (at least 1). Other fields are unchanged."""
        if self.required_yes is not None:
            return self
        return replace(self, required_yes=max(1, min(2, n_judges)))


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
    binding: dict | None = None  # the round's ballot binding (BINDING_FIELDS), shared by every ballot

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
    """Effective locality (Judge.is_local), not the declared ``local_weights`` flag."""
    is_local = getattr(j, "is_local", None)
    return bool(is_local()) if callable(is_local) else False


def _maker(j) -> str:
    """The maker key for the diversity floor: NFKC, trimmed, and case-folded, so "OpenAI" and
    "openai " are one maker, not two."""
    raw = str(getattr(j, "maker", None) or getattr(j, "provider", None) or "?")
    return unicodedata.normalize("NFKC", raw).strip().casefold() or "?"


def unmeetable_floor(judges: Sequence, policy: QuorumPolicy) -> str | None:
    """The deny reason when the policy needs more judges or providers than are configured, which no round can
    meet; None otherwise. ``TwoKey`` refuses to start on it, and ``convene`` denies without calling a judge (#54)."""
    need = max(policy.required_yes, policy.effective_min_responding or 0)
    if len(judges) < need:
        return f"too_few_judges_configured:{len(judges)}<{need}"
    # A ballot's provider is its judge's (_collect), so the configured providers bound the responding ones.
    providers = {unicodedata.normalize("NFKC", str(getattr(j, "provider", "?"))).strip().casefold() for j in judges}
    if len(providers) < policy.min_distinct_providers:
        return f"insufficient_distinct_providers:{len(providers)}<{policy.min_distinct_providers}"
    return None


def heterogeneity_shortfall(judges: Sequence, policy: QuorumPolicy) -> str | None:
    makers = {_maker(j) for j in judges}
    local = sum(1 for j in judges if _local(j))
    if len(makers) < policy.min_makers:
        return f"insufficient_makers:{len(makers)}<{policy.min_makers}"
    if local < policy.min_local_judges:
        return f"insufficient_local_judges:{local}<{policy.min_local_judges}"
    if policy.require_local_yes and local == 0:
        return "require_local_yes_without_local_judge"
    return None


def lone_judge_warning(judges: Sequence, policy: QuorumPolicy) -> str | None:
    """Text for a start-up warning when one judge's yes approves a call while every other judge is down, times
    out, or abstains: two or more judges, ``required_yes`` 1, and ``min_responding`` 1 (its default then).
    Allowed, and sometimes meant; but the second judge is then no check at all while it is unreachable
    (live run 6x, X03). Not a refusal."""
    n = len(judges)
    if n >= 2 and policy.required_yes == 1 and (policy.effective_min_responding or 0) <= 1:
        return (f"quorum: required_yes 1 with {n} judges and min_responding {policy.effective_min_responding}: one "
                "judge approves a call alone whenever the others are down, time out, or abstain. Set "
                f"min_responding: {n} to require every judge to answer, or required_yes: 2")
    return None


def check_judge_set(judges: Sequence, policy: QuorumPolicy) -> None:
    """Refuse a judge set below the policy's floors (makers, local judges, a local yes). Raises QuorumConfigError."""
    short = heterogeneity_shortfall(judges, policy)
    if short:
        raise QuorumConfigError(f"judge set is not heterogeneous enough: {short}")


BINDING_FIELDS = ("action_hash", "constitution_hash", "nl_hash", "bytecode_hash")


def _bind(b: Ballot, binding: Mapping[str, str] | None, policy: QuorumPolicy) -> Ballot:
    """Check a judge-reported binding and stamp the expected one. A mismatch makes the ballot an abstention."""
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


def _accepted(fn, kw: Mapping) -> dict:
    """The keyword arguments in ``kw`` that ``fn`` takes, read from its signature. Asking the signature, not
    retrying on TypeError, keeps a TypeError raised inside a judge an abstention, never a call without the session.
    A signature that cannot be read gets every keyword: if the judge does not take them, it abstains."""
    try:
        params = list(inspect.signature(fn).parameters.values())
    except (TypeError, ValueError):
        return dict(kw)
    if any(p.kind is p.VAR_KEYWORD for p in params):
        return dict(kw)
    names = {p.name for p in params}
    return {k: v for k, v in kw.items() if k in names}


def _score_one(j: Judge, constitution_text: str, action: Action, proposal: str,
               binding: Mapping[str, str] | None = None, agent_session: str | None = None,
               configured_secrets: frozenset[str] = frozenset()) -> Ballot:
    from .judges.llm import comparing_configured_secrets
    # Set on this thread, including a judge thread. Not a keyword of the judge: a **kwargs judge
    # would otherwise be handed the monitored agent's credential.
    with comparing_configured_secrets(configured_secrets):
        return _score_one_call(j, constitution_text, action, proposal, binding, agent_session)


def _score_one_call(j: Judge, constitution_text: str, action: Action, proposal: str,
                    binding: Mapping[str, str] | None = None, agent_session: str | None = None) -> Ballot:
    try:
        sb = getattr(j, "score_bound", None)
        if sb is not None:
            kw = _accepted(sb, {"agent_session": agent_session})
            b = sb(constitution_text, action, proposal, binding, **kw)
        else:
            b = j.score(constitution_text, action, proposal)
        if not isinstance(b, Ballot) or b.vote not in ("yes", "no", "abstain"):
            b = Ballot(getattr(j, "judge_id", "?"), getattr(j, "provider", "?"), "abstain",
                       None, "", error="judge returned an invalid ballot object")
        elif b.judge_id != getattr(j, "judge_id", None):
            # A ballot naming another judge (for example the local one) is not that judge's vote.
            b = Ballot(getattr(j, "judge_id", "?"), getattr(j, "provider", "?"), "abstain",
                       None, "", error="judge_id_mismatch")
        else:
            # Identity comes from the judge object, never from what the ballot says about itself.
            b = replace(b, judge_id=j.judge_id, provider=getattr(j, "provider", b.provider))
    except Exception as e:  # a failing judge is an abstention, never a yes
        b = Ballot(getattr(j, "judge_id", "?"), getattr(j, "provider", "?"), "abstain",
                   None, "", error=exception_ledger_error(e))
    return b


def _collect(judges: Sequence[Judge], constitution_text: str, action: Action, proposal: str,
             policy: QuorumPolicy, binding: Mapping[str, str] | None = None,
             agent_session: str | None = None,
             configured_secrets: frozenset[str] = frozenset()) -> list[Ballot]:
    if not judges:
        return []
    if not policy.parallel and policy.timeout_seconds is None:
        return [_score_one(j, constitution_text, action, _proposal_for(j, proposal, policy), binding, agent_session,
                           configured_secrets)
                for j in judges]
    # One daemon thread per judge: a hung judge can neither delay the decision past the deadline
    # nor keep the process alive at exit (its HTTP timeout ends the thread eventually).
    results: list[Ballot | None] = [None] * len(judges)
    done = [threading.Event() for _ in judges]

    def run(i: int, j: Judge) -> None:
        results[i] = _score_one(j, constitution_text, action, _proposal_for(j, proposal, policy), binding,
                                agent_session, configured_secrets)
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
    configured_secrets: frozenset[str] | None = None,
) -> QuorumResult:
    """Convene the judges.

    ``binding`` = {action_hash, constitution_hash, nl_hash, bytecode_hash} (Two-Key always passes it).
    """
    policy = (policy or QuorumPolicy()).resolved(len(judges))
    k_floor = policy.effective_min_responding
    judge_action = action
    if tool_args:
        raw = dict(action.raw)
        raw["tool_args"] = dict(tool_args)
        judge_action = replace(action, raw=raw)
    ballots: list[Ballot] = []
    # Ballots are matched to judges by id (local yes, responding heterogeneity). Two judges with
    # one id would let one judge's ballot stand in for the other's, so the judges are not called.
    ids = [getattr(j, "judge_id", None) for j in judges]
    duplicate = len(set(ids)) != len(ids) or any(not isinstance(i, str) or not i for i in ids)
    selection = heterogeneity_shortfall(judges, policy) if judges and not duplicate else None
    # A floor no round can meet: deny before any judge (or its vendor) sees the call.
    unmeetable = unmeetable_floor(judges, policy) if judges and not duplicate else None
    secrets = frozenset(configured_secrets or ())
    # The named agent credential. A match denies before any judge is called, so the key is not
    # handed to a judge function. A placeholder ``agent_session`` does not count as this.
    reused = False
    if secrets and judges and not duplicate and selection is None and unmeetable is None:
        from .judges.llm import presents_configured_secret
        reused = any(presents_configured_secret(j, secrets) for j in judges)
    if judges and not duplicate and selection is None and unmeetable is None and not reused:
        ballots = [_bind(b, binding, policy)
                   for b in _collect(judges, constitution_text, judge_action, proposal, policy, binding,
                                     agent_session, secrets)]
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
    if duplicate:
        return result(False, "duplicate_judge_id", counted=False)
    if selection is not None:
        return result(False, f"judge_set_not_heterogeneous:{selection}", counted=False)
    if unmeetable is not None:
        return result(False, unmeetable, counted=False)
    if reused:
        return result(False, "cloud_judge_reused_agent_session", counted=False)
    if any(getattr(j, "is_cloud", lambda: False)() for j in judges) and not agent_session:
        return result(False, "cloud_judge_session_required")
    if any((b.error or "").startswith("cloud_judge_") for b in ballots):
        return result(False, next(b.error for b in ballots if (b.error or "").startswith("cloud_judge_")))
    # Availability floor K (min_responding): below it, deny WITHOUT counting.
    if len(responding) < k_floor:
        return result(False, f"insufficient_responses:{len(responding)}<{k_floor}", counted=False)
    # Ballots are paired with judges by position (_collect keeps the order), not by the id a ballot reports.
    pairs = list(zip(judges, ballots))
    if policy.heterogeneity_scope == "responding":
        short = heterogeneity_shortfall([j for j, b in pairs if b.responded], policy)
        if short:
            return result(False, f"responding_not_heterogeneous:{short}", counted=False)
    providers = {unicodedata.normalize("NFKC", str(b.provider)).strip().casefold() for b in responding}
    if len(providers) < policy.min_distinct_providers:
        return result(False, f"insufficient_distinct_providers:{len(providers)}<{policy.min_distinct_providers}")
    yes = sum(1 for b in responding if b.vote == "yes")
    if yes < policy.required_yes:
        return result(False, f"insufficient_yes:{yes}<{policy.required_yes}")
    if policy.require_local_yes:
        if not any(b.vote == "yes" and _local(j) for j, b in pairs):
            return result(False, "local_judge_required")
    return result(True, "quorum_pass")
