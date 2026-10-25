# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The judge history summary (0.8.0, #1): what Path B judges are told about recent decisions.

Before the judges are asked, ``TwoKey`` builds a short summary of recent decisions from its own ledger: for the
call's signed tool and allow-listed counterparty, the last decisions, the days since the last one that was allowed
and run, and the allowed totals over 7, 30 and 90 days; for all tools, counts over the last hour and day; and the
agent's recent bursts of denied calls (*attempt episodes*). Judges get it in a ``<decision_history>`` prompt section,
and its digest is bound to the round and ledgered with the decision (``history_digest``).

**Attacker-controlled text never reaches a judge.** The agent chooses tool names, counterparties, argument values,
proposal and decline text, and none of it is copied here. Every string in a summary is one of: a tool id that has
a signed spec; a counterparty that is an exact signed allow entry, or the signed ``@domain`` entry an address
matched (never the address itself, whose local part is agent text), and never one on ``deny_counterparties``; a
reason code from a fixed list (``rule_denied:<id>`` keeps the signed rule id); an agent id the operator configured,
or ``unnamed``; a scan verdict from a fixed set; a time Two-Key formatted; or a number.

The index (:class:`HistoryIndex`) is built once from the ledger's entries when ``TwoKey`` starts and reads the
entries added since it last looked, this process's and other processes', before each summary. It is standard
library only, and keeps per-tool records for at most ``window_days`` plus the newest few per tool, so it is bounded
by the window, not by the ledger.

Each decision since 0.8.0 carries ``at`` (UTC, RFC 3339 to the second) and ``subject`` (the filtered tool,
counterparties and amount), so the index never reads agent text. A decision written before 0.8.0 has neither: it
is paired with the ``action_normalized`` entry in its own run of entries (one authorization's entries are written
in one hold of the ledger lock), shows as ``"age": "before_upgrade"``, and counts in no window.
"""

from __future__ import annotations

import calendar
import math
import re
import time
from collections import deque
from dataclasses import dataclass, field, fields
from typing import Any, Iterable, Mapping

from .canonical import canonical_hash

FORMAT = "two-key-judge-history-v1"
WINDOWS = (7, 30, 90)
ON_FAILURE = ("deny", "judge_without_history")
# An approved call whose token has not been redeemed is shown as approved_not_run for at most this long: the
# longest a token can live (capability.MAX_TTL_SECONDS).
APPROVED_NOT_RUN_SECONDS = 300
# Undated (pre-0.8.0) or older decisions kept per tool beyond the window, for last_decisions.
KEEP_NEWEST = 50
HOUR, DAY = 3600.0, 86400.0

# The library's reason codes: the text before the first ':' of a decision reason. Anything else is "other".
REASON_CODES = frozenset({
    "agent_declined", "malformed_proposal", "malformed_action", "invalid_call", "action_too_large",
    "args_too_large", "proposal_too_large", "derive_failed", "amount_mismatch", "counterparty_mismatch",
    "irreversible_mismatch", "counterparty_not_allowed", "agent_credential_unreadable", "ledger_failed",
    "internal_error", "no_issuer_key", "rule_denied", "no_pass", "vm_fault", "resource_limit", "insufficient_yes",
    "insufficient_responses", "no_judges", "duplicate_judge_id", "judge_set_not_heterogeneous",
    "responding_not_heterogeneous", "insufficient_distinct_providers", "local_judge_required",
    "cloud_judge_session_required", "cloud_judge_reused_agent_session", "too_few_judges_configured",
    "file_unreadable", "file_too_large", "too_many_files", "call_files_too_large", "history_changed",
    "invalid_agent_metadata", "agent_metadata_too_large", "ledger_body_too_large", "scan_mismatch",
})
MALFORMED = frozenset({"malformed_action", "malformed_proposal", "invalid_call"})
SCAN_VERDICTS = ("clean", "flagged", "unavailable", "encrypted")
_RULE_ID = re.compile(r"[A-Za-z0-9_.:/-]{1,64}")
UNNAMED = "unnamed"


class HistoryConfigError(ValueError):
    """The ``quorum.judge_history`` settings are not valid."""


@dataclass(frozen=True)
class JudgeHistoryPolicy:
    """``quorum.judge_history`` in judges.yaml. On by default (maintainer's decision, 2026-10-14)."""
    enabled: bool = True
    window_days: int = 90                 # 7, 30 or 90: the longest window shown
    max_items: int = 10                   # last decisions (and episodes) shown, 1..50
    on_failure: str = "deny"              # deny | judge_without_history (D1)
    burst_denies: int = 5                 # an attempt episode: at least this many denies ...
    burst_minutes: int = 10               # ... within this many minutes (D4)

    def __post_init__(self):
        if not isinstance(self.enabled, bool):
            raise HistoryConfigError("judge_history.enabled must be a boolean")
        if self.window_days not in WINDOWS or isinstance(self.window_days, bool):
            raise HistoryConfigError("judge_history.window_days must be 7, 30 or 90")
        for name, lo, hi in (("max_items", 1, KEEP_NEWEST), ("burst_denies", 2, 1000), ("burst_minutes", 1, 1440)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
                raise HistoryConfigError(f"judge_history.{name} must be an integer from {lo} to {hi}")
        if self.on_failure not in ON_FAILURE:
            raise HistoryConfigError("judge_history.on_failure must be deny or judge_without_history")

    @classmethod
    def from_value(cls, value: Any) -> "JudgeHistoryPolicy":
        if isinstance(value, JudgeHistoryPolicy):
            return value
        if not isinstance(value, Mapping):
            raise HistoryConfigError("judge_history must be a mapping")
        unknown = set(value) - KEYS
        if unknown:
            raise HistoryConfigError(f"unknown judge_history keys {sorted(map(str, unknown))}")
        return cls(**dict(value))

    def to_record(self) -> dict:
        return {"enabled": self.enabled, "window_days": self.window_days, "max_items": self.max_items,
                "on_failure": self.on_failure, "burst_denies": self.burst_denies,
                "burst_minutes": self.burst_minutes}

    def less_than_default(self) -> list[str]:
        """The settings that show judges less than the defaults do, for the start-up warning (D2)."""
        default = JudgeHistoryPolicy()
        out = []
        if not self.enabled:
            out.append("enabled: false (judges see no decision history)")
        else:
            if self.window_days < default.window_days:
                out.append(f"window_days: {self.window_days} (judges see less history)")
            if self.max_items < default.max_items:
                out.append(f"max_items: {self.max_items} (judges see fewer past decisions)")
            if self.on_failure == "judge_without_history":
                out.append("on_failure: judge_without_history (a call can be judged without its history)")
        return out


KEYS = frozenset(f.name for f in fields(JudgeHistoryPolicy))


# -- text Two-Key writes -------------------------------------------------------------------------------------


def format_time(seconds: float) -> str:
    """UTC, RFC 3339, to the second: ``2026-10-25T01:03:15Z``."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def parse_time(text: Any) -> float | None:
    """A time :func:`format_time` wrote, or None."""
    if not isinstance(text, str) or len(text) != 20:
        return None
    try:
        return float(calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ")))
    except ValueError:
        return None


def reason_code(reason: Any) -> str:
    """The code of a decision reason, from the fixed list; its detail is dropped (``derive_failed:<detail>``,
    ``malformed_action:<msg>``, ``internal_error:<type>``). ``rule_denied:<id>`` keeps the signed rule id."""
    if not isinstance(reason, str):
        return "other"
    code, _, rest = reason.partition(":")
    if code not in REASON_CODES:
        return "other"
    if code == "rule_denied" and _RULE_ID.fullmatch(rest):
        return f"rule_denied:{rest}"
    return code


def shown_parties(spec: Mapping[str, Any] | None, parties: Iterable[str], blocked: Iterable[str]) -> list[str]:
    """The counterparties a judge may see for this call: an exact signed allow entry, or the signed ``@domain``
    entry an address matched. A party on ``deny_counterparties`` or on no allow list is left out."""
    from .derive import is_domain_entry, party_allowed
    if not isinstance(spec, Mapping):
        return []
    allow: set[str] = set()
    for entry in spec.get("counterparties") or []:
        if isinstance(entry, Mapping):
            allow.update(a for a in entry.get("allow") or [] if isinstance(a, str))
    blocked = set(blocked)
    out = set()
    for party in parties:
        if not isinstance(party, str) or party in blocked or not party_allowed(party, allow):
            continue
        if party in allow and not is_domain_entry(party):
            out.add(party)
        else:
            out.add("@" + party.rpartition("@")[2])
    return sorted(out)


def subject_record(tool: str | None, parties: Iterable[str] = (), amount: float | None = None) -> dict:
    """The ``subject`` of a decision entry: the signed tool id or None, the shown counterparties, the amount."""
    return {"tool": tool, "counterparties": sorted(parties), "amount_usd": amount}


def digest(summary: Mapping[str, Any]) -> str:
    return "sha256:" + canonical_hash(summary)


# -- the index -----------------------------------------------------------------------------------------------


@dataclass
class _Record:
    seq: int
    at: float | None
    allowed: bool
    code: str
    tool: str | None
    parties: frozenset
    amount: float | None
    agent: str
    abstains: int = 0
    jti: str | None = None
    verdict: str | None = None
    ran: bool = False
    started: bool = False
    aborted: bool = False

    @property
    def run(self) -> bool:
        """Approved and actually run (D6): redeemed, or started and not aborted (fail toward showing more)."""
        return self.allowed and (self.ran or (self.started and not self.aborted))


@dataclass
class Episode:
    """A run of at least ``burst_denies`` denied decisions for one agent within ``burst_minutes`` (D4)."""
    agent: str
    started: float
    ended: float
    denies: int = 0
    reasons: dict = field(default_factory=dict)
    tools: set = field(default_factory=set)
    seq: int = -1               # the decision that made it an episode

    def record(self) -> dict:
        return {"started": format_time(self.started), "ended": format_time(self.ended), "denies": self.denies,
                "reasons": dict(sorted(self.reasons.items())), "tools": sorted(self.tools)}

    def ledger_body(self) -> dict:
        return {"agent_id": self.agent, "started": format_time(self.started), "denies": self.denies,
                "reasons": dict(sorted(self.reasons.items()))}


class _AgentRuns:
    def __init__(self):
        self.recent: deque = deque()          # (at, code, tool) of the denies inside the burst window
        self.open: Episode | None = None
        self.episodes: list[Episode] = []


class HistoryIndex:
    """Decisions by signed tool, the last day of all decisions, and attempt episodes by agent.

    ``tool_specs`` and ``blocked`` are the running constitution's; they filter what a pre-0.8.0 decision shows.
    ``agent_ids`` are the agent ids the operator configured; any other id is kept and shown as ``unnamed``.
    """

    def __init__(self, policy: JudgeHistoryPolicy, tool_specs: Mapping[str, Any], blocked: Iterable[str] = (),
                 agent_ids: Iterable[str] = ()):
        self.policy = policy
        self.specs = tool_specs
        self.blocked = frozenset(blocked)
        self.agent_ids = frozenset(a for a in agent_ids if isinstance(a, str) and a)
        self.seen = 0
        self.by_tool: dict[str, list[_Record]] = {}
        self.recent: deque = deque()          # dated records of the last day, for all_tools
        self.by_jti: dict[str, _Record] = {}
        self.agents: dict[str, _AgentRuns] = {}
        self.history_starts: float | None = None
        self.latest: float | None = None
        self.pending: dict[str, Any] = {}
        self._added = 0

    # -- reading the ledger ------------------------------------------------------------------------------

    def agent_key(self, agent: Any) -> str:
        aid = agent.get("id") if isinstance(agent, Mapping) else None
        return aid if isinstance(aid, str) and aid in self.agent_ids else UNNAMED

    def sync(self, entries: list) -> list[Episode]:
        """Read the entries added since the last call. Returns the episodes those entries started."""
        found = []
        for entry in entries[self.seen:]:
            episode = self._take(entry)
            if episode is not None:
                found.append(episode)
        self.seen = len(entries)
        return found

    def _take(self, entry) -> Episode | None:
        kind, body = entry.kind, entry.body
        if not isinstance(body, Mapping):
            return None
        if kind == "proposal":
            self.pending = {}
        elif kind in ("action_normalized", "path_b", "capability_issued", "scan"):
            self.pending[kind] = body
        elif kind in ("redemption", "redemption_started", "redemption_aborted"):
            rec = self.by_jti.get(body.get("jti"))
            if rec is not None:
                if kind == "redemption":
                    rec.ran = True
                elif kind == "redemption_started":
                    rec.started = True
                else:
                    rec.aborted = True
        elif kind == "decision":
            pending, self.pending = self.pending, {}
            return self._add(self._record(entry.seq, body, pending))
        return None

    def _record(self, seq: int, body: Mapping, pending: Mapping) -> _Record:
        subject = body.get("subject")
        if isinstance(subject, Mapping):
            tool = subject.get("tool") if isinstance(subject.get("tool"), str) else None
            parties = frozenset(p for p in subject.get("counterparties") or () if isinstance(p, str))
            amount = _number(subject.get("amount_usd"))
        else:
            tool, parties, amount = self._legacy_subject(pending)
        if tool is not None and tool not in self.specs:
            tool = None          # a tool the running constitution no longer signs counts in all_tools only
        path_b = pending.get("path_b") if isinstance(pending.get("path_b"), Mapping) else {}
        abstains = path_b.get("abstain")
        issued = pending.get("capability_issued") if isinstance(pending.get("capability_issued"), Mapping) else {}
        scan = pending.get("scan") if isinstance(pending.get("scan"), Mapping) else {}
        verdict = scan.get("verdict") if scan.get("verdict") in SCAN_VERDICTS else None
        allowed = body.get("allowed") is True
        rec = _Record(seq=seq, at=parse_time(body.get("at")), allowed=allowed,
                      code="allowed" if allowed else reason_code(body.get("reason")), tool=tool, parties=parties,
                      amount=amount, agent=self.agent_key(body.get("agent")),
                      abstains=abstains if isinstance(abstains, int) and not isinstance(abstains, bool) else 0,
                      jti=issued.get("jti") if allowed and isinstance(issued.get("jti"), str) else None,
                      verdict=verdict)
        return rec

    def _legacy_subject(self, pending: Mapping) -> tuple[str | None, frozenset, float | None]:
        """Before 0.8.0: the tool, counterparties, and amount from the action_normalized entry of the same run,
        filtered by today's spec."""
        normalized = pending.get("action_normalized")
        if not isinstance(normalized, Mapping) or normalized.get("tool") not in self.specs:
            return None, frozenset(), None
        tool = normalized["tool"]
        spec = self.specs[tool]
        form = normalized.get("form")
        if not isinstance(form, Mapping):
            return tool, frozenset(), None
        raw = form.get("counterparties") or []
        parties = frozenset(shown_parties(spec, raw if isinstance(raw, list) else [], self.blocked))
        return tool, parties, _number(form.get("amount_usd")) if spec.get("amount") else None

    def _add(self, rec: _Record) -> Episode | None:
        if rec.at is not None:
            if self.history_starts is None or rec.at < self.history_starts:
                self.history_starts = rec.at
            self.latest = rec.at if self.latest is None else max(self.latest, rec.at)
            self.recent.append(rec)
        if rec.tool is not None:
            self.by_tool.setdefault(rec.tool, []).append(rec)
        if rec.jti:
            self.by_jti[rec.jti] = rec
        self._added += 1
        if self._added % 1000 == 0:
            self.prune(self.latest or 0.0)
        return self._episode(rec)

    def _episode(self, rec: _Record) -> Episode | None:
        """Track runs of denies by agent; return an episode the moment ``rec`` makes one."""
        if rec.allowed or rec.at is None:
            return None
        runs = self.agents.setdefault(rec.agent, _AgentRuns())
        span = self.policy.burst_minutes * 60.0
        ep = runs.open
        if ep is not None and rec.at - ep.ended <= span:
            ep.ended = max(ep.ended, rec.at)
            ep.denies += 1
            ep.reasons[rec.code] = ep.reasons.get(rec.code, 0) + 1
            if rec.tool:
                ep.tools.add(rec.tool)
            return None
        runs.open = None
        runs.recent.append((rec.at, rec.code, rec.tool))
        while runs.recent and rec.at - runs.recent[0][0] > span:
            runs.recent.popleft()
        if len(runs.recent) < self.policy.burst_denies:
            return None
        ep = Episode(rec.agent, started=min(a for a, _, _ in runs.recent), ended=rec.at, seq=rec.seq)
        for _, code, tool in runs.recent:
            ep.denies += 1
            ep.reasons[code] = ep.reasons.get(code, 0) + 1
            if tool:
                ep.tools.add(tool)
        runs.recent.clear()
        runs.open = ep
        runs.episodes.append(ep)
        return ep

    def prune(self, now: float) -> None:
        """Forget what no summary can show: records older than the window beyond the newest few per tool."""
        horizon = now - self.policy.window_days * DAY
        for tool, recs in self.by_tool.items():
            keep_from = max(0, len(recs) - KEEP_NEWEST)
            self.by_tool[tool] = [r for i, r in enumerate(recs)
                                  if i >= keep_from or (r.at is not None and r.at >= horizon)]
        while self.recent and self.recent[0].at < now - DAY:
            self.recent.popleft()
        # A token is redeemed within its lifetime, so an older one gets no more redemption entries.
        self.by_jti = {j: r for j, r in self.by_jti.items()
                       if r.at is not None and r.at >= now - 2 * APPROVED_NOT_RUN_SECONDS}
        for runs in self.agents.values():
            runs.episodes = [e for e in runs.episodes if e.ended >= horizon]

    # -- the summary -------------------------------------------------------------------------------------

    def summary(self, now: float, *, tool: str | None, parties: Iterable[str] = (), amount_mapped: bool = False,
                agent: Any = None, in_flight: int = 0, scanned: bool = False) -> dict:
        """The summary a judge sees for one call. Built from the index only; see the module docstring."""
        parties = frozenset(parties)
        out: dict[str, Any] = {"format": FORMAT, "now": format_time(now),
                               "history_starts": None if self.history_starts is None
                               else format_time(self.history_starts)}
        back = any(r.at is not None and r.at > now for r in self.recent) or (
            tool is not None and any(r.at is not None and r.at > now for r in self.by_tool.get(tool, ())))
        if back:
            out["clock_went_back"] = True
        if tool is not None and tool in self.specs:
            out["this_tool"] = self._this_tool(now, tool, parties, amount_mapped, in_flight, scanned)
        out["all_tools"] = {"1h": self._counts(now, HOUR), "24h": self._counts(now, DAY)}
        out["agent"] = self._agent(now, self.agent_key(agent))
        return out

    def matching(self, tool: str, parties: frozenset) -> list[_Record]:
        """The tool's records for this call: those that share a counterparty with it, or every one when the
        call shows none."""
        recs = self.by_tool.get(tool, [])
        if not parties:
            return list(recs)
        return [r for r in recs if r.parties & parties]

    def _this_tool(self, now: float, tool: str, parties: frozenset, amount_mapped: bool, in_flight: int,
                   scanned: bool) -> dict:
        recs = self.matching(tool, parties)
        last = [_last_item(r, now, amount_mapped) for r in reversed(recs[-self.policy.max_items:])]
        if not parties:
            shown = None
        elif len(parties) == 1:
            shown = next(iter(parties))
        else:
            shown = sorted(parties)
        ran = [r for r in recs if r.run and r.at is not None]
        newest = max((r.at for r in ran), default=None)
        totals = {}
        for days in WINDOWS:
            if days > self.policy.window_days:
                continue
            inside = [r for r in ran if _within(now, r.at, days * DAY)]
            totals[f"{days}d"] = _total(inside, amount_mapped)
        waiting = [r for r in recs if r.allowed and not r.run and r.at is not None
                   and _within(now, r.at, APPROVED_NOT_RUN_SECONDS)]
        out: dict[str, Any] = {
            "tool": tool, "counterparty": shown, "last_decisions": last,
            "days_since_last_allowed": None if newest is None else _round(max(0.0, now - newest) / DAY),
            "allowed_totals": totals,
            "approved_not_run": _total(waiting, amount_mapped),
            "denied_1h": _denied(recs, now, HOUR), "denied_24h": _denied(recs, now, DAY),
            "in_flight": in_flight,
        }
        if scanned:
            out["scan_verdicts_7d"] = _scan_counts(recs, now)
        return out

    def _counts(self, now: float, span: float) -> dict:
        inside = [r for r in self.recent if _within(now, r.at, span)]
        return {"allowed": sum(1 for r in inside if r.allowed), "denied": _denied(inside, now, span),
                "abstains": sum(r.abstains for r in inside),
                "declined": sum(1 for r in inside if r.code == "agent_declined"),
                "malformed": sum(1 for r in inside if r.code in MALFORMED)}

    def _agent(self, now: float, key: str) -> dict:
        runs = self.agents.get(key)
        horizon = self.policy.window_days * DAY
        episodes = [e for e in (runs.episodes if runs else ()) if _within(now, e.ended, horizon)]
        span = 90 * DAY
        return {"agent": key,
                "episodes": [e.record() for e in reversed(episodes[-self.policy.max_items:])],
                "episodes_90d": sum(1 for e in (runs.episodes if runs else ()) if _within(now, e.ended, span))}

    @staticmethod
    def approved_after(entries: list, start: int, tool: str, parties: frozenset) -> bool:
        """Whether an approved decision for this tool and counterparty was written at or after ``start`` (the
        ledger size when the summary was built): the re-check at mint (D7)."""
        for entry in entries[start:]:
            if entry.kind != "decision" or not isinstance(entry.body, Mapping) or entry.body.get("allowed") is not True:
                continue
            subject = entry.body.get("subject")
            if not isinstance(subject, Mapping) or subject.get("tool") != tool:
                continue
            theirs = frozenset(p for p in subject.get("counterparties") or () if isinstance(p, str))
            if not parties or not theirs or theirs & parties:
                return True
        return False


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _round(value: float) -> float:
    return round(value, 2)


def _within(now: float, at: float | None, span: float) -> bool:
    """Inside the window. A time later than now (a clock that went back) counts as inside every window."""
    return at is not None and (at >= now or now - at <= span)


def _last_item(r: _Record, now: float, amount_mapped: bool) -> dict:
    """One entry of ``last_decisions``: its age, outcome, whether it ran or why it was denied, and its amount."""
    item: dict[str, Any] = ({"age": "before_upgrade"} if r.at is None
                            else {"age_hours": _round(max(0.0, now - r.at) / HOUR)})
    item["outcome"] = "allowed" if r.allowed else "denied"
    if r.allowed:
        item["run"] = r.run
    else:
        item["reason"] = r.code
    if amount_mapped and r.amount is not None:
        item["amount_usd"] = r.amount
    return item


def _scan_counts(recs: Iterable[_Record], now: float) -> dict:
    """Each scan verdict's count over the last seven days."""
    counts = {v: 0 for v in SCAN_VERDICTS}
    for r in recs:
        if r.verdict and r.at is not None and _within(now, r.at, 7 * DAY):
            counts[r.verdict] += 1
    return counts


def _total(recs: list[_Record], amount_mapped: bool) -> dict:
    out: dict[str, Any] = {"count": len(recs)}
    if amount_mapped:
        out["amount_usd"] = round(sum(r.amount or 0.0 for r in recs), 2)
    return out


def _denied(recs: Iterable[_Record], now: float, span: float) -> dict:
    out: dict[str, int] = {}
    for r in recs:
        if not r.allowed and _within(now, r.at, span):
            out[r.code] = out.get(r.code, 0) + 1
    return dict(sorted(out.items()))
