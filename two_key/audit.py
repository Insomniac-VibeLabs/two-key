# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Recompute the digests a decision entry carries and check them against ``constitution_loaded``.

Each ``constitution_loaded`` entry holds the resolved judge and agent identities
(``judge_agent_separation``) and the full quorum policy (``quorum_policy``), with
their digests. Each later ``decision`` entry carries only ``identities_digest`` and
``policy_digest``. ``check_decision_digests`` recomputes both from the latest
``constitution_loaded`` before each decision and reports any mismatch::

    from two_key.audit import check_decision_digests
    problems = check_decision_digests(ledger)   # [] when every digest matches

The recipe by hand: ``identities_digest`` is ``canonical_hash({"agents": sep["agents"],
"judges": sep["judges"]})`` and ``policy_digest`` is ``canonical_hash(quorum_policy)``,
where ``canonical_hash`` is SHA-256 of sorted-key, compact, ASCII JSON (two_key.canonical).

``witness_pins`` lists the ledger's witness pin entries (``witness_pinned`` and ``witness_rotated``); the last
one names the witness key pinned now. ``Ledger.verify()`` returns it with the out-of-ledger pin and the key
that signed the head (``Ledger.witness_report``).
"""

from __future__ import annotations

from typing import Any, Mapping

from .canonical import EncodingError, canonical_hash


def identities_digest(separation: Mapping[str, Any]) -> str:
    """The digest of the resolved identities in a ``judge_agent_separation`` record."""
    return canonical_hash({"agents": separation["agents"], "judges": separation["judges"]})


def policy_digest(policy: Mapping[str, Any]) -> str:
    """The digest of a ``quorum_policy`` record (``QuorumPolicy.to_record()``)."""
    return canonical_hash(policy)


def check_decision_digests(ledger) -> list[str]:
    """Return a list of problems; empty when every decision's digests match its constitution_loaded."""
    problems: list[str] = []
    current: tuple[str | None, str | None] | None = None
    for entry in ledger.entries:
        if entry.kind == "constitution_loaded":
            current = _loaded_digests(entry.body)
            if current[0] is None or entry.body["judge_agent_separation"].get("identities_digest") != current[0]:
                problems.append(f"seq {entry.seq}: constitution_loaded identities_digest does not match its identities")
            if current[1] is None or entry.body.get("policy_digest") != current[1]:
                problems.append(f"seq {entry.seq}: constitution_loaded policy_digest does not match its quorum_policy")
        elif entry.kind == "decision":
            problems.extend(f"seq {entry.seq}: {p}" for p in _decision_digest_problems(entry.body, current))
    return problems


def _loaded_digests(body: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """The identities and policy digests recomputed from a constitution_loaded entry; None where it cannot be."""
    sep, policy = body.get("judge_agent_separation"), body.get("quorum_policy")
    try:
        ids = identities_digest(sep) if isinstance(sep, Mapping) else None
    except (KeyError, EncodingError):
        ids = None
    try:
        pol = policy_digest(policy) if isinstance(policy, Mapping) else None
    except EncodingError:
        pol = None
    return ids, pol


def _decision_digest_problems(body: Mapping[str, Any], current) -> list[str]:
    """How a decision's digests differ from the constitution_loaded before it."""
    if current is None:
        return ["decision before any constitution_loaded"]
    problems = []
    if body.get("identities_digest") != current[0]:
        problems.append("decision identities_digest does not match constitution_loaded")
    if body.get("policy_digest") != current[1]:
        problems.append("decision policy_digest does not match constitution_loaded")
    return problems


def witness_pins(ledger) -> list[dict]:
    """The ``witness_pinned``, ``witness_rotated`` and ``keys_upgraded`` entries, oldest first, with key
    fingerprints.

    Read from the entries as loaded. ``Ledger`` checks them when it opens: one ``witness_pinned``, and each
    rotation starts from the pinned key and carries the principal, old witness, and new witness signatures.
    """
    from .ledger import witness_key_fingerprint
    pins: list[dict] = []
    for entry in ledger.entries:
        body = entry.body
        if entry.kind == "witness_pinned":
            pin = {"seq": entry.seq, "kind": entry.kind, "source": body.get("source"),
                   "fingerprint": witness_key_fingerprint(body["witness_public_key"])}
            if "head_size" in body:
                pin["head_size"] = body["head_size"]
            pins.append(pin)
        elif entry.kind in ("witness_rotated", "keys_upgraded"):
            pins.append({"seq": entry.seq, "kind": entry.kind,
                         "reason": body.get("reason") if entry.kind == "witness_rotated" else "key upgrade",
                         "old_fingerprint": witness_key_fingerprint(body["old_witness_public_key"]),
                         "fingerprint": witness_key_fingerprint(body["new_witness_public_key"])})
    return pins


def check_history_digests(ledger, constitution) -> list[str]:
    """Rebuild every judge history summary from the ledger and check each decision's ``history_digest`` (0.8.0).

    ``constitution`` is the verified ``Constitution`` the decisions ran under; a decision made under another
    constitution is reported as not checked, never as matching. For each decision with a digest, the summary is
    rebuilt from the entries before ``history_basis.ledger_size``, with the decision's subject and agent, the basis's
    time and calls in flight, and the judge history settings and agent ids of a ``constitution_loaded`` before it
    that carries the decision's ``policy_digest``. A ledger several processes share (two proxies, each for its own
    agent) has one such entry per process, and a decision does not say which process made it, so each distinct
    one is tried, newest first; the digest is confirmed when one rebuilds it. Returns a list of problems; empty
    when every digest matches. ``two-key audit --check-history`` runs it.
    """
    from .compiler import compile_both
    from .derive import blocked_from_rules
    compiled = compile_both(constitution.prose, constitution.hard_rules, constitution.tool_specs,
                            specs_enforced=True, fields=constitution.fields)
    rebuild = _HistoryRebuild(ledger.entries, compiled.tool_specs, blocked_from_rules(compiled.rules))
    problems: list[str] = []
    # policy_digest -> each distinct constitution_loaded with it, by the settings a rebuild reads
    loaded: dict[str, dict[str, Mapping[str, Any]]] = {}
    for entry in rebuild.entries:
        body = entry.body
        if entry.kind == "constitution_loaded" and isinstance(body.get("policy_digest"), str):
            starts = loaded.setdefault(body["policy_digest"], {})
            key = _start_key(body)
            starts.pop(key, None)                   # re-inserted last: the newest is tried first
            starts[key] = body
        elif entry.kind == "decision" and body.get("history_digest"):
            problem = rebuild.check_any(entry, loaded.get(body.get("policy_digest")) or {}, constitution.digest)
            if problem is not None:
                problems.append(f"seq {entry.seq}: {problem}")
    return problems


class _HistoryRebuild:
    """Rebuilds judge history summaries for ``check_history_digests``, one index per settings and agent ids."""

    def __init__(self, entries, specs: Mapping[str, Any], blocked) -> None:
        self.entries, self.specs, self.blocked = entries, specs, blocked
        self.indexes: dict[str, Any] = {}

    def check_any(self, entry, starts: Mapping[str, Mapping[str, Any]], constitution_digest: str) -> str | None:
        """None when the settings of any of ``starts`` (newest first) rebuild the decision's digest; otherwise the
        problem the newest one found."""
        first = None
        for start in reversed(list(starts.values())):
            problem = self.check(entry, start, constitution_digest)
            if problem is None:
                return None
            first = first or problem
        return first or self.check(entry, None, constitution_digest)

    def check(self, entry, start, constitution_digest: str) -> str | None:
        """Why one decision's ``history_digest`` was not confirmed, or None when the rebuilt summary matches."""
        from .history import HistoryIndex, digest
        body, basis = entry.body, entry.body.get("history_basis")
        problem = _history_basis_problem(start, basis, entry.seq, constitution_digest)
        if problem is not None:
            return problem
        policy = _loaded_history_policy(start)
        if policy is None:
            return "constitution_loaded judge_history settings do not load"
        ids = tuple(start.get("history_agent_ids") or ())
        key = canonical_hash({"policy": policy.to_record(), "ids": list(ids)})
        index = self.indexes.get(key)
        if index is None or index.seen > basis["ledger_size"]:
            index = self.indexes[key] = HistoryIndex(policy, self.specs, self.blocked, ids)
        index.sync(self.entries[:basis["ledger_size"]])
        if digest(_rebuilt_summary(index, body, basis, self.specs, "scanner" in start)) != body["history_digest"]:
            return "history_digest does not match the summary rebuilt from the ledger"
        return None


def _start_key(start: Mapping[str, Any]) -> str:
    """What a history rebuild reads from a constitution_loaded entry, as one key."""
    return canonical_hash({"digest": start.get("digest"), "quorum_policy": start.get("quorum_policy"),
                           "history_agent_ids": start.get("history_agent_ids"), "scanned": "scanner" in start})


def _history_basis_problem(start, basis, seq: int, constitution_digest: str) -> str | None:
    """Why a decision's history digest cannot be rebuilt, or None when it can."""
    if start is None or start.get("digest") != constitution_digest:
        return "not checked: decided under another constitution"
    if not isinstance(basis, Mapping) or not isinstance(basis.get("ledger_size"), int) \
            or not isinstance(basis.get("now"), int) or not 0 <= basis["ledger_size"] <= seq:
        return "history_digest without a usable history_basis"
    return None


def _loaded_history_policy(start: Mapping[str, Any]):
    """The judge history settings a constitution_loaded entry recorded, or None when they do not load."""
    from .history import HistoryConfigError, JudgeHistoryPolicy
    try:
        return JudgeHistoryPolicy.from_value((start.get("quorum_policy") or {}).get("judge_history") or {})
    except (HistoryConfigError, TypeError):
        return None


def _rebuilt_summary(index, body: Mapping[str, Any], basis: Mapping[str, Any], specs: Mapping[str, Any],
                     scanned: bool) -> dict:
    """The summary the judges were sent for one decision, rebuilt from its subject, agent, and basis."""
    subject = body.get("subject") if isinstance(body.get("subject"), Mapping) else {}
    tool = subject.get("tool")
    spec = specs.get(tool) if isinstance(tool, str) else None
    return index.summary(float(basis["now"]), tool=tool if spec is not None else None,
                         parties=subject.get("counterparties") or (),
                         amount_mapped=bool(spec and spec.get("amount")), agent=body.get("agent"),
                         in_flight=basis.get("in_flight") or 0, scanned=scanned)
