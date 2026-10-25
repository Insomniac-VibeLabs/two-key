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
        body = entry.body
        if entry.kind == "constitution_loaded":
            sep, policy = body.get("judge_agent_separation"), body.get("quorum_policy")
            try:
                ids = identities_digest(sep) if isinstance(sep, Mapping) else None
            except (KeyError, EncodingError):
                ids = None
            try:
                pol = policy_digest(policy) if isinstance(policy, Mapping) else None
            except EncodingError:
                pol = None
            if ids is None or sep.get("identities_digest") != ids:
                problems.append(f"seq {entry.seq}: constitution_loaded identities_digest does not match its identities")
            if pol is None or body.get("policy_digest") != pol:
                problems.append(f"seq {entry.seq}: constitution_loaded policy_digest does not match its quorum_policy")
            current = (ids, pol)
        elif entry.kind == "decision":
            if current is None:
                problems.append(f"seq {entry.seq}: decision before any constitution_loaded")
                continue
            if body.get("identities_digest") != current[0]:
                problems.append(f"seq {entry.seq}: decision identities_digest does not match constitution_loaded")
            if body.get("policy_digest") != current[1]:
                problems.append(f"seq {entry.seq}: decision policy_digest does not match constitution_loaded")
    return problems


def witness_pins(ledger) -> list[dict]:
    """The ``witness_pinned`` and ``witness_rotated`` entries, oldest first, with key fingerprints.

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
        elif entry.kind == "witness_rotated":
            pins.append({"seq": entry.seq, "kind": entry.kind, "reason": body.get("reason"),
                         "old_fingerprint": witness_key_fingerprint(body["old_witness_public_key"]),
                         "fingerprint": witness_key_fingerprint(body["new_witness_public_key"])})
    return pins


def check_history_digests(ledger, constitution) -> list[str]:
    """Rebuild every judge history summary from the ledger and check each decision's ``history_digest`` (0.8.0).

    ``constitution`` is the verified ``Constitution`` the decisions ran under; a decision made under another
    constitution is reported as not checked, never as matching. For each decision with a digest, the summary is
    rebuilt from the entries before ``history_basis.ledger_size``, with the judge history settings and agent ids of
    the last ``constitution_loaded`` before it that carries the decision's ``policy_digest``, the decision's subject
    and agent, and the basis's time and calls in flight. Returns a list of problems; empty when every digest
    matches. ``two-key audit --check-history`` runs it.
    """
    from .compiler import compile_both
    from .derive import blocked_from_rules
    from .history import HistoryIndex, digest
    compiled = compile_both(constitution.prose, constitution.hard_rules, constitution.tool_specs,
                            specs_enforced=True, fields=constitution.fields)
    blocked = blocked_from_rules(compiled.rules)
    problems: list[str] = []
    loaded: dict[str, Mapping[str, Any]] = {}       # policy_digest -> the last constitution_loaded with it
    indexes: dict[str, HistoryIndex] = {}
    entries = ledger.entries
    for entry in entries:
        body = entry.body
        if entry.kind == "constitution_loaded" and isinstance(body.get("policy_digest"), str):
            loaded[body["policy_digest"]] = body
            continue
        if entry.kind != "decision" or not body.get("history_digest"):
            continue
        start = loaded.get(body.get("policy_digest"))
        basis = body.get("history_basis")
        problem = _history_basis_problem(start, basis, entry.seq, constitution.digest)
        policy = None if problem is not None else _loaded_history_policy(start)
        if policy is None:
            problems.append(f"seq {entry.seq}: {problem or 'constitution_loaded judge_history settings do not load'}")
            continue
        ids = tuple(start.get("history_agent_ids") or ())
        key = canonical_hash({"policy": policy.to_record(), "ids": list(ids)})
        index = indexes.get(key)
        if index is None or index.seen > basis["ledger_size"]:
            index = indexes[key] = HistoryIndex(policy, compiled.tool_specs, blocked, ids)
        index.sync(entries[:basis["ledger_size"]])
        if digest(_rebuilt_summary(index, body, basis, compiled.tool_specs, "scanner" in start)) \
                != body["history_digest"]:
            problems.append(f"seq {entry.seq}: history_digest does not match the summary rebuilt from the ledger")
    return problems


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
