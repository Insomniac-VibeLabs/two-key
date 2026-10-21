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
