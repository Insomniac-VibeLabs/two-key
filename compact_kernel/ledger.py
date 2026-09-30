"""
Compact Kernel: personal ledger
===============================
An append-only JSONL hash chain owned by the principal (spec 5.6), plus:

- a Merkle tree (RFC 6962 style) over entry digests, with inclusion proofs;
- a signed chain head: after every append, the principal's Ed25519 key
  signs {size, head digest, merkle root}. Rewriting the whole chain, which
  the original prototype could not detect, now fails verification because
  the attacker cannot produce a head signature under the principal's key.
  Truncation and unsigned extra entries are detected too;
- an anchoring hook (anchoring.py). It is a stub; nothing is published.

The ledger file and head file are created with mode 0600. The ledger is
*not encrypted*; see DESIGN_OPTIONS.md.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import keys, merkle
from .anchoring import Anchor
from .canonical import canonical_bytes, sha256_hex

GENESIS = "0" * 64
HEAD_FORMAT = "compact-kernel-ledger-head/1"


class LedgerError(RuntimeError):
    pass


@dataclass(frozen=True)
class Entry:
    seq: int
    ts: float
    kind: str
    body: dict
    prev: str
    digest: str


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    reason: str
    size: int


def _entry_digest(seq: int, ts: float, kind: str, body: dict, prev: str) -> str:
    return sha256_hex(canonical_bytes({"seq": seq, "ts": ts, "kind": kind, "body": body, "prev": prev}))


def _write_private(path: Path, data: str, append: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "a" if append else "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


class PersonalLedger:
    def __init__(self, path: Path, signing_key: Ed25519PrivateKey | None = None):
        self.path = Path(path)
        self.head_path = self.path.with_name(self.path.name + ".head.json")
        self.signing_key = signing_key
        self.entries: list[Entry] = []
        self._index: dict[str, int] = {}
        if self.path.exists():
            self._load()

    # -- storage -------------------------------------------------------------
    def _load(self) -> None:
        for n, line in enumerate(self.path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                e = Entry(**json.loads(line))
            except (TypeError, ValueError) as ex:
                raise LedgerError(f"malformed ledger line {n + 1}") from ex
            self.entries.append(e)
            self._index[e.digest] = e.seq

    def append(self, kind: str, body: dict) -> Entry:
        prev = self.tip()
        seq = len(self.entries)
        ts = time.time()
        digest = _entry_digest(seq, ts, kind, body, prev)  # raises on non-canonical body
        entry = Entry(seq, ts, kind, body, prev, digest)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _write_private(self.path, json.dumps(asdict(entry), sort_keys=True) + "\n", append=True)
        self.entries.append(entry)
        self._index[digest] = seq
        if self.signing_key is not None:
            self._write_head()
        return entry

    # -- chain -------------------------------------------------------------------
    def tip(self) -> str:
        return self.entries[-1].digest if self.entries else GENESIS

    def root(self) -> str:
        """Chain head digest (the 'ledger root' bound into capability tokens)."""
        return self.tip()

    def index_of(self, digest: str) -> int | None:
        return self._index.get(digest)

    def kinds_after(self, seq: int) -> list[str]:
        return [e.kind for e in self.entries[seq + 1:]]

    def verify_chain(self) -> bool:
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e.seq != i or e.prev != prev or _entry_digest(e.seq, e.ts, e.kind, e.body, e.prev) != e.digest:
                return False
            prev = e.digest
        return True

    # -- merkle ------------------------------------------------------------------
    def _leaves(self, size: int | None = None) -> list[bytes]:
        es = self.entries if size is None else self.entries[:size]
        return [bytes.fromhex(e.digest) for e in es]

    def merkle_root(self, size: int | None = None) -> str:
        return merkle.root(self._leaves(size)).hex()

    def inclusion_proof(self, seq: int) -> dict:
        leaves = self._leaves()
        return {"seq": seq, "size": len(leaves), "leaf": self.entries[seq].digest,
                "proof": [p.hex() for p in merkle.inclusion_proof(leaves, seq)],
                "merkle_root": merkle.root(leaves).hex()}

    @staticmethod
    def verify_inclusion_proof(p: dict) -> bool:
        return merkle.verify_inclusion(bytes.fromhex(p["leaf"]), p["seq"], p["size"],
                                       [bytes.fromhex(x) for x in p["proof"]], bytes.fromhex(p["merkle_root"]))

    # -- signed head -------------------------------------------------------------
    def signed_head(self) -> dict:
        if self.signing_key is None:
            raise LedgerError("no signing key configured")
        body = {"format": HEAD_FORMAT, "size": len(self.entries), "head": self.tip(),
                "merkle_root": self.merkle_root(), "signed_at": time.time(),
                "public_key": keys.b64e(keys.public_key_raw(self.signing_key))}
        return {"head": body, "sig": keys.sign(self.signing_key, canonical_bytes(body))}

    def _write_head(self) -> None:
        tmp = self.head_path.with_name(self.head_path.name + ".tmp")
        _write_private(tmp, json.dumps(self.signed_head(), sort_keys=True) + "\n", append=False)
        os.replace(tmp, self.head_path)

    def verify(self, trusted_key: Ed25519PublicKey) -> VerifyReport:
        """Full verification: chain, signed head under the trusted key, size, and Merkle root."""
        n = len(self.entries)
        if not self.verify_chain():
            return VerifyReport(False, "hash_chain_broken", n)
        if not self.head_path.exists():
            return VerifyReport(n == 0, "no_signed_head" if n else "empty", n)
        try:
            sh = json.loads(self.head_path.read_text(encoding="utf-8"))
            body, sig = sh["head"], sh["sig"]
        except (ValueError, KeyError, TypeError):
            return VerifyReport(False, "malformed_head", n)
        if body.get("format") != HEAD_FORMAT:
            return VerifyReport(False, "bad_head_format", n)
        if keys.b64d(body.get("public_key", "")) != keys.public_key_raw(trusted_key):
            return VerifyReport(False, "head_signed_by_untrusted_key", n)
        if not keys.verify(trusted_key, canonical_bytes(body), sig):
            return VerifyReport(False, "head_signature_invalid", n)
        if body["size"] != n:
            return VerifyReport(False, f"size_mismatch:head={body['size']},file={n}", n)
        if body["head"] != self.tip():
            return VerifyReport(False, "head_digest_mismatch", n)
        if body["merkle_root"] != self.merkle_root():
            return VerifyReport(False, "merkle_root_mismatch", n)
        return VerifyReport(True, "ok", n)

    # -- anchoring (stub) --------------------------------------------------------
    def anchor(self, anchor: Anchor) -> dict:
        receipt = anchor.publish(self.signed_head())
        self.append("anchored", {"receipt": receipt})
        return receipt
