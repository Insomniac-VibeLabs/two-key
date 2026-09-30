"""
Compact Kernel: personal ledger
===============================
An append-only JSONL hash chain owned by the principal (spec 5.6), plus:

- a Merkle tree (RFC 6962 style) over entry digests, with inclusion proofs.
  The root is maintained incrementally (merkle.MerkleFrontier);
- a signed chain head: the principal's key signs {size, head digest, merkle
  root}. Rewriting the whole chain, which the original prototype could not
  detect, fails verification because the attacker cannot produce a head
  signature under the principal's key. Truncation and unsigned extra
  entries are detected too. The head can be signed with legacy Ed25519,
  ECDSA P-384, or a hybrid ML-DSA-65 suite (compact_kernel.crypto);
- configurable head-signing cadence: ``auto_sign_every=N`` signs after every
  N appends (1 = every append, the default for direct use; 0 = only on
  ``checkpoint()``). The kernel and gateway call ``checkpoint()`` at decision
  boundaries, so one signature covers all entries of a decision;
- configurable digest algorithm: SHA-256 (legacy default) or SHA-384 (the
  default when the signing key is a post-quantum hybrid suite);
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

from . import merkle
from .anchoring import Anchor
from .canonical import canonical_bytes, digest_hex
from .crypto.provider import DIGEST_SIZE, CryptoProvider, default_provider
from .crypto.signatures import LEGACY_SUITE, as_private_keyset, as_public_keyset

GENESIS = "0" * 64
HEAD_FORMAT = "compact-kernel-ledger-head/1"


def genesis(alg: str = "sha256") -> str:
    return "0" * (2 * DIGEST_SIZE[alg])


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
    alg: str = "sha256"

    def to_json(self) -> str:
        d = asdict(self)
        if self.alg == "sha256":
            del d["alg"]  # keep the legacy on-disk format byte-identical
        return json.dumps(d, sort_keys=True)


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    reason: str
    size: int


def _entry_digest(seq: int, ts: float, kind: str, body: dict, prev: str, alg: str = "sha256",
                  provider: CryptoProvider | None = None) -> str:
    material = {"seq": seq, "ts": ts, "kind": kind, "body": body, "prev": prev}
    if alg != "sha256":
        material["alg"] = alg  # bind the algorithm into non-legacy digests
    return digest_hex(canonical_bytes(material), alg, provider)


def _write_private(path: Path, data: str, append: bool, fsync: bool = True) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "a" if append else "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        if fsync:
            os.fsync(f.fileno())


class PersonalLedger:
    def __init__(self, path: Path, signing_key: Any = None, *, digest_alg: str | None = None,
                 auto_sign_every: int = 1, fsync: bool = True, crypto: CryptoProvider | None = None):
        self.path = Path(path)
        self.head_path = self.path.with_name(self.path.name + ".head.json")
        self.crypto = crypto or default_provider()
        self.signing_key = None if signing_key is None else as_private_keyset(signing_key, self.crypto)
        if not isinstance(auto_sign_every, int) or isinstance(auto_sign_every, bool) or auto_sign_every < 0:
            raise ValueError("auto_sign_every must be an integer >= 0")
        self.auto_sign_every = auto_sign_every
        self.fsync = bool(fsync)
        self.entries: list[Entry] = []
        self._index: dict[str, int] = {}
        self._unsigned = 0
        if self.path.exists():
            self._load()
        existing = self.entries[0].alg if self.entries else None
        if digest_alg is None:
            digest_alg = existing or ("sha384" if self.signing_key is not None and self.signing_key.is_pq
                                      else "sha256")
        elif existing is not None and existing != digest_alg:
            raise LedgerError(f"ledger uses {existing}, not {digest_alg}")
        self.crypto.check("hash", digest_alg)
        self.digest_alg = digest_alg
        self._h = self.crypto.hash_fn(digest_alg)
        self._frontier = merkle.MerkleFrontier(self._h)
        for e in self.entries:
            self._frontier.append(bytes.fromhex(e.digest))

    # -- storage -------------------------------------------------------------
    def _load(self) -> None:
        for n, line in enumerate(self.path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                e = Entry(**json.loads(line))
                bytes.fromhex(e.digest)
            except (TypeError, ValueError) as ex:
                raise LedgerError(f"malformed ledger line {n + 1}") from ex
            self.entries.append(e)
            self._index[e.digest] = e.seq

    def append(self, kind: str, body: dict) -> Entry:
        prev = self.tip()
        seq = len(self.entries)
        ts = time.time()
        digest = _entry_digest(seq, ts, kind, body, prev, self.digest_alg, self.crypto)  # raises on bad body
        entry = Entry(seq, ts, kind, body, prev, digest, self.digest_alg)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _write_private(self.path, entry.to_json() + "\n", append=True, fsync=self.fsync)
        self.entries.append(entry)
        self._index[digest] = seq
        self._frontier.append(bytes.fromhex(digest))
        self._unsigned += 1
        if self.signing_key is not None and self.auto_sign_every and self._unsigned >= self.auto_sign_every:
            self._write_head()
        return entry

    def checkpoint(self) -> bool:
        """Sign the current head if any entries are not yet covered. Returns True if a head was written."""
        if self.signing_key is None or (self._unsigned == 0 and self.head_path.exists()):
            return False
        self._write_head()
        return True

    @property
    def unsigned_entries(self) -> int:
        return self._unsigned

    # -- chain -------------------------------------------------------------------
    def tip(self) -> str:
        return self.entries[-1].digest if self.entries else genesis(getattr(self, "digest_alg", "sha256"))

    def root(self) -> str:
        """Chain head digest (the 'ledger root' bound into capability tokens)."""
        return self.tip()

    def index_of(self, digest: str) -> int | None:
        return self._index.get(digest)

    def kinds_after(self, seq: int) -> list[str]:
        return [e.kind for e in self.entries[seq + 1:]]

    def verify_chain(self) -> bool:
        prev = genesis(self.digest_alg)
        for i, e in enumerate(self.entries):
            if e.alg != self.digest_alg or e.seq != i or e.prev != prev or \
                    _entry_digest(e.seq, e.ts, e.kind, e.body, e.prev, e.alg, self.crypto) != e.digest:
                return False
            prev = e.digest
        return True

    # -- merkle ------------------------------------------------------------------
    def _leaves(self, size: int | None = None) -> list[bytes]:
        es = self.entries if size is None else self.entries[:size]
        return [bytes.fromhex(e.digest) for e in es]

    def merkle_root(self, size: int | None = None) -> str:
        if size is None or size == len(self.entries):
            return self._frontier.root().hex()
        return merkle.root(self._leaves(size), self._h).hex()

    def inclusion_proof(self, seq: int) -> dict:
        leaves = self._leaves()
        return {"seq": seq, "size": len(leaves), "leaf": self.entries[seq].digest, "alg": self.digest_alg,
                "proof": [p.hex() for p in merkle.inclusion_proof(leaves, seq, self._h)],
                "merkle_root": self._frontier.root().hex()}

    @staticmethod
    def verify_inclusion_proof(p: dict, crypto: CryptoProvider | None = None) -> bool:
        h = (crypto or default_provider()).hash_fn(p.get("alg", "sha256"))
        return merkle.verify_inclusion(bytes.fromhex(p["leaf"]), p["seq"], p["size"],
                                       [bytes.fromhex(x) for x in p["proof"]], bytes.fromhex(p["merkle_root"]), h)

    # -- signed head -------------------------------------------------------------
    def signed_head(self) -> dict:
        if self.signing_key is None:
            raise LedgerError("no signing key configured")
        pub = self.signing_key.public()
        body = {"format": HEAD_FORMAT, "size": len(self.entries), "head": self.tip(),
                "merkle_root": self.merkle_root(), "signed_at": time.time(), "public_key": pub.encoded}
        if pub.suite != LEGACY_SUITE:
            body["suite"] = pub.suite
        if self.digest_alg != "sha256":
            body["digest_alg"] = self.digest_alg
        return {"head": body, "sig": self.signing_key.sign(canonical_bytes(body))}

    def _write_head(self) -> None:
        tmp = self.head_path.with_name(self.head_path.name + ".tmp")
        _write_private(tmp, json.dumps(self.signed_head(), sort_keys=True) + "\n", append=False, fsync=self.fsync)
        os.replace(tmp, self.head_path)
        self._unsigned = 0

    def verify(self, trusted_key: Any) -> VerifyReport:
        """Full verification: chain, signed head under the trusted key, size, and Merkle root.

        Raises PQUnavailableError if the trusted key is a hybrid PQ key and no PQ backend is
        available (never falls back to checking only the classical half).
        """
        trusted = as_public_keyset(trusted_key, self.crypto)
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
        if not isinstance(body, dict) or body.get("format") != HEAD_FORMAT:
            return VerifyReport(False, "bad_head_format", n)
        if body.get("public_key") != trusted.encoded:
            return VerifyReport(False, "head_signed_by_untrusted_key", n)
        if body.get("suite", LEGACY_SUITE) != trusted.suite:
            return VerifyReport(False, "head_suite_mismatch", n)
        if body.get("digest_alg", "sha256") != self.digest_alg:
            return VerifyReport(False, "digest_alg_mismatch", n)
        if not trusted.verify(canonical_bytes(body), sig):
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
