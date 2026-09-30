"""
Compact Kernel — Personal Capability Ledger
==========================================
Append-only Merkle log owned by the principal. Every proposal, VM
result, quorum ballot, and issued capability is hashed into a chain
the vendor cannot rewrite.

In production the root is periodically anchored to a public bulletin
(blockchain, transparency log, or notary). This prototype keeps an
on-disk hash chain and can export a portable proof.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


@dataclass
class Entry:
    seq: int
    ts: float
    kind: str
    body: dict
    prev: str
    digest: str


class PersonalLedger:
    def __init__(self, path: Path):
        self.path = path
        self.entries: list[Entry] = []
        if path.exists():
            self._load()

    def _load(self) -> None:
        for line in self.path.read_text().splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            self.entries.append(Entry(**d))

    def tip(self) -> str:
        return self.entries[-1].digest if self.entries else "0" * 64

    def append(self, kind: str, body: dict) -> Entry:
        prev = self.tip()
        seq = len(self.entries)
        ts = time.time()
        material = {"seq": seq, "ts": ts, "kind": kind, "body": body, "prev": prev}
        digest = _sha(canonical(material))
        entry = Entry(seq=seq, ts=ts, kind=kind, body=body, prev=prev, digest=digest)
        self.entries.append(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")
        return entry

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for e in self.entries:
            material = {"seq": e.seq, "ts": e.ts, "kind": e.kind, "body": e.body, "prev": e.prev}
            if e.prev != prev:
                return False
            if _sha(canonical(material)) != e.digest:
                return False
            prev = e.digest
        return True

    def root(self) -> str:
        return self.tip()
