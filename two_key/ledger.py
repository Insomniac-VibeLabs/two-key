"""
Two-Key: personal ledger
===============================
An append-only JSONL hash chain owned by the principal (spec 5.6), plus:

- a Merkle tree (RFC 6962/9162) over entry digests, with inclusion proofs
  and consistency proofs between any two sizes (merkle.MerkleTree). The
  tool gateway uses the consistency proofs to check that the root bound
  into a token is an ancestor of the ledger it knows (PRIOR_ART.md §4 (i));
- O(1) indexes for the gateway: capability_issued entry by jti, the latest
  constitution_loaded entry, and revocation entries;
- a signed chain head: the principal's key signs {size, head digest, merkle
  root}. Rewriting the whole chain, which the original prototype could not
  detect, fails verification because the attacker cannot produce a head
  signature under the principal's key. Truncation and unsigned extra
  entries are detected too. The head can be signed with legacy Ed25519,
  ECDSA P-384, or a hybrid ML-DSA-65 suite (two_key.crypto);
- configurable head-signing cadence: ``auto_sign_every=N`` signs after every
  N appends (1 = every append, the default for direct use; 0 = only on
  ``checkpoint()``). TwoKey and the gateway call ``checkpoint()`` at decision
  boundaries, so one signature covers all entries of a decision;
- configurable digest algorithm: SHA-256 (legacy default) or SHA-384 (the
  default when the signing key is a post-quantum hybrid suite);
- an anchoring hook (anchoring.py). With ``head_anchor=`` every signed head is
  also published to that anchor (enterprise mode: a permissioned chain) and
  the receipt is recorded as an ``anchored`` entry. Without one, nothing is
  published;
- the single-use record for capability tokens (``redeem``). Every gateway
  on this ledger (every ``tk.gateway()`` of one TwoKey instance) consults the
  same record, so a token is accepted once however many gateways exist.
  It is rebuilt from the capability_redeemed entries on load, so it
  survives restarts. ``append``, ``checkpoint``, ``begin_attempt``, and ``redeem``
  share one re-entrant lock. A gateway writes ``redemption_started`` before
  the tool runs. A tool exception writes ``redemption_aborted`` and leaves
  the token usable. Success writes ``capability_redeemed``. A later call
  that still sees ``redemption_started`` does not run the tool. On POSIX,
  those writes hold an advisory ``flock`` and refuse if another writer
  changed the file.

The ledger file and head file are created with mode 0600. Every record and
the signed head are AES-256-GCM ciphertext. A new ledger wraps the data key
with a ledger key stored in ``two-key-secrets/`` next to the ledger, not with
the principal key. The head is signed by the principal and by a witness key
in that same secrets directory. A stolen principal key cannot decrypt the
log or sign a new head. A ledger created before this split still unwraps
with the principal key and has no witness signature.
"""

from __future__ import annotations

import json
import os
import threading
import time
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import merkle
from .anchoring import Anchor, AnchorError
from .canonical import canonical_bytes, digest_hex
from .crypto.provider import DIGEST_SIZE, CryptoProvider, default_provider
from .crypto.signatures import LEGACY_SUITE, as_private_keyset, as_public_keyset
from . import ledger_at_rest
from . import keys as keyio

try:  # POSIX advisory file locks for cross-process redemption; absent on Windows
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

GENESIS = "0" * 64
HEAD_FORMAT = "two-key-ledger-head/1"


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
        # Same output as json.dumps(asdict(self)), without asdict's deep copy of the body.
        d = {"seq": self.seq, "ts": self.ts, "kind": self.kind, "body": self.body, "prev": self.prev,
             "digest": self.digest}
        if self.alg != "sha256":
            d["alg"] = self.alg  # legacy (sha256) entries omit it, keeping the on-disk format byte-identical
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
                 auto_sign_every: int = 1, fsync: bool = True, crypto: CryptoProvider | None = None,
                 head_anchor: Anchor | None = None, ledger_key: bytes | None = None):
        self.path = Path(path)
        self.head_path = self.path.with_name(self.path.name + ".head.json")
        self.key_path = self.path.with_name(self.path.name + ".key.json")
        self.crypto = crypto or default_provider()
        self.signing_key = None if signing_key is None else as_private_keyset(signing_key, self.crypto)
        self._data_key: bytes | None = None
        self._ledger_key = ledger_key
        if not isinstance(auto_sign_every, int) or isinstance(auto_sign_every, bool) or auto_sign_every < 0:
            raise ValueError("auto_sign_every must be an integer >= 0")
        self.auto_sign_every = auto_sign_every
        self.fsync = bool(fsync)
        self.entries: list[Entry] = []
        self._index: dict[str, int] = {}
        self._issued: dict[str, int] = {}          # jti -> seq of its capability_issued entry
        self._latest_constitution: int | None = None
        self._revoke_all_seq = -1                   # seq of the latest "revoke all" entry
        self._revoked_jti: dict[str, int] = {}
        self._redeemed: dict[str, int] = {}         # jti -> seq of its capability_redeemed entry
        self._started: dict[str, int] = {}          # jti -> seq of an open redemption_started entry
        self._lock = threading.RLock()              # append / checkpoint / redeem (shared by all gateways)
        self._file_size = 0                         # bytes of the ledger file this instance has read or written
        self._lock_fd: int | None = None            # fd for the cross-process redemption flock (lazy)
        self._stale: str | None = None              # set once redeem() finds another writer on the file
        self._unsigned = 0
        self.head_anchor = head_anchor              # publish every signed head here (None: local only)
        self._anchoring = False
        self._witness = None
        self._open_data_key()
        if self.path.exists():
            self._load()
        existing = self.entries[0].alg if self.entries else None
        if digest_alg is None:
            # An existing ledger keeps its algorithm (legacy SHA-256 ledgers still load and verify);
            # a new one is SHA-384 (F_REVIEW; CONCEPTION_NOTES Entry 10).
            digest_alg = existing or "sha384"
        elif existing is not None and existing != digest_alg:
            raise LedgerError(f"ledger uses {existing}, not {digest_alg}")
        self.crypto.check("hash", digest_alg)
        self.digest_alg = digest_alg
        self._h = self.crypto.hash_fn(digest_alg)
        self._tree = merkle.MerkleTree(self._h)
        for e in self.entries:
            self._tree.append(bytes.fromhex(e.digest))
        self._ensure_witness()
        self._assert_principal()

    def secrets_dir(self) -> Path:
        """Key material that must not sit in the ledger file set. Copying the ``.jsonl`` files does not copy this."""
        return self.path.parent / "two-key-secrets"

    def ledger_key_path(self) -> Path:
        return self.secrets_dir() / (self.path.name + ".ledger-key")

    def witness_path(self) -> Path:
        return self.secrets_dir() / (self.path.name + ".witness.pem")

    def witness_pub_path(self) -> Path:
        return self.secrets_dir() / (self.path.name + ".witness.pub.pem")

    # -- storage -------------------------------------------------------------
    def _open_data_key(self) -> None:
        """Unwrap the data key, or create one. Missing and wrong keys fail closed.

        New ledgers wrap with a ledger key file under ``two-key-secrets/``. An
        explicit ``ledger_key`` argument (a non-exportable principal) still wins.
        A ledger whose wrap file already exists and has no ledger key file is
        the older principal-wrapped form and still opens with that key.
        """
        if self._ledger_key is not None:
            if not isinstance(self._ledger_key, bytes) or len(self._ledger_key) != 32:
                raise LedgerError("ledger_key must be 32 bytes")
            kek = self._ledger_key
        elif self.signing_key is not None and self.ledger_key_path().exists():
            kek = self.ledger_key_path().read_bytes()
            if len(kek) != 32:
                raise LedgerError("ledger key must be 32 bytes")
        elif self.signing_key is not None and self.key_path.exists():
            try:
                kek = ledger_at_rest.wrap_key_from_principal(self.signing_key)
            except ledger_at_rest.LedgerCryptoError as e:
                raise LedgerError(str(e)) from e
        elif self.signing_key is not None:
            kek = os.urandom(32)
            self.secrets_dir().mkdir(parents=True, exist_ok=True)
            os.chmod(self.secrets_dir(), 0o700)
            self.ledger_key_path().write_bytes(kek)
            os.chmod(self.ledger_key_path(), 0o600)
        else:
            kek = None
        if self.key_path.exists():
            if kek is None:
                raise LedgerError("encrypted ledger requires the principal key (or ledger_key)")
            try:
                blob = json.loads(self.key_path.read_text(encoding="utf-8"))
                self._data_key = ledger_at_rest.unwrap_data_key(kek, blob)
            except (OSError, ValueError, ledger_at_rest.LedgerCryptoError) as e:
                raise LedgerError(f"ledger key rejected: {e}") from e
            if not (self.path.exists() and self.path.stat().st_size):
                raise LedgerError("ledger file missing; refusing to reuse an existing wrapped data key")
            return
        if self.path.exists() and self.path.stat().st_size:
            raise LedgerError("ledger is not encrypted; refusing to open a plaintext ledger")
        if kek is None:
            return  # a new ledger; append fails closed until a key is supplied
        data_key = os.urandom(32)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _write_private(self.key_path, json.dumps(ledger_at_rest.wrap_data_key(kek, data_key)) + "\n",
                       append=False, fsync=self.fsync)
        self._data_key = data_key

    def _ensure_witness(self) -> None:
        if self.witness_path().exists():
            self._witness = keyio.load_private_key(self.witness_path())
            return
        self._witness = None
        if self.signing_key is None or self.head_path.exists():
            return
        self.secrets_dir().mkdir(parents=True, exist_ok=True)
        os.chmod(self.secrets_dir(), 0o700)
        key = keyio.generate_private_key()
        keyio.save_private_key(self.witness_path(), key)
        keyio.save_public_key(self.witness_pub_path(), key.public_key())
        self._witness = key

    def _load_witness_public(self):
        if self.witness_pub_path().exists():
            return keyio.load_public_key(self.witness_pub_path())
        if self._witness is not None:
            return self._witness.public_key()
        if self.witness_path().exists():
            return keyio.load_private_key(self.witness_path()).public_key()
        raise LedgerError("witness key missing")

    def _assert_principal(self) -> None:
        if self.signing_key is None or not self.head_path.exists() or self._data_key is None:
            return
        try:
            sh = json.loads(self._open_line(self.head_path.read_text(encoding="utf-8").strip()))
            pub = sh["head"].get("public_key")
        except (OSError, ValueError, KeyError, LedgerError) as e:
            raise LedgerError(f"ledger head rejected: {e}") from e
        if pub != self.signing_key.public().encoded:
            raise LedgerError("head principal key does not match the signing key")

    def _seal(self, plaintext: str) -> str:
        if self._data_key is None:
            raise LedgerError("encrypted ledger requires the principal key (or ledger_key)")
        return ledger_at_rest.seal(self._data_key, plaintext)

    def _open_line(self, line: str) -> str:
        if self._data_key is None:
            raise LedgerError("encrypted ledger requires the principal key (or ledger_key)")
        try:
            return ledger_at_rest.open_record(self._data_key, line)
        except ledger_at_rest.LedgerCryptoError as e:
            raise LedgerError(str(e)) from e

    def _load(self) -> None:
        raw = self.path.read_bytes()
        self._file_size = len(raw)
        for n, line in enumerate(raw.decode("utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                e = Entry(**json.loads(self._open_line(line)))
                bytes.fromhex(e.digest)
            except (TypeError, ValueError, LedgerError) as ex:
                raise LedgerError(f"malformed ledger line {n + 1}") from ex
            self.entries.append(e)
            self._index[e.digest] = e.seq
            self._track(e)

    def _track(self, e: Entry) -> None:
        if e.kind == "capability_issued":
            jti = e.body.get("jti")
            if isinstance(jti, str):
                self._issued.setdefault(jti, e.seq)
        elif e.kind == "constitution_loaded":
            self._latest_constitution = e.seq
        elif e.kind == "revocation":
            jti = e.body.get("jti")
            if jti is None:
                self._revoke_all_seq = e.seq
            elif isinstance(jti, str):
                self._revoked_jti.setdefault(jti, e.seq)
        elif e.kind == "capability_redeemed":
            jti = e.body.get("jti")
            if isinstance(jti, str):
                self._redeemed.setdefault(jti, e.seq)
                self._started.pop(jti, None)
        elif e.kind == "redemption_started":
            jti = e.body.get("jti")
            if isinstance(jti, str) and jti not in self._redeemed:
                self._started.setdefault(jti, e.seq)
        elif e.kind == "redemption_aborted":
            jti = e.body.get("jti")
            if isinstance(jti, str):
                self._started.pop(jti, None)

    def append(self, kind: str, body: dict) -> Entry:
        with self._lock:
            if self._stale:
                raise LedgerError(self._stale)
            prev = self.tip()
            seq = len(self.entries)
            ts = time.time()
            digest = _entry_digest(seq, ts, kind, body, prev, self.digest_alg, self.crypto)  # raises on bad body
            entry = Entry(seq, ts, kind, body, prev, digest, self.digest_alg)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = self._seal(entry.to_json()) + "\n"
            _write_private(self.path, line, append=True, fsync=self.fsync)
            self._file_size += len(line.encode("utf-8"))
            self.entries.append(entry)
            self._index[digest] = seq
            self._track(entry)
            self._tree.append(bytes.fromhex(digest))
            self._unsigned += 1
            if self.signing_key is not None and self.auto_sign_every and self._unsigned >= self.auto_sign_every:
                self._write_head()
            return entry

    def checkpoint(self) -> bool:
        """Sign the current head if any entries are not yet covered. Returns True if a head was written."""
        with self._lock:
            if self.signing_key is None or (self._unsigned == 0 and self.head_path.exists()):
                return False
            self._write_head()
            return True

    # -- single use (shared by every gateway on this ledger) -----------------------
    @property
    def lock(self) -> threading.RLock:
        """The ledger's re-entrant lock. Gateways hold it across their ledger checks and the redemption."""
        return self._lock

    def is_redeemed(self, jti: str) -> bool:
        return jti in self._redeemed

    def redemption_started(self, jti: str) -> bool:
        return jti in self._started and jti not in self._redeemed

    def redemption_for(self, jti: str) -> Entry | None:
        seq = self._redeemed.get(jti)
        return None if seq is None or seq < 0 else self.entries[seq]

    def begin_attempt(self, jti: str, body: dict) -> tuple[Entry | None, str]:
        """Checkpoint ``redemption_started`` before a tool runs. A second call returns
        ``already_attempted`` and does not append. ``replayed`` if the token is already spent."""
        if not isinstance(jti, str) or not jti:
            return None, "replayed"
        with self._lock:
            if jti in self._redeemed:
                return None, "replayed"
            if jti in self._started:
                return None, "already_attempted"
            fd = self._redeem_lock_fd()
            if fd is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                other = self._other_writer_state(jti)
                if other is not None:
                    self._stale = "ledger file changed by another writer; reopen the ledger"
                    return None, other
                try:
                    return self.append("redemption_started", {"jti": jti, **body}), "ok"
                except BaseException:
                    self._started.setdefault(jti, -1)
                    raise
            finally:
                if fd is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)

    def abort_attempt(self, jti: str, body: dict) -> Entry | None:
        """Clear an open attempt so a tool exception can be retried. No-op if it is not open."""
        if not isinstance(jti, str) or not jti:
            return None
        with self._lock:
            if jti not in self._started or jti in self._redeemed:
                return None
            return self.append("redemption_aborted", {"jti": jti, **body})

    def redeem(self, jti: str, body: dict) -> tuple[Entry | None, str]:
        """Record the single use of ``jti`` atomically. Returns (capability_redeemed entry, "ok") exactly
        once per jti; afterwards (None, "replayed"). Across processes (POSIX flock), returns
        (None, "replayed") if another writer already redeemed it, or (None, "ledger_concurrent_writer")
        if another writer changed the file at all; this instance is then stale and refuses
        further writes (append and checkpoint raise LedgerError) until it is reopened."""
        if not isinstance(jti, str) or not jti:
            return None, "replayed"
        with self._lock:
            if jti in self._redeemed:
                return None, "replayed"
            fd = self._redeem_lock_fd()
            if fd is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                other = self._other_writer_state(jti)
                if other is not None:
                    self._stale = "ledger file changed by another writer; reopen the ledger"
                    return None, other
                try:
                    return self.append("capability_redeemed", {"jti": jti, **body}), "ok"
                except BaseException:
                    self._redeemed.setdefault(jti, -1)  # burned in memory even if the write failed (as before)
                    raise
            finally:
                if fd is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)

    def _redeem_lock_fd(self) -> int | None:
        if fcntl is None:
            return None
        if self._lock_fd is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_RDONLY | os.O_CREAT, 0o600)
            self._lock_fd = fd
            weakref.finalize(self, os.close, fd)
        return self._lock_fd

    def _other_writer_state(self, jti: str) -> str | None:
        """None if the file is exactly what this instance wrote; otherwise the reason to refuse."""
        try:
            size = os.stat(self.path).st_size
        except OSError:
            return "ledger_concurrent_writer"
        if size == self._file_size:
            return None
        if size < self._file_size:
            return "ledger_concurrent_writer"
        with open(self.path, "rb") as f:
            f.seek(self._file_size)
            tail = f.read(size - self._file_size)
        found_started = False
        for line in tail.splitlines():
            try:
                rec = json.loads(self._open_line(line.decode("utf-8")))
            except (ValueError, LedgerError, UnicodeError):
                continue  # an entry another writer is still writing; never the redemption (written under flock)
            if not isinstance(rec, dict) or not isinstance(rec.get("body"), dict) or rec["body"].get("jti") != jti:
                continue
            if rec.get("kind") == "capability_redeemed":
                return "replayed"
            if rec.get("kind") == "redemption_started":
                found_started = True
        if found_started:
            return "already_attempted"
        return "ledger_concurrent_writer"

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

    @property
    def size(self) -> int:
        return len(self.entries)

    def capability_entry(self, jti: str) -> Entry | None:
        seq = self._issued.get(jti)
        return None if seq is None else self.entries[seq]

    def latest_constitution(self) -> Entry | None:
        return None if self._latest_constitution is None else self.entries[self._latest_constitution]

    def revocation_for(self, jti: str, issued_at_size: int) -> Entry | None:
        """The revocation entry that covers a token issued when the ledger had ``issued_at_size`` entries."""
        seq = self._revoked_jti.get(jti)
        if seq is not None:
            return self.entries[seq]
        if self._revoke_all_seq >= issued_at_size:
            return self.entries[self._revoke_all_seq]
        return None

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
        return self._tree.root(size).hex()

    def inclusion_proof(self, seq: int) -> dict:
        return {"seq": seq, "size": self.size, "leaf": self.entries[seq].digest, "alg": self.digest_alg,
                "proof": [p.hex() for p in self._tree.inclusion_proof(seq)],
                "merkle_root": self._tree.root().hex()}

    def consistency_proof(self, first: int, second: int | None = None) -> dict:
        """RFC 9162 consistency proof that the tree of size ``first`` is a prefix of size ``second``."""
        second = self.size if second is None else second
        return {"first": first, "second": second, "alg": self.digest_alg,
                "first_root": self._tree.root(first).hex(), "second_root": self._tree.root(second).hex(),
                "proof": [p.hex() for p in self._tree.consistency_proof(first, second)]}

    def consistency_path(self, first: int, second: int | None = None) -> list[bytes]:
        """Raw proof nodes (hot path for the gateway; no hex encoding)."""
        return self._tree.consistency_proof(first, second)

    def root_bytes(self, size: int | None = None) -> bytes:
        return self._tree.root(size)

    def hash_fn(self):
        return self._h

    @staticmethod
    def verify_consistency_proof(p: dict, first_root: str, second_root: str,
                                 crypto: CryptoProvider | None = None) -> bool:
        """Check a proof against roots the verifier already holds (not the roots inside the proof)."""
        try:
            h = (crypto or default_provider()).hash_fn(p.get("alg", "sha256"))
            return merkle.verify_consistency(int(p["first"]), int(p["second"]), bytes.fromhex(first_root),
                                             bytes.fromhex(second_root), [bytes.fromhex(x) for x in p["proof"]], h)
        except (KeyError, TypeError, ValueError):
            return False

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
        if self._witness is None and self._head_requires_witness():
            raise LedgerError("witness key missing; refusing to sign a head the principal key alone could forge")
        if self._witness is not None:
            body["witness_public_key"] = keyio.public_key_raw(self._witness).hex()
        signed = {"head": body, "sig": self.signing_key.sign(canonical_bytes(body))}
        if self._witness is not None:
            signed["witness_sig"] = self._witness.sign(canonical_bytes(body)).hex()
        return signed

    def _head_requires_witness(self) -> bool:
        if not self.head_path.exists() or self._data_key is None:
            return False
        try:
            sh = json.loads(self._open_line(self.head_path.read_text(encoding="utf-8").strip()))
        except (OSError, ValueError, LedgerError):
            return False
        head = sh.get("head") if isinstance(sh, dict) else None
        return isinstance(head, dict) and bool(head.get("witness_public_key"))

    def _write_head(self) -> None:
        with self._lock:
            if self._stale:
                raise LedgerError(self._stale)
            tmp = self.head_path.with_name(self.head_path.name + ".tmp")
            sh = self.signed_head()
            _write_private(tmp, self._seal(json.dumps(sh, sort_keys=True)) + "\n", append=False, fsync=self.fsync)
            os.replace(tmp, self.head_path)
            self._unsigned = 0
            if self.head_anchor is not None and not self._anchoring:
                self._anchor_head(sh)

    def _anchor_head(self, sh: dict) -> None:
        """Publish a just-signed head. The receipt (or the failure) is recorded in an ``anchored`` /
        ``anchor_failed`` entry with the head it covers, then the head is re-signed so the signed head
        still covers the whole ledger. That last head is anchored by the next checkpoint. A failure
        raises AnchorError after it is recorded, so the checkpoint fails (and a decision is denied)."""
        self._anchoring = True
        try:
            try:
                receipt = self.head_anchor.publish(sh)
            except Exception as e:  # noqa: BLE001 - recorded, then raised as AnchorError
                self.append("anchor_failed", {"anchor": self.head_anchor.describe(), "size": sh["head"]["size"],
                                              "error": f"{type(e).__name__}: {e}"[:300]})
                if self._unsigned:
                    self._write_head()
                raise AnchorError(f"anchoring failed: {type(e).__name__}: {e}"[:300]) from None
            self.append("anchored", {"receipt": receipt, "signed_head": sh})
            if self._unsigned:
                self._write_head()
        finally:
            self._anchoring = False

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
            sh = json.loads(self._open_line(self.head_path.read_text(encoding="utf-8").strip()))
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
        wpub = body.get("witness_public_key")
        if wpub or self.witness_path().exists():
            if not wpub or "witness_sig" not in sh:
                return VerifyReport(False, "witness_signature_missing", n)
            try:
                witness_pub = self._load_witness_public()
            except (LedgerError, ValueError, OSError):
                return VerifyReport(False, "witness_key_missing", n)
            if keyio.public_key_raw(witness_pub).hex() != wpub:
                return VerifyReport(False, "witness_key_mismatch", n)
            try:
                witness_pub.verify(bytes.fromhex(sh["witness_sig"]), canonical_bytes(body))
            except Exception:
                return VerifyReport(False, "witness_signature_invalid", n)
        if body["size"] != n:
            return VerifyReport(False, f"size_mismatch:head={body['size']},file={n}", n)
        if body["head"] != self.tip():
            return VerifyReport(False, "head_digest_mismatch", n)
        if body["merkle_root"] != self.merkle_root():
            return VerifyReport(False, "merkle_root_mismatch", n)
        return VerifyReport(True, "ok", n)

    # -- anchoring (manual) ------------------------------------------------------
    def anchor(self, anchor: Anchor) -> dict:
        receipt = anchor.publish(self.signed_head())
        self.append("anchored", {"receipt": receipt})
        return receipt
