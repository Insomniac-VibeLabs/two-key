# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Append-only hash-chained ledger with a signed head.

Entries and the head are AES-256-GCM ciphertext at rest. The data key is
wrapped by a ledger key that is not the principal key. The head is signed by
the principal and by a witness key. The capability minting key also lives
outside the ledger directory (`<ledger>.capability/capability.pem`). This
module does not load it. The gateway must not either. A stolen principal
key can neither decrypt the log nor sign a new head, and it does not mint
tokens. Appends and checkpoints take `<ledger>.lock` next to the
ledger directory. A write is refused if another writer changed the entries file's
size since this ledger read or wrote it. The Merkle root is extended as
entries are appended, not recomputed from the first leaf.
Redemption locks live in `<ledger>.redeem-locks`, also outside the directory.

The witness public key is pinned twice (#58):

* In the ledger: the first entry of a new ledger is ``witness_pinned``. A
  ledger made before 0.2.3 pins the key that signed its current head on its
  first open (``source: first_use``, trust on first use). A head signed by
  another witness key, and a ``witness.pem`` that does not match, are refused
  (``witness_key_changed``). The key changes only by ``rotate_witness``, a
  ``witness_rotated`` entry signed by the principal and the old and new
  witness keys. Whoever holds the principal key and the ledger key can still
  rewrite the chain from its first entry, pin included.
* Outside the ledger (optional): ``Ledger(..., witness_public_key=...)``, kept
  where whoever writes the ledger directory cannot change it. With it, a head
  also needs the witness private key. The operator updates it after a rotation.

The key upgrade (0.9.0): a ledger made by 0.8.0 is signed with Ed25519 keys. Once
its key files are hybrid (``two_key/upgrade.py`` adds an ML-DSA-65 half to each),
the ledger opens with ``upgrade_pending`` set and refuses every write until
``upgrade_keys`` records ``keys_upgraded``: the old and new principal and witness
keys, signed by all four, and the new capability and stamp key fingerprints. From
that entry on, the head, the anchor and every rotation are hybrid, and a 0.8.0
key is refused. The new keys keep the old Ed25519 halves, so the entries before
it are checked with those.

Neither pin detects a rollback to an earlier signed head, or a wipe (#62).
A separate head anchor does. It lives outside the ledger directory, by default
beside the ledger key (``<ledger>.ledger-key/head.anchor``), and it records the
newest signed head this process has checkpointed. Opening a ledger whose signed
head is older than that anchor, or a wiped directory that no longer holds that
head, is refused (``ledger_rolled_back``). The anchor is adopted from the
current head when it is missing, which is how a ledger from 0.2.3 starts being
protected, and which is also why deleting the anchor undoes the check. Someone
who can write the anchor file can roll it back together with the ledger. Pass
``anchor_path`` (or ``--head-anchor``) to keep the file somewhere a ledger-directory
writer cannot change.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import _platform
from .canonical import EncodingError, canonical_bytes, canonical_hash
from .agent_meta import cap_ledger_text, type_tag
from .keys import (
    CLASSICAL_ALG, ED_PUB_BYTES, HYBRID_ALG, HybridPrivateKey, HybridPublicKey, classical_half, generate_private_key,
    is_hybrid, load_private_key_file, load_public_key, public_from_raw, public_key, public_raw, save_private_key,
    save_public_key, sign, verify,
)

WRAP_FORMAT = "two-key-ledger-wrap/1"
RECORD_FORMAT = "two-key-ledger-enc/1"
ANCHOR_FORMAT = "two-key-head-anchor/1"
_WRAP_INFO = b"two-key-ledger-wrap/1"
_RECORD_AAD = b"two-key-ledger-enc/1"


LEDGER_KEY_BYTES = 32

WITNESS_ROTATION_FORMAT = "two-key-witness-rotation/1"
KEYS_UPGRADE_FORMAT = "two-key-keys-upgraded/1"
KEYS_UPGRADE_PENDING = ("keys_upgrade_pending: this ledger's key files are hybrid, and the ledger has not recorded the "
                        "key upgrade yet; run two-key keys upgrade (docs/UPGRADING.md)")
# Formats written by the two-key-concept repository (before two-key 0.4.0). They are not read; a file in
# one gets a clear error instead of a decryption or parse failure.
LEGACY_PREFIX = "two-key-concept-"
LEGACY_MESSAGE = "made by two-key-concept (before two-key 0.4.0); two-key cannot read it"


def _legacy(fmt) -> bool:
    return isinstance(fmt, str) and fmt.startswith(LEGACY_PREFIX)
# Written only by the ledger itself: Ledger.append refuses these kinds.
_WITNESS_KINDS = frozenset({"witness_pinned", "witness_rotated", "keys_upgraded"})
_ANCHOR_FIELDS = ("format", "size", "tip", "merkle_root", "public_key", "witness_public_key")
# The signed statement of a witness_rotated entry; the entry body is these plus the three signatures.
_ROTATION_FIELDS = ("format", "seq", "prev", "old_witness_public_key", "new_witness_public_key", "reason")
# The signed statement of a keys_upgraded entry; the entry body is these plus the four signatures.
_UPGRADE_FIELDS = ("format", "seq", "prev", "from_alg", "to_alg", "old_principal_public_key",
                   "new_principal_public_key", "old_witness_public_key", "new_witness_public_key",
                   "capability_key_fingerprint", "stamp_key_fingerprint")
_UPGRADE_SIGNATURES = ("old_principal_signature", "new_principal_signature", "old_witness_signature",
                       "new_witness_signature")


def witness_key_fingerprint(raw: str) -> str:
    """The fingerprint of a raw witness public key (the base64 form the head carries): ``hybrid-sha256:`` for a
    hybrid key, ``sha256:`` for a 0.8.0 Ed25519 key, then the hex SHA-256 (``keys.key_fingerprint``)."""
    data = base64.b64decode(raw)
    return ("sha256:" if len(data) == ED_PUB_BYTES else "hybrid-sha256:") + hashlib.sha256(data).hexdigest()


def _witness_public(raw, what: str):
    try:
        return public_from_raw(raw)
    except Exception:
        raise LedgerError(f"{what} is not a hybrid Ed25519 + ML-DSA-65 (or 0.8.0 Ed25519) public key") from None


def _write_new_secret(path, data: bytes) -> None:
    """Create ``path`` owner-only (mode 0600, or a private access list on Windows) and write ``data``.

    An existing file or a planted symlink raises FileExistsError instead of being
    overwritten, and there is no window in which the bytes are readable before a chmod.
    """
    fd = _platform.create_new(path)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _read_secret(path, size: int, label: str) -> bytes:
    """Read a ``size``-byte key with O_NOFOLLOW; refuse a non-regular file, group/other access, or a wrong length."""
    try:
        fd = _platform.open_nofollow(path)
    except OSError as e:
        raise LedgerError(f"{label}_unreadable: {path}: {e.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise LedgerError(f"{label}_unreadable: {path} is not a regular file")
        problem = _platform.access_problem(fd, st)
        if problem:
            raise LedgerError(f"{label}_insecure: {_platform.insecure(path, problem)}")
        data = os.read(fd, size + 1)
    finally:
        os.close(fd)
    if len(data) != size:
        raise LedgerError(f"{label}_unreadable: {path} is not a {size}-byte key")
    return data


class LedgerError(RuntimeError):
    pass


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle tree hash. Empty input is SHA-256("empty"), not a leaf."""

    def mth(items: list[bytes]) -> bytes:
        n = len(items)
        if n == 0:
            return hashlib.sha256(b"empty").digest()
        if n == 1:
            return hashlib.sha256(b"\x00" + items[0]).digest()
        k = 1 << (n.bit_length() - 1)
        if k == n:
            k >>= 1
        return hashlib.sha256(b"\x01" + mth(items[:k]) + mth(items[k:])).digest()

    return mth(leaves)


def _fold_ranges(ranges: list[tuple[int, bytes]]) -> bytes:
    """RFC 6962 root of complete subtrees, left to right. Empty is SHA-256(b"empty")."""
    if not ranges:
        return hashlib.sha256(b"empty").digest()
    acc = ranges[-1][1]
    for _, node in reversed(ranges[:-1]):
        acc = hashlib.sha256(b"\x01" + node + acc).digest()
    return acc


def _merkle_push(ranges: list[tuple[int, bytes]], leaf: bytes) -> bytes:
    """Add one leaf to an RFC 6962 tree and return the new root.

    ``ranges`` is the compact range, left to right: complete subtrees whose sizes
    are the bits of the leaf count. Equal sizes on the right are joined. The root
    matches ``merkle_root`` of the same leaves.
    """
    ranges.append((1, hashlib.sha256(b"\x00" + leaf).digest()))
    while len(ranges) >= 2 and ranges[-1][0] == ranges[-2][0]:
        size, right = ranges.pop()
        _, left = ranges.pop()
        ranges.append((size * 2, hashlib.sha256(b"\x01" + left + right).digest()))
    return _fold_ranges(ranges)


def merkle_root_incremental(leaves: list[bytes]) -> bytes:
    """``merkle_root`` built one leaf at a time. Tests check the two stay equal."""
    ranges: list[tuple[int, bytes]] = []
    root = hashlib.sha256(b"empty").digest()
    for leaf in leaves:
        root = _merkle_push(ranges, leaf)
    return root


def _kek(ledger_key: bytes) -> bytes:
    if len(ledger_key) != 32:
        raise LedgerError("ledger key must be 32 bytes")
    return HKDF(SHA256(), 32, salt=b"two-key-ledger", info=_WRAP_INFO).derive(ledger_key)


def _seal(data_key: bytes, plaintext: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(data_key).encrypt(nonce, plaintext.encode("utf-8"), _RECORD_AAD)
    return json.dumps({"enc": RECORD_FORMAT, "n": nonce.hex(), "c": ct.hex()}, separators=(",", ":"))


def _open(data_key: bytes, record: str) -> str:
    try:
        blob = json.loads(record)
        if blob.get("enc") != RECORD_FORMAT:
            raise LedgerError("ledger record is not encrypted")
        return AESGCM(data_key).decrypt(
            bytes.fromhex(blob["n"]), bytes.fromhex(blob["c"]), _RECORD_AAD).decode("utf-8")
    except LedgerError:
        raise
    except Exception as e:
        raise LedgerError("ledger record rejected (wrong key or tampered ciphertext)") from e


_KEEP_CHARS = 200


# Always retained on body_omitted decision/audit entries (compact hashes; never the full body).
_DIGEST_KEEP = frozenset({"policy_digest", "identities_digest"})


def omitted_body(body: dict, error: Exception) -> dict:
    """What ``append_bounded`` records for a body that cannot be encoded: its short scalar fields, and the
    size and SHA-256 of its JSON (non-JSON values written as ``<type_tag>``, never raw
    unbounded ``__name__``), never the other values.

    ``policy_digest`` and ``identities_digest`` are always retained when present (even if longer than
    the ordinary string cap) so auditors can still bind a truncated decision to the loaded policy
    and identities. ``body_omitted: true`` flags that other fields were dropped.
    """
    kept = {}
    for k, v in body.items():
        if type(k) is not str or len(k) > 64 or k in ("body_size", "body_digest", "body_omitted"):
            continue
        if k in _DIGEST_KEEP and type(v) is str and len(v) <= 128:
            kept[k] = v
            continue
        if v is None or type(v) in (bool, int) or (type(v) is str and len(v) <= _KEEP_CHARS):
            kept[k] = v
    try:
        data = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          default=lambda o: f"<{type_tag(o)}>").encode("utf-8", "surrogatepass")
    except (RecursionError, ValueError, TypeError):
        data = None
    return {**kept, "body_size": -1 if data is None else len(data),
            "body_digest": None if data is None else "sha256:" + hashlib.sha256(data).hexdigest(),
            "body_omitted": True, "body_error": str(error)[:_KEEP_CHARS]}


@dataclass(frozen=True)
class Entry:
    seq: int
    prev: str
    kind: str
    body: dict
    entry_hash: str

    def to_json(self) -> dict:
        return {"seq": self.seq, "prev": self.prev, "kind": self.kind,
                "body": self.body, "entry_hash": self.entry_hash}


class Ledger:
    def __init__(self, path: Path | str, private_key, public_key=None, *,
                 witness_path: Path | str | None = None, ledger_key_path: Path | str | None = None,
                 witness_public_key=None, anchor_path: Path | str | None = None, _load: bool = True):
        """Open or create the ledger at ``path``.

        ``witness_public_key`` is the out-of-ledger witness pin: the witness public key, kept where whoever
        writes the ledger directory cannot change it. With it, a head signed by any other witness key is
        refused (``witness_key_changed``), and so is a ``witness.pem`` that does not match.

        ``anchor_path`` is the monotonic head anchor (#62). The default is ``<ledger>.ledger-key/head.anchor``.
        It must sit outside the ledger directory. A signed head older than the anchor, or a wiped ledger
        directory, is refused. A missing anchor is adopted from the current head.

        Opening a new ledger writes its ``witness_pinned`` entry and warns on stderr, because a typo of a
        new path creates an empty ledger that has forgotten every redemption. Opening a ledger made before
        0.2.3 for the first time pins the witness key that signed its head (trust on first use). Both are
        checkpointed. ``_load=False`` is only for ``recover_tail``.
        """
        if witness_public_key is not None and not isinstance(witness_public_key, (Ed25519PublicKey, HybridPublicKey)):
            raise LedgerError("witness_public_key must be a Two-Key public key")
        if public_key is not None and public_raw(private_key.public_key()) != public_raw(public_key):
            # Every head it signed would fail "principal head signature failed" on the next open (#60 item 5).
            raise LedgerError("principal key mismatch: the principal private key does not match the principal "
                              "public key given for this ledger; refusing to open it")
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        if self.path.resolve() == self.path.parent.resolve():
            raise LedgerError("ledger path must be a directory, not a filesystem root")
        self.private_key = private_key
        self.public_key = public_key or private_key.public_key()
        self._public_key_arg = public_key
        self._witness_public_arg = witness_public_key
        self.witness_path = Path(witness_path) if witness_path else self.path.parent / f"{self.path.name}.witness" / "witness.pem"
        self.ledger_key_path = Path(ledger_key_path) if ledger_key_path else self.path.parent / f"{self.path.name}.ledger-key" / "ledger.key"
        self._anchor_path = Path(anchor_path) if anchor_path else self.ledger_key_path.parent / "head.anchor"
        if _platform.inside(self.witness_path, self.path):
            raise LedgerError("witness key must live outside the ledger directory")
        if _platform.inside(self.ledger_key_path, self.path):
            raise LedgerError("ledger key must live outside the ledger directory")
        if _platform.inside(self._anchor_path, self.path):
            raise LedgerError("head anchor must live outside the ledger directory")
        # Re-entrant, so one ``exclusive()`` block can hold the write lock across several appends and the
        # checkpoint that covers them (run 9y, S6c); ``_depth`` counts this thread's nested holds.
        self._lock = threading.RLock()
        self._depth = 0
        self._observers: list = []          # called after each append (two_key/siem.py); never blocking
        self.entries: list[Entry] = []
        self._redeemed: set[str] = set()
        self._started: set[str] = set()
        # Tools held after a bad receipt under high_assurance (#28): tool -> the tool_held entry's seq.
        self._held: dict[str, int] = {}
        self._configured_witness = None if witness_public_key is None else public_raw(witness_public_key)
        self._witness_pin: tuple[str, int, str] | None = None    # (raw key, seq, source) pinned in the ledger
        # The key upgrade: True while the key files are hybrid and the ledger is still Ed25519 (no keys_upgraded
        # yet); the keys_upgraded entry's seq once it is read; rotations signed by the Ed25519 principal half
        # before it, which only a keys_upgraded entry after them makes valid.
        self.upgrade_pending = False
        self._upgraded_at: int | None = None
        self._classical_rotations: list[int] = []
        self._head_witness: str | None = None                   # the witness key in the verified head
        self._merkle_ranges: list[tuple[int, bytes]] = []
        self._merkle_roots: list[str] = []
        self._kind_seqs: dict[str, list[int]] = {}   # kind -> entry seqs, in order (#50)
        self._entries_size: int | None = None                   # bytes of entries.jsonl last read or written
        self._from_others: set[int] = set()     # seqs another process appended while this one had it open
        anchor = self._read_anchor()
        if anchor is not None and anchor["size"] > 0 and self._ledger_files_incomplete():
            raise LedgerError(self._rollback_message(0, anchor))
        self.created = not (
            self.wrap_path.exists() or self.head_path.exists() or self.entries_path.exists() or anchor is not None)
        if self.created and _load:
            sib = self.path.name
            print(f"two-key: creating a new ledger at {self.path} (no existing entries). "
                  f"If this path is a typo, stop and remove it and the sibling {sib}.ledger-key, "
                  f"{sib}.witness, and {sib}.capability directories before anything uses it.",
                  file=sys.stderr)
        self._ledger_key = self._open_ledger_key()
        self._data_key = self._open_data_key()
        self._witness = self._open_witness()
        if _load:
            self._load()

    def capability_key_path(self) -> Path:
        """Minting key. Outside the ledger directory. The gateway does not read it."""
        path = self.path.parent / f"{self.path.name}.capability" / "capability.pem"
        if _platform.inside(path, self.path):
            raise LedgerError("capability key must live outside the ledger directory")
        return path

    def lock_path(self) -> Path:
        path = self.path.parent / f"{self.path.name}.lock"
        if _platform.inside(path, self.path):
            raise LedgerError("ledger lock must live outside the ledger directory")
        return path

    def redeem_lock_path(self, jti: str) -> Path:
        if not isinstance(jti, str) or not jti:
            raise LedgerError("jti required")
        directory = self.path.parent / f"{self.path.name}.redeem-locks"
        if _platform.inside(directory, self.path):
            raise LedgerError("redemption lock must live outside the ledger directory")
        directory.mkdir(parents=True, exist_ok=True)
        _platform.owner_only_dir(directory)
        return directory / hashlib.sha256(jti.encode("utf-8")).hexdigest()

    def agent_lock_path(self, agent_id: str) -> Path:
        """The lock a running ``two-key mcp-proxy`` holds for its agent on this ledger (0.8.0, D10): one file per
        agent id, named by its SHA-256, in an owner-only folder outside the ledger directory."""
        if not isinstance(agent_id, str) or not agent_id:
            raise LedgerError("agent id required")
        directory = self.path.parent / f"{self.path.name}.agents"
        if _platform.inside(directory, self.path):
            raise LedgerError("agent lock must live outside the ledger directory")
        directory.mkdir(parents=True, exist_ok=True)
        _platform.owner_only_dir(directory)
        return directory / f"{hashlib.sha256(agent_id.encode('utf-8')).hexdigest()}.lock"

    def _entries_file_size(self) -> int:
        try:
            return self.entries_path.stat().st_size
        except FileNotFoundError:
            return 0

    def _note_entries_size(self) -> None:
        """Remember the entries file size. The next write compares it, instead of re-reading the file (#50)."""
        self._entries_size = self._entries_file_size()

    def _exclusive(self, *, check_stale: bool = True):
        ledger = self

        class _Guard:
            def __enter__(self):
                ledger._lock.acquire()
                self.held = True
                self.fd = None
                if ledger._depth:       # already held by this thread: the outer block caught up and holds the file
                    ledger._depth += 1
                    return self
                try:
                    self.fd = _platform.open_lock_file(ledger.lock_path())
                    _platform.lock(self.fd)
                    if check_stale and ledger._entries_size is not None and ledger._entries_file_size() != ledger._entries_size:
                        ledger._catch_up_unlocked()
                    ledger._depth = 1
                    return self
                except BaseException:
                    self._release()
                    raise

            def __exit__(self, exc_type, exc, tb):
                self._release()
                return False

            def _release(self):
                if self.held and ledger._depth > 1:  # skipcq: PYL-W0212 - the guard belongs to this ledger and tracks the ledger's own lock depth
                    ledger._depth -= 1
                    ledger._lock.release()  # skipcq: PYL-W0212 - the guard belongs to this ledger and releases the ledger's own lock
                    self.held = False
                    return
                ledger._depth = 0  # skipcq: PYL-W0212 - the guard belongs to this ledger and tracks the ledger's own lock depth
                if self.fd is not None:
                    try:
                        _platform.unlock(self.fd)
                    finally:
                        os.close(self.fd)
                    self.fd = None
                if self.held:
                    ledger._lock.release()  # skipcq: PYL-W0212 - the guard belongs to this ledger and releases the ledger's own lock
                    self.held = False

        return _Guard()

    @property
    def entries_path(self) -> Path:
        return self.path / "entries.jsonl"

    @property
    def head_path(self) -> Path:
        return self.path / "head.json"

    def anchor_path(self) -> Path:
        """The monotonic head anchor (``anchor_path`` at construction, or the default beside the ledger key)."""
        return self._anchor_path

    def exclusive(self):
        """Hold the ledger's write lock, against this process and others, for the ``with`` block. A backup
        copies the ledger's files under it so it never sees a half-written entry.

        On entry it reads what other processes appended. Inside it, ``append`` and ``checkpoint`` take the
        same lock again, so entries and the checkpoint that signs them are written in one hold: another
        process sharing the ledger never reads entries the signed head does not cover yet (run 9y, S6c)."""
        return self._exclusive()

    def record(self, kind: str, body: dict) -> Entry:
        """``append_bounded`` and ``checkpoint`` in one hold of the write lock."""
        with self._exclusive():
            entry = self.append_bounded(kind, body)
            self.checkpoint()
            return entry

    def fingerprint_key_path(self) -> Path:
        """Per-install HMAC key for credential fingerprints, beside the ledger key, outside the ledger."""
        return self.ledger_key_path.parent / "fingerprint.key"

    def fingerprint_key(self) -> bytes:
        """The HMAC key for credential fingerprints (identity.py): 32 bytes, O_EXCL, 0600, created once."""
        from .identity import IdentityError, load_fingerprint_key
        try:
            return load_fingerprint_key(self.fingerprint_key_path())
        except IdentityError as e:
            raise LedgerError(str(e)) from None

    @property
    def wrap_path(self) -> Path:
        return self.path / "keywrap.json"

    def _open_ledger_key(self) -> bytes:
        path = self.ledger_key_path
        if not os.path.lexists(path):
            if self.wrap_path.exists():
                raise LedgerError("ledger key missing; refusing to open ciphertext with the principal key")
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _platform.owner_only_dir(path.parent)
            try:
                _write_new_secret(path, os.urandom(LEDGER_KEY_BYTES))
            except FileExistsError:
                pass                       # another process created it first: read theirs
            except OSError as e:
                raise LedgerError(f"ledger_key_unavailable: cannot create {path}: {e.strerror}") from None
        return _read_secret(path, LEDGER_KEY_BYTES, "ledger_key")

    def _open_data_key(self) -> bytes:
        kek = _kek(self._ledger_key)
        if not os.path.lexists(self.wrap_path):
            with self._exclusive(check_stale=False):
                if not os.path.lexists(self.wrap_path):
                    data_key = os.urandom(32)
                    nonce = os.urandom(12)
                    blob = {"format": WRAP_FORMAT, "nonce": nonce.hex(),
                            "wrapped": AESGCM(kek).encrypt(nonce, data_key, _WRAP_INFO).hex()}
                    tmp = self.wrap_path.with_name(f".keywrap.{os.getpid()}.{os.urandom(4).hex()}.tmp")
                    try:
                        _write_new_secret(tmp, (json.dumps(blob, indent=2) + "\n").encode("utf-8"))
                        _platform.replace(tmp, self.wrap_path)
                    finally:
                        if os.path.lexists(tmp):
                            os.unlink(tmp)
                    return data_key
        try:
            fd = _platform.open_nofollow(self.wrap_path)
        except OSError as e:
            raise LedgerError(f"ledger key file unreadable: {e.strerror}") from None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise LedgerError("ledger key file is not a regular file")
            with os.fdopen(fd, "rb", closefd=False) as fh:
                raw = fh.read(64 * 1024)
        finally:
            os.close(fd)
        try:
            blob = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise LedgerError("ledger key file is not a two-key wrapped data key") from None
        if not isinstance(blob, dict) or blob.get("format") != WRAP_FORMAT:
            if isinstance(blob, dict) and _legacy(blob.get("format")):
                raise LedgerError(f"ledger key file {LEGACY_MESSAGE}: start a new ledger")
            raise LedgerError("ledger key file is not a two-key wrapped data key")
        try:
            return AESGCM(kek).decrypt(bytes.fromhex(blob["nonce"]), bytes.fromhex(blob["wrapped"]), _WRAP_INFO)
        except Exception as e:
            raise LedgerError("ledger data key rejected (wrong ledger key)") from e

    def _open_witness(self):
        if not self.witness_path.exists():
            if self.head_path.exists():
                raise LedgerError("witness key missing; refusing to open a head the principal key alone could replace")
            if self._configured_witness is not None:
                raise LedgerError(f"witness_key_missing: {self.witness_path} does not exist, and a new witness key "
                                  "cannot match the configured witness public key")
            key = generate_private_key()
            save_private_key(self.witness_path, key, private_dir=self._default_witness_dir())   # dir 0700
            save_public_key(self.witness_path.with_suffix(".pub.pem"), public_key(key))
            return key
        if self._default_witness_dir():
            try:
                _platform.owner_only_dir(self.witness_path.parent)   # <ledger>.witness is Two-Key's own directory
            except OSError:
                pass                                        # not ours to change; the key file is still checked
        return self._load_witness()

    def _default_witness_dir(self) -> bool:
        return self.witness_path.parent == self.path.parent / f"{self.path.name}.witness"

    def _load_witness(self):
        """``witness.pem`` through the safe loader, as the ledger key is read: no symlink, a regular file, and no
        group or other access (#57)."""
        try:
            return load_private_key_file(self.witness_path)
        except ValueError as e:
            raise LedgerError(f"witness key: {e}") from None

    def _load(self) -> None:
        with self._exclusive(check_stale=False):
            lines = self.entries_path.read_text(encoding="utf-8").splitlines() if self.entries_path.exists() else []
            last = None
            for i, line in enumerate(lines):
                if line.strip():
                    last = i
            prev = "0" * 64
            for i, line in enumerate(lines):
                if not line.strip():
                    continue
                try:
                    opened = _open(self._data_key, line)
                except LedgerError:
                    if i == last:
                        raise LedgerError(
                            "ledger record rejected (the last record does not decrypt). "
                            "A torn write from a crash looks like this; see HOWTO "
                            "\"If the ledger will not open after a crash\". It can also be tampering."
                        ) from None
                    raise
                raw = json.loads(opened)
                entry = Entry(raw["seq"], raw["prev"], raw["kind"], raw["body"], raw["entry_hash"])
                expect = self._hash(entry.seq, entry.prev, entry.kind, entry.body)
                if entry.entry_hash != expect or entry.prev != prev or entry.seq != len(self.entries):
                    raise LedgerError("ledger chain failed verification")
                self._track(entry, verify=True)
                self.entries.append(entry)
                self._merkle_add(bytes.fromhex(entry.entry_hash))
                prev = entry.entry_hash
            self._note_entries_size()
            self._verify_head()
            # Read again under the lock: a rotation in another process may have finished since __init__ read it.
            self._witness = self._load_witness()
            self._reject_if_behind_anchor()
            if self._witness_pin is None:
                self._pin_witness()
            else:
                self._check_witness(self._witness, str(self.witness_path))
            self._sync_witness_public()
            self._sync_anchor_forward()

    def _catch_up_unlocked(self) -> None:
        """Read the entries another process appended since this one last read or wrote the file. Caller holds
        both locks.

        Two processes may share a ledger (two proxies, say): each appends under the cross-process lock, and
        the other then finds the file longer than it left it. The new lines are verified as ``_load`` verifies
        them (each decrypts, continues the chain from this process's last entry, and carries a valid witness
        pin or rotation), then the signed head must match the longer chain and the anchor must not be ahead of
        it. They are not passed to the observers: the process that wrote them reports them. A file that got
        shorter, or ends in a partial line, is not something another writer does under the lock, so it is
        refused as before and the ledger must be reopened.
        """
        size, known = self._entries_file_size(), self._entries_size
        stale = "ledger file changed by another writer; reopen the ledger"
        if known is None or size < known:
            raise LedgerError(stale)
        fd = _platform.open_nofollow(self.entries_path, os.O_RDONLY | _platform.O_BINARY)
        with os.fdopen(fd, "rb") as fh:
            fh.seek(known)
            data = fh.read(size - known)
        if len(data) != size - known or not data.endswith(b"\n"):
            raise LedgerError(stale)
        prev = self.entries[-1].entry_hash if self.entries else "0" * 64
        for line in data.decode("utf-8").splitlines():
            if not line.strip():
                continue
            raw = json.loads(_open(self._data_key, line))
            entry = Entry(raw["seq"], raw["prev"], raw["kind"], raw["body"], raw["entry_hash"])
            expect = self._hash(entry.seq, entry.prev, entry.kind, entry.body)
            if entry.entry_hash != expect or entry.prev != prev or entry.seq != len(self.entries):
                raise LedgerError("ledger chain failed verification")
            self._track(entry, verify=True)
            self.entries.append(entry)
            self._merkle_add(bytes.fromhex(entry.entry_hash))
            self._from_others.add(entry.seq)
            prev = entry.entry_hash
        self._entries_size = size
        self._verify_head()
        self._witness = self._load_witness()        # the other process may have rotated it
        self._check_witness(self._witness, str(self.witness_path))
        self._reject_if_behind_anchor()

    def _sync_witness_public(self) -> bool:
        """Keep ``witness.pub.pem`` in step with ``witness.pem`` once that key matches the pins. It is derived and
        public: operators copy it to keep the out-of-ledger pin. Returns False if it could not be written."""
        path = self.witness_path.with_suffix(".pub.pem")
        want = self._witness.public_key()
        try:
            if path.is_file() and not path.is_symlink() and public_raw(load_public_key(path)) == public_raw(want):
                return True
        except (OSError, ValueError):
            pass
        try:
            if path.is_symlink():
                path.unlink()
            save_public_key(path, want)
            return True
        except OSError:
            return False

    def _track(self, entry: Entry, *, verify: bool) -> None:
        """Update the redemption sets and the witness pin for ``entry``. ``verify`` checks a pin entry read
        from disk: one ``witness_pinned``, and rotations that start from the pinned key and carry the three
        signatures."""
        jti = entry.body.get("jti")
        if entry.kind == "redemption" and jti:
            self._redeemed.add(jti)
            self._started.discard(jti)
        elif entry.kind == "redemption_started" and jti:
            self._started.add(jti)
        # 0.9.0: redemption_aborted leaves the jti started, so a token whose tool failed is spent (already_attempted).
        # A ledger written by 0.8.0 may hold a later redemption of that jti; it still reads as redeemed.
        elif entry.kind == "tool_held" and isinstance(entry.body.get("tool"), str):
            self._held[entry.body["tool"]] = entry.seq
        elif entry.kind == "tool_released" and isinstance(entry.body.get("tool"), str):
            self._held.pop(entry.body["tool"], None)
        elif entry.kind in ("witness_pinned", "witness_rotated"):
            self._track_witness(entry, check=verify)
        elif entry.kind == "keys_upgraded":
            self._track_upgrade(entry, check=verify)
        seqs = self._kind_seqs.setdefault(entry.kind, [])
        seqs.append(entry.seq)

    def _track_witness(self, entry: Entry, *, check: bool) -> None:
        """Move the witness pin for a ``witness_pinned`` or ``witness_rotated`` entry (see ``_track``)."""
        if entry.kind == "witness_pinned":
            raw = entry.body.get("witness_public_key")
            if check:
                if self._witness_pin is not None:
                    raise LedgerError("ledger chain failed verification: a second witness_pinned entry "
                                      f"at {entry.seq}; the witness key changes only by witness_rotated")
                _witness_public(raw, f"witness_pinned at {entry.seq}")
            self._witness_pin = (raw, entry.seq, str(entry.body.get("source")))
            return
        if check:
            self._verify_rotation(entry)
        self._witness_pin = (entry.body["new_witness_public_key"], entry.seq, "rotated")

    def _verify_rotation(self, entry: Entry) -> None:
        body = entry.body
        try:
            statement = {k: body[k] for k in _ROTATION_FIELDS}
        except KeyError:
            raise LedgerError(f"witness_rotated at {entry.seq} is malformed") from None
        if (statement["format"] != WITNESS_ROTATION_FORMAT or statement["seq"] != entry.seq
                or statement["prev"] != entry.prev):
            raise LedgerError(f"witness_rotated at {entry.seq} does not belong at this place in the chain")
        if self._witness_pin is None or statement["old_witness_public_key"] != self._witness_pin[0]:
            raise LedgerError(f"witness_rotated at {entry.seq} does not start from the pinned witness key")
        message = canonical_bytes(statement)
        self._verify_rotation_principal(entry.seq, message, body.get("principal_signature") or "")
        for public, field in ((_witness_public(statement["old_witness_public_key"], "old witness key"),
                               "old_witness_signature"),
                              (_witness_public(statement["new_witness_public_key"], "new witness key"),
                               "new_witness_signature")):
            if not verify(public, message, body.get(field) or ""):
                raise LedgerError(f"witness_rotated at {entry.seq}: {field} failed")

    def _verify_rotation_principal(self, seq: int, message: bytes, signature: str) -> None:
        """A rotation's principal signature. Before keys_upgraded, the principal was the Ed25519 half of today's
        key; a keys_upgraded entry later in the chain must vouch for that (``_check_classical_rotations``)."""
        if verify(self.public_key, message, signature):
            return
        if self._upgraded_at is None and self._is_classical_signature(message, signature):
            self._classical_rotations.append(seq)
            return
        raise LedgerError(f"witness_rotated at {seq}: principal_signature failed")

    def _is_classical_signature(self, message: bytes, signature: str) -> bool:
        old = self._classical_principal()
        return old is not None and verify(old, message, signature)

    def _is_ledger_principal(self, raw: str) -> bool:
        """Whether ``raw`` is this ledger's principal key, or the Ed25519 key it was upgraded from."""
        old = self._classical_principal()
        return raw == public_raw(self.public_key) or (old is not None and raw == public_raw(old))

    def _classical_principal(self):
        """The Ed25519 public key the principal signed with before the key upgrade, or None for an Ed25519
        principal (nothing to upgrade from)."""
        return classical_half(self.public_key) if is_hybrid(self.public_key) else None

    def _suite_keys(self, witness) -> tuple:
        """The principal private and public keys and the witness key this ledger signs with now: the Ed25519 halves
        while the upgrade is pending (the ledger is still Ed25519), else the keys as given."""
        if self.upgrade_pending:
            return classical_half(self.private_key), classical_half(self.public_key), classical_half(witness)
        return self.private_key, self.public_key, witness

    def _track_upgrade(self, entry: Entry, *, check: bool) -> None:
        """Move the principal suite and the witness pin for a ``keys_upgraded`` entry (see ``_track``)."""
        if check:
            self._verify_upgrade(entry)
        self._upgraded_at = entry.seq
        self.upgrade_pending = False
        self._classical_rotations.clear()
        self._witness_pin = (entry.body["new_witness_public_key"], entry.seq, "upgraded")

    def _verify_upgrade(self, entry: Entry) -> None:
        """A ``keys_upgraded`` entry read from disk: the only one, at its place in the chain, from Ed25519 to the
        hybrid suite, from the pinned witness, each new key the old key plus an ML-DSA-65 half, the new principal
        the one this ledger was opened with, and all four signatures good."""
        body = entry.body
        where = f"keys_upgraded at {entry.seq}"
        statement = self._upgrade_statement(entry, where)
        keys = {}
        for name in ("old_principal", "new_principal", "old_witness", "new_witness"):
            keys[name] = _witness_public(statement[f"{name}_public_key"], f"{where}: {name} key")
        for name in ("principal", "witness"):
            old, new = keys[f"old_{name}"], keys[f"new_{name}"]
            if is_hybrid(old) or not is_hybrid(new) or public_raw(classical_half(new)) != public_raw(old):
                raise LedgerError(f"{where}: the new {name} key is not the old one with an ML-DSA-65 half added")
        message = canonical_bytes(statement)
        for name, field in zip(("old_principal", "new_principal", "old_witness", "new_witness"), _UPGRADE_SIGNATURES):
            if not verify(keys[name], message, body.get(field) or ""):
                raise LedgerError(f"{where}: {field} failed")

    def _upgrade_statement(self, entry: Entry, where: str) -> dict:
        """The signed statement of a ``keys_upgraded`` entry, checked for its place, its suites and its keys."""
        try:
            statement = {k: entry.body[k] for k in _UPGRADE_FIELDS}
        except KeyError:
            raise LedgerError(f"{where} is malformed") from None
        if (statement["format"] != KEYS_UPGRADE_FORMAT or statement["seq"] != entry.seq
                or statement["prev"] != entry.prev):
            raise LedgerError(f"{where} does not belong at this place in the chain")
        if (self._upgraded_at is not None or statement["from_alg"] != CLASSICAL_ALG
                or statement["to_alg"] != HYBRID_ALG):
            raise LedgerError(f"{where}: a ledger moves from {CLASSICAL_ALG} to {HYBRID_ALG} once")
        if self._witness_pin is None or statement["old_witness_public_key"] != self._witness_pin[0]:
            raise LedgerError(f"{where} does not start from the pinned witness key")
        if statement["new_principal_public_key"] != public_raw(self.public_key):
            raise LedgerError(f"{where} names a principal key other than this ledger's")
        return statement

    def _witness_mismatch(self, raw: str) -> str | None:
        """What a witness public key fails to match: the pin in the ledger, then the configured pin."""
        if self._witness_pin is not None and raw != self._witness_pin[0]:
            return "the witness key pinned in the ledger"
        if self._configured_witness is not None and raw != self._configured_witness:
            return "the configured witness public key"
        return None

    def _check_witness(self, key, where: str) -> None:
        expected = self._witness_mismatch(public_raw(self._suite_keys(key)[2].public_key()))
        if expected:
            raise LedgerError(f"witness_key_changed: {where} does not match {expected}; restore that key, or "
                              "change it with rotate_witness")

    def _require_witness(self, *, writing: bool = False):
        """Load ``witness.pem`` for a write and refuse it if it is missing or does not match a pin. ``writing`` is
        a change only a ledger past any pending key upgrade may make."""
        if writing and self.upgrade_pending:
            raise LedgerError(KEYS_UPGRADE_PENDING)
        if not self.witness_path.exists():
            raise LedgerError("witness key missing; refusing to sign a head the principal key alone could forge")
        key = self._load_witness()
        self._check_witness(key, str(self.witness_path))
        return key

    def _pin_witness(self) -> None:
        """Write the ``witness_pinned`` entry and checkpoint. Caller holds the lock.

        A new ledger pins ``witness.pem``. A ledger with entries (made before 0.2.3) pins the key that signed
        its head, and only if ``witness.pem`` is that key.
        """
        self._check_witness(self._witness, str(self.witness_path))     # the configured pin, if any
        raw = public_raw(self._witness.public_key())
        body = {"witness_public_key": raw}
        if self.entries:
            if raw != self._head_witness:
                raise LedgerError(f"witness_key_changed: {self.witness_path} does not match the witness key that "
                                  "signed the head; refusing to pin it")
            body.update(source="first_use", head_size=len(self.entries))
        else:
            body["source"] = "new_ledger"
        self._append_unlocked("witness_pinned", body)
        self._checkpoint_unlocked(self._witness)

    @staticmethod
    def _hash(seq: int, prev: str, kind: str, body: dict) -> str:
        return canonical_hash({"seq": seq, "prev": prev, "kind": kind, "body": body})

    def append_bounded(self, kind: str, body: dict) -> Entry:
        """``append``, except that a body the canonical encoder refuses (nested too deeply, a type JSON has
        no form for) is still recorded. Only its short scalar fields (reason, jti, tool, allowed) are kept,
        plus the body's size and digest and the encoding error, so the entry is never silently lost."""
        try:
            return self.append(kind, body)
        except EncodingError as e:
            return self.append(kind, omitted_body(body, e))

    def append(self, kind: str, body: dict) -> Entry:
        if not isinstance(body, dict):
            raise LedgerError("ledger body must be an object")
        if kind in _WITNESS_KINDS:
            raise LedgerError(f"{kind} entries are written by the ledger itself; change the witness key with "
                              "rotate_witness, and upgrade the keys with upgrade_keys")
        if kind == "ledger_recovered":
            raise LedgerError("ledger_recovered entries are written by two-key recover")
        with self._exclusive():
            # Refuse before writing: an entry the next checkpoint cannot cover would keep the ledger from opening.
            self._require_witness()
            return self._append_unlocked(kind, body)

    def _append_unlocked(self, kind: str, body: dict) -> Entry:
        if self.upgrade_pending and kind not in ("keys_upgraded", "ledger_recovered"):
            raise LedgerError(KEYS_UPGRADE_PENDING)
        prev = self.entries[-1].entry_hash if self.entries else "0" * 64
        seq = len(self.entries)
        entry_hash = self._hash(seq, prev, kind, body)
        entry = Entry(seq, prev, kind, body, entry_hash)
        line = _seal(self._data_key, json.dumps(entry.to_json(), separators=(",", ":"), sort_keys=True))
        with self.entries_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self.entries.append(entry)
        self._merkle_add(bytes.fromhex(entry.entry_hash))
        self._note_entries_size()
        self._track(entry, verify=False)
        self._notify(entry)
        return entry

    def from_another_process(self, seq: int) -> bool:
        """True for an entry another process sharing this ledger appended after this one opened it. Its SIEM
        copy is that process's to send; one sent from here as well is marked ``replay`` (run 9y, F4)."""
        return seq in self._from_others

    def observe(self, callback) -> None:
        """Call ``callback(entry.seq)`` after each entry is written and fsynced.

        For the SIEM export (``two_key/siem.py``). It runs while this ledger holds its lock, so it must
        not block or raise: the one caller puts a number on a bounded queue. An exception is caught and
        reported, because a copy of an entry is never a reason to fail the append.
        """
        self._observers.append(callback)

    def _notify(self, entry: Entry) -> None:
        for callback in self._observers:
            try:
                callback(entry.seq)
            except Exception as e:      # the ledger is the record; the copy is best effort
                print(f"two-key: ledger observer failed: {type(e).__name__}", file=sys.stderr)

    def checkpoint(self) -> dict:
        with self._exclusive():
            return self._checkpoint_unlocked()

    def _checkpoint_unlocked(self, witness=None) -> dict:
        if witness is None:
            witness = self._require_witness()
        else:
            self._check_witness(witness, "the witness key")
        self._witness = witness
        principal, principal_public, witness_signer = self._suite_keys(witness)
        head = {
            "size": len(self.entries),
            "tip": self.entries[-1].entry_hash if self.entries else "0" * 64,
            "merkle_root": self.merkle_root(),
            "public_key": public_raw(principal_public),
            "witness_public_key": public_raw(witness_signer.public_key()),
        }
        signed = canonical_bytes(head)
        stored = dict(head)
        stored["signature"] = sign(principal, signed)
        stored["witness_signature"] = sign(witness_signer, signed)
        self._store_head(_seal(self._data_key, json.dumps(stored)) + "\n")
        self._head_witness = head["witness_public_key"]
        self._sync_anchor_forward()
        return stored

    def _store_head(self, text: str) -> None:
        """Write the head, fsync the file, replace it, then fsync the directory (#49).

        ``write_text`` does not fsync, so a kill after the temporary file was created and
        before the data reached disk could leave a stale ``head.json.tmp`` or a head that
        does not match what was signed. The name stays ``head.json.tmp``, which HOWTO tells
        an operator to delete after a crash.
        """
        tmp = self.head_path.with_suffix(".json.tmp")
        data = text.encode("utf-8")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _platform.O_BINARY, 0o666)
        try:
            view = memoryview(data)
            while view:
                wrote = os.write(fd, view)
                if wrote <= 0:
                    raise LedgerError("could not write the signed head")
                view = view[wrote:]
            os.fsync(fd)
        finally:
            os.close(fd)
        _platform.replace(tmp, self.head_path)
        _platform.fsync_dir(self.path)

    def _ledger_files_incomplete(self) -> bool:
        """True when a wiped directory would otherwise open as a new, empty ledger."""
        if not self.wrap_path.exists() or not self.head_path.exists() or not self.entries_path.exists():
            return True
        return self.entries_path.stat().st_size == 0

    def _rollback_message(self, size: int, anchor: dict) -> str:
        relation = "is behind" if size < anchor["size"] else "differs from"
        return (f"ledger_rolled_back: the signed head (size {size}) {relation} the anchor at "
                f"{self._anchor_path} (size {anchor['size']}). Restore the newer ledger and that anchor "
                "together. Deleting the anchor makes the next open accept the ledger as it stands; do not "
                "delete it to silence this.")

    def _read_anchor(self) -> dict | None:
        """The signed head anchor, or None when the file is absent.

        A present file that does not verify is a refusal, not an absence: treating a broken anchor as
        missing would adopt whatever ledger is on disk. The witness key in the file is the one that
        signed it, which may be older than the current pin when the anchor has not yet caught up. The
        head check, not this one, enforces the current witness pin.
        """
        path = self._anchor_path
        if not os.path.lexists(path):
            return None
        try:
            fd = _platform.open_nofollow(path)
        except OSError as e:
            raise LedgerError(f"head_anchor_unreadable: {path}: {e.strerror}") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise LedgerError(f"head_anchor_unreadable: {path} is not a regular file")
            problem = _platform.access_problem(fd, st)
            if problem:
                raise LedgerError(f"head_anchor_insecure: {_platform.insecure(path, problem)}")
            raw = os.read(fd, 64 * 1024 + 1)
        finally:
            os.close(fd)
        if len(raw) > 64 * 1024:
            raise LedgerError("head anchor is too large")
        try:
            stored = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise LedgerError("head anchor is not a two-key head anchor") from None
        if not isinstance(stored, dict) or stored.get("format") != ANCHOR_FORMAT:
            if isinstance(stored, dict) and _legacy(stored.get("format")):
                raise LedgerError(f"head anchor {LEGACY_MESSAGE}: start a new ledger")
            raise LedgerError("head anchor is not a two-key head anchor")
        try:
            body = {k: stored[k] for k in _ANCHOR_FIELDS}
        except KeyError:
            raise LedgerError("head anchor is not a two-key head anchor") from None
        if type(body["size"]) is not int or body["size"] < 0:
            raise LedgerError("head anchor size is not a valid count")
        for field in ("tip", "merkle_root", "public_key", "witness_public_key"):
            if type(body[field]) is not str:
                raise LedgerError("head anchor is not a two-key head anchor")
        principal = self._anchor_principal(body["public_key"])
        message = canonical_bytes(body)
        if not verify(principal, message, stored.get("signature") or ""):
            raise LedgerError("head anchor principal signature failed")
        witness_pub = _witness_public(body["witness_public_key"], "head anchor witness key")
        if not verify(witness_pub, message, stored.get("witness_signature") or ""):
            raise LedgerError("head anchor witness signature failed")
        return body

    def _anchor_principal(self, raw: str):
        """The key an anchor's principal signature is checked with: this ledger's, or, for an anchor from before
        the key upgrade, the Ed25519 key it was upgraded from (``_checked_anchor`` says when that is accepted)."""
        if not self._is_ledger_principal(raw):
            self._refuse_upgraded_from(raw)
            raise LedgerError("head anchor was signed by a different principal key")
        return self.public_key if raw == public_raw(self.public_key) else self._classical_principal()

    def _checked_anchor(self) -> dict | None:
        """The anchor, once the chain is read. One signed by the Ed25519 principal half is accepted only while the
        upgrade is pending, or when it is from before the upgrade and the ledger ends at the keys_upgraded entry
        (the upgrade stopped between its head and its anchor); else an Ed25519 forger could pass off an old anchor."""
        anchor = self._read_anchor()
        if anchor is None or anchor["public_key"] == public_raw(self.public_key) or self.upgrade_pending:
            return anchor
        if (self._upgraded_at is not None and anchor["size"] <= self._upgraded_at
                and len(self.entries) == self._upgraded_at + 1):
            return anchor
        raise LedgerError("head anchor was signed by the principal key from before the key upgrade, and the "
                          "ledger has moved on since; it is not this ledger's anchor")

    def _anchor_view(self) -> dict:
        _, principal_public, witness_signer = self._suite_keys(self._witness)
        witness_raw = self._head_witness or public_raw(witness_signer.public_key())
        return {
            "format": ANCHOR_FORMAT,
            "size": len(self.entries),
            "tip": self.entries[-1].entry_hash if self.entries else "0" * 64,
            "merkle_root": self.merkle_root(),
            "public_key": public_raw(principal_public),
            "witness_public_key": witness_raw,
        }

    def _write_anchor(self, body: dict) -> None:
        """Atomically replace the anchor with ``body``, signed by the principal and the current witness."""
        principal, _, witness_signer = self._suite_keys(self._witness)
        signed = canonical_bytes(body)
        stored = dict(body)
        stored["signature"] = sign(principal, signed)
        stored["witness_signature"] = sign(witness_signer, signed)
        parent = self._anchor_path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent == self.ledger_key_path.parent:
            _platform.owner_only_dir(parent)
        data = (json.dumps(stored, indent=2) + "\n").encode("utf-8")
        tmp = parent / f".head.anchor.{os.getpid()}.{os.urandom(4).hex()}.tmp"
        try:
            _write_new_secret(tmp, data)
            _platform.replace(tmp, self._anchor_path)
        finally:
            if os.path.lexists(tmp):
                os.unlink(tmp)
        _platform.fsync_dir(parent)

    def _reject_if_behind_anchor(self) -> None:
        anchor = self._checked_anchor()
        if anchor is None:
            return
        size = len(self.entries)
        tip = self.entries[-1].entry_hash if self.entries else "0" * 64
        root = self.merkle_root()
        if size < anchor["size"] or (size == anchor["size"] and (tip != anchor["tip"] or root != anchor["merkle_root"])):
            raise LedgerError(self._rollback_message(size, anchor))

    def _sync_anchor_forward(self) -> None:
        """Write the anchor when this head is newer. Never move it backwards. Caller holds the lock."""
        if not self.entries:
            return
        if self._head_witness is None:
            return
        current = self._anchor_view()
        existing = self._checked_anchor()
        if existing is not None:
            if existing["size"] > current["size"]:
                raise LedgerError(self._rollback_message(current["size"], existing))
            if existing["size"] == current["size"]:
                if (existing["tip"] != current["tip"] or existing["merkle_root"] != current["merkle_root"]):
                    raise LedgerError(self._rollback_message(current["size"], existing))
                return
        self._write_anchor(current)

    def _reopen(self) -> "Ledger":
        return Ledger(self.path, self.private_key, self._public_key_arg, witness_path=self.witness_path,
                      ledger_key_path=self.ledger_key_path, witness_public_key=self._witness_public_arg,
                      anchor_path=self._anchor_path)

    @classmethod
    def recover_tail(cls, path: Path | str, private_key, public_key=None, *,
                     witness_path: Path | str | None = None, ledger_key_path: Path | str | None = None,
                     witness_public_key=None, anchor_path: Path | str | None = None) -> dict:
        """Drop only the bytes after the signed head, then record that fact.

        Refuses when the signed prefix itself does not verify, when the head is behind the anchor (that is
        a rollback, not a crash), or when ``entries.jsonl`` or ``head.json`` is missing. Does not run on
        open. The dropped ciphertext is copied to ``<ledger>.recovery/`` before it is truncated. The ledger
        entry names the size and digest of that ciphertext, not its plaintext.
        """
        path = Path(path)
        if not (path / "entries.jsonl").is_file() or not (path / "head.json").is_file():
            raise LedgerError("recovery refused: entries.jsonl and head.json must both be present; "
                              "this is not an uncheckpointed tail")
        if not (path / "keywrap.json").is_file():
            raise LedgerError("recovery refused: keywrap.json is missing; refusing to create a new data key")
        led = cls(path, private_key, public_key, witness_path=witness_path, ledger_key_path=ledger_key_path,
                  witness_public_key=witness_public_key, anchor_path=anchor_path, _load=False)
        return led._recover_tail()

    def _signed_prefix(self, raw: bytes, head_text: str):
        """Bytes of ``entries.jsonl`` that the signed head covers, and the tail after them."""
        try:
            stored = json.loads(_open(self._data_key, head_text))
        except LedgerError as e:
            raise LedgerError(f"recovery refused: the signed head does not decrypt ({e})") from None
        try:
            body = {k: stored[k] for k in ("size", "tip", "merkle_root", "public_key", "witness_public_key")}
        except (TypeError, KeyError):
            raise LedgerError("recovery refused: the signed head is malformed") from None
        message = canonical_bytes(body)
        if not verify(public_from_raw(body["public_key"]), message, stored.get("signature") or ""):
            raise LedgerError("recovery refused: principal head signature failed")
        if not verify(public_from_raw(body["witness_public_key"]), message, stored.get("witness_signature") or ""):
            raise LedgerError("recovery refused: witness head signature failed")
        if not self._is_ledger_principal(body["public_key"]):
            raise LedgerError("recovery refused: head principal public key does not match this ledger's principal key")
        if type(body["size"]) is not int or isinstance(body["size"], bool) or body["size"] < 1:
            raise LedgerError("recovery refused: the signed head does not cover any entry; refusing to clear the file")
        lines = raw.splitlines(keepends=True)
        if sum(len(line) for line in lines) != len(raw):
            raise LedgerError("recovery refused: could not account for every byte of entries.jsonl")
        kept = 0
        count = 0
        prev = "0" * 64
        leaves: list[bytes] = []
        target = body["size"]
        for line in lines:
            if count == target:
                break
            kept += len(line)
            stripped = line.strip()
            if not stripped:
                continue
            try:
                opened = _open(self._data_key, stripped.decode("utf-8"))
                entry_raw = json.loads(opened)
                entry = Entry(entry_raw["seq"], entry_raw["prev"], entry_raw["kind"], entry_raw["body"],
                              entry_raw["entry_hash"])
            except (LedgerError, EncodingError, UnicodeDecodeError, ValueError, KeyError):
                raise LedgerError("recovery refused: a record the signed head covers does not decrypt or chain. "
                                  "This is not a trailing tail; the file was not changed.") from None
            expect = self._hash(entry.seq, entry.prev, entry.kind, entry.body)
            if entry.entry_hash != expect or entry.prev != prev or entry.seq != count:
                raise LedgerError("recovery refused: a record the signed head covers does not decrypt or chain. "
                                  "This is not a trailing tail; the file was not changed.")
            leaves.append(bytes.fromhex(entry.entry_hash))
            prev = entry.entry_hash
            count += 1
        if count != target or prev != body["tip"] or merkle_root(leaves).hex() != body["merkle_root"]:
            raise LedgerError("recovery refused: the entries end before the signed head, or do not match it. "
                              "Refusing to move the head backwards. The file was not changed.")
        tail = raw[kept:]
        nonempty = [ln for ln in tail.splitlines() if ln.strip()]
        torn = False
        for ln in nonempty:
            try:
                _open(self._data_key, ln.decode("utf-8"))
            except (LedgerError, UnicodeDecodeError):
                torn = True
                break
        return kept, tail, body, len(nonempty), torn

    def _recover_tail(self) -> dict:
        raw = self.entries_path.read_bytes()
        head_text = self.head_path.read_text(encoding="utf-8")
        kept, tail, head, tail_lines, tail_torn = self._signed_prefix(raw, head_text)
        anchor = self._read_anchor()
        if anchor is not None and (
                head["size"] < anchor["size"] or (head["size"] == anchor["size"] and (
                    head["tip"] != anchor["tip"] or head["merkle_root"] != anchor["merkle_root"]))):
            raise LedgerError(self._rollback_message(head["size"], anchor)
                              + " recover will not roll the anchor back.")
        if head["witness_public_key"] not in (public_raw(self._witness.public_key()),
                                              public_raw(classical_half(self._witness).public_key())):
            raise LedgerError("recovery refused: witness.pem does not match the signed head; the file was not changed")
        if self._configured_witness is not None and head["witness_public_key"] != self._configured_witness:
            raise LedgerError("witness_key_changed: the head is signed by a witness key other than the configured "
                              "witness public key; the file was not changed")
        tmp = self.head_path.with_suffix(".json.tmp")
        if not tail.strip():
            removed_tmp = False
            if os.path.lexists(tmp) and not tmp.is_symlink():
                os.unlink(tmp)
                removed_tmp = True
            opened = self._reopen()
            return {"changed": False, "removed_head_tmp": removed_tmp, "size": opened.size(),
                    "dropped_bytes": 0}
        digest = hashlib.sha256(tail).hexdigest()
        dest_dir = self.path.parent / f"{self.path.name}.recovery"
        if _platform.inside(dest_dir, self.path):
            raise LedgerError("recovery notes must live outside the ledger directory")
        dest_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        _platform.owner_only_dir(dest_dir)
        dest = dest_dir / f"dropped-{digest[:16]}.bin"
        if not os.path.lexists(dest):
            _write_new_secret(dest, tail)
        with self._exclusive(check_stale=False):
            if self.entries_path.read_bytes() != raw:
                raise LedgerError("ledger changed during recovery; stop other writers and run recover again")
            fd = _platform.open_nofollow(self.entries_path, os.O_RDWR)
            try:
                os.ftruncate(fd, kept)
                os.fsync(fd)
            finally:
                os.close(fd)
            if os.path.lexists(tmp) and not tmp.is_symlink():
                os.unlink(tmp)
            _platform.fsync_dir(self.path)
        body = {"dropped_bytes": len(tail), "dropped_sha256": "sha256:" + digest,
                "dropped_nonempty_lines": tail_lines, "tail_torn": tail_torn,
                "head_size": head["size"], "tail_file": str(dest)}
        opened = self._reopen()
        if opened.size() != head["size"]:
            raise LedgerError("ledger changed during recovery; stop other writers and run recover again")
        with opened._exclusive():
            opened._require_witness()
            entry = opened._append_unlocked("ledger_recovered", body)
            opened._checkpoint_unlocked()
        return {"changed": True, "seq": entry.seq, "size": opened.size(), **body}

    def _merkle_add(self, leaf: bytes) -> None:
        self._merkle_roots.append(_merkle_push(self._merkle_ranges, leaf).hex())

    def rotate_witness(self, new_witness: HybridPrivateKey | None = None, *, reason: str = "") -> dict:
        """Replace the witness key with ``new_witness`` (a new key when omitted), as a ledgered change.

        Writes a ``witness_rotated`` entry signed by the principal, the current ``witness.pem``, and the new
        key, then a head signed by the new key, then moves the new key into ``witness.pem`` (and its public
        half into ``witness.pub.pem``). The new key is staged first as ``witness.pem.new``. If the rotation
        stops after the head is written and before the move, the ledger refuses to open with
        ``witness_key_changed`` until ``witness.pem.new`` is moved to ``witness.pem``.

        If the head cannot be written after the entry is, the staged key stays and the ledger will not open
        until the entry is removed, as after a crash. ``witness_public_key_path`` in the result is None if
        ``witness.pub.pem`` could not be written; the next open writes it.

        An out-of-ledger pin given to this ``Ledger`` follows the rotation in memory only. Update the stored
        pin (the operator's copy of the witness public key) before the next open.
        """
        if new_witness is None:
            new_witness = generate_private_key()
        if not isinstance(new_witness, HybridPrivateKey):
            raise LedgerError("the new witness key must be a hybrid Ed25519 + ML-DSA-65 private key")
        if not isinstance(reason, str) or len(reason) > _KEEP_CHARS:
            raise LedgerError(f"reason must be a string of at most {_KEEP_CHARS} characters")
        staged = self.witness_path.with_name(self.witness_path.name + ".new")
        with self._exclusive():
            old = self._require_witness(writing=True)
            old_raw, new_raw = public_raw(old.public_key()), public_raw(new_witness.public_key())
            if new_raw == old_raw:
                raise LedgerError("witness_rotation_refused: the new witness key is the current one")
            if new_raw == public_raw(self.public_key):
                raise LedgerError("witness_rotation_refused: the witness key must not be the principal key")
            statement = {"format": WITNESS_ROTATION_FORMAT, "seq": len(self.entries),
                         "prev": self.entries[-1].entry_hash if self.entries else "0" * 64,
                         "old_witness_public_key": old_raw, "new_witness_public_key": new_raw, "reason": reason}
            message = canonical_bytes(statement)
            body = {**statement, "principal_signature": sign(self.private_key, message),
                    "old_witness_signature": sign(old, message), "new_witness_signature": sign(new_witness, message)}
            if not verify(self.public_key, message, body["principal_signature"]):
                raise LedgerError("witness_rotation_refused: the principal private key does not match this "
                                  "ledger's principal public key")
            try:
                save_private_key(staged, new_witness)
            except FileExistsError:
                raise LedgerError(f"witness_rotation_refused: {staged} exists, left by an interrupted rotation; "
                                  "see HOWTO \"Rotate the witness key\"") from None
            try:
                self._append_unlocked("witness_rotated", body)
            except BaseException:
                os.unlink(staged)
                raise
            configured = self._configured_witness
            if configured is not None:
                self._configured_witness = new_raw
            try:
                self._checkpoint_unlocked(new_witness)
            except Exception as e:
                # The entry is on disk and the head does not cover it: the same state as a crash here. The
                # staged key stays so the files match HOWTO "Rotate the witness key".
                self._configured_witness = configured
                raise LedgerError(f"witness_rotated was written but no head covers it ({cap_ledger_text(f'{type_tag(e)}: {e}')}); the ledger "
                                  "will not open until that entry is removed (HOWTO \"If the ledger will not open "
                                  f"after a crash\"); then delete {staged}") from e
            try:
                _platform.replace(staged, self.witness_path)
            except OSError as e:
                raise LedgerError(f"witness rotated in the ledger, but {staged} could not be moved to "
                                  f"{self.witness_path} ({e.strerror}); move it by hand") from None
            written = self._sync_witness_public()
        return {"seq": statement["seq"], "old_witness_key_fingerprint": witness_key_fingerprint(old_raw),
                "new_witness_key_fingerprint": witness_key_fingerprint(new_raw),
                "witness_public_key_path": str(self.witness_path.with_suffix(".pub.pem")) if written else None}

    def upgrade_keys(self, new_principal: HybridPrivateKey | None = None, *,
                     capability_key_fingerprint: str | None = None, stamp_key_fingerprint: str | None = None) -> dict:
        """Record the key upgrade (0.9.0, ``two_key/upgrade.py``).

        Writes a ``keys_upgraded`` entry: the old (Ed25519) and new (hybrid) principal and witness keys and the
        new capability and stamp key fingerprints, signed by all four keys, then a head and an anchor signed by
        the new keys. ``witness.pem`` is already hybrid. A ledger opened with the 0.8.0 principal key takes the
        hybrid key made from it as ``new_principal``; one opened with the hybrid key (``upgrade_pending``)
        needs none. The fingerprints are those of the hybrid capability and stamp keys on disk, None for one
        this deployment does not have. If the head cannot be written after the entry is, the ledger will not
        open until the entry is removed, as after a crash. An out-of-ledger witness pin follows the upgrade in
        memory only; the operator replaces it with ``witness.pub.pem``.
        """
        with self._exclusive():
            if new_principal is not None and not self.upgrade_pending:
                self._adopt_upgraded_principal(new_principal)
            if not self.upgrade_pending:
                raise LedgerError("keys_upgrade_refused: this ledger is not waiting for a key upgrade")
            witness = self._require_witness()
            if not is_hybrid(witness) or not isinstance(self.private_key, HybridPrivateKey):
                raise LedgerError("keys_upgrade_refused: the principal and witness key files must be hybrid first")
            statement = {"format": KEYS_UPGRADE_FORMAT, "seq": len(self.entries),
                         "prev": self.entries[-1].entry_hash if self.entries else "0" * 64,
                         "from_alg": CLASSICAL_ALG, "to_alg": HYBRID_ALG,
                         "old_principal_public_key": public_raw(classical_half(self.public_key)),
                         "new_principal_public_key": public_raw(self.public_key),
                         "old_witness_public_key": self._witness_pin[0],
                         "new_witness_public_key": public_raw(witness.public_key()),
                         "capability_key_fingerprint": capability_key_fingerprint,
                         "stamp_key_fingerprint": stamp_key_fingerprint}
            message = canonical_bytes(statement)
            signers = (classical_half(self.private_key), self.private_key, classical_half(witness), witness)
            body = {**statement, **{field: sign(key, message) for field, key in zip(_UPGRADE_SIGNATURES, signers)}}
            # The check a later open makes, before anything is written: a wrong key stops here.
            self._verify_upgrade(Entry(statement["seq"], statement["prev"], "keys_upgraded", body, ""))
            self._append_unlocked("keys_upgraded", body)
            configured = self._configured_witness
            if configured is not None:
                self._configured_witness = statement["new_witness_public_key"]
            try:
                self._checkpoint_unlocked(witness)
            except Exception as e:
                self._configured_witness = configured
                raise LedgerError(f"keys_upgraded was written but no head covers it "
                                  f"({cap_ledger_text(f'{type_tag(e)}: {e}')}); the ledger will not open until that "
                                  "entry is removed (HOWTO \"If the ledger will not open after a crash\"); then "
                                  "run two-key keys upgrade again") from e
            self._sync_witness_public()
        return {"seq": statement["seq"],
                "principal_key_fingerprint": witness_key_fingerprint(statement["new_principal_public_key"]),
                "witness_key_fingerprint": witness_key_fingerprint(statement["new_witness_public_key"])}

    def _adopt_upgraded_principal(self, new_principal) -> None:
        """Take the hybrid key made from this ledger's 0.8.0 principal key; the upgrade is then pending."""
        if (self._upgraded_at is not None or is_hybrid(self.public_key) or not is_hybrid(new_principal)
                or public_raw(classical_half(new_principal).public_key()) != public_raw(self.public_key)):
            raise LedgerError("keys_upgrade_refused: the new principal key is not this ledger's 0.8.0 principal key "
                              "with an ML-DSA-65 half added")
        self.private_key, self.public_key = new_principal, new_principal.public_key()
        self._public_key_arg = None
        self.upgrade_pending = True

    def _verify_head(self) -> None:
        if not self.entries:
            return
        if not self.head_path.exists():
            raise LedgerError("ledger has entries but no signed head")
        stored = json.loads(_open(self._data_key, self.head_path.read_text(encoding="utf-8")))
        body = {k: stored[k] for k in ("size", "tip", "merkle_root", "public_key", "witness_public_key")}
        message = canonical_bytes(body)
        if not verify(public_from_raw(body["public_key"]), message, stored.get("signature") or ""):
            raise LedgerError("principal head signature failed")
        if not verify(public_from_raw(body["witness_public_key"]), message, stored.get("witness_signature") or ""):
            raise LedgerError("witness head signature failed")
        self._check_head_principal(body["public_key"], body["size"])
        if body["size"] != len(self.entries) or body["tip"] != self.entries[-1].entry_hash:
            raise LedgerError("signed head does not match the chain")
        if body["merkle_root"] != self.merkle_root():
            raise LedgerError("signed head merkle root mismatch")
        # After the chain checks, so an entry the head does not cover (a crash before a checkpoint, including
        # a rotation's) reports as that, and the pin compared is the one the head covers.
        expected = self._witness_mismatch(body["witness_public_key"])
        if expected:
            raise LedgerError(f"witness_key_changed: the head is signed by a witness key other than {expected}")
        self._head_witness = body["witness_public_key"]

    def _check_head_principal(self, raw: str, size) -> None:
        """The signed head's principal is this ledger's key, or (``_head_from_other_suite``) the Ed25519 key it was
        upgraded from; and no rotation signed by that Ed25519 key is left without a keys_upgraded after it."""
        if raw != public_raw(self.public_key):
            self._head_from_other_suite(raw, size)
        if self._classical_rotations and not self.upgrade_pending:
            raise LedgerError(f"ledger chain failed verification: witness_rotated at {self._classical_rotations[0]} "
                              "is signed by the Ed25519 half of the principal key, and no keys_upgraded entry "
                              "follows it")

    def _head_from_other_suite(self, raw: str, size) -> None:
        """A head whose principal is not this ledger's key. Signed by the Ed25519 half of this hybrid key, before
        any keys_upgraded entry: the upgrade is pending. One from before a keys_upgraded entry it does not cover
        (the upgrade stopped before its head) is left to the chain check, which says so. Anything else is
        refused, and a 0.8.0 key on a ledger that has been upgraded is told so."""
        old = self._classical_principal()
        if old is not None and raw == public_raw(old):
            if self._upgraded_at is None:
                self.upgrade_pending = True
                return
            if type(size) is int and size <= self._upgraded_at:
                return
        self._refuse_upgraded_from(raw)
        raise LedgerError("head principal public key does not match this ledger's principal key")

    def _refuse_upgraded_from(self, raw) -> None:
        """Refuse with ``keys_upgraded`` when this ledger was opened with the 0.8.0 key that ``raw`` (a signed
        head's or anchor's principal) was upgraded from: there is no way back to Ed25519 alone."""
        try:
            signer = public_from_raw(raw)
        except (TypeError, ValueError):
            return
        if (not is_hybrid(self.public_key) and is_hybrid(signer)
                and public_raw(classical_half(signer)) == public_raw(self.public_key)):
            raise LedgerError("keys_upgraded: this ledger's keys were upgraded to hybrid Ed25519 + ML-DSA-65, and "
                              "the 0.8.0 principal key is refused; use the upgraded principal key file")

    def merkle_root(self, size: int | None = None) -> str:
        n = len(self.entries) if size is None else size
        if n == 0:
            return hashlib.sha256(b"empty").hexdigest()
        if not isinstance(n, int) or isinstance(n, bool) or n < 0 or n > len(self._merkle_roots):
            raise LedgerError("merkle size is outside this ledger")
        return self._merkle_roots[n - 1]

    def size(self) -> int:
        return len(self.entries)

    def is_redeemed(self, jti: str) -> bool:
        return jti in self._redeemed

    def redemption_started(self, jti: str) -> bool:
        return jti in self._started and jti not in self._redeemed

    def tool_held(self, tool: str) -> bool:
        """True while ``tool`` is held: a ``tool_held`` entry with no ``tool_released`` after it (#28)."""
        return tool in self._held

    def held_tools(self) -> list[str]:
        return sorted(self._held)

    def last_before(self, size: int, kind: str) -> Entry | None:
        """The last entry of ``kind`` with ``seq`` below ``size``, or None.

        ``size`` is a ledger length, the same number a token carries. This does not copy the entry list.
        """
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            return None
        seqs = self._kind_seqs.get(kind)
        if not seqs:
            return None
        lo, hi = 0, len(seqs)
        while lo < hi:
            mid = (lo + hi) // 2
            if seqs[mid] < size:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            return None
        return self.entries[seqs[lo - 1]]

    def kinds_after(self, size: int, kinds: set[str]) -> list[Entry]:
        """Entries at or after ``size`` whose kind is in ``kinds``, in ledger order."""
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            return [e for e in self.entries[size:] if e.kind in kinds]
        found = []
        for kind in kinds:
            seqs = self._kind_seqs.get(kind, ())
            lo, hi = 0, len(seqs)
            while lo < hi:
                mid = (lo + hi) // 2
                if seqs[mid] < size:
                    lo = mid + 1
                else:
                    hi = mid
            found.extend(self.entries[seq] for seq in seqs[lo:])
        found.sort(key=lambda e: e.seq)
        return found

    def verify(self) -> dict:
        """Check the chain and the signed head, and return ``witness_report()``. Raises ``LedgerError``."""
        prev = "0" * 64
        for i, entry in enumerate(self.entries):
            if entry.seq != i or entry.prev != prev:
                raise LedgerError(f"chain break at {i}")
            if entry.entry_hash != self._hash(entry.seq, entry.prev, entry.kind, entry.body):
                raise LedgerError(f"hash mismatch at {i}")
            prev = entry.entry_hash
        self._verify_head()
        return self.witness_report()

    def witness_report(self) -> dict:
        """Both witness pins, as fingerprints (``sha256:`` of the raw public key).

        ``head``: the key that signed the verified head. ``in_ledger``: the key pinned in the ledger, the
        entry that pinned it, and how (``new_ledger``, ``first_use``, or ``rotated``). ``configured``: the
        out-of-ledger pin, or None when none was given. ``history``: every pin entry
        (``two_key.audit.witness_pins``).
        """
        from .audit import witness_pins
        pin = self._witness_pin
        return {
            "head": None if self._head_witness is None else witness_key_fingerprint(self._head_witness),
            "in_ledger": None if pin is None else {"fingerprint": witness_key_fingerprint(pin[0]),
                                                   "seq": pin[1], "source": pin[2]},
            "configured": (None if self._configured_witness is None
                           else witness_key_fingerprint(self._configured_witness)),
            "history": witness_pins(self),
        }
