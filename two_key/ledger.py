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
import heapq
import json
import os
import shutil
import stat
import sys
import threading
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import _platform
from . import ledger_archive as archive
from .canonical import EncodingError, canonical_bytes, canonical_hash
from .agent_meta import cap_ledger_text, type_tag
from .keys import (
    CLASSICAL_ALG, ED_PUB_BYTES, HYBRID_ALG, HybridPrivateKey, HybridPublicKey, classical_half, generate_private_key,
    is_hybrid, load_private_key_file, load_public_key, public_from_raw, public_key, public_raw, save_private_key,
    save_public_key, sign, verify,
)

WRAP_FORMAT = "two-key-ledger-wrap/1"
# Records were hex (enc/1) until 0.9.1; they are written in base64 (enc/2) now, a third smaller. Both are read.
RECORD_FORMAT_HEX = "two-key-ledger-enc/1"
RECORD_FORMAT = "two-key-ledger-enc/2"
ANCHOR_FORMAT = "two-key-head-anchor/1"
_WRAP_INFO = b"two-key-ledger-wrap/1"
_RECORD_AAD = {RECORD_FORMAT_HEX: b"two-key-ledger-enc/1", RECORD_FORMAT: b"two-key-ledger-enc/2"}


LEDGER_KEY_BYTES = 32

WITNESS_ROTATION_FORMAT = "two-key-witness-rotation/1"
KEYS_UPGRADE_FORMAT = "two-key-keys-upgraded/1"
# How a hold ended, in tool_released ``by`` (0.9.0, #10). Entries written before 0.9.0 have no ``by``.
RELEASED_BY_EXPIRY = "expiry"
RELEASED_BY_PRINCIPAL = "principal"
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
_ROLLOVER_KINDS = frozenset({"ledger_sealed", "ledger_continued"})
SEALED_FORMAT = "two-key-ledger-sealed/1"
CONTINUED_FORMAT = "two-key-ledger-continued/1"
# The ledger rolls over into sealed segments and archives (0.9.1; two_key/ledger_archive.py, docs/HOWTO.md).
MAX_CARRIED_TOKENS = 4096
ROLLOVER_RETRY_SECONDS = 60
REDEEM_LOCK_AGE_SECONDS = 300           # capability.MAX_TTL_SECONDS: no token lives longer
_CARRY_SECONDS = 305                    # MAX_TTL_SECONDS and capability.MAX_CLOCK_SKEW_SECONDS
_HOLD_KINDS = ("tool_receipt_invalid", "redemption", "tool_held", "tool_released")
_SPENT_KINDS = ("redemption_started", "redemption", "redemption_aborted")
ARCHIVED = "ledger_size_archived"
_ANCHOR_FIELDS = ("format", "size", "tip", "merkle_root", "public_key", "witness_public_key")
# The signed statement of a witness_rotated entry; the entry body is these plus the three signatures.
_ROTATION_FIELDS = ("format", "seq", "prev", "old_witness_public_key", "new_witness_public_key", "reason")
# The signed statement of a keys_upgraded entry; the entry body is these plus the four signatures.
_UPGRADE_FIELDS = ("format", "seq", "prev", "from_alg", "to_alg", "old_principal_public_key",
                   "new_principal_public_key", "old_witness_public_key", "new_witness_public_key",
                   "capability_key_fingerprint", "stamp_key_fingerprint")
_UPGRADE_SIGNATURES = ("old_principal_signature", "new_principal_signature", "old_witness_signature",
                       "new_witness_signature")


_SHA256 = "sha256:"      # the prefix of a digest, and of a 0.8.0 Ed25519 key's fingerprint


def witness_key_fingerprint(raw: str) -> str:
    """The fingerprint of a raw witness public key (the base64 form the head carries): ``hybrid-sha256:`` for a
    hybrid key, ``sha256:`` for a 0.8.0 Ed25519 key, then the hex SHA-256 (``keys.key_fingerprint``)."""
    data = base64.b64decode(raw)
    return (_SHA256 if len(data) == ED_PUB_BYTES else "hybrid-sha256:") + hashlib.sha256(data).hexdigest()


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


_HEX64 = frozenset("0123456789abcdef")


def _is_hash(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX64


def _ranges(raw, size: int) -> list[tuple[int, bytes]]:
    """A Merkle compact range from a ``ledger_continued`` or ``ledger_sealed`` body: complete subtrees, largest
    first, each a power of two, adding up to ``size``."""
    ranges = []
    for item in raw:
        n, node = item
        if type(n) is not int or n < 1 or n & (n - 1) or not _is_hash(node) or (ranges and n >= ranges[-1][0]):
            raise ValueError("merkle_range is not a compact range")
        ranges.append((n, bytes.fromhex(node)))
    if sum(n for n, _ in ranges) != size:
        raise ValueError("merkle_range does not cover the sealed entries")
    return ranges


_META_FIELDS = {"segment": int, "name": str, "first_seq": int, "last_seq": int, "last_hash": str, "sealed_at": int,
                "bytes": int, "sha256": str, "plain_bytes": int, "compression": str}


def _catalogue(raw, seal_seq: int, seal_hash: str) -> list[dict]:
    """The archive catalogue: segments 1, 2, … with seq ranges that meet, the last ending at the seal."""
    if not isinstance(raw, list) or not raw:
        raise ValueError("catalogue is empty")
    first = 0
    for number, meta in enumerate(raw, start=1):
        if not isinstance(meta, dict) or any(type(meta.get(k)) is not t for k, t in _META_FIELDS.items()):
            raise ValueError(f"catalogue entry {number} is malformed")
        if (meta["segment"] != number or meta["name"] != archive.archive_name(number) or meta["first_seq"] != first
                or meta["last_seq"] < first or not _is_hash(meta["last_hash"])
                or meta["compression"] not in archive.COMPRESSIONS or meta["bytes"] < 1 or meta["plain_bytes"] < 1):
            raise ValueError(f"catalogue entry {number} does not follow the one before")
        first = meta["last_seq"] + 1
    if raw[-1]["last_seq"] != seal_seq or raw[-1]["last_hash"] != seal_hash:
        raise ValueError("the catalogue does not end at the seal")
    return raw


def _entry_from(raw) -> Entry:
    """An entry from its JSON form, its hash checked against its fields."""
    entry = Entry(raw["seq"], raw["prev"], raw["kind"], raw["body"], raw["entry_hash"])
    if (type(entry.seq) is not int or not isinstance(entry.kind, str) or not isinstance(entry.body, dict)
            or not _is_hash(entry.prev) or entry.entry_hash != Ledger._hash(entry.seq, entry.prev, entry.kind,
                                                                              entry.body)):
        raise ValueError(f"the entry at {raw.get('seq')!r} is not a ledger entry")
    return entry


_TOKEN_FIELDS = ("jti", "token_hash", "ledger_size", "ledger_root", "capability_key_fingerprint", "issued_at")


def _token_record(raw) -> dict:
    """A carried token from ``ledger_continued``."""
    if not isinstance(raw, dict) or set(raw) != set(_TOKEN_FIELDS):
        raise ValueError("a carried token is malformed")
    if (not isinstance(raw["jti"], str) or not isinstance(raw["token_hash"], str) or type(raw["ledger_size"]) is not int
            or not isinstance(raw["ledger_root"], str) or type(raw["issued_at"]) is not int
            or not (raw["capability_key_fingerprint"] is None or isinstance(raw["capability_key_fingerprint"], str))):
        raise ValueError("a carried token is malformed")
    return dict(raw)


def _entry_time(entry) -> float | None:
    """The time an entry records in ``at``: whole seconds, or the text decisions write. None when it has none."""
    at = entry.body.get("at") if isinstance(entry.body, dict) else None
    if type(at) is int:
        return float(at)
    if isinstance(at, str):
        from .history import parse_time
        return parse_time(at)
    return None


def _whole_time(at: float | None) -> int | None:
    return None if at is None else int(at)


def _kek(ledger_key: bytes) -> bytes:
    if len(ledger_key) != 32:
        raise LedgerError("ledger key must be 32 bytes")
    return HKDF(SHA256(), 32, salt=b"two-key-ledger", info=_WRAP_INFO).derive(ledger_key)


def _seal(data_key: bytes, plaintext: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(data_key).encrypt(nonce, plaintext.encode("utf-8"), _RECORD_AAD[RECORD_FORMAT])
    return json.dumps({"enc": RECORD_FORMAT, "n": base64.b64encode(nonce).decode("ascii"),
                       "c": base64.b64encode(ct).decode("ascii")}, separators=(",", ":"))


def _record_bytes(fmt: str, text) -> bytes:
    if not isinstance(text, str):
        raise ValueError("not text")
    if fmt == RECORD_FORMAT_HEX:
        return bytes.fromhex(text)
    return base64.b64decode(text, validate=True)


def _open(data_key: bytes, record: str) -> str:
    try:
        blob = json.loads(record)
        fmt = blob.get("enc")
        if fmt not in _RECORD_AAD:
            raise LedgerError("ledger record is not encrypted")
        return AESGCM(data_key).decrypt(
            _record_bytes(fmt, blob["n"]), _record_bytes(fmt, blob["c"]), _RECORD_AAD[fmt]).decode("utf-8")
    except LedgerError:
        raise
    except Exception as e:      # binascii.Error, a bad tag, a missing field: all the same refusal
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
            "body_digest": None if data is None else _SHA256 + hashlib.sha256(data).hexdigest(),
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


def _whole_in(value, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


@dataclass(frozen=True)
class RolloverSettings:
    """When the ledger seals its active segment into an archive (proxy.yaml ``ledger_rollover``, docs/SETTINGS.md).

    ``segment_mb``: seal once the active segment's file reaches this size. ``segment_days``: also seal once its first
    entry is this old (0 is off). ``hard_limit_mb``: past this size, a rollover that was put off must run before
    another token is issued (``Ledger.over_hard_limit``); the default is twice ``segment_mb``. ``compression``: zlib,
    or none (still encrypted and chunked). ``keep_archives``: all; nothing deletes an archive.
    """
    enabled: bool = True
    segment_mb: int = 64
    segment_days: int = 0
    hard_limit_mb: int | None = None
    compression: str = "zlib"
    keep_archives: str = "all"

    def __post_init__(self):
        if type(self.enabled) is not bool:
            raise ValueError("ledger_rollover.enabled must be true or false")
        if not _whole_in(self.segment_mb, 8, 1024):
            raise ValueError("ledger_rollover.segment_mb must be a whole number from 8 to 1024")
        if not _whole_in(self.segment_days, 0, 3650):
            raise ValueError("ledger_rollover.segment_days must be a whole number from 0 (off) to 3650")
        if self.hard_limit_mb is not None and not _whole_in(self.hard_limit_mb, self.segment_mb, 4096):
            raise ValueError("ledger_rollover.hard_limit_mb must be a whole number from segment_mb to 4096")
        if self.compression not in archive.COMPRESSIONS:
            raise ValueError("ledger_rollover.compression must be zlib or none")
        if self.keep_archives != "all":
            raise ValueError("ledger_rollover.keep_archives must be all (archives are never deleted)")

    @property
    def segment_bytes(self) -> int:
        return self.segment_mb * 1024 * 1024

    @property
    def hard_limit_bytes(self) -> int:
        return (self.hard_limit_mb if self.hard_limit_mb is not None else 2 * self.segment_mb) * 1024 * 1024

    @classmethod
    def or_default(cls, settings: "RolloverSettings | None") -> "RolloverSettings":
        """``settings``, or the defaults when it is None."""
        return cls() if settings is None else settings

    @classmethod
    def from_mapping(cls, block) -> "RolloverSettings":
        """The ``ledger_rollover:`` block of proxy.yaml. An unknown key or a value out of range is refused."""
        if block is None:
            return cls()
        if not isinstance(block, dict):
            raise ValueError("ledger_rollover must be a mapping")
        unknown = sorted(set(block) - ROLLOVER_KEYS)
        if unknown:
            raise ValueError(f"ledger_rollover: unknown key {unknown[0]!r}")
        return cls(**block)


_OUTSIDE = "seq outside the ledger"

# How much of the entries file's first record identifies the file: past the first record's nonce in either format.
_FILE_ID_BYTES = 96

# The keys of proxy.yaml's ``ledger_rollover:`` block (RolloverSettings.from_mapping, tests/test_settings_doc.py).
ROLLOVER_KEYS = frozenset({"enabled", "segment_mb", "segment_days", "hard_limit_mb", "compression", "keep_archives"})


class _EntryView(Sequence):
    """``Ledger.entries``: every entry by its global ``seq``, archived or active. Indexing and iterating the active
    segment reads memory; anything before it streams the archive that holds it (``Ledger.iter_entries``)."""

    def __init__(self, ledger: "Ledger"):
        self._ledger = ledger

    def __len__(self) -> int:
        return self._ledger.size()

    def __bool__(self) -> bool:
        return self._ledger.size() > 0

    def __getitem__(self, index):
        ledger = self._ledger
        size = ledger.size()
        if isinstance(index, slice):
            start, stop, step = index.indices(size)
            if step != 1:
                return list(ledger.iter_entries(start, stop))[::step]
            return list(ledger.iter_entries(start, stop))
        if isinstance(index, bool) or not isinstance(index, int):
            raise TypeError("ledger entries are indexed by seq")
        if index < 0:
            index += size
        if not 0 <= index < size:
            raise IndexError(_OUTSIDE)
        return ledger.entry(index)

    def __iter__(self) -> Iterator["Entry"]:
        return self._ledger.iter_entries(0, None)

    def __reversed__(self) -> Iterator["Entry"]:
        return self._ledger.iter_entries_reversed()


# A checked tool that raises an error or times out leaves the call unanswered, with no receipt (#28). With
# unanswered_hold (always under high_assurance) this many in a row,
# or this many within the window, hold it for UNANSWERED_HOLD_SECONDS; the hold then ends by itself (maintainer's
# decision, 2026-11-03). A forged or missing receipt still holds it until ``two-key tool release``.
TOOL_ERROR_PREFIX = "tool_error:"
UNANSWERED_HOLD_COUNT = 3
UNANSWERED_WINDOW_SECONDS = 600
UNANSWERED_HOLD_SECONDS = 900


def _whole(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def is_unanswered(body: dict) -> bool:
    """A ``tool_receipt_invalid`` body for a checked tool that raised or timed out, not a bad receipt."""
    why = body.get("why")
    return isinstance(why, str) and why.startswith(TOOL_ERROR_PREFIX)


def _missed_receipt_hold(tool: str, entries: list) -> dict | None:
    """A bad receipt with no redemption after it: under high_assurance its hold is written before the redemption."""
    redeemed = {e.body.get("jti") for e in entries if e.kind == "redemption"}
    for e in entries:
        if e.kind == "tool_receipt_invalid" and not is_unanswered(e.body) and e.body.get("jti") not in redeemed:
            return {"tool": tool, "jti": e.body.get("jti"), "why": e.body.get("why")}
    return None


def _missed_unanswered_hold(tool: str, entries: list, now: float) -> dict | None:
    """The newest unanswered call, if the count reached a hold there and that hold's time is not up at ``now``."""
    for i, e in enumerate(entries):
        if e.kind != "tool_receipt_invalid" or not is_unanswered(e.body):
            continue
        at = e.body.get("at")
        if not _whole(at) or now >= at + UNANSWERED_HOLD_SECONDS or not _hold_due(entries[i:], at):
            return None
        return {"tool": tool, "jti": e.body.get("jti"), "why": "unanswered", "until": at + UNANSWERED_HOLD_SECONDS}
    return None


def _hold_due(entries, now: float) -> bool:
    """``Ledger.unanswered_hold_due`` over ``entries``: one tool's receipt problems and redemptions, newest first."""
    in_a_row = in_window = 0
    streak = True
    for entry in entries:
        if entry.kind == "redemption":
            streak = streak and entry.body.get("receipt_outcome") != "ran"
            continue
        if entry.kind != "tool_receipt_invalid" or not is_unanswered(entry.body):
            continue
        at = entry.body.get("at")
        in_a_row += int(streak)
        in_window += int(_whole(at) and now - at < UNANSWERED_WINDOW_SECONDS)
        if UNANSWERED_HOLD_COUNT in (in_a_row, in_window):
            return True
    return False


class _ArchiveAudit:
    """What ``Ledger.audit_archives`` keeps while it streams the archives in order."""

    def __init__(self):
        self.pin = None
        self.ranges: list[tuple[int, bytes]] = []
        self.roots: dict[int, str] = {}             # size -> Merkle root, within the segment being read
        self.issued: dict[str, Entry] = {}          # jti -> capability_issued, within that segment
        self.tokens: dict[str, dict] = {}           # the tokens the last ledger_continued carried
        self.hashes: dict[int, str] = {}            # seq -> entry hash, within that segment
        self.carried: dict[int, str] = {}           # what the last ledger_continued carried: seq -> entry hash
        self.before_last: list = []

    def range_before(self, seq: int) -> list:
        return self.before_last if seq + 1 in self.roots else []

    def take(self, item: Entry) -> None:
        self.hashes[item.seq] = item.entry_hash
        if item.kind == "capability_issued" and isinstance(item.body.get("jti"), str):
            self.issued[item.body["jti"]] = item
        self.before_last = [[n, node.hex()] for n, node in self.ranges]
        self.roots[item.seq + 1] = _merkle_push(self.ranges, bytes.fromhex(item.entry_hash)).hex()

    def continued(self, item: Entry, segment: int) -> None:
        """Check a ``ledger_continued`` against the segment just read, then start the next one."""
        body = item.body
        bad = f"ledger_archive_invalid: ledger_continued at {item.seq}"
        if body.get("segment") != segment or body.get("merkle_range") != [[n, x.hex()] for n, x in self.ranges]:
            raise LedgerError(f"{bad} does not match the archive before it")
        if body.get("witness_pin", {}).get("witness_public_key") != self.pin:
            raise LedgerError(f"{bad} carries another witness pin than the archive before it ends with")
        for record in body.get("carried_tokens", []):
            known = self.tokens.get(record.get("jti"))
            issued = self.issued.get(record.get("jti"))
            if known is not None:
                same = known == record
            else:
                same = (issued is not None and issued.body.get("token_hash") == record.get("token_hash")
                        and issued.body.get("ledger_root") == record.get("ledger_root")
                        and self.roots.get(record.get("ledger_size")) == record.get("ledger_root"))
            if not same:
                raise LedgerError(f"{bad}: the carried token {str(record.get('jti'))[:40]} does not match its "
                                  "capability_issued entry")
        carried = {raw["seq"]: raw["entry_hash"] for raw in body.get("carried_entries", [])}
        for seq, entry_hash in carried.items():
            if self.hashes.get(seq, self.carried.get(seq)) != entry_hash:
                raise LedgerError(f"{bad}: the carried entry at seq {seq} is not the archived one")
        self.tokens = {record["jti"]: record for record in body.get("carried_tokens", [])}
        self.carried, self.issued, self.roots, self.hashes = carried, {}, {}, {}


class Ledger:
    def __init__(self, path: Path | str, private_key, public_key=None, *,
                 witness_path: Path | str | None = None, ledger_key_path: Path | str | None = None,
                 witness_public_key=None, anchor_path: Path | str | None = None,
                 rollover: RolloverSettings | None = None, _load: bool = True):
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

        ``rollover`` says when the active segment is sealed into an archive (``RolloverSettings``; the default seals
        at 64 MB). A ledger that has rolled over opens from its active segment; the archives it names must be there.
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
        # The active segment, from global seq ``_base`` (0 until the first rollover). ``entries`` reaches every seq.
        self._active: list[Entry] = []
        self._base = 0
        self.entries = _EntryView(self)
        self.rollover = RolloverSettings.or_default(rollover)
        self._continued: dict | None = None          # the active segment's ledger_continued body
        self._carried: dict[int, Entry] = {}         # archived entries ledger_continued carries, by seq
        self._carried_tokens: dict[str, dict] = {}   # jti -> open token carried across the seal
        self._base_root: str | None = None           # the Merkle root at size ``_base`` (through the seal)
        self._roll_after = 0.0                       # an automatic rollover put off is tried again after this
        self._rolling = False
        self.last_rollover: dict | None = None       # what the last rollover tried here did
        self._reader: list | None = None             # an open archive reader: [entries, next seq, catalogue item]
        self._reader_lock = threading.Lock()
        self._redeemed: set[str] = set()
        self._started: set[str] = set()
        # Tools held after a bad receipt under high_assurance (#28): tool -> (the tool_held entry's seq, the time
        # a hold for unanswered calls ends, or None for a hold that lasts until ``two-key tool release``).
        self._held: dict[str, tuple[int, int | None]] = {}
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
        self._entries_id: tuple[int, int, bytes] | None = None  # its device, inode, first bytes: a rollover replaces it
        self._from_others: set[int] = set()     # seqs another process appended while this one had it open
        self._head_size: int | None = None      # the size the signed head on disk covers
        self._appended = False                  # this hold of the write lock appended an entry
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

    def _entries_file_id(self) -> tuple[int, int, bytes] | None:
        """The entries file's device, inode, and first bytes. A rollover replaces the file, and the file system may
        give the new one an inode it freed before (two rollovers while another process was away); the first record
        starts with its own random nonce, so its first bytes tell the files apart."""
        try:
            fd = _platform.open_nofollow(self.entries_path, os.O_RDONLY | _platform.O_BINARY)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            return st.st_dev, st.st_ino, fh.read(_FILE_ID_BYTES)

    def _entries_changed(self) -> bool:
        """Whether another process wrote the entries file since this one read or wrote it: longer, or replaced by
        a rollover."""
        if self._entries_size is None:
            return False
        return (self._entries_file_size() != self._entries_size
                or (self._entries_id is not None and self._entries_file_id() != self._entries_id))

    def _note_entries_size(self) -> None:
        """Remember the entries file size. The next write compares it, instead of re-reading the file (#50)."""
        self._entries_size = self._entries_file_size()
        self._entries_id = self._entries_file_id()

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
                    if check_stale and ledger._entries_changed():
                        ledger._catch_up_unlocked()
                    ledger._depth = 1
                    return self
                except BaseException:
                    self._release()
                    raise

            def __exit__(self, exc_type, exc, tb):
                try:
                    ledger.roll_if_due(after_error=exc_type is not None)
                finally:
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
            self._read_active()
            self._verify_head()
            if self._base:
                self._check_archives()
            # Read again under the lock: a rotation in another process may have finished since __init__ read it.
            self._witness = self._load_witness()
            self._reject_if_behind_anchor()
            if self._witness_pin is None:
                self._pin_witness()
            else:
                self._check_witness(self._witness, str(self.witness_path))
            self._sync_witness_public()
            if self._head_size != self.size():
                self._checkpoint_unlocked()         # a rollover stopped before its last checkpoint
            else:
                self._sync_anchor_forward()
            self._finish_interrupted_rollover()

    def _reset_state(self) -> None:
        """Forget what was read, before reading the active segment (again)."""
        self._active, self._base, self._continued = [], 0, None
        self._carried, self._carried_tokens, self._base_root = {}, {}, None
        self._redeemed, self._started, self._held = set(), set(), {}
        self._witness_pin, self._upgraded_at, self._classical_rotations = None, None, []
        self._merkle_ranges, self._merkle_roots, self._kind_seqs = [], [], {}

    def _read_active(self) -> None:
        """Read and verify ``entries.jsonl``: a chain from 000…0, or, after a rollover, from the ``ledger_continued``
        entry that starts the active segment. Caller holds the lock."""
        self._reset_state()
        lines = self.entries_path.read_text(encoding="utf-8").splitlines() if self.entries_path.exists() else []
        filled = [i for i, line in enumerate(lines) if line.strip()]
        prev = None
        for i in filled:
            raw = json.loads(self._open_line(lines[i], last=i == filled[-1]))
            entry = Entry(raw["seq"], raw["prev"], raw["kind"], raw["body"], raw["entry_hash"])
            if prev is None:
                prev = self._start_segment(entry) if entry.kind == "ledger_continued" else "0" * 64
            self._take_read(entry, prev)
            prev = entry.entry_hash
        self._note_entries_size()

    def _open_line(self, line: str, *, last: bool) -> str:
        """Decrypt one record of ``entries.jsonl``. One that does not decrypt as the last line is named a torn write."""
        try:
            return _open(self._data_key, line)
        except LedgerError:
            if last:
                raise LedgerError(
                    "ledger record rejected (the last record does not decrypt). "
                    "A torn write from a crash looks like this; see HOWTO "
                    "\"If the ledger will not open after a crash\". It can also be tampering."
                ) from None
            raise

    def _take_read(self, entry: Entry, prev: str) -> None:
        """Check one entry read from disk against the chain so far and add it to the active segment."""
        expect = self._hash(entry.seq, entry.prev, entry.kind, entry.body)
        if entry.entry_hash != expect or entry.prev != prev or entry.seq != self.size():
            raise LedgerError("ledger chain failed verification")
        if self._active and self._active[-1].kind == "ledger_sealed":
            raise LedgerError(f"ledger chain failed verification: entry {entry.seq} follows ledger_sealed")
        if entry.kind == "ledger_continued" and self._active:
            raise LedgerError(f"ledger chain failed verification: ledger_continued at {entry.seq} is not the "
                              "first entry of its segment")
        self._track(entry, verify=True)
        self._active.append(entry)
        self._merkle_add(bytes.fromhex(entry.entry_hash))

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
        if known is not None and self._entries_id is not None and self._entries_file_id() != self._entries_id:
            self._catch_up_rollover(stale)
            return
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
            self._take_read(entry, prev)
            self._from_others.add(entry.seq)
            prev = entry.entry_hash
        self._entries_size = size
        self._after_catch_up()

    def _after_catch_up(self) -> None:
        self._verify_head()
        self._witness = self._load_witness()        # the other process may have rotated it
        self._check_witness(self._witness, str(self.witness_path))
        self._reject_if_behind_anchor()
        if self._head_size != self.size():
            self._checkpoint_unlocked()             # its rollover stopped before the last checkpoint
        self._finish_interrupted_rollover()

    def _catch_up_rollover(self, stale: str) -> None:
        """Another process rolled the ledger over: ``entries.jsonl`` is a new file that starts with
        ``ledger_continued``. Its seal must be at or past the last entry this process saw, and that entry must be
        in the archives with the hash this process knew. The entries between are read from the archives when
        something asks for them, and are another process's for the SIEM. Anything else is refused."""
        old_size, old_base = self.size(), self._base
        old_tip = self._active[-1].entry_hash if self._active else None
        self._read_active()
        if self._continued is None or self._base <= old_base or self._base < old_size:
            raise LedgerError(stale)
        if old_tip is not None and self.entry(old_size - 1).entry_hash != old_tip:
            raise LedgerError("ledger chain failed verification: the archives do not hold the entries this "
                              "process read; reopen the ledger")
        self._from_others.update(range(old_size, self.size()))
        self._after_catch_up()

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
            self._track_hold(entry)
        elif entry.kind == "tool_released" and isinstance(entry.body.get("tool"), str):
            self._held.pop(entry.body["tool"], None)
        elif entry.kind in ("witness_pinned", "witness_rotated"):
            self._track_witness(entry, check=verify)
        elif entry.kind == "keys_upgraded":
            self._track_upgrade(entry, check=verify)
        seqs = self._kind_seqs.setdefault(entry.kind, [])
        seqs.append(entry.seq)

    def _track_hold(self, entry: Entry) -> None:
        """Hold the tool of a ``tool_held`` entry: until a time (unanswered calls), or until ``two-key tool release``.
        A hold until ``two-key tool release`` is never cut short by a timed one written after it."""
        tool = entry.body["tool"]
        until = entry.body.get("until") if _whole(entry.body.get("until")) else None
        earlier = self._held.get(tool)
        if until is None or earlier is None or earlier[1] is not None:
            self._held[tool] = (entry.seq, until)

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
        if kind in _ROLLOVER_KINDS or kind == "ledger_rollover_failed":
            raise LedgerError(f"{kind} entries are written by the ledger itself when it rolls over")
        with self._exclusive():
            # Refuse before writing: an entry the next checkpoint cannot cover would keep the ledger from opening.
            self._require_witness()
            return self._append_unlocked(kind, body)

    def _append_unlocked(self, kind: str, body: dict) -> Entry:
        if self.upgrade_pending and kind not in ("keys_upgraded", "ledger_recovered"):
            raise LedgerError(KEYS_UPGRADE_PENDING)
        if self._active and self._active[-1].kind == "ledger_sealed" and not self._rolling:
            self._finish_interrupted_rollover()     # a rollover here stopped after its seal: finish it first
        prev = self.entries[-1].entry_hash if self.entries else "0" * 64
        seq = len(self.entries)
        entry_hash = self._hash(seq, prev, kind, body)
        entry = Entry(seq, prev, kind, body, entry_hash)
        line = _seal(self._data_key, json.dumps(entry.to_json(), separators=(",", ":"), sort_keys=True))
        with self.entries_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._active.append(entry)
        self._merkle_add(bytes.fromhex(entry.entry_hash))
        self._note_entries_size()
        self._track(entry, verify=False)
        self._appended = True
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
        self._head_size = head["size"]
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
            raise LedgerError("head anchor was signed by a different principal key (the key given is not this "
                              "ledger's principal key; check --key or principal_key)")
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
        body = self._recovery_head(head_text)
        lines = raw.splitlines(keepends=True)
        if sum(len(line) for line in lines) != len(raw):
            raise LedgerError("recovery refused: could not account for every byte of entries.jsonl")
        kept, count, prev, root = self._covered_prefix(lines, body["size"])
        if count != body["size"] or prev != body["tip"] or root != body["merkle_root"]:
            raise LedgerError("recovery refused: the entries end before the signed head, or do not match it. "
                              "Refusing to move the head backwards. The file was not changed.")
        tail = raw[kept:]
        nonempty = [ln for ln in tail.splitlines() if ln.strip()]
        return kept, tail, body, len(nonempty), self._any_torn(nonempty)

    def _recovery_head(self, head_text: str) -> dict:
        """The signed head ``recover`` keeps to: it decrypts, both signatures verify, it is this ledger's principal's,
        and it covers at least one entry."""
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
        return body

    def _covered_prefix(self, lines: list[bytes], target: int) -> tuple[int, int | None, str, str]:
        """Read ``lines`` until ``target`` entries (global seq) are chained: the bytes kept, the seq reached, the last
        hash and the Merkle root. The active segment may start with ``ledger_continued`` after a rollover."""
        kept, count, prev = 0, None, "0" * 64
        ranges: list[tuple[int, bytes]] = []
        root = hashlib.sha256(b"empty").hexdigest()
        broken = LedgerError("recovery refused: a record the signed head covers does not decrypt or chain. "
                             "This is not a trailing tail; the file was not changed.")
        for line in lines:
            if count == target:
                break
            kept += len(line)
            stripped = line.strip()
            if not stripped:
                continue
            try:
                entry = self._recovery_entry(stripped)
                if count is None:       # the first entry: the genesis, or ledger_continued after a rollover
                    count, prev, ranges = self._recovery_start(entry, ranges)
            except (LedgerError, ValueError, KeyError, TypeError):
                raise broken from None
            if entry.entry_hash != self._hash(entry.seq, entry.prev, entry.kind, entry.body) or entry.prev != prev \
                    or entry.seq != count:
                raise broken
            root = _merkle_push(ranges, bytes.fromhex(entry.entry_hash)).hex()
            prev = entry.entry_hash
            count += 1
        return kept, count, prev, root

    def _recovery_entry(self, line: bytes) -> Entry:
        raw = json.loads(_open(self._data_key, line.decode("utf-8")))
        return Entry(raw["seq"], raw["prev"], raw["kind"], raw["body"], raw["entry_hash"])

    @staticmethod
    def _recovery_start(entry: Entry, ranges: list) -> tuple[int, str, list]:
        """Where the chain ``recover`` reads starts: seq 0 from 000…0, or the ``ledger_continued`` that opens the
        active segment after a rollover, from its seal's hash and Merkle range."""
        if entry.kind != "ledger_continued":
            return 0, "0" * 64, ranges
        return entry.seq, entry.body["seal_hash"], _ranges(entry.body["merkle_range"], entry.seq)

    def _any_torn(self, lines: list[bytes]) -> bool:
        """Whether any of the tail's lines does not decrypt."""
        for ln in lines:
            try:
                _open(self._data_key, ln.decode("utf-8"))
            except (LedgerError, UnicodeDecodeError):
                return True
        return False

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
        body = {"dropped_bytes": len(tail), "dropped_sha256": _SHA256 + digest,
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
        if self._head_at_seal(body):
            pass                            # a rollover stopped before its last checkpoint; _load finishes it
        elif body["size"] != len(self.entries) or body["tip"] != self.entries[-1].entry_hash:
            if self._continued is not None and type(body["size"]) is int and body["size"] < self._base:
                raise LedgerError("ledger_rollover_incomplete: the signed head is older than the active segment's "
                                  "ledger_continued; see HOWTO \"If a ledger rollover did not finish\"")
            raise LedgerError("signed head does not match the chain (a write stopped before its head, or the files "
                              "were changed; after a crash see HOWTO \"If the ledger will not open after a crash\": "
                              "two-key recover)")
        elif body["merkle_root"] != self.merkle_root():
            raise LedgerError("signed head merkle root mismatch")
        self._head_size = body["size"]
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

    # -- segments, archives and rollover (0.9.1) ---------------------------------------------------------------

    def _head_at_seal(self, body: dict) -> bool:
        """A head that ends at the seal while the active segment holds only its ``ledger_continued``: a rollover
        stopped before its last checkpoint (``_load`` writes it)."""
        return (self._continued is not None and len(self._active) == 1 and body.get("size") == self._base
                and body.get("tip") == self._continued["seal_hash"] and body.get("merkle_root") == self._base_root)

    def _start_segment(self, entry: Entry) -> str:
        """Take the ``ledger_continued`` entry that starts the active segment: the global seq, the Merkle range, the
        catalogue of archives and the state carried across the seal. Returns the hash the entry must point at."""
        body = entry.body
        where = f"ledger chain failed verification: ledger_continued at {entry.seq}"
        try:
            ranges = _ranges(body["merkle_range"], entry.seq)
            catalogue = _catalogue(body["catalogue"], entry.seq - 1, body["seal_hash"])
            pin = body["witness_pin"]
            pin = (pin["witness_public_key"], pin["seq"], pin["source"])
            carried = [_entry_from(raw) for raw in body["carried_entries"]]
            tokens = {t["jti"]: _token_record(t) for t in body["carried_tokens"]}
            upgraded = body["upgraded_at"]
        except (KeyError, TypeError, ValueError) as e:
            raise LedgerError(f"{where} is malformed ({e})") from None
        if (body.get("format") != CONTINUED_FORMAT or body.get("segment") != len(catalogue) + 1
                or body.get("seal_seq") != entry.seq - 1 or entry.prev != body["seal_hash"]
                or not all(isinstance(v, str) for v in pin[::2]) or type(pin[1]) is not int
                or not (upgraded is None or type(upgraded) is int)
                or any(c.seq >= entry.seq for c in carried) or len({c.seq for c in carried}) != len(carried)):
            raise LedgerError(f"{where} does not continue the seal it names")
        self._base, self._continued = entry.seq, body
        self._merkle_ranges = ranges
        self._base_root = _fold_ranges(ranges).hex()
        for item in sorted(carried, key=lambda c: c.seq):
            self._carried[item.seq] = item
            self._track(item, verify=False)
        self._witness_pin, self._upgraded_at = pin, upgraded
        self._carried_tokens = tokens
        return body["seal_hash"]

    def catalogue(self) -> list[dict]:
        """Every archive of this ledger, oldest first: segment, file name, seq range, times, length and digest."""
        return [dict(meta) for meta in (self._continued or {}).get("catalogue", [])]

    def archive_dir(self) -> Path:
        return self.path / "archive"

    def _archive_path(self, meta: dict) -> Path:
        return self.archive_dir() / archive.archive_name(meta["segment"])

    def _check_archives(self) -> None:
        """Opening a ledger that has rolled over: every archive in the catalogue is there, owner-only, with its
        recorded length, and the newest one has its recorded digest (``two-key audit`` checks every digest)."""
        catalogue = self.catalogue()
        for meta in catalogue:
            fd = self._open_archive(meta)
            try:
                length = os.fstat(fd).st_size
            finally:
                os.close(fd)
            if length != meta["bytes"]:
                raise LedgerError(f"ledger_archive_invalid: {self._archive_path(meta)} is {length} bytes, and the "
                                  f"catalogue says {meta['bytes']}")
        newest = catalogue[-1]
        try:
            _, digest = archive.file_digest(self._archive_path(newest))
        except archive.ArchiveError as e:
            raise LedgerError(str(e)) from None
        if digest != newest["sha256"]:
            raise LedgerError(f"ledger_archive_invalid: {self._archive_path(newest)} does not match the SHA-256 in "
                              "the catalogue")

    def _open_archive(self, meta: dict) -> int:
        try:
            return archive.open_archive_file(self._archive_path(meta))
        except archive.ArchiveError as e:
            raise LedgerError(str(e)) from None

    def _archive_lines(self, meta: dict, *, digest: bool = True) -> Iterator:
        try:
            yield from archive.read_archive(self._archive_path(meta), self._data_key, meta["segment"],
                                            max_plain=meta["plain_bytes"], expect_bytes=meta["bytes"],
                                            expect_sha256=meta["sha256"] if digest else None)
        except archive.ArchiveError as e:
            raise LedgerError(str(e)) from None

    def _archive_entries(self, meta: dict, *, with_head: bool = False) -> Iterator:
        """The entries of one archive, each checked against the chain from the seal before it, ending at the seal
        the catalogue names. The file's digest is checked before the first entry is given out. With
        ``with_head``, the archive's signed head is given last."""
        catalogue = self.catalogue()
        n = meta["segment"]
        prev = "0" * 64 if n == 1 else catalogue[n - 2]["last_hash"]
        seq, head = meta["first_seq"], None
        bad = f"ledger_archive_invalid: segment {n}"
        for line in self._archive_lines(meta):
            if head is not None:
                raise LedgerError(f"{bad}: a line follows its signed head")
            if isinstance(line, dict) and line.get("format") == archive.HEAD_LINE_FORMAT:
                head = line.get("head")
                continue
            try:
                entry = _entry_from(line)
            except (KeyError, TypeError, ValueError):
                raise LedgerError(f"{bad}: a line is not a ledger entry") from None
            if (entry.seq != seq or entry.prev != prev
                    or entry.entry_hash != self._hash(entry.seq, entry.prev, entry.kind, entry.body)):
                raise LedgerError(f"{bad}: the chain breaks at seq {seq}")
            yield entry
            prev, seq = entry.entry_hash, seq + 1
        if seq != meta["last_seq"] + 1 or prev != meta["last_hash"] or not isinstance(head, dict):
            raise LedgerError(f"{bad}: it does not end at the seal the catalogue names")
        if with_head:
            yield head

    def entry(self, seq: int) -> Entry:
        """The entry at global ``seq``: from memory for the active segment and carried entries, else from its
        archive."""
        if seq >= self._base:
            return self._active[seq - self._base]
        if seq in self._carried:
            return self._carried[seq]
        return self._archived(seq)

    def _archived(self, seq: int) -> Entry:
        """One archived entry. Reading forward through an archive one seq at a time (a SIEM sink catching up,
        ``siem-verify``) keeps one reader open instead of starting the archive again for each entry."""
        with self._reader_lock:
            reader = self._reader
            if reader is None or not reader[1] <= seq <= reader[2]["last_seq"]:
                meta = next((m for m in self.catalogue() if m["first_seq"] <= seq <= m["last_seq"]), None)
                if meta is None:
                    raise IndexError(_OUTSIDE)
                reader = [self._archive_entries(meta), meta["first_seq"], meta]
            for item in reader[0]:
                if item.seq == seq:
                    reader[1] = seq + 1
                    self._reader = reader
                    return item
            self._reader = None
            raise IndexError(_OUTSIDE)

    def iter_entries(self, start: int = 0, stop: int | None = None) -> Iterator[Entry]:
        """Entries ``start`` to ``stop - 1`` in order, streaming the archives that hold any of them."""
        size = self.size()
        stop = size if stop is None else min(stop, size)
        start = max(0, start)
        if start >= stop:
            return
        for meta in self.catalogue() if start < self._base else ():
            if meta["last_seq"] >= start and meta["first_seq"] < stop:
                yield from self._archived_range(meta, start, stop)
        yield from self._active[max(start - self._base, 0):stop - self._base]

    def _archived_range(self, meta: dict, start: int, stop: int) -> Iterator[Entry]:
        """The entries of one archive from ``start`` to ``stop - 1``."""
        for item in self._archive_entries(meta):
            if item.seq >= stop:
                return
            if item.seq >= start:
                yield item

    def iter_entries_reversed(self) -> Iterator[Entry]:
        """Every entry, newest first. Each archive reached is read whole, one at a time."""
        yield from reversed(self._active)
        for meta in reversed(self.catalogue()):
            yield from reversed(list(self._archive_entries(meta)))

    def state_entries(self) -> list[Entry]:
        """The entries a start-up check needs, in seq order: those ``ledger_continued`` carried across the seals
        (the last constitution_loaded, keys_upgraded, capability_issued, the top serials, recent tool holds), then
        the active segment. Before any rollover, every entry."""
        return [*(self._carried[seq] for seq in sorted(self._carried)), *self._active]

    def carried_token(self, jti) -> dict | None:
        """The open token ``ledger_continued`` carried across the seal for ``jti``, or None. The gateway takes a
        token whose ``ledger_size`` is archived only when it is carried and its hash is this record's."""
        record = self._carried_tokens.get(jti) if isinstance(jti, str) else None
        return dict(record) if record is not None else None

    def segment_opened_at(self) -> float | None:
        """When the active segment began: its ``ledger_continued``, else the first entry that records a time."""
        if self._continued is not None:
            return self._continued["at"]
        for item in self._active[:64]:
            at = _entry_time(item)
            if at is not None:
                return at
        return None

    def over_hard_limit(self) -> bool:
        """True when the active segment has passed ``hard_limit_mb``: no new token until a rollover runs."""
        return self.rollover.enabled and (self._entries_size or 0) >= self.rollover.hard_limit_bytes

    def _roll_due(self, now: float) -> str | None:
        if len(self._active) < 2 or self._active[-1].kind == "ledger_sealed" or self._head_size != self.size():
            return None
        if (self._entries_size or 0) >= self.rollover.segment_bytes:
            return "size"
        opened = self.segment_opened_at() if self.rollover.segment_days else None
        if opened is not None and now - opened >= self.rollover.segment_days * 86400:
            return "age"
        return None

    def roll_if_due(self, now: float | None = None, *, after_error: bool = False) -> dict | None:
        """At the end of a hold of the write lock that appended, unless it ended in an error: seal the active segment
        if ``rollover`` says it is due. A rollover that cannot run now is put off for a minute, never forced, and
        never fails the write."""
        if after_error or self._depth != 1 or not self._appended or self._rolling:
            return None
        self._appended = False
        now = time.time() if now is None else now
        if not self.rollover.enabled or self.upgrade_pending or now < self._roll_after:
            return None
        why = self._roll_due(now)
        if why is None:
            return None
        try:
            result = self._roll_unlocked(why, now)
        except (LedgerError, OSError) as e:
            result = {"rolled": False, "reason": cap_ledger_text(f"{type_tag(e)}: {e}")}
        if not result["rolled"]:
            self._roll_after = now + ROLLOVER_RETRY_SECONDS
            print(f"two-key: ledger rollover put off: {result['reason']}", file=sys.stderr)
        return result

    def roll(self, reason: str = "manual", now: float | None = None) -> dict:
        """Seal the active segment into an archive now (``two-key ledger roll``). Returns what happened:
        ``rolled`` False with a ``reason`` when it was put off (nothing to seal, low disk, too many open tokens)."""
        if not isinstance(reason, str) or not reason or len(reason) > _KEEP_CHARS:
            raise LedgerError(f"reason must be a string of 1 to {_KEEP_CHARS} characters")
        with self._exclusive():
            return self._roll_unlocked(reason, time.time() if now is None else now)

    def _put_off(self, code: str, why: str) -> dict:
        self.last_rollover = {"rolled": False, "reason": f"{code}: {why}"}
        return dict(self.last_rollover)

    def _roll_unlocked(self, reason: str, now: float) -> dict:
        """The rollover, under the write lock. The archive is written to a temporary file and read back before the
        seal is appended, so a failure up to there leaves the active segment as it was (``ledger_rollover_failed``).
        Then: the seal and its checkpoint, the archive moved into place, ``entries.jsonl`` replaced by a file that
        holds only ``ledger_continued``, and a checkpoint. A crash after the seal is finished on the next open."""
        if self.upgrade_pending:
            raise LedgerError(KEYS_UPGRADE_PENDING)
        if self._active and self._active[-1].kind == "ledger_sealed":
            self._finish_interrupted_rollover()
            return dict(self.last_rollover or {"rolled": True})
        if len(self._active) < 2:
            return self._put_off("ledger_rollover_empty", "the active segment has nothing to seal yet")
        witness = self._require_witness(writing=True)
        segment_bytes = self._entries_file_size()
        if shutil.disk_usage(self.path).free < 2 * segment_bytes:
            return self._put_off("ledger_rollover_low_disk", f"less than twice the segment ({segment_bytes} bytes) "
                                 "is free beside the ledger")
        tokens = self._tokens_to_carry(now)
        if len(tokens) > MAX_CARRIED_TOKENS:
            return self._put_off("ledger_rollover_open_tokens", f"{len(tokens)} open tokens is more than "
                                 f"{MAX_CARRIED_TOKENS}; it waits until fewer are open")
        segment = (self._continued or {}).get("segment", 1)
        final = self.archive_dir() / archive.archive_name(segment)
        seal_body = {"format": SEALED_FORMAT, "segment": segment, "first_seq": self._base,
                     "last_seq": self.size(), "reason": reason, "at": int(now),
                     "opened_at": _whole_time(self.segment_opened_at()),
                     "merkle_range": [[n, node.hex()] for n, node in self._merkle_ranges]}
        seal = Entry(self.size(), self._active[-1].entry_hash, "ledger_sealed", seal_body,
                     self._hash(self.size(), self._active[-1].entry_hash, "ledger_sealed", seal_body))
        try:
            if os.path.lexists(final):
                raise LedgerError(f"ledger_archive_exists: {final} is already there; it is not this segment's")
            head = self._head_after(seal, witness)
            tmp, stats = self._write_archive(segment, [*self._active, seal], head)
        except (LedgerError, OSError, ValueError) as e:      # an EncodingError is a ValueError
            why = cap_ledger_text(f"{type_tag(e)}: {e}")
            self._append_unlocked("ledger_rollover_failed", {"segment": segment, "reason": reason, "error": why})
            self._checkpoint_unlocked(witness)
            return self._put_off("ledger_rollover_failed", why)
        self._rolling = True
        try:
            written = self._append_unlocked("ledger_sealed", seal_body)
            if written.entry_hash != seal.entry_hash:
                raise LedgerError("ledger_rollover_incomplete: the seal written is not the one archived")
            self._checkpoint_unlocked(witness)
            _platform.replace(tmp, final)
            _platform.fsync_dir(self.archive_dir())
            meta = self._archive_meta(segment, written, stats)
            return self._continue_after_seal(meta, now)
        finally:
            self._rolling = False
            if os.path.lexists(tmp):
                os.unlink(tmp)

    def _head_after(self, seal: Entry, witness) -> dict:
        """The signed head over the chain with ``seal`` added, as the checkpoint after it will sign it."""
        ranges = list(self._merkle_ranges)
        principal, principal_public, witness_signer = self._suite_keys(witness)
        head = {"size": seal.seq + 1, "tip": seal.entry_hash,
                "merkle_root": _merkle_push(ranges, bytes.fromhex(seal.entry_hash)).hex(),
                "public_key": public_raw(principal_public),
                "witness_public_key": public_raw(witness_signer.public_key())}
        signed = canonical_bytes(head)
        return {**head, "signature": sign(principal, signed), "witness_signature": sign(witness_signer, signed)}

    def _archive_folder(self) -> Path:
        folder = self.archive_dir()
        if _platform.is_link(folder):
            raise LedgerError(f"ledger_archive_insecure: {folder} is a link")
        folder.mkdir(mode=0o700, exist_ok=True)
        _platform.owner_only_dir(folder)
        for stray in folder.glob(".segment-*.tmp"):      # left by a rollover that stopped before its seal
            if stray.is_file() and not stray.is_symlink():
                stray.unlink()
        return folder

    def _write_archive(self, segment: int, entries: list[Entry], head: dict) -> tuple[Path, dict]:
        """Write the archive of ``entries`` and ``head`` to a temporary file beside where it goes, fsync it, and
        read it back: every line must be the one written. Returns the file and its length, digest and plaintext
        length."""
        folder = self._archive_folder()
        tmp = folder / f".{archive.archive_name(segment)}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
        expected = [archive.entry_line(e.to_json()) for e in entries] + [archive.head_line(head)]
        fd = _platform.create_new(tmp)
        try:
            with os.fdopen(fd, "wb") as fh:
                stats = archive.write_archive(fh, self._data_key, segment, iter(expected), self.rollover.compression)
                fh.flush()
                os.fsync(fh.fileno())
            got = archive.read_archive(tmp, self._data_key, segment, max_plain=stats["plain_bytes"],
                                       expect_bytes=stats["bytes"], expect_sha256=stats["sha256"])
            count = 0
            for count, (line, want) in enumerate(zip(got, expected, strict=False), start=1):
                if line != json.loads(want):
                    raise LedgerError(f"ledger_rollover_failed: the archive read back differs at line {count}")
            if count != len(expected) or next(got, None) is not None:
                raise LedgerError("ledger_rollover_failed: the archive read back has a different number of lines")
        except archive.ArchiveError as e:
            os.unlink(tmp)
            raise LedgerError(f"ledger_rollover_failed: the archive does not read back ({e})") from None
        except BaseException:
            if os.path.lexists(tmp):
                os.unlink(tmp)
            raise
        return tmp, stats

    def _archive_meta(self, segment: int, seal: Entry, stats: dict) -> dict:
        return {"segment": segment, "name": archive.archive_name(segment), "first_seq": seal.body["first_seq"],
                "last_seq": seal.seq, "last_hash": seal.entry_hash, "opened_at": seal.body["opened_at"],
                "sealed_at": seal.body["at"], "bytes": stats["bytes"], "sha256": stats["sha256"],
                "plain_bytes": stats["plain_bytes"], "compression": stats["compression"]}

    def _continue_after_seal(self, meta: dict, now: float) -> dict:
        """Steps 5 and 6: replace ``entries.jsonl`` with a file holding only ``ledger_continued``, then checkpoint.
        The archive is in place and the head ends at the seal."""
        sealed = list(self._active)
        seal = sealed[-1]
        tokens = self._tokens_to_carry(now)
        pin = self._witness_pin
        body = {"format": CONTINUED_FORMAT, "segment": meta["segment"] + 1, "seal_seq": seal.seq,
                "seal_hash": seal.entry_hash, "at": int(now), "archive": meta,
                "catalogue": [*self.catalogue(), meta],
                "merkle_range": [[n, node.hex()] for n, node in self._merkle_ranges],
                "witness_pin": {"witness_public_key": pin[0], "seq": pin[1], "source": pin[2]},
                "upgraded_at": self._upgraded_at,
                "carried_entries": [e.to_json() for e in self._entries_to_carry()],
                "carried_tokens": tokens}
        entry = Entry(seal.seq + 1, seal.entry_hash, "ledger_continued", body,
                      self._hash(seal.seq + 1, seal.entry_hash, "ledger_continued", body))
        line = _seal(self._data_key, json.dumps(entry.to_json(), separators=(",", ":"), sort_keys=True))
        following = self.path / "entries.next.jsonl"
        if os.path.lexists(following):
            os.unlink(following)
        fd = _platform.create_new(following)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        _platform.replace(following, self.entries_path)
        _platform.fsync_dir(self.path)
        self._adopt(entry)
        self._notify(entry)
        self._checkpoint_unlocked()
        pruned = self._prune_redeem_locks(sealed, tokens, now)
        self.last_rollover = {"rolled": True, "segment": meta["segment"], "archive": str(self._archive_path(meta)),
                              "first_seq": meta["first_seq"], "last_seq": meta["last_seq"], "bytes": meta["bytes"],
                              "plain_bytes": meta["plain_bytes"], "carried_tokens": len(tokens),
                              "redeem_locks_removed": pruned, "reason": seal.body["reason"]}
        return dict(self.last_rollover)

    def _adopt(self, entry: Entry) -> None:
        """Make ``entry`` (the new ``ledger_continued``) the whole active segment in memory."""
        held_from_others = self._from_others
        self._reset_state()
        self._from_others = held_from_others
        self._take_read(entry, self._start_segment(entry))
        self._note_entries_size()

    def _finish_interrupted_rollover(self) -> None:
        """The active segment ends with ``ledger_sealed``: a rollover stopped after its seal. Finish it, using the
        archive if it is there and holds this segment, else writing it again. An archive that is there and does
        not hold this segment is refused (``ledger_rollover_incomplete``)."""
        if not self._active or self._active[-1].kind != "ledger_sealed":
            return
        if self._head_size != self.size():
            raise LedgerError("ledger_rollover_incomplete: the seal is not covered by the signed head")
        seal = self._active[-1]
        segment = seal.body.get("segment")
        if segment != (self._continued or {}).get("segment", 1):
            raise LedgerError("ledger_rollover_incomplete: the seal names another segment")
        leftover = self.path / "entries.next.jsonl"
        if os.path.lexists(leftover):
            os.unlink(leftover)
        final = self.archive_dir() / archive.archive_name(segment)
        if os.path.lexists(final):
            stats = self._archive_matches(final, segment)
        else:
            head = json.loads(_open(self._data_key, self.head_path.read_text(encoding="utf-8")))
            tmp, stats = self._write_archive(segment, list(self._active), head)
            _platform.replace(tmp, final)
            _platform.fsync_dir(self.archive_dir())
        self._continue_after_seal(self._archive_meta(segment, seal, stats), time.time())

    def _archive_matches(self, path: Path, segment: int) -> dict:
        """The length, digest and plaintext length of an archive already in place, if it holds exactly the active
        segment; else ``ledger_rollover_incomplete``."""
        expected = [archive.entry_line(e.to_json()) for e in self._active]
        plain = sum(len(line) for line in expected)
        try:
            length, digest = archive.file_digest(path)
            lines = list(archive.read_archive(path, self._data_key, segment, max_plain=plain + 256 * 1024))
        except archive.ArchiveError as e:
            raise LedgerError(f"ledger_rollover_incomplete: {path} is there and does not read ({e}); see HOWTO "
                              "\"If a ledger rollover did not finish\"") from None
        head_line = lines[-1] if lines else None
        if ([archive.entry_line(line) for line in lines[:-1]] != expected or not isinstance(head_line, dict)
                or head_line.get("format") != archive.HEAD_LINE_FORMAT):
            raise LedgerError(f"ledger_rollover_incomplete: {path} does not hold this segment; see HOWTO \"If a "
                              "ledger rollover did not finish\"")
        return {"bytes": length, "sha256": digest, "plain_bytes": plain + len(archive.entry_line(head_line)),
                "compression": self.rollover.compression}

    def _entries_to_carry(self) -> list[Entry]:
        """What ``ledger_continued`` carries from the sealed segment: the entries start-up checks and the gateway
        read (``state_entries``), and, for each tool with receipt trouble, what its hold count reads back to its last
        hold or release."""
        picked = {item.seq: item for item in self._state_to_carry()}
        for tool, (seq, _) in self._held.items():
            picked[seq] = self.entry(seq)
            picked.update((item.seq, item) for item in self._hold_trail(tool))
        troubled = {self.entry(seq).body.get("tool") for seq in self._kind_seqs.get("tool_receipt_invalid", ())}
        for tool in sorted(t for t in troubled if isinstance(t, str) and t not in self._held):
            picked.update((item.seq, item) for item in self._hold_trail(tool))
        return [picked[seq] for seq in sorted(picked)]

    def _state_to_carry(self) -> list[Entry]:
        """The last ``constitution_loaded``, ``keys_upgraded`` and ``capability_issued``, the last
        ``constitution_loaded`` that pins a stamp key, and every ``constitution_loaded`` at the top serial."""
        last: dict[str, Entry] = {}
        top, tops = None, {}
        for item in self.state_entries():
            if item.kind in ("constitution_loaded", "keys_upgraded", "capability_issued"):
                last[item.kind] = item
            if item.kind != "constitution_loaded":
                continue
            if item.body.get("stamp_key_fingerprint"):
                last["stamp"] = item
            serial = item.body.get("serial")
            if type(serial) is int and (top is None or serial >= top):
                tops = tops if serial == top else {}
                top = serial
                tops[item.body.get("digest")] = item
        return [*last.values(), *tops.values()]

    def _hold_trail(self, tool: str) -> list[Entry]:
        """``tool``'s receipt problems and redemptions, newest first, back to and including its last hold or
        release: enough for ``unanswered_hold_due`` and ``catch_up_hold`` to decide the same in the next segment."""
        found, unanswered = [], 0
        seqs = heapq.merge(*(reversed(self._kind_seqs.get(kind, [])) for kind in _HOLD_KINDS), reverse=True)
        for seq in seqs:
            item = self.entry(seq)
            if item.body.get("tool") != tool:
                continue
            found.append(item)
            unanswered += item.kind == "tool_receipt_invalid"
            if item.kind in ("tool_held", "tool_released") or unanswered > UNANSWERED_HOLD_COUNT or len(found) >= 64:
                break
        return found if any(i.kind != "redemption" for i in found) else []

    def _tokens_to_carry(self, now: float) -> list[dict]:
        """The open tokens: issued in the active segment (or carried into it) less than 305 s ago, with no
        redemption started or done, and no revocation or constitution_loaded after the size they name."""
        spent = {self.entry(seq).body.get("jti") for kind in _SPENT_KINDS for seq in self._kind_seqs.get(kind, ())
                 if seq >= self._base}
        dead = [seq for kind in ("constitution_loaded", "revocation") for seq in self._kind_seqs.get(kind, ())
                if seq >= self._base]
        newest_dead = max(dead, default=-1)
        records = [t for t in self._carried_tokens.values()
                   if t["jti"] not in spent and now - t["issued_at"] < _CARRY_SECONDS and newest_dead < 0]
        for seq in self._kind_seqs.get("capability_issued", ()):
            if seq < self._base:
                continue
            record = self._open_token(self.entry(seq), now)
            if record is not None and record["jti"] not in spent and newest_dead < record["ledger_size"]:
                records.append(record)
        return records

    def _open_token(self, issued: Entry, now: float) -> dict | None:
        """The carried record of a ``capability_issued`` entry younger than 305 s, or None (fail closed: a token
        whose size or time cannot be read is not carried, and is then refused as ``ledger_size_archived``)."""
        body = issued.body
        jti, token_hash, root = body.get("jti"), body.get("token_hash"), body.get("ledger_root")
        if not (isinstance(jti, str) and jti and isinstance(token_hash, str) and isinstance(root, str)):
            return None
        at = body.get("issued_at")
        if isinstance(at, bool) or not isinstance(at, (int, float)):
            at = self._decision_time_after(issued.seq)
        if at is None or now - at >= _CARRY_SECONDS:
            return None
        size = body.get("ledger_size")
        if not (type(size) is int and self._base < size <= issued.seq):
            size = next((n for n in range(issued.seq, self._base, -1) if self.merkle_root(n) == root), None)
        if size is None or self.merkle_root(size) != root:
            return None
        pinned = self.last_before(size, "constitution_loaded")
        return {"jti": jti, "token_hash": token_hash, "ledger_size": size, "ledger_root": root,
                "capability_key_fingerprint": None if pinned is None else pinned.body.get("capability_key_fingerprint"),
                "issued_at": int(at)}

    def _decision_time_after(self, seq: int) -> float | None:
        """The time of the decision written with a token in 0.9.0 (its capability_issued has none)."""
        for item in self._active[seq - self._base + 1:seq - self._base + 8]:
            if item.kind == "decision":
                return _entry_time(item)
        return None

    def _prune_redeem_locks(self, sealed: list[Entry], tokens: list[dict], now: float) -> int:
        """Delete the redemption lock of each token in the sealed segment that can never be redeemed again: not
        carried, and the lock file older than 300 s. Only plain files named for such a jti, directly in the folder;
        a link is never followed. Returns how many were deleted."""
        folder = self.path.parent / f"{self.path.name}.redeem-locks"
        if _platform.is_link(folder) or not folder.is_dir():
            return 0
        keep = {t["jti"] for t in tokens}
        names = {hashlib.sha256(e.body["jti"].encode("utf-8")).hexdigest() for e in sealed
                 if e.kind in ("capability_issued", "tool_receipt_invalid", *_SPENT_KINDS)
                 and isinstance(e.body.get("jti"), str) and e.body["jti"] and e.body["jti"] not in keep}
        removed = 0
        for name in sorted(names):
            path = folder / name
            try:
                st = os.lstat(path)
                if stat.S_ISREG(st.st_mode) and now - st.st_mtime > REDEEM_LOCK_AGE_SECONDS:
                    os.unlink(path)
                    removed += 1
            except OSError:
                continue            # gone already, or held open on Windows: a later rollover tries again
        return removed

    def audit_archives(self) -> dict:
        """Check every archive (``two-key audit``): its digest, its chain, its seal (seq range and Merkle range),
        its signed head (the principal, and the witness key pinned at that point, following each rotation), and
        that what each ``ledger_continued`` carried is what the archive before it holds. Raises ``LedgerError``
        naming the segment."""
        catalogue = self.catalogue()
        audit = _ArchiveAudit()
        for meta in catalogue:
            self._audit_archive(meta, audit)
        if self._continued is not None:
            audit.continued(self._active[0], len(catalogue) + 1)
        return {"archives": len(catalogue), "archived_entries": self._base,
                "bytes": sum(meta["bytes"] for meta in catalogue)}

    def _audit_archive(self, meta: dict, audit: "_ArchiveAudit") -> None:
        """One archive of ``audit_archives``: its entries, its seal, and its signed head."""
        n = meta["segment"]
        head, seal = None, None
        for item in self._archive_entries(meta, with_head=True):
            if isinstance(item, dict):
                head = item
                break
            if item.kind == "ledger_continued":
                audit.continued(item, n)
            audit.pin = self._audit_pin(item, audit.pin)
            audit.take(item)
            if item.kind == "ledger_sealed":
                seal = item
                if item.body.get("merkle_range") != audit.range_before(item.seq):
                    raise LedgerError(f"ledger_archive_invalid: segment {n}: the seal's Merkle range is wrong")
        if seal is None or seal.body.get("segment") != n or seal.body.get("first_seq") != meta["first_seq"]:
            raise LedgerError(f"ledger_archive_invalid: segment {n} does not end with its own seal")
        self._audit_head(head, seal, audit.roots[seal.seq + 1], audit.pin, n)

    def _audit_pin(self, item: Entry, pin):
        """The witness key pinned after ``item``, checking a rotation's three signatures."""
        if item.kind == "witness_pinned":
            return item.body.get("witness_public_key")
        if item.kind == "keys_upgraded":
            return item.body.get("new_witness_public_key")
        if item.kind != "witness_rotated":
            return pin
        body = item.body
        try:
            statement = {k: body[k] for k in _ROTATION_FIELDS}
        except KeyError:
            raise LedgerError(f"ledger_archive_invalid: witness_rotated at {item.seq} is malformed") from None
        message = canonical_bytes(statement)
        principals = [self.public_key] + ([self._classical_principal()] if self._classical_principal() else [])
        if (statement["old_witness_public_key"] != pin
                or not any(verify(p, message, body.get("principal_signature") or "") for p in principals)
                or not verify(_witness_public(pin, "old witness key"), message, body.get("old_witness_signature") or "")
                or not verify(_witness_public(statement["new_witness_public_key"], "new witness key"), message,
                              body.get("new_witness_signature") or "")):
            raise LedgerError(f"ledger_archive_invalid: witness_rotated at {item.seq} does not verify")
        return statement["new_witness_public_key"]

    def _audit_head(self, head, seal: Entry, root: str, pin, segment: int) -> None:
        bad = f"ledger_archive_invalid: segment {segment}: its signed head"
        try:
            body = {k: head[k] for k in ("size", "tip", "merkle_root", "public_key", "witness_public_key")}
        except (KeyError, TypeError):
            raise LedgerError(f"{bad} is malformed") from None
        message = canonical_bytes(body)
        if (body["size"] != seal.seq + 1 or body["tip"] != seal.entry_hash or body["merkle_root"] != root
                or not self._is_ledger_principal(body["public_key"])
                or not verify(public_from_raw(body["public_key"]), message, head.get("signature") or "")):
            raise LedgerError(f"{bad} does not cover its seal, or its principal signature fails")
        if body["witness_public_key"] != pin or not verify(public_from_raw(pin), message,
                                                           head.get("witness_signature") or ""):
            raise LedgerError(f"{bad} is not signed by the witness key pinned then")

    def merkle_root(self, size: int | None = None) -> str:
        """The RFC 6962 root over the first ``size`` entries (all of them by default). A size inside an archived
        segment is refused (``ledger_size_archived``); only the root at the seal is kept."""
        n = self.size() if size is None else size
        if not isinstance(n, int) or isinstance(n, bool) or n < 0 or n > self.size():
            raise LedgerError("merkle size is outside this ledger")
        if n == 0:
            return hashlib.sha256(b"empty").hexdigest()
        if n < self._base:
            raise LedgerError(f"{ARCHIVED}: size {n} is inside an archived segment")
        if n == self._base:
            return self._base_root
        return self._merkle_roots[n - self._base - 1]

    def size(self) -> int:
        return self._base + len(self._active)

    def segment_start(self) -> int:
        """The seq of the active segment's first entry: 0 until the ledger has rolled over."""
        return self._base

    def is_redeemed(self, jti: str) -> bool:
        return jti in self._redeemed

    def redemption_started(self, jti: str) -> bool:
        return jti in self._started and jti not in self._redeemed

    def tool_held(self, tool: str, now: float | None = None) -> bool:
        """True while ``tool`` is held: a ``tool_held`` entry with no ``tool_released`` after it (#28), and, for a
        hold for unanswered calls, before its ``until``."""
        held = self._held.get(tool)
        if held is None:
            return False
        until = held[1]
        return until is None or (time.time() if now is None else now) < until

    def held_tools(self) -> list[str]:
        return sorted(tool for tool in self._held if self.tool_held(tool))

    def release_expired_hold(self, tool: str, now: float | None = None) -> None:
        """End a hold for unanswered calls whose time is up with a ``tool_released`` entry, so the ledger says when calls went
        ahead again. A hold with no ``until`` is left for ``two-key tool release``."""
        with self._exclusive():
            held = self._held.get(tool)
            if held is not None and held[1] is not None and not self.tool_held(tool, now):
                self.record("tool_released", {"tool": tool, "by": RELEASED_BY_EXPIRY, "reason": "hold expired"})

    def _since_last_hold(self, tool: str):
        """``tool``'s receipt problems and redemptions, newest first, back to its last hold or release."""
        kinds = ("tool_receipt_invalid", "redemption", "tool_held", "tool_released")
        seqs = heapq.merge(*(reversed(self._kind_seqs.get(kind, [])) for kind in kinds), reverse=True)
        for seq in seqs:
            entry = self.entries[seq]
            if entry.body.get("tool") != tool:
                continue
            if entry.kind in ("tool_held", "tool_released"):
                return
            yield entry

    def unanswered_hold_due(self, tool: str, now: float) -> bool:
        """True when ``tool``'s unanswered calls since its last hold or release call for a hold: ``UNANSWERED_HOLD_COUNT`` in a
        row with no verified receipt between them, or that many within ``UNANSWERED_WINDOW_SECONDS`` whatever came
        between. An agent cannot end either count by sending good calls."""
        return _hold_due(self._since_last_hold(tool), now)

    def catch_up_hold(self, tool: str, now: float | None = None, *, unanswered_hold: bool, high_assurance: bool) -> bool:
        """Write the ``tool_held`` entry a kill kept from being written, and return True (run 13, Y8).

        A hold is a second ledger write after the ``tool_receipt_invalid`` that calls for it. A process killed
        between the two left the tool free after a restart. So before a call to a checked tool, this looks at what
        happened since the tool's last hold or release, the same way the hold itself is decided: a bad receipt under
        ``high_assurance`` with no redemption after it (the bad-receipt path always writes one, after the hold), or
        unanswered calls that called for a hold whose time is not up yet. The hold it writes ends when the missed one
        would have: until ``two-key tool release``, or 15 minutes after the last unanswered call."""
        if now is None:
            now = time.time()
        with self._exclusive():
            if self.tool_held(tool, now):
                return False
            body = self._missed_hold(tool, now, unanswered_hold=unanswered_hold, high_assurance=high_assurance)
            if body is None:
                return False
            self.record("tool_held", body)
            return True

    def _missed_hold(self, tool: str, now: float, *, unanswered_hold: bool, high_assurance: bool) -> dict | None:
        """The ``tool_held`` body ``catch_up_hold`` writes, or None when no hold was missed."""
        entries = list(self._since_last_hold(tool))
        body = _missed_receipt_hold(tool, entries) if high_assurance else None
        if body is None and unanswered_hold:
            body = _missed_unanswered_hold(tool, entries, now)
        return body

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
        """Check the active segment's chain and the signed head, and return ``witness_report()``. Raises
        ``LedgerError``. ``audit_archives`` checks the archived segments."""
        prev = self._continued["seal_hash"] if self._continued is not None else "0" * 64
        for i, entry in enumerate(self._active, start=self._base):
            if entry.seq != i or entry.prev != prev:
                raise LedgerError(f"chain break at {i}")
            if entry.entry_hash != self._hash(entry.seq, entry.prev, entry.kind, entry.body):
                raise LedgerError(f"hash mismatch at {i}")
            prev = entry.entry_hash
        self._verify_head()
        return self.witness_report()

    def witness_report(self, *, archives: bool = True) -> dict:
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
            "history": witness_pins(self, archives=archives),
        }
