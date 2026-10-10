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

Neither pin detects a rollback to an earlier signed head, or a wipe (#62).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import threading
from dataclasses import dataclass
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX only
    fcntl = None

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .canonical import EncodingError, canonical_bytes, canonical_hash
from .agent_meta import cap_ledger_text, type_tag
from .keys import (
    generate_private_key, load_private_key_file, load_public_key, public_from_raw, public_key,
    public_raw, save_private_key, save_public_key, sign, verify,
)

WRAP_FORMAT = "two-key-concept-ledger-wrap/1"
RECORD_FORMAT = "two-key-concept-ledger-enc/1"
_WRAP_INFO = b"two-key-concept-ledger-wrap/1"
_RECORD_AAD = b"two-key-concept-ledger-enc/1"


LEDGER_KEY_BYTES = 32

WITNESS_ROTATION_FORMAT = "two-key-concept-witness-rotation/1"
# Written only by the ledger itself: Ledger.append refuses these kinds.
_WITNESS_KINDS = frozenset({"witness_pinned", "witness_rotated"})
# The signed statement of a witness_rotated entry; the entry body is these plus the three signatures.
_ROTATION_FIELDS = ("format", "seq", "prev", "old_witness_public_key", "new_witness_public_key", "reason")


def witness_key_fingerprint(raw: str) -> str:
    """``sha256:`` and the hex SHA-256 of a raw witness public key (the base64 form the head carries)."""
    return "sha256:" + hashlib.sha256(base64.b64decode(raw)).hexdigest()


def _witness_public(raw, what: str):
    try:
        return public_from_raw(raw)
    except Exception:
        raise LedgerError(f"{what} is not an Ed25519 public key") from None


def _write_new_secret(path, data: bytes) -> None:
    """Create ``path`` with O_CREAT | O_EXCL | O_NOFOLLOW at mode 0600 and write ``data``.

    An existing file or a planted symlink raises FileExistsError instead of being
    overwritten, and there is no window in which the bytes are readable before a chmod.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _read_secret(path, size: int, label: str) -> bytes:
    """Read a ``size``-byte key with O_NOFOLLOW; refuse a non-regular file, group/other access, or a wrong length."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        raise LedgerError(f"{label}_unreadable: {path}: {e.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise LedgerError(f"{label}_unreadable: {path} is not a regular file")
        if st.st_mode & 0o077:
            raise LedgerError(f"{label}_insecure: {path} is readable by group or others; chmod 600 it")
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
    return HKDF(SHA256(), 32, salt=b"two-key-concept-ledger", info=_WRAP_INFO).derive(ledger_key)


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
                 witness_public_key: Ed25519PublicKey | None = None):
        """Open or create the ledger at ``path``.

        ``witness_public_key`` is the out-of-ledger witness pin: the witness public key, kept where whoever
        writes the ledger directory cannot change it. With it, a head signed by any other witness key is
        refused (``witness_key_changed``), and so is a ``witness.pem`` that does not match.

        Opening a new ledger writes its ``witness_pinned`` entry. Opening a ledger made before 0.2.3 for the
        first time pins the witness key that signed its head (trust on first use). Both are checkpointed.
        """
        if witness_public_key is not None and not isinstance(witness_public_key, Ed25519PublicKey):
            raise LedgerError("witness_public_key must be an Ed25519 public key")
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
        self.witness_path = Path(witness_path) if witness_path else self.path.parent / f"{self.path.name}.witness" / "witness.pem"
        self.ledger_key_path = Path(ledger_key_path) if ledger_key_path else self.path.parent / f"{self.path.name}.ledger-key" / "ledger.key"
        if self.witness_path.resolve().is_relative_to(self.path.resolve()):
            raise LedgerError("witness key must live outside the ledger directory")
        if self.ledger_key_path.resolve().is_relative_to(self.path.resolve()):
            raise LedgerError("ledger key must live outside the ledger directory")
        self._lock = threading.Lock()
        self.entries: list[Entry] = []
        self._redeemed: set[str] = set()
        self._started: set[str] = set()
        self._configured_witness = None if witness_public_key is None else public_raw(witness_public_key)
        self._witness_pin: tuple[str, int, str] | None = None    # (raw key, seq, source) pinned in the ledger
        self._head_witness: str | None = None                   # the witness key in the verified head
        self._merkle_ranges: list[tuple[int, bytes]] = []
        self._merkle_roots: list[str] = []
        self._entries_size: int | None = None                   # bytes of entries.jsonl last read or written
        self._ledger_key = self._open_ledger_key()
        self._data_key = self._open_data_key()
        self._witness = self._open_witness()
        self._load()

    def capability_key_path(self) -> Path:
        """Minting key. Outside the ledger directory. The gateway does not read it."""
        path = self.path.parent / f"{self.path.name}.capability" / "capability.pem"
        if path.resolve().is_relative_to(self.path.resolve()):
            raise LedgerError("capability key must live outside the ledger directory")
        return path

    def lock_path(self) -> Path:
        path = self.path.parent / f"{self.path.name}.lock"
        if path.resolve().is_relative_to(self.path.resolve()):
            raise LedgerError("ledger lock must live outside the ledger directory")
        return path

    def redeem_lock_path(self, jti: str) -> Path:
        if not isinstance(jti, str) or not jti:
            raise LedgerError("jti required")
        directory = self.path.parent / f"{self.path.name}.redeem-locks"
        if directory.resolve().is_relative_to(self.path.resolve()):
            raise LedgerError("redemption lock must live outside the ledger directory")
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        return directory / hashlib.sha256(jti.encode("utf-8")).hexdigest()

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
                try:
                    if fcntl is not None:
                        self.fd = os.open(ledger.lock_path(), os.O_CREAT | os.O_RDWR, 0o600)
                        fcntl.flock(self.fd, fcntl.LOCK_EX)
                    if check_stale and ledger._entries_size is not None and ledger._entries_file_size() != ledger._entries_size:
                        raise LedgerError("ledger file changed by another writer; reopen the ledger")
                    return self
                except BaseException:
                    self._release()
                    raise

            def __exit__(self, exc_type, exc, tb):
                self._release()
                return False

            def _release(self):
                if self.fd is not None:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                    os.close(self.fd)
                    self.fd = None
                if self.held:
                    ledger._lock.release()
                    self.held = False

        return _Guard()

    @property
    def entries_path(self) -> Path:
        return self.path / "entries.jsonl"

    @property
    def head_path(self) -> Path:
        return self.path / "head.json"

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
            os.chmod(path.parent, 0o700)
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
                        os.replace(tmp, self.wrap_path)
                    finally:
                        if os.path.lexists(tmp):
                            os.unlink(tmp)
                    return data_key
        try:
            fd = os.open(self.wrap_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
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
            raise LedgerError("ledger key file is not a concept wrapped data key") from None
        if not isinstance(blob, dict) or blob.get("format") != WRAP_FORMAT:
            raise LedgerError("ledger key file is not a concept wrapped data key")
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
                os.chmod(self.witness_path.parent, 0o700)   # <ledger>.witness is Two-Key's own directory
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
            if self._witness_pin is None:
                self._pin_witness()
            else:
                self._check_witness(self._witness, str(self.witness_path))
            self._sync_witness_public()

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
        elif entry.kind == "redemption_aborted" and jti:
            self._started.discard(jti)
        elif entry.kind == "witness_pinned":
            raw = entry.body.get("witness_public_key")
            if verify:
                if self._witness_pin is not None:
                    raise LedgerError("ledger chain failed verification: a second witness_pinned entry "
                                      f"at {entry.seq}; the witness key changes only by witness_rotated")
                _witness_public(raw, f"witness_pinned at {entry.seq}")
            self._witness_pin = (raw, entry.seq, str(entry.body.get("source")))
        elif entry.kind == "witness_rotated":
            if verify:
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
        for public, field in ((self.public_key, "principal_signature"),
                              (_witness_public(statement["old_witness_public_key"], "old witness key"),
                               "old_witness_signature"),
                              (_witness_public(statement["new_witness_public_key"], "new witness key"),
                               "new_witness_signature")):
            if not verify(public, message, body.get(field) or ""):
                raise LedgerError(f"witness_rotated at {entry.seq}: {field} failed")

    def _witness_mismatch(self, raw: str) -> str | None:
        """What a witness public key fails to match: the pin in the ledger, then the configured pin."""
        if self._witness_pin is not None and raw != self._witness_pin[0]:
            return "the witness key pinned in the ledger"
        if self._configured_witness is not None and raw != self._configured_witness:
            return "the configured witness public key"
        return None

    def _check_witness(self, key, where: str) -> None:
        expected = self._witness_mismatch(public_raw(key.public_key()))
        if expected:
            raise LedgerError(f"witness_key_changed: {where} does not match {expected}; restore that key, or "
                              "change it with rotate_witness")

    def _require_witness(self):
        """Load ``witness.pem`` for a write and refuse it if it is missing or does not match a pin."""
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

    def _hash(self, seq: int, prev: str, kind: str, body: dict) -> str:
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
                              "rotate_witness")
        with self._exclusive():
            # Refuse before writing: an entry the next checkpoint cannot cover would keep the ledger from opening.
            self._require_witness()
            return self._append_unlocked(kind, body)

    def _append_unlocked(self, kind: str, body: dict) -> Entry:
        prev = self.entries[-1].entry_hash if self.entries else "0" * 64
        seq = len(self.entries)
        entry_hash = self._hash(seq, prev, kind, body)
        entry = Entry(seq, prev, kind, body, entry_hash)
        line = _seal(self._data_key, json.dumps(entry.to_json(), separators=(",", ":"), sort_keys=True))
        with self.entries_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self.entries.append(entry)
        self._merkle_add(bytes.fromhex(entry.entry_hash))
        self._note_entries_size()
        self._track(entry, verify=False)
        return entry

    def checkpoint(self) -> dict:
        with self._exclusive():
            return self._checkpoint_unlocked()

    def _checkpoint_unlocked(self, witness=None) -> dict:
        if witness is None:
            witness = self._require_witness()
        else:
            self._check_witness(witness, "the witness key")
        self._witness = witness
        head = {
            "size": len(self.entries),
            "tip": self.entries[-1].entry_hash if self.entries else "0" * 64,
            "merkle_root": self.merkle_root(),
            "public_key": public_raw(self.public_key),
            "witness_public_key": public_raw(witness.public_key()),
        }
        signed = canonical_bytes(head)
        stored = dict(head)
        stored["signature"] = sign(self.private_key, signed)
        stored["witness_signature"] = sign(witness, signed)
        self._store_head(_seal(self._data_key, json.dumps(stored)) + "\n")
        self._head_witness = head["witness_public_key"]
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
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o666)
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
        os.replace(tmp, self.head_path)
        dirfd = os.open(self.path, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)

    def _merkle_add(self, leaf: bytes) -> None:
        self._merkle_roots.append(_merkle_push(self._merkle_ranges, leaf).hex())

    def rotate_witness(self, new_witness: Ed25519PrivateKey | None = None, *, reason: str = "") -> dict:
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
        if not isinstance(new_witness, Ed25519PrivateKey):
            raise LedgerError("the new witness key must be an Ed25519 private key")
        if not isinstance(reason, str) or len(reason) > _KEEP_CHARS:
            raise LedgerError(f"reason must be a string of at most {_KEEP_CHARS} characters")
        staged = self.witness_path.with_name(self.witness_path.name + ".new")
        with self._exclusive():
            old = self._require_witness()
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
                os.replace(staged, self.witness_path)
            except OSError as e:
                raise LedgerError(f"witness rotated in the ledger, but {staged} could not be moved to "
                                  f"{self.witness_path} ({e.strerror}); move it by hand") from None
            written = self._sync_witness_public()
        return {"seq": statement["seq"], "old_witness_key_fingerprint": witness_key_fingerprint(old_raw),
                "new_witness_key_fingerprint": witness_key_fingerprint(new_raw),
                "witness_public_key_path": str(self.witness_path.with_suffix(".pub.pem")) if written else None}

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
        if body["public_key"] != public_raw(self.public_key):
            raise LedgerError("head principal public key does not match this ledger's principal key")
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

    def kinds_after(self, size: int, kinds: set[str]) -> list[Entry]:
        return [e for e in self.entries[size:] if e.kind in kinds]

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
