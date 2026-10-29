# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Passphrase-protected backup of this package's own keys.

Three bundles, so that one file never holds every key a signed head needs
(the principal key, the witness key, and the ledger key) when the witness
public key is pinned outside the ledger:

* ``principal.bundle.json`` — ``principal.pem``, ``capability.pem``, and ``stamp.pem`` (the tool check's
  stamp key, 0.9.0) where the deployment has one
* ``ledger.bundle.json`` — ``ledger.key``, ``fingerprint.key``, the ledger
  files, and ``head.anchor`` from the same moment
* ``witness.bundle.json`` — ``witness.pem``

The bundle names its key-derivation function. 0.3 ships one:
``pbkdf2-sha256`` at 600,000 iterations (NIST SP 800-132), then AES-256-GCM.
The name and the format version are there so a later release can add a
function, or refuse one, without a new file format. This is not a seed phrase.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import _platform
from .canonical import EncodingError, canonical_bytes
from .capability import _pinned as pinned_capability_key, capability_key_fingerprint
from .keys import (CLASSICAL_ALG, HYBRID_ALG, HYBRID_ENCRYPTED_FORMAT, Passphrase, decrypt_private_key, encrypted_header,
                   is_encrypted, is_hybrid, key_fingerprint, load_private_key_file, load_public_key, passphrase_bytes,
                   private_key_from_pem, public_raw, remember, save_public_key)
from .ledger import witness_key_fingerprint
from .strict import StrictParseError, loads_json


class BackupError(ValueError):
    """A backup cannot be written, opened, or restored. Nothing was changed when this is raised
    before the restore write, and a rejected bundle is never treated as empty."""


FORMAT = "two-key-key-backup/1"
PAYLOAD_FORMAT = "two-key-key-backup-payload/1"
BACKUP_VERSION = 1
ALG = "pbkdf2-sha256+aes-256-gcm"
KDF_NAME = "pbkdf2-sha256"
ENC_NAME = "aes-256-gcm"
# The same iteration count identity.py uses for a password fingerprint. Named in the bundle.
PBKDF2_ITERATIONS = 600_000
MIN_ITERATIONS = 1_000          # below this, PBKDF2 is refused (the OpenSSL FIPS floor is 1,000)
MAX_ITERATIONS = 10_000_000     # a bundle cannot ask the operator's machine to run forever
KDF_LENGTH = 32
SALT_BYTES = 16                 # 128 bits, the FIPS salt floor
NONCE_BYTES = 12
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
# Base64 plus the JSON wrapper has to fit in MAX_BUNDLE_BYTES, so the plaintext stops shorter.
MAX_PLAINTEXT_BYTES = 45 * 1024 * 1024
MAX_PASSPHRASE_BYTES = 1024
ROLES = ("principal", "ledger", "witness")
BUNDLE_NAMES = {
    "principal": "principal.bundle.json",
    "ledger": "ledger.bundle.json",
    "witness": "witness.bundle.json",
}
# What each role may carry. A file outside its role is a refusal, not an extra. A private key's alg is the key's
# own: ``ed25519+ml-dsa-65`` from 0.9.0, ``ed25519`` in a 0.8.0 backup (the key upgrade runs after its restore).
_KEY = "key"
_STAMP = "stamp.pem"
_ROLE_FILES = {
    "principal": {"principal.pem": ("pem", _KEY), "capability.pem": ("pem", _KEY), _STAMP: ("pem", _KEY)},
    "witness": {"witness.pem": ("pem", _KEY)},
    "ledger": {
        "ledger.key": ("raw", "raw-32"),
        "fingerprint.key": ("raw", "raw-32"),
        "entries.jsonl": ("bytes", "ledger-file"),
        "head.json": ("bytes", "ledger-file"),
        "keywrap.json": ("bytes", "ledger-file"),
        "head.anchor": ("bytes", "head-anchor"),
    },
}
# Present only where the deployment has it: the stamp key exists once a signed tool turns the tool check on.
_OPTIONAL_FILES = frozenset({_STAMP})
# principal.pem may also be Two-Key's encrypted form (two_key/keys.py): it is kept that way, bundle and all,
# and opening the bundle then needs the key's own passphrase as well as the bundle's.
ENCRYPTED_KEY_ALG = "ed25519-encrypted"
HYBRID_ENCRYPTED_KEY_ALG = f"{HYBRID_ALG}-encrypted"
_ENCRYPTABLE = frozenset({"principal.pem"})
_HEADER_FIELDS = ("format", "version", "role", "alg", "kdf", "enc", "ciphertext")
_KDF_FIELDS = ("name", "iterations", "salt", "length")
_ENC_FIELDS = ("name", "nonce")
_WEAK_BELOW_BYTES = 12      # a length, in bytes: a backup passphrase shorter than this draws a warning


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text, what: str, limit: int) -> bytes:
    if not isinstance(text, str) or len(text) > (limit * 4 // 3) + 8:
        raise BackupError(f"backup_refused: {what} is not a backup field")
    try:
        return base64.b64decode(text, validate=True)
    except Exception:
        raise BackupError(f"backup_refused: {what} is not a backup field") from None


def _passphrase(value, role: str) -> bytes:
    if not isinstance(value, str) or value == "":
        raise BackupError(f"backup_refused: {role} passphrase is empty")
    raw = value.encode("utf-8")
    if len(raw) > MAX_PASSPHRASE_BYTES:
        raise BackupError(f"backup_refused: {role} passphrase is too long")
    return raw


def _iterations(value) -> int:
    if type(value) is not int or isinstance(value, bool) or not MIN_ITERATIONS <= value <= MAX_ITERATIONS:
        raise BackupError("backup_refused: kdf iterations are not allowed")
    return value


def _derive(passphrase: bytes, salt: bytes, iterations: int) -> bytes:
    return PBKDF2HMAC(SHA256(), KDF_LENGTH, salt, iterations).derive(passphrase)


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write_new(path: Path, data: bytes) -> None:
    """Create ``path`` owner-only (mode 0600, or a private access list on Windows). An existing file or a
    symlink is an error, not an overwrite."""
    fd = _platform.create_new(path)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _fsync_dir(directory: Path) -> None:
    """The file fsync is not enough: the directory entry has to reach disk too."""
    _platform.fsync_dir(directory)


def _read_file(path: Path, limit: int, *, secret: bool = True) -> bytes:
    """Read a regular file. A symlink is refused, not followed. Secret files must be mode 0600.

    ``entries.jsonl`` and ``head.json`` are ciphertext the ledger itself creates without that mode,
    so those two are read even when the group can read them. Keys, the anchor, and bundles are not.
    """
    try:
        fd = _platform.open_nofollow(path)
    except OSError as e:
        raise BackupError(f"backup_refused: {path} cannot be read ({e.strerror})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise BackupError(f"backup_refused: {path} is not a regular file")
        problem = _platform.access_problem(fd, st) if secret else None
        if problem:
            raise BackupError(f"backup_refused: {_platform.insecure(path, problem)}")
        if st.st_size > limit:
            raise BackupError(f"backup_too_large: {path} is over {limit} bytes")
        chunks = []
        remaining = st.st_size
        while remaining > 0:
            block = os.read(fd, remaining)
            if not block:
                raise BackupError(f"backup_refused: {path} could not be read completely")
            chunks.append(block)
            remaining -= len(block)
        return b"".join(chunks)
    finally:
        os.close(fd)


# The ledger creates these two as ciphertext without forcing mode 0600. Everything else in a
# bundle is a key, the wrapped data key, the anchor, or a bundle file, and those stay 0600.
_LOOSE_FILES = {"entries.jsonl", "head.json"}


def _read_named(path: Path, name: str) -> bytes:
    return _read_file(path, MAX_BUNDLE_BYTES, secret=name not in _LOOSE_FILES)


def _load_pem(data: bytes, what: str):
    """A Two-Key private key (hybrid, or a 0.8.0 Ed25519 key) from a backup's unencrypted PEM file."""
    try:
        return private_key_from_pem(data, what)
    except ValueError:
        raise BackupError(f"backup_refused: {what} is not a Two-Key private key") from None


def _key_alg(data: bytes, name: str) -> str:
    """The alg a backup names for the private key file ``data``: which suite, and whether it is encrypted."""
    if is_encrypted(data):
        try:
            header = encrypted_header(data, name)     # its shape; opening it needs the key's passphrase
        except ValueError:
            raise BackupError(f"backup_rejected: {name} is not a private key") from None
        return HYBRID_ENCRYPTED_KEY_ALG if header["format"] == HYBRID_ENCRYPTED_FORMAT else ENCRYPTED_KEY_ALG
    return HYBRID_ALG if is_hybrid(_load_pem(data, name)) else CLASSICAL_ALG


def _exact_fields(obj, fields: tuple, what: str) -> dict:
    if not isinstance(obj, dict) or set(obj) != set(fields):
        raise BackupError(f"backup_refused: {what} is not a backup field")
    return obj


def _warn_passphrases(passphrases: dict) -> None:
    texts = {role: passphrases[role] for role in ROLES}
    if texts["principal"] == texts["ledger"] == texts["witness"]:
        print("two-key: WARNING: the three backup bundles share one passphrase. A guess that opens one "
              "opens the others if the files are stored together. Store the bundles apart.", file=sys.stderr)
    else:
        shared = [f"{a} and {b}" for a, b in (("principal", "ledger"), ("principal", "witness"), ("ledger", "witness"))
                  if texts[a] == texts[b]]
        if shared:
            print("two-key: WARNING: the " + " and ".join(shared) + " backup passphrases match. A guess that "
                  "opens one opens the other if those files are stored together. Store the bundles apart.",
                  file=sys.stderr)
    for role in ROLES:
        if len(passphrases[role].encode("utf-8")) < _WEAK_BELOW_BYTES:
            print(f"two-key: WARNING: the {role} passphrase is shorter than {_WEAK_BELOW_BYTES} bytes. "
                  "The backup is only as strong as that passphrase, and PBKDF2 is not memory-hard.",
                  file=sys.stderr)


def _encrypt(role: str, payload: dict, passphrase: str, iterations: int) -> bytes:
    iterations = _iterations(iterations)
    if payload.get("role") != role or payload.get("format") != PAYLOAD_FORMAT:
        raise BackupError("backup_refused: payload role does not match the bundle")
    try:
        plain = canonical_bytes(payload)
    except EncodingError as e:
        raise BackupError(f"backup_refused: {e}") from None
    if len(plain) > MAX_PLAINTEXT_BYTES:
        raise BackupError(f"backup_too_large: the {role} backup is over {MAX_PLAINTEXT_BYTES} bytes")
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    header = {
        "format": FORMAT,
        "version": BACKUP_VERSION,
        "role": role,
        "alg": ALG,
        "kdf": {"name": KDF_NAME, "iterations": iterations, "salt": _b64e(salt), "length": KDF_LENGTH},
        "enc": {"name": ENC_NAME, "nonce": _b64e(nonce)},
    }
    aad = canonical_bytes(header)
    ciphertext = AESGCM(_derive(_passphrase(passphrase, role), salt, iterations)).encrypt(nonce, plain, aad)
    header["ciphertext"] = _b64e(ciphertext)
    return (json.dumps(header, indent=2, sort_keys=True) + "\n").encode("ascii")


def _decrypt(blob: bytes, passphrase: str, expect_role: str) -> dict:
    if len(blob) > MAX_BUNDLE_BYTES:
        raise BackupError(f"backup_too_large: bundle is over {MAX_BUNDLE_BYTES} bytes")
    try:
        header = loads_json(blob)
    except StrictParseError as e:
        raise BackupError(f"backup_refused: {e}") from None
    header = _exact_fields(header, _HEADER_FIELDS, "bundle")
    if header["format"] != FORMAT or type(header["version"]) is not int or header["version"] != BACKUP_VERSION:
        if isinstance(header["format"], str) and header["format"].startswith("two-key-concept-"):
            raise BackupError("backup_refused: bundle made by two-key-concept (before two-key 0.4.0); "
                              "export a new backup with two-key")
        raise BackupError("backup_refused: unsupported backup format")
    if header["role"] not in ROLES or header["role"] != expect_role:
        raise BackupError("backup_refused: bundle role does not match the file")
    if header["alg"] != ALG:
        raise BackupError(f"backup_refused: algorithm is {str(header['alg'])[:80]!r}, not {ALG}")
    kdf = _exact_fields(header["kdf"], _KDF_FIELDS, "kdf")
    enc = _exact_fields(header["enc"], _ENC_FIELDS, "enc")
    if kdf["name"] != KDF_NAME or kdf["length"] != KDF_LENGTH or enc["name"] != ENC_NAME:
        raise BackupError("backup_refused: this backup's key derivation or cipher is not one 0.3 opens")
    iterations = _iterations(kdf["iterations"])
    salt = _b64d(kdf["salt"], "salt", 64)
    nonce = _b64d(enc["nonce"], "nonce", 32)
    if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
        raise BackupError("backup_refused: salt or nonce is the wrong length")
    ciphertext = _b64d(header["ciphertext"], "ciphertext", MAX_BUNDLE_BYTES)
    aad = canonical_bytes({k: header[k] for k in _HEADER_FIELDS if k != "ciphertext"})
    key = _derive(_passphrase(passphrase, expect_role), salt, iterations)
    try:
        plain = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise BackupError("backup_rejected: wrong passphrase or tampered bundle") from None
    except Exception:
        raise BackupError("backup_rejected: wrong passphrase or tampered bundle") from None
    try:
        payload = loads_json(plain)
    except StrictParseError as e:
        raise BackupError(f"backup_rejected: {e}") from None
    return _check_payload(payload, expect_role)


def _check_payload(payload, role: str) -> dict:
    if not isinstance(payload, dict) or set(payload) != {"format", "version", "role", "files", "fingerprints"}:
        raise BackupError("backup_rejected: payload is not a backup field")
    files = payload.get("files")
    fingerprints = payload.get("fingerprints")
    version = payload.get("version")
    if (payload.get("format") != PAYLOAD_FORMAT or type(version) is not int or version != BACKUP_VERSION
            or payload.get("role") != role or not isinstance(files, dict) or not _role_files_match(role, files)
            or not isinstance(fingerprints, dict)):
        raise BackupError("backup_rejected: payload does not match this backup role")
    out_files = {}
    for name, spec in files.items():
        raw = _checked_file(role, name, spec)
        if fingerprints.get(name) != _sha256(raw):
            raise BackupError(f"backup_rejected: {name} fingerprint does not match the bytes")
        out_files[name] = raw
    if set(fingerprints) != set(files):
        raise BackupError("backup_rejected: fingerprint list does not match the files")
    return {"format": PAYLOAD_FORMAT, "version": BACKUP_VERSION, "role": role,
            "files": out_files, "fingerprints": dict(fingerprints)}


def _role_files_match(role: str, names) -> bool:
    """Every file the role needs is there, and nothing outside it."""
    allowed = set(_ROLE_FILES[role])
    return allowed - _OPTIONAL_FILES <= set(names) <= allowed


def _checked_file(role: str, name: str, spec) -> bytes:
    """The bytes of one file in a decrypted payload, its encoding and alg checked against what it is."""
    encoding, alg = _ROLE_FILES[role][name]
    if not isinstance(spec, dict) or set(spec) != {"encoding", "alg", "data"} or spec["encoding"] != encoding:
        raise BackupError(f"backup_rejected: {name} is not a {role} backup field")
    if encoding != "pem":
        return _checked_bytes(role, name, spec, alg)
    if not isinstance(spec["data"], str) or not spec["data"].isascii():
        raise BackupError(f"backup_rejected: {name} is not a private key")
    raw = spec["data"].encode("ascii")
    if is_encrypted(raw) and name not in _ENCRYPTABLE:
        raise BackupError(f"backup_rejected: {name} is not a {role} backup field")
    if spec["alg"] != _key_alg(raw, name):
        raise BackupError(f"backup_rejected: {name} is not a {role} backup field")
    return raw


def _checked_bytes(role: str, name: str, spec: dict, alg: str) -> bytes:
    raw = _b64d(spec["data"], name, MAX_BUNDLE_BYTES)
    if spec["encoding"] == "raw" and len(raw) != 32:
        raise BackupError(f"backup_rejected: {name} is not a 32-byte key")
    if spec["alg"] != alg:
        raise BackupError(f"backup_rejected: {name} is not a {role} backup field")
    return raw


def _file_entry(data: bytes, encoding: str, alg: str, name: str) -> dict:
    if encoding == "pem":
        alg = _key_alg(data, name)
        text = data.decode("ascii")
        stored = text
    else:
        stored = _b64e(data)
    return {"encoding": encoding, "alg": alg, "data": stored}


def _payload(role: str, files: dict) -> dict:
    if not _role_files_match(role, files):
        raise BackupError(f"backup_refused: the {role} backup is missing a file")
    stored = {}
    fingerprints = {}
    for name, (encoding, alg) in _ROLE_FILES[role].items():
        if name not in files:
            continue
        data = files[name]
        if not isinstance(data, bytes):
            raise BackupError(f"backup_refused: {name} is not bytes")
        stored[name] = _file_entry(data, encoding, alg, name)
        fingerprints[name] = _sha256(data)
    return {"format": PAYLOAD_FORMAT, "version": BACKUP_VERSION, "role": role,
            "files": stored, "fingerprints": fingerprints}


def _passphrases(mapping) -> dict:
    if not isinstance(mapping, dict) or set(mapping) != set(ROLES):
        raise BackupError("backup_refused: passphrases must name principal, ledger, and witness")
    for role in ROLES:
        _passphrase(mapping[role], role)
    return {role: mapping[role] for role in ROLES}


def _read_bundles(directory: Path, passphrases: dict) -> dict:
    directory = Path(directory)
    opened = {}
    for role, name in BUNDLE_NAMES.items():
        path = directory / name
        if not os.path.lexists(path):
            raise BackupError(f"backup_refused: {path} is missing")
        opened[role] = _decrypt(_read_file(path, MAX_BUNDLE_BYTES), passphrases[role], role)
    return opened


def _ledger_layout(root: Path):
    """Paths a ``Ledger(root / 'ledger', ...)`` would use, for a staged restore."""
    ledger = root / "ledger"
    return {
        "ledger": ledger,
        "principal.pem": root / "principal.pem",
        "capability.pem": ledger.parent / f"{ledger.name}.capability" / "capability.pem",
        _STAMP: ledger.parent / f"{ledger.name}.capability" / _STAMP,
        "witness.pem": ledger.parent / f"{ledger.name}.witness" / "witness.pem",
        "ledger.key": ledger.parent / f"{ledger.name}.ledger-key" / "ledger.key",
        "fingerprint.key": ledger.parent / f"{ledger.name}.ledger-key" / "fingerprint.key",
        "entries.jsonl": ledger / "entries.jsonl",
        "head.json": ledger / "head.json",
        "keywrap.json": ledger / "keywrap.json",
        "head.anchor": ledger.parent / f"{ledger.name}.ledger-key" / "head.anchor",
    }


def _materialize(bundles: dict, root: Path) -> dict:
    layout = _ledger_layout(root)
    files = {}
    for role in ROLES:
        files.update(bundles[role]["files"])
    for name, data in files.items():
        path = layout[name]
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_new(path, data)
    return layout


def _principal_of(data: bytes, key_passphrase: Passphrase):
    if not is_encrypted(data):
        return _load_pem(data, "principal.pem")
    try:
        secret = passphrase_bytes(key_passphrase, "principal.pem (in the backup)")
        if secret is None:
            raise ValueError("key_passphrase_needed: the backup's principal.pem is encrypted; give its "
                             "passphrase (--key-passphrase-file FILE, or type it on a terminal)")
        return decrypt_private_key(data, secret, "principal.pem (in the backup)")
    except ValueError as e:
        raise BackupError(f"backup_rejected: {e}") from None


def _fingerprints_of(bundles: dict, key_passphrase: Passphrase = None) -> dict:
    """Public-style fingerprints an operator can compare. Raw key bytes are not returned."""
    principal = _principal_of(bundles["principal"]["files"]["principal.pem"], key_passphrase)
    capability = _load_pem(bundles["principal"]["files"]["capability.pem"], "capability.pem")
    witness = _load_pem(bundles["witness"]["files"]["witness.pem"], "witness.pem")
    if public_raw(principal.public_key()) == public_raw(capability.public_key()):
        raise BackupError("backup_rejected: the capability key is the principal key")
    stamp = bundles["principal"]["files"].get(_STAMP)
    return {
        "principal": capability_key_fingerprint(principal.public_key()),
        "capability": capability_key_fingerprint(capability.public_key()),
        **({"stamp": key_fingerprint(_load_pem(stamp, _STAMP).public_key())} if stamp is not None else {}),
        "witness": witness_key_fingerprint(public_raw(witness.public_key())),
        "ledger_key": bundles["ledger"]["fingerprints"]["ledger.key"],
        "fingerprint_key": bundles["ledger"]["fingerprints"]["fingerprint.key"],
    }


def _open_staged(root: Path, *, witness_public_key=None, anchor_name: str = "head.anchor",
                 require_anchor: bool = True, key_passphrase: Passphrase = None) -> dict:
    """Open the staged ledger and check the pins. The stage is disposable.

    ``require_anchor`` is false only when the ledger on disk has no anchor file. Opening then
    adopts one in the stage. That adoption is not compared, and it is not copied back.
    """
    from .capability import open_capability_key
    from .ledger import Ledger, LedgerError

    layout = _ledger_layout(root)
    anchor_before = layout["head.anchor"].read_bytes() if require_anchor else None
    try:
        principal = load_private_key_file(layout["principal.pem"], key_passphrase)
    except ValueError as e:
        raise BackupError(f"backup_rejected: {e}") from None
    try:
        ledger = Ledger(layout["ledger"], principal, witness_public_key=witness_public_key,
                        anchor_path=layout["head.anchor"])
    except LedgerError as e:
        raise BackupError(f"backup_rejected: {e}") from None
    if require_anchor and layout["head.anchor"].read_bytes() != anchor_before:
        raise BackupError("backup_rejected: head.anchor is not from the same moment as the ledger")
    try:
        cap = open_capability_key(ledger, principal.public_key())
    except Exception as e:
        raise BackupError(f"backup_rejected: {e}") from None
    # The last constitution_loaded, or keys_upgraded when that is later: right after the key upgrade the
    # capability key is hybrid and the last constitution_loaded still names its Ed25519 fingerprint.
    pinned = pinned_capability_key(ledger)
    got = capability_key_fingerprint(cap.public_key())
    if isinstance(pinned, str) and pinned and pinned != got:
        raise BackupError("backup_rejected: capability key does not match the fingerprint pinned in the ledger")
    issued = any(entry.kind == "capability_issued" for entry in ledger.entries)
    if issued and pinned != got:
        raise BackupError("backup_rejected: the ledger has issued tokens and pins no matching capability key")
    _check_stamp(ledger, layout[_STAMP])
    report = ledger.witness_report()
    return {"ok": True, "ledger_size": ledger.size(), "merkle_root": ledger.merkle_root(),
            "witness": report, "capability_key_fingerprint": got,
            "anchor": anchor_name}


def _check_stamp(ledger, path: Path) -> None:
    """The stamp key is the one the ledger pins, when it pins one: the checking tools hold its public key."""
    from .core import _pinned_stamp_key
    pinned = _pinned_stamp_key(ledger)
    if not pinned:
        return
    if not os.path.lexists(path):
        raise BackupError("backup_rejected: the ledger pins a stamp key (the tool check) and stamp.pem is missing")
    if key_fingerprint(_load_pem(_read_named(path, _STAMP), _STAMP).public_key()) != pinned:
        raise BackupError("backup_rejected: stamp key does not match the fingerprint pinned in the ledger")


def verify_backup(bundles_dir, passphrases, *, witness_public_key=None, key_passphrase: Passphrase = None) -> dict:
    """Decrypt the three bundles into a temporary ledger and check fingerprints. Writes nothing else.
    ``key_passphrase`` opens an encrypted principal.pem in the bundle."""
    phrases = _passphrases(passphrases)
    _warn_passphrases(phrases)
    key_passphrase = remember(key_passphrase)
    bundles = _read_bundles(bundles_dir, phrases)
    fingerprints = _fingerprints_of(bundles, key_passphrase)
    with tempfile.TemporaryDirectory(prefix="two-key-backup-") as tmp:
        _materialize(bundles, Path(tmp))
        opened = _open_staged(Path(tmp), witness_public_key=witness_public_key, key_passphrase=key_passphrase)
    return {"ok": True, "fingerprints": fingerprints, "ledger_size": opened["ledger_size"],
            "merkle_root": opened["merkle_root"], "witness": opened["witness"],
            "capability_key_fingerprint": opened["capability_key_fingerprint"],
            "format": FORMAT, "alg": ALG}


def _destination_paths(ledger_path, principal_path, anchor_path) -> dict:
    ledger_path = Path(ledger_path)
    anchor = Path(anchor_path) if anchor_path else (
        ledger_path.parent / f"{ledger_path.name}.ledger-key" / "head.anchor")
    ledger_abs = ledger_path.resolve()
    anchor_abs = anchor.resolve()
    if anchor_abs == ledger_abs or ledger_abs in anchor_abs.parents:
        raise BackupError("backup_refused: head anchor must live outside the ledger directory")
    return {
        "principal.pem": Path(principal_path),
        "capability.pem": ledger_path.parent / f"{ledger_path.name}.capability" / "capability.pem",
        _STAMP: ledger_path.parent / f"{ledger_path.name}.capability" / _STAMP,
        "witness.pem": ledger_path.parent / f"{ledger_path.name}.witness" / "witness.pem",
        "ledger.key": ledger_path.parent / f"{ledger_path.name}.ledger-key" / "ledger.key",
        "fingerprint.key": ledger_path.parent / f"{ledger_path.name}.ledger-key" / "fingerprint.key",
        "entries.jsonl": ledger_path / "entries.jsonl",
        "head.json": ledger_path / "head.json",
        "keywrap.json": ledger_path / "keywrap.json",
        "head.anchor": anchor,
    }


def _same_bytes(path: Path, data: bytes, name: str) -> bool:
    if not os.path.lexists(path):
        return False
    return _read_named(path, name) == data


def _install(path: Path, data: bytes, *, overwrite: bool, name: str) -> str:
    """Write ``data`` unless the same bytes are already there. Never follows a symlink."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.path.lexists(path):
        current = _read_named(path, name)
        if current == data:
            return "unchanged"
        if not overwrite:
            raise BackupError(f"backup_conflict: {path} differs from the backup and was not overwritten")
        tmp = path.parent / f".{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
        try:
            _write_new(tmp, data)
            _platform.replace(tmp, path)
        finally:
            if os.path.lexists(tmp):
                os.unlink(tmp)
        _fsync_dir(path.parent)
        return "replaced"
    _write_new(path, data)
    _fsync_dir(path.parent)
    return "created"


_LEDGER_BODY = ("entries.jsonl", "head.json", "keywrap.json")
_KEY_FILES = ("principal.pem", "capability.pem", _STAMP, "witness.pem", "ledger.key", "fingerprint.key")
# Public halves restored beside their keys when missing: tool-key trust reads them for a checking tool.
_PUBLIC_FILES = {"capability.pem": "capability.pub.pem", _STAMP: "stamp.pub.pem"}


def _exists_differs(path: Path, data: bytes, name: str) -> bool:
    return os.path.lexists(path) and not _same_bytes(path, data, name)


def restore_backup(ledger_path, principal_path, bundles_dir, passphrases, *,
                   witness_public_key=None, anchor_path=None, replace_ledger: bool = False,
                   key_passphrase: Passphrase = None) -> dict:
    """Put the keys back. The ledger and ``head.anchor`` are written together, or not at all.

    An existing ledger whose files differ from the backup is left in place unless ``replace_ledger``
    is set. Setting it writes the backup's ledger files, then the keys, then that backup's
    ``head.anchor``. Deleting the anchor is not a step this function takes. When the ledger
    files already match the backup, a missing or different anchor is written back from the same bundle
    without that flag: it is the anchor from that moment, not a deletion.

    A newer ledger keeps a key file that is already there, even when the backup has an older copy
    (a witness rotated after the backup). Only a missing key file is created from the backup, and
    only after that mix opens the ledger on disk. A key that differs while the ledger files still
    match the backup is ``backup_conflict`` and is not overwritten.

    An encrypted principal.pem is restored as it was backed up, still encrypted; ``key_passphrase`` opens it.
    """
    phrases = _passphrases(passphrases)
    _warn_passphrases(phrases)
    key_passphrase = remember(key_passphrase)
    bundles = _read_bundles(bundles_dir, phrases)
    fingerprints = _fingerprints_of(bundles, key_passphrase)
    files = {}
    for role in ROLES:
        files.update(bundles[role]["files"])
    dest = _destination_paths(ledger_path, principal_path, anchor_path)
    with tempfile.TemporaryDirectory(prefix="two-key-backup-") as tmp:
        _materialize(bundles, Path(tmp))
        opened = _open_staged(Path(tmp), witness_public_key=witness_public_key, key_passphrase=key_passphrase)
    files_differ = any(_exists_differs(dest[name], files[name], name) for name in _LEDGER_BODY)
    files_missing = any(not os.path.lexists(dest[name]) for name in _LEDGER_BODY)
    anchor_differs = _exists_differs(dest["head.anchor"], files["head.anchor"], "head.anchor")
    anchor_missing = not os.path.lexists(dest["head.anchor"])
    write_files = False
    write_anchor = False
    key_only = False
    if files_differ or (files_missing and anchor_differs):
        if not replace_ledger:
            if files_differ and not files_missing:
                _preflight_live(dest, files, witness_public_key=witness_public_key, key_passphrase=key_passphrase)
                key_only = True
            else:
                raise BackupError(
                    "backup_refused: the destination ledger differs from the backup. "
                    "Pass replace_ledger to put the backup's ledger and head.anchor back together. "
                    "Deleting the anchor is not the restore procedure.")
        else:
            if files_differ or files_missing:
                print("two-key: WARNING: replace_ledger writes the backup's ledger and head.anchor over "
                      "the destination. Entries checkpointed after that backup are gone, and a token spent "
                      "after it can look unspent.", file=sys.stderr)
            write_files = True
            write_anchor = True
    elif files_missing:
        write_files = True
        write_anchor = True
    elif anchor_missing or anchor_differs:
        # The ledger bytes are the backup's bytes. Put that moment's anchor back. Do not delete it.
        write_anchor = True
    actions = {}
    # Ledger body, then keys, then the anchor. A crash before the anchor leaves a ledger that
    # refuses to open (ledger_rolled_back) instead of advancing a newer anchor past the backup.
    # Decide every conflict before writing, so a refusal does not leave a half-applied restore.
    order = list(_LEDGER_BODY) if write_files else []
    order += [name for name in _KEY_FILES if name in files]
    if write_anchor:
        order.append("head.anchor")
    pending = []
    for name in order:
        overwrite = ((name in _KEY_FILES and replace_ledger)
                     or (name in _LEDGER_BODY and write_files)
                     or (name == "head.anchor" and write_anchor))
        path = dest[name]
        if os.path.lexists(path):
            if _read_named(path, name) == files[name]:
                actions[name] = "unchanged"
                continue
            if key_only and name in _KEY_FILES:
                # The ledger on disk is newer and this key is the one that opened it. Do not roll it back.
                actions[name] = "kept"
                continue
            if not overwrite:
                raise BackupError(f"backup_conflict: {path} differs from the backup and was not overwritten. "
                                  "Move that file aside and run restore again. Do not delete head.anchor.")
        pending.append(name)
    if any(actions.get(name) == "kept" for name in _KEY_FILES):
        print("two-key: WARNING: a key file on disk differs from the backup and was left in place. "
              "A restore onto a newer ledger does not roll a key back. Move that file aside and run "
              "restore again if you meant to put the backup's copy there. Do not delete head.anchor.",
              file=sys.stderr)
    for name in pending:
        actions[name] = _install(dest[name], files[name], overwrite=True, name=name)
    _restore_public_files(dest, files, actions)
    return {"ok": True, "actions": actions, "replaced_ledger": bool(replace_ledger and (files_differ or files_missing)),
            "fingerprints": fingerprints, "ledger_size": opened["ledger_size"],
            "format": FORMAT, "alg": ALG}


def _restore_public_files(dest: dict, files: dict, actions: dict) -> None:
    """Write ``capability.pub.pem`` and ``stamp.pub.pem`` from the backup's key where that key is now in place and
    the public file is missing or holds another key."""
    for name, public_name in _PUBLIC_FILES.items():
        if name not in files or actions.get(name) == "kept":
            continue
        key = _load_pem(files[name], name).public_key()
        public = dest[name].with_name(public_name)
        if not os.path.lexists(public):
            actions[public_name] = "created"
        elif not _platform.is_link(public) and not _holds(public, key):
            actions[public_name] = "replaced"
        else:
            continue
        save_public_key(public, key)


def _holds(path: Path, public) -> bool:
    try:
        return public_raw(load_public_key(path)) == public_raw(public)
    except (OSError, ValueError):
        return False


def _preflight_live(dest: dict, files: dict, *, witness_public_key, key_passphrase: Passphrase = None) -> None:
    """Open a copy of the ledger on disk. Write nothing to ``dest``.

    A key that is already on disk is the one opened, including a witness rotated after the backup.
    A missing key comes from the backup. The backup's old witness is not required to open a ledger
    that has already moved on.
    """
    from .ledger import LedgerError
    with tempfile.TemporaryDirectory(prefix="two-key-live-") as tmp:
        root = Path(tmp)
        layout = _ledger_layout(root)
        for name in ("entries.jsonl", "head.json", "keywrap.json"):
            data = _read_named(dest[name], name)
            layout[name].parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _write_new(layout[name], data)
        anchor_present = os.path.lexists(dest["head.anchor"])
        if anchor_present:
            layout["head.anchor"].parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _write_new(layout["head.anchor"], _read_named(dest["head.anchor"], "head.anchor"))
        for name in _KEY_FILES:
            if os.path.lexists(dest[name]):
                data = _read_named(dest[name], name)
            elif name in files:
                data = files[name]
            else:
                continue
            layout[name].parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _write_new(layout[name], data)
        try:
            _open_staged(root, witness_public_key=witness_public_key, require_anchor=anchor_present,
                         key_passphrase=key_passphrase)
        except BackupError as e:
            raise BackupError("backup_rejected: those keys do not open the ledger on disk "
                              f"({e}). The destination was not changed.") from None
        except LedgerError as e:
            raise BackupError(f"backup_rejected: {e}. The destination was not changed.") from None


def export_backup(ledger_path, principal_path, out_dir, passphrases, *,
                  witness_public_key=None, anchor_path=None, iterations: int = PBKDF2_ITERATIONS,
                  key_passphrase: Passphrase = None) -> dict:
    """Encrypt the three bundles. Refuses to start when a key this package created is missing,
    when a witness rotation is unfinished, or when the copied bytes would not open as a ledger.

    The ledger lock is held while the files are copied into memory, so the three bundles are one
    moment. Those bytes are opened in a temporary directory before any bundle is written. A copy
    that would not restore is ``backup_refused`` and leaves the output directory untouched.
    """
    from .ledger import Ledger, LedgerError

    phrases = _passphrases(passphrases)
    iterations = _iterations(iterations)
    _warn_passphrases(phrases)
    key_passphrase = remember(key_passphrase)
    try:
        principal = load_private_key_file(principal_path, key_passphrase)
    except ValueError as e:
        raise BackupError(f"backup_refused: {e}") from None
    try:
        ledger = Ledger(ledger_path, principal, witness_public_key=witness_public_key, anchor_path=anchor_path)
    except LedgerError as e:
        raise BackupError(f"backup_refused: {e}") from None
    try:
        with ledger.exclusive():
            groups = _snapshot_files(ledger, principal_path)
    except LedgerError as e:       # a BackupError from the snapshot is not a LedgerError and passes through
        raise BackupError(f"backup_refused: {e}") from None
    _require_snapshot_opens(groups, witness_public_key=witness_public_key, key_passphrase=key_passphrase)
    out = _prepare_output_dir(Path(out_dir))
    for role, name in BUNDLE_NAMES.items():
        if os.path.lexists(out / name):
            raise BackupError(f"backup_conflict: refusing to overwrite {out / name}")
    payloads = {role: _payload(role, groups[role]) for role in ROLES}
    blobs = {role: _encrypt(role, payloads[role], phrases[role], iterations) for role in ROLES}
    decoded = {role: _check_payload(loads_json(canonical_bytes(payloads[role])), role) for role in ROLES}
    fingerprints = _fingerprints_of(decoded, key_passphrase)
    written = {}
    created: list[Path] = []
    try:
        for role, name in BUNDLE_NAMES.items():
            path = out / name
            _write_new(path, blobs[role])
            created.append(path)
            written[role] = str(path)
        if created:
            _fsync_dir(created[0].parent)
    except Exception:
        for path in created:
            try:
                os.unlink(path)
            except OSError:
                pass
        raise
    from .upgrade import backup_made
    backup_made(ledger.ledger_key_path)      # the key upgrade's reminder to back up stops here
    return {"ok": True, "bundles": written, "fingerprints": fingerprints,
            "ledger_size": ledger.size(), "iterations": iterations,
            "kdf": KDF_NAME, "alg": ALG, "format": FORMAT}


def _prepare_output_dir(out: Path) -> Path:
    """The directory the bundles are written into. A symlink is refused, not followed.

    An existing directory the group or others can write is refused. A new directory is created
    mode 0700. The bundles themselves are mode 0600; this is about where those files land.
    """
    out = Path(out)
    if os.path.lexists(out):
        if _platform.is_link(out):
            raise BackupError("backup_refused: the output directory is a symlink")
        st = os.lstat(out)
        if not stat.S_ISDIR(st.st_mode):
            raise BackupError("backup_refused: the output directory is not a directory")
        problem = _platform.dir_write_problem(out)
        if problem and not _platform.WINDOWS:
            raise BackupError("backup_refused: the output directory is writable by group or others")
        if problem:
            raise BackupError(f"backup_refused: the output directory is writable by other accounts: {problem}")
        return out
    try:
        out.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        raise BackupError("backup_refused: the output directory is a symlink") from None
    except OSError as e:
        raise BackupError(f"backup_refused: cannot create the output directory ({e.strerror})") from None
    return out


def _snapshot_files(ledger, principal_path) -> dict:
    """Copy the backup's files while the caller holds the ledger lock. One moment, in memory."""
    pending = ledger.witness_path.with_name("witness.pem.new")
    if os.path.lexists(pending):
        raise BackupError("backup_refused: witness rotation is unfinished (witness.pem.new); "
                          "finish it or remove that file before export")
    cap_path = ledger.capability_key_path()
    fp_path = ledger.fingerprint_key_path()
    if not os.path.lexists(cap_path) or not os.path.lexists(fp_path):
        raise BackupError("backup_refused: the capability key or the fingerprint key is missing. "
                          "Start TwoKey once so both exist, then export. Export does not create them.")
    anchor = _read_file(ledger.anchor_path(), MAX_BUNDLE_BYTES)
    stamp_path = cap_path.with_name(_STAMP)
    stamp = {_STAMP: _read_file(stamp_path, MAX_BUNDLE_BYTES)} if os.path.lexists(stamp_path) else {}
    return {
        "principal": {
            "principal.pem": _read_file(Path(principal_path), MAX_BUNDLE_BYTES),
            "capability.pem": _read_file(cap_path, MAX_BUNDLE_BYTES),
            **stamp,
        },
        "witness": {"witness.pem": _read_file(ledger.witness_path, MAX_BUNDLE_BYTES)},
        "ledger": {
            "ledger.key": _read_file(ledger.ledger_key_path, MAX_BUNDLE_BYTES),
            "fingerprint.key": _read_file(fp_path, MAX_BUNDLE_BYTES),
            "entries.jsonl": _read_named(ledger.entries_path, "entries.jsonl"),
            "head.json": _read_named(ledger.head_path, "head.json"),
            "keywrap.json": _read_named(ledger.wrap_path, "keywrap.json"),
            "head.anchor": anchor,
        },
    }


def _require_snapshot_opens(groups: dict, *, witness_public_key, key_passphrase: Passphrase = None) -> None:
    """Refuse before any bundle is written when these bytes would not restore."""
    bundles = {}
    for role in ROLES:
        bundles[role] = _check_payload(
            {"format": PAYLOAD_FORMAT, "version": BACKUP_VERSION, "role": role,
             "files": {name: _file_entry(data, *_ROLE_FILES[role][name], name) for name, data in groups[role].items()},
             "fingerprints": {name: _sha256(data) for name, data in groups[role].items()}},
            role)
    try:
        with tempfile.TemporaryDirectory(prefix="two-key-backup-") as tmp:
            _materialize(bundles, Path(tmp))
            _open_staged(Path(tmp), witness_public_key=witness_public_key, key_passphrase=key_passphrase)
    except BackupError as e:
        raise BackupError(f"backup_refused: this backup would not open ({e}). Nothing was written.") from None
