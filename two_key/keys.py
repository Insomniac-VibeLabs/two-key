# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Two-Key's signing keys: hybrid Ed25519 + ML-DSA-65 (FIPS 204) from 0.9.0, and the Ed25519 keys of 0.8.0.

Every key Two-Key makes is a hybrid: an Ed25519 key and an ML-DSA-65 key that sign together. A hybrid
signature is both signatures over the same labelled message (``hybrid_message``), and it verifies only when
both do, so a forger has to break both algorithms. A classical (Ed25519-only) key is read only to upgrade a
0.8.0 deployment (``two_key/upgrade.py``); a hybrid public key never accepts a classical signature.

All signing and verifying goes through this module (``sign``, ``verify``), so a later backend (FIPS 140-3
mode, 1.0.0) changes one place.

A key file is unencrypted PEM, or, with a passphrase, Two-Key's own encrypted form (``BEGIN TWO-KEY
ENCRYPTED PRIVATE KEY``): the key sealed with AES-256-GCM under a key from PBKDF2-SHA256 at 600,000
iterations, the construction ``backup.py`` uses, with every header field bound in as associated data. A
hybrid key file holds two standard PKCS8 blocks, the Ed25519 key then the ML-DSA-65 key (seed form); its
encrypted form seals both (format ``two-key-encrypted-key/2``). A passphrase comes from a file only its owner
can read, or from a prompt on a terminal; never from the command line or the environment (docs/SETUP.md).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Callable, Union

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
try:
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey
except ImportError:                 # cryptography before 48, or one built against an OpenSSL before 3.5
    MLDSA65PrivateKey = MLDSA65PublicKey = None
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import _platform

ENCRYPTED_FORMAT = "two-key-encrypted-key/1"          # a classical key (0.8.0): the PKCS8 DER
HYBRID_ENCRYPTED_FORMAT = "two-key-encrypted-key/2"   # a hybrid key: its two PKCS8 PEM blocks
KDF_NAME = "pbkdf2-sha256"
ENC_NAME = "aes-256-gcm"
KDF_ITERATIONS = 600_000            # NIST SP 800-132, as backup.py; a file asking for fewer is refused
MAX_ITERATIONS = 10_000_000         # a file cannot ask this machine to run forever
KDF_LENGTH = 32
SALT_BYTES = 16
NONCE_BYTES = 12
MIN_PASSPHRASE_BYTES = 12           # for a new passphrase; shorter is refused
MAX_PASSPHRASE_BYTES = 1024
NOT_ED25519 = "key_file_invalid: a Two-Key key is a hybrid Ed25519 + ML-DSA-65 key (or a 0.8.0 Ed25519 key)"
# The suites, as signed objects and fingerprints name them.
HYBRID_ALG = "ed25519+ml-dsa-65"
CLASSICAL_ALG = "ed25519"
HYBRID_LABEL = b"two-key-hybrid/1"
ML_DSA_CONTEXT = b"two-key"                 # the FIPS 204 context string
ED_SIG_BYTES, ML_SIG_BYTES = 64, 3309
ED_PUB_BYTES, ML_PUB_BYTES = 32, 1952
ML_DSA_UNAVAILABLE = ("ml_dsa_unavailable: this Python's cryptography package cannot make ML-DSA-65 signatures "
                      "(it needs cryptography 48 or later, built with OpenSSL 3.5 or later, as the PyPI wheels are); "
                      "install it with pip install --upgrade 'cryptography>=48'")
MAX_KEY_FILE_BYTES = 64 * 1024
_KEY_FILE = "the key file"               # what a message calls a key file when it has no name
_ENCRYPTED_BEGIN = b"-----BEGIN TWO-KEY ENCRYPTED PRIVATE KEY-----"
_ENCRYPTED_END = b"-----END TWO-KEY ENCRYPTED PRIVATE KEY-----"
_OPENSSL_ENCRYPTED = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
_HEADER_FIELDS = ("format", "kdf", "enc", "ciphertext")
_KDF_FIELDS = ("name", "iterations", "salt", "length")
_ENC_FIELDS = ("name", "nonce")

# A passphrase, or what to call for one (given the key file's path) when the file turns out to be
# encrypted. ``None`` means there is none to give.
Passphrase = Union[bytes, Callable[[str], bytes], None]


class HybridPublicKey:
    """The public half of a hybrid key: an Ed25519 public key and an ML-DSA-65 public key."""

    __slots__ = ("ed", "ml")

    def __init__(self, ed: Ed25519PublicKey, ml):
        self.ed, self.ml = ed, ml

    def raw(self) -> bytes:
        """The 32-byte Ed25519 key then the 1,952-byte ML-DSA-65 key: what fingerprints and pins hash."""
        return self.ed.public_bytes_raw() + self.ml.public_bytes_raw()

    def public_bytes(self, encoding, fmt) -> bytes:
        """``Raw``/``Raw`` is ``raw()``; PEM is the two SubjectPublicKeyInfo blocks, Ed25519 first."""
        if encoding == serialization.Encoding.Raw:
            return self.raw()
        return self.ed.public_bytes(encoding, fmt) + self.ml.public_bytes(encoding, fmt)

    def __eq__(self, other) -> bool:
        return isinstance(other, HybridPublicKey) and other.raw() == self.raw()

    def __hash__(self) -> int:
        return hash(self.raw())


class HybridPrivateKey:
    """A hybrid signing key: an Ed25519 key and an ML-DSA-65 key, kept and used as one."""

    __slots__ = ("ed", "ml")

    def __init__(self, ed: Ed25519PrivateKey, ml):
        self.ed, self.ml = ed, ml

    def public_key(self) -> HybridPublicKey:
        return HybridPublicKey(self.ed.public_key(), self.ml.public_key())

    def private_bytes(self, encoding, fmt, encryption) -> bytes:
        """The two PKCS8 blocks, Ed25519 first: the hybrid key file's content."""
        return self.ed.private_bytes(encoding, fmt, encryption) + self.ml.private_bytes(encoding, fmt, encryption)


def ml_dsa_available() -> bool:
    """Whether this Python can make and check ML-DSA-65 signatures."""
    if MLDSA65PrivateKey is None:
        return False
    try:
        MLDSA65PrivateKey.from_seed_bytes(bytes(32))
    except (UnsupportedAlgorithm, ValueError, TypeError):
        return False
    return True


def require_ml_dsa() -> None:
    """Refuse (``ml_dsa_unavailable``) where ML-DSA-65 is missing. Two-Key never falls back to Ed25519 alone."""
    if not ml_dsa_available():
        raise ValueError(ML_DSA_UNAVAILABLE)


def generate_private_key() -> HybridPrivateKey:
    """A new hybrid key. Where ML-DSA-65 is missing this refuses (``ml_dsa_unavailable``)."""
    require_ml_dsa()
    return HybridPrivateKey(Ed25519PrivateKey.generate(), MLDSA65PrivateKey.generate())


def add_ml_dsa(private_key) -> HybridPrivateKey:
    """A 0.8.0 Ed25519 key made hybrid: the same Ed25519 key, with a new ML-DSA-65 key beside it."""
    require_ml_dsa()
    if isinstance(private_key, HybridPrivateKey):
        return private_key
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError(NOT_ED25519)
    return HybridPrivateKey(private_key, MLDSA65PrivateKey.generate())


def is_hybrid(key) -> bool:
    """Whether ``key`` (private or public) is a hybrid key."""
    return isinstance(key, (HybridPrivateKey, HybridPublicKey))


def classical_half(key):
    """The Ed25519 half of a hybrid key (private or public): the 0.8.0 key it was made from by ``add_ml_dsa``.
    A classical key is returned as it is."""
    return key.ed if is_hybrid(key) else key


def key_alg(key) -> str:
    """The suite ``key`` (private or public) signs with: ``HYBRID_ALG`` or ``CLASSICAL_ALG``."""
    return HYBRID_ALG if is_hybrid(key) else CLASSICAL_ALG


def public_key(private_key):
    return private_key.public_key()


def _raw_public(public) -> bytes:
    if isinstance(public, HybridPublicKey):
        return public.raw()
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(public) -> str:
    """A short form for messages: the first 16 hex digits of the SHA-256 of the raw public key."""
    return hashlib.sha256(_raw_public(public)).hexdigest()[:16]


def key_fingerprint(public) -> str:
    """The pin of a public key: ``hybrid-sha256:<hex>`` for a hybrid key (both halves, one value), or
    ``sha256:<hex>`` for an Ed25519 key, so a fingerprint always says which kind of key it is."""
    prefix = "hybrid-sha256:" if isinstance(public, HybridPublicKey) else "sha256:"
    return prefix + hashlib.sha256(_raw_public(public)).hexdigest()


def save_private_key(path: Path | str, private_key, *, private_dir: bool = False,
                     passphrase: bytes | None = None) -> None:
    """Create a new key file, mode 0600 from the first byte. Never overwrite one.

    The file is opened with O_CREAT | O_EXCL (and O_NOFOLLOW where available), so an
    existing file or a planted symlink is an error rather than a silent overwrite, and
    there is no window in which the key is readable before a chmod. On Windows it gets a
    private access list instead of mode 0600 (``two_key._platform``). A directory this
    creates is mode 0700. ``private_dir=True`` also sets an existing directory to 0700
    (a private access list on Windows); use it for directories Two-Key owns, such as
    ``<ledger>.capability``. With ``passphrase``, the file is the encrypted form (``encrypt_private_key``).
    """
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if private_dir:
        _platform.owner_only_dir(path.parent)
    data = private_key_bytes(private_key, passphrase)
    fd = _platform.create_new(path)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def private_key_bytes(private_key, passphrase: bytes | None = None) -> bytes:
    """What a key file holds: unencrypted PKCS8 PEM, or the encrypted form when there is a passphrase."""
    if passphrase is not None:
        return encrypt_private_key(private_key, passphrase)
    return private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text, limit: int) -> bytes:
    if not isinstance(text, str) or len(text) > limit * 4 // 3 + 8:
        raise ValueError
    return base64.b64decode(text, validate=True)


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _derive(passphrase: bytes, salt: bytes, iterations: int) -> bytes:
    return PBKDF2HMAC(SHA256(), KDF_LENGTH, salt, iterations).derive(passphrase)


def check_new_passphrase(passphrase: bytes) -> bytes:
    """A passphrase for a new encrypted key: 12 to 1024 bytes, no NUL, not all whitespace."""
    if not isinstance(passphrase, bytes) or len(passphrase) > MAX_PASSPHRASE_BYTES:
        raise ValueError(f"key_passphrase_invalid: a passphrase is at most {MAX_PASSPHRASE_BYTES} bytes")
    if b"\0" in passphrase or not passphrase.strip():
        raise ValueError("key_passphrase_invalid: the passphrase is empty or has a NUL byte")
    if len(passphrase) < MIN_PASSPHRASE_BYTES:
        raise ValueError(f"key_passphrase_short: the passphrase is {len(passphrase)} bytes; use at least "
                         f"{MIN_PASSPHRASE_BYTES} (a generated one is best: docs/SETUP.md)")
    return passphrase


def encrypt_private_key(private_key, passphrase: bytes) -> bytes:
    """The encrypted key file: the key under AES-256-GCM, its key from PBKDF2-SHA256, the header as AAD. A hybrid
    key seals its two PKCS8 PEM blocks (format /2); a 0.8.0 Ed25519 key its PKCS8 DER (format /1)."""
    check_new_passphrase(passphrase)
    hybrid = isinstance(private_key, HybridPrivateKey)
    plain = private_key.private_bytes(serialization.Encoding.PEM if hybrid else serialization.Encoding.DER,
                                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    salt, nonce = os.urandom(SALT_BYTES), os.urandom(NONCE_BYTES)
    header = {"format": HYBRID_ENCRYPTED_FORMAT if hybrid else ENCRYPTED_FORMAT,
              "kdf": {"name": KDF_NAME, "iterations": KDF_ITERATIONS, "salt": _b64e(salt), "length": KDF_LENGTH},
              "enc": {"name": ENC_NAME, "nonce": _b64e(nonce)}}
    ciphertext = AESGCM(_derive(passphrase, salt, KDF_ITERATIONS)).encrypt(nonce, plain, _canonical(header))
    header["ciphertext"] = _b64e(ciphertext)
    body = base64.encodebytes(_canonical(header))
    return _ENCRYPTED_BEGIN + b"\n" + body + _ENCRYPTED_END + b"\n"


def is_encrypted(data: bytes) -> bool:
    """Whether key file bytes are Two-Key's encrypted form (by its armour; ``encrypted_header`` checks it)."""
    return data.lstrip().startswith(_ENCRYPTED_BEGIN)


def encrypted_header(data: bytes, what: str = _KEY_FILE) -> dict:
    """The parsed header of an encrypted key file, every field checked, nothing decrypted. A file that
    is not exactly that form is ``key_file_invalid``."""
    bad = ValueError(f"key_file_invalid: {what} is not a Two-Key encrypted private key")
    text = data.strip()
    if not (text.startswith(_ENCRYPTED_BEGIN) and text.endswith(_ENCRYPTED_END)):
        raise bad
    try:
        header = json.loads(base64.b64decode(b"".join(text[len(_ENCRYPTED_BEGIN):-len(_ENCRYPTED_END)].split()),
                                             validate=True))
        if not isinstance(header, dict) or set(header) != set(_HEADER_FIELDS):
            raise ValueError
        kdf, enc = header["kdf"], header["enc"]
        if (header["format"] not in (ENCRYPTED_FORMAT, HYBRID_ENCRYPTED_FORMAT) or not isinstance(kdf, dict) or set(kdf) != set(_KDF_FIELDS)
                or not isinstance(enc, dict) or set(enc) != set(_ENC_FIELDS) or kdf["name"] != KDF_NAME
                or kdf["length"] != KDF_LENGTH or enc["name"] != ENC_NAME):
            raise ValueError
        iterations = kdf["iterations"]
        if type(iterations) is not int or not KDF_ITERATIONS <= iterations <= MAX_ITERATIONS:
            raise ValueError
        if len(_b64d(kdf["salt"], 64)) != SALT_BYTES or len(_b64d(enc["nonce"], 32)) != NONCE_BYTES:
            raise ValueError
        _b64d(header["ciphertext"], MAX_KEY_FILE_BYTES)
    except (ValueError, TypeError, KeyError):
        raise bad from None
    return header


def decrypt_private_key(data: bytes, passphrase: bytes, what: str = _KEY_FILE):
    """Open the encrypted form. A wrong passphrase, or a file changed by one bit, is ``key_passphrase_wrong``."""
    header = encrypted_header(data, what)
    if not isinstance(passphrase, bytes) or not passphrase or len(passphrase) > MAX_PASSPHRASE_BYTES:
        raise ValueError(f"key_passphrase_wrong: the passphrase does not open {what}")
    kdf, enc = header["kdf"], header["enc"]
    aad = _canonical({k: header[k] for k in _HEADER_FIELDS if k != "ciphertext"})
    try:
        plain = AESGCM(_derive(passphrase, _b64d(kdf["salt"], 64), kdf["iterations"])).decrypt(
            _b64d(enc["nonce"], 32), _b64d(header["ciphertext"], MAX_KEY_FILE_BYTES), aad)
    except InvalidTag:
        raise ValueError(f"key_passphrase_wrong: the passphrase does not open {what} (or the file was "
                         "changed)") from None
    if header["format"] == HYBRID_ENCRYPTED_FORMAT:
        return private_key_from_pem(plain, what)
    try:
        key = serialization.load_der_private_key(plain, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm):
        raise ValueError(f"key_file_invalid: {what} does not hold a private key") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(NOT_ED25519)
    return key


_PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z ]+)-----\r?\n.*?-----END \1-----\r?\n?", re.S)


def _pem_blocks(data: bytes, label: bytes) -> list[bytes] | None:
    """The PEM blocks of ``data`` when it is nothing but blocks with this label (blank space between is
    fine); else None."""
    blocks, at = [], 0
    for match in _PEM_BLOCK.finditer(data):
        if data[at:match.start()].strip() or match.group(1) != label:
            return None
        blocks.append(match.group(0))
        at = match.end()
    return blocks if blocks and not data[at:].strip() else None


def private_key_from_pem(data: bytes, what: str = _KEY_FILE):
    """A key from unencrypted PEM: one Ed25519 block (a 0.8.0 key), or an Ed25519 block then an ML-DSA-65
    block (a hybrid key). Anything else is ``key_file_invalid``."""
    blocks = _pem_blocks(data, b"PRIVATE KEY")
    invalid = ValueError(f"key_file_invalid: {what} is not an unencrypted PEM private key, or Two-Key's encrypted "
                         "form")
    if blocks is None or len(blocks) > 2:
        raise invalid
    if len(blocks) == 2:
        require_ml_dsa()
    try:
        keys = [serialization.load_pem_private_key(block, password=None) for block in blocks]
    except (TypeError, ValueError, UnsupportedAlgorithm):
        raise invalid from None
    if not isinstance(keys[0], Ed25519PrivateKey):
        raise ValueError(NOT_ED25519)
    if len(keys) == 1:
        return keys[0]
    if MLDSA65PrivateKey is None or not isinstance(keys[1], MLDSA65PrivateKey):
        raise ValueError(NOT_ED25519)
    return HybridPrivateKey(keys[0], keys[1])


def public_key_from_pem(data: bytes, what: str = "the public key file"):
    """A public key from PEM: one Ed25519 block, or an Ed25519 block then an ML-DSA-65 block (hybrid)."""
    blocks = _pem_blocks(data, b"PUBLIC KEY")
    invalid = ValueError(f"public_key_invalid: {what} is not a Two-Key public key (PEM: Ed25519, then ML-DSA-65)")
    if blocks is None or len(blocks) > 2:
        raise invalid
    if len(blocks) == 2:
        require_ml_dsa()
    try:
        keys = [serialization.load_pem_public_key(block) for block in blocks]
    except (TypeError, ValueError, UnsupportedAlgorithm):
        raise invalid from None
    if not isinstance(keys[0], Ed25519PublicKey):
        raise invalid
    if len(keys) == 1:
        return keys[0]
    if MLDSA65PublicKey is None or not isinstance(keys[1], MLDSA65PublicKey):
        raise invalid
    return HybridPublicKey(keys[0], keys[1])


def _read_owner_only(path, code: str, limit: int) -> tuple[bytes, str | None, int]:
    """The bytes of a file only its owner can read or write: no link, a regular file, at most ``limit``
    bytes. Returns the bytes, the access problem and the mode, which the caller turns into its own refusal (a public
    key given as a private key is told apart first)."""
    try:
        fd = _platform.open_nofollow(path)
    except OSError as e:
        raise ValueError(f"{code}_unreadable: {path}: {e.strerror}") from None
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{code}_insecure: {path} is not a regular file")
        problem = _platform.access_problem(fh.fileno(), st)
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{code}_invalid: {path} is over {limit} bytes")
    return data, problem, st.st_mode


def _insecure(path, code: str, problem: str, st_mode: int) -> ValueError:
    if not _platform.WINDOWS:
        return ValueError(f"{code}_insecure: {path} is mode {stat.S_IMODE(st_mode):04o}; run chmod 600 {path}")
    return ValueError(f"{code}_insecure: {_platform.insecure(path, problem)}")


def read_passphrase_file(path: Path | str) -> bytes:
    """A passphrase from a file only its owner can read: one line, at most 1024 bytes. One trailing
    newline (``\\n`` or ``\\r\\n``) is not part of it. The passphrase is never printed."""
    data, problem, mode = _read_owner_only(path, "passphrase_file", MAX_PASSPHRASE_BYTES + 2)
    if problem:
        raise _insecure(path, "passphrase_file", problem, mode)
    if data.endswith(b"\r\n"):
        data = data[:-2]
    elif data.endswith(b"\n"):
        data = data[:-1]
    if not data or b"\n" in data or b"\0" in data or len(data) > MAX_PASSPHRASE_BYTES:
        raise ValueError(f"passphrase_file_invalid: {path} must hold one line of 1 to {MAX_PASSPHRASE_BYTES} "
                         "bytes")
    return data


def prompt_passphrase(path: str, *, new: bool = False) -> bytes:
    """Ask on the terminal, without echo. No terminal (a pipe, a script, an agent) is a refusal."""
    import getpass
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        raise ValueError(f"key_passphrase_needed: {path} is encrypted and there is no terminal to ask for its "
                         "passphrase on; give --key-passphrase-file FILE")
    try:
        first = getpass.getpass(f"{'New passphrase' if new else 'Passphrase'} for {path}: ").encode("utf-8")
        if not new:
            return first
        check_new_passphrase(first)
        if getpass.getpass("The same passphrase again: ").encode("utf-8") != first:
            raise ValueError("key_passphrase_mismatch: the two passphrases differ; nothing was written")
        return first
    except (EOFError, KeyboardInterrupt):
        raise ValueError("key_passphrase_needed: no passphrase was given") from None


def passphrase_source(passphrase_file: Path | str | None = None, *, prompt: bool = True) -> Passphrase:
    """Where a passphrase comes from, asked for only when a key file turns out to be encrypted: the file
    when one is named, else a prompt on the terminal (unless ``prompt`` is false), else none."""
    if passphrase_file is not None:
        return lambda _path: read_passphrase_file(passphrase_file)
    if prompt:
        return lambda path: prompt_passphrase(path)
    return None


def remember(passphrase: Passphrase) -> Passphrase:
    """The same source, asked at most once per key file: a command that opens a key more than once
    prompts once."""
    if not callable(passphrase):
        return passphrase
    got: dict[str, bytes] = {}

    def ask(path: str) -> bytes:
        if path not in got:
            got[path] = passphrase(path)
        return got[path]
    return ask


def passphrase_bytes(passphrase: Passphrase, path: str) -> bytes | None:
    """The bytes a source gives for ``path`` (asking if it is a prompt), or None when there is none."""
    return passphrase(path) if callable(passphrase) else passphrase


def key_file_is_encrypted(path: Path | str) -> bool:
    """Whether the key file at ``path`` is the encrypted form. It reads the file as the loader does."""
    data, _, _ = _read_owner_only(path, "key_file", MAX_KEY_FILE_BYTES)
    return is_encrypted(data)


def load_private_key(path: Path | str):
    return private_key_from_pem(Path(path).read_bytes(), str(path))


_PUBLIC_PEM = b"-----BEGIN PUBLIC KEY-----"


def _public_key_given(path) -> ValueError:
    return ValueError(f"key_file_public: {path} is a public key; give the private key "
                      f"(init-key writes principal.pem, mode 0600, next to principal.pub.pem)")


def load_private_key_file(path: Path | str, passphrase: Passphrase = None):
    """The safe loader for a key file named by an operator, as on the command line.

    It refuses a symlink (O_NOFOLLOW), anything that is not a regular file, and a file
    that the group or others can read or write (``key_file_insecure``). The check is on
    the open descriptor, so the file cannot be swapped between the check and the read.
    A public key is ``key_file_public`` (whatever its mode: chmod would not help), and a
    file that is neither an unencrypted PEM private key nor Two-Key's encrypted form is
    ``key_file_invalid``.

    An encrypted file needs ``passphrase``: the bytes, or a callable given the path that
    returns them (asked only when the file is encrypted). Without one it is
    ``key_passphrase_needed``; a wrong one is ``key_passphrase_wrong``.
    """
    data, problem, mode = _read_owner_only(path, "key_file", MAX_KEY_FILE_BYTES)
    if problem and data.startswith(_PUBLIC_PEM):
        raise _public_key_given(path)
    if problem:
        raise _insecure(path, "key_file", problem, mode)
    if data.lstrip().startswith(_PUBLIC_PEM):
        raise _public_key_given(path)
    if is_encrypted(data):
        if passphrase is None:
            raise ValueError(f"key_passphrase_needed: {path} is encrypted; give its passphrase "
                             "(--key-passphrase-file FILE, keys.passphrase_file in proxy.yaml, or type it on a terminal)")
        return decrypt_private_key(data, passphrase_bytes(passphrase, str(path)), str(path))
    if data.lstrip().startswith(_OPENSSL_ENCRYPTED):
        raise ValueError(f"key_file_invalid: {path} is encrypted by another tool; Two-Key opens only its own "
                         "encrypted form (two-key config key-passphrase, docs/SETUP.md)")
    return private_key_from_pem(data, str(path))


def save_public_key(path: Path | str, public) -> None:
    Path(path).write_bytes(public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def load_public_key(path: Path | str):
    """A public key file: a hybrid key (two PEM blocks) or a 0.8.0 Ed25519 key (one)."""
    return public_key_from_pem(Path(path).read_bytes(), str(path))


def public_raw(public) -> str:
    """Base64 of the raw public key: 32 bytes for Ed25519, 1,984 for a hybrid key (Ed25519 then ML-DSA-65)."""
    return base64.b64encode(_raw_public(public)).decode("ascii")


def public_from_raw(raw: str):
    """The key ``public_raw`` wrote; its length says which kind. Anything else raises ``ValueError``."""
    data = base64.b64decode(raw, validate=True)
    if len(data) == ED_PUB_BYTES:
        return Ed25519PublicKey.from_public_bytes(data)
    if len(data) == ED_PUB_BYTES + ML_PUB_BYTES:
        require_ml_dsa()
        return HybridPublicKey(Ed25519PublicKey.from_public_bytes(data[:ED_PUB_BYTES]),
                               MLDSA65PublicKey.from_public_bytes(data[ED_PUB_BYTES:]))
    raise ValueError("public_key_invalid: not an Ed25519 or hybrid Ed25519 + ML-DSA-65 public key")


def hybrid_message(message: bytes) -> bytes:
    """What both halves of a hybrid signature sign: the label, the suite, then the message, NUL-separated. Neither
    half is a signature over ``message`` itself, so neither can be passed off as a classical signature."""
    return HYBRID_LABEL + b"\0" + HYBRID_ALG.encode("ascii") + b"\0" + message


def sign(private_key, message: bytes) -> str:
    """Base64 of the signature: for a hybrid key, the Ed25519 signature then the ML-DSA-65 signature (3,373
    bytes), both over ``hybrid_message(message)``; for a 0.8.0 Ed25519 key, its 64-byte signature."""
    if isinstance(private_key, HybridPrivateKey):
        signed = hybrid_message(message)
        data = private_key.ed.sign(signed) + private_key.ml.sign(signed, ML_DSA_CONTEXT)
    else:
        data = private_key.sign(message)
    return base64.b64encode(data).decode("ascii")


def verify(public, message: bytes, signature: str) -> bool:
    """True only for a signature by ``public``'s kind: a hybrid key needs both halves, and refuses a classical
    signature (a downgrade); an Ed25519 key takes only its own 64-byte signature."""
    try:
        data = base64.b64decode(signature, validate=True)
        if isinstance(public, HybridPublicKey):
            if len(data) != ED_SIG_BYTES + ML_SIG_BYTES:
                return False
            signed = hybrid_message(message)
            public.ed.verify(data[:ED_SIG_BYTES], signed)
            public.ml.verify(data[ED_SIG_BYTES:], signed, ML_DSA_CONTEXT)
            return True
        if len(data) != ED_SIG_BYTES:
            return False
        public.verify(data, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
