# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Ed25519 principal keys. Hybrid ML-DSA is not implemented yet (ROADMAP).

A principal key file is either an unencrypted PKCS8 PEM (``BEGIN PRIVATE KEY``) or, with a passphrase,
Two-Key's own encrypted form (``BEGIN TWO-KEY ENCRYPTED PRIVATE KEY``): the PKCS8 DER sealed with
AES-256-GCM under a key from PBKDF2-SHA256 at 600,000 iterations, the construction ``backup.py`` uses,
with every header field bound in as associated data. A passphrase comes from a file only its owner can
read, or from a prompt on a terminal; never from the command line or the environment (docs/SETUP.md).
"""

from __future__ import annotations

import base64
import json
import os
import stat
import sys
from pathlib import Path
from typing import Callable, Union

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import _platform

ENCRYPTED_FORMAT = "two-key-encrypted-key/1"
KDF_NAME = "pbkdf2-sha256"
ENC_NAME = "aes-256-gcm"
KDF_ITERATIONS = 600_000            # NIST SP 800-132, as backup.py; a file asking for fewer is refused
MAX_ITERATIONS = 10_000_000         # a file cannot ask this machine to run forever
KDF_LENGTH = 32
SALT_BYTES = 16
NONCE_BYTES = 12
MIN_PASSPHRASE_BYTES = 12           # for a new passphrase; shorter is refused
MAX_PASSPHRASE_BYTES = 1024
NOT_ED25519 = "principal key must be Ed25519"
MAX_KEY_FILE_BYTES = 64 * 1024
_ENCRYPTED_BEGIN = b"-----BEGIN TWO-KEY ENCRYPTED PRIVATE KEY-----"
_ENCRYPTED_END = b"-----END TWO-KEY ENCRYPTED PRIVATE KEY-----"
_OPENSSL_ENCRYPTED = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
_HEADER_FIELDS = ("format", "kdf", "enc", "ciphertext")
_KDF_FIELDS = ("name", "iterations", "salt", "length")
_ENC_FIELDS = ("name", "nonce")

# A passphrase, or what to call for one (given the key file's path) when the file turns out to be
# encrypted. ``None`` means there is none to give.
Passphrase = Union[bytes, Callable[[str], bytes], None]


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key(private_key: Ed25519PrivateKey) -> Ed25519PublicKey:
    return private_key.public_key()


def fingerprint(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    import hashlib
    return hashlib.sha256(raw).hexdigest()[:16]


def save_private_key(path: Path | str, private_key: Ed25519PrivateKey, *, private_dir: bool = False,
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


def private_key_bytes(private_key: Ed25519PrivateKey, passphrase: bytes | None = None) -> bytes:
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


def encrypt_private_key(private_key: Ed25519PrivateKey, passphrase: bytes) -> bytes:
    """The encrypted key file: PKCS8 DER under AES-256-GCM, its key from PBKDF2-SHA256, the header as AAD."""
    check_new_passphrase(passphrase)
    plain = private_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
    salt, nonce = os.urandom(SALT_BYTES), os.urandom(NONCE_BYTES)
    header = {"format": ENCRYPTED_FORMAT,
              "kdf": {"name": KDF_NAME, "iterations": KDF_ITERATIONS, "salt": _b64e(salt), "length": KDF_LENGTH},
              "enc": {"name": ENC_NAME, "nonce": _b64e(nonce)}}
    ciphertext = AESGCM(_derive(passphrase, salt, KDF_ITERATIONS)).encrypt(nonce, plain, _canonical(header))
    header["ciphertext"] = _b64e(ciphertext)
    body = base64.encodebytes(_canonical(header))
    return _ENCRYPTED_BEGIN + b"\n" + body + _ENCRYPTED_END + b"\n"


def is_encrypted(data: bytes) -> bool:
    """Whether key file bytes are Two-Key's encrypted form (by its armour; ``encrypted_header`` checks it)."""
    return data.lstrip().startswith(_ENCRYPTED_BEGIN)


def encrypted_header(data: bytes, what: str = "the key file") -> dict:
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
        if (header["format"] != ENCRYPTED_FORMAT or not isinstance(kdf, dict) or set(kdf) != set(_KDF_FIELDS)
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


def decrypt_private_key(data: bytes, passphrase: bytes, what: str = "the key file") -> Ed25519PrivateKey:
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
    try:
        key = serialization.load_der_private_key(plain, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm):
        raise ValueError(f"key_file_invalid: {what} does not hold a private key") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(NOT_ED25519)
    return key


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


def load_private_key(path: Path | str) -> Ed25519PrivateKey:
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(NOT_ED25519)
    return key


_PUBLIC_PEM = b"-----BEGIN PUBLIC KEY-----"


def _public_key_given(path) -> ValueError:
    return ValueError(f"key_file_public: {path} is a public key; give the private key "
                      f"(init-key writes principal.pem, mode 0600, next to principal.pub.pem)")


def load_private_key_file(path: Path | str, passphrase: Passphrase = None) -> Ed25519PrivateKey:
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
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm):
        raise ValueError(f"key_file_invalid: {path} is not an unencrypted PEM private key, or Two-Key's "
                         "encrypted form") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(NOT_ED25519)
    return key


def save_public_key(path: Path | str, public: Ed25519PublicKey) -> None:
    Path(path).write_bytes(public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def load_public_key(path: Path | str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key must be Ed25519")
    return key


def public_raw(public: Ed25519PublicKey) -> str:
    return base64.b64encode(public.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")


def public_from_raw(raw: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(raw))


def sign(private_key: Ed25519PrivateKey, message: bytes) -> str:
    return base64.b64encode(private_key.sign(message)).decode("ascii")


def verify(public: Ed25519PublicKey, message: bytes, signature: str) -> bool:
    try:
        public.verify(base64.b64decode(signature), message)
        return True
    except (InvalidSignature, ValueError):
        return False
