"""Ed25519 principal keys. Hybrid ML-DSA is not implemented yet (ROADMAP)."""

from __future__ import annotations

import base64
import os
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import _platform


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key(private_key: Ed25519PrivateKey) -> Ed25519PublicKey:
    return private_key.public_key()


def fingerprint(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    import hashlib
    return hashlib.sha256(raw).hexdigest()[:16]


def save_private_key(path: Path | str, private_key: Ed25519PrivateKey, *, private_dir: bool = False) -> None:
    """Create a new key file, mode 0600 from the first byte. Never overwrite one.

    The file is opened with O_CREAT | O_EXCL (and O_NOFOLLOW where available), so an
    existing file or a planted symlink is an error rather than a silent overwrite, and
    there is no window in which the key is readable before a chmod. On Windows it gets a
    private access list instead of mode 0600 (``two_key._platform``). A directory this
    creates is mode 0700. ``private_dir=True`` also sets an existing directory to 0700
    (a private access list on Windows); use it for directories Two-Key owns, such as
    ``<ledger>.capability``.
    """
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if private_dir:
        _platform.owner_only_dir(path.parent)
    data = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    fd = _platform.create_new(path)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def load_private_key(path: Path | str) -> Ed25519PrivateKey:
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("principal key must be Ed25519")
    return key


_PUBLIC_PEM = b"-----BEGIN PUBLIC KEY-----"


def _public_key_given(path) -> ValueError:
    return ValueError(f"key_file_public: {path} is a public key; give the private key "
                      f"(init-key writes principal.pem, mode 0600, next to principal.pub.pem)")


def load_private_key_file(path: Path | str) -> Ed25519PrivateKey:
    """The safe loader for a key file named by an operator, as on the command line.

    It refuses a symlink (O_NOFOLLOW), anything that is not a regular file, and a file
    that the group or others can read or write (``key_file_insecure``). The check is on
    the open descriptor, so the file cannot be swapped between the check and the read.
    A public key is ``key_file_public`` (whatever its mode: chmod would not help), and a
    file that is not an unencrypted PEM private key is ``key_file_invalid``.
    """
    try:
        fd = _platform.open_nofollow(path)
    except OSError as e:
        raise ValueError(f"key_file_unreadable: {path}: {e.strerror}") from None
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"key_file_insecure: {path} is not a regular file")
        problem = _platform.access_problem(fh.fileno(), st)
        if problem and fh.read(len(_PUBLIC_PEM)) == _PUBLIC_PEM:
            raise _public_key_given(path)
        if problem and not _platform.WINDOWS:
            raise ValueError(f"key_file_insecure: {path} is mode {stat.S_IMODE(st.st_mode):04o}; "
                             f"run chmod 600 {path}")
        if problem:
            raise ValueError(f"key_file_insecure: {_platform.insecure(path, problem)}")
        data = fh.read()
    if data.lstrip().startswith(_PUBLIC_PEM):
        raise _public_key_given(path)
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm):
        raise ValueError(f"key_file_invalid: {path} is not an unencrypted PEM private key") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("principal key must be Ed25519")
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
