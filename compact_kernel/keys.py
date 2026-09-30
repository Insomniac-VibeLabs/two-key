"""Ed25519 key handling for the principal (uses the `cryptography` library).

Private keys are written with mode 0600 and can be encrypted with a
passphrase. Keys are never hardcoded, and none are shipped in this repo
(see .gitignore). Production should hold the principal key in a
TEE/Secure Enclave/HSM (spec 5.1); this file-based storage is a prototype.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_raw(key: Ed25519PublicKey | Ed25519PrivateKey) -> bytes:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_key_from_raw(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def fingerprint(key: Ed25519PublicKey | Ed25519PrivateKey) -> str:
    import hashlib
    return "ed25519:" + hashlib.sha256(public_key_raw(key)).hexdigest()[:32]


def save_private_key(path: Path, key: Ed25519PrivateKey, passphrase: bytes | None = None) -> None:
    enc = (serialization.BestAvailableEncryption(passphrase) if passphrase
           else serialization.NoEncryption())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def load_private_key(path: Path, passphrase: bytes | None = None) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def save_public_key(path: Path, key: Ed25519PublicKey | Ed25519PrivateKey) -> None:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(pub.public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo))


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


def sign(key: Ed25519PrivateKey, data: bytes) -> str:
    return b64e(key.sign(data))


def verify(pub: Ed25519PublicKey, data: bytes, sig_b64: str) -> bool:
    try:
        pub.verify(b64d(sig_b64), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
