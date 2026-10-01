"""Principal key handling (uses the `cryptography` library).

Legacy Ed25519 keys are PEM files (PKCS#8 private, SPKI public), as before.
Other suites (ECDSA P-384, hybrid ML-DSA-65 + Ed25519/P-384; see
two_key.crypto.signatures) are stored as a JSON key bundle. The
private components are encrypted with AES-256-GCM under a key derived by
PBKDF2-HMAC-SHA-256 (600,000 iterations, SP 800-132) from the passphrase.

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


def fingerprint(key) -> str:
    from .crypto.signatures import as_public_keyset
    return as_public_keyset(key).fingerprint


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


# ---------------------------------------------------------------------------
# Key sets (non-legacy suites)
# ---------------------------------------------------------------------------
KEYSET_FORMAT = "two-key-keyset/1"
PUBLIC_KEYSET_FORMAT = "two-key-public-keyset/1"
PBKDF2_ITERATIONS = 600_000
KEYSET_KDF = "pbkdf2-hmac-sha384"          # new bundles (F_REVIEW; CONCEPTION_NOTES Entry 10)
KEYSET_KDFS = ("pbkdf2-hmac-sha384", "pbkdf2-hmac-sha256")   # sha256: bundles written before; still loaded


def generate_keyset(suite: str, provider=None):
    from .crypto.signatures import LEGACY_SUITE, PrivateKeySet
    if suite == LEGACY_SUITE:
        return generate_private_key()
    return PrivateKeySet.generate(suite, provider)


def _kdf(passphrase: bytes, salt: bytes, iterations: int, provider, kdf: str) -> bytes:
    """A 256-bit AES key from the passphrase (PBKDF2, SP 800-132), through the provider's policy check."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    if kdf not in KEYSET_KDFS:
        raise ValueError(f"unsupported key derivation {kdf!r}")
    provider.check("kdf", kdf)
    h = hashes.SHA384() if kdf == "pbkdf2-hmac-sha384" else hashes.SHA256()
    return PBKDF2HMAC(h, 32, salt, iterations).derive(passphrase)


def save_keyset(path: Path, ks, passphrase: bytes | None = None, provider=None) -> None:
    import json
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from .canonical import canonical_bytes
    from .crypto.provider import default_provider
    provider = provider or default_provider()
    header = {"format": KEYSET_FORMAT, "suite": ks.suite, "public_key": ks.public().encoded}
    plain = canonical_bytes(ks.export_components())
    if passphrase:
        provider.check("cipher", "aes-256-gcm")
        salt, nonce = provider.random_bytes(16), provider.random_bytes(12)
        kdf = KEYSET_KDF
        enc = {"kdf": kdf, "iterations": PBKDF2_ITERATIONS, "salt": b64e(salt),
               "cipher": "aes-256-gcm", "nonce": b64e(nonce)}
        header["encryption"] = enc
        ct = AESGCM(_kdf(passphrase, salt, PBKDF2_ITERATIONS, provider, kdf)).encrypt(nonce, plain,
                                                                                    canonical_bytes(header))
        header["private"] = b64e(ct)
    else:
        header["encryption"] = None
        header["private"] = b64e(plain)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(header, indent=1, sort_keys=True) + "\n")


def load_keyset(path: Path, passphrase: bytes | None = None, provider=None):
    import json
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from .canonical import canonical_bytes
    from .crypto.provider import default_provider
    from .crypto.signatures import PrivateKeySet
    provider = provider or default_provider()
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    if d.get("format") != KEYSET_FORMAT:
        raise ValueError("not a two-key key bundle")
    enc = d.get("encryption")
    if enc:
        if not passphrase:
            raise ValueError("key bundle is encrypted; passphrase required")
        if enc.get("kdf") not in KEYSET_KDFS or enc.get("cipher") != "aes-256-gcm" or \
                int(enc.get("iterations", 0)) < 100_000:
            raise ValueError("unsupported key bundle encryption parameters")
        header = {k: d[k] for k in ("format", "suite", "public_key", "encryption")}
        try:
            plain = AESGCM(_kdf(passphrase, b64d(enc["salt"]), int(enc["iterations"]), provider,
                                enc["kdf"])).decrypt(
                b64d(enc["nonce"]), b64d(d["private"]), canonical_bytes(header))
        except InvalidTag:
            raise ValueError("wrong passphrase or corrupted key bundle") from None
    else:
        plain = b64d(d["private"])
    ks = PrivateKeySet.from_components(d["suite"], json.loads(plain), provider)
    if ks.public().encoded != d["public_key"]:
        raise ValueError("key bundle public key does not match its private components")
    return ks


def save_public_keyset(path: Path, pub) -> None:
    import json
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps({"format": PUBLIC_KEYSET_FORMAT, "suite": pub.suite,
                                      "public_key": pub.encoded, "fingerprint": pub.fingerprint},
                                     indent=1, sort_keys=True) + "\n", encoding="utf-8")


def load_public_any(path: Path, provider=None):
    """Load a legacy Ed25519 PEM public key or a JSON public key set."""
    import json
    from .crypto.signatures import public_keyset_from_encoded
    data = Path(path).read_bytes()
    if data.lstrip().startswith(b"-----BEGIN"):
        return load_public_key(path)
    d = json.loads(data)
    if d.get("format") != PUBLIC_KEYSET_FORMAT:
        raise ValueError("not a two-key public key set")
    pub = public_keyset_from_encoded(d["public_key"], provider)
    if pub.suite != d.get("suite"):
        raise ValueError("public key set suite mismatch")
    return pub


def load_private_any(path: Path, passphrase: bytes | None = None, provider=None):
    """Load a legacy Ed25519 PEM private key or a JSON key bundle."""
    if Path(path).read_bytes().lstrip().startswith(b"-----BEGIN"):
        return load_private_key(path, passphrase)
    return load_keyset(path, passphrase, provider)


def sign(key: Ed25519PrivateKey, data: bytes) -> str:
    return b64e(key.sign(data))


def verify(pub: Ed25519PublicKey, data: bytes, sig_b64: str) -> bool:
    try:
        pub.verify(b64d(sig_b64), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
