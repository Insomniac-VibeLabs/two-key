"""Pluggable crypto provider with an optional FIPS mode.

Every hash, MAC, random draw, and signature algorithm choice in Two-Key
goes through a ``CryptoProvider``. The provider:

* allows only algorithms on the FIPS-approved list below when ``fips_mode``
  is on, and raises ``CryptoPolicyError`` for anything else;
* can refuse to start unless the underlying OpenSSL reports that a FIPS
  provider is active (``require_fips_module=True``);
* draws random bytes only from ``os.urandom`` (the OS DRBG / getrandom);
* runs a known-answer self-test once before first use
  (``ensure_selftest``; see selftest.py).

IMPORTANT: this code is not "FIPS certified" or "FIPS validated", and nothing
here makes it so. FIPS 140-3 compliance comes only from running on a
cryptographic module that holds a CMVP certificate (for example the OpenSSL 3
FIPS provider or AWS-LC FIPS), in its approved mode, under that module's
security policy. See docs/CRYPTO.md.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import os
import threading
from typing import Callable

# Approved-algorithm lists (FIPS 180-4, FIPS 202, FIPS 198-1, FIPS 186-5, FIPS 204).
APPROVED: dict[str, frozenset[str]] = {
    "hash": frozenset({"sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"}),
    "mac": frozenset({"hmac-sha256", "hmac-sha384", "hmac-sha512"}),
    "sig": frozenset({"ed25519", "ecdsa-p384", "ml-dsa-65"}),
    # pbkdf2-hmac-sha512 (the BIP-39 seed step) and hkdf-sha384 (SP 800-56C) are used by the optional
    # seed-phrase backup (seedphrase.py), which itself is refused in fips_mode.
    "kdf": frozenset({"pbkdf2-hmac-sha256", "pbkdf2-hmac-sha384", "pbkdf2-hmac-sha512", "hkdf-sha384"}),
    "cipher": frozenset({"aes-256-gcm"}),
    "rng": frozenset({"os.urandom"}),
}
# Algorithms the code knows but that are NOT approved. They exist so that
# fips_mode refusal can be demonstrated and tested. Nothing uses them by default.
NON_APPROVED: dict[str, frozenset[str]] = {
    "hash": frozenset({"blake2b", "md5", "sha1"}),
    "mac": frozenset({"hmac-md5", "hmac-sha1", "hmac-blake2b"}),
    "sig": frozenset(),
    "kdf": frozenset(),
    "cipher": frozenset(),
    "rng": frozenset({"random"}),
}
_HASHLIB_NAME = {"sha256": "sha256", "sha384": "sha384", "sha512": "sha512", "sha3-256": "sha3_256",
                 "sha3-384": "sha3_384", "sha3-512": "sha3_512", "blake2b": "blake2b", "md5": "md5",
                 "sha1": "sha1"}
DIGEST_SIZE = {"sha256": 32, "sha384": 48, "sha512": 64, "sha3-256": 32, "sha3-384": 48, "sha3-512": 64,
               "blake2b": 64, "md5": 16, "sha1": 20}
PQ_BACKENDS = ("auto", "pyca", "liboqs", "none")


class CryptoPolicyError(RuntimeError):
    """An algorithm or backend was refused by policy (e.g. not FIPS-approved)."""


class PQUnavailableError(RuntimeError):
    """A post-quantum (ML-DSA) operation is required but no PQ backend is available."""


class SelfTestError(RuntimeError):
    """A cryptographic known-answer or pairwise-consistency self-test failed."""


def openssl_fips_status() -> dict:
    """Report whether the OpenSSL instances used by Python report FIPS mode.

    Two OpenSSL instances can be in play: the one linked into CPython's
    ``hashlib`` and the one bundled with or linked by pyca ``cryptography``.
    Both must be FIPS-enabled for a FIPS deployment.
    """
    st: dict = {"hashlib_fips": False, "cryptography_fips": False,
                "hashlib_openssl": None, "cryptography_openssl": None, "cryptography_version": None}
    try:
        import ssl
        import _hashlib  # type: ignore
        st["hashlib_fips"] = bool(_hashlib.get_fips_mode())
        st["hashlib_openssl"] = ssl.OPENSSL_VERSION
    except Exception:
        pass
    try:
        import cryptography
        from cryptography.hazmat.backends.openssl.backend import backend
        st["cryptography_version"] = cryptography.__version__
        st["cryptography_openssl"] = backend.openssl_version_text()
        st["cryptography_fips"] = bool(getattr(backend, "_fips_enabled", False))
    except Exception:
        pass
    return st


class CryptoProvider:
    """Routes all primitive calls; enforces fips_mode; owns the PQ backend choice.

    Parameters
    ----------
    fips_mode: refuse algorithms outside APPROVED and refuse non-validated
        PQ backends (liboqs).
    require_fips_module: additionally refuse to start unless OpenSSL reports
        an active FIPS provider (both hashlib and pyca). Off by default because
        developer machines rarely run a FIPS provider.
    pq_backend: "auto" (pyca if it has ML-DSA, else liboqs, else unavailable),
        "pyca", "liboqs", or "none". A PQ operation with no backend raises
        PQUnavailableError. Nothing silently falls back to classical-only.
    """

    def __init__(self, *, fips_mode: bool = False, require_fips_module: bool = False,
                 pq_backend: str = "auto", name: str = "openssl-default"):
        if pq_backend not in PQ_BACKENDS:
            raise CryptoPolicyError(f"pq_backend must be one of {PQ_BACKENDS}")
        if fips_mode and pq_backend == "liboqs":
            raise CryptoPolicyError("pq_backend='liboqs' refused in fips_mode: liboqs is not a FIPS 140-3 "
                                    "validated module")
        self.fips_mode = bool(fips_mode)
        self.require_fips_module = bool(require_fips_module)
        self.pq_backend_choice = pq_backend
        self.name = name
        self._selftest_result: dict | None = None
        self._lock = threading.Lock()
        self._pq = None
        self._pq_resolved = False
        if self.require_fips_module:
            st = openssl_fips_status()
            if not (st["hashlib_fips"] and st["cryptography_fips"]):
                raise CryptoPolicyError(
                    "require_fips_module=True but no active FIPS provider was detected "
                    f"(hashlib_fips={st['hashlib_fips']}, cryptography_fips={st['cryptography_fips']}). "
                    "Deploy on a FIPS 140-3 validated module; see docs/CRYPTO.md.")

    def __repr__(self) -> str:
        return f"<CryptoProvider {self.name} fips_mode={self.fips_mode} pq_backend={self.pq_backend_choice}>"

    # -- policy ------------------------------------------------------------
    def check(self, kind: str, alg: str) -> str:
        """Raise CryptoPolicyError unless ``alg`` is allowed for ``kind``; return ``alg``."""
        approved = APPROVED.get(kind)
        if approved is None:
            raise CryptoPolicyError(f"unknown algorithm kind {kind!r}")
        if alg in approved:
            return alg
        if alg in NON_APPROVED.get(kind, ()):
            if self.fips_mode:
                raise CryptoPolicyError(f"{kind} algorithm {alg!r} is not FIPS-approved (fips_mode is on)")
            return alg
        raise CryptoPolicyError(f"unsupported {kind} algorithm {alg!r}")

    # -- primitives -----------------------------------------------------------
    def hash(self, alg: str, data: bytes) -> bytes:
        self.check("hash", alg)
        return hashlib.new(_HASHLIB_NAME[alg], data).digest()

    def hash_hex(self, alg: str, data: bytes) -> str:
        self.check("hash", alg)
        return hashlib.new(_HASHLIB_NAME[alg], data).hexdigest()

    def hash_fn(self, alg: str) -> Callable[[bytes], bytes]:
        """Return a fast bound hash function after one policy check (for Merkle trees)."""
        self.check("hash", alg)
        ctor = getattr(hashlib, _HASHLIB_NAME[alg])
        return lambda b: ctor(b).digest()

    def hmac(self, alg: str, key: bytes, data: bytes) -> bytes:
        return self.hmac_factory(alg, key)(data)

    def hmac_factory(self, alg: str, key: bytes) -> Callable[[bytes], bytes]:
        """Check policy and key length once; return a fast MAC function (key schedule cached)."""
        self.check("mac", alg)
        if len(key) < 32:
            raise CryptoPolicyError("HMAC keys must be at least 256 bits")
        proto = _hmac.new(key, digestmod=_HASHLIB_NAME[alg.split("-", 1)[1]])

        def mac(data: bytes) -> bytes:
            h = proto.copy()
            h.update(data)
            return h.digest()
        return mac

    @staticmethod
    def constant_time_eq(a, b) -> bool:
        return _hmac.compare_digest(a, b)

    def random_bytes(self, n: int) -> bytes:
        """The only RNG entry point: os.urandom (getrandom(2) / OS DRBG)."""
        self.check("rng", "os.urandom")
        return os.urandom(n)

    # -- post-quantum backend -------------------------------------------------
    def pq_backend(self):
        """Return the resolved ML-DSA backend adapter, or None if unavailable."""
        with self._lock:
            if not self._pq_resolved:
                from .signatures import resolve_mldsa_backend
                self._pq = resolve_mldsa_backend(self.pq_backend_choice, fips_mode=self.fips_mode)
                self._pq_resolved = True
            return self._pq

    def require_pq(self):
        be = self.pq_backend()
        if be is None:
            raise PQUnavailableError(
                f"ML-DSA-65 is required but no post-quantum backend is available (pq_backend="
                f"{self.pq_backend_choice!r}). Install a pyca cryptography release with ML-DSA "
                "support (tested with 50.0.1: pip install 'cryptography>=50') or liboqs-python. Refusing to downgrade to classical-only.")
        return be

    # -- self-test ------------------------------------------------------------
    def ensure_selftest(self) -> dict:
        with self._lock:
            if self._selftest_result is not None:
                return self._selftest_result
        from .selftest import run_selftest
        res = run_selftest(self)
        with self._lock:
            self._selftest_result = res
        return res

    def describe(self) -> dict:
        be = self.pq_backend()
        return {"provider": self.name, "fips_mode": self.fips_mode,
                "require_fips_module": self.require_fips_module,
                "pq_backend_choice": self.pq_backend_choice,
                "pq_backend": None if be is None else be.describe(),
                "openssl": openssl_fips_status(),
                "claim": "not FIPS certified/validated; compliance requires a validated module"}


_default: CryptoProvider | None = None
_default_lock = threading.Lock()


def default_provider() -> CryptoProvider:
    global _default
    if _default is None:
        with _default_lock:
            if _default is None:
                _default = CryptoProvider()
    return _default


def set_default_provider(p: CryptoProvider) -> CryptoProvider:
    """Replace the process-wide default provider; returns the previous one."""
    global _default
    with _default_lock:
        prev, _default = _default, p
    return prev or CryptoProvider()
