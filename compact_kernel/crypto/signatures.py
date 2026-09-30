"""Signature suites: classic (Ed25519, ECDSA P-384) and hybrid post-quantum.

Suites
------
``ed25519``                 legacy default (FIPS 186-5 EdDSA). Wire formats are
                            unchanged from earlier versions: the raw message is
                            signed and keys/signatures are raw base64.
``ecdsa-p384``              ECDSA over P-384 with SHA-384 (FIPS 186-5).
``hybrid-mldsa65-ed25519``  ML-DSA-65 (FIPS 204) AND Ed25519.
``hybrid-mldsa65-p384``     ML-DSA-65 (FIPS 204) AND ECDSA P-384.

Hybrid rule: a hybrid signature is valid only if EVERY component verifies.
If either half is missing, altered, reordered, or fails, the signature is
rejected. The verifier requires the suite of the TRUSTED key, so a
signature made under a weaker suite is refused (no downgrade).

For non-legacy suites each component signs the domain-separated message
``b"compact-kernel/sig/v1\\0" + suite + b"\\0" + message``. That binds the
suite name into every component, so a component cannot be lifted out of a
hybrid signature and replayed as a standalone classic signature.

ML-DSA backends are selectable (CryptoProvider(pq_backend=...)):
``pyca`` (a cryptography release with ML-DSA; tested with 50.0.1, which bundles OpenSSL 4.0.2)
or ``liboqs`` (liboqs-python). When no backend is available, any PQ
operation raises PQUnavailableError. Nothing silently downgrades.
"""

from __future__ import annotations

import base64
import binascii
import functools
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .provider import CryptoPolicyError, CryptoProvider, PQUnavailableError, default_provider

DOMAIN = b"compact-kernel/sig/v1\x00"
LEGACY_SUITE = "ed25519"
SUITES: dict[str, tuple[str, ...]] = {
    "ed25519": ("ed25519",),
    "ecdsa-p384": ("ecdsa-p384",),
    "hybrid-mldsa65-ed25519": ("ml-dsa-65", "ed25519"),
    "hybrid-mldsa65-p384": ("ml-dsa-65", "ecdsa-p384"),
}
PQ_SUITES = frozenset(s for s, algs in SUITES.items() if "ml-dsa-65" in algs)
MLDSA65_PUBLIC_BYTES = 1952
MLDSA65_SIGNATURE_BYTES = 3309


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


# ---------------------------------------------------------------------------
# Classic components (pyca cryptography -> OpenSSL)
# ---------------------------------------------------------------------------
class _Ed25519:
    alg = "ed25519"

    @staticmethod
    def generate():
        return Ed25519PrivateKey.generate()

    @staticmethod
    def public_of(priv):
        return priv.public_key()

    @staticmethod
    def private_raw(priv) -> bytes:
        return priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())

    @staticmethod
    def private_from_raw(raw: bytes):
        return Ed25519PrivateKey.from_private_bytes(raw)

    @staticmethod
    def public_raw(pub) -> bytes:
        return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @staticmethod
    def public_from_raw(raw: bytes):
        return Ed25519PublicKey.from_public_bytes(raw)

    @staticmethod
    def sign(priv, msg: bytes) -> bytes:
        return priv.sign(msg)

    @staticmethod
    def verify(pub, sig: bytes, msg: bytes) -> bool:
        try:
            pub.verify(sig, msg)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False


class _EcdsaP384:
    alg = "ecdsa-p384"
    _curve = ec.SECP384R1()

    @classmethod
    def generate(cls):
        return ec.generate_private_key(cls._curve)

    @staticmethod
    def public_of(priv):
        return priv.public_key()

    @staticmethod
    def private_raw(priv) -> bytes:
        return priv.private_numbers().private_value.to_bytes(48, "big")

    @classmethod
    def private_from_raw(cls, raw: bytes):
        if len(raw) != 48:
            raise ValueError("P-384 private scalar must be 48 bytes")
        return ec.derive_private_key(int.from_bytes(raw, "big"), cls._curve)

    @staticmethod
    def public_raw(pub) -> bytes:
        return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    @classmethod
    def public_from_raw(cls, raw: bytes):
        return ec.EllipticCurvePublicKey.from_encoded_point(cls._curve, raw)

    @staticmethod
    def sign(priv, msg: bytes) -> bytes:
        return priv.sign(msg, ec.ECDSA(hashes.SHA384()))

    @staticmethod
    def verify(pub, sig: bytes, msg: bytes) -> bool:
        try:
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA384()))
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False


# ---------------------------------------------------------------------------
# ML-DSA-65 backends
# ---------------------------------------------------------------------------
class PycaMLDSA65:
    """ML-DSA-65 via pyca ``cryptography`` (needs a build whose OpenSSL has ML-DSA)."""

    alg = "ml-dsa-65"
    name = "pyca"
    private_format = "seed"

    def __init__(self):
        import importlib
        try:
            mldsa = importlib.import_module("cryptography.hazmat.primitives.asymmetric.mldsa")
            from cryptography.hazmat.backends.openssl.backend import backend
        except ImportError as e:
            raise ImportError(f"cryptography has no ML-DSA module: {e}") from e
        ok = getattr(backend, "mldsa_supported", None)
        if ok is not None and not ok():
            raise ImportError("cryptography's OpenSSL build does not support ML-DSA")
        self._m = mldsa
        self._backend = backend

    def describe(self) -> dict:
        import cryptography
        return {"backend": "pyca-cryptography", "version": cryptography.__version__,
                "openssl": self._backend.openssl_version_text(), "algorithm": "ML-DSA-65 (FIPS 204)"}

    def generate(self):
        return self._m.MLDSA65PrivateKey.generate()

    def public_of(self, priv):
        return priv.public_key()

    def private_raw(self, priv) -> bytes:
        return priv.private_bytes_raw()  # the 32-byte seed (FIPS 204 xi)

    def private_from_raw(self, raw: bytes, fmt: str = "seed"):
        if fmt != "seed" or len(raw) != 32:
            raise ValueError("pyca ML-DSA backend needs a 32-byte seed private key")
        return self._m.MLDSA65PrivateKey.from_seed_bytes(raw)

    def public_raw(self, pub) -> bytes:
        return pub.public_bytes_raw()

    def public_from_raw(self, raw: bytes):
        return self._m.MLDSA65PublicKey.from_public_bytes(raw)

    def sign(self, priv, msg: bytes) -> bytes:
        return priv.sign(msg)

    def verify(self, pub, sig: bytes, msg: bytes) -> bool:
        try:
            pub.verify(sig, msg)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False


class LiboqsMLDSA65:
    """ML-DSA-65 via liboqs-python (``import oqs``). Not a FIPS-validated module."""

    alg = "ml-dsa-65"
    name = "liboqs"
    private_format = "liboqs-pk-sk"
    MECH = "ML-DSA-65"

    def __init__(self):
        try:
            import oqs  # type: ignore
        except ImportError as e:
            raise ImportError(f"liboqs-python is not installed: {e}") from e
        mechs = oqs.get_enabled_sig_mechanisms()
        if self.MECH not in mechs:
            raise ImportError("liboqs build does not enable ML-DSA-65")
        self._oqs = oqs

    def describe(self) -> dict:
        v = getattr(self._oqs, "oqs_version", lambda: "?")
        pv = getattr(self._oqs, "oqs_python_version", lambda: "?")
        return {"backend": "liboqs-python", "version": f"{pv()} (liboqs {v()})", "algorithm": "ML-DSA-65 (FIPS 204)"}

    def generate(self):
        with self._oqs.Signature(self.MECH) as s:
            pk = s.generate_keypair()
            sk = s.export_secret_key()
        return (bytes(pk), bytes(sk))

    def public_of(self, priv):
        return priv[0]

    def private_raw(self, priv) -> bytes:
        return priv[0] + priv[1]

    def private_from_raw(self, raw: bytes, fmt: str = "liboqs-pk-sk"):
        if fmt != self.private_format or len(raw) <= MLDSA65_PUBLIC_BYTES:
            raise ValueError("liboqs ML-DSA backend needs a pk||sk private key")
        return (raw[:MLDSA65_PUBLIC_BYTES], raw[MLDSA65_PUBLIC_BYTES:])

    def public_raw(self, pub) -> bytes:
        return bytes(pub)

    def public_from_raw(self, raw: bytes):
        if len(raw) != MLDSA65_PUBLIC_BYTES:
            raise ValueError("ML-DSA-65 public key must be 1952 bytes")
        return bytes(raw)

    def sign(self, priv, msg: bytes) -> bytes:
        with self._oqs.Signature(self.MECH, priv[1]) as s:
            return bytes(s.sign(msg))

    def verify(self, pub, sig: bytes, msg: bytes) -> bool:
        try:
            with self._oqs.Signature(self.MECH) as s:
                return bool(s.verify(msg, sig, pub))
        except Exception:
            return False


def resolve_mldsa_backend(choice: str, *, fips_mode: bool = False):
    """Return an ML-DSA-65 adapter for ``choice`` or None if it is unavailable."""
    if choice == "none":
        return None
    if choice == "liboqs" and fips_mode:
        raise CryptoPolicyError("pq_backend='liboqs' refused in fips_mode: liboqs is not a FIPS 140-3 "
                                "validated module")
    order = {"pyca": [PycaMLDSA65], "liboqs": [LiboqsMLDSA65],
             "auto": [PycaMLDSA65] + ([] if fips_mode else [LiboqsMLDSA65])}[choice]
    for cls in order:
        try:
            return cls()
        except ImportError:
            continue
    return None


def pq_available(provider: CryptoProvider | None = None) -> bool:
    return (provider or default_provider()).pq_backend() is not None


# ---------------------------------------------------------------------------
# Key sets
# ---------------------------------------------------------------------------
def _impls(suite: str, provider: CryptoProvider) -> list:
    if suite not in SUITES:
        raise CryptoPolicyError(f"unknown signature suite {suite!r}")
    out = []
    for alg in SUITES[suite]:
        provider.check("sig", alg)
        if alg == "ed25519":
            out.append(_Ed25519)
        elif alg == "ecdsa-p384":
            out.append(_EcdsaP384)
        else:
            out.append(provider.require_pq())
    return out


def _signing_input(suite: str, msg: bytes) -> bytes:
    if suite == LEGACY_SUITE:
        return msg
    return DOMAIN + suite.encode("ascii") + b"\x00" + msg


class PublicKeySet:
    def __init__(self, suite: str, pubs: list, raws: list[bytes], provider: CryptoProvider):
        self.suite, self._pubs, self._raws, self.provider = suite, pubs, raws, provider
        self._impls = _impls(suite, provider)
        if suite == LEGACY_SUITE:
            self.encoded = _b64e(raws[0])
        else:
            self.encoded = _b64e(_canon({"suite": suite,
                                         "keys": [[a, _b64e(r)] for a, r in zip(SUITES[suite], raws)]}))

    def __repr__(self) -> str:
        return f"<PublicKeySet {self.suite} {self.fingerprint}>"

    def __eq__(self, other) -> bool:
        return isinstance(other, PublicKeySet) and other.encoded == self.encoded

    def __hash__(self) -> int:
        return hash(self.encoded)

    @property
    def is_pq(self) -> bool:
        return self.suite in PQ_SUITES

    @property
    def legacy_raw(self) -> bytes:
        return self._raws[0]

    @property
    def fingerprint(self) -> str:
        if self.suite == LEGACY_SUITE:
            return "ed25519:" + self.provider.hash_hex("sha256", self._raws[0])[:32]
        return f"{self.suite}:" + self.provider.hash_hex("sha384", self.encoded.encode("ascii"))[:32]

    @property
    def envelope_alg(self) -> str:
        """The ``alg`` label written into signature envelopes ("Ed25519" for legacy)."""
        return "Ed25519" if self.suite == LEGACY_SUITE else self.suite

    def verify(self, msg: bytes, sig_b64: Any) -> bool:
        """True only if every component signature verifies under this key set's suite."""
        if not isinstance(sig_b64, str):
            return False
        try:
            if self.suite == LEGACY_SUITE:
                return _Ed25519.verify(self._pubs[0], _b64d(sig_b64), msg)
            obj = json.loads(_b64d(sig_b64))
            if not isinstance(obj, dict) or set(obj) != {"suite", "sigs"} or obj["suite"] != self.suite:
                return False
            sigs = obj["sigs"]
            algs = SUITES[self.suite]
            if not isinstance(sigs, list) or len(sigs) != len(algs):
                return False
            m = _signing_input(self.suite, msg)
            results = []
            for (alg, impl, pub), item in zip(zip(algs, self._impls, self._pubs), sigs):
                if not (isinstance(item, list) and len(item) == 2 and item[0] == alg):
                    return False
                results.append(impl.verify(pub, _b64d(item[1]), m))
            return len(results) == len(algs) and all(results)
        except (ValueError, TypeError, KeyError, binascii.Error, UnicodeError):
            return False


class PrivateKeySet:
    def __init__(self, suite: str, privs: list, provider: CryptoProvider | None = None):
        self.provider = provider or default_provider()
        self.suite = suite
        self._impls = _impls(suite, self.provider)
        self._privs = privs
        pubs = [impl.public_of(p) for impl, p in zip(self._impls, privs)]
        self._public = PublicKeySet(suite, pubs, [impl.public_raw(p) for impl, p in zip(self._impls, pubs)],
                                    self.provider)

    def __repr__(self) -> str:
        return f"<PrivateKeySet {self.suite} [private material redacted]>"

    @classmethod
    def generate(cls, suite: str = "hybrid-mldsa65-ed25519", provider: CryptoProvider | None = None):
        provider = provider or default_provider()
        return cls(suite, [impl.generate() for impl in _impls(suite, provider)], provider)

    @property
    def is_pq(self) -> bool:
        return self.suite in PQ_SUITES

    def public(self) -> PublicKeySet:
        return self._public

    def public_key(self) -> PublicKeySet:  # mirrors the pyca API used by legacy call sites
        return self._public

    def sign(self, msg: bytes) -> str:
        if self.suite == LEGACY_SUITE:
            return _b64e(self._privs[0].sign(msg))
        m = _signing_input(self.suite, msg)
        sigs = [[alg, _b64e(impl.sign(p, m))] for alg, impl, p in zip(SUITES[self.suite], self._impls, self._privs)]
        return _b64e(_canon({"suite": self.suite, "sigs": sigs}))

    def export_components(self) -> list[dict]:
        """Raw private components (for the encrypted key bundle in keys.py)."""
        out = []
        for alg, impl, p in zip(SUITES[self.suite], self._impls, self._privs):
            out.append({"alg": alg, "raw": _b64e(impl.private_raw(p)),
                        "format": getattr(impl, "private_format", "raw")})
        return out

    @classmethod
    def from_components(cls, suite: str, comps: list[dict], provider: CryptoProvider | None = None):
        provider = provider or default_provider()
        impls = _impls(suite, provider)
        if [c.get("alg") for c in comps] != list(SUITES[suite]):
            raise ValueError("key bundle components do not match the suite")
        privs = []
        for impl, c in zip(impls, comps):
            raw = _b64d(c["raw"])
            if c["alg"] == "ml-dsa-65":
                privs.append(impl.private_from_raw(raw, c.get("format", "seed")))
            else:
                privs.append(impl.private_from_raw(raw))
        return cls(suite, privs, provider)


@functools.lru_cache(maxsize=256)
def _parse_public(encoded: str, provider: CryptoProvider) -> PublicKeySet:
    raw = _b64d(encoded)
    if len(raw) == 32:  # legacy raw Ed25519
        return PublicKeySet(LEGACY_SUITE, [_Ed25519.public_from_raw(raw)], [raw], provider)
    obj = json.loads(raw)
    if not isinstance(obj, dict) or set(obj) != {"suite", "keys"}:
        raise ValueError("malformed public key set")
    suite = obj["suite"]
    impls = _impls(suite, provider)
    keys = obj["keys"]
    if not isinstance(keys, list) or [k[0] for k in keys] != list(SUITES[suite]):
        raise ValueError("public key set components do not match the suite")
    raws = [_b64d(k[1]) for k in keys]
    return PublicKeySet(suite, [impl.public_from_raw(r) for impl, r in zip(impls, raws)], raws, provider)


def public_keyset_from_encoded(encoded: str, provider: CryptoProvider | None = None) -> PublicKeySet:
    """Parse an encoded public key set. Results are cached (key parsing is off the hot path)."""
    return _parse_public(encoded, provider or default_provider())


def as_private_keyset(key: Any, provider: CryptoProvider | None = None) -> PrivateKeySet:
    """Wrap/convert a private key. A key set built under a different provider is rebuilt under
    ``provider`` so that provider's policy (fips_mode, PQ backend choice) applies."""
    if isinstance(key, PrivateKeySet):
        if provider is None or key.provider is provider:
            return key
        return PrivateKeySet.from_components(key.suite, key.export_components(), provider)
    if isinstance(key, Ed25519PrivateKey):
        return PrivateKeySet(LEGACY_SUITE, [key], provider)
    raise TypeError(f"unsupported private key type {type(key).__name__}")


def as_public_keyset(key: Any, provider: CryptoProvider | None = None) -> PublicKeySet:
    """Wrap/convert a public key. A key set parsed under a different provider is re-parsed under
    ``provider`` so that provider's policy (fips_mode, PQ backend choice) applies."""
    if isinstance(key, PrivateKeySet):
        key = key.public()
    if isinstance(key, PublicKeySet):
        if provider is None or key.provider is provider:
            return key
        return public_keyset_from_encoded(key.encoded, provider)
    if isinstance(key, Ed25519PrivateKey):
        key = key.public_key()
    if isinstance(key, Ed25519PublicKey):
        return public_keyset_from_encoded(_b64e(_Ed25519.public_raw(key)), provider)
    raise TypeError(f"unsupported public key type {type(key).__name__}")
