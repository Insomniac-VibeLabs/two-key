"""Optional seed-phrase backup of the principal's signing keys (personal mode only).

Stephan Busch, 2026-10-01 (CONCEPTION_NOTES.md Entry 11): "add a seed phrase
backup for personal use". Before this, keys were random and kept only in a
passphrase-encrypted file; losing the file lost the key. This module is
AI-prepared engineering. The open settings are listed in
docs/PROVISIONAL_READINESS.md.

How it works
------------
1. **Phrase.** 256 bits of entropy from the crypto provider's RNG
   (``os.urandom``) become a standard BIP-39 phrase: 24 words from the English
   wordlist, with the last 8 bits a SHA-256 checksum.
2. **BIP-39 seed.** PBKDF2-HMAC-SHA512 (2048 iterations, salt ``"mnemonic"``
   + the optional passphrase, both NFKD-normalized), exactly as BIP-39
   specifies. The result is a 64-byte seed. A different passphrase gives
   different keys, and there is no "wrong passphrase" error.
3. **Per-algorithm keys.** HKDF-SHA-384 (SP 800-56C) expands the seed into
   each component key, with a distinct domain label per algorithm (see
   ``LABELS``):
   - Ed25519: the 32-byte RFC 8032 private key;
   - ML-DSA-65: the 32-byte FIPS 204 key-generation seed (xi);
   - ECDSA P-384: 56 bytes reduced mod n-1, plus 1 (FIPS 186-5 A.2.1).

   The same phrase therefore gives the same Ed25519 component in the
   ``ed25519`` and ``hybrid-mldsa65-ed25519`` suites, and unrelated keys for
   different algorithms.

Policy
------
- **Refused in fips_mode.** In a FIPS 140-3 deployment, keys must come from
  the validated module's own approved key generation; a key derived from
  human-held words is outside that boundary.
- **Refused in enterprise mode.** Enterprise identities come from PKI
  (pki.py).
- **The words are never logged.** ``SeedPhrase`` redacts itself in ``repr``
  and ``str``; error messages name word positions, never words.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import unicodedata
from pathlib import Path
from typing import Any

from .crypto.provider import CryptoProvider, default_provider

WORDS = 24
ENTROPY_BYTES = 32
BIP39_ITERATIONS = 2048
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
WORDLIST_PATH = Path(__file__).with_name("data") / "bip39_english.txt"
SEED_KDF = "pbkdf2-hmac-sha512"
COMPONENT_KDF = "hkdf-sha384"
HKDF_SALT = b"two-key/seed/v1/hkdf-salt"
LABELS = {  # HKDF info strings: one domain label per algorithm
    "ed25519": b"two-key/seed/v1/ed25519",
    "ml-dsa-65": b"two-key/seed/v1/ml-dsa-65",
    "ecdsa-p384": b"two-key/seed/v1/ecdsa-p384",
}
_P384_N = int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)


class SeedPhraseError(ValueError):
    """The words are not a valid 24-word BIP-39 phrase (the message never contains the words)."""


class SeedPhrasePolicyError(RuntimeError):
    """Seed-phrase backup is not allowed here (fips_mode or enterprise mode)."""


class SeedPhrase:
    """A 24-word phrase. ``repr`` and ``str`` are redacted; call ``reveal()`` to show the words once."""

    __slots__ = ("_words",)

    def __init__(self, words):
        self._words = tuple(words)

    def reveal(self) -> str:
        return " ".join(self._words)

    def __repr__(self) -> str:
        return f"<SeedPhrase {len(self._words)} words [redacted]>"

    __str__ = __repr__

    def __len__(self) -> int:
        return len(self._words)


@functools.lru_cache(maxsize=1)
def wordlist() -> tuple[str, ...]:
    data = WORDLIST_PATH.read_bytes()
    if hashlib.sha256(data).hexdigest() != WORDLIST_SHA256:
        raise SeedPhraseError(f"{WORDLIST_PATH} is not the BIP-39 English wordlist (SHA-256 mismatch)")
    words = tuple(data.decode("utf-8").split())
    if len(words) != 2048:
        raise SeedPhraseError("BIP-39 wordlist must have 2048 words")
    return words


@functools.lru_cache(maxsize=1)
def _index() -> dict[str, int]:
    return {w: i for i, w in enumerate(wordlist())}


def check_allowed(provider: CryptoProvider | None = None, deployment: Any = None) -> None:
    """Raise SeedPhrasePolicyError in fips_mode or in enterprise mode."""
    provider = provider or default_provider()
    if provider.fips_mode:
        raise SeedPhrasePolicyError(
            "seed-phrase backup is disabled in fips_mode: in a FIPS 140-3 deployment, keys must be generated "
            "by the validated module, not derived from words a person holds. Use the key file (keygen without "
            "--seed-phrase) or an HSM (docs/KEYS_AND_PKI.md)")
    if deployment is not None and getattr(deployment, "is_enterprise", False):
        raise SeedPhrasePolicyError(
            "seed-phrase backup is for personal mode only; enterprise mode uses PKI identities "
            "(X.509 certificates, optionally on a PKCS#11 token; docs/KEYS_AND_PKI.md)")
    provider.check("kdf", SEED_KDF)
    provider.check("kdf", COMPONENT_KDF)


def entropy_to_phrase(entropy: bytes) -> SeedPhrase:
    if not isinstance(entropy, (bytes, bytearray)) or len(entropy) != ENTROPY_BYTES:
        raise SeedPhraseError(f"entropy must be {ENTROPY_BYTES} bytes")
    checksum = hashlib.sha256(entropy).digest()[0]           # 256/32 = 8 checksum bits
    bits = (int.from_bytes(entropy, "big") << 8) | checksum  # 264 bits = 24 x 11
    wl = wordlist()
    return SeedPhrase(wl[(bits >> (11 * (WORDS - 1 - i))) & 0x7FF] for i in range(WORDS))


def _words(phrase: Any) -> list[str]:
    if isinstance(phrase, SeedPhrase):
        phrase = phrase.reveal()
    if not isinstance(phrase, str):
        raise SeedPhraseError("the seed phrase must be text")
    return unicodedata.normalize("NFKD", phrase).casefold().split()


def phrase_to_entropy(phrase: Any) -> bytes:
    """Validate a phrase (word count, wordlist membership, checksum) and return its 32-byte entropy."""
    words = _words(phrase)
    if len(words) != WORDS:
        raise SeedPhraseError(f"a seed phrase has {WORDS} words; got {len(words)}")
    idx = _index()
    bad = [i + 1 for i, w in enumerate(words) if w not in idx]
    if bad:
        raise SeedPhraseError(f"word(s) at position {', '.join(map(str, bad))} are not in the BIP-39 English "
                              "wordlist")
    bits = 0
    for w in words:
        bits = (bits << 11) | idx[w]
    entropy, checksum = (bits >> 8).to_bytes(ENTROPY_BYTES, "big"), bits & 0xFF
    if hashlib.sha256(entropy).digest()[0] != checksum:
        raise SeedPhraseError("checksum mismatch: a word is wrong or out of order")
    return entropy


def validate(phrase: Any) -> SeedPhrase:
    phrase_to_entropy(phrase)
    return SeedPhrase(_words(phrase))


def new_phrase(provider: CryptoProvider | None = None, deployment: Any = None) -> SeedPhrase:
    """A fresh 24-word phrase from 256 bits of provider randomness."""
    provider = provider or default_provider()
    check_allowed(provider, deployment)
    return entropy_to_phrase(provider.random_bytes(ENTROPY_BYTES))


def bip39_seed(phrase: Any, passphrase: str = "", provider: CryptoProvider | None = None) -> bytes:
    """The 64-byte BIP-39 seed (PBKDF2-HMAC-SHA512). The checksum is validated first."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    provider = provider or default_provider()
    provider.check("kdf", SEED_KDF)
    phrase_to_entropy(phrase)
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be a str")
    mnemonic = " ".join(_words(phrase)).encode("utf-8")
    salt = b"mnemonic" + unicodedata.normalize("NFKD", passphrase).encode("utf-8")
    return PBKDF2HMAC(hashes.SHA512(), 64, salt, BIP39_ITERATIONS).derive(mnemonic)


def component_seed(seed: bytes, alg: str, provider: CryptoProvider | None = None, length: int | None = None) -> bytes:
    """HKDF-SHA-384 expansion of the BIP-39 seed under the algorithm's domain label."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    provider = provider or default_provider()
    provider.check("kdf", COMPONENT_KDF)
    if alg not in LABELS:
        raise SeedPhraseError(f"no seed derivation for algorithm {alg!r}")
    if length is None:
        length = 56 if alg == "ecdsa-p384" else 32
    return HKDF(hashes.SHA384(), length, HKDF_SALT, LABELS[alg]).derive(seed)


def _component_raw(seed: bytes, alg: str, provider: CryptoProvider) -> bytes:
    raw = component_seed(seed, alg, provider)
    if alg == "ecdsa-p384":  # FIPS 186-5 A.2.1: d = (c mod (n-1)) + 1 from N+64 bits
        return ((int.from_bytes(raw, "big") % (_P384_N - 1)) + 1).to_bytes(48, "big")
    return raw


def derive_key(phrase: Any, suite: str = "ed25519", passphrase: str = "", provider: CryptoProvider | None = None,
               deployment: Any = None):
    """The private key for ``suite`` derived from the phrase (deterministic).

    Returns an Ed25519PrivateKey for the legacy ``ed25519`` suite (saved as PEM), otherwise a PrivateKeySet.
    """
    from .crypto.signatures import LEGACY_SUITE, SUITES, PrivateKeySet, _b64e, _Ed25519
    provider = provider or default_provider()
    check_allowed(provider, deployment)
    if suite not in SUITES:
        raise SeedPhraseError(f"unknown signature suite {suite!r}")
    seed = bip39_seed(phrase, passphrase, provider)  # Python can't wipe bytes; keep the seed short-lived
    if suite == LEGACY_SUITE:
        return _Ed25519.private_from_raw(_component_raw(seed, "ed25519", provider))
    comps = [{"alg": a, "raw": _b64e(_component_raw(seed, a, provider)),
              **({"format": "seed"} if a == "ml-dsa-65" else {})} for a in SUITES[suite]]
    return PrivateKeySet.from_components(suite, comps, provider)


def generate(suite: str = "ed25519", passphrase: str = "", provider: CryptoProvider | None = None,
             deployment: Any = None):
    """A new phrase and the key derived from it: ``(SeedPhrase, key)``. Show the phrase once."""
    phrase = new_phrase(provider, deployment)
    return phrase, derive_key(phrase, suite, passphrase, provider, deployment)


def public_encoded(key: Any, provider: CryptoProvider | None = None) -> str:
    from .crypto.signatures import as_public_keyset
    return as_public_keyset(key, provider or default_provider()).encoded


def matches(phrase: Any, public_key: Any, passphrase: str = "", provider: CryptoProvider | None = None,
            deployment: Any = None) -> bool:
    """True if the phrase (and passphrase) re-derive ``public_key``. Nothing is written."""
    from .crypto.signatures import as_public_keyset
    provider = provider or default_provider()
    want = as_public_keyset(public_key, provider)
    got = derive_key(phrase, want.suite, passphrase, provider, deployment)
    return hmac.compare_digest(public_encoded(got, provider), want.encoded)
