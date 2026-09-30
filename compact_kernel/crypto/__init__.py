"""Crypto layer: pluggable provider (FIPS mode), signature suites (classic + hybrid PQ), self-test.

Not FIPS certified or validated. See docs/CRYPTO.md.
"""

from .provider import (APPROVED, CryptoPolicyError, CryptoProvider, PQUnavailableError, SelfTestError,
                       default_provider, openssl_fips_status, set_default_provider)
from .signatures import (LEGACY_SUITE, PQ_SUITES, SUITES, PrivateKeySet, PublicKeySet, as_private_keyset,
                         as_public_keyset, pq_available, public_keyset_from_encoded, resolve_mldsa_backend)

__all__ = [
    "APPROVED", "CryptoPolicyError", "CryptoProvider", "PQUnavailableError", "SelfTestError",
    "default_provider", "openssl_fips_status", "set_default_provider", "LEGACY_SUITE", "PQ_SUITES",
    "SUITES", "PrivateKeySet", "PublicKeySet", "as_private_keyset", "as_public_keyset", "pq_available",
    "public_keyset_from_encoded", "resolve_mldsa_backend",
]
