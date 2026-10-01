"""Startup cryptographic self-test (known-answer tests + pairwise consistency).

Modelled on the FIPS 140-3 pre-operational / conditional self-test idea. A
validated module runs its own mandatory self-tests; these application-level
tests are an extra check that the provider in use computes the right answers
before Two-Key accepts any constitution or issues any token.

Vectors
-------
* SHA-256("abc"), SHA-384("abc")          FIPS 180-4 examples (NIST CSRC)
* SHA3-256("abc")                         FIPS 202 examples (NIST CSRC)
* HMAC-SHA-256 / HMAC-SHA-384             RFC 4231 test case 2 (key "Jefe")
* Ed25519                                 RFC 8032 section 7.1, TEST 1 (empty message)
* ECDSA P-384                             pairwise consistency test (randomised signatures)
* ML-DSA-65                               pairwise consistency test, plus (pyca backend) a
                                          deterministic seed->public-key regression value.
                                          The regression value was produced by this project
                                          with pyca cryptography 50.0.1; it is NOT an
                                          official NIST ACVP vector.
Any failure raises SelfTestError and Two-Key refuses to start.
"""

from __future__ import annotations

import time

from .provider import CryptoProvider, PQUnavailableError, SelfTestError

KATS = {
    "sha256": (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    "sha384": (b"abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                       "8086072ba1e7cc2358baeca134c825a7"),
    "sha3-256": (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
}
HMAC_KATS = {
    "hmac-sha256": (b"Jefe", b"what do ya want for nothing?",
                    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    "hmac-sha384": (b"Jefe", b"what do ya want for nothing?",
                    "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e"
                    "8e2240ca5e69e2c78b3239ecfab21649"),
}
ED25519_KAT = {
    "sk": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "pk": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "msg": "",
    "sig": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
}
# Regression value (not an official NIST vector): SHA-256 of the ML-DSA-65 public key
# derived from seed bytes(range(32)) per FIPS 204 ML-DSA.KeyGen_internal.
MLDSA65_SEED_REGRESSION = "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9"


def _check(cond: bool, name: str) -> None:
    if not cond:
        raise SelfTestError(f"crypto self-test failed: {name}")


def run_selftest(p: CryptoProvider) -> dict:
    """Run all applicable self-tests against provider ``p``. Returns a report or raises SelfTestError."""
    from .signatures import _EcdsaP384, _Ed25519

    t0 = time.perf_counter()
    passed: list[str] = []
    try:
        for alg, (msg, want) in KATS.items():
            _check(p.hash_hex(alg, msg) == want, f"KAT {alg}")
            passed.append(f"KAT {alg}")
        for alg, (key, msg, want) in HMAC_KATS.items():
            # RFC 4231 TC2 uses a 4-byte key, below this project's 256-bit minimum for real
            # keys, so the KAT calls the primitive directly (still through the policy check).
            p.check("mac", alg)
            import hmac as _h
            _check(_h.new(key, msg, alg.split("-", 1)[1]).hexdigest() == want, f"KAT {alg}")
            passed.append(f"KAT {alg} (RFC 4231 TC2)")

        p.check("sig", "ed25519")
        sk = _Ed25519.private_from_raw(bytes.fromhex(ED25519_KAT["sk"]))
        _check(_Ed25519.public_raw(sk.public_key()).hex() == ED25519_KAT["pk"], "KAT Ed25519 public key")
        sig = _Ed25519.sign(sk, bytes.fromhex(ED25519_KAT["msg"]))
        _check(sig.hex() == ED25519_KAT["sig"], "KAT Ed25519 signature")
        _check(_Ed25519.verify(sk.public_key(), sig, b""), "KAT Ed25519 verify")
        _check(not _Ed25519.verify(sk.public_key(), sig, b"x"), "KAT Ed25519 negative verify")
        passed.append("KAT Ed25519 (RFC 8032 TEST 1)")

        p.check("sig", "ecdsa-p384")
        ek = _EcdsaP384.generate()
        esig = _EcdsaP384.sign(ek, b"two-key selftest")
        _check(_EcdsaP384.verify(ek.public_key(), esig, b"two-key selftest"), "PCT ECDSA P-384")
        _check(not _EcdsaP384.verify(ek.public_key(), esig, b"tampered"), "PCT ECDSA P-384 negative")
        passed.append("PCT ECDSA P-384")

        pq = None
        try:
            pq = p.pq_backend()
        except Exception as e:  # policy refusal of the PQ backend is reported, not hidden
            passed.append(f"ML-DSA-65 skipped ({type(e).__name__}: {e})")
        if pq is not None:
            p.check("sig", "ml-dsa-65")
            if pq.name == "pyca":
                k = pq.private_from_raw(bytes(range(32)), "seed")
                _check(p.hash_hex("sha256", pq.public_raw(pq.public_of(k))) == MLDSA65_SEED_REGRESSION,
                       "ML-DSA-65 seed keygen regression")
                passed.append("ML-DSA-65 seed keygen regression (project value)")
            k = pq.generate()
            s = pq.sign(k, b"two-key selftest")
            _check(pq.verify(pq.public_of(k), s, b"two-key selftest"), "PCT ML-DSA-65")
            _check(not pq.verify(pq.public_of(k), s, b"tampered"), "PCT ML-DSA-65 negative")
            passed.append(f"PCT ML-DSA-65 ({pq.name})")
        elif not any(x.startswith("ML-DSA-65 skipped") for x in passed):
            passed.append("ML-DSA-65 skipped (no PQ backend)")

        _check(len(p.random_bytes(32)) == 32, "RNG os.urandom")
        passed.append("RNG os.urandom available")
    except SelfTestError:
        raise
    except PQUnavailableError:
        raise
    except Exception as e:
        raise SelfTestError(f"crypto self-test error: {type(e).__name__}: {e}") from e
    return {"ok": True, "passed": passed, "fips_mode": p.fips_mode,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000, 3)}
