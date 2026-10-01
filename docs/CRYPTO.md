# Cryptography: FIPS 140-3 posture and quantum resistance

Status as of 2026-09-30. Written by the AI engineering assistant at Stephan
Busch's direction. **This software is not "FIPS certified" or "FIPS
validated", and nothing in this repository makes it so.** It uses only
FIPS-approved algorithms, routed through one pluggable crypto provider, so
that it *can* be deployed on a FIPS 140-3 validated cryptographic module.

## 1. What FIPS 140-3 compliance requires

FIPS 140-3 validates **cryptographic modules**, not applications. An
application can claim to use FIPS 140-3 validated cryptography only when
**all** of these hold:

1. every cryptographic operation runs inside a module that holds an active
   CMVP certificate (check the NIST CMVP search at
   <https://csrc.nist.gov/projects/cryptographic-module-validation-program>);
2. the module is the exact validated version, built and installed as its
   Security Policy requires (e.g. `openssl fipsinstall` for the OpenSSL FIPS
   provider), on a tested operational environment;
3. the module runs in its approved mode, and the application uses only the
   algorithms, key sizes, and modes that the Security Policy lists as
   approved for that module.

On the development machine used for this work **no FIPS provider is
active**: `python -m two_key selftest` reports `hashlib_fips: false`
and `cryptography_fips: false`. CPython's `hashlib` there links the system
OpenSSL 3.5.7; the pyca `cryptography` 50.0.1 wheel bundles its own OpenSSL
4.0.2. Neither is a validated module as installed.

### What the code does

| Mechanism | Where | Behaviour |
|---|---|---|
| Single provider | `two_key/crypto/provider.py` (`CryptoProvider`) | Every hash, HMAC, random draw, and signature-algorithm choice goes through it. `canonical.py`, `ledger.py`, `merkle.py` (via the ledger), `capability.py`, `constitution.py`, `keys.py`, and Two-Key all take or use a provider. |
| `fips_mode=True` | provider | Refuses anything outside the approved list (`CryptoPolicyError`): e.g. `blake2b`, `md5`, `sha1`, `hmac-sha1`, unknown algorithms. Also refuses the `liboqs` PQ backend, because liboqs is not a validated module. `blake2b`/`md5`/`sha1` exist in the code only so the refusal can be tested. Nothing uses them by default. |
| `require_fips_module=True` | provider | Refuses to start unless **both** OpenSSL instances report FIPS mode (`_hashlib.get_fips_mode()` and pyca `backend._fips_enabled`). This is the switch to turn on in a real FIPS deployment. |
| RNG | provider `random_bytes` → `os.urandom`; token ids use `secrets` | No other randomness source is used. |
| Startup self-test | `two_key/crypto/selftest.py` | Runs once per provider before Two-Key accepts a constitution. Any failure raises `SelfTestError` and Two-Key refuses to start. See section 5. |
| Key sizes | provider, `capability.py` | HMAC keys shorter than 256 bits are refused. Default token keys are 256 bits (tk1) or 384 bits (tk1-hs384). |

The application-level self-test is extra. It does not replace the module's
own mandatory FIPS 140-3 self-tests.

## 2. Candidate validated modules

Verify every entry on CMVP before relying on it. Certificates move to
"historical", and new ones are issued often. The status below is what could
be found on 2026-09-30.

| Module | FIPS 140-3 status found | Notes for this project |
|---|---|---|
| **OpenSSL 3 FIPS provider** | 3.1.2 provider: certificate **#4985** (active, sunset March 2030). The 3.5.x provider (adds ML-DSA, ML-KEM, SLH-DSA) was submitted and is listed as in CMVP review (3.5.4). The older 140-2 certificates #4282/#4811 moved to historical on 21 Sep 2026. | In the 3.1.2 provider **Ed25519 is present but not approved**. OpenSSL marked EdDSA approved only from the 3.4 provider onward. On #4985, use the `ecdsa-p384` or `hybrid-mldsa65-p384` suite. #4985 has **no ML-DSA**, so hybrid PQ signing on that module runs ML-DSA outside the validated boundary. pyca `cryptography` must be built against the FIPS-enabled system OpenSSL, not from the wheel (the wheel bundles its own OpenSSL). |
| **AWS-LC (AWS-LC FIPS)** | Several FIPS 140-3 certificates (#4631, #4759, #4816, #5146; #5298 for AWS-LC 3 dynamic, active from 2026-06-03, whose listing includes EdDSA and ML-KEM). ML-DSA on an active AWS-LC certificate could **not** be confirmed. | pyca `cryptography` supports building against AWS-LC (since 45.0.2; `OPENSSL_DIR=<aws-lc>`), including its ML-DSA API. Candidate for a pyca-based deployment. CPython `hashlib` would still need a FIPS OpenSSL (or route all hashing through pyca; the provider interface allows that). |
| **BoringCrypto** (BoringSSL FIPS module) | Holds FIPS 140 validations for specific versions. | Usable via pyca built against BoringSSL; check the version-specific certificate and its algorithm list. |
| **Microsoft SymCrypt** | Validated on Windows/Azure Linux builds. | Would need a custom `CryptoProvider` implementation. |
| **Distribution FIPS packages** (RHEL, Ubuntu Pro FIPS, SUSE, Chainguard FIPS images) | Each vendor validates its own OpenSSL build. | Simplest route for Linux servers: enable the distro FIPS mode and use distro-built Python and `python3-cryptography` linked to that OpenSSL. |
| **HSM / PKCS#11 module** | Many HSMs hold FIPS 140-3 Level 3 certificates. | Recommended for the principal signing key (spec §5.1 item 6). Would need a `PrivateKeySet` backend that calls the HSM. Not implemented. |

## 3. Every cryptographic use, its algorithm, and its standard

"Legacy" is the default profile, unchanged from the previous version
(Ed25519 key). "PQ" is the profile chosen automatically when the principal
key is a hybrid ML-DSA suite (it also applies to the `ecdsa-p384` suite).

| Use | Legacy profile | PQ / non-legacy profile | Standard(s) |
|---|---|---|---|
| Constitution signature | Ed25519 | ML-DSA-65 **and** Ed25519, or ML-DSA-65 **and** ECDSA P-384 (both must verify). Classical-only alternative: ECDSA P-384 | FIPS 186-5 (EdDSA, ECDSA), FIPS 204 (ML-DSA) |
| Constitution digest (bound into tokens and ledger) | SHA-256 | SHA-384 | FIPS 180-4 |
| Constitution text hash inside the signed document | SHA-256 | SHA-256 (the text itself is covered by the signature) | FIPS 180-4 |
| Ledger hash chain (entry digests) | SHA-256 | SHA-384 (the algorithm is bound into each digest) | FIPS 180-4 |
| Ledger Merkle tree (RFC 6962 structure) | SHA-256 | SHA-384 | FIPS 180-4 |
| Ledger chain-head signature | Ed25519 | same suite as the principal key (hybrid) | FIPS 186-5, FIPS 204 |
| Capability token tag | HMAC-SHA-256 (`tk1`), key ≥ 256 bits | HMAC-SHA-384 (`tk1-hs384`), 384-bit key; optional `tk1-sig` signed tokens (hybrid ML-DSA-65) | FIPS 198-1 + FIPS 180-4; FIPS 204 |
| Tool-call argument binding (`args_hash`) | SHA-256 | SHA-384 | FIPS 180-4 |
| Ledger consistency and inclusion proofs (RFC 9162), the gateway's ancestor check for the token's root R (PRIOR_ART.md §4 (i)) | SHA-256 | SHA-384 | FIPS 180-4 |
| `bytecode_hash` = H(canonical Path A bytecode), `nl_hash` = H(Path B prose) (§4 (ii)); bound into ballots and tokens | SHA-256 | SHA-384 | FIPS 180-4 |
| Ballot binding H(action record) (§4 (iii)); `result_hash` of executed tools (§4 (i)) | SHA-256 | SHA-384 | FIPS 180-4 |
| Source hash inside a single-source (`/2`) constitution document | SHA-256 | SHA-256 (the source is covered by the signature) | FIPS 180-4 |
| Token identifier in ledger (`token_sha256`) | SHA-256 | SHA-256 (an identifier; the binding is the tag) | FIPS 180-4 |
| Token `jti`, HMAC keys, salts, nonces | `os.urandom` / `secrets` | same | OS CSPRNG. In a FIPS deployment the entropy source and DRBG must be the ones covered by the platform's validation (e.g. a validated kernel crypto module and an SP 800-90B entropy source); check the module's Security Policy. |
| Key bundle encryption (non-legacy suites) | n/a (legacy keys: PEM PKCS#8 via `BestAvailableEncryption`, whose algorithm is chosen by the `cryptography` library) | PBKDF2-HMAC-SHA-256, 600,000 iterations, 128-bit salt → AES-256-GCM, 96-bit nonce, header as AAD | SP 800-132, SP 800-38D, FIPS 197 |
| Startup self-test | KATs and PCTs listed in section 5 | same | FIPS 140-3 self-test concept (application level) |
| Judge HTTPS (Path B) | Python `ssl` (system OpenSSL) | same | Outside Two-Key; TLS configuration is the deployment's responsibility |

Notes:

* In a FIPS deployment on OpenSSL 3.1.2 (#4985), replace Ed25519 with ECDSA
  P-384 (`keygen --suite ecdsa-p384` or `hybrid-mldsa65-p384`), because
  Ed25519 is not approved in that module.
* Legacy PEM keys: `BestAvailableEncryption` in pyca may choose a
  non-approved PBE scheme. For FIPS, use the JSON key bundle (non-legacy
  suites) or an HSM.

## 4. Quantum resistance

| Primitive | Quantum threat | What this project does |
|---|---|---|
| Ed25519, ECDSA P-384 | Broken by Shor's algorithm on a large fault-tolerant quantum computer | Hybrid suites add **ML-DSA-65** (FIPS 204, NIST security category 3) to constitution signing and the ledger chain head, and optionally to capability tokens (`tk1-sig`). |
| SHA-256 / SHA-384 | Grover roughly halves preimage security; quantum collision search gives a smaller speed-up | PQ profile uses **SHA-384** for all security-relevant digests (ledger chain, Merkle tree, constitution digest, args binding). |
| HMAC-SHA-256/384 tokens | Grover at most halves the effective key strength | **Symmetric HMAC tokens with keys of 256 bits or more are already considered quantum-resistant.** Keys below 256 bits are refused. `tk1-hs384` uses 384-bit keys. |
| AES-256-GCM (key bundles) | Grover halves the effective key strength (to about 128 bits) | Adequate. |

### Hybrid rule and wire format

* Suites: `hybrid-mldsa65-ed25519` and `hybrid-mldsa65-p384`
  (`two_key/crypto/signatures.py`).
* A hybrid signature is accepted only if **both** components verify. A
  missing, altered, reordered, duplicated, or replaced component, or a
  relabelled suite, means reject. Tests: `tests/test_pq_hybrid.py`.
* Each component signs `b"two-key/sig/v1\0" + suite + b"\0" +
  message`. The suite name is bound into both halves, so the classical half
  cannot be lifted out and presented as a plain Ed25519 signature.
* **No downgrade:** the verifier uses the suite of the *trusted* key. A
  hybrid-trusted constitution, ledger head, or token with a classical-only
  signature is rejected (`downgrade refused`, `head_suite_mismatch`,
  `unsupported_token_version`).
* **No silent fallback:** if a hybrid key is configured but no ML-DSA
  backend is available, key generation, key parsing, verification, and
  Two-Key start-up raise `PQUnavailableError`. `require_pq=True` also refuses
  to start with a classical principal key.
* Encoding: public key = base64 of canonical JSON
  `{"suite", "keys": [[alg, b64], …]}`; signature = base64 of canonical JSON
  `{"suite", "sigs": [[alg, b64], …]}`. ML-DSA-65 public keys are 1,952
  bytes and signatures 3,309 bytes (FIPS 204 encodings). A hybrid signature
  is about 6.1 KB in base64. Legacy Ed25519 formats are unchanged.

### PQ backend selection

`CryptoProvider(pq_backend=…)`, or `--pq-backend` on the CLI:

| Choice | Behaviour |
|---|---|
| `auto` (default) | pyca `cryptography` if its OpenSSL has ML-DSA, else liboqs-python (liboqs is never used in `fips_mode`), else unavailable. |
| `pyca` | pyca `cryptography` only. |
| `liboqs` | liboqs-python only (`oqs.Signature("ML-DSA-65")`). Refused in `fips_mode`. |
| `none` | No PQ. Any hybrid operation raises `PQUnavailableError`. |

**Used for this work:** pyca `cryptography` **50.0.1** (wheel with bundled
**OpenSSL 4.0.2**), installed in a virtualenv. The system interpreter has
`cryptography` 43.0.0 without ML-DSA; the test suite runs under both, and
the PQ tests are skipped (with the missing-library tests active) on 43.0.0.
liboqs-python was **not** installed. Its adapter is exercised only with a
fake `oqs` module in the tests, so it has not been run against real liboqs.

### ML-DSA and FIPS validation

ML-DSA is a FIPS-approved algorithm (FIPS 204, August 2024). Whether a
given deployment uses *validated* ML-DSA depends entirely on the module:

* pyca 50.0.1 with its bundled OpenSSL 4.0.2 (what was used here): not a
  validated module.
* OpenSSL 3.1.2 FIPS provider (#4985): has no ML-DSA.
* OpenSSL 3.5.x FIPS provider: includes ML-DSA; it was in CMVP review when
  last checked.
* AWS-LC: ML-DSA on an active certificate could not be confirmed.
* liboqs: not validated; refused in `fips_mode`.

In `fips_mode` the provider allows ML-DSA as an *algorithm*. Pair it with
`require_fips_module=True` and a module whose Security Policy lists ML-DSA
before claiming validated PQ signatures.

## 5. Self-test contents

| Test | Vector source |
|---|---|
| SHA-256("abc"), SHA-384("abc") | FIPS 180-4 examples (NIST CSRC) |
| SHA3-256("abc") | FIPS 202 examples (NIST CSRC) |
| HMAC-SHA-256 and HMAC-SHA-384 | RFC 4231 test case 2 |
| Ed25519 key derivation, signature, verify, negative verify | RFC 8032 §7.1 TEST 1 |
| ECDSA P-384 | Pairwise consistency test (signatures are randomised) |
| ML-DSA-65 | Pairwise consistency test (sign, verify, negative verify). With the pyca backend, also a seed→public-key regression value produced by this project with pyca 50.0.1. **This is not an official NIST ACVP vector.** |
| RNG | `os.urandom` returns the requested length |

`python -m two_key selftest [--require-pq]` prints the report and the
provider description. A forced failure (tested in `tests/test_crypto.py`)
stops Two-Key before it writes anything.

## 6. What is not done / limits

* No module was validated, and none can be validated by this repository. A
  FIPS claim needs a deployment on a validated module (section 2).
* The development box has no FIPS provider, so `require_fips_module=True`
  was only tested for its refusal path.
* liboqs-python was not installed; its adapter has been tested only against
  a fake module.
* ML-DSA KATs from NIST ACVP are not bundled. The ML-DSA self-test is a
  pairwise-consistency test plus a project regression value.
* Private keys are file-based (encrypted JSON bundle or PEM), not in an HSM.
* No key-exchange (ML-KEM) is used, because Two-Key has no key-exchange
  step. TLS to judge providers is outside Two-Key.
