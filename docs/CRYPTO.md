# Cryptography: FIPS 140-3 posture and quantum resistance

Status as of 2026-09-30. Written by the AI engineering assistant at Stephan
Busch's direction.

**Posture: FIPS-approved algorithms, validated module required for compliance.**

This software is not "FIPS certified" or "FIPS validated", and nothing in
this repository makes it so. Every algorithm goes through one pluggable
crypto provider, so the software *can* be deployed on a FIPS 140-3
validated cryptographic module.

Since the F_REVIEW fixes (approved by Stephan, CONCEPTION_NOTES Entry 10:
"A, but ensure quantum resistance and fips 140-3 compliance where
applicable"), every profile uses SHA-384 hashes and HMAC-SHA-384 MACs with
keys of 256 bits or more by default. Tool arguments and action records are
hashed in the typed, injective `two-key-enc/2` encoding. Older artifacts
still verify through legacy readers (section 3.1).

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
| Key sizes | provider, `capability.py`, `scanning.py` | HMAC keys shorter than 256 bits are refused (tokens and the scan-verdict webhook). Default token keys are 384 bits (`tk1-hs384`). |

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

"Default" applies to every principal-key suite since the F_REVIEW fixes.
"Before" is what the Ed25519 ("legacy") profile used until then. Records
written that way are still read (section 3.1). The hybrid and P-384
profiles already used SHA-384 and HMAC-SHA-384.

| Use | Default (every suite) | Before (Ed25519 profile) | Standard(s) |
|---|---|---|---|
| Constitution signature | Same suite as the principal key: Ed25519, ECDSA P-384, or hybrid ML-DSA-65 **and** Ed25519 / P-384 (both must verify) | unchanged | FIPS 186-5 (EdDSA, ECDSA), FIPS 204 (ML-DSA) |
| Constitution digest (bound into tokens and ledger) | SHA-384 | SHA-256 | FIPS 180-4 |
| Constitution text / source hash inside the signed document | SHA-384 (`constitution_text_sha384`, `source_sha384`) | SHA-256 (`..._sha256`; still accepted) | FIPS 180-4 |
| Ledger hash chain (entry digests; the algorithm is bound into each digest) | SHA-384 | SHA-256 | FIPS 180-4 |
| Ledger Merkle tree (RFC 6962 structure), consistency and inclusion proofs (RFC 9162), the gateway's ancestor check (PRIOR_ART.md §4 (i)) | SHA-384 | SHA-256 | FIPS 180-4 |
| Ledger chain-head signature | same suite as the principal key | unchanged | FIPS 186-5, FIPS 204 |
| Capability token tag | HMAC-SHA-384 (`tk1-hs384`), 384-bit key by default, ≥ 256 bits required; optional `tk1-sig` (hybrid ML-DSA-65) | HMAC-SHA-256 (`tk1`); still selectable explicitly | FIPS 198-1 + FIPS 180-4; FIPS 204 |
| Tool-call argument binding (`args_hash`): H(two-key-enc/2 of {tool, args}), also what the gateway scans and executes | SHA-384 over the typed encoding | SHA-256 over canonical JSON (not injective) | FIPS 180-4 |
| `bytecode_hash`, `nl_hash` (§4 (ii)); bound into ballots and tokens | SHA-384 | SHA-256 | FIPS 180-4 |
| Ballot binding H(action record) (§4 (iii)), decision `action_digest` | SHA-384 over two-key-enc/2 (`two-key/action-record` label) | SHA-256 over canonical JSON | FIPS 180-4 |
| `result_hash` of executed tools | SHA-384 over two-key-enc/2 (`two-key/tool-result`) | SHA-256 over canonical JSON | FIPS 180-4 |
| Proposal text digest in the ledger | `proposal_digest` with the ledger's algorithm (SHA-384) | `proposal_sha256` | FIPS 180-4 |
| Token identifier in the ledger | `token_digest` (SHA-384) | `token_sha256` | FIPS 180-4 |
| Permissioned-chain anchor record (`docs/DEPLOYMENT_MODES.md`) | SHA-384 | (new) | FIPS 180-4 |
| Scan-verdict webhook (`WebhookReceiver`) | HMAC-SHA-384 (`sha384=`; `hmac-sha512` optional), key ≥ 256 bits | HMAC-SHA-256, 128-bit minimum key | FIPS 198-1 |
| Token `jti`, HMAC keys, salts, nonces | `os.urandom` / `secrets` | unchanged | OS CSPRNG. In a FIPS deployment the entropy source and DRBG must be the ones covered by the platform's validation (e.g. a validated kernel crypto module and an SP 800-90B entropy source); check the module's Security Policy. |
| Key bundle encryption (JSON bundles, non-Ed25519 suites) | PBKDF2-HMAC-SHA-384, 600,000 iterations, 128-bit salt → AES-256-GCM, 96-bit nonce, header as AAD | PBKDF2-HMAC-SHA-256 (still loaded) | SP 800-132, SP 800-38D, FIPS 197 |
| Ed25519 PEM keys | PKCS#8 via pyca `BestAvailableEncryption` (scheme chosen by the library) | unchanged | see notes |
| Seed-phrase backup (optional, personal mode; `docs/KEYS_AND_PKI.md`) | BIP-39: 256-bit entropy (`os.urandom`), 24 words, PBKDF2-HMAC-SHA-512 (2048 iterations) → 64-byte seed; HKDF-SHA-384 per algorithm with domain labels → Ed25519 key, ML-DSA-65 seed, P-384 scalar (FIPS 186-5 A.2.1) | (new) | SP 800-132, SP 800-56C. **Refused in `fips_mode`:** keys derived from words a person holds are outside a validated module's key generation |
| PKI identities (enterprise; `docs/KEYS_AND_PKI.md`) | X.509 chains via pyca's verifier; certificate keys ECDSA P-384 or Ed25519; ML-DSA-65 key bound by SHA-384 in a CA-signed extension; OCSP request IDs SHA-256 | (new) | RFC 5280, RFC 6960, FIPS 186-5, FIPS 204 |
| Key fingerprint shown for Ed25519 keys | `ed25519:` + first 128 bits of SHA-256 of the public key (a display identifier; verification compares the full key) | unchanged | FIPS 180-4 |
| Startup self-test | KATs and PCTs listed in section 5 | fewer KATs | FIPS 140-3 self-test concept (application level) |
| Judge HTTPS (Path B) | Python `ssl` (system OpenSSL) | unchanged | Outside Two-Key; TLS configuration is the deployment's responsibility |

Notes:

* In a FIPS deployment on OpenSSL 3.1.2 (#4985), replace Ed25519 with ECDSA
  P-384 (`keygen --suite ecdsa-p384` or `hybrid-mldsa65-p384`), because
  Ed25519 is not approved in that module.
* Legacy PEM keys: `BestAvailableEncryption` in pyca may choose a
  non-approved PBE scheme. For FIPS, use the JSON key bundle (non-legacy
  suites) or an HSM.
* `merkle.py`'s module-level default hash is SHA-256, for its RFC 6962/9162
  test vectors. The ledger and gateway always pass the provider's hash.

### 3.1 Versioning and legacy readers

Changing the default hash and the encoding would break verification of
existing artifacts. The safer option was chosen: every artifact says which
algorithm or encoding it uses, and older ones still verify. Nothing written
before is reinterpreted.

| Artifact | How it is versioned | Old artifacts |
|---|---|---|
| Ledger entries | Each entry carries `alg` (entries without it are SHA-256) | Verify as before (`PersonalLedger(path).verify(key)`, `python -m two_key verify-ledger`). `TwoKey` refuses to *append* to a SHA-256 ledger unless `digest_alg="sha256"` is passed explicitly. The error says so. |
| Signed constitutions | Field name says the hash: `constitution_text_sha384` / `source_sha384` (new) or `..._sha256` (old) | Verify as before; every digest field present must match |
| Key bundles | `encryption.kdf` names the KDF | `pbkdf2-hmac-sha256` bundles still load |
| Capability tokens | Payload `args_enc: "two-key-enc/2"` | Refused (`unsupported_args_encoding`). Tokens live `ttl_seconds` (30 s by default) and are single-use, so only tokens in flight during an upgrade are affected |
| `args_hash` values in old ledgers | `capability_issued` / `capability_redeemed` record `args_enc` from now on | `capability.args_hash_legacy` recomputes the old value for audits. It is never used to authorize a call |
| Signatures | unchanged | unchanged |

### 3.2 The `two-key-enc/2` encoding

`two_key/canonical.py` (`typed_bytes`, `typed_loads`, `freeze_call`). It
fixes F_REVIEW findings 1 and 2:

* The output is canonical JSON: `{"domain": <label>, "enc": "two-key-enc/2",
  "value": <tagged>}`. The version and the domain-separation label
  (`two-key/tool-call`, `two-key/action-record`, `two-key/tool-result`)
  are inside the hashed bytes.
* Every value is type-tagged: `["z"]` None, `["b", bool]`, `["i", "<decimal>"]`,
  `["f", "<repr>"]`, `["s", str]`, `["l", [...]]` list, `["t", [...]]`
  tuple, `["m", [[key, value], ...]]` mapping, sorted by key. Tuple vs list,
  `1` vs `"1"`, `1` vs `1.0`, `True` vs `1`, and `0.0` vs `-0.0` all encode
  differently.
* Non-string mapping keys, duplicate keys, sets, bytes, other objects,
  NaN/infinity, and nesting deeper than 64 are refused (`EncodingError`, a
  `TypeError`), so the call is denied (`invalid_action:` / `invalid_call:`).
* No Unicode normalization: differently normalized strings stay different
  (a false mismatch, never a false match). Whether to normalize (NFC) is
  an open question.
* `canonical_bytes` (canonical JSON, for JSON-native records) now refuses
  non-string keys instead of coercing them. No record that already verifies
  changes bytes.

The gateway serializes the call once with `freeze_call`, hashes those
bytes for the `args_hash` check, sends the same bytes to content scanners,
and gives the extractor and the tool their own copies decoded from them.
The caller's object is read exactly once, so changing it later (or a
mapping that answers differently on a second read) can't change what runs.
`authorize` logs the arguments decoded from the bytes it hashed.

## 4. Quantum resistance

| Primitive | Quantum threat | What this project does |
|---|---|---|
| Ed25519, ECDSA P-384 | Broken by Shor's algorithm on a large fault-tolerant quantum computer | Hybrid suites add **ML-DSA-65** (FIPS 204, NIST security category 3) to constitution signing and the ledger chain head, and optionally to capability tokens (`tk1-sig`). |
| SHA-256 / SHA-384 | Grover roughly halves preimage security; quantum collision search gives a smaller speed-up | **SHA-384** by default for all security-relevant digests in every profile (ledger chain, Merkle tree, constitution digest, args binding, ballots, anchors). SHA-512 and SHA3-384/512 are approved and self-tested alternatives (`digest_alg=`). |
| HMAC tokens and the webhook MAC | Grover at most halves the effective key strength | **HMAC-SHA-384** by default; keys below 256 bits are refused; `tk1-hs384` uses 384-bit keys. |
| AES-256-GCM (key bundles) | Grover halves the effective key strength (to about 128 bits) | Adequate. The key comes from PBKDF2-HMAC-SHA-384; its strength is bounded by the passphrase. |

**Signatures are quantum-resistant only with a hybrid suite.** The default
`keygen` suite is still Ed25519 (`--suite` chooses). Ed25519 and ECDSA P-384
alone are not quantum-resistant. Use `hybrid-mldsa65-ed25519` or
`hybrid-mldsa65-p384`, and `require_pq=True` to refuse anything else.

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
| SHA-256, SHA-384, SHA-512 ("abc") | FIPS 180-4 examples (NIST CSRC) |
| SHA3-256, SHA3-384, SHA3-512 ("abc") | FIPS 202 examples (NIST CSRC) |
| HMAC-SHA-256, -384, -512 | RFC 4231 test case 2 |
| PBKDF2-HMAC-SHA-256 | RFC 7914 §11 ("passwd", "salt", c = 1) |
| PBKDF2-HMAC-SHA-384 | Project regression value ("password", "salt", c = 4096, 48 bytes), cross-checked against Python's `hashlib`. **Not an official NIST ACVP vector.** |
| PBKDF2-HMAC-SHA-512 | BIP-39 reference vector (trezor/python-mnemonic `vectors.json`: 24-word all-zero mnemonic, passphrase "TREZOR") |
| HKDF-SHA-384 | Wycheproof `hkdf_sha384_test.json` tcId 70 |
| Ed25519 key derivation, signature, verify, negative verify | RFC 8032 §7.1 TEST 1 |
| ECDSA P-384 | Pairwise consistency test (signatures are randomised) |
| ML-DSA-65 | Pairwise consistency test (sign, verify, negative verify). With the pyca backend, also a seed→public-key regression value produced by this project with pyca 50.0.1. **This is not an official NIST ACVP vector.** |
| RNG | `os.urandom` returns the requested length |

`python -m two_key selftest [--require-pq]` prints the report and the
provider description. A forced failure (tested in `tests/test_crypto.py`)
stops Two-Key before it writes anything.

## 6. What is not done / limits

* FIPS-approved algorithms, validated module required for compliance. No
  module was validated, and none can be validated by this repository
  (section 2).
* The development box has no FIPS provider, so `require_fips_module=True`
  was only tested for its refusal path.
* liboqs-python was not installed; its adapter has been tested only against
  a fake module.
* ML-DSA KATs from NIST ACVP are not bundled. The ML-DSA self-test is a
  pairwise-consistency test plus a project regression value.
* Private keys are file-based (encrypted JSON bundle or PEM), not in an HSM.
* No key-exchange (ML-KEM) is used, because Two-Key has no key-exchange
  step. TLS to judge providers is outside Two-Key.
