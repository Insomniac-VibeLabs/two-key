# Provisional-patent readiness (2026-10-01)

This is a working checklist for Stephan and his patent counsel. It is not
legal advice. It lists every capability claimed in `README.md`,
`docs/SPEC_DRAFT.md`, and `CONCEPTION_NOTES.md` Entries 1–11; where each is
implemented; and the evidence that it works. It then lists what is a stub,
a placeholder, or untested against real vendors, and the open questions
for Stephan.

Prepared by the AI engineering assistant at Stephan's 2026-10-01 9:56 AM MT
direction (Entry 11: "make sure the code is at least functional enough for
a provisional patent"). This document records engineering status. It is
not conception, and it does not decide any design question.

**How to reproduce the evidence**

- Full suite: `python -m unittest discover -s tests`. On 2026-10-01:
  - 413 tests, all passing, on Python 3.13 with `cryptography` 50.0.1,
    `python-pkcs11` 0.10.0 and SoftHSM 2.6.1. 2 tests were skipped: they
    exercise the "no ML-DSA backend" path, which can't occur on that setup.
  - The same 413 pass on `cryptography` 43.0.0 without ML-DSA or
    `python-pkcs11`, with 20 skipped (hybrid PQ and the SoftHSM token).
- End-to-end demo: `python -m two_key e2e-demo`. It runs offline with no
  vendor credentials, using fake judges, pattern scanners, a test CA, a
  software PKCS#11 token, and an in-memory permissioned chain.
  - It makes 42 checks in 8 sections and exits non-zero if any check fails.
  - `tests/test_e2e_demo.py` runs it as a subprocess and in-process.
  - Without an ML-DSA backend, the hybrid section reports SKIP rather than
    PASS.
- Doc examples: `python tools/doccheck.py README.md docs/HOWTO.md` runs
  every example in both documents and checks its output. Both passed on
  2026-10-01.

## 1. Claimed features: implementation and evidence

"e2e §n" refers to section n of `python -m two_key e2e-demo`.

| # | Feature (source) | Implemented in | Evidence |
|---|---|---|---|
| 1 | Constitution upload and signing: one uploaded document signed by the principal; modified or foreign-signed documents refused (Entry 1; SPEC §5.2) | `two_key/constitution.py`, `two_key/keys.py`, `two_key/cli.py` (`keygen`, `sign`, `verify`) | `tests/test_constitution.py` (SignVerify, FileUpload), `tests/test_cli_demo.py`; e2e §2 |
| 2 | Action record and Path A: constitution rules compiled to bytecode and evaluated by a deterministic policy VM; faults deny (D §5.2–5.3; SPEC §5.3–5.4) | `two_key/action.py`, `two_key/compiler.py`, `two_key/policy_vm.py` | `tests/test_original.py` (VMTests), `tests/test_bugfixes.py` (CompilerStrictness, VMFaults, AmountValidation); e2e §4 |
| 3 | One signed constitution, two compilations: prose for Path B, rules for Path A (SB-2 (ii); SPEC §5.5) | `two_key/constitution.py`, `two_key/compiler.py` | `tests/test_two_compilations.py`; e2e §2 |
| 4 | Path B: a quorum of judges on the principal's chosen AI, with a strict ballot schema, model heterogeneity, an availability floor, and ballot binding (Entry 1; SB-2 (iii); SPEC §5.6–5.7) | `two_key/quorum.py`, `two_key/judges/` | `tests/test_judges.py`, `tests/test_quorum_protocol.py`, `tests/test_perf_paths.py` (ParallelJudges); e2e §4 |
| 5 | Both paths required for an allow, with Path B ordered after Path A by default (D §5.4; SPEC §5.10a) | `two_key/core.py` (`TwoKey.authorize`) | `tests/test_original.py` (TwoKeyTests), `tests/test_ordering.py`; e2e §4 (each path denies on its own) |
| 6 | Capability tokens: single use, bound to tool and args hash, with expiry; HMAC-SHA-384 or signed `tk1-sig` (D §5.5; SPEC §5.8) | `two_key/capability.py` | `tests/test_gateway_ledger.py` (GatewayChecks), `tests/test_shared_redemption.py`; e2e §5 |
| 7 | Ledger-root-bound tokens: a token carries the ledger root, and execution is linked to the token entry (SB-2 (i); SPEC §5.8) | `two_key/capability.py`, `two_key/ledger.py`, `two_key/gateway.py` | `tests/test_ledger_root_token.py` |
| 8 | Gateway enforcement with frozen bytes: the call is serialized once, checked, and executed from the same bytes (Entry 10, F_REVIEW §8) | `two_key/gateway.py` (`ToolGateway`), `two_key/canonical.py` (`freeze_call`) | `tests/test_f_review.py` (HashThenExecute, InjectiveEncoding); e2e §5 |
| 9 | Content-scanning hooks, outbound (before execution) and inbound (results, files, email); five hook types; verdict bound into the token and ledger (Entries 5–7) | `two_key/scanning.py`, `two_key/gateway.py` | `tests/test_scanning_adapters.py`, `tests/test_scanning_gateway.py`; e2e §6 |
| 10 | Ledger: hash chain, signed head (size, head, Merkle root), RFC 9162 inclusion and consistency proofs (D §5.6; SPEC §5.9) | `two_key/ledger.py`, `two_key/merkle.py` | `tests/test_gateway_ledger.py` (LedgerIntegrity), `tests/test_merkle_consistency.py`, `tests/test_perf_paths.py` (MerkleAndCheckpoints); e2e §7 |
| 11 | Anchoring by deployment mode: personal = local file; enterprise = permissioned chain (Fabric or REST), fail closed, set once per ledger (Entry 9) | `two_key/anchoring.py`, `two_key/deployment.py` | `tests/test_deployment.py`, `tests/test_bugfixes.py` (AnchorReceiptSize); e2e §7 (local) and §8 (permissioned) |
| 12 | Fail-closed defaults: VM fault, missing quorum, signing failure, or ledger failure all deny (D §5.7; SPEC §5.10) | `two_key/core.py` | `tests/test_bugfixes.py` (TwoKeyGuards, Quorum), `tests/test_original.py` |
| 13 | Crypto provider: approved algorithms only, `fips_mode`, and a self-test before startup (SPEC §5.12) | `two_key/crypto/provider.py`, `two_key/crypto/selftest.py` | `tests/test_crypto.py`; `python -m two_key selftest` (18 checks with ML-DSA, 17 without) |
| 14 | Hybrid post-quantum signatures (ML-DSA-65 with Ed25519 or P-384) on constitutions, ledger heads, and signed tokens; both halves required, no downgrade (SPEC §5.12) | `two_key/crypto/signatures.py` | `tests/test_pq_hybrid.py`, `tests/test_pki.py` (HybridBinding); e2e §3 and §8 |
| 15 | Seed-phrase backup, personal mode, optional (Entry 11) | `two_key/seedphrase.py`, `two_key/data/bip39_english.txt`, `two_key/cli.py` (`keygen --seed-phrase`, `recover-key`, `verify-seed-phrase`) | `tests/test_seedphrase.py` (BIP-39 vectors, round trip, checksum, passphrase, labels, determinism, refusals, CLI); e2e §1; HOWTO §2 |
| 16 | Enterprise PKI: X.509 chain, validity, key usage, CRL/OCSP revocation, role mapping, ML-DSA binding extension, agent assertions, judge identities, enterprise startup check (Entry 11) | `two_key/pki.py`, `two_key/core.py` (`pki=`, `principal_credential=`, `judge_credentials=`, `authorize(agent_assertion=)`), `two_key/deployment.py` (`check_pki`) | `tests/test_pki.py` (Chain, Revocation, Roles, HybridBinding, Enterprise); e2e §8; HOWTO §12 |
| 17 | PKCS#11 signer: an HSM or smart-card key used without export (Entry 11) | `two_key/pki.py` (`Pkcs11Token`, `Pkcs11PrivateKey`, `PythonPkcs11Token`, `signing_keyset`), `two_key/crypto/signatures.py` | `tests/test_pki.py` (Pkcs11: fake token, missing library, real SoftHSM); e2e §8 (agent key on `SoftwareToken`) |
| 18 | Judge prompt hardening: delimiters escaped; judges get the action record, not the agent's free text (F_REVIEW) | `two_key/judges/llm.py`, `two_key/quorum.py` | `tests/test_f_review.py` (JudgePromptDelimiters), `tests/test_quorum_protocol.py` (JudgeInputsAndOrdering) |
| 19 | Model-swap invariance: judges are swapped in `judges.yaml` without re-signing (D §5.8; SPEC §5.11) | `two_key/judges/config.py` | `tests/test_judges.py` (Config); by construction, because bytecode and signature don't cover `judges.yaml` |
| 20 | Judge credentials: env or keyring API keys, static or callback tokens (README) | `two_key/judges/credentials.py` | `tests/test_judges.py` (Credentials) |
| 21 | Measured performance (SPEC §5.13) | `bench.py`, `docs/PERFORMANCE.md` | `tests/test_perf_paths.py` (no network in the gateway path); the measured numbers are from 2026-09-30 |

## 2. Stubs, placeholders, and what has not been tested against real systems

**Stubs or interfaces only (by design)**
- Public anchoring: `NullAnchor` and `LocalFileAnchor` only. Nothing is
  published to a public transparency log or blockchain.
- `UsernamePasswordProvider` and `OAuthDeviceCodeProvider` (judge
  credentials) are hook points. `get_token` raises `NotImplementedError`
  unless a callback is supplied, and no vendor endpoints are preconfigured.
- `_HfcGateway`, the real Hyperledger Fabric client, needs `fabric-sdk-py`
  and a network. It is marked untested.
- `pki.default_transport()` (CRL and OCSP fetch over HTTP, used when
  `network_revocation: true`) has not been tested against a real CA. The
  tests inject fetchers.
- Problem F (action-record normalization; Entry 4's proposed-hash vs.
  actual-hash comparison): reviewed in `F_REVIEW.md` but **not
  implemented**. No option has been chosen. The existing hooks (a
  caller-supplied record, a gateway extractor) are unchanged.
- PRIOR_ART.md §4 (iv)–(vi): not selected, not implemented.
- A TEE for key storage is not implemented.

**Implemented, but tested only with fakes or local stand-ins**
- Vendor LLM judges (OpenAI-compatible, Anthropic, Gemini, Ollama): tested
  with recorded or mocked HTTP only. No real vendor call was made.
- Content scanners (vendor REST, ICAP, clamd, sidecar, async webhook):
  tested against in-process fake servers and pattern rules, not real
  DLP/AV products.
- Permissioned chains (`FabricAnchor`, `RestPermissionedAnchor`): tested
  against in-memory fakes.
- PKCS#11: tested with SoftHSM 2.6.1 (P-384, Ed25519) and the in-memory
  `SoftwareToken`, not with a real HSM or smart card. The ML-DSA half of a
  hybrid identity stays in software.
- PKI: tested with a CA, intermediate, and leaves generated by
  `two_key/pki_testing.py`, not with a production CA. The ML-DSA binding
  extension uses a private OID under `2.25` (UUID arc) and is not
  registered with anyone.
- liboqs backend: tested only with a fake module. ML-DSA was tested with
  pyca `cryptography` 50.0.1 on OpenSSL 4.0.2, which is **not a validated
  FIPS module**. No FIPS provider was active on the development machine.
  Two-Key is FIPS-ready, not FIPS validated.

**Placeholders pending Stephan** (each is a setting, so changing it is a
one-line edit)
- `PkiConfig.revocation_unreachable = "fail_closed"`: if no revocation
  answer can be obtained, the certificate is refused.
- `PkiConfig.require_agent_identity = True` (enterprise): every
  `authorize` needs a signed agent assertion.
- `PkiConfig.require_judge_identities = False`.
- `PkiConfig.agent_assertion_max_age = 300` seconds. The nonce
  replay cache is in memory, per process.
- Enterprise startup refuses without PKI or a principal certificate
  (Entry 11), and without a permissioned anchor (Entry 9).
- `PermissionedLedgerAnchor` endorsement policy: `min_endorsing_orgs=1`,
  `required_orgs=()`.
- `DeploymentConfig.mode_defaults()` returns `{}`, so no other setting
  depends on the mode yet.
- Scanning defaults listed in `docs/SCANNING_HOOKS.md` ("Engineering
  defaults and interpretations").
- Quorum and ordering defaults (`short_circuit_path_b=True`; quorum
  sizes) in `DESIGN_OPTIONS.md` §§4, 7.

## 3. Open questions for Stephan

New with Entry 11 (seed phrase and PKI):
1. **Revocation unreachable.** Keep fail closed (deny when no CRL or OCSP
   answer is available), or allow a grace period or fail open for some
   roles?
2. **Agent identity.** In enterprise mode, should every request need an
   agent certificate (today's default)? Should agent identity also be bound
   into the capability token and re-checked at the gateway? Today it is
   checked once, at `authorize`.
3. **Judge identities.** Should enterprise judges be *required* to have
   certificates? Should their ballots be signed with the certified key?
   Today a judge's certificate is validated, but there is no proof of
   possession.
4. **Assertion freshness.** Is 300 seconds right? Should the replay cache
   be shared (for example, in the ledger) across gateway processes?
5. **Role mapping.** Exact names only today (`email:`, `uri:`, `dns:`,
   `subject:`). Should wildcards, OU/group-based rules, or certificate
   policy OIDs map to roles?
6. **ML-DSA binding.** A CA-issued certificate extension was chosen over a
   holder-signed binding record. Is that acceptable? Should the OID be
   registered under a Two-Key/Stephan arc? Should composite or pure
   ML-DSA certificates replace it once CAs issue them?
7. **PKI in personal mode.** It is optional today. Should it be refused,
   allowed, or encouraged?
8. **Seed phrase.** 24 English words only today. Should 12 words or other
   BIP-39 languages be allowed? Should there be a key hierarchy (several
   keys from one phrase) or Shamir/SLIP-39 split backups? Should it remain
   refused in `fips_mode` and enterprise mode?
9. **HSM requirement.** Should enterprise mode *require* the principal key
   on a PKCS#11 token?

Still open from earlier entries (details in the linked documents):
10. **Problem F**: which normalization option, if any (`DESIGN_OPTIONS.md`
    §1; `F_REVIEW.md` §9).
11. Quorum protocol and ordering open points from Stephan's §4 (iii)
    selection (`DESIGN_OPTIONS.md` §§4, 7).
12. Judge credentials and SSO (`DESIGN_OPTIONS.md` §5).
13. Deployment modes: endorsement policy, enterprise without an anchor,
    anchoring cadence, anchor failure, and per-mode defaults
    (`docs/DEPLOYMENT_MODES.md`, open questions).
14. Scanning (`docs/SCANNING_HOOKS.md`, open questions).
15. FIPS deployment target: which validated module, and whether to use
    P-384 suites where Ed25519 isn't approved (`docs/CRYPTO.md` §2).
