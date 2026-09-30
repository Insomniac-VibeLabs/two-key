# CHANGES

Changes from the package as received (`Compact_Kernel_Invention_Package.zip`,
files dated 2026-09-30 01:05–01:09 MDT) to this working copy. All work was
done 2026-09-30 by the AI engineering assistant at Stephan Busch's direction.

**"Decided by" key:**
- **Stephan**: Stephan Busch's own conception (`CONCEPTION_NOTES.md`) or his explicit instruction for this work (2026-09-30).
- **Disclosure spec**: behavior already specified in the original `docs/INVENTION_DISCLOSURE.md`.
- **Attorney recommendation**: guidance from the patent-attorney agent (keep the conception record separate; for open design questions, implement only a minimal configurable reference and list options for Stephan).
- **Engineering bug fix**: a defect correction or ordinary implementation detail, not asserted as inventive.

A change that was *instructed* by Stephan is not thereby *conceived* by him.
Conception is recorded only in `CONCEPTION_NOTES.md`.

| # | Change | Files | Decided by | Commit |
|---|---|---|---|---|
| 1 | Import baseline; drop `__pycache__/*.pyc`; add `.gitignore` (keys, ledgers, caches) | all | Stephan (instruction) / Engineering | 56d824b |
| 2 | Record Stephan's conception statement verbatim with date and attribution | `CONCEPTION_NOTES.md` | Stephan (content) / Attorney recommendation (separate record) | 341e7cf |
| 3 | Proper package (`compact_kernel/`, relative imports, `python -m compact_kernel`), tests moved to `tests/` | package, tests | Stephan (instruction) / Engineering | bc6b0b8 |
| 4 | Reject negative, NaN, infinite, and non-numeric amounts (fixes the negative-wire bypass) | `action.py` | Engineering bug fix | bc6b0b8 |
| 5 | data_class enum enforcement; trim and case-fold data_class, counterparty, tool (fixes the "Medical" and "OFFSHORE-MULE" bypasses) | `action.py`, `policy_vm.py` | Engineering bug fix (enum per Disclosure spec §5.2) | bc6b0b8 |
| 6 | Missing fields default to irreversible=True, data_class=classified | `action.py` | Disclosure spec §5.2, Claim 5 | bc6b0b8 |
| 7 | Strict compiler: unknown rule types/keys, typos, wrong types, and empty constitutions rejected | `policy_vm.py` | Engineering bug fix (fail closed per Disclosure spec §5.7) | bc6b0b8 |
| 8 | Allow-list rule required by default (`require_allow_list=True`; can be overridden) | `policy_vm.py` | Engineering default (reading of Disclosure spec §4 "fail-closed"); **open**, see DESIGN_OPTIONS §6 | bc6b0b8 |
| 9 | Per-rule `ASSERT` so the deny names the rule; rule `id` labels | `policy_vm.py` | Stephan (instruction) / Engineering | bc6b0b8 |
| 10 | VM faults become explicit denies; step limit configurable (default 4096) and checked at compile time | `policy_vm.py` | Engineering bug fix (Disclosure spec §5.7) | bc6b0b8 |
| 11 | Exact integer k-of-n quorum (2-of-3 works); `min_responding` (K); zero judges deny; raising or invalid judges abstain | `quorum.py` | Engineering bug fix (Disclosure spec §3 "two of three", §5.4 "K") | bc6b0b8 |
| 12 | Optional `min_distinct_providers` check, off by default | `quorum.py` | Attorney recommendation (configurable reference only); **open**, DESIGN_OPTIONS §2 | bc6b0b8 |
| 13 | `assert` replaced with real checks; invalid actions and VM faults logged as `decision` entries | `kernel.py` | Engineering bug fix | bc6b0b8 |
| 14 | Heuristic judge moved to `testing.py` as a test double; the kernel refuses test doubles unless explicitly allowed | `testing.py`, `kernel.py` | Stephan (instruction) | bc6b0b8 |
| 15 | Constitution upload: plain-English text file plus JSON/YAML hard rules | `constitution.py`, `cli.py`, `examples/` | Stephan (conception SB-1: "upload a human language constitution") | 6b215a5 |
| 16 | Ed25519 principal signing; verification before use; reject unsigned, modified, or foreign-signed constitutions | `constitution.py`, `keys.py`, `kernel.py` | Disclosure spec §5.1 item 2 / Stephan (instruction: Ed25519, `cryptography`) | 6b215a5 |
| 17 | Pluggable Path B judges: abstract interface plus OpenAI-compatible, Anthropic, Gemini, and Ollama adapters | `judges/` | Stephan (conception SB-1: "whichever AI (local or vendor)") | 21b6b51 |
| 18 | Auth: API key from env or keyring; callback token hook; username/password and OAuth device-code as documented stubs | `judges/credentials.py` | Stephan (conception SB-1: "api or username/password or single sign on login"; instruction: stubs, no faked login) | 21b6b51 |
| 19 | Judge prompt includes the constitution text; strict JSON ballot; malformed → abstain | `judges/llm.py` | Disclosure spec §5.4 / Stephan (instruction) | 21b6b51 |
| 20 | HTTPS required for judge endpoints except loopback; inline secrets rejected in config; secrets redacted in repr | `judges/llm.py`, `judges/config.py`, `judges/credentials.py` | Engineering | 21b6b51 |
| 21 | `judges.yaml` config for the judge list and quorum policy | `judges/config.py`, `examples/judges.yaml` | Stephan (instruction) | 21b6b51 |
| 22 | Tool gateway with all spec 5.5 checks | `gateway.py` | Disclosure spec §5.5 | 2103d37 |
| 23 | Gateway additions: data-class match, principal match, single-use jti (persisted via ledger), constitution-reload check | `gateway.py`, `capability.py` | Stephan (instruction) / Disclosure spec §5.5 (reload) | 2103d37 |
| 24 | Token bound to canonical hash of the literal tool-call args | `capability.py` | Stephan (instruction: "reference option"); **open**, DESIGN_OPTIONS §3 | 2103d37 |
| 25 | Counterparty check uses strict equality (stricter than spec's "matches if present") | `gateway.py` | Engineering default; **open**, DESIGN_OPTIONS §3 | 2103d37 |
| 26 | Call fields come from the caller or a per-tool extractor hook (no derivation design chosen) | `gateway.py` | Attorney recommendation (hook only); **open**, DESIGN_OPTIONS §1 | 2103d37 |
| 27 | Full token returned to the caller; only its SHA-256 logged | `kernel.py`, `capability.py` | Stephan (instruction) / Engineering bug fix | 2103d37 |
| 28 | Ledger logs the full canonical action record, args hash, token hash, deny reason/rule | `kernel.py`, `ledger.py` | Stephan (instruction) / Disclosure spec Claim 1(e) | 2103d37 |
| 29 | Ed25519-signed chain head (full rewrite, truncation, unsigned append detected) | `ledger.py` | Stephan (instruction) | 2103d37 |
| 30 | RFC 6962-style Merkle tree plus inclusion proofs | `merkle.py`, `ledger.py` | Stephan (instruction) / Disclosure spec §3 ("Merkle / hash chain") | 2103d37 |
| 31 | Anchoring interface with Null/LocalFile stubs; no public anchoring | `anchoring.py` | Stephan (instruction) / Disclosure spec §5.6 | 2103d37 |
| 32 | Ledger and head files created 0600; kernel refuses a tampered existing ledger | `ledger.py`, `kernel.py` | Engineering | 2103d37 |
| 33 | Ledger append failure or any internal error → deny, no token | `kernel.py` | Disclosure spec §5.7 | 2103d37 |
| 34 | Path B short-circuited after a Path A deny (default on), option to run both | `kernel.py` | Stephan (instruction: default on for privacy); **open**, DESIGN_OPTIONS §4 | 0e6b683 |
| 35 | Demo rewritten: signed constitution, gateway redemption, replay, regressions, rewrite detection; principal id changed to `did:ck:demo-principal` | `demo.py` | Engineering | c2b6fe6 |
| 36 | Demo rules: wire ban is now `deny_if {tool: wire_transfer}` (was `amount_usd_gt: 0`); added `spend-cap` matching the demo constitution's "$200" sentence | `demo.py`, `examples/hard_rules.*` | Engineering bug fix (demo config matched to its own English constitution) | bc6b0b8, c2b6fe6 |
| 37 | CLI: keygen, sign/verify constitution, verify-ledger, check-judges, demo; `pyproject.toml` with no license field | `cli.py`, `pyproject.toml` | Stephan (instruction) / Engineering | 6b215a5, c2b6fe6 |
| 38 | Test suite: 115 tests covering all review defects and new features; no network | `tests/` | Stephan (instruction) | multiple |
| 39 | Figures (Mermaid plus SVG/PNG) | `docs/figures/` | Stephan (instruction) | a379291 |
| 40 | Design options memo (no decisions) | `DESIGN_OPTIONS.md` | Attorney recommendation | 98fd90e |
| 41 | Specification draft with source tags; advocacy removed; original disclosure unchanged | `docs/SPEC_DRAFT.md` | Stephan (instruction) | 9160844 |
| 42 | README rewritten for the new layout | `README.md` | Engineering | 39305e3 |
| 43 | Pluggable `CryptoProvider`: approved-algorithm list, `fips_mode` refusal, `require_fips_module` check, RNG only via `os.urandom`/`secrets` | `crypto/provider.py`, `canonical.py` | Stephan (instruction: FIPS 140-3 requirements) | ccf92cf |
| 44 | Start-up self-test (SHA-2/SHA-3/HMAC/Ed25519 KATs, ECDSA and ML-DSA pairwise tests); kernel refuses to start on failure | `crypto/selftest.py`, `kernel.py` | Stephan (instruction) | ccf92cf, ea42dc6 |
| 45 | Signature suites: ECDSA P-384; hybrid ML-DSA-65 + Ed25519 / P-384, both halves must verify; verifier requires the trusted key's suite (no downgrade) | `crypto/signatures.py` | Stephan (instruction) | ccf92cf, 5ae5dda |
| 46 | Suite name bound into each component's signing input (domain separation); canonical JSON encoding of hybrid keys/signatures | `crypto/signatures.py` | Engineering | ccf92cf |
| 47 | Selectable ML-DSA backend (auto / pyca / liboqs / none); `PQUnavailableError` when hybrid is required and no backend exists; no silent downgrade | `crypto/`, `kernel.py` | Stephan (instruction) | ccf92cf, ea42dc6 |
| 48 | liboqs backend refused in `fips_mode` (not a validated module); key sets built under another provider are re-checked under the caller's provider | `crypto/` | Engineering | ccf92cf, 5ae5dda |
| 49 | Ledger: SHA-384 digests for PQ profiles (algorithm bound into each digest), hybrid-signed chain head, `auto_sign_every` batching, configurable fsync | `ledger.py` | Stephan (instruction: SHA-384+, PQ chain head, batching) | f749c4b |
| 50 | Incremental Merkle root (`MerkleFrontier`, O(log n)), replacing a full rebuild on every signed head | `merkle.py`, `ledger.py` | Engineering (performance) | f749c4b |
| 51 | Constitution signing/verification for all suites; SHA-384 constitution digest for non-legacy suites; encrypted JSON key bundles (PBKDF2-HMAC-SHA-256 + AES-256-GCM); CLI `keygen --suite`, `selftest`, `--fips`, `--pq-backend` | `constitution.py`, `keys.py`, `cli.py` | Stephan (instruction) / Engineering (bundle format) | fc979ca |
| 52 | Token modes: `ck1` (HMAC-SHA-256), `ck1-hs384` (HMAC-SHA-384, default for non-legacy suites), optional `ck1-sig` (hybrid-signed); HMAC keys ≥ 256 bits; MAC key schedule cached | `capability.py` | Stephan (instruction: optional PQ tokens, ≥256-bit HMAC keys) | e7be218 |
| 53 | Gateway checkpoints the signed head per call (`checkpoint_every`, 0 = caller-managed) | `gateway.py`, `kernel.py` | Stephan (instruction: batched/configurable head updates) | e7be218, ee862b1 |
| 54 | Path B judges in parallel with an overall `timeout_seconds` (default 45 s); late judges abstain; daemon threads | `quorum.py`, `judges/config.py`, `examples/judges.yaml` | Stephan (instruction: parallel with timeouts) | 615f89e, 2752c5b |
| 55 | Kernel: `crypto=` provider, `require_pq`, PQ-profile defaults (SHA-384, `ck1-hs384`), one signed head per decision (`head_signing`), checkpoint failure → deny | `kernel.py` | Stephan (instruction) / Engineering (fail closed on checkpoint) | ea42dc6 |
| 56 | 58 new tests (173 total): fips_mode rejection, self-test incl. forced failure, hybrid tamper/strip/reorder/downgrade, missing-PQ behaviour, fake-liboqs adapter, parallel judges/timeout, no-network hot path, checkpoints | `tests/` | Stephan (instruction) | 22cfc2e, ee862b1 |
| 57 | `bench.py` and `docs/PERFORMANCE.md` (measured latency and memory, classic vs hybrid) | `bench.py`, `docs/PERFORMANCE.md` | Stephan (instruction) | bae09cd |
| 58 | `docs/CRYPTO.md` (not FIPS validated; candidate modules; algorithm/standard map; PQ notes) | `docs/CRYPTO.md` | Stephan (instruction) | a286ac4 |
| 59 | README, CHANGES, DESIGN_OPTIONS (token-scheme row), `pyproject.toml` (`compact_kernel.crypto` package, `pq`/`liboqs` extras) | docs, `pyproject.toml` | Engineering | (this commit) |

**Not changed:** `docs/INVENTION_DISCLOSURE.md` (byte-identical to the
received file). No LICENSE file has been added or changed; licensing is
Stephan's decision.
