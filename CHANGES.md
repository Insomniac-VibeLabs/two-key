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
| 42 | README rewritten for the new layout | `README.md` | Engineering | (this commit) |

**Not changed:** `docs/INVENTION_DISCLOSURE.md` (byte-identical to the
received file). No LICENSE file has been added or changed; licensing is
Stephan's decision.
