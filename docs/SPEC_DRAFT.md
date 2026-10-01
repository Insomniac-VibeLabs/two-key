# SPECIFICATION DRAFT (working document, not filed)

**Title:** Method and System for Dual-Path Constitutional Enforcement of Personal Artificial Intelligence Agents Using a Deterministic Policy Virtual Machine and a Multi-Model Intent Quorum

**Short name:** Two-Key ("two-key")

**Draft prepared:** 2026-09-30. Derived from `docs/INVENTION_DISCLOSURE.md` (disclosure date 30 September 2026, kept unchanged for the record) and updated to match the prototype in this repository. **Updated 2026-09-30, about 7:40 AM MT:** added the cryptographic profile (`docs/CRYPTO.md`), the measured performance (`docs/PERFORMANCE.md`), and the three `PRIOR_ART.md` §4 directions that Stephan selected at about 7:02 AM MT (§§5.6–5.13, Figures 5–7).

**Status:** Working draft for review by a registered patent attorney. Not a filed application. Not legal advice.

### Source tags used in this draft

| Tag | Meaning |
|---|---|
| **[D §n]** | Carried over from the original invention disclosure, section n |
| **[SB-1]** | Stephan Busch's conception statement, `CONCEPTION_NOTES.md` entry 1 (2026-09-30, ~4:03 AM MT) |
| **[SB-2 (i)/(ii)/(iii)]** | Stephan Busch's **selection**, `CONCEPTION_NOTES.md` entry 2 (2026-09-30, ~7:02 AM MT, relayed through his patent-attorney assistant): "A, B, C, and F all together", choosing directions (i), (ii), (iii) of `PRIOR_ART.md` §4 and flagging the normalization problem (F). The wording of each direction comes from `PRIOR_ART.md` §4, an AI-prepared prior-art memo by the patent-attorney agent that is kept outside this repository. Selecting among proposed directions is recorded as a selection, not as conception; counsel should assess |
| **[IMPL]** | How the prototype implements something. It is an engineering detail, not asserted as inventive. Where several designs are possible, see `DESIGN_OPTIONS.md` |

**Inventorship:** to be determined with counsel. Some mechanisms in §§5.5, 5.7 and 5.8 were proposed by an AI agent (`PRIOR_ART.md` §4) and selected by Stephan; each is tagged accordingly. The conception record is in `CONCEPTION_NOTES.md`; engineering changes and who decided them are in `CHANGES.md`. The original disclosure text and the prototype code were largely drafted with an AI assistant. AI is not an inventor.

---

## 1. Field [D header]

Computer security; autonomous software agents; applied cryptography; human-computer interaction.

## 2. Problem [D §2, condensed]

Software agents now propose, and in some systems execute, actions that spend money, disclose records, send mail, and operate browsers. The model that proposes an action is trained, hosted, updated, and aligned by a vendor whose incentives may differ from the principal's. Prompt injection, tool-description attacks, and silent model updates can cause an agent to take actions the principal forbade, even when every cryptographic signature involved is valid.

Binding an agent to a person (a hardware key, a biometric template) answers "who owns this agent?" It doesn't answer "may this agent take *this* action *now*?" A single LLM acting as a judge is still one linguistic surface that a crafted string can talk into approving an action.

## 3. Summary

A runtime sits between any language model and any tool gateway. A proposed action reaches the real world only if **two independent paths both agree** [D §3; SB-1: "Both path A and B need to agree to let the action occur."]. Then a short-lived capability token is issued, and the whole decision is written to a principal-controlled ledger.

- **Constitution upload.** The principal supplies a constitution written in ordinary human language [SB-1: "have a user able to upload a human language constitution"]. Alongside it goes a restricted-schema set of hard rules for Path A [D §5.3]. The principal signs the bundle; changing it requires a fresh signature, and model vendors cannot push a new constitution [D §5.1 item 2].
- **Path A: deterministic policy VM.** The hard rules are compiled ahead of time into bytecode for a small stack machine. At decision time it reads only fields of a normalized action record. It does not read English [D §3].
- **Path B: multi-model intent quorum.** N judges each receive the principal's natural-language constitution and the proposal, and each votes on whether the proposal is consistent with the constitution. A threshold must be met [D §3]. The judges are connected to whichever AI the principal chooses, local or vendor. The connection may use an API key, a username/password, or single sign-on [SB-1: "the AI judge/judges be connected to whichever AI (local or vendor) the user desires (api or username/password or single sign on login)"].
- **Capability issuance.** Only after both paths pass is a token issued. It is bound to the principal, the tool, the numeric and party scope, a short expiry, and the current ledger root [D §3]. A tool gateway refuses any invocation without a valid, unexpired, correctly scoped token [D §3, §5.5].
- **Personal ledger.** Every proposal, VM result, ballot, and issued capability is appended to a hash chain under the principal's control [D §3, §5.6].
- **Ledger-root-bound token** [SB-2 (i)]. The token carries the root R of the principal's append-only Merkle ledger at issuance, H(bytecode), and H(NL constitution). Before executing, the gateway verifies that R equals its last-known root or is an ancestor of it, via a Merkle consistency proof. It checks that the hashes match the ledger's latest constitution-load entry, rejects tokens issued before a later reload or revocation, and appends the result linked to the token's entry (§5.8).
- **One signed constitution, two compilations** [SB-2 (ii)]. The principal signs one document. A deterministic compiler splits it into stack bytecode for Path A, which does no string operations on natural-language fields, and the prose judge prompt for Path B. Both hashes are recorded at load and bound into ballots and tokens. A vendor-signed update cannot replace either (§5.5).
- **Quorum protocol specifics** [SB-2 (iii)]. Judge-set selection enforces vendor heterogeneity (at least two vendors, including at least one local weight file). An availability floor K, distinct from the approval threshold T, denies without counting. Ballots are schema-constrained Booleans bound to H(action record) and H(constitution); a malformed ballot is an abstain, which counts as deny. Judge inputs are restricted to the normalized record and the constitution. Path B runs only after Path A returns true (§5.7, §5.10a).

Technical improvements stated in the disclosure [D §3]:
- less unauthorized tool invocation under prompt injection, because Path A has no natural-language parser;
- less single-vendor goal hijack, because of the cross-model quorum;
- the constitution carries over across model swaps;
- Path A decides in microseconds (the prototype measured ~7–12 µs per evaluation on a shared cloud VM, 2026-09-30; §5.13);
- a third party can re-run Path A against logged actions and the published bytecode and check the result.

## 4. Known prior-art families [D §4]

These are not claimed as the invention:
- binding an AI agent to a person with a TEE-sealed key and biometric template (the disclosure refers to "issued U.S. patents in 2025–2026"; **specific references still need to be identified**);
- policy engines and allow-lists in API gateways (e.g. OPA, Cedar, IAM);
- multi-party computation and threshold signatures;
- verifiable credentials and decentralized identifiers;
- LLM-as-judge and constitutional-AI training.

The disclosure's stated gap is the *combination* of (i) a compiled, non-linguistic enforcement path that can fail closed, (ii) a multi-model intent quorum on the linguistic path, and (iii) a scope-bound capability chained to a principal-owned ledger root [D §4].

## 5. Detailed description

### 5.1 Architecture (Figure 1: `docs/figures/architecture.svg`)

Components [D §5.1]: principal device, constitution store, proposal interface, policy VM, quorum convenor, capability issuer, tool gateway, personal ledger.

[IMPL] Python package `two_key`: `constitution.py`, `compiler.py` (§5.5), `action.py`, `policy_vm.py`, `quorum.py`, `judges/`, `capability.py`, `gateway.py`, `ledger.py`, `merkle.py`, `anchoring.py`, `crypto/` (§5.12), `core.py` (class `TwoKey`), `cli.py`.

### 5.2 Constitution upload and signing [SB-1; D §5.1 item 2]

The principal provides (a) a plain-English constitution file (`.txt`/`.md`) and (b) a hard-rules file (`.json`/`.yaml`).

[IMPL] The two are bundled into a canonical document {format, principal, created_at, constitution_text, its SHA-256, hard_rules} and signed with the principal's key: Ed25519 (legacy default), ECDSA P-384, or a hybrid ML-DSA-65 suite in which both component signatures must verify (§5.12). Before use, Two-Key verifies the signature against a public key the principal trusts. It rejects unsigned envelopes, modified text or rules, envelopes signed by a different key, envelopes whose embedded key was swapped, and suite downgrades. CLI: `keygen [--suite]`, `sign-constitution`, `verify-constitution`.

[SB-2 (ii); IMPL for the format] The principal may instead sign **one** Markdown source (format `two-key-constitution/2`, `sign-constitution --document`). The rules sit in a single fenced ```` ```twokey-rules ```` block of JSON inside the prose; §5.5 describes the split.

### 5.3 Action record and normalization [D §5.2]

Fields: tool, amount_usd, currency, counterparty, data_class ∈ {public, personal, medical, financial, classified}, destination, duration_hours, irreversible, tags, raw. Missing high-impact fields default to conservative values (irreversible = true, data_class = classified) or cause rejection [D §5.2, Claim 5].

[IMPL] Validation rejects negative, non-finite, and non-numeric amounts, unknown fields, and non-boolean `irreversible`. Strings are trimmed and case-folded, and data_class must be one of the enum values. Invalid records become an explicit, logged deny.

*Open question (DESIGN_OPTIONS.md §1):* which component produces the action record (the proposing model, the gateway working from the literal tool-call arguments, a classifier, or a hybrid). The prototype accepts a caller-supplied record and offers a gateway extractor hook. It does not select a design. On 2026-09-30 Stephan flagged this as problem "F" together with his §4 selection [SB-2]. **No option has been chosen or implemented;** the hooks are unchanged.

### 5.4 Path A: constitution compilation and VM [D §5.3]

The hard rules use a restricted schema: `allow_only_tools`, `deny_counterparties`, `deny_if {tool, amount_usd_gt, data_class_in, irreversible}`, and `deny_if_irreversible_over`. They compile to stack operations, and the VM evaluates them against the action. Compilation happens when the principal saves the constitution, so an attacker who can only talk to the model can't alter the bytecode [D §5.3, Claim 2].

[IMPL]
- Each rule compiles to a block ending in `ASSERT <rule id>`, so the deny reason names the rule.
- The compiler rejects unknown rule types, unknown keys, wrong types, and empty rule sets. By default it also requires an allow-list.
- VM faults (type errors, stack underflow, unknown opcodes, exceeding the step limit) are denies.
- The step limit is configurable (default 4096) and checked at compile time.

### 5.5 One signed constitution, two compilations (Figure 6: `docs/figures/two_compilations.svg`) [SB-2 (ii)]

The principal signs one constitution document. A compiler splits it deterministically: structured rules become stack bytecode with no string operations on natural-language fields, and the prose becomes the judge prompt. Both hashes are recorded in the ledger at load and bound into each ballot and token. A vendor-signed update cannot replace either without the principal's signature [SB-2 (ii), wording from PRIOR_ART.md §4 (ii) and §3 item 2; the principal-signature requirement is also D §5.1 item 2].

[IMPL]
- `compiler.compile_both` takes the verified document and produces the Path A bytecode (`policy_vm.compile_constitution`) and the Path B judge text. `bytecode_hash` = H(canonical JSON of `[[opcode name, operands...], ...]`) and `nl_hash` = H(judge text), using SHA-256 in the legacy profile and SHA-384 in the post-quantum profile.
- The split for format `/2` (`compiler.split_source`): exactly one ```` ```twokey-rules ```` block, parsed as JSON. The prose is the source minus that block, with CRLF turned into LF and leading and trailing whitespace stripped. Other code blocks stay in the prose. Zero or two rule blocks, an unterminated fence, invalid JSON, or empty prose are rejected. Formats `/1` and `/2` with the same prose and rules give identical hashes.
- `verify_structured_only` is a static check at load. Path A may LOAD only structured action fields (every field except `raw`), use only the opcodes the compiler emits (not CONTAINS), and push only scalar or list constants; the program must end in PASS. Any violation refuses the load.
- The `constitution_loaded` ledger entry records `constitution_digest`, `bytecode_hash`, `nl_hash`, `source_format`, and the compiler id `two-key-compiler/1`.
- `tk.reload_constitution` accepts only documents signed by the principal's trusted key and naming the same principal. A refused reload, for example one signed by a vendor key or with the principal's public key substituted, is logged as `constitution_reload_refused`, and the active constitution is unchanged.
- The judges receive only the prose, never the rule block.

*Open points: DESIGN_OPTIONS.md §7.8–7.13.*

### 5.6 Path B: judges connected to the principal's chosen AI, and the quorum protocol [SB-1; D §5.4]

Each judge receives the constitution text and the proposal and returns a structured ballot {consistent, confidence, rationale}. The convenor counts booleans; it doesn't average prose. Judges must be independently reachable, and the convenor refuses to decide if fewer than K judges respond [D §5.4].

[IMPL]
- Abstract `Judge` interface with adapters:
  - OpenAI-compatible Chat Completions, covering OpenAI, xAI, and local servers such as llama.cpp, vLLM, and Ollama `/v1`;
  - Anthropic Messages;
  - Google Gemini `generateContent`;
  - native Ollama.
- The prompt always includes the full constitution text and labels the action and proposal as untrusted data.
- Responses must be exactly the ballot JSON. Anything else, and any transport or credential error, counts as an abstention, never a yes.
- Credentials:
  - API key from an environment variable or the OS keyring (working);
  - a generic callback hook for SSO tokens (working);
  - username/password and OAuth device-code (RFC 8628) providers, which are interfaces with documented stubs.
- The judges and the quorum are listed in `judges.yaml`, with exact integer k-of-n (`required_yes`), `min_responding` (K), and an optional `min_distinct_providers`.
- Judges run in parallel under an overall deadline (`timeout_seconds`, default 45 s). A judge that has not answered by then is an abstention.

*Open question (DESIGN_OPTIONS.md §2):* how judge independence should be ensured. §5.7 adds the §4 (iii) mechanisms.

### 5.7 Quorum protocol specifics (Figure 7: `docs/figures/quorum_protocol.svg`) [SB-2 (iii)]

Judge-set selection enforces vendor heterogeneity, with at least two vendors including at least one local weight file [SB-2 (iii); cf. D Claim 4, "at least two distinct model vendors or local weight files"]. An availability floor K, distinct from the approval threshold T, means fewer than K valid ballots is a deny without counting [SB-2 (iii); K itself is D §5.4]. Ballots are schema-constrained Booleans bound to H(action record) and H(constitution), and a malformed ballot is an abstention, which counts as deny [SB-2 (iii)]. Judge inputs are restricted to the normalized record and the constitution, never the agent transcript or tool outputs [SB-2 (iii)]. Path B is invoked only after Path A returns true [SB-2 (iii); previously a configurable default, §5.10a].

[IMPL]
- Each judge has `vendor` (defaulting to its provider label) and `local_weights` (true by default for Ollama judges; configurable), plus an optional recorded `weights_sha256`. `QuorumPolicy.min_vendors` and `min_local_judges` are checked when Two-Key starts, and it refuses to start below the floor. The convenor checks again (`judge_set_not_heterogeneous`). With `heterogeneity_scope="responding"`, the floor must also hold among the judges that returned valid ballots. `QuorumPolicy.section4()` applies §4's figures (2 vendors, 1 local). The general default is still permissive (open point).
- Floor K: below `min_responding` valid ballots, the result is `counted=false` with no yes/no tally (`insufficient_responses:x<K`). Otherwise yes votes are compared with T (`required_yes`).
- Binding: for each round Two-Key computes {H(normalized action record), constitution digest, nl_hash, bytecode_hash}. Every ballot is bound to it: stamped by the convenor (`ballot_binding="stamp"`, the default), or echoed by the judge (`"echo"`: LLM judges with `echo_binding` get the hashes in the prompt and must return them as two extra JSON keys). A ballot reporting a different binding abstains (`binding_mismatch`). In echo mode an unechoed yes/no abstains (`unbound_ballot`). The binding is written once per `quorum_result` entry.
- Judge inputs: `judge_inputs="record_only"` (default) sends the constitution prose and the normalized action record; the proposal text is not sent (it is still logged). `"record_and_proposal"` is available.
- `require_path_a_first=True` makes Two-Key refuse `short_circuit_path_b=False`.

*Open points: DESIGN_OPTIONS.md §7.14–7.21.*

### 5.8 Capability token and tool gateway (Figure 3: `docs/figures/token_gateway_sequence.svg`; Figure 5: `docs/figures/ledger_root_token.svg`) [D §5.5; SB-2 (i)]

Payload [D §5.5]: principal, tool, scope, issued_at, expires_at, ledger_root. Default TTL is 30 seconds. The gateway checks the signature, expiry, tool match, that the amount is within scope, that the counterparty matches, and that the ledger root equals the last-known root or is an ancestor of it. The disclosure states that replay across tools, replay after expiry, and replay after a new constitution load (if the gateway tracks roots) all fail [D §5.5].

[IMPL]
- The token also carries a single-use `jti`, `args_hash`, and the constitution digest.
- Its tag is HMAC-SHA-256 (`tk1`) or HMAC-SHA-384 (`tk1-hs384`, the default for non-legacy key suites). A signed mode (`tk1-sig`, e.g. hybrid ML-DSA-65 + Ed25519) is optional. Production would use a hardware-backed key [D §5.1 item 6].
- The gateway additionally checks the principal, data class, `args_hash` (the canonical hash of the literal tool-call arguments), that no constitution has been loaded since the token's root, and single use. The used-jti record is kept by the ledger itself, so every gateway on one TwoKey instance and its ledger shares it and a token is accepted exactly once however many gateways or threads present it (checks and redemption run under the ledger's lock; on POSIX the redemption also holds an `flock` on the ledger file and refuses, fail closed, if another writer has changed the file: `replayed` / `ledger_concurrent_writer`). The record is rebuilt from the ledger's `capability_redeemed` entries on restart [IMPL; engineering fix on Stephan's instruction, 2026-09-30].
- The full token goes back to the caller; only its SHA-256 is logged.

*Open question (DESIGN_OPTIONS.md §3):* the token binding details. `args_hash` is the reference option specified in Stephan's 2026-09-30 instructions, and alternatives are listed in the memo.

**Ledger-root-bound token** [SB-2 (i)]. The token carries (a) the root R of the principal's append-only Merkle ledger at issuance, (b) H(bytecode), and (c) H(NL constitution). Before executing, the gateway (1) verifies that R equals its last-known root or is an ancestor of it, via a Merkle consistency proof; (2) verifies that H(bytecode) and H(constitution) match the ledger's latest constitution-load entry; (3) rejects any token issued before a later constitution-reload or revocation entry; and (4) appends the execution result, linking it to the token's entry [SB-2 (i), wording from PRIOR_ART.md §4 (i); the ancestor idea itself is D §5.5].

[IMPL]
- New payload fields: `ledger_size` and `ledger_merkle_root` (R: the ledger's size and RFC 9162 Merkle root just before the token's own `capability_issued` entry), `bytecode_hash`, and `nl_hash`. The chain-tip `ledger_root` and `constitution_digest` stay.
- The gateway keeps a last-known view (V, R_V). Each call first checks that the ledger still has root R_V at size V; otherwise it denies `ledger_fork_detected`, which catches rewrites and truncations. If R is older than the view, an RFC 9162 consistency proof PROOF(size, V) must show R is an ancestor of R_V. If R is newer, PROOF(V, size) must show R_V is an ancestor of R, and the view then advances to R, which the token authenticates. Either way it is one proof per call. The chain digest at size−1 must equal the token's `ledger_root`. Deny reasons: `ledger_root_not_ancestor`, `token_missing_ledger_binding`. `view_refresh="every_call"` also advances the view to the current ledger each call.
- The hashes are compared with the latest `constitution_loaded` entry (`constitution_hash_mismatch`). Any `constitution_loaded` entry after issuance gives `constitution_changed_since_issue`. `tk.revoke(jti)` and `tk.revoke()` (all tokens so far) append `revocation` entries (`revoked`).
- The token's own `capability_issued` entry must exist at seq = `ledger_size` with the same token hash (`capability_not_recorded`).
- `capability_redeemed`, `tool_executed`, and `tool_error` carry `capability_entry_seq` and `capability_entry_digest`. `tool_executed` also carries `result_hash` (the result itself is not stored).
- Proofs cost O(log n) to O(log² n) hash operations. The ledger keeps every perfect-subtree root (`merkle.MerkleTree`) and indexes the latest constitution load, revocations, and each jti's entry.

*Open points: DESIGN_OPTIONS.md §7.1–7.7.*

### 5.9 Personal ledger (Figure 4: `docs/figures/ledger_structure.svg`) [D §5.6]

Hash chain: `digest_i = H(canonical(seq, ts, kind, body, prev))`. Verification walks the chain, and production anchoring writes the root to a public log on a schedule [D §5.6].

[IMPL]
- The ledger logs the full canonical action record, the args hash, the ballots, the token hash, and the deny reason or rule.
- The principal's key signs the chain head {size, head digest, RFC 6962/9162 Merkle root}, by default once per decision (`head_signing="decision"`; `"append"` signs every append). A full rewrite, truncation, or an unsigned append is then detected. Digests are SHA-256 (legacy) or SHA-384 (post-quantum profile, with the algorithm bound into each digest). The head signature uses the principal's suite, including hybrid ML-DSA-65.
- Merkle inclusion proofs and RFC 9162 consistency proofs between any two sizes are available (`inclusion_proof`, `consistency_proof`, `verify_consistency_proof`).
- Anchoring is an interface with local stubs only; nothing is published.
- Files are created with mode 0600. The ledger is not encrypted.

### 5.10 Fail-closed defaults [D §5.7]

If the VM faults, deny. If the quorum isn't met, deny. If the issuer can't sign, deny. If the ledger can't append, deny. There is no best-effort allow [D §5.7].

[IMPL] All four are implemented and tested. Unexpected exceptions inside `authorize` produce a deny with no token. A decision whose signed-head checkpoint fails is also a deny. The crypto self-test must pass before Two-Key starts.

### 5.10a Ordering of the paths

[IMPL] By default Path B is not convened when Path A denies (`short_circuit_path_b=True`), so forbidden proposals aren't sent to external judges. It can be configured to run both. Both must pass for an allow either way. Stephan's §4 (iii) selection includes "Path B invoked only after Path A returns true" [SB-2 (iii)]; `require_path_a_first=True` enforces it (§5.7). *Open question: DESIGN_OPTIONS.md §4, §7.21.*

### 5.11 Model-swap invariance [D §5.8]

Replacing the proposing model doesn't require a new constitution. Replacing a judge only requires that the new judge speak the ballot schema. Path A is unaffected by any model change [D §5.8]. [IMPL] Judges are swapped by editing `judges.yaml`; the signed constitution and bytecode don't change. (PRIOR_ART.md §4 (vi), a narrower model-swap direction, was not selected and is not implemented.)

### 5.12 Cryptographic profile, FIPS 140-3 posture, and quantum resistance (from `docs/CRYPTO.md`) [IMPL]

Added at Stephan's 2026-09-30 instruction (CHANGES.md rows 43–59). It is engineering detail, not asserted as inventive.
- **Not FIPS certified or validated.** FIPS 140-3 validates cryptographic modules, not applications. The prototype uses only FIPS-approved algorithms, routed through one `CryptoProvider`, so it can be deployed on a validated module. `fips_mode=True` refuses non-approved algorithms (and the liboqs backend). `require_fips_module=True` refuses to start unless both OpenSSL instances report FIPS mode. No FIPS provider was active on the development machine. Candidate modules and their certificate status are listed in `docs/CRYPTO.md` §2 (for example, the OpenSSL 3.1.2 FIPS provider, #4985, has no ML-DSA, and Ed25519 is not approved there, so ECDSA P-384 suites are needed on it).
- **Algorithms.**
  - Signatures: Ed25519, ECDSA P-384, and ML-DSA-65 (FIPS 186-5, FIPS 204). Hybrid suites `hybrid-mldsa65-ed25519` and `hybrid-mldsa65-p384`: both components must verify, the suite name is bound into each component, and downgrades and silent fallback are refused.
  - Digests: SHA-256 (legacy profile) or SHA-384 (non-legacy profile) for the ledger chain, the Merkle tree and its proofs, the constitution digest, `args_hash`, `bytecode_hash`, `nl_hash`, the ballot binding, and `result_hash`.
  - Tokens: HMAC-SHA-256/384 with keys of at least 256 bits, considered quantum-resistant. Optional `tk1-sig` signed tokens.
  - Key bundles: PBKDF2-HMAC-SHA-256 with 600,000 iterations, then AES-256-GCM.
  - RNG: the OS CSPRNG.
- **Self-test** before Two-Key starts: known-answer tests for SHA-2/3 (FIPS 180-4, FIPS 202), HMAC (RFC 4231), and Ed25519 (RFC 8032); pairwise consistency tests for ECDSA and ML-DSA; and an RNG length check. Any failure stops Two-Key.
- **PQ backend:** pyca `cryptography` 50.0.1 with OpenSSL 4.0.2 was used, and is not a validated module. The liboqs adapter was tested only with a fake module.

### 5.13 Measured performance (from `docs/PERFORMANCE.md`) [IMPL]

One run on a shared 8-vCPU cloud VM, 2026-09-30 about 07:33 MDT, with local test-double judges and no network. Medians:

| Operation | Ed25519 | Hybrid ML-DSA-65 + Ed25519 |
|---|---:|---:|
| Path A evaluation (6 rules, allow / deny) | 12.1 / 7.2 µs | same |
| HMAC token issue / verify | 10.8 / 8.7 µs | 11.6 / 9.7 µs (HMAC-SHA-384) |
| §4 (i) gateway binding checks (incl. token verify and one consistency proof) | 34 µs | ≈ same |
| Gateway `invoke`, full (checks, redeem, tool, signed head), fsync off | 322 µs | 1.04 ms |
| Full `authorize` (A + B with 3 local judges + token + ledger), fsync off | 1.12 ms | 2.14 ms |
| Merkle consistency proof + verify, 10,000 entries | 10.5–22.5 µs | ≈ same |
| Peak RSS after 1,000 authorize+invoke cycles | 45.8 MiB | 46.7 MiB |

Compared with the code before the §4 phase, measured in the same session, the §4 (i)–(iii) checks added about 23–25 µs (9–18%) to gateway `invoke`, 53 µs on an 18,000-entry ledger, and 66–117 µs (6–12%) to `authorize`. Details and causes are in `docs/PERFORMANCE.md`. Real judge latency, which is network- and model-bound and not measured, dominates end to end. Judges run in parallel under an overall deadline.

## 6. Reduction to practice (as of 2026-09-30)

[IMPL] The Python 3 prototype is in `two_key/`. The test suite (`python -m unittest discover -s tests`, 249 tests) covers:
- the defects found in the 2026-09-30 review: the negative-amount wire, permissive missing-field defaults, silently ignored typo rules, case variants such as "Medical", 2-of-3 quorums, and zero judges;
- every gateway check, including replay across tools, expiry, scope, and ledger-root ancestry;
- single use across several gateways on one TwoKey instance, concurrent threads, forked processes, a second ledger instance, and restart (`tests/test_shared_redemption.py`);
- detection of full ledger rewrites;
- constitution and token signature tampering;
- malformed judge output;
- FIPS-mode rejection, the crypto self-test, and hybrid-signature tampering and downgrade;
- [SB-2 (i)] RFC 9162 consistency proofs against a reference implementation for every pair of sizes up to 65, with tampered, truncated, and extended proofs. Gateway ancestry, fork and truncation detection, hash mismatch, reload, revocation, a token without its ledger entry, and result linking (`tests/test_merkle_consistency.py`, `tests/test_ledger_root_token.py`);
- [SB-2 (ii)] the deterministic split, the static structured-only check, identical hashes for `/1` and `/2`, hashes in the load entry, ballots, and tokens, judges receiving the prose only, and vendor-signed or forged reloads being refused (`tests/test_two_compilations.py`);
- [SB-2 (iii)] heterogeneity at selection and among responders, the K floor denying without counting, K distinct from T, stamped and echoed ballot binding including LLM echo, record-only judge inputs, and Path A first (`tests/test_quorum_protocol.py`).

`python -m two_key demo` runs the original three scenarios plus the review's regressions, entirely offline with test-double judges. No real vendor API has been called; the connectors are tested against mocked transports.

| Element | Status |
|---|---|
| Constitution upload and signing (Ed25519, ECDSA P-384, hybrid ML-DSA-65) | Implemented |
| Path A compiler and VM | Implemented |
| One signed constitution, two compilations, hashes recorded and bound [SB-2 (ii)] | Implemented |
| Path B quorum protocol | Implemented |
| Heterogeneity floor, K floor without counting, bound ballots, record-only inputs [SB-2 (iii)] | Implemented (heterogeneity floor off by default; `QuorumPolicy.section4()`) |
| Path B connectors (OpenAI-compatible, Anthropic, Gemini, Ollama) | Implemented; tested with mocks only |
| API-key and keyring auth | Implemented |
| Username/password and OAuth device-code auth | Interface only (documented stub) |
| Capability token and gateway checks | Implemented |
| Ledger-root-bound token with consistency-proof ancestry, revocation, linked results [SB-2 (i)] | Implemented |
| Ledger: hash chain, signed head, Merkle tree, inclusion and consistency proofs | Implemented |
| FIPS-approved-algorithm mode, self-test, hybrid PQ signatures | Implemented; not a validated module |
| Action-record normalization design (F) | **Open; no option implemented** |
| PRIOR_ART.md §4 (iv) replay audit, (v) imputation logging, (vi) model-swap | Not selected; not implemented |
| Public anchoring | Stub interface only |
| Hardware-backed keys (TEE/HSM) | Not implemented |
| Ledger encryption | Not implemented |

## 7. Example claims

The seven teaching claims in `docs/INVENTION_DISCLOSURE.md` §7 are **unchanged** and not reproduced here; the attorney should work from that text. This draft adds no claim language.

Themes the attorney may want to consider, by source:
- User-uploaded human-language constitution, signed by the principal, as the input to Path B, together with compiled hard rules as the input to Path A [SB-1; D §5.1 item 2].
- Path B judges connected to principal-selected AI providers, local or vendor, through principal-selected authentication (API key, username/password, SSO) [SB-1].
- Both paths must agree before any action occurs [SB-1; D §3; Claim 1(d)].
- The three narrower directions Stephan selected on 2026-09-30 [SB-2 (i), (ii), (iii)]. Their wording is from the patent-attorney agent's `PRIOR_ART.md` §4, and §§5.5, 5.7, and 5.8 above describe how they are implemented. Whether they are claimable, and whether a selection among AI-proposed directions supports inventorship, is for counsel.

The open design questions in `DESIGN_OPTIONS.md` (including §7, the details §4 left open, and §1, the normalization problem F) are not reflected in any claim theme.

## 8. Notes for counsel

- The original disclosure cites USPTO guidance (revised 28 Nov 2025) on AI-assisted inventions and *Ex parte Desjardins* on technical-improvement framing [D §1, §9]. Neither has been verified by the assistant.
- Licensing: the repository's license is Stephan's decision. The `LICENSE` file comes from the original repository's history and was not changed by this work. Whether the repository or package has ever been public is unknown; please check the commit history and visibility history.
- `PRIOR_ART.md` (the patent-attorney agent's prior-art triage) is referenced here but is kept outside this repository. Its §4 wording is quoted only as the source of the [SB-2] directions.
- Problem F (who produces the action record) was flagged by Stephan but is deliberately unimplemented; the (i)–(iii) guarantees depend on the fields Path A reads, which F would settle.
- The original disclosure's advocacy sections (§8, and most of §9 on institutional risk surveys and climate funding) are left out of this draft. They remain in the original file.
