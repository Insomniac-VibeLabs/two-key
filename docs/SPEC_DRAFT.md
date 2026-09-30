# SPECIFICATION DRAFT (working document, not filed)

**Title:** Method and System for Dual-Path Constitutional Enforcement of Personal Artificial Intelligence Agents Using a Deterministic Policy Virtual Machine and a Multi-Model Intent Quorum

**Short name:** Compact Kernel ("two-key")

**Draft prepared:** 2026-09-30. Derived from `docs/INVENTION_DISCLOSURE.md` (disclosure date 30 September 2026, kept unchanged for the record) and updated to match the prototype in this repository.

**Status:** Working draft for review by a registered patent attorney. Not a filed application. Not legal advice.

### Source tags used in this draft

| Tag | Meaning |
|---|---|
| **[D §n]** | Carried over from the original invention disclosure, section n |
| **[SB-1]** | Stephan Busch's conception statement, `CONCEPTION_NOTES.md` entry 1 (2026-09-30, ~4:03 AM MT) |
| **[IMPL]** | How the prototype implements something. It is an engineering detail, not asserted as inventive. Where several designs are possible, see `DESIGN_OPTIONS.md` |

**Inventorship:** to be determined with counsel. The conception record is in `CONCEPTION_NOTES.md`; engineering changes and who decided them are in `CHANGES.md`. The original disclosure text and the prototype code were largely drafted with an AI assistant. AI is not an inventor.

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

Technical improvements stated in the disclosure [D §3]:
- less unauthorized tool invocation under prompt injection, because Path A has no natural-language parser;
- less single-vendor goal hijack, because of the cross-model quorum;
- the constitution carries over across model swaps;
- Path A decides in microseconds (the prototype measured ~10 µs per evaluation on commodity hardware, 2026-09-30);
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

[IMPL] Python package `compact_kernel`: `constitution.py`, `action.py`, `policy_vm.py`, `quorum.py`, `judges/`, `capability.py`, `gateway.py`, `ledger.py`, `merkle.py`, `anchoring.py`, `kernel.py`, `cli.py`.

### 5.2 Constitution upload and signing [SB-1; D §5.1 item 2]

The principal provides (a) a plain-English constitution file (`.txt`/`.md`) and (b) a hard-rules file (`.json`/`.yaml`).

[IMPL] The two are bundled into a canonical document {format, principal, created_at, constitution_text, its SHA-256, hard_rules} and signed with the principal's Ed25519 key. Before use, the kernel verifies the signature against a public key the principal trusts. It rejects unsigned envelopes, modified text or rules, envelopes signed by a different key, and envelopes whose embedded key was swapped. CLI: `keygen`, `sign-constitution`, `verify-constitution`.

### 5.3 Action record and normalization [D §5.2]

Fields: tool, amount_usd, currency, counterparty, data_class ∈ {public, personal, medical, financial, classified}, destination, duration_hours, irreversible, tags, raw. Missing high-impact fields default to conservative values (irreversible = true, data_class = classified) or cause rejection [D §5.2, Claim 5].

[IMPL] Validation rejects negative, non-finite, and non-numeric amounts, unknown fields, and non-boolean `irreversible`. Strings are trimmed and case-folded, and data_class must be one of the enum values. Invalid records become an explicit, logged deny.

*Open question (DESIGN_OPTIONS.md §1):* which component produces the action record (the proposing model, the gateway working from the literal tool-call arguments, a classifier, or a hybrid). The prototype accepts a caller-supplied record and offers a gateway extractor hook. It does not select a design.

### 5.4 Path A: constitution compilation and VM [D §5.3]

The hard rules use a restricted schema: `allow_only_tools`, `deny_counterparties`, `deny_if {tool, amount_usd_gt, data_class_in, irreversible}`, and `deny_if_irreversible_over`. They compile to stack operations, and the VM evaluates them against the action. Compilation happens when the principal saves the constitution, so an attacker who can only talk to the model can't alter the bytecode [D §5.3, Claim 2].

[IMPL]
- Each rule compiles to a block ending in `ASSERT <rule id>`, so the deny reason names the rule.
- The compiler rejects unknown rule types, unknown keys, wrong types, and empty rule sets. By default it also requires an allow-list.
- VM faults (type errors, stack underflow, unknown opcodes, exceeding the step limit) are denies.
- The step limit is configurable (default 4096) and checked at compile time.

### 5.5 Path B: judges connected to the principal's chosen AI, and the quorum protocol [SB-1; D §5.4]

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

*Open question (DESIGN_OPTIONS.md §2):* how judge independence should be ensured.

### 5.6 Capability token and tool gateway (Figure 3: `docs/figures/token_gateway_sequence.svg`) [D §5.5]

Payload [D §5.5]: principal, tool, scope, issued_at, expires_at, ledger_root. Default TTL is 30 seconds. The gateway checks the signature, expiry, tool match, that the amount is within scope, that the counterparty matches, and that the ledger root equals the last-known root or is an ancestor of it. The disclosure states that replay across tools, replay after expiry, and replay after a new constitution load (if the gateway tracks roots) all fail [D §5.5].

[IMPL]
- The token also carries a single-use `jti`, `args_hash`, and the constitution digest.
- It is signed with HMAC-SHA256 in the prototype; production would use a hardware-backed key [D §5.1 item 6].
- The gateway additionally checks the principal, data class, `args_hash` (the canonical hash of the literal tool-call arguments), that no constitution has been loaded since the token's root, and single use. The set of used jtis is rebuilt from the ledger on restart.
- The full token goes back to the caller; only its SHA-256 is logged.

*Open question (DESIGN_OPTIONS.md §3):* the token binding details. `args_hash` is the reference option specified in Stephan's 2026-09-30 instructions, and alternatives are listed in the memo.

### 5.7 Personal ledger (Figure 4: `docs/figures/ledger_structure.svg`) [D §5.6]

Hash chain: `digest_i = H(canonical(seq, ts, kind, body, prev))`. Verification walks the chain, and production anchoring writes the root to a public log on a schedule [D §5.6].

[IMPL]
- The ledger logs the full canonical action record, the args hash, the ballots, the token hash, and the deny reason or rule.
- After every append, the principal's Ed25519 key signs the chain head {size, head digest, RFC 6962-style Merkle root}. A full rewrite, truncation, or an unsigned append is then detected.
- Merkle inclusion proofs are available.
- Anchoring is an interface with local stubs only; nothing is published.
- Files are created with mode 0600. The ledger is not encrypted.

### 5.8 Fail-closed defaults [D §5.7]

If the VM faults, deny. If the quorum isn't met, deny. If the issuer can't sign, deny. If the ledger can't append, deny. There is no best-effort allow [D §5.7].

[IMPL] All four are implemented and tested. Unexpected exceptions inside `authorize` produce a deny with no token.

### 5.9 Ordering of the paths

[IMPL] By default Path B is not convened when Path A denies (`short_circuit_path_b=True`), so forbidden proposals aren't sent to external judges. It can be configured to run both. Both must pass for an allow either way. *Open question: DESIGN_OPTIONS.md §4.*

### 5.10 Model-swap invariance [D §5.8]

Replacing the proposing model doesn't require a new constitution. Replacing a judge only requires that the new judge speak the ballot schema. Path A is unaffected by any model change [D §5.8]. [IMPL] Judges are swapped by editing `judges.yaml`; the signed constitution and bytecode don't change.

## 6. Reduction to practice (as of 2026-09-30)

[IMPL] The Python 3 prototype is in `compact_kernel/`. The test suite (`python -m unittest discover -s tests`) covers:
- the defects found in the 2026-09-30 review: the negative-amount wire, permissive missing-field defaults, silently ignored typo rules, case variants such as "Medical", 2-of-3 quorums, and zero judges;
- every gateway check, including replay across tools, expiry, scope, and ledger-root ancestry;
- detection of full ledger rewrites;
- constitution and token signature tampering;
- malformed judge output.

`python -m compact_kernel demo` runs the original three scenarios plus the review's regressions, entirely offline with test-double judges. No real vendor API has been called; the connectors are tested against mocked transports.

| Element | Status |
|---|---|
| Constitution upload and Ed25519 signing | Implemented |
| Path A compiler and VM | Implemented |
| Path B quorum protocol | Implemented |
| Path B connectors (OpenAI-compatible, Anthropic, Gemini, Ollama) | Implemented; tested with mocks only |
| API-key and keyring auth | Implemented |
| Username/password and OAuth device-code auth | Interface only (documented stub) |
| Capability token and gateway checks | Implemented |
| Ledger: hash chain, signed head, Merkle tree | Implemented |
| Public anchoring | Stub interface only |
| Hardware-backed keys (TEE/HSM) | Not implemented |
| Ledger encryption | Not implemented |

## 7. Example claims

The seven teaching claims in `docs/INVENTION_DISCLOSURE.md` §7 are **unchanged** and not reproduced here; the attorney should work from that text. This draft adds no claim language.

Themes the attorney may want to consider, by source:
- User-uploaded human-language constitution, signed by the principal, as the input to Path B, together with compiled hard rules as the input to Path A [SB-1; D §5.1 item 2].
- Path B judges connected to principal-selected AI providers, local or vendor, through principal-selected authentication (API key, username/password, SSO) [SB-1].
- Both paths must agree before any action occurs [SB-1; D §3; Claim 1(d)].

The open design questions in `DESIGN_OPTIONS.md` are not reflected in any claim theme.

## 8. Notes for counsel

- The original disclosure cites USPTO guidance (revised 28 Nov 2025) on AI-assisted inventions and *Ex parte Desjardins* on technical-improvement framing [D §1, §9]. Neither has been verified by the assistant.
- Licensing: the repository's license is Stephan's decision. This working copy adds no license text. Whether the repository or package has ever been public is unknown; please check the commit history and visibility history.
- The original disclosure's advocacy sections (§8, and most of §9 on institutional risk surveys and climate funding) are left out of this draft. They remain in the original file.
