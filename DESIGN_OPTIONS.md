# Design options memo: open questions for Stephan

**Prepared:** 2026-09-30, by the AI engineering assistant, for Stephan Busch.
**Status:** options only. **No decision has been made on any item below.**

The prototype needs *some* behavior to run. Where a question is still open,
the code uses a minimal, clearly configurable reference behavior and marks
it "current prototype default". That default is an engineering placeholder,
not a recommendation and not a claimed design. Choosing among these options,
or coming up with others, is Stephan's call, and it may matter for
conception and inventorship. Talk to the patent attorney before treating
any option as part of the invention.

---

## 1. Action-record normalization: who produces the fields Path A reads?

Path A is only as trustworthy as the structured record it evaluates
(`tool`, `amount_usd`, `counterparty`, `data_class`, `irreversible`, ...).
If the proposing model writes that record, an injected model can simply
misstate it (for example, label medical data "public").

**Implemented regardless of the choice (engineering):** strict validation and
canonicalization (`action.py`) and conservative defaults for missing fields
(spec 5.2 / Claim 5). A literal-args hash binds the token to the exact call
(`capability.args_hash`). The gateway has a per-tool extractor hook
(`ToolGateway(extractors=...)`).

**Current prototype default:** the caller supplies the action record (option
A). The gateway compares caller-declared call fields, or extractor output if
an extractor is registered, against the token scope.

| Option | How it works | Pros | Cons |
|---|---|---|---|
| **A. Model-proposed, kernel-validated** | The proposing model emits the record; the kernel validates types and enums | Simple, works for any tool | The model can lie about semantic fields; Path A's "no English input surface" guarantee then depends on the model's honesty |
| **B. Derived at the gateway from literal tool-call args** | Per-tool deterministic extractors compute amount, counterparty, etc. from the actual call arguments; the token binds to a canonical hash of those args | Fields come from what will actually execute; no model in the loop; deterministic and auditable | An extractor is needed for every tool; semantic fields (`data_class`, "is this irreversible?") often can't be derived from args |
| **C. Separate classifier** | A dedicated component (rules, a small local model, a DLP scanner) assigns `data_class` and similar fields from the payload | Covers semantic fields; can run locally | A model-based classifier brings back a linguistic surface; accuracy and false positives; extra latency |
| **D. Hybrid** | B for derivable fields, C for semantic fields, and the model's proposal used only as a hint; any disagreement means deny | Defense in depth; disagreements become signals | Most complex; needs a policy for resolving disagreements |

Sub-questions:
- Should a missing `amount_usd` default to 0 (current) or be required for money-moving tools?
- Should tool names be case-folded (current) or matched exactly?
- Is the five-value `data_class` taxonomy (spec 5.2) the right one?

## 2. Judge independence (Path B)

Spec 5.4 says judges "must be independently reachable". Claim 4 mentions "at
least two distinct model vendors or local weight files". How to *ensure*
independence is open.

**Current prototype default:** no independence enforcement.
`min_distinct_providers: 1`; the check exists but is off. Quorum is an exact
k-of-n (`required_yes`) with a minimum number of valid responses
(`min_responding`).

| Option | Pros | Cons |
|---|---|---|
| **A. None: trust the user's judge list** (current) | Simple; the user picks | Three judges from one vendor are not independent |
| **B. Distinct self-declared provider labels** (`min_distinct_providers >= 2`, implemented but off) | Easy; config-level | Labels are self-declared; nothing stops two labels pointing at the same backend |
| **C. Distinct verified endpoints** (different registrable domains or hosts in `base_url`) | Harder to fake by accident | Resellers and proxies (one gateway fronting many models) defeat it; a local model has no domain |
| **D. Require at least one local judge** | Survives vendor outage or vendor alignment; privacy | Local models may be weaker; needs hardware |
| **E. Role diversity** (different prompts, e.g. one adversarial "find the violation" judge) | Reduces correlated failure modes | Prompt design becomes part of the security surface |
| **F. Model identity attestation** | Strongest assurance | Generally not available from vendors today |
| **G. Correlation monitoring** (flag judges that always agree) | Detects degraded independence over time | Needs history; after the fact |

Related quorum-rule options: k-of-n (current), unanimity, any-single-"no"-is-a-veto,
weighted votes, and whether abstentions should count as "no" (currently they are
simply not "yes", and they don't count toward `min_responding`).

## 3. Capability-token binding details

**Current prototype default** (the reference option specified in Stephan's
2026-09-30 instructions): a single-use HMAC token bound to principal, tool,
scope {amount, counterparty, data class}, **args_hash** (canonical hash of the
literal tool-call args), ledger root, and constitution digest; TTL 30 s.

| Question | Options | Notes |
|---|---|---|
| What binds the token to the call? | **(a) literal-args hash** (current); (b) scope only (spec 5.5 as written); (c) hash of the normalized action record; (d) both (a) and (c) | (a) prevents "same scope, different payload" swaps but breaks if a tool reorders or re-encodes args; (b) is more flexible but weaker |
| Signature scheme | **HMAC shared secret** (current default: HMAC-SHA-256 `ck1`, or HMAC-SHA-384 `ck1-hs384` for non-legacy key suites); asymmetric signed tokens (`ck1-sig`, optional since 2026-09-30, e.g. hybrid ML-DSA-65 + Ed25519; see docs/CRYPTO.md); TEE/HSM-held key (spec 5.1 item 6) | With HMAC, anything that can verify can also mint. Asymmetric keys separate the two, at a cost of about 0.3 ms per verify and 6.8 KB per token for the hybrid (docs/PERFORMANCE.md) |
| Holder binding | **Bearer** (current); proof-of-possession (the caller signs each call with its own key, DPoP-style) | PoP stops stolen-token use |
| Uses | **Single-use jti** (current); multi-use within TTL; N uses | Single-use means retries need a new authorization |
| Counterparty check | **Strict equality** (current, stricter than spec's "matches if present"); spec's "matches if present" | Strict equality rejects a call naming a counterparty when the token has none |
| Ledger-root freshness | **Any ancestor of the current head, and no constitution reload since** (current); exact current head only; within N entries or T seconds | Exact-head breaks under concurrent authorizations |
| TTL | **30 s default** (spec 5.5); per-tool TTLs | |
| Amount semantics | **Call amount ≤ scope amount** (current); exact equality | |

## 4. Ordering of Path A and Path B

**Current prototype default** (per Stephan's 2026-09-30 instructions, for
privacy): `short_circuit_path_b=True`, so Path B is skipped if Path A denies.
Set `False` to run both.

| Option | Pros | Cons |
|---|---|---|
| **A. Short-circuit after an A deny** (current) | Forbidden proposals, which may contain sensitive data, never reach external judges; lower cost and latency | Less audit data about how judges would have voted |
| **B. Always run both** (option available) | Full audit trail; can calibrate judges against Path A | Sends denied content to vendors; cost |
| **C. Path B first** | Judges see everything first | Worst for privacy; Path A's cheap deny comes last |
| **D. Parallel, cancel on first deny** | Lowest latency | Content already sent to judges before the cancel |
| **E. After an A deny, run only local judges** | Audit value without sending data off-device | Requires a local judge |

## 5. Credential, username/password, and SSO handling for judges

Stephan's conception (CONCEPTION_NOTES.md entry 1) names "api or
username/password or single sign on login".

**Implemented:** API key from an environment variable; API key from the OS
keyring (optional `keyring` package); a generic callback token hook.
**Interfaces with documented stubs:** `UsernamePasswordProvider` (needs a login
hook) and `OAuthDeviceCodeProvider` (RFC 8628 steps documented; needs a
`fetch_token` hook). No vendor login is imitated.

| Option | Pros | Cons |
|---|---|---|
| **A. API keys via env** (implemented) | Universal for vendor APIs | Keys in the process environment; rotation is manual |
| **B. OS keyring / secret store** (implemented, optional) | Keys encrypted at rest by the OS | Platform differences; headless servers |
| **C. Username/password via a user-supplied login hook** (interface) | Fits self-hosted gateways that issue sessions | **Most vendor APIs don't offer password login.** Automating a consumer chat login may violate vendor terms; check each vendor's terms. Storing passwords is risky |
| **D. OAuth device-code flow (RFC 8628)** (stub) | Good UX on headless or CLI devices; no password handling | Only where the identity provider supports it for model access |
| **E. OAuth authorization code + PKCE in a browser** | Standard SSO for desktop and mobile | Needs a redirect handler; per-IdP setup |
| **F. Enterprise SSO through an internal model gateway/proxy** | One login fronts many models; central audit | The proxy becomes a single point that can undermine judge independence (see section 2) |
| **G. Hardware-backed secrets (TPM, Secure Enclave, HSM)** | Strongest at rest | Platform-specific work |

## 6. Other open items (not decided, not implemented beyond noted defaults)

- **Allow-list requirement:** the compiler requires an `allow_only_tools` rule by default (fail-closed reading of spec section 4). Should this be mandatory, a default, or optional?
- **Ledger confidentiality:** the ledger is plaintext JSONL with 0600 permissions, not encrypted. Options: file encryption with a key derived from the principal key; per-entry encryption; OS-level encryption only.
- **Anchoring target and schedule** (spec 5.6): a public transparency log, blockchain, notary, or none. What to anchor (the Merkle root only?), and how often. Only a stub interface exists.
- **Capability secret management:** it is currently random per process unless supplied. Options: a derived key, an HSM, asymmetric keys (section 3).
- **Constitution lifecycle:** versioning, rollback, multi-device sync, key loss or recovery, and key rotation.
- **Proposal logging:** the full proposal text is logged in the principal's ledger. Should it be hash-only, truncated, or full (current)?
