# Design options memo: open questions for the maintainers

**Prepared:** 2026-09-30, by the AI engineering assistant, for the author.
**Status:** options only. **No decision has been made on any item below**,
except where a section says so. **Update 2026-09-30, ~7:02 AM MT:** The author
selected the design reviewer's `PRIOR_ART.md` §4 directions (i)
ledger-root-bound token, (ii) one signed constitution / two compilations,
and (iii) quorum protocol specifics, and flagged the normalization problem
(§1 below, "F") (`CONCEPTION_NOTES.md` Entry 2). (i)–(iii) are now
implemented as `PRIOR_ART.md` §4 describes them. The details §4 leaves open
are listed in **§7** with the reference behaviour chosen. **§1 is still
open:** no normalization option was implemented. (`PRIOR_ART.md` is the
reviewer agent's memo and is kept outside this repository.)

The prototype needs *some* behavior to run. Where a question is still open,
the code uses a minimal, clearly configurable reference behavior and marks
it "current prototype default". That default is an engineering placeholder,
not a recommendation and not a pointed design. Choosing among these options,
or coming up with others, is the author's call, and it may matter for
conception and inventorship. Talk to the reviewer before treating
any option as part of the invention.

---

## 1. Action-record normalization: who produces the fields Path A reads?

Path A is only as trustworthy as the structured record it evaluates
(`tool`, `amount_usd`, `counterparty`, `data_class`, `irreversible`, ...).
If the proposing model writes that record, an injected model can simply
misstate it (for example, label medical data "public").

**Implemented regardless of the choice (engineering):** strict validation and
canonicalization (`action.py`) and conservative defaults for missing fields
(spec 5.2 / the missing-field rule). A literal-args hash binds the token to the exact call
(`capability.args_hash`). The gateway has a per-tool extractor hook
(`ToolGateway(extractors=...)`).

**Status after 2026-09-30 (Entry 2, "F"):** The author flagged this problem
together with §4 (i)–(iii). **No option has been chosen or implemented.**
The hooks below are unchanged.

**Current prototype default:** the caller supplies the action record (option
A). The gateway compares caller-declared call fields, or extractor output if
an extractor is registered, against the token scope.

| Option | How it works | Pros | Cons |
|---|---|---|---|
| **A. Model-proposed, Two-Key-validated** | The proposing model emits the record; Two-Key validates types and enums | Simple, works for any tool | The model can lie about semantic fields; Path A's "no English input surface" guarantee then depends on the model's honesty |
| **B. Derived at the gateway from literal tool-call args** | Per-tool deterministic extractors compute amount, counterparty, etc. from the actual call arguments; the token binds to a canonical hash of those args | Fields come from what will actually execute; no model in the loop; deterministic and auditable | An extractor is needed for every tool; semantic fields (`data_class`, "is this irreversible?") often can't be derived from args |
| **C. Separate classifier** | A dedicated component (rules, a small local model, a DLP scanner) assigns `data_class` and similar fields from the payload | Covers semantic fields; can run locally | A model-based classifier brings back a linguistic surface; accuracy and false positives; extra latency |
| **D. Hybrid** | B for derivable fields, C for semantic fields, and the model's proposal used only as a hint; any disagreement means deny | Defense in depth; disagreements become signals | Most complex; needs a policy for resolving disagreements |

Sub-questions:
- Should a missing `amount_usd` default to 0 (current) or be required for money-moving tools?
- Should tool names be case-folded (current) or matched exactly?
- Is the five-value `data_class` taxonomy (spec 5.2) the right one?

## 2. Judge independence (Path B)

Spec 5.4 says judges "must be independently reachable". the two-vendor rule mentions "at
least two distinct model vendors or local weight files". How to *ensure*
independence is open.

**Current prototype default:** no independence enforcement.
`min_distinct_providers: 1`; the check exists but is off. Since the author's
2026-09-30 selection of §4 (iii), a vendor and local-weights floor exists
(`min_vendors`, `min_local_judges`; `QuorumPolicy.section4()` sets §4's
figures of ≥ 2 vendors including ≥ 1 local weight file). It is still off by
default; see §7.14–7.16. Quorum is an exact
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

**Current prototype default** (the reference option specified in the author's
2026-09-30 instructions): a single-use HMAC token bound to principal, tool,
scope {amount, counterparty, data class}, **args_hash** (canonical hash of the
literal tool-call args), ledger root, and constitution digest; TTL 30 s.

| Question | Options | Notes |
|---|---|---|
| What binds the token to the call? | **(a) literal-args hash** (current); (b) scope only (spec 5.5 as written); (c) hash of the normalized action record; (d) both (a) and (c) | (a) prevents "same scope, different payload" swaps but breaks if a tool reorders or re-encodes args; (b) is more flexible but weaker |
| Signature scheme | **HMAC shared secret** (current default: HMAC-SHA-384 `tk1-hs384` for every key suite since the F_REVIEW fixes; HMAC-SHA-256 `tk1` only if chosen); asymmetric signed tokens (`tk1-sig`, optional since 2026-09-30, e.g. hybrid ML-DSA-65 + Ed25519; see docs/CRYPTO.md); TEE/HSM-held key (spec 5.1 item 6) | With HMAC, anything that can verify can also mint. Asymmetric keys separate the two, at a cost of about 0.3 ms per verify and 6.8 KB per token for the hybrid (docs/PERFORMANCE.md) |
| Holder binding | **Bearer** (current); proof-of-possession (the caller signs each call with its own key, DPoP-style) | PoP stops stolen-token use |
| Uses | **Single-use jti** (current); multi-use within TTL; N uses | Single-use means retries need a new authorization |
| Counterparty check | **Strict equality** (current, stricter than spec's "matches if present"); spec's "matches if present" | Strict equality rejects a call naming a counterparty when the token has none |
| Ledger-root freshness | **Any ancestor of the current head, and no constitution reload since** (current); exact current head only; within N entries or T seconds | Exact-head breaks under concurrent authorizations. Since 2026-09-30 (§4 (i)), ancestry is proven with an RFC 9162 consistency proof against the gateway's last-known view (§7.1–7.2) |
| TTL | **30 s default** (spec 5.5); per-tool TTLs | |
| Amount semantics | **Call amount ≤ scope amount** (current); exact equality | |

## 4. Ordering of Path A and Path B

**Current prototype default** (per the author's 2026-09-30 instructions, for
privacy): `short_circuit_path_b=True`, so Path B is skipped if Path A denies.
Set `False` to run both. §4 (iii), which the author selected, says "Path B
invoked only after Path A returns true". `require_path_a_first=True` (set
by `QuorumPolicy.section4()`) makes Two-Key refuse `False`; see §7.21.

| Option | Pros | Cons |
|---|---|---|
| **A. Short-circuit after an A deny** (current) | Forbidden proposals, which may contain sensitive data, never reach external judges; lower cost and latency | Less audit data about how judges would have voted |
| **B. Always run both** (option available) | Full audit trail; can calibrate judges against Path A | Sends denied content to vendors; cost |
| **C. Path B first** | Judges see everything first | Worst for privacy; Path A's cheap deny comes last |
| **D. Parallel, cancel on first deny** | Lowest latency | Content already sent to judges before the cancel |
| **E. After an A deny, run only local judges** | Audit value without sending data off-device | Requires a local judge |

## 5. Credential, username/password, and SSO handling for judges

The author's conception (CONCEPTION_NOTES.md entry 1) names "api or
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

## 7. Open points in the PRIOR_ART.md §4 (i)–(iii) implementation

The author selected these three directions on 2026-09-30 (`CONCEPTION_NOTES.md`
Entry 2). The code follows the text of `PRIOR_ART.md` §4. Where §4 does not
settle a detail, the prototype uses the minimal, configurable reference
behaviour listed here. **These are engineering placeholders, not decisions.**

### (i) Ledger-root-bound token (`gateway.py`, `ledger.py`, `merkle.py`, `capability.py`)

| # | Open point | Current reference behaviour | Alternatives |
|---|---|---|---|
| 7.1 | Where the gateway's "last-known root" comes from and when it moves | Gateway memory: taken from the (Two-Key-verified) ledger when the gateway is built. It advances only along a verified consistency proof: to a newer token's root R (the token authenticates R), or to the current ledger with `view_refresh="every_call"` / `refresh_view()`. On restart the view is re-read from the ledger. | Take the view only from a signed head (verify the principal's signature each time); persist the view separately from the ledger; take it from an external witness or anchor; refresh on a timer |
| 7.2 | Where consistency proofs come from | In process, the gateway asks the same ledger object (`consistency_path`). `PersonalLedger.consistency_proof()` also returns a serializable proof for a separate verifier | A ledger service API; proofs attached to the token; gossip between gateways |
| 7.3 | Which later entries invalidate a token | Any `constitution_loaded` after issuance (even a byte-identical reload), and `revocation` entries | Only reloads whose hashes differ; key-rotation entries; judge-set changes |
| 7.4 | Revocation granularity and authority | `tk.revoke(jti)` for one token, `tk.revoke()` for all tokens issued so far. Anyone who can call Two-Key may revoke; the entry is covered by the next signed head | Per tool, per counterparty, time-window; require a principal signature on each revocation; revocation by the gateway itself |
| 7.5 | What "appends the execution result" stores | `tool_executed` carries the capability entry's seq and digest plus `result_hash` = H(canonical JSON of the result), or H(repr) if the result isn't JSON. The result itself is not stored | Store the full result; store an encrypted result; store nothing but the link |
| 7.6 | Which root R the token binds | Root of the ledger just before the token's own `capability_issued` entry (`ledger_size` = that entry's seq) | Include the decision entries; two-phase issuance that also covers the capability entry |
| 7.7 | Tokens without the new fields | Refused (`token_missing_ledger_binding`); no compatibility mode | Accept with a legacy flag during migration |

### (ii) One signed constitution, two compilations (`compiler.py`, `constitution.py`)

| # | Open point | Current reference behaviour | Alternatives |
|---|---|---|---|
| 7.8 | How rules sit inside the single document | Format `/2`: a Markdown `source` with exactly one fenced ```` ```twokey-rules ```` block of JSON. Format `/1` (separate fields in one signed document) is still accepted | YAML in the fence; several blocks merged; inline annotations in the prose; a controlled-English rule syntax compiled directly |
| 7.9 | Whether judges also see the rules | No. Judges get the prose only; the rule block is removed (headings and other text around it stay) | Include the rules as context; include a rendered English summary of the rules |
| 7.10 | Exact bytes hashed as H(NL constitution) | The judge prompt text: the source minus the rule block, CRLF turned into LF, leading and trailing whitespace stripped | Unicode NFC normalization; whitespace canonicalization; hash the whole signed source instead |
| 7.11 | What H(bytecode) covers | Canonical JSON of `[[opcode name, operands...], ...]`. The compiler id (`two-key-compiler/1`) and `max_steps` are recorded next to it, not inside it | Bind compiler version and limits into the hash |
| 7.12 | "No string operations on NL fields": what the static check allows | LOAD only of structured action fields (every field except `raw`); opcodes emitted by the compiler only (CONTAINS excluded); scalar or list constants; program ends in PASS | Typed field schema; a per-field operation whitelist (this depends on §1 / F: which fields exist and who fills them) |
| 7.13 | Reload ordering and rollback | Any document signed by the principal's key is accepted by `reload_constitution`; no version counter | Require a monotonic version or `created_at`; require a signed reference to the previous digest |

### (iii) Quorum protocol specifics (`quorum.py`, `judges/`)

| # | Open point | Current reference behaviour | Alternatives |
|---|---|---|---|
| 7.14 | Whether §4's heterogeneity figures are the default | Off by default (`min_vendors=1`, `min_local_judges=0`) so existing configurations keep working. `QuorumPolicy.section4()` applies ≥ 2 vendors, ≥ 1 local weight file, record-only inputs, and Path A first | Make `section4()` the default; refuse any configuration below it |
| 7.15 | What counts as a vendor, and as a "local weight file" | Self-declared: `vendor` (defaults to `provider`) and `local_weights` (defaults to true for Ollama, false otherwise). `weights_sha256` is recorded in the ledger but not verified | Derive the vendor from the endpoint; hash the weight file at start-up; attestation (see §2 options C, F) |
| 7.16 | Whether heterogeneity must also hold among the judges that answered | `heterogeneity_scope="selection"` (checked at Two-Key start and at each convene); `"responding"` also checks the judges that returned valid ballots | Also require it among the yes votes |
| 7.17 | How a ballot is "bound" to H(action record) and H(constitution) | `ballot_binding="stamp"` (default): the convenor attaches the round's binding (H(action record), constitution digest, nl_hash, bytecode_hash) to every ballot. A judge that reports different hashes abstains. `"echo"`: every yes/no ballot must carry hashes the judge itself returned (LLM judges with `echo_binding: true` get them in the prompt and must copy them) | Judge-signed ballots (a key per judge); a provider-side structured-output schema; a MAC over the ballot. Note that an echo from an LLM is a consistency check, not a cryptographic binding |
| 7.18 | How much of a round below the floor K is logged | Not counted: `counted=false`, and `yes`/`no` are null. The individual ballots, including their votes, are still logged | Log only abstention reasons; log ballot hashes only |
| 7.19 | What exactly judges receive | `judge_inputs="record_only"` (default): constitution prose + normalized action record (+ binding). The proposal text is not sent (it is still logged in the ledger, §6). `"record_and_proposal"` restores the earlier behaviour. The record's free-form `raw` field is still part of the record (§1 / F) | Drop `raw`; send a redacted record; per-judge input policies |
| 7.20 | Values of K and T | The principal's choice; K (`min_responding`) defaults to T (`required_yes`) | Require K > T; derive K from n |
| 7.21 | Whether "Path B only after Path A" is mandatory | Default behaviour (`short_circuit_path_b=True`), enforced only with `require_path_a_first=True` | Remove the option to run both (§4 option B) |

### Not built

`PRIOR_ART.md` §4 also lists (iv) third-party replay audit, (v)
conservative imputation logging, and (vi) model-swap invariance. They were
not selected, and §4 does not make them part of (i)–(iii), so they were not
implemented. (v) overlaps the normalization problem (§1 / F), which stays
open.
