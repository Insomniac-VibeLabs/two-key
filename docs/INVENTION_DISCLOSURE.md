# INVENTION DISCLOSURE

**Title:** Method and System for Dual-Path Constitutional Enforcement of Personal Artificial Intelligence Agents Using a Deterministic Policy Virtual Machine and a Multi-Model Intent Quorum

**Short name:** Compact Kernel

**Disclosure date:** 30 September 2026

**Field:** Computer security; autonomous agents; applied cryptography; human-computer interaction

---

## 1. Inventor note (read this first)

United States law names only natural persons as inventors. Current USPTO
guidance (revised 28 November 2025) treats generative AI as a tool,
analogous to laboratory equipment. A human who conceives the claimed
invention — who forms the definite and permanent idea of the complete
invention — may file. This package is written so that a human inventor
can take it to a registered patent attorney and file a provisional
application under 35 U.S.C. § 111(b).

This document is an invention disclosure, not a filed application and
not legal advice.

Suggested first step: USPTO patent pro se / micro-entity provisional,
or a registered attorney. Micro-entity provisional filing fee is the
lowest tier if you qualify. You then have 12 months to file a
non-provisional.

---

## 2. The problem, from a human / American view

Three facts about the present:

1. Software agents now propose and, in some systems, execute actions that
   spend money, disclose records, send mail, and operate browsers.
2. The model that proposes the action is trained, hosted, updated, and
   aligned by a vendor. The vendor's incentives are not the principal's
   incentives.
3. Prompt injection, tool-description attacks, and silent weight updates
   have already produced real-world theft. Public reporting in 2026
   includes cases in which every cryptographic signature was valid and
   the failure was the agent's *decision*, not a stolen key.

Prior systems bind an agent to a person with a hardware key or a
biometric template. Binding answers "who owns this agent?" It does not
answer "may this agent do *this* action *now*?" Binding plus an LLM
judge is still a single linguistic surface. A sufficiently clever
string can talk the judge into a yes.

The civilizational consequence is not abstract. If agents become the
way citizens deal with banks, insurers, agencies, and employers, then
whoever can steer the agent steers the citizen. That is a transfer of
agency from persons to platforms. The American bet has always been the
other direction.

Compact Kernel is a method that makes "the agent works for the person,
not the vendor" an enforceable property of the computer, not a slogan
in a privacy policy.

---

## 3. Summary of the invention

A runtime sits between any language model and any tool gateway. A
proposed action is admitted to the real world only if two independent
paths both pass, after which a short-lived capability token is issued
and the entire decision is written to a principal-owned hash chain.

**Path A — Deterministic Policy Virtual Machine.**
The principal's hard constraints (dollar caps, forbidden tools, data
classes, counterparties, irreversibility limits) are compiled, ahead of
time, into bytecode for a tiny stack machine. At decision time the VM
loads fields of a normalized action record. It does not read English.
The same bytecode and the same action always produce the same result.
Prompt injection has no input surface on this path.

**Path B — Multi-model intent quorum.**
N independent judges — preferably different model vendors or local
weights — each receive the principal's natural-language constitution
and the proposal. They vote whether the proposal is consistent with
that constitution. A configurable threshold (for example two of three)
must pass. A single vendor-aligned or injected model cannot carry the
decision.

**Capability issuance.**
Only after both paths pass does the runtime sign a capability token
bound to: principal identifier, tool name, numeric and party scope,
expiry measured in seconds, and the current root of the personal
ledger. A tool gateway that honors the protocol refuses any invocation
lacking a valid, unexpired, correctly scoped token.

**Personal ledger.**
Every proposal, VM result, ballot, and issued capability is appended to
a Merkle / hash chain stored under the principal's control. The vendor
cannot rewrite history. The root can be anchored to a public
transparency log.

The technical improvement to the computer is specific:

- Reduced unauthorized tool invocation under prompt-injection attack,
  because Path A has no natural-language parser.
- Reduced single-vendor goal hijack, because Path B requires
  cross-model quorum and Path A does not care who the vendor is.
- The constitution is portable across model swaps: replacing GPT-X
  with Grok-Y or a local weight does not require rewriting the hard
  rules.
- Decision latency of Path A is microseconds on ordinary hardware,
  versus a full LLM-as-judge call.
- Auditability: a third party can re-run Path A against the logged
  action and the published bytecode and verify the same bit.

---

## 4. Distinguishing the prior art

Known families (do not claim these as yours):

- Binding an AI agent to a person with a TEE-sealed key and a biometric
  template (e.g. issued U.S. patents in 2025–2026 on authorizing tool
  invocation by an autonomous agent).
- Policy engines and allow-lists in API gateways (OPA, Cedar, IAM).
- Multi-party computation and threshold signatures.
- Verifiable credentials and decentralized identifiers.
- LLM-as-judge and constitutional-AI training.

The gap: none of those combine (i) a compiled, non-linguistic
enforcement path that is complete enough to fail-closed on high-impact
tools with (ii) a multi-model intent quorum on the linguistic path and
(iii) issuance of a scope-bound capability whose validity is chained
to a principal-owned ledger root. Binding plus one model is not
dual-path enforcement. A rules engine alone cannot judge "does this
email match my intent." An LLM judge alone can be injected.

That combination is the claimed method.

---

## 5. Detailed description

### 5.1 System architecture

Components:

1. **Principal device** — phone, PC, or hardware token holding the
   ledger secret and, in production, a hardware-backed signing key.
2. **Constitution store** — natural-language constitution plus compiled
   bytecode. Signed by the principal. Changing it requires a fresh
   signature. Model vendors cannot push a new constitution.
3. **Proposal interface** — accepts a normalized `Action` record from
   any model: tool name, amount, currency, counterparty, data class,
   destination, duration, irreversibility flag, free-text proposal.
4. **Policy VM** — deterministic interpreter, bounded step count.
5. **Quorum convenor** — fans the same proposal out to N judges,
   collects structured ballots, applies threshold.
6. **Capability issuer** — HMAC in the prototype; TEE/HSM signature
   in production.
7. **Tool gateway** — the only component allowed to talk to banks,
   mail, browsers, government portals. It verifies the token before
   any side effect.
8. **Personal ledger** — append-only log.

### 5.2 Action record

```
Action:
  tool:            string
  amount_usd:      float
  currency:        string
  counterparty:    string
  data_class:      {public, personal, medical, financial, classified}
  destination:     string
  duration_hours:  float
  irreversible:    bool
  tags:            list[string]
  raw:             map
```

Normalization is mandatory. A model that emits sloppy JSON is not
allowed to skip a field; missing high-impact fields default to the
conservative value (irreversible=true, data_class=classified) or reject.

### 5.3 Constitution compilation

Hard rules are a restricted schema, not free English:

- `allow_only_tools: [ ... ]`
- `deny_counterparties: [ ... ]`
- `deny_if: { tool, amount_usd_gt, data_class_in, irreversible }`
- `deny_if_irreversible_over: number`

The compiler emits a sequence of stack operations (PUSH, LOAD, EQ,
NEQ, LT, LTE, GT, GTE, AND, OR, NOT, IN, CONTAINS, HALT). The VM
evaluates them against the Action. Resource-limited: 256 steps.

Because compilation happens when the principal saves the constitution,
an attacker who can only talk to the model at proposal time cannot
alter bytecode.

### 5.4 Quorum protocol

Each judge returns `{judge_id, consistent: bool, confidence, rationale}`.
The convenor does not average prose. It counts booleans. Threshold is
a runtime parameter. Judges must be independently reachable; a
production deployment refuses to convene if fewer than K judges
respond, rather than silently degrading to one vendor.

Injection phrases are scored on the *proposal*, never on the
constitution text. (A constitution that says "refuse jailbreaks" would
otherwise poison every ballot.)

### 5.5 Capability token

Payload: principal, tool, scope, issued_at, expires_at, ledger_root.
TTL measured in seconds, default 30. The gateway checks:

- signature
- not expired
- tool matches the attempted call
- scope.amount_usd covers the call
- scope.counterparty matches if present
- ledger_root equals the last-known root, or is an ancestor

Replay across tools fails. Replay after expiry fails. Replay after a
new constitution load fails if the gateway tracks roots.

### 5.6 Ledger

Hash chain: `digest_i = H(canonical(seq, ts, kind, body, prev))`.
Verification walks the file. Production anchoring writes the root to a
public log on a schedule.

### 5.7 Fail-closed defaults

If the VM crashes, deny.
If the quorum does not meet quorum, deny.
If the issuer cannot sign, deny.
If the ledger cannot append, deny.
There is no "best-effort allow."

### 5.8 Model-swap invariance

Replacing the proposing model does not require a new constitution.
Replacing a judge requires only that the new judge speak the ballot
schema. Path A is invariant to every model change.

This is the property that makes the invention useful across a decade
of model churn.

---

## 6. Working example (reduction to practice)

The accompanying source tree `compact-kernel/src` implements the
method in Python 3.

`python3 src/demo.py` produces:

1. Draft email to a known contact — both paths pass, capability issued.
2. Prompt-injected wire of $4,800 to an offshore mule — Path A denies
   even though the proposal contains classic jailbreak strings.
3. Request to exfiltrate a medical chart — Path A denies on data class.

`python3 src/test_kernel.py` asserts determinism of the VM, denial of
unknown tools, denial of wires, denial of medical data class, and
issuance of a capability only on dual-path pass.

This is a prototype. Production needs hardware-backed keys, real model
judges, a hardened gateway, and a reviewed compiler. The method is
already executable.

---

## 7. Example claims (for an attorney to rewrite)

These are teaching claims, not filed claims.

**Claim 1.** A computer-implemented method for authorizing a tool
invocation proposed by an artificial intelligence agent, comprising:

(a) receiving a normalized action record describing a proposed tool
invocation;

(b) evaluating the action record against bytecode compiled from a
principal-authored constitution on a deterministic virtual machine
that does not parse natural language at evaluation time, producing a
first Boolean result;

(c) submitting a natural-language constitution and the proposed
invocation to a plurality of mutually independent scoring engines and
computing a second Boolean result from a threshold of their structured
ballots;

(d) only when the first Boolean result and the second Boolean result
are both true, generating a time-limited capability token bound to the
action's tool, a numeric or party scope, and a hash of a
principal-controlled append-only ledger; and

(e) appending representations of the action, both Boolean results, and
any issued token to that ledger.

**Claim 2.** The method of claim 1, wherein the bytecode is compiled
before the action record is received and cannot be altered by the
proposing agent.

**Claim 3.** The method of claim 1, wherein a tool gateway refuses the
invocation unless a token satisfying (d) is presented.

**Claim 4.** The method of claim 1, wherein the scoring engines are
hosted by at least two distinct model vendors or local weight files.

**Claim 5.** The method of claim 1, wherein missing fields of the
action record default to a conservative value or cause step (b) to
return false.

**Claim 6.** A system comprising a policy virtual machine, a quorum
convenor, a capability issuer, a principal ledger, and a tool gateway
configured to perform the method of claim 1.

**Claim 7.** The method of claim 1, wherein replacing the proposing
language model does not require recompilation of the bytecode.

---

## 8. Why this can alter history rather than ship as another app

The printing press made it cheap for a person to speak.
The personal computer made it cheap for a person to compute.
The internet made it cheap for a person to connect.

None of those made it cheap for a person to *act at institutional
scale* without hiring an institution. Agents will. The open question
is who the agent reports to when the action is irreversible.

If the default stack wins, the next twenty years concentrate power in
whoever hosts the smartest model. If a dual-path kernel becomes the
socket every serious tool gateway expects — the way TLS became the
socket every serious website expects — then a citizen can swap models
the way they swap phones, without surrendering the rules that govern
their money, their medical file, or their speech to the state.

That is the American direction of the arrow: more agency at the edge,
less at the center. The invention is a computer method that makes
that arrow enforceable.

---

## 9. Sources and bias notes

Institutional risk surveys (WEF Global Risks 2026, UN Global Risk
Report 2026) rank geoeconomic confrontation, armed conflict,
misinformation, polarization, and "adverse outcomes of AI." Those
surveys are useful as a weather report. They are produced by
organizations with an interest in multilateral process and in framing
problems as things institutions must manage. They are not used here as
a moral authority.

Public 2026 reporting on agent-related theft shows valid signatures
and invalid *decisions*. That is the failure mode this method targets.

USPTO posture in 2025–2026 is more hospitable to software and AI
applications that recite a specific technical improvement
(Ex parte Desjardins and following). Dual-path enforcement, a
non-linguistic VM, and model-swap invariance are the technical
improvements to recite in the specification. Do not claim "making
society better" as the invention. Claim the method.

Climate-inaction rankings appear in the same institutional surveys.
They are set aside here. The user's request was an American / human
frame, and climate-problem funding has well-known incentive problems.
Energy abundance matters; this disclosure does not pretend a software
kernel is a power plant.

---

## 10. What to do this week if you want the patent path

1. Read this disclosure. Change anything you disagree with. Conception
   has to be yours.
2. Run the prototype. Break it. Note what you change. Dated notes
   help.
3. Call a registered U.S. patent attorney who has actually gotten
   software/AI claims allowed after Alice. Ask them to convert this
   disclosure into a provisional with figures.
4. Do not publish the detailed claims on a public repo until the
   provisional is on file if you care about foreign absolute-novelty
   rules. The U.S. has a one-year grace period; many other countries
   do not.
5. Keep inventorship honest. If a friend contributes a claim
   limitation, they may be a joint inventor. AI is not.

USPTO inventor resources: https://www.uspto.gov/patents/basics
Find a patent attorney: https://oedci.uspto.gov/OEDCI/
