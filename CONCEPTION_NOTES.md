# Conception Notes

This file records, verbatim and dated, statements of conception by the
human inventor. Engineering work by the AI assistant is recorded
separately in `CHANGES.md` and in git history. It is not conception.

---

## Entry 1

- **Attributed to:** Stephan Busch
- **Date/time:** 2026-09-30, about 4:03 AM Mountain Time (MDT, UTC-6)
- **How it was captured:** Stephan typed it in a chat with his AI assistant.
  The assistant copied it here word for word, with no edits to spelling,
  grammar, or punctuation.
- **Context:** Given after reviewing the Two-Key invention disclosure
  package (`docs/INVENTION_DISCLOSURE.md`, disclosure date 30 September 2026).

> "To elaborate on the intent (beyond what was already identified) is to have a user able to upload a human language constitution. Then (Path B) the AI judge/judges be connected to whichever AI (local or vendor) the user desires (api or username/password or single sign on login). Path A I assume is self explanatory. Both path A and B need to agree to let the action occur."

### How this entry maps to the implementation (assistant's note, not conception)

| Concept in the entry | Where implemented |
|---|---|
| User uploads a human-language constitution | `two_key/constitution.py`, CLI `sign-constitution` / `verify-constitution` |
| Path B judges connected to any AI the user picks (local or vendor) | `two_key/judges/` (OpenAI-compatible, Anthropic, Gemini, Ollama), `examples/judges.yaml` |
| Auth by API key, username/password, or single sign-on | `two_key/judges/credentials.py` (API key works now; username/password and SSO/OAuth are interfaces with documented stubs) |
| Both Path A and Path B must agree before the action occurs | `two_key/core.py` `TwoKey.authorize` |

---

## Entry 2

- **Attributed to:** Stephan Busch
- **Date/time:** 2026-09-30, about 7:02 AM Mountain Time (MDT, UTC-6)
- **How it was captured:** Stephan's selection was relayed to the AI
  engineering assistant through his patent-attorney assistant (another AI
  agent). The quoted text is reproduced word for word as relayed.
- **Context:** Given after reviewing the patent-attorney agent's prior-art
  triage (`PRIOR_ART.md`, kept outside this repository), §4 "Suggested
  narrower claim directions", and the related action-record normalization
  question.

> "A, B, C, and F all together"

### What the selection refers to (as relayed; assistant's note, not conception)

| Letter | Refers to | Source |
|---|---|---|
| A | Ledger-root-bound token | `PRIOR_ART.md` §4 direction (i) |
| B | One signed constitution, two compilations | `PRIOR_ART.md` §4 direction (ii) |
| C | Quorum protocol specifics | `PRIOR_ART.md` §4 direction (iii) |
| F | The action-record normalization problem (who produces the fields Path A reads) | `DESIGN_OPTIONS.md` §1; `PRIOR_ART.md` §3 |

This entry records a *selection* among directions that the attorney agent
proposed. The directions' wording comes from `PRIOR_ART.md`, which is an
AI-prepared document; this entry does not attribute that wording to Stephan.
For F, the selection identifies the problem; no solution option has been
chosen or implemented.

---

## Entry 3

- **Attributed to:** Stephan Busch
- **Date/time:** 2026-09-30, about 7:39 PM Mountain Time (MDT, UTC-6)
- **How it was captured:** relayed to the AI engineering assistant by the
  agent coordinating the work. The instruction is recorded as relayed, in
  substance; it is not a verbatim quote.
- **What was decided:** Stephan named the product "Two-Key".

### How this entry maps to the implementation (assistant's note, not conception)

The product name in prose is "Two-Key"; the repository, the distribution,
and the CLI are `two-key`; the Python package is `two_key` (the main class
is `TwoKey`, in `two_key/core.py`); the constitution rules block is
`twokey-rules`; example DIDs use `did:twokey:`. `docs/INVENTION_DISCLOSURE.md`
and the original invention-package zip are unchanged, because they are the
dated original invention record. The rename changes no mechanism. (Wording
updated per Entry 6.)

---

## Entry 4

- **Attributed to:** Stephan Busch
- **Date/time:** 2026-09-30, about 8:01 PM Mountain Time (MDT, UTC-6);
  clarification about 8:02 PM MDT; further context about 8:07 PM MDT
- **How it was captured:** the 8:01 and 8:02 PM statements were relayed to
  the AI engineering assistant by Stephan's patent-attorney assistant
  (another AI agent); the 8:07 PM statement was said directly to Programer.
  All three quotes are reproduced word for word as relayed, including
  spelling and punctuation.
- **Context:** Stephan's approach to problem F (action-record normalization:
  the gap where a lying or injected agent misstates the action it will take;
  `DESIGN_OPTIONS.md` §1, Entry 2).

> "Would Two-key asking for a hash (string converted to hash) of the agent's proposed throught process before it takes an action and then comparing Two-Key running the same algorithm to hash the instructions solve this securely? I think it would have to be ran twice; once to hash the proposed actions/thought process and once to hash the actual actions/thought process taken by the agent."

Clarification (about 8:02 PM MDT, relayed):

> "Yes, I thought that's how I explained it, maybe I wasn't clear."

Further context (about 8:07 PM MDT; said by Stephan directly to Programer,
the engineering agent coordinating this work, and passed on word for word):

> "Well, that's the whole point of a constitution and separate agent (local or service) that acts as a judge…so see if the proposed action is allowed by the constitution. Or is my logical flawed somewhere. The agent being controlled should not be the same agent as running the judges."

### What the clarification confirmed (as relayed; assistant's note, not conception)

As relayed, the clarification confirmed this reading: Two-Key itself
computes the second ("actual") hash, with the same algorithm, from the
action it intercepts, rather than the agent supplying it. The first
("proposed") hash covers the agent's proposed actions or thought process and
is submitted before the agent acts; the two hashes are then compared.

A security review of exactly this idea is in `F_REVIEW.md`. That review is
an AI-prepared analysis, not part of the conception. No option for F has
been implemented.

## Entry 5

- **Attributed to:** Stephan Busch
- **Date/time:** 2026-09-30, about 8:13 PM Mountain Time (MDT, UTC-6);
  further statements at 8:17 PM, 8:19 PM, and 8:22 PM MDT
- **How it was captured:** relayed word for word to the AI engineering
  assistant in the task instructions from Programer, the engineering agent
  coordinating this work. The quotes are reproduced exactly as relayed,
  including spelling and punctuation.
- **Context:** content scanning (data-loss prevention and antivirus) of what
  agents send through Two-Key, for example file uploads.

About 8:13 PM MDT:

> "Well, if we're talking about file uploads, that's more the function of some sort of DLP software. Do you think Two-key should have some form of integrated DLP solution that scans, parses, OCRs, and/or filters files through an agent (serious performance overhead) or let a third party software take care of it as Two-Key is more of a agent custodial standard? Or…if you concur it's a better idea…find a way a third party DLP solution can hook into Two-key to scan files agents are sending."

8:17 PM MDT:

> "What are the pros and cons of each DLP handling option (allowing them to inject)?  I'm thinking API is the best, but want to compare."

8:19 PM MDT:

> "Yeah, offer all three; so it's vendor and version agnostic."

8:22 PM MDT:

> "All 5 should be options; but none required (as there may not be a DLP software in place)."

> "Also, make the same type of availability for antivirus scanning; insure malicious scripts can't be injected either (not sure if AMSI is the right answer here, as the agent isn't running the script)."

### What the AI assistant said in between (assistant's statements, not conception)

These are the AI assistant's contributions to the exchange, recorded as
context. They are not Stephan's conception.

- The assistant presented five hook types for third-party scanners:
  1. a vendor API (REST or gRPC);
  2. ICAP;
  3. an in-process or local plugin;
  4. a sidecar or local daemon reached over a local socket;
  5. asynchronous post-send scanning by webhook or storage-event callback.
     This only flags a problem after the fact, unless the payload is held
     until the verdict arrives.
- The assistant agreed with Stephan's direction that third-party DLP should
  hook into Two-Key rather than be built in.
- The assistant noted that the gateway passing the actual intercepted
  content lets the scan verdict replace the agent's self-label.
- The assistant noted that AMSI is a Windows interface that script engines
  call before running a script. It doesn't fit, because Two-Key doesn't run
  scripts. Content scanning at the gateway fits instead, with AMSI possibly
  one optional Windows local plugin.

The implementation of these hooks (`two_key/scanning.py`,
`docs/SCANNING_HOOKS.md`) is AI-prepared engineering. Settings that Stephan
has not decided ship with placeholder defaults, and those questions are
listed as open in `docs/SCANNING_HOOKS.md`.

## Entry 6

- **Attributed to:** Stephan Busch
- **Date/time:** 2026-09-30, about 9:49 PM Mountain Time (MDT, UTC-6)
- **How it was captured:** relayed word for word to the AI engineering
  assistant in the task instructions from Programer, the engineering agent
  coordinating this work. The quote is reproduced exactly as relayed,
  including spelling, punctuation, quotation marks, and ellipses.
- **Context:** Stephan's decisions on the open content-scanning questions
  from Entry 5, and his authorization to finish the rename.

> "The timeout option should be configurable (both time in seconds to wait and action taken…default should be deny but with the optional configuration to be changed to allow.)
>
> As far override; fail to the most restrictive (either two-key or DLP/AV…if one denies/blocks…the action is block).
>
> Scanners get the exact bytes and strings (for malicious script detection) sent.
>
> As far as ‘CompactKernel’; yes modify it so it reflects ‘two-key’ in all places and references; but in a way the code doesn’t break at all."

### What this entry resolves and changes (assistant's note, not conception)

- **Open questions resolved.** This resolves open questions (a), (b), and
  (c) from Entry 5 and `docs/SCANNING_HOOKS.md`:
  - (a) a scan timeout: both the wait in seconds and the action taken are
    configurable, and the action defaults to deny/block;
  - (b) Two-Key and the DLP/AV verdicts combine by "most restrictive": if
    either denies or blocks, the action is blocked;
  - (c) scanners receive the exact bytes sent and the decoded strings.
- **Rename authorization.** The last paragraph authorizes the rename "in all
  places and references". Per that authorization, the non-quote wording of
  earlier entries that still used the former name was updated.
  `docs/INVENTION_DISCLOSURE.md` and the original invention-package zip are
  not changed. Stephan's verbatim quotes are not changed; this entry's quote
  keeps the former name because it is verbatim. The changes, with the
  original text preserved here for the record:
  - **Entry 3, "What was decided".** Original:
    > Stephan renamed the product from "Compact Kernel" to "Two-Key".

    Now:
    > Stephan named the product "Two-Key".
  - **Entry 3, implementation note.** Original:
    > (the class formerly `CompactKernel` is `TwoKey`, in `two_key/core.py`)
    > [...] Entries 1 and 2, `docs/INVENTION_DISCLOSURE.md`, the original
    > invention-package zip, and earlier `CHANGES.md` rows keep the former
    > name, because they are historical records.

    Now:
    > (the main class is `TwoKey`, in `two_key/core.py`) [...]
    > `docs/INVENTION_DISCLOSURE.md` and the original invention-package zip
    > are unchanged, because they are the dated original invention record.
    > [...] (Wording updated per Entry 6.)
  - **Entry 1, "Context".** "the Compact Kernel invention disclosure package"
    became "the Two-Key invention disclosure package".
  - **Entry 1, implementation table.** The paths `compact_kernel/constitution.py`,
    `compact_kernel/judges/`, `compact_kernel/judges/credentials.py`, and
    `compact_kernel/kernel.py` `CompactKernel.authorize` became
    `two_key/constitution.py`, `two_key/judges/`,
    `two_key/judges/credentials.py`, and `two_key/core.py` `TwoKey.authorize`
    (the current, working paths).
- **CHANGES.md.** Rows 3, 59, 78, 79, and 81 were updated the same way
  (`CHANGES.md` row 85). The earlier wording is in git history at commit
  97dedbd.

## Entry 7

- **Attributed to:** Stephan Busch
- **Date/time:** 2026-09-30, about 10:16 PM Mountain Time (MDT, UTC-6)
- **How it was captured:** relayed word for word to the AI engineering
  assistant in the task instructions from Programer, the engineering agent
  coordinating this work. The quote is reproduced exactly as relayed,
  including spelling, punctuation, spacing, and the apostrophe.
- **Context:** Stephan's answers to the content-scanning questions left open
  after Entry 6 (scanner errors, run order, holding for the verdict,
  data-class disagreement), plus a new statement about inbound content.

> "Scanner error should be logged in the ledger and treated like a timeout.
>
> Which is faster, running multiple scanners at once or one after the other?  Whichever is more optimized, choose that.
>
> Always hold a file until verdict is returned (then based on verdict take appropriate action) or the timeout limit is reached.
>
> Don’t worry about disagreement; if one (two-key or DLP or AV) convicts (would deny) then default to deny.
>
> Scans should be done before files are sent.  Likewise, they should be done before files are received or processed."

### Assistant's note (not conception)

- **Run order.** Stephan asked which is faster and delegated the choice
  ("Whichever is more optimized, choose that."). The assistant answered that
  running the scanners at the same time (parallel) is faster: the wait is
  about as long as the slowest scanner, not the sum of all of them. Because
  any deny decides the call (most restrictive wins, Entry 6), the order
  doesn't change the outcome. So parallel was selected, per his delegation.
  Running one after the other (sequential) remains available as an option.
- **How the statements are implemented** is AI-prepared engineering,
  described in `docs/SCANNING_HOOKS.md` and `CHANGES.md` row 86.

## Entry 8

- **Attributed to:** Stephan Busch
- **Date/time:** 2026-09-30, about 10:17 PM Mountain Time (MDT, UTC-6)
- **How it was captured:** relayed word for word to the AI engineering
  assistant in the task instructions from Programer, the engineering agent
  coordinating this work. The quote is reproduced exactly as relayed.
- **Context:** Stephan's answer to whether the original wording should be
  restored in Entries 1 and 3 and in `CHANGES.md` rows 3, 59, 78, 79, and 81,
  which were edited for the rename.

> "Keep as is, but document that I told you to change those things due to better naming conventions."

### Assistant's note (not conception)

- Stephan directed the edits to the non-quote wording of Entries 1 and 3
  and of `CHANGES.md` rows 3, 59, 78, 79, and 81, for better naming
  conventions. His instruction is recorded verbatim in Entry 6 (2026-09-30,
  about 9:49 PM MT): "yes modify it so it reflects ‘two-key’ in all
  places and references".
- The original wording is preserved in Entry 6 (Entries 1 and 3) and in git
  commit 97dedbd (all of them).
- The patent lawyer advised against editing earlier entries. Stephan chose
  to keep the edited wording ("Keep as is"). Nothing was reverted.
- From Entry 7 on, earlier entries and earlier `CHANGES.md` rows are not
  edited; new information is only appended.

## Entry 9

- **Attributed to:** Stephan Busch
- **Date/time:** 2026-09-30, about 10:26 PM Mountain Time (MDT, UTC-6); the
  question quoted as context was asked at about 10:20 PM MT.
- **How it was captured:** relayed word for word to the AI engineering
  assistant in the task instructions from Programer, the engineering agent
  coordinating this work. The quotes are reproduced exactly as relayed,
  including spelling, spacing, quotation marks, and apostrophes.
- **Context:** Stephan's question about the ledger (about 10:20 PM MT):

> "Just to be clear, the ‘ledger’ is a cryptographic ledger like a blockchain right?  Where it’s auditable and nonreputable?
>
> If so, I think it’s currently locally stored; is that true?"

### Assistant's answer to that question (not conception)

- The ledger is a cryptographic ledger, but not a blockchain. It is a hash
  chain of entries plus a Merkle tree over them, with a head signed by the
  principal's key. Tampering with, reordering, or truncating entries is
  detectable against a signed head, which makes it auditable.
- Yes, it is stored locally: one file per principal, with its signed head
  next to it.
- Non-repudiation needs external anchoring. The principal holds the signing
  key, so the principal could rewrite the history and sign a new head unless
  earlier heads were published somewhere the principal doesn't control.
- `two_key/anchoring.py` had only two anchors, `NullAnchor` and
  `LocalFileAnchor`. Neither publishes anything outside the machine.

### Stephan's statement (about 10:26 PM MT)

> "I think locally is fine for personal use.  However, I think for enterprise use, an enterprise level (not fully public) blockchain would be the best for this.  If you concur, create the option.  Tie the configuration to a whether or not it’s being used for personal use or for an enterprise (likely need to be an early on configuration setting/global variable to denote ‘personal’ or ‘enterprise’ use; as many other settings will likely need to be addressed based on the use case.)"

### Assistant's note (not conception)

- The assistant concurred. It cautioned that a permissioned chain adds
  non-repudiation only if its nodes, and the organizations that endorse
  transactions, are run by parties who are not all under one
  administrator. If one administrator controls every node, that
  administrator can rewrite the chain too.
- The implementation (the `deployment_mode` setting, a permissioned-ledger
  anchor interface, and a Hyperledger Fabric adapter) is AI-prepared
  engineering. It is described in `docs/DEPLOYMENT_MODES.md` and
  `CHANGES.md` row 88. Settings he has not decided are listed there as
  open questions.

## Entry 10

- **Attributed to:** Stephan Busch
- **Date/time:** 2026-09-30, 10:30 PM Mountain Time (MDT, UTC-6)
- **How it was captured:** relayed by Stephan's patent-attorney agent, and
  passed on to the AI engineering assistant by Programer, the engineering
  agent coordinating this work. The quote is reproduced exactly as relayed.
- **Nature:** **an approval of routine bug fixes, not conception.** Stephan
  approved fixing defects found in the existing code (F_REVIEW.md §8,
  findings 1–3: the gateway's hash-then-execute gap, the non-injective
  canonical encoding, and unescaped judge-prompt delimiters). This entry
  records his approval and his condition. It does not record an inventive
  contribution.

### Stephan's words (10:30 PM MT, relayed by the patent-attorney agent)

> "A, but ensure quantum resistance and fips 140-3 compliance where applicable."

### Assistant's note (not conception)

- According to the relaying instruction, "A" means approving the three
  F_REVIEW bug fixes. The text of the options he was choosing between was
  not relayed to the engineering assistant.
- The fixes, and how his condition was applied, are AI-prepared
  engineering:
  - hashes and MACs use FIPS-approved algorithms with a quantum margin
    (SHA-384, HMAC-SHA-384, keys of at least 256 bits) by default in every
    profile;
  - the hybrid ML-DSA-65 signatures are kept;
  - everything goes through the existing crypto provider and its self-test;
  - older artifacts are versioned and still verify.
- The documentation wording is "FIPS-approved algorithms, validated module
  required for compliance". No validation is claimed.
- Details are in `CHANGES.md` row 89, `docs/CRYPTO.md` §3, and
  `F_REVIEW.md` §12.

---

*Future entries: add a new dated section. Don't edit earlier entries. If
something needs correcting, add a later entry that says so.*
