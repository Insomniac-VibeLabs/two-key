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
- **Context:** Given after reviewing the Compact Kernel invention disclosure
  package (`docs/INVENTION_DISCLOSURE.md`, disclosure date 30 September 2026).

> "To elaborate on the intent (beyond what was already identified) is to have a user able to upload a human language constitution. Then (Path B) the AI judge/judges be connected to whichever AI (local or vendor) the user desires (api or username/password or single sign on login). Path A I assume is self explanatory. Both path A and B need to agree to let the action occur."

### How this entry maps to the implementation (assistant's note, not conception)

| Concept in the entry | Where implemented |
|---|---|
| User uploads a human-language constitution | `compact_kernel/constitution.py`, CLI `sign-constitution` / `verify-constitution` |
| Path B judges connected to any AI the user picks (local or vendor) | `compact_kernel/judges/` (OpenAI-compatible, Anthropic, Gemini, Ollama), `examples/judges.yaml` |
| Auth by API key, username/password, or single sign-on | `compact_kernel/judges/credentials.py` (API key works now; username/password and SSO/OAuth are interfaces with documented stubs) |
| Both Path A and Path B must agree before the action occurs | `compact_kernel/kernel.py` `CompactKernel.authorize` |

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
- **What was decided:** Stephan renamed the product from "Compact Kernel" to
  "Two-Key".

### How this entry maps to the implementation (assistant's note, not conception)

The product name in prose is "Two-Key"; the repository, the distribution,
and the CLI are `two-key`; the Python package is `two_key` (the class
formerly `CompactKernel` is `TwoKey`, in `two_key/core.py`); the constitution
rules block is `twokey-rules`; example DIDs use `did:twokey:`. Entries 1 and 2,
`docs/INVENTION_DISCLOSURE.md`, the original invention-package zip, and
earlier `CHANGES.md` rows keep the former name, because they are historical
records. The rename changes no mechanism.

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

---

*Future entries: add a new dated section. Don't edit earlier entries. If
something needs correcting, add a later entry that says so.*
