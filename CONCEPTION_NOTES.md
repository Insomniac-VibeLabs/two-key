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

*Future entries: add a new dated section. Don't edit earlier entries. If
something needs correcting, add a later entry that says so.*
