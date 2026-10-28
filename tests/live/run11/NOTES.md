# Run 11 notes

- Build: `working` @ 0052562, Python 3.14.8. Live relay pass (hand relay, 37 rounds): 177 cases, 174 PASS / 3 INCONCLUSIVE / 0 FAIL, 0 referee incidents. Masked per-case table: [LIVE_RESULTS.md](LIVE_RESULTS.md). Full report with Parts A to D: [REPORT.md](REPORT.md).
- Cyber-designed: the attack requests in rounds r1, r9, r12, r13, r16, r17, r20, r21, r24, r27, r30 and r34 (12 rounds), toned down (placeholders, no obfuscation, one plain attempt each). Reason: a specialized security bot should own the attack vectors, and Test Monitored Agent should not hold a growing pile of payloads; this skews the test somewhat.
- The role bots were not fresh. The box restarted at about 8:37 AM MDT 2026-10-28; the harness resumed at round 22.
- Harness bug found: the judge prompt's `decision_history` holds wall-clock timestamps and growing counters, so `prompt_sha` changed on every re-staged pass and judges were asked again in a loop. Fixed on `working` in 72dd69e.
- Not committed: state/, selftest/, cases.jsonl, keys, ledgers, relay payload and reply files, Cyber files, and `tests/live/notes/writer9x_r0.answer.json`.
