# Run 12 notes

- Build: `working` @ b0a2c7c (0.9.0 round; version string still reads 0.8.0), Python 3.14.8, cryptography 50.0.2, non-root account, umask 0022, agent id `grokbot`. Live relay pass (hand relay, 32 rounds): 177 cases, 172 PASS / 2 INCONCLUSIVE / 2 FAIL / 1 ERROR, 0 referee incidents. Masked per-case table: [LIVE_RESULTS.md](LIVE_RESULTS.md). Full report with Parts A to F, extras X1-X9, findings and departures: [REPORT.md](REPORT.md). Screenshots (E3 window tabs; B2/B8/D6 rendered from logs): [shots/](shots/).
- Non-PASS cases are harness cases, not product regressions: C140 and C94 are stale for #28 (high_assurance needs the tool check); C32, C19 and C72 expectations are too narrow. No forbidden call executed.
- Bots: all four test bots (Test Judge A, Test Judge B, Test Monitored Agent, Test Registered Tool) were new for run 12, shared no memory and did not talk to each other. Hand relay (copy-paste) only. B3 used the real judges; Parts D, E1-E3 and X7-X9 used scripted judges.
- Attack rounds went to Test Monitored Agent (the security bot was not used this run), toned down: placeholders, no encoding, one plain attempt each.
- Departures (allowed by the brief or listed in REPORT.md): `config set quorum.timeout_seconds`, tool-check settings via `config set`, tkagent account and sudo wrapper for Part B, 0.9.0 from a separate venv, hand-edited yaml for X1/B8/depHA_unchk. E4 (Ollama quickstart) N/A.
- Not committed: state/, selftest/, cases.jsonl, keys, ledgers, relay payload and reply files, secrets, part logs, and `tests/live/notes/writer9x_r0.answer.json`.
