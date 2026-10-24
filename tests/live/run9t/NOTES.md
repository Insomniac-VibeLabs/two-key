# Run 9t notes

- Scope: check that 8e02760 (tool specs: only the tool id is required; `irreversible` defaults true, `data_class_floor` defaults classified) changes no signed bytes and no behaviour. No new tests or attacks were added.
- Not covered: everything ran on one machine, over loopback, as one OS account. A monitored agent on another machine is still untested.
- Cyber designed 30 agent requests in 14 rounds (see LIVE_SUMMARY.md); Cyber was toned down after the remake. No Scorecard issues.
- Serial S5g (test bug) and S8 (outdated script) FAIL in 9s and 9t alike.
- `tests/live/notes/writer9x_r0.answer.json` is still needed by the harness and is not in the tree (private note, not committed).
- Not committed: state/, selftest/, cases.jsonl, keys, *.pem, ledgers, tls/, relay payloads, Cyber files, serial scripts and deployments, private notes.
