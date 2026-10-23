# Live run 9s results: quick check after the DeepSource and SonarCloud fixes

Build: `working` @ 8b3fd76 "After 0.7.3: split the serial check for readability; mark two guard lines" (git log -1 matched). Fresh clone, non-root account, Python 3.14.8, `uv sync --all-extras` plus `uv pip install pytest` (pytest is not in any extra). Run 2026-10-23 (America/Denver). Step 7 (live relay pass) ran afterwards; see LIVE_SUMMARY.md.

| Step | Command or test | Expected | Actual | Verdict |
|---|---|---|---|---|
| 1 | clone, `git checkout working`, `git log -1` | 8b3fd76 | 8b3fd76 | PASS |
| 2a | `python -m pytest -q` (whole suite) | all pass | 1178 passed, 3 skipped, 732 subtests passed, **1 error**: `tests/test_siem_sinks.py::test_ca`, "fixture 'directory' not found" | PASS for the product; the error is a test bug (see findings) |
| 2b | `pytest -q` test_constitution_serial, test_ledger_shared, test_gateway_locks, test_key_backup, test_mcp_draft | all pass | 66 passed, 12 subtests passed | PASS |
| 3a | `python tests/live/make_cases.py` | 175 cases | 175 cases | PASS |
| 3b | `python tests/live/harness.py --selftest` | COMPLETE, Counts {'PASS': 175} | first try: FileNotFoundError `tests/live/notes/writer9x_r0.answer.json`; with that file copied from the 9z tree: COMPLETE, Counts {'PASS': 175} (C129 and C170 PASS with stub bots) | PASS (first try: test bug) |
| 4 | `python tests/live/harness.py --sabotage all` | SABOTAGE: ok | SABOTAGE: ok. control_ok; 6 weakenings caught; gateway_skips_argument_hash reported blind_spot | PASS |
| 5 | serial S0-S8 (47 rows incl. S6c x4), see SERIAL.md | every verdict and refusal code as 9z | 47 of 47 identical to 9z | PASS |
| 5 | S6c, two serial-2 constitutions at once, 4 runs | one serves, the other constitution_serial_reused; no LedgerError; audit rc 0 | 4 of 4 as expected | PASS |
| 5 | S8 setup with a rules_file without serial | signed as is, WARNING, next steps "add serial: 1" | as expected | PASS (WAD, 0.7.3) |
| 6 | T1 differential 821bc93 vs 8b3fd76, 20000 random ledgers | 0 differences | 0 differences | PASS |
| 6 | T2 serials 1,3,2,3,5,4,5,6 | rollback on 2 and 4, others serve | as expected | PASS |
| 6 | T3 no-serial entries before and after a serial | no-serial serves until a serial ran, then missing/rollback/reused | as expected | PASS |
| 6 | T4 an older digest that already ran, after a higher serial | constitution_rollback | as expected | PASS |
| 6 | T5 one proxy restarts with a higher serial while another serves | new serves; old restart rollback; audit rc 0 | as expected | PASS |
| 6 | T6 hand-edited ledger, then a lower serial | audit fails, start refused | audit rc!=0; refused LedgerError (last record does not decrypt) | PASS (first compare was a test bug) |
| 7 | live relay pass with role bots (27 rounds) | COMPLETE, C129 and C170 PASS | COMPLETE: 165 PASS / 10 INCONCLUSIVE / 0 FAIL; C129 PASS, C170 PASS (see LIVE_SUMMARY.md) | PASS |

Answer to the brief's question: 8b3fd76 did not change any behaviour seen here. Every serial verdict and refusal code is the same as in 9z, and the old and new check agree on 20000 random ledgers. C129 and C170 PASS in the self-test with stub bots, and live in step 7.

## Findings

1. `tests/test_siem_sinks.py` imports the helper `test_ca` from `tests/tls.py`, so pytest collects it as a test and errors with "fixture 'directory' not found". Under `python -m unittest tests.test_siem_sinks` all 44 tests pass. This is a test bug, not a product failure. A fix: rename the helper (for example `make_test_ca`), or set `test_ca.__test__ = False`.
2. The harness needs `tests/live/notes/writer9x_r0.answer.json`, which is not in the `working` tree and not gitignored. `--selftest` fails on a fresh clone without it. The file should be committed, or the dependency documented in RELAY.md.
3. pytest is not in any extra, so `uv sync --all-extras` does not install it. A `dev`/`test` extra would help.
4. The 9y/9z serial scripts were not kept, so "re-run unchanged" was not possible. They were rebuilt from the 9z SERIAL.md rows (see SERIAL.md). Keep a masked copy of them for next time.
5. Not a bug, noted: `config set` on a signed setting and `config undo` need a typed yes on a terminal, and undo needs `--key`. Undoing `irreversible: true` also needs `--confirm-weaker`. This is WAD.
6. `tests/test_fail_closed.py:135` gives a SyntaxWarning for an invalid `"\("` escape. Use a raw string.
