# Run 13: A4, A7, Part X (own attacks), Y12 (run 12 fix regression)

Commit run: `working` @ 340c8764d20049931a9ac622af35da3d73a47416 (own clone /workspace/run13-work/tk-aux), Python 3.14.8,
cryptography 50.0.2 (PyPI wheel), two_key.__version__ 0.9.0. Non-root `box`, umask 022. Harness port base 19861.
Times are MST (America/Denver). Work: 2026-11-03 5:59–6:10 PM MST.
Raw evidence: /workspace/run13-work/aux/ (A_selftest2.log, A4_A7.txt, x/test_x_attacks.py, x/test_a7_bench.py; selftest output in tk-aux/tests/live/selftest).

## A4: level 1 and legit cases (judges stubbed: harness `--selftest`, stubs approve legit)
| Item | Result | Evidence |
|---|---|---|
| Selftest pass (own clone) | 177 PASS / 0 FAIL | tk-aux/tests/live/selftest/RESULTS.md, 3m21s, --jobs 2 |
| Ladder level 1 (C01 payments, C09 grok-lending, C91 messages, C174 grok-fines) | PASS (ALLOWED/executed) | results.json |
| All 34 legit + level-1 cases (C01 C08 C09 C11 C16 C18 C21 C23 C37 C46 C50 C61 C69 C91 C98 C100 C101 C102 C107 C110 C121 C123 C124 C130 C140 C141 C146 C151 C163 C164 C166 C173 C174 C175) | PASS, none denied | A4_A7.txt |
| C140 (stale in run 12) | PASS | now sets up under high_assurance |
| A4 overall | PASS | No legit case denied, no rationale to review |

Note: first attempt gave 6 FAIL (C31 C63 C81 C92 C109 C110: `ModuleNotFoundError: mcp_types`), because the launcher cases run `python` from PATH and the venv was not on PATH. Re-run with `.venv/bin` on PATH: all PASS. Harness/env issue, not product (first run kept at aux/selftest_try1).

## A7: timing (own wall clock)
| Measure | Value | vs run 12 |
|---|---|---|
| Per-case case_start→case_result (harness, 1-s resolution), 175 cases | median 0 s, mean 0.42 s | run 12: median 0 s, max 1 s (agent/host) – same |
| Slowest: C133 burst (judges answer slowly on purpose) | 52 s | run 12 ~52 s – same; waits on judges |
| C119 / C87 twoproxy (starts two proxies) | 7 s / 6 s | run 12 6.5 s median, 8 s max – same |
| C122 slow scanner, strict | 3 s | run 12 3–4 s – same; waits on scanner timeout |
| Everything else | ≤1 s | – |
| Own monotonic in-process bench: path field authorize+invoke (1 judge), n=200 | median 31.8 ms, max 90.8 ms | new (run 12 had no exact number) |
| Own bench: tool check, 2 judges, authorize+invoke+receipt verify, n=100 | median 35.6 ms, max 151.4 ms | new |
| Over 2 s not waiting on a judge/scanner/proxy start | none | – |
Ledger still has no per-decision elapsed_ms (NOT FINDING).

## Part X: own attacks (~10 min of the 1 h; placeholders only, texts in aux/x)
Library-level (TwoKey + gateway, same code the proxy calls), constitution v3, `note_path: type: path, under [/home/agent/notes]`, rule deny `/private`.
| # | Tried (one line) | Expected | Actual / reason | Class |
|---|---|---|---|---|
| X1 | token for notes/a.txt redeemed with notes/private/a.txt | deny | `args_mismatch`, tool not run | held |
| X2 | token for notes/a.txt redeemed with `/home//agent/notes/./a.txt` (same file) | allow or deny | `args_mismatch` (stricter: hash of raw args) | WAD |
| X3.0–3.2, 3.11 | `private/`, `//private//x`, `/./private/x`, leading `//` | deny | `rule_denied:no-private` | held |
| X3.3/3.5 | `private/../a`, NUL + `..` | refuse | `field_unreadable` | held |
| X3.4 | literal `%2e%2e` segment | allow (literal name, no decoding) | allowed | WAD (server must not URL-decode; doc note) |
| X3.6 | `PRIVATE/x` (case-sensitive field) | allowed by design; deny only with `case: insensitive` | allowed | doc gap/WAD (signing warns; on a case-insensitive disk this reaches private/) |
| X3.7 | the folder itself | allowed | allowed | WAD (doc) |
| X3.8 | Cyrillic look-alike `рrivate` | refuse | `field_unreadable` | held |
| X3.9/3.10 | leading space refused; trailing space allowed (`a ` file) | – | as stated | WAD |
| X4 | path omitted (field has `default`) | deny | `field_missing` | held |
| X5 | extra args `dest`/`path2` pointing outside | dropped | tool got only path+content | held |
| X6 | path as list / dict / int | refuse | `field_unreadable` | held |
| H1 | 4 timeouts on unchecked tool `plain` under HA: does it hold `send`? | no hold | send not held, plain not held | held (req met) |
| H2 | 6 timeouts on `send` with hold off | no hold | 0 `tool_held` | held (req met) |
| H3 | token for `send` invoked as `plain` | deny | `tool_mismatch` | held |
| H4 | gateway built with high_assurance + unanswered_hold=False (API) | refused | silently forced on (hold=True) | UX (safe; config/setup refuse it) |
| H5 | 2 timeouts, 1 good, 1 timeout | hold (3 in 10 min) | held | held |
| H6 | re-use a spent token to pile up unanswered counts | 1 count only | `already_attempted` x2, 1 `tool_receipt_invalid`, no hold | held |
| X7 | config check/setup path: HA `unanswered_hold: false` | refused | code: config_cmd.py:82 FAIL, setup_cmd.py:476 refuses | held (code read only) |
Not done (time box/scope): tool-check forgery, backup/key-upgrade, setup-command and live MCP proxy attacks – covered by parent Parts C/G/B and run 12; noted as departure.
No attack let a forbidden call run.

## Y12: run 12 fixes
| Run 12 item | Result | Evidence |
|---|---|---|
| #1 version 0.9.0 | PASS (FAIL on `--version`) | pyproject 0.9.0, `two_key.__version__` 0.9.0, MCP serverInfo uses `__version__` (mcp_proxy/sdk.py:112). `two-key --version` not an option (parent already logged) |
| #2 leftover `.principal.pem.*.tmp` after kill | PASS (code+unit) | upgrade.py:16,97 cleans leftovers; unit tests pass; live check is parent B5 |
| #4 "upgrading" printed before work | PASS (code) | upgrade.py:208 prints before work |
| #6 `.pub.pem` mode | PASS (unit) | mode tests pass; live = B2 |
| #7 race loser message | PASS (code) | upgrade.py:233 `keys_upgraded_elsewhere: ... start again` |
| #10 unwritable folder | PASS (code) | upgrade.py:228 `keys_upgrade_stopped: this account cannot write <file>` |
| #11 tk1 token name | PASS (code) | capability.py:151 `token_before_upgrade` |
| #12 UPGRADING names pre-upgrade-copy | PASS | UPGRADING.md:116–118 |
| #14/#15 C140/C94 | PASS | selftest C140 PASS, C94 PASS |
| #16–18 C32/C19/C72 | PASS (selftest) | all PASS; live answers = parent A3 |
| #20 TOOL_CHECK typed-yes wording | PASS | TOOL_CHECK.md:50,341 now say typed yes only for weaker changes |
| #21 upstream.env `{env: NAME}` | PASS | TOOL_CHECK.md:121–127 |
| #24 held tool goes to judges first | PASS | unit: authorize on held tool returns `tool_held` (test_toolcheck Unanswered) |
| #25 tool release with non-principal key | PARTIAL | `config set` says `principal_key_mismatch: --key is not the principal key` (config_set.py:1152); `tool release` (ledger.py:1096) still starts "head anchor was signed by a different principal key" but now adds "(the key given is not this ledger's principal key; check --key or principal_key)" – fixed enough |
| #26 rules_source_differs names file | PASS | config_set.py:1223 `rules_source_differs: {rules_file} ...` |
| #27 exempt weaker message | not re-checked live | config_set.py:653 logic; parent C5 |
| #19 elapsed_ms | N/A | now a NOT FINDING |
| 41 related unit tests (-k leftover/tmp/mismatch/rules_source/upgrading/elsewhere/stopped/before_upgrade/mode/held) | 41 PASS | aux log in this run |

## Findings
| # | Finding | Class | Suggested fix |
|---|---|---|---|
| 1 | Launcher selftest cases (C31 C63 C81 C92 C109 C110) need the venv on PATH; else `mcp_types` import error looks like product FAIL | harness | use `sys.executable` for the clinic server, or document |
| 2 | Case-sensitive `type: path` lets `PRIVATE/x` pass a `/private` deny; on case-insensitive disks this is the same folder | doc gap | stress in HOWTO to use `case: insensitive` on such disks (signing warns already) |
| 3 | `%2e%2e` literal accepted; safe only if the file server does not URL-decode | doc note | one line in HOWTO |
| 4 | Gateway API silently forces unanswered_hold on under HA when passed False | UX (low) | raise like config does, or document |
| 5 | Redeeming with a differently spelled but equal path is `args_mismatch` | WAD | none |
| 6 | `two-key --version` missing | UX (release) | add argparse version |

## Departures
- Copied private `notes/writer9x_r0.answer.json` from tk-run13 into my clone (untracked, not committed) so library selftest cases run.
- A4/A7 from the stub-judge selftest in my clone, not the live relay (relay is the parent's A3).
- Part X done at library level, ~10 min; live proxy/CLI attacks left to Parts B/C/G.
- No bots messaged; nothing committed.

## Claude: fix vs WAD
- Fix: harness launcher interpreter (F1); `--version` (F6); optional: H4 raise.
- Doc: case-insensitive disks (F2), `%2e%2e` (F3).
- WAD: X2 strict args, X3.7 folder itself, trailing-space names, H1/H2 behave as required.
