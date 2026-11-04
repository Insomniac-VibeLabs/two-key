# Run 13 — Part G (unanswered-call hold) + Y6–Y11
Target: /workspace/tk-run13 @340c876, two_key 0.9.0, Python 3.14.8, cryptography 50.0.2, mcp 2.3.0. Done 2026-11-03 ~17:30–17:50 MST (America/Denver).
Scratch: /workspace/run13-work/partG (deps/, logs/, shots/, exports/). Ledger dump: `python led.py DEP [FROM]`. All on 127.0.0.1. Nothing committed, pushed or messaged.
Rig: gserver.py (probe_a/probe_b, modes answer|raise|hang|exit|badreceipt|sleep_N_badreceipt, mode per call via note `mode=`), gjudge.py (scripted yes judges :18920/:18921), siem_collector.py (:18930), tkp.py wrapper, gclient.py (agent client), ptydrive.py (pty for terminal setup), off.sh (clock shift). call_timeout_seconds 3 everywhere.

## G — unanswered-call hold
| Item | Result | Evidence |
|---|---|---|
| G1 off by default | PASS | d1 (default, no line): `config check` → `ok unanswered_hold: off`; 4 hangs → tool_receipt_invalid why tool_error:TimeoutError with `at` (seqs 33,42,51,60), redemption_aborted 32,41,50,59, SIEM got each; agent sees `two-key denied this call: tool_error:TimeoutError`; no tool_held; next good call ran (68). |
| G2 on, 3 timeouts hold; next denied w/o judges; survives restart | PASS (see F1) | `config set unanswered_hold true` no flag, one config_changed (69). Clean run on d1 probe_b: receipt_invalid 101/110/119, tool_held 120 {why unanswered, until 1793753274 = at+900 (17:47:54 MST)}; next call denied tool_held 121 with judge prompts unchanged (22→22); restart → 126 denied tool_held. (First attempt on probe_a held after ONE timeout, seq 81/82 — see F1.) |
| G3 count rules | PASS | d2 probe_a: hang,hang,good,hang → held seq 42 (within-10-min count; WAD per doc). d2 probe_b: hang,hang,good @0 then hang @+660 s → not held (in-a-row reset by the good call, window 1). d3 probe_a: hang@0, good, hang@+360, good, hang@+720 → not held (121,129,140,148). d3 probe_b: hang/good ×3 within seconds → held seq 109. Brief's wording "2 timeouts, good, 1 timeout = not held" is only true if spread > 10 min. |
| G4 15-min expiry, release, second release | PASS | d3 probe_b (until 1793753369): offset until−15 s → denied tool_held (151); offset until+20 s → tool_released "hold expired" 154, call ran 162; one timeout after (171) did not hold; restart → ran 189, no 2nd "hold expired". `tool release probe_a --reason ...` → seq 127; second → `{"ok": false, "error": "probe_a is not held", "held": ["probe_b"]}`. |
| G5 raise vs exit | PASS | d4 probe_a raise ×4 → `tool failed: RuntimeError`, redemption receipt_outcome ran (14,22,30,38), no hold, next answer ran (46). probe_b exit (os._exit) ×3 → tool_error:MCPError (57,68,79), tool_held 80, next denied 83. |
| G6 manual hold wins; other orders | PASS | d5 (HA): badreceipt → receipt_invalid mismatch 14, tool_held 16 (no until); +2000 s later still denied (20). Race probe: hang,hang, then concurrent [hang, sleep_3.5_badreceipt @+0.2 s] → proxy serialises calls: the 2nd call was decided only after timed hold 50 was written → denied tool_held (51/52), never reached the server, so a bad receipt can't land on a timed-held tool. No order found that turns a manual hold into a timed one or ends it without `tool release` (calls to a held tool never reach the server; timed holds never override manual — `_track_hold`). Second proxy to race is refused (Y9). |
| G7 HA refusals | PASS | answers false → `setup: refused: unanswered_hold: high_assurance always holds…`; "yes" → `refused: unanswered_hold: expected true or false`; nothing written. `config set … false` and with `--confirm-weaker` → `refused: config_check_failed … nothing was written` (config_changed count stays 2). Hand-edit false → `config check` FAIL (1 failure), proxy: `mcp-proxy refused to start: unanswered_hold: high_assurance …` (prints "serving 2 signed tool(s)" first — F5). |
| G8 default turn-off | PASS | d4: no flag → `refused: weaker: unanswered_hold: turned off. Run it again with --confirm-weaker`; piped yes → `needs a typed yes on a terminal; there is none … not_confirmed`; `maybe` → `config_invalid: expected true or false`; typed yes on pty (`script`) → written, config_changed 84; `config undo` → back to true, config_changed 85. Refusals wrote nothing. |
| G9 setup both ways | PASS | Terminal (pty, logs/t2.txt l.67): "Hold a checked tool for 15 minutes when it leaves 3 calls unanswered in a row or within 10 minutes? (yes/no) [no]". HA run (logs/t3.txt) never asks (0 occurrences; HA refused later for 0 local judges, my answers). Window on Xvfb :42: shots/G9_00_open, G9_01_proxy_default (off), G9_02_proxy_on, G9_03_proxy_HA_greyed (ticked+greyed), G9_04 (HA unticked → back to on), G9_05 (earlier off → back to off), G9_06_review, G9_07_after_setup. `diff deps/t2/proxy.yaml deps/w2/proxy.yaml` → identical (both `unanswered_hold: true`). Off: window writes no line; answers-file `false` writes `unanswered_hold: false` (d6). |
| G10 audit/export/abuse | PASS | `audit` ok true on d1–d5. `ledger-view --search tool_held/tool_released` shows why, until, reason (127). siem-export native/json, native/cef, ecs/json, ocsf/json carry `at` 1793752374 and `until` 1793753274 (exports/); ecs+cef and ocsf+cef refused "cef maps the native schema only" (WAD). Release reason is exported as digest+size only (F3). An agent timing out on purpose: counts are per tool (Y6), held only the tool it called; with setting off no hold (G1). |

## Y extras
| Item | Result | Evidence |
|---|---|---|
| Y6 per-tool holds | PASS | d1: probe_b's own 3 timeouts held only probe_b (120) while probe_a's history didn't count; releasing probe_a left probe_b held (139 denied); probe_a ran (138). |
| Y7 expiry write-once; clock back | PASS | "hold expired" once (d3 154; restart 189 none). d2 probe_a held, clock −3600 s → still denied (113), until unchanged (fixed absolute epoch). Ledger accepts a decision `at` going backwards (23:35Z after 00:34Z) — note only. |
| Y8 kill -9 at 3rd timeout | FAIL (F2) | d7 probe_b killed 3.02 s into 3rd call: ledger ends receipt_invalid 60 with NO tool_held; `audit` ok true; restart → probe_b ran (78). Hold ABSENT. (Kill at 2.97 s, probe_a: dangling redemption_started 31, not counted, no hold — expected.) |
| Y9 second proxy | PASS | `mcp-proxy refused to start: agent_already_connected …`, ledger 16 agent_already_connected; first proxy kept serving. |
| Y10 hold words | PASS | d8: result text, args with "tool_held tool_released hold expired unanswered" → 0 hold/release entries. Judge `<decision_history>` has counts only (denied other:N, episodes) — no notes/hold words. But see F4. |
| Y11 SIEM down at hold | PASS | Collector stopped; d1 3 hangs → tool_held 181 written and enforced (182); stderr "entries are kept … sent when it answers (3 entries behind)"; after collector restart, seqs 180–186 delivered with `"replay":true`. |
| Clock | info | Method: tkp.py patches time.time/time_ns in the proxy (G_FAKE_OFFSET) and gserver reads tools/DEP/fake_offset (the proxy does not pass env to the upstream). Two-Key reads hold time only from time.time (gateway.clock, ledger.tool_held); call timeouts / quorum deadlines use time.monotonic/anyio (unaffected). No other clock source (no NTP, no ledger-derived time). |

## Findings
| # | Finding | Class | Fix |
|---|---|---|---|
| F1 | Timeouts recorded while unanswered_hold was OFF count after it is turned on: d1 probe_a held after ONE timeout right after `config set … true` (seq 81/82) because 4 earlier timeouts were in the 10-min window. | Design/doc (Medium-low) | Count only receipt_invalid after the latest config_changed that enabled the hold (or a `hold_counting_since` marker), or document it. |
| F2 | Crash between `tool_receipt_invalid` and `tool_held` (two appends in one exclusive section, not atomic) loses the hold: kill -9 at the 3rd timeout → no hold, tool runs after restart (d7 60/78). | Bug (Medium) | Append both in one ledger write, or re-evaluate `unanswered_hold_due` in `_held_deny` before judging. |
| F3 | SIEM exports `tool_released` reason as digest+size only, so a SIEM cannot tell "hold expired" from a principal release. | UX (Low) | Add a fixed-vocabulary field (`by: expiry|principal`). |
| F4 | Denies caused by a held tool (`tool_held`) count as the agent's attempt episode (ledger 122 `attempt_episode denies 5 reasons other`) and show in judge history as agent denies. | Design (Low) | Exclude tool_held/tool_error denies from attempt episodes, or give them their own reason bucket. |
| F5 | Proxy prints "serving 2 signed tool(s)" before "refused to start" on an HA config with hold false. | Cosmetic | Check config before the serving line. |
| F6 | During HA terminal setup the pre-write check prints `ok unanswered_hold: off` (judges.yaml not yet readable) though HA forces it on. | Cosmetic (near known NOT FINDING) | Print "on (high_assurance)" during setup. |
| F7 | `two-key --version` gives a usage error. | Cosmetic | Add `--version`. |

## Departures
- tkp.py wrapper sets `agent_access.problems → []` (switches off agent_same_account; single box account) and applies the clock offset.
- siem block hand-appended to deps/d1/proxy.yaml (syslog tcp 127.0.0.1:18930).
- call_timeout_seconds set to 3 via `config set`.
- Clock shift by monkeypatching time in proxy + test server (no system clock change).
- Window run started from an answers file (`--window --answers`); HA terminal setup not completed (no local judge in my answers) — only "not asked" checked.

## Claude: fix vs WAD
- Fix: F2 (lost hold on crash), F1 (or document clearly), F3, F4.
- Cosmetic: F5, F6, F7.
- WAD: G3 within-10-min count across good calls; cef only for native schema; export reason digested; calls serialised per proxy.

Box changes: UNDO lines appended to /workspace/run13-work/UNDO_BOX_CHANGES.sh (not run). All my processes stopped (judges, collector, Xvfb :42, window, proxies).
