# Run 9y serial (anti-rollback) tests: masked summary

These tests use the CLI only, with fictitious credentials and throwaway keys. This file records results only; the scripts, keys, ledgers and raw output are not committed.

| Test | Expected | Actual | Verdict |
|---|---|---|---|
| S0 baseline serial 1 | serves | serves | PASS |
| S1/S1c changed rules, same serial | serial_reused | serial_reused | PASS |
| S1b identical rules re-signed | serves | serves | PASS |
| S2a-g serial "2"/true/2.0/0/-3/"two"/setup "1" | refused at sign | refused | PASS |
| S2h-i hand-edited serial | signature error | signature error | PASS |
| S3a 2^53-1, S3h 2^53 | serves | serves | PASS |
| S3b lower serial / S3c same serial | rollback / reused | as expected | PASS |
| S3d-g >2^53, 20k-digit serial | clean refusal | refused in 0.1s | PASS |
| S3i config set after 2^53 | refused | refused (rules locked for good) | PASS, design note |
| S4a-b serial missing after serial seen | serial_missing | serial_missing | PASS |
| S4c serial stripped | signature error | signature error | PASS |
| S4d ledger that never saw a serial | accepts any (documented) | accepts | PASS (documented limit) |
| S5a-f set, undo before/after run, hand-copied .prev | serial 2, undo ok, then rollback | as expected | PASS |
| S5g set while a proxy is serving | set ok, undo refused once serial 2 has run | first run rc=1 "unchanged" (my test set an already-set value); clean rerun: set ok, 2nd proxy serves, undo refused rollback, restart serves | PASS (first FAIL = test bug) |
| S6a/S6b staggered proxies with different serials | lower one refused | refused | PASS |
| S6c two different serial-2 constitutions started at the same moment | 2nd refused serial_reused | 3 of 4 runs: both serve; afterwards BOTH keep restarting, including the weaker one (missing block-wire-parties). 1 run: 2nd refused with "LedgerError: signed" | FAIL |
| S7a v2 with serial | refused at sign | refused | PASS |
| S7b-e relabelled formats | refused | refused | PASS |
| S7f-g genuine v1/v2 with no serial | serial_missing | serial_missing | PASS |
| S8 setup with an operator rules_file that has no serial | serial 1 (per docs) or a warning | serial None, no warning | FAIL |

