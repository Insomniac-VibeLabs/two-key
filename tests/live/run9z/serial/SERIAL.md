# Run 9z serial (anti-rollback) tests: masked summary

These are the 9y serial scripts and cases, re-run unchanged on `working` @ 821bc93 (nothing added). They use the CLI only, with fictitious credentials and throwaway keys. This file records results only; the scripts, keys, ledgers and raw output are not committed.

| Test | Expected | Actual | Verdict |
|---|---|---|---|
| S0 baseline serial 1 | serves | serves | PASS |
| S1/S1c changed rules, same serial | serial_reused | serial_reused | PASS |
| S1b identical rules re-signed | serves | serves | PASS |
| S2a-g serial "2"/true/2.0/0/-3/"two"/setup "1" | refused at sign | refused | PASS |
| S2h-i hand-edited serial | signature error | signature error | PASS |
| S3a 2^53-1, S3h 2^53 | serves | serves | PASS |
| S3b lower serial / S3c same serial | rollback / reused | as expected | PASS |
| S3d-g >2^53, 20k-digit serial | clean refusal | refused | PASS |
| S3i config set after 2^53 | refused | refused (rules locked for good; HOWTO "The serial" now documents the ceiling) | PASS |
| S4a-b serial missing after serial seen | serial_missing | serial_missing | PASS |
| S4c serial stripped | signature error | signature error | PASS |
| S4d ledger that never saw a serial | accepts any (documented) | accepts | PASS (documented limit) |
| S5a-f set, undo before/after run, hand-copied .prev | serial 2, undo ok, then rollback | as expected | PASS |
| S5g set while a proxy is serving | set ok, undo refused once serial 2 has run | first run rc=1 "unchanged" (the script sets an already-set value, as in 9y); clean rerun: set ok, 2nd proxy serves, undo refused constitution_rollback, restart serves | PASS (first FAIL = test bug) |
| S6a/S6b staggered proxies with different serials | lower one refused | refused | PASS |
| S6c two different serial-2 constitutions started at the same moment (4 runs) | 2nd refused, writes nothing | 4 of 4: one serves, the other refused constitution_serial_reused; later restarts: only the registered one serves; no LedgerError; audit rc=0 | PASS (9y fix works) |
| S7a v2 with serial | refused at sign | refused | PASS |
| S7b-e relabelled formats | refused | refused | PASS |
| S7f-g genuine v1/v2 with no serial | serial_missing | serial_missing | PASS |
| S8 setup with an operator rules_file that has no serial | per 0.7.3: signed as is, "WARNING: rules_file has no serial", next steps list "add serial: 1" | serial None, the WARNING is printed and next steps list "add serial: 1 ..." | PASS (WAD; the 9y script still checks for serial 1 and prints FAIL, so the script is outdated) |
