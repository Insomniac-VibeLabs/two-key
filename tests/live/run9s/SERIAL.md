# Run 9s serial (anti-rollback) tests: masked summary

Build: `working` @ 8b3fd76 (the serial check split into `_serial_history`). CLI only (`two-key setup`, `sign-constitution`, `config set/undo`, `mcp-proxy`, `audit`), throwaway keys, fictitious credentials, one machine, loopback. The scripts, keys, ledgers and raw output are not committed.

**The 9y/9z S0-S8 scripts no longer existed** (they were deleted with the 9z private files), so they were rebuilt from the 9z SERIAL.md rows. Same test ids and the same expected verdicts and refusal codes, but not byte-identical scripts. Two first-run FAILs were bugs in the rebuilt scripts and were fixed and rerun: S1c used an invalid `data_class_floor` so signing failed and the old constitution served; S5a-g ran `config set`/`undo` without a terminal (`not_confirmed`), without `--key` (`principal_key_needed`) and without `--confirm-weaker` on undo (the undo un-sets `irreversible`, which counts as weaker). After those fixes every row matches 9z.

| Test | What | Expected | Actual | Verdict | Same as 9z |
|---|---|---|---|---|---|
| S0 | baseline serial 1 | serves | serves | PASS | yes |
| S1 | changed rules, same serial | constitution_serial_reused | constitution_serial_reused | PASS | yes |
| S1b | identical rules re-signed | serves | serves | PASS | yes |
| S1c | changed spec, same serial | constitution_serial_reused | constitution_serial_reused | PASS | yes |
| S2a | serial '2' at sign | refused at sign | refused at sign | PASS | yes |
| S2b | serial True at sign | refused at sign | refused at sign | PASS | yes |
| S2c | serial 2.0 at sign | refused at sign | refused at sign | PASS | yes |
| S2d | serial 0 at sign | refused at sign | refused at sign | PASS | yes |
| S2e | serial -3 at sign | refused at sign | refused at sign | PASS | yes |
| S2f | serial 'two' at sign | refused at sign | refused at sign | PASS | yes |
| S2g | setup rules_file serial "1" | refused | refused | PASS | yes |
| S2h | hand-edited serial | signature error | signature error | PASS | yes |
| S2i | hand-edited rules under serial | signature error | signature error | PASS | yes |
| S3a | serial 2^53-1 | serves | serves | PASS | yes |
| S3h | serial 2^53 | serves | serves | PASS | yes |
| S3b | lower serial | constitution_rollback | constitution_rollback | PASS | yes |
| S3c | same serial, other rules | constitution_serial_reused | constitution_serial_reused | PASS | yes |
| S3d | serial >2^53 (16 digits) | clean refusal | clean refusal | PASS | yes |
| S3e | serial >2^53 (20 digits) | clean refusal | clean refusal | PASS | yes |
| S3f | serial >2^53 (21 digits) | clean refusal | clean refusal | PASS | yes |
| S3g | serial >2^53 (20000 digits) | clean refusal | clean refusal | PASS | yes |
| S3i | config set after 2^53 | refused | refused | PASS | yes |
| S4a | no serial (v1) after serial seen | constitution_serial_missing | constitution_serial_missing | PASS | yes |
| S4b | no serial (v3) after serial seen | constitution_serial_missing | constitution_serial_missing | PASS | yes |
| S4c | serial stripped from signed file | signature error | signature error | PASS | yes |
| S4d | ledger that never saw a serial | serves | serves | PASS | yes |
| S5a | config set signed setting | rc0 serial 2 | rc0 serial 2 | PASS | yes |
| S5b | undo before run | ok | ok | PASS | yes |
| S5c | serial-1 serves after undo | serves | serves | PASS | yes |
| S5d | set again, run serial 2 | serves | serves | PASS | yes |
| S5e | undo after serial 2 ran | constitution_rollback | constitution_rollback | PASS | yes |
| S5f | hand-copied .prev | constitution_rollback | constitution_rollback | PASS | yes |
| S5g | set while a proxy is serving | set rc0; p1 serves; p2 serves; undo constitution_rollback; restart serves | set rc0; p1 serves; p2 serves; undo constitution_rollback; restart serves | PASS | yes |
| S6a | staggered: serial 2 then serial 1 | constitution_rollback | constitution_rollback | PASS | yes |
| S6b | staggered: serial 3 then serial 2 | constitution_rollback | constitution_rollback | PASS | yes |
| S6c#1 | two serial-2 at once | ['constitution_serial_reused', 'serves']; restarts winner=serves loser=constitution_serial_reused; LedgerError=False; audit rc=0 | ['constitution_serial_reused', 'serves']; restarts winner=serves loser=constitution_serial_reused; LedgerError=False; audit rc=0 | PASS | yes |
| S6c#2 | two serial-2 at once | ['constitution_serial_reused', 'serves']; restarts winner=serves loser=constitution_serial_reused; LedgerError=False; audit rc=0 | ['constitution_serial_reused', 'serves']; restarts winner=serves loser=constitution_serial_reused; LedgerError=False; audit rc=0 | PASS | yes |
| S6c#3 | two serial-2 at once | ['constitution_serial_reused', 'serves']; restarts winner=serves loser=constitution_serial_reused; LedgerError=False; audit rc=0 | ['constitution_serial_reused', 'serves']; restarts winner=serves loser=constitution_serial_reused; LedgerError=False; audit rc=0 | PASS | yes |
| S6c#4 | two serial-2 at once | ['constitution_serial_reused', 'serves']; restarts winner=serves loser=constitution_serial_reused; LedgerError=False; audit rc=0 | ['constitution_serial_reused', 'serves']; restarts winner=serves loser=constitution_serial_reused; LedgerError=False; audit rc=0 | PASS | yes |
| S7a | v2 with serial | refused at sign | refused at sign | PASS | yes |
| S7b | relabelled format two-key-constitution-v1 | refused | refused | PASS | yes |
| S7c | relabelled format two-key-constitution-v2 | refused | refused | PASS | yes |
| S7d | relabelled format v1 | refused | refused | PASS | yes |
| S7e | relabelled format bogus | refused | refused | PASS | yes |
| S7f | genuine v1, no serial | constitution_serial_missing | constitution_serial_missing | PASS | yes |
| S7g | genuine v2, no serial | constitution_serial_missing | constitution_serial_missing | PASS | yes |
| S8 | setup rules_file without serial | rc0 serial None warning True next True | rc0 serial None warning True next True | PASS | yes |

S6c (also the ledger lock guard in ledger.py) was run 4 times: 4 of 4 one proxy serves, the other is refused `constitution_serial_reused` and writes nothing; restarts: only the registered one serves; no LedgerError; audit rc 0.

## Own tests aimed at the split check (expectations written in the script before it ran)

| Test | What | Expected | Actual | Verdict |
|---|---|---|---|---|
| T1 | differential old vs new over 20000 random ledgers | 0 differences between 821bc93 and 8b3fd76 check_constitution_order over 20000 random ledgers | 0 differences between 821bc93 and 8b3fd76 check_constitution_order over 20000 random ledgers | PASS |
| T2 | serials up, down and repeat (1,3,2,3,5,4,5,6) | 3 serves; 2 rollback; 3 serves; 5 serves; 4 rollback; 5 serves; 6 serves | 3 serves; 2 rollback; 3 serves; 5 serves; 4 rollback; 5 serves; 6 serves | PASS |
| T3 | no-serial entries before and after a serial | noserial serves; noserial2 serves; 2 serves; noserial constitution_serial_missing; 1 constitution_rollback; 2-other constitution_serial_reused | noserial serves; noserial2 serves; 2 serves; noserial constitution_serial_missing; 1 constitution_rollback; 2-other constitution_serial_reused | PASS |
| T4 | older digest that already ran, after a higher serial | A2 serves; B3 serves; A2 constitution_rollback; B3 serves | A2 serves; B3 serves; A2 constitution_rollback; B3 serves | PASS |
| T5 | one proxy restarts with a higher serial while the other serves | P1(2) serves; P2(3) serves while P1 serves; P1 restart constitution_rollback; audit rc0 | P1(2) serves; P2(3) serves while P1 serves; P1 restart constitution_rollback; audit rc0 | PASS |
| T6 | hand-edited ledger then a lower serial | audit rc!=0; start refused | audit rc!=0; start refused (LedgerError: the last record does not decrypt) | PASS (the first comparison was a test bug: the actual text carried the refusal detail; audit failed and the start was refused LedgerError, as expected) |

T1 is in-process, not CLI: it runs 821bc93's `check_constitution_order` (extracted from `git show 821bc93:two_key/core.py`) and 8b3fd76's on the same 20000 random ledgers (0-30 entries, mixed kinds, serials None/1-5/True/False/"3"/2.0/0/-1, repeated digests) and compares the return value or the exact error text.
