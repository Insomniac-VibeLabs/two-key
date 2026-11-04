# A5: `two-key audit --check-history` on every ledger of the A3 pass (run 13)
Run 2026-11-03 ~8:15 PM MST on a copy of tests/live/state at /workspace/run13-work/a5/copy (`cp -a`; original state not modified apart from the shared `keys` symlink target, whose folder `audit` resets to 0700: expected, not a finding). Script: /workspace/run13-work/a5/run_a5.sh; raw output per ledger: /workspace/run13-work/a5/copy/out_*.txt.
Command: `two-key audit --ledger <dir>/ledger --key <dir>/[keys/]principal.pem [--key-passphrase-file F] --check-history <dir>/constitution.signed.json`; main key/constitution when a folder has none (tamper_C03/C56/C64/C117, as harness.py does). Fingerprint rule: every printed fingerprint must start `hybrid-sha256:`.

**Summary: 44 ledgers. 39 `ok true`, all fingerprints `hybrid-sha256:` (none plain `sha256:`), no decision/history digest problems except config_C15's 23 expected "decided under another constitution" notes. 5 `ok false` are the deliberately tampered ledgers (config_C165, tamper_C03, C56, C64, C117), each PASSed in A3. 0 FAIL.** Same picture as run 12 (C15 had 22 notes then, 23 now; main ledger size 319 vs 321).

| Ledger | Constitution | rc | Result | Notes |
|---|---|---|---|---|
| state/config_C02/ledger | state/config_C02/constitution.signed.json | 0 | PASS: ok true | size 4; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C105/ledger | state/config_C105/constitution.signed.json | 0 | PASS: ok true | size 3; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C109/ledger | state/config_C109/constitution.signed.json | 0 | PASS: ok true | size 3; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C110/ledger | state/config_C110/constitution.signed.json | 0 | PASS: ok true | size 3; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C132/ledger | state/config_C132/constitution.signed.json | 0 | PASS: ok true | size 3; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C152/ledger | state/config_C152/constitution.signed.json | 0 | PASS: ok true | size 3; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C155/ledger | state/config_C155/constitution.signed.json | 0 | PASS: ok true | size 4; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C15/ledger | state/config_C15/constitution.signed.json | 0 | PASS: ok true | size 173; decision/history problems 0/23; fingerprints hybrid-sha256: (all 23 = "not checked: decided under another constitution"; rollback case, expected, same as run 12) |
| state/config_C165/ledger | state/config_C165/constitution.signed.json | 1 | PASS (expected ok false) | error: signed head does not match the chain (a write stopped before its head, or the files were changed; after a crash see HOWTO "If the ledger will not open after a crash": two-key recover). deliberately tampered (A3 PASS) |
| state/config_C176/ledger | state/config_C176/constitution.signed.json | 0 | PASS: ok true | size 2; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C177/ledger | state/config_C177/constitution.signed.json | 0 | PASS: ok true | size 3; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C31/ledger | state/config_C31/constitution.signed.json | 0 | PASS: ok true | size 3; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C38/ledger | state/config_C38/constitution.signed.json | 0 | PASS: ok true | size 3; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C48/ledger | state/config_C48/constitution.signed.json | 0 | PASS: ok true | size 1; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C49/ledger | state/config_C49/constitution.signed.json | 0 | PASS: ok true | size 2; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C60/ledger | state/config_C60/constitution.signed.json | 0 | PASS: ok true | size 3; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C63/ledger | state/config_C63/constitution.signed.json | 0 | PASS: ok true | size 3; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C68/ledger | state/config_C68/constitution.signed.json | 0 | PASS: ok true | size 3; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C71/ledger | state/config_C71/constitution.signed.json | 0 | PASS: ok true | size 2; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C74/ledger | state/config_C74/constitution.signed.json | 0 | PASS: ok true | size 2; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C81/ledger | state/config_C81/constitution.signed.json | 0 | PASS: ok true | size 3; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C82/ledger | state/config_C82/constitution.signed.json | 0 | PASS: ok true | size 1; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/config_C92/ledger | state/config_C92/constitution.signed.json | 0 | PASS: ok true | size 3; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/deploy/deploy_a/ledger | state/deploy/deploy_a/constitution.signed.json | 0 | PASS: ok true | size 7; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/deploy/deploy_b/ledger | state/deploy/deploy_b/constitution.signed.json | 0 | PASS: ok true | encrypted key: `--key-passphrase-file deploy/principal.pass`. size 9; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/deploy/deploy_c/ledger | state/deploy/deploy_c/constitution.signed.json | 0 | PASS: ok true | size 2; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/deploy/deploy_g/ledger | state/deploy/deploy_g/constitution.signed.json | 0 | PASS: ok true | size 7; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/deploy/deploy_grok_passphrase_12/ledger | state/deploy/deploy_grok_passphrase_12/constitution.signed.json | 0 | PASS: ok true | first without passphrase: rc 1 `key_passphrase_needed` (correct); result shown is with `--key-passphrase-file deploy/grok_pass_12`. size 2; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/deploy/deploy_h/ledger | state/deploy/deploy_h/constitution.signed.json | 0 | PASS: ok true | size 2; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/ledger | state/constitution.signed.json | 0 | PASS: ok true | size 319; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/stance_encrypted_pass/ledger | state/stance_encrypted_pass/constitution.signed.json | 0 | PASS: ok true | size 19; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/stance_freeplay/ledger | state/stance_freeplay/constitution.signed.json | 0 | PASS: ok true | size 48; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/stance_grok2p/ledger | state/stance_grok2p/constitution.signed.json | 0 | PASS: ok true | size 40; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/stance_library_burst/ledger | state/stance_library_burst/constitution.signed.json | 0 | PASS: ok true | size 70; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/stance_library_freeplay/ledger | state/stance_library_freeplay/constitution.signed.json | 0 | PASS: ok true | size 45; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/stance_library/ledger | state/stance_library/constitution.signed.json | 0 | PASS: ok true | size 173; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/stance_monitor/ledger | state/stance_monitor/constitution.signed.json | 0 | PASS: ok true | size 20; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/stance_strict/ledger | state/stance_strict/constitution.signed.json | 0 | PASS: ok true | size 40; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/stance_twoproxy/ledger | state/stance_twoproxy/constitution.signed.json | 0 | PASS: ok true | size 42; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/tamper_C03/ledger | state/constitution.signed.json (main; folder has none, as harness.py does) | 1 | PASS (expected ok false) | error: signed head does not match the chain (a write stopped before its head, or the files were changed; after a crash see HOWTO "If the ledger will not open after a crash": two-key recover). deliberately tampered (A3 PASS) |
| state/tamper_C117/ledger | state/constitution.signed.json (main; folder has none, as harness.py does) | 1 | PASS (expected ok false) | error: ledger record rejected (wrong key or tampered ciphertext). deliberately tampered (A3 PASS) |
| state/tamper_C144/ledger | state/tamper_C144/constitution.signed.json | 0 | PASS: ok true | size 322; decision/history problems 0/0; fingerprints hybrid-sha256: |
| state/tamper_C56/ledger | state/constitution.signed.json (main; folder has none, as harness.py does) | 1 | PASS (expected ok false) | error: ledger record rejected (wrong key or tampered ciphertext). deliberately tampered (A3 PASS) |
| state/tamper_C64/ledger | state/constitution.signed.json (main; folder has none, as harness.py does) | 1 | PASS (expected ok false) | error: ledger chain failed verification. deliberately tampered (A3 PASS) |
