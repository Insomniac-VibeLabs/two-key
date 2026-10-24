# Live run 9t results: tool-spec change check (8e02760)

Build: `working` @ 8e02760 "Tool specs: only the tool id is required; README Path B wording" (sha checked). Non-root account, Python 3.14.8. Run 2026-10-23 (America/Denver, MDT UTC-6). The live relay pass ran afterwards; see LIVE_SUMMARY.md.

| Step | Check | Expected | Actual | Verdict |
|---|---|---|---|---|
| 1 | clone, `working`, `git log -1` | 8e02760 | 8e02760 | PASS |
| 2 | `harness.py --sabotage all` | SABOTAGE: ok | SABOTAGE: ok. control_ok; 6 weakenings caught (path_a_ignored 31, missing_ballot_is_yes 3, scan_flag_ignored 13, siem_passes_arguments 1 + SIEM incident, upstream_paths_ignored 5, config_confirmation_skipped 13 cases failed); gateway_skips_argument_hash reported blind_spot | PASS |
| 3 | `harness.py --selftest` | 175 PASS | COMPLETE, 175 PASS | PASS |
| 4 | 1a: signed-envelope hashes 9s vs 9t | identical | 46 of 46 harness envelopes and 27 of 27 serial envelopes identical | PASS |
| 5 | 1b: re-sign rules.yaml as written; delete `irreversible` where it was true | same bytes and hash | same | PASS |
| 6 | 1c: omit both `irreversible` and `data_class_floor` | defaults (true, classified) | (true, classified); a call claiming irreversible false is refused `irreversible_mismatch` | PASS |
| 7 | 1d: bad values for the two fields | refused at signing | all three refused | PASS |
| 8 | 2: setup with the starter tools | every tool signed true/classified | as expected | PASS |
| 9 | 3: setup marks unknown data class | `REPLACE_WITH_DATA_CLASS` written, signing refused until replaced | written for 5 tools; signing refused | PASS |
| 10 | 4: `weaker()` on defaulted vs written specs | empty | empty in both cases | PASS |
| 11 | serial S0-S8 re-run (44 rows), see SERIAL.md | verdicts as 9s | 42 PASS / 2 FAIL, every verdict identical to 9s (S5g test bug, S8 outdated script, both FAIL in 9s too) | PASS |
| 12 | live relay pass with role bots (30 rounds) | COMPLETE | COMPLETE: 170 PASS / 5 INCONCLUSIVE / 0 FAIL, 0 referee incidents | PASS |

Answer: 8e02760 changes no behaviour seen here. Every signed envelope hashes the same as under 8b3fd76, and every serial verdict is the same as in 9s.
