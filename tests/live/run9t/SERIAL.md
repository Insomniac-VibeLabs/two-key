# Run 9t serial (anti-rollback) re-run

The 9s serial scripts were re-run unchanged against 8e02760. Results only; the scripts and their deployments are not committed.

| Group | Rows | 9t | Same verdict as 9s |
|---|---|---|---|
| S0, S1/S1b/S1c | 4 | PASS | yes |
| S2a-S2i | 9 | PASS | yes |
| S3a-S3i | 9 | PASS | yes (S3g output timing text differs, verdict same) |
| S4a-S4d | 4 | PASS (S4d documented limit) | yes |
| S5a-S5f | 6 | PASS | yes |
| S5g | 1 | FAIL | yes; known test bug (first run sets a value that is already set) |
| S6a, S6b, S6c | 3 | PASS | yes |
| S7a-S7g | 7 | PASS | yes |
| S8 | 1 | FAIL | yes; WAD, the script is outdated (0.7.3 signs as is with a WARNING) |

Total 44 rows: 42 PASS, 2 FAIL (both known, both FAIL in 9s). Excluding the two known script problems: 42 of 42.

Hash comparison (1a): 46 of 46 harness signed envelopes and 27 of 27 serial signed envelopes have the same sha256 under 9s (8b3fd76) and 9t (8e02760). 1b: re-signing the harness rules.yaml gives the same canonical hash as the proxy's signed constitution, and deleting `irreversible: true` leaves tool_specs bytes and hash unchanged.
