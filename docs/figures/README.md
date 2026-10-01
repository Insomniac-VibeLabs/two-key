# Figures

| # | Figure | Source | Rendered |
|---|---|---|---|
| 1 | System architecture | `architecture.mmd` | `architecture.svg`, `architecture.png` |
| 2 | `authorize()` flowchart | `authorize_flow.mmd` | `authorize_flow.svg`, `authorize_flow.png` |
| 3 | Token issuance and gateway redemption sequence | `token_gateway_sequence.mmd` | `token_gateway_sequence.svg`, `token_gateway_sequence.png` |
| 4 | Ledger structure (hash chain, Merkle tree, signed head) | `ledger_structure.mmd` | `ledger_structure.svg`, `ledger_structure.png` |
| 5 | Ledger-root-bound token and gateway checks (PRIOR_ART.md §4 (i)) | `ledger_root_token.mmd` | `ledger_root_token.svg`, `ledger_root_token.png` |
| 6 | One signed constitution, two compilations (§4 (ii)) | `two_compilations.mmd` | `two_compilations.svg`, `two_compilations.png` |
| 7 | Quorum protocol: heterogeneity, K floor, bound ballots, record-only inputs (§4 (iii)) | `quorum_protocol.mmd` | `quorum_protocol.svg`, `quorum_protocol.png` |

The figures show the prototype as implemented on 2026-09-30. Figures 5–7 are drafts
of the PRIOR_ART.md §4 directions (i)–(iii) that the author selected on
2026-09-30 (CONCEPTION_NOTES.md Entry 2); Figures 2 and 3 were updated for them. A patent
attorney will usually want formal drawings redrawn from these.

To regenerate (requires Node.js and Chrome/Chromium):

```bash
npm i @mermaid-js/mermaid-cli
npx mmdc -i architecture.mmd -o architecture.svg -b white
npx mmdc -i architecture.mmd -o architecture.png -b white -s 2
```
