# Figures

| # | Figure | Source | Rendered |
|---|---|---|---|
| 1 | System architecture | `architecture.mmd` | `architecture.svg`, `architecture.png` |
| 2 | `authorize()` flowchart | `authorize_flow.mmd` | `authorize_flow.svg`, `authorize_flow.png` |
| 3 | Token issuance and gateway redemption sequence | `token_gateway_sequence.mmd` | `token_gateway_sequence.svg`, `token_gateway_sequence.png` |
| 4 | Ledger structure (hash chain, Merkle tree, signed head) | `ledger_structure.mmd` | `ledger_structure.svg`, `ledger_structure.png` |

The figures show the prototype as implemented on 2026-09-30. A patent
attorney will usually want formal drawings redrawn from these.

To regenerate (requires Node.js and Chrome/Chromium):

```bash
npm i @mermaid-js/mermaid-cli
npx mmdc -i architecture.mmd -o architecture.svg -b white
npx mmdc -i architecture.mmd -o architecture.png -b white -s 2
```
