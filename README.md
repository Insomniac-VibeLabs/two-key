# Compact Kernel (two-key)

Dual-path constitutional enforcement for personal AI agents.
**Prototype. Not production cryptography.**

A language model may *propose* an action. This runtime decides whether the
action may touch the real world. It allows the action only when **both**
paths agree:

```
any LLM ─▶ Compact Kernel ─▶ single-use capability token ─▶ tool gateway ─▶ tool
               │
               ├─ Path A: deterministic Policy VM over compiled hard rules (never reads English)
               ├─ Path B: quorum of judges on AIs you choose (local or vendor), reading your constitution
               └─ Personal ledger: hash chain + Merkle root, head signed by your key
```

See `docs/figures/` for the architecture, flow, sequence, and ledger diagrams.

## Quick start

Requires Python ≥ 3.10 and `cryptography`. PyYAML is needed for YAML files.

```bash
pip install cryptography pyyaml
python -m unittest discover -s tests     # 115 tests, no network
python -m compact_kernel demo            # offline demo (test-double judges)
```

### Use your own constitution

```bash
python -m compact_kernel keygen --out ~/.compact-kernel        # keep principal.pem secret
python -m compact_kernel sign-constitution \
    --text examples/constitution.md --rules examples/hard_rules.yaml \
    --principal did:ck:me --key ~/.compact-kernel/principal.pem --out my-constitution.signed.json
python -m compact_kernel verify-constitution \
    --signed my-constitution.signed.json --pub ~/.compact-kernel/principal.pub.pem
```

### Choose your judges

Edit `examples/judges.yaml`: pick providers and models, and name the
environment variables that hold your API keys. Keys never go in the file.
Then:

```bash
python -m compact_kernel check-judges --config judges.yaml   # validates only; makes no API calls
```

### In code

```python
from pathlib import Path
from compact_kernel import keys
from compact_kernel.constitution import load_envelope
from compact_kernel.judges.config import load_config_file
from compact_kernel.kernel import CompactKernel

key = keys.load_private_key(Path("~/.compact-kernel/principal.pem").expanduser(), b"passphrase")
judges, quorum = load_config_file(Path("judges.yaml"))
k = CompactKernel(load_envelope(Path("my-constitution.signed.json")), key.public_key(),
                  Path("~/.compact-kernel/ledger.jsonl").expanduser(), judges,
                  ledger_signing_key=key, quorum_policy=quorum)
args = {"payee": "power-co.example", "amount": 42.5}
d = k.authorize({"tool": "pay_bill", "amount_usd": 42.5, "counterparty": "power-co.example",
                 "data_class": "financial", "irreversible": False}, "Pay the electric bill.", args)
gw = k.gateway(tools={"pay_bill": my_pay_bill_function})
if d.allowed:
    gw.invoke(d.capability, "pay_bill", args,
              {"amount_usd": 42.5, "counterparty": "power-co.example", "data_class": "financial"})
```

## Layout

| Path | What |
|---|---|
| `compact_kernel/action.py` | Normalized action record, validation, conservative defaults |
| `compact_kernel/policy_vm.py` | Path A compiler (strict) and VM |
| `compact_kernel/quorum.py` | Path B k-of-n quorum |
| `compact_kernel/judges/` | Judge interface, OpenAI-compatible / Anthropic / Gemini / Ollama adapters, credentials, config |
| `compact_kernel/constitution.py`, `keys.py` | Constitution upload and Ed25519 signing |
| `compact_kernel/capability.py`, `gateway.py` | Tokens and the tool gateway |
| `compact_kernel/ledger.py`, `merkle.py`, `anchoring.py` | Signed ledger, Merkle tree, anchoring stub |
| `compact_kernel/kernel.py` | `CompactKernel.authorize` |
| `compact_kernel/testing.py` | Offline test-double judges (not for deployment) |
| `examples/` | Example constitution, hard rules (JSON/YAML), judges.yaml |
| `docs/INVENTION_DISCLOSURE.md` | Original disclosure, **unchanged** |
| `docs/SPEC_DRAFT.md` | Updated working specification draft |
| `docs/figures/` | Diagrams (Mermaid sources plus SVG/PNG) |
| `CONCEPTION_NOTES.md` | Dated conception statements by the inventor |
| `DESIGN_OPTIONS.md` | Open design questions and options (no decisions) |
| `CHANGES.md` | Every change and who decided it |

## Limitations

- The connectors to real judges are tested only against mocked HTTP. No live API call has been made.
- Username/password and OAuth device-code auth are interface stubs.
- Capability tokens use HMAC with a secret shared between issuer and gateway.
- Keys are file-based, not held in TEE/HSM hardware.
- The ledger is not encrypted, and public anchoring is a stub.
- Open design questions are listed in `DESIGN_OPTIONS.md`.

## Patent posture

This repository contains an invention disclosure and a working prototype. AI
cannot be named as an inventor. Read `CONCEPTION_NOTES.md`,
`docs/SPEC_DRAFT.md`, and `DESIGN_OPTIONS.md` with a registered patent
attorney. This is not legal advice.
