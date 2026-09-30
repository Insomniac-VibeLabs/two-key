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

Crypto: FIPS-approved algorithms only, routed through a pluggable provider
with an optional `fips_mode` and a start-up self-test; optional hybrid
post-quantum signatures (ML-DSA-65 + Ed25519 or ECDSA P-384). **Not FIPS
certified or validated.** Compliance requires deployment on a validated
module; see `docs/CRYPTO.md`. Measured latency and memory:
`docs/PERFORMANCE.md`.

See `docs/figures/` for the architecture, flow, sequence, and ledger diagrams.

## Quick start

Requires Python ≥ 3.10 and `cryptography`. PyYAML is needed for YAML files.

```bash
pip install cryptography pyyaml         # add 'cryptography>=50' for ML-DSA (hybrid PQ)
python -m unittest discover -s tests     # 173 tests, no network (PQ tests skip without ML-DSA)
python -m compact_kernel demo            # offline demo (test-double judges)
python -m compact_kernel selftest        # crypto known-answer self-test + provider info
python bench.py --quick                  # latency and memory benchmarks
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

Other key suites (JSON key bundle, encrypted with PBKDF2 + AES-256-GCM):

```bash
python -m compact_kernel keygen --out ~/.ck-pq --suite hybrid-mldsa65-ed25519   # or hybrid-mldsa65-p384, ecdsa-p384
python -m compact_kernel sign-constitution ... --key ~/.ck-pq/principal.keys.json ...
python -m compact_kernel verify-constitution --signed ... --pub ~/.ck-pq/principal.pub.json
python -m compact_kernel --fips selftest --require-pq    # refuse non-approved algorithms; fail without ML-DSA
```

In code: `CompactKernel(..., crypto=CryptoProvider(fips_mode=True), require_pq=True)`.
A hybrid principal key switches the defaults to SHA-384 digests and
HMAC-SHA-384 tokens. If ML-DSA is missing, the kernel raises
`PQUnavailableError`; it never falls back to classical-only.

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
| `compact_kernel/quorum.py` | Path B k-of-n quorum (parallel judges, overall timeout) |
| `compact_kernel/judges/` | Judge interface, OpenAI-compatible / Anthropic / Gemini / Ollama adapters, credentials, config |
| `compact_kernel/constitution.py`, `keys.py` | Constitution upload and signing (Ed25519, ECDSA P-384, hybrid ML-DSA-65), key bundles |
| `compact_kernel/crypto/` | Crypto provider (`fips_mode`, approved-algorithm policy), signature suites, self-test |
| `compact_kernel/capability.py`, `gateway.py` | Tokens and the tool gateway |
| `compact_kernel/ledger.py`, `merkle.py`, `anchoring.py` | Signed ledger, Merkle tree, anchoring stub |
| `compact_kernel/kernel.py` | `CompactKernel.authorize` |
| `compact_kernel/testing.py` | Offline test-double judges (not for deployment) |
| `examples/` | Example constitution, hard rules (JSON/YAML), judges.yaml |
| `docs/INVENTION_DISCLOSURE.md` | Original disclosure, **unchanged** |
| `docs/SPEC_DRAFT.md` | Updated working specification draft |
| `docs/figures/` | Diagrams (Mermaid sources plus SVG/PNG) |
| `docs/CRYPTO.md` | FIPS 140-3 posture, candidate modules, algorithm map, PQ design |
| `docs/PERFORMANCE.md`, `bench.py` | Measured latency and memory; the benchmark script |
| `CONCEPTION_NOTES.md` | Dated conception statements by the inventor |
| `DESIGN_OPTIONS.md` | Open design questions and options (no decisions) |
| `CHANGES.md` | Every change and who decided it |

## Limitations

- The connectors to real judges are tested only against mocked HTTP. No live API call has been made.
- Username/password and OAuth device-code auth are interface stubs.
- Capability tokens use HMAC with a secret shared between issuer and gateway by default (an optional signed-token mode exists).
- Keys are file-based, not held in TEE/HSM hardware.
- Not FIPS validated. The development machine had no FIPS provider; see `docs/CRYPTO.md`.
- The liboqs backend adapter has been tested only against a fake module.
- The ledger is not encrypted, and public anchoring is a stub.
- Open design questions are listed in `DESIGN_OPTIONS.md`.

## Patent posture

This repository contains an invention disclosure and a working prototype. AI
cannot be named as an inventor. Read `CONCEPTION_NOTES.md`,
`docs/SPEC_DRAFT.md`, and `DESIGN_OPTIONS.md` with a registered patent
attorney. This is not legal advice.
