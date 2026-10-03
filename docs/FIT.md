# Is this for you

Prototype. Not a FIPS 140-3 validated module. Not on PyPI. There is no MCP
server in this release. Package version 0.1.5. Apache-2.0.

This is [two-key](https://github.com/Insomniac-VibeLabs/two-key). The smaller
package, without scanning, PKI, or anchoring, is
[two-key-concept](https://github.com/Insomniac-VibeLabs/two-key-concept).

## Use this if

- A tool should run only after Path A and Path B both allow. Path A is a
  policy VM over a structured action record. It does not read English. Path B
  is a judge quorum. Hooks exist for xAI, OpenAI-compatible APIs, Anthropic,
  Gemini, and local Ollama.
- The only component that runs the tool should be the gateway. It holds a
  single-use token, 30 seconds by default, bound to the tool, the exact
  argument bytes, the scope, the ledger Merkle root, and the constitution
  hashes.
- You want a signed Merkle ledger. Records are AES-256-GCM. The ledger key
  and the witness key live outside the ledger directory. The principal key
  cannot unwrap the log.
- You may also want the optional pieces, and you will read the threat model
  before treating them as live products: DLP and antivirus hooks, enterprise
  X.509 identities, permissioned-chain anchoring, hybrid ML-DSA-65, and a
  personal-mode seed phrase.

## Do not use this if

- You need a content filter, or a moderation API, to be the authorization
  decision. Path A does not read the proposal.
- You need user login or MCP session authorization.
- You need a validated cryptographic module, or a control that has had an
  independent review. This release has not.
- You need a hosted DLP or antivirus product. The gateway can call scanner
  hooks. The scanners in this repository are examples. Tests use fakes.
- You wanted only the first working cut. That is `two-key-concept`.

## Smallest working shape

From a checkout:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[yaml]"
python -m two_key demo
```

The demo does not call a vendor. Real judges are `examples/judges.yaml`.
Operator steps are [HOWTO.md](HOWTO.md).

Read next: [COMPARISON.md](COMPARISON.md), [THREAT_MODEL.md](THREAT_MODEL.md).
