
# Is this for you

Prototype. Not a FIPS 140-3 validated module. Not on PyPI. There is no MCP
server in this release. Package `two-key-concept` version 0.3.0 on branch `working` (not tagged). Tag `v0.2.4` on `main` is the tagged release. Tag `v0.2.3` stays on `4a4352e`. Tag `v0.2.0` stays on `2f756ac`.
`v0.1.6` stays on the previous tree.
Apache-2.0.
Crypto is Ed25519 and SHA-256.

This package has a ledger, Path A, Path B, and judge and
monitored-agent hooks. It does not scan payloads. It has no PKI or
external anchor, and no seed phrase. A local head anchor can detect a
rollback or wipe of the ledger directory alone, but it is not an external
anchor and does not protect against someone who can also delete or roll
back that anchor. It can back up its own keys under passphrases (0.3.0).
That backup is not a seed phrase.

## Use this if

- A tool should run only after Path A and Path B both allow. Path A is a
  policy VM over a structured action record. It does not read English. Path B
  is a judge quorum. Hooks exist for xAI, OpenAI-compatible APIs, Anthropic,
  Gemini, and local Ollama.
- You understand how the configured judge quorum behaves. The default
  affirmative threshold is `min(2, number_of_judges)`, not a majority.
  Diversity and local-judge requirements are opt-in through
  `QuorumPolicy.high_assurance()`. Maker labels are operator-supplied and
  are not independently verified. See
  [JUDGES_AND_QUORUM.md](JUDGES_AND_QUORUM.md) for threshold,
  abstention, timeout, and path-combination details.
- The only component that runs the tool should be the gateway. It holds a
  single-use token, 120 seconds by default, signed by the capability key.
  That private key is not on the gateway. The token is bound to the tool,
  the argument hash, the ledger Merkle root and size at issuance, and the
  constitution hashes (`bytecode_hash`, `nl_hash`, and `spec_hash`), plus
  the form derived from the argument bytes. A constitution that omits
  `tool_specs` does not load. Unnamed argument keys do not reach the tool.
  `deny_unmapped` defaults off and drops them; set it to deny the call. A
  counterparty path copies only parties on its `allow` list. A payload
  `shape`, when set, checks the kind of value and does not read it.
- You want an encrypted ledger. Records and the head are AES-256-GCM. The
  ledger key and the witness key live outside the ledger directory. The
  principal key cannot unwrap the log and cannot sign a head alone. The
  witness public key is pinned in the ledger, and you can also pin it
  outside the ledger so that a forged head needs the witness key too. A
  head anchor beside the ledger key refuses a rollback of the ledger
  directory alone. It is not an external anchor: deleting that file
  accepts the ledger as it stands.

## Do not use this if

- You need a content filter, or a moderation API, to be the authorization
  decision. Path A does not read the proposal.
- You need user login or MCP session authorization.
- You need a validated cryptographic module, or a control that has had an
  independent review. This release has not.
- You need DLP, antivirus, PKI, permissioned anchoring, a seed phrase, or
  hybrid ML-DSA. Those are not here.

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

Read next: [COMPARISON.md](COMPARISON.md), [THREAT_MODEL.md](THREAT_MODEL.md),
[SCOPE.md](SCOPE.md).
