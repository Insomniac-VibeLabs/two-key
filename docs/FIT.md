<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Is this for you?

Beta (pre-1.0), maintainer-reviewed, not yet independently audited. Every algorithm it uses is FIPS-approved; a FIPS
140-3 approved mode follows once a validated module offers ML-DSA-65 ([ROADMAP](../ROADMAP.md#fips-approved-mode)).
This page describes `two-key` 0.8.0, which is on PyPI (`pip install "two-key"`); the release steps are
[PYPI.md](PYPI.md). 0.8.0 gives the judges a summary of recent decisions, records each judge's ballot, and
adds a ledger audit window and a constitution editor; 0.7.3 added `two-key setup` and the `config` commands, a passphrase on the principal key,
and a signed serial against older rules; 0.7.0 added the SIEM export and a start-up check for a monitored agent that runs as
Two-Key's own account; 0.6.0 added Windows support, content scanning through your antivirus or DLP
product, and a start-up check for paths another account could change; 0.5.0 added an MCP adapter (a
stdio proxy, a spec drafter, caller-supplied facts, and a guard core for any agent loop). What each
release shipped is under "Shipped" in [ROADMAP.md](../ROADMAP.md), and tags are in
[AGENTS.md](../AGENTS.md).
Apache-2.0.
Crypto is hybrid Ed25519 + ML-DSA-65 signatures (from 0.9.0), SHA-256, and AES-256-GCM (the ledger's
ciphertext).

This package has a ledger, Path A, Path B, and judge and
monitored-agent hooks. It has no scanning engine; from 0.6.0 it can call your antivirus or DLP product for the tools you
mark ([SCANNERS.md](SCANNERS.md)). It has no PKI or
external anchor, and no seed phrase. A local head anchor can detect a
rollback or wipe of the ledger directory alone, but it is not an external
anchor and does not protect against someone who can also delete or roll
back that anchor. It can back up its own keys under passphrases (0.3.0).
That backup is not a seed phrase.

## Contents

<!-- toc -->
- [Use this if](#use-this-if)
- [Do not use this if](#do-not-use-this-if)
- [Smallest working shape](#smallest-working-shape)
<!-- /toc -->

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
  That private key is not on the gateway object, but it is in the same
  process: the gateway runs in the `TwoKey` process (`TwoKey.gateway()`),
  and a gateway in another process or on another host is not supported,
  by design ([why](HOWTO.md#deployment-boundary-the-gateway-runs-in-the-twokey-process)). The token is bound to the tool,
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
- You want the decisions in the SIEM you already run (0.7.0). Each entry can
  be copied, as it is written, to syslog or an HTTPS webhook, in Two-Key's
  own schema, ECS, or OCSF: reason codes, digests, sizes, the tool id, and
  the data class, never argument values. A collector that is down never
  blocks a decision, and `two-key siem-export` backfills history
  ([SIEM.md](SIEM.md)).

## Do not use this if

- You need a content filter, or a moderation API, to be the authorization
  decision. Path A does not read the proposal.
- You need user login or MCP session authorization.
- You need a validated cryptographic module, or a control that has had an
  independent review. This release has not.
- You need Two-Key itself to be the DLP or antivirus product, or the SIEM,
  or you need PKI, permissioned anchoring, or a seed phrase.
  Those are not here. (0.6.0 can call a DLP or antivirus product you run,
  and 0.7.0 can feed a SIEM you run; neither stores, searches, or alerts.)

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
