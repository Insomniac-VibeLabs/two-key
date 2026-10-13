# Scope

`two-key-concept` is the first working cut. Package version 0.3.0 on branch
`working` (not tagged). Tag `v0.2.4` on `main` is the tagged release. Tag
`v0.2.3` stays on `4a4352e`. Tag `v0.2.0` stays on `2f756ac`. Tag `v0.1.12`
is on `main`. `v0.1.6` stays on the previous tree.

It has:

- a signed constitution, Path A bytecode, and a policy VM that does not read English
- required `tool_specs` that fill Path A's form from argument bytes. Omitting them does not load. `deny_unmapped` defaults off: an unnamed key does not reach the tool. Set the flag to deny it. A counterparty path requires `allow`. A payload `shape`, when set, locks the value to a string, a number, or a list of strings and does not read it
- Path B judge hooks for xAI, OpenAI-compatible APIs, Anthropic, Gemini, and local Ollama. One judge by default, no diversity floors; `high_assurance` turns them on. No judge may be the monitored agent (a judge holding its credential, the same API token or the same username and password, at any address and whether or not either side sends it; or both keyless on one address); other overlaps warn. After a derive deny, argument bytes are withheld from judges unless `tool_args_on_derive_deny` is set. Path B still runs
- monitored-agent hooks; `authorize_from_agent` does not execute a tool
- an AES-256-GCM ledger, a ledger key, and a witness key outside the ledger directory. The witness public key is pinned in the ledger (`witness_pinned`) and, optionally, outside it (`witness_public_key=`, `--witness-public-key`); it changes only by a ledgered `witness_rotated` entry (`two-key rotate-witness`). A head anchor beside the ledger key (`head.anchor`, or `--head-anchor`) refuses a rollback or wipe of the ledger directory alone; deleting that file accepts the ledger as it stands. `two-key recover` drops an uncheckpointed tail and does not run on open. `two-key audit` reports both pins
- a capability key outside the ledger directory. The gateway verifies
  tokens with the public half only. Today it shares the `TwoKey` process
  and ledger object; separate-process/host isolation and a gateway-only
  ledger role are designed but not yet built (#45)
- a single-use token and a gateway intended to be the only component that
  invokes registered tools; this does not stop an agent from calling a
  tool directly through another path
- passphrase backup of this package's own keys (0.3.0): three bundles, so the ledger key and the witness key are never in one file. `backup-verify` checks fingerprints in a temporary ledger. `backup-restore` puts `head.anchor` back from the same moment as the ledger. This is not a seed phrase

Modules that carry these rules include `two_key/identity.py` (judge ≠ agent),
`two_key/strict.py` (duplicate-key JSON/YAML), `two_key/audit.py` (decision
digest checks), `two_key/backup.py` (key backup), and the per-install fingerprint key beside the ledger
(`*.ledger-key/fingerprint.key`).

It does not include scanning, antivirus, DLP, PKI, permissioned-chain
anchoring, seed phrases, or hybrid ML-DSA.

## Planned additions

[ROADMAP.md](../ROADMAP.md) lists optional additions to this repository. 0.3.0
(key backup) is on `working` and is described above. None of the later phases
exists yet. When one ships, this file and [THREAT_MODEL.md](THREAT_MODEL.md)
change in the same release.

- Ledger export for SIEM (target 0.4): a command that verifies and decrypts
  the ledger locally and writes events without argument values. A field
  allowlist leaves out the proposal text and the derived amount and
  counterparty, which the ledger holds today.
- Inspection hooks for DLP and antivirus (target 0.5): an interface that
  calls external scanners. This package still does not scan or classify
  content itself.
- MCP adapter (target 0.6): an optional proxy in front of the gateway. This
  package is still not an MCP server.
- PKI and certificate recovery (target 0.7): X.509 identities for the
  principal, witness, capability issuer, and optionally agents, for personal
  use (a small local CA) and enterprise use (an existing CA and trust
  anchors), with revocation recorded in the ledger. Recovery is a backup
  bundle unlocked by a recovery key for personal use, and a key split k-of-n
  among custodians for enterprise use. This package does not become a
  general-purpose certificate authority.
- Post-quantum signatures (target 0.8): hybrid Ed25519 plus ML-DSA-65 for the
  long-lived signatures (the constitution and the ledger head), sized to this
  repository's scope.
- FIPS approved mode (target 0.9): an opt-in mode that refuses to start unless
  the cryptography library runs on a FIPS 140-3 validated module in approved
  mode, and that refuses algorithms outside the approved set. This package is
  not FIPS validated today, and that mode would not make it validated.
  Running on a validated module is not the same as this package being
  validated or compliant, and the docs will not describe it that way.
- Local GUI (target 0.10): a loopback-only interface for configuration and
  ledger auditing, built on the CLI and the existing file formats. It does not
  hold the principal key, and it is not a hosted or multi-user service.
  Filtering by judge needs per-judge ballot records (judge id, vote, and
  capped error only, never the rationale text), which the ledger does not
  hold today.
- Generic spec field types (planned, not scheduled): a typed field per
  argument path, each kind with its own limits. `amount` and `counterparty`
  become ordinary typed fields.

Read [FIT.md](FIT.md) before adopting it, [COMPARISON.md](COMPARISON.md)
before treating it as a substitute, and [THREAT_MODEL.md](THREAT_MODEL.md)
before treating a residual risk as closed.
