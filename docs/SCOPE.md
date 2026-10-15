# Scope

`two-key` is beta (pre-1.0). Package version 0.4.0. Tag
`v0.4.0` on `main` is the tagged release. Tags `v0.3.1` and earlier are in the archived `two-key-concept` repository. There, tag `v0.3.0` stays on `e44be56`. Tag `v0.2.4` stays on `fc836bb`.
Tag `v0.2.3` stays on `4a4352e`. Tag `v0.2.0` stays on `2f756ac`. Tag `v0.1.12`
is on `main`. `v0.1.6` stays on the previous tree.

It has:

- a signed constitution, Path A bytecode, and a policy VM that does not read English
- required `tool_specs` that fill Path A's form from argument bytes.
  Omitting them does not load. Path A evaluates five built-in structured
  fields (`tool`, `amount_usd`, `data_class`, `counterparty`,
  `irreversible`) plus up to 64 operator-declared custom fields (0.3.0):
  `boolean`, `integer`, `enum`, or `string`, each with a signed default and
  an optional description that is never an authorization rule. Enum and
  string values are printable ASCII by default, or Unicode with a declared
  script. Rules name them with `deny_if_fields`. A rules file that declares
  fields signs as a v2 constitution. `deny_unmapped`
  defaults off: an unnamed key does not reach the tool. Set the flag to deny
  it. A counterparty path requires `allow`. A payload `shape`, when set,
  locks the value to a string, a number, or a list of strings and does not
  read the contents
- Path B judge hooks for xAI, OpenAI-compatible APIs, Anthropic, Gemini, and local Ollama. At least one judge must be configured. With `required_yes` unset, the
affirmative threshold is `min(2, number_of_judges)`: one judge requires
one yes; two or more judges require two yes votes. This is not a majority
rule. Diversity floors are off by default; `high_assurance` requires at
least two operator-labelled model makers, at least one local judge, and
a yes from a local judge. No judge may be the monitored agent (a judge holding its credential, the same API token or the same username and password, at any address and whether or not either side sends it; or both keyless on one address); other overlaps warn. After a derive deny, argument bytes are withheld from judges unless `tool_args_on_derive_deny` is set, and a call that cannot be read (`derive_failed:`) is not sent to the judges at all
- monitored-agent hooks; `authorize_from_agent` does not execute a tool
- an AES-256-GCM ledger, a ledger key, and a witness key outside the ledger directory. The witness public key is pinned in the ledger (`witness_pinned`) and, optionally, outside it (`witness_public_key=`, `--witness-public-key`); it changes only by a ledgered `witness_rotated` entry (`two-key rotate-witness`). A head anchor beside the ledger key (`head.anchor`, or `--head-anchor`) refuses a rollback or wipe of the ledger directory alone; deleting that file accepts the ledger as it stands. `two-key recover` drops an uncheckpointed tail and does not run on open. `two-key audit` reports both pins
- a capability key outside the ledger directory. The gateway verifies
  tokens with the public half only. It runs in the `TwoKey` process on the
  `TwoKey` ledger object (`TwoKey.gateway()`); a gateway in another process
  or on another host is not supported (#45), and there is no gateway-only
  ledger role
- a single-use token and a gateway intended to be the only component that
  invokes registered tools; this does not stop an agent from calling a
  tool directly through another path
- on branch `working` (for 0.5.0), behind the optional `mcp` extra (the
  official MCP Python SDK): `two-key mcp-proxy`, a stdio proxy in front of
  one upstream MCP server. It starts the server as a child process, shows
  the agent only the signed tools, pins their schemas
  (`upstream.schema_digest`; a mismatch refuses to start unless
  `on_schema_change: warn`), refuses an unresolved judge or agent identity
  unless `allow_unresolved_identity: true`, and runs each `tools/call`
  through `authorize` and the in-process gateway with a per-tool claim
  policy. `two-key mcp-draft-specs` drafts `tool_specs` and the digest for
  the principal to review and sign; a draft does not sign until the
  principal decides each floor, amount unit, and allow list. The proxy
  speaks MCP to the agent's host but offers no tools of its own
- on branch `working` (for 0.5.0): caller-supplied facts. A field
  declared `source: caller` (constitution v3) takes its value from the
  integration's `facts=`, never from the agent's arguments; the gateway
  takes the facts again at redemption (`fact_mismatch`). The guard core
  (`two_key/guard.py`) runs one call through both keys for any agent loop,
  with fact hooks before authorize and again before the tool; the MCP
  proxy runs on it (`tools.<id>.facts`). Two-Key checks where a fact came
  from, not whether the hook is right
- passphrase backup of this package's own keys (0.3.0): three bundles, so the ledger key and the witness key are never in one file. `backup-verify` checks fingerprints in a temporary ledger. `backup-restore` puts `head.anchor` back from the same moment as the ledger. This is not a seed phrase

Modules that carry these rules include `two_key/fields.py` (custom Path A fields), `two_key/identity.py` (judge ≠ agent), `two_key/guard.py` (one guarded call, with fact hooks), `two_key/mcp_proxy/` (the MCP proxy and drafter; only `sdk.py` imports the SDK),
`two_key/strict.py` (duplicate-key JSON/YAML), `two_key/audit.py` (decision
digest checks), `two_key/backup.py` (key backup), and the per-install fingerprint key beside the ledger
(`*.ledger-key/fingerprint.key`).

It does not include scanning, antivirus, DLP, PKI, permissioned-chain
anchoring, seed phrases, or hybrid ML-DSA.

## Planned additions

[ROADMAP.md](../ROADMAP.md) lists optional additions to this repository, in
this order: the MCP adapter (0.5.0), DLP and antivirus hooks (0.6.0), and
the SIEM export (0.7.0), then 1.0. Nothing below exists in a release yet.
When an item ships, this file and [THREAT_MODEL.md](THREAT_MODEL.md) change
in the same release.

- MCP adapter (0.5.0): the proxy, the drafter, caller-supplied facts,
  and the framework-neutral guard core are built (above) and go through
  live test run 6 before the release. HTTP transports come later. The proxy offers no tools of its own.
- Inspection hooks for DLP and antivirus (0.6.0, next): an interface that
  calls external scanners. This package still does not scan or classify
  content itself.
- Judge connection reuse (#6, 0.6.0): judge connections are not reused
  today; each quorum round opens new ones.
- Ledger export for SIEM (0.7.0): a command that verifies and decrypts
  the ledger locally and writes events without argument values. A field
  allowlist leaves out the proposal text and the derived amount and
  counterparty, which the ledger holds today.
- Judge history summary (#1, before 1.0): judges get a summary of recent
  decisions built from the ledger, on by default, after its own security
  review.

After 1.0, not scheduled:

- PKI and certificate recovery: X.509 identities for the
  principal, witness, capability issuer, and optionally agents, for personal
  use (a small local CA) and enterprise use (an existing CA and trust
  anchors), with revocation recorded in the ledger. Recovery is a backup
  bundle unlocked by a recovery key for personal use, and a key split k-of-n
  among custodians for enterprise use. This package does not become a
  general-purpose certificate authority.
- Post-quantum signatures: hybrid Ed25519 plus ML-DSA-65 for the
  long-lived signatures (the constitution and the ledger head), sized to this
  repository's scope.
- FIPS approved mode: an opt-in mode that refuses to start unless
  the cryptography library runs on a FIPS 140-3 validated module in approved
  mode, and that refuses algorithms outside the approved set. This package is
  not FIPS validated today, and that mode would not make it validated.
  Running on a validated module is not the same as this package being
  validated or compliant, and the docs will not describe it that way.
- Local GUI: a loopback-only interface for configuration and
  ledger auditing, built on the CLI and the existing file formats. It does not
  hold the principal key, and it is not a hosted or multi-user service.
  Filtering by judge uses the per-judge ballot records planned for 1.0
  (judge id, vote, confidence, error class, and a rationale digest, never
  the rationale text); the ledger does not hold them today.
- More spec field types: decimal, URL, path,
  email, and opaque bytes. `amount` and `counterparty` become ordinary typed
  fields. Custom `boolean`, `integer`, `enum`, and `string` fields shipped
  in 0.3.0 and are described above.

Read [FIT.md](FIT.md) before adopting it, [COMPARISON.md](COMPARISON.md)
before treating it as a substitute, and [THREAT_MODEL.md](THREAT_MODEL.md)
before treating a residual risk as closed.
