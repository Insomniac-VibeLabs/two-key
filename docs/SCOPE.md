<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Scope

`two-key` is beta (pre-1.0). Package version 0.9.0, tag `v0.9.0` on `main`, is the latest release; what
it added is marked 0.9.0. What each release
shipped is under "Shipped" in [ROADMAP.md](../ROADMAP.md); tags and branches are in
[AGENTS.md](../AGENTS.md).

It has:

- a signed constitution, Path A bytecode, and a policy VM that does not read English
- required `tool_specs` that fill Path A's form from argument bytes.
  Omitting them does not load. Path A evaluates five built-in structured
  fields (`tool`, `amount_usd`, `data_class`, `counterparty`,
  `irreversible`) plus up to 64 operator-declared custom fields (0.3.0):
  `boolean`, `integer`, `enum`, `string`, or `path`, each with a signed default and
  an optional description that is never an authorization rule. Enum and
  string values are printable ASCII by default, or Unicode with a declared
  script, or, for a case-sensitive id, `case: exact` (0.5.0). A `path`
  value (0.9.0) is an absolute file path inside one of the field's signed
  folders, cleaned as text only; Two-Key does not open the file, so it is a
  signed check on the request, not a sandbox. Rules name
  them with `deny_if_fields`, and every tool maps each field a rule reads
  or marks it `not_applicable` (0.5.0). A rules file that declares fields
  signs as a v2 constitution, or v3 with a 0.5.0 feature. `deny_unmapped`
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
  or on another host is not supported, by design ([why](HOWTO.md#deployment-boundary-the-gateway-runs-in-the-twokey-process)), and there is no gateway-only
  ledger role
- a single-use token and a gateway intended to be the only component that
  invokes registered tools; this does not stop an agent from calling a
  tool directly through another path
- since 0.5.0, behind the optional `mcp` extra (the
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
- since 0.5.0: caller-supplied facts. A field
  declared `source: caller` (constitution v3) takes its value from the
  integration's `facts=`, never from the agent's arguments; the gateway
  takes the facts again at redemption (`fact_mismatch`). The guard core
  (`two_key/guard.py`) runs one call through both keys for any agent loop,
  with fact hooks before authorize and again before the tool; the MCP
  proxy runs on it (`tools.<id>.facts`). Two-Key checks where a fact came
  from, not whether the hook is right
- since 0.5.0, from live run 6: every tool maps each
  field a rule reads or marks it `not_applicable` (a forgotten mapping does
  not sign or load); `case: exact` string fields for case-sensitive ids;
  `@domain` allow entries for every plain address at one domain, with a
  signing warning; no judge is asked about a call that cannot be read
  (`skipped:derive_failed`); a start-up warning when one judge can approve
  alone; and a drafter warning for a payee or amount with no upstream
  description
- since 0.6.0: Windows support
  (`two_key/_platform.py`), judge connection reuse (#6), and optional
  content scanning. A scanner (`two_key/scan.py`; adapters for ClamAV
  `clamd`, ICAP, a command, and Python in `two_key/scanners.py`) calls the
  operator's antivirus or DLP product for each call to a tool the signed
  constitution marks, files included (base64, or a path in a declared
  folder). Two-Key starts every scan; the verdict is a caller-supplied
  enum fact that a signed rule decides on, told to the judges and recorded
  without content. An encrypted file passes only on a tool signed
  `encrypted: pass` (docs/SCANNERS.md)
- in 0.7.0: the SIEM export
  (`two_key/siem.py`, `two_key/siem_sinks.py`, `two_key/siem_export.py`).
  Optional: with no `siem=` setting nothing changes. Each ledger entry is
  copied, after it is written, to a syslog sink (TLS by default, or plain
  TCP or UDP) or an HTTPS webhook, in Two-Key's own schema, ECS, or OCSF,
  as JSON or CEF. An explicit per-kind field allowlist decides what leaves:
  reason codes, digests, sizes, the tool id, the data class, never argument
  values, proposal text, derived amounts, counterparties, or custom field
  values. A collector that is down never blocks an authorization.
  `two-key siem-export` writes the same events to a file and
  `two-key siem-verify` checks a file against the ledger. The gateway also
  counts tokens it refuses without a ledger entry, by class, rate-limited,
  with no token text (docs/SIEM.md). It is not a SIEM and it does not alert
- in 0.7.3: `two-key setup` and `two-key config set`, `get`, `undo`, `show`
  and `check` (docs/SETUP.md). A change is checked as a whole before it is
  written, a weaker one needs a typed yes, a signed one needs the principal
  key, and each is recorded in the ledger as `config_changed` with no
  values. A principal key can be encrypted with a passphrase. A signed
  `serial` orders constitutions: once a ledger has run one, it refuses an
  older, reused, or missing serial. The start-up checks also look at the
  upstream server's files named in `upstream.command` and
  `upstream.check_paths` (#13)
- in 0.8.0: the judge history summary (#1,
  `two_key/history.py`). Each judge's prompt gets a
  `<decision_history>` section built from the ledger: recent decisions on
  the same tool and signed counterparty, ages, totals of redeemed calls,
  denies in the last hour and day, recent scan verdicts, and denial bursts
  as attempt episodes. Reason codes and signed values only, never proposal
  text or rationale. On by default (`quorum.judge_history`); a summary that
  cannot be built denies by default, and a decision whose history changed
  before the token is issued is denied `history_changed`. Each ballot is
  recorded per judge with an HMAC digest of its rationale, never the text.
  `two-key ledger-view` shows the ledger in a read-only window (tkinter, no
  network port) to search, filter, and sort every field of every entry for an
  audit, or prints the matches as JSON Lines (`--print`); it opens the ledger
  the way `two-key audit` does and writes nothing
  ([LEDGER_VIEW.md](LEDGER_VIEW.md)).
  `two-key constitution-editor` writes, checks, and signs a constitution
  (prose, hard rules, tool specs, custom fields, serial) in a window
  (tkinter, no network port), and runs a trial call on a throwaway key and
  ledger to show Path A's decision and a judge's prompt; it signs with the
  same code as `sign-constitution` ([CONSTITUTION_EDITOR.md](CONSTITUTION_EDITOR.md))
  The MCP proxy allows one proxy per agent by default
  (`one_proxy_per_agent`)
- in 0.9.0: every signature is hybrid
  Ed25519 + ML-DSA-65, and a 0.8.0 deployment's keys are upgraded once at
  the first start (`keys_upgraded`, [UPGRADING.md](UPGRADING.md#the-key-upgrade-090));
  a tool behind the proxy can check each call itself and sign a receipt
  (the tool check, [TOOL_CHECK.md](TOOL_CHECK.md)), required under
  `high_assurance`; a tool error spends the token; `two-key setup --window`
  asks setup's questions in a window ([SETUP.md](SETUP.md#the-setup-window-two-key-setup---window));
  `config set 'tools[*].claim'` changes one setting on every tool as one
  change; and a ten-minute [quickstart](QUICKSTART.md)
- passphrase backup of this package's own keys (0.3.0): three bundles, so the ledger key and the witness key are never in one file. `backup-verify` checks fingerprints in a temporary ledger. `backup-restore` puts `head.anchor` back from the same moment as the ledger. This is not a seed phrase

Modules that carry these rules include `two_key/keys.py` and `two_key/upgrade.py` (hybrid keys and the key upgrade), `two_key/toolcheck.py` (the tool check), `two_key/fields.py` (custom Path A fields), `two_key/identity.py` (judge ≠ agent), `two_key/guard.py` (one guarded call, with fact hooks), `two_key/mcp_proxy/` (the MCP proxy and drafter; only `sdk.py` imports the SDK),
`two_key/strict.py` (duplicate-key JSON/YAML), `two_key/audit.py` (decision
digest checks), `two_key/history.py` (the judge history summary), `two_key/backup.py` (key backup), `two_key/siem.py` and
`two_key/siem_sinks.py` (the SIEM field allowlist and sinks), and the per-install fingerprint key beside the ledger
(`*.ledger-key/fingerprint.key`).

It does not include a scanning, antivirus, or DLP engine (the 0.6.0 hooks
call the operator's product), a SIEM or log management product (the 0.7.0
export feeds the operator's collector), PKI, permissioned-chain anchoring,
or seed phrases. Signatures are hybrid Ed25519 + ML-DSA-65 from 0.9.0.

## Planned additions

[ROADMAP.md](../ROADMAP.md) lists optional additions to this repository, in
this order: the MCP adapter (0.5.0), DLP and antivirus hooks (0.6.0), the
SIEM export (0.7.0), the judge history (0.8.0), the tool check and hybrid
signatures (0.9.0), then 1.0. An item marked shipped or built is described
above; the rest is not in a release yet.
When an item ships, this file and [THREAT_MODEL.md](THREAT_MODEL.md) change
in the same release.

- MCP adapter (0.5.0): shipped (above). HTTP transports come later. The
  proxy offers no tools of its own.
- Inspection hooks for DLP and antivirus (0.6.0): shipped (above). This
  package still does not scan or classify content itself.
- Judge connection reuse (#6, 0.6.0): shipped; a lock-guarded pool keyed by
  origin.
- Ledger export for SIEM (0.7.0): shipped (above). Live
  delivery and a file export, both on a field allowlist that leaves out the
  proposal text and the derived amount, counterparty, and custom field
  values, which the ledger holds today. With it, a rate-limited count of
  tokens the gateway refused without a ledger entry (forged, expired, or
  malformed), kept outside the ledger (live run 7). What the collector
  stores, who can read it, and what it alerts on stay the operator's.
- Judge history summary (#1, 0.8.0): shipped. Judges get a summary of
  recent decisions built from the ledger (`two_key/history.py`), on by
  default, with per-judge ballot records and one proxy per agent
  ([JUDGES_AND_QUORUM.md](JUDGES_AND_QUORUM.md#judge-history)).

- Hybrid post-quantum signatures (0.9.0): built (above).

After 1.0, not scheduled:

- FIPS approved mode, once a validated module offers ML-DSA-65: an opt-in
  mode that refuses to start unless the cryptography library runs on a FIPS
  140-3 validated module in approved mode, and that refuses algorithms
  outside the approved set. Every algorithm Two-Key uses is FIPS-approved
  already, and the mode never drops ML-DSA-65. OpenSSL 3.5, the first
  OpenSSL with ML-DSA, is in NIST's validation queue (submitted October 2025,
  no certificate as of 2026-10-29). Running on a validated module is not the
  same as this package being validated, and the docs will not describe it
  that way.
- PKI and certificate recovery: X.509 identities for the
  principal, witness, capability issuer, and optionally agents, for personal
  use (a small local CA) and enterprise use (an existing CA and trust
  anchors), with revocation recorded in the ledger. Recovery is a backup
  bundle unlocked by a recovery key for personal use, and a key split k-of-n
  among custodians for enterprise use. This package does not become a
  general-purpose certificate authority.
- Local GUI: a loopback-only interface for configuration and
  ledger auditing, built on the CLI and the existing file formats. The
  read-only audit view shipped early as `two-key ledger-view` (0.8.0, above), and the
  constitution part as `two-key constitution-editor` (0.8.0, above), and setup as
  `two-key setup --window` (0.9.0); all are tkinter windows and hold the
  principal key while they use it. It is not a hosted or multi-user service.
  Filtering by judge uses the per-judge ballot records the ledger holds since
  0.8.0 (judge id, vote, confidence, error class, and a rationale digest,
  never the rationale text).
- More spec field types: decimal, URL,
  email, and opaque bytes. `amount` and `counterparty` become ordinary typed
  fields. Custom `boolean`, `integer`, `enum`, and `string` fields shipped
  in 0.3.0, and `path` fields in 0.9.0; they are described above.

Read [FIT.md](FIT.md) before adopting it, [COMPARISON.md](COMPARISON.md)
before treating it as a substitute, and [THREAT_MODEL.md](THREAT_MODEL.md)
before treating a residual risk as closed.
