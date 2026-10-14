# Threat model

This is the design model for `two-key-concept` 0.3.0. Tag `v0.3.0` on `main` is the tagged release. Tag `v0.2.4` stays on `fc836bb`. Tag `v0.2.3` stays on `4a4352e`. `v0.2.0` stays on `2f756ac`. 0.3.0 adds passphrase backup of this package's own keys, in three bundles. 0.2.4 adds a head anchor outside the ledger directory (#62) and `two-key recover` for an uncheckpointed tail (#49). 0.2.3 pins the ledger's witness public key in the ledger and, optionally, outside it (#58), refuses a judge that holds the monitored agent's credential whether or not it is sent and in either form (token or username and password), and removes the `vendor` / `min_vendors` aliases. Password fingerprints use PBKDF2-HMAC-SHA256, an approved function, instead of scrypt. 0.2.2 changed when a judge counts as the monitored agent and added HTTP Basic auth.
It is not a penetration test and it is not an independent review. The package is a
prototype. It is not a FIPS 140-3 validated module. Crypto is Ed25519,
SHA-256, and AES-256-GCM from the `cryptography` package.

How to report a vulnerability is [SECURITY.md](../SECURITY.md). The longer
narrative is the README. This file is the register. If the two disagree,
the code wins, then this file should be corrected.

## Assets

- The signed constitution and the two compilation hashes (bytecode and prose).
- The principal signing key. It signs the constitution and the ledger head.
  It does not sign capability tokens.
- The capability private key, outside the ledger directory
  (`<ledger>.capability/capability.pem`). `TwoKey` mints with it. The
  gateway's verifier holds only the public half. This is key separation
  at the API, not process isolation: the gateway runs in the `TwoKey`
  process on the `TwoKey` ledger object (`TwoKey.gateway()`), which holds
  the principal, witness, and ledger keys, and the minting key is in the
  same process. A gateway in another process or on another host is not
  supported (#45).
- The ledger key and the witness key, both outside the ledger directory
  (`<ledger>.ledger-key` and `<ledger>.witness`).
- The witness public key the operator keeps outside the ledger
  (`witness_public_key=`, `--witness-public-key`), when one is configured. It
  is not secret, but whoever can change it can make a forged head pass.
- The head anchor (`<ledger>.ledger-key/head.anchor`, or `anchor_path=` /
  `--head-anchor`). It is not secret. Whoever can change or delete it can
  make a rolled-back ledger pass. It is not an external anchor.
- The per-install fingerprint key (`<ledger>.ledger-key/fingerprint.key`),
  which keys credential fingerprints. It sits beside the ledger key, so it
  protects fingerprints only from someone without that directory. Against
  someone with it, a random API token is safe by its length, a guessable
  token (a placeholder such as `EMPTY`, or a short key chosen for a local
  server) is not, and a password is protected only by PBKDF2's cost
  (600,000 iterations), which slows guessing but does not stop it for a
  guessable password. PBKDF2 is not memory-hard, so dedicated hardware
  guesses faster against it than against scrypt; it is used because it is
  an approved function and scrypt is not (ROADMAP 0.9).
- The wrapped data key stored inside the ledger directory.
- Judge credentials and monitored-agent credentials. They are not the same secret.
- The capability token and the argument bytes it is bound to.
- Tool credentials, which only the gateway should hold.
- The ledger head and the hash chain.

## Actors

- The principal, who holds the signing key and writes the constitution.
- An untrusted agent, local or cloud. Hosting is not trust.
- Path B judges, each with its own credential. A judge can be wrong.
- The caller that invokes authorize, then the gateway.
- Anyone who can read or write the ledger directory, the ledger key, or the
  witness key.

## Trust boundaries

- Caller to the monitored agent. The agent gets the system prompt, the
  constitution prose, the instruction, and, only when the caller passes
  it, the syntax-only `agent_vocabulary()`. It never gets bytecode, an
  `allow` list, a rule, a threshold, or a credential. Ids written in the
  prose or the instruction do reach it and its host.
- Agent to `authorize_from_agent`. The reply is a proposal or a decline. The
  method does not execute a tool. A decline (`agent_declined`) runs neither
  path and issues no token; a decline mixed with a call is
  `malformed_proposal`. A hostile agent can decline to deny service, as it
  already could with a bad proposal; it cannot turn a decline into an allow. A cloud judge must not reuse an agent credential.
  A missing session is a deny (`cloud_judge_session_required`).
- Caller to Path A. The VM sees the normalized action record, not the proposal.
- Caller to Path B. Judges see the constitution prose and the normalized
  record. Non-empty tool arguments are attached on that record as
  `tool_args`, except after a derive deny (`derive_failed:*`,
  `amount_mismatch`, `counterparty_mismatch`, `irreversible_mismatch`).
  `tool_args_on_derive_deny` defaults false. Set it true to send those
  bytes. Path B still runs either way. Other denies still attach the
  arguments. The proposal is withheld unless that judge sets
  `receives_proposal` or the quorum policy is `judge_inputs: record_and_proposal`.
  The default is record-only.
- Both paths run once the call is well-formed and within limits; a malformed or oversized
  call is denied before either path (size and digest only). `require_path_a_first` is stored on the policy and
  copied into `to_record`. `TwoKey.authorize` does not read it. There is no
  `short_circuit_path_b` setting on `TwoKey`.
- Gateway to the tool. The token is checked against the caller's argument
  bytes, then `redemption_started` is checkpointed, then the registered
  function is called with declared paths only. Unnamed keys are not passed
  in. A counterparty path is the canonical party, not the raw spelling.
  Nothing in this package scans those bytes.
- Process to the ledger. Appends and checkpoints take a POSIX `flock` on
  `<ledger>.lock` next to the ledger directory. If the file changed since
  this process loaded it, the write is refused. Redemption also takes a
  `flock` under `<ledger>.redeem-locks/`, outside the ledger directory.
  Where `fcntl` is absent, only the in-process lock remains.

## What this design is meant to stop

- A tool execution inside `authorize_from_agent`.
- An allow when either path denies or does not answer. A missing, malformed,
  or timed-out ballot is an abstention, not a yes. A ballot that names
  another judge abstains (`judge_id_mismatch`). At least one judge must
  be configured. With `required_yes` unset, the affirmative threshold is
  `min(2, number_of_judges)`; this is not a majority rule. The default
  has no diversity floors. `QuorumPolicy.high_assurance()` needs judges
  from two model makers (the operator's `maker:` labels, not verified),
  one local judge, and a yes from a local judge;
  `QuorumPolicy.section4()` is that plus `require_path_a_first`. The flag
  is still not a skip. `min_distinct_providers` still defaults to 1.
- A judge is not the monitored agent: `TwoKey` refuses to start when a
  judge holds the agent's credential (the same API token, or the same
  username and password) at any address, whether or not either side sends
  it and whether it is held as a token or as a Basic pair, or when both
  sides send no credential on one address, compared as configured
  (`host:port`, local aliases folded, no DNS). Any model and any
  vendor is allowed otherwise. The likely accidents (one side keyless on
  the agent's address, the agent's model on its address or through a
  shared or undeclared proxy, a shared tenant id, an unresolved upstream)
  start with a warning on stderr and in `constitution_loaded`. The agent
  is declared by the operator, never by the agent. A judge that presents
  the runtime agent's session abstains, wherever it connects.
- A value read twice: every JSON and YAML input refuses a repeated key and
  a YAML merge key (`<<`).
  Oversized or too-deeply nested arguments are a deny before the ledger.
  Inputs stop at 62 levels, two under the encoder's 64, so the ledger and
  judge wrappers always encode.
- A token replay, a token used for different argument bytes, a token used
  after expiry (120 seconds unless you change it, at most 300), a token
  whose lifetime exceeds the TTL or whose issue time is in the future, and
  a token issued before a revocation or a constitution reload and used after
  it. `revoke` ends earlier tokens only: it does not stop new approvals and it
  does not survive a restart (see HOWTO, "Revoke outstanding tokens").
- A second run of a token after `redemption_started` has been checkpointed.
  A tool exception writes `redemption_aborted` and leaves the token usable.
- A silent edit of a ledger record that still verifies, and opening the log
  with only the principal key. The head needs a witness signature as well.
- A replaced `witness.pem`, or a head signed by another witness key, on a
  chain that was not rewritten (#58). The witness public key is pinned in
  the ledger: the first entry of a new ledger is `witness_pinned`, and a
  ledger from 0.2.2 or earlier pins the key that signed its head on its
  first open under 0.2.3. A head or a `witness.pem` that does not match is
  refused (`witness_key_changed`) on open, append, and checkpoint. The key
  changes only by a `witness_rotated` entry signed by the principal and the
  old and new witness keys.
- With the witness public key also configured outside the ledger
  (`witness_public_key=`, `--witness-public-key`), a head forged with the
  principal key and the ledger key but without the witness private key,
  even on a chain rewritten from its first entry.

## Assumptions

- The gateway is the only holder of tool credentials. This package cannot
  stop an agent that can call the tool by another path.
- The principal key and the ledger key are not both in the attacker's
  hands, unless the witness public key is configured outside the ledger.
  With that pin, the assumption is that the principal, witness, and ledger
  keys are not all in the attacker's hands, and that the attacker cannot
  change the configured copy of the witness public key.
- The action record describes the real call only for fields the tool spec
  names. Every loaded constitution has `tool_specs`. A tool with no spec
  does not redeem. A counterparty path requires `allow`. A party off that
  list does not authorize (`counterparty_not_allowed`), unless a blocked
  party is also present, in which case the block rule still denies.
  `deny_unmapped` defaults off. An unnamed key does not reach the tool.
  Setting the flag denies the call instead (`unmapped_field`). Custom
  fields (`fields:`, `deny_if_fields`) are read the same way: from the
  argument path the signed spec names, never from the agent's claim. A tool
  that does not map a field gets that field's signed default.
- Judges are one key of two. The quorum does not prove the models are
  independent. The diversity floors are off by default; `high_assurance`
  turns them on. A judge that is not the same agent may still share a
  provider and its blind spots with the agent, or run the agent's model
  under another key (allowed; warned on the same address or through a
  shared or undeclared route, silent through a recognized router). A declared `upstream:` and a
  `model_prefix` resolution are operator-attested and not verified; they
  change which warnings print, not what is refused. Two names for one
  server (a CNAME, or a host name and its IP) are two addresses.
- Without a local judge, the constitution prose, the action record, and any
  attached tool arguments go to the cloud judges' vendors.

## Residual risks

These are accepted or still open. They are not bugs the design already
claims to close.

- No independent review, and no production deployment.
- Custom Path A fields (0.3.0). A tool that does not map a field gets the
  field's signed default, as a tool with no amount spec has `amount_usd` 0.
  A mapping the operator forgot is therefore silent. Rules written as
  allow-lists (`not_in`) and restrictive defaults fail closed in that case;
  rules written as deny-lists (`in`, `eq`) do not. A deny-list on a
  `string` field also misses spelling variants (`prod` and `production`).
  Characters are controlled, meaning is not: lookalike letters from another
  script, invisible characters, and direction controls deny, but this
  package does not know that two words mean the same thing. A field
  declares one script or one approved combination (`japanese`, `korean`,
  `chinese`), so one field cannot hold words from two unrelated scripts.
  Script detection uses Unicode character names from Python's
  `unicodedata`, whose Unicode version differs by Python release; a
  character newer than the running Python's data is refused. Derived field
  values are written to the encrypted ledger and sent to judges, including
  cloud judges; descriptions are not. A description is shown to people
  only, and direction controls are refused in it, but its wording can still
  mislead a reviewer; it is signed with the rest of the constitution.
- Trusting the agent's claimed fields instead of reading them from the
  argument bytes is closed for loaded constitutions. `tool_specs` is required to
  sign and to load. `two_key/derive.py` reads amount and counterparties by
  JSON path. It does not read English. A present claim that disagrees with
  the bytes is a deny (`amount_mismatch`, `counterparty_mismatch`,
  `irreversible_mismatch`). An omitted amount or counterparty is filled from
  the bytes. A missing amount path, a non-numeric amount, or a currency path
  that is not `usd` denies. `data_class` is the stricter of the claim and
  `data_class_floor`. Two different middle classes (`personal`, `medical`,
  `financial`) join to `classified`. The token binds `spec_hash` and that
  form. The gateway recomputes the form from the same bytes and refuses a
  mismatch. Changing a spec changes `spec_hash`, so outstanding tokens fail
  at the gateway. This package does not classify free text and does not
  track per-value information flow. A counterparty the spec copies must be
  on that path's `allow` list. The tool receives the canonical value
  (`strip`, casefold), not the raw spelling. A party that is not listed is
  `counterparty_not_allowed`, unless a blocked party is also present, in
  which case the block rule denies. A currency path is delivered as `usd`.
  A path the spec does not declare does not
  change the form and is not passed to the tool. With `deny_unmapped` left
  off (the default), the call can still allow. With `deny_unmapped` set,
  the unnamed key is `unmapped_field`. Neither mode interprets the value.
  `payload` names a value that may be present. With no `shape`, the path
  covers that value and its children, and the value is not classified.
  `shape` of `string`, `number`, or `list` (strings only) refuses a
  different kind. `max_length` bounds a string or a list. A boolean is not
  a number. `payload_shape` is a derive deny. Shape does not read contents.
  Meaning stays with Path B. A DLP hook is planned (see
  [ROADMAP.md](../ROADMAP.md)). The token still binds
  the caller's original argument bytes. Redeem with those same bytes. The
  function is called with the projection. Missing `data_class` still becomes
  `classified` before the floor, and the floor cannot lower that default.
  Missing `irreversible` is taken from the spec, so a tool signed as
  reversible stays reversible. A present `irreversible` claim that differs
  is `irreversible_mismatch`. The policy VM has one counterparty string. A
  list is reduced to one party, preferring any party on
  `deny_counterparties`, so a blocked party is not hidden behind an allowed
  one. A derived amount that is not finite or above the action sanity cap
  is `amount_unreadable`.
- A derive deny does not skip Path B. Judges still receive the normalized
  action record. They do not receive `tool_args` unless
  `tool_args_on_derive_deny` is true. A deny that is not a derive deny still
  attaches non-empty arguments. The tool still does not run on a deny.
- The gateway's verifier has no capability-minting private key. The minting
  key is the capability key outside the ledger directory. The principal
  key remains on the shared ledger object because the ledger head needs it.
  A token signed with the principal key fails `bad_signature`. The gateway
  is not a separate process or host, and a split gateway is not supported
  (#45): it shares the `TwoKey` process and ledger object. Registered tools
  run in that process, so a compromised tool or dependency can read the
  minting key and the principal, witness, and ledger keys. Do not treat the
  implementation as providing process-level isolation. A gateway built on a
  ledger no `TwoKey` in the process opened warns once
  (`TwoKeyDeploymentWarning`) and refuses tokens issued after that ledger
  opened: the check fails as `ledger_size_invalid`, and recording that
  refusal fails too, so the caller sees `ledger_failed: ledger file changed
  by another writer`.
- Stealing the ledger key decrypts the log. Stealing the principal key does
  not, and it does not mint a token the gateway will accept. Stealing the
  capability private key does. Stealing the principal key and the ledger
  key is still enough to forge a head when no witness public key is
  configured outside the ledger: the in-ledger pin is part of the chain, and
  those two keys can rewrite the chain from its first entry, pin included,
  under a new witness key. With the out-of-ledger pin, forging a head needs
  the principal, witness, and ledger keys together (#58). There is no
  external anchor, so those keys are enough to rewrite a ledger that never
  leaves the machine.
- Trust on first use: a ledger from 0.2.2 or earlier pins the witness key
  that signed its current head on its first open under 0.2.3. A witness key
  swapped before the upgrade, and the heads it signed, cannot be detected.
  A configured out-of-ledger pin, if the operator kept a copy of the
  original witness public key, does detect it.
- A rollback or wipe that also deletes `head.anchor`, or replaces it with an
  older copy. The anchor sits outside the ledger directory
  (`<ledger>.ledger-key/head.anchor`, or `--head-anchor`). A ledger-directory
  writer who cannot touch that file is refused (`ledger_rolled_back`). The
  file is adopted when it is missing, so deleting it and opening accepts the
  ledger as it stands. With the principal key and write access to
  `<ledger>.ledger-key` and `<ledger>.witness`, a whole replacement ledger
  under a new ledger key verifies once that attacker also removes the
  anchor, unless the witness public key is configured outside the ledger.
  Neither witness pin, by itself, detects a rollback. There is still no
  external anchor (#62).
- A rotation interrupted after its head is written and before the new key
  is moved into place leaves `witness.pem.new` beside `witness.pem`, and the
  ledger refuses to open (`witness_key_changed`) until it is moved. A lost
  witness key is restored from the witness bundle (0.3.0). Without that
  bundle it means a new ledger.
- Key backup bundles (0.3.0). A bundle is equal to the keys it holds.
  `principal.bundle.json` holds the principal key and the capability key.
  `ledger.bundle.json` holds the ledger key, the fingerprint key, the ledger
  ciphertext, and `head.anchor` from that moment. `witness.bundle.json` holds
  the witness key. One bundle never holds every key a signed head needs.
  Guessing a bundle's passphrase opens that bundle. PBKDF2-HMAC-SHA256
  (600,000 iterations) slows guessing and is not memory-hard. The same
  passphrase on two bundles, or on all three, stored together, is one guess.
  Export holds the ledger lock while it copies, and it does not write a
  bundle set that would not open. It refuses a symlink output directory and
  a directory the group or others can write.
  A restore onto a newer ledger fills missing key files only. A key already
  on disk stays, including a witness rotated after the backup, so that
  restore does not roll the witness back. `--replace-ledger` is what writes
  the older ledger, its anchor, and the keys from that moment.
  `backup-restore --replace-ledger` writes an older ledger and its anchor
  together, and replaces a key file that differs, which can make a token
  spent after the backup look unspent and undoes a later witness rotation.
  Deleting `head.anchor` is still not detected, and restore does not do it.
  The backup is not an external anchor.
- What the ledger holds today: the agent's proposal text in full (the
  `proposal` entry), the derived form (`action_normalized.form`: the amount,
  counterparty, counterparties, and custom field values read from the
  argument bytes), reasons,
  digests, and sizes. It never holds the raw argument bytes of an oversized
  or dropped value, only its size, digest, or key name. It never holds keys.
  Anyone who can decrypt the log can read the proposal text and the derived
  amount, counterparties, and custom field values.
- A crash after `redemption_started` and before the tool runs refuses a
  retry, even if the tool did not run. Exactly-once execution is not claimed.
- Where `fcntl` is absent, another process can still append. This package
  does not claim cross-process exclusion on those platforms.
- There is no TEE. OAuth device-code judge auth is rejected. A username and
  password is accepted only as HTTP Basic over HTTPS (`type: basic`). Use
  `env`, `keyring`, `callback`, or `basic`.
- `judges.yaml` and `agents.yaml` are trusted operator configuration. A
  `callback` auth entry names `module:function`, and that module is
  imported when the file loads. An attacker who can write either file can
  run code in the `TwoKey` process, which holds every key. Protect them
  like the code.
- By default the monitored agent is not given `tool_specs`. It learns
  tool ids, argument keys, counterparty ids, and data classes only from
  the signed prose. An agent that guesses them is denied, which is
  fail-closed but makes legitimate calls fail when the prose leaves them
  out. The opt-in `TwoKey.agent_vocabulary()` sends tool ids, argument
  paths, value syntax, floors, and data classes, and grants nothing. It
  never lists a value (no `allow` list, enum value, integer bound, rule,
  threshold, `deny_counterparties`, description, default, or
  `irreversible` flag), so an agent doing reconnaissance learns the shape
  of a call, not which payee or amount would pass; each wrong guess is a
  ledgered deny. Ids written in the prose do reach the agent and its
  host. Two-Key does not map display names to ids and does no fuzzy
  matching.
- The signatures are not quantum resistant. Ed25519 signs the constitution,
  the ledger head (principal and witness), and capability tokens. A
  sufficiently capable quantum computer could forge an Ed25519 signature.
  The exposure is greatest for long-lived signatures, the constitution and
  the ledger head. A capability token lives at most 300 seconds, so it is a
  smaller exposure. AES-256-GCM and SHA-256 are not the concern at these
  sizes. Hybrid signatures are planned (see [ROADMAP.md](../ROADMAP.md)).

## Out of scope

- The prototype status itself and missing FIPS validation. A planned
  approved mode (see [ROADMAP.md](../ROADMAP.md)) would run on a validated
  module. It would not validate this package.
- Prompt injection that Path A denies because the structured record tripped
  a rule.
- A vulnerability in a judge vendor's API.
- Using this package as an MCP server, as user login, or as a DLP or
  antivirus product. It is none of those. An optional MCP adapter and
  scanner hooks are planned (see [ROADMAP.md](../ROADMAP.md)). They would sit
  in front of or beside the gateway, and they would not make this package a
  server or a scanner.
- Full per-value information-flow tracking, and a content classifier. A
  tool-spec floor is not a taint label. Scanning engines, external or
  permissioned-chain anchoring, and seed phrases are not here and are not
  planned. Planned scanner hooks, PKI with certificate recovery, and hybrid
  signatures are in [ROADMAP.md](../ROADMAP.md). Key backup shipped in
  0.3.0. See [SCOPE.md](SCOPE.md).

## Planned changes to this model

These come from [ROADMAP.md](../ROADMAP.md). None of what follows is in 0.3.0, and nothing in
this section describes current behavior. Each item is added to the sections
above in the release that ships it. Key backup and custom Path A fields
shipped in 0.3.0 and are described above, not here.

- Ledger export for SIEM (target 0.4). New boundary: ledger to exporter to
  SIEM. Export decrypts, so the exported stream leaves encryption at rest. It
  is meant to carry digests, sizes, and reason codes, not argument values.
  It is meant to use a field allowlist that leaves out the proposal text and
  the derived amount, counterparty, and custom field values, which the
  ledger holds today.
  Whoever can read the SIEM becomes a new audience for ledger metadata.
- Inspection hooks for DLP and antivirus (target 0.5). New trust boundary:
  the scanner. A scanner error, timeout, or missing result is meant to be a
  deny. A scanner sees only what the tool spec lets through, so a payload
  value it cannot read stays a residual risk. Where the hook runs relative to
  the judges is an open choice, because cloud judges receive `tool_args`
  today.
- MCP adapter (target 0.6). New boundary: MCP client to proxy to MCP server.
  The assumption that the gateway is the only holder of tool credentials
  becomes the central one, because an agent that can reach an MCP server
  directly bypasses the proxy. A `tool_specs` draft made from MCP schemas is
  a proposal for the principal to review and sign, not trusted input.
- PKI and certificate recovery (target 0.7). New assets: the certificate
  authority key (a personal local CA or an enterprise CA), issued
  certificates, the revocation list, and recovery material (a backup bundle,
  a recovery key, or key shares). New boundary: certificate validation, meaning
  chain building to a configured trust anchor, validity period, key usage, and
  revocation. A stolen CA key lets an attacker mint identities the package
  accepts, so it is treated as equal to the principal key or higher. Recovery
  is itself an attack path: a stolen recovery key, enough colluding or
  coerced custodians, or a social-engineered recovery request can replace an
  identity. Recovery is meant to be a ledger event and to end with the old
  certificate revoked. Validity checks depend on a correct clock. Existing
  bare-key setups stay valid.
- Post-quantum signatures (target 0.8). New assets: a second signing key per
  signing role, and larger signatures in the constitution, ledger head, and
  possibly tokens. A hybrid signature is meant to verify only when both
  halves verify. New risk to design against: a downgrade, where the
  post-quantum half is stripped. Every signed format carries an algorithm
  identifier, and a verifier that expects the hybrid form refuses a
  classical-only one. Existing 0.2.x ledgers stay readable.
- FIPS approved mode (target 0.9). New boundary: the cryptographic provider.
  The mode is meant to refuse to start unless the library runs on a FIPS
  140-3 validated module in approved mode, and to refuse algorithms outside
  the approved set. The module's certificate and version are meant to be
  recorded in `constitution_loaded`. The claim is limited to "runs on a
  validated module". This package stays unvalidated, and the mode does not
  cover the rest of the host. How a hybrid signature is treated in approved
  mode depends on what the validated module supports, and is decided when
  the mode is built.
- Local GUI (target 0.10). New boundary: browser to a local server. It is
  meant to bind to loopback only and to require a per-session token, which
  is meant to address other local pages, cross-site requests, and DNS
  rebinding. It is the first place decrypted ledger content is displayed, so
  anyone who can see the screen or reach the local port is a new audience. It
  is meant to show digests, sizes, and reason codes, not argument values.
  Filtering by judge needs per-judge ballot records, which the ledger does
  not hold today. They are meant to carry the judge id, the vote, and a
  capped error only, never the rationale text, which is model output and may
  quote arguments.
  Configuration edits change policy, so the GUI is meant never to hold the
  principal key. It prepares a constitution and hands it to the existing
  signing command. A GUI that is reachable from another machine is out of
  scope.
- More spec field types (planned, not scheduled). Custom `boolean`,
  `integer`, `enum`, and `string` fields shipped in 0.3.0 and are described
  above. Decimal, URL, path, email, and opaque-bytes kinds are not built,
  and `amount` and `counterparty` remain special kinds.

## What to re-check when the code changes

- `two_key/core.py`: both paths run once the call is well-formed and within limits, and `authorize_from_agent` does not call a tool. A spec disagreement denies after both paths answer.
- `two_key/fields.py` and `two_key/policy_vm.py`: custom field values come from argument paths only; `LOAD` never reads `Action.raw` or a custom name, and custom fields load with `LOAD_FIELD` from the derived mapping only. A mapped field is required. Enum and string values are normalized (ASCII, or NFKC_Casefold with declared scripts) and a character outside the declared scripts denies. A description is never compiled, sent to a judge, or used in a reason.
- `two_key/derive.py`: JSON paths only. A claim can raise a data class and cannot lower one. Disagreement denies. `deny_unmapped` defaults off and drops unnamed keys at the tool. A counterparty path requires `allow`. Payload `shape` checks kind only. A declared path with no shape covers its children.
- `two_key/quorum.py`: an abstention is not a yes, ballots pair with judges by position, the default has no diversity floors (high_assurance has them), maker names compare case-insensitively, and `require_path_a_first` is not a skip. `tool_args_on_derive_deny` defaults false. Path B still runs.
- `two_key/gateway.py`: argument hash of the caller's bytes, spec hash, recomputed form, then `redemption_started`, then the tool with declared paths only. The verifier has no private key. No scanner.
- `two_key/capability.py`: the token fields are tool, args hash, ledger root, ledger size, the two constitution hashes, `spec_hash`, and, when issued, `form` and `claimed_data_class`. The signing key is the capability key, not the principal key. TTL default is 120 seconds, at most 300.
- `two_key/identity.py`, `netloc.py`: judge versus monitored agent from operator configuration only; refuse on the same credential at any address, or both keyless on one address; everything else warns and is recorded; credential fingerprints under the per-install key: HMAC-SHA256 for API tokens, PBKDF2-HMAC-SHA256 (600,000 iterations) for a username and password as one pair and for any secret containing `:`; addresses as configured, no DNS; local means the loopback, RFC 1918, or fc00::/7 allowlist.
- `two_key/strict.py`: every JSON and YAML input refuses duplicate keys, YAML merge keys, and integers over 4,300 digits.
- `two_key/ledger.py`: the ledger key, the witness key, the capability key, the head anchor, the append lock, and the redemption locks stay outside the directory. The ledger does not load the capability private key. The principal key is not a decryption key and not the minting key. A stale in-memory ledger refuses to append. The witness public key is pinned (`witness_pinned`, first entry or first open) and checked against the head and `witness.pem` on open, append, and checkpoint, and against the configured pin when one is given; it changes only by `witness_rotated` with three signatures; `append` refuses both kinds. The head anchor moves only forward; a missing file is adopted; `recover_tail` drops only an uncheckpointed tail and does not run on open.
- `two_key/backup.py`: three bundles; the ledger key and the witness key are never in one file; a wrong passphrase or a tampered bundle is a refusal; restore writes `head.anchor` from the same moment as the ledger and does not delete it. `--replace-ledger` is the only path that overwrites a different ledger, and it also overwrites a key file that differs. A missing anchor on a newer ledger is left missing; the next open adopts that head.
