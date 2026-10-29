<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# AGENTS.md

Guidance for coding agents working in this clone of
[Insomniac-VibeLabs/two-key](https://github.com/Insomniac-VibeLabs/two-key).

This file is a short contributor guide for agents. Product and API context for
any LLM reader is in [llms.txt](llms.txt). Do not replace one with the other.

## Contents

<!-- toc -->
- [Scope](#scope)
- [Branch and commit rules](#branch-and-commit-rules)
- [Install and version matrix](#install-and-version-matrix)
- [Tests and docs](#tests-and-docs)
- [Crypto and security changes](#crypto-and-security-changes)
- [Fail-closed defaults to preserve](#fail-closed-defaults-to-preserve)
<!-- /toc -->

## Scope

Core only: signed constitution, Path A bytecode, Path B judge hooks,
monitored-agent hooks, encrypted ledger, single-use capability token, a
verify-only gateway, and the SIEM export. Beta (pre-1.0), maintainer-reviewed, not independently
audited. Apache-2.0.

Do **not** add a scanning or antivirus engine, a SIEM or log storage, chain
anchoring, or seed phrases here. The items in [ROADMAP.md](ROADMAP.md) are in
scope: key backup (shipped in 0.3.0), an MCP adapter (0.5.0), DLP and
antivirus hooks that call external scanners (0.6.0), ledger export for a SIEM
(0.7.0), hybrid ML-DSA signatures (0.9.0), and, after 1.0, PKI with certificate recovery, a FIPS approved
mode once a validated module offers ML-DSA-65, and a local GUI. Build them in the order and with the limits stated
there, unless the operator says otherwise. See [docs/SCOPE.md](docs/SCOPE.md).

## Branch and commit rules

- Package 0.8.0 (package name `two-key`) is tag `v0.8.0` on `main`; 0.7.3 is
  tag `v0.7.3`; 0.7.0 is
  tag `v0.7.0` (PyPI's 0.7.1 and 0.7.2 are its code, repackaged on the
  `PyPI` branch), 0.6.0 is tag `v0.6.0`, 0.5.0 is
  tag `v0.5.0`, and 0.4.0 (tag `v0.4.0`) was the first release from this repository. Tags `v0.3.1` and earlier are in the archived `two-key-concept` repository. There, tag `v0.3.0` stays on `e44be56`.
  Tag `v0.2.4` stays on `fc836bb`.
  Tag `v0.2.3` stays on `4a4352e`. Do not move `v0.8.0`, `v0.7.3`, `v0.7.0`, `v0.6.0`, `v0.5.0`, `v0.4.0`, `v0.3.1`, `v0.3.0`, or `v0.2.0`
  (`2f756ac`). `v0.1.12` and `v0.1.6` stay on their trees. `working` is
  where the next changes land.
- Do not push, force-push, or open PRs unless the operator asks.
- Never commit keys, ledgers, or credentials.
- Update `CHANGES.md` with every commit. Read
  `CHANGES.md` "Upgrading from 0.1.12" before changing 0.2.0 config shapes.

## Install and version matrix

Requires Python ≥ 3.10; CI tests 3.10 to 3.14 (3.15 in a Linux job that does not block, until PyYAML ships 3.15 wheels; no `requires-python` cap). Package name `two-key`, import name `two_key`,
version `0.9.0` on PyPI (`pip install "two-key[yaml]==0.9.0"`), tag `v0.9.0` on `main`. Tags are not moved. docs/PYPI.md is the release process. `server.json` (the MCP Registry listing) carries the same version as `pyproject.toml`; bump them together.
Linux, macOS, and Windows (from 0.6.0). CI runs tests, the demo,
the build, bandit, and CodeQL on all three (CONTRIBUTING).

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[yaml]"
python -m unittest discover -s tests
python -m two_key demo
```

CI does not use that floating install. `.github/workflows/tests.yml` installs
`uv==0.13.5` (with its hashes, `.github/requirements/uv.txt`) and runs `uv sync --locked --no-build --extra yaml --extra mcp`, which
installs `uv.lock` (cryptography, PyYAML, the MCP SDK, and their dependencies) as wheels.
Regenerate `uv.lock` with that uv when a dependency range changes, and
commit the lock. Do not treat the lock as a release pin for consumers.
Build, coverage, bandit, and the publish tools are pinned with hashes in
`.github/requirements/` (each `NAME.in` is compiled to `NAME.txt` by `compile.sh`
there), not in `pyproject.toml`. CI installs them with `--require-hashes`.

| Extra | Provides | When needed |
| --- | --- | --- |
| (none) | `cryptography>=48` | Hybrid Ed25519 + ML-DSA-65 signatures, SHA-256, AES-256-GCM ledger |
| `yaml` | PyYAML | `.yaml` rules and judge configs |
| `mcp` | MCP Python SDK (`mcp>=2.2,<3`), PyYAML | `two-key mcp-proxy`, `two-key mcp-draft-specs` (0.5.0); `two-key config show`, `get`, `check`, `set`, and `undo`, and `two-key setup`, read and write the proxy config without the SDK (`setup` needs it only to read a schema digest from the server) |

Index install: `pip install "two-key[yaml]==0.9.0"`.
From the tag: `pip install "two-key[yaml] @ git+https://github.com/Insomniac-VibeLabs/two-key.git@v0.8.0"`.

## Tests and docs

- Tests: `python -m unittest discover -s tests` (no network). Keep the suite
  network-free; use `two_key.testing` doubles only where the docs allow.
- When a claim changes, update `README.md`, `ROADMAP.md`, `docs/HOWTO.md`,
  `docs/CONNECTING.md` (a new connection or hook gets a row there),
  `docs/FIT.md`, `docs/COMPARISON.md`, `docs/THREAT_MODEL.md`,
  `docs/SCOPE.md`, `docs/SIEM.md`, `docs/LEDGER_VIEW.md`, `docs/CONSTITUTION_EDITOR.md`, `docs/TOOL_CHECK.md`, `docs/QUICKSTART.md`, `docs/PYPI.md`, `CHANGES.md`, `SECURITY.md`,
  `CONTRIBUTING.md`, `AGENTS.md`, and `llms.txt` as needed.
- docs/QUICKSTART.md (0.9.0) is run in CI by `tests/quickstart_run.py`: every ```bash block runs in order
  in a new folder and must exit 0, unless the `<!-- quickstart: ... -->` line above it says `skip`, `exit=N`
  or `expect=TEXT`. Its judge there is a stand-in that always votes yes; keep that stand-in out of the
  package and out of any example. A command changed on the page is a command changed in CI.
- A new setting (a key a loader accepts) gets a row in `two_key/settings.py`.
  `docs/SETTINGS.md` is generated from it: run `python tests/test_settings_doc.py
  --write`. The test fails on a key with no row and on a page that is not what
  the catalogue renders. Do not edit the page by hand.
- When a roadmap item ships, update `docs/SCOPE.md` and `docs/THREAT_MODEL.md`
  in the same release.
- Keep [docs/HOWTO.md](docs/HOWTO.md) "Known trade-offs by configuration"
  accurate when a config trade-off changes.
- The live harness (`tests/live/`) is test code and needs no network. A new
  fail-closed default in this file gets a row in `tests/live/COVERAGE.md`
  (`tests/test_live_harness.py` fails without one), and a check a live case
  relies on can get a weakening in `tests/live/sabotage.py`, so the
  harness's own sensitivity stays visible (`harness.py --sabotage all`).
  Never commit `tests/live/state/`, `selftest/`, or `cases.jsonl`.
- Diagrams are real Mermaid on `working` and `main`, never pictures. Follow
  the house style in `tests/test_doc_diagrams.py`: it fails on a long label
  line, a sequence diagram with more than five participants, a diagram with no
  one-line italic caption under it, and the rest of the rules in its docstring.
- New files open with the copyright header (copyright Insomniac-VibeLabs, author Stephan Busch,
  `SPDX-License-Identifier: Apache-2.0`); `tests/test_file_headers.py` fails without it. See CONTRIBUTING.md.
- Tables of contents are generated: after changing a heading, run
  `python tests/test_doc_toc.py --write` (`tests/test_doc_toc.py` fails
  while one is stale).

## Crypto and security changes

Crypto here is hybrid Ed25519 + ML-DSA-65 signatures (0.9.0) and SHA-256 via
`cryptography`, plus AES-256-GCM for ledger ciphertext. Every signature is made
and checked in `two_key/keys.py` (`sign`, `verify`); do not call a key's own
`sign` or `verify` elsewhere, and never add a path that accepts an Ed25519-only
signature where a hybrid one is expected. The ledger key, witness key, and
capability private key live outside the ledger directory. The gateway must
verify only; it must not mint.

Before changing authorization, tokens, the gateway, the ledger, or judge ≠
agent identity checks: get a security review from the maintainer. Report
security findings privately, per [SECURITY.md](SECURITY.md).

## Fail-closed defaults to preserve

- A missing ballot is not a yes.
- Both paths run once the call is well-formed and within limits. The one
  exception (maintainer's decision, 0.5.0): a call that cannot be read under
  its spec (`derive_failed:`) is not sent to the judges unless
  `tool_args_on_derive_deny` is set, and Path B is ledgered as
  `skipped:derive_failed`. Mismatches and rule denies still go to the
  judges. Do not widen the skip.
- `authorize_from_agent` does not execute a tool.
- A decline (`{"decline": ...}`) is not a call: `agent_declined` deny,
  neither path runs, never a token. A decline that also carries a tool,
  arguments, or a claim is `malformed_proposal` (`tests/test_agent_decline.py`).
- `require_path_a_first` is not a skip.
- JSON/YAML inputs refuse duplicate keys and YAML merge keys. Oversized or malformed calls deny
  before either path.
- Default quorum needs one judge and has no diversity floors.
  When `required_yes` is unset, it resolves to
  `min(2, number_of_judges)` (at least one); this is **not** a majority
  rule. `min_responding` defaults to the effective `required_yes`
  threshold. With `required_yes: 1`, two or more judges, and
  `min_responding` 1, `TwoKey` warns at start (`lone_judge_warning`); it
  does not refuse. `QuorumPolicy.high_assurance` / `profile: high_assurance`
  adds requirements for judges from two makers (`min_makers`), one
  local judge, and a local yes. Note that
  `QuorumPolicy.without_diversity_floors()` explicitly defaults
  `required_yes` to `2`.
- `tool_specs` is required. A disagreeing claim is a deny. Inside a spec
  only the tool id is required: `irreversible` defaults to `true` and
  `data_class_floor` to `classified` (`two_key/constitution.py`
  `validate_tool_specs`), and both defaults are written into the signed spec,
  so leaving them out signs the same bytes as writing them
  (`tests/test_optional_tool_spec_fields.py`). Do not default either to the
  permissive value.
- An omitted `data_class` is `classified`, before the floor. Do not
  default it to the tool's floor. Classes combine as a set
  (`join_data_class`): `financial` and `medical` replace `personal`,
  together they are `financial+medical`, and only `classified` (claimed,
  floored, or omitted) is `classified` (`tests/test_data_class_sets.py`).
  A `data_class_in` rule matches any class the call carries. Do not map display names to
  counterparty ids or fuzzy-match them. The one wider form is a signed
  `@domain` allow entry (v3): a plain address at exactly that ASCII domain,
  no subdomains, no wildcards, never in `deny_counterparties`
  (`tests/test_domain_allow.py`). Do not widen it.
- `agent_vocabulary()` is opt-in and lists syntax, never a value: no
  `allow` list, enum value, integer bound, rule, threshold,
  `deny_counterparties`, description, default, or `irreversible` flag
  (`tests/test_agent_prompt.py`). Do not add a mode that sends them.
  Without `vocabulary=`, the agent user prompt stays byte-for-byte the 0.3.0
  prompt.
- Path A evaluates five built-in structured fields (`tool`, `amount_usd`,
  `data_class`, `counterparty`, `irreversible`) and the operator's custom
  fields (`two_key/fields.py`). Custom field values come from argument
  paths in the signed spec only, never from the agent's claim or
  `Action.raw`, or, for a field declared `source: caller`, from the
  integration's `facts=` only: written in the arguments it denies
  (`caller_field_in_arguments`), and the gateway takes the facts again
  (`fact_mismatch`) (`tests/test_caller_facts.py`). The agent writes the
  arguments, so an argument field is what the call says, not a verified
  fact, and a caller fact is as true as its hook; do not describe fields as
  verification
  (HOWTO "What Two-Key verifies"); `LOAD` refuses any name but a built-in field, and custom
  fields load with `LOAD_FIELD`. A mapped field is required. Every tool
  maps each field a `deny_if_fields` rule reads or marks it
  `not_applicable` (then it gets the signed default); a forgotten decision
  is refused at signing and on load, never read as the default
  (`tests/test_field_decisions.py`). A description is never compiled, sent to a
  judge, or used in a reason. A `case: exact` ASCII string is compared and passed to the tool as
  written; never forward an original value after a case-folded check
  (`tests/test_case_exact.py`). A constitution with no custom fields must
  stay byte-for-byte v1 (`tests/test_fields_compat.py`); one without a
  0.5.0 feature (a caller field, a `case: exact` field, a `not_applicable`
  mark, an `@domain` allow entry) must not sign as v3. Each signs only as
  v3, and a v1 or v2 envelope that carries one is refused.
- Format identifiers are `two-key-...` (0.4.0). Files with the old
  `two-key-concept-...` formats are refused with a clear message, never
  read (`tests/test_legacy_formats.py`). Do not change a format name
  again without a new version suffix and a migration note. Path A evaluates
  structured data, not English-language policy prose.
- No judge may be the monitored agent: a judge holding the agent's
  credential (the same API token, or the same username and password) is
  refused at any address, whether or not either side sends it; so are two
  sides that send no credential on one address. Other overlaps warn
  and are recorded. Addresses are compared as configured, without DNS.
- The ledger's witness public key is pinned: a head or `witness.pem` that
  does not match the pin in the ledger, or the configured
  `witness_public_key`, is refused. It changes only by `rotate_witness`.
- A ledger never goes back to an older constitution (live run 9x, C44;
  `core.check_constitution_order`). The order is the principal's signed
  `serial` in the rules file (v3 only; without one the envelope stays
  byte-for-byte as before). Once a ledger has run serial N, a lower serial
  (`constitution_rollback`), N again with other bytes
  (`constitution_serial_reused`), and no serial (`constitution_serial_missing`)
  refuse to start before anything is written, and `config undo` refuses to
  put such a constitution back. The check runs again under the ledger's write
  lock, on what other processes wrote, just before `constitution_loaded` is
  recorded, so two proxies started at once on one ledger cannot both run one
  serial (live run 9y, S6c). `setup`'s starter rules and `mcp-draft-specs`
  start at serial 1, and `config set` on a signed setting signs the next.
  There is no setting that turns it off; going back to older rules means
  signing them again with a higher serial (`tests/test_constitution_serial.py`).
- Each ledger write and the checkpoint that signs it happen in one hold of the
  ledger's write lock (`Ledger.record`, `Ledger.exclusive`), so a process
  sharing the ledger never reads entries the signed head does not cover yet
  (`tests/test_ledger_shared.py`).
- The gateway verifies only; it never mints.
- The guard (`two_key/guard.py`) uses a fixed claim and proposal per tool,
  never the agent's; looks facts up before `authorize` and again before
  `invoke`, under one lock; and treats a hook that raises or returns None as
  a missing fact (deny). It does not import the MCP SDK
  (`tests/test_guard.py`).
- The MCP proxy (`two_key/mcp_proxy/`): only `sdk.py` imports the MCP SDK;
  `config.py`, `core.py`, and `draft.py` must not. Every `tools/call` goes
  through the guard (`authorize`, then `gateway.invoke` in the same
  process); the upstream call is the gateway's registered tool, never
  called directly. Only signed tools are shown, with caller-supplied paths
  removed from `inputSchema`; any other name is `tool_not_offered`,
  ledgered. `mcp_proxy_started` is ledgered before serving. A
  schema mismatch refuses to start unless `on_schema_change: warn`.
  `unresolved_identity` refuses unless `allow_unresolved_identity: true`;
  the library keeps warning. The claim comes from `proxy.yaml` only, never
  from the agent. A deny returns a reason code, never a value. Nothing but
  MCP on stdout. Drafts must not sign until the principal decides; server
  text stays in ASCII comments. An input Path A reads that the upstream
  schema leaves undescribed (no `description`, no `enum`) is a WARNING in
  the draft, at `--constitution`, and at proxy start, for any field, never
  a looser match (`core.undescribed_inputs`). SDK tests skip without the extra; CI installs
  it (`--extra mcp`).
- Platforms (0.6.0): every key read or write, owner-only directory, lock,
  and no-follow open goes through `two_key/_platform.py`. On POSIX it does
  what the code did before (mode 0600/0700, `O_NOFOLLOW`, `flock`, the same
  messages). On Windows a key is created with an access list for the
  current user only, and one whose owner or allow entries name anyone but
  the user, SYSTEM, Administrators, or OWNER RIGHTS is refused; a reparse
  point is refused; the lock is `LockFileEx`. Do not accept a wider access
  list or fall back to "no lock". Text files Two-Key writes use
  `newline="\n"` and a named encoding (`tests/test_text_io.py`).
- Writable paths (0.6.0, `two_key/writable.py`): at start, `TwoKey` names
  each file or folder of the running Python (program, import path, `.pth`
  files, loaded modules and their compiled files) and of `check_paths`,
  and every folder above them, that an account other than its own (or
  root, SYSTEM, Administrators, TrustedInstaller) could change, through
  `_platform.write_problem`. `warn` is the default; `on_writable_paths:
  refuse` refuses; `high_assurance` always refuses and refuses `warn`
  (maintainer's decision, 2026-10-16). A path that cannot be checked is
  named, not passed. There is no setting that turns it off, and on POSIX a
  group write bit counts for every group but 0; do not add either. It runs
  before anything is written to the ledger (`tests/test_writable_paths.py`).
  The MCP proxy adds the upstream server's files (#13,
  `mcp_proxy/core.upstream_paths`): each absolute argument of
  `upstream.command` that exists (a file with its folder) and each
  `upstream.check_paths` entry (absolute; one that does not exist refuses,
  `check_path_missing`). A launcher as `command[0]` with nothing named warns
  `upstream_paths_unchecked` and refuses under `high_assurance`. Do not
  follow a launcher to its target or guess at relative arguments
  (`tests/test_upstream_paths.py`).
- Agent account (0.7.0, `two_key/agent_access.py`): the MCP proxy reads the
  real user of its parent process (`_platform.parent_account`, never an
  environment variable) before it opens the ledger, and refuses to start
  when that account is Two-Key's own (`agent_same_account`), root
  (`agent_account_root`), unknown (`agent_account_unknown`, Windows
  included for now), or can change a path of the writable-path check
  (`agent_can_write`). `on_agent_access: refuse` is the default (maintainer's
  decision, 2026-10-16); `warn` starts; `high_assurance` refuses and does
  not accept `warn`. Unknown is never a different account; an account whose
  groups cannot be listed is in every group (`tests/test_agent_access.py`).
- Shared ledger (0.7.0): a `Ledger` that finds the file longer than it
  left it reads and verifies the new entries under the cross-process lock
  (chain, head, witness pin, anchor) and does not pass them to its
  observers; a shorter file or a partial line is still refused
  (`tests/test_ledger_shared.py`).
- Content scanning (0.6.0, `two_key/scan.py`): Two-Key alone starts a scan,
  for every call to a tool whose signed spec maps the scan field, and fills
  the verdict; nothing the agent writes turns it on or off, and `scan` in
  `facts=` is refused (`scan_fact_supplied`). Unavailable is never clean: a
  timeout, an exception, or an invalid result is `unavailable`.
  Could-not-finish (`limits_exceeded`) is flagged. A declared file Two-Key
  cannot read (`file_unreadable`), one over its `max_bytes`
  (`file_too_large`), more than 32 files (`too_many_files`), or more than
  100 MiB of files in one call (`call_files_too_large`) is denied before
  the scanner and both paths under every stance, monitor included
  (maintainer's decision, 2026-10-15); nothing past a limit is read. Every
  declared file states `max_bytes`, with no default (base64 at most
  196608). Do not make these denies depend on the stance or give
  `max_bytes` a default. An encrypted file is flagged; only a tool whose
  signed spec maps the scan field with `encrypted: pass` turns an
  `encrypted` finding into the verdict `encrypted`, and only when it is the
  sole finding (with another finding it is flagged; with a part not
  scanned, unavailable). The gateway refuses that verdict for any other
  tool (`scan_mismatch`); an adapter reads only ClamAV's
  `Heuristics.Encrypted` name as encrypted (`tests/test_scan_encrypted.py`).
  Do not make it a `proxy.yaml` setting or a default (maintainer's
  decision, 2026-10-15). The stance is the signed rule. Content never reaches
  the ledger or a reason code, and file content never reaches a judge; a
  flagged call's arguments and proposal reach the judges only with
  `tool_args_on_scan_flag`. The gateway never scans: it checks the token's
  verdict and file digests (`file_changed`). Without a scanner, the judge
  prompts, tokens, and ledger stay byte for byte as before
  (`tests/test_scan.py`). Do not add a scanning engine; adapters
  (`two_key/scanners.py`, standard library only) call external products,
  never keep a threat name or matched text, and read an answer they cannot
  parse as `unavailable`; an ICAP 200 that changes the body is flagged
  (`tests/test_scanners.py`). A `kind: path` file stays inside its declared
  folder (no `..`, no link below it, a regular file), opened through
  `_platform`; do not widen that.
- The gateway runs in the `TwoKey` process on the `TwoKey` ledger object
  (`TwoKey.gateway()`). A gateway in another process or host is not
  supported, by design ([why](docs/HOWTO.md#deployment-boundary-the-gateway-runs-in-the-twokey-process)); do not add a gateway-only ledger role, remote gateway,
  or cross-process protocol without the operator. Do not describe
  verify-only as key isolation: the process holds the minting, principal,
  witness, and ledger keys, and the registered tools run there.

- Configuration changes (`two_key/config_set.py`, `two_key/setup_cmd.py`):
  `two-key config set`, `config undo`, and `two-key setup` refuse root and
  any file they write, or its folder, that another account could change, or
  that is a link; nothing is written until the whole changed config passes
  `config check` (only the findings about the shell's own variables do
  not block; a judge's missing key is a warning); a change `weaker()` names needs `--confirm-weaker` and `yes`
  typed on a terminal, and no terminal is no; a signed setting needs the
  principal key and a rules file that signs to exactly what is signed, and
  the new envelope is verified before it is written; a literal for
  `upstream.env.*` or `scan.env.*` never comes from argv; a key passphrase
  comes from an owner-only file or a terminal prompt, never argv or the
  environment, the proxy never prompts, and `config key-passphrase` keeps no
  plain `.prev` of the key. Each change is a
  `config_changed` ledger entry (setting names, file names, digests; never
  a value) written before the files are renamed in; a ledger that does not
  open refuses the change. Files are written owner-only beside the old ones
  and renamed, with `<file>.prev` and `<config>.undo.json` for one-step
  undo. There is no hot reload. Do not add a way past any of these, and do
  not let a GUI or another front end skip them (`tests/test_config_set.py`).

- SIEM export (0.7.0, `two_key/siem.py`, `two_key/siem_sinks.py`,
  `two_key/siem_export.py`): optional, and with no `siem=` nothing is sent
  and nothing changes. What may leave the box is an explicit per-kind
  allowlist (`KINDS`): every body key of every ledger kind is `sent`,
  `hashed`, `excluded`, or extracted, and a key nobody decided fails
  `tests/test_siem.py`. Argument values, proposal and decline text, the
  derived amount, counterparties, custom field values, scanner threat names
  and matched text, and credentials stay excluded, with canary values in the
  tests; add a new ledger field to the allowlist on purpose or not at all.
  The ledger observer only enqueues a sequence number: projecting,
  formatting, and sending happen on the sender thread, so a collector that
  is down, slow, or hostile never blocks, delays, or changes an
  authorization, and a full queue drops rather than waits. TLS sets
  TLS 1.2 as the minimum and always verifies the certificate and the host
  name; do not add a setting that turns either off. A plaintext sink (`udp`,
  `tcp`) is refused under `high_assurance` (`siem_plaintext_refused`) and
  warns at start otherwise. A webhook never follows a redirect and reads its
  authorization header and HMAC key from owner-only files through
  `_platform`. A token the gateway refuses is still not ledgered: it only
  increments an in-memory class counter, reported at most once an interval
  with no token text, digest, or id (`ledgered: false`, `seq: -1`).
  `two-key siem-export` verifies the ledger first, writes a new owner-only
  file and refuses to overwrite, and `two-key siem-verify` re-derives every
  event from the ledger (`tests/test_siem_export.py`). Keep the unit tests
  network-free: loopback only, with `tests/tls.py` for certificates.
- The judge history summary (0.8.0, `two_key/history.py`) is on by default
  and is built from the ledger, never from the agent's claim. It carries
  library reason codes, ages, counts, and values the signed spec maps, never
  proposal text, argument values, rationale, or an unsigned counterparty,
  and it is sent with `untrusted_json` in its own `<decision_history>`
  section (`tests/test_judge_history.py`). A summary that cannot be built
  denies (`on_failure: deny`, `internal_error:history`, a
  `judge_history_failed` entry); judging without it is a setting, and a
  weaker one. Its digest is bound to every ballot (`history_hash`) and
  recorded on the decision. Do not drop the re-check before the token: a
  call whose history gained an allow on the same target is denied
  `history_changed`.
- Path B records each judge's ballot (0.8.0): id, vote, confidence, error
  class, and an HMAC-SHA256 digest of its rationale under the fingerprint
  key. Never the rationale or error text, in the ledger or the SIEM copy.
- The MCP proxy allows one proxy per agent id on a ledger by default
  (`one_proxy_per_agent`): a second refuses to start with
  `agent_already_connected`, recorded in the ledger. Turning it off is a
  weaker setting and warns at start.
- `two-key ledger-view` (0.8.0) only reads: it opens the ledger the way
  `two-key audit` does and must never append, write a file, or open a port
  (`tests/test_ledger_view.py`, `tests/test_ledger_gui.py`). The filtering
  and sorting live in `two_key/ledger_view.py` so they run without a
  display; `two_key/ledger_gui.py` is only the tkinter window. The window
  tests skip without tkinter or a display; CI's coverage job runs them
  under `xvfb-run`.
- `two-key constitution-editor` (0.8.0) signs only through
  `constitution.sign_constitution` and checks only through
  `constitution.signed_body`, the checks `sign_constitution` itself runs;
  keep it that way, so the window can never sign something
  `sign-constitution` would refuse. Its trial call runs on a throwaway key,
  a temporary ledger, and a test-double judge. Logic in
  `two_key/constitution_editor.py`, the window in
  `two_key/constitution_gui.py` (`tests/test_constitution_editor.py`,
  `tests/test_constitution_gui.py`).
- The tool check (#28, 0.9.0, `two_key/toolcheck.py`, docs/TOOL_CHECK.md) is for tools behind
  `two-key mcp-proxy` only, turned on in the tool's signed spec (`tool_check`), and required (or `exempt`,
  weaker) under `high_assurance`. The stamp key signs stamps only; every signed object carries a purpose label;
  the token and stamp leave the process only after `redemption_started`. The tool helper fails closed: keep
  every error inside it a refusal. The test vectors in docs/TOOL_CHECK.md are generated
  (`python tests/test_toolcheck_vectors.py --write`). A tool error spends the token for every tool.
- `two-key setup --window` (0.9.0) is a front end only: it builds the same
  answers the terminal interview does and calls the same
  `setup_cmd.build`, so it can never write what `setup --answers` would
  refuse. Keep the checks it shows in `two_key/setup_form.py`, the window
  in `two_key/setup_gui.py` (`tests/test_setup_form.py`, which also checks
  the window and the interview write the same files, and
  `tests/test_setup_gui.py`).

See [CONTRIBUTING.md](CONTRIBUTING.md) for the human contributor checklist.
