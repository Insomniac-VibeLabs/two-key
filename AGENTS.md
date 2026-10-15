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
monitored-agent hooks, encrypted ledger, single-use capability token, and a
verify-only gateway. Beta (pre-1.0), maintainer-reviewed, not independently
audited. Apache-2.0.

Do **not** add a scanning or antivirus engine, chain anchoring, or seed
phrases here. The items in [ROADMAP.md](ROADMAP.md) are in scope: key backup
(shipped in 0.3.0), an MCP adapter (0.5.0), DLP and antivirus hooks that call
external scanners (0.6.0), ledger export for a SIEM (0.7.0), and, after 1.0,
PKI with certificate recovery, hybrid ML-DSA signatures, a FIPS approved
mode, and a local GUI. Build them in the order and with the limits stated
there, unless the operator says otherwise. See [docs/SCOPE.md](docs/SCOPE.md).

## Branch and commit rules

- Package 0.5.0 (package name `two-key`) is tag `v0.5.0` on `main`; 0.4.0
  (tag `v0.4.0`) was the first release from this repository. Tags `v0.3.1` and earlier are in the archived `two-key-concept` repository. There, tag `v0.3.0` stays on `e44be56`.
  Tag `v0.2.4` stays on `fc836bb`.
  Tag `v0.2.3` stays on `4a4352e`. Do not move `v0.5.0`, `v0.4.0`, `v0.3.1`, `v0.3.0`, or `v0.2.0`
  (`2f756ac`). `v0.1.12` and `v0.1.6` stay on their trees. `working` is
  where the next changes land.
- Do not push, force-push, or open PRs unless the operator asks.
- Never commit keys, ledgers, or credentials.
- Update `CHANGES.md` with every commit. Read
  `CHANGES.md` "Upgrading from 0.1.12" before changing 0.2.0 config shapes.

## Install and version matrix

Requires Python ≥ 3.10. Package name `two-key`, import name `two_key`,
version `0.5.0`, tag `v0.5.0` on `main`. Not on PyPI.
Linux and macOS; Windows from 0.6.0 (on `working`). CI runs tests, the demo,
the build, bandit, and CodeQL on all three (CONTRIBUTING).

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[yaml]"
python -m unittest discover -s tests
python -m two_key demo
```

CI does not use that floating install. `.github/workflows/tests.yml` pins
`uv==0.13.0` and runs `uv sync --locked --no-build --extra yaml --extra mcp`, which
installs `uv.lock` (cryptography, PyYAML, the MCP SDK, and their dependencies) as wheels.
Regenerate `uv.lock` with that uv when a dependency range changes, and
commit the lock. Do not treat the lock as a release pin for consumers.
Build, coverage, and bandit are pinned in their workflows, not in
`pyproject.toml`.

| Extra | Provides | When needed |
| --- | --- | --- |
| (none) | `cryptography>=41` | Ed25519, SHA-256, AES-256-GCM ledger |
| `yaml` | PyYAML | `.yaml` rules and judge configs |
| `mcp` | MCP Python SDK (`mcp>=2.2,<3`), PyYAML | `two-key mcp-proxy`, `two-key mcp-draft-specs` (0.5.0) |

Git install:  
`pip install "two-key[yaml] @ git+https://github.com/Insomniac-VibeLabs/two-key.git@v0.5.0"`

## Tests and docs

- Tests: `python -m unittest discover -s tests` (no network). Keep the suite
  network-free; use `two_key.testing` doubles only where the docs allow.
- When a claim changes, update `README.md`, `ROADMAP.md`, `docs/HOWTO.md`,
  `docs/FIT.md`, `docs/COMPARISON.md`, `docs/THREAT_MODEL.md`,
  `docs/SCOPE.md`, `CHANGES.md`, `SECURITY.md`, `CONTRIBUTING.md`,
  `AGENTS.md`, and `llms.txt` as needed.
- When a roadmap item ships, update `docs/SCOPE.md` and `docs/THREAT_MODEL.md`
  in the same release.
- Keep [docs/HOWTO.md](docs/HOWTO.md) "Known trade-offs by configuration"
  accurate when a config trade-off changes.
- Tables of contents are generated: after changing a heading, run
  `python tests/test_doc_toc.py --write` (`tests/test_doc_toc.py` fails
  while one is stale).

## Crypto and security changes

Crypto here is Ed25519 and SHA-256 via `cryptography`, plus AES-256-GCM for
ledger ciphertext. The ledger key, witness key, and capability private key
live outside the ledger directory. The gateway must verify only; it must not
mint.

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
- `tool_specs` is required. A disagreeing claim is a deny.
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
- The gateway runs in the `TwoKey` process on the `TwoKey` ledger object
  (`TwoKey.gateway()`). A gateway in another process or host is not
  supported (#45); do not add a gateway-only ledger role, remote gateway,
  or cross-process protocol without the operator. Do not describe
  verify-only as key isolation: the process holds the minting, principal,
  witness, and ledger keys, and the registered tools run there.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the human contributor checklist.
