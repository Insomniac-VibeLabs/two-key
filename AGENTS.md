# AGENTS.md

Guidance for coding agents working in this clone of
[Insomniac-VibeLabs/two-key-concept](https://github.com/Insomniac-VibeLabs/two-key-concept).

This file is a short contributor guide for agents. Product and API context for
any LLM reader is in [llms.txt](llms.txt). Do not replace one with the other.

## Scope

Concept line only: signed constitution, Path A bytecode, Path B judge hooks,
monitored-agent hooks, encrypted ledger, single-use capability token, and a
verify-only gateway. Prototype. Apache-2.0.

Do **not** add a scanning or antivirus engine, chain anchoring, or seed
phrases here. The items in [ROADMAP.md](ROADMAP.md) are in scope: key backup
(shipped in 0.3.0), ledger export for a SIEM, DLP and antivirus hooks that call external scanners,
an MCP adapter, PKI with certificate recovery, hybrid ML-DSA signatures, a FIPS
approved mode, and a local GUI. Build them in the order and with the limits stated there, unless the
operator says otherwise. See [docs/SCOPE.md](docs/SCOPE.md).

## Branch and commit rules

- Package 0.3.0 is tag `v0.3.0` on `main`. Tag `v0.2.4` stays on `fc836bb`.
  Tag `v0.2.3` stays on `4a4352e`. Do not move `v0.3.0` or `v0.2.0`
  (`2f756ac`). `v0.1.12` and `v0.1.6` stay on their trees. `working` is
  where the next changes land.
- Do not push, force-push, or open PRs unless the operator asks.
- Never commit keys, ledgers, or credentials.
- Update `CHANGES.md` with every commit. Read
  `CHANGES.md` "Upgrading from 0.1.12" before changing 0.2.0 config shapes.

## Install and version matrix

Requires Python ≥ 3.10. Package name `two-key-concept`, import name `two_key`,
version `0.3.0`, tag `v0.3.0` on `main`. Not on PyPI.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[yaml]"
python -m unittest discover -s tests
python -m two_key demo
```

CI does not use that floating install. `.github/workflows/tests.yml` pins
`uv==0.13.0` and runs `uv sync --locked --no-build --extra yaml`, which
installs `uv.lock` (cryptography, PyYAML, and their dependencies) as wheels.
Regenerate `uv.lock` with that uv when a dependency range changes, and
commit the lock. Do not treat the lock as a release pin for consumers.
Build, coverage, and bandit are pinned in their workflows, not in
`pyproject.toml`.

| Extra | Provides | When needed |
| --- | --- | --- |
| (none) | `cryptography>=41` | Ed25519, SHA-256, AES-256-GCM ledger |
| `yaml` | PyYAML | `.yaml` rules and judge configs |

Git install:  
`pip install "two-key-concept[yaml] @ git+https://github.com/Insomniac-VibeLabs/two-key-concept.git@v0.3.0"`

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

## Crypto and security changes

Crypto here is Ed25519 and SHA-256 via `cryptography`, plus AES-256-GCM for
ledger ciphertext. The ledger key, witness key, and capability private key
live outside the ledger directory. The gateway must verify only; it must not
mint.

Before changing authorization, tokens, the gateway, the ledger, or judge ≠
agent identity checks: get a security review from the maintainer. While this is
a prototype, report security findings as public issues, per
[SECURITY.md](SECURITY.md).

## Fail-closed defaults to preserve

- A missing ballot is not a yes.
- Both paths run once the call is well-formed and within limits.
- `authorize_from_agent` does not execute a tool.
- `require_path_a_first` is not a skip.
- JSON/YAML inputs refuse duplicate keys and YAML merge keys. Oversized or malformed calls deny
  before either path.
- Default quorum needs one judge and has no diversity floors.
  When `required_yes` is unset, it resolves to
  `min(2, number_of_judges)` (at least one); this is **not** a majority
  rule. `min_responding` defaults to the effective `required_yes`
  threshold. `QuorumPolicy.high_assurance` / `profile: high_assurance`
  adds requirements for judges from two makers (`min_makers`), one
  local judge, and a local yes. Note that
  `QuorumPolicy.without_diversity_floors()` explicitly defaults
  `required_yes` to `2`.
- `tool_specs` is required. A disagreeing claim is a deny.
- An omitted `data_class` is `classified`, before the floor. Do not
  default it to the tool's floor. Do not map display names to
  counterparty ids or fuzzy-match them.
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
  `Action.raw`; `LOAD` refuses any name but a built-in field, and custom
  fields load with `LOAD_FIELD`. A mapped field is required; an unmapped
  tool gets the signed default. A description is never compiled, sent to a
  judge, or used in a reason. A constitution with no custom fields must
  stay byte-for-byte v1 (`tests/test_fields_compat.py`). Path A evaluates
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
- The gateway runs in the `TwoKey` process on the `TwoKey` ledger object
  (`TwoKey.gateway()`). A gateway in another process or host is not
  supported (#45); do not add a gateway-only ledger role, remote gateway,
  or cross-process protocol without the operator. Do not describe
  verify-only as key isolation: the process holds the minting, principal,
  witness, and ledger keys, and the registered tools run there.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the human contributor checklist.
