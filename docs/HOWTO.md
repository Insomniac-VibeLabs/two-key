# How to run the concept

Whether this package is the right control is [FIT.md](FIT.md). What it is
not a substitute for is [COMPARISON.md](COMPARISON.md). Boundaries and
residual risk are [THREAT_MODEL.md](THREAT_MODEL.md). What this package
leaves out is [SCOPE.md](SCOPE.md).

Commands are from the repository root.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[yaml]"
python -m unittest discover -s tests
```

That follows the ranges in `pyproject.toml`. The same checkout's `uv.lock`
is what CI installs (wheels only). To match it, install the uv version
pinned in `.github/workflows/tests.yml`, then `uv sync --locked --no-build
--extra yaml --no-dev`, and run tests with `.venv/bin/python`. When a
dependency range changes, regenerate `uv.lock` with that same uv and commit
it. The lock is not a consumer pin: a git install still uses the ranges.

## Create a principal key and sign a constitution

```bash
python -m two_key init-key ./keys
python -m two_key sign-constitution \
  --key ./keys/principal.pem \
  --prose examples/constitution.md \
  --rules examples/hard_rules.yaml \
  --out constitution.signed.json
```

`init-key` writes `principal.pem` with mode 0600 (created that way, never
chmodded afterwards) and refuses to overwrite an existing key. Commands that
take `--key` refuse a key file that the group or others can read
(`key_file_insecure`) or that is a symlink.

The signature covers the prose, the hard rules, and `tool_specs`. A modified
file will not load. `tool_specs` is required. A bare rule list, a missing
key, `null`, and an empty mapping are refused. `examples/hard_rules.yaml`
has a spec for every allow-listed tool. Amount, counterparty, and
irreversible are read from the argument bytes, and a claim that disagrees
is a deny. `data_class` is the stricter of the claim and the tool's
`data_class_floor`. This package does not classify free text. A tool that
carries text the rules must treat as sensitive needs that class as its
`data_class_floor`. A missing amount path, a non-numeric amount, or a
currency other than `usd` on `pay_bill` is a deny. A value that cannot be
read at all is a `derive_failed` deny: `derive_failed:amount_unreadable`
for an amount such as `10**400`, `derive_failed:value_unreadable:<type_tag>` for
any other value (type label via `type_tag`, ≤32 chars; never raw `__name__`).

A key the spec does not name does not change the form and does not reach
the tool. The spec does not have to list every nested key. `deny_unmapped`
defaults off: the call can still allow, and the gateway drops the unnamed
key. The ledger records the names of dropped keys (`dropped_keys`), never
their values. Set it true to deny that key (`unmapped_field`). `payload`
names a value that may be present and is not interpreted. A payload path
may not equal, contain, or sit under an amount, currency, or counterparty
path, compared without regard to case (`TO.name` overlaps `to.name`);
such a spec does not load. With no `shape`, that
path covers the value and its children. `shape` is optional: `string`,
`number`, or `list` (a list of strings). `max_length` bounds a string or
a list. A nested value, a boolean, or a too-long value is
`payload_shape`. Shape does not read the contents. Classification of what
the text means is left to Path B, or to DLP outside this package.

A counterparty path must include `allow`, a non-empty list of strings. A
party that is not on that list is `counterparty_not_allowed`. The tool
receives the canonical party (trimmed, lower case), not the raw spelling.
`examples/hard_rules.yaml` allows `ada@example` on the mail tools and
`power-co.example` on `pay_bill`. Those mail tools name `subject` and
`body` as strings (`max_length` 200 and 8000). The words are not read. A
field that is neither a control path nor a payload path is dropped. A
blocked party still denies through `deny_counterparties` when one is present.

Missing `data_class` still defaults to `classified` before the floor, and
a floor never lowers that. Missing `irreversible` follows the tool spec,
so a reversible tool stays reversible. A present claim that disagrees with
the spec is a deny. Pass `--data-class public` only when that class is
allowed after the floor, and pass `--no-irreversible` only for a tool the
spec marks reversible.

## Designing a constitution

The commands above sign a constitution. They do not design one. The operator owns the signed constitution; Two-Key enforces only what is signed. A weak or incomplete constitution is the most common way the dual-path control fails to protect the intended actions. The points below are advisory, not a guarantee that a constitution is correct.

1. Define the tools and actions the agent is allowed to perform. Use an `allow_only_tools` rule. An allow-list is required by default so unknown tools fail closed.
2. Define the actions it must never perform. Use `deny_if`, `deny_counterparties`, or `deny_if_irreversible_over` rules for the cases that must be hard denials.
3. Specify tool arguments and their schemas in `tool_specs`. Path A derives the structured fields (`tool`, `amount_usd`, `data_class`, `counterparty`, `irreversible`) from the argument bytes according to those specs. A claim that disagrees with the derived values is a deny. The current field set is fixed for testing; configurability of the field set itself is intended but not yet implemented.
4. Set `data_class_floor` and counterparty `allow` lists where they matter. A floor never lowers a claimed class. A party not on an `allow` list is `counterparty_not_allowed`. Payload paths constrain type and length only; they do not read contents. Classification of free text is left to Path B or to DLP outside this package.
5. Decide how many judges are needed and what their agreement threshold should be. One judge is the minimum and the default. When multiple judges are configured, set `required_yes` (or use the `high_assurance` profile for destructive, irreversible, financial, or external-send tools). Missing, malformed, errored, or timed-out ballots never count as yes.
6. Test allowed, denied, ambiguous, and adversarial examples before trusting the constitution. Confirm that Path A denies the cases the hard rules are meant to catch, that Path B receives the intended context, and that the gateway drops or denies unmapped keys as configured (`deny_unmapped` defaults off).

The signed constitution remains the authority. A future GUI constitution maker (planned later) should help construct and validate choices, but the principal must still sign the resulting constitution. The GUI must not silently weaken the rules.

See `examples/hard_rules.yaml` and `examples/constitution.md` for a working starting point.

## Judges
