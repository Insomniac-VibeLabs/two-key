<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Set up and change Two-Key

Two-Key's settings stay in separate files on purpose: the signed rules, the operator's configuration, and the
secrets ([SETTINGS](SETTINGS.md) says why, and lists every setting). These commands are one way in to all of
them, so you do not have to know which file holds what:

- `two-key setup` writes a new deployment: keys, rules, judges, and the proxy's config, signed and checked.
- `two-key config set`, `get` and `undo` change one setting, read one, and put the last change back.
- `two-key config key-passphrase` encrypts the principal key with a passphrase, changes it, or removes it.
- `two-key config show` and `config check` show what a config resolves to and whether the proxy would start.

Every one of them runs as **Two-Key's own account**: the account the proxy runs as, which owns Two-Key's files.
Never as root, and never as the monitored agent's account. Each part below says what that means for that
command and what it refuses.

## Contents

<!-- toc -->
- [Who may run these commands](#who-may-run-these-commands)
- [Full setup: `two-key setup`](#full-setup-two-key-setup)
  - [The questions](#the-questions)
  - [What it writes, and where](#what-it-writes-and-where)
  - [What it refuses](#what-it-refuses)
  - [After it finishes](#after-it-finishes)
- [Changing one setting: `config set`, `get`, `undo`](#changing-one-setting-config-set-get-undo)
  - [Finding a setting's name](#finding-a-settings-name)
  - [Giving a value](#giving-a-value)
  - [What happens, in order](#what-happens-in-order)
  - [What counts as weaker, and why it needs `--confirm-weaker`](#what-counts-as-weaker-and-why-it-needs---confirm-weaker)
  - [Signed settings need the principal key](#signed-settings-need-the-principal-key)
  - [What the ledger records](#what-the-ledger-records)
  - [Why a restart is needed](#why-a-restart-is-needed)
  - [Putting a change back: `config undo`](#putting-a-change-back-config-undo)
  - [What `config set` refuses](#what-config-set-refuses)
- [Protecting the principal key with a passphrase](#protecting-the-principal-key-with-a-passphrase)
- [Showing settings: `config show`, `get`, `check`](#showing-settings-config-show-get-check)
<!-- /toc -->

## Who may run these commands

| Command | Who | What it refuses |
| --- | --- | --- |
| `setup` | Two-Key's own account, in a folder only that account can change | Root, a target that exists, a folder above it another account can change |
| `config set`, `config undo`, `config key-passphrase` | Two-Key's own account, the owner of every file it changes | Root, and any file it would write, or the folder that holds it, that another account could change, or that is a link |
| `config show`, `config get`, `config check` | Anyone who can read the files | Nothing: they write nothing and open no ledger |

How this keeps the agent out: when the agent runs as its own account, as it must (the proxy refuses to start
otherwise, `agent_same_account`), Two-Key's files belong to another account, so `config set` and `config undo`
refuse to write them (`config_target_unsafe`). Root is refused (`config_as_root`) because a file root writes
there would belong to root, and because root can change anything anyway. What these commands cannot tell is an
agent that runs as Two-Key's own account; that setup gives the agent every key whatever this command does, so
keep the agent off that account ([CONNECTING](CONNECTING.md)). On Windows there is no root refusal; the
access-list check on each file and folder still applies.

These commands are a convenience, not the only lock. An account that can write `proxy.yaml` can edit it
without them. File permissions and the start-up checks (`on_writable_paths`, `on_agent_access`) are what stop
that, as before.

## Full setup: `two-key setup`

```
two-key setup --dir /srv/two-key/billing
two-key setup --dir /srv/two-key/billing --answers answers.yaml
```

Without `--answers`, it asks its questions on a terminal; without a terminal it refuses and asks for
`--answers`. It never asks for a secret. A judge's API key, the agent's credential, and the agent session are
named by the environment variable that will hold them; their values never go in a file.

### The questions

The same keys go in an `--answers` file (YAML or JSON). An unknown key is refused.

| Answer key | Question | Default |
| --- | --- | --- |
| `route` | `proxy` (`two-key mcp-proxy` in front of an MCP server), `guard`, or `library` | `proxy` |
| `profile` | `default` or `high_assurance` | `default` |
| `judges` | For each judge: `type`, `id`, `model`, `base_url` (for `openai_compatible` and `ollama`), `maker`, and `auth_env`, the name of the environment variable that holds its API key. Any other key of a judge in [SETTINGS](SETTINGS.md) can be given too | (asked) |
| `monitored_agent` | `id`, `model`, `provider`, `base_url`, and `credential_env` (or `credential: none`) | (asked) |
| `rules_file` | A rules file you reviewed. For the proxy, the `rules.draft.yaml` that `two-key mcp-draft-specs` drafted from the server | none |
| `tools` | Without `rules_file`: the tools a starter allows, each with `id`, `irreversible`, and `data_class_floor` | (asked) |
| `prose_file` | The prose the judges read. Without it, a short starter you edit later | the starter |
| `upstream` | Proxy only: `command` (a list; the wizard splits a line as a shell would, and the proxy runs it without a shell) and `schema_digest` | (asked) |
| `agent_session_env` | Proxy only: the name of the variable that holds the agent's session | none |
| `key_passphrase_file` | The absolute path of a file only this account can read, holding a passphrase to encrypt the principal key with ([below](#protecting-the-principal-key-with-a-passphrase)). Never the passphrase itself | none: not encrypted |

`schema_digest` is the `sha256:` digest that `two-key mcp-draft-specs --constitution` prints. Leave it blank
and `setup` reads it from the server itself after signing, the same way: it starts the server to list its tools
(this needs the `mcp` extra), and refuses if the server does not list a signed tool.

A starter rules file allows the tools you name and maps no argument. An argument a spec does not name is
dropped before the tool sees it, so a starter is for trying Two-Key out. For a real MCP server, review and sign
what `mcp-draft-specs` drafts ([HOWTO](HOWTO.md#put-two-key-in-front-of-an-mcp-server-two-key-mcp-proxy)).

### What it writes, and where

Everything goes in the `--dir` folder. Each file is owner-only from its first byte (mode 0600, or on Windows
an access list for your account only), except the public key, which is not a secret.

| File | What it is |
| --- | --- |
| `principal.pem` | The principal private key. Signs the constitution and the ledger head. Encrypted when `key_passphrase_file` is given, and then `proxy.yaml` names that file as `keys.passphrase_file` |
| `principal.pub.pem` | Its public half |
| `constitution.md` | The prose the judges read |
| `hard_rules.yaml` | The rules Path A runs, with the tool specs |
| `constitution.signed.json` | Both, signed with the principal key |
| `judges.yaml` | The judges, the quorum `profile`, and the `monitored_agent` |
| `proxy.yaml` | Proxy only. Every scalar setting at its default, written out: `ttl_seconds: 120`, `allow_unresolved_identity: false`, `on_agent_access: refuse`, `on_writable_paths: warn` (`refuse` under `high_assurance`, which does not accept `warn`), and `upstream.on_schema_change: refuse` with `call_timeout_seconds: 60` |
| `ledger/` | The ledger, with its key and witness folders beside it (`ledger.ledger-key/`, `ledger.witness/`) |

It writes all of this into a new hidden folder beside `--dir`, checks it there, and renames that folder to
`--dir` only when the check passes. For the proxy route the check is `config check` on the new `proxy.yaml`;
for the guard and library routes it verifies the constitution and loads the judges and the monitored agent.
Then it creates the ledger and writes its first entry, `config_changed` with `command: setup`: the name and
SHA-256 digest of each file it wrote except the private key, and the digest of the signed constitution.

### What it refuses

- Root (`config_as_root`).
- A `--dir` that exists (`setup_target_exists`): it writes a new folder and never over one.
- A folder above `--dir` that another account could change (`setup_target_unsafe`).
- A `key_passphrase_file` that is not an absolute path, that another account can read
  (`passphrase_file_insecure`), or whose passphrase is shorter than 12 bytes (`key_passphrase_short`).
- An answer the loaders refuse (an unknown judge type, a tool with no spec, a malformed digest), and anything
  `config check` fails (`config_check_failed`). `high_assurance` with fewer judges than it needs is one such
  failure. A variable the config names that is not set in your shell does not count
  (`upstream_env_missing`, `agent_session_missing`, `agent_credential_missing`), since the proxy's own
  environment may differ. A judge's key that is not set is only a warning (`judge_env_missing`).

A refused setup leaves nothing behind: the hidden folder is removed and `--dir` is never created.

### After it finishes

It prints the files and the next steps:

1. Set each variable it names (the judges' keys, the agent's credential) in the proxy's own environment.
2. Run `two-key config check --config DIR/proxy.yaml` where the proxy will run.
3. Start the proxy from the agent's host, as another account ([CONNECTING](CONNECTING.md)).
4. If you used the starter prose, edit `constitution.md` and sign again with `two-key sign-constitution --key
   DIR/principal.pem --prose DIR/constitution.md --rules DIR/hard_rules.yaml --out
   DIR/constitution.signed.json --force`. `sign-constitution` writes no `config_changed` entry; the next start
   records the new constitution's digest (`constitution_loaded`).
5. Copy `ledger.witness/witness.pub.pem` where the ledger's account cannot change it, and pin it
   ([HOWTO](HOWTO.md#pin-the-witness-key)). That setting is one `config set` does not change, so add
   `witness_public_key:` to `proxy.yaml` by hand and run `config check`.

For the guard and library routes there is no `proxy.yaml`: load the files from Python as
[HOWTO "Authorize from Python"](HOWTO.md#authorize-from-python) shows. `config set`, `get`, and `undo` work on
a proxy config; on those routes, edit the files and sign again with `sign-constitution`.

## Changing one setting: `config set`, `get`, `undo`

```
two-key config get   --config proxy.yaml siem.sinks[0].port
two-key config set   --config proxy.yaml siem.sinks[0].port 6514
two-key config set   --config proxy.yaml on_agent_access warn --confirm-weaker
two-key config set   --config proxy.yaml tool_specs.pay.irreversible true --key principal.pem --rules hard_rules.yaml
two-key config set   --config proxy.yaml upstream.env.API_TOKEN --value-file token.txt
two-key config set   --config proxy.yaml ttl_seconds --unset
two-key config undo  --config proxy.yaml
```

Each prints the change, then a JSON result. It exits 0 when the change is written and 1 when it is refused,
with one line that starts `two-key: config set: refused:` and a reason code. A refused change writes nothing.

### Finding a setting's name

A setting's name is its path in [SETTINGS](SETTINGS.md), with each list item numbered from 0 and a key that
has a dot in it in brackets:

| Name | File |
| --- | --- |
| `ttl_seconds`, `on_agent_access`, `upstream.call_timeout_seconds`, `siem.sinks[0].port`, `tools[fs.read].claim` | `proxy.yaml` |
| `quorum.profile`, `judges[1].timeout`, `monitored_agent.model` | `judges.yaml` (the `judges:` path in `proxy.yaml`) |
| `hard_rules[2].deny_if.amount_usd_gt`, `tool_specs.pay.data_class_floor`, `fields.region.default` | the signed rules |

The first part picks the file, so you never name one. A name that is not a setting is refused
(`unknown_setting`), and so is a typo. `config get NAME` prints the value, the file, the tier, and the default.

Not changed by `config set` (`not_settable`): `constitution`, `keys.principal`, `ledger`, `judges`,
`witness_public_key`, and `head_anchor` in `proxy.yaml`. They say which files, keys, and ledger Two-Key trusts,
so moving one is a change of deployment: edit `proxy.yaml` by hand, then run `config check`. The prose is
`constitution.md`: edit it and run `sign-constitution`. `agents.yaml`, for the library route, is not changed
here either.

### Giving a value

Exactly one of:

- `VALUE`: JSON when it reads as JSON (`true`, `120`, `["a", "b"]`, `{"env": "NAME"}`, `"120"` for the text
  120), and plain text otherwise (`warn`, `high_assurance`).
- `--value-file FILE`: the file's text, without one final newline. The file must be owner-only
  (`value_file_insecure` otherwise).
- `--prompt`: typed at a hidden prompt, on a terminal.
- `--unset`: remove the setting, so its default applies.

**Secrets never go on the command line**, where shell history and `ps` keep them. A literal for
`upstream.env.NAME` or `scan.env.NAME` can be a secret, so on the command line it is refused
(`secret_on_command_line`); give it with `--value-file` or `--prompt`, or name a variable with
`{"env": "NAME"}`. No other setting holds a secret: those that name one take the name of a variable or the path
of an owner-only file ([SETTINGS](SETTINGS.md)). Never put a secret in `upstream.command`.

### What happens, in order

```mermaid
flowchart TD
  ask["config set NAME VALUE"] --> acct["Own account?<br/>Files only its own?"]
  acct --> stage["New files staged<br/>beside the old ones"]
  stage --> check["config check passes<br/>on the staged files?"]
  check --> weak["Weaker, or signed?<br/>--confirm-weaker, yes"]
  weak --> led["config_changed<br/>in the ledger"]
  led --> swap["Old kept as .prev,<br/>new renamed in"]
  acct -. "no" .-> stop["Refused,<br/>nothing written"]
  check -. "FAIL" .-> stop
  weak -. "no yes" .-> stop
```

*Each step must pass before the next one runs; the dashed lines are refusals, and a refusal writes nothing.*

1. **The account.** Not root, and every file it will write, and the folder that holds it, can be changed by no
   other account and is not a link. One change at a time: a lock file beside the proxy config
   (`.proxy.yaml.config.lock`) holds the next one back.
2. **The new files**, written owner-only next to the real ones under hidden names. YAML is written plainly, so
   comments are not kept; the previous version is kept as `<file>.prev`.
3. **`config check` on the whole new set**: the staged file, with every other file as it is. Any `FAIL` refuses
   the change and prints the findings (`config_check_failed`), except a variable not set in your shell. This is
   also why what `high_assurance` forbids stays forbidden: `on_agent_access: warn`, `on_writable_paths: warn`
   and a plaintext SIEM sink each fail the check under that profile.
4. **Weaker, or signed.** A weaker change without `--confirm-weaker` is refused, with the reasons
   (`weaker:`). With it, and for every signed change, it asks for `yes` typed on a terminal. Anything else, or
   no terminal (a script, a pipe, an agent), is no (`not_confirmed`).
5. **The ledger.** It opens the deployment's ledger with the proxy's own keys and appends `config_changed`.
   A ledger that is missing (`ledger_missing`) or does not open (`ledger_refused`) refuses the change, so
   nothing changes without a record.
6. **The files.** Each old version is renamed to `<file>.prev`, each new one renamed into place, and
   `proxy.yaml.undo.json` says which files the change wrote and their digests before and after.

### What counts as weaker, and why it needs `--confirm-weaker`

A weaker setting is one that lets more through, checks less, or shows judges more, so a mistyped command or a
copied snippet should not be enough for it. It is read from what the old and new configurations enforce,
loaded the way the proxy loads them, not from the key you typed. Each of these is weaker:

| What changes | Weaker when |
| --- | --- |
| The quorum profile | `high_assurance` is turned off (the two-maker, local-judge and local-yes floors no longer all hold) |
| `on_writable_paths`, `on_agent_access`, `upstream.on_schema_change` | It goes from `refuse` to `warn` |
| `allow_unresolved_identity` | It is turned on |
| `ttl_seconds` | Tokens live longer |
| `agent_session_env` | It is removed |
| `upstream.check_paths` | A path is no longer checked |
| `siem` | The copy is turned off, a sink no longer gets it, or a sink sends in the clear |
| `scan` | The content scanner is removed |
| `tools.<id>.claim` | It claims a lower data class (`classified`, the default, is the highest) |
| `tools.<id>.files` | A file is no longer declared for the scanner |
| `quorum.required_yes`, `min_responding`, `min_distinct_providers`, `min_makers`, `min_local_judges` | It is lowered |
| `quorum.require_local_yes` | It is turned off |
| `quorum.judge_inputs`, `tool_args_on_derive_deny`, `tool_args_on_scan_flag` | Judges see the proposal or the arguments |
| `quorum.ballot_binding`, `heterogeneity_scope` | `echo` becomes `stamp`, `responding` becomes `selection` |
| `judges` | A judge is added or removed, or any of its keys changes but `timeout`, `json_mode`, `max_tokens`, `response_format`, and `reasoning_effort` |
| `monitored_agent` | It is removed or changed (judges are checked against it) |
| Signed rules | Anything but adding a rule, turning `irreversible` or `deny_unmapped` on, or raising a `data_class_floor`: whether an edit to a rule allows more cannot be told in general |

An `undo` that weakens needs `--confirm-weaker` too: undoing a stricter setting is weaker.

### Signed settings need the principal key

`hard_rules`, `tool_specs`, and `fields` are signed. Changing one means signing a new constitution, so it needs:

- `--key FILE`: the principal private key, the one `keys.principal` names (`principal_key_mismatch`
  otherwise), the same file `sign-constitution` takes. Unencrypted, whoever can read it can sign anything:
  that is why it must be owner-only, why Two-Key refuses one that is not, and why the agent's account must not
  be able to read it. Encrypted ([below](#protecting-the-principal-key-with-a-passphrase)), it opens with
  `--key-passphrase-file FILE`, else `keys.passphrase_file`.
- `--rules FILE`: the rules file the constitution was signed from. It must sign to exactly what the current
  constitution signs (`rules_source_differs` otherwise), so the signature you add covers your one change and
  nothing someone else left in the file.

It shows the change and the part of the signed text that differs, asks for a typed `yes`, signs the rules with
the prose already signed, in at least the current envelope format, and verifies the new envelope with the
principal's public key before anything is written. Then `config check` verifies the staged envelope again,
as the proxy will. It writes the rules file and the envelope together, both owner-only, and records the new
constitution's digest in the ledger.

### What the ledger records

`config_changed`, for `setup`, `set`, `undo`, and `key-passphrase`:

| Field | What it holds | Sent to the SIEM |
| --- | --- | --- |
| `command` | `setup`, `set`, `undo`, or `key-passphrase` | Yes |
| `settings` | The names of the settings changed | Yes |
| `files` | Each file's role (`proxy`, `judges`, `rules`, `constitution`, `key`), name, and SHA-256 digest before and after. The principal key file (`key`) is named with no digest | Yes |
| `signed` | Whether a constitution was signed | Yes |
| `weaker` | Why the change is weaker, if it is: setting names and a few fixed words | Yes |
| `confirmed` | Whether someone typed `yes` | Yes |
| `constitution_hash` | The digest of the new signed constitution, or none | Yes |
| `account` | The account that ran the command | No: the ledger only |

It never holds a value: not the old or new value of a setting, not a secret, not a file's content. To see what
a change was, compare the file with its `.prev`, or the digests with the files you keep.

The SIEM copy is sent by the proxy, not by this command. A running proxy sends the entry after it next writes an
entry of its own. A proxy that starts later sends it on start with `replay_from: cursor` (the default) or
`start`; with `replay_from: now` it does not, so send it with `two-key siem-export` if the proxy was not running.

### Why a restart is needed

There is no hot reload. A running proxy keeps the settings it started with, so nothing changes under a call in
progress, and every setting it enforces is the one its start-up checks passed. A change takes effect when the
proxy next starts. Each command says so in its result.

### Putting a change back: `config undo`

`config undo --config proxy.yaml` puts back the files the last `config set` (or `undo`) replaced, from their
`.prev` copies, through the same steps: the account, `config check`, `--confirm-weaker` and a typed `yes` when
it weakens, a `config_changed` entry with `command: undo`, and owner-only renames. Running it again puts the
change back, so it holds one step, not a history; the ledger is the history.

It refuses (`undo_stale`) when a file changed after the last change, or its `.prev` is not the version that
change replaced, so it never overwrites an edit made by hand. Undoing a signed change needs `--key`, and the
constitution it puts back must verify with that key. Nothing to undo is `nothing_to_undo`, and so is a last
change made by `config key-passphrase`, which keeps no copy of the key as it was.

### What `config set` refuses

| Reason code | Why |
| --- | --- |
| `config_as_root` | Run as root |
| `config_target_unsafe` | A file it would write, or its folder, could be changed by another account: run as Two-Key's own account |
| `config_target_link`, `config_target_missing` | A file it would write is a link, or not there |
| `config_invalid`, `config_current_invalid` | The new file, or the files as they are, do not load |
| `unknown_setting`, `not_settable` | Not a setting, or one this command does not change |
| `secret_on_command_line`, `value_file_insecure` | A literal that can be a secret on the command line, or a value file others can read |
| `config_check_failed` | The new set would not start, or would refuse something it starts with today |
| `weaker`, `not_confirmed` | Weaker without `--confirm-weaker`, or no typed `yes` |
| `principal_key_needed`, `principal_key_mismatch`, `rules_file_needed`, `rules_source_differs`, `rules_invalid`, `constitution_refused`, `unchanged` | A signed setting without the key or the signed rules, or a change that does not sign |
| `principal_key` (with `key_passphrase_needed`, `key_passphrase_wrong`) | The principal key, which signs the ledger entry, does not open |
| `ledger_missing`, `ledger_refused` | The change could not be recorded |
| `nothing_to_undo`, `undo_stale`, `undo_invalid` | `undo` has nothing safe to put back |

## Protecting the principal key with a passphrase

The principal key signs the constitution and the ledger. Unencrypted, a copy of `principal.pem` is a copy of
that power: a backup taken carelessly, a file sent to the wrong place, a disk image. Encrypted, the copy is
useless without the passphrase.

```
( umask 077; head -c 32 /dev/urandom | base64 > /etc/two-key/principal.pass )
two-key config key-passphrase --config proxy.yaml --new-from /etc/two-key/principal.pass
```

`--new-from FILE` encrypts the key with the passphrase in that file, or changes the passphrase of a key that
is already encrypted (opened with `keys.passphrase_file`, or `--key-passphrase-file` for the current one), and
sets `keys.passphrase_file` in `proxy.yaml` to that file, in one change. `--remove`
stores the key unencrypted again and removes the setting; that is weaker, so it needs `--confirm-weaker` and a
typed `yes`. Both are recorded as `config_changed` with `command: key-passphrase`.

**Where the passphrase comes from.** A file only its owner can read (mode 0600, or a private access list on
Windows), holding one line of 12 to 1024 bytes; one final newline is not part of it. Or, for a command you run
by hand, typed at a hidden prompt on a terminal. Never the command line, where shell history and `ps` keep it,
and never an environment variable: the proxy is started by the agent's host, so its environment is the one
place a passphrase must not come from.

**The proxy reads `keys.passphrase_file` at start.** Its stdin is the agent's channel, so it never prompts. An
encrypted key without that setting, a passphrase file another account can read, or a wrong passphrase refuses
to start (`key_passphrase_needed`, `passphrase_file_insecure`, `key_passphrase_wrong`), and `config check`
says so first. The passphrase file is one of the paths the start-up checks look at: if the agent's account can
change it, the proxy refuses to start (`on_agent_access`, `refuse` by default), and another account that can
change it is reported by `on_writable_paths`.

**Every other command that takes `--key`** (`sign-constitution`, `authorize`, `audit`, `recover`,
`rotate-witness`, `siem-export`, `siem-verify`, `backup-export`, `backup-verify`, `backup-restore`) takes
`--key-passphrase-file FILE` too, and without it asks on the terminal. `config set` and `undo` use
`--key-passphrase-file`, else `keys.passphrase_file`; an encrypted key without `keys.passphrase_file` fails
`config check`, since the proxy could not start, so they refuse until it is set. For a new key, `two-key init-key DIR --passphrase` asks
for one twice, and `--passphrase-file FILE` reads it from a file. From Python, give
`load_private_key_file(path, passphrase_source(PASSPHRASE_FILE))`.

**Backups keep it encrypted.** `backup-export` puts the key file in the principal bundle as it is, still
encrypted, and `backup-restore` writes it back that way. Opening that bundle then needs both the bundle's
passphrase and the key's.

**What it protects, and what it does not.** It protects a copy of `principal.pem` on its own: in a backup, on
another machine, sent by mistake. It does not protect against:

- An account that can read both `principal.pem` and the passphrase file. Two-Key's own account can, since the
  proxy opens the key unattended; that is why the agent must never run as that account.
- A copy of the key made before it was encrypted. `config key-passphrase` keeps no `.prev`, but an old backup,
  or the old file's blocks on the disk, stay unencrypted. If one may have leaked, a passphrase does not help:
  make a new deployment.

So keep the passphrase file away from the key: another disk, a secrets mount, or a credential that systemd
or your secret store puts in place at start, readable only by Two-Key's account. A passphrase file in the same
folder as the key protects only against a copy of the key file alone. The ledger key, the witness key, and
the capability key are not encrypted by this; they live in the ledger's own folders, owner-only, as before.

The format is Two-Key's own: the key, as PKCS8, sealed with AES-256-GCM under a key from PBKDF2-SHA256 at
600,000 iterations with a random 16-byte salt, every header field bound in, the same construction as the key
backup. A file that asks for fewer iterations is refused before the derivation runs. A key encrypted by
another tool (`BEGIN ENCRYPTED PRIVATE KEY`) is refused by name; encrypt the unencrypted key with
`config key-passphrase` instead.

## Showing settings: `config show`, `get`, `check`

```
two-key config show  --config proxy.yaml       # every effective setting, as JSON
two-key config get   --config proxy.yaml NAME  # one setting
two-key config check --config proxy.yaml       # would the proxy start?
```

Anyone who can read the files may run them. They write nothing, open no ledger, start no process, and contact
no judge, scanner, collector, or upstream server.

- **`show`** prints the proxy's settings with defaults filled in: the files it names, `ttl_seconds`, the
  resolved `on_writable_paths` and `on_agent_access` (what applies after the profile: `refuse` under
  `high_assurance`, where a `warn` in the file is an error, as it is at start), `high_assurance: true` or
  `false`, the upstream, the tools, the
  scanner, the SIEM sinks, the effective quorum, and each judge: its type, address (`base_url`), model, and the
  names of the variables it reads.
- **`get`** prints one setting: `value` (`null` when the file does not set it), `set`, the `file` that holds
  it, its `tier` (`operator` or `signed`), and from [SETTINGS](SETTINGS.md) its `default`, what
  `high_assurance` does to it, and what it does. A signed setting is read from the signed constitution.
- **`check`** prints one line per finding, `ok`, `WARN`, or `FAIL`, and exits 1 on any `FAIL`: the config
  parses, the principal key opens (encrypted, with `keys.passphrase_file`, as at start) and signed the
  constitution, each `tools:` entry is signed, the judges and
  quorum load, a monitored agent is declared, every variable the proxy and its judges read is set here (each
  missing one is named: an upstream or agent variable is a `FAIL`, since the proxy would not start or the
  upstream would not get it; a judge's key is a `WARN`, since that judge would abstain on every call), the writable-path
  check, the `on_agent_access` setting (a `FAIL` for `warn` under `high_assurance`), and plaintext SIEM sinks.
  It cannot see which account will start the proxy, or whether the upstream still lists the same tools; the
  proxy checks both at start.

None of them prints a secret. A key file is shown by its path, a judge's key and the agent's credential by
the name of their variable, and an `upstream.env` or `scan.env` literal as `<literal>`.
