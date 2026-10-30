<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Upgrading Two-Key

Upgrading means installing the new package over the old one and keeping your
keys, ledger, and configuration where they are. Two-Key has no `migrate`
command; its one upgrade step of its own is 0.9.0's key upgrade, which runs by
itself at the first start ([The key upgrade (0.9.0)](#the-key-upgrade-090)). Coming from 0.8.0, follow
[From 0.8.0 to 0.9.0, step by step](#from-080-to-090-step-by-step). Whether your data opens under the new version is decided by
the version's own notes, not by a converter. This page is the procedure. The
per-version facts are in [CHANGES.md](../CHANGES.md), under "Upgrading from
X.Y.Z".

Your keys and your ledger are not part of the package. Installing a new
version does not touch them, and Two-Key never rewrites a key file on open,
except once, in 0.9.0's key upgrade, which keeps each key and adds to it.
Upgrading while keeping "the same keys and everything" is the normal case.
The one release that did not keep old ledgers readable is 0.4.0 (see
[Versions that need more than a reinstall](#versions-that-need-more-than-a-reinstall)).

## What carries over

Everything below lives outside the installed package, so a reinstall leaves it
alone. Keep every path as it is, and pass the same `--head-anchor` and
`--witness-public-key` you already use.

| What | Where (defaults) |
| --- | --- |
| Principal key | `keys/principal.pem`, `keys/principal.pub.pem` (your `--key`) |
| Ledger directory | `ledger/` (`entries.jsonl`, the signed head) |
| Ledger key, fingerprint key, head anchor | `<ledger>.ledger-key/` (`ledger.key`, `fingerprint.key`, `head.anchor`) |
| Witness key | `<ledger>.witness/witness.pem` |
| Capability key | `<ledger>.capability/` |
| Crash-recovery copies, locks | `<ledger>.recovery/`, `<ledger>.lock`, `<ledger>.redeem-locks/` |
| Signed constitution | the file you passed to `sign-constitution` |
| Configuration | `judges.yaml`, `proxy.yaml`, judge keys, the agent session |
| Key backups | the three `*.bundle.json` files from `backup-export` |
| Witness pin kept outside the ledger | the file you give as `--witness-public-key` |

Do not delete `head.anchor`. Deleting it makes the next open accept the
ledger as it stands, which removes the rollback protection.

## Procedure

Run these in order. Steps 1 to 4 are before the change, so a bad upgrade can
be undone.

### 1. Read the notes for every version you skip

Find your current version and the one you are moving to:

```bash
python -c "import two_key; print(two_key.__version__)"      # installed
grep '^version' pyproject.toml                              # in a checkout
```

Read "Upgrading from X.Y.Z" in [CHANGES.md](../CHANGES.md) for your version
and for each release after it. The README's "Upgrading from an older version"
list is a one-line summary of each. Skipping a version does not skip its
notes. Look for three kinds of line: a file that stops loading, a setting
that now refuses to start, and a step you must do by hand.

### 2. Stop everything that uses the ledger

Stop the proxy (`two-key mcp-proxy`), any process that imports `TwoKey`, and
anything that calls `authorize` or the gateway. Backup, restore, and recover
all expect the ledger to be idle.

### 3. Check the ledger and take a backup

`audit` verifies the ledger and prints its witness pins and digest checks; it
refuses a ledger that does not verify. Fix a ledger that does not verify before you
upgrade, not after.

```bash
two-key audit --key keys/principal.pem --ledger ledger
```

If it refuses with `signed head does not match the chain`, the previous run
was killed mid-write. Follow "If the ledger will not open after a crash" in
[HOWTO](HOWTO.md#if-the-ledger-will-not-open-after-a-crash).

Export the keys and verify them without touching the real ledger. The
passphrases come from environment variables, one per bundle, and should all
differ ([HOWTO "Back up the keys"](HOWTO.md#back-up-the-keys)):

```bash
read -rs TWO_KEY_PRINCIPAL_PASSPHRASE; echo
read -rs TWO_KEY_LEDGER_PASSPHRASE; echo
read -rs TWO_KEY_WITNESS_PASSPHRASE; echo
export TWO_KEY_PRINCIPAL_PASSPHRASE TWO_KEY_LEDGER_PASSPHRASE TWO_KEY_WITNESS_PASSPHRASE

two-key backup-export --key keys/principal.pem --ledger ledger --out backups-pre-upgrade \
  --principal-passphrase-env TWO_KEY_PRINCIPAL_PASSPHRASE \
  --ledger-passphrase-env TWO_KEY_LEDGER_PASSPHRASE \
  --witness-passphrase-env TWO_KEY_WITNESS_PASSPHRASE

two-key backup-verify --bundles backups-pre-upgrade \
  --principal-passphrase-env TWO_KEY_PRINCIPAL_PASSPHRASE \
  --ledger-passphrase-env TWO_KEY_LEDGER_PASSPHRASE \
  --witness-passphrase-env TWO_KEY_WITNESS_PASSPHRASE
```

`backup-export` only works after Two-Key has started once on this ledger
(so `capability.pem` and `fingerprint.key` exist), and only on 0.3.0 or
later. On an older install, take the file copy below instead.

Then copy the whole set, which is what the bundles cannot replace if a file
is lost between steps:

```bash
mkdir pre-upgrade-copy
cp -a keys ledger ledger.ledger-key ledger.witness ledger.capability pre-upgrade-copy/
cp -a constitution.* judges.yaml proxy.yaml pre-upgrade-copy/ 2>/dev/null || true
```

Adjust the names to your layout. Keep the copies private: they hold the
keys, mode 0600 files included (`cp -a` keeps the modes). Store the three
bundles apart from each other and from the machine, as the table in HOWTO
says.

### 4. Install the new version

Install into the same environment that runs Two-Key. Pin the version.

```bash
# from PyPI
pip install -U "two-key[yaml]==X.Y.Z"          # add the mcp extra for the proxy: "two-key[yaml,mcp]==X.Y.Z"

# from a tagged release on GitHub
pip install -U "two-key[yaml] @ git+https://github.com/Insomniac-VibeLabs/two-key.git@vX.Y.Z"

# from a checkout installed with `pip install -e`
git fetch --tags && git checkout vX.Y.Z && pip install -e ".[yaml]"
```

Confirm what is installed, and that only one provider of the `two_key` module
exists:

```bash
python -c "import two_key; print(two_key.__version__)"
pip list 2>/dev/null | grep -i two-key       # coming from before 0.4.0: two-key-concept must be gone
```

If you run Two-Key from a lockfile (`uv.lock`), update the lock the way your
project normally does. CI installs from `uv.lock` and wheels only, so match
that if you want the same dependency versions.

### 5. Open the ledger under the new version

Do not start the agent yet. Run `audit` first:

```bash
two-key audit --key keys/principal.pem --ledger ledger
```

What a good result looks like: it opens and prints the witness pins and digest
checks without an error. The first open under a newer release may
write new bookkeeping the older release did not have. For example, 0.2.3
pinned the witness key on the first open, and 0.2.4 wrote `head.anchor` on
the first open of an existing ledger. Those are additions, not rewrites of
your keys.

Then start the proxy or your own process with the same `--key`,
`--ledger`, `--head-anchor`, and `--witness-public-key` as before. Read its
start-up output. Moving to 0.9.0, the first start also upgrades the keys and
says so ([The key upgrade (0.9.0)](#the-key-upgrade-090)). Some releases add start-up refusals (0.6.0, 0.7.0 and 0.7.3
do, see below), and the output names what to change.

### 6. Back up again

A new version may have added files to the ledger or the key set. Repeat the
`backup-export` and `backup-verify` from step 3 with `--out backups-post-upgrade`
and store them. Keep `backups-pre-upgrade` until you have run on the new
version long enough to trust it.

## If something goes wrong

- **A refusal at start-up.** Read the message and the matching "Upgrading
  from" note. A refusal on `high_assurance` is intended and has no
  `warn` override. Change the setting or the deployment, not the check.
- **`ledger_rolled_back`.** The ledger directory is older than `head.anchor`.
  You restored an older ledger copy without its anchor, or copied one
  without the other. Copy the ledger and its anchor together. Do not delete
  the anchor to get past this.
- **Rolling back to the old version.** Reinstall the old version
  (`pip install "two-key[yaml]==<old>"`). The new version may have written
  entries or files the old one does not read; nothing in the documentation
  says an older release opens a ledger a newer one wrote. If the old version
  refuses it, stop and use the copies from step 3: restore `pre-upgrade-copy`
  as a set, so the ledger, `head.anchor`, and keys
  all match. Never mix a new ledger with an old anchor.
- **Restoring keys from a bundle.** `backup-restore` puts the keys, the ledger
  files, and `head.anchor` back together. Stop every process first. If the
  ledger on disk is newer than the backup, it restores only missing keys and
  leaves that ledger and its anchor alone. See
  [HOWTO "Back up the keys"](HOWTO.md#back-up-the-keys).
- **A lost passphrase** cannot be recovered. This is why the file copies in
  step 3 matter.

## Versions that need more than a reinstall

These are the releases where reinstalling was not the whole upgrade. The
README summary and CHANGES.md have the rest.

| Moving to | What to do |
| --- | --- |
| 0.9.0 from 0.8.0 | Step by step: [From 0.8.0 to 0.9.0](#from-080-to-090-step-by-step). Needs `cryptography` 48 or later (the PyPI wheels have ML-DSA-65). The first start upgrades the keys to hybrid Ed25519 + ML-DSA-65, once: it rewrites each key file with its Ed25519 key kept, signs the constitution again with the same body, and records `keys_upgraded` in the ledger. There is no way back: 0.8.0 keys are refused afterwards, and 0.8.0 does not open the upgraded ledger. Stop every process on the ledger first, back up before and after, and with an out-of-ledger witness pin run `two-key keys upgrade` yourself ([The key upgrade (0.9.0)](#the-key-upgrade-090)). Tokens are now `tk2`. A tool that raises now spends its token: a second redemption of the same token is refused `already_attempted`, and the agent asks again. A caller that retried the same token after `tool_error:<type>` must ask for a new one. A `high_assurance` proxy refuses to start until every tool it offers has the tool check on or is marked `exempt` (`tool_check_required`; [TOOL_CHECK](TOOL_CHECK.md)): run `two-key config check` first. Other deployments need nothing for the tool check; it stays off until a tool's signed spec turns it on. A constitution with `tool_check` in a spec does not load on 0.8.0, and neither does one with a `path` field (new in 0.9.0); constitutions without them load on both. |
| 0.8.0 from 0.7.3 | Constitutions, keys and ledgers load unchanged; nothing is re-signed. Judge history is on by default, so each judge's prompt now carries a `<decision_history>` section: tune or turn it off under `quorum.judge_history` ([JUDGES_AND_QUORUM](JUDGES_AND_QUORUM.md#judge-history)). The policy digest changes, because the quorum policy now records `judge_history`. Decisions made before the upgrade appear to the judges with `"age": "before_upgrade"`. New decisions gain `at`, `subject`, `history_digest` and `history_basis`, and Path B entries gain per-judge `ballots`. The MCP proxy now refuses a second proxy for an agent already connected to the same ledger (`agent_already_connected`), and a proxy with no `agent_id` counts as one agent: give each its own `agent_id`, or set `one_proxy_per_agent: false` in `proxy.yaml` where two are intended. The MCP proxy also refuses to start when a judge is not on this machine and `proxy.yaml` has no `agent_session_env` (`cloud_judge_session_required`); such a proxy denied every call before, so add `agent_session_env` ([SETUP](SETUP.md#a-cloud-judge-needs-the-agents-session)). A ledger written by 0.8.0 is not meant to be opened by 0.7.3 again: keep a backup from before the upgrade. |
| 0.7.3 from 0.7.0 (or 0.7.1, 0.7.2) | Everything loads unchanged; nothing is re-signed. The proxy now checks the upstream server's files in `upstream.command`, and warns `upstream_paths_unchecked` (under `high_assurance`, refuses) when a launcher such as `sudo`, `env` or `npx` names none: give the program as an absolute path or list its folder in `upstream.check_paths`. On Windows a `check_paths` entry needs its drive. Once a ledger has run a constitution with a `serial`, it refuses an older one, the same serial with other rules, or none. `config check` now fails on an unset agent credential variable. A tool spec may leave out `irreversible` and `data_class_floor`; left out, they are `true` and `classified`. |
| 0.7.0 from 0.6.0 | Everything loads unchanged; nothing is re-signed. Under `high_assurance`, change a plaintext syslog sink (`udp`, `tcp`) to `transport: tls`. The proxy refuses to start if the monitored agent runs as Two-Key's own account, as root, or can change Two-Key's files: give the agent its own account ([CONNECTING](CONNECTING.md)), or set `on_agent_access: warn` in `proxy.yaml` where that is the deployment (not under `high_assurance`). Nothing is sent to a SIEM until you configure one. |
| 0.6.0 from 0.5.0 | Files load unchanged. At start it names each file or folder it runs or reads that another account could change; `high_assurance` refuses to start until there are none. |
| 0.5.0 from 0.4.0 | A constitution in which a tool neither maps nor marks `not_applicable` a field a rule reads no longer loads. An `allow` entry that starts with `@` is now a whole domain. A call that cannot be read under its spec is no longer sent to the judges. Check the constitution before upgrading. |
| 0.4.0 from 0.3.1 | **Not a plain reinstall.** The package was renamed. Uninstall `two-key-concept` and install `two-key`; do not keep both. **Key files (PEM) still load**, so the principal key is kept. Constitutions, ledgers, head anchors, and backups made before 0.4.0 do not load: re-sign the constitution with the same key, start a new ledger with the same keys, and export a new backup. Keep the old ledger directory and old bundles for audit; the new version will not open them. |
| 0.3.1 from 0.3.0 | Data classes combine differently and agent declines were added. See CHANGES.md "Release v0.3.1" > "Upgrading". |
| 0.3.0 from 0.2.4 | Existing ledgers and constitutions open unchanged. A constitution that declares custom fields signs as v2, which installs before 0.3.0 refuse. |
| 0.2.4 from 0.2.3 | Writes a head anchor on the first open of an existing ledger, and then refuses a rolled-back ledger directory. |
| 0.2.3 from 0.2.2 | Refuses the `vendor:` and `min_vendors:` keys and some judges 0.2.2 accepted, and pins each ledger's witness key on first open. |

If your table row says "loads unchanged", that is the project's statement for
that release, not something this page checks. When in doubt, the `audit` in
step 5 is the test: it either opens your ledger or it says why not.

## From 0.8.0 to 0.9.0, step by step

This is the general procedure above, filled in for 0.9.0. Most of 0.9.0 needs nothing from you: the setup window,
`tools[*].claim` and the tool check are new and optional. One change is not optional and cannot be undone: the
keys become hybrid Ed25519 + ML-DSA-65 at the first start ([The key upgrade (0.9.0)](#the-key-upgrade-090) says
exactly what it does). A new deployment made by 0.9.0 is hybrid from the start, and none of this applies to it.

1. **Stop and back up**, as in steps 2 and 3 above: stop the proxy and everything else on the ledger, run
   `two-key audit`, export and verify the three bundles into `backups-pre-upgrade`, and copy the folders into
   `pre-upgrade-copy`. Keep the bundles with that copy. They hold the 0.8.0 keys, which only the 0.8.0 ledger
   copy accepts. "Going back to 0.8.0" below restores `pre-upgrade-copy`.

2. **Install 0.9.0.** It needs `cryptography` 48 or later, which pip installs with it:

   ```bash
   pip install -U "two-key[yaml,mcp]==0.9.0"     # leave out mcp if you don't run the proxy
   python -c "import cryptography; print(cryptography.__version__)"   # 48 or later
   ```

   Use the PyPI wheel of `cryptography` (a virtual environment is the simple way). A copy built against an
   OpenSSL older than 3.5, such as some Linux distributions' own package, cannot sign with ML-DSA-65, and Two-Key
   refuses to start with `ml_dsa_unavailable` rather than sign with Ed25519 alone.

3. **Check before the first start.** `audit` opens the ledger with the 0.8.0 key and changes nothing:

   ```bash
   two-key audit --key keys/principal.pem --ledger ledger
   two-key config check --config proxy.yaml       # proxy deployments
   ```

   `config check` warns `principal_key: a 0.8.0 Ed25519 key`, which is expected. It fails in two cases you
   fix now:

   - `principal_key: a 0.8.0 Ed25519 key, and witness_public_key pins the witness outside the ledger`: the
     proxy will not upgrade by itself, and a start refuses with `keys_upgrade_needed`. Do step 4 by hand with
     `two-key keys upgrade --config proxy.yaml`, then copy `<ledger>.witness/witness.pub.pem` over your pin
     file.
   - `tool_check_required` (`high_assurance` only): give each tool the tool check or mark it `exempt`
     ([TOOL_CHECK](TOOL_CHECK.md)). Under other profiles the check stays off and nothing changes.

4. **Start once, which upgrades the keys.** Which start does it depends on how you run Two-Key:

   | You run | What upgrades the keys |
   | --- | --- |
   | `two-key mcp-proxy --config proxy.yaml` | Its first start |
   | `two-key authorize` | Its next run |
   | `two-key config set`, `config undo` or `config key-passphrase` | That command |
   | `TwoKey` from your own Python code | Nothing: it refuses with `keys_upgrade_needed`, so run `two-key keys upgrade` once, below |
   | A witness pin outside the ledger | Nothing by itself: run `two-key keys upgrade` once, below |

   ```bash
   two-key keys upgrade --config proxy.yaml
   # or, without a proxy:
   two-key keys upgrade --key keys/principal.pem --ledger ledger \
       --constitution constitution.signed.json        # add --key-passphrase-file FILE for an encrypted key
   ```

   Pass the constitution you run with: the upgrade signs that file again with the hybrid key, and the signed
   rules stay the same. `keys upgrade` is safe to run twice; the second run says `"upgraded": false`. The
   first start prints a line before it starts and two when it is done, like these:

   ```text
   two-key: upgrading the keys to hybrid ed25519+ml-dsa-65, once; let it finish
   two-key: keys upgraded to hybrid ed25519+ml-dsa-65 (keys_upgraded at seq 16): principal hybrid-sha256:10cc...,
     witness hybrid-sha256:3cce...; files replaced: principal.pem, principal.pub.pem, ledger.witness/witness.pem, ...
   two-key: back up now: the key upgrade changed every key file, and a backup made before it restores the old keys,
     which this ledger refuses (...)
   ```

   Let it finish. The account that runs it must be able to write the key folders (it replaces each key file);
   otherwise it stops with `keys_upgrade_stopped: this account cannot write ...`. What it wrote is safe: fix
   the modes and start again. Each `.pub.pem` file keeps its mode. If two first starts race, the
   one that waited says `keys_upgraded_elsewhere` and the next start opens the upgraded keys. If the start is
   killed part way, the next start goes on from there, with one exception: killed after `keys_upgraded` is
   written and before the head that covers it, the next start refuses with `signed head does not match the
   chain`. Run `two-key recover` (HOWTO, "If the ledger will not open after a crash"), then start again; it
   records `ledger_recovered` and finishes the upgrade. A temporary key file a kill left beside a key
   (`.principal.pem.<pid>.<hex>.tmp`) is removed by the next upgrade.
5. **Back up again, at once.** Export and verify into a new folder, as in step 6 above. The `back up now` line
   comes back at every start until `two-key backup-export` succeeds. `backup-verify` checks a bundle set by
   itself, so the old bundles from step 1 still verify `ok`. Pass `--witness-public-key
   <ledger>.witness/witness.pub.pem` to check a set against the upgraded ledger: the old set is then refused
   (`witness_key_changed`), the new one passes.

6. **Check the result.** `two-key audit` lists `keys_upgraded` among the witness pins, with the old `sha256:`
   and new `hybrid-sha256:` fingerprints. To see the whole entry:

   ```bash
   two-key ledger-view --key keys/principal.pem --ledger ledger --where kind = keys_upgraded --print
   ```

   Or open `two-key ledger-view` and search for `keys_upgraded`. Decisions go on as before. The SIEM copy of
   the entry has `stamp_key_fingerprint: null` when the deployment had no stamp key yet (no tool had the tool
   check on), which is the usual case for a 0.8.0 deployment.

7. **Sign other copies again.** The upgrade signs one constitution file, the one that start used. Any other
   signed copy you keep, such as a staged next version, still carries the 0.8.0 signature, and Two-Key refuses
   it. Sign it again with `two-key keys upgrade --constitution FILE` (as in the key upgrade section below),
   `two-key sign-constitution` or the [constitution editor](CONSTITUTION_EDITOR.md). The unsigned files
   (`constitution.md`, `hard_rules.yaml`) do not change. Make rule changes after the upgrade, not before it.

Two behavior changes reach callers rather than files. Tokens are `tk2`; code that only passes them on to the
gateway does not notice, and a `tk1` token minted before the upgrade is refused `token_before_upgrade`. A tool
that raises now spends its token, so a caller that retried the same token after `tool_error:<type>` must ask for
a new one: the same process refuses it `already_attempted`, and after a restart it is `revoked_or_reloaded`
(the restart's `constitution_loaded` is checked first).

**Going back to 0.8.0** means going back to the copy from step 1. 0.8.0 refuses the upgraded ledger
(`head anchor was signed by a different principal key`), and 0.9.0 refuses the 0.8.0 keys once the upgrade is
recorded. Reinstall 0.8.0 and restore `pre-upgrade-copy` as a set. Decisions made since the upgrade are only in
the upgraded ledger, so keep that folder for audit.

## The key upgrade (0.9.0)

0.9.0 signs everything with hybrid keys: an Ed25519 key and an ML-DSA-65
(FIPS 204) key that sign together, so a forger has to break both. A
deployment made by 0.8.0 has Ed25519 keys. The first start of 0.9.0 upgrades
them by itself, once: `two-key mcp-proxy`, `two-key authorize`, and a
`two-key config` change that opens the principal key each do it when they find
0.8.0 keys. It runs under the
ledger's lock. A stop at any step before the entry is written is taken up by
the next start; a stop between the entry and its head needs `two-key recover`
first (see the end of this section):

1. It opens the ledger with the 0.8.0 key; the ledger must open and verify as
   it is.
2. It writes the principal key file again as a hybrid key with the same
   Ed25519 key and a new ML-DSA-65 key. An encrypted key is encrypted again
   under the same passphrase.
3. It does the same for `witness.pem`, `capability.pem` and `stamp.pem`, and
   updates the `.pub.pem` files beside them and `principal.pub.pem`.
4. It signs the constitution again with the hybrid key. The signed body is
   unchanged, so its digest and serial still match the ledger.
5. It records `keys_upgraded` in the ledger: the old and new principal and
   witness keys, signed by all four, and the new capability and stamp key
   fingerprints. The head and anchor are hybrid from then on, and the entry
   goes to your SIEM like any other (severity notice).
6. It prints what it did, and `back up now` at every start until
   `two-key backup-export` succeeds.

Because each new key keeps its Ed25519 key, everything signed before the
upgrade still checks. After it, an Ed25519 signature is refused wherever a
hybrid one is expected, and opening the ledger with the 0.8.0 key fails with
`keys_upgraded`. There is no way back to Ed25519 alone.

A fresh 0.9.0 install never runs any of this: `two-key setup` makes hybrid
keys from the start, so there is no `keys_upgraded` entry, no upgrade message
and no backup reminder.

The upgrade signs again only the constitution that start was given. Any other
constitution file still signed by the 0.8.0 key is refused when you start
with it, with a message that says so; a later start never signs it again by
itself, because then an Ed25519 forger could pass one off. Sign it again
yourself, once:

```bash
two-key keys upgrade --key keys/principal.pem --ledger ledger \
    --constitution other.signed.json
```

If you run Two-Key from Python (`TwoKey.load`), there is no first start to
upgrade at: `TwoKey` refuses a 0.8.0 key with `keys_upgrade_needed`. Run
`two-key keys upgrade` once, or open the deployment with
`two_key.upgrade.open_upgraded`, which upgrades it as the proxy does.

Take the backup the reminder asks for with `two-key backup-export`. From
0.9.0 the principal bundle also holds `stamp.pem`, the tool check's stamp key,
where the deployment has one, and a restore writes `capability.pub.pem` and
`stamp.pub.pem` back beside their keys.

It refuses, and changes nothing, in two cases:

- **`keys_upgrade_needed`**: the witness public key is also pinned outside the
  ledger (`witness_public_key` in `proxy.yaml`, or `--witness-public-key`).
  That copy is yours, kept where Two-Key cannot change it. Run the upgrade
  yourself, then replace your copy with `<ledger>.witness/witness.pub.pem`:

  ```bash
  two-key keys upgrade --config proxy.yaml
  # or, without a proxy:
  two-key keys upgrade --key keys/principal.pem --ledger ledger \
      --constitution constitution.signed.json --witness-public-key witness.pin.pem
  ```

  Until you replace the copy, the ledger refuses to open with it
  (`witness_key_changed`). `two-key config check` warns about a 0.8.0 key,
  and fails when the out-of-ledger pin means the proxy will not upgrade it.
- **`ml_dsa_unavailable`**: the `cryptography` package cannot make ML-DSA-65
  signatures (older than 48, or built against an OpenSSL before 3.5). Two-Key
  never falls back to Ed25519 alone. Install the PyPI wheel:
  `pip install --upgrade 'cryptography>=48'`.

If the upgrade stops part way (a crash, a full disk), the next start goes on
from where it stopped. Meanwhile the ledger refuses every write with
`keys_upgrade_pending`. If it stops after `keys_upgraded` is written and
before the head that covers it, follow [HOWTO "If the ledger will not open
after a crash"](HOWTO.md#if-the-ledger-will-not-open-after-a-crash), then
start again.

## Where else this is written down

- [README](../README.md): "Upgrading from an older version".
- [CHANGES.md](../CHANGES.md): the full per-version notes.
- [HOWTO](HOWTO.md): "Back up the keys", "If the ledger will not open after a
  crash", "Rotate the witness key", and "Key custody".
- [PYPI.md](PYPI.md): the release and install procedure.
