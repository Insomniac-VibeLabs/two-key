<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Upgrading Two-Key

Two-Key has no `upgrade` or `migrate` command. Upgrading means installing the
new package over the old one and keeping your keys, ledger, and configuration
where they are. Whether your data opens under the new version is decided by
the version's own notes, not by a converter. This page is the procedure. The
per-version facts are in [CHANGES.md](../CHANGES.md), under "Upgrading from
X.Y.Z".

Your keys and your ledger are not part of the package. Installing a new
version does not touch them, and Two-Key never rewrites a key file on open.
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
start-up output. Some releases add start-up refusals (0.6.0 and 0.7.0 do, see
below), and the output names what to change.

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

## Where else this is written down

- [README](../README.md): "Upgrading from an older version".
- [CHANGES.md](../CHANGES.md): the full per-version notes.
- [HOWTO](HOWTO.md): "Back up the keys", "If the ledger will not open after a
  crash", "Rotate the witness key", and "Key custody".
- [PYPI.md](PYPI.md): the release and install procedure.
