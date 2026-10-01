# Deployment modes and permissioned-ledger anchoring

Stephan's direction (CONCEPTION_NOTES Entry 9, 2026-09-30, about 10:26 PM
MT): local storage is fine for personal use. Enterprise use should anchor
to an enterprise-level (not fully public) blockchain. Whether the
installation is personal or enterprise should be an early, global setting,
because other settings will depend on it.

Everything below is AI-prepared engineering that carries out that
direction. It is not part of the conception. Where Stephan has not
decided something, the code uses a placeholder and the question is listed
at the end.

**Tested with fakes only.** The Fabric and REST anchors are tested against
in-memory stand-ins for a Fabric client and an HTTP service. Nothing here
has been run against a live Hyperledger Fabric network or a vendor chain.

## What the ledger is, and why anchoring matters

The ledger (`two_key/ledger.py`) is a hash chain of entries plus a Merkle
tree over them. Its head is signed by the principal's key. It is stored
locally: one file per principal, with the signed head next to it. That
makes it auditable, because tampering with, reordering, or truncating
entries is detectable against a signed head.

It is not a blockchain, and on its own it doesn't provide
non-repudiation. The principal holds the signing key, so the principal can
rewrite the history and sign a new head. Non-repudiation needs earlier
heads published somewhere the principal does not control. That is what
anchoring does.

A permissioned chain adds non-repudiation only if its nodes, and the
organizations that endorse transactions, are run by parties who are not
all under one administrator. If a single administrator runs every peer
and every endorsing org, that administrator can rewrite the chain too.

## The setting: `deployment_mode`

| Mode | Default | Anchor allowed | Startup check |
|---|---|---|---|
| `personal` | yes | none, `NullAnchor`, `LocalFileAnchor` | A permissioned anchor is refused. Set `enterprise` to use one. |
| `enterprise` | no | a `PermissionedLedgerAnchor` (`FabricAnchor`, `RestPermissionedAnchor`, or your own subclass) | Startup fails if no permissioned anchor is configured, or (since Entry 11) without `pki` and a valid principal certificate (placeholders pending Stephan) |

**Identities by mode (CONCEPTION_NOTES Entry 11).** Personal mode keeps
key files and can add an optional 24-word seed-phrase backup. Enterprise
mode uses PKI: X.509 certificates for the principal, agents, and judges,
with chain, revocation, and role checks, and optional PKCS#11 keys. Seed
phrases are refused there. See [KEYS_AND_PKI.md](KEYS_AND_PKI.md).

There are three places to set it. If more than one is set, they must
agree; if they disagree, startup fails rather than picking one.

1. The argument: `TwoKey(..., deployment_mode="enterprise")`.
2. The environment variable `TWOKEY_DEPLOYMENT_MODE`.
3. A config file: `TwoKey(..., deployment_config="deploy.yaml")` with
   `deployment_mode: enterprise` (JSON or YAML; YAML needs PyYAML).

If none is set, the mode is `personal`. `two_key.deployment.resolve()`
returns the mode and where it came from. The CLI shows it:

```
python -m two_key deployment-mode [--mode personal|enterprise] [--config deploy.yaml]
OK: deployment_mode=personal source=default
```

**Set once per ledger.** The mode is recorded in the ledger's first
`constitution_loaded` entry as `"deployment": {mode, source, anchor}`.
Reopening that ledger in the other mode is refused. A ledger created
before this setting existed counts as `personal`.

`DeploymentConfig.mode_defaults()` is the single place where other
settings will take mode-specific defaults. It returns `{}` today: no other
setting changes with the mode yet (see the open questions).

## Anchoring flow

`TwoKey(anchor=...)` gives the ledger a `head_anchor`. Every time the
ledger signs a head (each checkpoint), the head is published through that
anchor. In personal mode with `LocalFileAnchor`, that means appending it
to the local file. In enterprise mode, a signed head goes through these
steps:

1. The signed head is turned into an **anchor record**. The record holds
   digests only, never ledger content:
   `{"format": "two-key-anchor/1", "digest_alg": "sha384", "ledger_id":
   SHA-384(principal public key), "size", "head", "merkle_root",
   "ledger_digest_alg", "signed_head_digest": SHA-384(signed head)}`.
   The hashes go through the crypto provider.
2. The anchor submits it under the key `ledger_id:size`.
3. The receipt is checked. The transaction must be `VALID`, have a
   transaction id and block number, and be endorsed by at least
   `min_endorsing_orgs` distinct organizations, including every org in
   `required_orgs`.
4. The ledger appends an `anchored` entry with `{receipt, signed_head}`,
   then signs a new head so the signed head still covers the whole ledger.
   That new head is anchored at the next checkpoint.

**Failure fails closed.** If the submit fails or the receipt is rejected,
the ledger appends an `anchor_failed` entry, re-signs the head, and raises
`AnchorError`. A decision that would have been allowed is denied with
`internal_error:ledger_checkpoint:AnchorError`. If the failure happens at
startup, startup fails.

**Verifying.** `check_anchored_entries(ledger, trusted_key, anchor=None)`
checks every `anchored` entry offline: the signed head covers exactly the
entries before it, its signature verifies, and the receipt's record
matches it. With `anchor=`, it also asks the chain (`verify_receipt`): the
transaction id, block, validation code, endorsing orgs, and stored record
must all match.

## `FabricAnchor` (Hyperledger Fabric)

```python
FabricAnchor(gateway, channel="audit", chaincode="twokey-anchor",
             min_endorsing_orgs=2, required_orgs=("AuditorMSP",))
```

`gateway` is any object with:

- `submit_transaction(channel, chaincode, function, args)`: submits the
  transaction and waits for the commit. Returns `tx_id`, `block_number`,
  `validation_code`, and `endorsing_orgs` (MSP ids).
- `evaluate_transaction(channel, chaincode, function, args)`: returns
  bytes or str.
- `get_transaction(channel, tx_id)`: returns the same four fields, read
  back from the chain (for example via the `qscc` system chaincode).

The chaincode contract:

- `PutAnchor(key, record_json)` stores the record under the key **once**
  and refuses to overwrite it.
- `GetAnchor(key)` returns the stored `record_json`.

The function names are settable (`put_function=`, `get_function=`). The
chaincode itself is not part of this repository.

The official Fabric Gateway clients are Go, Node, and Java. From Python,
either write a small bridge with the three methods above, or use
`FabricAnchor.from_fabric_sdk_py(...)`. That needs the optional, unofficial
`fabric-sdk-py` package (import name `hfc`) and raises `AnchorUnavailable`
if it isn't installed. The `hfc` bridge is **untested**.

## `RestPermissionedAnchor` (any chain behind a JSON API)

`RestPermissionedAnchor(submit_url, lookup_url=None, credential=None,
network="...")` sends:

- `POST {"op": "put", "key", "record"}` to submit;
- `POST {"op": "get", "key", "tx_id"}` to look up.

Both answer with `tx_id`, `block_number`, `validation_code`, and
`endorsing_orgs`. The lookup answer also includes `record`. The URLs must
be HTTPS (loopback HTTP is allowed). `credential.get_token()` supplies a
bearer token. A custom `transport=` can replace HTTP.

## Open questions for Stephan

1. **Endorsement policy defaults.** `min_endorsing_orgs=1` and
   `required_orgs=()` are placeholders. Should enterprise mode require at
   least two orgs, or a named independent org such as an auditor?
2. **Enterprise without an anchor.** Startup fails today (placeholder).
   Should it instead warn, or fall back to local anchoring?
3. **Cadence and cost.** Every signed head is anchored, which means one
   chain transaction per checkpoint. Should it anchor on a schedule or
   every N entries instead?
4. **Failure behavior.** Anchor failure fails closed (the action is
   denied). Should there be a queued or retry mode that allows actions
   while the chain is unreachable?
5. **Personal mode with a permissioned anchor.** It is refused today.
   Should personal users be allowed to opt in?
6. **Other settings by mode** (`mode_defaults()`):
   - judge quorum size;
   - `fips_mode`;
   - whether content scanners are required;
   - timeout defaults;
   - key storage (file vs HSM/TEE; a PKCS#11 signer now exists, but
     enterprise mode does not require it);
   - SSO-only auth for enterprise.
7. **Which chain.** Fabric is implemented. Should others (for example
   Besu with permissioning, or Corda) get their own adapters, or is the
   REST adapter enough?
