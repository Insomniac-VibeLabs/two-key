# Security

This is a prototype and a public concept. It has had no independent review and
has no production use. Security findings are welcome as public issues on this
repository: the project would rather have them seen and argued over than
hidden. State what the code does, what the docs claim, and how you checked.

Private vulnerability reporting (the repository's Security tab, "Report a
vulnerability") will become the channel once the product is more mature and in
use. This file will say so when that happens.

The threat model is [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). This file
is how to report a vulnerability. It is not the model.

## In scope

- Fail-open on either path (a deny or a missing ballot must not become allow)
- Token replay, argument substitution, or redemption of a token issued before
  a revocation (`revoke` ends earlier tokens; it does not stop new approvals)
- Ledger tampering that still verifies, including a head signed by a witness
  key other than the one pinned in the ledger or configured outside it
- Judge credential sent to a redirected host
- Agent proposal that causes tool execution inside `authorize_from_agent`
- An agent decline that issues a token, runs either path, or is read as a call
- A redeeming gateway that can mint a token it will accept
- A judge that is the monitored agent being accepted at start-up: a judge
  holding the agent's credential (the same API token, or the same username
  and password) at any address, whether or not either side sends it, or
  both sides keyless on one address. Other overlaps start with a warning
  by design.

## Out of scope for this repository

- Malware or DLP scanning of tool payloads. It is intentionally absent here.
- FIPS validation. Algorithms are Ed25519 and SHA-256 from `cryptography`.
- Code run from operator configuration. `judges.yaml` and `agents.yaml` are
  trusted: an `auth: {type: callback, callback: "module:function"}` entry
  imports that module when the file loads. Whoever can write those files
  can run code in the `TwoKey` process. A way to run code from a file the
  docs do not call trusted is in scope.

Ledger entries and the head are AES-256-GCM ciphertext. The data key is
wrapped by a ledger key stored outside the ledger directory. The head needs
both the principal signature and a witness signature. The witness key is also
outside the ledger directory. Stealing only the principal key does not decrypt
the log, does not sign a new head, and does not mint a capability token.
The minting key is `<ledger>.capability/capability.pem`, also outside the
ledger directory. The gateway is given only the public half. Stealing the
ledger key decrypts. The witness public key is pinned in the ledger, so a
replaced `witness.pem` is refused (`witness_key_changed`). Stealing the
principal key and the ledger key still allows a forged head, by rewriting
the chain from its first entry, unless the witness public key is also
configured outside the ledger (`witness_public_key=`,
`--witness-public-key`); with it, a forged head needs the witness private
key as well (#58). A head anchor outside the ledger directory
(`<ledger>.ledger-key/head.anchor`, or `--head-anchor`) refuses a rollback
or a wipe of that directory alone (#62). Deleting the anchor, or writing an
older copy of it, accepts the ledger as it stands. Stealing the capability
private key mints tokens. A backup bundle is equal to the keys it holds.
`two-key backup-export` splits them into three files so one bundle never
holds the principal key, the witness key, and the ledger key together.
Guessing a bundle's passphrase opens that bundle. PBKDF2-HMAC-SHA256
(600,000 iterations) slows guessing and is not memory-hard. There is no
seed phrase. `backup-restore` onto a newer ledger fills missing key files and
leaves a key that is already there, including a witness rotated later.
`--replace-ledger` writes an older ledger and
its `head.anchor` together; a token spent after that backup can look unspent.
Restore does not delete the anchor. Export refuses a copy that would not open,
a symlink output directory, and a directory the group or others can write.

The gateway runs in the `TwoKey` process, on the `TwoKey` ledger object
(`TwoKey.gateway()`). A gateway in another process or on another host is
not supported (#45). The gateway's verifier holds only the capability
public key, so it cannot mint; that is an API property, not key isolation.
The same process holds the capability minting key and, on the shared
ledger object, the principal, witness, and ledger keys, and the registered
tools run there. A compromised tool or dependency can read those keys. Do
not treat this architecture as providing process-level key isolation.

A redemption intent is checkpointed before the tool runs. A later retry does
not run the tool. Concurrent calls are locked. A crash before the tool runs
blocks a retry; a tool exception does not.

Code scanning in CI is `.github/workflows/security.yml` (bandit). CodeQL is
`.github/workflows/codeql.yml`. It uploads results when code scanning is
enabled for this repository.
