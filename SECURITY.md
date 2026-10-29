<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Security

Status: beta (pre-1.0). The maintainer reviews changes with live LLM testing
(a refereed functional harness) and automated scanners (Semgrep, DeepSource,
Bandit, CodeQL). There has been no independent or paid audit, and no
production use is claimed.

Report a vulnerability privately through GitHub's form:
<https://github.com/Insomniac-VibeLabs/two-key/security/advisories/new>
(the repository's Security tab, "Report a vulnerability"). Do not report a
vulnerability in a public issue, a pull request, or a discussion. State what
the code does, what the docs claim, and how you checked. Hardening ideas and
documentation errors that do not expose users are welcome as public issues.

The maintainer acknowledges a report within 7 days. A fix ships in a new
release; earlier releases do not get backports.

The threat model is [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). This file
is how to report a vulnerability. It is not the model.

## Supported versions

Only the latest release on [PyPI](https://pypi.org/project/two-key/) gets
security fixes. Upgrade to it before reporting, if you can.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Any earlier release | No |

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
- Behind the MCP proxy: a `tools/call` that reaches the
  upstream server without both keys, a tool the proxy shows that is not
  signed, an argument that reaches the server outside the signed spec, a
  changed tool schema accepted under `on_schema_change: refuse`, an
  unresolved identity accepted without `allow_unresolved_identity: true`, or
  an argument value in a deny reason
- A constitution that signs or loads although a tool neither maps nor marks
  `not_applicable` a field a rule reads, or a `case: exact` value that
  reaches the tool changed
- An `@domain` allow entry that admits a subdomain, a lookalike domain, an
  address whose local part is not plain (a space, a line break, a quoted
  part, a second `@`), or the entry itself as a party
- A caller-supplied fact (`source: caller`) taken from the agent's
  arguments or claim, a v1 or v2 constitution accepted with a caller field,
  or a redemption that runs the tool after the fact changed (0.5.0)
- A start that does not name, or under `high_assurance` or
  `on_writable_paths: refuse` does not refuse, a file or folder Two-Key
  runs or reads that another account could change, where
  docs/CONNECTING.md says it is checked (0.6.0), the upstream server's files
  named by an absolute argument or `upstream.check_paths` included, or a
  proxy that starts under `high_assurance` when `upstream.command` starts
  with a launcher and nothing names the server's files (#13)
- A proxy that starts, by default or under `high_assurance`, when the real
  account of the process that started it is Two-Key's own, is root, cannot
  be told, or can change a file or folder the proxy runs or reads
  (`on_agent_access`, 0.7.0)
- A ledger shared by two processes accepting another writer's entries
  without verifying them, or writing after a file that got shorter
- A judge that is the monitored agent being accepted at start-up: a judge
  holding the agent's credential (the same API token, or the same username
  and password) at any address, whether or not either side sends it, or
  both sides keyless on one address. Other overlaps start with a warning
  by design.
- With a content scanner configured (0.6.0): a call to a
  scanned tool that reaches Path A without a scan, a verdict the agent can
  set or avoid (in its arguments, claim, or proposal, or through
  `facts=`), an unavailable or failed scan read as `clean`, a declared file
  that goes unscanned or reaches the tool when it cannot be read (a path
  outside its folder, a link, bad base64) or is over its `max_bytes`, under
  any stance, an encrypted file that passes on a tool whose signed spec
  does not say `encrypted: pass` or alongside another finding, a
  file that changes between the scan and the tool without `file_changed`,
  or content (an argument value, a file, a matched string) in the ledger, a
  reason code, or a judge's prompt where docs/SCANNERS.md says it is
  withheld
- With a SIEM configured (0.7.0): a field that leaves the box although
  docs/SIEM.md says it does not (an argument value, proposal or decline
  text, the derived amount, a counterparty, a custom field value, a scanner
  threat name, a credential, or any token text), a ledger entry whose body
  carries a key the allowlist has not decided, a sink that delays or blocks
  an authorization or changes a decision, a TLS sink that does not verify
  the certificate or the host name, a plaintext sink accepted under
  `high_assurance`, a webhook that follows a redirect or sends its
  credential to a redirected host, a refused token that reaches the ledger
  or whose text or digest is kept, or a `two-key siem-verify` that passes a
  file whose events do not match the ledger

## Out of scope for this repository

- A malware or DLP scanning engine. Two-Key has none; from 0.6.0 it can
  call your antivirus or DLP product (docs/SCANNERS.md). What that product
  detects, or misses, is a matter for its vendor.
- A SIEM, log management, or alerting product. Two-Key has none; from 0.7.0
  it can send each ledger entry to the collector you run
  (docs/SIEM.md). What that collector stores, who may read it, how long it
  keeps it, and what it alerts on are yours to decide.
- FIPS validation. Algorithms are hybrid Ed25519 + ML-DSA-65 and SHA-256 from `cryptography`.
- An agent that reaches an MCP server directly, around the proxy, and an
  upstream server run as the proxy's OS user. Both are deployment
  choices (HOWTO "Key custody").
- Code run from operator configuration. `judges.yaml`, `agents.yaml`, and
  the MCP proxy's `proxy.yaml` (which names the upstream command and the
  fact hooks) are trusted: an `auth: {type: callback, callback: "module:function"}` entry
  imports that module when the file loads. Whoever can write those files
  can run code in the `TwoKey` process. A way to run code from a file the
  docs do not call trusted is in scope.
- A fact hook that returns a wrong value, or the agent's own argument. Hooks
  are operator code; Two-Key checks where a fact came from, not that it is
  true.

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
not supported, by design ([why](docs/HOWTO.md#deployment-boundary-the-gateway-runs-in-the-twokey-process)). The gateway's verifier holds only the capability
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

## Publishing

The `PyPI` branch can upload the package without a long-lived token
(docs/PYPI.md). The workflow asks PyPI for a short-lived credential from
GitHub's identity token, and each uploaded file gets a Sigstore
attestation. A PyPI token in the repository, in a GitHub secret, or in a
committed `.pypirc` is not part of that design. Report a release that was
uploaded from somewhere else, or a file whose attestation does not name
this repository's `pypi-publish.yml` workflow, through the Security tab.
