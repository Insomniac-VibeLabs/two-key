# Threat model

This is the design model for `two-key` 0.1.6. It is not a penetration test
and it is not an independent review. The package is a prototype. It is not
a FIPS 140-3 validated module. Algorithms were chosen so a later build can
run on a validated module. This release is not that build.

How to report a vulnerability is [SECURITY.md](../SECURITY.md). The longer
narrative is the README section "Security model and limitations". This file
is the register. If the two disagree, the code wins, then this file should
be corrected.

## Assets

- The signed constitution and the two compilation hashes (bytecode and prose).
- The principal signing key. Personal mode can derive it from a 24-word
  seed phrase. That backup is refused in `fips_mode` and in enterprise mode.
- The ledger key and the witness key, both outside the ledger directory
  (`<ledger>.ledger-key` and `<ledger>.witness`).
- The wrapped data key stored with the ledger.
- Judge credentials and monitored-agent credentials. They are not the same secret.
- The capability token and the argument bytes it is bound to.
- Tool credentials, which only the gateway should hold.
- Enterprise identities: trust anchors, certificates, CRLs, and OCSP state.
- The ledger head, the hash chain, and any permissioned-chain anchor.

## Actors

- The principal, who holds the signing key and writes the constitution.
- An untrusted agent, local or cloud. Hosting is not trust.
- Path B judges, each with its own credential. A judge can be wrong.
- The caller that invokes authorize, then the gateway.
- Optional scanner hooks, and an enterprise SIEM.
- Anyone who can read or write the ledger directory, the ledger key, or the
  witness key.

## Trust boundaries

- Agent to `authorize_from_agent`. The reply is a proposal. The method does
  not execute a tool. A cloud judge must not reuse an agent credential.
- Caller to Path A. The VM sees the normalized action record, not the proposal.
- Caller to Path B. Judges see the constitution prose and the normalized
  record. The proposal is withheld unless that judge sets `receives_proposal`
  or the quorum policy is `judge_inputs: record_and_proposal`. The default is
  record-only.
- Both paths always run. `require_path_a_first` is recorded and does not skip
  Path B. `short_circuit_path_b` is ignored.
- Gateway to the tool. The call is serialized once. Those bytes are hashed
  and checked against the token. If scanners are configured, they see those
  same bytes. `redemption_started` is checkpointed, and then the tool
  receives a decode of those bytes.
- Process to the ledger. One process should own a ledger. Appends,
  checkpoints, and redemption writes in that process share one lock. On
  POSIX they also take an advisory lock on `<ledger-directory>.lock`,
  beside the ledger directory and not on the ledger file, and refuse if
  another writer changed the file. There is no flock on Windows.

## What this design is meant to stop

- A tool execution inside `authorize_from_agent`.
- An allow when either path denies or does not answer. A missing, malformed,
  or timed-out ballot is an abstention, not a yes. The section-4 floors
  (two vendors, one local judge) are off unless `QuorumPolicy.section4()` is
  used.
- A token replay, a token used for different argument bytes, a token used
  after expiry (30 seconds unless you change it), and a token used after
  revocation or a constitution reload.
- A second run of a token after `redemption_started` has been checkpointed.
  A tool exception writes `redemption_aborted` and leaves the token usable.
- A silent edit of a ledger record that still verifies, and opening the log
  with only the principal key. New ledgers have no principal-wrapped
  fallback. A new head carries a witness signature. A head that already
  exists without one can still be signed by the principal key alone.
- In enterprise mode: a start without PKI, a permissioned anchor, and a SIEM
  syslog target. An unidentified or revoked principal identity. An agent
  assertion, unless `require_agent_identity` is off. Judge certificates,
  only when `require_judge_identities` is on (it is off by default). An
  anchoring failure on the decision checkpoint does not release a token. A
  later checkpoint failure does not undo a tool that already ran.

## Assumptions

- The gateway is the only holder of tool credentials. This package cannot
  stop an agent that can call the tool by another path.
- The principal key, the witness key, and the ledger key are not all in the
  attacker's hands.
- The action record describes the real call. Extractors can derive some
  fields from the literal arguments. That does not close problem F, below.
- Judges are one key of two. The quorum does not prove the models are
  independent. The diversity floors are off by default.
- Scanner hooks, when configured, see the bytes you hand them. A hook that
  is not configured does not run.

## Residual risks

These are accepted or still open. They are not bugs the design already
claims to close.

- No independent review, and no production deployment.
- Problem F is open. Path A is only as good as the structured fields it is
  given. A lie in `amount_usd`, `data_class`, `counterparty`, or
  `irreversible` can pass Path A while the argument bytes say something
  else. The gateway binds those bytes. Missing `data_class` becomes
  `classified` and missing `irreversible` becomes true. A built-in check
  refuses some sensitive bodies labelled `public`
  (`record_args_mismatch:sensitive_labeled_public`). That is not a DLP
  product.
- These integrations are tested only against fakes or local stand-ins. No
  live vendor judge API, no real DLP or antivirus product, no real
  Hyperledger Fabric network, no real HSM or smart card, no real PKI
  revocation network, and no real liboqs module. PKCS#11 was tried with
  SoftHSM. The ML-DSA half of a hybrid identity stays in software.
- Public anchoring is an interface. `LocalFileAnchor` writes a local file.
  There is no public transparency log.
- Stealing the ledger key decrypts the log. Stealing the principal key does
  not. Stealing the witness key as well as the principal key can forge a
  head. There is no external anchor in personal mode, so those two keys
  plus the ledger key are enough to rewrite a ledger that never leaves the
  machine.
- HMAC token mode (`tk1-hs384`) is off unless chosen. In that mode the
  verifier can also mint. The default is a signature (`tk1-sig`).
- A crash after `redemption_started` and before the tool runs refuses a
  retry, even if the tool did not run. Exactly-once execution is not claimed.
- There is no TEE. Username/password and OAuth device-code judge auth are
  rejected. Use `env`, `keyring`, or `callback`.
- ML-DSA in development came from pyca `cryptography` with its bundled
  OpenSSL, which is not a validated module. `fips_mode` refuses algorithms
  outside the approved list. It does not make this process a validated
  module.
- `ScanSettings.on_timeout` defaults to block. Setting it to `allow` lets a
  scanner timeout or error through. A conviction still denies.
- A down SIEM does not change the decision. Enterprise mode still will not
  start without a SIEM target, and an anchoring failure on the decision
  checkpoint does not release a token.

## Out of scope

- The prototype status itself, missing FIPS validation, and the untested
  vendor adapters listed above.
- Prompt injection that Path A denies because the structured record tripped
  a rule.
- A vulnerability in a judge vendor's API.
- Using this package as an MCP server or as user login. It is neither.

## What to re-check when the code changes

- `two_key/core.py`: both paths run, and `authorize_from_agent` does not call a tool.
- `two_key/quorum.py`: an abstention is not a yes, and `require_path_a_first` is not a skip.
- `two_key/gateway.py`: frozen bytes, then `redemption_started`, then the tool. Scanners run only when configured.
- `two_key/ledger.py`: the ledger key and the witness key stay outside the directory, and the principal key is not a decryption key.
- `two_key/scanning.py` and `tests/scan_fakes.py`: a new scanner claim needs a real engine, or the fake-only line above stays.
