# Security policy

Two-Key is a prototype. It has not had an independent security review and it
is not a validated cryptographic module. Do not put it in front of real
money, mail, or production tools.

## Reporting a vulnerability

Please do not put exploit detail in a public place.

Report it through a private GitHub security advisory:

https://github.com/Insomniac-VibeLabs/two-key/security/advisories/new

Do not open a public issue and do not post the details in Discussions.
Include the version or commit, the path (policy VM, quorum, token, gateway,
ledger, scanners, PKI), and a minimal reproduction that does not require a
live vendor key. We will acknowledge receipt and say whether the report is
in scope.

## In scope

- A tool call that executes without both paths approving it
- A capability token that can be replayed, retargeted, or used after expiry
- Argument mutation between check and execution
- Ledger rewrite, truncation, or an unsigned append that still verifies
- A constitution that loads when unsigned, modified, or signed by another key
- A downgrade of the hybrid signature or hash suite

## Out of scope

- The prototype status itself, missing FIPS validation, or untested vendor
  adapters (those are documented limits)
- Prompt injection that Path A denies
- Vulnerabilities in a judge vendor's API
