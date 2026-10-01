# Security policy

Two-Key is a prototype. It has not had an independent security review and it
is not a validated cryptographic module. Do not put it in front of real
money, mail, or production tools.

## Reporting a vulnerability

Please do not open a public GitHub issue for a vulnerability.

Use a private GitHub security advisory on this repository:

https://github.com/Insomniac-VibeLabs/two-key/security/advisories/new

If that page is unavailable, open an issue titled "security report" with no
exploit detail and ask the maintainers for a private channel.

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
