# Contributing

This repository is the concept line. Changes should stay inside the initial
two-key: ledger, Path A, Path B, judge hooks, monitored-agent hooks. Work on
the items in [ROADMAP.md](ROADMAP.md) is also in scope, in the order and with
the limits given there.

Do not add a scanning, antivirus, or DLP engine here. Hooks that call external
scanners are on the roadmap, as are PKI and certificate recovery.
Permissioned-chain anchoring and seed phrases are not planned. Key backup
shipped in 0.3.0 (three passphrase bundles, not a seed phrase).

Update `README.md`, `ROADMAP.md`, `docs/HOWTO.md`, `docs/FIT.md`,
`docs/COMPARISON.md`, `docs/THREAT_MODEL.md`, `docs/SCOPE.md`, `CHANGES.md`,
`SECURITY.md`, `CONTRIBUTING.md`, and `AGENTS.md` when a claim changes.
When a roadmap item ships, update `docs/SCOPE.md` and `docs/THREAT_MODEL.md`
in the same release.
Run `python -m unittest discover -s tests` before opening a pull request.
