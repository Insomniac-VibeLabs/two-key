# Contributing

Changes should stay inside the core of
Two-Key: ledger, Path A, Path B, judge hooks, monitored-agent hooks. Work on
the items in [ROADMAP.md](ROADMAP.md) is also in scope, in the order and with
the limits given there.

Do not add a scanning, antivirus, or DLP engine here. Hooks that call external
scanners are next on the roadmap (0.6.0); PKI and certificate recovery come
after 1.0.
Permissioned-chain anchoring and seed phrases are not planned. Key backup
shipped in 0.3.0 (three passphrase bundles, not a seed phrase).

Update `README.md`, `ROADMAP.md`, `docs/HOWTO.md`, `docs/FIT.md`,
`docs/COMPARISON.md`, `docs/THREAT_MODEL.md`, `docs/SCOPE.md`, `CHANGES.md`,
`SECURITY.md`, `CONTRIBUTING.md`, `AGENTS.md`, `llms.txt`, and
`docs/JUDGES_AND_QUORUM.md` when a claim changes.
When a roadmap item ships, update `docs/SCOPE.md` and `docs/THREAT_MODEL.md`
in the same release.
When `dependencies`, the `yaml` extra, or the `mcp` extra changes, regenerate `uv.lock` with
the uv version pinned in `.github/workflows/tests.yml` and commit it.
After adding, renaming, or moving a heading in a document that has a table of
contents, run `python tests/test_doc_toc.py --write`; the test suite fails
while a table is out of date.
Run `python -m unittest discover -s tests` before opening a pull request.
