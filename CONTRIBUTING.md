# Contributing

Changes should stay inside the core of
Two-Key: ledger, Path A, Path B, judge hooks, monitored-agent hooks. Work on
the items in [ROADMAP.md](ROADMAP.md) is also in scope, in the order and with
the limits given there.

Do not add a scanning, antivirus, or DLP engine here. Hooks that call external
scanners shipped in 0.6.0 (`two_key/scan.py`,
`two_key/scanners.py`, docs/SCANNERS.md): an adapter calls a product, it
never detects anything itself. Do not add a SIEM, log storage, search, or
alerting here either. The export shipped in 0.7.0 (`two_key/siem.py`,
`two_key/siem_sinks.py`, `two_key/siem_export.py`, docs/SIEM.md) hands
allowlisted fields to the operator's collector and keeps nothing: a new
ledger field leaves the box only when it is added to that allowlist on
purpose, and the tests fail while one is undecided. PKI and certificate recovery come after 1.0.
Permissioned-chain anchoring and seed phrases are not planned. Key backup
shipped in 0.3.0 (three passphrase bundles, not a seed phrase).

Update `README.md`, `ROADMAP.md`, `docs/HOWTO.md`, `docs/FIT.md`,
`docs/COMPARISON.md`, `docs/THREAT_MODEL.md`, `docs/SCOPE.md`, `CHANGES.md`,
`SECURITY.md`, `CONTRIBUTING.md`, `AGENTS.md`, `llms.txt`,
`docs/JUDGES_AND_QUORUM.md`, and `docs/PYPI.md`, and, for a new connection or hook,
`docs/CONNECTING.md` when a claim changes.
When a roadmap item ships, update `docs/SCOPE.md` and `docs/THREAT_MODEL.md`
in the same release.
When `dependencies`, the `yaml` extra, or the `mcp` extra changes, regenerate `uv.lock` with
the uv version pinned in `.github/workflows/tests.yml` and commit it.
After adding, renaming, or moving a heading in a document that has a table of
contents, run `python tests/test_doc_toc.py --write`; the test suite fails
while a table is out of date.
Run `python -m unittest discover -s tests` before opening a pull request.

CI runs every pipeline that runs code on Linux, macOS, and Windows: the tests
and the demo (`tests.yml`, Python 3.10 to 3.12), the build with a wheel
install and the demo (`build.yml`), and bandit (`security.yml`). Every job
blocks, Windows included. CodeQL (`codeql.yml`)
runs on all three as well. Semgrep (`semgrep.yml`) stays on Linux: it
analyses the source, not the running system, and its container image runs
only on Linux runners. Coverage (`coverage.yml`) is one report, from Linux.
Tests that start a child process build its environment with
`tests/child_env.py`, which keeps the variables Windows needs.

The suite never reaches the network. A test that needs a server starts one on
loopback and stops it (the SIEM sink tests do this, with a throwaway
certificate authority from `tests/tls.py`). An integration that needs a real
product, such as the Elastic example under `examples/siem/`, belongs in a
manual, non-required workflow, never in the suite.

Publishing is [docs/PYPI.md](docs/PYPI.md), on the `PyPI` branch. Do not
put a PyPI token in the repository or in a GitHub secret. The workflow
there uses trusted publishing. Do not move tag `v0.7.0` to point at a
packaging commit.
