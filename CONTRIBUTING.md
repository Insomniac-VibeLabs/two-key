# Contributing

Issues and pull requests are welcome. Two-Key is a prototype; changes should
keep the fail-closed behavior and the network-free test suite.

1. Create a virtualenv and run `pip install -e ".[yaml,pq]"`.
2. Make the change with tests. Keep the suite network-free. Use the fakes in
   `two_key/testing.py`, `two_key/pki_testing.py`, and `tests/scan_fakes.py`.
3. Route cryptography through `two_key.crypto`. The provider enforces the
   approved-algorithm list and `fips_mode`.
4. Run `python -m unittest discover -s tests` and
   `python tools/doccheck.py README.md docs/HOWTO.md`. If a doc example
   shows the behavior you changed, update the example.
5. Add a row to `CHANGES.md`. Open design questions belong in
   `DESIGN_OPTIONS.md`. Do not settle them silently in code.
6. Never commit keys, ledgers, or credentials. `.gitignore` covers the
   default file names.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md), not in a
public issue. Expected behavior is in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
