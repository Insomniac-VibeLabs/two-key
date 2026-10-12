# Two-Key concept

[![tests](https://github.com/Insomniac-VibeLabs/two-key-concept/actions/workflows/tests.yml/badge.svg)](https://github.com/Insomniac-VibeLabs/two-key-concept/actions/workflows/tests.yml) [![build](https://github.com/Insomniac-VibeLabs/two-key-concept/actions/workflows/build.yml/badge.svg)](https://github.com/Insomniac-VibeLabs/two-key-concept/actions/workflows/build.yml) [![Code Coverage](https://github.com/Insomniac-VibeLabs/two-key-concept/actions/workflows/coverage.yml/badge.svg)](https://github.com/Insomniac-VibeLabs/two-key-concept/actions/workflows/coverage.yml) [![Latest Release](https://img.shields.io/github/v/release/Insomniac-VibeLabs/two-key-concept)](https://github.com/Insomniac-VibeLabs/two-key-concept/releases)
[![License](https://img.shields.io/github/license/Insomniac-VibeLabs/two-key-concept)](https://github.com/Insomniac-VibeLabs/two-key-concept/blob/v0.2.4/LICENSE) [![Security Scan](https://github.com/Insomniac-VibeLabs/two-key-concept/actions/workflows/security.yml/badge.svg)](https://github.com/Insomniac-VibeLabs/two-key-concept/actions/workflows/security.yml) [![Semgrep](https://github.com/Insomniac-VibeLabs/two-key-concept/actions/workflows/semgrep.yml/badge.svg)](https://github.com/Insomniac-VibeLabs/two-key-concept/actions/workflows/semgrep.yml)

Two independent keys must turn before an AI agent can act.

This repository is the initial concept, kept small on purpose. It has a
working ledger, Path A, Path B, and the judge and monitored-agent hooks. It does
not scan payloads and it has no antivirus or DLP hooks today. Hooks for
them, and the rest of the path to a 1.0 release, are on the
[roadmap](#roadmap).

Apache License 2.0. See [LICENSE](LICENSE).

Read [docs/FIT.md](docs/FIT.md) first, then
[docs/COMPARISON.md](docs/COMPARISON.md),
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and
[docs/SCOPE.md](docs/SCOPE.md), before relying on it. For where the project
is going, see [ROADMAP.md](ROADMAP.md).
