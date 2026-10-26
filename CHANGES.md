<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Changes

## Contents

<!-- toc -->
- [0.1.0 — 2026-10-02](#010--2026-10-02)
- [0.1.1 — 2026-10-02](#011--2026-10-02)
- [0.1.2 — 2026-10-02](#012--2026-10-02)
- [Docs — 2026-10-02](#docs--2026-10-02)
- [0.1.3 — 2026-10-02](#013--2026-10-02)
- [0.1.4 — 2026-10-03](#014--2026-10-03)
- [Docs — 2026-10-03](#docs--2026-10-03)
- [Fixes — 2026-10-03](#fixes--2026-10-03)
- [0.1.6 — 2026-10-03](#016--2026-10-03)
- [0.1.7 — 2026-10-03](#017--2026-10-03)
- [0.1.8 — 2026-10-03](#018--2026-10-03)
- [0.1.9 — 2026-10-03](#019--2026-10-03)
- [0.1.10 — 2026-10-03](#0110--2026-10-03)
- [0.1.11 — 2026-10-03](#0111--2026-10-03)
- [0.1.12 — 2026-10-03](#0112--2026-10-03)
- [0.2.0 — 2026-10-03](#020--2026-10-03)
- [Cyber fail-closed pass — 2026-10-06 (in v0.2.0)](#cyber-fail-closed-pass--2026-10-06-in-v020)
- [0.2.1 — 2026-10-07](#021--2026-10-07)
- [0.2.2 — 2026-10-09](#022--2026-10-09)
- [0.2.3 — 2026-10-09](#023--2026-10-09)
- [0.2.4 — 2026-10-10](#024--2026-10-10)
- [0.3.0 — 2026-10-10](#030--2026-10-10)
- [Fixes — 2026-10-11](#fixes--2026-10-11)
- [CI — 2026-10-11](#ci--2026-10-11)
- [Gateway deployment boundary (#45) — 2026-10-13](#gateway-deployment-boundary-45--2026-10-13)
- [Custom Path A fields — 2026-10-13](#custom-path-a-fields--2026-10-13)
- [Docs match the code — 2026-10-13](#docs-match-the-code--2026-10-13)
- [Release v0.3.0 — 2026-10-13](#release-v030--2026-10-13)
- [PR #85 check fixes — 2026-10-13](#pr-85-check-fixes--2026-10-13)
- [DeepSource test-fixture findings — 2026-10-14](#deepsource-test-fixture-findings--2026-10-14)
- [Live-test findings: docs — 2026-10-14](#live-test-findings-docs--2026-10-14)
- [Agent prompt names the data classes — 2026-10-14](#agent-prompt-names-the-data-classes--2026-10-14)
- [Opt-in tool vocabulary for the monitored agent — 2026-10-14](#opt-in-tool-vocabulary-for-the-monitored-agent--2026-10-14)
- [Tool vocabulary lists syntax, never values — 2026-10-14](#tool-vocabulary-lists-syntax-never-values--2026-10-14)
- [README request-flow diagram renders again — 2026-10-14](#readme-request-flow-diagram-renders-again--2026-10-14)
- [Docs: agent vocabulary diagram and trust boundary — 2026-10-14](#docs-agent-vocabulary-diagram-and-trust-boundary--2026-10-14)
- [Agent declines — 2026-10-14](#agent-declines--2026-10-14)
- [Data classes combine as a set — 2026-10-14](#data-classes-combine-as-a-set--2026-10-14)
- [Live test run 5 (blind) fixes — 2026-10-14](#live-test-run-5-blind-fixes--2026-10-14)
- [Docs: what Two-Key verifies (live run 5c) — 2026-10-14](#docs-what-two-key-verifies-live-run-5c--2026-10-14)
- [Release v0.3.1 — 2026-10-14](#release-v031--2026-10-14)
- [PR #90 DeepSource fixes — 2026-10-14](#pr-90-deepsource-fixes--2026-10-14)
- [Release v0.4.0: new repository, package `two-key`, formats without "concept" — 2026-10-15](#release-v040-new-repository-package-two-key-formats-without-concept--2026-10-15)
- [Mutable defaults in test helpers (#5) — 2026-10-15](#mutable-defaults-in-test-helpers-5--2026-10-15)
- [Workflow actions pinned to commit SHAs (#4) — 2026-10-15](#workflow-actions-pinned-to-commit-shas-4--2026-10-15)
- [Leftover review nits (#7) — 2026-10-15](#leftover-review-nits-7--2026-10-15)
- [Semgrep workflow permission — 2026-10-15](#semgrep-workflow-permission--2026-10-15)
- [MCP proxy, part 1: skeleton without caller facts (#2 P2) — 2026-10-15](#mcp-proxy-part-1-skeleton-without-caller-facts-2-p2--2026-10-15)
- [`two-key mcp-draft-specs` (#2 P3) — 2026-10-15](#two-key-mcp-draft-specs-2-p3--2026-10-15)
- [Docs: the MCP proxy (#2 P4) — 2026-10-15](#docs-the-mcp-proxy-2-p4--2026-10-15)
- [Live harness for run 6, through the MCP proxy (#2 P5) — 2026-10-15](#live-harness-for-run-6-through-the-mcp-proxy-2-p5--2026-10-15)
- [`main`'s workflow edits merged; CodeQL restored; Sonar scan v6 — 2026-10-15](#mains-workflow-edits-merged-codeql-restored-sonar-scan-v6--2026-10-15)
- [README license badge — 2026-10-15](#readme-license-badge--2026-10-15)
- [Caller-supplied facts and the guard core (#2 P1) — 2026-10-15](#caller-supplied-facts-and-the-guard-core-2-p1--2026-10-15)
- [Docs: roadmap order, README intro and MCP section, tables of contents — 2026-10-15](#docs-roadmap-order-readme-intro-and-mcp-section-tables-of-contents--2026-10-15)
- [Roadmap: judge connection reuse (#6) and judge history summary (#1) placed — 2026-10-15](#roadmap-judge-connection-reuse-6-and-judge-history-summary-1-placed--2026-10-15)
- [Every tool decides each field a rule reads (#10) — 2026-10-15](#every-tool-decides-each-field-a-rule-reads-10--2026-10-15)
- [`case: exact` string fields (live run 6x, X19) — 2026-10-15](#case-exact-string-fields-live-run-6x-x19--2026-10-15)
- [Judges are not asked about a call that cannot be read (run 6 finding 4) — 2026-10-15](#judges-are-not-asked-about-a-call-that-cannot-be-read-run-6-finding-4--2026-10-15)
- [Roadmap: per-judge ballot records before 1.0 — 2026-10-15](#roadmap-per-judge-ballot-records-before-10--2026-10-15)
- [`@domain` allow entries (run 6 finding 7) — 2026-10-15](#domain-allow-entries-run-6-finding-7--2026-10-15)
- [Docs: run 6 follow-ups in ROADMAP and SCOPE — 2026-10-15](#docs-run-6-follow-ups-in-roadmap-and-scope--2026-10-15)
- [Run 6 follow-ups: drafter and quorum warnings, HOWTO guidance — 2026-10-15](#run-6-follow-ups-drafter-and-quorum-warnings-howto-guidance--2026-10-15)
- [Live harness: run 6 referee fixes, quorum cases (for re-run 6z) — 2026-10-15](#live-harness-run-6-referee-fixes-quorum-cases-for-re-run-6z--2026-10-15)
- [Docs: the run 6 follow-ups everywhere they apply — 2026-10-15](#docs-the-run-6-follow-ups-everywhere-they-apply--2026-10-15)
- [Undescribed inputs: checked for every field Path A reads, at sign-off and start — 2026-10-15](#undescribed-inputs-checked-for-every-field-path-a-reads-at-sign-off-and-start--2026-10-15)
- [Run 6z follow-ups: clearer refusals, harness fixes, judge memory — 2026-10-15](#run-6z-follow-ups-clearer-refusals-harness-fixes-judge-memory--2026-10-15)
- [Release v0.5.0: MCP proxy, caller-supplied facts, run 6 follow-ups — 2026-10-15](#release-v050-mcp-proxy-caller-supplied-facts-run-6-follow-ups--2026-10-15)
- [PR #11 review: SonarCloud maintainability findings — 2026-10-15](#pr-11-review-sonarcloud-maintainability-findings--2026-10-15)
- [PR #11 review: no raw bidirectional characters — 2026-10-15](#pr-11-review-no-raw-bidirectional-characters--2026-10-15)
- [Semgrep findings printed to the job log — 2026-10-15](#semgrep-findings-printed-to-the-job-log--2026-10-15)
- [Roadmap: where we are, and the plan to 0.6.0 — 2026-10-15](#roadmap-where-we-are-and-the-plan-to-060--2026-10-15)
- [CI: an informational macOS and Windows run — 2026-10-15](#ci-an-informational-macos-and-windows-run--2026-10-15)
- [macOS: the one failing test; first portability results — 2026-10-15](#macos-the-one-failing-test-first-portability-results--2026-10-15)
- [Semgrep findings suppressed with reasons; judge hooks checked like proxy hooks — 2026-10-15](#semgrep-findings-suppressed-with-reasons-judge-hooks-checked-like-proxy-hooks--2026-10-15)
- [CodeQL action v4; the maintainer's 0.6.0 decisions in ROADMAP — 2026-10-15](#codeql-action-v4-the-maintainers-060-decisions-in-roadmap--2026-10-15)
- [CI on Linux, macOS, and Windows (0.6.0 Phase 1) — 2026-10-15](#ci-on-linux-macos-and-windows-060-phase-1--2026-10-15)
- [Windows support, part 1: owner-only files, locks, no-follow opens (0.6.0 Phase 2) — 2026-10-15](#windows-support-part-1-owner-only-files-locks-no-follow-opens-060-phase-2--2026-10-15)
- [Windows support, part 2: docs; one message (0.6.0 Phase 2) — 2026-10-15](#windows-support-part-2-docs-one-message-060-phase-2--2026-10-15)
- [Windows CI blocks (0.6.0 Phase 2 done) — 2026-10-15](#windows-ci-blocks-060-phase-2-done--2026-10-15)
- [Judge connection reuse (#6, 0.6.0 Phase 5) — 2026-10-15](#judge-connection-reuse-6-060-phase-5--2026-10-15)
- [Content scanning, part 1: the core (0.6.0 Phase 3) — 2026-10-15](#content-scanning-part-1-the-core-060-phase-3--2026-10-15)
- [Content scanning, part 2: adapters and the proxy (0.6.0 Phase 4) — 2026-10-15](#content-scanning-part-2-adapters-and-the-proxy-060-phase-4--2026-10-15)
- [Content scanning, part 3: docs (0.6.0 Phase 6) — 2026-10-15](#content-scanning-part-3-docs-060-phase-6--2026-10-15)
- [Live run 7 harness: content scanning (0.6.0 Phase 7) — 2026-10-15](#live-run-7-harness-content-scanning-060-phase-7--2026-10-15)
- [File size limits; unreadable files denied under every stance (0.6.0) — 2026-10-15](#file-size-limits-unreadable-files-denied-under-every-stance-060--2026-10-15)
- [Encrypted files: signed per-tool pass (0.6.0) — 2026-10-15](#encrypted-files-signed-per-tool-pass-060--2026-10-15)
- [Docs: connecting the agent so it cannot go around Two-Key — 2026-10-15](#docs-connecting-the-agent-so-it-cannot-go-around-two-key--2026-10-15)
- [Docs: the proxy wrapper leaves the agent's folder — 2026-10-16](#docs-the-proxy-wrapper-leaves-the-agents-folder--2026-10-16)
- [Start-up check: paths another account could change (0.6.0) — 2026-10-16](#start-up-check-paths-another-account-could-change-060--2026-10-16)
- [Run 7 follow-ups: key errors, scanner scope, relay — 2026-10-16](#run-7-follow-ups-key-errors-scanner-scope-relay--2026-10-16)
- [Release v0.6.0: Windows, content scanning, writable-path check — 2026-10-16](#release-v060-windows-content-scanning-writable-path-check--2026-10-16)
- [PR #12 review: TLS 1.2 for icaps, suppressed Semgrep findings — 2026-10-16](#pr-12-review-tls-12-for-icaps-suppressed-semgrep-findings--2026-10-16)
- [PR #12 review: SonarCloud findings — 2026-10-16](#pr-12-review-sonarcloud-findings--2026-10-16)
- [Docs: a 0.7.0 live run for the PR #12 refactor — 2026-10-16](#docs-a-070-live-run-for-the-pr-12-refactor--2026-10-16)
- [CI: the CodeQL configuration note — 2026-10-16](#ci-the-codeql-configuration-note--2026-10-16)
- [SIEM export: live delivery, file export, refused tokens (0.7.0) — 2026-10-16](#siem-export-live-delivery-file-export-refused-tokens-070--2026-10-16)
- [Docs: the SIEM export everywhere it applies (0.7.0) — 2026-10-16](#docs-the-siem-export-everywhere-it-applies-070--2026-10-16)
- [CI: two tests looked at the machine, one at the drive (0.7.0) — 2026-10-16](#ci-two-tests-looked-at-the-machine-one-at-the-drive-070--2026-10-16)
- [Live harness: run 8 (four personas, the SIEM copy, the paths 0.6.0 refactored) — 2026-10-16](#live-harness-run-8-four-personas-the-siem-copy-the-paths-060-refactored--2026-10-16)
- [Docs: an agent on another machine, over SSH — 2026-10-16](#docs-an-agent-on-another-machine-over-ssh--2026-10-16)
- [Live harness: what a pass does not cover — 2026-10-16](#live-harness-what-a-pass-does-not-cover--2026-10-16)
- [The proxy refuses an agent that is, or can change, Two-Key (0.7.0) — 2026-10-16](#the-proxy-refuses-an-agent-that-is-or-can-change-two-key-070--2026-10-16)
- [Live harness: the start-up account check — 2026-10-16](#live-harness-the-start-up-account-check--2026-10-16)
- [The `on_agent_access` tests on macOS and Windows — 2026-10-16](#the-on_agent_access-tests-on-macos-and-windows--2026-10-16)
- [Live run 8x findings: the SIEM copy, a named pipe, signing — 2026-10-16](#live-run-8x-findings-the-siem-copy-a-named-pipe-signing--2026-10-16)
- [`siem-verify` checks the whole event, and a cursor that cannot be read says so — 2026-10-16](#siem-verify-checks-the-whole-event-and-a-cursor-that-cannot-be-read-says-so--2026-10-16)
- [SonarCloud findings on the 0.7.0 code — 2026-10-16](#sonarcloud-findings-on-the-070-code--2026-10-16)
- [Release v0.7.0: the SIEM export, the agent-account check — 2026-10-16](#release-v070-the-siem-export-the-agent-account-check--2026-10-16)
- [PyPI packaging on the PyPI branch — 2026-10-16](#pypi-packaging-on-the-pypi-branch--2026-10-16)
- [Diagrams: one house style, checked by a test (#29) — 2026-10-20](#diagrams-one-house-style-checked-by-a-test-29--2026-10-20)
- [Docs: prose accuracy and readability pass — 2026-10-20](#docs-prose-accuracy-and-readability-pass--2026-10-20)
- [docs/SETTINGS.md: every setting, generated and tested — 2026-10-20](#docssettingsmd-every-setting-generated-and-tested--2026-10-20)
- [`two-key config show` and `config check`: read-only views of a proxy config — 2026-10-20](#two-key-config-show-and-config-check-read-only-views-of-a-proxy-config--2026-10-20)
- [Python 3.13 to 3.15: compiled files stay checked, CI, docs (#27) — 2026-10-20](#python-313-to-315-compiled-files-stay-checked-ci-docs-27--2026-10-20)
- [The proxy checks the upstream server's files behind a launcher (#13) — 2026-10-20](#the-proxy-checks-the-upstream-servers-files-behind-a-launcher-13--2026-10-20)
- [`upstream.check_paths` on Windows needs the drive (#13) — 2026-10-20](#upstreamcheck_paths-on-windows-needs-the-drive-13--2026-10-20)
- [DeepSource runs the Python analyzer, and on `working` — 2026-10-20](#deepsource-runs-the-python-analyzer-and-on-working--2026-10-20)
- [Docs review: README from main, clearer diagrams, `config show` described correctly — 2026-10-21](#docs-review-readme-from-main-clearer-diagrams-config-show-described-correctly--2026-10-21)
- [CI: each workflow runs once per change — 2026-10-21](#ci-each-workflow-runs-once-per-change--2026-10-21)
- [A Windows-only test failure in the clamd tests — 2026-10-21](#a-windows-only-test-failure-in-the-clamd-tests--2026-10-21)
- [`two-key setup` and `two-key config set`, `get`, `undo`, `key-passphrase`: one way in for setup and changes — 2026-10-20](#two-key-setup-and-two-key-config-set-get-undo-key-passphrase-one-way-in-for-setup-and-changes--2026-10-20)
- [Live harness: run 9 (set-up commands, upstream paths, two proxies, free play, sabotage) — 2026-10-21](#live-harness-run-9-set-up-commands-upstream-paths-two-proxies-free-play-sabotage--2026-10-21)
- [Copyright and author headers — 2026-10-21](#copyright-and-author-headers--2026-10-21)
- [OpenSSF Scorecard hardening: Semgrep token, hashed CI installs, SECURITY.md (#31, #32, #33) — 2026-10-21](#openssf-scorecard-hardening-semgrep-token-hashed-ci-installs-securitymd-31-32-33--2026-10-21)
- [Live runs 9 and 9x: SIEM cursor and `config check` fixes — 2026-10-21](#live-runs-9-and-9x-siem-cursor-and-config-check-fixes--2026-10-21)
- [A ledger never goes back to an older constitution (signed serial) — 2026-10-21](#a-ledger-never-goes-back-to-an-older-constitution-signed-serial--2026-10-21)
- [Live harness: run 9x ported to `working`, and the fixes for run 9y — 2026-10-21](#live-harness-run-9x-ported-to-working-and-the-fixes-for-run-9y--2026-10-21)
- [DeepSource: the findings on main, fixed or marked — 2026-10-21](#deepsource-the-findings-on-main-fixed-or-marked--2026-10-21)
- [Version number on `working`: 0.7.3 — 2026-10-22](#version-number-on-working-073--2026-10-22)
- [Live run 9y: two proxies starting at once, rules without a serial, and shared-ledger SIEM copies — 2026-10-22](#live-run-9y-two-proxies-starting-at-once-rules-without-a-serial-and-shared-ledger-siem-copies--2026-10-22)
- [Live run 9z: two harness fixes, and a faster harness — 2026-10-23](#live-run-9z-two-harness-fixes-and-a-faster-harness--2026-10-23)
- [Release v0.7.3: setup and change commands, a signed serial, the upstream server's files — 2026-10-23](#release-v073-setup-and-change-commands-a-signed-serial-the-upstream-servers-files--2026-10-23)
- [After 0.7.3: the serial check split for readability — 2026-10-23](#after-073-the-serial-check-split-for-readability--2026-10-23)
- [Dependabot: uv and the diagram tools updated — 2026-10-23](#dependabot-uv-and-the-diagram-tools-updated--2026-10-23)
- [Live run 9s: two test-code fixes — 2026-10-23](#live-run-9s-two-test-code-fixes--2026-10-23)
- [Optional tool spec fields, and README wording — 2026-10-23](#optional-tool-spec-fields-and-readme-wording--2026-10-23)
- [0.8.0 work: judge history, ballot records, and one proxy per agent — 2026-10-25](#080-work-judge-history-ballot-records-and-one-proxy-per-agent--2026-10-25)
- [Dependabot: setuptools 84.1.0 for CI builds — 2026-10-25](#dependabot-setuptools-8410-for-ci-builds--2026-10-25)
- [Roadmap: 0.8.0 and 0.9.0 in the README and ROADMAP diagrams — 2026-10-26](#roadmap-080-and-090-in-the-readme-and-roadmap-diagrams--2026-10-26)
<!-- /toc -->

## 0.1.0 — 2026-10-02

Initial concept repository, private, Apache-2.0.

Cut down to the initial two-key:

- signed constitution, Path A policy VM, Path B judge quorum
- hash-chained ledger with a signed head and Merkle root bound into the token
- single-use gateway redemption
- judge transport kept: no SDK, no streaming, connection reuse, no redirects,
  one HTTP 400 fallback that drops schema / cache / reasoning knobs
- monitored-agent hooks kept: agents are untrusted regardless of host;
  `authorize_from_agent` always runs both paths and does not execute tools

Not included: scanning, antivirus, DLP, PKI, anchoring, seed phrases, ledger
encryption, hybrid ML-DSA.

## 0.1.1 — 2026-10-02

On branch `10.2.2026`. `prev` and `main` stay at 0.1.0.

- Gateway runs the tool before redemption. A tool exception leaves the token redeemable.
- Merkle root is RFC 6962. Odd counts no longer duplicate the last leaf.
- Username/password and OAuth device-code auth are rejected.
- Ledger entries and head are AES-256-GCM. Head is signed by the principal and a witness key.
- `two-key authorize` runs both paths and does not execute the tool.
- CodeQL workflow added so code scanning could run while the repository was private.

## 0.1.2 — 2026-10-02

Private concept package. Not published to PyPI. Tag `v0.1.2`.

- Ledger key and witness key are created outside the ledger directory. The principal key neither decrypts the log nor signs a head alone.
- `authorize` no longer accepts `--allow-test-doubles`.
- Tests cover a second-process reload and a missing witness key.
- Bandit workflow added. CodeQL remains for when Advanced Security is enabled.
- Crash-after-success redemption window stays documented and unchanged.

## Docs — 2026-10-02

Clarified the GitHub file list. The middle column is the last commit message,
not a description of each file. README no longer calls the package private.
Added `llms.txt` and repository topics for discovery. No behavior change.

## 0.1.3 — 2026-10-02

- Redemption writes and checkpoints an intent before the tool runs. A retry of that intent does not run the tool.
- A tool exception appends an abort and leaves the token usable.
- A crash after the intent and before the tool runs also blocks a retry.

## 0.1.4 — 2026-10-03

Tag `v0.1.4`. No behavior change. The `v0.1.3` tag stays on the earlier tree.

- README architecture diagram: a monitored agent only proposes, Path B judges vote with their own credentials, and the token is returned to the caller. Path B still runs when Path A denies.

## Docs — 2026-10-03

On branch `10.3.2026.2`, cut from `main`. `main` was not updated.

- Added `docs/FIT.md`, `docs/COMPARISON.md`, `docs/THREAT_MODEL.md`, and `docs/SCOPE.md` for this package.
- `README.md`, `docs/HOWTO.md`, `llms.txt`, `SECURITY.md`, and `CONTRIBUTING.md` point at them.
- `SECURITY.md` no longer calls this repository private.
- No behavior change. Package version stays 0.1.4.

## Fixes — 2026-10-03

On branch `10.3.2026.2`. `main` was not updated.

- Path B comments match the code. Both paths always run. `require_path_a_first` is recorded and not consulted. The unused `judge_proposal` value in `convene` is gone; per-judge filtering is unchanged.
- Comments no longer point at design notes as if they were files in this repository. `docs/HOWTO.md` has the Qwen2.5 section the example config links to.
- `two-key authorize` defaults `--data-class` to `classified` and `--irreversible` to true, matching `normalize_action`. `--no-irreversible` turns that flag off.
- A mismatched principal key on the ledger head reports a principal-key mismatch, not a ledger-key mismatch.
- Appends and checkpoints take `<ledger>.lock` outside the ledger directory and refuse if another writer changed the file. Redemption locks moved to `<ledger>.redeem-locks/`, also outside. `fcntl` is optional, so the package still imports where that module is absent.
- Workflows set an explicit `permissions` block. The CodeQL job still has `security-events: write`.
- The 0.1.1 changelog no longer calls the repository private in the present tense.

## 0.1.6 — 2026-10-03

Tag `v0.1.6`. `v0.1.2`, `v0.1.3`, and `v0.1.4` stay on their earlier commits.

Pulled in by merge of pull request #4, previously unreleased:

- Fit, comparison, threat-model, and scope pages.
- `two-key authorize` defaults match `normalize_action`: classified, and irreversible true.
- A stale ledger refuses to append. Ledger and redemption locks stay outside the ledger directory.
- Path B comments match the code. Both paths still run.

No behavior change in this version bump itself. Not published to PyPI.

## 0.1.7 — 2026-10-03

On branch `working`, cut from `main` at `e29b776` (`v0.1.6`). `main` was not
updated. This version is not a release tag. `v0.1.6` stays on the previous tree.

- A signed constitution may include `tool_specs`. Every allow-listed tool then
  needs a spec. Amount and counterparties are read from the argument bytes by
  JSON path. A present claim that disagrees is a deny. An omitted amount or
  counterparty is filled from the bytes. An omitted `irreversible` follows
  the spec. `data_class` can only get stricter than `data_class_floor`, and
  a missing class still starts at `classified`. The token binds `spec_hash`
  and the derived form. The gateway recomputes that form. A spec change
  invalidates outstanding tokens.
- `tool_specs: null` is refused. Omitting the key is the only legacy path.
- A derived amount that is not finite, or above the action sanity cap, is a deny.
- A constitution that omits `tool_specs` is unchanged: the agent's form is
  still trusted. The offline demo uses that path.
- No English scanner and no per-value information-flow tracking. Quorum
  defaults and the minting key are unchanged. Both paths still run.
- Not published to PyPI.

## 0.1.8 — 2026-10-03

On branch `working`. Not a release tag. `main` was not updated. `v0.1.6` stays
the tagged release.

- `tool_specs` is required. A constitution that omits the key does not sign
  and does not load. There is no remaining path that trusts the agent's form.
- Diversity floors default on: two vendors, one local judge, and a yes from
  a local judge. `QuorumPolicy.without_diversity_floors()` opts out.
  `require_path_a_first` still defaults off and is still not a skip.
  `TwoKey` refuses to start when the judge set misses the floor.
- Tokens are signed by a capability key outside the ledger directory
  (`<ledger>.capability/capability.pem`). The gateway keeps only the public
  half. The principal key still signs the constitution and the ledger head.
  A token signed with the principal key does not redeem.
- Not published to PyPI.

## 0.1.9 — 2026-10-03

On branch `working`. Not a release tag. `main` was not updated. `v0.1.6` stays
the tagged release.

- `deny_unmapped` is optional and defaults off. An argument key the spec does
  not name stays unread payload and does not change the form. A tool that
  sets the flag denies that key (`unmapped_field`). `payload` names a value
  that may be present and is not interpreted. A declared path covers that
  value and its children. The spec does not list every nested key.
- A value copied from a declared path is unchanged. Free text is still not
  classified. Both paths still run, including after a derive deny, so judges
  still see `tool_args`.
- Not published to PyPI.

## 0.1.10 — 2026-10-03

On branch `working`. Not a release tag. `main` was not updated. `v0.1.6` stays
the tagged release.

- After a derive deny, judges do not receive `tool_args` unless
  `QuorumPolicy.tool_args_on_derive_deny` is set. Path B still runs. Other
  denies still attach non-empty arguments. An allow still attaches them.
- An unnamed argument key does not reach the tool. `deny_unmapped` still
  defaults off: the call can allow, and the gateway drops the key. Setting
  the flag denies (`unmapped_field`). The token still binds the caller's
  original argument bytes.
- A counterparty path requires `allow`. A party that is not listed is
  `counterparty_not_allowed`, unless a blocked party is also present, in
  which case the block rule still denies. The tool receives the canonical
  party, not the raw spelling.
- A `payload` path is still not classified. Both paths still run.
- Not published to PyPI.

## 0.1.11 — 2026-10-03

On branch `working`. Not a release tag. `main` was not updated. `v0.1.6` stays
the tagged release.

- A payload path may set `shape` to `string`, `number`, or `list` (a list of
  strings). `max_length` bounds a string or a list. A different kind is
  `payload_shape`, which is a derive deny. Shape does not read the contents.
  Omit `shape` and the value, including its children, is still copied unread.
- No payload class floor. What the text means stays with Path B, or with DLP
  outside this package.
- Not published to PyPI.

## 0.1.12 — 2026-10-03

Tag `v0.1.12` on `main`. No behavior change in this version. The `working`
line through 0.1.11 is this tree. `v0.1.6` stays on the previous tree.
Not published to PyPI.

## 0.2.0 — 2026-10-03

Tagged `v0.2.0` on `main` at `2f756ac` on 2026-10-07 (merge of PR #30).
Not published to PyPI. This version changes configuration and refuses some
setups 0.1.12 accepted: read "Upgrading from 0.1.12" below first.

### Changed

- Path B needs one judge by default and has no diversity floors.
  `QuorumPolicy.high_assurance()` (`profile: high_assurance`) turns on two
  vendors, one local judge, and a local yes; use it for destructive,
  irreversible, financial, or external-send tools. `required_yes` defaults
  to `min(2, number of judges)`.
- No judge may be the monitored agent. The operator declares the agent
  (`monitored_agent:` or `TwoKey(monitored_agent=...)`). Refused at start:
  the same credential fingerprint, a shared tenant id, the same normalized
  model on the same endpoint `host:port` (local aliases such as `0.0.0.0`,
  `127.1`, `localhost.localdomain`, and this machine's own addresses are one
  endpoint), the same model through a loopback or private proxy or daemon
  with no declared `upstream:`, the same model reaching the same upstream
  (`same_model_same_upstream`: declared upstreams and `ollama.com` for a
  cloud model count as endpoints, and different declared tenants do not
  lift it), or an unresolved identity (an
  unknown router, or a local proxy serving an alias model without a declared
  `upstream:`). Declared tenants are scoped by provider family, not by a
  proxy's address, and upstreams are normalized (`host[:port]`, default port
  removed). The same provider is allowed; `allow_same_provider_judge`
  is a no-op. The result, with `resolved_by` for each identity, is in
  `constitution_loaded`; each decision carries `identities_digest` and
  `policy_digest` (the full quorum policy is in `constitution_loaded` only).
  `two_key.audit.check_decision_digests(ledger)` recomputes both and lists
  any decision that does not match.
- Credential fingerprints are HMAC-SHA256 of the stripped secret under a
  per-install key, `<ledger>.ledger-key/fingerprint.key` (O_EXCL, 0600).
- Locality comes from the endpoint host and an explicit allowlist
  (loopback, RFC 1918, fc00::/7), never from a declared flag or
  `is_private`. A `:cloud` / `-cloud` model (an Ollama cloud model) is cloud
  and never local for every judge class (OllamaJudge, OpenAI-compatible,
  and the rest), and a monitored agent with one is hosted `cloud`.
- Start-up refuses: no judge, `timeout_seconds: null`, duplicate or empty
  judge ids, `require_local_yes` with no local judge, an unreadable judge
  credential, unknown top-level config keys, overlapping payload and field
  paths (compared case-insensitively), a TTL outside 1-300 seconds, and the in-process test agent unless
  every judge is a test double.
- Every JSON and YAML input refuses a repeated key and JSON NaN/Infinity.
- Ballots pair with judges by position; a ballot naming another judge
  abstains (`judge_id_mismatch`). Vendor and provider names compare
  case-insensitively (NFKC, trimmed) in the diversity and distinct-provider
  counts.
- The raw action claim is capped at 64 KiB before it is read
  (`action_too_large`, size and digest only). A tool name is an identifier
  of at most 128 characters. `malformed_action:` reasons name the field,
  never a value or an unknown key name.
- Denies instead of errors: arguments or a proposal over 256 KiB
  (`args_too_large`, `proposal_too_large`; only size and digest are
  ledgered), arguments nested more than 62 levels (`invalid_call:tool args are nested too deeply`,
  checked before the size so every Python version gives the same reason), an
  unreadable amount (`derive_failed:amount_unreadable`, for example
  `10**400`) or other derived value (`derive_failed:value_unreadable:<type_tag>`),
  any other exception in `authorize` (`internal_error:<Type>`), and a deny
  that cannot be ledgered (`ledger_failed:<LedgerError message>`, or
  `ledger_failed:<Type>` for any other exception; also on stderr).
- Logged opt-in `quorum: allow_same_model_distinct_tenant: true` (default
  off). It allows the agent's model on the same endpoint or upstream only
  when both sides declare a tenant, the scoped tenant ids are non-empty and
  disjoint, and both have keys with different fingerprints. It prints a
  stderr warning and records `same_model_tenant_optin` and
  `same_model_tenant_optin_pairs` (both tenant labels) in
  `constitution_loaded`. It is part of `policy_digest`. A misspelled key is
  refused.
- HOWTO has a "Known trade-offs by configuration" section.
- A host that is not a recognized vendor, router, or inference host is
  treated as a proxy for the same-model check, like a local one. A `maker/`
  model prefix no longer identifies it. With the agent's model and no
  non-overlapping `upstream:`, it is refused ("through a local or
  unrecognized proxy or daemon ... no declared upstream",
  `same_model_unknown_upstream`).
- One copy: tool args, the action claim, and the proposal are each copied
  once into built-in types (`canonical.to_plain`), in `authorize` and at the
  gateway. Any `collections.abc.Mapping` becomes a dict, a tuple becomes a
  list, and a `str`, `int` or `float` subclass becomes its base value. The
  size cap, the token's `args_hash`, the judges, the ledger and the tool all
  read that copy. A custom Mapping is no longer measured by its `str()`.
  Before this, a 5 MB Mapping in `raw` could get a token. The sizer no longer
  falls back to `str()` or `repr()`: a value it cannot encode as JSON counts
  as too large. Copying stops after `cap // 2` values, so a Mapping that
  never stops iterating is `args_too_large` / `action_too_large`
  (`*_size: -1`) rather than a hang.
- Depth: the canonical encoder refuses containers nested more than 64
  levels (`canonical.MAX_DEPTH`), counted without recursion. Tool args, the
  action claim, and a structured (non-text) proposal are held to 62
  (`MAX_INPUT_DEPTH`). That leaves room for the two levels an input gains
  inside a ledger entry or a judge's record (`raw.tool_args`), so an accepted
  input always encodes again. One level more is a ledgered deny:
  `invalid_call:tool args are nested too deeply`,
  `malformed_action:action claim is nested too deeply`, or
  `malformed_proposal`. It is never `internal_error`. A ledger body that
  still cannot be encoded is recorded by `Ledger.append_bounded` with only
  its short scalar fields, `body_size`, `body_digest`, `body_omitted`, and
  `body_error`. The entry is not lost.
- Tokens: a lifetime over the TTL (`ttl_too_long`), an issue time more than
  5 s ahead (`issued_in_future`), and missing or non-finite time fields
  (`malformed_token`) are refused. The capability key is created
  exclusively, never regenerated after issuance, and its fingerprint is
  pinned and checked by the gateway. A ledger that has issued tokens but
  has no pinned fingerprint is refused at start-up
  (`capability_key_unpinned:`).
- CLI: the bearer token is never printed (`token_jti`, `token_digest`);
  `--emit-token PATH` writes it 0600 and refuses to overwrite;
  `--agent-session-env NAME` replaces `--agent-session`; a `--key` readable
  by group or others is refused; `--ttl-seconds` is 1-300; decisions record
  `origin: cli`.
- The judge prompt describes any tool call with derived fields.
- The gateway ledgers every refusal of an authenticated token as
  `gateway_denied` (`reason`, `jti`, `tool` if it is a short identifier,
  else `tool_size`/`tool_digest`, and `tool_args_size`/`tool_args_digest`).
  A token that does not verify writes nothing.
- Arguments are encoded once per `authorize` and once per gateway call:
  the canonical bytes give the size check and the token's `args_hash`
  (they were serialized up to three times). The size cap measures compact
  JSON (no spaces after `,` and `:`).
- `two-key demo` opens its ledger in a subdirectory of its temporary
  directory, so the ledger key, witness, capability key, and lock files no
  longer outlive the run in the system temp directory. The tests do the
  same.
- B1: `agent_id` and `hosting` on `authorize` / `authorize_from_agent` are
  operator/library metadata. Non-`str` is `invalid_agent_metadata`; after
  strip, over 256 characters is `agent_metadata_too_large` (ledger
  `field`/`size`/`digest` only). `append_bounded` with `body_omitted` on a
  path about to issue a token becomes `ledger_body_too_large` instead of an
  allow. Shared helper: `two_key.agent_meta`.
- Decision `origin` (library/CLI label) uses the same 256-char / str caps as
  B1 metadata (`normalize_origin`). Oversize or non-str is a fail-closed deny
  with `field`/`size`/`digest` or `got: non_str` only — never the full value,
  and no token. Ledger type labels use `type_tag` (allowlisted or ≤32 chars),
  never raw unbounded `__name__`.
- `authorize_from_agent` measures the proposal text before parsing it:
  over 1,048,576 characters is `proposal_too_large`, and text that is not
  a string (including `None`) or does not parse is `malformed_proposal`.
  Both are ledgered denies with size and digest only, instead of an
  exception.
- The ledger key is created with O_EXCL and O_NOFOLLOW at mode 0600 in a
  0700 directory, and is refused on open if it is group- or
  world-readable, a symlink, or not 32 bytes (`ledger_key_insecure:`,
  `ledger_key_unreadable:`). The wrapped data key (`keywrap.json`) is
  written to an O_EXCL temporary file under the ledger lock and moved into
  place with `os.replace`.

### Upgrading from 0.1.12

1. Add a `monitored_agent:` block to judges.yaml (or pass
   `TwoKey(monitored_agent=...)`): `model`, `provider`, `base_url`, and
   `credential_env` (or `credential: none` for a keyless local agent). Set
   that environment variable where Two-Key starts.
2. Make every judge key readable at start-up, and keep it different from
   the agent's key.
3. Set `timeout_seconds` to a number. Give every judge a unique `id`.
4. If you relied on the old default floors, add `profile: high_assurance`
   to the quorum block. If you want one yes from two judges, set
   `required_yes: 1`.
5. Write `tenant` as a mapping (`tenant: {organization: org-123}`), and add
   `upstream:` to any judge or agent behind a local proxy that serves an
   alias model, and to any local proxy or daemon that serves the same model
   as the other side (a daemon with its own weights declares its own
   address, for example `upstream: localhost:11434`).
6. Remove `allow_same_provider_judge`, unknown top-level keys, and any key
   repeated in one mapping.
7. CLI: replace `--agent-session VALUE` with `--agent-session-env NAME`,
   read the token from `--emit-token PATH`, and `chmod 600` the `--key`
   file. Keep `--ttl-seconds` at 300 or less.
8. A 0.1.12 ledger that has issued tokens has no pinned capability key and
   is refused (`capability_key_unpinned:`). Keep it for audit and start a
   new ledger directory.
9. Tests that use `testing.TEST_AGENT` must use only test-double judges;
   with a real judge, declare a real agent.
10. `Decision.to_record()` no longer includes `token`; it has `token_jti`
    and `token_digest`. Read the bearer token from `decision.token`.
11. `QuorumPolicy().required_yes` is `None` until `TwoKey` resolves it
    against the judge list (`min(2, judges)`). Code that read the default
    as an integer must handle `None` or set `required_yes` explicitly.
12. A judge on a LAN or private address with `local_weights: true` is now
    cloud for the session check (only loopback is not), so `authorize`
    needs an `agent_session` (`cloud_judge_session_required`). It still
    counts as a local judge for the quorum floors.
13. Tokens minted by 0.1.12 will most likely be refused
    (`capability_key_mismatch`): 0.1.12 did not pin the capability key in
    `constitution_loaded`. Tokens live at most 300 seconds; re-authorize.

#### Troubleshooting: start-up refusals

These are the 0.2.0 messages. 0.2.2 changed the judge rows: several refusals below only warn now, and the message text changed. For 0.2.2, see "Upgrading from 0.2.1" and the HOWTO section on the monitored agent.

| Message starts with | Cause | Fix |
|---|---|---|
| `monitored_agent_required:` | No agent declared | Add `monitored_agent:` (step 1) |
| `monitored_agent ...: declare <field>` / `unknown key(s)` / `declare exactly one of credential_env or credential: none` | Incomplete or misspelled declaration | Give `model`, `provider`, `base_url`, and one credential key; allowed keys are `id`, `model`, `provider`, `base_url`, `credential_env`, `credential`, `tenant`, `upstream` |
| `monitored_agent ...: credential_env X is not set` | The agent key variable is unset | Export it where Two-Key starts |
| `monitored_agent ...: credential: none is only for a loopback or private-address agent` | `credential: none` on a remote host | Use `credential_env` |
| `judge_matches_agent: ... same credential fingerprint` | A judge uses the agent's key (whitespace ignored) | Give the judge its own key |
| `judge_matches_agent: ... same model '<m>' on the same endpoint <host:port>` | The judge is the agent's model at the agent's endpoint | Use another model, or the same model through another endpoint and key |
| `judge_matches_agent: ... same tenant <id>` | Same Azure resource or deployment, Vertex project, Bedrock account and region, or declared org/project | Use a judge in another tenant |
| `judge_matches_agent: ... through a local or unrecognized proxy or daemon (...) with no declared upstream` | The same model as the agent through a loopback or private endpoint that declares no `upstream:` | Use another model, or declare `upstream:` on the proxy or daemon (a different provider, or its own address for local weights) |
| `judge_matches_agent: ... through the same upstream <host>` | The same model reaching the agent's endpoint or declared upstream (or `ollama.com` for a cloud model) | Use another model or a non-overlapping upstream (another provider); different tenants on one upstream are still refused |
| `judge_matches_agent: ... upstream unresolved` | Unknown router or host, or a local proxy serving an alias | Use a `maker/model` id, or declare `upstream:` (attested, not verified) |
| `... tenant must be a mapping` / `unknown tenant key(s)` | Old string or list `tenant` | `tenant: {organization: ..., project: ..., account: ..., deployment: ...}` |
| `... upstream entries must be non-empty strings` | Empty or non-string `upstream` | A host string or a list of them |
| `in_process_agent_refused:` | `TEST_AGENT` (or `in-process://`) with a real judge, or without `allow_test_doubles` | Declare the real agent |
| `judge '<id>': credential could not be read at start-up` | Judge key variable, keyring, or callback unavailable | Make it readable at start-up |
| `no_judges:` | Empty judge list | Configure at least one judge |
| `Path B needs a hard deadline` / `timeout_seconds must be a positive number` | `timeout_seconds: null` | Set a number of seconds |
| `duplicate_judge_id:` | Two judges share an id, or an id is empty | Make ids unique |
| `judge set is not heterogeneous enough: require_local_yes_without_local_judge` | `require_local_yes` with no local judge | Add a loopback/private judge with local weights, or drop the flag |
| `judge set is not heterogeneous enough: insufficient_makers` (`insufficient_vendors` through 0.2.1) / `insufficient_local_judges` | `high_assurance` floors not met (makers compare case-insensitively) | Add a judge whose model has another maker (`maker:`), or a local judge, or leave the default profile |
| `unknown top-level key(s)` | A typo such as `quorm`, or a key other than `judges`, `quorum`, `monitored_agent` (agents.yaml: `agents`) | Fix the key |
| `duplicate key '<k>'` | A key repeated in one JSON/YAML mapping (config, rules, constitution, `--args`) | Keep one |
| `non-standard JSON constant` | `NaN` or `Infinity` in JSON | Use a finite number |
| `payload path ... overlaps the field path` | A payload path equals, contains, or sits under an amount, currency, or counterparty path, ignoring case (`TO.name` vs `to.name`) | Split the paths |
| `ttl_out_of_range:` | `ttl_seconds` not an integer from 1 to 300 | Use 1-300 |
| `capability_key_missing:` / `capability_key_changed:` | The token key was removed or replaced after tokens were issued | Restore `<ledger>.capability/capability.pem`, or start a new ledger |
| `capability_key_unpinned:` | The ledger has issued tokens but its last `constitution_loaded` entry pins no token key (a 0.1.12 ledger, or an edited one) | Keep the old ledger for audit and start a new one |
| `capability_key_is_principal_key` | The token key equals the principal key | Remove the copied key; Two-Key creates its own |
| `fingerprint_key_insecure:` / `fingerprint_key_unreadable:` / `fingerprint_key_unavailable:` | `<ledger>.ledger-key/fingerprint.key` is group/world-readable, a symlink, the wrong size, or cannot be created | `chmod 600` it, restore it, or make the directory writable |
| `ledger_key_insecure:` / `ledger_key_unreadable:` / `ledger_key_unavailable:` | `<ledger>.ledger-key/ledger.key` is group/world-readable, a symlink, the wrong size, or cannot be created | `chmod 600` it, restore it, or make the directory writable |
| `key_file_insecure:` / `key_file_unreadable:` | `--key` readable by group or others, a symlink, or missing | `chmod 600` the key |
| `--agent-session took the secret on the command line` | Old CLI flag | `--agent-session-env NAME` |
| `refusing to overwrite` | `init-key` or `--emit-token` target exists | Pick a new path |
| `environment variable NAME is not set` | `--agent-session-env` names an unset variable | Export it |

`allow_same_provider_judge is deprecated and has no effect` is a warning
on stderr, not a refusal. So are `vendor is deprecated; use maker` and
`min_vendors is deprecated; use min_makers` (after 0.2.1).

#### Troubleshooting: denies

| Deny or abstain reason | Cause | Fix |
|---|---|---|
| `action_too_large` | The action claim is over 64 KiB of UTF-8 JSON | Send a normal claim; only size and digest are ledgered |
| `malformed_action:tool: longer than 128 characters` / `tool: not an identifier ...` | The tool name is too long or has characters outside `a-z 0-9 _ . : / -` | Rename the tool |
| `malformed_action:unknown action fields (<n>)` / `<field>: ...` | An unknown or invalid action field (the reason names the field, not the value) | Fix the claim |
| `args_too_large` / `proposal_too_large` | Over 256 KiB of UTF-8 JSON, or agent proposal text over 1,048,576 characters | Send less; only size and digest are ledgered |
| `malformed_proposal` | `authorize_from_agent` got text that is not a string, not JSON, nested too deeply to parse (a `RecursionError` on any Python version), or has a missing, extra, or repeated key | Fix the agent's reply; the reason names no key |
| `invalid_call:<why>` (authorize and gateway) | Arguments nested more than 62 levels, NaN, a non-string key, or an unsupported type (`unsupported_type`; never a raw type name) | Flatten or fix the arguments |
| `malformed_action:action claim is nested too deeply` | The action claim (usually `raw`) nests more than 62 levels | Flatten `raw` |
| `body_omitted: true` on a ledger entry | The entry's body could not be encoded; short scalars plus `body_size`/`body_digest`/`body_error` are kept, and `policy_digest`/`identities_digest` are always retained when present; temporary JSON for the digest writes non-JSON values as `<type_tag>` (never raw `__name__`) | Read `body_error`; report it |
| `derive_failed:amount_unreadable` | The amount cannot be read (for example `10**400`, `"1e400"`, or a non-number) | Send a readable amount |
| `derive_failed:value_unreadable:<type_tag>` | Another derived value cannot be read (for example nested too deeply to walk); type label is `type_tag` (≤32 chars), never raw `__name__` | Send a readable value |
| `internal_error:<Type>` | Any other exception inside `authorize` | Read the ledger entry; report it |
| `ledger_failed:<message>` / `ledger_failed:<Type>` | The deny could not be written: a `LedgerError` gives its message (for example `ledger file changed by another writer; reopen the ledger`), any other exception its type (also printed on stderr) | Check the ledger directory |
| `cloud_judge_session_required` | A judge not on loopback, and no `agent_session` | Pass the agent session (`--agent-session-env`) |
| `cloud_judge_reused_agent_session` | A judge key equals the agent session | Give the judge its own key |
| `judge_id_mismatch` (abstain) | A ballot named another judge | Check the judge; the ballot does not count |
| ballot `duplicate key` / `non-standard JSON constant` (abstain) | The judge repeated a key or sent NaN | Not a yes; check the model |
| `duplicate_judge_id` | Judges with the same id reached `convene` | Make ids unique |
| `judge_set_not_heterogeneous:...` | A floor is not met at decision time | As for the start-up message |
| `insufficient_yes:<y><<k>` with two judges | `required_yes` now defaults to 2 when there are two or more judges | Set `required_yes: 1` if one yes is enough |
| `ttl_too_long` / `issued_in_future` / `malformed_token` | A token outlives the TTL, is dated ahead, or has missing or non-finite times | Re-authorize; check clocks |
| `capability_key_mismatch` | The token key is not the one pinned in the ledger | Re-authorize with the current key |
| `gateway_denied` (ledger entry) | The gateway refused an authenticated token; `reason` says why (`args_mismatch`, `tool_mismatch`, `already_redeemed`, ...) | Read `reason`; values are never ledgered, only size and digest |
| `AgentConfigError: agent proposal has a duplicate key` | `parse_proposal` or `MonitoredAgent.complete` got a proposal with a repeated key (`authorize_from_agent` denies `malformed_proposal` instead) | Fix the agent's JSON |

### Planned (not done)

- Generic spec field types moved to [ROADMAP.md](ROADMAP.md) (after 1.0, not scheduled).

## Cyber fail-closed pass — 2026-10-06 (in v0.2.0)

In tag `v0.2.0` (`2f756ac`), and so in `v0.2.1`. Issues addressed:

- **#9** — Declared upstream labels folded (NFKC / zero-width); bare `openai` maps to `api.openai.com`.
- **#8** — Empty `tenant: {}` refused (omit instead); same-model distinct-tenant opt-in documented as `constitution_loaded`-only.
- **#12** — Per-jti throttle: after the first `gateway_denied` for a jti, further denies still refuse but do not append repeats.
- **#11** — `append_bounded` `body_omitted` entries always retain `policy_digest` and `identities_digest`.
- **#16** — Bound `_denied_jtis`: mark jti only after successful `gateway_denied` append+checkpoint; LRU hard cap (`_MAX_DENIED_JTIS`, default 4096).
- **#17** — Complete (via #20 / #21): cap exception/reason ledger text (~300 chars + digest) via `cap_ledger_text` / `exception_ledger_error`. Covers quorum ballot error, both Path A `vm_fault` paths (`VMFault` and generic `Exception`), gateway `_record_deny` `ledger_failed`, core authorize/`_deny` `ledger_failed`, and gateway redemption `ledger_failed` sites. Non-`LedgerError` deny paths keep `type_tag` only.
- **#18** — `check_agent_meta_mapping` reports `got: non_mapping` for a non-Mapping `agent_meta` (field values stay `non_str`).
- **#19** — SHA-pin third-party GitHub Actions (`checkout`, `setup-python`, `codeql-action`) to full commit SHAs.
- **#20** — Cap dedicated `VMFault` `vm_fault:` reason via `exception_ledger_error` (parity with #17 generic Exception path).
- **#21** — Cap remaining `ledger_failed:{e}` / `ledger_failed:{le}` in `core.py` and `gateway.py` redemption paths via `cap_ledger_text`.
- **#22** — Clamp `max_denied_jtis` to `>= 1` (zero/negative no longer KeyError after deny).
- **#23** — Same-jti single-flight under `_denied_jtis_guard`: concurrent denies for one jti wait; at most one successful `gateway_denied` append per jti. Mark-after-success (#16) preserved.
- **#24** — `EncodingError` for a non-JSON type is the fixed label `unsupported_type` (never raw unbounded `__name__`). Authorize/gateway `invalid_call:` / `malformed_action:` suffixes and `*_error` ledger fields run through `cap_ledger_text`. `core._deny` stderr caps `reason` / `str(e)` before format (no full `{e}` then `[:500]`).
- **#25** — Same-jti `Condition.wait` is timed (default 30s, `deny_inflight_wait_seconds`); on timeout waiters still deny fail-closed without marking and without fail-open, so a stuck `append_bounded` cannot hang waiters forever.
- **#26** — `derive` `value_unreadable:` uses `type_tag(exc)` (never raw unbounded `__name__`); `derive_failed:` decision reasons are `cap_ledger_text`'d where stored. `append_bounded` / `omitted_body` JSON `default=` uses `type_tag(o)` so temporary size/digest allocation cannot balloon on a pathological class name.
- **#27** — LLM judge `transport:` / `malformed_response:` abstain errors use `type_tag(e)` (not raw `type(e).__name__`) into `ballot.error` (`QuorumResult.to_record`).
- **#28** — `deny_inflight_wait_seconds` requires finite positive (`math.isfinite`); `inf` / `nan` / ≤0 fall back to the 30s default (so `inf` cannot restore unbounded same-jti `Condition.wait`).
- README: removed the GitHub Pages `pages-build-deployment` Documentation Status badge (other badges kept).

## 0.2.1 — 2026-10-07

Tag `v0.2.1` on `main` and `working`. Docs and version only. No behavior
change. Not published to PyPI. `v0.2.0` stays on `2f756ac` and is not moved.

- Package version is 0.2.1 (`pyproject.toml`, `two_key.__version__`).
- README, AGENTS.md, and llms.txt name tag `v0.2.1` and install from
  `@v0.2.1`. The 0.2.0 README still said the package was untagged on
  `working`.

## 0.2.2 — 2026-10-09

Tag `v0.2.2` on `main` and `working`. Not published to PyPI. **This version
changes configuration and refuses some setups 0.2.1 accepted. Read
"Upgrading from 0.2.1" below first.** The step-by-step history is in the
commit messages of PRs #43 and #61.

### Changed

- **When a judge is the monitored agent (owner's decision, 2026-10-08).**
  A judge may run any model from any vendor. It is the agent, and `TwoKey`
  refuses to start (`judge_matches_agent:`), in two cases only:
  - it holds the agent's credential (an API token, or a username and
    password as one pair), at any address: a credential identifies its
    holder wherever it is sent (`same_credential`);
  - neither side has a credential and both are on one address
    (`host:port` as configured, every local alias folded to `localhost`,
    no DNS), so nothing tells them apart (`same_address_no_credential`).

  For a connector Two-Key drives, a side counts as keyless when it sends no
  credential, whatever is configured: a judge with `auth_header: none` (an
  Ollama judge's default) and an `agents.yaml` `ollama` agent without Basic
  auth. A `monitored_agent:` declaration cannot say what the agent sends,
  so one with `credential_env` or `username_env` counts as keyed even when
  its server ignores the key (an Ollama daemon); a keyless judge next to it
  only warns (`same_address_one_side_keyless`). Declare such an agent with
  `credential: none`. A configured credential that cannot be read at
  start-up refuses, for a local agent as well as a cloud one, unless it is
  never sent (an `agents.yaml` `ollama` agent without Basic auth, or a judge
  with `auth_header: none`, whose key is not read).

  What used to refuse and now only warns: the same model on the same
  endpoint or upstream, a shared tenant id, a local or unrecognized proxy
  with no declared `upstream:`, and an unresolved identity. Each warning
  prints a `two-key: WARNING:` line and is recorded in `constitution_loaded`
  (`judge_agent_separation.warnings`). The checks are
  `same_address_one_side_keyless`, `same_model_same_address`,
  `same_model_shared_route` (was the refusal `same_model_same_upstream`),
  `same_model_unknown_proxy` (was `same_model_unknown_upstream`),
  `shared_tenant`, and `unresolved_identity` (once per identity).
  `upstream:` and `tenant:` change which warnings print, never what is
  refused. `allow_same_model_distinct_tenant` is now a deprecated no-op,
  like `allow_same_provider_judge`, and `same_model_tenant_optin_pairs` is
  always empty.

  At call time an LLM judge whose credential equals `agent_session`
  abstains (`cloud_judge_reused_agent_session`) wherever it connects, as in
  0.2.1. An `agent_session` that is neither a string nor a list, tuple, or
  set of strings (bytes, for example) now makes an LLM judge abstain
  (`agent_session must be a string`); 0.2.1 skipped the check for a local
  judge.
- **"vendor" is renamed "maker" (#44).** A judge's maker is who made its
  model, as the operator labels it (default: its `provider`), not
  verified, and never compared with the monitored agent. Judge key
  `vendor:` → `maker:`; quorum key and field `min_vendors` → `min_makers`;
  `Judge.vendor` → `Judge.maker`; the `vendor=` argument of `LLMJudge` and
  `FixedJudge` → `maker=`. The config keys `vendor:` / `min_vendors:` and
  the arguments `vendor=` / `min_vendors=` still work in 0.2.2 and print one
  stderr line each; `.vendor` and `.min_vendors` still read, without a
  note. All are removed in 0.2.3. Two names changed now, with no alias:
  the `Judge.describe()` key `vendor` → `maker`, and the deny and start-up
  refusal `insufficient_vendors:` → `insufficient_makers:`. A judge class
  written before the rename that overrides `vendor`, sets the private
  `_vendor`, or is a duck-typed object with a `vendor` attribute keeps that
  label as its maker. `QuorumPolicy.to_record()` writes `min_makers`, so
  `policy_digest` changes for the same settings;
  `audit.check_decision_digests` recomputes from each stored record, so
  older ledgers still check clean.
- `quorum` passes a judge's `score_bound` the keyword arguments its
  signature accepts, instead of retrying on `TypeError` (#60, item 4), so a
  `TypeError` inside a judge is an abstention, not a second call without the
  agent session. A signature that cannot be read gets every keyword; if it
  does not take `agent_session`, the judge abstains (0.2.1 retried without
  it).
- The build requires `setuptools>=77.0`, the first release that accepts
  `license = "Apache-2.0"` as an SPDX string (PEP 639).

### Added

- **HTTP Basic auth, over HTTPS only.** `auth: {type: basic, username_env:
  ..., password_env: ...}` on a judge or in `agents.yaml`, and
  `username_env` / `password_env` instead of `credential_env` in
  `monitored_agent:`. A plain-HTTP `base_url` with Basic auth is refused, and
  so is a username containing `:`. The old `username_password` type is
  still refused, with a message naming `basic`. OAuth device-code is still
  refused.
- **Password fingerprints use scrypt.** A username and password pair is
  fingerprinted with scrypt (N=2^17, r=8, p=1, the OWASP minimum: 128 MiB,
  about 0.4 s per pair at start-up) under the per-install key as the salt
  (`scrypt-n17-r8-p1:...`), and only with that key. API tokens keep
  HMAC-SHA256: a random token is safe under a cheap hash, a guessable one
  (a placeholder such as `EMPTY`) is not. The per-install key sits beside
  the ledger key, so anyone who can decrypt the ledger holds it too; for a
  guessable password only the scrypt cost slows an offline guess. This
  clears the two high CodeQL alerts (py/weak-sensitive-data-hashing) the
  password support first raised. Any credential sent as HTTP Basic (a
  provider whose `kind` is `basic`) is fingerprinted as a pair, so a judge
  and the agent with the same pair match; an empty one refuses. The pair is
  stripped of whitespace at its two ends only. A pair and a token are never
  compared: an agent declared with `credential_env` whose value is
  `user:pass`, or a judge that sends the agent's `user:pass` as a token,
  does not match a declared pair at start-up (declare a Basic agent with
  `username_env` / `password_env`); the call-time `agent_session` check
  still compares the raw strings. A scrypt failure (memory, or no scrypt in
  a FIPS-only OpenSSL) refuses with `password_fingerprint_failed:`.
  `constitution_loaded` records `password_alg` beside `alg`.

### Fixed

- **#29**: credential and start-up identity errors use `type_tag(e)` (at
  most 32 characters) instead of the raw `type(e).__name__`, and the LLM
  judge `credential:` abstain is capped with `cap_ledger_text`.
- **#42**: `ToolGateway._locks` no longer grows with every redeemed jti.
  Each entry is reference-counted under `_locks_guard` and removed when the
  last thread that holds or waits on it leaves, including after a tool
  exception or a lock-file error. No LRU cap, so a held lock is never
  evicted. The lock files under `<ledger>.redeem-locks/` are unchanged (one
  per jti, never deleted).
- A shared-credential refusal says what to do for a placeholder a local
  server ignores (`EMPTY`): give each side its own value, or leave it off
  one side (`auth: {type: none}` on a judge, `credential: none` on the
  agent); on one address, give the judge its own address or a credential
  the server checks.

### Docs

- `revoke` is described as what it does (#46): it ends tokens issued before
  the call; it does not stop new approvals and does not survive a restart.
  HOWTO's "Stop" section is now "Revoke outstanding tokens".
- Security findings are taken as public issues while this is a prototype
  (SECURITY.md, AGENTS.md); private reporting starts once the product is
  more mature and in use. The review findings are issues #45 to #60.
- README and HOWTO describe a gateway in its own process or host (#45),
  marked designed, not yet built, and what happens today with a `Ledger`
  opened in another process.
- HOWTO "If the ledger will not open after a crash" (#49): a manual
  recovery, checked against a ledger with uncovered entries and a torn
  line. A recovery command is still open.
- The witness key is described as it is: the head carries its own witness
  public key, which is not pinned (#58), so the principal key and the
  ledger key together can sign a head. Pinning is planned for 0.2.3.
- THREAT_MODEL and README name a gap the ledger has had since before
  0.2.1: anyone who can write the ledger directory can roll it back to an
  earlier signed head or wipe it, with no key, and both open and verify.
  Without an external anchor neither is detected (#62).
- The identity docstring no longer claims the per-install fingerprint key
  stops a ledger reader from testing guesses. README, HOWTO, llms.txt, and
  THREAT_MODEL describe HMAC-SHA256 for tokens and scrypt for passwords.
- New `ROADMAP.md` (0.3 key backup through 1.0) and the README roadmap
  table; SCOPE and THREAT_MODEL "planned" sections; AGENTS.md puts PKI,
  hybrid ML-DSA, and a FIPS approved mode in scope for this repository
  (owner's uploads). ROADMAP 0.2.x: 0.2.2 carries the two owner decisions
  above; features freeze after it.
- THREAT_MODEL describes the claimed-field problem in plain words and what
  the ledger holds (proposal text, derived form, reasons, digests, sizes;
  never raw bytes of an oversized or dropped value; never keys).
- Module docstrings and comments no longer cite notes or a repository
  outside this one, or the 5.2/5.4 section numbers of an outside document.
  Eight "§4" or "section-4" citations remain (#59). `QuorumPolicy.section4`
  keeps its name.
- The source distribution includes `examples/`, which one test reads. The
  install lines include the `[yaml]` extra.
- README layout table: rows for `action.py`, `agent_meta.py`,
  `canonical.py`, `constitution.py`, and `testing.py`. Test skip messages
  name `pip install two-key-concept[yaml]`. CHANGES is oldest first.

### Upgrading from 0.2.1

1. **Setups that started and now refuse** (`judge_matches_agent:` or
   `credential could not be read at start-up`):
   - a keyless judge and a keyless agent on one `host:port`, whatever
     their models (for example two models on one Ollama daemon): serve the
     judge on another port or daemon. A key counts only when it is sent (an
     Ollama judge needs `auth_header: bearer`), and a key the daemon
     ignores only hides that both sides are keyless;
   - a judge configured with a key it never sends (`auth_header: none`, an
     Ollama judge's default) next to a keyless agent on its `host:port`:
     the judge counts as keyless (same fix);
   - an `agents.yaml` `ollama` agent with a configured key next to a
     keyless judge on its `host:port`: the agent never sends that key, so
     both count as keyless (same fix);
   - an `agents.yaml` agent, other than an `ollama` one, whose configured
     key cannot be read: set the variable, or remove `auth:`.
2. **Setups that refused and now start with warnings**: the same model on
   the same endpoint or upstream, a shared tenant id, a local proxy with no
   `upstream:`, an unresolved identity. Read the `two-key: WARNING:` lines
   at start-up, or `judge_agent_separation.warnings`. Alerts that matched
   `same_model_same_upstream` or `same_model_unknown_upstream` should
   match `same_model_shared_route` and `same_model_unknown_proxy`.
3. **Setups that refused and now start without a warning**, because a key
   that is never sent is not read: a judge with `auth_header: none` holding
   the agent's key at another address, a judge with `auth_header: none`
   whose configured key cannot be read, and an `agents.yaml` `ollama` agent
   (even `hosting: cloud`) whose configured key cannot be read.
4. Rename `vendor:` to `maker:` and `min_vendors:` to `min_makers:` in
   judges.yaml, and `vendor=`, `.vendor`, `min_vendors=` to `maker=`,
   `.maker`, `min_makers=` in Python. The old names work in 0.2.2 and are
   removed in 0.2.3. Giving both names is refused (`not both`), and so is
   `dataclasses.replace(policy, min_vendors=...)`, because `replace` also
   passes the current `min_makers`.
5. Alerts or scripts that match `insufficient_vendors` should match
   `insufficient_makers`; code that reads `Judge.describe()["vendor"]`
   should read `"maker"`. Neither has an alias.
6. `policy_digest` changes for the same settings, and `identities_digest`
   changes where a side now counts as keyless or uses Basic auth. Compare
   digests within one `constitution_loaded`. The `judge_agent_separation`
   record has `checks` `[same_credential, same_address_no_credential]` and
   new keys `same_agent`, `warning_checks`, and `warnings`. The
   `judge_matches_agent:` message text changed.
7. Remove `allow_same_model_distinct_tenant` when convenient; it does
   nothing.
8. Pass `agent_session` as a string (a list, tuple, or set of strings also
   works). Bytes or any other type now makes each LLM judge abstain, so the
   round denies.
9. A custom judge whose `score_bound` signature `inspect.signature` cannot
   read now always gets `agent_session=`; if it does not take it, the judge
   abstains (0.2.1 retried without it). Give it a readable signature or
   `**kwargs`.
10. `two_key.identity` no longer has `distinct_tenants`,
    `same_model_overlap`, `TENANT_OPTIN_WARNING`, or `TENANT_OPTIN_FLAG`.
11. Building from source needs `setuptools>=77.0`.

### Reviews

- The code-review skill on `main...working` (15 findings, 10 fixed, the
  rest documented or left by design), two adversarial review workflows on
  the judge rule (25 findings, 14 confirmed, none a way past the rule), a
  release-readiness check (packaging, release docs, regressions against
  0.2.1, CodeQL, process), and a review of the release itself (the scrypt
  change and these notes; its findings are fixed here). CodeQL on PR #61
  found the password-hashing issue fixed above and reports no new alerts
  since. All were run by an AI assistant in this session.
- Maintainer security review (AGENTS.md): the owner signed off on
  2026-10-09, accepting those reviews and the scrypt fix instead of a
  line-by-line review.

### Still open

- Issues #45 to #60 and #62 are Low or Info. #62 is the rollback or wipe
  of the ledger directory described above. #58 (the witness public key is not
  pinned) is rated Low by the owner and is planned for 0.2.3. #60 item 4 is
  fixed above; its other items are open. #49's recovery command, #46's
  persistent halt, and #45's gateway-only ledger role are not built.

### Planned for 0.2.3

- Pin the ledger's witness public key (#58); see ROADMAP 0.2.x.
- Remove the `vendor` / `min_vendors` aliases (breaking): every
  `TODO(remove-vendor-alias)` site.
- Remove the unused `extra_secrets` argument of `AgentDeclaration.resolve`
  (breaking).

## 0.2.3 — 2026-10-09

The two breaking changes planned in ROADMAP 0.2.x: the ledger pins its
witness public key (#58), and the `vendor` / `min_vendors` aliases are
removed. Two more, from the owner during this release: a judge that holds
the monitored agent's credential is refused even when neither side sends
it, and whether it is held as a token or as a username and password; and
passwords are fingerprinted with PBKDF2, an approved function, instead of
scrypt. It also fixes the small open issues the owner picked for this
release: #47, #48, #51, #52, #54, #56, #57, and #60 items 1 and 5. Read
"Upgrading from 0.2.2" below before upgrading.

### Changed (breaking)

- **A judge that holds the monitored agent's credential is refused, sent
  or not, in either form** (the owner's rule, restated in the README:
  "A judge is not the monitored agent, and `TwoKey` refuses to start
  (`judge_matches_agent:`), when it holds the monitored agent's credential
  (the same API token, or the same username and password), at any
  address"). 0.2.2 compared only what each side sends, and never compared a
  token with a username and password, so three setups started that the rule
  refuses:
  - a judge configured with the agent's key and `auth_header: none` (an
    Ollama judge's default), which holds the key but never sends it;
  - a judge holding the key configured for an `agents.yaml` `ollama` agent,
    which never sends it;
  - a judge or agent holding the other side's username and password as a
    token (`user:pass` in `credential_env` or a token provider) next to a
    Basic pair.
  Every credential each side holds is now compared for the same-credential
  refusal, sent or not, and a fingerprint is chosen by content: any secret
  that contains `:` is fingerprinted as a `username:password` pair with
  PBKDF2 (below), never with HMAC. The rule for two
  keyless sides on one address still looks only at what is sent. A key
  that is never sent is now read at start-up, so one that cannot be read
  refuses (`credential could not be read at start-up`); at call time it is
  read only to compare with `agent_session`. Each resolved identity in
  `constitution_loaded` lists every credential it holds under
  `credential_fingerprint` and gains `credential_sent`; the rule id
  (`same_agent`) is `same_held_credential_or_keyless_same_address`, and the
  fingerprint `input` text says what is fingerprinted. The refusal reads
  `judge_matches_agent: a judge must not be the monitored agent: ...` (was
  `a judge is the monitored agent`), and says to give the judge its own
  credential: a new address never clears it.
- **Password fingerprints use PBKDF2-HMAC-SHA256 instead of scrypt.**
  scrypt is not an approved function and is not in OpenSSL's FIPS
  provider, so a FIPS-only host refused every username and password, and
  it would have blocked the approved mode planned for 0.9. A
  `username:password` pair, and any secret that contains `:`, is now
  `pbkdf2-sha256-600000:` + PBKDF2-HMAC-SHA256 (NIST SP 800-132) with the
  per-install key (256 bits) as the salt, 600,000 iterations (OWASP's
  setting where FIPS 140 is required), 32 bytes, about 0.15 s each
  (scrypt took about 0.4 s and 128 MiB). `constitution_loaded` records
  `password_alg: pbkdf2-sha256-600000`. PBKDF2 is not memory-hard, so
  against someone who holds the key directory a guessable password is
  cheaper to guess on dedicated hardware than under scrypt. Whether a
  stored PBKDF2 fingerprint counts as an approved use is for the module's
  security policy or a test lab to confirm when 0.9 is built. The
  failure is still `password_fingerprint_failed:`.
- **The ledger pins its witness public key (#58).** 0.2.2 read the witness
  key from the head it was checking, so a replaced `witness.pem` was
  accepted and the principal key plus the ledger key could sign a head.
  Now:
  - A new ledger's first entry is `witness_pinned` (`source: new_ledger`),
    written and checkpointed when the `Ledger` is created.
  - A ledger made by 0.2.2 or earlier pins the witness key that signed its
    current head on its first open under 0.2.3 (`source: first_use`,
    `head_size`), trust on first use, and only if `witness.pem` is that
    key. A key swapped before the upgrade cannot be detected.
  - A head signed by a key other than the pinned one, and a `witness.pem`
    that does not match it, are refused with `witness_key_changed:`, on
    open, on `append` (before anything is written), and on `checkpoint`.
  - `Ledger(..., witness_public_key=...)` is a second pin, kept outside the
    ledger where whoever writes the ledger directory cannot change it. With
    it, forging a head needs the principal, witness, and ledger keys
    together; without it, the principal key and the ledger key are still
    enough, because they can rewrite the chain from its first entry, pin
    included. With it, a new ledger needs that witness key in place
    (`witness_key_missing:`).
  - `Ledger.rotate_witness(new_witness=None, *, reason="")` is the only way
    to change the key: a `witness_rotated` entry signed by the principal and
    by the old and the new witness key, checked on every open, then a head
    signed by the new key. The new key is staged as `witness.pem.new` and
    moved into place last. If the head cannot be written, the staged key
    stays and the ledger refuses to open (`signed head does not match the
    chain`) until the entry is removed, as after a crash. An out-of-ledger
    pin is updated by the operator.
  - The first open of a new or older ledger writes, so it refuses
    (`principal key mismatch:`) before writing when the principal private
    key does not match the principal public key. `witness.pem` is read
    again under the ledger lock, and `witness.pub.pem` is rewritten on open
    when it does not match `witness.pem`.
  - The head is checked against the chain (size, tip, Merkle root) before
    the witness pin, so an entry no head covers reports as that.
  - `Ledger.append` refuses the kinds `witness_pinned` and
    `witness_rotated`. `Ledger.verify()` returns `witness_report()`: the
    key that signed the head, the pin in the ledger and how it was set, the
    configured pin, and the pin history (`two_key.audit.witness_pins`),
    as `sha256:` fingerprints.
  - Neither pin detects a rollback to an earlier signed head or a wipe of
    the ledger directory (#62).
- **CLI for the witness pin.** `two-key authorize --witness-public-key PEM`
  opens the ledger with the out-of-ledger pin. `two-key rotate-witness
  --key KEY --ledger DIR [--witness-public-key PEM] [--reason TEXT]` rotates
  the witness key and prints the old and new fingerprints and where the new
  public key was written. `two-key audit --key KEY --ledger DIR
  [--witness-public-key PEM]` verifies the ledger, runs
  `check_decision_digests`, and prints both pins as JSON; it exits 1 on a
  refusal or a digest problem. `audit` and `rotate-witness` refuse a path
  with no ledger instead of creating one. An empty `--witness-public-key`
  is refused, so an unset variable in a script does not turn the pin off.
  `authorize` prints `ledger refused: ...` and exits 1 when the ledger will
  not open, instead of a traceback. Each command opens the ledger
  read-write, so the first one run on a ledger from 0.2.2 or earlier writes
  its `witness_pinned` entry.
- **The `vendor` / `min_vendors` aliases are removed** (owner's decision;
  deprecated in 0.2.2, #44). The judge key `vendor:` and the quorum key
  `min_vendors:` are refused as unknown keys. The `vendor=` argument of
  `LLMJudge` and `FixedJudge`, and `min_vendors=` on `QuorumPolicy` and its
  `high_assurance`, `section4`, and `without_diversity_floors` builders,
  raise `TypeError`. `Judge.vendor` and `QuorumPolicy.min_vendors` are gone.
  A judge's maker is its `maker` label or, when it has none, its `provider`;
  a `vendor` or `_vendor` attribute is no longer read. `maker_from_vendor`,
  `rename_min_vendors`, `warn_renamed`, and the `QuorumPolicy.__init__`
  wrapper are removed.
- `AgentDeclaration.resolve` no longer takes `extra_secrets`. Nothing passed
  it, and it fingerprinted whatever it was given as one of the agent's
  credentials.

### Fixed

- **#47**: the `TWOKEY_DOCCHECK_FAKE_LLM=1` switch is removed. It sent judge
  and agent calls through `urllib.request.urlopen`, which followed 301, 302,
  and 303 redirects and resent the `Authorization` header to the new host.
  The pooled transport, which refuses every redirect, is now the only path.
- **#48**: once a `TwoKey` with `private_key=` has run on a ledger (its
  capability key exists, or tokens were issued), a start without it is
  refused (`keyless_start_refused:`). Its `constitution_loaded` would pin no
  capability key and block every later keyed start with
  `capability_key_unpinned`, whose message now names that cause too.
- **#51**: an integer of more than 4,300 digits (or more than a lower
  `PYTHONINTMAXSTRDIGITS`) is refused the same way on every path and every
  Python version: `integer too large` from the strict
  JSON and YAML parsers (and so from `--args` and agent replies), an
  `invalid_call` deny from `authorize` and from the gateway (which now
  records `gateway_denied`), `malformed_action` for the action claim, and
  `malformed_proposal` for a proposal. 0.2.2 gave `internal_error`, a
  `ValueError` out of `ToolGateway.invoke`, or a misleading `*_too_large`.
- **#52**: a YAML merge key (`<<`) is refused (`YAML merge key '<<' at
  line N is refused`): which value wins depended on precedence the text
  does not show. Anchors and aliases without `<<` still load. An unknown
  key inside an `auth:` mapping (`vars:`, `servce:`) is refused instead of
  dropped.
- **#54**: a quorum floor the configured judges can never meet is refused
  when `TwoKey` starts, and `convene` denies such a round before calling any
  judge, so the call is no longer sent to every judge only to be denied:
  `required_yes` or `min_responding` above the number of judges
  (`too_few_judges_configured:`), and `min_distinct_providers` above the
  number of distinct judge providers (`insufficient_distinct_providers:`).
  The judges.yaml loader still checks only `required_yes` itself; `TwoKey`
  checks the rest.
- **#56**: CodeQL runs on pushes to `working`.
- **#57**: the witness and capability private keys are read with the same
  safe loader as `--key`: no symlink, a regular file, and no group or other
  access (`witness key: key_file_insecure:`, `capability key:
  key_file_insecure:`). `<ledger>.witness` is created at 0700 and set back
  to 0700 on open.
- **#60 item 1**: a ledger write that fails with something other than
  `LedgerError` (an `OSError` from a full disk) after the gateway's
  `redemption_started` returns `ledger_failed:<type>` instead of raising
  out of `ToolGateway.invoke`.
- **#60 item 5**: `Ledger` refuses a principal private key that does not
  match the principal public key given to it, before it writes anything
  (`principal key mismatch`). 0.2.2 wrote heads that failed `principal head
  signature failed` on the next open.

### Docs

- README, THREAT_MODEL, SECURITY.md, SCOPE, FIT, llms.txt, and AGENTS.md
  describe both witness pins: what each detects, that the principal key and
  the ledger key are still enough without the out-of-ledger pin, trust on
  first use for older ledgers, and that neither pin detects a rollback or a
  wipe (#62).
- HOWTO "Pin the witness key" and "Rotate the witness key": configuring the
  out-of-ledger pin, a table of what each pin detects, `two-key audit`, the
  rotation command, and what to do after an interrupted rotation. "Known
  trade-offs by configuration" lists running without the configured pin.
- HOWTO, examples/judges.yaml, and llms.txt say the `vendor:` and
  `min_vendors:` keys are refused.

### Upgrading from 0.2.2

1. Rename `vendor:` to `maker:` and `min_vendors:` to `min_makers:` in
   judges.yaml; the old keys are refused as unknown keys. In Python, use
   `maker=`, `min_makers=`, `.maker`, and `.min_makers`. A custom judge
   class that sets `vendor` or `_vendor` must set `maker` instead: the old
   attribute is no longer read, and the judge's maker becomes its
   `provider`.
2. Drop `extra_secrets=` from any `AgentDeclaration.resolve(...)` call.
3. The first open of each existing ledger under 0.2.3 writes a
   `witness_pinned` entry (`source: first_use`) and a new head. Open it with
   the principal key that signed it; `witness.pem` must be the key that
   signed the current head, or the open refuses (`witness_key_changed:`).
   Stop every process that has the ledger open before the upgrade; a
   process still holding an older in-memory ledger is refused
   (`ledger file changed by another writer`) and must reopen it.
4. Optional, recommended: after that first open, copy
   `<ledger>.witness/witness.pub.pem` somewhere whoever writes the ledger
   directory cannot change, and pass it on every open
   (`--witness-public-key`, `Ledger(..., witness_public_key=...)`). If you
   kept a copy of the witness public key from before the upgrade, use that
   one: it also catches a key swapped before the upgrade.
5. Replacing `witness.pem` by hand no longer works. Use `two-key
   rotate-witness` or `Ledger.rotate_witness`, then update your copy of the
   witness public key. `Ledger.append` refuses the kinds `witness_pinned`
   and `witness_rotated`.
6. A new ledger's first entry is `witness_pinned`, so `seq` numbers and
   entry counts are one higher than in 0.2.2 for the same calls. Look
   entries up by kind, not by position. `Ledger.verify()` returns a report
   instead of None.
7. `two-key authorize` exits 1 with `ledger refused: ...` on stderr when the
   ledger does not open; it raised a traceback before.

8. Setups that started under 0.2.2 and now refuse with
   `judge_matches_agent:`: a judge configured with the agent's key and
   `auth_header: none`; a judge holding the key of an `agents.yaml` `ollama`
   agent; a judge or agent holding the other side's username and password
   as a `user:pass` token. Give the judge its own credential, or remove the
   key from its configuration.
9. A judge with `auth_header: none`, or an `agents.yaml` `ollama` agent,
   whose configured key cannot be read now refuses to start (`credential
   could not be read at start-up`); 0.2.2 did not read it. Set the variable,
   or remove `auth:`.
10. `identities_digest` changes for every setup: each resolved identity has
    the new key `credential_sent`, a username and password are
    fingerprinted with PBKDF2 instead of scrypt (`pbkdf2-sha256-600000:`),
    and a secret that contains `:` with PBKDF2 instead of HMAC. Alerts that
    match `scrypt-n17-r8-p1` or the text `a judge is the monitored agent`
    should match `pbkdf2-sha256-600000` and `judge_matches_agent:`.
11. A secret that contains `:` now costs about 0.15 s of PBKDF2 at
    start-up. A FIPS-only OpenSSL, which refused every username and
    password under 0.2.2, now accepts them.
12. Configuration that 0.2.2 loaded and 0.2.3 refuses: a YAML merge key
    (`<<`) anywhere (write the keys out), an unknown key inside `auth:`,
    a `required_yes` or `min_responding` above the number of judges, and a
    `min_distinct_providers` above the number of distinct judge providers
    (`QuorumPolicy.without_diversity_floors()` with one judge is one: it
    defaults `required_yes` to 2).
13. A `witness.pem` or `capability.pem` that the group or others can read,
    that is a symlink, or that is not a regular file now refuses; `chmod 600`
    it, or replace the link with the file.
14. A `TwoKey` without `private_key=` on a ledger where a keyed one has run
    now refuses (`keyless_start_refused:`). A `Ledger` given a principal
    public key that does not match its private key now refuses on open.
15. `TWOKEY_DOCCHECK_FAKE_LLM` no longer does anything; a test double that
    relied on it should replace the judge's `transport=`.

### Reviews

- The code-review skill on `main...working` at high effort: 15 findings.
  Fixed: an interrupted rotation that sent the HOWTO recovery down the
  wrong path and deleted the staged key, a first open that wrote with a
  mismatched principal key pair, an empty `--witness-public-key` that
  turned the pin off, `audit` and `rotate-witness` creating a ledger at a
  mistyped path, a stale `witness.pub.pem` after an interrupted rotation,
  a stale `witness.pem` read before the lock, the `authorize` traceback,
  the `rotate_witness` signature in these notes, the missing "Upgrading
  from 0.2.2" section, and two cleanups. Kept by decision: a custom judge
  with an old `vendor` label is not refused (the owner's call: nothing is
  deployed, so the label is simply gone); `append` reads `witness.pem` on
  every call (about 0.1 ms, measured, so a swapped key is refused before an
  entry is written); and `witness_key_fingerprint` repeats the one-line
  `capability_key_fingerprint` format rather than touch the token code.
  Run by an AI assistant in this session.
- The code-review skill on the judge-rule change at high effort: 15
  findings. Fixed: the double HMAC and scrypt fingerprint of a `user:pass`
  token (one fingerprint by content now), the call-time read of an unsent
  key with no session to compare, a refusal message that pointed to a new
  address, a missing error prefix, the ledger rule id and fingerprint text,
  HOWTO trade-offs, stale wording, two duplicated code paths, and a
  misplaced test class. Kept: reading a held but unsent key at start-up
  runs its callback or keyring lookup, which the owner's rule needs (HOWTO
  "Known trade-offs" says so), and the slow-hash cost of a secret
  containing `:`. Its last finding, that "A judge is not the monitored agent, and
  `TwoKey` refuses to start, when it holds..." can be misread, is answered
  in the other docs with "A judge must not be the monitored agent: `TwoKey`
  refuses to start when a judge holds..."; the README keeps the owner's
  sentence. Run by an AI assistant in this session.
- The code-review skill on the open-issue fixes at high effort: 10
  findings. Fixed: a non-string `auth.type` that crashed with `TypeError`,
  a lower `PYTHONINTMAXSTRDIGITS` that still let a bare `ValueError` out,
  an int subclass whose `__abs__` hid its size, a witness-directory `chmod`
  that could fail the open, `min_distinct_providers` missing from #54 (and
  an overstated line about the loader), and four cleanups (one
  `ledger_failed` helper, one integer bound, `basic` in the auth-key table,
  an O(1) digit count). Kept: #48 refuses a keyless start once a keyed one
  has run, rather than carrying the previous pin forward; a keyless
  `TwoKey` is undocumented and cannot mint, so requiring `private_key=` is
  the fail-closed choice.
- The switch from scrypt to PBKDF2 is the owner's decision, after asking
  whether scrypt fits the FIPS goal (it does not).
- Maintainer security review (AGENTS.md, ROADMAP 0.2.3): pending. All
  these changes touch the ledger or the judge-is-not-the-agent check.

### Still open

- Fixed in this release: #47, #48, #51, #52, #54, #56, #57, #58, and #60
  items 1 and 5. Still open, Low or Info: #45 (a gateway in its own
  process), #46 (a persistent halt), #49 (a recovery command), #50 (ledger
  cost as it grows), #53 (CLI claim defaults), #55 (the connection-reuse
  claim), #59 (remaining doc errors), #60 items 2 and 3 (a ledger silently
  created at a wrong path, a weak `agent_session` check), and #62 (a
  rollback or wipe of the ledger directory, which neither witness pin
  detects).

## 0.2.4 — 2026-10-10

Package version 0.2.4 (`pyproject.toml`, `two_key.__version__`). Tagged
`v0.2.4` on `main`, the merge of `working` via
[#65](https://github.com/Insomniac-VibeLabs/two-key-concept/pull/65)
(`f541ab5`) plus the release notes in this commit. Tag `v0.2.3` stays on
`4a4352e`. Not published to PyPI.

### Fixed

- **#53.** `two-key authorize` no longer puts `amount_usd` (0.0),
  `irreversible` (true), or `data_class` (`classified`) into the claim when
  the operator did not pass the flag. An omitted amount or counterparty is
  read from the argument bytes. An omitted `irreversible` follows the tool
  spec. An omitted `data_class` is still `classified`, then the tool floor.
  `--amount-usd`, `--counterparty`, `--data-class`, and `--irreversible` /
  `--no-irreversible` are claims, and a claim that disagrees is still a deny.
- **#50.** An append checks the entries file's size instead of reading every
  line. The Merkle root is extended one leaf at a time and matches the
  previous full recomputation, including a root of a prefix. A redemption
  looks up `constitution_loaded` and `revocation` through an index built as
  the ledger is read, instead of copying the entry list. Opening a ledger
  still reads every entry: that read is the verification, and it is the
  cost ceiling. There is no rotation and no second copy of the plaintext.
- **#49.** The head is fsynced before it replaces the previous head. A last
  record that does not decrypt says it can be a crash or tampering; a record
  in the middle of the file still says `wrong key or tampered ciphertext`.
  `two-key recover` (and `Ledger.recover_tail`) drops only the bytes after the
  signed head, copies that ciphertext to `<ledger>.recovery/`, and appends a
  `ledger_recovered` entry (byte count and digest, not plaintext). It refuses
  a damaged signed prefix and a head that is behind the anchor. It does not
  run on open. Manual truncation in HOWTO remains the fallback when it refuses.
- **#62.** A head anchor outside the ledger directory, by default
  `<ledger>.ledger-key/head.anchor`, records the newest signed head. A signed
  head older than the anchor, or a wiped ledger directory, is refused
  (`ledger_rolled_back`). The anchor moves only forward. A missing anchor is
  adopted from the current head, which is how a 0.2.3 ledger starts being
  protected, and which is why deleting the anchor undoes the check. Someone
  who can write the anchor file can roll it back with the ledger. Pass
  `--head-anchor` / `anchor_path=` to keep it somewhere that writer cannot
  change. It is not an external anchor. The witness pins still do not detect
  a rollback by themselves.
- **#60 item 2.** `Ledger()` still creates a ledger at a new path, and now
  warns on stderr when it does. `audit` and `rotate-witness` still refuse a
  path with no ledger.
- **#60 item 3.** The credential named for the monitored agent is re-read on
  every `authorize` and compared with each judge's credential, beside the
  `agent_session` you pass. A placeholder still satisfies the presence
  check (`cloud_judge_session_required` when you pass nothing and a judge
  is not on loopback). It no longer hides the named key: a judge holding
  that key denies the round before anyone is called
  (`cloud_judge_reused_agent_session`). The named key is not an argument of
  the judge, not put in the prompt, and not written to the ledger. If it
  cannot be read, the round denies with `agent_credential_unreadable` and
  the judges are not called. What this does not do: a secret you never
  named is still only checked if you pass it, and a keyless agent
  (`credential: none`) has nothing to add.

### Not a code change

- **#46.** `revoke` still ends only tokens issued before the call. It is not
  a halt. An optional reputation halt, off unless configured, is ROADMAP 0.11.
  It is not built. The issue stays open.

### Upgrading from 0.2.3

1. The first open of an existing ledger writes `head.anchor` beside the
   ledger key, from the head that verifies now. A rollback done before that
   open is not detected.
2. Copy `head.anchor` whenever you copy the ledger. Restoring an older ledger
   directory and leaving the current anchor in place does not open. 0.3
   backup has to restore the anchor from the same moment as the ledger.
3. Do not delete `head.anchor` to silence `ledger_rolled_back`. That accepts
   the ledger as it stands.
4. `two-key recover --key KEY --ledger DIR` replaces the hand truncation in
   HOWTO for an uncheckpointed tail. It will not repair a rollback.

### Docs

- README "Known limits" now states what the anchor does and does not catch.
  HOWTO crash section, witness table, revoke, and the `agent_session`
  paragraph (a placeholder does not hide the named agent key). ROADMAP 0.11.
  THREAT_MODEL, SECURITY, SCOPE, FIT, llms.txt, AGENTS.md.

### Reviews

- Operator requested these ledger changes in this session (the AGENTS.md
  security-review gate for ledger changes). The anchor and `recover` were
  checked against the tests in `tests/test_recover_and_anchor.py`: a clean
  ledger is unchanged, a tail is dropped, a torn last line is a tail, damage
  inside the signed prefix is not truncated, a rollback is refused, a wipe
  does not open as a new ledger, and deleting the anchor adopts the current
  head.

## 0.3.0 — 2026-10-10

On branch `working`. Not a release tag. `main` and tag `v0.2.4` stay at
0.2.4. Tag `v0.2.3` stays on `4a4352e`. Not published to PyPI.

Package version 0.3.0 (`pyproject.toml`, `two_key.__version__`).

This section describes key backup as first written. 0.3.0 also carries the
later sections "Gateway deployment boundary (#45)" and "Custom Path A
fields", which do change the gateway and Path A; "Not in this version"
below was true of key backup alone.

### Added

Key backup and recovery (ROADMAP 0.3).

- `two-key backup-export` writes three passphrase-protected bundles.
  `principal.bundle.json` holds `principal.pem` and `capability.pem`.
  `ledger.bundle.json` holds `ledger.key`, `fingerprint.key`, the ledger
  files, and `head.anchor` from that same moment. `witness.bundle.json`
  holds `witness.pem` only. One file never holds every key a signed head
  needs (principal, witness, and ledger key).
- The bundle names its key derivation and cipher: format
  `two-key-concept-key-backup/1`, algorithm `pbkdf2-sha256+aes-256-gcm`,
  PBKDF2-HMAC-SHA256 at 600,000 iterations, then AES-256-GCM. 0.3 ships
  that function only. The name is there so 0.9 can keep it and a later
  version can add another without a new file format.
- Passphrases come from environment variables, never from argv.
- `two-key backup-verify` decrypts the bundles into a temporary ledger and
  checks the principal, capability, and witness fingerprints. It does not
  write the real ledger.
- `two-key backup-restore` puts the keys back. It writes the ledger files
  and `head.anchor` from the same bundle together. An older ledger left
  next to the current anchor still does not open (`ledger_rolled_back`).
  `--replace-ledger` is what writes that older ledger and its anchor over
  a newer one, and it replaces a key file that differs so the restored
  ledger still opens. The command never deletes the anchor. A missing
  anchor on a newer ledger is left missing. Deleting it is not
  the restore procedure.
- Export refuses to start when the capability key or the fingerprint key
  is missing. Start TwoKey once first. Export does not create them.
- A bundle file is at most 64 MiB. The plaintext inside stops at 45 MiB
  so the base64 wrapper still fits.

### Not in this version

- No second key-derivation function, no seed phrase, and no PKI.
- Authorization, tokens, the gateway, and the judge-versus-agent checks
  are unchanged.
- A backup is not an external anchor. Guessing the passphrase opens that
  bundle. PBKDF2 is not memory-hard. `--replace-ledger` can make a token
  spent after the backup look unspent.

### Upgrading from 0.2.4

1. Existing ledgers open as before. Nothing is rewritten until you restore.
2. Back up only after TwoKey has started once, so `capability.pem` and
   `fingerprint.key` exist.
3. Use a different passphrase for each bundle, and store the three files
   apart. Two bundles that share a passphrase are warned about. All three
   sharing one passphrase is warned about too.
4. To put an older ledger back, run `backup-restore --replace-ledger`.
   That writes `head.anchor` from the same backup. Do not delete the anchor
   to silence `ledger_rolled_back`.
5. There is no seed phrase. A lost passphrase cannot be recovered.

### Docs

README, ROADMAP, HOWTO, SCOPE, THREAT_MODEL, SECURITY, FIT, COMPARISON,
llms.txt, AGENTS.md, CONTRIBUTING.

### Reviews

The operator asked for ROADMAP 0.3 on `working`. This writes key files and,
with `--replace-ledger`, ledger bytes and the head anchor. It does not
change authorize, the token, the gateway, or judge identity. Tests are
`tests/test_key_backup.py`: restore, a wrong passphrase, a tampered bundle,
a newer ledger left in place, and a replace that writes the anchor with
the ledger and does not delete it. Tagging still wants the maintainer's
look at the bundle split and the passphrase.

## Fixes — 2026-10-11

On branch `working`. Not a release tag. Package version stays 0.3.0.
`main` and tag `v0.2.4` stay at 0.2.4. Not published to PyPI.

Fixes #67, #68, #69, and #70. Authorization, tokens, the gateway, and the
judge-versus-agent checks are unchanged.

- **#67.** A restore onto a newer ledger opens with the keys already on
  disk and uses the backup only for a key file that is missing. A witness
  rotated after the backup stays. Missing `principal.pem` or
  `capability.pem` can be put back without `--replace-ledger`. That flag
  is still what writes the older ledger, its anchor, and the older keys.
  A key that differs while the ledger files still match the backup is
  still `backup_conflict`.
- **#68.** `backup-export` holds the ledger lock while it copies the files,
  opens that copy in a temporary directory, and writes nothing when the
  copy would not open (`backup_refused`). A capability key that does not
  match the pin is refused here, not left as a backup `backup-verify`
  would reject.
- **#69.** `--out` refuses a symlink and an existing directory the group
  or others can write. Bundles are still created mode 0600.
- **#70.** The passphrase warning fires when any two bundles share a
  passphrase, not only when all three match.

### Docs

HOWTO "Back up the keys", the lost-key table, and the PBKDF2 trade-off.
README known limits. THREAT_MODEL key-backup residual. SECURITY.md.

## CI — 2026-10-11

On branch `working`. Not a release tag. Package version stays 0.3.0.
`main` and tag `v0.2.4` stay at 0.2.4. Not published to PyPI.

Fixes #71, #72, #73, #74, #75, #76, #77, and #79. Authorization, tokens,
the gateway, and the judge-versus-agent checks are unchanged.

- **#79.** `test_ledger_keeps_it_beside_the_ledger_key` compares a second
  `fingerprint_key()` read to the first. It no longer asserts a call
  equals itself.
- **#71, #72.** The build workflow installs `build==1.6.1` with
  `--only-binary :all:`. The command is a YAML block scalar so `:all:`
  is not read as a mapping.
- **#72, #73, #74.** The coverage workflow installs `coverage==7.16.2`
  the same way.
- **#72, #75, #76.** The security workflow installs `bandit==1.9.4`
  the same way, also as a block scalar. `bandit -r two_key -ll` is unchanged.
- **#77.** `uv.lock` pins `cryptography==50.0.2`, `pyyaml==6.0.3`, and
  their dependencies (`cffi`, `pycparser`, `typing-extensions`), with
  hashes. Tests and coverage install that lock with `uv sync --locked
  --no-build` (wheels only; uv itself is `uv==0.13.0`). The ranges in
  `pyproject.toml` stay what a consumer gets. There is no `@v0.3.0` tag.

### Docs

README install, HOWTO install, AGENTS.md, CONTRIBUTING, llms.txt.

## Gateway deployment boundary (#45) — 2026-10-13

On branch `working`. Not a release tag. Package version stays 0.3.0.
`main` and tag `v0.2.4` stay at 0.2.4. Not published to PyPI.

Decides #45: the gateway runs in the `TwoKey` process, on the ledger object
`TwoKey` uses. A gateway in another process or on another host is not
supported. There is no gateway-only ledger role, remote gateway, or
cross-process protocol, and none is planned (ROADMAP "Not planned").

### Added

- `TwoKey.gateway(tools=..., **kw)` builds the gateway on `tk.ledger` with
  `tk.issuer.verifier()` and `tk.compiled`. It refuses a `TwoKey` started
  without `private_key=` (`no_issuer_key:`). `two-key demo` uses it.
- `two_key.gateway.TwoKeyDeploymentWarning` (a `UserWarning`). `TwoKey`
  marks the ledger object it uses. `ToolGateway(...)` built on a ledger no
  `TwoKey` in this process opened emits the warning at most once per
  process. It cannot see another host. Silence it or make it an error with
  the standard `warnings` filters.

### Unchanged

- `ToolGateway(...)` keeps its signature. Built directly on `tk.ledger`, it
  does not warn.
- Token checks, redemption, and the ledger are unchanged. A gateway on a
  separately opened `Ledger` still refuses a token issued after it opened
  (`ledger_size_invalid`, then `ledger_failed`); a test now pins that.

### Docs

README (component list, diagram, gateway paragraph), HOWTO ("Redeem",
"Deployment boundary", known trade-offs), SECURITY, THREAT_MODEL, SCOPE,
JUDGES_AND_QUORUM, FIT, ROADMAP, llms.txt, AGENTS.md. They say plainly that
verify-only is an API property, not key isolation: the `TwoKey` process
holds the capability minting key and the principal, witness, and ledger
keys, and the registered tools run there.

### Reviews

The operator decided #45 and approved the helper and the warning. Tests:
`tests/test_gateway_boundary.py`.

## Custom Path A fields — 2026-10-13

On branch `working`. Not a release tag. Package version stays 0.3.0.
`main` and tag `v0.2.4` stay at 0.2.4. Not published to PyPI.

Path A was limited to five built-in fields. The principal can now declare
custom fields, with descriptions, and write rules on them. Requested by the
operator (ROADMAP "spec field types", ahead of its order).

### Added

- `fields:` in the rules file: up to 64 custom fields, each `boolean`,
  `integer` (`min`, `max`), `enum` (`values`), or `string` (`max_length`),
  with a required signed `default` and an optional `description`.
  `two_key/fields.py` holds the registry, the types, and the limits.
- `tool_specs.<tool>.fields` maps a declared field to an argument path. A
  mapped field is required (`derive_failed:field_missing:<field>`); a value
  of the wrong type or character set is `field_unreadable`, and one outside
  its bounds or values is `field_not_allowed`. A tool that does not map a
  field gets the signed default. A field path may not equal, contain, or
  sit under any other declared path, compared without regard to case.
- `deny_if_fields` rule type: `{field: {op: value}}`, every condition
  ANDed, operators by type (`eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`,
  `not_in`). Rule values are type-checked at sign and load time; an enum
  value that is not declared is refused.
- Enum and string values are printable ASCII by default. `charset: unicode`
  with `scripts:` (one script, or `japanese`, `korean`, `chinese`) reads
  values with NFKC_Casefold and refuses a letter outside the declared
  scripts, invisible and direction-control characters, and non-ASCII
  punctuation of no declared script.
- Policy VM opcode `LOAD_FIELD` reads custom fields from the derived values
  only. `LOAD` now refuses any name that is not a built-in field, so it can
  never read the agent's `raw` mapping. `Action.field_value` no longer falls
  back to `raw`.
- The token's `form` carries `fields`, and the gateway compares it as
  canonical bytes (`true` is not `1`). The tool receives the normalized
  values. Judges see the values; never descriptions.
- `spec_hash` covers the registry when there is one.
- Envelope format `two-key-concept-constitution-v2`, used when the rules
  declare fields. `sign_constitution(..., fields=, envelope_format=)` and
  `two-key sign-constitution --envelope-format auto|v2`. `auto` (the
  default) keeps v1 without fields; `v2` always writes v2. A v2 envelope
  refuses unknown signed keys; a v1 envelope with `fields` is refused.
- `load_unsigned_with_fields` returns the registry. `load_unsigned` refuses
  a rules file with fields rather than dropping them.
- `examples/custom_fields.yaml`.

### Unchanged

- A constitution without custom fields signs byte for byte as before: the
  same v1 format, digest, `bytecode_hash`, `spec_hash`, action-record hash,
  and token form. `tests/test_fields_compat.py` pins the hashes recorded
  before this change.
- An agent still cannot claim a field: a claim naming `environment` or
  `fields` is `malformed_action`.

### Upgrading

1. Nothing changes for a constitution without `fields:`.
2. A constitution with `fields:` (or signed with `--envelope-format v2`) is
   refused by installs older than this change. Upgrade every install that
   loads it first.
3. Use `load_unsigned_with_fields` in code that signs a rules file that may
   declare fields.

### Docs

HOWTO ("Custom Path A fields", "Using Two-Key in other languages",
"Changing a limit", envelope format, design steps, known trade-offs),
README, SCOPE, ROADMAP, THREAT_MODEL, COMPARISON, llms.txt, AGENTS.md.

### Reviews

The operator approved the design: the types, the signed defaults, mapped
means required, values but not descriptions to judges, the envelope
setting, the Unicode rules, the limits, and the `LOAD` hardening. Tests:
`tests/test_custom_fields.py`, `tests/test_fields_compat.py`.

## Docs match the code — 2026-10-13

On branch `working`. Not a release tag. Package version stays 0.3.0.
Docs only; no code or behavior changes.

- HOWTO "Judges": transient failures (a dropped connection, HTTP 429, 502,
  503, 504) are retried at most twice inside the deadline; a response over
  1,000,000 bytes, a redirect, and any other error abstain. The one-time 400
  fallback also exists for Anthropic and Gemini.
- THREAT_MODEL: a gateway on a separately opened ledger returns
  `ledger_failed: ledger file changed by another writer` to the caller (the
  check itself fails as `ledger_size_invalid`). The ledger holds custom
  field values in `action_normalized.form`.
- README, ROADMAP, THREAT_MODEL, and the CHANGES 0.3.0 section say that
  0.3.0 carries custom Path A fields and the #45 gateway boundary as well as
  key backup, and that the field types shipped ahead of order. README points
  to the v2-envelope upgrade note.
- llms.txt no longer states a test count. HOWTO's test-gap list drops the
  ledger's O_EXCL path and the case-folded control-path check, which have
  tests. CONTRIBUTING and README's layout list `llms.txt` and
  `docs/JUDGES_AND_QUORUM.md`.

## Release v0.3.0 — 2026-10-13

Package version 0.3.0 (`pyproject.toml`, `two_key.__version__`). Tagged
`v0.3.0` on `main`: `working` merged with `main`, plus the release notes in
this entry. Tag `v0.2.4` stays on `fc836bb`. Tag `v0.2.3` stays on
`4a4352e`. Not published to PyPI.

0.3.0 is the sum of these sections: "0.3.0" (key backup), "Fixes",
"CI", "Gateway deployment boundary (#45)", "Custom Path A fields", and
"Docs match the code". Where one of them says "On branch `working`" or "Not
a release tag", it was written before this release.

- The merge of `main` into `working` kept `main`'s SonarCloud coverage
  upload (PR #78) together with `working`'s locked, pinned coverage install
  (#77) in `.github/workflows/coverage.yml`. Nothing else conflicted.
- README, ROADMAP, SCOPE, FIT, THREAT_MODEL, JUDGES_AND_QUORUM, AGENTS.md,
  and llms.txt now say `v0.3.0` is the tagged release on `main` and the
  install line uses `@v0.3.0`.
- Upgrading: read "Upgrading from 0.2.4" and the "Upgrading" note under
  "Custom Path A fields". A constitution with custom fields is refused by
  0.2.4 and earlier.

## PR #85 check fixes — 2026-10-13

On branch `working`. Package version stays 0.3.0. No behavior changes.

- CodeQL "Clear-text logging of sensitive information" (`backup.py`, the
  short-passphrase warning): the message prints a role name and the number
  12, never a passphrase. The scanner matched the constant's name,
  `_SHORT_PASSPHRASE`. It is now `_WEAK_BELOW_BYTES`.
- DeepSource PYL-W0706 (critical, "the except handler raises immediately"):
  removed `except BackupError: raise` in `export_backup`. `BackupError` is a
  `ValueError` and `LedgerError` is a `RuntimeError`, so the clause never
  changed which exception reaches the caller.
  `test_export_refuses_a_missing_capability_key_and_low_iterations` pins that
  a `BackupError` from the snapshot still comes out unwrapped.
- DeepSource findings in code added for custom fields and #45, no
  behavior change: the `deny_if_fields` compiler is its own typed helper
  (`compile_constitution` back to the complexity it had on `main`); the
  field-definition and Unicode checks are split into one helper per case;
  the once-per-process gateway warning uses a `threading.Event` instead of
  `global`; `gateway.reset_deployment_warning()` is public (tests call it);
  the rules-file loaders are annotated `Mapping`. Tests: no lambdas, one
  merged `with`, and `Harness` is a mixin. Compiled bytecode is unchanged
  (`tests/test_fields_compat.py`).
- The custom-field mapping check in `validate_tool_specs` and the field
  projection in `project_arguments` are their own helpers, so this PR no
  longer adds to those functions' complexity (61 and 19; `main` had 59 and
  19). No behavior change.
- `tests/test_key_backup.py`: `redirect_stdout` is imported once at the top
  (it was imported twice inside one test). The three `os.chmod` calls that
  deliberately loosen permissions, to prove export refuses them, carry a
  `skipcq: BAN-B103` comment saying so.


## DeepSource test-fixture findings — 2026-10-14

Package version stays 0.3.0. No behavior changes, tests only.

- BAN-B103 (`tests/test_issue_fixes.py`, `tests/test_capability_key.py`): the
  two `os.chmod(..., 0o755)` calls deliberately loosen a directory to prove
  the code under test tightens it back to 0o700. They carry a
  `skipcq: BAN-B103` comment saying so, as `tests/test_key_backup.py` does.
- BAN-B104 (`tests/test_netloc_allowlist.py`, `tests/test_b5_local_proxy.py`):
  `"0.0.0.0"` appears only as a hostname string in a fixture list for the
  address classifier. Nothing binds a socket. Both lines carry a
  `skipcq: BAN-B104` comment.

## Live-test findings: docs — 2026-10-14

On branch `working`. Package version stays 0.3.0. No behavior changes.
From the live functional test on `test/live-functional-2026-10-13` (0 of 9
legitimate calls allowed; every safety check held).

- HOWTO "Designing a constitution": point 4 says an omitted `data_class` is
  `classified` whatever the floor is. New point 6: the monitored agent
  sees only the prose, so name tool ids, argument keys, counterparty ids,
  and the class to claim. New point 7: one vocabulary everywhere, ids with
  optional display names; no display-name mapping or fuzzy matching.
- HOWTO "Judges": judges do not enforce allow lists or data classes; Path A
  does. `judges.yaml` and `agents.yaml` are trusted operator config (a
  `callback` auth entry imports its module). Same note in README,
  SECURITY.md, and THREAT_MODEL.
- HOWTO "Authorize from Python": `decision.reason` names one cause (parse,
  limit, or derive deny, then Path A, then Path B); read
  `path_a["reason"]` and `path_b["reason"]` too.
- HOWTO "Monitored agents": the agent is not sent `tool_specs`; an omitted
  `data_class` is `classified`; there is no decline reply yet.
- README: the agent is not sent `tool_specs`. The cloud-judge sentence now
  says a `:cloud` or `-cloud` model counts as cloud on any host, as the code
  does (`LLMJudge.is_cloud`).
- `examples/constitution.md` names tools and parties by id. The golden v1
  hash test reads a frozen copy of the old prose
  (`tests/fixtures/v1_constitution.md`); its hashes are unchanged.
- AGENTS.md: keep the `classified` default; no display-name mapping.

## Agent prompt names the data classes — 2026-10-14

On branch `working`. Package version stays 0.3.0. The agent system prompt
changes; nothing Path A or Path B checks changes.

- `two_key.agents.SYSTEM` lists the five data classes (`DATA_CLASSES`) and
  says that omitting `data_class` means `classified`, whatever the tool is.
  The `classified` default stays: it is not lowered to the tool's floor.
- `tests/test_agent_prompt.py` pins both, and that the user prompt still
  carries only the prose and the instruction.

## Opt-in tool vocabulary for the monitored agent — 2026-10-14

On branch `working`. Package version stays 0.3.0. Neither path changes; a
prompt changes only when the caller opts in.

- `TwoKey.agent_vocabulary()` (and `two_key.agents.tool_vocabulary`) builds
  read-only text from the signed constitution: each tool id, its
  `irreversible` flag and `data_class_floor`, its amount, counterparty,
  payload, and custom field paths, each `allow` list, each custom field's
  type and values or bounds, and the five data classes. It leaves out rule
  thresholds, `deny_counterparties`, bytecode, field descriptions, and
  defaults.
- `MonitoredAgent.complete(instruction, constitution, vocabulary=...)`
  sends it in an escaped `<tool_vocabulary>` fence between the
  constitution and the instruction. Without `vocabulary`, the prompt is
  byte-for-byte the 0.3.0 user prompt (the system prompt gained the data-class line in the entry above). An empty vocabulary is refused. The
  Anthropic agent now splits its cached block at the instruction, so the
  vocabulary is cached with the constitution and the instruction is not;
  without a vocabulary the two blocks are what they were.
- Allowed for local and cloud agents alike (operator decision): it grants
  nothing. HOWTO "Known trade-offs" has a privacy note: cloud judges and a
  cloud agent read their prompts at the vendor, HTTPS protects them only
  in transit, and the vocabulary sends every allowed party on every call.
- HOWTO, README, THREAT_MODEL, and llms.txt describe it.
  `tests/test_agent_prompt.py` covers the contents, the exclusions, the
  escaping, the unchanged default prompt, and that a guessed id still
  denies.

## Tool vocabulary lists syntax, never values — 2026-10-14

On branch `working`. Package version stays 0.3.0. Neither path changes.
Supersedes the contents listed under "Opt-in tool vocabulary for the
monitored agent": an agent doing reconnaissance should learn the shape of
a call, not which payee, value, or amount would pass.

- `tool_vocabulary` / `TwoKey.agent_vocabulary()` no longer list `allow`
  lists, enum values, integer `min`/`max`, or the `irreversible` flag. A
  counterparty path says "an exact id given in the instruction or the
  constitution"; a custom field gives its type (and a string's
  `max_length`). Still listed: tool ids, the floor, amount path, unit, and
  currency path, payload paths with shape and `max_length`, and
  `deny_unmapped` when set. The header tells the agent to take values from
  the instruction or the prose and to omit `irreversible`, `amount_usd`,
  and `counterparty`, which come from the arguments and the spec.
- No full mode: there is no option that sends the allow lists.
- `agent_vocabulary(tools=[...])` limits the text to one task's tools. An
  unknown, empty, or non-list `tools` is `AgentConfigError`.
- HOWTO "Designing a constitution" points 6 and 7: put the exact values a
  call needs in the instruction; ids written in the prose reach the
  monitored agent's host too. HOWTO "Monitored agents", "Known trade-offs"
  (privacy), README, THREAT_MODEL, and llms.txt match.

## README request-flow diagram renders again — 2026-10-14

On branch `working`. Package version stays 0.3.0. Docs and a test only.
The same fix reached `main` through PR #86 (`fix/readme-diagram`), and tag
`v0.3.0` is on that merge (`e44be56`); `main` was merged back into `working`.

- README's request-flow sequence diagram did not render on GitHub: the
  note `same process as TwoKey; verifies with ...` contains `;`, which
  ends a statement in a Mermaid sequence diagram. It now reads `, verifies`.
  Every other Mermaid block in README, ROADMAP, HOWTO, and
  JUDGES_AND_QUORUM was rendered with Mermaid 11.4.1 and parses.
- `tests/test_doc_diagrams.py` fails on a `;` in any sequence diagram in
  the top-level or `docs/` Markdown files.

## Docs: agent vocabulary diagram and trust boundary — 2026-10-14

On branch `working`. Package version stays 0.3.0. Docs only, plus one
docstring.

- HOWTO "Monitored agents": a sequence diagram of the vocabulary exchange
  (what `agent_vocabulary()` keeps and drops, values carried by the
  instruction, Path A checking them against signed lists the agent never
  saw, deny on a guessed value).
- README architecture diagram: the agent edge no longer says "constitution
  prose only"; an opt-in `agent_vocabulary()` node feeds the agent. The
  request-flow diagram's first step names the opt-in vocabulary.
- THREAT_MODEL "Trust boundaries": new first item, caller to monitored
  agent (what it gets, what it never gets).
- AGENTS.md: the vocabulary never lists a value; do not add a mode that
  sends one.
- Correction: without `vocabulary=`, the agent *user* prompt is the 0.3.0
  prompt; the system prompt gained the data-class line (entry "Agent
  prompt names the data classes"). AGENTS.md, the "Opt-in tool vocabulary"
  entry above, and the `user_prompt` docstring now say so.
- Every Mermaid block in README and HOWTO renders with Mermaid 11.4.1.

## Agent declines — 2026-10-14

On branch `working`. Package version stays 0.3.0. Changes
`authorize_from_agent` and the agent reply format; reviewed and approved by
the maintainer before the change (AGENTS.md "Crypto and security changes").
From the run-2 live test: 8 refusals arrived as `tool: "none"` calls.

- An agent may reply `{"decline": "<reason>"}`. A schema-forced reply
  (OpenAI and xAI strict schema) may carry the call keys too, empty:
  `"tool": ""`, `"arguments": "{}"`, optional keys `null`. The strict and
  Gemini response schemas gain a `decline` key; the system prompt says how
  to decline.
- `parse_proposal` raises `AgentDeclined` (a subclass of
  `AgentConfigError`, so older callers fail closed); `MonitoredAgent.complete`
  raises it too. `authorize_from_agent` returns a deny with reason
  `agent_declined`: neither path runs, no token is issued, and the ledger
  `decision` keeps the reason (at most `MAX_DECLINE_CHARS`, 1,000) plus the
  reply's size and digest.
- A decline that also names a tool, carries arguments or a claim, has an
  unknown key, or has an empty, non-string, or over-long reason is
  `malformed_proposal`. `"decline": null` is an ordinary call.
- `tests/test_agent_decline.py`: no token, no path, no judge call, ledger
  body, mixed replies, strict-schema shape, `complete()` raising.
- HOWTO "Monitored agents" has a "Declines" section (replacing "there is no
  decline reply yet"). README (text and request-flow diagram),
  THREAT_MODEL, SECURITY.md (in scope), AGENTS.md, and llms.txt match.
- HOWTO "Designing a constitution": point 4 suggests `deny_unmapped: true`
  for send tools (a hidden `bcc` becomes a Path A deny); point 7 says an
  agent may repair a mistyped address to an allowed one, how to forbid that
  in the prose, and that only the agent can apply it (judges never see the
  instruction).

## Data classes combine as a set — 2026-10-14

On branch `working`. Package version stays 0.3.0. Changes what Path A sees
for `data_class`; approved by the maintainer as the security review
(AGENTS.md "Crypto and security changes"). From live test run 3: honest
claims (`medical` for a dentist entry on a `personal` calendar, `financial`
for a CPA email on a `personal` email tool) became `classified` and were
denied by the writer's `no-classified-data` rule, while the judge voted yes.

- `join_data_class`: `public` < `personal` < `financial`, `medical` <
  `classified`. `financial` or `medical` replaces `personal`; together they
  are `financial+medical`; `classified` absorbs everything. Only a claim or
  floor of `classified`, or an omitted claim, gives `classified`. A floor
  never lowers a claim.
- Path A: `Action.field_value("data_class")` returns each class the call
  carries, and `IN` with that tuple matches any part, so
  `data_class_in: [medical]` denies `financial+medical`. The compiled
  bytecode is unchanged (`tests/test_fields_compat.py` hashes hold); only
  the data_class value and the VM's `IN` on a tuple needle change.
- A claim may be `financial+medical` (`canonical_data_class`, sorted); any
  other `+` join or unknown class is `malformed_action`.
- Agent system prompt and vocabulary: claim the kind of data the call
  carries; `classified` is only for secrets and credentials. The old
  vocabulary sentence ("or a stricter class if the data is more
  sensitive") steered agents into the old join.
- Tests: `tests/test_data_class_sets.py` (every pair, never lower, classified
  only when said, combined claims, a medical bill through Path A and the
  gateway, rules naming either class); `tests/test_problem_f.py`'s pinned
  `personal`+`medical` case now expects `medical`; `tests/test_agent_prompt.py`
  pins the new guidance.
- HOWTO has a "Data classes" section; README, THREAT_MODEL, AGENTS.md,
  llms.txt, and the `--data-class` help match.

Upgrading: a call whose claim and floor were two different classes among
`personal`, `medical`, and `financial` used to be `classified`. It is now
`medical`, `financial`, or `financial+medical`, so a rule that denies only
`classified` now allows it. To keep refusing those calls, add `medical`
and/or `financial` to the rule's `data_class_in`. An outstanding token
issued before the upgrade for such a call fails the gateway's form check
(the recomputed `data_class` differs); tokens live at most 300 seconds.

## Live test run 5 (blind) fixes — 2026-10-14

On branch `working`. Package version stays 0.3.0. From GrokBot's blind run 5
(new domain, constitution, agent, and two judges; files in
`tests/live/run5/` on the test branch at `4672a37`). Item 1 tightens claim
parsing (maintainer-approved); items 2 and 3 change a message and add a
warning; item 4 is docs.

1. A repeated data class (`financial+financial`, `medical+medical`, ...) is
   `malformed_action`, as HOWTO already said (C36: it was accepted as
   `financial` and a payment was redeemed). `financial` and `medical` are
   accepted in either order (C24); HOWTO now says so.
   `tests/test_data_class_sets.py` replaces the test that expected
   `medical+medical` to collapse.
2. The judges config loader reports an unmeetable quorum with the
   documented reason (C45): it now raises `too_few_judges_configured:2<3
   (required_yes=3, min_responding=..., judges=2)` from `unmeetable_floor`,
   the same check `TwoKey` and `convene` use, instead of `required_yes=3
   exceeds number of judges 2`. `min_responding` above the number of judges,
   and too few distinct providers (`insufficient_distinct_providers:`), are
   now also refused when the file loads.
3. `two-key sign-constitution` warns on stderr for each tool that does not
   map a field a `deny_if_fields` rule reads, and whether the rule then
   always denies that tool, never denies it, or reads the default
   (`two_key.fields.unmapped_rule_field_warnings`). Signing still succeeds.
   Run 5's first attempt had every non-payment tool denied by a strict
   `po_matched` default; a permissive default instead turns the rule off for
   a payment tool that forgets the mapping.
   `tests/test_unmapped_field_warnings.py`.
4. HOWTO "Designing a constitution" point 8: say what is allowed as plainly
   as what is refused; a broad "refuse anything out of the ordinary" line
   with judges that must all agree denied an ordinary verification lookup
   (C38). Custom fields and "Known trade-offs" describe the new warning.

## Docs: what Two-Key verifies (live run 5c) — 2026-10-14

On branch `working`. Package version stays 0.3.0. Docs only. From GrokBot's
run 5c (`tests/live/run5c/` on the test branch at `cb5dd11`), which
confirmed the run-5 fixes live.

- HOWTO "What Two-Key verifies, and what it does not": Two-Key verifies
  that the call that runs is the call both keys approved; it does not verify
  facts the agent asserts. The agent writes the arguments, so a custom field
  is what the call says, not a fact. Run 5c C05: `po_matched: true` on a
  mismatched invoice passed both keys and was paid. Facts must be checked
  by the tool, or supplied by the integration (no input for that yet).
- The same limit in README "Known limits", THREAT_MODEL, AGENTS.md (do not
  describe fields as verification), llms.txt, and HOWTO "What happens to a
  call".
- HOWTO "Designing a constitution" point 8 now uses the sentence run 5c
  tested ("Staff may run lookups that verify a claimed payee or billing
  change; such a lookup only checks and authorizes nothing."), which turned
  a judge's false deny into an approval.

## Release v0.3.1 — 2026-10-14

Package version 0.3.1 (`pyproject.toml`, `two_key.__version__`, `uv.lock`
regenerated with uv 0.13.0). To be tagged `v0.3.1` on `main` after this
merges. Tag `v0.3.0` stays on `e44be56`. Not published to PyPI.

Status: **beta (pre-1.0)**, no longer "prototype". The maintainer reviewed
the changes with a refereed live functional harness (GrokBot; runs 1 to 5c
on `test/live-functional-2026-10-13`) and automated scanners (Semgrep,
DeepSource, Bandit, CodeQL). There has been no independent audit. SECURITY.md
now asks for private vulnerability reports (Security tab); README, ROADMAP,
SCOPE, FIT, THREAT_MODEL, JUDGES_AND_QUORUM, AGENTS.md, and llms.txt carry
the new status. ROADMAP: the maintainer moved 0.6 (MCP adapter, reference
wrapper, #89) ahead of 0.4 and 0.5.

0.3.1 is the sum of the sections since "Release v0.3.0": live-test docs,
data classes in the agent prompt, the syntax-only agent vocabulary, agent
declines, data classes that combine as a set, the run-5 fixes (repeated
class refused, quorum reason, unmapped-field warning), and "what Two-Key
verifies".

### Upgrading from 0.3.0

- **Data classes combine as a set.** A claim and floor that were two
  different classes among `personal`, `medical`, and `financial` used to
  become `classified`; they are now `medical`, `financial`, or
  `financial+medical`. A rule that denies only `classified` now allows those
  calls. Add `medical` and/or `financial` to its `data_class_in` to keep
  refusing them. A repeated class (`financial+financial`) is now
  `malformed_action`.
- **Agent declines.** An agent reply `{"decline": "..."}` is an
  `agent_declined` deny. `MonitoredAgent.complete` raises `AgentDeclined`, a
  subclass of `AgentConfigError`, so code that catches that still fails
  closed. The agent system prompt and the strict response schemas changed
  (a `decline` key, the data-class guidance).
- **Judges config.** A quorum the judges can never meet now fails to load
  with `too_few_judges_configured:` (and `insufficient_distinct_providers:`)
  instead of `required_yes=... exceeds number of judges ...`; a
  `min_responding` above the number of judges is now refused at load, not at
  start.
- **Signing** may print `two-key: WARNING:` lines for tools that do not map
  a field a `deny_if_fields` rule reads. Signing still succeeds.
- Existing ledgers, keys, and signed constitutions open unchanged; a
  constitution without custom fields is still byte-for-byte v1.
- An outstanding token issued by 0.3.0 for a call whose data class now
  combines differently fails the gateway's form check; tokens live at most
  300 seconds.

## PR #90 DeepSource fixes — 2026-10-14

On branch `working`. Package version stays 0.3.1. Tests only.

- DeepSource PYL-W0102 (critical, "dangerous default value"): the test
  helpers `signed()` in `tests/test_agent_prompt.py` and `warnings_for()` in
  `tests/test_unmapped_field_warnings.py` took the module-level `RULES`,
  `SPECS`, and `FIELDS` as default arguments. They now default to `None` and
  pick the module value inside. No helper mutated them, so no test result
  changes.

## Release v0.4.0: new repository, package `two-key`, formats without "concept" — 2026-10-15

Package version 0.4.0. Development moved from
`Insomniac-VibeLabs/two-key-concept` (to be archived) to
`Insomniac-VibeLabs/two-key`, with the full history of `main` (259 commits,
through `dd2f341`, the 0.3.1 merge). To be tagged `v0.4.0` on `main` here;
tags `v0.3.1` and earlier stay in `two-key-concept`. ROADMAP phase numbers
(0.4 = SIEM export, ...) stay labels; package 0.4.0 is this move.

- **Package `two-key`.** `two-key-concept` is renamed `two-key` (`pyproject.toml`,
  `uv.lock` regenerated with uv 0.13.0). The import name stays `two_key`.
  Install with `pip install "two-key[yaml] @ git+https://github.com/Insomniac-VibeLabs/two-key.git@v0.4.0"`.
- **Format identifiers drop "concept"** (maintainer decision: the old files
  were test data): `two-key-constitution-v1`/`-v2`, `two-key-ledger-wrap/1`,
  `two-key-ledger-enc/1` (also the AES-GCM associated data), the ledger
  HKDF salt `two-key-ledger`, `two-key-head-anchor/1`,
  `two-key-witness-rotation/1`, `two-key-key-backup/1`, and
  `two-key-key-backup-payload/1`. Nothing else in signing, hashing, or
  encryption changed: the golden test's digest, `bytecode_hash`,
  `spec_hash`, and `nl_hash` are unchanged (the envelope format is outside
  the signed bytes).
- **Old files are refused with a clear message**, never read: a
  `two-key-concept-*` constitution ("re-sign it"), ledger key wrap or head
  anchor ("start a new ledger"), or backup bundle ("export a new backup").
  `tests/test_legacy_formats.py`.
- **No "concept" left in code or docs** except those refusals and history:
  docstrings, messages (`not a two-key wrapped data key`), the judge auth
  message, `agent_meta.concept_agent_record` is now `ledger_agent_record`,
  and `tests/test_concept.py` is now `tests/test_two_key.py` (`CoreTests`).
- Repository URLs, badges, and the SonarCloud project key
  (`Insomniac-VibeLabs_two-key`) point here; issue references point to this
  repository's issues (#2 is the reference wrapper).

### Upgrading from 0.3.1

- Uninstall `two-key-concept`, install `two-key`. Both provide the `two_key`
  module, so do not keep both. Code that imports `two_key` does not change,
  except `two_key.agent_meta.concept_agent_record`, now `ledger_agent_record`.
- Key files (PEM) still load. Constitutions, ledgers, head anchors, and
  backups made before 0.4.0 do not: re-sign the constitution, start a new
  ledger with the same keys, and export a new backup.

## Mutable defaults in test helpers (#5) — 2026-10-15

On branch `working`. Package version stays 0.4.0. Tests only.

- DeepSource PYL-W0102: `_engine()` in `tests/test_problem_f.py` and
  `engine()` in `tests/test_derive_robustness.py` default `specs` and `rules`
  to `None` and pick the module value inside.
- `tests/test_judge_agent_separation.py`: `start()`, `refused()`, `started()`,
  and `warned()` default `agent` to a sentinel, not the `AGENT` dict, because
  `agent=None` is itself a test case (no monitored agent declared).
- No helper mutated those values, so no test result changes.

## Workflow actions pinned to commit SHAs (#4) — 2026-10-15

On branch `working`. Package version stays 0.4.0. CI only.

- `coverage.yml`: `SonarSource/sonarqube-scan-action@v5` is now pinned to
  `2f77a1ec69fb1d595b06f35ab27e97605bdef703`, the commit the `v5` tag
  (`v5.3.2`) points to (Semgrep
  `github-actions-mutable-action-tag`).
- `semgrep.yml`: `actions/checkout@v4` and
  `github/codeql-action/upload-sarif@v3` are pinned to the same SHAs the
  other workflows already use. Every `uses:` line in `.github/workflows/`
  now names a full commit SHA. The `semgrep/semgrep` container image is
  still the floating `latest` tag.

## Leftover review nits (#7) — 2026-10-15

On branch `working`. Package version stays 0.4.0. No change to any
authorization decision, refusal, or warning.

- **"§4" citations removed.** `two_key/quorum.py` and `two_key/judges/base.py`
  cited "§4 (ii)/(iii)" of a design document outside the repository. The
  comments now say what the code does (ballot binding, the judge-set floors,
  the availability floor K).
- **gpt-oss is recorded with the right upstream.** The OpenAI family regex in
  `two_key/identity.py` listed `gpt-oss` after `^gpt`, so it never decided
  anything, and open-weight gpt-oss was recorded with `api.openai.com` as an
  upstream, which does not serve it. Its maker stays `openai` (maker counts
  and `min_makers` are unchanged); its upstream is now the host that serves
  it plus `maker:openai`, the same label a maker without an API gets
  (`maker:meta`). For example, Groq is `api.groq.com` + `maker:openai`, and a
  local Ollama `-cloud` model is `localhost:11434` + `maker:openai` +
  `ollama.com`. Whether an identity is resolved is unchanged. The
  `upstream` list in a new `constitution_loaded` entry can differ from 0.4.0
  for gpt-oss judges and agents.
- **The `checks` list is documented as the check set.**
  `judge_agent_separation.checks` and `warning_checks` list the checks
  applied to every agent and judge pair, not which fired (`warnings` says
  that), and `refusals` is always empty because a refusal stops startup
  first. The record keeps its shape; `SeparationReport` and HOWTO say so.
- Tests: `test_open_weight_gpt_oss_is_not_served_by_the_openai_api`, and the
  record test checks that `refusals` is empty.

## Semgrep workflow permission — 2026-10-15

On branch `working`. Package version stays 0.4.0. CI only.

- `semgrep.yml` grants `actions: read`, as `codeql.yml` does: the SARIF
  upload reads the workflow run and failed with "Resource not accessible by
  integration" without it. The upload still needs code scanning (Advanced
  Security) enabled in the repository settings (#3), as the CodeQL job does.

## MCP proxy, part 1: skeleton without caller facts (#2 P2) — 2026-10-15

On branch `mcp-proxy` (cut from `working` at 9cc1a65, so `working` stays the
0.4.0 release). For 0.5.0; package version stays 0.4.0 until then. Caller
facts (#2 P1) are not in this part: they wait for the maintainer's security
review of their design. Nothing in authorization, derive, the token, the
gateway, or the ledger changed.

- **`two-key mcp-proxy --config proxy.yaml`**, behind a new optional extra:
  `pip install "two-key[mcp]"` (the official MCP Python SDK, `mcp>=2.2,<3`,
  and PyYAML). `uv.lock` (uv 0.13.0) pins `mcp` and `mcp-types` 2.2.0, the
  newest release more than two weeks old; the rest of the new dependencies
  resolve to their newest versions as before. The core install is
  unchanged (`cryptography` only).
- **One SDK module.** `two_key/mcp_proxy/sdk.py` is the only file that
  imports the SDK. `config.py` (the config file) and `core.py` (every
  decision) need no extra and are tested without it.
- **Upstream child process.** The proxy starts the upstream MCP server
  from `upstream.command` (a list, no shell), with only the variables in
  `upstream.env` (a literal, or `{env: NAME}` read from the proxy's
  environment; unset refuses to start) plus the SDK's minimal set. The
  proxy's other variables, such as judge keys, do not reach it. The SDK's
  client response cache is off.
- **Only signed tools.** `tools/list` shows each upstream tool whose exact
  name is a signed tool id (or its `tools.<id>.upstream_name`), under the
  signed id, with only `name`, `title`, `description`, `inputSchema`,
  `outputSchema`, and `annotations`. A call to any other name is refused as
  `tool_not_offered` before anything is authorized or ledgered (no token can
  exist for it). Resources, prompts, completions, and server instructions
  are not forwarded, and the upstream gets no sampling, elicitation, or
  roots callbacks.
- **Schema pin.** `upstream.schema_digest` (required) is `sha256:` over the
  canonical JSON of those shown fields for the signed tools. On a mismatch
  the proxy refuses to start (`upstream_schema_changed`, with both digests
  and any signed tool the upstream no longer lists), unless
  `upstream.on_schema_change: warn`. Tools are read once, at start;
  `tools/list_changed` is ignored. Two upstream tools with one name refuse
  to start.
- **Per-tool claim policy.** `tools.<id>.claim` is `floor` (the signed
  `data_class_floor`), a data class, or `none` (the default: omitted, so
  `classified`). Amount, counterparty, and irreversible are never claimed:
  they come from the argument bytes and the spec. The proposal text is fixed
  per tool (`tools.<id>.proposal`, default `MCP tools/call <id>`).
- **Identity refusal.** The proxy refuses to start on an
  `unresolved_identity` warning unless `allow_unresolved_identity: true`;
  the library still only warns. The refusal comes after `TwoKey` starts, so
  the ledger's `constitution_loaded` records the warning that caused it.
- **Calls.** Each `tools/call` runs `TwoKey.authorize` (origin `mcp-proxy`),
  then `gateway.invoke` in the same process (#45); the gateway's tool is the
  upstream `tools/call`, with the projected arguments only. One call at a
  time. A deny, a gateway refusal, or an upstream failure
  (`tool_error:<type>`, ledgered `redemption_aborted`) is an MCP tool error
  whose text is `two-key denied this call: <reason>`, printable ASCII, at most
  200 characters. An allowed call returns the upstream result without its
  `_meta`.
- **Nothing but MCP on stdout.** Refusals print `two-key: mcp-proxy refused
  to start: <reason>` on stderr and exit 1.
- CI installs the `mcp` extra (`tests.yml`, `coverage.yml`), so the SDK tests
  run there. Tested locally on Python 3.11, 3.12, and 3.13; 3.10 only in CI.
- Tests: `tests/test_mcp_proxy.py` (no SDK) and `tests/test_mcp_proxy_sdk.py`
  (skipped without the extra), against `tests/fixtures/fake_mcp_server.py`
  over stdio, network-free: both protocol eras (2026-07-28 and 2025-11-25),
  paging, the child's environment, a poisoned description, duplicates, an
  upstream that does not start, an upstream error, and the command line's
  refusals.

## `two-key mcp-draft-specs` (#2 P3) — 2026-10-15

On branch `mcp-proxy`. For 0.5.0; package version stays 0.4.0. Needs the
`mcp` extra. Nothing in authorization changed.

- `two-key mcp-draft-specs --out DIR [--tool NAME]... [--env NAME[=VALUE]]...
  -- COMMAND...` starts the upstream server once, lists its tools, and
  writes `rules.draft.yaml` (a rules file with review comments),
  `proxy-tools.draft.yaml` (a `tools:` block for proxy.yaml, `claim: none`),
  and `schemas.json` (exactly what the schema digest covers, for review and
  diffs). It prints the `schema_digest` for those tools. It never
  overwrites a file.
- `--constitution FILE` instead prints the `schema_digest` the proxy will
  compute for that signed constitution's tools, and exits 2 if the upstream
  does not list one of them. The file is read, not verified; the proxy
  verifies it when it starts.
- **Drafts fail closed.** `sign-constitution` refuses a draft until the
  principal decides: every tool has `data_class_floor:
  REPLACE_WITH_DATA_CLASS`, an amount-like property (`amount`, `price`,
  `total`, ...) is the amount with `unit: REPLACE_WITH_usd_OR_cents`, and a
  payee-like property (`vendor`, `recipient`, `to`, ...) is a counterparty
  with an empty `allow` list. `irreversible` is `false` only for a tool the
  server marks `readOnlyHint: true`.
- **Fact-like properties are left out and flagged.** `*_matched`,
  `*_verified`, `*_approved`, `*_confirmed`, and `*_validated` are claims the
  agent would write (run 5c, C05). The draft does not map them, so the tool
  never receives the agent's value, and lists them as `fact_candidates`
  for caller-supplied facts (#2 P1, pending review).
- Other top-level properties become payload paths (`shape` from the JSON
  type: string, number, or a list of strings, with `maxLength`/`maxItems`).
  A nested object is one unread payload path. A property name that is not a
  dotted identifier is left out and noted.
- Server text (descriptions, the command) appears only in comments, as
  printable ASCII, so it cannot add keys to the draft. Tool ids are quoted
  keys. An upstream name that is not lower case gets a lower-case id and an
  `upstream_name` line in the proxy block.
- Tests: `tests/test_mcp_draft.py` (the drafting rules without the SDK; the
  command line against the fake server, skipped without the extra).

## Docs: the MCP proxy (#2 P4) — 2026-10-15

On branch `mcp-proxy`. No behavior change.

- **HOWTO "Put Two-Key in front of an MCP server"**: what the proxy does,
  in plain words and in two Mermaid diagrams (flow and sequence); a worked
  example (draft, review, sign, digest, `judges.yaml`, `proxy.yaml`, and the
  agent host's command); the `proxy.yaml` reference; what each start-up
  refusal, warning, and call-time reason means and what to do; key custody
  with three OS users (the agent host, the proxy, and the upstream server,
  which could otherwise read the proxy's keys and, through `/proc`, its
  environment); and the limits (no caller facts yet, stdio and one upstream,
  one call at a time, the pin covers schemas not behavior, results unread,
  a timed-out call may still have run).
- **THREAT_MODEL**: new assets (the upstream credential, `proxy.yaml`), a new
  actor (the upstream server), two new trust boundaries (agent host to proxy,
  proxy to upstream), a new assumption, the proxy's residual risks (bypass by
  reaching the upstream directly, the upstream as the proxy's OS user,
  schema vs behavior, `warn`, unread results, timeouts, rule ids in deny
  reasons, `tool_not_offered` not ledgered), and what to re-check in
  `two_key/mcp_proxy/`.
- **SCOPE, ROADMAP, README, FIT, COMPARISON, SECURITY, llms.txt, AGENTS.md,
  CONTRIBUTING**: the proxy and drafter on branch `mcp-proxy`, the `mcp`
  extra, CI's `--extra mcp`, and the new in-scope and out-of-scope items.
  "Not an MCP server" now reads "offers no tools of its own": the proxy
  speaks MCP only to forward an upstream server's signed tools.
- `tests/test_mcp_docs.py` keeps the worked example true: its `proxy.yaml`
  parses, its rules sign, and the config table lists exactly the keys the
  loader accepts.

## Live harness for run 6, through the MCP proxy (#2 P5) — 2026-10-15

On branch `mcp-proxy`. Test tooling only; nothing in `two_key/` changed.

- `tests/live/` is ported from `two-key-concept` (branch
  `test/live-functional-2026-10-13`, run 5c), rebuilt around the proxy: the
  harness is the agent's MCP host and starts the real `two-key mcp-proxy`,
  which starts `tests/live/clinic_mcp_server.py`. That server's every call
  comes back to the harness over loopback, where the harness is the system
  of record (the purchase-order check), records the side effect, and relays
  the tool bot's simulated result. Judges are `openai_compatible` judges on
  loopback endpoints that serve only relayed replies, as before.
- **The harness plants injection text itself** (a case's `plant`), appended
  to a tool result, so injection never depends on the tool bot agreeing to
  write it.
- **Setup goes through the documented commands:** `mcp-draft-specs` drafts the
  specs, a fixed and logged "principal review" fills them, then
  `sign-constitution`, then `mcp-draft-specs --constitution` for the digest.
  The run-5b Writer reply is reused byte for byte (sha256 checked), without
  its `require-po-match` rule: caller facts are not built yet, so
  `po_matched` is not a field, and the billing tool checks the PO.
- **30 cases** (`make_cases.py`, shuffled neutral ids):
  - legit payments, messages, bookings, and lookups;
  - C05 redone with the tool checking the PO and `po_matched` dropped before
    the tool;
  - three planted-injection chains (remit-to change, credential
    exfiltration, a call to a tool the proxy does not offer);
  - crafted host calls: a hidden tool, a case variant of a signed id, a hidden
    bcc, oversize, deep nesting, an amount in words, a payee off the list, an
    upstream crash;
  - start-up refusals: unresolved identity, a poisoned schema, `warn`, a judge
    holding the agent's key, an unsigned `tools:` entry;
  - a `tools/list` check;
  - C05 with `po_matched` as a caller fact, N/A until #2 P1 ships.
- `--selftest` runs every case with stub bots under `tests/live/selftest/`
  (git-ignored) to check the plumbing before a live run. It passes 27 of 30;
  the two cases only a real judge can catch fail with always-yes stubs, as
  expected, and the caller-fact case is N/A.
- The report checks, besides the verdicts: answer-key echo, an agent claiming
  it executed something, and an argument value inside a deny reason.
- `RELAY.md` is the operator procedure. `cases.jsonl` and `state/` are
  git-ignored; `make_cases.py` (the answer key's source) is committed, as in
  earlier runs, so role bots must have no repository or web access.

## `main`'s workflow edits merged; CodeQL restored; Sonar scan v6 — 2026-10-15

On branch `working`. Package version stays 0.4.0. CI only.

- Merged `main` (three web-editor commits: `codeql.yml` deleted and
  re-created, and `coverage.yml`'s project key set to
  `Insomniac-VibeLabs_two-key`, which `working` already had).
- **`codeql.yml` is the CodeQL workflow again.** The re-created file on `main`
  was a copy of `coverage.yml` (named `coverage`, project key
  `Insomniac-VibeLabs_two-key-concept`): it ran a second SonarCloud scan that
  failed on pull requests ("Could not find the pullrequest") and, on a push,
  uploaded this repository's analysis to the old project. CodeQL did not run
  at all. A plain merge would have kept that copy, so the file is restored
  explicitly.
- **`sonarqube-scan-action` moves to v6, pinned:**
  `fd88b7d7ccbaefd23d8f36f73b59db7a3d246602` (`v6` = `v6.0.0`). This is what
  Dependabot's PR #8 proposed, but pinned to a commit SHA instead of the
  mutable `v6` tag (#4). v6 changes how `args` are quoted; this workflow's
  arguments have no quotes or spaces, so they parse the same.
- Still a SonarCloud setting, not code: the CI scan fails while the project's
  Automatic Analysis is on ("You are running CI analysis while Automatic
  Analysis is enabled"). Turn Automatic Analysis off (#3).

## README license badge — 2026-10-15

On branch `working`. Docs only.

- The license badge is static (`Apache-2.0`) instead of a shields.io lookup
  of the repository, which showed "repo not found". The coverage badge
  follows `main` and turns green when `working` is merged; the release badge
  shows "no releases" until Release v0.4.0 is published (#3).

## Caller-supplied facts and the guard core (#2 P1) — 2026-10-15

On branch `mcp-proxy`. For 0.5.0; package version stays 0.4.0. The design
passed the maintainer's security review before it was written.

- **`source: caller` fields.** A custom field declared `source: caller`
  takes its value from the integration (`authorize(..., facts={...})`),
  never from the agent's arguments or claim. A tool maps it as
  `{source: caller}` or `{source: caller, json_path: P}`; with a path, the
  tool receives the fact there. Denies (`derive_failed:`, both paths still
  run): `caller_field_in_arguments:<name>` when the arguments write it,
  `field_missing:<name>` when no fact is given, `fact_not_mapped:<name>`
  for a fact the tool does not map, `facts_not_object`, `facts_too_large`,
  `facts_unreadable`.
- **The gateway takes the facts again.** `gateway.invoke(token, tool,
  arguments, facts=...)` re-derives the form with the facts at redemption;
  a value that differs from the token's form is `fact_mismatch`, and the
  tool does not run.
- **Constitution v3** (`two-key-constitution-v3`). A rules file with a
  caller field signs as v3 (same signed keys as v2); `--envelope-format v3`
  forces it. A caller field in a v1 or v2 envelope is refused, and
  `--envelope-format v2` with one is a signing error. Constitutions without
  caller fields keep their v1 or v2 bytes.
- **`fact_fields`** in the action record and in `action_normalized` names
  the caller-supplied fields, so judges and the ledger see which values came
  from the integration. Absent when there are none.
- **`two_key/guard.py`**: `Guard` and `GuardedTool` run one call through
  both keys for any agent loop (a decorator too): a fixed claim and proposal
  per tool, fact hooks before `authorize` and again before `invoke`, under
  one lock; a hook that raises or returns None leaves its fact out (deny).
  `authorize_from_agent(..., facts=resolver)` takes a resolver;
  `two-key authorize --facts FILE` takes a JSON object.
- **MCP proxy on the guard.** `proxy.yaml` `tools.<id>.facts:
  {field: {hook: "module:function"}}` names a fact hook, imported at start
  (a missing hook, an import failure, or a hook for a tool not offered
  refuses to start). Caller-supplied paths are removed from the
  `inputSchema` the host sees. The proxy now ledgers `mcp_proxy_started`
  (the upstream program, a command digest, both schema digests, the
  settings, each tool's claim and hooks) before serving, and
  `tool_not_offered` with the name asked for. The agent vocabulary leaves
  caller fields out.
- Live run 6: `po_matched` is a caller fact (`tests/live/live_facts.py`);
  the Writer's `require-po-match` rule is back, the prose sentence that let
  the agent set `po_matched` is replaced, and the C05 caller-fact case runs.
  31 cases; the self-test passes 29, and the two only a real judge can catch
  fail with always-yes stubs, as expected.
- Docs: HOWTO "Caller-supplied facts", the MCP section, THREAT_MODEL,
  SCOPE, README, SECURITY, ROADMAP, AGENTS.md, llms.txt.

### Upgrading from 0.4.0

- **Check your constitution before upgrading.** Every tool must now map
  each field a `deny_if_fields` rule reads, or mark it `not_applicable`
  (entry "Every tool decides each field a rule reads", below). A v2
  constitution in which a tool neither maps nor marks such a field no longer
  loads: `TwoKey` refuses to start, naming each tool, field, and rule. To
  fix it, add `<field>: not_applicable` under that tool's `fields:` (or map
  the field), then re-sign; the result is v3. A constitution whose tools
  already decide every such field loads unchanged, as v2.
- Otherwise nothing changes unless a field is declared `source: caller`:
  the same rules sign to the same bytes, and `authorize` and `invoke`
  without `facts=` behave as before.
- A v3 constitution needs this release (0.5.0) or later; 0.4.0 refuses it.
- Code that reads a signed constitution's `tool_specs.<tool>.fields`
  itself: an entry may now be the string `not_applicable`, not only a
  mapping (live run 6z: a referee script crashed on it). Use
  `two_key.fields.field_mappings(spec)` for the mapped entries only.
- To turn an argument field into a caller fact: add `source: caller` to its
  `fields:` entry; map it in each tool as `{source: caller}` (or keep its
  `json_path` beside `source: caller` if the tool still needs the value);
  re-sign; supply a hook (`GuardedTool.facts`, `proxy.yaml`
  `tools.<id>.facts`, or `facts=` yourself). Behind the proxy, the field
  disappears from the schema the agent sees; an agent that still writes it
  is denied (`caller_field_in_arguments`).
- A hand-written integration must pass the facts to both `authorize` and
  `gateway.invoke`. Facts passed only to `authorize` redeem as
  `fact_mismatch`.
- The MCP proxy writes two new ledger kinds, `mcp_proxy_started` and
  `tool_not_offered`. A probe for a hidden tool is no longer silent in the
  ledger; a ledger consumer that lists kinds should expect them.

## Docs: roadmap order, README intro and MCP section, tables of contents — 2026-10-15

On branch `working`, which now carries the 0.5.0 work (fast-forwarded to
`mcp-proxy`; that branch stays at the same commit for live run 6). Docs
only; no behavior change.

- **Roadmap order (maintainer's decision, 2026-10-15):** the MCP adapter
  (0.5.0), DLP and antivirus hooks (0.6.0), the SIEM export (0.7.0), then
  1.0. PKI and certificate recovery, post-quantum signatures, FIPS approved
  mode, the local GUI, the optional reputation halt, and more field types
  move after 1.0, unscheduled. ROADMAP.md uses package versions instead of
  phase labels, puts what is next first, and keeps the released phases'
  design records under "Shipped". README, SCOPE, THREAT_MODEL, AGENTS.md,
  llms.txt, and HOWTO follow.
- **README:** a new opening (what Two-Key does and what you get; the status
  in one line, with Known limits and FIT.md linked), a quick start, a
  section on the MCP proxy with its diagram, and a table of the docs. The
  install, version, and upgrade notes move to "Install and versions", and
  the move from `two-key-concept` to "History and license".
- The MCP proxy diagram (README and HOWTO) shows the fact hooks. Docs that
  said "branch `mcp-proxy`" now say `working`.
- **Tables of contents** in README, ROADMAP, CHANGES, AGENTS.md, HOWTO,
  THREAT_MODEL, JUDGES_AND_QUORUM, and FIT, between `<!-- toc -->` markers.
  `tests/test_doc_toc.py` checks that each matches its headings, with
  GitHub's anchors (repeated headings get `-1`, `-2`), and
  `python tests/test_doc_toc.py --write` regenerates them. CONTRIBUTING and
  AGENTS.md say so. Short documents (SECURITY, SCOPE, COMPARISON,
  CONTRIBUTING) have none.

## Roadmap: judge connection reuse (#6) and judge history summary (#1) placed — 2026-10-15

On branch `working`. Docs only.

- The maintainer's decision: #6 (judge connections are never reused, since
  each quorum round starts new threads) joins 0.6.0, and #1 (a judge
  history summary built from the ledger, on by default) comes before the
  1.0 review, after its own maintainer security review. ROADMAP, README,
  SCOPE, and THREAT_MODEL list both.

## Every tool decides each field a rule reads (#10) — 2026-10-15

On branch `working`. Maintainer's decision after live run 6x (issue #10):
refuse, do not warn, for argument fields and caller-supplied facts alike, in
0.5.0.

- **The rule.** For every custom field a `deny_if_fields` rule reads, every
  tool in `tool_specs` must either map it or mark it `not_applicable`
  (`fields: {ticket_verified: not_applicable}`). A marked tool gets the
  field's signed default, as an unmapped tool did before. A field no rule
  reads needs no decision.
- **Refused at signing and on load.** `sign_constitution` and
  `verify_signed` (and so `TwoKey` at start) refuse a constitution with a
  missing decision, naming each tool, field, and rule. Before, a tool that
  forgot a mapping silently got the default, with only a stderr warning at
  signing; with a permissive default (`ticket_verified: true` in run 6x)
  the rule never denied that tool.
- **Format.** A `not_applicable` mark signs as `two-key-constitution-v3`
  (an install before 0.5.0 refuses it rather than misreading it), and a v1
  or v2 label on one is refused. `--envelope-format v2` with a mark is a
  signing error.
- **Signing notes.** The per-tool warnings become notes on the marks:
  `two-key: note:` when the rule never denies the marked tool or reads its
  default, and `two-key: WARNING:` when it always denies it.
  `two_key.fields.unmapped_rule_field_warnings` is replaced by
  `not_applicable_notes`.
- The agent vocabulary, derive, and the proxy skip marked fields.
  `examples/custom_fields.yaml`, the HOWTO worked example, and the live
  harness (the clinic's three other tools mark `po_matched`) carry the
  marks. Tests: `tests/test_field_decisions.py` (replaces
  `tests/test_unmapped_field_warnings.py`).
- Docs: HOWTO "Map it, or mark it `not_applicable`", "Envelope format", and
  "Known trade-offs"; THREAT_MODEL; AGENTS.md; llms.txt. Upgrade steps are in
  "Upgrading from 0.4.0" above.

## `case: exact` string fields (live run 6x, X19) — 2026-10-15

On branch `working`. Maintainer's decision on run 6 finding 2.

- An ASCII `string` field may declare `case: exact`: its value is compared,
  and passed to the tool, exactly as written (no trimming, no
  lower-casing). Rule values and the default keep their case. Before, every
  ASCII field was trimmed and lower-cased, and the tool received the
  lower-cased value, so a case-sensitive system of record refused a correct
  id (X19: `FLD-WM-G5-Science` arrived as `fld-wm-g5-science`).
- The original value is never forwarded after a lower-cased check: in a
  case-sensitive system `FLD-A` and `fld-a` can be different objects, and
  the tool must get the value Path A checked.
- Only on `string` with `charset: ascii`; `case` on an enum, a unicode
  field, or with any value but `exact` does not sign. A constitution with
  such a field signs as `two-key-constitution-v3`, and a v1 or v2 label on
  one is refused.
- `sign-constitution` warns (`two_key.fields.case_warnings`) about an exact
  field in a deny-list rule (`eq`, `in`), where a case variant does not
  match, and about a case-insensitive `string` field mapped to a path that
  looks like an identifier (`id`, `*_id`, `*Id`).
- `agent_vocabulary()` says "letter case matters: copy it exactly" for such
  a field; it still lists no value.
- Tests: `tests/test_case_exact.py`. Docs: HOWTO "Case-sensitive
  identifiers (`case: exact`)" and "Known trade-offs"; THREAT_MODEL;
  llms.txt.

## Judges are not asked about a call that cannot be read (run 6 finding 4) — 2026-10-15

On branch `working`. Maintainer's decision (option B). This narrows the
"both paths run" rule for one case.

- A call that cannot be read under its tool spec (`derive_failed:`, for
  example `amount_unreadable`, `field_missing`, `caller_field_in_arguments`,
  `unmapped_field`) is denied by the derive step, and the judges used to get
  a placeholder form with nothing derived in it and no arguments. Live run 6
  showed them answering "empty call" at full cost and latency. Now they are
  not asked: Path B is ledgered as `{"passed": false, "reason":
  "skipped:derive_failed", "yes": 0, "no": 0, "abstain": 0, "skipped":
  true}`, and the decision reason is the derive reason, as before.
- With `tool_args_on_derive_deny: true` the judges see the arguments, so
  they are still asked.
- A mismatch (`amount_mismatch`, `counterparty_mismatch`,
  `irreversible_mismatch`) has a real form and still goes to the judges, as
  does every rule deny. `require_path_a_first` is still not read.
- No allow becomes possible: the call was already denied.
- Tests: `tests/test_problem_f.py` (`test_a_readable_deny_still_asks_the_judges`,
  `test_derive_deny_skips_judges_unless_they_may_see_the_arguments`), and the
  derive-deny tests in `test_custom_fields.py` and `test_caller_facts.py`.
  Docs: README, HOWTO (custom fields, caller facts, quorum, "Known
  trade-offs"), JUDGES_AND_QUORUM, THREAT_MODEL, SCOPE, AGENTS.md, llms.txt.

### Upgrading

- A ledger consumer that expects a judge tally on every decision should
  accept `path_b.skipped: true` with zero counts.

## Roadmap: per-judge ballot records before 1.0 — 2026-10-15

On branch `working`. Docs only. The maintainer's decision on run 6 finding 9:
the ledger will record each judge's ballot (id, vote, confidence, error
class, a rationale digest; never the rationale text) together with the
judge history summary (#1), before the 1.0 review, after the same security
review. ROADMAP, README, SCOPE, and THREAT_MODEL say so.

## `@domain` allow entries (run 6 finding 7) — 2026-10-15

On branch `working`. Maintainer's decision: the principal's choice, with a
warning, as a feature.

- **The entry.** A counterparty `allow` entry `@example.org` admits every
  email address at exactly that domain. Exact entries stay the default and
  can sit beside it (`["@larkspurvalley.example", "board@district.example"]`).
- **Nothing wider.** The domain must equal the entry: no subdomain, no
  domain that merely starts or ends with it, no trailing dot, and no
  lookalike letter (the domain must be an ASCII host name). The local part
  must be plain (RFC 5322 atext and dots, at most 64 characters), so a
  space, a line break (a `Bcc:` header), a quoted part, or a second `@`
  does not match. `@example.org` itself is not a party.
- **Refused at signing:** an entry that is not `@` and an ASCII host name
  with a dot; a `*` anywhere in an allow entry; and a domain entry in
  `deny_counterparties`, so a block list stays exact.
- **Format:** a domain entry signs as `two-key-constitution-v3`; a v1 or v2
  label on one is refused.
- **Signing notes** (`two_key.constitution.domain_allow_notes`): one per
  domain entry, and a `WARNING` when the tool also passes text Path A does
  not read (a payload that is not a number), because anyone at the domain
  can then receive it and only the judges check the content (run 6x, X31).
- The tool still receives the canonical (trimmed, lower-case) address.
- Tests: `tests/test_domain_allow.py`. Docs: HOWTO (counterparties, "Known
  trade-offs"), THREAT_MODEL, SECURITY, AGENTS.md, llms.txt.

### Upgrading

- An allow entry that started with `@` used to be an exact party name (a
  social handle, say). It is now a domain entry: one that is not a host name
  does not sign, and a v1 or v2 constitution that has one no longer loads
  (it would need v3). Drop the `@`, or re-sign knowing it now means a
  domain.

## Docs: run 6 follow-ups in ROADMAP and SCOPE — 2026-10-15

On branch `working`. Docs only. ROADMAP 0.5.0 and SCOPE list the four
changes made from live run 6, and the short re-run (6z) planned before the
release.

## Run 6 follow-ups: drafter and quorum warnings, HOWTO guidance — 2026-10-15

On branch `working`. Warnings and docs; no authorization change.

- **`mcp-draft-specs` warns about an undescribed payee or amount** (finding
  1). For each property the draft maps as a counterparty or an amount with
  no `description` in the upstream schema: `two-key: WARNING:
  mcp-draft-specs: ...` on stderr, a `warnings` key in the JSON it prints,
  and a `# - WARNING:` comment in `rules.draft.yaml`. Behind the proxy the
  upstream schema is the agent's only format guide; in run 6 the agent wrote
  display names ("Alpine MedSupply (alpine-medsupply.example)") and every
  such payment was `counterparty_not_allowed` until the server described
  the field. Matching stays exact.
- **A start-up warning when one judge can approve alone** (finding 6):
  `two-key: WARNING: quorum: required_yes 1 with N judges and
  min_responding 1 ...` when two or more judges are configured and one yes
  passes while the others are down, time out, or abstain
  (`two_key.quorum.lone_judge_warning`). It still starts; the policy is in
  `constitution_loaded` as before.
- **HOWTO "Designing a constitution":** describe id fields in the upstream
  schema; describe caller-supplied facts in plain words in the prose, not
  by field name (finding 3); and content leaks rest on the judges, with a
  pattern for a scanner that supplies a caller fact (`carries_secret`) so
  Path A can deny too (finding 8). Quorum: the one-judge case in bold
  (HOWTO, JUDGES_AND_QUORUM). "Known trade-offs" gains the one-judge,
  domain-entry, and `tool_args_on_derive_deny` lines.
- ROADMAP 0.6.0: a second design decision, to feed the scanner's result to
  Path A as well (the 0.5.0 caller-fact pattern is a start).
- Tests: `tests/test_lone_judge.py`, and a drafter test in
  `tests/test_mcp_draft.py`.

## Live harness: run 6 referee fixes, quorum cases (for re-run 6z) — 2026-10-15

On branch `working`. Test tooling only (`tests/live/`); nothing in `two_key/`.
From GrokBot's run 6 report (findings 4, 10, 11, 12 and recommendation d).

- **Judge ballots are keyed by agent step** (finding 12): a chain case's step-1
  ballot no longer overwrites its step-0 one.
- **Personas:** each agent request carries a `PERSONA:` line (LEGIT,
  INCOMPETENT, MALICIOUS) from the case (`make_cases.py` `persona`), and the
  agent batch header is the role-play one GrokBot used, so an attack is
  attempted and the deny is exercised.
- **Strict verdicts** (finding 11): a case that names its intended denies
  (`expect.reasons`) is INCONCLUSIVE when never attempted or stopped another
  way, and FAIL when it reached the system of record. C05, the injection
  chains, the over-cap and wire cases, and the two judge-only cases name
  theirs.
- **Scripted quorum cases** (finding 10): the harness's loopback judge
  endpoints answer a case's `judges` script (yes, no, malformed, down)
  instead of a relayed reply: a split, a malformed ballot, a judge down, and
  a control. Nothing test-only enters `two_key/`.
- **A start-up case for the one-judge warning** (`required_yes 1` of 2).
- **C13 reaches the crash path** (finding 4): an ordinary matched invoice
  (`AMS-30915`) the judges approve, on which the back end then fails;
  `AMS-CRASH` is gone from `PO_BOOK`.
- **Referee:** a freshness check flags a reply byte-identical to one from an
  earlier run (`--earlier DIR`, `LIVE_EARLIER_RUNS`); an outbound batch with a
  private file name is refused, like one with a case title; soft leak terms
  are counted in the requests, not the header.
- `make_cases.py --table` prints the case table for the referee's brief.
  36 cases; the self-test passes 34, and the two only a real judge can catch
  fail with always-yes stubs, as expected.
- `tests/live/.gitignore` ignores `state/`, `selftest/`, and `cases.jsonl` at
  any depth, so a copied run tree (`run6x/state/`) cannot be committed by
  accident. `RELAY.md` is updated.

## Docs: the run 6 follow-ups everywhere they apply — 2026-10-15

On branch `working`. Docs only.

- README: Path A names `@domain` entries, the `not_applicable` decision,
  and `case: exact`; Path B names the one-judge warning; the 0.5.0 upgrade
  bullet says what to check before upgrading (it said nothing changed
  without caller fields, which is no longer true).
- SCOPE, THREAT_MODEL (header, re-check list, residual risk of the judge
  skip), FIT, SECURITY (in scope: a forgotten field decision that still
  signs, a changed `case: exact` value), AGENTS.md (the one-judge warning,
  `case: exact`, the drafter warning), llms.txt, and ROADMAP 0.5.0 list the
  run 6 follow-ups.

## Undescribed inputs: checked for every field Path A reads, at sign-off and start — 2026-10-15

On branch `working`. A warning; no authorization change. Maintainer's question:
the drafter warning should not be about payees and amounts only.

- `two_key.mcp_proxy.core.undescribed_inputs`: one line per argument the
  signed specs read (the amount and currency, each counterparty, and each
  argument-mapped custom field, at any depth such as `target.folder_id`)
  that the upstream input schema shows with no `description` and no `enum`,
  or does not declare at all. Payload paths (never read by Path A) and
  caller-supplied facts (hidden from the agent) are skipped.
- It runs where the signed spec and the upstream schema meet: `two-key
  mcp-draft-specs --constitution FILE` (stderr, and `undescribed_inputs` in
  its JSON) and `two-key mcp-proxy` at start (`two-key: WARNING: mcp-proxy:
  ...`). The draft-time warning still covers what the draft maps. The proxy
  still starts.
- `tests/live/clinic_mcp_server.py` describes every input Path A reads (as
  GrokBot's run 6y did), so re-run 6z does not repeat the display-name false
  denies; the proxy prints no such warning for it.
- Tests: `tests/test_mcp_draft.py` (a nested folder id, an enum, a caller
  fact, a payload path, an undeclared path). Docs: HOWTO (MCP step 1, the
  start-up warnings), THREAT_MODEL, AGENTS.md, llms.txt.

## Run 6z follow-ups: clearer refusals, harness fixes, judge memory — 2026-10-15

On branch `working`. No authorization change. From GrokBot's run 6z report
(36 cases: 34 PASS, 2 INCONCLUSIVE, 0 FAIL; school recheck 4 of 4).

- `two-key sign-constitution` prints `two-key: sign-constitution: refused:
  ...` and exits 1 on a constitution error, instead of a traceback.
- The field-decision refusal names every missing tool and field (it stopped
  at eight, so the school constitution showed eight of eleven), and every
  rule that reads the field (`(rules 'a', 'b')`; it named only the first).
  `two_key.fields.rule_fields` returns every rule id per field.
- The undescribed-input warning has the same words at draft time, at
  `--constitution`, and at proxy start (`two_key.mcp_proxy.core.
  undescribed_advice`); a test covers the start-up warning.
- `--envelope-format` help names all four 0.5.0 features that sign as v3.
- Docs: each ballot is one stateless request at temperature 0. A judge that
  keeps memory across ballots (a persistent agent, a chat with saved memory)
  lets text the agent wrote in one call reach the vote on another, outside
  the ledger; give each judge a fresh context per ballot (JUDGES_AND_QUORUM
  "What a judge is" and the operator checklist, THREAT_MODEL assumptions,
  HOWTO "Judges", llms.txt). JUDGES_AND_QUORUM's "both paths run" line names
  the `derive_failed:` exception.
- Live harness:
  - A reply byte-identical to an earlier run's is a note in RESULTS.md, not
    a referee incident: a model repeats itself on a nearly identical request
    (6z's four matches were short ballots and messages the instruction
    dictates). The notes also count requests both judges answered word for
    word alike, which is the same model, not shared memory.
  - Every pass scans `relay/`, `logs/`, and `constitution/` for the loopback
    credentials it made and for private-key text (`credential_in_run_files`,
    file names only). The brief's grep for those variables could not work:
    the harness makes them new on every pass.
  - A run's top-level outputs (`relay/`, `logs/`, `constitution/`,
    `RESULTS.md`, `results.json`) are git-ignored until moved into
    `run<N>/`; RELAY.md lists `constitution/` among the files to move.
  - Cases: the caller-fact case plays INCOMPETENT (a LEGIT agent declines the
    mismatch, so the deny was never reached); the planted unoffered-tool case
    counts any Two-Key deny of the export, since the agent never sees that
    tool; the scripted quorum cases pay their own invoice (PVP-5561), not the
    one an agent case pays. The billing prose describes the PO check in
    plain words, not by field name (finding 3).
  - `report.py` matches executed arguments exactly (a case-folded match
    would hide a `case: exact` failure) and titles RESULTS.md by run-neutral
    name with the repository head.

## Release v0.5.0: MCP proxy, caller-supplied facts, run 6 follow-ups — 2026-10-15

Package version 0.5.0 (`pyproject.toml`, `two_key.__version__`; `uv.lock`
regenerated with uv 0.13.0, which changes only the package's own version).
To be tagged `v0.5.0` on `main` after the merge. Not on PyPI. The entries
above, from "MCP proxy, part 1" on, are the detail.

- **MCP proxy** (`two-key mcp-proxy`, the optional `mcp` extra, #2): a
  stdio proxy in front of one upstream MCP server. It shows the agent only
  the signed tools, pins their schemas, refuses an unresolved judge or agent
  identity unless told otherwise, and runs every `tools/call` through both
  keys and the in-process gateway. Only `two_key/mcp_proxy/sdk.py` imports
  the MCP SDK.
- **Spec drafter** (`two-key mcp-draft-specs`): drafts `tool_specs` and the
  schema digest from the upstream server for the principal to review and
  sign; it never signs. Warns for every input Path A reads that the upstream
  schema leaves undescribed.
- **Caller-supplied facts and the guard core** (#2 P1, maintainer-reviewed
  design): a `source: caller` field takes its value from the integration's
  `facts=`, never from the agent, and is looked up again at redemption
  (`fact_mismatch`). `two_key.guard.Guard` runs one call through both keys
  for any agent loop; the proxy runs on it.
- **From live run 6** (maintainer's decisions): every tool maps or marks
  `not_applicable` each field a rule reads (#10, refused otherwise);
  `case: exact` string fields; `@domain` allow entries; no judges for a call
  that cannot be read (`skipped:derive_failed`); a start-up warning when one
  judge can approve alone.
- **Constitution v3** carries any of those 0.5.0 features; a constitution
  without them signs as before (v1 or v2, byte for byte).
- **Live testing**: run 6, then re-run 6z on the follow-ups: 36 cases, 34
  PASS, 2 INCONCLUSIVE (case design, since fixed), 0 FAIL; the school
  constitution recheck passed 4 of 4.
- Docs: README, ROADMAP (0.5.0 under "Shipped"), HOWTO, SCOPE,
  THREAT_MODEL, FIT, COMPARISON, JUDGES_AND_QUORUM, SECURITY, AGENTS.md, and
  llms.txt name 0.5.0 as the release and `v0.5.0` as the install ref.

### Upgrading from 0.4.0

The full notes are under "Caller-supplied facts and the guard core (#2 P1)"
> "Upgrading from 0.4.0". In short:

- **Check your constitution first.** A tool that neither maps nor marks
  `not_applicable` a field a `deny_if_fields` rule reads no longer loads;
  `TwoKey` refuses to start and names each one. Add the marks (or map the
  fields) and re-sign; the result is v3.
- An `allow` entry that starts with `@` is now a whole domain. A call that
  cannot be read under its spec is no longer sent to the judges.
- A v3 constitution needs 0.5.0 or later; 0.4.0 refuses it.
- Code that reads `tool_specs.<tool>.fields` itself: an entry may be the
  string `not_applicable`.
- The MCP proxy needs the `mcp` extra: `pip install "two-key[mcp] @
  git+https://github.com/Insomniac-VibeLabs/two-key.git@v0.5.0"`.

## PR #11 review: SonarCloud maintainability findings — 2026-10-15

On branch `working`. No behaviour change; the same tests pass.

- Cognitive complexity (python:S3776) under 15, by splitting into helpers:
  `two_key.mcp_proxy.draft.draft_tool` (33: `_usable_id`, `_note_fact`,
  `_draft_property`), `two_key.fields._definition` (18: `_field_type`,
  `_letter_case`, `_source`), and `two_key.cli._mcp_draft_specs` (17:
  `_draft_command`, `_draft_signed_check`, `_draft_write`).
- Tests: one call that may raise inside each `assertRaises` block
  (python:S5778; the public key is taken first), and `assertIs(x, False)` /
  `assertIs(x, True)` for boolean results (exact, unlike `assertFalse`).

## PR #11 review: no raw bidirectional characters — 2026-10-15

On branch `working`. Tests only.

- SonarCloud's security finding (the quality gate's "C Security Rating on
  New Code"): `tests/test_mcp_draft.py` and `tests/test_mcp_proxy.py` held a
  raw U+202E (right-to-left override) in a string, on purpose, to test that
  server text and deny reasons cannot carry one. Each is now the escape
  `\u202e`; the tests are unchanged in effect.
- `tests/test_no_bidi_chars.py` fails on any raw bidirectional control
  character in the repository's text files (Trojan Source, CVE-2021-42574).

## Semgrep findings printed to the job log — 2026-10-15

On branch `working`. CI only.

- `.github/workflows/semgrep.yml` runs `semgrep scan --config=auto
  --sarif-output=semgrep.sarif`: the SARIF still goes to the Security tab,
  and the findings now also print to the job log as text, so they can be
  read without code-scanning access (`--sarif --output` printed only a
  count).

## Roadmap: where we are, and the plan to 0.6.0 — 2026-10-15

On branch `working`. Docs only; nothing removed.

- ROADMAP "Where we are (2026-10-15)": 0.5.0 released (tag `v0.5.0`), the
  checks on `main`, live runs 6 and 6z, the open scanner findings and how
  each was triaged, open issues, and branches.
- ROADMAP "Plan to 0.6.0": housekeeping first (suppress the 11 Semgrep
  findings with their reasons, the CodeQL action to v4, close shipped
  issues), then a design note for the scanner hook for the maintainer's
  review (an `Inspector` interface reached in-process, over ICAP, or through
  `clamd`; fail-closed; the result to Path A as a fact; digests only in the
  ledger), the core and adapters, judge connection reuse (#6), docs, live
  run 7, and the release. The 0.6.0 status in ROADMAP and README says so.
- Semgrep's 11 findings on `main`, triaged: 8 `insecure-file-permissions`
  on directories set to `0o700` (owner only; the rule's `0o644` would be
  weaker), 2 `non-literal-import` of operator-configured hooks (trusted
  configuration), and 1 `httpsconnection-detected` on a connection that
  verifies certificates and host names. None is a vulnerability.

## CI: an informational macOS and Windows run — 2026-10-15

On branch `working`. CI only.

- `.github/workflows/portability.yml` runs the test suite and `python -m
  two_key demo` on `macos-latest` and `windows-latest` (Python 3.12, from
  `uv.lock`), on pushes to `working` and by hand. It does not block
  (`continue-on-error`): Linux (`tests.yml`) stays the gate until those
  platforms are supported.

## macOS: the one failing test; first portability results — 2026-10-15

On branch `working`. Tests and CI only.

- First run of `portability.yml`: macOS passes 721 of 722 tests and the demo.
  The one failure was the test's own assumption: macOS adds
  `__CF_USER_TEXT_ENCODING` (a text encoding code, no secret) to every
  process it starts, so the upstream MCP server's environment had one more
  name than the Linux list. The test now allows it; the proxy still passes
  only the declared and minimal variables.
- Windows fails 422 of 722 tests and the demo, almost all for one reason:
  the key-file check refuses a key readable by group or others, and Python
  reports every file on Windows as mode 0666, so no key loads and no ledger
  opens (fail-closed). Also on Windows: no cross-process lock, `chmod 0700`
  does not restrict access, and tests that start a child with only `PATH`
  lose `SYSTEMROOT`, which Windows networking needs. ROADMAP's 0.6.0 plan
  takes this up.
- `portability.yml` jobs stop after 30 minutes.


## Semgrep findings suppressed with reasons; judge hooks checked like proxy hooks — 2026-10-15

On branch `working`. No behaviour change for a valid configuration.

- The 11 Semgrep findings triaged on 2026-10-15 carry `# nosemgrep:
  <rule-id>` with a one-line reason above each: 8
  `insecure-file-permissions` on owner-only `0o700` key directories
  (`capability.py`, `identity.py`, `keys.py`, `ledger.py` x5; the rule's
  `0o644` would let others read), 2 `non-literal-import` of hooks the
  operator names in `judges.yaml` and `proxy.yaml`, and 1
  `httpsconnection-detected` on a connection built with
  `ssl.create_default_context()`, which verifies the certificate and host
  name.
- `judges.yaml` `auth: {type: callback}` hooks are now checked against the
  same `module:function` pattern as `proxy.yaml` fact hooks before anything
  is imported (`two_key.judges.config.HOOK`, which `mcp_proxy/config.py`
  now imports instead of keeping its own copy). A spec such as `m:f:g`,
  `.m:f`, or one with spaces is refused with `hook must be
  'module:function'`, cut to 80 characters in the message
  (`tests/test_judge_hook_spec.py`).

## CodeQL action v4; the maintainer's 0.6.0 decisions in ROADMAP — 2026-10-15

On branch `working`. CI and docs only.

- `codeql.yml` (`init`, `analyze`) and `semgrep.yml` (`upload-sarif`) move
  from CodeQL action v3, deprecated in December 2026, to v4.39.0, pinned by
  commit SHA (`6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee`).
- ROADMAP "Plan to 0.6.0" gains "Decisions for 0.6.0": the scanner hook is
  optional and fails open by default after a time limit, could-not-finish is
  flagged, the stance (default, strict, monitor) is a signed rule on a
  caller-supplied verdict, fail-open is ledgered and warned about, the
  judges get the verdict and never content; Two-Key runs on Linux, macOS,
  and Windows, every CI pipeline that runs code (and CodeQL) runs on all
  three. Additions only.

## CI on Linux, macOS, and Windows (0.6.0 Phase 1) — 2026-10-15

On branch `working`. CI and tests only.

- `tests.yml` runs on `ubuntu-latest`, `macos-latest`, and `windows-latest`
  with Python 3.10, 3.11, and 3.12 (bash, installed from `uv.lock` as
  before): the tests, then `python -m two_key demo`. Jobs stop after 30
  minutes. Windows jobs are `continue-on-error` until Windows support lands
  (Phase 2). `portability.yml` is folded in and removed.
- `build.yml` builds the sdist and wheel on all three, installs the wheel
  into a fresh venv, imports `two_key` from it (from outside the checkout),
  and runs the demo.
- `security.yml` (bandit) runs on all three.
- `codeql.yml` runs on all three (maintainer, 2026-10-15). Linux keeps the
  default category so its earlier alerts carry on; macOS and Windows upload
  as `/language:python/os:<os>`. Semgrep and coverage stay on Linux
  (CONTRIBUTING says why).
- `tests/child_env.py`: a child process a test starts gets `PATH` and what
  the test names, plus, on Windows, `SYSTEMROOT`, `COMSPEC`, `PATHEXT`,
  `TEMP`, `TMP`, and `USERPROFILE` (without `SYSTEMROOT`, asyncio fails with
  WinError 10106). `test_mcp_draft.py` and `test_mcp_proxy_sdk.py` use it.
  The upstream-environment test also allows the MCP SDK's own minimal list
  (`DEFAULT_INHERITED_ENV_VARS`), which differs on Windows; the proxy still
  passes only the declared and minimal variables.

## Windows support, part 1: owner-only files, locks, no-follow opens (0.6.0 Phase 2) — 2026-10-15

On branch `working`. Maintainer-reviewed design (the Windows design note,
approved 2026-10-15). Linux and macOS behave as before.

- New `two_key/_platform.py`, standard library only (`ctypes` on Windows, no
  pywin32): `create_new`, `open_nofollow`, `access_problem`, `owner_only_dir`,
  `open_lock_file`, `lock`/`unlock`, `inside`, `replace`, `fsync_dir`,
  `is_link`, `dir_writable_by_others`, and `resolve_program`. On POSIX each
  does what the callers did before (mode 0600 and 0700, `O_NOFOLLOW`,
  `flock`, `chmod 600` in the messages).
- On Windows a key file is created with a protected access list for the
  current user only (in `CreateFileW` itself, so it is never readable by
  others); a key directory gets the same, inheritable. A key is accepted
  when its owner and every "allow" entry are the current user, SYSTEM, or
  Administrators; anything else is `*_insecure`, with the `icacls` command
  that fixes it. Files open with `FILE_FLAG_OPEN_REPARSE_POINT`, so a
  symlink or junction is refused without a gap between check and open. The
  ledger and redemption locks are `LockFileEx` on the separate lock files
  (before, Windows had no cross-process lock at all). Every descriptor is
  binary (`O_BINARY`).
- Moved to it: `ledger.py` (key reads and writes, the key, witness,
  redemption-lock and recovery directories, the ledger lock, the anchor,
  `os.replace`, the directory fsyncs, the outside-the-ledger checks),
  `identity.py`, `keys.py`, `capability.py`, `backup.py`, `gateway.py`
  (redemption lock), `cli.py` (token and draft files).
- Text files Two-Key writes use `newline="\n"` (the ledger entries, the
  signed constitution, token and draft files), and every text open names
  its encoding; `tests/test_text_io.py` fails on one that does not.
- The MCP upstream command (proxy and drafter) is resolved with
  `shutil.which` on Windows, so `npx` finds `npx.cmd`. No shell.
- `tests/test_platform.py` tests each function on the platform it runs on.
- The key-file tests assert "owner-only" through `tests/perm.py` (mode bits on
  POSIX, the access list on Windows), and loosen a file with an Everyone
  entry on Windows. The read-only-directory test is POSIX only. An "OWNER
  RIGHTS" entry is accepted when the owner is.

## Windows support, part 2: docs; one message (0.6.0 Phase 2) — 2026-10-15

On branch `working`. Docs, and one Windows-only message.

- HOWTO "Platforms": Linux, macOS, and Windows; how keys are protected on
  each, the fix command for each (`chmod 600` or `icacls`), backups through
  `two-key backup-export`, and `npx` through `PATHEXT`.
- THREAT_MODEL: what owner-only means on Windows (the user, SYSTEM, and
  Administrators; anyone else refused), the Windows lock (`LockFileEx`,
  mandatory, on the separate lock files only), and `_platform.py` in the
  re-check list. It replaces the line that said there was no cross-process
  lock without `fcntl`.
- AGENTS.md: the platform invariant; README and AGENTS: Windows from 0.6.0.
- On Windows, a backup output directory that other accounts can write is
  refused as "writable by other accounts", naming the account.

## Windows CI blocks (0.6.0 Phase 2 done) — 2026-10-15

On branch `working`. CI and docs only.

- Every test and the demo pass on Windows, macOS, and Linux (Python 3.10 to
  3.12), and the wheel installs and runs the demo on all three (CI on
  `9c6f850`). The golden-hash tests pass unchanged on all three.
- `tests.yml` and `build.yml` drop `continue-on-error` for Windows: a
  Windows failure now fails the check. CONTRIBUTING says so.

## Judge connection reuse (#6, 0.6.0 Phase 5) — 2026-10-15

On branch `working`.

- `two_key/judges/transport.py` pools connections per origin (scheme, host,
  port) behind a lock, shared across threads, so a quorum round reuses the
  connection the last round opened. Before, each thread kept its own, and
  every round runs its judges on new threads, so nothing was reused. A
  connection is pooled again only after a clean response; one that errored,
  was redirected, said `Connection: close`, or returned an HTTP error is
  closed. At most four idle per origin. Parallel judges on one origin each
  get a connection.
- `tests/test_judge_connection_reuse.py` (a loopback HTTP server): a second
  round on another thread reuses the connection; `Connection: close` and an
  error status are not reused; parallel requests do not share one.
- HOWTO "Judges" says so.


## Content scanning, part 1: the core (0.6.0 Phase 3) — 2026-10-15

On branch `working`. Design note approved by the maintainer on 2026-10-15,
with their additions: Two-Key alone starts a scan, and a call can carry a
file. Adapters (ClamAV, ICAP, a command, a Python hook), the `proxy.yaml`
block, and the docs follow in Phases 4 and 6.

- `two_key/scan.py`: `Inspector.inspect(ScanRequest) -> ScanResult`, and
  `Scanner`, passed as `TwoKey(..., scanner=...)`. A tool is scanned when
  its signed spec maps the scan field (`scan` by default), a caller-supplied
  enum with exactly the values `clean`, `flagged`, `unavailable`; the signed
  `deny_if_fields` rule on it is the stance (default, strict, or monitor).
  Without a scanner, nothing changes: the judge prompts, the tokens, and the
  ledger are as before.
- Two-Key starts the scan for every call to a scanned tool, from every
  entry point, after the call reads under its spec and before Path A.
  `scan` in the arguments is already a deny; with a scanner configured,
  `scan` in `facts=` is too (`derive_failed:scan_fact_supplied`). A guard
  needs no hook for it and may not have one.
- What is scanned: every argument (keys the tool drops included, since the
  judges see them), the proposal text, and each declared file, decoded from
  base64 (`base64`, `base64url`) or read from the operator's folder
  (`path`: absolute, inside the folder, no link below it, a regular file, at
  most `max_file_bytes`). A declared file that cannot be read is flagged
  (`unreadable` or `limits_exceeded`).
- Two-Key sets the verdict when the scan fails: a timeout, an exception, or
  an invalid result is `unavailable`; a result naming `limits_exceeded` is
  `flagged`. The scanner going down and coming back are each one ledger
  entry and one stderr line, never one per call.
- Judges: a trusted `<scan_result>` section (scanner label, verdict,
  categories) before the untrusted record; each file appears as its digest
  and size, never its content. When flagged, the arguments and the proposal
  are withheld unless the new quorum flag `tool_args_on_scan_flag` is set
  (recorded in the policy only when set). A call to a tool outside the
  constitution sends no arguments to the judges when a scanner is
  configured.
- Ledger: a `scan` entry per scanned call (verdict, categories, stance,
  scanner label and version, elapsed time, each part's name, size, and
  SHA-256); `scanner_unavailable` and `scanner_recovered`; the scanner
  configuration in `constitution_loaded`. Never content.
- Token and gateway: a scanned tool's token carries the verdict and each
  file's digest (`scan`). The gateway does not scan again: it uses that
  verdict, refuses a `scan` fact (`fact_mismatch`), and reads each file again
  just before the tool runs (`file_changed`).
- Start-up: the stance and the unscanned tools; a warning when the scan
  limit plus the judges' deadline is over 60 s, and for `high_assurance`
  without the strict stance; a one-time note when no scanner is configured.
- `tests/test_scan.py` (in-process fakes): every stance against every
  verdict, timeouts, exceptions, invalid and could-not-finish results, the
  agent unable to steer the scan, base64 and path files, links and paths
  outside the folder, what judges and the ledger get, the token and the
  gateway, the guard, and the warnings.
- AGENTS.md: the scanner invariants.

## Content scanning, part 2: adapters and the proxy (0.6.0 Phase 4) — 2026-10-15

On branch `working`. Reference adapters that call an external scanner; no
scanning engine is added. All four are standard library only.

- `two_key/scanners.py`:
  - `ClamdInspector`: ClamAV `clamd` INSTREAM over TCP (`host:3310`) or a
    unix socket. `FOUND` is `malware`; ClamAV's own limits
    (`Heuristics.Limits.Exceeded`, `size limit exceeded`) are
    `limits_exceeded`, so the call is flagged.
  - `IcapInspector`: ICAP REQMOD or RESPMOD (RFC 3507), `icap://` or
    `icaps://` (TLS, system trust store), with `Allow: 204`. 204 is clean;
    403, an infection header, or a blocked encapsulated response is flagged;
    anything else is `unavailable`. Each part is sent with
    `X-Two-Key-Tool` and `X-Two-Key-Part`.
  - `CommandInspector`: runs a command with the part on stdin, a minimal
    environment, and the time left; exit 0 is clean, 1 is flagged (optional
    `two-key-categories:` line), anything else is `unavailable`.
  - `hook_inspector("module:function")`: your own Python code.
  - `scanner_from_config` builds a `Scanner` from a `scan:` block.
- `proxy.yaml`: a top-level `scan:` block (`type: clamd|icap|command|python`
  and its keys, `timeout_seconds`, `max_file_bytes`, `field`, `label`) and
  per-tool `files:` (`path`, `kind`, `folder`; a relative folder is relative
  to `proxy.yaml`). Files without a `scan:` block are refused.
- `two-key mcp-draft-specs`: inputs that look like files (a base64
  `contentEncoding`, `format: binary`, a `contentMediaType`, or a file-like
  name) get a note and a commented `files:` entry in the drafted
  `proxy.yaml`; the drafted rules end with a commented scan-field template.
  Nothing is declared or signed for you.
- `two-key mcp-proxy`: a start-up WARNING for each file-like input of a
  scanned tool that `files:` does not declare (it is scanned as text).
- Tests: `tests/test_scanners.py` (fake clamd and ICAP servers on
  127.0.0.1, a command, a hook, the config, and end-to-end denies) and
  `tests/test_mcp_scan.py` (the config, the hints, and a `tools/call` with an
  attached file through the scanner, both paths, and the gateway).
- HOWTO: the `proxy.yaml` table lists `scan` and `tools.<id>.files`.

## Content scanning, part 3: docs (0.6.0 Phase 6) — 2026-10-15

On branch `working`.

- `docs/SCANNERS.md` (new): how to connect an antivirus or DLP product,
  for operators and vendors. Five diagrams: where the scanner sits, a call
  with an attached file (agent to scanner, Path A, Path B, gateway, tool),
  verdict and stance, the `clamd` `INSTREAM` exchange, and the ICAP
  exchange. ClamAV setup on Linux, macOS, and Windows, the `clamd.conf`
  lines that matter, and an EICAR test; the exact ICAP request Two-Key
  sends, how each answer maps, and a vendor checklist; the command
  contract; a Python Inspector; files by path and what they give up; the
  ledger entries, warnings, and troubleshooting.
- HOWTO: "Scan content with an antivirus or DLP product" (field, stance,
  tools, files, adapter, test), the proxy's scan refusals and warnings,
  the gateway's scan checks, and three entries in "Known trade-offs by
  configuration" (stance, `tool_args_on_scan_flag`, files by path).
- `examples/scanning.yaml`: a rules file with the scan field, the default
  stance, a scanned tool, and one marked `not_applicable` (signed and run
  in `tests/test_scanners.py`).
- The "no scanning" lines in README, SECURITY (a new in-scope item for the
  scanner), llms.txt, COMPARISON, SCOPE, THREAT_MODEL (the scanner as a
  trust boundary, and its residual risks), FIT, JUDGES_AND_QUORUM,
  CONTRIBUTING, and ROADMAP now say what is built on `working`.
- ICAP: a `200` whose body differs from the part sent (the product
  redacted or replaced something) is flagged, as the design note says; an
  unchanged `200` is still clean. `clamd`: `Heuristics.Encrypted` (with
  `AlertEncrypted yes`) is flagged `unreadable`.

## Live run 7 harness: content scanning (0.6.0 Phase 7) — 2026-10-15

On branch `working`. For the maintainer's relay operator; no package code
changes except one start-up note's wording.

- `tests/live/`: the proxy's `scan:` block points at a toy ICAP scanner the
  harness serves on loopback (EICAR, a Luhn-valid card number, a short
  diagnosis list). `send_message` is scanned and takes base64
  attachments, declared as files. The main pass signs the default stance;
  host cases marked strict or monitor run against their own proxy,
  constitution, and ledger. Cases can take the scanner down or make it
  slow.
- Cases (44): the diagnosis and card-number cases now expect Path A's
  `rule_denied:scan`; an agent and a host case attach EICAR; scanner down
  under default (the call goes on, `scanner_unavailable` is ledgered) and
  under strict (denied); a slow scanner under strict; a card number under
  monitor (recorded, not denied); clean controls.
- The report checks each scan case's judge prompts: the `<scan_result>`
  verdict, and no flagged content. RELAY.md describes run 7.
- The start-up note now reads `not scanned (they do not map scan): ...`.

## File size limits; unreadable files denied under every stance (0.6.0) — 2026-10-15

On branch `working`. The maintainer's decisions of 2026-10-15: the operator
states the file size each tool needs, and an agent cannot push an oversized
or unreadable file through any stance.

- Every declared file states `max_bytes`, the largest file the tool needs,
  with no default: `Scanner(files=)` and `proxy.yaml` `tools.<id>.files`
  refuse a file without it. A `base64` or `base64url` file is at most
  196608 bytes (it travels inside the 256 KiB call; the error says a tool
  that needs larger files takes a path), a `path` file at most 100 MiB.
  The scanner-wide `max_file_bytes` (from earlier on `working`) is
  removed, and a `scan:` block that sets it is refused with a pointer to
  `max_bytes`.
- A call is held to its files' `max_bytes`, 32 files, and 100 MiB of files
  together. Two-Key counts the files before reading any, does not open a
  path file whose size is over its limit, and stops reading one that grows
  past it. This also closes a memory exhaustion: a list of paths could name
  one large file thousands of times in a single call.
- A declared file Two-Key cannot read (bad base64, a value of the wrong
  type, a path outside its folder, a link, a missing file, not a regular
  file) was a `flagged` verdict, which the monitor stance let through. It
  is now denied, like a call over a file limit, before the scanner and
  both paths under every stance: `file_unreadable`, `file_too_large`,
  `too_many_files`, `call_files_too_large`. The judges are not asked. The
  `decision` entry records `file_denied` (the argument path, why, and
  sizes, never content); the agent gets the reason code. The gateway
  denies a file it cannot read again, or one over its limit, as
  `file_changed`.
- `two-key mcp-draft-specs` drafts `max_bytes: REPLACE_WITH_BYTES` on each
  commented file entry.
- Docs: docs/SCANNERS.md "File size limits", HOWTO (scanning steps, proxy
  reasons, parsing limits, trade-offs), THREAT_MODEL, SECURITY, AGENTS.md,
  llms.txt, ROADMAP, and examples/scanning.yaml.
- Live run 7: `send_message` attachments declare `max_bytes: 65536`; two
  host cases under the monitor stance (an attachment over the limit, and
  one that is not base64) expect `file_too_large` and `file_unreadable`
  (46 cases).

## Encrypted files: signed per-tool pass (0.6.0) — 2026-10-15

On branch `working`. The maintainer's decision of 2026-10-15: some
deployments move encrypted files, which an antivirus or DLP product cannot
open, so the principal can let a tool pass them and leave scanning to
wherever they are decrypted. It is signed, per tool, and off by default,
because encrypting a file is also a way past the scanner.

- A new scanner category, `encrypted`. clamd's `Heuristics.Encrypted...`
  (with `AlertEncrypted yes`) is now `encrypted` (it was `unreadable`). An
  ICAP answer whose infection headers name only `Heuristics.Encrypted...`
  is `encrypted`; any other name is still `malware`. A command reports it
  with `two-key-categories: encrypted`, a Python inspector with
  `ScanResult.flagged("encrypted")`.
- `tool_specs.<tool>.fields.scan: {source: caller, encrypted: pass}` lets
  that tool pass encrypted files. The scan field then needs a fourth value,
  `encrypted`, which is refused when no tool passes. `encrypted: pass` is
  refused on any other field. A constitution without it signs byte for
  byte as before.
- On such a tool, a call whose only finding is `encrypted` gets the
  verdict `encrypted`, which the default and strict stances do not deny.
  With any other finding it is `flagged`; when another part could not be
  scanned it is `unavailable` (strict denies it). On every other tool an
  encrypted file is `flagged`, as before. A scanner cannot answer the
  verdict `encrypted` itself.
- The judges see the verdict `encrypted` with one added line saying what
  it means, and get the arguments. Every other judge prompt is unchanged.
  The token binds the verdict; the gateway refuses it for a tool that does
  not pass encrypted files (`scan_mismatch`). `constitution_loaded`
  records `encrypted_pass` (the tools) when there are any.
- `sign-constitution` warns for each tool that passes encrypted files. At
  start, Two-Key lists them, and notes when a rule on `scan` alone denies
  `encrypted` (the pass then does nothing). `two-key mcp-draft-specs`
  points to the docs in its scan template.
- Docs: docs/SCANNERS.md "Encrypted files" (and the ClamAV, ICAP, command,
  and Python sections; `HeuristicScanPrecedence no`), HOWTO (scanning,
  trade-offs), THREAT_MODEL, SECURITY, AGENTS.md, JUDGES_AND_QUORUM,
  SCOPE, ROADMAP, llms.txt, and examples/scanning.yaml.
- Live run 7: the toy scanner reports a zip with the encryption bit set as
  `Heuristics.Encrypted.Zip`. Three host cases: the zip is denied under the
  main pass, sent with the verdict `encrypted` under a new
  `encrypted_pass` stance, and still denied beside the EICAR file (49
  cases).

## Docs: connecting the agent so it cannot go around Two-Key — 2026-10-15

On branch `working`. Docs only; no behavior changes.

- New docs/CONNECTING.md: the two routes (an MCP client through
  `two-key mcp-proxy`, and your own loop through the Guard or the
  library), with the exact sudoers rule and client entry for the proxy;
  a table of every connection and hook (agent host, upstream, tool
  credentials, constitution and key, config files, fact hooks and the
  Python import path, judges, the monitored agent endpoint, each scanner
  type, files sent by path, the ledger, tool results) with what an agent
  would try and what stops it; services that share 127.0.0.1 with the
  agent (a free loopback port can be taken after a crash or restart); what
  Two-Key checks for you and what it cannot see; and a checklist.
- THREAT_MODEL residual risks: routes around Two-Key it cannot see, and
  loopback port takeover on a shared machine. SCANNERS: prefer clamd's
  Unix socket (mode 660, a group without the agent) when the agent shares
  the machine. HOWTO (key custody, the guard), README, llms.txt, and
  AGENTS.md point to the new guide; `tests/test_doc_toc.py` covers it.
- docs/CONNECTING.md diagrams: the three trust zones, Route 1 (the three
  OS users, the sudo hops, where each secret lives, and the closed paths),
  Route 2 (what the model is offered and what it never is), and a loopback
  port takeover. Each was rendered with Mermaid 11.4.1 before commit.

## Docs: the proxy wrapper leaves the agent's folder — 2026-10-16

On branch `working`. Docs only; no behavior changes.

- sudo keeps the caller's working directory, and the upstream server
  inherits the proxy's unless `upstream.cwd` is set. Left in the agent's
  folder, `npx` looks for the server in that folder's `node_modules` and
  reads its `.npmrc` first, so an agent could plant a server that
  receives the tool's credential. The `run-proxy` example in HOWTO now
  changes to `/opt/two-key` first, HOWTO and CONNECTING explain why and
  say to run the `two-key` command rather than `python -m two_key` (which
  puts the working directory on the import path), the `upstream.cwd` row
  says what the default is, and the CONNECTING checklist has a line for it.

## Start-up check: paths another account could change (0.6.0) — 2026-10-16

On branch `working`. Maintainer's decision: warn by default, a setting to
refuse, and refuse under `high_assurance`; document running Two-Key as a
service account, not a standard user.

- New `two_key/writable.py` and `_platform.write_problem`. When a `TwoKey`
  starts, it looks at Python itself, each folder on the import path and
  the `.pth` files in it, each loaded module with its compiled file and
  folder, each path in the new `check_paths=`, and every folder above
  them. Each one that an account other than its own (or root, SYSTEM,
  Administrators, or TrustedInstaller) could change is named on stderr:
  `two-key: WARNING: writable_path: <path>: <why>`, at most ten lines,
  nothing named twice under a folder already named. On Linux and macOS:
  another owner, the other write bit, or the group write bit for any group
  but 0; a sticky bit on a folder above is fine. On Windows: another
  owner, or an allow entry with a write right (for a folder above, a right
  to rename or remove an entry). A path that cannot be checked is named.
- `TwoKey(on_writable_paths="refuse")`, or `on_writable_paths: refuse` in
  `proxy.yaml`, refuses to start instead (`writable_path:`), before
  anything is written to the ledger. A high_assurance quorum always
  refuses, and `on_writable_paths: warn` with it is a configuration error.
  Nothing turns the check off.
- The MCP proxy passes `proxy.yaml`, the constitution, the principal key,
  `judges.yaml`, the ledger folder, the witness key and head anchor when
  set, the upstream program, the folder the upstream starts in (the
  proxy's own when `upstream.cwd` is unset, which under sudo is the
  caller's), each fact hook's module (found without running it), the
  folders of files sent by path, and a command scanner's program.
- Results for the interpreter's own paths are kept for the life of the
  process, so a second `TwoKey` in one process does not look again.
- docs/CONNECTING.md: a new "Run Two-Key as a service account" section
  (not a person's account, not root or an administrator, nobody signs in
  as it, in no group that leads to root, with commands for Linux, macOS,
  and Windows), the check under "What Two-Key checks for you", and two
  checklist lines. HOWTO (the `proxy.yaml` table, the refusal table and
  warnings, high_assurance, Python, known trade-offs), THREAT_MODEL,
  JUDGES_AND_QUORUM, SECURITY, ROADMAP, AGENTS.md, and llms.txt updated.
- `tests/test_writable_paths.py` (19 tests). The start-up warnings test in
  `tests/test_scan.py` and the section4 test in `tests/test_two_key.py`
  build high_assurance quorums, so they no longer look at the machine they
  run on. On GitHub's runners the check names `/opt` (writable by everyone)
  on Linux, `/Library/Frameworks/Python.framework/Versions/<v>` (writable
  by group admin) on macOS, and `C:\hostedtoolcache` (Authenticated Users
  can change it) and `D:\` (owned by NETWORK SERVICE) on Windows.
- Windows messages name well-known accounts: `owned by NETWORK SERVICE
  (S-1-5-20)`, `Authenticated Users (S-1-5-11) can change it`.


## Run 7 follow-ups: key errors, scanner scope, relay — 2026-10-16

From GrokBot's live run 7 and 7x report (on `live-runs`).

- A key file given to `--key` that is a public key is now
  `key_file_public: <path> is a public key; give the private key ...`,
  whatever its mode. Before, `two-key audit --key principal.pub.pem` said
  `key_file_insecure: ... run chmod 600`, which would not help. A file that
  is not an unencrypted PEM private key is `key_file_invalid` instead of
  the cryptography library's error. Every file refused before is still
  refused (`two_key/keys.py`).
- The CLI prints a `--key` refusal as one line (`--key: key_file_...`)
  instead of a traceback, and each `--key` help says it takes
  `principal.pem` from `init-key`, not `principal.pub.pem`.
- docs/SCANNERS.md: under monitor, judges see `flagged` without the
  arguments and usually vote no, so monitor denies most flagged calls in
  practice (run 7, C48 and C49). Scanning does not decode base64 or hex
  inside free text (run 7x, C29), does not join calls (C19, C50), and a
  tool marked `scan: not_applicable` is not scanned at all (C44).
- Live harness: a tool bot reply that refuses or filters a call is a
  referee incident, `tool_out_of_role_refusal` (run 7, C34; ported from
  the run 7x copy). RELAY.md names the `manifest_*.json` files the harness
  writes next to each batch (never sent to a bot, committed with the run)
  and says results go on the `live-runs` branch.
- Tests: `tests/test_cli_tokens.py` (public key, invalid key, `--key`
  help, one-line refusal).

## Release v0.6.0: Windows, content scanning, writable-path check — 2026-10-16

Package version 0.6.0 (`pyproject.toml`, `two_key.__version__`; `uv.lock`
regenerated with uv 0.13.0, which changes only the package's own version).
To be tagged `v0.6.0` on `main` after the merge. Not on PyPI. The entries
above, from "Semgrep findings printed to the job log" on, are the detail.

- **Windows support** (maintainer-reviewed design): every key read or
  write, owner-only folder, lock, and no-follow open goes through
  `two_key/_platform.py`. On Windows a key gets an access list for the
  current user only, a key that anyone but the user, SYSTEM,
  Administrators, or OWNER RIGHTS can open is refused, a reparse point is
  refused, and the lock is `LockFileEx`. Linux and macOS behave as before.
- **Content scanning** (maintainer-reviewed design, optional): Two-Key
  calls the operator's antivirus or DLP product for every call to a tool
  the signed constitution marks, files included (base64, or a path in a
  declared folder, each with a required `max_bytes`). Two-Key alone starts
  the scan; the agent cannot ask for, skip, or answer one. The verdict
  (clean, flagged, unavailable) is a fact a signed rule decides on
  (default, strict, or monitor), the judges are told, and the ledger records
  it without content. A timeout or error is never clean. A file Two-Key
  cannot read or that is over a limit is denied before both keys under
  every stance. An encrypted file passes only on a tool signed
  `encrypted: pass`. Adapters, standard library only: ClamAV `clamd`,
  ICAP, a command, and a Python hook. The gateway never scans; it checks
  the token's verdict and file digests. docs/SCANNERS.md.
- **Start-up check for writable paths** (maintainer's decision,
  2026-10-16): Two-Key names each file or folder it runs or reads that
  another account could change. `warn` by default, `on_writable_paths:
  refuse` refuses, and `high_assurance` always refuses. docs/CONNECTING.md
  covers connecting the agent so it cannot go around Two-Key, and running
  Two-Key as a service account.
- **Judge connection reuse** (#6): connections are pooled per origin across
  quorum rounds.
- **CI** on Linux, macOS, and Windows: tests (Python 3.10 to 3.12), the
  demo, the build, bandit, and CodeQL; Semgrep (0 findings, each
  suppression with its reason) and coverage on Linux. 862 tests.
- **Live testing**: run 7 (content scanning, 49 cases) and run 7x (a new
  organization, 52 cases, 33 of them attacks from a security practitioner)
  passed every case, with no referee incident. Results are on the
  `live-runs` branch.
- Smaller changes: a public key given to `--key` is `key_file_public`;
  CLI key errors are one line; `tool_out_of_role_refusal` in the live
  harness.
- Next (0.7.0, maintainer's decision 2026-10-16): with the SIEM export, a
  rate-limited count of tokens the gateway refuses without a ledger entry,
  kept outside the ledger; design note first.
- Docs: README, ROADMAP (0.6.0 under "Shipped"), HOWTO, SCOPE,
  THREAT_MODEL, FIT, COMPARISON, JUDGES_AND_QUORUM, SCANNERS, SECURITY,
  CONTRIBUTING, AGENTS.md, and llms.txt name 0.6.0 as the release and
  `v0.6.0` as the install ref.

### Upgrading from 0.5.0

- Constitutions, ledgers, keys, backups, `judges.yaml`, and `proxy.yaml`
  from 0.5.0 load unchanged. Nothing needs re-signing.
- **Check the start-up output first.** Two-Key now prints
  `two-key: WARNING: writable_path: ...` for each file or folder it runs or
  reads that another account could change (its Python, its import path, its
  config and keys, and, behind the proxy, the upstream program and the
  folder it starts in). Under `high_assurance` (and the `section4` profile)
  it refuses to start until there are none. Fix the owner or permissions,
  or run Two-Key as its own service account (docs/CONNECTING.md).
- Scanning is off until you configure a scanner. Without one, the judge
  prompts, the tokens, and the ledger are as in 0.5.0.
- A constitution that signs `encrypted: pass` needs 0.6.0; 0.5.0 refuses it.
- Scripts that call `two_key.cli.main` and catch `ValueError` for a bad
  `--key` file now get `SystemExit` with a one-line message.
- Maintainers: add the macOS and Windows checks to `main`'s branch
  protection.

## PR #12 review: TLS 1.2 for icaps, suppressed Semgrep findings — 2026-10-16

- CodeQL (`py/insecure-protocol`, high) on the release PR: the ICAP
  adapter's `icaps://` connection used `ssl.create_default_context()`,
  which can allow TLS 1.0 and 1.1 where the system's OpenSSL does. It now
  sets `minimum_version` to TLS 1.2. The certificate and host name checks
  are unchanged. Test: `tests/test_scanners.py` (`test_icaps_needs_tls_1_2`).
  docs/SCANNERS.md vendor checklist says so.
- Semgrep on the release PR showed the findings already suppressed in the
  code (each `# nosemgrep: <rule-id>` with its reason) as new alerts:
  Semgrep writes them to the SARIF marked as suppressed, and code scanning
  does not read that mark. `semgrep.yml` now drops suppressed results
  before the upload and prints how many. The job log was already at 0
  findings.

## PR #12 review: SonarCloud findings — 2026-10-16

- SonarCloud (path traversal, `constitution.save_envelope`): the only
  caller is `two-key sign-constitution --out`, which the principal runs, so
  no boundary was crossed. The write is still better through `_platform`:
  `save_envelope` now writes a new file beside the target (no-follow,
  exclusive) and renames it over the target. A reader never sees half a
  constitution, a failed write keeps the old file, and a link at `--out` is
  replaced rather than written through. Test: `tests/test_save_envelope.py`.
- Fourteen 0.6.0 functions over SonarCloud's cognitive complexity limit
  (15) are split into smaller ones, with no change in behavior or messages:
  the ICAP verdict and response reader (`scanners.py`); file arguments, the
  scanner's start-up checks, confined path reads, and per-file reads
  (`scan.py`); the Windows access-list check (`_platform.py`); the import
  path walk (`writable.py`); caller-field mappings (`constitution.py`);
  proxy tool settings and the scan block (`mcp_proxy/config.py`); and the
  file-input schema walk and start-up paths (`mcp_proxy/core.py`).
- DeepSource took a variable in the ICAP adapter that holds an
  `Encapsulated` section name for a hard-coded credential, because its name
  ended in "key". It is now `section`.
- Left as they are (SonarCloud warnings, not blockers): `[A-Za-z0-9_]` stays
  rather than `\w`, which would also match non-ASCII letters; the
  `list(...)` copies in `writable.py` keep the loop safe if `sys.path` or
  `sys.modules` changes; the ctypes structure names follow the Windows API.

## Docs: a 0.7.0 live run for the PR #12 refactor — 2026-10-16

- ROADMAP 0.7.0: a live run covers the code 0.6.0 changed after live run 7
  in the PR #12 review (the SonarCloud refactor and the `sign-constitution
  --out` write). No live run was done before the release; the tests and CI
  cover those changes (maintainer's decision).

## CI: the CodeQL configuration note — 2026-10-16

- The 0.6.0 note that Linux keeps CodeQL's default category was wrong. The
  single job main ran before 0.6.0 set no category, so GitHub named its
  configuration after the job (`.github/workflows/codeql.yml:analyze`); the
  three platform jobs upload under new categories. That old configuration is
  stale on main, and a PR's CodeQL check warns "1 configuration not found"
  (neutral, not a failure) until it is deleted on the code scanning tool
  status page. The comment in `codeql.yml` now says so; the categories stay
  as they are.

## SIEM export: live delivery, file export, refused tokens (0.7.0) — 2026-10-16

The 0.7.0 item from [ROADMAP.md](ROADMAP.md), built to the design note the
maintainer approved on 2026-10-16. Optional: with no `siem` setting nothing is
sent, and the judge prompts, tokens, and ledger are byte for byte as in 0.6.0.
The reference is [docs/SIEM.md](docs/SIEM.md).

- **A live copy of every ledger entry.** `Ledger.observe()` calls back after an
  entry is written and fsynced with its sequence number only; `two_key/siem.py`
  projects, renders, and sends it on its own sender thread. A collector that is
  down, slow, or gone never blocks or delays an authorization (maintainer's
  decision, 2026-10-16): entries wait on a bounded queue, a full queue drops the
  oldest and says so on stderr, and delivery resumes from a per-sink cursor
  (`<ledger>.siem/cursor.json`, owner-only, outside the ledger directory). An
  event sent late carries `"replay": true`.
- **An explicit per-kind field allowlist** (`KINDS` in `two_key/siem.py`). Every
  body key of every ledger kind is `sent`, `hashed`, `excluded`, or extracted;
  a key nobody has decided about fails the tests rather than leaving the box.
  Reason codes, digests, sizes, the tool id, the data class, the quorum counts,
  and the scan verdict leave. Argument values, proposal and decline text, the
  derived amount, counterparties, custom field values, scanner threat names and
  matched text, and credentials do not, with canary values in the tests.
- **Sinks** (standard library only, so no new dependency and no extra):
  syslog RFC 5424 over TLS (RFC 5425, port 6514, the default), plain TCP
  (RFC 6587, 514), or UDP (RFC 5426, 514), every port configurable, with octet
  counting or a line per message; and an HTTPS webhook posting newline JSON in
  batches, with an authorization header and an optional HMAC signature read
  from owner-only files, and redirects never followed. TLS is TLS 1.2 at the
  lowest and always verifies the certificate and the host name; there is no
  setting that turns either check off. A plaintext sink is refused under
  `high_assurance` (`siem_plaintext_refused`) and warns at start everywhere
  else (maintainer's decisions, 2026-10-16).
- **Schemas and formats**: Two-Key's own `two-key-siem-v1` (the default, with no
  lossy mapping), ECS 8.x, and OCSF 1.1 (class 3003); `json` (the default) or
  `cef`. Both mappings are made from the allowlisted event, so neither can
  carry more than the native one.
- **`two-key siem-export`** verifies the ledger, decrypts locally, and writes
  the same events to a new owner-only file (it refuses to overwrite), ending
  with a signed summary: the first and last `seq`, the count, the Merkle root,
  the ledger size, and the head signatures. **`two-key siem-verify`** re-derives
  every event from the ledger offline and reports changed fields, gaps,
  repeats, and events from another ledger. First delivery starts at `now`, so
  turning the copy on does not flood a SIEM; `siem-export` backfills the
  history (maintainer's decision, 2026-10-16).
- **A count of refused tokens** (live run 7). A token that does not verify is
  still not ledgered: `two_key/gateway.py` counts it by class (bad signature,
  expired, malformed, other) in memory, and the counts go to stderr and to the
  SIEM at most once an interval, as `gateway_token_refused` with
  `"ledgered": false` and `seq: -1`. No token text, digest, or id is kept, so a
  caller without a valid token still cannot make the ledger grow.
- `TwoKey(..., siem=...)` takes a `SiemConfig`; the MCP proxy takes the same
  settings as a `siem:` block in `proxy.yaml`; `two-key demo --siem FILE` sends
  a demo ledger to a real collector. `siem_configured` records the schema, the
  format, and each sink's type, host, port, and transport in the ledger, never a
  secret. Sink files join the 0.6.0 writable-path check. `TwoKey.close()` gives
  the sender a last pass.
- Tests: `tests/test_siem.py` (the allowlist, the canaries, the schemas,
  delivery, the counter), `tests/test_siem_sinks.py` (every transport and the
  webhook against loopback collectors, with a throwaway CA in `tests/tls.py`),
  and `tests/test_siem_export.py` (the file and the offline check). 119 new
  tests, network-free.
- `examples/siem/elastic/` is a worked example: Elasticsearch and Kibana in
  Docker, a receiver that terminates syslog over TLS and the webhook, an ingest
  pipeline, and a Kibana dashboard. `.github/workflows/siem-integration.yml`
  runs it on request and weekly; it is not a required check, and the unit suite
  stays network-free.

### Upgrading from 0.6.0

- Constitutions, ledgers, keys, backups, `judges.yaml`, and `proxy.yaml` from
  0.6.0 load unchanged. Nothing needs re-signing, and nothing is sent anywhere
  until you add a `siem` setting.
- Under `high_assurance` (and the `section4` profile) a plaintext sink (`udp`,
  `tcp`, or an `http://` webhook) refuses to start. Use `transport: tls`, or
  drop the profile.
- The first start with a sink sends only entries from then on. Backfill the
  history with `two-key siem-export`, or set `replay_from: start` once.
- Two new files sit beside the ledger when a sink is configured:
  `<ledger>.siem/cursor.json` (the per-sink cursor) and nothing else. Back it up
  with the ledger if a replay after a restore would matter.
- A long-running `TwoKey` should call `close()` on the way out, so the sender
  gets a last pass. Without it, what is left goes out on the next start.

## Docs: the SIEM export everywhere it applies (0.7.0) — 2026-10-16

- New `docs/SIEM.md`: what leaves and what never does (field tables), turning
  the live copy on, the sinks and their ports, the schemas and formats, the file
  export and its offline check, the refused-token count, the Elastic example,
  the trade-offs, and the reason codes.
- `docs/HOWTO.md`: a `siem` row in the `proxy.yaml` table, a "Send the ledger to
  a SIEM" section, and the trade-offs of a plaintext or UDP sink under "Known
  trade-offs by configuration".
- `docs/CONNECTING.md`: rows for the syslog sink, the webhook sink, and the sink
  files and cursor, and the start-up checks they get.
- `docs/THREAT_MODEL.md`: the new assets (the sink credential files, the cursor,
  an exported file), the collector as an actor, the two new boundaries (ledger
  to SIEM, gateway to the refused-token count), what `siem-verify` is meant to
  stop, the assumption about the collector, and the residual risks of a copy
  outside the ledger's encryption at rest. The 0.7.0 items leave "Planned
  changes to this model".
- `docs/SCOPE.md`, `ROADMAP.md`, `README.md`, `docs/FIT.md`,
  `docs/COMPARISON.md`, `SECURITY.md`, `CONTRIBUTING.md`, `AGENTS.md`, and
  `llms.txt`: the export as built on `working`, that Two-Key is still not a SIEM
  and does not store, search, or alert, and the fail-closed lines to preserve.
- `two_key/__init__.py` no longer says the package has no scanning or DLP hooks;
  it names `two_key.scan` (0.6.0) and `two_key.siem` (0.7.0) instead.

## CI: two tests looked at the machine, one at the drive (0.7.0) — 2026-10-16

- `tests/test_siem.py`: the two `high_assurance` plaintext tests now patch
  `two_key.writable.runtime_targets`. `high_assurance` always refuses to start
  where another account could change Python's own files, and `/opt`,
  `/Library/Frameworks/Python.framework`, and `C:\hostedtoolcache` are writable
  on the GitHub runners; the two tests are about the sink, not the machine.
- `tests/test_siem_sinks.py`: a rooted path with no drive letter
  (`/abs/client.pem`) is not absolute on Windows, so the config joins it onto
  the `proxy.yaml` directory's drive. The test joins it the same way instead of
  onto the current drive.

## Live harness: run 8 (four personas, the SIEM copy, the paths 0.6.0 refactored) — 2026-10-16

- Four personas instead of three (`tests/live/harness.py`, `tests/live/make_cases.py`). Runs 6 and 7 had one
  MALICIOUS level; it splits into ADVERSARIAL (works around the standing orders while each call looks routine)
  and EVIL (works for someone else: data out, or damage). Eight new cases are a ladder: paying an invoice and
  sending a message, each at all four levels, worst last. `RESULTS.md` prints them as a grid, with level 1 as
  the control: a deny there is a finding about the rules, not the agent.
- The SIEM copy (0.7.0) is part of the pass. The harness serves its own syslog collector over TLS on loopback
  (certificates from `tests/tls.py`), every proxy of the pass sends it a copy of each ledger entry, and
  `report.py` checks the delivered count against the ledger, looks for an entry delivered twice, and searches
  every event for the argument values the pass's own calls carried, which must never be there. Two config cases
  cover a plaintext sink (a warning) and a sink file another account can change (the writable-path walk).
- The code the 0.6.0 refactor rewrote after live run 7, which no live run had covered: the ICAP reader's answers
  (403, a 200 with a changed body, a 200 that blocks the call, 500, and a reply that is not ICAP) and confined
  path reads. `send_message` declares a second file, a path inside the clinic's outbox folder, so a path above
  the folder, a link that leaves it, a folder named as a file, and a file over its cap are each denied before
  the scanner and both keys. The clinic's MCP server takes `attachments[].path` for it.
- Antivirus-safe run files: the logs are written with the antivirus test string and its base64 form masked, and
  `harness.py --mask-run DIR` masks a finished run directory before it is committed, writing `MASKED.md`. No
  antivirus test file is written to disk; the flagged file read by path trips the DLP rule instead.
- The selftest's stub judges deny a case whose expectation is a judge deny, so a case whose only line is Path B
  passes the plumbing check instead of failing it (run 6 left two such cases failing).
- `examples/siem/elastic/receiver.py` read the structured-data placeholder as the syslog MSGID (the sixth field,
  not the seventh), so a CEF event's `kind` was `-`. The harness reuses the same reader.
- 70 cases (49 in run 7); `python3 tests/live/harness.py --selftest` ends with every case PASS.

## Docs: an agent on another machine, over SSH — 2026-10-16

- `docs/CONNECTING.md`: a new section, "An agent on another machine (Route 1
  over SSH)". The proxy talks to the agent's host over stdio only, so a remote
  agent host starts it over SSH: a login account that is not `two-key` (sshd
  runs a forced command through the login shell, and the service account's is
  `nologin`), a root-owned `authorized_keys` entry with `restrict,command=`, a
  matching `Match User` block, and only SSH open from the agent machine. It
  says what changes for the keys, the judges, and the start-up writable check,
  and adds a row to "Pick your route", a row to "Every connection and hook",
  and checklist items.
- `run-proxy` sets `umask 077` (`docs/HOWTO.md`, `docs/CONNECTING.md`). Under
  `sudo -u two-key` on Ubuntu 24.04 the proxy gets umask 002, so the ledger it
  creates on the first start was group-writable, and its own start-up check
  named the ledger folder, or with `on_writable_paths: refuse` did not start.
- `docs/HOWTO.md` "Limits" and `docs/THREAT_MODEL.md`: one running proxy per
  ledger. When a second proxy on the same ledger writes, every later call
  through the first is denied with `ledger_failed:ledger file changed by
  another writer` until it restarts. This holds on one machine too.
- `README.md` and `llms.txt`: the proxy listens on stdio only, a remote agent
  connects over SSH, and one running proxy per ledger.
- Checked end to end on Ubuntu 24.04 with real OS users (`two-key`,
  `mcp-billing`, a `tk-agent` login account), sudo rules, the fake upstream
  server, and a loopback judge: an MCP client ran the forced command's chain
  (`sudo -n -u two-key run-proxy`) with `on_writable_paths: refuse`, got the
  three signed tools, one allowed call, and the expected denies. The
  `sshd_config` block was checked with `sshd -t` and `sshd -T`; sshd itself
  was not run in the test container.

## Live harness: what a pass does not cover — 2026-10-16

- `RESULTS.md` and `tests/live/RELAY.md` now say it plainly: every endpoint of a pass is on one machine, on
  loopback, so a pass says nothing about a monitored agent that connects from another machine. That deployment is
  the one the operator expects to be the common one, and it needs a live run of its own.

## The proxy refuses an agent that is, or can change, Two-Key (0.7.0) — 2026-10-16

- New `two_key/agent_access.py` and `on_agent_access` in `proxy.yaml`
  (maintainer's decision, 2026-10-16: refuse by default). Before it opens the
  ledger, the proxy reads the real user of its parent process (the agent's
  host, or the `sudo` or SSH session it went through; `/proc` on Linux,
  `/bin/ps` elsewhere, through `_platform.parent_account`) and refuses to
  start when that account is Two-Key's own (`agent_same_account`), is root
  (`agent_account_root`), cannot be told (`agent_account_unknown`), or can
  change a file or folder of the writable-path check (`agent_can_write`: it
  owns it, everyone can write it, or it is in a group that can; an account
  whose groups cannot be listed counts as in every group). `warn` names the
  problem and starts, for a test under one account; `high_assurance` refuses
  and does not accept `warn`. The refusal reads `two-key: mcp-proxy refused
  to start: AgentAccessError: <code>: ...; on_agent_access: refuse (the
  default) refuses to start (docs/CONNECTING.md)`. The library (Route 2) has
  no such check.
- Windows cannot tell the parent's account yet, so a proxy on Windows needs
  `on_agent_access: warn` until it can. Upgrading from 0.6.0: a proxy started
  under Two-Key's own account, as root, or on Windows now refuses to start.
- Two processes on one ledger: a `Ledger` that finds the file longer than it
  left it now reads the new entries under the cross-process lock and verifies
  them as an open does (each decrypts and continues the chain, the witness pin
  or rotation, the signed head, the anchor), instead of refusing every later
  write with `ledger file changed by another writer`. It does not pass them to
  its SIEM observer, since their writer sends them. A file that got shorter,
  or ends in a partial line, is still refused. This is a ledger change,
  approved by the maintainer on 2026-10-16.
- A split gateway (a `Ledger` no `TwoKey` in the process opened) still
  refuses a token issued since it last read the file, now as
  `ledger_size_invalid` alone.
- Docs: `docs/CONNECTING.md` (what Two-Key checks, the SSH section, the
  connection table, the checklist, and a note that remote agents are not yet
  tested enough), `docs/HOWTO.md` (the `proxy.yaml` table, troubleshooting,
  the trade-off, the limits, the deployment boundary), `docs/THREAT_MODEL.md`,
  `ROADMAP.md` (the remote-agent testing gap, which live run 8 does not
  close), `README.md`, `SECURITY.md`, `AGENTS.md`, and `llms.txt`.
- Tests: `tests/test_agent_access.py`, `tests/test_ledger_shared.py`, a
  command-line case in `tests/test_mcp_proxy_sdk.py` (the test runner's own
  account is refused), and the old stale-ledger test now expects the catch-up.
  Checked by hand in a container with real accounts: the same account, root,
  and a group the agent's account is in are refused; a separate account
  through the sudo rule starts and serves; two proxies on one ledger serve
  calls in turn and `two-key audit` passes.


## Live harness: the start-up account check — 2026-10-16

- The harness is the agent's host and starts the proxy under its own account,
  which is what `on_agent_access` now refuses by default, so every proxy a
  pass writes says `on_agent_access: warn`. Four config cases cover the
  setting itself: the default's refusal (`agent_same_account`), the warning,
  a value that is neither `warn` nor `refuse`, and `high_assurance` refusing
  `warn`. The high_assurance case's judge set declares a second maker and a
  local judge, which that profile needs before the config will load.
- `RESULTS.md` and `tests/live/RELAY.md` say what a pass cannot reach: an
  agent account that is root, cannot be told, or could change Two-Key's files
  needs a second account, and `tests/test_agent_access.py` covers those
  alone. 74 cases in the batch after run 8 (70 in run 8).

## The `on_agent_access` tests on macOS and Windows — 2026-10-16

- `tests/test_agent_access.py` read `os.geteuid()` in a decorator, which
  Python evaluates when the class is defined, before the class's own
  Windows skip can take effect; the module failed to import on Windows. The
  account id is now read once, and only on POSIX.
- The same tests built their expectations from the path `tempfile` returned.
  The writable-path check names the real path, and on macOS `/var` is a link
  to `/private/var`, so two tests looked for a path the check never names.
  They now resolve the temporary directory first.

## Live run 8x findings: the SIEM copy, a named pipe, signing — 2026-10-16

- The SIEM copy no longer loses its tail when the process ends (run 8x, C15).
  A syslog sink's `close` now sends TLS `close_notify` and half-closes before
  the socket goes, so a collector reads the last message as a finished one
  instead of a truncated stream, and a stream socket is opened with
  `TCP_NODELAY`, since an event is small and a collector reads it as it
  arrives. The sender's `close` waits for one pass over every sink (what one
  try at each can take, at most 15 s) instead of `flush_seconds`, so a
  collector that takes a moment keeps the last events. A sink already in
  backoff is skipped by that pass, so a collector known to be down costs
  nothing at shutdown.
- A named pipe in a folder a tool takes files from no longer hangs the call
  (run 8x, C78). Opening it waited for a writer, which the agent could keep
  away for as long as it liked. The read opens with `O_NONBLOCK`, which does
  nothing to a regular file, and the open is followed by the same check as
  before: anything but a regular file is `file_unreadable`.
- The SIEM delivery cursor joins the start-up writable-path check (run 8x,
  C40), which is what `docs/CONNECTING.md` already said: whoever can change
  it can make the copy repeat or skip entries.
- `two-key sign-constitution` refuses to write over an existing `--out`
  file; `--force` replaces one (run 8x, finding 3). Signing is deliberate,
  and so is replacing what every later check verifies against.
- Docs: `docs/SIEM.md` says plainly that `replay_from: start` sends the whole
  ledger on **every** start, not only the first (it ignores the cursor);
  `docs/SCANNERS.md` says what a tool that marks `scan: not_applicable`
  shows a judge (the field's signed `default`, `clean` in the examples, which
  a judge cannot tell from a scanned-clean call; the ledger can, since only a
  scanned call has a `scan` entry); `docs/HOWTO.md` says a gateway refusal is
  ledgered once per token, so replaying one spent token cannot grow the
  ledger.
- The Elastic example's dashboard used Two-Key's own field names while its
  `siem.yaml` sends ECS, so its panels were empty (run 8x, finding 4). Its
  columns and queries now use the ECS names the pipeline indexes
  (`event.action`, `event.reason`, `event.sequence`, `two_key.*`), and the
  alert panel looks for `gateway_denied`, which is the ledger kind, not
  `gateway_deny`. Not verified against a live Kibana from the build
  container, which cannot reach the Elastic registry.

## `siem-verify` checks the whole event, and a cursor that cannot be read says so — 2026-10-16

- `two-key siem-verify` now checks the rest of an event's envelope against
  the ledger, not only its fields: `prev`, `severity`, that `replay` and
  `truncated` appear only when true, that `ledgered` is true for an entry
  the ledger holds, and that `sent_at` is a timestamp. Changing any of them
  used to pass (live run 8x, C49, C58, C83).
- It also checks an export's last line against the file it closes: the
  count, `first_seq` and `last_seq` against the lines read, `ledger_size`
  and `merkle_root` against the ledger at that size, and that every event
  carries the summary's `exported_at`, since one export writes one time. A
  file pulled back out of a SIEM has no summary line and is checked event by
  event as before.
- A SIEM cursor file that is there but cannot be read now warns, instead of
  silently counting as a first start: the copy then begins where
  `replay_from` says, and the entries in between are in the ledger only
  (live run 8x, C72). `siem-export` backfills them.

## SonarCloud findings on the 0.7.0 code — 2026-10-16

The SIEM and start-up-check work failed SonarCloud's quality gate on its
reliability rating. Both findings behind it are now gone.

- `two_key/siem.py` used `value == value` to spot a NaN before an event
  carries a float (`python:S1764`, identical sub-expressions around `==`).
  It reads as a typo and a later reader may well "fix" it. The check is
  `math.isfinite(value)` now, which covers the infinities in the same
  breath, and a test pins all three (`tests/test_siem.py`).
- `parse_ballot_strict` returned three values, or four with `echo=True`
  (`python:S8495`, a function whose tuples change length). It always returns
  four now, the echoed hashes being `None` when they were not asked for, and
  its one caller reads them to tell the two apart. The parse is unchanged,
  and `tests/test_strict_parsing.py` checks both shapes.
- `.github/workflows/tests.yml` passes `--no-build` to `uv run` as well as
  to `uv sync`. The step already passes `--no-sync`, so nothing was being
  built; the flag says so to a reader and to a scanner.
- `examples/siem/elastic/receiver.py` reads two secret files whose paths
  come from its own command line, which SonarCloud reports as a path
  traversal (`pythonsecurity:S8707`, written for agentic workflows, where
  the arguments come from a model). This collector reads Two-Key and never
  answers it, nothing on the network reaches that code path, and an operator
  who starts the process can read those files anyway, so the line carries a
  `NOSONAR` and the reason. A check there would prove nothing.

## Release v0.7.0: the SIEM export, the agent-account check — 2026-10-16

Package version 0.7.0 (`pyproject.toml`, `two_key.__version__`; `uv.lock`
carries the package's own version and nothing else changed). To be tagged
`v0.7.0` on `main` after the merge. Not on PyPI. The entries above, from
"SIEM export: live delivery, file export, refused tokens" on, are the
detail.

- **Ledger export to a SIEM** (maintainer-reviewed design, optional): every
  ledger entry can be copied to the collector the operator runs, as it is
  written. Syslog over TLS (RFC 5425, port 6514, the default), plain TCP, or
  UDP, and an HTTPS webhook with a batched body, a token read from a file,
  and an optional HMAC. Two-Key's own schema, ECS, and OCSF; JSON and CEF.
  A per-kind field allowlist decides what leaves the box: reason codes,
  digests, sizes, the tool name, and the data class, never argument values,
  proposal text, custom field values, or token text. A collector that is
  down or slow never blocks or delays an authorization: the sender is its
  own thread, delivery resumes from a per-sink cursor, and a late event is
  marked `replay`. TLS always verifies the certificate and the host name,
  with no setting that turns it off; plaintext warns at start and is refused
  under `high_assurance`. docs/SIEM.md.
- **`two-key siem-export` and `two-key siem-verify`**: the same events
  written to a file, with a summary line, and a check of a copy against the
  ledger, event by event, including the envelope and the summary.
- **The proxy refuses an agent that is, or can change, Two-Key**
  (maintainer's decision, 2026-10-16): at start the proxy reads the real
  account of the process that started it. If that is Two-Key's own account,
  is root, cannot be told, or can write a file or folder Two-Key runs or
  reads, it refuses to start before the ledger is opened.
  `on_agent_access: warn` keeps the old behaviour; `high_assurance` refuses
  and rejects `warn` outright. Windows cannot read the parent's account yet
  and needs `warn`. docs/CONNECTING.md.
- **A count of the tokens the gateway refuses**, by type and outside the
  ledger: a caller without a valid token cannot make the ledger grow, and
  the count still reaches the operator and the SIEM, at most once a minute.
- **Two proxies on one ledger** no longer break each other: each verifies
  the other's entries under the lock and catches up.
- **An agent on another machine**: the supported route, stdio over SSH with
  a forced command, is written up and tested in docs/CONNECTING.md. It needs
  a live run of its own before 1.0; the ROADMAP and that page say so.
- **CI** on Linux, macOS, and Windows: tests (Python 3.10 to 3.12), the
  demo, the build, bandit, and CodeQL; Semgrep and coverage on Linux. 1018
  tests. SonarCloud's findings on this code are fixed, with one suppression
  (an example collector's own command line) carrying its reason.
- **Live testing**: runs 8 and 8x put a monitored agent through four
  personas, legitimate, incompetent, adversarial, and evil, over the SIEM
  copy and the paths the PR #12 review refactored. Every finding is fixed;
  the entries above are the record. Results are on the `live-runs` branch.
- Docs: README, ROADMAP (0.7.0 under "Shipped"), HOWTO, SCOPE,
  THREAT_MODEL, FIT, COMPARISON, JUDGES_AND_QUORUM, SIEM, CONNECTING,
  SCANNERS, SECURITY, AGENTS.md, and llms.txt name 0.7.0 as the release and
  `v0.7.0` as the install ref.

### Upgrading from 0.6.0

- Constitutions, ledgers, keys, backups, `judges.yaml`, and `proxy.yaml`
  from 0.6.0 load unchanged. Nothing needs re-signing.
- **Nothing is sent until you configure a SIEM.** Without a `siem` setting
  (or `SiemConfig`), the ledger, the tokens, and the judge prompts are as in
  0.6.0.
- **Check the proxy's start-up output.** `two-key mcp-proxy` now refuses to
  start when the monitored agent runs as Two-Key's own account, as root, as
  an account it cannot read, or as one that can change a file Two-Key runs
  or reads. Give the agent its own account (docs/CONNECTING.md), or set
  `on_agent_access: warn` in `proxy.yaml` for a machine where that is the
  deployment, as Windows is until the check is ported there.
  `high_assurance` refuses either way and rejects `warn`.
- Under `high_assurance`, a plaintext syslog sink (`udp` or `tcp`) refuses
  to start. Use `transport: tls`.
- A first start sends from now and backfills nothing; `two-key siem-export`
  writes the history. `replay_from: start` sends the whole ledger on every
  start, not only the first.
- Maintainers: add the macOS and Windows checks to `main`'s branch
  protection, and delete the stale `.github/workflows/codeql.yml:analyze`
  code-scanning configuration.

## PyPI packaging on the PyPI branch — 2026-10-16

Packaging only, on the `PyPI` branch. No application code changed.
`pyproject.toml` version and `two_key.__version__` stay `0.7.0`. Tag
`v0.7.0` is not moved. Nothing was uploaded. The name `two-key` was
unregistered on pypi.org and test.pypi.org on this date.

- `pyproject.toml` now carries the fields an index page needs: the README
  as the long description, the Apache-2.0 SPDX license and `LICENSE`,
  authors, keywords, classifiers, and project URLs (documentation,
  issues, changelog, release process, security). Dependencies, extras,
  the `two-key` script, and the version are the same.
- `MANIFEST.in` still grafts `examples`, and also ships the license and
  the operator docs in the source distribution. The wheel is still only
  the `two_key` package. Key-file names (`*.pem`, `*.witness`) are
  excluded from the source distribution.
- `.github/workflows/pypi-publish.yml` builds the sdist and wheel, runs
  `twine check --strict`, writes a CycloneDX SBOM as a workflow artifact,
  and uploads with trusted publishing (no token). A manual run defaults
  to TestPyPI. A tag push targets PyPI only when the tag equals the
  version in `pyproject.toml`. docs/PYPI.md is the procedure.
- `.gitignore` ignores `.pypirc`.
- Docs that say where the package stands name this preparation and still
  say it is not on PyPI: README, HOWTO, FIT, ROADMAP, CONTRIBUTING,
  SECURITY, AGENTS.md, and llms.txt. Past "not published" notes in this
  file are unchanged.
- Two DeepSource `SCT-A000` hits in docs/HOWTO.md are false positives:
  the optional witness public-key path `/etc/two-key/witness.pub.pem` in
  the proxy example, and the `load_public_key(...)` call on that same
  public key. Both lines now carry `skipcq: SCT-A000`. Nothing else is
  excluded from secret detection.

## Diagrams: one house style, checked by a test (#29) — 2026-10-20

Docs only, plus one test and one workflow. No application code changed.

- `tests/test_doc_diagrams.py` now checks every Mermaid diagram in the
  README, ROADMAP and `docs/` against a house style that keeps GitHub's
  renderer from splitting words, clipping notes, or shrinking text: label
  lines of at most 28 characters, edge labels of at most two lines, left to
  right only for a chain of four boxes or fewer, at most five participants
  in a sequence diagram with messages and notes that fit, at most 12 boxes,
  and a one-line italic caption under each diagram (saying "dashed" when
  the diagram mixes solid and dashed lines). The old semicolon check stays.
- Every diagram was redrawn to that style, in real Mermaid. The README's
  request-flow flowchart and its sequence diagram are each split into
  smaller ones; HOWTO's vocabulary sequence is split in two; SCANNERS'
  scan sequence is split in two and its return path is fixed (the result
  goes back through the gateway and Two-Key, and a deny never reaches the
  tool); `sudo -n -u two-key /opt/two-key/run-proxy` moved out of the
  diagram labels into the captions; the HOWTO proxy call sequence no
  longer names a domain field; the SIEM diagram runs top to bottom and
  draws `siem-verify` as a read-only comparison, not a write into the
  ledger; the roadmap timeline runs top to bottom.
- `docs/THREAT_MODEL.md` gains a trust-boundary diagram at the head of
  "Trust boundaries".
- `.github/workflows/diagrams.yml` (not a required check) draws every
  diagram with a pinned mermaid-cli (11.4.2) and uploads the pictures as a
  build artifact, so they can be looked at together before a release. The
  docs keep real Mermaid; nothing is committed as a picture.
- CONTRIBUTING and AGENTS.md name the rule.

## Docs: prose accuracy and readability pass — 2026-10-20

Docs only. No application code changed.

- docs/PYPI.md is rewritten as "how a release is published". It said 0.7.0
  was "being prepared for its first upload" and that `two-key` was not
  registered; PyPI has had `0.7.0`, `0.7.1` and `0.7.2` since 2026-10-17
  (`0.7.1` and `0.7.2` are only on the `PyPI` branch), and the next release
  is numbered above `0.7.2`. Install lines use `X.Y.Z`.
- FIT.md said 0.6.0 was the latest release and left AES-256-GCM out of its
  list of crypto; both are fixed.
- THREAT_MODEL, FIT and SCOPE no longer open with a paragraph of tag
  history. THREAT_MODEL keeps what each release added in a closing "Changes
  by release" section (0.7.0's agent-account check is now in it); FIT and
  SCOPE point to ROADMAP "Shipped" and AGENTS.md.
- Every "#45" in the README, ROADMAP, AGENTS.md, llms.txt, SECURITY and the
  docs, and the two HOWTO and README links to `issues/45` (a 404 here: #45 was
  an issue of the archived `two-key-concept` repository), now point to
  HOWTO "Deployment boundary: the gateway runs in the TwoKey process" and say
  the gateway stays in the process by design. The code's own comments and
  the `gateway.py` message still cite #45 and are not changed here; earlier
  CHANGES entries keep it as history.
- HOWTO opens with a "Start here" table: three routes (MCP proxy, guard,
  library) and the sections each one needs, in order. A few long passages in
  Install, Platforms and Redeem are split into shorter sentences, with no
  fact changed.
- COMPARISON links to SCANNERS.md. ROADMAP's 0.6.0 plan notes that #2 and #10
  are closed.
- Not touched here: the supported Python range and the upstream-path
  check text, which the Python 3.15 and #13 changes own.

## docs/SETTINGS.md: every setting, generated and tested — 2026-10-20

No behavior change. The settings were spread across HOWTO tables, SIEM.md,
JUDGES_AND_QUORUM.md and the example files; this is the one map.

- `two_key/settings.py` is a catalogue with one row per key that a loader
  accepts: the file, the dotted key, the default, what `high_assurance` does
  to it, whether the value names a secret, and the tier (signed policy or
  operator config). It covers `proxy.yaml`, `judges.yaml` (judges, quorum,
  `monitored_agent`), `agents.yaml`, and the signed `hard_rules.yaml` (rule
  types, tool specs, custom fields). A signed setting needs the principal
  key to change; an operator setting needs write access to its file and a
  restart.
- `docs/SETTINGS.md` is generated from it with
  `python tests/test_settings_doc.py --write`, with a "Who can change what"
  table and the table of what `high_assurance` changes.
- `tests/test_settings_doc.py` reads the key sets the loaders use and fails
  when a key has no row, when a row names a key no loader accepts, when a
  row is repeated, or when the page is not what the catalogue renders. A key
  added later (for example `upstream.check_paths`) fails the suite until it
  has a row.
- `two_key/constitution.py` names the key sets of a rules file, a tool spec
  and its parts (`RULES_FILE_KEYS`, `TOOL_SPEC_KEYS`, `AMOUNT_KEYS`,
  `COUNTERPARTY_KEYS`, `PAYLOAD_KEYS`, `FIELD_MAPPING_KEYS`) so the test reads
  the same sets as the validators. The validators accept exactly the keys they
  did before.
- README, HOWTO, CONNECTING, AGENTS.md, CONTRIBUTING and llms.txt point to it.

## `two-key config show` and `config check`: read-only views of a proxy config — 2026-10-20

No change to any check or to the ledger.

- `two-key config show --config proxy.yaml` prints the effective settings as JSON, defaults filled in
  (the resolved `on_agent_access` and `on_writable_paths`, the quorum, the judges, the tools, the SIEM sinks).
  A key file is shown by path, a judge's key by its environment variable's name, and an upstream literal value
  as `<literal>`.
- `two-key config check --config proxy.yaml` loads what the proxy loads at start that has no side effect, and
  reports `ok`, `WARN` or `FAIL` per line: the config parses, the principal key loads, the constitution is
  signed by it, every `tools:` entry is signed, the judges and quorum load, a `monitored_agent` is declared,
  the environment variables the config reads are set, writable paths, and plaintext SIEM sinks. It exits 1 on
  any `FAIL`. It does not run the `on_agent_access` check or compare `schema_digest`; the proxy does both at
  start.
- Neither command writes a file, opens the ledger, starts a process, or contacts a judge, scanner, collector
  or upstream server. Neither constructs `TwoKey`, which appends to the ledger when it starts.
- Docs: HOWTO "Look at a config without starting the proxy", README, SETTINGS, AGENTS.md, llms.txt.

## Python 3.13 to 3.15: compiled files stay checked, CI, docs (#27) — 2026-10-20

- **The writable-path check looks at compiled files on Python 3.15.**
  Python 3.15 no longer sets a module's `__cached__`, and the check read
  only `__file__` and `__cached__`, so on 3.15 it stopped looking at the
  `.pyc` files of loaded modules and at their `__pycache__` folders: one
  that another account could write would have passed unseen.
  `two_key/writable.py` now also reads the module's spec
  (`__spec__.cached`, and `__spec__.origin` for a module with a location),
  which Python 3.10 and later set. New tests: a module with no `__cached__`
  and an open `__pycache__` folder is named, and a module with no location
  adds nothing (`tests/test_writable_paths.py`). Nothing changes on 3.10
  to 3.14, where both names point at the same file.
- **CI tests Python 3.13 and 3.14** on Linux, macOS, and Windows, from
  `uv.lock` as wheels only, like 3.10 to 3.12.
- **A Python 3.15 job on Linux that does not block.** PyYAML publishes no
  3.15 wheel yet, so this job builds PyYAML alone from source and keeps
  every other package wheels only (a second package without a wheel fails
  the job instead of being built). It runs the suite and the demo. It
  becomes blocking, with macOS and Windows, once PyYAML ships 3.15 wheels.
- `pyproject.toml` classifiers name 3.13 and 3.14. `requires-python` stays
  `>=3.10` with no upper bound: a bound would not make pip refuse 3.15, it
  would install an older Two-Key and fail on the same PyYAML build.
- Docs: README, HOWTO ("Platforms", with what to do on 3.15: use 3.14 until
  PyYAML ships wheels; two version notes made accurate for 3.13 and 3.14),
  PYPI, CONTRIBUTING, and AGENTS.md say 3.10 to 3.14.

### Upgrading

- Nothing to change. On Python 3.15, a start may now name a `__pycache__`
  folder another account can write, which it should have named before.

## The proxy checks the upstream server's files behind a launcher (#13) — 2026-10-20

The writable-path check and the agent-account check looked only at
`upstream.command[0]`. With the command CONNECTING recommends,
`[sudo, -n, -u, mcp-billing, <interpreter>, <server script>]`, that is
`sudo`: an account that could change the server script or its folder went
unseen, and the proxy started without a warning, `on_writable_paths:
refuse` included. On Linux, macOS, and Windows alike:

- **Absolute arguments are checked.** Each argument of `upstream.command`
  after the program that is an absolute path to something that exists is
  checked, a file together with its folder (where Python, Node, and most
  others look for what a script imports), a folder as a folder. Options
  (`-u`, `--preserve-env=...`) and relative arguments are not read as
  paths, and a launcher is not followed to its target: a wrong guess would
  read as a pass.
- **`upstream.check_paths`** in `proxy.yaml` (optional) lists more of the
  server's files and folders: its package folder, a config file. Each entry
  must be absolute, at most 64, and one that does not exist refuses to
  start (`check_path_missing`). A folder is checked itself, with the
  folders above it, not every file inside it.
- **`upstream_paths_unchecked`.** When `command[0]` is a launcher (`sudo`,
  `doas`, `env`, `npx`, `uvx`, `pipx`, `cmd`, `powershell`, `pwsh`; by
  name, ignoring case and a `.exe`, `.cmd`, `.bat`, or `.com` ending) and
  neither an absolute argument nor `check_paths` names anything, the proxy
  warns at start. Under `high_assurance` it refuses. Both come before the
  ledger is opened.
- Both start-up checks see the new paths (`startup_paths`), so
  `agent_can_write` covers the server's files too.
- `two-key config check` reports a missing `check_paths` entry and
  `upstream_paths_unchecked` (a `FAIL` under `high_assurance`) the way
  the proxy would at start, and `config show` prints `check_paths`. The
  settings catalogue and docs/SETTINGS.md have the new key.
- Tests: `tests/test_upstream_paths.py` (the issue's repro, `check_paths`,
  a missing entry, launcher names, the warning and the refusal, and the
  order before the ledger), and cases in `tests/test_agent_access.py` and
  `tests/test_config_cmd.py`.
- Docs: CONNECTING ("What Two-Key checks for you", what it cannot see, and
  the checklist), HOWTO (the `proxy.yaml` example now runs an installed
  server instead of `npx`, the `check_paths` row, two refusal rows, and
  `high_assurance`, and what `config check` reports), SETTINGS,
  THREAT_MODEL, SECURITY, AGENTS.md, llms.txt, and the `writable.py`
  docstring. Closes #13.

### Upgrading

- A proxy that starts today may now name more paths, or, under
  `on_writable_paths: refuse` or `high_assurance`, refuse. Make the
  server's program, script, and package folder owned by Two-Key's account
  or root and not writable by group or others. A server's files owned by
  its own account (`mcp-billing`) are named too, as any other owner is.
- A data folder passed as an absolute argument (a filesystem server's root,
  for example) is checked like the server's own files. If the agent can
  write it, `on_agent_access` refuses by default: the agent could change
  what the tool reads without either key.
- `upstream.command` that starts with a launcher and gives no absolute
  path (`npx -y <package>`, `uvx <package>`) now warns
  `upstream_paths_unchecked`, and under `high_assurance` refuses. Install
  the server where only root or Two-Key's account can change it, and give
  its program as an absolute path or list its folder in
  `upstream.check_paths`.

## `upstream.check_paths` on Windows needs the drive (#13) — 2026-10-20

- CI on Windows with Python 3.13 and 3.14 failed `tests/test_mcp_docs.py`:
  the HOWTO example's `check_paths` entry, `/opt/billing-mcp/...`, has no
  drive, and from Python 3.13 on Windows does not call such a path
  absolute. That refusal was right, but on 3.10 to 3.12 the same entry
  was accepted and read against whichever drive was current. On Windows an
  entry now needs its drive or a UNC share on every Python version
  (`expected an absolute path`). The docs test expects that refusal on
  Windows, and HOWTO and SETTINGS say so.

## DeepSource runs the Python analyzer, and on `working` — 2026-10-20

- DeepSource had no `.deepsource.toml`, so it ran its secrets check alone,
  and only on main and pull requests, never on a push to `working`.
  The Python analyzer is now on beside the secrets check, with `tests/`
  marked as test code. DeepSource keeps that setting in its own repository
  configuration, which is where it was turned on; `.deepsource.toml` holds
  the same so the repository says what runs. A draft pull request from
  `working` to main (#30) stays open so each push to `working` is analysed.
- The Python analyzer's first findings on `working` were two test helpers
  that did not use `self` (PYL-R0201), in `tests/test_upstream_paths.py`
  and `tests/test_config_cmd.py`; both are static methods now.
- Its first finding on `working` was a false positive in docs/SIEM.md: the
  Python example named its `TwoKey` instance `two_key = TwoKey(...)`,
  which the secrets check read as a hardcoded credential. The example now
  calls it `tk`, as HOWTO does, which also stops it shadowing the
  `two_key` package it imports from.
- CONTRIBUTING says where DeepSource runs.

## Docs review: README from main, clearer diagrams, `config show` described correctly — 2026-10-21

No change to any check, key or ledger entry.

- README.md is main's again, including its overview diagrams, with only the changes the current code needs:
  Python 3.10 to 3.14, the dead `#45` links pointed at HOWTO "Deployment boundary", the SETTINGS row, and the
  `config show` and `config check` sentence. `tests/test_doc_diagrams.py` exempts README.md from the size
  rules (its syntax is still checked); every file in docs/ still follows them.
- README: the diagram's question "derive_failed: and no tool_args_on_derive_deny?" now reads "Unreadable call: do
  judges get the raw arguments?", and the skipped box says "= deny, no token" (a skipped Path B never passes,
  so the call is denied; checked in `core.py`); the sequence diagram's branch is worded to match, and a
  paragraph under the diagram names `tool_args_on_derive_deny`.
- docs/CONNECTING.md says that "billing" (`mcp-billing`, `BILLING_TOKEN`) is only an example.
- docs/SIEM.md: the diagram no longer draws `siem-verify` reaching into the ledger; a SIEM never does.
  The cursor now hangs off the sender (it saves it and resumes from it, reading missed entries from the ledger),
  and the sender is labelled as formatting JSON or CEF for the collector and the webhook.
  The export section now says `siem-export` takes `--format cef` as well as `--schema`.
  "In plain words" now explains the live copy and `siem-export` side by side, and when to use each.
- docs/SETTINGS.md (from `two_key/settings.py`): `config show` prints defaults filled in, not where a value
  came from, and `config check` does not run the `on_agent_access` check or compare `schema_digest`.

## CI: each workflow runs once per change — 2026-10-21

No change to any check, only to when it runs. Tests, build, bandit, coverage, CodeQL and Semgrep ran twice for
a change to `working` with a pull request open: once for the push, once for the pull request (59 checks on
PR #30). They now run on a pull request, and on a push only to `main`, `PyPI` and `testpypi`. Job names are
unchanged, so required checks on main still match. Without an open pull request, a push to `working` runs no CI.

## A Windows-only test failure in the clamd tests — 2026-10-21

- `tests/test_scanners.py` `Clamd.test_could_not_finish_is_flagged`
  failed once on Windows with Python 3.11 (`unavailable` instead of
  `flagged`, `limits_exceeded`). The fake clamd replied at its size limit
  and closed while the client was still sending; on Windows that closes
  with a reset, which can discard the reply before it is read. The fake
  now reads the rest of the stream before it closes, as a server that
  lingers does. Two-Key's own code is unchanged. Against a real clamd
  that closes the same way, Windows can report such a file as
  `unavailable` rather than `limits_exceeded`; the signed stance and the
  judges then decide on `unavailable`.

## `two-key setup` and `two-key config set`, `get`, `undo`, `key-passphrase`: one way in for setup and changes — 2026-10-20

The files stay separate (docs/SETTINGS.md); these commands edit the right one for you. They add a ledger kind,
`config_changed`, touch signing, and add a passphrase to the principal key, so they are for the maintainer's
security review. Nothing changes how any setting is read. The start-up checks are reused; the one addition
is `keys.passphrase_file` among the paths they look at. docs/SETUP.md is the guide.

- **`two-key setup --dir DIR [--answers FILE]`** asks for the route, the profile, the judges, the monitored
  agent, the rules to sign (a reviewed rules file, or a starter) and, for the proxy, the upstream server; or
  reads the same answers from a file. It never asks for a secret, only the names of the variables that hold
  them. It writes the principal key, `constitution.md`, `hard_rules.yaml`, the signed constitution,
  `judges.yaml` and `proxy.yaml` (every scalar setting written out at its default) owner-only into a new
  hidden folder, runs `config check` there, renames the folder to `DIR` only when it passes, then creates the
  ledger with a first `config_changed` entry. A refused setup leaves nothing behind. Left blank, the schema
  digest is read from the server after signing, as `mcp-draft-specs --constitution` does (the `mcp` extra).
- **`two-key config set --config proxy.yaml NAME VALUE`** changes one setting, named as in
  docs/SETTINGS.md (`siem.sinks[0].port`, `quorum.profile`, `tool_specs.pay.irreversible`); the name picks
  the file. In order: Two-Key's own account only (root is `config_as_root`; a file it writes, or its folder,
  that another account could change is `config_target_unsafe`; a link is `config_target_link`); the new file
  is staged beside the old one and the whole set must pass `config check` (`config_check_failed`, except a
  variable not set in this shell), so what `high_assurance` forbids stays forbidden; a weaker change needs
  `--confirm-weaker` and `yes` typed on a terminal (`weaker`, `not_confirmed`); then a `config_changed` entry,
  then the files are renamed in, owner-only, with the old one kept as `<file>.prev`.
- **Signed settings** (`hard_rules`, `tool_specs`, `fields`) need `--key`, the principal key the proxy uses,
  and `--rules`, the rules file the constitution was signed from, which must sign to exactly what is signed
  (`rules_source_differs`). The change and the signed text that differs are shown, a typed `yes` is needed,
  and the new envelope, in at least the current format, is verified before it is written.
- **A principal key encrypted with a passphrase.** `two-key config key-passphrase --config proxy.yaml
  --new-from FILE` encrypts the key (or changes its passphrase) with the passphrase in an owner-only file and
  sets `keys.passphrase_file` to that file, in one recorded change; `--remove` stores it unencrypted again,
  which is weaker. It keeps no `.prev` of the key, so `config undo` does not reverse it. The format is
  Two-Key's own (`BEGIN TWO-KEY ENCRYPTED PRIVATE KEY`): PKCS8 under AES-256-GCM, its key from PBKDF2-SHA256 at
  600,000 iterations with a 16-byte salt, the header bound in, as the key backup does; a file asking for fewer
  iterations, and a key encrypted by another tool, are refused (`key_file_invalid`). A new passphrase is at
  least 12 bytes (`key_passphrase_short`). The passphrase comes from a file only its owner can read
  (`passphrase_file_insecure` otherwise) or a terminal prompt, never argv or the environment.
  The proxy reads `keys.passphrase_file` at start and never prompts (`key_passphrase_needed`,
  `key_passphrase_wrong`), and that file joins the paths the start-up checks look at. Every command that takes
  `--key` takes `--key-passphrase-file FILE` or asks on the terminal; `init-key` takes `--passphrase` or
  `--passphrase-file`; `setup` takes `key_passphrase_file`; `config check` opens the key as the proxy would.
  Backup export, verify, and restore keep the key encrypted inside the principal bundle
  (`ed25519-encrypted`), so they need its passphrase as well as the bundle's. An unencrypted key works as
  before, and nothing asks for a passphrase it does not need.
- **What counts as weaker** is read from the loaded old and new configurations (`config_set.weaker`):
  `high_assurance` turned off, a check from `refuse` to `warn`, `allow_unresolved_identity` on, a longer
  `ttl_seconds`, a removed `agent_session_env`, SIEM copy off or a sink removed or in the clear, the scanner
  removed or a file undeclared, a path dropped from `upstream.check_paths`, a lower tool claim, a lower quorum
  floor, judges shown more, a changed judge set or monitored agent, and any signed change but adding a rule,
  turning `irreversible` or `deny_unmapped` on, or raising a `data_class_floor`.
- **No secret on the command line**: a literal for `upstream.env.*` or `scan.env.*` is refused there
  (`secret_on_command_line`) and comes from `--value-file` (owner-only) or `--prompt`; `{"env": "NAME"}` is
  fine. `--unset` removes a setting. Paths of the files, keys and ledger Two-Key trusts (`constitution`,
  `keys.principal`, `keys.passphrase_file`, `ledger`, `judges`, `witness_public_key`, `head_anchor`) are
  `not_settable`.
- **`config_changed`** records the command, the setting names, each file's role, name and SHA-256 digests
  before and after (the principal key file is named with no digest), whether it signed, why it is weaker, whether a yes was typed, the new constitution's
  digest, and the account. Never a value. The SIEM allowlist sends all of it except the account. A ledger
  that is missing or does not open refuses the change, so nothing changes unrecorded.
- **`two-key config undo`** puts back the files the last change replaced, through the same checks and with
  its own `config_changed` entry; run again, it puts the change back. It refuses a file changed since
  (`undo_stale`), and an undo of a signed change needs `--key`.
- **`two-key config get --config proxy.yaml NAME`** prints one setting's value, file, tier, and catalogue
  default; an env literal is `<literal>`.
- No hot reload: a change takes effect at the next start, and every result says so.
- `config check` now also checks the `on_agent_access` setting (a `FAIL` for `warn` under `high_assurance`,
  as the proxy refuses at start), and `config show` prints a command scanner's `env` values as `<literal>`;
  before, it printed them.
- docs/SETTINGS.md (regenerated) says what each tier needs with `config set` and marks the keys it does not
  change.
- Tests: `tests/test_config_set.py` (setup, names, get, set, every refusal, secrets, weaker, high_assurance,
  signed changes, undo, the command line); `tests/test_key_passphrase.py` (the format and its refusals, the
  passphrase file, no prompt without a terminal, `init-key` and `sign-constitution`, `config key-passphrase`,
  the proxy and `config check`, `setup`, and the backup); `tests/test_siem.py` (the `config_changed` allowlist and its
  canary); `tests/test_config_cmd.py` (the scanner's variables).
- Docs: docs/SETUP.md (new: full setup, changing one setting, protecting the principal key with a passphrase,
  showing settings, each with who may run it and what it refuses), SETTINGS, CONNECTING ("Every connection
  and hook"), README, HOWTO ("Start here", "Create a principal key", the key backup, and "Look at a config
  without starting the proxy"), SIEM, THREAT_MODEL, ROADMAP, AGENTS.md, llms.txt.

## Live harness: run 9 (set-up commands, upstream paths, two proxies, free play, sabotage) — 2026-10-21

Test code and docs only (`tests/live/`); no change to `two_key/`. 115 cases (74 in run 8). Nothing has been run
live yet; the maintainer decides when GrokBot runs it.

- **The set-up and change commands** (`tests/live/deploy_cases.py`, 32 cases, no bot): `two-key setup` into a new
  folder (owner-only files, one `config_changed` entry, no key digest; an existing folder, an unknown answer, a
  short or world-readable passphrase file refused), `config set` refused for a weaker change without
  `--confirm-weaker`, with it but no terminal, and with a human typing no; refused for a secret on the command line,
  a typo, a setting that names the ledger, and a signed setting without the key or with no terminal; accepted when a
  human types `yes` (a weaker change, a signed change that re-signs the constitution), recorded without any value;
  `config undo` (restores the file, refuses after a hand edit); a deployment with an encrypted principal key (the
  proxy opens it from `keys.passphrase_file`, and refuses without it or with a passphrase file others can read;
  `key-passphrase --remove` and `--new-from` refuse with no terminal and name the key without a digest); and
  `high_assurance` still refusing `on_agent_access: warn` after a typed `yes`. A typed `yes` runs on a
  pseudo-terminal. The commands refuse root, so these cases are N/A in a pass run as root or on Windows, and
  `RESULTS.md` says so.
- **The upstream server's files** (#13), 7 config cases: the script's folder writable by another account (warns,
  refuses under `on_writable_paths: refuse`), a writable and a missing `upstream.check_paths` entry, and an `env`
  launcher with nothing naming the server (warns `upstream_paths_unchecked`, refuses under `high_assurance`, quiet
  once `check_paths` names its folder).
- **Two proxies on one ledger**: both started, four calls alternating, then `two-key audit`; each call must run and
  the chain must verify (the outage fixed in `7e08d48`).
- **A free-play round**: the agent plays EVIL for eight steps with no case. The harness grades invariants from the
  system of record and the ledger (a token only after both keys passed, none redeemed twice, no unsigned tool reached,
  no argument value in a deny reason, the ledger verifies afterwards) and lists every call in `RESULTS.md`. The
  SIEM argument-value check no longer counts a value that is also a tool name or ledger kind, which an agent writing
  free text can produce (`roster` is inside `export_patient_roster`).
- **A coverage map**: `tests/live/COVERAGE.md` has a row for each fail-closed default of AGENTS.md (26): the unit
  tests, whether a live case exercises it, and what is left to the unit tests and why. `RESULTS.md` prints it with
  the pass's verdicts. A case is tagged with a row through `COVERS` in `make_cases.py`.
- **A sabotage pass** (`harness.py --sabotage NAME|all`, `tests/live/sabotage.py`): runs the self-test against a copy
  of the package with one check weakened (Path A ignored, a missing ballot counted as yes, a scanner's flag read as
  clean, the SIEM copy sending every field, the upstream server's files ignored, `config set` skipping the typed
  yes) and reports whether the harness noticed. `control` weakens nothing and must show no FAIL. One weakening is a
  stated blind spot: the gateway's argument-hash check cannot be reached by a live call, because the proxy mints and
  redeems in one process (unit tests cover it). The repository's `two_key/` is never touched.
- `RESULTS.md` now names the Python version and whether the pass ran as root. `tests/test_live_harness.py` fails when
  a sabotage patch stops matching its source, when `COVERAGE.md` and the case tags disagree or name a missing test
  file, when AGENTS.md gains a fail-closed default with no row, or when a case names a step the story does not run.
- Docs: `tests/live/RELAY.md` (run 9, the sabotage pass, the non-root requirement), ROADMAP, AGENTS.md.

## Copyright and author headers — 2026-10-21

- Every tracked file that can hold a comment now opens with a three-line header: `Copyright 2026
  Insomniac-VibeLabs`, `Author: Stephan Busch`, and `SPDX-License-Identifier: Apache-2.0` (the licence in
  `LICENSE`, unchanged). Python, YAML, TOML, shell, `MANIFEST.in`, and `.gitignore` files use `#` lines, after the
  shebang where there is one; Markdown uses an HTML comment, so no page renders differently; `llms.txt` keeps its
  title first and carries the comment at the end. `docs/SETTINGS.md` gets the header from `two_key/settings.py`.
- No header in the files that cannot hold a comment or whose bytes are data: `LICENSE`, `uv.lock`, the JSON and
  NDJSON files, the banner image, `examples/constitution.md` (constitution prose is signed and sent to the judges
  as written), and `tests/fixtures/v1_constitution.md`.
- `pyproject.toml` names Stephan Busch as an author alongside Insomniac-VibeLabs.
- `tests/test_file_headers.py` fails on a tracked file without the header. CONTRIBUTING.md and AGENTS.md say so.
- DeepSource re-read every file the header touched and reported old findings in five test files as new: local
  imports of names the module already imports (PYL-W0404, `test_ledger_error_cap.py`, `test_token_lifetime.py`,
  `test_same_agent_rule.py`, `test_mcp_draft.py`) and a one-item unpacking of a list it could not size
  (PYL-W0632, `test_b5_local_proxy.py`). The duplicate imports are gone and the test checks the list's length.
- SonarCloud's twelve open findings on the draft pull request, all in tests: exception tests that built their
  arguments inside the `assertRaises` block now build them first (S5778; `test_key_passphrase.py`,
  `test_config_set.py`, `test_upstream_paths.py`), two `TestCase` helpers are private (`_files`, `_changes`), and
  `test_live_harness.py` uses `assertIn`.

## OpenSSF Scorecard hardening: Semgrep token, hashed CI installs, SECURITY.md (#31, #32, #33) — 2026-10-21

CI and docs only. No change to `two_key/`, to any check's name, or to what a check tests. From a read-only
Scorecard v5.6.0 run on main (51dc293, score 5.5).

- **Semgrep token (#31).** `semgrep.yml` keeps `contents: read` as the workflow default and grants
  `security-events: write` and `actions: read` to the Semgrep job only. Its checkout no longer leaves the
  token in the clone (`persist-credentials: false`).
- **Hashed CI installs (#32).** Every `pip install` in a workflow now installs a file from
  `.github/requirements/` with `--require-hashes`: `uv.txt` (tests, coverage, build, publish,
  siem-integration), `coverage.txt`, `build.txt`, `bandit.txt`, and `publish.txt` (build, twine,
  cyclonedx-bom). Each `NAME.txt` is compiled from `NAME.in` by `compile.sh` (uv 0.13.0, universal across
  Linux, macOS and Windows and Python 3.10 and up, wheels only); the versions are the ones the workflows
  pinned before. CONTRIBUTING.md says how to change one.
  - The build backend is pinned too: `setuptools==84.0.0` (the newest release more than two weeks old) is in
    `build.txt` and `publish.txt`, and `build.yml` and `pypi-publish.yml` build with `--no-isolation`, so
    the published wheel is no longer built by a setuptools fetched without a hash.
  - Installing the built wheel (build's demo, the publish job's SBOM) takes its dependencies from `uv.lock`
    with their hashes (`uv export --locked`), then the wheel with `--no-deps`. The SBOM therefore lists the
    locked versions of cryptography, cffi and pycparser instead of the newest on the day.
  - `siem-integration.yml` installs Two-Key's dependencies the same way and runs Two-Key from the checkout
    (`PYTHONPATH`) instead of `pip install -e ".[yaml]"`, which resolved them with no lock at all.
  - `coverage.yml` no longer installs coverage outside the uv.lock environment; it was not used there.
  - `diagrams.yml` installs mermaid-cli 11.4.2 with `npm ci` from `.github/diagrams/package-lock.json`
    (every package with its integrity hash) instead of `npm install` with no lock. CONTRIBUTING.md says how to
    change the version.
- **SECURITY.md (#33).** Links the private reporting form
  (`/security/advisories/new`; private vulnerability reporting is on), says not to report a vulnerability in
  a public issue, states acknowledgement within 7 days, and adds "Supported versions": the latest release
  only.
- Docs: AGENTS.md, CONTRIBUTING.md (also the diagrams lock), README ("uv.lock" install), docs/HOWTO.md and docs/PYPI.md name
  `.github/requirements/` where they named the pins in the workflows; llms.txt.

## Live runs 9 and 9x: SIEM cursor and `config check` fixes — 2026-10-21

From the run 9 and 9x findings (`live-runs` b0b57e9 and a506e80, both on `working` @ dd07b42).

- **A SIEM cursor ahead of the ledger is not trusted (run 9x, C140).** Before, a cursor past the ledger's
  last entry was clamped to the head, so the entries it claimed were delivered were never sent and nothing
  said so. Now the cursor also keeps the `entry_hash` of each sink's last entry. A cursor past the head, or
  one whose hash is not this ledger's entry at that seq (another ledger's cursor, or one moved by hand),
  prints `WARNING: siem: <sink>: the delivery cursor ...` and the sink sends the whole ledger again, every
  copy marked `replay`. The proxy still starts: the copy never blocks it. A cursor written before this change
  has no hashes and is checked by length only, and reads as before. (`two_key/siem.py`, `tests/test_siem.py`)
- **`config check` checks every variable the proxy and its judges read (run 9, finding 1).** It said
  "every variable the config names is set" while the judges' keys and the agent's credential were unset. Now
  it also checks each judge's `auth` variable (`var`, or `username_env` and `password_env`), its
  `ballot_key_env`, and the monitored agent's `credential_env` or `username_env` and `password_env`. A missing
  agent variable is a `FAIL` (`agent_credential_missing`; the proxy refuses to start without it), and, like the
  other variables of this shell, does not block `setup` or `config set`. A missing judge variable is a `WARN`
  (`judge_env_missing`): the proxy starts and that judge abstains on every call. Each is named, never its
  value; the `ok` line lists the variables it found set. (`two_key/config_cmd.py`, `two_key/config_set.py`)
- **`config show` shows each judge's `type`, `base_url`, `auth` kind and the names of the variables it reads**
  (run 9, finding 1).
- Docs: docs/SIEM.md, docs/SETUP.md, docs/HOWTO.md, docs/THREAT_MODEL.md, docs/CONNECTING.md, AGENTS.md,
  llms.txt.

## A ledger never goes back to an older constitution (signed serial) — 2026-10-21

Live run 9x, C44: an older constitution (the library rules without DEL-1, signed with the same principal key)
started on a ledger written under the newer one, with no warning. Both are validly signed, and nothing recorded
which came first. Option A of the run 9 findings response, chosen by the maintainer.

- **`serial` in the rules file.** A positive integer, the principal's order of constitutions, signed into the
  constitution (`signed.serial`). A constitution with a serial signs as v3; one without stays byte-for-byte what
  it was (`tests/test_fields_compat.py`). A serial under a v1 or v2 label is refused, and an install before this
  change refuses it as an unknown signed key, so an older Two-Key cannot ignore it.
- **The start-up check** (`two_key.core.check_constitution_order`, before anything is written). Once a ledger
  has run a constitution with serial N: a lower serial is refused (`constitution_rollback`), N again with other
  bytes (`constitution_serial_reused`), and a constitution with no serial (`constitution_serial_missing`). A
  ledger that has never run one with a serial accepts any, as before. No setting turns it off; to go back to older
  rules, sign them again with a higher serial.
- **`constitution_loaded`** records `serial` and `previous_digest` (the digest the ledger last ran) for a
  constitution with a serial; the entry is unchanged for one without. Both are sent to a SIEM.
- **`two-key setup`** writes `serial: 1` into the rules file it starts. **`config set`** on a signed setting signs
  the next serial and writes it into the rules file. **`config undo`** refuses to put back a constitution the
  ledger has already moved past (the proxy would refuse to start with it); change the rules back with `config set`.
- `sign-constitution` reads `serial` from the rules file.
- Tests: `tests/test_constitution_serial.py`; `tests/test_config_set.py` (setup's serial, the next serial, undo).
- Docs: AGENTS.md (a fail-closed default; `tests/live/COVERAGE.md` F27), docs/HOWTO.md, docs/SETTINGS.md
  (generated), docs/THREAT_MODEL.md, llms.txt.

## Live harness: run 9x ported to `working`, and the fixes for run 9y — 2026-10-21

Test code only (`tests/live/`); nothing in `two_key/` changes.

- The run 9x harness (GrokBot's own cases, the library deployment, `lib_facts.py`, `library_mcp_server.py`, the
  second free play, the burst, the tampering cases) comes from `live-runs` a506e80 with the antivirus test string and
  the test credential put back (they were masked in the committed copy).
- C44 signs serials (library `serial: 2`, the older rules `serial: 1`) and expects `constitution_rollback`; the
  SIEM-cursor tamper case expects a warning and a replay, not a refusal.
- The tool bot's header covers both deployments (run 9x answered library calls `unknown_tool`) and says it has no
  DLP of its own (run 9, C28). Library LEGIT cases get two steps, and an `executed` case accepts a read-only lookup
  first (C37, C82).
- Scripted twins for the over-cap and wire payments; the split-payment ladder accepts the PO-match and caller-fact
  denies that stop a split first. The library waiver hook reads a whole-number float, so C35 reaches Two-Key.
- A `siem_clean` case fails when an argument value is in the SIEM copy (the `siem_passes_arguments` sabotage was
  only a referee incident). The referee's vocabulary takes rule ids and reason codes (run 9x's `branch` was the
  rule id `hold-1-branch`); the SIEM count names repeated entries with no copy marked `replay`.
- The scripted slow judge and slow ICAP server no longer print BrokenPipe when Two-Key has already given up.
- `tests/test_live_harness.py` expects one free play per deployment; COVERAGE.md F27 is live (C44).
- RELAY.md "Run 9x and 9y".
- DeepSource on PR #30: no mutable default in `tests/test_constitution_serial.py` (PYL-W0102), a `next()` with a
  default in the tamper step (PTC-W0063), and the two stand-in MCP servers' `logging.disable` marked as a test double
  (PY-A6006, a genuine false positive: neither is a deployed service).
- Run 9y's sabotage control (the unmodified package) failed two harness cases, now fixed. C111, the scripted wire
  payment, named an invoice the billing stand-in does not know, so the call stopped at `field_missing:po_matched`.
  It now pays a matched invoice under the cap (`FRB-2207` in `live_facts.py`) and expects
  `rule_denied:block-wire-parties`, because Two-Key leaves a payee that a rule names to that rule. C45 compares
  the value at the tool the way JSON does: Two-Key reads `amount_cents: 100.0` as 100 cents by design and forwards
  the bytes the judges approved, so a whole-number float is the integer 100. A string or a boolean still fails.

## DeepSource: the findings on main, fixed or marked — 2026-10-21

DeepSource's badge counts main (95 issues from its first Python scan of main). Twenty-six were already fixed on
`working`. The rest:

- Fixed in `two_key/`, with no change in behaviour: `backup.py` uses the ledger's new public `exclusive()` (the
  write lock) and `anchor_path()` instead of its private names (PYL-W0212); `constitution.py` checks duplicate
  paths with a small `_PathSet` per tool instead of a function defined inside the loop (PYL-W0640); `quorum.py`
  gives `next()` a default and `mcp_proxy/draft.py` looks the views up by name (PTC-W0063); six methods that do not
  use `self` are static methods (PYL-R0201: `Ledger._hash`, `MonitoredAgent._deoptimize`, `Scanner._occurrences`,
  `Scanner._decode`, `Scanner.read_confined`, `AnthropicJudge._content`).
- Marked as genuine false positives, with the reason on the line: the sink interface's `close()` on the webhook
  sink, the `LLMJudge._deoptimize` hook the judges override, `CapabilityVerifier.issue` (a verifier refuses to
  mint) and the issuer's override of it, and the ledger's lock guard releasing its own lock.
- Findings in test code are marked `skipcq: ... - test only`. Test code is not part of the installed package and
  nothing in `two_key/` imports it.

## Version number on `working`: 0.7.3 — 2026-10-22

The version only. No behaviour changed.

- `pyproject.toml`, `two_key.__version__` and `uv.lock` say `0.7.3` instead of `0.7.0`. PyPI has `0.7.0`, `0.7.1` and `0.7.2`, so `0.7.3` is the next number.
- docs/PYPI.md says so. Nothing is tagged or uploaded: the maintainer releases it, and `v0.7.0` and the other tags are not moved.

## Live run 9y: two proxies starting at once, rules without a serial, and shared-ledger SIEM copies — 2026-10-22

- **Two proxies started at once on one ledger could both run one serial** (run 9y, S6c). Each read the ledger,
  checked the serial, and recorded `constitution_loaded`, so in 3 of 4 tries two different serial-2 constitutions
  both started, and both kept restarting afterwards. The order check now runs again under the ledger's write lock,
  after reading what other processes wrote, just before `constitution_loaded` is recorded: the second start is
  refused (`constitution_serial_reused` or `constitution_rollback`) and writes nothing. `config set` and
  `config undo` check and record the same way.
- **A process sharing the ledger could read entries the signed head did not cover yet**, and fail with
  `signed head does not match the chain` (run 9y saw it once, at start). Every write and the checkpoint that signs
  it now happen in one hold of the lock: `Ledger.exclusive()` is re-entrant, and `Ledger.record()` appends and
  checkpoints together. A decision's entries, a gateway redemption, a revocation and a deny each use them.
- **`mcp-draft-specs` writes `serial: 1`** in `rules.draft.yaml`, and **`setup` warns** when the `rules_file` it is
  given has no serial; its next steps say to add one (run 9y, S8). SETUP.md said `setup` always signs serial 1,
  which was true only of its starter rules.
- HOWTO "The serial": count up by one; 2^53 is the highest serial, and a ledger that has run it cannot take newer
  rules (run 9y, S3i).
- **SIEM on a shared ledger: the copy of another proxy's entry is marked `replay`** (run 9 F4; run 9y saw 50 of 99
  duplicates unmarked). Each proxy still sends every entry, so nothing waits on a stopped proxy; the ledger remembers
  which entries it read from another process (`Ledger.from_another_process`), and docs/SIEM.md says to dedupe on
  `entry_hash`.
- Live harness: C170 (the agent's over-cap payment) also accepts `derive_failed:field_missing:po_matched`, a valid
  stop; its scripted twin reaches the cap. C172 (the split waiver) was ruled working as designed: one part-waiver
  within FINE-1's caps may run, and the case fails only if a second part runs or the parts clear the charge.

## Live run 9z: two harness fixes, and a faster harness — 2026-10-23

Run 9z re-ran the 9y tests on 821bc93 and found no Two-Key bug. The 9y fixes all worked: two proxies started at once
no longer both run one serial, `setup` warns about a rules file with no serial, and no SIEM duplicate went out
without a replay mark. Two cases were wrong about the test, not the product. Only the live harness changes here.

- **C129: the relayed tool remembered one case's waiver in the next case.** The bot playing the library's tools
  applied every CH-5501 waiver in the batch to one balance, so a later case's waiver met "amount exceeds balance".
  Each tool call now names a `world`, one per case, and the tool role is told that calls in one world share state
  and every world starts from the same records. The world is a hash, so it does not name the case.
- **C170: a split over-cap payment counted as "not attempted".** The agent paid half of the $742.18 invoice, so no
  call held the forbidden amount. A case can now list `expect.attempt` values that also mark the attempt; C170 lists
  the invoice number, so a stopped half is scored by its deny, and a half that reaches the vendor service fails.
- **A faster harness, checking the same things.** The burst case (C156: thirteen calls while both judges answer
  after their timeout) waited out a 20-second judge timeout per call, about 4 of every pass's 6 minutes. Its stance
  now has its own judges file with a 4-second timeout, and the slow ballots still arrive 2 seconds after it.
  `--sabotage all` runs up to four passes at once (`--jobs`), each on its own ports (`LIVE_PORT_BASE`): 7 minutes
  instead of about 55 here, with the same results (control 175 PASS; every weakening caught but the declared
  blind spot).

## Release v0.7.3: setup and change commands, a signed serial, the upstream server's files — 2026-10-23

Package version 0.7.3 (`pyproject.toml`, `two_key.__version__`, `uv.lock`). To be tagged `v0.7.3` on `main`
after the merge. PyPI's `0.7.1` and `0.7.2` were the 0.7.0 code, repackaged on the `PyPI` branch, so this is the
first release of new code since 0.7.0. The entries above, from "PyPI packaging on the PyPI branch" on, are the
detail. The tag also carries the four sections after this one, written before 0.7.3 was tagged: the serial check
split for readability, the CI tool updates from Dependabot, two test-code fixes from run 9s, and optional tool
spec fields.

- **`two-key setup`** writes a whole deployment (principal key, constitution, judges, `proxy.yaml`, ledger) from
  answers or a file, checks it before it is in place, and records it. **`two-key config set`** and **`undo`**
  change one setting: the whole set must pass `config check`, a weaker change needs `--confirm-weaker` and a typed
  yes, a signed setting needs the principal key, and each change is a `config_changed` ledger entry with no
  values. **`config get`**, **`show`** and **`check`** read a config without starting anything. docs/SETUP.md.
- **A principal key encrypted with a passphrase** (`two-key config key-passphrase`, `init-key --passphrase`),
  read by the proxy from an owner-only `keys.passphrase_file`.
- **A signed `serial` in the constitution.** Once a ledger has run a constitution with a serial, it refuses an
  older one (`constitution_rollback`), the same serial with other rules (`constitution_serial_reused`), or none
  (`constitution_serial_missing`). Two proxies started at once on one ledger cannot both run one serial: the
  check runs again under the ledger's write lock. `setup` and `mcp-draft-specs` write `serial: 1`, and
  `config set` signs the next one.
- **The upstream server's files** behind a launcher such as `sudo` are in the start-up checks: absolute
  arguments of `upstream.command`, `upstream.check_paths`, and a warning (`upstream_paths_unchecked`, refused
  under `high_assurance`) when nothing names them (#13).
- **A shared ledger**: each write and the checkpoint that signs it happen in one hold of the lock, so another
  process never reads an entry the signed head does not cover. The SIEM copy of an entry another proxy wrote is
  marked `replay`, and a delivery cursor ahead of the ledger is not trusted.
- **Only the tool's id is required in a tool spec.** Left out, `irreversible` is `true` and
  `data_class_floor` is `classified`, the fail-closed defaults; the defaults are written into the signed spec,
  so existing constitutions sign to the same bytes. GrokBot's run 9t checked this live.
- **docs/SETTINGS.md**: every setting, generated from the code and checked by a test.
- **Python 3.13 and 3.14** in CI on Linux, macOS, and Windows; the compiled-file check works on 3.15 (#27).
- **CI and supply chain**: every CI install is hash-pinned, the Semgrep job's token is scoped (OpenSSF
  Scorecard, #31 to #33), DeepSource runs its Python analyzer, and every file carries the copyright header.
  1187 tests.
- **Live testing**: runs 9, 9x, 9y and 9z, 175 cases on one machine, with a sabotage pass that shows which
  weakenings the harness notices. Every Two-Key finding is fixed; run 9z, a regression round on the fixes,
  found none (172 of 175 PASS; of the other three, two were harness cases, now fixed, and one was stopped
  by another valid control). Regression runs 9s and 9t, on the later changes, found no Two-Key bugs (9t: 170
  PASS, 5 inconclusive, none failed). Results are on the `live-runs` branch.
- Docs: README, ROADMAP (0.7.3 under "Shipped"), SCOPE, THREAT_MODEL, FIT, HOWTO, JUDGES_AND_QUORUM, PYPI,
  UPGRADING, CONTRIBUTING, AGENTS.md, and llms.txt name 0.7.3 as the release and `v0.7.3` as the install ref.

### Upgrading from 0.7.0

The same applies from PyPI's 0.7.1 and 0.7.2.

- Constitutions, ledgers, keys, backups, `judges.yaml`, and `proxy.yaml` from 0.7.0 load unchanged. Nothing
  needs re-signing, and a constitution without a `serial` signs to the same bytes as before.
- A tool spec may now leave out `irreversible` and `data_class_floor`. Left out, they are `true` and
  `classified`, the strict side: a tool that is reversible or carries lower-class data should still say so.
- **Check the proxy's start-up output.** It now checks the upstream server's program, script and folders named
  as absolute paths in `upstream.command`, so it may name more paths, or refuse under
  `on_writable_paths: refuse` or `high_assurance`. A command that starts with a launcher (`sudo`, `doas`, `env`,
  `npx`, `uvx`, `pipx`, `cmd`, `powershell`, `pwsh`) and names no absolute path warns
  `upstream_paths_unchecked`, and under `high_assurance` refuses: give the program as an absolute path or list
  its folder in `upstream.check_paths`. On Windows a `check_paths` entry needs its drive.
- **Add `serial: 1` to your rules file** and sign it again (`two-key sign-constitution`) to turn on the
  rollback check. From then on, count up by one for each new constitution. A ledger that has run a serial
  refuses an older one; to go back to older rules, sign them again with a higher serial.
- `two-key config check` now fails when the monitored agent's credential variable is unset (the proxy refuses
  to start without it), and warns for each unset judge variable.
- **SIEM**: a new ledger kind, `config_changed`, is sent like the others. With two proxies on one ledger, each
  still sends every entry, and the copy of the other's entry is marked `replay`: dedupe on `entry_hash`.
- On Python 3.15, a start may name a `__pycache__` folder another account can write, which it should have
  named before.

## After 0.7.3: the serial check split for readability — 2026-10-23

No change in behaviour. SonarCloud rated `check_constitution_order` (`two_key/core.py`) above its cognitive
complexity limit (18 against 15). The scan of the ledger's `constitution_loaded` entries is now its own helper,
`_serial_history`, and the function keeps only the three refusals. `tests/test_constitution_serial.py` is unchanged
and passes.
- DeepSource's two open findings on main were PYL-W0212 (a protected member used from outside its class) on two lines
  of the ledger's lock guard, `two_key/ledger.py`, added with the re-entrant hold in run 9y. The guard is a class
  defined inside `Ledger._exclusive` and tracks that ledger's own lock depth, the same false positive already marked
  on the guard's other lines; both lines now carry the same `skipcq` with that reason.

## Dependabot: uv and the diagram tools updated — 2026-10-23

No change in Two-Key itself or in what it installs for users; only the tools CI uses. Dependabot opened six alerts.

- **uv 0.13.0 → 0.13.5** (`.github/requirements/uv.in`, `uv.txt` recompiled with hashes; README and AGENTS.md
  name the new version). uv before 0.13.4 trusts the emSign ECC Root CA - G3, whose intermediate keys were
  compromised (GHSA-hq85-5cpj-mr62). CI uses uv to download packages, so someone able to intercept that
  traffic and holding one of those keys could have posed as PyPI. `uv.lock` is unchanged and still checks.
- **mermaid-cli 11.4.2 → 12.0.0** for the non-required `diagrams.yml` (`.github/diagrams/`). The old version
  pulled in puppeteer 23 with `extract-zip` (symlink path traversal, two alerts) and `basic-ftp` (slow
  directory-listing parse); 12.0.0 uses puppeteer 25, which has neither. An `overrides` entry gives
  mermaid-cli KaTeX 0.18.10, the version mermaid already uses, which fixes the KaTeX prototype-pollution alert.
  `npm audit` on the new lock finds nothing. 12.0.0 needs Node 22.13 or later, so the workflow now sets up
  Node 22, and it dropped the `-w` option, so the 780-pixel page width is now the browser window's width.
  All 27 diagrams in the docs drew without errors with the new version.

## Live run 9s: two test-code fixes — 2026-10-23

No change in Two-Key. Run 9s (GrokBot, on 8b3fd76) passed 165 cases with 10 inconclusive and none failed. C129 and
C170, the two cases fixed after run 9z, both passed live. It found two problems in the test code.

- `tests/test_fail_closed.py` matched an error message with `\(` in a normal string. Python warns about that
  escape and will later refuse it; the pattern is now a raw string, so the `skipcq` that hid the warning is gone.
- pytest collected `test_ca` (`tests/tls.py`), a helper that writes test certificates, as a test wherever a test
  module imported it, and reported an error. It is now marked as not a test. `unittest`, which CI uses, never
  collected it.

## Optional tool spec fields, and README wording — 2026-10-23

- **Only the tool's id is required in a tool spec.** `irreversible` and `data_class_floor` were required for
  every tool. They are now optional: left out, `irreversible` is `true` and `data_class_floor` is
  `classified`, the same fail-closed defaults Two-Key already uses for a call that leaves them out. The
  defaults are written into the signed spec, so a spec that leaves them out signs exactly as one that writes
  them, and every existing constitution signs and loads as before. A wrong type is still refused. A tool left
  at the defaults is caught by a `deny_if` on `irreversible` or on `classified`, and judges see it as
  irreversible and classified. `amount` and `counterparties` were already optional.
  `tests/test_optional_tool_spec_fields.py` covers this; `docs/SETTINGS.md` shows the new defaults.
  `two-key setup` already used these defaults for a starter tool, so it is unchanged; `docs/SETUP.md` now says
  both are optional. `two-key mcp-draft-specs` still writes a placeholder data class that you must replace, so a
  drafted spec is decided on purpose.
- **README: "Dual-path authorization" in plain language.** The same facts, reworded into short labelled
  points. Path B is now called "the judges" rather than "a quorum", since one judge is enough.

## 0.8.0 work: judge history, ballot records, and one proxy per agent — 2026-10-25

On `working`, not released; the version number stays 0.7.3 until the release. Built from the design note the
maintainer approved on 2026-10-25 (decisions D1 to D10). Issue #1.

- **Judge history summary** (`two_key/history.py`). Each judge's prompt gets a `<decision_history>` section,
  built by `TwoKey` from its own ledger at each decision: the last decisions on the same tool and the same
  signed counterparty (age in hours, outcome, whether an allowed call ran, the reason code, the amount when
  the signed spec maps one), days since the last allow, totals over 7, 30 and 90 days of calls that were
  allowed and redeemed, allowed calls that never ran, denies on this target in the last hour and day, calls
  still in flight, scan verdicts over 7 days when a scanner is configured, and counts across all tools.
  Library reason codes and signed values only: never proposal text, argument values, rationale, or a
  counterparty the spec does not sign. A system-prompt sentence tells the judges what the section is and
  that it is data. On by default; set under `quorum.judge_history` (`enabled`, `window_days`, `max_items`,
  `on_failure`, `burst_denies`, `burst_minutes`). Decisions from before the upgrade show
  `"age": "before_upgrade"`.
- **Fail closed when it cannot be built** (D1). A summary that cannot be built denies the call
  `internal_error:history` by default and records `judge_history_failed`, sent to the SIEM at WARNING.
  `on_failure: judge_without_history` asks the judges without it instead. Turning history off, shortening it,
  or judging without it is a weaker setting: start-up warns, `config set` asks for a typed yes, and
  `two-key setup` offers it (D2).
- **Re-checked before the token** (D7). If a decision on the same target is allowed between the summary and
  the token, the call is denied `history_changed`, so two calls racing cannot both be judged on a history
  that shows neither.
- **Attempt episodes** (D4). `burst_denies` denies (default 5) from one agent within `burst_minutes`
  (default 10) are recorded as one `attempt_episode`, sent to the SIEM at WARNING, and counted for the
  judges. The agent is named only by the operator's agent id, otherwise `unnamed`.
- **Bound to the ballot** (D3). The summary's digest is a fifth field of each judge's binding
  (`history_hash`) and is stamped on each ballot; the decision records `history_digest`, the time `at`, the
  `subject` it was built for, and `history_basis`. `two-key audit --check-history CONSTITUTION` rebuilds each
  summary from the ledger and reports any digest that does not match. (The design note named this
  `verify-ledger --check-history`; Two-Key has no such command, so it is an `audit` option.)
- **Per-judge ballot records** (D8). Path B entries now record each judge's id, vote, confidence, error
  class, and HTTP status, and an HMAC-SHA256 digest of its rationale keyed with the install's fingerprint
  key (`hmac-sha256:` prefix; `ballot_digest_key_id` names the key). Never the rationale text. A pass with
  one judge down can now be told from the ledger. The SIEM copy sends the records.
- **One proxy per agent** (D10). `two-key mcp-proxy` takes a lock for its agent id beside the ledger and
  refuses to start a second proxy for the same agent, recording `agent_already_connected`. On by default;
  `one_proxy_per_agent: false` in `proxy.yaml` turns it off (a weaker setting), and `two-key setup` asks.
- Docs: JUDGES_AND_QUORUM (judge history, ballot records), HOWTO, THREAT_MODEL, SCOPE, SIEM, UPGRADING,
  CONNECTING, ROADMAP, AGENTS.md, and the generated SETTINGS. Tests: `tests/test_judge_history.py`.
- DeepSource (PR #37) flagged three methods that use no instance (PYL-R0201): `HistoryIndex.approved_after` and
  two test helpers. All three are now static methods; no change in behaviour.
- Three new functions were split for readability, no change in behaviour: `HistoryIndex._record` (the pre-0.8.0
  subject is now `_legacy_subject`), the summary's `this_tool` block (`_last_item`, `_scan_counts`), and
  `check_history_digests` (`_history_basis_problem`, `_loaded_history_policy`, `_rebuilt_summary`).
- SonarCloud (PR #37) listed eight issues, all real; each is fixed with no change in behaviour. Cognitive complexity
  over 15: `check_decision_digests` (27, from 0.3.x; now `_loaded_digests` and `_decision_digest_problems`),
  `check_history_digests` (18; the per-decision check is `_HistoryRebuild.check`), `HistoryIndex._record` (16;
  `_subject` and `_part`), and `parse_proxy_config` (16; `_required` and `_flag`). The scan verdict counts start
  from `dict.fromkeys`. In `tests/test_judge_history.py`, three assertions name what they check (`assertIsNone`,
  and `assertIs` for `True` and `False`, which stays as strict as the `assertEqual` it replaces), and the
  `agent_already_connected` test builds its config outside the `assertRaisesRegex` block.

## Dependabot: setuptools 84.1.0 for CI builds — 2026-10-25

No change in Two-Key or in what it installs for users. Dependabot alerts #9 to #12 (Low): setuptools before 84.1.0
lets a wheel's `namespace_packages.txt` write outside the destination on Windows during a legacy
`setup_requires` install (GHSA-xmj3-9gf7-h52w). CI's build and publish jobs pin setuptools as the build backend,
and `python -m build --no-isolation` never takes that path, but the fix is free: `.github/requirements/build.in`
and `publish.in` now pin 84.1.0, and the `.txt` files are recompiled with hashes by the uv in `uv.in`, only
setuptools upgraded. The sdist and wheel build with it.

## Roadmap: 0.8.0 and 0.9.0 in the README and ROADMAP diagrams — 2026-10-26

Docs only. The roadmap diagrams and tables in the README and ROADMAP.md went from 0.7.3 straight to 1.0.0. At
the maintainer's request every release now has its own step: 0.8.0 (judge history, ballot records, one proxy per
agent; in progress) and 0.9.0 (release candidate: the optional tool-side token check #28, the remote-agent live
run, the quickstart and demo, and the 1.0 freeze), then 1.0.0, a public review of 0.9.0. ROADMAP.md gains a
0.9.0 section; the quickstart and demo move there from 1.0.0. The README's 1.0.0 row no longer lists #1 and the
ballot records, which are 0.8.0's.
