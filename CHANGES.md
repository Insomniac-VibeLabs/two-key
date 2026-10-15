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
