# Run 8: the SIEM checks done by hand (brief sections 5, 6 and 8)

Date: 2026-10-16 (America/Denver). Library: `working` @ `7e636d3` (0.7.0 SIEM export; `pyproject.toml` says 0.6.0).
Everything listened on 127.0.0.1. Nothing in this folder holds a key, a ledger, a token, or a certificate.

## Section 5: file export and verify (before any other pass rebuilt state/)

- `siem-export --key state/keys/principal.pem --ledger state/ledger --out run8.jsonl`: ok, 310 lines
  (309 events + summary), seq 0..308, ledger_size 309, merkle_root `bfa5d67f…c755`.
  Output: `siem-export_run8.out.json`. File sha256 `a1c1a4f8deca28997df38f032ad88ce1b902e3d5b39f39e7786d84916a4a00ad`
  (kept out of the commit with the ledger it copies).
- `siem-verify … --events run8.jsonl --require-complete`: exit 0, ok, events 309, missing 0, duplicates 0,
  problems []. Output: `siem-verify_run8.out.json`. Re-run after all other checks: same.
- Export over an existing file: exit 1, `{"ok": false, "error": "refusing to overwrite run8.jsonl"}`; file unchanged.
- **One byte flipped: NOT caught.** The brief's byte flip landed in seq 150's `prev` hash and `siem-verify` still
  said ok. `check_event` compares `seq`, `entry_hash`, `kind`, and the allowlisted fields, but none of the envelope
  (`prev`, `severity`, `replay`, `sent_at`). `prev` and `severity` follow from the ledger, so a check is possible.
  The summary line is read but not checked (its `merkle_root`, `count`, and signatures can be changed). Edits to a
  body field, a deleted line, a repeated line, and `ledgered: false` (which skips the line and leaves a gap) are
  caught. Full matrix: `siem-verify_tamper_matrix.txt`. docs/SIEM.md says "an event edited after export … is caught".
  That holds for body fields but not for the envelope.
- Plaintext under high_assurance (`high_assurance_and_writable_checks.py`, real `siem_from_config` sinks):
  syslog udp, syslog tcp, and an `http://` webhook each refused with `siem_plaintext_refused: high_assurance does not
  send the ledger copy in the clear; [...] use syslog over TLS (6514) or an https webhook`. That happens with or
  without the machine's writable-path walk. The default quorum with plaintext udp starts with the warning.
  A refused start wrote nothing past the ledger's own creation entry.

## Section 6: writable paths and sign-constitution --out (by hand)

- `on_writable_paths: refuse` with a world-writable file in `check_paths`: refused (`writable_path: …: writable
  by everyone; on_writable_paths: refuse refuses to start …`). A world-writable folder is refused the same way. An
  owner-only file starts. The default (warn) names the file on stderr and starts.
- high_assurance: a world-writable file is refused (`… high_assurance refuses to start …`).
  `on_writable_paths: warn` under high_assurance is refused outright (`on_writable_paths: high_assurance refuses
  to start when another account can change a path …; remove on_writable_paths: warn`). high_assurance with nothing
  writable started on this box.
- `sign-constitution --out`: a new file is written (mode 644, a temp file renamed into place). A link at the target,
  dangling or pointing at a file, is replaced by a regular file and its target is untouched (no follow).
  **The brief says it "refuses to write over an existing file". It does not:** signing different rules onto an
  existing `--out` replaced it, exit 0. That is the design in `constitution.save_envelope` and CHANGES.md
  ("PR #12 review: SonarCloud findings": "renames it over the target … a failed write keeps the old file").
  So the brief, or the intended behavior, needs a decision.
- Windows access-list check: skipped. No Windows machine was available (the two registered computers were
  offline, and the box is Linux).

## Section 8: Elasticsearch and Kibana 8.15.3

Setup: `docker.io` 26.1.5 and `docker-compose` 2.26.1 from Debian (sudo apt). `dockerd` started by hand (the box has
no systemd). Images were pulled from docker.elastic.co in 28 s, so the registry was reachable from this cloud box.
The example folder was copied outside the repository, so `tls/` never touched the repo. Overrides:
- Heap: `ES_JAVA_OPTS=-Xms512m -Xmx512m`, mem limits 1.5 GB (ES) and 1.2 GB (Kibana), because about 2 GB was free.
- **First failure:** with the compose file's bridge network, Kibana could not reach Elasticsearch
  (`[ERROR][elasticsearch-service] Unable to retrieve version information from Elasticsearch nodes. Request timed
  out`). `curl http://elasticsearch:9200` from the Kibana container: no answer. The box drops container-to-container
  bridge traffic. Fix outside the repo: `compose.hostnet-override.yml` (host network, both bound to 127.0.0.1).
  Kibana was then available in 25 s. The pipeline PUT was acknowledged.
- The first dashboard import attempt (while Kibana was unavailable) returned HTTP 415. After the fix it returned
  success, 5 objects.

Counts (`two-key-siem/_count`):
- **`demo --siem siem.yaml` (syslog over TLS, unmodified): 5 or 6 of its 17 events arrived** (5, 5, 6, 5 in four
  runs). The demo writes 16 ledger entries plus the refused-token count, and every send returned success.
  - Root cause, from tcpdump and strace: the later sends are small writes that Nagle holds back while the first
    one waits for an ACK. `SyslogSink.close()` then closes the TLS socket with the collector's TLS 1.3 session
    tickets still unread, so the kernel sends a RST and throws away the unsent bytes.
  - The cursor had already moved past those entries, so they are never resent. The collector loses them for
    good and nothing is said on stderr.
  - The same demo with a 0.5 s pause before close (`demo_delay.py`), or with TCP_NODELAY on the socket
    (`demo_nodelay.py`): 17 of 17. Those two scripts are diagnostics only, not changes to Two-Key.
  - The webhook sink (`siem_webhook.yaml`, unmodified demo): 17 of 17.
  - Long-lived proxies (the pass's own collector got 385 of 385) do not show it, because the queue is flushed
    long before close. It hits the last events before any shutdown or restart.
- Run 8's own main ledger (a copy) sent through Two-Key's webhook sink with `replay_from: start`
  (`send_run8_ledger.py`): 311 of 311 (309 plus the copy's own 2 start entries). Index total: 351.

Dashboard "Two-Key: ledger copy" (each panel's KQL run as the matching Elasticsearch query; I did not open the
dashboard in a browser):
- **denied calls (`allowed:false`): no data, and allowed calls (`allowed:true`): no data.** With
  `schema: ecs` (the example's `siem.yaml`) the field is `two_key.allowed` (4 true, 5 false), so the panels'
  `allowed` matches nothing.
- events worth an alert (`kind:(gateway_token_refused or …)`): partial. `kind` exists only because receiver.py
  copies the syslog MSGID into it. The webhook copy of the refused-token event (no `kind`) is missing from the
  panel: 1 of 2 matched (`event.action` has both).
- Dashboard and siem.yaml disagree on the schema. Either `schema: native` or ECS field names in the saved searches.

Outage test (`outage.py`: a persistent ledger, 20 authorize calls per phase, both sinks):
- Receiver up: median 4.9 ms (webhook) and 6.3 ms (syslog) per authorize, max 9.5 and 11.7 ms.
- Receiver stopped: median 4.0 and 4.3 ms, max 9.7 and 9.2 ms, so no slower. stderr:
  `two-key: WARNING: siem: elastic-syslog: cannot connect to 127.0.0.1:6514: Connection refused; entries are kept
  in the ledger and sent when it answers` and `siem: elastic-syslog: unreachable: … (3 entries behind)`. The
  webhook gives the same.
- Receiver restarted, next start on the same ledger: all 102 late entries arrived with `two_key.replay: true`,
  plus the 2 start entries (also replay). Before the outage, 100 events arrived with replay false. Nothing was
  lost and nothing came twice, for either sink.
- `demo --siem` with the receiver stopped: authorized as usual (wall 205 ms against 215 ms with it up), and
  printed the warning above.

Refused tokens (`refused_tokens.py`, persistent ledger, webhook):
- 3 tokens that do not verify. Each was refused as `malformed_token`. The ledger stayed at 3 entries (3 before,
  3 after). stderr said `gateway refused N token(s) that did not verify … malformed=N; no ledger entry`.
- The events in Elasticsearch: `event.action: gateway_token_refused`, `two_key.ledgered: false`,
  `event.sequence: -1`, counts only, and none of the token texts.
- The demo's stderr line matched the README. With the syslog sink the demo's refused-token event is one of the
  events lost on close (above).

Canary search over all 351 documents (substring and `query_string`): 0 hits each for the run 8 card number
(spaced and digits-only), invoice RMW-4410, payee domains rockymtn-medwaste.example and alpine-medsupply.example,
the outside address domain mailsink.example, the demo's recipient, the demo's proposal text, and the demo's
malformed token. All 128 run 8 call-argument values of 5+ characters: 0 found.

Other notes: the README says a document carries nothing "about a token", but `two_key.jti` and
`two_key.token_hash` are sent for `capability_issued` and redemptions. docs/SIEM.md lists them, so only the
README is off. `observer.version` reads 0.6.0.

Stopped afterwards: `docker compose down -v` (containers and data removed), receiver and dockerd stopped,
`tls/` deleted with the scratch copy.
