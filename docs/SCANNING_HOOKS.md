# Content-scanning hooks: third-party DLP and antivirus

Two-Key can hand what an agent is about to send to third-party data-loss
prevention (DLP) and antivirus (AV) software, and act on the verdict. This
follows Stephan's direction (`CONCEPTION_NOTES.md` Entry 5, 2026-09-30):
third-party DLP hooks into Two-Key rather than Two-Key having DLP built in;
all five hook types are offered, vendor- and version-agnostic; **none is
required**, since there may be no DLP software in place; and antivirus gets
the same availability.

The code is in `two_key/scanning.py` and the gateway wiring is in
`two_key/gateway.py`. The implementation is AI-prepared engineering.
Stephan decided the timeout, the combination rule, and what scanners receive
on 2026-09-30 (`CONCEPTION_NOTES.md` Entry 6; see
[Stephan's decisions (Entry 6)](#stephans-decisions-entry-6)), and then
scanner errors, run order, holding for the verdict, data-class disagreement,
and inbound scanning (Entry 7; see
[Stephan's decisions (Entry 7)](#stephans-decisions-entry-7)). What is still
open is listed under [Open questions for Stephan](#open-questions-for-stephan).

## Contents

- [Where scanning happens](#where-scanning-happens)
- [Inbound: before the agent receives or processes content](#inbound-before-the-agent-receives-or-processes-content)
- [The verdict and how it binds to the token and ledger](#the-verdict-and-how-it-binds-to-the-token-and-ledger)
- [The five hook types](#the-five-hook-types)
- [Comparison](#comparison)
- [Antivirus, malicious scripts, and AMSI](#antivirus-malicious-scripts-and-amsi)
- [Stephan's decisions (Entry 6)](#stephans-decisions-entry-6)
- [Stephan's decisions (Entry 7)](#stephans-decisions-entry-7)
- [Engineering defaults and interpretations](#engineering-defaults-and-interpretations)
- [Open questions for Stephan](#open-questions-for-stephan)
- [Limits](#limits)

## Where scanning happens

Scanning runs in the tool gateway, the one component that sees the exact
call that is about to execute. With `scanners` configured, `gateway.invoke`:

1. verifies the token and runs checks 1-8 as before (signature, expiry,
   principal, tool, literal-argument hash, amount, counterparty, data
   class). Any deny here is final; the scanners aren't called.
2. takes **one snapshot** of the arguments, their canonical encoding. That
   snapshot is what check 5 hashes, what the scanners receive (part `call`),
   and what the tool executes (decoded from the snapshot).
3. adds file parts (`file:<name>`) from an optional per-tool
   `file_extractors[tool](args) -> [(name, bytes, content_type), ...]`,
   for example a base64 attachment decoded to its bytes.
4. adds the **decoded strings** (Entry 6, decision c): every string in the
   arguments, unescaped, as UTF-8 parts named `text:<path>`. Examples are
   `text:args.body`, `text:args.cc[0]`, and `text:args.body#key` for a key.
   The `call` part is ASCII-escaped JSON, so a script or pattern containing
   non-ASCII characters is only visible in the decoded strings. These texts
   are scanned too, but the digest binding (`payload_digest`) covers the
   exact-byte parts.
5. runs the scanners **in parallel** (the default, Entry 7) and decides.
   **Any conviction denies** (Entries 6 and 7): a scanner can only add a
   deny, never remove one.
   - `block` gives the deny `scan_blocked:<id>`;
   - `quarantine` gives `scan_quarantined:<id>`;
   - `timeout` gives `scan_timeout:<id>`, and a scanner `error` gives
     `scan_error:<id>`, unless `on_timeout="allow"` (errors are treated like
     timeouts, Entry 7);
   - a DLP data class other than the one the token permits gives
     `scan_data_class_mismatch`. The call's own label already has to match
     the token (check 8), so the label and every DLP verdict must agree.

   These denials happen before redemption, so the token isn't used up.
6. continues with the ledger checks 9-11, redemption, and execution as before.
7. scans what the tool returned **before the agent receives it** (see
   [Inbound](#inbound-before-the-agent-receives-or-processes-content)).

**Parallel order.** All scanners start at once. If any verdict denies, the
call is denied: nothing another scanner says can turn that into an allow.
So the gateway stops waiting, records every verdict that has arrived, and
records the scanners still running as `cancelled` (their late results are
ignored; `abandon()` is called on them). Without a deny, the gateway waits
for every scanner, up to `timeout_seconds` in total; a scanner that hasn't
answered by then is a `timeout`. `order="sequential"` is still available: it
runs the scanners one after the other and stops at the first deny.

**With no scanners configured, none of this runs.** `scanners=None` and
`scanners=[]` both leave `gateway.scan_engine` as `None`, and `invoke`
takes the original code path unchanged. The regression test is
`tests/test_scanning_gateway.py::test_no_scanners_means_the_original_path`.

## Inbound: before the agent receives or processes content

Stephan: "Scans should be done before files are sent.  Likewise, they should
be done before files are received or processed." (Entry 7)

- **Tool results.** After the tool runs, the gateway scans its return value
  with the same scanners, settings (timeout, errors, parallel order), and
  rules before returning it. The parts are:
  - `result`, the canonical JSON of the result (its digest equals the
    `result_hash` in `tool_executed`);
  - raw bytes for a `bytes` result, which is treated as a file;
  - `repr()` for a result that isn't JSON;
  - `file:<name>` parts from an optional per-tool
    `result_file_extractors[tool](result) -> [(name, bytes, content_type)]`;
  - the decoded strings, as `text:result...`.
- **Withheld, not undone.** If the inbound scan denies, the agent doesn't get
  the result: `GatewayResult(False, "result_withheld:<reason>")`, for example
  `result_withheld:scan_blocked:av`. The tool has already run, so its side
  effects stand. The `tool_executed` entry records `result_scans`,
  `result_scan_errors`, `result_scan_policy`, `result_scan_data_classes`, and
  `result_withheld` (the reason, or null).
- **Data class.** The same rule applies: a DLP class other than the token's
  withholds the result (an interpretation; see the open questions).
- **Content outside a tool call.** `gateway.scan_inbound(content,
  source=..., files=[(name, bytes, content_type)], data_class=None)` scans
  content that reaches the agent some other way, for example an email
  attachment. It returns `InboundScanResult(allowed, reason, verdicts)` and
  writes a `content_scan_inbound` ledger entry. With `data_class`, every DLP
  class must be that class.
- **Scanners see the direction.** `ScanRequest.direction` is `"outbound"` or
  `"inbound"`, and the default request body includes `"direction"`. ICAP
  uses `method` (default `REQMOD`) outbound and `inbound_method` (default
  `RESPMOD`) inbound.
- **No scanners, no change.** Results are returned exactly as before, and
  `scan_inbound` returns `not_scanned` without writing anything.

**F_REVIEW note.** F_REVIEW.md §8 finding 1 describes a hash-then-execute gap.
The gateway reads `args` once to hash it and again to run the tool, so a
crafted argument object can show different values the second time. The
single snapshot in step 2 closes that gap **only when scanners are
configured**, because the scanned bytes have to be the executed bytes.
Without scanners the gap is still there. That bug is not fixed by this
change, and fixing it in general needs Stephan's decision (F_REVIEW Q15).
The snapshot also changes what the tool receives when scanning is on: it
gets the JSON-decoded copy, so tuples arrive as lists and non-string keys as
strings.

## The verdict and how it binds to the token and ledger

Every scanner returns one `ScanVerdict`:

| Field | Meaning |
|---|---|
| `outcome` | `allow`, `block`, `quarantine`, `error`, `timeout`, `pending` (async post-send only), or `cancelled` (set by the gateway only: not awaited because the call was already denied) |
| `scanner_id`, `adapter`, `kind` | Which scanner, which hook type, `dlp` / `av` / `dlp+av` |
| `scanner_version` | Configured, or learned from the scanner (API field, ICAP `ISTag`/`Service`, clamd `VERSION`) |
| `parts` | Each exact-byte part's name, content type, size, and digest |
| `texts` | Each decoded string's name (`text:<path>`), size, and digest (of its UTF-8 encoding) |
| `payload_digest` | Digest over the exact-byte part list, computed by the gateway, never taken from the scanner |
| `labels`, `data_classes` | Vendor labels; Two-Key data classes (from the response or a label map) |
| `findings` | Malware names or rule names (never the matched text) |
| `elapsed_ms`, `detail`, `scan_id` | Timing; short untrusted detail text; async scan id |
| `error_type` | For `error` and `timeout`: the exception or failure type (for example `OSError`, `ScanTimeout`, `DigestMismatch`) |
| `direction` | `outbound` or `inbound` |

The binding chain in the ledger:

- `capability_issued.args_hash` is the hash of the call's canonical
  encoding, fixed at `authorize` time.
- `capability_redeemed` repeats that `args_hash` and adds:
  - `content_scans`, the list of verdict records. The digest of part `call`
    equals `args_hash`, so the scan provably covered the same bytes the token
    authorized.
  - `scan_policy`, the settings in force.
  - `scan_data_classes`, the call's own data class and every DLP class found.
  - `scan_errors` (Entry 7: "Scanner error should be logged in the ledger"):
    one record per scanner error or timeout, with the scanner id and version,
    the outcome, the error type, the detail, the payload digest, the
    direction, and the action taken (`block` or `allow`, from `on_timeout`).
- `gateway_denied` carries the same fields when a scan denies the call.
- `tool_executed` carries the inbound fields (`result_scans`,
  `result_scan_errors`, ...) and `result_withheld`.
- `content_scan_inbound` records a `scan_inbound` call.
- `content_scan_async` (adapter 5, post-send) records a late verdict with the
  token's `jti`, the direction, and the same `payload_digest`.

If a scanner reports which payload digest it scanned and that differs, the
verdict is an `error` (`digest_mismatch`).

## The five hook types

All five are optional. They can be mixed, for example a DLP API plus a
local AV sidecar. Each takes `kind=` (`dlp`, `av`, `dlp+av`) and an optional
per-scanner `payload_mode=` (`exact` or `digest_only`).

### 1. Vendor API (REST or gRPC): `VendorApiScanner`

```python
from two_key.judges.credentials import EnvApiKey
from two_key.scanning import ResponseMapping, VendorApiScanner

dlp = VendorApiScanner(
    "vendor-dlp", endpoint="https://dlp.example.com/v1/scan",
    credential=EnvApiKey("DLP_API_KEY"),            # sent as "Authorization: Bearer <key>"; never logged
    mapping=ResponseMapping(outcome_path="result.verdict",
                            outcome_map={"clean": "allow", "violation": "block", "review": "quarantine"},
                            labels_path="result.policies", label_to_data_class={"hipaa": "medical"},
                            version_path="engine_version"))
```

- **Request:** the default body is `{"protocol": "two-key-scan/1",
  "request_id", "tool", "digest_alg", "payload_mode", "payload_digest",
  "parts": [{name, content_type, size, digest, data_b64}], "texts": [{name,
  content_type, size, digest, text}], "direction"}`. Pass
  `body_builder=` to fit a vendor's schema.
- **Response:** `ResponseMapping` maps the vendor's JSON fields by dotted
  path. Two-Key ships no vendor-specific mappings.
- **Transport security:** HTTPS is required except for loopback, unless you
  set `allow_insecure_http`.
- **gRPC:** `transport=grpc_transport("host:443", "/vendor.Scanner/Scan",
  channel_credentials=...)` needs the optional `grpcio` package and raises
  `ScannerUnavailable` without it. Any callable `(body, headers, timeout) ->
  response` also works as `transport=`, for example a wrapper around a
  vendor's own client library.

### 2. ICAP (RFC 3507): `IcapScanner`

```python
from two_key.scanning import IcapScanner

av = IcapScanner("icap-av", host="127.0.0.1", port=1344, service="avscan", method="REQMOD")
```

- **Request:** each part is sent as the body of an encapsulated HTTP message.
  `REQMOD` wraps it in a POST (the agent uploading it); `RESPMOD` wraps it
  in a 200 response. `method` is used outbound and `inbound_method`
  (default `RESPMOD`) inbound.
- **Verdicts:** `204 No Content` is an allow, and so is a 200 that returns
  the same body. A changed body, a replacement response (a block page),
  `X-Infection-Found`, or `X-Violations-Found` gives `modified_outcome`
  (default `block`). Other ICAP statuses are errors.
- **Version:** `options()` sends ICAP OPTIONS; `ISTag` and `Service` become
  the version.
- **Transport security:** plain-text ICAP is allowed only to loopback unless
  `allow_plaintext_remote=True`; pass `tls=` (an `ssl.SSLContext`) for ICAP
  over TLS.

### 3. In-process or local plugin: the registry, `PatternScanner`, `ClamdScanner`

```python
from two_key.scanning import PatternRule, PatternScanner, create_plugin, load_entry_point_plugins

load_entry_point_plugins()          # packages can publish factories under the "two_key.scanners" entry point
example = PatternScanner("example", rules=PatternScanner.example_rules())   # EICAR + an SSN-shaped number
custom = PatternScanner("dx", kind="dlp",
                        rules=[PatternRule("dx", rb"(?i)diagnosis", label="health", data_class="medical")])
same = create_plugin("pattern", scanner_id="p", rules=[])
```

- **Writing a plugin:** subclass `ContentScanner` and implement
  `scan(request, timeout) -> ScanReport`. Register it with `register_plugin`
  or an entry point.
- **`PatternScanner`:** a built-in example of the interface, not a DLP or AV
  product. Its example rules are illustrations, not a recommended policy.
- **`ClamdScanner`:** uses the optional `clamd` Python package; the scan
  engine itself runs in ClamAV's clamd. Without the package, construction
  raises `ScannerUnavailable`, and nothing else is affected.

### 4. Sidecar or local daemon over a local socket: `SidecarScanner`

```python
from two_key.scanning import SidecarScanner

dlp = SidecarScanner("local-dlp", unix_socket="/run/dlp/scan.sock")                  # Two-Key JSON framing
clam = SidecarScanner("clamd", unix_socket="/run/clamav/clamd.ctl", protocol="clamd-instream", kind="av")
```

- **Connection:** a Unix socket, or TCP to a loopback address only (remote
  scanners use adapter 1 or 2).
- **`two-key-json`:** one request frame and one response frame, each a
  4-byte big-endian length followed by canonical JSON. The request is the
  same body as adapter 1, and the response goes through `ResponseMapping`.
- **`clamd-instream`:** speaks clamd's `zINSTREAM`/`zVERSION` directly, with
  no extra package.

### 5. Asynchronous (webhook or storage event): `AsyncCallbackScanner`

```python
from two_key.scanning import AsyncCallbackScanner, WebhookReceiver


def submit(request, scan_id):       # e.g. upload to the vendor's scanning bucket, tagged with scan_id
    ...


scanner = AsyncCallbackScanner("async-dlp", submit)    # holds until the verdict or the timeout (default)
receiver = WebhookReceiver(scanner, secret=b"a shared secret of 16+ bytes").start()   # or call scanner.deliver()
```

- **Hold** (`hold_until_verdict=True`, **the default**, Entry 7: "Always
  hold a file until verdict is returned [...] or the timeout limit is
  reached"): the gateway waits for the verdict, up to `timeout_seconds`, and
  decides on it like any other verdict. The verdict arrives through
  `deliver(scan_id, response)`, from a storage-event handler or from
  `WebhookReceiver`. No verdict in time is a `timeout` (`on_timeout`
  decides; blocked by default). A verdict that arrives after the wait is
  recorded as post-send (`content_scan_async`). That includes one that
  arrives at the deadline itself: when the gateway stops waiting, it calls
  the scanner's `abandon(request)` hook, which `AsyncCallbackScanner` uses
  to record such a verdict instead of dropping it.
- **Post-send** (`hold_until_verdict=False`): **weaker, never the default.**
  Kept only for a deployment that explicitly chooses it. The call proceeds
  with a `pending` verdict, the later verdict is recorded as
  `content_scan_async`, and `on_flag` is called for a block or quarantine.
  **This only flags after the fact; the content has already been sent (or,
  inbound, already handed to the agent).**
- **`WebhookReceiver`:** binds to 127.0.0.1 by default. It requires
  `X-Two-Key-Signature: sha256=<HMAC-SHA256 of the body>` and refuses
  unsigned callbacks, because an unauthenticated callback could post an
  "allow".

## Comparison

This is a neutral comparison to support Stephan's choice. He said he is
"thinking API is the best, but want to compare" (Entry 5). All five stay
available whatever he picks.

| | 1. Vendor API (REST/gRPC) | 2. ICAP | 3. In-process plugin | 4. Sidecar (local socket) | 5. Async post-send |
|---|---|---|---|---|---|
| **Latency** | Network round trip per call (LAN or internet); vendor processing | Network round trip per part; usually LAN | Lowest: no I/O except what the plugin does | Local IPC; low | Full scan time (held, the default); none on the call path in post-send mode |
| **Isolation / security** | Content leaves the host (TLS); vendor sees it; API credential to protect | Content leaves the host; plain text unless ICAP over TLS; ICAP has no standard auth | Plugin runs inside Two-Key's process with its privileges; a plugin crash or compromise affects Two-Key | Separate process; content stays on the host; socket permissions control access | Content goes to vendor storage; the callback channel must be authenticated (HMAC); verdict is decoupled from the call |
| **Vendor support** | Most cloud DLP/AV services have an API, each with its own schema (handled by mapping/body builder) | A long-standing standard; many network DLP and AV gateways, and open-source c-icap, speak it | Needs a Python SDK or a wrapper; per-vendor code | Needs a local daemon (clamd works directly) or a small shim | Fits vendors that scan uploads to storage or offer async APIs |
| **Failure behavior** | Timeout is `timeout`; HTTP error or unmapped answer is `error`; both follow `on_timeout` | Socket timeout is `timeout`; non-204/200 status is `error` | Timeout is `timeout`; exception is `error` | Socket timeout is `timeout`; other socket errors are `error` | Submit failure is `error`; post-send: a late block only flags; held: no verdict in time is `timeout` |
| **Binding to token/ledger** | Verdict in `capability_redeemed`/`gateway_denied`; part digests match `args_hash`; optional echoed-digest check | Same; version from ISTag | Same | Same; optional echoed-digest check | Held: like the others. Post-send: pending verdict at redemption, then `content_scan_async` with the same `jti` and payload digest |

## Antivirus, malicious scripts, and AMSI

- **Same mechanism.** Antivirus uses the same interface (`kind="av"`) and
  the same five hook types: ICAP AV servers, clamd as a sidecar or plugin,
  vendor AV APIs, and asynchronous bucket scanning.
- **What it covers.** At the gateway, an AV verdict covers the bytes the
  agent is sending (the call encoding, plus any file parts a file extractor
  provides) and the decoded strings in the call (Entry 6, decision c, for
  malicious-script detection). Known malicious content is blocked before the
  tool runs. What the tool returns is scanned the same way before the agent
  receives it (Entry 7); the tests use the harmless EICAR test string and a script
  pattern found only in a decoded string.
- **What it can't guarantee.** Signature scanning can't prove that content
  holds no malicious script. Unknown or obfuscated scripts can pass a
  scanner. The structural limits stay the same as without scanning:
  - Path A's tool allow-list decides which tools an agent may call at all.
  - The token binds the exact arguments, so a script can't be swapped in
    after approval.
  - The judges see the action record.
- **Why not AMSI.** AMSI (Windows Antimalware Scan Interface) is the
  interface Windows script engines (PowerShell, Windows Script Host, Office
  VBA and others) call to submit a script to the registered antivirus just
  before they run it. Two-Key doesn't run the scripts an agent sends; it
  passes content to tools. So Two-Key isn't the place AMSI expects to sit,
  and AMSI doesn't cover content that is sent rather than executed. Content
  scanning at the gateway is the fitting control. On Windows, a local plugin
  (hook type 3) could still submit the payload buffer to the registered
  antivirus through AMSI's scan call. That is one possible optional plugin,
  and it is not implemented here.

## Stephan's decisions (Entry 6)

Stephan decided these on 2026-09-30, about 9:49 PM MT (`CONCEPTION_NOTES.md`
Entry 6). They resolve open questions (a), (b), and (c) from Entry 5.

| Decision | What the code does |
|---|---|
| **(a)** "The timeout option should be configurable (both time in seconds to wait and action taken…default should be deny but with the optional configuration to be changed to allow.)" | `ScanSettings.timeout_seconds` (default 10; the number is an engineering default, the setting is his decision) and `ScanSettings.on_timeout` (`"block"` by default, `"allow"` optional). The gateway waits exactly `timeout_seconds` for each scanner. A timeout is its own outcome, `timeout`. That covers the engine's wait, socket and HTTP timeouts, a gRPC deadline, and `hold_until_verdict` with no verdict in time. |
| **(b)** "fail to the most restrictive (either two-key or DLP/AV…if one denies/blocks…the action is block)" | Scanners run only after every Two-Key check has passed, and a verdict can only add a deny. The effective data class is the most restrictive of the call's own class and the DLP classes; it must equal the token's scope. The earlier `dlp_overrides_data_class` setting is removed. |
| **(c)** "Scanners get the exact bytes and strings (for malicious script detection) sent." | `ScanSettings.payload="exact"`: every scanner gets the exact-byte parts plus the decoded strings (`texts`). The digest binding stays on the exact bytes. |

After Entry 6 the code briefly had a separate `on_error` setting and a
data-class ranking (`classified` above `personal`/`medical`/`financial`
above `public`). Entry 7 replaced both; see the next section.

**Digest-only stays available.** A scanner can still be set to
`payload_mode="digest_only"` (names, sizes, digests only) as an explicit
per-scanner choice, for example for a hash-reputation service. It is not the
default, and content scanners return `error` in that mode.

## Stephan's decisions (Entry 7)

Stephan decided these on 2026-09-30, about 10:16 PM MT (`CONCEPTION_NOTES.md`
Entry 7). They resolve the open questions left after Entry 6.

| Decision | What the code does |
|---|---|
| "Scanner error should be logged in the ledger and treated like a timeout." | `on_error` follows `on_timeout` (`ScanSettings.error_action`); setting `on_error` to anything else is refused. Every error and timeout is recorded in `scan_errors` / `result_scan_errors` with the scanner id and version, the error type, the payload digest, and the action taken. |
| "Which is faster [...]?  Whichever is more optimized, choose that." | The assistant answered that parallel is faster (the wait is about as long as the slowest scanner, not the sum), and since any deny decides, the order doesn't change the outcome. Parallel was selected per his delegation: `ScanSettings.order="parallel"` is the default. `"sequential"` stays available. |
| "Always hold a file until verdict is returned [...] or the timeout limit is reached." | `AsyncCallbackScanner(hold_until_verdict=True)` is the default; no verdict in time is a timeout (`on_timeout`). The other adapters already wait for their verdict. Post-send mode is kept as a weaker, non-default option. |
| "Don’t worry about disagreement; if one (two-key or DLP or AV) convicts (would deny) then default to deny." | No ranking: any DLP data class other than the one the token permits denies (`scan_data_class_mismatch`). The ranking question is removed. |
| "Scans should be done before files are sent.  Likewise, they should be done before files are received or processed." | Outbound as before. Inbound: tool results and their files are scanned before the agent gets them (withheld on a deny), and `scan_inbound()` covers content arriving outside a tool call. |

## Engineering defaults and interpretations

These are AI-prepared engineering, not Stephan's decisions:

| Item | Choice | Note |
|---|---|---|
| `timeout_seconds` | 10 | The setting is his decision (Entry 6); the number isn't. In parallel order it is the total wait. |
| Parallel early stop | Stop waiting at the first deny; the scanners still running are recorded as `cancelled` | Waiting longer can't change a deny. Without a deny, every scanner is awaited up to the timeout. |
| Inbound data class | The token's data class also applies to what comes back | "If one convicts, deny" read as covering inbound content too. |
| Withheld results | The tool has already run; only the result is withheld | A tool's side effects can't be undone by a later scan. |
| ICAP inbound | `RESPMOD` | Inbound content is a response. |
| `digest_only` | Per-scanner opt-in only | Entry 6 (c) is exact bytes and strings. |

## Open questions for Stephan

The questions from Entries 5 and 6 are decided (Entries 6 and 7). Still
open:

- **After-the-fact block:** in the non-default post-send mode, what should a
  late block or quarantine trigger beyond the `content_scan_async` entry and
  the `on_flag` hook (for example, revoking the session's tokens or
  notifying the principal)?
- **Post-send mode:** should the weaker post-send mode be kept at all, or
  removed?
- **Inbound data class:** should the token's data class also limit what the
  agent may receive (the current interpretation), or should inbound
  checking apply only to blocks, quarantines, errors, and timeouts?
- **Withheld results:** a withheld result has already been produced by the
  tool. Should anything else happen (for example, notifying the principal)?
- **Timeout number:** is 10 seconds a good default?

## Limits

- **Tested against local fakes only.** The tests use a fake HTTP API, a fake
  ICAP server, fake Unix-socket and TCP sidecars, a fake clamd, and fake
  async callbacks. No real DLP or AV product, `grpcio`, or `clamd` package
  was exercised. `grpcio` and `clamd` aren't installed on the development
  machine; the graceful-degradation paths are tested.
- **Files read by path.** A file extractor can only provide bytes Two-Key
  sees. If a tool reads a file from disk by path, the scanned bytes may
  differ from what the tool sends, unless the tool sends exactly the bytes
  in its arguments.
- **JSON escaping.** The `call` and `result` parts are canonical JSON with ASCII escapes.
  Pattern-based scanners see `\uXXXX` for non-ASCII text; file parts are
  raw bytes.
- **Untrusted scanner output.** Labels, findings, and details are recorded
  truncated and are never interpreted beyond the documented fields.
- **Post-send can't undo.** The non-default post-send mode can't undo a
  send.
- **Inbound can't undo the tool.** Withholding a result doesn't undo what
  the tool did.
- **Cancelled scanners keep running.** A scanner that isn't awaited is told
  through `abandon()` but its thread isn't killed (Python can't stop a
  thread); its result is ignored.
