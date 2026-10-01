# Content-scanning hooks: third-party DLP and antivirus

Two-Key can hand what an agent is about to send to third-party data-loss
prevention (DLP) and antivirus (AV) software, and act on the verdict. This
follows Stephan's direction (`CONCEPTION_NOTES.md` Entry 5, 2026-09-30):
third-party DLP hooks into Two-Key rather than Two-Key having DLP built in;
all five hook types are offered, vendor- and version-agnostic; **none is
required**, since there may be no DLP software in place; and antivirus gets
the same availability.

The code is in `two_key/scanning.py` and the gateway wiring is in
`two_key/gateway.py`. The implementation is AI-prepared engineering. Where
Stephan has not decided something, the code has a **placeholder default**
(listed under [Open questions for Stephan](#open-questions-for-stephan)).

## Contents

- [Where scanning happens](#where-scanning-happens)
- [The verdict and how it binds to the token and ledger](#the-verdict-and-how-it-binds-to-the-token-and-ledger)
- [The five hook types](#the-five-hook-types)
- [Comparison](#comparison)
- [Antivirus, malicious scripts, and AMSI](#antivirus-malicious-scripts-and-amsi)
- [Placeholder defaults](#placeholder-defaults)
- [Open questions for Stephan](#open-questions-for-stephan)
- [Limits](#limits)

## Where scanning happens

Scanning runs in the tool gateway, the one component that sees the exact
call that is about to execute. With `scanners` configured, `gateway.invoke`:

1. verifies the token and runs checks 1-7 as before (signature, expiry,
   principal, tool, literal-argument hash, amount, counterparty). The
   data-class check 8 also runs here, unless `dlp_overrides_data_class` is on.
2. takes **one snapshot** of the arguments, their canonical encoding. That
   snapshot is what check 5 hashes, what the scanners receive (part `call`),
   and what the tool executes (decoded from the snapshot).
3. adds file parts (`file:<name>`) from an optional per-tool
   `file_extractors[tool](args) -> [(name, bytes, content_type), ...]`,
   for example a base64 attachment decoded to its bytes.
4. runs the scanners and decides:
   - `block` gives the deny `scan_blocked:<id>`;
   - `quarantine` gives `scan_quarantined:<id>`;
   - `error` gives `scan_error:<id>` if `on_error="block"`;
   - with the override on, a DLP class different from the token's scope
     gives `scan_data_class_mismatch`.

   These denials happen before redemption, so the token isn't used up.
5. continues with the ledger checks 9-11, redemption, and execution as before.

**With no scanners configured, none of this runs.** `scanners=None` and
`scanners=[]` both leave `gateway.scan_engine` as `None`, and `invoke`
takes the original code path unchanged. The regression test is
`tests/test_scanning_gateway.py::test_no_scanners_means_the_original_path`.

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
| `outcome` | `allow`, `block`, `quarantine`, `error`, or `pending` (async post-send only) |
| `scanner_id`, `adapter`, `kind` | Which scanner, which hook type, `dlp` / `av` / `dlp+av` |
| `scanner_version` | Configured, or learned from the scanner (API field, ICAP `ISTag`/`Service`, clamd `VERSION`) |
| `parts` | Each scanned part's name, content type, size, and digest |
| `payload_digest` | Digest over the part list, computed by the gateway, never taken from the scanner |
| `labels`, `data_classes` | Vendor labels; Two-Key data classes (from the response or a label map) |
| `findings` | Malware names or rule names (never the matched text) |
| `elapsed_ms`, `detail`, `scan_id` | Timing; short untrusted detail text; async scan id |

The binding chain in the ledger:

- `capability_issued.args_hash` is the hash of the call's canonical
  encoding, fixed at `authorize` time.
- `capability_redeemed` repeats that `args_hash` and adds:
  - `content_scans`, the list of verdict records. The digest of part `call`
    equals `args_hash`, so the scan provably covered the same bytes the token
    authorized.
  - `scan_policy`, the settings in force.
  - `scan_data_class`, if the override is on.
- `gateway_denied` carries the same fields when a scan denies the call.
- `content_scan_async` (adapter 5, post-send) records a late verdict with the
  token's `jti` and the same `payload_digest`.

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
  "parts": [{name, content_type, size, digest, data_b64}]}`. Pass
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
  in a 200 response.
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

### 5. Asynchronous post-send (webhook or storage event): `AsyncCallbackScanner`

```python
from two_key.scanning import AsyncCallbackScanner, WebhookReceiver


def submit(request, scan_id):       # e.g. upload to the vendor's scanning bucket, tagged with scan_id
    ...


scanner = AsyncCallbackScanner("async-dlp", submit, hold_until_verdict=False, on_flag=print)
receiver = WebhookReceiver(scanner, secret=b"a shared secret of 16+ bytes").start()   # or call scanner.deliver()
```

- **Post-send** (`hold_until_verdict=False`, the placeholder default): the
  call proceeds with a `pending` verdict. The real verdict arrives later
  through `deliver(scan_id, response)`, either from a storage-event handler
  or from `WebhookReceiver`. It is recorded as `content_scan_async`, and
  `on_flag` is called for a block or quarantine. **This only flags after
  the fact; the content has already been sent.**
- **Hold** (`hold_until_verdict=True`): the gateway waits for the verdict,
  up to the timeout, and decides on it like any other verdict. A verdict
  that arrives after the wait is recorded as post-send.
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
| **Latency** | Network round trip per call (LAN or internet); vendor processing | Network round trip per part; usually LAN | Lowest: no I/O except what the plugin does | Local IPC; low | None on the call path (post-send); full scan time if held |
| **Isolation / security** | Content leaves the host (TLS); vendor sees it; API credential to protect | Content leaves the host; plain text unless ICAP over TLS; ICAP has no standard auth | Plugin runs inside Two-Key's process with its privileges; a plugin crash or compromise affects Two-Key | Separate process; content stays on the host; socket permissions control access | Content goes to vendor storage; the callback channel must be authenticated (HMAC); verdict is decoupled from the call |
| **Vendor support** | Most cloud DLP/AV services have an API, each with its own schema (handled by mapping/body builder) | A long-standing standard; many network DLP and AV gateways, and open-source c-icap, speak it | Needs a Python SDK or a wrapper; per-vendor code | Needs a local daemon (clamd works directly) or a small shim | Fits vendors that scan uploads to storage or offer async APIs |
| **Failure behavior** | Timeout/HTTP error/unmapped answer is `error`, then `on_error` | Timeout or non-204/200 status is `error` | Exception or timeout is `error` | Socket error/timeout is `error` | Submit failure is `error`; post-send: a late block only flags; held: no verdict in time is `error` |
| **Binding to token/ledger** | Verdict in `capability_redeemed`/`gateway_denied`; part digests match `args_hash`; optional echoed-digest check | Same; version from ISTag | Same | Same; optional echoed-digest check | Pending verdict at redemption, then `content_scan_async` with the same `jti` and payload digest |

## Antivirus, malicious scripts, and AMSI

- **Same mechanism.** Antivirus uses the same interface (`kind="av"`) and
  the same five hook types: ICAP AV servers, clamd as a sidecar or plugin,
  vendor AV APIs, and asynchronous bucket scanning.
- **What it covers.** At the gateway, an AV verdict covers the bytes the
  agent is sending: the call encoding, plus any file parts a file extractor
  provides. Known malicious content (the tests use the harmless EICAR test
  string) is blocked before the tool runs.
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

## Placeholder defaults

These code defaults are **placeholders pending Stephan's decision**. Each is
the option closest to Two-Key's current behavior, not a recommendation.

| Setting | Placeholder | Why this placeholder |
|---|---|---|
| (a) `ScanSettings.on_error` | `"block"` | Every other component failure in Two-Key is already a deny (spec 5.7) |
| (b) `ScanSettings.dlp_overrides_data_class` | `False` | The gateway keeps checking the call's own data class, as today; DLP classes are recorded only |
| (c) `ScanSettings.payload` | `"exact"` | The only mode in which a verdict describes the bytes that execute |
| `ScanSettings.order` | `"sequential"` (stop at the first deny) | No content goes to later scanners for a call that is already denied |
| `ScanSettings.timeout_seconds` | `10` | Placeholder value |
| `AsyncCallbackScanner(hold_until_verdict=)` | `False` | Doesn't change when calls execute |
| No DLP class, or several, with the override on | treated as `classified` | The existing default for a data class that can't be determined (spec 5.2, Claim 5) |

## Open questions for Stephan

- **(a) Scan error or timeout:** should it block the call (fail closed) or
  allow it (the error is still recorded)? Setting: `ScanSettings.on_error`.
- **(b) DLP override of `data_class`:** should a DLP verdict override the
  agent's self-declared `data_class`? Setting:
  `ScanSettings.dlp_overrides_data_class`. With it on, the scan rather than
  the agent's label decides the class compared with the token. This is the
  gap F_REVIEW.md describes, where a mislabeled action passes both the
  judges and the hash match.
- **(c) What scanners receive:** should the gateway send the exact bytes it
  is about to transmit, or only digests and metadata? Setting:
  `ScanSettings.payload`, plus per-scanner `payload_mode`. Digest-only keeps
  content off third-party scanners, but content scanners can't work from
  digests (they return `error`).
- **Run order:** should DLP and AV run in sequence or in parallel? Setting:
  `ScanSettings.order`. Nothing else about the order is decided.
- **Timeout and post-send:** what timeout, and should post-send scanning
  hold calls until the verdict? Settings: `timeout_seconds` and
  `hold_until_verdict`.
- **Several classes:** when DLP finds no data class or several, which class
  applies? The placeholder is `classified`.
- **After-the-fact block:** what should a post-send block or quarantine
  trigger beyond the `content_scan_async` entry and the `on_flag` hook (for
  example, revoking the session's tokens or notifying the principal)?

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
- **JSON escaping.** The `call` part is canonical JSON with ASCII escapes.
  Pattern-based scanners see `\uXXXX` for non-ASCII text; file parts are
  raw bytes.
- **Untrusted scanner output.** Labels, findings, and details are recorded
  truncated and are never interpreted beyond the documented fields.
- **Post-send can't undo.** Asynchronous post-send scanning can't undo a
  send.
