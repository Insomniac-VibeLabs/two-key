"""
Two-Key: content-scanning hooks for third-party DLP and antivirus
=================================================================
Stephan's direction (CONCEPTION_NOTES.md Entry 5, 2026-09-30): third-party
DLP software should be able to hook into Two-Key and scan what agents send,
through any of five hook types, all optional and none required (there may be
no DLP software in place), vendor- and version-agnostic, with the same
availability for antivirus scanning.

This module provides one scanner interface (``ContentScanner``) that returns
a structured ``ScanVerdict``, and five adapter types:

  1. ``VendorApiScanner``      vendor API over REST (built-in HTTP transport)
                               or gRPC (``grpc_transport``, needs grpcio)
  2. ``IcapScanner``           ICAP client, RFC 3507 REQMOD / RESPMOD
  3. in-process plugins        ``PatternScanner`` (built-in example),
                               ``ClamdScanner`` (optional ``clamd`` package),
                               and a registry with entry-point discovery
  4. ``SidecarScanner``        a local daemon over a Unix socket or loopback
                               TCP (Two-Key JSON framing, or clamd INSTREAM)
  5. ``AsyncCallbackScanner``  post-send scanning; the verdict arrives later by
                               webhook (``WebhookReceiver``) or a
                               storage-event handler calling ``deliver()``.
                               ``hold_until_verdict`` waits for it instead.

The tool gateway (gateway.py) runs the configured scanners on the payload it
is about to execute, and records each verdict (scanner id and version, digest
of the scanned bytes, outcome) in the ledger. With no scanners configured the
gateway behaves exactly as before.

Settings Stephan has NOT decided (docs/SCANNING_HOOKS.md, "Open questions for
Stephan") are fields of ``ScanSettings`` (plus ``hold_until_verdict`` on the
async adapter). Their code defaults are PLACEHOLDERS pending his decision,
chosen to stay closest to Two-Key's current behavior. They are not a policy
recommendation.

Scanner output (labels, findings, details) is untrusted text: it is
recorded in the ledger, truncated, and never interpreted beyond the
documented fields.
"""

from __future__ import annotations

import abc
import base64
import hashlib
import hmac
import io
import ipaddress
import json
import re
import socket
import ssl
import struct
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from .action import DATA_CLASSES, DEFAULT_DATA_CLASS
from .canonical import canonical_bytes, canonical_hash, digest_hex
from .crypto.provider import CryptoProvider

OUTCOMES = ("allow", "block", "quarantine", "error", "pending")
KINDS = ("dlp", "av", "dlp+av")
PAYLOAD_MODES = ("exact", "digest_only")
ON_ERROR = ("block", "allow")
ORDERS = ("sequential", "parallel")
PROTOCOL = "two-key-scan/1"
LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_MAX_ITEMS, _MAX_STR, _MAX_DETAIL = 50, 200, 300
_GRACE_SECONDS = 1.0  # extra wait for an adapter that overruns its own timeout before it counts as hung


class ScannerUnavailable(RuntimeError):
    """An optional scanner dependency (grpcio, clamd) is not installed."""


class ScanError(RuntimeError):
    """A scan could not be completed. The verdict outcome is ``error``; ``ScanSettings.on_error`` decides."""


# ---------------------------------------------------------------------------
# Settings (placeholders pending Stephan's decision)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ScanSettings:
    """Gateway scanning settings.

    PLACEHOLDER DEFAULTS, pending Stephan's decision (docs/SCANNING_HOOKS.md,
    "Open questions for Stephan"). Each was chosen as the option closest to
    Two-Key's current behavior; none is a decided policy.

    - ``on_error`` (question a): what a scan error or timeout does. ``"block"``
      denies the call; ``"allow"`` lets it proceed (the error is still
      recorded). Placeholder ``"block"``: every other component failure in
      Two-Key is already a deny (spec 5.7).
    - ``dlp_overrides_data_class`` (question b): whether the DLP verdict's
      data class replaces the call's declared or extracted ``data_class`` in
      the gateway's scope check. Placeholder ``False``: the check uses the
      call's data class, as it does today; DLP labels are recorded only.
    - ``payload`` (question c): what the gateway sends to scanners.
      ``"exact"`` sends the exact bytes it is about to execute (the
      canonical call encoding, plus any file parts); ``"digest_only"`` sends
      only names, sizes, and digests. Placeholder ``"exact"``: it is the only
      mode in which a verdict describes the bytes that run. A scanner can
      override it with its own ``payload_mode``.
    - ``order``: ``"sequential"`` (in the order given, stopping at the first
      verdict that denies) or ``"parallel"``. Placeholder ``"sequential"``.
    - ``timeout_seconds``: per-scanner time limit; a scanner that exceeds it
      gives an ``error`` verdict. Placeholder 10 seconds.
    """
    on_error: str = "block"                  # PLACEHOLDER pending Stephan (question a)
    dlp_overrides_data_class: bool = False   # PLACEHOLDER pending Stephan (question b)
    payload: str = "exact"                   # PLACEHOLDER pending Stephan (question c)
    order: str = "sequential"                # PLACEHOLDER pending Stephan
    timeout_seconds: float = 10.0            # PLACEHOLDER pending Stephan

    def __post_init__(self):
        if self.on_error not in ON_ERROR:
            raise ValueError(f"on_error must be one of {ON_ERROR}")
        if not isinstance(self.dlp_overrides_data_class, bool):
            raise ValueError("dlp_overrides_data_class must be a bool")
        if self.payload not in PAYLOAD_MODES:
            raise ValueError(f"payload must be one of {PAYLOAD_MODES}")
        if self.order not in ORDERS:
            raise ValueError(f"order must be one of {ORDERS}")
        t = self.timeout_seconds
        if isinstance(t, bool) or not isinstance(t, (int, float)) or not 0 < t <= 3600:
            raise ValueError("timeout_seconds must be a number in (0, 3600]")

    def to_record(self) -> dict:
        return {"on_error": self.on_error, "dlp_overrides_data_class": self.dlp_overrides_data_class,
                "payload": self.payload, "order": self.order, "timeout_seconds": float(self.timeout_seconds)}


# ---------------------------------------------------------------------------
# Requests, reports, verdicts
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ScanPart:
    """One piece of the payload. ``data`` is None when the scanner gets digests only."""
    name: str
    content_type: str
    data: bytes | None
    size: int
    digest: str

    def info(self) -> dict:
        return {"name": self.name, "content_type": self.content_type, "size": self.size, "digest": self.digest}


@dataclass(frozen=True)
class ScanRequest:
    request_id: str
    tool: str
    digest_alg: str
    payload_mode: str
    payload_digest: str
    parts: tuple[ScanPart, ...]
    context: Mapping[str, Any] = field(default_factory=dict, repr=False)  # gateway bookkeeping; never sent

    def require_content(self) -> None:
        if self.payload_mode != "exact" or any(p.data is None for p in self.parts):
            raise ScanError("this scanner needs content, but payload_mode is digest_only")


@dataclass(frozen=True)
class ScanReport:
    """What an adapter returns. The engine turns it into a ScanVerdict."""
    outcome: str
    labels: tuple[str, ...] = ()
    data_classes: tuple[str, ...] = ()
    findings: tuple[str, ...] = ()
    scanner_version: str | None = None
    echoed_digest: str | None = None     # the payload digest the scanner says it scanned, if it reports one
    detail: str = ""
    scan_id: str | None = None


@dataclass(frozen=True)
class ScanVerdict:
    scanner_id: str
    adapter: str
    kind: str
    scanner_version: str
    outcome: str
    payload_mode: str
    digest_alg: str
    payload_digest: str                  # computed by the gateway over the parts it scanned, never by the scanner
    parts: tuple[dict, ...]
    labels: tuple[str, ...] = ()
    data_classes: tuple[str, ...] = ()
    findings: tuple[str, ...] = ()
    elapsed_ms: float = 0.0
    detail: str = ""
    scan_id: str | None = None

    @property
    def is_dlp(self) -> bool:
        return self.kind in ("dlp", "dlp+av")

    def to_record(self) -> dict:
        return {"scanner_id": self.scanner_id, "adapter": self.adapter, "kind": self.kind,
                "scanner_version": self.scanner_version, "outcome": self.outcome,
                "payload_mode": self.payload_mode, "digest_alg": self.digest_alg,
                "payload_digest": self.payload_digest, "parts": [dict(p) for p in self.parts],
                "labels": list(self.labels), "data_classes": list(self.data_classes),
                "findings": list(self.findings), "elapsed_ms": round(self.elapsed_ms, 3),
                "detail": self.detail, "scan_id": self.scan_id}


def _clip(s: Any, n: int = _MAX_STR) -> str:
    s = s if isinstance(s, str) else str(s)
    return s if len(s) <= n else s[:n] + "…"


def _jsonable(o: Any) -> Any:
    try:
        canonical_bytes(o)
        return o
    except (TypeError, ValueError):
        return repr(o)


def _strings(items: Any) -> tuple[str, ...]:
    if items is None:
        return ()
    if isinstance(items, (str, bytes)):
        items = [items]
    if not isinstance(items, (list, tuple)):
        items = [items]
    out = []
    for it in list(items)[:_MAX_ITEMS]:
        if isinstance(it, Mapping):
            it = it.get("name", it.get("id", canonical_bytes(_jsonable(dict(it))).decode()))
        if isinstance(it, bytes):
            it = it.decode("utf-8", "replace")
        out.append(_clip(it))
    return tuple(out)


def split_classes(labels: Iterable[str], data_classes: Iterable[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Keep only Two-Key data classes in data_classes; anything else becomes a label."""
    classes, extra = [], []
    for c in data_classes:
        c2 = c.strip().casefold()
        if c2 in DATA_CLASSES:
            classes.append(c2)
        else:
            extra.append(_clip(c))
    return tuple(dict.fromkeys(list(labels) + extra)), tuple(dict.fromkeys(classes))


# ---------------------------------------------------------------------------
# The scanner interface
# ---------------------------------------------------------------------------
class ContentScanner(abc.ABC):
    """Base class for every scanner, DLP or antivirus, whatever the transport.

    Subclasses implement ``scan(request, timeout) -> ScanReport``. They should
    respect ``timeout`` themselves; the engine also stops waiting after
    ``timeout`` plus a short grace period and records an ``error`` verdict.
    Raising any exception also gives an ``error`` verdict.
    """
    adapter = "plugin"
    supports_pending = False

    def __init__(self, scanner_id: str, *, kind: str = "dlp", payload_mode: str | None = None,
                 version: str | None = None):
        if not isinstance(scanner_id, str) or not _ID_RE.match(scanner_id):
            raise ValueError("scanner_id must be 1-64 characters of [A-Za-z0-9._:-], starting alphanumeric")
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        if payload_mode is not None and payload_mode not in PAYLOAD_MODES:
            raise ValueError(f"payload_mode must be one of {PAYLOAD_MODES} or None")
        self.scanner_id, self.kind, self.payload_mode, self._version = scanner_id, kind, payload_mode, version
        self._seen_version: str | None = None

    def version(self) -> str:
        """Scanner/engine/signature version for the audit record (configured, else learned from responses)."""
        return self._version or self._seen_version or "unknown"

    @abc.abstractmethod
    def scan(self, request: ScanRequest, timeout: float) -> ScanReport:
        ...

    def describe(self) -> dict:
        return {"scanner_id": self.scanner_id, "adapter": self.adapter, "kind": self.kind,
                "payload_mode": self.payload_mode, "version": self.version()}


# ---------------------------------------------------------------------------
# Engine: builds requests, runs scanners, makes verdicts, decides
# ---------------------------------------------------------------------------
def _call_with_timeout(fn: Callable[[], Any], timeout: float) -> Any:
    box: dict = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as e:  # noqa: BLE001 - reported as a scan error
            box["error"] = e

    t = threading.Thread(target=run, name="two-key-scan", daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise ScanError(f"timeout after {timeout:.3g}s")
    if "error" in box:
        raise box["error"]
    return box["value"]


class ScanEngine:
    """Runs the configured scanners for one call and decides on their verdicts."""

    def __init__(self, scanners: Sequence[ContentScanner], settings: ScanSettings | None = None):
        self.scanners = list(scanners)
        self.settings = settings or ScanSettings()
        if not all(isinstance(s, ContentScanner) for s in self.scanners):
            raise TypeError("scanners must be ContentScanner instances")
        ids = [s.scanner_id for s in self.scanners]
        if len(set(ids)) != len(ids):
            raise ValueError("scanner_id values must be unique")
        if self.settings.dlp_overrides_data_class and not any(s.kind in ("dlp", "dlp+av") for s in self.scanners):
            raise ValueError("dlp_overrides_data_class=True needs at least one scanner of kind 'dlp' or 'dlp+av'")

    def describe(self) -> dict:
        return {"settings": self.settings.to_record(), "scanners": [s.describe() for s in self.scanners]}

    @staticmethod
    def build_parts(raw: Sequence[tuple[str, str, bytes]], alg: str,
                    provider: CryptoProvider | None) -> tuple[ScanPart, ...]:
        names: set = set()
        parts = []
        for name, ctype, data in raw:
            if not isinstance(name, str) or not name or name in names:
                raise ValueError(f"scan part names must be unique non-empty strings (got {name!r})")
            if not isinstance(data, (bytes, bytearray, memoryview)):
                raise TypeError(f"scan part {name!r}: data must be bytes")
            data = bytes(data)
            names.add(name)
            parts.append(ScanPart(name, str(ctype or "application/octet-stream"), data, len(data),
                                  digest_hex(data, alg, provider)))
        return tuple(parts)

    def run(self, tool: str, parts: tuple[ScanPart, ...], alg: str, provider: CryptoProvider | None,
            context: Mapping[str, Any] | None = None) -> list[ScanVerdict]:
        payload_digest = canonical_hash([p.info() for p in parts], alg, provider)
        requests = []
        for s in self.scanners:
            mode = s.payload_mode or self.settings.payload
            ps = parts if mode == "exact" else tuple(ScanPart(p.name, p.content_type, None, p.size, p.digest)
                                                     for p in parts)
            requests.append(ScanRequest(uuid.uuid4().hex, tool, alg, mode, payload_digest, ps, dict(context or {})))
        if self.settings.order == "parallel":
            out: list = [None] * len(self.scanners)

            def one(i: int) -> None:
                out[i] = self._one(self.scanners[i], requests[i])

            threads = [threading.Thread(target=one, args=(i,), daemon=True) for i in range(len(self.scanners))]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            return out
        verdicts = []
        for s, r in zip(self.scanners, requests):
            v = self._one(s, r)
            verdicts.append(v)
            if self.denies(v):
                break  # sequential: later scanners don't receive content for a call that is already denied
        return verdicts

    def _one(self, s: ContentScanner, req: ScanRequest) -> ScanVerdict:
        timeout = float(self.settings.timeout_seconds)
        t0 = time.perf_counter()
        try:
            rep = _call_with_timeout(lambda: s.scan(req, timeout), timeout + _GRACE_SECONDS)
            if not isinstance(rep, ScanReport):
                raise ScanError("scanner returned no ScanReport")
        except Exception as e:  # noqa: BLE001 - any failure is an error verdict
            rep = ScanReport("error", detail=f"{type(e).__name__}: {e}")
        return self.make_verdict(s, req, rep, (time.perf_counter() - t0) * 1000.0)

    @staticmethod
    def make_verdict(s: ContentScanner, req: ScanRequest, rep: ScanReport, elapsed_ms: float) -> ScanVerdict:
        outcome, detail = rep.outcome, rep.detail
        if outcome not in OUTCOMES or (outcome == "pending" and not s.supports_pending):
            outcome, detail = "error", f"invalid outcome {_clip(rep.outcome, 40)!r}"
        if rep.echoed_digest is not None and rep.echoed_digest != req.payload_digest:
            outcome, detail = "error", "digest_mismatch: the scanner reports a different payload digest"
        labels, classes = split_classes(_strings(rep.labels), _strings(rep.data_classes))
        return ScanVerdict(
            scanner_id=s.scanner_id, adapter=s.adapter, kind=s.kind,
            scanner_version=_clip(rep.scanner_version or s.version(), 120), outcome=outcome,
            payload_mode=req.payload_mode, digest_alg=req.digest_alg, payload_digest=req.payload_digest,
            parts=tuple(p.info() for p in req.parts), labels=labels, data_classes=classes,
            findings=_strings(rep.findings), elapsed_ms=elapsed_ms, detail=_clip(detail, _MAX_DETAIL),
            scan_id=rep.scan_id)

    def denies(self, v: ScanVerdict) -> bool:
        return v.outcome in ("block", "quarantine") or (v.outcome == "error" and self.settings.on_error == "block")

    @staticmethod
    def effective_data_class(verdicts: Sequence[ScanVerdict]) -> str:
        """The data class the DLP verdicts establish (used only with dlp_overrides_data_class=True).

        Exactly one class across the allowing DLP verdicts: that class. None, or
        more than one: ``classified``, the existing default for a data class
        that can't be determined (action.py, spec 5.2 / Claim 5). PLACEHOLDER
        pending Stephan: how several classes should combine is an open question.
        """
        classes = {c for v in verdicts if v.is_dlp and v.outcome == "allow" for c in v.data_classes}
        return next(iter(classes)) if len(classes) == 1 else DEFAULT_DATA_CLASS

    def decide(self, verdicts: Sequence[ScanVerdict], scope_data_class: Any) -> str | None:
        """Deny reason, or None. Blocks and quarantines always deny; errors deny if on_error='block'."""
        for v in verdicts:
            if v.outcome == "block":
                return f"scan_blocked:{v.scanner_id}"
            if v.outcome == "quarantine":
                return f"scan_quarantined:{v.scanner_id}"
            if v.outcome == "error" and self.settings.on_error == "block":
                return f"scan_error:{v.scanner_id}"
        if self.settings.dlp_overrides_data_class and self.effective_data_class(verdicts) != scope_data_class:
            return "scan_data_class_mismatch"
        return None


# ---------------------------------------------------------------------------
# Response mapping (vendor-agnostic) and the default request body
# ---------------------------------------------------------------------------
def _get_path(obj: Any, path: str | None) -> Any:
    if not path:
        return None
    cur = obj
    for key in path.split("."):
        if isinstance(cur, Mapping):
            cur = cur.get(key)
        elif isinstance(cur, list) and key.isdigit() and int(key) < len(cur):
            cur = cur[int(key)]
        else:
            return None
    return cur


@dataclass(frozen=True)
class ResponseMapping:
    """Maps a vendor's JSON response onto a ScanReport. Paths are dotted (``"result.verdict"``).

    ``outcome_map`` translates vendor outcome values (compared case-folded) to
    Two-Key outcomes; values that already are Two-Key outcomes map to
    themselves; anything else is an ``error``. ``label_to_data_class``
    translates vendor labels to Two-Key data classes. These maps are
    deployment configuration: Two-Key ships no vendor-specific defaults.
    """
    outcome_path: str = "outcome"
    outcome_map: Mapping[str, str] = field(default_factory=dict)
    labels_path: str | None = "labels"
    data_class_path: str | None = "data_classes"
    label_to_data_class: Mapping[str, str] = field(default_factory=dict)
    findings_path: str | None = "findings"
    version_path: str | None = "scanner_version"
    digest_path: str | None = "payload_digest"
    scan_id_path: str | None = "scan_id"
    detail_path: str | None = "detail"

    def apply(self, obj: Any) -> ScanReport:
        if not isinstance(obj, Mapping):
            raise ScanError("scanner response is not a JSON object")
        raw = _get_path(obj, self.outcome_path)
        key = raw.strip().casefold() if isinstance(raw, str) else None
        omap = {str(k).casefold(): v for k, v in self.outcome_map.items()}
        outcome = omap.get(key, key) if key is not None else None
        if outcome not in OUTCOMES:
            return ScanReport("error", detail=f"unmapped outcome {_clip(raw, 40)!r}")
        labels = _strings(_get_path(obj, self.labels_path))
        classes = list(_strings(_get_path(obj, self.data_class_path)))
        lmap = {str(k).casefold(): v for k, v in self.label_to_data_class.items()}
        classes += [lmap[lb.casefold()] for lb in labels if lb.casefold() in lmap]
        ver, dig = _get_path(obj, self.version_path), _get_path(obj, self.digest_path)
        sid, det = _get_path(obj, self.scan_id_path), _get_path(obj, self.detail_path)
        return ScanReport(outcome, labels, tuple(classes), _strings(_get_path(obj, self.findings_path)),
                          str(ver) if ver is not None else None, str(dig) if dig is not None else None,
                          _clip(det, _MAX_DETAIL) if det is not None else "", str(sid) if sid is not None else None)


def default_request_body(req: ScanRequest) -> dict:
    """The JSON body sent by the API and sidecar adapters unless a ``body_builder`` is given."""
    parts = []
    for p in req.parts:
        d = p.info()
        if p.data is not None:
            d["data_b64"] = base64.b64encode(p.data).decode("ascii")
        parts.append(d)
    return {"protocol": PROTOCOL, "request_id": req.request_id, "tool": req.tool, "digest_alg": req.digest_alg,
            "payload_mode": req.payload_mode, "payload_digest": req.payload_digest, "parts": parts}


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host in LOOPBACK:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# 1. Vendor API: REST (built in) or gRPC (grpc_transport)
# ---------------------------------------------------------------------------
Transport = Callable[[dict, dict, float], Any]   # (request body, headers, timeout) -> response mapping


def http_json_transport(url: str, *, allow_insecure_http: bool = False, ssl_context: ssl.SSLContext | None = None,
                        max_response_bytes: int = 1 << 20) -> Transport:
    """POST the request body as JSON to ``url`` and return the parsed JSON response.

    HTTPS is required except for loopback hosts, unless ``allow_insecure_http``.
    Non-2xx responses and oversize or non-JSON bodies raise ScanError.
    """
    u = urlparse(url)
    if u.scheme not in ("https", "http") or not u.hostname:
        raise ValueError(f"scanner endpoint must be an http(s) URL, got {url!r}")
    if u.scheme == "http" and not _is_loopback(u.hostname) and not allow_insecure_http:
        raise ValueError(f"refusing plain-HTTP scanner endpoint {url!r} (set allow_insecure_http for a LAN)")

    # A private opener: scanner traffic doesn't depend on a process-wide opener (install_opener / patched urlopen).
    opener = urllib.request.build_opener(*([urllib.request.HTTPSHandler(context=ssl_context)]
                                           if ssl_context is not None else []))

    def post(body: dict, headers: dict, timeout: float) -> Any:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json", "Accept": "application/json",
                                              **headers})
        try:
            with opener.open(req, timeout=timeout) as r:
                raw = r.read(max_response_bytes + 1)
        except urllib.error.HTTPError as e:
            raise ScanError(f"http_status_{e.code}") from None
        except (urllib.error.URLError, OSError) as e:
            raise ScanError(f"transport: {type(e).__name__}") from None
        if len(raw) > max_response_bytes:
            raise ScanError("response too large")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ScanError("response is not JSON") from None
    return post


def grpc_transport(target: str, method: str, *, channel_credentials: Any = None, allow_insecure: bool = False,
                   request_serializer: Callable[[dict], bytes] | None = None,
                   response_deserializer: Callable[[bytes], Any] | None = None) -> Transport:
    """A unary gRPC call to ``method`` (e.g. ``"/vendor.Scanner/Scan"``) on ``target`` (``host:port``).

    Needs the optional ``grpcio`` package (ScannerUnavailable otherwise).
    Messages are JSON bytes unless you pass the vendor's protobuf
    serializers (dict -> bytes, bytes -> dict). TLS channel credentials are
    required except for a loopback target, unless ``allow_insecure``.
    Request headers are sent as gRPC metadata (lower-cased).
    """
    try:
        import grpc  # type: ignore
    except ImportError:
        raise ScannerUnavailable("grpc_transport needs the optional 'grpcio' package") from None
    host = target.rsplit(":", 1)[0].strip("[]")
    if channel_credentials is None and not _is_loopback(host) and not allow_insecure:
        raise ValueError("refusing an insecure gRPC channel to a non-loopback target (pass channel_credentials)")
    channel = (grpc.secure_channel(target, channel_credentials) if channel_credentials is not None
               else grpc.insecure_channel(target))
    ser = request_serializer or (lambda d: json.dumps(d, separators=(",", ":")).encode("utf-8"))
    de = response_deserializer or (lambda b: json.loads(b.decode("utf-8")))
    call = channel.unary_unary(method, request_serializer=ser, response_deserializer=de)

    def invoke(body: dict, headers: dict, timeout: float) -> Any:
        try:
            return call(body, timeout=timeout, metadata=[(k.lower(), v) for k, v in headers.items()])
        except grpc.RpcError as e:
            raise ScanError(f"grpc: {e.code() if hasattr(e, 'code') else type(e).__name__}") from None
    return invoke


class VendorApiScanner(ContentScanner):
    """Adapter 1: a vendor's scanning API. Generic: endpoint, auth, and response mapping are configuration.

    Give either ``endpoint`` (REST: JSON POST) or ``transport`` (any callable
    ``(body, headers, timeout) -> response``, e.g. from ``grpc_transport``).
    ``credential`` is any ``two_key.judges.credentials.CredentialProvider``;
    its token is sent as ``{auth_header}: {auth_scheme} {token}`` and is
    never logged. ``body_builder`` adapts the request to the vendor's schema.
    """
    adapter = "vendor_api"

    def __init__(self, scanner_id: str, *, endpoint: str | None = None, transport: Transport | None = None,
                 credential: Any = None, auth_header: str = "Authorization", auth_scheme: str = "Bearer",
                 mapping: ResponseMapping | None = None, body_builder: Callable[[ScanRequest], dict] | None = None,
                 extra_headers: Mapping[str, str] | None = None, allow_insecure_http: bool = False,
                 kind: str = "dlp", payload_mode: str | None = None, version: str | None = None):
        super().__init__(scanner_id, kind=kind, payload_mode=payload_mode, version=version)
        if (endpoint is None) == (transport is None):
            raise ValueError("give exactly one of endpoint or transport")
        self.transport = transport or http_json_transport(endpoint, allow_insecure_http=allow_insecure_http)
        self.adapter = "vendor_api:rest" if endpoint else "vendor_api:custom"
        self.credential, self.auth_header, self.auth_scheme = credential, auth_header, auth_scheme
        self.mapping = mapping or ResponseMapping()
        self.body_builder = body_builder or default_request_body
        self.extra_headers = dict(extra_headers or {})

    def scan(self, request: ScanRequest, timeout: float) -> ScanReport:
        headers = dict(self.extra_headers)
        if self.credential is not None:
            try:
                tok = self.credential.get_token()
            except Exception as e:  # noqa: BLE001
                raise ScanError(f"credential: {type(e).__name__}") from None
            headers[self.auth_header] = f"{self.auth_scheme} {tok}" if self.auth_scheme else tok
        rep = self.mapping.apply(self.transport(self.body_builder(request), headers, timeout))
        if rep.scanner_version:
            self._seen_version = rep.scanner_version
        return rep


# ---------------------------------------------------------------------------
# 2. ICAP (RFC 3507)
# ---------------------------------------------------------------------------
_THREAT = re.compile(r"Threat=([^;]+)", re.I)


def _read_until(sock: socket.socket, buf: bytearray, marker: bytes, limit: int) -> int:
    while True:
        i = buf.find(marker)
        if i >= 0:
            return i
        if len(buf) > limit:
            raise ScanError("ICAP response too large")
        chunk = sock.recv(65536)
        if not chunk:
            raise ScanError("ICAP connection closed early")
        buf += chunk


def _read_exact(sock: socket.socket, buf: bytearray, n: int, limit: int) -> None:
    if n > limit:
        raise ScanError("ICAP response too large")
    while len(buf) < n:
        chunk = sock.recv(65536)
        if not chunk:
            raise ScanError("ICAP connection closed early")
        buf += chunk


def _read_chunked(sock: socket.socket, buf: bytearray, limit: int) -> bytes:
    body = bytearray()
    while True:
        i = _read_until(sock, buf, b"\r\n", limit)
        size_line = bytes(buf[:i]).split(b";", 1)[0].strip()
        del buf[:i + 2]
        try:
            n = int(size_line, 16)
        except ValueError:
            raise ScanError("ICAP: bad chunk size") from None
        if n == 0:
            j = _read_until(sock, buf, b"\r\n", limit)   # end of the (empty) trailer section
            del buf[:j + 2]
            return bytes(body)
        if len(body) + n > limit:
            raise ScanError("ICAP response too large")
        _read_exact(sock, buf, n + 2, limit)
        body += buf[:n]
        del buf[:n + 2]


def _worse(a: str, b: str) -> str:
    order = ("allow", "quarantine", "block")
    return a if order.index(a) >= order.index(b) else b


def _headers(block: bytes) -> tuple[str, dict]:
    lines = block.decode("iso-8859-1").split("\r\n")
    hdrs: dict = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return lines[0], hdrs


class IcapScanner(ContentScanner):
    """Adapter 2: an ICAP server (RFC 3507), e.g. a DLP appliance or c-icap with an AV module.

    Each payload part is sent as the body of an encapsulated HTTP message:
    ``REQMOD`` wraps it in a POST request (the agent sending it), ``RESPMOD``
    in a 200 response. ``204 No Content`` means unmodified (allow), and so
    does a ``200`` that returns the same body. A 200 that returns a
    different body, or replaces the request with a response (a block page),
    means the server changed or refused the content; so do
    ``X-Infection-Found`` / ``X-Violations-Found`` headers (recorded as
    findings). Either gives ``modified_outcome`` (default ``"block"``, since
    the exact bytes would not pass unchanged). ``ISTag`` and ``Service`` give
    the version. Other status codes are errors.

    Plain-text ICAP is allowed only to loopback unless ``allow_plaintext_remote``;
    pass ``tls`` (an SSLContext) for ICAP over TLS.
    """
    adapter = "icap"

    def __init__(self, scanner_id: str, *, host: str, port: int = 1344, service: str = "avscan",
                 method: str = "REQMOD", tls: ssl.SSLContext | None = None, allow_plaintext_remote: bool = False,
                 modified_outcome: str = "block", kind: str = "av", payload_mode: str | None = None,
                 version: str | None = None, max_response_bytes: int = 16 << 20):
        super().__init__(scanner_id, kind=kind, payload_mode=payload_mode, version=version)
        if method not in ("REQMOD", "RESPMOD"):
            raise ValueError("method must be REQMOD or RESPMOD")
        if modified_outcome not in ("block", "quarantine", "allow"):
            raise ValueError("modified_outcome must be block, quarantine, or allow")
        if tls is None and not _is_loopback(host) and not allow_plaintext_remote:
            raise ValueError("refusing plain-text ICAP to a non-loopback host (pass tls, or allow_plaintext_remote)")
        self.host, self.port, self.service, self.method, self.tls = host, int(port), service.strip("/"), method, tls
        self.modified_outcome, self.max_response_bytes = modified_outcome, max_response_bytes

    @property
    def uri(self) -> str:
        return f"icap://{self.host}:{self.port}/{self.service}"

    def _connect(self, timeout: float) -> socket.socket:
        s = socket.create_connection((self.host, self.port), timeout=timeout)
        return self.tls.wrap_socket(s, server_hostname=self.host) if self.tls else s

    def build_request(self, tool: str, part: ScanPart) -> bytes:
        data = part.data or b""
        target = f"/two-key/{tool}/{part.name}".replace(" ", "%20")
        body = (f"{len(data):x}\r\n".encode() + data + b"\r\n0\r\n\r\n") if data else b"0\r\n\r\n"
        if self.method == "REQMOD":
            req_hdr = (f"POST {target} HTTP/1.1\r\nHost: two-key.local\r\nContent-Type: {part.content_type}\r\n"
                       f"Content-Length: {len(data)}\r\n\r\n").encode()
            enc, encapsulated = f"req-hdr=0, req-body={len(req_hdr)}", req_hdr
        else:
            req_hdr = f"GET {target} HTTP/1.1\r\nHost: two-key.local\r\n\r\n".encode()
            res_hdr = (f"HTTP/1.1 200 OK\r\nContent-Type: {part.content_type}\r\n"
                       f"Content-Length: {len(data)}\r\n\r\n").encode()
            enc = f"req-hdr=0, res-hdr={len(req_hdr)}, res-body={len(req_hdr) + len(res_hdr)}"
            encapsulated = req_hdr + res_hdr
        head = (f"{self.method} {self.uri} ICAP/1.0\r\nHost: {self.host}\r\nAllow: 204\r\n"
                f"Encapsulated: {enc}\r\n\r\n").encode()
        return head + encapsulated + body

    def _exchange(self, payload: bytes, timeout: float) -> tuple[int, dict, list, bytes | None]:
        """Send one ICAP request; returns (status, ICAP headers, encapsulated section names, body or None)."""
        with self._connect(timeout) as s:
            s.settimeout(timeout)
            s.sendall(payload)
            buf, lim = bytearray(), self.max_response_bytes
            i = _read_until(s, buf, b"\r\n\r\n", lim)
            status_line, hdrs = _headers(bytes(buf[:i]))
            del buf[:i + 4]
            m = re.match(r"ICAP/1\.0\s+(\d{3})", status_line)
            if not m:
                raise ScanError("not an ICAP response")
            code = int(m.group(1))
            if code != 200:
                return code, hdrs, [], None
            sections = []
            for item in hdrs.get("encapsulated", "").split(","):
                if "=" in item:
                    name, off = item.strip().split("=", 1)
                    sections.append((name.strip(), int(off)))
            body_sec = [x for x in sections if x[0].endswith("-body")]
            if not body_sec:
                raise ScanError("ICAP 200 without a body section in Encapsulated")
            hdr_len = body_sec[0][1]
            _read_exact(s, buf, hdr_len, lim)   # encapsulated HTTP headers (only their section names are used)
            del buf[:hdr_len]
            body = _read_chunked(s, buf, lim) if body_sec[0][0] != "null-body" else None
            return code, hdrs, [n for n, _ in sections], body

    def options(self, timeout: float = 5.0) -> dict:
        """Send ICAP OPTIONS; returns its headers (lower-cased) and records the version."""
        req = f"OPTIONS {self.uri} ICAP/1.0\r\nHost: {self.host}\r\nEncapsulated: null-body=0\r\n\r\n".encode()
        code, hdrs, _, _ = self._exchange(req, timeout)
        if code != 200:
            raise ScanError(f"ICAP OPTIONS status {code}")
        self._learn_version(hdrs)
        return hdrs

    def _learn_version(self, hdrs: dict) -> None:
        v = " ".join(x for x in (hdrs.get("service"), f"ISTag={hdrs['istag']}" if hdrs.get("istag") else None) if x)
        if v:
            self._seen_version = v

    def scan(self, request: ScanRequest, timeout: float) -> ScanReport:
        request.require_content()
        findings, details, flagged = [], [], False
        for part in request.parts:
            code, hdrs, sections, body = self._exchange(self.build_request(request.tool, part), timeout)
            self._learn_version(hdrs)
            for h in ("x-infection-found", "x-violations-found", "x-virus-id"):
                if hdrs.get(h):
                    found = _THREAT.findall(hdrs[h]) or [hdrs[h]]
                    findings += [f"{part.name}:{f.strip()}" for f in found]
            if code == 204:
                continue
            if code != 200:
                return ScanReport("error", findings=tuple(findings), detail=f"ICAP status {code} on {part.name}")
            replaced = self.method == "REQMOD" and "res-hdr" in sections
            if replaced or (body or b"") != (part.data or b""):
                details.append(f"{part.name}: modified by ICAP server")
                flagged = True
        outcome = _worse("allow", self.modified_outcome) if (flagged or findings) else "allow"
        return ScanReport(outcome, findings=tuple(findings), scanner_version=self._seen_version,
                          detail="; ".join(details))


# ---------------------------------------------------------------------------
# 3. In-process plugins: registry, built-in pattern example, optional ClamAV
# ---------------------------------------------------------------------------
_PLUGINS: dict[str, Callable[..., ContentScanner]] = {}
ENTRY_POINT_GROUP = "two_key.scanners"


def register_plugin(name: str, factory: Callable[..., ContentScanner]) -> None:
    """Register an in-process scanner factory under ``name`` (e.g. a wrapper around a vendor SDK)."""
    if not isinstance(name, str) or not _ID_RE.match(name):
        raise ValueError("plugin name must match [A-Za-z0-9._:-]{1,64}")
    if not callable(factory):
        raise TypeError("factory must be callable")
    _PLUGINS[name] = factory


def available_plugins() -> list[str]:
    return sorted(_PLUGINS)


def create_plugin(name: str, **kwargs: Any) -> ContentScanner:
    if name not in _PLUGINS:
        raise ScannerUnavailable(f"no scanner plugin named {name!r} (registered: {available_plugins()})")
    s = _PLUGINS[name](**kwargs)
    if not isinstance(s, ContentScanner):
        raise TypeError(f"plugin {name!r} did not return a ContentScanner")
    return s


def load_entry_point_plugins(group: str = ENTRY_POINT_GROUP) -> list[str]:
    """Register factories that installed packages publish under the ``two_key.scanners`` entry-point group.

    Returns the names loaded. A plugin that fails to import is skipped and
    listed as ``"name: ErrorType"``, so one broken plugin doesn't stop the others.
    """
    from importlib.metadata import entry_points
    loaded = []
    for ep in entry_points().select(group=group):
        try:
            register_plugin(ep.name, ep.load())
            loaded.append(ep.name)
        except Exception as e:  # noqa: BLE001
            loaded.append(f"{ep.name}: {type(e).__name__}")
    return loaded


@dataclass(frozen=True)
class PatternRule:
    """``action``: ``label`` (record the label/data class and still allow), ``block``, or ``quarantine``."""
    name: str
    pattern: bytes
    label: str | None = None
    data_class: str | None = None
    action: str = "label"

    def __post_init__(self):
        if self.action not in ("label", "block", "quarantine"):
            raise ValueError("action must be label, block, or quarantine")
        if self.data_class is not None and self.data_class not in DATA_CLASSES:
            raise ValueError(f"data_class must be one of {DATA_CLASSES}")


# The EICAR antivirus test string: a harmless, industry-standard test file.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class PatternScanner(ContentScanner):
    """Built-in in-process example: regular expressions over each part's bytes.

    A demonstration of the plugin interface, not a DLP or AV product. Rules
    come from the deployment. ``PatternScanner.example_rules()`` has two
    illustrative ones (the EICAR test string, and a US SSN-shaped number
    labelled ``personal``); they are examples, not a recommended policy.
    Only rule names are recorded, never the matched text.
    """
    adapter = "plugin:pattern"

    def __init__(self, scanner_id: str = "pattern", *, rules: Sequence[PatternRule], kind: str = "dlp+av",
                 payload_mode: str | None = None, version: str | None = None):
        super().__init__(scanner_id, kind=kind, payload_mode=payload_mode, version=version)
        self.rules = [(r, re.compile(r.pattern)) for r in rules]
        digest = hashlib.sha256(canonical_bytes([[r.name, r.pattern.decode("latin-1"), r.label, r.data_class,
                                                  r.action] for r in rules])).hexdigest()[:16]
        self._version = version or f"pattern-rules:{digest}"

    @staticmethod
    def example_rules() -> list[PatternRule]:
        return [PatternRule("eicar-test", re.escape(EICAR), label="malware:eicar-test", action="block"),
                PatternRule("us-ssn-shape", rb"\b\d{3}-\d{2}-\d{4}\b", label="us_ssn", data_class="personal")]

    def scan(self, request: ScanRequest, timeout: float) -> ScanReport:
        request.require_content()
        labels, classes, findings, actions = [], [], [], set()
        for part in request.parts:
            for rule, rx in self.rules:
                if rx.search(part.data or b""):
                    findings.append(f"{part.name}:{rule.name}")
                    if rule.label:
                        labels.append(rule.label)
                    if rule.data_class:
                        classes.append(rule.data_class)
                    actions.add(rule.action)
        outcome = "block" if "block" in actions else "quarantine" if "quarantine" in actions else "allow"
        return ScanReport(outcome, tuple(labels), tuple(classes), tuple(findings))


class ClamdScanner(ContentScanner):
    """Optional ClamAV adapter through the ``clamd`` Python package (the engine itself runs in clamd).

    If ``clamd`` isn't installed, construction raises ScannerUnavailable: a
    deployment that asks for it learns at configuration time, and
    deployments that don't use it are unaffected. ``SidecarScanner`` with
    ``protocol="clamd-instream"`` talks to clamd without any extra package.
    """
    adapter = "plugin:clamd"

    def __init__(self, scanner_id: str = "clamav", *, unix_socket: str | None = None, host: str = "127.0.0.1",
                 port: int = 3310, kind: str = "av", payload_mode: str | None = None, version: str | None = None):
        super().__init__(scanner_id, kind=kind, payload_mode=payload_mode, version=version)
        try:
            import clamd  # type: ignore
        except ImportError:
            raise ScannerUnavailable("ClamdScanner needs the optional 'clamd' package "
                                     "(or use SidecarScanner(protocol='clamd-instream'))") from None
        self._clamd = clamd
        self._args = (unix_socket, host, port)

    def _client(self, timeout: float) -> Any:
        unix_socket, host, port = self._args
        if unix_socket:
            return self._clamd.ClamdUnixSocket(path=unix_socket, timeout=timeout)
        return self._clamd.ClamdNetworkSocket(host=host, port=port, timeout=timeout)

    def scan(self, request: ScanRequest, timeout: float) -> ScanReport:
        request.require_content()
        cd = self._client(timeout)
        try:
            self._seen_version = str(cd.version())
        except Exception:  # noqa: BLE001 - version is best effort
            pass
        findings = []
        for part in request.parts:
            res = cd.instream(io.BytesIO(part.data or b""))
            status, name = (res or {}).get("stream", ("ERROR", "no result"))
            if status == "FOUND":
                findings.append(f"{part.name}:{name}")
            elif status != "OK":
                raise ScanError(f"clamd: {status} {name}")
        return ScanReport("block" if findings else "allow", findings=tuple(findings),
                          scanner_version=self._seen_version)


register_plugin("pattern", PatternScanner)
register_plugin("clamav", ClamdScanner)


# ---------------------------------------------------------------------------
# 4. Sidecar / local daemon over a local socket
# ---------------------------------------------------------------------------
def send_frame(sock: socket.socket, obj: Any) -> None:
    """Two-Key JSON framing: 4-byte big-endian length, then canonical JSON."""
    data = canonical_bytes(obj)
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_n(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ScanError("sidecar connection closed early")
        buf += chunk
    return bytes(buf)


def recv_frame(sock: socket.socket, max_bytes: int = 16 << 20) -> Any:
    (n,) = struct.unpack(">I", _recv_n(sock, 4))
    if n > max_bytes:
        raise ScanError("sidecar frame too large")
    try:
        return json.loads(_recv_n(sock, n).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ScanError("sidecar frame is not JSON") from None


class SidecarScanner(ContentScanner):
    """Adapter 4: a scanner daemon on the same host (Unix socket, or loopback TCP only).

    Protocols:
    - ``"two-key-json"``: one request frame, one response frame (``send_frame``
      framing). The request is ``default_request_body``; the response is
      mapped with ``mapping``.
    - ``"clamd-instream"``: ClamAV clamd's ``zINSTREAM`` command, one
      connection per part, plus ``zVERSION`` for the version.

    Remote hosts are refused: a remote scanner is adapter 1 (API) or 2 (ICAP).
    """
    adapter = "sidecar"

    def __init__(self, scanner_id: str, *, unix_socket: str | None = None, host: str | None = None,
                 port: int | None = None, protocol: str = "two-key-json", mapping: ResponseMapping | None = None,
                 kind: str = "dlp", payload_mode: str | None = None, version: str | None = None,
                 max_response_bytes: int = 16 << 20, chunk_size: int = 65536):
        super().__init__(scanner_id, kind=kind, payload_mode=payload_mode, version=version)
        if (unix_socket is None) == (host is None):
            raise ValueError("give exactly one of unix_socket or host")
        if host is not None and (not _is_loopback(host) or port is None):
            raise ValueError("sidecar TCP must be a loopback host with a port (remote scanners: use API or ICAP)")
        if protocol not in ("two-key-json", "clamd-instream"):
            raise ValueError("protocol must be 'two-key-json' or 'clamd-instream'")
        self.unix_socket, self.host, self.port, self.protocol = unix_socket, host, port, protocol
        self.adapter = f"sidecar:{protocol}"
        self.mapping = mapping or ResponseMapping()
        self.max_response_bytes, self.chunk_size = max_response_bytes, chunk_size

    def _connect(self, timeout: float) -> socket.socket:
        if self.unix_socket is not None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect(self.unix_socket)
            except OSError:
                s.close()
                raise
            return s
        return socket.create_connection((self.host, self.port), timeout=timeout)

    def scan(self, request: ScanRequest, timeout: float) -> ScanReport:
        if self.protocol == "clamd-instream":
            return self._clamd(request, timeout)
        with self._connect(timeout) as s:
            send_frame(s, default_request_body(request))
            rep = self.mapping.apply(recv_frame(s, self.max_response_bytes))
        if rep.scanner_version:
            self._seen_version = rep.scanner_version
        return rep

    def _clamd_cmd(self, timeout: float, cmd: bytes, chunks: Iterable[bytes] = ()) -> str:
        with self._connect(timeout) as s:
            s.sendall(cmd)
            if cmd == b"zINSTREAM\0":
                for c in chunks:
                    s.sendall(struct.pack(">I", len(c)) + c)
                s.sendall(b"\0\0\0\0")
            buf = bytearray()
            while b"\0" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 65536:
                    raise ScanError("clamd reply too large")
        return bytes(buf).split(b"\0", 1)[0].decode("utf-8", "replace").strip()

    def _clamd(self, request: ScanRequest, timeout: float) -> ScanReport:
        request.require_content()
        try:
            self._seen_version = self._clamd_cmd(timeout, b"zVERSION\0") or self._seen_version
        except OSError:
            pass
        findings = []
        for part in request.parts:
            data = part.data or b""
            chunks = [data[i:i + self.chunk_size] for i in range(0, len(data), self.chunk_size)]
            reply = self._clamd_cmd(timeout, b"zINSTREAM\0", chunks)
            body = reply.split(":", 1)[1].strip() if ":" in reply else reply
            if body == "OK":
                continue
            if body.endswith(" FOUND"):
                findings.append(f"{part.name}:{body[:-6].strip()}")
            else:
                raise ScanError(f"clamd: {_clip(body, 100)}")
        return ScanReport("block" if findings else "allow", findings=tuple(findings),
                          scanner_version=self._seen_version)


# ---------------------------------------------------------------------------
# 5. Asynchronous post-send scanning (webhook / storage-event callback)
# ---------------------------------------------------------------------------
Listener = Callable[[Mapping[str, Any], ScanVerdict], None]


class AsyncCallbackScanner(ContentScanner):
    """Adapter 5: submit the payload to a scanner that answers later.

    ``submit(request, scan_id)`` hands the payload to the vendor (for example
    an upload to a scanning bucket, or a POST to an asynchronous API) and must
    arrange for the vendor's verdict to come back with the same ``scan_id``.
    The verdict arrives through ``deliver(scan_id, response)``: call it from a
    storage-event handler, or run ``WebhookReceiver``. ``response`` is mapped
    with ``mapping``.

    - ``hold_until_verdict=False`` (post-send): ``scan`` returns ``pending``
      at once, the call proceeds, and the later verdict is recorded in the
      ledger (``content_scan_async``). A block or quarantine verdict can then
      only flag after the fact: ``on_flag(record)`` is called if given.
      PLACEHOLDER default ``False`` pending Stephan (no change to when calls
      execute).
    - ``hold_until_verdict=True``: ``scan`` waits for the verdict, up to the
      engine's timeout, and the gateway decides on it like any other verdict.
      A verdict that arrives after the wait is recorded as post-send.
    """
    adapter = "async_callback"
    supports_pending = True

    def __init__(self, scanner_id: str, submit: Callable[[ScanRequest, str], Any], *,
                 hold_until_verdict: bool = False,      # PLACEHOLDER pending Stephan
                 mapping: ResponseMapping | None = None, on_flag: Callable[[dict], None] | None = None,
                 kind: str = "dlp", payload_mode: str | None = None, version: str | None = None,
                 max_pending: int = 10000):
        super().__init__(scanner_id, kind=kind, payload_mode=payload_mode, version=version)
        if not callable(submit):
            raise TypeError("submit must be callable")
        self.submit, self.hold_until_verdict = submit, bool(hold_until_verdict)
        self.mapping = mapping or ResponseMapping()
        self.on_flag, self.max_pending = on_flag, max_pending
        self._pending: dict[str, dict] = {}
        self._listeners: list[Listener] = []
        self._lock = threading.Lock()
        self.callback_errors: list[str] = []

    def subscribe(self, listener: Listener) -> None:
        with self._lock:
            if listener not in self._listeners:
                self._listeners.append(listener)

    def pending_ids(self) -> list[str]:
        with self._lock:
            return list(self._pending)

    def scan(self, request: ScanRequest, timeout: float) -> ScanReport:
        scan_id = uuid.uuid4().hex
        rec = {"request": request, "event": threading.Event(), "report": None, "held": self.hold_until_verdict,
               "t0": time.perf_counter()}
        with self._lock:
            if len(self._pending) >= self.max_pending:
                raise ScanError("too many pending async scans")
            self._pending[scan_id] = rec       # registered before submit, so an immediate callback finds it
        try:
            self.submit(request, scan_id)
        except Exception as e:  # noqa: BLE001
            with self._lock:
                self._pending.pop(scan_id, None)
            raise ScanError(f"submit: {type(e).__name__}") from None
        if not self.hold_until_verdict:
            return ScanReport("pending", scan_id=scan_id, detail="post-send: the verdict is recorded on arrival")
        got = rec["event"].wait(timeout)
        with self._lock:
            if got:
                self._pending.pop(scan_id, None)
            else:
                rec["held"] = False            # a late verdict is then recorded as post-send
        if not got:
            raise ScanError(f"hold_until_verdict: no verdict within {timeout:.3g}s (scan_id {scan_id})")
        rep = rec["report"]
        return ScanReport(rep.outcome, rep.labels, rep.data_classes, rep.findings, rep.scanner_version,
                          rep.echoed_digest, rep.detail, scan_id)

    def deliver(self, scan_id: str, response: Mapping[str, Any]) -> bool:
        """Accept a verdict for ``scan_id``. Returns False if the id is unknown or already answered."""
        try:
            rep = self.mapping.apply(response)
        except ScanError as e:
            rep = ScanReport("error", detail=str(e))
        if rep.outcome == "pending":
            rep = ScanReport("error", detail="a delivered verdict can't be 'pending'")
        with self._lock:
            rec = self._pending.get(scan_id)
            if rec is None or rec["report"] is not None:
                return False
            rec["report"] = rep
            held = rec["held"]
            if not held:
                self._pending.pop(scan_id, None)
            listeners = list(self._listeners)
        if held:
            rec["event"].set()
            return True
        req: ScanRequest = rec["request"]
        rep = ScanReport(rep.outcome, rep.labels, rep.data_classes, rep.findings, rep.scanner_version,
                         rep.echoed_digest, rep.detail, scan_id)
        verdict = ScanEngine.make_verdict(self, req, rep, (time.perf_counter() - rec["t0"]) * 1000.0)
        for fn in listeners:
            try:
                fn(req.context, verdict)
            except Exception as e:  # noqa: BLE001 - one listener must not stop the others
                self.callback_errors.append(f"listener: {type(e).__name__}")
        if verdict.outcome in ("block", "quarantine") and self.on_flag is not None:
            try:
                self.on_flag({"context": dict(req.context), "verdict": verdict.to_record()})
            except Exception as e:  # noqa: BLE001
                self.callback_errors.append(f"on_flag: {type(e).__name__}")
        return True


class WebhookReceiver:
    """A minimal HTTP receiver for asynchronous verdicts (adapter 5).

    ``POST {path}`` with a JSON body containing ``scan_id`` and the verdict
    fields, and the header ``X-Two-Key-Signature: sha256=<hex HMAC-SHA256 of
    the raw body under the shared secret>``. Unsigned or wrongly signed
    callbacks are refused (401): an unauthenticated channel would let anyone
    post an "allow". Binds to 127.0.0.1 by default; put a TLS-terminating
    proxy in front if the vendor calls in from outside.
    Responses: 204 accepted, 400 bad body, 401 bad signature, 404 unknown path or scan_id.
    """

    def __init__(self, scanner: AsyncCallbackScanner, secret: bytes, *, host: str = "127.0.0.1", port: int = 0,
                 path: str = "/two-key/scan-verdict", max_body: int = 1 << 20):
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
            raise ValueError("secret must be at least 16 bytes")
        self.scanner, self._secret, self.path, self.max_body = scanner, bytes(secret), path, max_body
        recv = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet: nothing from callbacks goes to stderr
                pass

            def do_POST(self):
                code = recv._handle(self.path, self.headers, self.rfile)
                self.send_response(code)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self._server = ThreadingHTTPServer((host, port), Handler)
        self._server.daemon_threads = True
        self._thread: threading.Thread | None = None

    @staticmethod
    def sign(secret: bytes, body: bytes) -> str:
        return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()

    def _handle(self, path: str, headers: Any, rfile: Any) -> int:
        if path != self.path:
            return 404
        try:
            n = int(headers.get("Content-Length", "-1"))
        except ValueError:
            return 400
        if not 0 <= n <= self.max_body:
            return 400
        body = rfile.read(n)
        if not hmac.compare_digest(self.sign(self._secret, body), headers.get("X-Two-Key-Signature", "")):
            return 401
        try:
            obj = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return 400
        if not isinstance(obj, dict) or not isinstance(obj.get("scan_id"), str):
            return 400
        return 204 if self.scanner.deliver(obj["scan_id"], obj) else 404

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}{self.path}"

    def start(self) -> "WebhookReceiver":
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.1},
                                        name="two-key-webhook", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> "WebhookReceiver":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
