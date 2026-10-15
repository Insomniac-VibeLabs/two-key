"""Stdlib HTTP transport for Path B judges.

No vendor SDK. Connections are pooled per origin (scheme, host, port) and shared across threads and
quorum rounds (#6): a request takes an idle connection or opens one, and gives it back after a clean
response. A connection that errored, was redirected, said ``Connection: close``, or answered with an
error status is closed, never pooled. One connection serves one request at a time.
Redirects are not followed, so a judge credential is never sent to a second
host. Transient failures (connection drop, 429, 502, 503, 504) are retried
inside the caller's timeout, at most twice. A response that was parsed is
never retried. There is no other path: 0.2.3 removed the
``TWOKEY_DOCCHECK_FAKE_LLM`` switch, which sent calls through
``urllib.request.urlopen`` and so followed redirects with the credential (#47).
"""

from __future__ import annotations

import http.client
import json
import ssl
import threading
import time
import urllib.error
from urllib.parse import urlsplit

from ..strict import StrictParseError, loads_json

_MAX_ATTEMPTS = 3
_MAX_BODY = 1_000_000
_TRANSIENT_STATUS = {429, 502, 503, 504}
_MAX_IDLE_PER_ORIGIN = 4
_lock = threading.Lock()
_idle: dict[tuple, list] = {}       # origin -> idle connections, guarded by _lock


class TransientHTTPError(Exception):
    def __init__(self, original: BaseException):
        super().__init__(str(original))
        self.original = original


def _close(conn) -> None:
    try:
        conn.close()
    except Exception:
        pass


def _checkout(parts, timeout: float):
    port = parts.port or (443 if parts.scheme == "https" else 80)
    key = (parts.scheme, parts.hostname, port)
    with _lock:
        idle = _idle.get(key)
        conn = idle.pop() if idle else None
    if conn is None:
        if parts.scheme == "https":
            # TLS is verified: ssl.create_default_context() checks the certificate and the host name.
            conn = http.client.HTTPSConnection(parts.hostname, port, timeout=timeout,  # nosemgrep: python.lang.security.audit.httpsconnection-detected.httpsconnection-detected
                                               context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(parts.hostname, port, timeout=timeout)
    else:
        conn.timeout = timeout
        if conn.sock is not None:
            conn.sock.settimeout(timeout)
    return key, conn


def _checkin(key, conn) -> None:
    with _lock:
        idle = _idle.setdefault(key, [])
        if len(idle) < _MAX_IDLE_PER_ORIGIN:
            idle.append(conn)
            return
    _close(conn)


def _once(url: str, headers: dict, payload: bytes, timeout: float) -> dict:
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError(f"invalid judge url {url!r}")
    key, conn = _checkout(parts, timeout)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    sent = {"Host": parts.hostname, "Content-Type": "application/json",
            "Content-Length": str(len(payload)), "Connection": "keep-alive", "Accept": "application/json"}
    for name, value in headers.items():
        if name.lower() in ("host", "content-length", "connection"):
            continue
        sent[name] = value
    try:
        conn.request("POST", path, body=payload, headers=sent)
        resp = conn.getresponse()
        raw = resp.read(_MAX_BODY + 1)
    except Exception as e:
        _close(conn)
        raise TransientHTTPError(e) from e
    if len(raw) > _MAX_BODY:
        _close(conn)
        raise urllib.error.HTTPError(url, resp.status, "response too large", resp.headers, None)
    if resp.status in (301, 302, 303, 307, 308):
        _close(conn)
        raise urllib.error.HTTPError(url, resp.status, "redirect refused", resp.headers, None)
    reusable = resp.headers.get("connection", "").lower() != "close"
    if resp.status in _TRANSIENT_STATUS:
        _close(conn)
        raise TransientHTTPError(urllib.error.HTTPError(url, resp.status, resp.reason, resp.headers, None))
    if resp.status >= 400:
        _close(conn)
        raise urllib.error.HTTPError(url, resp.status, resp.reason, resp.headers, None)
    try:
        parsed = loads_json(raw.decode("utf-8"))
    except (UnicodeDecodeError, StrictParseError) as e:
        _close(conn)
        raise urllib.error.HTTPError(url, resp.status, f"not json: {e}", resp.headers, None) from e
    if reusable:
        _checkin(key, conn)
    else:
        _close(conn)
    return parsed


def pooled_transport(url: str, headers: dict, body: dict, timeout: float) -> dict:
    """Reuse a pooled connection to the origin. Retries only transient failures inside timeout."""
    deadline = time.monotonic() + max(0.0, float(timeout))
    payload = json.dumps(body).encode()
    last: BaseException | None = None
    for attempt in range(_MAX_ATTEMPTS):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            return _once(url, headers, payload, remaining)
        except TransientHTTPError as e:
            last = e.original
            if attempt + 1 >= _MAX_ATTEMPTS:
                break
            delay = min(0.05 * (2 ** attempt), max(0.0, deadline - time.monotonic() - 0.01))
            if delay > 0:
                time.sleep(delay)
    if isinstance(last, urllib.error.HTTPError):
        raise last
    raise TimeoutError("judge transport failed") if last is None else last


def reset_pool() -> None:
    """Close every idle pooled connection. Tests use this between cases."""
    with _lock:
        conns = [c for idle in _idle.values() for c in idle]
        _idle.clear()
    for conn in conns:
        _close(conn)
