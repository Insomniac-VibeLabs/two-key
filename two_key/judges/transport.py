"""Stdlib HTTP transport for Path B judges.

No vendor SDK. Each thread keeps one connection per origin and reuses it.
Redirects are not followed, so a judge credential is never sent to a second
host. Transient failures (connection drop, 429, 502, 503, 504) are retried
inside the caller's timeout, at most twice. A response that was parsed is
never retried.

TWOKEY_DOCCHECK_FAKE_LLM=1 keeps urllib.request.urlopen so the documentation
checker's fake can intercept calls. That path is not used otherwise.
"""

from __future__ import annotations

import http.client
import json
import os
import ssl
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

_MAX_ATTEMPTS = 3
_MAX_BODY = 1_000_000
_TRANSIENT_STATUS = {429, 502, 503, 504}
_local = threading.local()


class TransientHTTPError(Exception):
    def __init__(self, original: BaseException):
        super().__init__(str(original))
        self.original = original


def urllib_transport(url: str, headers: dict, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (scheme checked in LLMJudge)
        return json.loads(r.read(_MAX_BODY + 1).decode("utf-8"))


def _pool() -> dict:
    pool = getattr(_local, "pool", None)
    if pool is None:
        pool = {}
        _local.pool = pool
    return pool


def _drop(key) -> None:
    conn = _pool().pop(key, None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass


def _connection(parts, timeout: float):
    port = parts.port or (443 if parts.scheme == "https" else 80)
    key = (parts.scheme, parts.hostname, port)
    conn = _pool().get(key)
    if conn is None:
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(parts.hostname, port, timeout=timeout,
                                               context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(parts.hostname, port, timeout=timeout)
        _pool()[key] = conn
    else:
        conn.timeout = timeout
    return key, conn


def _once(url: str, headers: dict, payload: bytes, timeout: float) -> dict:
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError(f"invalid judge url {url!r}")
    key, conn = _connection(parts, timeout)
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
        _drop(key)
        raise TransientHTTPError(e) from e
    if len(raw) > _MAX_BODY:
        _drop(key)
        raise urllib.error.HTTPError(url, resp.status, "response too large", resp.headers, None)
    if resp.status in (301, 302, 303, 307, 308):
        _drop(key)
        raise urllib.error.HTTPError(url, resp.status, "redirect refused", resp.headers, None)
    if resp.headers.get("connection", "").lower() == "close":
        _drop(key)
    if resp.status in _TRANSIENT_STATUS:
        _drop(key)
        raise TransientHTTPError(urllib.error.HTTPError(url, resp.status, resp.reason, resp.headers, None))
    if resp.status >= 400:
        _drop(key)
        raise urllib.error.HTTPError(url, resp.status, resp.reason, resp.headers, None)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        _drop(key)
        raise urllib.error.HTTPError(url, resp.status, f"not json: {e}", resp.headers, None) from e


def pooled_transport(url: str, headers: dict, body: dict, timeout: float) -> dict:
    """Reuse a per-thread connection. Retries only transient failures inside timeout."""
    if os.environ.get("TWOKEY_DOCCHECK_FAKE_LLM") == "1":
        return urllib_transport(url, headers, body, timeout)
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
    """Close this thread's pooled connections. Tests use this between cases."""
    for key in list(_pool()):
        _drop(key)
