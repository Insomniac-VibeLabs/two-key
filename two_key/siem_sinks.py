# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Where the ledger copy goes (0.7.0): syslog over UDP, TCP, or TLS, and an HTTPS webhook.

Standard library only (``socket``, ``ssl``, ``http.client``): no new dependency and no extra. Linux,
macOS, and Windows.

| Sink | Standard | Default port | On the network |
| --- | --- | --- | --- |
| ``syslog`` ``transport: tls`` (the default) | RFC 5425 | 6514 | encrypted; the server certificate and hostname are always checked |
| ``syslog`` ``transport: tcp`` | RFC 6587 | 514 | plaintext; no silent drops while connected |
| ``syslog`` ``transport: udp`` | RFC 5426 | 514 | plaintext; may drop or be spoofed |
| ``webhook`` | HTTPS POST, one event per line | 443 | encrypted, as above; ``http://`` is plaintext |

Plaintext is refused under ``high_assurance`` and allowed elsewhere with a start-up warning (maintainer's
decision, 2026-10-16). There is no setting that turns a certificate check off.

A sink never holds a decision: :class:`~two_key.siem.Delivery` sends from its own thread, and a failure
here is a :class:`~two_key.siem.SiemError` that leaves the cursor where it was.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import os
import socket
import ssl
import threading
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from .siem import Message, SiemConfig, SiemConfigError, SiemError, now_text, read_secret_file

TYPES = ("syslog", "webhook")
TRANSPORTS = ("tls", "tcp", "udp")
FRAMINGS = ("octet", "newline")
DEFAULT_PORTS = {"tls": 6514, "tcp": 514, "udp": 514}
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_DATAGRAM = 2048         # RFC 5426 asks senders to keep a datagram small enough not to fragment
DEFAULT_BATCH_MAX = 100
GOODBYE_SECONDS = 1.0               # a close sends close_notify and waits no longer than this for the
                                    # collector's; ours is on the wire either way
MAX_HOSTNAME_CHARS = 255
MAX_APP_NAME_CHARS = 48
# Syslog facilities an operator may pick. local0 is the default; "two-key" is not a system service.
FACILITIES = {"kern": 0, "user": 1, "daemon": 3, "auth": 4, "syslog": 5, "authpriv": 10, "audit": 13,
              "local0": 16, "local1": 17, "local2": 18, "local3": 19, "local4": 20, "local5": 21,
              "local6": 22, "local7": 23}

_SYSLOG_KEYS = {"type", "host", "transport", "port", "framing", "facility", "app_name", "hostname",
                "ca_file", "cert_file", "key_file", "timeout_seconds", "max_datagram", "label"}
_WEBHOOK_KEYS = {"type", "url", "auth_header", "auth_value_file", "hmac_key_file", "ca_file", "cert_file",
                 "key_file", "timeout_seconds", "batch_max", "label"}
_TOP_KEYS = {"schema", "format", "replay_from", "sinks", "batch_max", "queue_max", "flush_seconds",
             "refused_token_interval_seconds"}


def _printable(value: Any, what: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SiemConfigError(f"{what}: expected a non-empty string")
    text = "".join(c for c in value.strip() if c.isprintable() and c not in " ")
    if not text or len(text) > limit:
        raise SiemConfigError(f"{what}: expected printable text of at most {limit} characters, with no spaces")
    return text


def _local_hostname() -> str:
    """This host's name for the syslog header, or ``-`` when it is not printable ASCII."""
    try:
        name = socket.gethostname()
    except OSError:
        return "-"
    name = "".join(c for c in name if 32 < ord(c) < 127)[:MAX_HOSTNAME_CHARS]
    return name or "-"


def _tls_context(ca_file: Path | None, cert_file: Path | None, key_file: Path | None, what: str):
    """A context that always checks the certificate and the hostname. TLS 1.2 at the lowest."""
    try:
        context = ssl.create_default_context(cafile=os.fspath(ca_file) if ca_file else None)
    except OSError as e:
        raise SiemConfigError(f"{what}.ca_file: {ca_file}: {e.strerror}") from None
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if cert_file is not None:
        if key_file is None:
            raise SiemConfigError(f"{what}.key_file: required with cert_file (the client certificate's key)")
        _owner_only(key_file, f"{what}.key_file")
        try:
            context.load_cert_chain(os.fspath(cert_file), os.fspath(key_file))
        except (OSError, ssl.SSLError) as e:
            raise SiemConfigError(f"{what}.cert_file: {cert_file}: {e}") from None
    elif key_file is not None:
        raise SiemConfigError(f"{what}.cert_file: required with key_file")
    return context


def _owner_only(path: Path, what: str) -> None:
    """Refuse a client key another account can read, the same way a principal key is refused."""
    from . import _platform
    try:
        fd = _platform.open_nofollow(os.fspath(path))
    except OSError as e:
        raise SiemConfigError(f"{what}: {path}: {e.strerror}") from None
    try:
        problem = _platform.access_problem(fd)
        if problem:
            raise SiemConfigError(f"{what}: {_platform.insecure(path, problem)}")
    finally:
        os.close(fd)


class SyslogSink:
    """One syslog collector. RFC 5424 messages; the body is whatever the renderer made (JSON or CEF).

    TCP and TLS keep one connection and frame each message by octet count (RFC 6587 / RFC 5425);
    ``framing: newline`` is there for a collector that wants a line per message. UDP sends one datagram per
    message and never splits one: an event too long for ``max_datagram`` is sent with its digests only, as
    ``truncated``.
    """

    def __init__(self, host: str, *, transport: str = "tls", port: int | None = None,
                 framing: str = "octet", facility: str = "local0", app_name: str = "two-key",
                 hostname: str | None = None, ca_file: Path | str | None = None,
                 cert_file: Path | str | None = None, key_file: Path | str | None = None,
                 timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
                 max_datagram: int = DEFAULT_MAX_DATAGRAM, label: str | None = None):
        if transport not in TRANSPORTS:
            raise SiemConfigError(f"siem.sinks[].transport: expected one of {list(TRANSPORTS)}")
        if framing not in FRAMINGS:
            raise SiemConfigError(f"siem.sinks[].framing: expected one of {list(FRAMINGS)}")
        if facility not in FACILITIES:
            raise SiemConfigError(f"siem.sinks[].facility: expected one of {sorted(FACILITIES)}")
        self.host = _printable(host, "siem.sinks[].host", MAX_HOSTNAME_CHARS)
        self.transport = transport
        self.port = _port(port, DEFAULT_PORTS[transport])
        self.framing = framing
        self.facility = FACILITIES[facility]
        self.facility_name = facility
        self.app_name = _printable(app_name, "siem.sinks[].app_name", MAX_APP_NAME_CHARS)
        self.hostname = (_printable(hostname, "siem.sinks[].hostname", MAX_HOSTNAME_CHARS)
                         if hostname is not None else _local_hostname())
        self.timeout_seconds = _timeout(timeout_seconds)
        self.max_datagram = _bounded_int(max_datagram, "siem.sinks[].max_datagram", 480, 65000)
        self.label = label or f"syslog:{self.host}:{self.port}/{transport}"
        self.plaintext = transport != "tls"
        self._context = (_tls_context(_as_path(ca_file), _as_path(cert_file), _as_path(key_file),
                                      "siem.sinks[]") if transport == "tls" else None)
        self._mutual = cert_file is not None
        self._lock = threading.Lock()
        self._socket: Any = None
        self._procid = str(os.getpid())

    @property
    def max_body_bytes(self) -> int | None:
        """What one body may hold. Only UDP has a limit; the header takes about 120 bytes of it."""
        return self.max_datagram - 160 if self.transport == "udp" else None

    def record(self) -> dict:
        """For the ``siem_configured`` ledger entry. Addresses and settings, never a secret."""
        return {"type": "syslog", "label": self.label, "transport": self.transport, "host": self.host,
                "port": self.port, "framing": self.framing, "facility": self.facility_name,
                "mutual_tls": self._mutual, "plaintext": self.plaintext}

    # -- the wire ----------------------------------------------------------

    def frame(self, message: Message) -> bytes:
        """The RFC 5424 message for one event, with the framing this transport uses."""
        pri = self.facility * 8 + message.severity
        msgid = "".join(c for c in message.msgid if c.isalnum() or c in "_-")[:32] or "-"
        stamp = message.sent_at or now_text()
        head = f"<{pri}>1 {stamp} {self.hostname} {self.app_name} {self._procid} {msgid} - "
        raw = (head + message.body).encode("utf-8", "replace")
        if self.transport == "udp" or self.framing == "newline":
            return raw
        return f"{len(raw)} ".encode("ascii") + raw

    def send(self, messages: Sequence[Message]) -> None:
        if not messages:
            return
        with self._lock:
            if self.transport == "udp":
                self._send_datagrams(messages)
            else:
                self._send_stream(messages)

    def _send_datagrams(self, messages: Sequence[Message]) -> None:
        sock = self._socket or self._open_datagram()
        for message in messages:
            frame = self.frame(message)[: self.max_datagram]
            try:
                sock.send(frame)
            except OSError as e:
                self._drop()
                raise SiemError(f"udp send failed: {e.strerror or type(e).__name__}") from None

    def _send_stream(self, messages: Sequence[Message]) -> None:
        sock = self._socket or self._open_stream()
        payload = b"".join(self.frame(m) + (b"\n" if self.framing == "newline" else b"") for m in messages)
        try:
            sock.sendall(payload)
        except (OSError, ssl.SSLError) as e:
            self._drop()
            raise SiemError(f"{self.transport} send failed: {_why(e)}") from None

    def _open_datagram(self):
        try:
            family, _, _, _, address = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_DGRAM)[0]
        except (OSError, IndexError) as e:
            raise SiemError(f"cannot resolve {self.host}: {_why(e)}") from None
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout_seconds)
        try:
            sock.connect(address)       # so a refused datagram is reported here, not silently dropped
        except OSError as e:
            sock.close()
            raise SiemError(f"cannot send to {self.host}:{self.port}: {_why(e)}") from None
        self._socket = sock
        return sock

    def _open_stream(self):
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout_seconds)
        except OSError as e:
            raise SiemError(f"cannot connect to {self.host}:{self.port}: {_why(e)}") from None
        try:        # an event is small, and a collector reads it as it arrives: no Nagle delay
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        if self._context is not None:
            try:
                sock = self._context.wrap_socket(sock, server_hostname=self.host)
            except (OSError, ssl.SSLError) as e:
                sock.close()
                raise SiemError(f"TLS to {self.host}:{self.port} failed: {_why(e)}") from None
        self._socket = sock
        return sock

    def _drop(self, *, graceful: bool = False) -> None:
        sock, self._socket = self._socket, None
        if sock is None:
            return
        if graceful:
            sock = self._goodbye(sock)
        try:
            sock.close()
        except OSError:
            pass

    def _goodbye(self, sock):
        """End the stream the way a collector expects before the socket goes: close_notify for TLS, then a
        half-close, so what was sent last is read as a finished message and not as a truncated stream
        (live run 8x, C15). Bounded by ``GOODBYE_SECONDS``; a collector that has already gone costs nothing.
        Returns the socket to close, which after ``unwrap`` is the one underneath."""
        try:
            sock.settimeout(min(self.timeout_seconds, GOODBYE_SECONDS))
            if isinstance(sock, ssl.SSLSocket):
                sock = sock.unwrap()
            sock.shutdown(socket.SHUT_WR)
        except (OSError, ssl.SSLError, ValueError):
            pass
        return sock

    def check(self) -> None:
        """Reach the collector once at start: a TLS handshake, a TCP connect, or a resolved address."""
        with self._lock:
            self._drop()
            if self.transport == "udp":
                self._open_datagram()
            else:
                self._open_stream()

    def close(self) -> None:
        with self._lock:
            self._drop(graceful=True)


class WebhookSink:
    """An HTTPS collector that takes a batch of events as one POST, one event per line.

    Redirects are not followed: a 3xx is a failure, reported by status code only, because a redirect could
    send the copy somewhere the operator did not configure. The optional header value and HMAC key are read
    from owner-only files and never logged, ledgered, or sent in an event.
    """

    def __init__(self, url: str, *, auth_header: str | None = None, auth_value_file: Path | str | None = None,
                 hmac_key_file: Path | str | None = None, ca_file: Path | str | None = None,
                 cert_file: Path | str | None = None, key_file: Path | str | None = None,
                 timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS, batch_max: int = DEFAULT_BATCH_MAX,
                 label: str | None = None, content_type: str = "application/x-ndjson"):
        parsed = urlparse(url) if isinstance(url, str) else None
        if parsed is None or parsed.scheme not in ("https", "http") or not parsed.hostname:
            raise SiemConfigError("siem.sinks[].url: expected https://host/path (http:// is plaintext)")
        if parsed.username or parsed.password:
            raise SiemConfigError("siem.sinks[].url: no user or password in the URL; use auth_value_file")
        self.url = url
        self.host = parsed.hostname
        self.plaintext = parsed.scheme == "http"
        self.port = parsed.port or (80 if self.plaintext else 443)
        self.target = parsed.path or "/"
        if parsed.query:
            self.target += f"?{parsed.query}"
        self.timeout_seconds = _timeout(timeout_seconds)
        self.batch_max = _bounded_int(batch_max, "siem.sinks[].batch_max", 1, 1000)
        self.label = label or f"webhook:{self.host}:{self.port}"
        self.content_type = content_type
        self.auth_header = (_printable(auth_header, "siem.sinks[].auth_header", 64)
                            if auth_header is not None else None)
        self._auth_value = (read_secret_file(auth_value_file, "siem.sinks[].auth_value_file")
                            if auth_value_file is not None else None)
        if self.auth_header is None and self._auth_value is not None:
            self.auth_header = "Authorization"
        if self.auth_header is not None and self._auth_value is None:
            raise SiemConfigError("siem.sinks[].auth_value_file: required with auth_header")
        self._hmac_key = (read_secret_file(hmac_key_file, "siem.sinks[].hmac_key_file").encode("utf-8")
                          if hmac_key_file is not None else None)
        self._context = (None if self.plaintext else
                         _tls_context(_as_path(ca_file), _as_path(cert_file), _as_path(key_file),
                                      "siem.sinks[]"))
        self._mutual = cert_file is not None
        self._lock = threading.Lock()

    max_body_bytes = None

    def record(self) -> dict:
        return {"type": "webhook", "label": self.label, "host": self.host, "port": self.port,
                "path": self.target.split("?")[0], "tls": not self.plaintext,
                "authenticated": self.auth_header is not None, "signed": self._hmac_key is not None,
                "mutual_tls": self._mutual, "plaintext": self.plaintext}

    def headers(self, body: bytes) -> dict:
        out = {"Content-Type": self.content_type, "Content-Length": str(len(body)),
               "User-Agent": "two-key-siem/1"}
        if self.auth_header and self._auth_value:
            out[self.auth_header] = self._auth_value
        if self._hmac_key:
            out["X-Two-Key-Signature"] = "sha256=" + hmac.new(self._hmac_key, body, hashlib.sha256).hexdigest()
        return out

    def send(self, messages: Sequence[Message]) -> None:
        if not messages:
            return
        with self._lock:
            for start in range(0, len(messages), self.batch_max):
                batch = messages[start: start + self.batch_max]
                self._post("\n".join(m.body for m in batch).encode("utf-8", "replace"))

    def _post(self, body: bytes) -> None:
        connection = self._connect()
        try:
            connection.request("POST", self.target, body=body, headers=self.headers(body))
            response = connection.getresponse()
            status = response.status
            response.read()
        except (OSError, ssl.SSLError, http.client.HTTPException) as e:
            raise SiemError(f"POST {self.host} failed: {_why(e)}") from None
        finally:
            connection.close()
        if 300 <= status < 400:
            raise SiemError(f"POST {self.host} was redirected (HTTP {status}); redirects are not followed")
        if not 200 <= status < 300:
            raise SiemError(f"POST {self.host} refused the batch (HTTP {status})")

    def _connect(self):
        try:
            if self.plaintext:
                return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout_seconds)
            # TLS is verified: _tls_context() checks the certificate and the host name and sets TLS 1.2
            # as the lowest version, with no setting that turns either check off.
            return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout_seconds,  # nosemgrep: python.lang.security.audit.httpsconnection-detected.httpsconnection-detected
                                               context=self._context)
        except (OSError, ssl.SSLError) as e:
            raise SiemError(f"cannot reach {self.host}:{self.port}: {_why(e)}") from None

    def check(self) -> None:
        """Open the connection once at start, so a bad certificate is a start-up warning, not a surprise
        at the first event. Nothing is posted."""
        connection = self._connect()
        try:
            connection.connect()
        except (OSError, ssl.SSLError) as e:
            raise SiemError(f"cannot reach {self.host}:{self.port}: {_why(e)}") from None
        finally:
            connection.close()

    def close(self) -> None:
        return None


def _why(error: Exception) -> str:
    """A short reason, with no address or certificate text beyond what the operator configured."""
    reason = getattr(error, "strerror", None) or getattr(error, "reason", None)
    return str(reason or type(error).__name__)[:120]


def _as_path(value: Any) -> Path | None:
    return None if value is None else Path(os.fspath(value))


def _port(value: Any, default: int) -> int:
    if value is None:
        return default
    return _bounded_int(value, "siem.sinks[].port", 1, 65535)


def _bounded_int(value: Any, what: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise SiemConfigError(f"{what}: expected an integer from {low} to {high}")
    return value


def _timeout(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 120:
        raise SiemConfigError("siem.sinks[].timeout_seconds: expected a number in (0, 120]")
    return float(value)


# ---------------------------------------------------------------------------- the siem: block


def _sink_mapping(item: Any, index: int) -> Mapping[str, Any]:
    if not isinstance(item, Mapping):
        raise SiemConfigError(f"siem.sinks[{index}]: expected a mapping with type: syslog or webhook")
    kind = item.get("type")
    if kind not in TYPES:
        raise SiemConfigError(f"siem.sinks[{index}].type: expected one of {list(TYPES)}")
    allowed = _SYSLOG_KEYS if kind == "syslog" else _WEBHOOK_KEYS
    extra = sorted(str(k) for k in set(item) - allowed)
    if extra:
        raise SiemConfigError(f"siem.sinks[{index}]: unknown key(s) {extra}; allowed: {sorted(allowed)}")
    return item


def _paths(item: Mapping[str, Any], base: Path, names: Iterable[str]) -> dict:
    out = {}
    for name in names:
        if item.get(name) is not None:
            path = Path(str(item[name])).expanduser()
            out[name] = path if path.is_absolute() else (base / path)
    return out


def sink_from_config(item: Any, base: Path, index: int = 0, content_type: str = "application/x-ndjson"):
    """One ``siem.sinks[]`` entry. A relative path is relative to the config file's directory."""
    item = _sink_mapping(item, index)
    settings = {k: v for k, v in item.items() if k not in ("type", "ca_file", "cert_file", "key_file",
                                                           "auth_value_file", "hmac_key_file", "host", "url")}
    if item["type"] == "syslog":
        if "host" not in item:
            raise SiemConfigError(f"siem.sinks[{index}].host: required")
        paths = _paths(item, base, ("ca_file", "cert_file", "key_file"))
        return SyslogSink(item["host"], **settings, **paths)
    if "url" not in item:
        raise SiemConfigError(f"siem.sinks[{index}].url: required")
    paths = _paths(item, base, ("ca_file", "cert_file", "key_file", "auth_value_file", "hmac_key_file"))
    return WebhookSink(item["url"], **settings, **paths, content_type=content_type)


def check_siem_block(data: Any, where: str = "siem") -> dict:
    """The ``siem:`` block of ``proxy.yaml``, checked for shape. The sinks are built when the proxy starts."""
    if not isinstance(data, Mapping):
        raise SiemConfigError(f"{where}: expected a mapping")
    extra = sorted(str(k) for k in set(data) - _TOP_KEYS)
    if extra:
        raise SiemConfigError(f"{where}: unknown key(s) {extra}; allowed: {sorted(_TOP_KEYS)}")
    sinks = data.get("sinks")
    if not isinstance(sinks, list) or not sinks:
        raise SiemConfigError(f"{where}.sinks: expected a non-empty list of sinks")
    for index, item in enumerate(sinks):
        _sink_mapping(item, index)
    return dict(data)


def siem_from_config(data: Mapping[str, Any], base: Path | str = ".") -> SiemConfig:
    """A :class:`~two_key.siem.SiemConfig` from a checked ``siem:`` block."""
    data = check_siem_block(data)
    base = Path(base)
    settings: dict[str, Any] = {}
    for name in ("schema", "format", "replay_from"):
        if name in data:
            settings[name] = _printable(data[name], f"siem.{name}", 16)
    for name in ("batch_max", "queue_max"):
        if name in data:
            settings[name] = _bounded_int(data[name], f"siem.{name}", 1, 1_000_000)
    for name in ("flush_seconds", "refused_token_interval_seconds"):
        if name in data:
            settings[name] = _timeout(data[name])
    renderer_type = "application/x-ndjson" if settings.get("format", "json") == "json" else "text/plain"
    sinks = tuple(sink_from_config(item, base, index, renderer_type)
                  for index, item in enumerate(data["sinks"]))
    return SiemConfig(sinks=sinks, **settings)


__all__ = ["DEFAULT_PORTS", "FACILITIES", "FRAMINGS", "SyslogSink", "TRANSPORTS", "TYPES", "WebhookSink",
           "check_siem_block", "siem_from_config", "sink_from_config"]
