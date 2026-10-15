"""Reference scanner adapters (0.6.0): ClamAV ``clamd``, ICAP, an external command, and a Python hook.

Each is an ``Inspector`` (scan.py): it sends each part of a call to an outside product and turns the answer
into ``clean``, ``flagged``, or ``unavailable``. None of them is a scanning engine, and none ever returns
content: a threat name or a matched string stays out of the result, the ledger, and the judges. Standard
library only; Linux, macOS, and Windows.

- ``ClamdInspector("127.0.0.1:3310")``: ``INSTREAM`` over TCP, or ``unix:/path/clamd.sock`` on Linux and
  macOS. ``OK`` is clean; ``FOUND`` is flagged (``malware``, or ``limits_exceeded`` for
  ``Heuristics.Limits.Exceeded``, or ``unreadable`` for ``Heuristics.Encrypted``); the stream size limit is
  flagged ``limits_exceeded``; anything else is unavailable.
- ``IcapInspector("icap://host:1344/service")``: RFC 3507 ``REQMOD`` (or ``RESPMOD``), one request per part,
  with ``Allow: 204``. 204, or a 200 that returns the part unchanged, is clean; a 200 carrying an infection or
  violation header, a block response, or a changed body, or an ICAP 403, is flagged; anything else is
  unavailable. ``icaps://`` uses TLS with the system's certificate
  checks.
- ``CommandInspector(["scanner", "--stdin"])``: the part on stdin, no shell, a minimal environment. Exit 0 is
  clean, 1 flagged, anything else (or the time limit) unavailable. A first stdout line
  ``two-key-categories: secret,credential`` names the categories.
- ``hook_inspector("module:function")``: your own code, ``function(request) -> ScanResult``.

``scanner_from_config`` builds a ``Scanner`` from the ``scan:`` block of ``proxy.yaml``.
"""

from __future__ import annotations

import importlib
import os
import re
import socket
import ssl
import struct
import subprocess  # nosec B404 - runs the operator's scanner command: an argv list, never a shell
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import quote, urlparse

from ._platform import WINDOWS, resolve_program
from .judges.config import HOOK
from .scan import CATEGORIES, DEFAULT_FIELD, DEFAULT_TIMEOUT_SECONDS, ScanConfigError, ScanRequest, \
    ScanResult, Scanner, combine

MAX_REPLY_BYTES = 64 * 1024
CHUNK_BYTES = 64 * 1024
DEFAULT_CLAMD_PORT = 3310
DEFAULT_ICAP_PORT = 1344
DEFAULT_ICAPS_PORT = 11344
# Variables a scanner command keeps from Two-Key's environment. Nothing else: judge keys stay out.
_KEEP_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR", "COMSPEC",
             "PATHEXT", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA")
_INFECTION_HEADERS = ("x-infection-found", "x-virus-id", "x-virus-name")
_VIOLATION_HEADERS = ("x-violations-found", "x-blocked", "x-block-reason", "x-dlp-violation")


class _Unanswered(Exception):
    """The product did not give an answer Two-Key can read."""


def _host_port(text: str, default_port: int, where: str) -> tuple[str, int]:
    parsed = urlparse(f"//{text}")
    try:
        port = parsed.port or default_port
    except ValueError:
        raise ScanConfigError(f"{where}: {text[:80]!r} has an invalid port") from None
    if not parsed.hostname or parsed.path or parsed.username or parsed.password:
        raise ScanConfigError(f"{where}: expected host:port, got {text[:80]!r}")
    return parsed.hostname, port


def _recv_until(sock: socket.socket, end: bytes, limit: int = MAX_REPLY_BYTES) -> bytes:
    data = b""
    while end not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise _Unanswered("reply too long")
    return data


_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]{1,16}")


def _dechunk(data: bytes) -> bytes | None:
    """The body of a chunked encoding (as ICAP encapsulates it), or None while it is incomplete."""
    out, i = bytearray(), 0
    while True:
        end = data.find(b"\r\n", i)
        if end < 0:
            return None
        size_text = data[i:end].split(b";", 1)[0].strip()       # a chunk extension such as "; ieof" is ignored
        if not _CHUNK_SIZE.fullmatch(size_text):
            raise _Unanswered("bad chunk size")
        size = int(size_text, 16)
        if size == 0:
            return bytes(out) if data[end:end + 4] == b"\r\n\r\n" else None
        start = end + 2
        if len(data) < start + size + 2:
            return None
        if data[start + size:start + size + 2] != b"\r\n":
            raise _Unanswered("bad chunk")
        out += data[start:start + size]
        i = start + size + 2


def _offsets(encapsulated: str) -> dict[str, int]:
    """``req-hdr=0, req-body=123`` as a mapping. Raises ``_Unanswered`` when it cannot be read."""
    out = {}
    for item in encapsulated.split(","):
        name, sep, value = item.strip().partition("=")
        if not sep or not value.strip().isdigit():
            raise _Unanswered("bad Encapsulated header")
        out[name.strip().casefold()] = int(value)
    return out


def _timeout(request: ScanRequest) -> float:
    left = request.remaining()
    if left <= 0:
        raise _Unanswered("no time left")
    return left


# --- ClamAV ---------------------------------------------------------------------------------------------

class ClamdInspector:
    """ClamAV's ``clamd`` over ``INSTREAM``: ``host:port`` (TCP 3310 by default) or ``unix:/path``."""

    def __init__(self, address: str, *, label: str = "clamav", chunk_bytes: int = CHUNK_BYTES):
        if not isinstance(address, str) or not address:
            raise ScanConfigError("clamd address: expected host:port or unix:/path/to/clamd.sock")
        if address.startswith("unix:"):
            if WINDOWS:
                raise ScanConfigError("clamd address: unix sockets are Linux and macOS only; use host:port")
            self.unix, self.host, self.port = address[5:], None, None
            if not os.path.isabs(self.unix):
                raise ScanConfigError("clamd address: unix: needs an absolute socket path")
        else:
            self.unix = None
            self.host, self.port = _host_port(address, DEFAULT_CLAMD_PORT, "clamd address")
        self.label = label
        self.chunk_bytes = chunk_bytes
        self._version: str | None = None

    def _connect(self, timeout: float) -> socket.socket:
        if self.unix is not None:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # pragma: no cover - not on Windows
            sock.settimeout(timeout)
            sock.connect(self.unix)
            return sock
        return socket.create_connection((self.host, self.port), timeout=timeout)

    def version(self, timeout: float) -> str:
        """``1.4.1/27400`` from ``VERSION`` (``ClamAV 1.4.1/27400/<date>``), cached after the first answer."""
        if self._version is None:
            with self._connect(timeout) as sock:
                sock.sendall(b"zVERSION\0")
                reply = _recv_until(sock, b"\0").rstrip(b"\0").decode("ascii", "replace").strip()
            text = reply.removeprefix("ClamAV ").strip()
            self._version = "/".join(text.split("/")[:2])
        return self._version

    @staticmethod
    def verdict(reply: str) -> ScanResult:
        """One ``INSTREAM`` reply as a result. A threat name is never kept."""
        text = reply.strip()
        if text.startswith("stream:"):
            text = text[len("stream:"):].strip()
        if text == "OK":
            return ScanResult.clean()
        if text.endswith(" FOUND"):
            name = text[:-len(" FOUND")]
            if name.startswith("Heuristics.Limits.Exceeded"):       # AlertExceedsMax: it could not finish
                return ScanResult.flagged("limits_exceeded")
            if name.startswith("Heuristics.Encrypted"):             # AlertEncrypted: it could not look inside
                return ScanResult.flagged("unreadable")
            return ScanResult.flagged("malware")
        if "size limit exceeded" in text:
            return ScanResult.flagged("limits_exceeded")
        return ScanResult.unavailable()

    def _scan(self, data: bytes, request: ScanRequest) -> ScanResult:
        with self._connect(_timeout(request)) as sock:
            try:
                sock.sendall(b"zINSTREAM\0")
                for i in range(0, len(data), self.chunk_bytes):
                    piece = data[i:i + self.chunk_bytes]
                    sock.sendall(struct.pack("!L", len(piece)) + piece)
                    sock.settimeout(_timeout(request))
                sock.sendall(struct.pack("!L", 0))
            except (BrokenPipeError, ConnectionResetError):
                pass        # clamd closes the stream at its size limit; its reply says so
            reply = _recv_until(sock, b"\0")
        if not reply:
            raise _Unanswered("no reply")
        return self.verdict(reply.rstrip(b"\0").decode("ascii", "replace"))

    def inspect(self, request: ScanRequest) -> ScanResult:
        try:
            version = self.version(_timeout(request))
        except (OSError, _Unanswered):
            version = ""
        results = []
        for part in request.parts:
            try:
                results.append(self._scan(part.data, request))
            except (OSError, _Unanswered):
                results.append(ScanResult.unavailable())
        out = combine(results)
        return ScanResult(out.verdict, out.categories, self.label, version)


# --- ICAP -----------------------------------------------------------------------------------------------

class IcapInspector:
    """An ICAP service (RFC 3507), as most commercial antivirus and DLP products offer: ``REQMOD`` by default,
    ``RESPMOD`` if the product scans responses. One request per part; ``Allow: 204``; no preview."""

    def __init__(self, url: str, *, method: str = "reqmod", label: str | None = None):
        parsed = urlparse(url) if isinstance(url, str) else None
        if parsed is None or parsed.scheme not in ("icap", "icaps") or not parsed.hostname:
            raise ScanConfigError("icap url: expected icap://host:1344/service (or icaps:// for TLS)")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ScanConfigError("icap url: no user, password, query, or fragment")
        if method not in ("reqmod", "respmod"):
            raise ScanConfigError("icap method: expected reqmod or respmod")
        try:
            port = parsed.port or (DEFAULT_ICAPS_PORT if parsed.scheme == "icaps" else DEFAULT_ICAP_PORT)
        except ValueError:
            raise ScanConfigError("icap url: invalid port") from None
        self.tls = parsed.scheme == "icaps"
        self.host, self.port = parsed.hostname, port
        self.service = parsed.path or "/"
        self.method = method
        self._label = label
        self.label = label or "icap"
        host = f"[{self.host}]" if ":" in self.host else self.host
        self.uri = f"{parsed.scheme}://{host}:{self.port}{self.service}"
        self.host_header = f"{host}:{self.port}"

    def request_bytes(self, tool: str, part: str, data: bytes) -> bytes:
        """The ICAP request for one part (public so a vendor can see exactly what Two-Key sends)."""
        target = f"/two-key/{quote(tool, safe='')}/{quote(part, safe='')}"
        body = (f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n0\r\n\r\n") if data else b"0\r\n\r\n"
        if self.method == "reqmod":
            req = (f"POST {target} HTTP/1.1\r\nHost: two-key.invalid\r\nContent-Type: application/octet-stream\r\n"
                   f"Content-Length: {len(data)}\r\n\r\n").encode("ascii")
            encapsulated = f"req-hdr=0, req-body={len(req)}"
            http = req
        else:
            req = f"GET {target} HTTP/1.1\r\nHost: two-key.invalid\r\n\r\n".encode("ascii")
            res = (f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {len(data)}"
                   "\r\n\r\n").encode("ascii")
            encapsulated = f"req-hdr=0, res-hdr={len(req)}, res-body={len(req) + len(res)}"
            http = req + res
        head = (f"{self.method.upper()} {self.uri} ICAP/1.0\r\nHost: {self.host_header}\r\nAllow: 204\r\n"
                f"Connection: close\r\nX-Two-Key-Tool: {tool}\r\nX-Two-Key-Part: {part}\r\n"
                f"Encapsulated: {encapsulated}\r\n\r\n").encode("ascii")
        return head + http + body

    def _connect(self, timeout: float) -> socket.socket:
        sock = socket.create_connection((self.host, self.port), timeout=timeout)
        if not self.tls:
            return sock
        try:     # TLS is verified: ssl.create_default_context() checks the certificate and the host name.
            return ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise

    def verdict(self, response: bytes, sent: bytes | None = None) -> tuple[ScanResult, str, str]:
        """(result, server label, ISTag) from an ICAP response. ``sent`` is the part's bytes: a 200 whose body
        differs from them (the product changed or removed content) is flagged."""
        head, _, rest = response.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        status = lines[0].split(" ", 2)
        if len(status) < 2 or not status[0].startswith("ICAP/") or not status[1].isdigit():
            raise _Unanswered("not an ICAP response")
        code = int(status[1])
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if sep:
                headers[name.strip().casefold()] = value.strip()
        server, istag = headers.get("server", ""), headers.get("istag", "").strip('"')
        if code == 204:
            return ScanResult.clean(), server, istag
        if code == 403:
            return ScanResult.flagged("policy"), server, istag
        if code != 200:
            return ScanResult.unavailable(), server, istag
        if any(h in headers for h in _INFECTION_HEADERS):
            return ScanResult.flagged("malware"), server, istag
        if any(h in headers for h in _VIOLATION_HEADERS):
            return ScanResult.flagged("policy"), server, istag
        offsets = _offsets(headers.get("encapsulated", "null-body=0"))
        if "res-hdr" in offsets:
            if self.method == "reqmod":     # a response instead of the request: the product blocked it
                return ScanResult.flagged("policy"), server, istag
            http_status = rest[offsets["res-hdr"]:].split(b"\r\n", 1)[0].split(b" ")
            if len(http_status) >= 2 and http_status[1].isdigit() and int(http_status[1]) >= 400:
                return ScanResult.flagged("policy"), server, istag
        if sent is not None:
            body_key = "req-body" if self.method == "reqmod" else "res-body"
            if body_key in offsets:
                body = _dechunk(rest[offsets[body_key]:])
                if body is None:
                    raise _Unanswered("body cut short")
            elif "null-body" in offsets:
                body = b""
            else:
                raise _Unanswered("no body in a 200")
            if body != sent:                # a modified 200: the product redacted or replaced something
                return ScanResult.flagged("policy"), server, istag
        return ScanResult.clean(), server, istag

    @staticmethod
    def _read_response(sock: socket.socket, sent: int) -> bytes:
        """The ICAP response head and, for a 200, everything it encapsulates (at most the part's size plus
        64 KiB), so a modified body can be told from an unchanged one."""
        response = _recv_until(sock, b"\r\n\r\n")
        head, sep, rest = response.partition(b"\r\n\r\n")
        if not sep:
            raise _Unanswered("no reply" if not response else "reply cut short")
        status = head.split(b"\r\n", 1)[0].split(b" ")
        if len(status) < 2 or status[1] != b"200":
            return response
        encapsulated = next((line.split(b":", 1)[1] for line in head.split(b"\r\n")[1:]
                             if line.split(b":", 1)[0].strip().lower() == b"encapsulated"), b"null-body=0")
        offsets = _offsets(encapsulated.decode("latin-1"))
        body = next((k for k in ("req-body", "res-body") if k in offsets), None)
        limit = sent + MAX_REPLY_BYTES
        while True:
            if body is None:
                if len(rest) >= offsets.get("null-body", 0):
                    break
            elif rest.endswith(b"\r\n\r\n") and _dechunk(rest[offsets[body]:]) is not None:
                break
            chunk = sock.recv(65536)
            if not chunk:
                raise _Unanswered("reply cut short")
            rest += chunk
            if len(rest) > limit:
                raise _Unanswered("reply too long")
        return head + sep + rest

    def _scan(self, tool: str, part: str, data: bytes, request: ScanRequest) -> tuple[ScanResult, str, str]:
        with self._connect(_timeout(request)) as sock:
            sock.sendall(self.request_bytes(tool, part, data))
            response = self._read_response(sock, len(data))
        return self.verdict(response, data)

    def inspect(self, request: ScanRequest) -> ScanResult:
        results, server, istag = [], "", ""
        for part in request.parts:
            try:
                result, server, istag = self._scan(request.tool, part.name, part.data, request)
            except (OSError, _Unanswered, ssl.SSLError):
                result = ScanResult.unavailable()
            results.append(result)
        out = combine(results)
        # The configured label, else the product's own Server header (cut to printable ASCII by Two-Key).
        return ScanResult(out.verdict, out.categories, self._label or server or "icap", istag)


# --- External command -----------------------------------------------------------------------------------

class CommandInspector:
    """An external scanner as a command: an argv list (no shell), each part on stdin.

    The command gets a minimal environment (``PATH``, ``HOME``, the locale and temp variables, and on Windows
    the system ones), plus ``TWO_KEY_TOOL``, ``TWO_KEY_PART``, and anything in ``env``. Exit 0 is clean, 1 is
    flagged, anything else unavailable. A first stdout line ``two-key-categories: secret,credential`` names
    the categories (known names only; ``policy`` otherwise). Other output is ignored and never recorded.
    """

    def __init__(self, argv: Iterable[str], *, env: Mapping[str, str] | None = None, label: str | None = None):
        if isinstance(argv, (str, bytes)) or not isinstance(argv, Iterable):
            raise ScanConfigError("command: expected a list (program, then arguments); it runs without a shell")
        argv = list(argv)
        if not argv or any(not isinstance(a, str) or not a or "\x00" in a for a in argv):
            raise ScanConfigError("command: expected a non-empty list of non-empty strings")
        extra = dict(env or {})
        if any(not isinstance(k, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) or not isinstance(v, str)
               or "\x00" in v for k, v in extra.items()):
            raise ScanConfigError("command env: expected NAME: value strings")
        self.argv, self.env = argv, extra
        self.label = label or os.path.basename(argv[0])

    def _environ(self, tool: str, part: str) -> dict[str, str]:
        out = {k: os.environ[k] for k in _KEEP_ENV if k in os.environ}
        out.update(self.env)
        out.update({"TWO_KEY_TOOL": tool, "TWO_KEY_PART": part})
        return out

    @staticmethod
    def _categories(stdout: bytes) -> tuple[str, ...]:
        first = stdout.split(b"\n", 1)[0].decode("ascii", "replace").strip()
        if not first.startswith("two-key-categories:"):
            return ("policy",)
        named = [c.strip() for c in first.split(":", 1)[1].split(",")]
        return tuple(c for c in named if c in CATEGORIES) or ("policy",)

    def _scan(self, tool: str, part: str, data: bytes, request: ScanRequest) -> ScanResult:
        argv = [resolve_program(self.argv[0])] + self.argv[1:]
        try:
            # The operator's own argv from its configuration (trusted, like a fact hook), run without a shell;
            # the agent's bytes reach it only on stdin, never as an argument.
            done = subprocess.run(argv, input=data, capture_output=True, timeout=_timeout(request),  # nosec B603  # nosemgrep: python.django.security.injection.command.subprocess-injection.subprocess-injection
                                  env=self._environ(tool, part), check=False)
        except subprocess.TimeoutExpired:
            return ScanResult.unavailable()
        if done.returncode == 0:
            return ScanResult.clean()
        if done.returncode == 1:
            return ScanResult.flagged(*self._categories(done.stdout))
        return ScanResult.unavailable()

    def inspect(self, request: ScanRequest) -> ScanResult:
        results = []
        for part in request.parts:
            try:
                results.append(self._scan(request.tool, part.name, part.data, request))
            except (OSError, _Unanswered):
                results.append(ScanResult.unavailable())
        out = combine(results)
        return ScanResult(out.verdict, out.categories, self.label, "")


# --- Python hook ----------------------------------------------------------------------------------------

class HookInspector:
    """Your own code as a scanner: ``fn(request) -> ScanResult`` (or an object with ``inspect``)."""

    def __init__(self, fn: Callable[[ScanRequest], ScanResult] | Any, label: str | None = None):
        inspect = getattr(fn, "inspect", None)
        self._fn = inspect if callable(inspect) else fn
        if not callable(self._fn):
            raise ScanConfigError("hook: expected a function of the request, or an object with inspect(request)")
        self.label = label or getattr(fn, "label", None) or getattr(fn, "__name__", "hook")

    def inspect(self, request: ScanRequest) -> ScanResult:
        return self._fn(request)


def hook_inspector(spec: str, label: str | None = None) -> HookInspector:
    """Import ``module:function`` (trusted operator configuration, like a fact hook) as an Inspector."""
    if not isinstance(spec, str) or not HOOK.fullmatch(spec):
        raise ScanConfigError(f"hook: expected module:function, got {str(spec)[:80]!r}")
    module, name = spec.split(":", 1)
    try:
        # The module named in the operator's configuration, checked by HOOK: trusted configuration.
        fn = getattr(importlib.import_module(module), name)  # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
    except (ImportError, AttributeError) as e:
        raise ScanConfigError(f"hook: cannot import {spec!r} ({type(e).__name__})") from None
    return HookInspector(fn, label or name)


# --- proxy.yaml ------------------------------------------------------------------------------------------

TYPES = ("clamd", "icap", "command", "python")
_TYPE_KEYS = {"clamd": {"address"}, "icap": {"url", "method"}, "command": {"command", "env"}, "python": {"hook"}}
_REQUIRED = {"clamd": "address", "icap": "url", "command": "command", "python": "hook"}
_COMMON = {"type", "timeout_seconds", "field", "label"}


def check_scan_block(data: Any, where: str = "scan") -> dict:
    """The shape of a ``scan:`` block: the type, its keys, and nothing else. Raises ``ScanConfigError``."""
    if not isinstance(data, Mapping):
        raise ScanConfigError(f"{where}: expected a mapping with type: {'|'.join(TYPES)}")
    kind = data.get("type")
    if kind not in TYPES:
        raise ScanConfigError(f"{where}.type: expected one of {list(TYPES)}")
    if "max_file_bytes" in data:
        raise ScanConfigError(f"{where}.max_file_bytes: replaced by max_bytes on each file under tools.<tool>.files, "
                              "the largest file that tool needs (docs/SCANNERS.md)")
    allowed = _COMMON | _TYPE_KEYS[kind]
    extra = sorted(str(k) for k in set(data) - allowed)
    if extra:
        raise ScanConfigError(f"{where}: unknown key(s) {extra} for type {kind}; allowed: {sorted(allowed)}")
    if _REQUIRED[kind] not in data:
        raise ScanConfigError(f"{where}.{_REQUIRED[kind]}: required for type {kind}")
    return dict(data)


def inspector_from_config(data: Mapping[str, Any], where: str = "scan") -> Any:
    data = check_scan_block(data, where)
    kind, label = data["type"], data.get("label")
    if label is not None and not isinstance(label, str):
        raise ScanConfigError(f"{where}.label: expected a string")
    if kind == "clamd":
        return ClamdInspector(data["address"], label=label or "clamav")
    if kind == "icap":
        return IcapInspector(data["url"], method=data.get("method", "reqmod"), label=label)
    if kind == "command":
        env = data.get("env")
        if env is not None and not isinstance(env, Mapping):
            raise ScanConfigError(f"{where}.env: expected a mapping of NAME: value")
        return CommandInspector(data["command"], env=env, label=label)
    return hook_inspector(data["hook"], label)


def scanner_from_config(data: Mapping[str, Any], files: Mapping[str, Iterable[Any]] | None = None,
                        where: str = "scan") -> Scanner:
    """A ``Scanner`` from a ``scan:`` block and each tool's declared files. Raises ``ScanConfigError``."""
    inspector = inspector_from_config(data, where)
    return Scanner(inspector, files=files or {},
                   timeout_seconds=data.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
                   field=data.get("field", DEFAULT_FIELD), label=data.get("label") or inspector.label)


__all__ = ["ClamdInspector", "CommandInspector", "HookInspector", "IcapInspector", "TYPES", "check_scan_block",
           "hook_inspector", "inspector_from_config", "scanner_from_config"]
