#!/usr/bin/env python3
"""Take Two-Key's SIEM copy and index it into Elasticsearch. Example code, standard library only.

A collector in front of Elasticsearch, the way a real one would sit there: it terminates syslog over
TLS (RFC 5425 octet counting or a line per message) and the HTTPS webhook, then posts the events to
``_bulk`` through an ingest pipeline. It reads Two-Key; it never answers it, and it holds no Two-Key
key: the copy is one way out of that process.

    python3 receiver.py --cert server.pem --key server.key            # TLS syslog on 6514
    python3 receiver.py --cert server.pem --key server.key --print    # no Elasticsearch, just stdout
    python3 receiver.py --plain --syslog-port 5514 --print            # plaintext, a quick local try

An event's ``seq`` and ``entry_hash`` are its document id, so a replay after an outage updates the
document instead of adding a second copy. Nothing here is a product: no retention, no alerting, no
authentication beyond the optional header and HMAC checks below.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import json
import socketserver
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

MAX_BODY_BYTES = 8 * 1024 * 1024        # one POST; Two-Key batches 100 events by default
READ_BYTES = 65536


class Collector:
    """Where every event lands, whichever sink it came in on."""

    def __init__(self, *, elasticsearch: str | None, index: str, pipeline: str | None,
                 to_stdout: bool, expect: int | None):
        self.elasticsearch = elasticsearch
        self.index = index
        self.pipeline = pipeline
        self.to_stdout = to_stdout
        self.expect = expect
        self.count = 0
        self.problems: list[str] = []
        self._lock = threading.Lock()
        self._enough = threading.Event()

    def take(self, body: str, *, source: str, msgid: str | None = None) -> None:
        body = body.strip()
        if not body:
            return
        document = self._document(body, msgid)
        document["event_source"] = source
        with self._lock:
            self.count += 1
            if self.to_stdout:
                print(json.dumps(document, sort_keys=True), flush=True)
            else:
                self._index(document)
            if self.expect is not None and self.count >= self.expect:
                self._enough.set()

    def wait(self, seconds: float) -> bool:
        return self._enough.wait(seconds)

    @staticmethod
    def _document(body: str, msgid: str | None) -> dict:
        """A JSON event becomes the document. A CEF line is kept as text, which is all CEF is."""
        if body.startswith("CEF:0|"):
            return {"message": body, "format": "cef", "kind": msgid}
        try:
            document = json.loads(body)
        except ValueError:
            return {"message": body, "format": "unparsed", "kind": msgid}
        if not isinstance(document, dict):
            return {"message": body, "format": "unparsed", "kind": msgid}
        if msgid and msgid != "-":
            document.setdefault("kind", msgid)
        return document

    def _index(self, document: dict) -> None:
        action: dict = {"index": {"_index": self.index}}
        identity = _document_id(document)
        if identity:
            action["index"]["_id"] = identity
        payload = (json.dumps(action) + "\n" + json.dumps(document) + "\n").encode("utf-8")
        target = "/_bulk" + (f"?pipeline={self.pipeline}" if self.pipeline else "")
        status, answer = _post(self.elasticsearch or "", target, payload, "application/x-ndjson")
        if status is None or not 200 <= status < 300:
            self.problems.append(f"Elasticsearch refused an event (HTTP {status}): {answer[:200]}")
        elif '"errors":true' in answer.replace(" ", ""):
            self.problems.append(f"Elasticsearch reported an item error: {answer[:200]}")


def _document_id(document: dict) -> str | None:
    seq, entry_hash = document.get("seq"), document.get("entry_hash")
    if isinstance(seq, int) and seq >= 0 and isinstance(entry_hash, str) and entry_hash:
        return f"{seq}-{entry_hash[:32]}"
    return None


def _post(base: str, target: str, body: bytes, content_type: str):
    """POST to Elasticsearch. The example runs it over loopback, so plain HTTP is the default there."""
    parsed = urlparse(base if "://" in base else f"http://{base}")
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # TLS is verified: create_default_context() checks the certificate and the host name.
        connection = http.client.HTTPSConnection(parsed.hostname or "", parsed.port or 443,  # nosemgrep: python.lang.security.audit.httpsconnection-detected.httpsconnection-detected
                                                 timeout=10, context=context)
    else:
        connection = http.client.HTTPConnection(parsed.hostname or "", parsed.port or 9200, timeout=10)
    try:
        connection.request("POST", (parsed.path.rstrip("/") + target) or target, body=body,
                           headers={"Content-Type": content_type, "Content-Length": str(len(body))})
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8", "replace")
    except OSError as e:
        return None, str(e)
    finally:
        connection.close()


# -- syslog ------------------------------------------------------------------

def frames(buffer: bytes):
    """Split a stream into messages: octet counting (``123 <134>1 ...``) or a line per message."""
    out: list[bytes] = []
    while buffer:
        head = buffer.split(b" ", 1)
        if len(head) == 2 and head[0].isdigit():
            length = int(head[0])
            start = len(head[0]) + 1
            if len(buffer) < start + length:
                break
            out.append(buffer[start:start + length])
            buffer = buffer[start + length:]
            continue
        line, newline, rest = buffer.partition(b"\n")
        if not newline:
            break
        out.append(line)
        buffer = rest
    return out, buffer


def message_of(raw: str):
    """The MSGID (Two-Key sends the ledger kind) and the event, from an RFC 5424 message.

    The header is PRI+VERSION, timestamp, hostname, app name, process id, MSGID, structured data, then the
    message, so the MSGID is the sixth field and the structured-data placeholder ("-") is the seventh.
    """
    parts = raw.split(" ", 7)
    if len(parts) == 8 and parts[0].startswith("<"):
        return parts[5], parts[7]
    brace = raw.find("{")
    return None, raw[brace:] if brace >= 0 else raw


class SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self):
        buffer = b""
        while True:
            try:
                chunk = self.request.recv(READ_BYTES)
            except (OSError, ssl.SSLError):
                return
            if not chunk:
                break
            buffer += chunk
            messages, buffer = frames(buffer)
            for message in messages:
                msgid, body = message_of(message.decode("utf-8", "replace"))
                self.server.collector.take(body, source="syslog", msgid=msgid)      # type: ignore[attr-defined]


class SyslogServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, collector: Collector, context: ssl.SSLContext | None):
        super().__init__(address, SyslogHandler)
        self.collector = collector
        if context is not None:
            self.socket = context.wrap_socket(self.socket, server_side=True)


# -- webhook -----------------------------------------------------------------

class WebhookHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "two-key-example-receiver"

    def do_POST(self):                                      # noqa: N802 - the name http.server wants
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            self.send_error(413, "expected a body of at most 8 MiB")
            return
        body = self.rfile.read(length)
        if not self._allowed(body):
            self.send_error(401, "the authorization header or the signature did not match")
            return
        for line in body.decode("utf-8", "replace").splitlines():
            self.server.collector.take(line, source="webhook")                      # type: ignore[attr-defined]
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _allowed(self, body: bytes) -> bool:
        expected = self.server.auth_value                                           # type: ignore[attr-defined]
        if expected is not None:
            sent = self.headers.get("Authorization") or ""
            if not hmac.compare_digest(sent, expected):
                return False
        key = self.server.hmac_key                                                  # type: ignore[attr-defined]
        if key is not None:
            sent = self.headers.get("X-Two-Key-Signature") or ""
            want = "sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sent, want):
                return False
        return True

    def log_message(self, fmt, *args):
        """Keep the request line and the status out of the log: a URL is not ours to print."""


class WebhookServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, collector: Collector, context: ssl.SSLContext | None,
                 auth_value: str | None, hmac_key: bytes | None):
        super().__init__(address, WebhookHandler)
        self.collector = collector
        self.auth_value = auth_value
        self.hmac_key = hmac_key
        if context is not None:
            self.socket = context.wrap_socket(self.socket, server_side=True)


# -- start -------------------------------------------------------------------

def server_context(cert: str | None, key: str | None, client_ca: str | None) -> ssl.SSLContext | None:
    if cert is None:
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    if client_ca:                       # mutual TLS: Two-Key sends cert_file and key_file
        context.load_verify_locations(client_ca)
        context.verify_mode = ssl.CERT_REQUIRED
    return context


def read_file(path: str | None) -> str | None:
    return Path(path).read_text(encoding="utf-8").strip() if path else None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bind", default="127.0.0.1", help="the address to listen on (default loopback)")
    parser.add_argument("--syslog-port", type=int, default=6514)
    parser.add_argument("--webhook-port", type=int, default=0, help="0 leaves the webhook off")
    parser.add_argument("--cert", help="the server certificate, PEM")
    parser.add_argument("--key", help="its private key, PEM")
    parser.add_argument("--client-ca", help="require a client certificate signed by this CA")
    parser.add_argument("--plain", action="store_true", help="no TLS (plaintext, for a local try only)")
    parser.add_argument("--auth-value-file", help="the exact Authorization header the webhook must carry")
    parser.add_argument("--hmac-key-file", help="verify X-Two-Key-Signature with this key")
    parser.add_argument("--elasticsearch", default="http://127.0.0.1:9200")
    parser.add_argument("--index", default="two-key-siem")
    parser.add_argument("--pipeline", default="two-key-siem")
    parser.add_argument("--no-pipeline", action="store_true", help="index without an ingest pipeline")
    parser.add_argument("--print", dest="to_stdout", action="store_true",
                        help="print events instead of indexing them")
    parser.add_argument("--expect", type=int, help="exit 0 once this many events have arrived")
    parser.add_argument("--seconds", type=float, default=120.0, help="how long to wait for --expect")
    args = parser.parse_args(argv)

    if not args.plain and not args.cert:
        parser.error("--cert and --key, or --plain for a plaintext listener")
    context = None if args.plain else server_context(args.cert, args.key, args.client_ca)
    collector = Collector(elasticsearch=args.elasticsearch, index=args.index,
                          pipeline=None if args.no_pipeline else args.pipeline,
                          to_stdout=args.to_stdout, expect=args.expect)

    servers: list = [SyslogServer((args.bind, args.syslog_port), collector, context)]
    if args.webhook_port:
        secret = read_file(args.hmac_key_file)
        servers.append(WebhookServer((args.bind, args.webhook_port), collector, context,
                                     read_file(args.auth_value_file),
                                     secret.encode("utf-8") if secret else None))
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        kind = "syslog" if isinstance(server, SyslogServer) else "webhook"
        print(f"listening for {kind} on {server.server_address[0]}:{server.server_address[1]}"
              f"{' (plaintext)' if context is None else ' (TLS)'}", file=sys.stderr, flush=True)

    code = 0
    try:
        if args.expect is None:
            while True:
                time.sleep(1.0)
        elif not collector.wait(args.seconds):
            print(f"only {collector.count} of {args.expect} events arrived in {args.seconds:g}s",
                  file=sys.stderr)
            code = 1
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
    for problem in collector.problems:
        print(problem, file=sys.stderr)
    print(f"{collector.count} events", file=sys.stderr)
    return 1 if collector.problems else code


if __name__ == "__main__":
    sys.exit(main())
