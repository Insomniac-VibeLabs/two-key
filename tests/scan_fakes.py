"""Local fake scanner servers for the content-scanning tests. Nothing here reaches the network."""
import json
import os
import socket
import socketserver
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from two_key.scanning import EICAR, recv_frame, send_frame


class FakeHttpScanner:
    """A REST scanning API on 127.0.0.1. ``respond(body_dict, headers) -> (status, json_obj)``."""

    def __init__(self, respond):
        self.requests = []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.requests.append((dict(self.headers), body))
                status, obj = respond(body, self.headers)
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/scan"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _read_until(conn, buf, marker):
    while marker not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    i = buf.index(marker)
    return bytes(buf[:i]), buf[i + len(marker):]


def _read_chunked(conn, buf):
    body = b""
    while True:
        line, buf = _read_until(conn, buf, b"\r\n")
        n = int(line.split(b";")[0], 16)
        if n == 0:
            _, buf = _read_until(conn, buf, b"\r\n")
            return body
        while len(buf) < n + 2:
            buf += conn.recv(65536)
        body += bytes(buf[:n])
        buf = buf[n + 2:]


class FakeIcapServer:
    """An ICAP server (RFC 3507 subset) on 127.0.0.1.

    mode: "av" (204 unless the body contains EICAR, then 200 + block page +
    X-Infection-Found), "echo200" (200 with the same body), "modify" (200 with
    a different body), "status500".
    """

    def __init__(self, mode="av"):
        self.mode, self.requests = mode, []
        fake = self

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                conn, buf = self.request, bytearray()
                head, buf = _read_until(conn, buf, b"\r\n\r\n")
                lines = head.decode("latin-1").split("\r\n")
                method = lines[0].split()[0]
                hdrs = {k.strip().lower(): v.strip() for k, v in (ln.split(":", 1) for ln in lines[1:] if ":" in ln)}
                if method == "OPTIONS":
                    conn.sendall(b'ICAP/1.0 200 OK\r\nService: FakeICAP 1.0\r\nISTag: "fake-sig-42"\r\n'
                                 b"Methods: REQMOD, RESPMOD\r\nEncapsulated: null-body=0\r\n\r\n")
                    return
                secs = [(s.split("=")[0].strip(), int(s.split("=")[1])) for s in hdrs["encapsulated"].split(",")]
                body_off = [o for n, o in secs if n.endswith("-body")][0]
                while len(buf) < body_off:
                    buf += conn.recv(65536)
                http_hdrs, buf = bytes(buf[:body_off]), buf[body_off:]
                body = _read_chunked(conn, buf)
                fake.requests.append({"method": method, "line": lines[0], "icap_headers": hdrs,
                                      "encapsulated": hdrs["encapsulated"], "http_headers": http_hdrs, "body": body})
                istag = b'ISTag: "fake-sig-42"\r\n'
                if fake.mode == "status500":
                    conn.sendall(b"ICAP/1.0 500 Server Error\r\n" + istag + b"\r\n")
                elif fake.mode == "av" and EICAR in body:
                    page = b"blocked"
                    res = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\n\r\n"
                    conn.sendall(b"ICAP/1.0 200 OK\r\n" + istag +
                                 b"X-Infection-Found: Type=0; Resolution=2; Threat=Eicar-Test-Signature;\r\n" +
                                 f"Encapsulated: res-hdr=0, res-body={len(res)}\r\n\r\n".encode() + res +
                                 f"{len(page):x}\r\n".encode() + page + b"\r\n0\r\n\r\n")
                elif fake.mode in ("echo200", "modify"):
                    out = body if fake.mode == "echo200" else body + b"[redacted]"
                    conn.sendall(b"ICAP/1.0 200 OK\r\n" + istag +
                                 f"Encapsulated: req-hdr=0, req-body={len(http_hdrs)}\r\n\r\n".encode() + http_hdrs +
                                 f"{len(out):x}\r\n".encode() + out + b"\r\n0\r\n\r\n")
                else:
                    conn.sendall(b"ICAP/1.0 204 No Content\r\n" + istag + b"\r\n")

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.port = self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class FakeSidecar:
    """A local scanner daemon. protocol "two-key-json" (respond(request) -> obj) or "clamd-instream"."""

    def __init__(self, respond=None, *, protocol="two-key-json", unix=True):
        self.requests, self.protocol, self.respond = [], protocol, respond
        fake = self

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                conn = self.request
                if fake.protocol == "two-key-json":
                    req = recv_frame(conn)
                    fake.requests.append(req)
                    send_frame(conn, fake.respond(req))
                    return
                buf = bytearray()
                cmd, buf = _read_until(conn, buf, b"\0")
                if cmd == b"zVERSION":
                    conn.sendall(b"ClamAV 1.4.1/27400/Fake\0")
                    return
                data = b""
                while True:
                    while len(buf) < 4:
                        buf += conn.recv(65536)
                    n = int.from_bytes(buf[:4], "big")
                    buf = buf[4:]
                    if n == 0:
                        break
                    while len(buf) < n:
                        buf += conn.recv(65536)
                    data += bytes(buf[:n])
                    buf = buf[n:]
                fake.requests.append(data)
                conn.sendall(b"stream: Eicar-Test-Signature FOUND\0" if EICAR in data else b"stream: OK\0")

        if unix:
            self._dir = tempfile.TemporaryDirectory()
            self.path = os.path.join(self._dir.name, "scan.sock")
            self.server = socketserver.ThreadingUnixStreamServer(self.path, H)
        else:
            self._dir = None
            self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
            self.port = self.server.server_address[1]
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        if self._dir:
            self._dir.cleanup()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
