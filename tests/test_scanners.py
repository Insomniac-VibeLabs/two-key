# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The reference scanner adapters (0.6.0): clamd, ICAP, a command, and a Python hook.

Fake clamd and ICAP servers run on 127.0.0.1 inside the tests; nothing leaves the machine. The EICAR test
string is assembled at run time, so no file in the repository carries it whole."""

import base64
import contextlib
import io
import os
import socket
import socketserver
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.scan import ScanConfigError, ScanPart, ScanRequest, Scanner
from two_key.scanners import (ClamdInspector, CommandInspector, IcapInspector, check_scan_block, hook_inspector,
                              scanner_from_config)
from two_key.testing import TEST_AGENT, FixedJudge

EICAR = "".join(["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-", "FILE!$H+H*"]).encode()
SIGNATURE = b"EICAR-STANDARD-" + b"ANTIVIRUS-TEST-FILE"
SECRET = b"FAKE-SECRET-NOT-REAL-0000"


def request(*parts, tool="t", seconds=5.0):
    return ScanRequest(tool, tuple(ScanPart(name, data) for name, data in parts), time.monotonic() + seconds)


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


class FakeClamd(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, limit=1 << 20):
        super().__init__(("127.0.0.1", 0), ClamdHandler)
        self.limit, self.hang, self.streams = limit, 0.0, []


class ClamdHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock, server = self.request, self.server
        command = b""
        while not command.endswith(b"\0"):
            chunk = sock.recv(1)
            if not chunk:
                return
            command += chunk
        if command == b"zVERSION\0":
            sock.sendall(b"ClamAV 1.4.1/27400/Wed Oct 15 2026\0")
            return
        if command != b"zINSTREAM\0":
            sock.sendall(b"UNKNOWN COMMAND\0")
            return
        data = b""
        while True:
            (size,) = struct.unpack("!L", recv_exact(sock, 4))
            if size == 0:
                break
            data += recv_exact(sock, size)
            if len(data) > server.limit:
                sock.sendall(b"INSTREAM size limit exceeded. ERROR\0")
                # Read what the client is still sending before closing: on Windows, a socket closed with
                # unread data resets the connection, and the reset can discard the reply before it is read.
                sock.shutdown(socket.SHUT_WR)
                sock.settimeout(5)
                with contextlib.suppress(OSError):
                    while sock.recv(65536):
                        pass
                return
        server.streams.append(data)
        if server.hang:
            time.sleep(server.hang)
        if SIGNATURE in data:
            sock.sendall(b"stream: Eicar-Test-Signature FOUND\0")
        elif b"BOMB" in data:
            sock.sendall(b"stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0")
        elif b"BREAK" in data:
            sock.sendall(b"stream: lstat() failed. ERROR\0")
        else:
            sock.sendall(b"stream: OK\0")


class FakeIcap(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), IcapHandler)
        self.requests = []


class IcapHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                return
            data += chunk
        while not data.endswith(b"0\r\n\r\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        self.server.requests.append(data)
        head = data.split(b"\r\n\r\n", 1)[0]
        tag = b'ISTag: "fake-7"\r\nServer: FakeICAP/2.1\r\n'
        if SIGNATURE in data:
            reply = (b"ICAP/1.0 200 OK\r\n" + tag + b"X-Infection-Found: Type=0; Resolution=2; Threat=Eicar;\r\n"
                     b"Encapsulated: null-body=0\r\n\r\n")
        elif SECRET in data:
            http = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
            reply = (b"ICAP/1.0 200 OK\r\n" + tag + f"Encapsulated: res-hdr=0, null-body={len(http)}\r\n\r\n".encode()
                     + http)
        elif b"ERRORME" in data:
            reply = b"ICAP/1.0 500 Server Error\r\n\r\n"
        elif b"REDACT" in data or b"UNCHANGED" in data:
            # A 200 that returns the request: unchanged (clean), or with the content replaced (flagged).
            req_head, body = data.split(b"\r\n\r\n", 1)[1].split(b"\r\n\r\n", 1)
            body = body.replace(b"REDACT-ME", b"XXXXXXXXX")
            reply = (b"ICAP/1.0 200 OK\r\n" + tag + f"Encapsulated: req-hdr=0, req-body={len(req_head) + 4}\r\n\r\n"
                     .encode() + req_head + b"\r\n\r\n" + body)
        elif head.startswith(b"RESPMOD") and b"ECHO" in data:
            http = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n"
            reply = (b"ICAP/1.0 200 OK\r\n" + tag + f"Encapsulated: res-hdr=0, res-body={len(http)}\r\n\r\n".encode()
                     + http + b"4\r\nECHO\r\n0\r\n\r\n")
        else:
            reply = b"ICAP/1.0 204 No Content\r\n" + tag + b"Encapsulated: null-body=0\r\n\r\n"
        sock.sendall(reply)


def serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class Clamd(unittest.TestCase):
    def setUp(self):
        self.server = serve(FakeClamd(limit=4096))
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        host, port = self.server.server_address
        self.clamd = ClamdInspector(f"{host}:{port}", chunk_bytes=1000)

    def test_clean_and_eicar(self):
        out = self.clamd.inspect(request(("arguments", b'{"body":"hello"}'), ("file:a", b"pdf bytes")))
        self.assertEqual((out.verdict, out.scanner, out.version), ("clean", "clamav", "1.4.1/27400"))
        self.assertEqual(self.server.streams[-1], b"pdf bytes")
        out = self.clamd.inspect(request(("arguments", b"{}"), ("file:a", b"head " + EICAR + b" tail")))
        self.assertEqual((out.verdict, out.categories), ("flagged", ("malware",)))
        self.assertNotIn("Eicar", repr(out))       # the threat name is never kept

    def test_streams_in_chunks(self):
        data = os.urandom(3500)
        self.assertEqual(self.clamd.inspect(request(("file:a", data))).verdict, "clean")
        self.assertEqual(self.server.streams[-1], data)

    def test_could_not_finish_is_flagged(self):
        for data in (b"x" * 5000, b"zip BOMB"):
            with self.subTest(size=len(data)):
                out = self.clamd.inspect(request(("file:a", data)))
                self.assertEqual((out.verdict, out.categories), ("flagged", ("limits_exceeded",)))

    def test_an_error_or_no_server_is_unavailable(self):
        self.assertEqual(self.clamd.inspect(request(("file:a", b"BREAK"))).verdict, "unavailable")
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.assertEqual(ClamdInspector(f"127.0.0.1:{port}").inspect(request(("a", b"x"))).verdict, "unavailable")

    def test_a_slow_server_is_unavailable_at_the_deadline(self):
        self.server.hang = 2.0
        started = time.monotonic()
        out = self.clamd.inspect(request(("a", b"x"), seconds=0.3))
        self.assertEqual(out.verdict, "unavailable")
        self.assertLess(time.monotonic() - started, 1.5)

    def test_reply_parsing(self):
        v = ClamdInspector.verdict
        self.assertEqual(v("stream: OK").verdict, "clean")
        self.assertEqual(v("stream: Win.Test.EICAR_HDB-1 FOUND").categories, ("malware",))
        self.assertEqual(v("stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND").categories, ("limits_exceeded",))
        self.assertEqual(v("stream: Heuristics.Encrypted.Zip FOUND").categories, ("encrypted",))
        self.assertEqual(v("stream: Heuristics.Encrypted.PDF FOUND").categories, ("encrypted",))
        self.assertEqual(v("stream: Heuristics.EncryptedLookalike FOUND").categories, ("malware",))
        self.assertEqual(v("INSTREAM size limit exceeded. ERROR").categories, ("limits_exceeded",))
        self.assertEqual(v("stream: something odd").verdict, "unavailable")

    def test_addresses(self):
        for bad in ("", "host:notaport", "unix:relative.sock", "http://x:1/y"):
            with self.subTest(bad=bad), self.assertRaises(ScanConfigError):
                ClamdInspector(bad)
        self.assertEqual((ClamdInspector("scanner.internal").port), 3310)


class Icap(unittest.TestCase):
    def setUp(self):
        self.server = serve(FakeIcap())
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        host, port = self.server.server_address
        self.url = f"icap://{host}:{port}/avscan"

    def test_clean_flagged_and_errors(self):
        icap = IcapInspector(self.url)
        out = icap.inspect(request(("arguments", b'{"a":1}'), ("file:x", b"fine")))
        self.assertEqual((out.verdict, out.scanner, out.version), ("clean", "FakeICAP/2.1", "fake-7"))
        self.assertEqual(icap.inspect(request(("file:x", EICAR))).categories, ("malware",))
        self.assertEqual(icap.inspect(request(("arguments", SECRET))).categories, ("policy",))
        self.assertEqual(icap.inspect(request(("arguments", b"ERRORME"))).verdict, "unavailable")
        self.assertEqual(IcapInspector(self.url, label="Vendor DLP").inspect(request(("a", b"x"))).scanner,
                         "Vendor DLP")

    def test_an_encrypted_answer_is_encrypted_only_when_that_is_all_it_names(self):
        icap = IcapInspector(self.url)

        def cats(*headers):
            response = ("ICAP/1.0 200 OK\r\n" + "".join(h + "\r\n" for h in headers) +
                        "Encapsulated: null-body=0\r\n\r\n").encode()
            return icap.verdict(response)[0].categories
        self.assertEqual(cats("X-Infection-Found: Type=0; Resolution=2; Threat=Heuristics.Encrypted.Zip;"),
                         ("encrypted",))
        self.assertEqual(cats("X-Virus-ID: Heuristics.Encrypted.RAR"), ("encrypted",))
        self.assertEqual(cats("X-Virus-ID: Heuristics.Encrypted.Zip",
                              "X-Infection-Found: Type=0; Resolution=2; Threat=Heuristics.Encrypted.Zip;"),
                         ("encrypted",))
        self.assertEqual(cats("X-Virus-ID: Heuristics.Encrypted.Zip, Win.Test.EICAR_HDB-1"), ("malware",))
        self.assertEqual(cats("X-Virus-ID: Heuristics.Encrypted.Zip", "X-Virus-Name: Eicar"), ("malware",))
        self.assertEqual(cats("X-Infection-Found: Type=0; Resolution=2;"), ("malware",))
        self.assertEqual(cats("X-Virus-ID: Heuristics.Encrypted.Zip", "X-Blocked: yes"), ("encrypted", "policy"))

    def test_a_200_is_clean_only_when_unchanged(self):
        icap = IcapInspector(self.url)
        self.assertEqual(icap.inspect(request(("arguments", b"UNCHANGED " * 3000))).verdict, "clean")
        out = icap.inspect(request(("arguments", b"REDACT-ME please"), ("file:a", b"fine")))
        self.assertEqual((out.verdict, out.categories), ("flagged", ("policy",)))

    def test_what_two_key_sends(self):
        icap = IcapInspector(self.url)
        icap.inspect(request(("file:attachments[0].content", b"hello"), tool="send_email"))
        sent = self.server.requests[-1]
        head, rest = sent.split(b"\r\n\r\n", 1)
        lines = head.decode().split("\r\n")
        self.assertEqual(lines[0], f"REQMOD {self.url} ICAP/1.0")
        self.assertIn("Allow: 204", lines)
        self.assertIn("X-Two-Key-Tool: send_email", lines)
        self.assertIn("X-Two-Key-Part: file:attachments[0].content", lines)
        offsets = dict(item.split("=") for item in
                       next(x for x in lines if x.startswith("Encapsulated:"))[14:].split(", "))
        http_head = rest[int(offsets["req-hdr"]):int(offsets["req-body"])]
        self.assertTrue(http_head.startswith(b"POST /two-key/send_email/"))
        self.assertTrue(http_head.endswith(b"Content-Length: 5\r\n\r\n"))
        self.assertEqual(rest[int(offsets["req-body"]):], b"5\r\nhello\r\n0\r\n\r\n")

    def test_respmod(self):
        icap = IcapInspector(self.url, method="respmod")
        self.assertEqual(icap.inspect(request(("a", b"fine"))).verdict, "clean")
        self.assertEqual(icap.inspect(request(("a", b"ECHO"))).verdict, "clean")       # an echoed 200 is clean
        self.assertEqual(icap.inspect(request(("a", SECRET))).verdict, "flagged")      # a 403 inside is not
        self.assertTrue(self.server.requests[-1].startswith(b"RESPMOD "))
        self.assertIn(b"res-hdr=", self.server.requests[-1].split(b"\r\n\r\n")[0])

    def test_urls(self):
        for bad in ("http://x/y", "icap://", "icap://u:p@x/y", "icap://x/y?q=1"):
            with self.subTest(bad=bad), self.assertRaises(ScanConfigError):
                IcapInspector(bad)
        with self.assertRaises(ScanConfigError):
            IcapInspector(self.url, method="options")
        self.assertEqual(IcapInspector("icaps://dlp.example/scan").port, 11344)
        self.assertEqual(IcapInspector("icap://dlp.example").service, "/")

    def test_icaps_needs_tls_1_2(self):
        icap = IcapInspector("icaps://dlp.example/scan")
        seen = []

        class Context:
            minimum_version = None

            def wrap_socket(self, sock, server_hostname):
                seen.append((self.minimum_version, server_hostname))
                return sock

        with mock.patch("two_key.scanners.socket.create_connection", return_value=object()), \
                mock.patch("two_key.scanners.ssl.create_default_context", return_value=Context()):
            icap._connect(1.0)
        self.assertEqual(seen, [(ssl.TLSVersion.TLSv1_2, "dlp.example")])

    def test_no_server_is_unavailable(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.assertEqual(IcapInspector(f"icap://127.0.0.1:{port}/x").inspect(request(("a", b"x"))).verdict,
                         "unavailable")


SCRIPT = """
import os, sys, time
data = sys.stdin.buffer.read()
if os.environ.get("TWO_KEY_TOOL") != "t" or not os.environ.get("TWO_KEY_PART"):
    sys.exit(4)
if "TWO_KEY_TEST_JUDGE_KEY" in os.environ:
    sys.exit(5)
if b"FAKE-SECRET" in data:
    print("two-key-categories: secret, credential, not-a-category")
    sys.exit(1)
if b"PLAIN-FLAG" in data:
    sys.exit(1)
if b"LOCKED" in data:
    print("two-key-categories: encrypted")
    sys.exit(1)
if b"SLOW" in data:
    time.sleep(10)
if b"CRASH" in data:
    sys.exit(3)
"""


class Command(unittest.TestCase):
    def setUp(self):
        self.cmd = CommandInspector([sys.executable, "-c", SCRIPT])

    def test_exit_codes(self):
        os.environ["TWO_KEY_TEST_JUDGE_KEY"] = "must-not-reach-the-scanner"
        self.addCleanup(os.environ.pop, "TWO_KEY_TEST_JUDGE_KEY")
        self.assertEqual(self.cmd.inspect(request(("arguments", b"fine"))).verdict, "clean")
        out = self.cmd.inspect(request(("arguments", b"fine"), ("file:a", SECRET)))
        self.assertEqual((out.verdict, out.categories), ("flagged", ("credential", "secret")))
        self.assertEqual(self.cmd.inspect(request(("a", b"PLAIN-FLAG"))).categories, ("policy",))
        self.assertEqual(self.cmd.inspect(request(("a", b"LOCKED"))).categories, ("encrypted",))
        self.assertEqual(self.cmd.inspect(request(("a", b"CRASH"))).verdict, "unavailable")
        self.assertEqual(self.cmd.label, os.path.basename(sys.executable))

    def test_the_time_limit_is_unavailable(self):
        started = time.monotonic()
        self.assertEqual(self.cmd.inspect(request(("a", b"SLOW"), seconds=1.0)).verdict, "unavailable")
        self.assertLess(time.monotonic() - started, 8)

    def test_a_missing_program_is_unavailable(self):
        missing = CommandInspector(["two-key-no-such-scanner-program"])
        self.assertEqual(missing.inspect(request(("a", b"x"))).verdict, "unavailable")

    def test_arguments(self):
        for bad in ("scanner --stdin", [], [""], ["a\x00b"]):
            with self.subTest(bad=bad), self.assertRaises(ScanConfigError):
                CommandInspector(bad)
        with self.assertRaises(ScanConfigError):
            CommandInspector(["x"], env={"BAD NAME": "v"})


class Hook(unittest.TestCase):
    def test_module_function(self):
        hook = hook_inspector("scan_hook_fixture:inspect")
        self.assertEqual(hook.inspect(request(("a", b"ok"))).verdict, "clean")
        self.assertEqual(hook.inspect(request(("a", SECRET))).categories, ("secret",))
        for bad in ("scan_hook_fixture", "no_such_module_x:fn", "scan_hook_fixture:missing", "os.path:sep"):
            with self.subTest(bad=bad), self.assertRaises(ScanConfigError):
                hook_inspector(bad)


class Config(unittest.TestCase):
    def test_blocks(self):
        bad = [None, {}, {"type": "av"}, {"type": "clamd"}, {"type": "clamd", "address": "x", "url": "y"},
               {"type": "icap", "address": "x"}, {"type": "command"}, {"type": "python", "hook": "m:f", "extra": 1}]
        for block in bad:
            with self.subTest(block=block), self.assertRaises(ScanConfigError):
                check_scan_block(block)

    def test_scanner_from_config(self):
        sc = scanner_from_config({"type": "clamd", "address": "127.0.0.1:3310", "timeout_seconds": 5,
                                  "label": "clamav-prod"},
                                 FILES)
        self.assertIsInstance(sc, Scanner)
        self.assertIsInstance(sc.inspector, ClamdInspector)
        self.assertEqual((sc.timeout_seconds, sc.label), (5.0, "clamav-prod"))
        self.assertEqual((sc.files["send_email"][0].path, sc.files["send_email"][0].max_bytes),
                         ("attachments[].content", 65536))
        with self.assertRaisesRegex(ScanConfigError, "replaced by max_bytes on each file"):
            scanner_from_config({"type": "clamd", "address": "127.0.0.1:3310", "max_file_bytes": 1000})
        self.assertIsInstance(scanner_from_config({"type": "icap", "url": "icap://h/s"}).inspector, IcapInspector)
        self.assertIsInstance(scanner_from_config({"type": "command", "command": ["x"]}).inspector, CommandInspector)
        self.assertEqual(scanner_from_config({"type": "python", "hook": "scan_hook_fixture:inspect"}).label,
                         "inspect")


FILES = {"send_email": [{"path": "attachments[].content", "kind": "base64", "max_bytes": 65536}]}


class EndToEnd(unittest.TestCase):
    """A TwoKey with the clamd adapter against the fake clamd: EICAR in an attachment is denied by Path A."""

    def test_eicar_attachment_and_a_scanner_that_goes_down(self):
        server = serve(FakeClamd())
        self.addCleanup(server.server_close)
        host, port = server.server_address
        key = generate_private_key()
        rules = [{"id": "tools", "allow_only_tools": ["send_email"]},
                 {"id": "scan", "deny_if_fields": {"scan": {"in": ["flagged", "unavailable"]}}}]
        specs = {"send_email": {"irreversible": True, "data_class_floor": "personal",
                                "payload": [{"json_path": "body", "shape": "string"}, {"json_path": "attachments"}],
                                "fields": {"scan": {"source": "caller"}}}}
        fields = {"scan": {"type": "enum", "values": ["clean", "flagged", "unavailable"], "default": "clean",
                           "source": "caller"}}
        env = sign_constitution("Never send malware.", rules, key, specs, fields=fields)
        scanner = scanner_from_config({"type": "clamd", "address": f"{host}:{port}", "timeout_seconds": 3},
                                      FILES)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()) as err:
            tk = TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                        [FixedJudge("a", "yes")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                        allow_test_doubles=True, monitored_agent=TEST_AGENT, scanner=scanner)
            claim = {"tool": "send_email", "data_class": "personal"}

            def send(data):
                return tk.authorize(claim, {"body": "see attached",
                                            "attachments": [{"content": base64.b64encode(data).decode()}]}, "p")
            self.assertTrue(send(b"quarterly numbers").allowed)
            d = send(b"x " + EICAR)
            self.assertEqual((d.allowed, d.path_a["denied_by"]), (False, "scan"))
            server.shutdown()
            server.server_close()
            d = send(b"quarterly numbers")
            self.assertFalse(d.allowed)            # strict: an unavailable scanner denies
            scans = [e.body for e in tk.ledger.entries if e.kind == "scan"]
            self.assertEqual([s["verdict"] for s in scans], ["clean", "flagged", "unavailable"])
            self.assertEqual(scans[0]["version"], "1.4.1/27400")
            self.assertIn("content scanner is unavailable", err.getvalue())



class ExampleFile(unittest.TestCase):
    """examples/scanning.yaml signs, and its default stance denies what the scanner flags."""

    def test_examples_scanning_yaml(self):
        from two_key.constitution import load_unsigned_with_fields
        root = Path(__file__).resolve().parent.parent
        prose, rules, specs, fields = load_unsigned_with_fields(root / "examples" / "constitution.md",
                                                               root / "examples" / "scanning.yaml")
        key = generate_private_key()
        env = sign_constitution(prose, rules, key, specs, fields=fields)
        self.assertEqual(env["format"], "two-key-constitution-v3")
        scanner = scanner_from_config({"type": "python", "hook": "scan_hook_fixture:inspect"},
                                      FILES)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()) as err:
            tk = TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                        [FixedJudge("a", "yes")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                        allow_test_doubles=True, monitored_agent=TEST_AGENT, scanner=scanner)
            self.assertEqual(scanner.stance, "default")
            self.assertIn("not scanned (they do not map scan): lookup", err.getvalue())
            claim = {"tool": "send_email", "data_class": "personal"}

            def send(data):
                return tk.authorize(claim, {"to": "ops@example.org", "subject": "report", "body": "attached",
                                            "attachments": [{"content": base64.b64encode(data).decode()}]}, "p")
            self.assertTrue(send(b"quarterly numbers").allowed)
            d = send(b"key=FAKE-SECRET-NOT-REAL-0000")
            self.assertEqual((d.allowed, d.reason), (False, "rule_denied:scan"))
            self.assertTrue(tk.authorize({"tool": "lookup", "data_class": "public"}, {"query": "x"}, "p").allowed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
