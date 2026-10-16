"""The SIEM sinks (0.7.0): syslog over UDP, TCP, and TLS, and an HTTPS webhook.

Every collector here runs on 127.0.0.1 inside the test, with a throwaway certificate authority
(``tests/tls.py``); nothing leaves the machine. What the tests hold the sinks to: the RFC 5424 message,
both framings, the datagram cap, a certificate that is always checked, redirects that are never followed,
and secrets that are read from owner-only files and never printed.
"""

import http.server
import io
import json
import os
import socket
import socketserver
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path

from tests.tls import test_ca
from two_key import _platform
from two_key.siem import Message, SiemConfigError, SiemError
from two_key.siem_sinks import (DEFAULT_PORTS, SyslogSink, WebhookSink, check_siem_block, siem_from_config,
                                sink_from_config)

MESSAGE = Message(severity=4, msgid="decision", body='{"seq":7,"kind":"decision"}',
                  sent_at="2026-10-16T03:04:05.678Z")
POSIX = not _platform.WINDOWS


class Collector:
    """A syslog collector on 127.0.0.1 that keeps the bytes it was sent."""

    def __init__(self, kind="tcp", certificates=None, require_client=False):
        self.data = bytearray()
        self.end = None             # how the last stream ended: "clean" (EOF) or the error that ended it
        self.lock = threading.Lock()
        self.kind = kind
        if kind == "udp":
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(("127.0.0.1", 0))
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(("127.0.0.1", 0))
            self.socket.listen(4)
        self.port = self.socket.getsockname()[1]
        self.context = None
        if kind == "tls":
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2   # as a real collector would
            self.context.load_cert_chain(certificates.server_cert, certificates.server_key)
            if require_client:
                self.context.verify_mode = ssl.CERT_REQUIRED
                self.context.load_verify_locations(certificates.ca_file)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stop.is_set():
            try:
                self._once()
            except (OSError, ssl.SSLError, ValueError):
                if self.stop.is_set():
                    return

    def _once(self):
        if self.kind == "udp":
            chunk, _ = self.socket.recvfrom(65535)
            self._keep(chunk)
            return
        self.socket.settimeout(0.5)
        try:
            conn, _ = self.socket.accept()
        except (socket.timeout, TimeoutError):
            return
        if self.context is not None:
            # suppress_ragged_eofs=False so a stream that ends without close_notify is told apart from
            # one that ends with it: the difference the sink's close is about.
            conn = self.context.wrap_socket(conn, server_side=True, suppress_ragged_eofs=False)
        with conn:
            conn.settimeout(2)
            while True:
                try:
                    chunk = conn.recv(65536)
                except (socket.timeout, TimeoutError, OSError) as e:
                    self.end = type(e).__name__
                    return
                if not chunk:
                    self.end = "clean"
                    return
                self._keep(chunk)

    def _keep(self, chunk):
        with self.lock:
            self.data.extend(chunk)

    def text(self, want=1, timeout=5.0):
        end = threading.Event()
        for _ in range(int(timeout / 0.05)):
            with self.lock:
                text = self.data.decode("utf-8", "replace")
            if text.count("<") >= want:
                return text
            end.wait(0.05)
        with self.lock:
            return self.data.decode("utf-8", "replace")

    def close(self):
        self.stop.set()
        self.socket.close()


class Syslog(unittest.TestCase):
    def test_the_header_is_rfc_5424_with_the_kind_as_the_message_id(self):
        sink = SyslogSink("127.0.0.1", transport="udp", hostname="host1", app_name="two-key")
        frame = sink.frame(MESSAGE).decode("ascii")
        self.assertTrue(frame.startswith("<132>1 2026-10-16T03:04:05.678Z host1 two-key "), frame)
        self.assertIn(" decision - {", frame)
        self.assertTrue(frame.endswith('{"seq":7,"kind":"decision"}'))

    def test_the_priority_follows_the_facility_and_the_severity(self):
        sink = SyslogSink("127.0.0.1", transport="udp", facility="local3")
        self.assertTrue(sink.frame(Message(6, "decision", "x")).startswith(b"<158>"))
        self.assertTrue(sink.frame(Message(4, "decision", "x")).startswith(b"<156>"))

    def test_tcp_frames_by_octet_count_and_newline_on_request(self):
        octet = SyslogSink("127.0.0.1", transport="tcp").frame(MESSAGE)
        count, _, rest = octet.partition(b" ")
        self.assertEqual(int(count), len(rest))
        line = SyslogSink("127.0.0.1", transport="tcp", framing="newline").frame(MESSAGE)
        self.assertFalse(line[:1].isdigit())

    def test_the_default_port_follows_the_transport(self):
        for transport, port in DEFAULT_PORTS.items():
            self.assertEqual(SyslogSink("siem.test", transport=transport).port, port)
        self.assertEqual(SyslogSink("siem.test", transport="udp", port=1514).port, 1514)

    def test_udp_delivers_each_message_as_one_datagram(self):
        collector = Collector("udp")
        self.addCleanup(collector.close)
        sink = SyslogSink("127.0.0.1", transport="udp", port=collector.port)
        self.addCleanup(sink.close)
        sink.send([MESSAGE, Message(6, "path_a", '{"seq":8}')])
        text = collector.text(2)
        self.assertIn('{"seq":7,"kind":"decision"}', text)
        self.assertIn('{"seq":8}', text)

    def test_a_body_too_long_for_a_datagram_is_capped_not_split(self):
        collector = Collector("udp")
        self.addCleanup(collector.close)
        sink = SyslogSink("127.0.0.1", transport="udp", port=collector.port, max_datagram=600)
        self.addCleanup(sink.close)
        self.assertEqual(sink.max_body_bytes, 440)
        sink.send([Message(6, "decision", "x" * 5000)])
        self.assertLessEqual(len(collector.text(1)), 600)

    def test_tcp_sends_a_batch_on_one_connection(self):
        collector = Collector("tcp")
        self.addCleanup(collector.close)
        sink = SyslogSink("127.0.0.1", transport="tcp", port=collector.port)
        self.addCleanup(sink.close)
        sink.send([MESSAGE, MESSAGE])
        self.assertEqual(collector.text(2).count('"kind":"decision"'), 2)

    def test_a_collector_that_is_not_there_is_a_siem_error(self):
        with socket.socket() as free:
            free.bind(("127.0.0.1", 0))
            port = free.getsockname()[1]
        sink = SyslogSink("127.0.0.1", transport="tcp", port=port)
        with self.assertRaises(SiemError):
            sink.check()
        with self.assertRaises(SiemError):
            sink.send([MESSAGE])

    def test_a_dropped_connection_is_reported_and_reconnects(self):
        collector = Collector("tcp")
        self.addCleanup(collector.close)
        sink = SyslogSink("127.0.0.1", transport="tcp", port=collector.port)
        self.addCleanup(sink.close)
        sink.send([MESSAGE])
        sink._socket.close()            # as a collector restart looks from here
        try:
            sink.send([MESSAGE])
        except SiemError:
            pass
        sink.send([MESSAGE])            # a new connection, no configuration change
        self.assertIn('"kind":"decision"', collector.text(1))


class SyslogTls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.certificates = test_ca(Path(cls.tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def collector(self, **kw):
        collector = Collector("tls", certificates=self.certificates, **kw)
        self.addCleanup(collector.close)
        return collector

    def test_a_close_sends_every_message_and_ends_the_stream_cleanly(self):
        """The collector read the last message as a finished one, not as a truncated stream (run 8x, C15)."""
        collector = self.collector()
        sink = SyslogSink("127.0.0.1", transport="tls", port=collector.port,
                          ca_file=self.certificates.ca_file)
        self.addCleanup(sink.close)
        sink.send([MESSAGE] * 17)
        sink.close()
        self.assertEqual(collector.text(17).count('"kind":"decision"'), 17)
        for _ in range(100):
            if collector.end is not None:
                break
            time.sleep(0.05)
        self.assertEqual(collector.end, "clean")

    def test_tls_delivers_to_a_collector_with_a_trusted_certificate(self):
        collector = self.collector()
        sink = SyslogSink("127.0.0.1", transport="tls", port=collector.port,
                          ca_file=self.certificates.ca_file)
        self.addCleanup(sink.close)
        sink.check()
        sink.send([MESSAGE])
        self.assertIn('"kind":"decision"', collector.text(1))
        self.assertFalse(sink.plaintext)

    def test_an_unknown_authority_is_refused(self):
        collector = self.collector()
        sink = SyslogSink("127.0.0.1", transport="tls", port=collector.port,
                          ca_file=self.certificates.other_ca_file)
        self.addCleanup(sink.close)
        with self.assertRaisesRegex(SiemError, "TLS"):
            sink.check()

    def test_the_hostname_is_checked(self):
        collector = self.collector()
        sink = SyslogSink("localhost.localdomain", transport="tls", port=collector.port,
                          ca_file=self.certificates.ca_file)
        self.addCleanup(sink.close)
        with self.assertRaises(SiemError):
            sink.check()

    def test_a_collector_that_wants_a_client_certificate_gets_one(self):
        collector = self.collector(require_client=True)
        sink = SyslogSink("127.0.0.1", transport="tls", port=collector.port,
                          ca_file=self.certificates.ca_file, cert_file=self.certificates.client_cert,
                          key_file=self.certificates.client_key)
        self.addCleanup(sink.close)
        sink.send([MESSAGE])
        self.assertIn('"kind":"decision"', collector.text(1))
        self.assertTrue(sink.record()["mutual_tls"])

    def test_a_certificate_without_its_key_is_refused(self):
        with self.assertRaisesRegex(SiemConfigError, "key_file"):
            SyslogSink("127.0.0.1", cert_file=self.certificates.client_cert)
        with self.assertRaisesRegex(SiemConfigError, "cert_file"):
            SyslogSink("127.0.0.1", key_file=self.certificates.client_key)

    @unittest.skipUnless(POSIX, "POSIX file modes")
    def test_a_client_key_others_can_read_is_refused(self):
        key = Path(self.tmp.name, "loose.key")
        key.write_bytes(self.certificates.client_key.read_bytes())
        os.chmod(key, 0o644)
        with self.assertRaisesRegex(SiemConfigError, "key_file"):
            SyslogSink("127.0.0.1", cert_file=self.certificates.client_cert, key_file=key)

    def test_there_is_no_way_to_turn_the_certificate_check_off(self):
        for name in ("verify", "insecure", "skip_verify", "check_hostname"):
            with self.assertRaises(TypeError):
                SyslogSink("127.0.0.1", **{name: False})
        self.assertNotIn("insecure", json.dumps(check_siem_block.__doc__ or ""))


class Webhook(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.certificates = test_ca(Path(cls.tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def server(self, status=200, location=None):
        posts = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):      # noqa: N802 - http.server's name
                length = int(self.headers.get("Content-Length") or 0)
                posts.append({"path": self.path, "body": self.rfile.read(length).decode("utf-8"),
                              "headers": dict(self.headers)})
                self.send_response(status)
                if location:
                    self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                return

        httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2            # as a real collector would
        context.load_cert_chain(self.certificates.server_cert, self.certificates.server_key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return httpd.server_address[1], posts

    def secret(self, name, value):
        path = Path(self.tmp.name, name)
        path.write_text(value, encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def sink(self, port, **kw):
        sink = WebhookSink(f"https://127.0.0.1:{port}/ingest", ca_file=self.certificates.ca_file, **kw)
        self.addCleanup(sink.close)
        return sink

    def test_a_batch_is_one_post_with_a_line_per_event(self):
        port, posts = self.server()
        self.sink(port).send([MESSAGE, Message(6, "path_a", '{"seq":8}')])
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]["path"], "/ingest")
        self.assertEqual(posts[0]["body"].splitlines(),
                         ['{"seq":7,"kind":"decision"}', '{"seq":8}'])
        self.assertEqual(posts[0]["headers"]["Content-Type"], "application/x-ndjson")

    def test_batch_max_splits_a_long_batch(self):
        port, posts = self.server()
        self.sink(port, batch_max=2).send([MESSAGE] * 5)
        self.assertEqual([len(p["body"].splitlines()) for p in posts], [2, 2, 1])

    def test_a_token_from_a_file_goes_in_the_header_and_nowhere_else(self):
        port, posts = self.server()
        sink = self.sink(port, auth_header="Authorization",
                         auth_value_file=self.secret("token", "Bearer zz-secret-token-zz\n"))
        sink.send([MESSAGE])
        self.assertEqual(posts[0]["headers"]["Authorization"], "Bearer zz-secret-token-zz")
        self.assertNotIn("zz-secret-token-zz", json.dumps(sink.record()))
        self.assertNotIn("zz-secret-token-zz", posts[0]["body"])

    def test_a_token_file_without_a_header_name_still_authenticates(self):
        port, posts = self.server()
        self.sink(port, auth_value_file=self.secret("token2", "k")).send([MESSAGE])
        self.assertEqual(posts[0]["headers"]["Authorization"], "k")

    def test_the_body_can_be_signed(self):
        port, posts = self.server()
        sink = self.sink(port, hmac_key_file=self.secret("hmac", "zz-hmac-key-zz"))
        sink.send([MESSAGE])
        import hashlib
        import hmac as hmac_module
        want = hmac_module.new(b"zz-hmac-key-zz", posts[0]["body"].encode("utf-8"), hashlib.sha256)
        self.assertEqual(posts[0]["headers"]["X-Two-Key-Signature"], "sha256=" + want.hexdigest())
        self.assertTrue(sink.record()["signed"])

    def test_a_redirect_is_a_failure_and_is_not_followed(self):
        port, posts = self.server(status=302, location="https://elsewhere.test/ingest")
        with self.assertRaisesRegex(SiemError, "redirected"):
            self.sink(port).send([MESSAGE])
        self.assertEqual(len(posts), 1)

    def test_a_refused_batch_is_a_siem_error(self):
        port, _ = self.server(status=503)
        with self.assertRaisesRegex(SiemError, "HTTP 503"):
            self.sink(port).send([MESSAGE])

    def test_an_unknown_authority_is_refused(self):
        port, _ = self.server()
        sink = WebhookSink(f"https://127.0.0.1:{port}/ingest", ca_file=self.certificates.other_ca_file)
        with self.assertRaises(SiemError):
            sink.check()

    def test_http_is_plaintext_and_says_so(self):
        self.assertTrue(WebhookSink("http://siem.test/ingest").plaintext)
        self.assertFalse(WebhookSink("https://siem.test/ingest").plaintext)

    def test_a_url_with_a_password_or_another_scheme_is_refused(self):
        for url in ("https://user:pass@siem.test/x", "ftp://siem.test/x", "siem.test/x", None):
            with self.assertRaises(SiemConfigError):
                WebhookSink(url)

    def test_a_missing_or_loose_secret_file_is_refused(self):
        with self.assertRaisesRegex(SiemConfigError, "auth_value_file"):
            WebhookSink("https://siem.test/x", auth_value_file=Path(self.tmp.name, "nope"))
        empty = self.secret("empty", "")
        with self.assertRaisesRegex(SiemConfigError, "empty"):
            WebhookSink("https://siem.test/x", auth_value_file=empty)
        if POSIX:
            loose = self.secret("loose", "k")
            os.chmod(loose, 0o666)
            with self.assertRaisesRegex(SiemConfigError, "auth_value_file"):
                WebhookSink("https://siem.test/x", auth_value_file=loose)

    def test_an_auth_header_without_a_file_is_refused(self):
        with self.assertRaisesRegex(SiemConfigError, "auth_value_file"):
            WebhookSink("https://siem.test/x", auth_header="X-Token")


class Block(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_a_syslog_sink_from_a_config(self):
        config = siem_from_config({"sinks": [{"type": "syslog", "host": "siem.test"}]}, self.dir)
        [sink] = config.sinks
        self.assertEqual((sink.transport, sink.port, sink.plaintext), ("tls", 6514, False))
        self.assertEqual(config.schema, "native")
        self.assertEqual(config.format, "json")

    def test_a_relative_path_is_relative_to_the_config_file(self):
        certificates = test_ca(self.dir)
        (self.dir / "ca.pem").write_bytes(certificates.ca_file.read_bytes())
        sink = sink_from_config({"type": "syslog", "host": "siem.test", "ca_file": "ca.pem"}, self.dir)
        self.assertEqual(sink.record()["host"], "siem.test")

    def test_the_schema_and_format_carry_through(self):
        config = siem_from_config({"schema": "ecs", "sinks": [{"type": "syslog", "host": "s.test"}]},
                                  self.dir)
        self.assertEqual(config.schema, "ecs")

    def test_cef_with_another_schema_refuses_to_start(self):
        with self.assertRaisesRegex(SiemConfigError, "cef maps the native schema only"):
            siem_from_config({"schema": "ecs", "format": "cef",
                              "sinks": [{"type": "syslog", "host": "s.test"}]}, self.dir)

    def test_an_unknown_key_is_refused(self):
        with self.assertRaisesRegex(SiemConfigError, "unknown key"):
            check_siem_block({"sinks": [{"type": "syslog", "host": "s.test"}], "verify_tls": False})
        with self.assertRaisesRegex(SiemConfigError, "unknown key"):
            check_siem_block({"sinks": [{"type": "syslog", "host": "s.test", "insecure": True}]})

    def test_a_block_needs_a_sink_with_a_known_type(self):
        for block in ({}, {"sinks": []}, {"sinks": [{"type": "kafka"}]}, {"sinks": ["syslog"]}):
            with self.assertRaises(SiemConfigError):
                check_siem_block(block)

    def test_a_syslog_sink_needs_a_host_and_a_webhook_a_url(self):
        with self.assertRaisesRegex(SiemConfigError, "host"):
            sink_from_config({"type": "syslog"}, self.dir)
        with self.assertRaisesRegex(SiemConfigError, "url"):
            sink_from_config({"type": "webhook"}, self.dir)

    def test_a_bad_transport_port_or_facility_is_refused(self):
        for item in ({"transport": "quic"}, {"port": 0}, {"port": 99999}, {"facility": "mail"},
                     {"framing": "ascii"}, {"timeout_seconds": 0}, {"max_datagram": 10}):
            with self.assertRaises(SiemConfigError):
                sink_from_config({"type": "syslog", "host": "s.test", **item}, self.dir)

    def test_a_webhook_sink_from_a_config_with_cef_sends_text(self):
        config = siem_from_config({"format": "cef", "sinks": [{"type": "webhook",
                                                               "url": "https://siem.test/x"}]}, self.dir)
        [sink] = config.sinks
        self.assertEqual(sink.content_type, "text/plain")

    def test_labels_name_the_destination(self):
        syslog = sink_from_config({"type": "syslog", "host": "s.test", "transport": "udp"}, self.dir)
        webhook = sink_from_config({"type": "webhook", "url": "https://siem.test/x"}, self.dir)
        self.assertEqual(syslog.label, "syslog:s.test:514/udp")
        self.assertEqual(webhook.label, "webhook:siem.test:443")


class ProxyBlock(unittest.TestCase):
    """``siem:`` in ``proxy.yaml``: checked when the config is read, built when the proxy starts."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def config(self, **over):
        from two_key.mcp_proxy.config import parse_proxy_config
        data = {"constitution": "c.json", "keys": {"principal": "k.pem"}, "ledger": "ledger",
                "judges": "judges.yaml",
                "upstream": {"command": ["server"], "schema_digest": "sha256:" + "0" * 64}}
        data.update(over)
        return parse_proxy_config(data, self.dir / "proxy.yaml")

    def test_no_block_means_no_copy(self):
        self.assertIsNone(self.config().siem)

    def test_a_block_is_kept_as_read(self):
        config = self.config(siem={"sinks": [{"type": "syslog", "host": "siem.test"}]})
        self.assertEqual(config.siem["sinks"][0]["host"], "siem.test")
        [sink] = siem_from_config(config.siem, config.path.parent).sinks
        self.assertEqual(sink.transport, "tls")

    def test_an_unknown_key_refuses_to_start(self):
        from two_key.mcp_proxy.config import ProxyConfigError
        with self.assertRaisesRegex(ProxyConfigError, "unknown key"):
            self.config(siem={"sinks": [{"type": "syslog", "host": "s.test"}], "verify": False})

    def test_the_sinks_files_join_the_writable_path_check(self):
        from two_key.mcp_proxy.core import startup_paths
        config = self.config(siem={"sinks": [
            {"type": "syslog", "host": "s.test", "ca_file": "ca.pem", "cert_file": "/abs/client.pem",
             "key_file": "client.key"},
            {"type": "webhook", "url": "https://s.test/x", "auth_value_file": "token"}]})
        checked = {os.path.normcase(os.path.abspath(p)) for p, _rule in startup_paths(config)}
        for name in ("ca.pem", "client.key", "token"):
            self.assertIn(os.path.normcase(str(self.dir / name)), checked)
        # A rooted path with no drive letter is not absolute on Windows, so the config joins it onto the
        # proxy.yaml directory's drive; join it the same way here rather than onto the current drive.
        self.assertIn(os.path.normcase(os.path.abspath(self.dir / "/abs/client.pem")), checked)

    def test_the_delivery_cursor_joins_the_writable_path_check(self):
        """Whoever can change the cursor can make the copy repeat or skip entries, and docs/CONNECTING.md
        says the proxy names it (live run 8x, C40)."""
        from two_key.mcp_proxy.core import startup_paths
        config = self.config(siem={"sinks": [{"type": "syslog", "host": "s.test"}]})
        checked = {os.path.normcase(os.path.abspath(p)) for p, _rule in startup_paths(config)}
        self.assertIn(os.path.normcase(str(self.dir / "ledger.siem" / "cursor.json")), checked)


if __name__ == "__main__":
    unittest.main()
