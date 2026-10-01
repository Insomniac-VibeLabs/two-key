"""Content-scanning adapters (two_key/scanning.py), each against a local fake. No network access."""
import base64
import hashlib
import http.client
import json
import sys
import threading
import time
import types
import unittest
from unittest import mock

from two_key import scanning
from two_key.canonical import canonical_hash
from two_key.judges.credentials import StaticToken
from two_key.scanning import (EICAR, AsyncCallbackScanner, ClamdScanner, IcapScanner, PatternRule, PatternScanner,
                              ResponseMapping, ScanEngine, ScannerUnavailable, ScanReport, ScanSettings,
                              SidecarScanner, VendorApiScanner, WebhookReceiver)
from scan_fakes import FakeHttpScanner, FakeIcapServer, FakeSidecar

CALL = b'{"args":{"body":"hello"},"tool":"email_send"}'


def run(scanner, parts=(("call", "application/json", CALL),), **settings):
    eng = ScanEngine([scanner], ScanSettings(**settings))
    ps = eng.build_parts(list(parts), "sha256", None)
    return eng.run("email_send", ps, "sha256", None, {"jti": "j1"}), ps


class EngineAndSettings(unittest.TestCase):
    def test_defaults(self):
        s = ScanSettings()   # Entry 6: timeout configurable, default deny; exact bytes + strings. Entry 7: parallel
        self.assertEqual(s.to_record(), {"timeout_seconds": 10.0, "on_timeout": "block", "on_error": "block",
                                         "payload": "exact", "order": "parallel"})
        self.assertFalse(hasattr(s, "dlp_overrides_data_class"))   # replaced by most-restrictive-wins
        self.assertFalse(hasattr(scanning, "most_restrictive"))     # Entry 7: no ranking, any conviction denies
        self.assertTrue(AsyncCallbackScanner("a", lambda r, i: None).hold_until_verdict)   # Entry 7: always hold

    def test_settings_validation(self):
        for kw in ({"on_error": "maybe"}, {"on_timeout": "maybe"}, {"payload": "some"}, {"order": "random"},
                   {"timeout_seconds": 0}, {"timeout_seconds": True}):
            with self.assertRaises(ValueError):
                ScanSettings(**kw)
        ScanSettings(timeout_seconds=2.5, on_timeout="allow", on_error="allow")

    def test_on_error_follows_on_timeout(self):
        # Entry 7: a scanner error is treated like a timeout.
        self.assertEqual(ScanSettings(on_timeout="allow").to_record()["on_error"], "allow")
        self.assertEqual(ScanSettings().error_action, "block")
        for kw in ({"on_error": "allow"}, {"on_error": "block", "on_timeout": "allow"}):
            with self.assertRaises(ValueError):
                ScanSettings(**kw)

    def test_ids_unique_and_valid(self):
        with self.assertRaises(ValueError):
            ScanEngine([PatternScanner("x", rules=[]), PatternScanner("x", rules=[])])
        with self.assertRaises(ValueError):
            PatternScanner("bad id!", rules=[])

    def test_digests_are_computed_by_the_engine(self):
        (v,), ps = run(PatternScanner(rules=[]))
        self.assertEqual(v.parts[0]["digest"], hashlib.sha256(CALL).hexdigest())
        self.assertEqual(v.payload_digest, canonical_hash([p.info() for p in ps], "sha256"))
        self.assertEqual(v.outcome, "allow")

    def test_scanner_exception_is_error_and_timeout_is_timeout(self):
        class Boom(PatternScanner):
            def scan(self, request, timeout):
                raise RuntimeError("down")

        class Slow(PatternScanner):
            def scan(self, request, timeout):
                time.sleep(2)
                return ScanReport("allow")

        class SocketTimeout(PatternScanner):
            def scan(self, request, timeout):
                raise TimeoutError("timed out")

        (v,), _ = run(Boom(rules=[]))
        self.assertEqual((v.outcome, v.detail), ("error", "RuntimeError: down"))
        t0 = time.perf_counter()
        (v,), _ = run(Slow(rules=[]), timeout_seconds=0.1)
        self.assertEqual(v.outcome, "timeout")
        self.assertIn("timeout", v.detail)
        (v2,), _ = run(SocketTimeout(rules=[]))
        self.assertEqual(v2.outcome, "timeout")
        self.assertLess(time.perf_counter() - t0, 1.5)

    def test_invalid_outcome_and_wrong_echoed_digest_are_errors(self):
        class Odd(PatternScanner):
            def __init__(self, rep):
                super().__init__("odd", rules=[])
                self.rep = rep

            def scan(self, request, timeout):
                return self.rep

        (v,), _ = run(Odd(ScanReport("maybe")))
        self.assertEqual(v.outcome, "error")
        (v,), _ = run(Odd(ScanReport("pending")))  # only async scanners may answer pending
        self.assertEqual(v.outcome, "error")
        (v,), _ = run(Odd(ScanReport("cancelled")))  # engine-only outcome: a scanner can't use it to avoid a deny
        self.assertEqual((v.outcome, v.error_type), ("error", "InvalidOutcome"))
        (v,), _ = run(Odd(ScanReport("allow", echoed_digest="00" * 32)))
        self.assertEqual(v.outcome, "error")
        self.assertIn("digest_mismatch", v.detail)

    def test_unknown_data_classes_become_labels(self):
        rep = ScanReport("allow", labels=("x",), data_classes=("Medical", "pci"))
        sc = PatternScanner(rules=[])
        with mock.patch.object(sc, "scan", return_value=rep):
            (v,), _ = run(sc)
        self.assertEqual((v.data_classes, v.labels), (("medical",), ("x", "pci")))

    def test_any_dlp_class_other_than_the_tokens_denies(self):
        # Entry 7: no ranking; if the DLP names a class the token doesn't permit, deny.
        def verdict(classes, kind="dlp", outcome="allow", sid="s"):
            return scanning.ScanVerdict(sid, "a", kind, "1", outcome, "exact", "sha256", "d", (), (), (),
                                        tuple(classes))
        eng = ScanEngine([PatternScanner(rules=[])])
        self.assertEqual(eng.decide([verdict(["medical"])], "public"), "scan_data_class_mismatch")
        self.assertEqual(eng.decide([verdict(["public"])], "personal"), "scan_data_class_mismatch")
        self.assertEqual(eng.decide([verdict(["financial"]), verdict(["personal"], sid="t")], "financial"),
                         "scan_data_class_mismatch")
        self.assertIsNone(eng.decide([verdict(["personal", "personal"])], "personal"))
        self.assertIsNone(eng.decide([verdict([])], "public"))                      # no DLP class: nothing to convict
        self.assertIsNone(eng.decide([verdict(["medical"], kind="av")], "public"))  # AV verdicts carry no class
        self.assertIsNone(eng.decide([verdict(["medical"])], None))                 # not checked
        self.assertEqual(eng.data_class_conflicts([verdict(["medical"], sid="d1")], "public"),
                         [{"scanner_id": "d1", "data_class": "medical"}])
        self.assertEqual(eng.data_classes_seen([verdict(["medical"]), verdict(["medical"])], "public"),
                         ["public", "medical"])

    def test_error_records_carry_type_digest_and_action(self):
        class Boom(PatternScanner):
            def scan(self, request, timeout):
                raise OSError("down")

        for on_timeout in ("block", "allow"):
            eng = ScanEngine([Boom("boom", rules=[], version="9.1")], ScanSettings(on_timeout=on_timeout))
            ps = eng.build_parts([("call", "application/json", CALL)], "sha256", None)
            (v,) = eng.run("email_send", ps, "sha256", None, {})
            self.assertEqual((v.outcome, v.error_type), ("error", "OSError"))
            self.assertEqual(eng.error_records([v]), [{
                "scanner_id": "boom", "scanner_version": "9.1", "outcome": "error", "error_type": "OSError",
                "detail": "OSError: down", "digest_alg": "sha256", "payload_digest": v.payload_digest,
                "direction": "outbound", "action": on_timeout}])
            self.assertEqual(eng.decide([v], "public"), "scan_error:boom" if on_timeout == "block" else None)


TEXTS = (("args.body", "caf\u00e9 <script>evil()</script>"),)


def run_texts(scanner, **settings):
    eng = ScanEngine([scanner], ScanSettings(**settings))
    call = b'{"args":{"body":"caf\\u00e9 <script>evil()</script>"},"tool":"email_send"}'
    ps = eng.build_parts([("call", "application/json", call)], "sha256", None)
    ts = eng.build_texts(list(TEXTS), "sha256", None)
    return eng.run("email_send", ps, "sha256", None, {}, texts=ts), ps, ts


class BytesAndStrings(unittest.TestCase):
    """Entry 6 (c): scanners get the exact bytes and the decoded strings; the digest binds the exact bytes."""

    def test_pattern_scanner_sees_unescaped_text(self):
        rule = PatternRule("script", "<script>evil\\(\\)</script>".encode(), action="block")
        cafe = PatternRule("cafe", "caf\u00e9".encode("utf-8"), label="cafe")
        (v,), ps, ts = run_texts(PatternScanner("p", rules=[rule, cafe]))
        self.assertEqual(v.outcome, "block")
        # The escaped JSON call part doesn't contain the UTF-8 "é"; the decoded string does.
        self.assertEqual(sorted(v.findings), ["call:script", "text:args.body:cafe", "text:args.body:script"])
        self.assertEqual(v.payload_digest, canonical_hash([p.info() for p in ps], "sha256"))   # exact bytes only
        self.assertEqual(v.texts[0]["digest"], hashlib.sha256(TEXTS[0][1].encode()).hexdigest())

    def test_digest_only_strips_texts_too(self):
        seen = []
        sc = VendorApiScanner("v", transport=lambda b, h, t: seen.append(b) or {"outcome": "allow"},
                              payload_mode="digest_only")
        run_texts(sc)
        self.assertNotIn("text", seen[0]["texts"][0])
        self.assertNotIn("data_b64", seen[0]["parts"][0])


class ParallelOrder(unittest.TestCase):
    """Entry 7: scanners run at once by default; any deny is final; otherwise wait up to the timeout."""

    class Sleepy(PatternScanner):
        def __init__(self, sid, seconds, report=None, kind="dlp"):
            super().__init__(sid, rules=[], kind=kind)
            self.seconds, self.report, self.abandoned = seconds, report or ScanReport("allow"), []

        def scan(self, request, timeout):
            time.sleep(self.seconds)
            return self.report

        def abandon(self, request):
            self.abandoned.append(request.request_id)

    def engine(self, *scanners, **settings):
        eng = ScanEngine(list(scanners), ScanSettings(**settings))
        return eng, eng.build_parts([("call", "application/json", CALL)], "sha256", None)

    def test_wall_time_is_the_slowest_not_the_sum(self):
        eng, ps = self.engine(self.Sleepy("a", 0.3), self.Sleepy("b", 0.3), self.Sleepy("c", 0.3, kind="av"))
        t0 = time.perf_counter()
        vs = eng.run("email_send", ps, "sha256", None, {})
        self.assertLess(time.perf_counter() - t0, 0.75)          # sequential would take about 0.9 s
        self.assertEqual([(v.scanner_id, v.outcome) for v in vs], [("a", "allow"), ("b", "allow"), ("c", "allow")])

    def test_a_deny_is_final_and_stragglers_are_cancelled(self):
        slow = self.Sleepy("slow", 2.0)
        eng, ps = self.engine(slow, self.Sleepy("av", 0.0, ScanReport("block"), kind="av"), timeout_seconds=5)
        t0 = time.perf_counter()
        vs = eng.run("email_send", ps, "sha256", None, {})
        self.assertLess(time.perf_counter() - t0, 1.0)           # didn't wait for the 2 s scanner
        self.assertEqual([(v.scanner_id, v.outcome) for v in vs], [("slow", "cancelled"), ("av", "block")])
        self.assertIn("already denied (av)", vs[0].detail)
        self.assertEqual(len(slow.abandoned), 1)
        self.assertEqual(eng.decide(vs, "public"), "scan_blocked:av")

    def test_a_data_class_conviction_is_final_too(self):
        eng, ps = self.engine(self.Sleepy("slow", 2.0, kind="av"),
                              self.Sleepy("dlp", 0.0, ScanReport("allow", data_classes=("medical",))),
                              timeout_seconds=5)
        t0 = time.perf_counter()
        vs = eng.run("email_send", ps, "sha256", None, {}, scope_data_class="public")
        self.assertLess(time.perf_counter() - t0, 1.0)
        self.assertEqual(vs[0].outcome, "cancelled")
        self.assertEqual(eng.decide(vs, "public"), "scan_data_class_mismatch")

    def test_without_a_deny_it_waits_for_every_scanner_up_to_the_timeout(self):
        eng, ps = self.engine(self.Sleepy("fast", 0.0), self.Sleepy("slow", 0.2), timeout_seconds=5)
        vs = eng.run("email_send", ps, "sha256", None, {})
        self.assertEqual([v.outcome for v in vs], ["allow", "allow"])
        late = self.Sleepy("late", 2.0)
        eng, ps = self.engine(self.Sleepy("fast", 0.0), late, timeout_seconds=0.2)
        t0 = time.perf_counter()
        vs = eng.run("email_send", ps, "sha256", None, {})
        self.assertLess(time.perf_counter() - t0, 1.0)
        self.assertEqual([(v.outcome, v.error_type) for v in vs], [("allow", None), ("timeout", "ScanTimeout")])
        self.assertEqual(len(late.abandoned), 1)
        self.assertEqual(eng.decide(vs, "public"), "scan_timeout:late")

    def test_sequential_is_still_available(self):
        b = self.Sleepy("b", 0.0)
        eng, ps = self.engine(self.Sleepy("a", 0.0, ScanReport("block")), b, order="sequential")
        vs = eng.run("email_send", ps, "sha256", None, {})
        self.assertEqual([v.scanner_id for v in vs], ["a"])        # stops at the first deny


class PatternPlugin(unittest.TestCase):
    def test_example_rules(self):
        sc = PatternScanner(rules=PatternScanner.example_rules())
        (v,), _ = run(sc, parts=[("call", "application/json", b'{"ssn":"123-45-6789"}')])
        self.assertEqual((v.outcome, v.data_classes, v.labels), ("allow", ("personal",), ("us_ssn",)))
        self.assertNotIn("123-45-6789", json.dumps(v.to_record()))      # matched text is never recorded
        (v,), _ = run(sc, parts=[("call", "application/json", b"x"), ("file:a", "text/plain", EICAR)])
        self.assertEqual((v.outcome, v.findings), ("block", ("file:a:eicar-test",)))

    def test_quarantine_rule(self):
        sc = PatternScanner(rules=[PatternRule("q", rb"hold-me", action="quarantine")])
        (v,), _ = run(sc, parts=[("call", "application/json", b"please hold-me")])
        self.assertEqual(v.outcome, "quarantine")

    def test_digest_only_payload_gives_error_for_content_scanners(self):
        (v,), _ = run(PatternScanner(rules=[]), payload="digest_only")
        self.assertEqual((v.outcome, v.payload_mode), ("error", "digest_only"))

    def test_registry_and_entry_points(self):
        self.assertIn("pattern", scanning.available_plugins())
        sc = scanning.create_plugin("pattern", scanner_id="p2", rules=[])
        self.assertIsInstance(sc, PatternScanner)
        with self.assertRaises(ScannerUnavailable):
            scanning.create_plugin("no-such-plugin")
        scanning.register_plugin("custom-test", lambda **kw: PatternScanner("custom", rules=[]))
        self.assertEqual(scanning.create_plugin("custom-test").scanner_id, "custom")
        self.assertEqual(scanning.load_entry_point_plugins("two_key.scanners.none-installed"), [])

    def test_clamd_python_adapter_degrades_gracefully(self):
        with mock.patch.dict(sys.modules, {"clamd": None}):
            with self.assertRaises(ScannerUnavailable):
                ClamdScanner()

    def test_clamd_python_adapter_with_fake_module(self):
        class Client:
            def __init__(self, **kw):
                self.kw = kw

            def version(self):
                return "ClamAV 1.4.1/fake"

            def instream(self, f):
                return {"stream": ("FOUND", "Eicar-Test-Signature") if EICAR in f.read() else ("OK", None)}

        fake = types.SimpleNamespace(ClamdUnixSocket=Client, ClamdNetworkSocket=Client)
        with mock.patch.dict(sys.modules, {"clamd": fake}):
            sc = ClamdScanner()
        (v,), _ = run(sc, parts=[("call", "application/json", EICAR)])
        self.assertEqual((v.outcome, v.findings, v.scanner_version),
                         ("block", ("call:Eicar-Test-Signature",), "ClamAV 1.4.1/fake"))
        (v,), _ = run(sc)
        self.assertEqual(v.outcome, "allow")


class VendorApi(unittest.TestCase):
    def setUp(self):
        self.reply = (200, {"result": {"verdict": "CLEAN"}, "tags": ["PHI"], "engine": "vendor-dlp 9.1"})
        self.fake = FakeHttpScanner(lambda body, headers: self.reply)
        self.mapping = ResponseMapping(outcome_path="result.verdict",
                                       outcome_map={"clean": "allow", "infected": "block", "held": "quarantine"},
                                       labels_path="tags", label_to_data_class={"phi": "medical"},
                                       version_path="engine")

    def tearDown(self):
        self.fake.close()

    def scanner(self, **kw):
        return VendorApiScanner("vendor", endpoint=self.fake.url, credential=StaticToken("test-token-not-real"),
                                mapping=self.mapping, **kw)

    def test_rest_exact_bytes_auth_and_mapping(self):
        (v,), ps = run(self.scanner())
        headers, body = self.fake.requests[0]
        self.assertEqual(headers["Authorization"], "Bearer test-token-not-real")
        self.assertEqual(base64.b64decode(body["parts"][0]["data_b64"]), CALL)
        self.assertEqual(body["payload_digest"], v.payload_digest)
        self.assertEqual((v.outcome, v.labels, v.data_classes, v.scanner_version, v.adapter),
                         ("allow", ("PHI",), ("medical",), "vendor-dlp 9.1", "vendor_api:rest"))
        self.assertNotIn("test-token-not-real", json.dumps(v.to_record()))

    def test_rest_block_and_unmapped(self):
        self.reply = (200, {"result": {"verdict": "Infected"}})
        (v,), _ = run(self.scanner())
        self.assertEqual(v.outcome, "block")
        self.reply = (200, {"result": {"verdict": "whatever"}})
        (v,), _ = run(self.scanner())
        self.assertEqual(v.outcome, "error")

    def test_rest_http_error_is_error(self):
        self.reply = (503, {"error": "busy"})
        (v,), _ = run(self.scanner())
        self.assertEqual((v.outcome, v.detail), ("error", "ScanError: http_status_503"))

    def test_rest_sends_exact_bytes_and_strings(self):
        sc = self.scanner()
        eng = ScanEngine([sc])
        eng.run("email_send", eng.build_parts([("call", "application/json", CALL)], "sha256", None), "sha256", None,
                {}, texts=eng.build_texts([("args.body", "h\u00e9llo")], "sha256", None))
        _, body = self.fake.requests[0]
        self.assertEqual(base64.b64decode(body["parts"][0]["data_b64"]), CALL)
        self.assertEqual((body["texts"][0]["name"], body["texts"][0]["text"]), ("text:args.body", "h\u00e9llo"))

    def test_rest_timeout_is_timeout(self):
        sc = VendorApiScanner("v", endpoint=self.fake.url)
        with mock.patch("urllib.request.OpenerDirector.open", side_effect=TimeoutError("timed out")):
            (v,), _ = run(sc)
        self.assertEqual(v.outcome, "timeout")

    def test_rest_digest_only_sends_no_content(self):
        (v,), _ = run(self.scanner(payload_mode="digest_only"))
        _, body = self.fake.requests[0]
        self.assertNotIn("data_b64", body["parts"][0])
        self.assertEqual(body["parts"][0]["digest"], hashlib.sha256(CALL).hexdigest())

    def test_rest_refuses_plain_http_to_remote_hosts(self):
        with self.assertRaises(ValueError):
            VendorApiScanner("v", endpoint="http://dlp.example.com/scan")
        VendorApiScanner("v", endpoint="http://dlp.example.com/scan", allow_insecure_http=True)
        VendorApiScanner("v", endpoint="https://dlp.example.com/scan")

    def test_custom_transport_for_grpc_style_stubs(self):
        seen = []

        def stub(body, headers, timeout):  # stands in for a vendor gRPC stub
            seen.append((body, headers, timeout))
            return {"outcome": "quarantine", "scanner_version": "grpc-fake 2"}

        (v,), _ = run(VendorApiScanner("grpc", transport=stub, credential=StaticToken("t0k")), timeout_seconds=3)
        self.assertEqual((v.outcome, v.scanner_version, v.adapter), ("quarantine", "grpc-fake 2", "vendor_api:custom"))
        self.assertEqual((seen[0][1]["Authorization"], seen[0][2]), ("Bearer t0k", 3.0))

    def test_grpc_transport_degrades_gracefully_without_grpcio(self):
        with mock.patch.dict(sys.modules, {"grpc": None}):
            with self.assertRaises(ScannerUnavailable):
                scanning.grpc_transport("127.0.0.1:50051", "/vendor.Scanner/Scan")


class Icap(unittest.TestCase):
    def tearDown(self):
        self.srv.close()

    def test_reqmod_clean_is_204_allow_with_exact_body(self):
        self.srv = FakeIcapServer("av")
        sc = IcapScanner("icap", host="127.0.0.1", port=self.srv.port)
        (v,), _ = run(sc)
        r = self.srv.requests[0]
        self.assertEqual((r["method"], r["body"]), ("REQMOD", CALL))
        self.assertTrue(r["line"].startswith(f"REQMOD icap://127.0.0.1:{self.srv.port}/avscan ICAP/1.0"))
        self.assertEqual(r["icap_headers"]["allow"], "204")
        self.assertTrue(r["http_headers"].startswith(b"POST /two-key/email_send/call HTTP/1.1\r\n"))
        self.assertEqual((v.outcome, v.scanner_version), ("allow", 'ISTag="fake-sig-42"'))

    def test_strings_are_sent_as_text_parts(self):
        self.srv = FakeIcapServer("av")
        sc = IcapScanner("icap", host="127.0.0.1", port=self.srv.port)
        eng = ScanEngine([sc])
        (v,) = eng.run("email_send", eng.build_parts([("call", "application/json", CALL)], "sha256", None), "sha256",
                       None, {}, texts=eng.build_texts([("args.body", "h\u00e9llo")], "sha256", None))
        self.assertEqual([r["body"] for r in self.srv.requests], [CALL, "h\u00e9llo".encode()])
        self.assertTrue(self.srv.requests[1]["http_headers"].startswith(b"POST /two-key/email_send/text:args.body"))
        self.assertEqual(v.outcome, "allow")

    def test_reqmod_infected_is_block_with_finding(self):
        self.srv = FakeIcapServer("av")
        sc = IcapScanner("icap", host="127.0.0.1", port=self.srv.port)
        (v,), _ = run(sc, parts=[("call", "application/json", b"x"), ("file:a.txt", "text/plain", EICAR)])
        self.assertEqual((v.outcome, v.findings), ("block", ("file:a.txt:Eicar-Test-Signature",)))

    def test_inbound_content_uses_respmod(self):
        self.srv = FakeIcapServer("av")
        sc = IcapScanner("icap", host="127.0.0.1", port=self.srv.port)       # REQMOD outbound by default
        eng = ScanEngine([sc])
        ps = eng.build_parts([("result", "application/json", CALL)], "sha256", None)
        (v,) = eng.run("email_send", ps, "sha256", None, {}, direction="inbound")
        self.assertEqual((self.srv.requests[0]["method"], v.outcome, v.direction), ("RESPMOD", "allow", "inbound"))
        with self.assertRaises(ValueError):
            IcapScanner("icap", host="127.0.0.1", inbound_method="GET")

    def test_respmod(self):
        self.srv = FakeIcapServer("av")
        sc = IcapScanner("icap", host="127.0.0.1", port=self.srv.port, method="RESPMOD")
        (v,), _ = run(sc)
        r = self.srv.requests[0]
        self.assertEqual((r["method"], r["body"], v.outcome), ("RESPMOD", CALL, "allow"))
        self.assertTrue(r["encapsulated"].startswith("req-hdr=0, res-hdr="))

    def test_200_same_body_allows_and_modified_body_blocks(self):
        self.srv = FakeIcapServer("echo200")
        (v,), _ = run(IcapScanner("icap", host="127.0.0.1", port=self.srv.port))
        self.assertEqual(v.outcome, "allow")
        self.srv.mode = "modify"
        (v,), _ = run(IcapScanner("icap", host="127.0.0.1", port=self.srv.port))
        self.assertEqual(v.outcome, "block")
        (v,), _ = run(IcapScanner("icap", host="127.0.0.1", port=self.srv.port, modified_outcome="quarantine"))
        self.assertEqual(v.outcome, "quarantine")

    def test_server_error_and_options(self):
        self.srv = FakeIcapServer("status500")
        sc = IcapScanner("icap", host="127.0.0.1", port=self.srv.port)
        (v,), _ = run(sc)
        self.assertEqual(v.outcome, "error")
        hdrs = sc.options()
        self.assertEqual(sc.version(), 'FakeICAP 1.0 ISTag="fake-sig-42"')
        self.assertIn("REQMOD", hdrs["methods"])

    def test_plaintext_remote_refused(self):
        self.srv = FakeIcapServer("av")
        with self.assertRaises(ValueError):
            IcapScanner("icap", host="icap.example.com")


class Sidecar(unittest.TestCase):
    def tearDown(self):
        self.srv.close()

    def test_unix_socket_json_protocol(self):
        self.srv = FakeSidecar(lambda req: {"outcome": "allow", "data_classes": ["financial"],
                                            "scanner_version": "sidecar 3", "payload_digest": req["payload_digest"]})
        (v,), _ = run(SidecarScanner("side", unix_socket=self.srv.path))
        req = self.srv.requests[0]
        self.assertEqual(req["protocol"], "two-key-scan/1")
        self.assertEqual(base64.b64decode(req["parts"][0]["data_b64"]), CALL)
        self.assertEqual((v.outcome, v.data_classes, v.scanner_version), ("allow", ("financial",), "sidecar 3"))

    def test_loopback_tcp_and_remote_refused(self):
        self.srv = FakeSidecar(lambda req: {"outcome": "block", "findings": [{"name": "rule-7"}]}, unix=False)
        (v,), _ = run(SidecarScanner("side", host="127.0.0.1", port=self.srv.port))
        self.assertEqual((v.outcome, v.findings), ("block", ("rule-7",)))
        with self.assertRaises(ValueError):
            SidecarScanner("side", host="10.0.0.5", port=1)

    def test_clamd_instream(self):
        self.srv = FakeSidecar(protocol="clamd-instream")
        sc = SidecarScanner("clam", unix_socket=self.srv.path, protocol="clamd-instream", kind="av", chunk_size=16)
        (v,), _ = run(sc, parts=[("call", "application/json", CALL), ("file:x", "application/octet-stream", EICAR)])
        self.assertEqual(self.srv.requests, [CALL, EICAR])            # chunked, reassembled exactly
        self.assertEqual((v.outcome, v.findings, v.scanner_version),
                         ("block", ("file:x:Eicar-Test-Signature",), "ClamAV 1.4.1/27400/Fake"))

    def test_unreachable_sidecar_is_error(self):
        self.srv = FakeSidecar(lambda req: {"outcome": "allow"})
        (v,), _ = run(SidecarScanner("side", unix_socket=self.srv.path + ".missing"))
        self.assertEqual(v.outcome, "error")


class AsyncCallback(unittest.TestCase):
    def test_post_send_returns_pending_then_delivers_to_listeners(self):
        submitted, seen, flags = [], [], []
        sc = AsyncCallbackScanner("async", lambda req, sid: submitted.append((req, sid)), on_flag=flags.append,
                                  hold_until_verdict=False)     # the weaker, non-default post-send mode
        sc.subscribe(lambda ctx, v: seen.append((ctx, v)))
        (v,), _ = run(sc)
        self.assertEqual(v.outcome, "pending")
        sid = submitted[0][1]
        self.assertEqual(v.scan_id, sid)
        self.assertTrue(sc.deliver(sid, {"outcome": "block", "findings": ["late-malware"]}))
        self.assertFalse(sc.deliver(sid, {"outcome": "allow"}))         # answered once only
        self.assertFalse(sc.deliver("unknown", {"outcome": "allow"}))
        ctx, late = seen[0]
        self.assertEqual((ctx["jti"], late.outcome, late.scan_id, late.findings), ("j1", "block", sid, ("late-malware",)))
        self.assertEqual(late.payload_digest, v.payload_digest)
        self.assertEqual(flags[0]["verdict"]["outcome"], "block")

    def test_hold_until_verdict(self):
        def submit(req, sid):
            threading.Timer(0.05, lambda: sc.deliver(sid, {"outcome": "allow", "data_classes": ["public"]})).start()

        sc = AsyncCallbackScanner("async", submit, hold_until_verdict=True)
        (v,), _ = run(sc)
        self.assertEqual((v.outcome, v.data_classes), ("allow", ("public",)))

    def test_hold_timeout_is_timeout_and_late_verdict_is_post_send(self):
        submitted, seen = [], []
        sc = AsyncCallbackScanner("async", lambda req, sid: submitted.append(sid), hold_until_verdict=True)
        sc.subscribe(lambda ctx, v: seen.append(v))
        (v,), _ = run(sc, timeout_seconds=0.1)
        self.assertEqual(v.outcome, "timeout")
        self.assertTrue(sc.deliver(submitted[0], {"outcome": "allow"}))
        self.assertEqual(seen[0].outcome, "allow")

    @staticmethod
    def _request():
        ps = ScanEngine.build_parts([("call", "application/json", CALL)], "sha256", None)
        return scanning.ScanRequest("r1", "email_send", "sha256", "exact", "d", ps, (), {"jti": "j1"})

    def test_engine_calls_abandon_when_it_stops_waiting(self):
        abandoned = []

        class Slow(PatternScanner):
            def scan(self, request, timeout):
                time.sleep(0.5)
                return ScanReport("allow")

            def abandon(self, request):
                abandoned.append(request.request_id)

        (v,), _ = run(Slow(rules=[]), timeout_seconds=0.05)
        self.assertEqual((v.outcome, len(abandoned)), ("timeout", 1))
        self.assertIsNone(PatternScanner(rules=[]).abandon(self._request()))   # default: no-op

    def test_abandoned_hold_records_a_later_verdict_as_post_send(self):
        submitted, seen, out = [], [], []
        sc = AsyncCallbackScanner("async", lambda req, sid: submitted.append(sid), hold_until_verdict=True)
        sc.subscribe(lambda ctx, v: seen.append(v))
        req = self._request()

        def held():
            try:
                out.append(sc.scan(req, 0.3))
            except Exception as e:  # noqa: BLE001
                out.append(e)

        t = threading.Thread(target=held)
        t.start()
        while not submitted:
            time.sleep(0.005)
        sc.abandon(req)                                  # the gateway stopped waiting
        self.assertTrue(sc.deliver(submitted[0], {"outcome": "block"}))
        self.assertEqual([v.outcome for v in seen], ["block"])  # recorded at once, as post-send
        t.join()
        self.assertIsInstance(out[0], scanning.ScanTimeout)
        self.assertEqual(sc.pending_ids(), [])

    def test_abandon_after_the_hold_picked_up_the_verdict_records_it_once(self):
        seen = []
        sc = AsyncCallbackScanner("async", lambda req, sid: sc.deliver(sid, {"outcome": "allow"}),
                                  hold_until_verdict=True)
        sc.subscribe(lambda ctx, v: seen.append(v))
        req = self._request()
        self.assertEqual(sc.scan(req, 1.0).outcome, "allow")   # picked up by the hold
        self.assertEqual(seen, [])
        sc.abandon(req)                                        # ...but the gateway had discarded it
        sc.abandon(req)
        self.assertEqual([v.outcome for v in seen], ["allow"])

    def test_submit_failure_is_error(self):
        def submit(req, sid):
            raise OSError("bucket unavailable")
        (v,), _ = run(AsyncCallbackScanner("async", submit))
        self.assertEqual((v.outcome, v.detail), ("error", "ScanError: submit: OSError"))

    def test_webhook_receiver_requires_hmac(self):
        submitted = []
        sc = AsyncCallbackScanner("async", lambda req, sid: submitted.append(sid), hold_until_verdict=False)
        run(sc)
        secret = b"webhook-test-secret-not-real-0001"
        with WebhookReceiver(sc, secret) as wh:
            host, port = wh._server.server_address[:2]

            def post(obj, sig=None, path=wh.path):
                body = json.dumps(obj).encode()
                c = http.client.HTTPConnection(host, port, timeout=5)
                c.request("POST", path, body, {"X-Two-Key-Signature": sig or WebhookReceiver.sign(secret, body)})
                return c.getresponse().status

            self.assertEqual(post({"scan_id": submitted[0], "outcome": "allow"}, sig="sha256=00"), 401)
            self.assertEqual(post({"scan_id": "nope", "outcome": "allow"}), 404)
            self.assertEqual(post({"outcome": "allow"}), 400)
            self.assertEqual(post({"scan_id": submitted[0]}, path="/other"), 404)
            self.assertEqual(post({"scan_id": submitted[0], "outcome": "allow"}), 204)
        with self.assertRaises(ValueError):
            WebhookReceiver(sc, b"short")


if __name__ == "__main__":
    unittest.main()
