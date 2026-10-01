"""Content scanning wired into the tool gateway: verdicts gate the call and are bound into the ledger."""
import base64
import threading
import time
import unittest
from collections.abc import Mapping

from two_key.canonical import DOMAIN_TOOL_RESULT, digest_hex, freeze_call, typed_bytes
from two_key.quorum import QuorumPolicy
from two_key.scanning import (EICAR, AsyncCallbackScanner, PatternRule, PatternScanner, ScanReport, ScanSettings)
from two_key.testing import FixedJudge
from helpers import TwoKeyFixture

RULES = [
    {"id": "tools", "allow_only_tools": ["email_send", "pay_bill"]},
    {"id": "sensitive", "deny_if": {"data_class_in": ["medical", "classified"]}},
]
YES = [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2")]
DX = PatternRule("dx", rb"(?i)diagnosis", label="health", data_class="medical")
SSN = PatternRule("ssn", rb"\d{3}-\d{2}-\d{4}", label="us_ssn", data_class="personal")
MED_ARGS = {"to": "clinic.example", "body": "Diagnosis: example condition"}
REDEEM_KEYS = {"jti", "token_digest", "tool", "args_hash", "args_enc", "capability_entry_seq", "capability_entry_digest"}


def email(data_class):
    return {"tool": "email_send", "counterparty": "clinic.example", "data_class": data_class, "irreversible": False}


def fields(data_class):
    return {"counterparty": "clinic.example", "data_class": data_class}


class Recorder(PatternScanner):
    """A DLP scanner that records the requests it receives and answers with a fixed report."""

    def __init__(self, scanner_id="rec", report=None, kind="dlp"):
        super().__init__(scanner_id, rules=[], kind=kind)
        self.report, self.requests = report or ScanReport("allow"), []

    def scan(self, request, timeout):
        self.requests.append(request)
        if isinstance(self.report, Exception):
            raise self.report
        return self.report


class ScanningGateway(unittest.TestCase):
    def setUp(self):
        self.fx = TwoKeyFixture(RULES, YES, quorum_policy=QuorumPolicy(required_yes=2))
        self.tk = self.fx.__enter__()
        self.sent = []
        self.tools = {"email_send": lambda **a: self.sent.append(a) or "sent"}

    def tearDown(self):
        self.fx.__exit__(None, None, None)

    def token(self, data_class, args):
        d = self.tk.authorize(email(data_class), "Send the email.", args)
        self.assertTrue(d.allowed, d.reason)
        return d

    def last(self, kind):
        return [e for e in self.tk.ledger.entries if e.kind == kind][-1].body

    # -- no scanners: nothing changes --------------------------------------------
    def test_no_scanners_means_the_original_path(self):
        args = {"to": "clinic.example", "body": "hi", "cc": ("a@x.example", "b@x.example")}
        for gw in (self.tk.gateway(tools=self.tools), self.tk.gateway(tools=self.tools, scanners=[]),
                   self.tk.gateway(tools=self.tools, scanners=None, scan_settings=ScanSettings(on_timeout="allow"))):
            self.assertIsNone(gw.scan_engine)
            d = self.token("public", args)
            r = gw.invoke(d.capability, "email_send", args, fields("public"))
            self.assertEqual(r.reason, "executed")
            self.assertIsInstance(self.sent[-1]["cc"], tuple)           # args passed through, no snapshot copy
            self.assertEqual(set(self.last("capability_redeemed")), REDEEM_KEYS)
            self.assertEqual(r.result, "sent")
            self.assertNotIn("result_scans", self.last("tool_executed"))   # no inbound scanning either
            self.assertEqual(gw.scan_inbound(b"anything", source="x").reason, "not_scanned")
        self.assertFalse(any(e.kind in ("content_scan_async", "content_scan_inbound") or "content_scans" in e.body
                             for e in self.tk.ledger.entries))
        self.assertTrue(self.tk.ledger.verify(self.fx.key.public_key()).ok)

    # -- Entries 6 (b) and 7: any conviction denies ------------------------------------
    def test_dlp_class_other_than_the_token_denies(self):
        gw = self.tk.gateway(tools=self.tools, scanners=[PatternScanner("dlp", rules=[DX], kind="dlp")])
        d = self.token("public", MED_ARGS)                # mislabeled: medical content declared public
        r = gw.invoke(d.capability, "email_send", MED_ARGS, fields("public"))
        self.assertEqual((r.allowed, r.reason), (False, "scan_data_class_mismatch"))
        self.assertEqual(self.sent, [])
        denied = self.last("gateway_denied")
        self.assertEqual((denied["scan_data_classes"], denied["content_scans"][0]["outcome"]),
                         (["public", "medical"], "allow"))
        self.assertFalse(self.tk.ledger.is_redeemed(d.token_payload["jti"]))

    def test_dlp_class_the_token_does_not_permit_denies_even_if_less_sensitive(self):
        # Entry 7: no ranking. A personal token doesn't permit content the DLP labels public.
        args = {"to": "clinic.example", "body": "plain text"}
        dlp = Recorder(report=ScanReport("allow", data_classes=("public",)))
        gw = self.tk.gateway(tools=self.tools, scanners=[dlp])
        d = self.token("personal", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("personal")).reason,
                         "scan_data_class_mismatch")
        self.assertEqual(self.last("gateway_denied")["scan_data_classes"], ["personal", "public"])

    def test_matching_class_and_no_class_execute(self):
        args = {"to": "clinic.example", "body": "my SSN is 123-45-6789"}
        gw = self.tk.gateway(tools=self.tools, scanners=[PatternScanner("dlp", rules=[SSN, DX], kind="dlp")])
        d = self.token("personal", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("personal")).reason, "executed")
        plain = {"to": "clinic.example", "body": "plain text"}
        d = self.token("public", plain)
        self.assertEqual(gw.invoke(d.capability, "email_send", plain, fields("public")).reason, "executed")
        self.assertEqual(self.last("capability_redeemed")["scan_data_classes"], ["public"])

    def test_disagreeing_classes_deny(self):
        args = {"to": "clinic.example", "body": "x"}
        dlp = Recorder(report=ScanReport("allow", data_classes=("personal",)))
        gw = self.tk.gateway(tools=self.tools, scanners=[dlp])
        # The call's own class is financial; the DLP says personal: the DLP convicts, so deny (Entry 7).
        d = self.tk.authorize({**email("financial")}, "Send.", args)
        self.assertTrue(d.allowed, d.reason)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("financial")).reason,
                         "scan_data_class_mismatch")
        self.assertEqual(self.last("gateway_denied")["scan_data_classes"], ["financial", "personal"])

    def test_two_key_deny_is_never_turned_into_allow(self):
        rec = Recorder(report=ScanReport("allow", data_classes=("public",)))
        gw = self.tk.gateway(tools=self.tools, scanners=[rec], scan_settings=ScanSettings(on_error="allow",
                                                                                          on_timeout="allow"))
        args = {"to": "clinic.example", "body": "x"}
        d = self.token("public", args)
        other = {"to": "clinic.example", "body": "something else"}
        self.assertEqual(gw.invoke(d.capability, "email_send", other, fields("public")).reason, "args_mismatch")
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("personal")).reason,
                         "data_class_mismatch")    # the call's own label still has to match the token
        self.assertFalse(gw.invoke("tk1.bogus.token", "email_send", args, fields("public")).allowed)
        self.assertEqual(rec.requests, [])        # scanners only run after every Two-Key check passed
        self.assertEqual(self.sent, [])

    # -- Entry 6 (a): timeout seconds and action ------------------------------------------
    def test_timeout_default_blocks_and_can_be_set_to_allow(self):
        class Slow(Recorder):
            def scan(self, request, timeout):
                import time
                time.sleep(0.5)
                return ScanReport("allow")

        args = {"to": "clinic.example", "body": "x"}
        gw = self.tk.gateway(tools=self.tools, scanners=[Slow()], scan_settings=ScanSettings(timeout_seconds=0.05))
        d = self.token("public", args)
        import time
        t0 = time.perf_counter()
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "scan_timeout:rec")
        self.assertLess(time.perf_counter() - t0, 0.4)   # waits the configured seconds, not the scanner's 0.5 s
        gw = self.tk.gateway(tools=self.tools, scanners=[Slow()],
                             scan_settings=ScanSettings(timeout_seconds=0.05, on_timeout="allow"))
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "executed")
        red = self.last("capability_redeemed")
        self.assertEqual((red["content_scans"][0]["outcome"], red["scan_policy"]["on_timeout"],
                          red["scan_policy"]["timeout_seconds"]), ("timeout", "allow", 0.05))

    # -- Entry 7: a scanner error is logged and treated like a timeout -------------------
    def test_scanner_error_follows_the_timeout_action_and_is_logged(self):
        args = {"to": "clinic.example", "body": "x"}
        d = self.token("public", args)
        gw = self.tk.gateway(tools=self.tools, scanners=[Recorder(report=OSError("down"))])
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "scan_error:rec")
        err = self.last("gateway_denied")["scan_errors"]
        self.assertEqual([(e["scanner_id"], e["outcome"], e["error_type"], e["action"]) for e in err],
                         [("rec", "error", "OSError", "block")])
        self.assertEqual(err[0]["payload_digest"], self.last("gateway_denied")["content_scans"][0]["payload_digest"])
        self.assertEqual(err[0]["scanner_version"], Recorder().version())
        gw = self.tk.gateway(tools=self.tools, scanners=[Recorder(report=OSError("down"))],
                             scan_settings=ScanSettings(on_timeout="allow"))
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "executed")
        red = self.last("capability_redeemed")
        self.assertEqual([(e["error_type"], e["action"]) for e in red["scan_errors"]], [("OSError", "allow")])
        self.assertEqual(red["scan_policy"]["on_error"], "allow")

    # -- Entry 6 (c): exact bytes and strings ------------------------------------------------
    def test_scanners_get_exact_bytes_and_decoded_strings(self):
        rec = Recorder()
        gw = self.tk.gateway(tools=self.tools, scanners=[rec])
        args = {"to": "clinic.example", "body": "caf\u00e9 <script>x()</script>", "cc": ["a@x.example"]}
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "executed")
        req = rec.requests[0]
        self.assertEqual(req.parts[0].data, freeze_call("email_send", args).data)
        self.assertNotIn("\u00e9".encode("utf-8"), req.parts[0].data)            # escaped in the exact bytes
        texts = {t.name: t.data.decode("utf-8") for t in req.texts}
        self.assertEqual(texts["text:args.body"], "caf\u00e9 <script>x()</script>")
        self.assertEqual(texts["text:args.cc[0]"], "a@x.example")
        self.assertEqual(texts["text:args.body#key"], "body")
        red = self.last("capability_redeemed")
        self.assertEqual(red["content_scans"][0]["parts"][0]["digest"], d.token_payload["args_hash"])
        self.assertEqual({t["name"] for t in red["content_scans"][0]["texts"]}, set(texts))

    def test_script_in_a_string_is_caught_through_the_decoded_text(self):
        rule = PatternRule("js-eval", "\u00e9val\\(".encode("utf-8"), action="block")   # matches only unescaped
        gw = self.tk.gateway(tools=self.tools, scanners=[PatternScanner("av", rules=[rule], kind="av")])
        args = {"to": "clinic.example", "body": "<script>\u00e9val(1)</script>"}
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "scan_blocked:av")
        self.assertEqual(self.last("gateway_denied")["content_scans"][0]["findings"], ["text:args.body:js-eval"])

    # -- digest binding --------------------------------------------------------------
    def test_verdict_is_bound_to_the_exact_hashed_bytes(self):
        rec = Recorder()
        gw = self.tk.gateway(tools=self.tools, scanners=[rec])
        args = {"to": "clinic.example", "body": "hello"}
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "executed")
        part = rec.requests[0].parts[0]
        self.assertEqual(part.data, freeze_call("email_send", args).data)
        h = digest_hex(part.data, self.tk.digest_alg)
        cap, red = self.last("capability_issued"), self.last("capability_redeemed")
        self.assertEqual({h}, {d.token_payload["args_hash"], cap["args_hash"], red["args_hash"],
                               red["content_scans"][0]["parts"][0]["digest"]})
        scan = red["content_scans"][0]
        self.assertEqual((scan["scanner_id"], scan["scanner_version"], scan["outcome"], scan["payload_digest"]),
                         ("rec", rec.version(), "allow", rec.requests[0].payload_digest))
        self.assertEqual(rec.requests[0].context["jti"], d.token_payload["jti"])
        self.assertTrue(self.tk.ledger.verify(self.fx.key.public_key()).ok)

    def test_snapshot_executes_what_was_hashed_and_scanned(self):
        honest = {"to": "clinic.example", "body": "hello"}

        class Shifty(Mapping):      # honest on the first read of each key, then something else
            def __init__(self):
                self.reads = {}

            def __getitem__(self, k):
                self.reads[k] = self.reads.get(k, 0) + 1
                return honest[k] if self.reads[k] == 1 else "attacker.example"

            def __iter__(self):
                return iter(honest)

            def __len__(self):
                return len(honest)

        rec = Recorder()
        gw = self.tk.gateway(tools=self.tools, scanners=[rec])
        d = self.token("public", honest)
        self.assertEqual(gw.invoke(d.capability, "email_send", Shifty(), fields("public")).reason, "executed")
        self.assertEqual(self.sent, [honest])
        self.assertEqual(rec.requests[0].parts[0].data, freeze_call("email_send", honest).data)

    # -- outcomes, errors, order -------------------------------------------------------
    def test_block_and_quarantine_deny_before_redemption(self):
        for rep, reason in ((ScanReport("block", findings=("x",)), "scan_blocked:rec"),
                            (ScanReport("quarantine"), "scan_quarantined:rec")):
            gw = self.tk.gateway(tools=self.tools, scanners=[Recorder(report=rep)])
            args = {"to": "clinic.example", "body": "x"}
            d = self.token("public", args)
            self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, reason)
            self.assertFalse(self.tk.ledger.is_redeemed(d.token_payload["jti"]))
        self.assertEqual(self.sent, [])

    def test_on_error_block_and_allow(self):
        args = {"to": "clinic.example", "body": "x"}
        gw = self.tk.gateway(tools=self.tools, scanners=[Recorder(report=OSError("scanner down"))])
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "scan_error:rec")
        gw = self.tk.gateway(tools=self.tools, scanners=[Recorder(report=OSError("scanner down"))],
                             scan_settings=ScanSettings(on_timeout="allow"))
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "executed")
        scan = self.last("capability_redeemed")["content_scans"][0]
        self.assertEqual((scan["outcome"], scan["detail"]), ("error", "OSError: scanner down"))

    def test_digest_only_payload_with_a_content_scanner_is_an_error(self):
        args = {"to": "clinic.example", "body": "x"}
        gw = self.tk.gateway(tools=self.tools, scanners=[PatternScanner(rules=[])],
                             scan_settings=ScanSettings(payload="digest_only"))
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "scan_error:pattern")

    def test_sequential_stops_at_first_deny_parallel_records_every_scanner(self):
        args = {"to": "clinic.example", "body": "x"}
        first, second = Recorder("first", ScanReport("block")), Recorder("second", kind="av")
        gw = self.tk.gateway(tools=self.tools, scanners=[first, second],
                             scan_settings=ScanSettings(order="sequential"))
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "scan_blocked:first")
        self.assertEqual(len(second.requests), 0)
        gw = self.tk.gateway(tools=self.tools, scanners=[Recorder("first", ScanReport("block")),
                                                         Recorder("second", kind="av")])      # parallel default
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "scan_blocked:first")
        scans = self.last("gateway_denied")["content_scans"]
        self.assertEqual([s["scanner_id"] for s in scans], ["first", "second"])
        self.assertIn(scans[1]["outcome"], ("allow", "cancelled"))
        self.assertEqual(self.last("gateway_denied")["scan_policy"]["order"], "parallel")

    def test_parallel_deny_does_not_wait_for_a_slow_scanner(self):
        class Slow(Recorder):
            def scan(self, request, timeout):
                time.sleep(1.5)
                return ScanReport("allow")

        args = {"to": "clinic.example", "body": "x"}
        gw = self.tk.gateway(tools=self.tools, scanners=[Slow("slow"), Recorder("av", ScanReport("block"), kind="av")])
        d = self.token("public", args)
        t0 = time.perf_counter()
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "scan_blocked:av")
        self.assertLess(time.perf_counter() - t0, 1.0)
        self.assertEqual([s["outcome"] for s in self.last("gateway_denied")["content_scans"]], ["cancelled", "block"])

    # -- file parts ------------------------------------------------------------------------
    def test_file_extractor_parts_are_scanned(self):
        def attachments(a):
            return [("report.txt", base64.b64decode(a["attachment_b64"]), "text/plain")]

        av = PatternScanner("av", rules=PatternScanner.example_rules(), kind="av")
        gw = self.tk.gateway(tools=self.tools, scanners=[av], file_extractors={"email_send": attachments})
        args = {"to": "clinic.example", "body": "see attached", "attachment_b64": base64.b64encode(EICAR).decode()}
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "scan_blocked:av")
        scan = self.last("gateway_denied")["content_scans"][0]
        self.assertEqual(scan["findings"], ["file:report.txt:eicar-test"])
        self.assertEqual([p["name"] for p in scan["parts"]], ["call", "file:report.txt"])
        self.assertEqual(scan["parts"][1]["digest"], digest_hex(EICAR, self.tk.digest_alg))

    def test_failing_file_extractor_denies(self):
        gw = self.tk.gateway(tools=self.tools, scanners=[Recorder()],
                             file_extractors={"email_send": lambda a: [("f", a["missing"], "x")]})
        args = {"to": "clinic.example", "body": "x"}
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason,
                         "invalid_call:file_extractor:KeyError")

    # -- adapter 5 through the gateway ---------------------------------------------------
    def test_async_post_send_records_late_verdict_and_flags(self):
        submitted, flags = [], []
        sc = AsyncCallbackScanner("async", lambda req, sid: submitted.append(sid), on_flag=flags.append,
                                  hold_until_verdict=False)       # the weaker, non-default post-send mode
        gw = self.tk.gateway(tools=self.tools, scanners=[sc])
        args = {"to": "clinic.example", "body": "x"}
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "executed")
        pending = self.last("capability_redeemed")["content_scans"][0]
        self.assertEqual((pending["outcome"], pending["scan_id"]), ("pending", submitted[0]))
        self.assertTrue(sc.deliver(submitted[0], {"outcome": "block", "findings": ["late"]}))
        late = self.last("content_scan_async")
        self.assertEqual((late["jti"], late["direction"], late["scan"]["outcome"], late["scan"]["payload_digest"]),
                         (d.token_payload["jti"], "outbound", "block", pending["payload_digest"]))
        self.assertEqual(flags[0]["context"]["jti"], d.token_payload["jti"])
        self.assertEqual(gw.async_scan_errors, [])
        self.assertTrue(self.tk.ledger.verify(self.fx.key.public_key()).ok)

    def test_async_hold_until_verdict_gates_the_call(self):
        def submit(req, sid):
            threading.Timer(0.05, lambda: sc.deliver(sid, {"outcome": "block"})).start()

        sc = AsyncCallbackScanner("async", submit)               # holds by default (Entry 7)
        gw = self.tk.gateway(tools=self.tools, scanners=[sc])
        args = {"to": "clinic.example", "body": "x"}
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "scan_blocked:async")
        self.assertEqual(self.sent, [])

    def test_async_hold_with_no_verdict_times_out_and_blocks_by_default(self):
        sc = AsyncCallbackScanner("async", lambda req, sid: None)
        gw = self.tk.gateway(tools=self.tools, scanners=[sc], scan_settings=ScanSettings(timeout_seconds=0.1))
        args = {"to": "clinic.example", "body": "x"}
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "scan_timeout:async")
        self.assertEqual(self.sent, [])
        self.assertEqual(self.last("gateway_denied")["scan_errors"][0]["outcome"], "timeout")

    # -- Entry 7: inbound, before the agent receives or processes it ---------------------
    def inbound_gateway(self, result, scanners, **kw):
        tools = {"email_send": lambda **a: self.sent.append(a) or result}
        return self.tk.gateway(tools=tools, scanners=scanners, **kw)

    def test_tool_result_is_scanned_before_it_is_returned(self):
        rec = Recorder()
        gw = self.inbound_gateway({"reply": "caf\u00e9 ok"}, [rec])
        args = {"to": "clinic.example", "body": "x"}
        d = self.token("public", args)
        r = gw.invoke(d.capability, "email_send", args, fields("public"))
        self.assertEqual((r.reason, r.result), ("executed", {"reply": "caf\u00e9 ok"}))
        out, inn = rec.requests
        self.assertEqual((out.direction, inn.direction), ("outbound", "inbound"))
        self.assertEqual(inn.parts[0].data, typed_bytes({"reply": "caf\u00e9 ok"}, DOMAIN_TOOL_RESULT))
        self.assertEqual({t.name: t.data.decode() for t in inn.texts}["text:result.reply"], "caf\u00e9 ok")
        ex = self.last("tool_executed")
        self.assertEqual(ex["result_scans"][0]["parts"][0]["digest"], ex["result_hash"])   # bound to H(result)
        self.assertEqual((ex["result_scans"][0]["direction"], ex["result_withheld"]), ("inbound", None))

    def test_blocked_result_is_withheld_after_the_tool_ran(self):
        av = PatternScanner("av", rules=PatternScanner.example_rules(), kind="av")
        gw = self.inbound_gateway({"download": EICAR.decode()}, [av])
        args = {"to": "clinic.example", "body": "x"}
        d = self.token("public", args)
        r = gw.invoke(d.capability, "email_send", args, fields("public"))
        self.assertEqual((r.allowed, r.reason, r.result), (False, "result_withheld:scan_blocked:av", None))
        self.assertEqual(len(self.sent), 1)                       # the tool did run
        ex = self.last("tool_executed")
        self.assertEqual((ex["result_withheld"], ex["result_scans"][0]["outcome"]), ("scan_blocked:av", "block"))
        self.assertTrue(self.tk.ledger.verify(self.fx.key.public_key()).ok)

    def test_inbound_files_bytes_and_result_file_extractors(self):
        av = PatternScanner("av", rules=PatternScanner.example_rules(), kind="av")
        gw = self.inbound_gateway(EICAR, [av])                    # raw bytes: scanned as a file
        args = {"to": "clinic.example", "body": "x"}
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason,
                         "result_withheld:scan_blocked:av")
        self.assertEqual(self.last("tool_executed")["result_scans"][0]["parts"][0]["content_type"],
                         "application/octet-stream")
        res = {"name": "a.txt", "b64": base64.b64encode(EICAR).decode()}
        gw = self.inbound_gateway(res, [av], result_file_extractors={
            "email_send": lambda r: [(r["name"], base64.b64decode(r["b64"]), "text/plain")]})
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason,
                         "result_withheld:scan_blocked:av")
        self.assertEqual(self.last("tool_executed")["result_scans"][0]["findings"], ["file:a.txt:eicar-test"])
        gw = self.inbound_gateway(res, [av], result_file_extractors={"email_send": lambda r: [("f", r["nope"], "x")]})
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason,
                         "result_withheld:invalid_result:file_extractor:KeyError")

    def test_inbound_uses_the_same_class_error_and_timeout_rules(self):
        args = {"to": "clinic.example", "body": "x"}

        class InboundOnly(Recorder):            # allows the outbound call, answers the result with `report`
            def scan(self, request, timeout):
                if request.direction == "outbound":
                    return ScanReport("allow")
                return super().scan(request, timeout)

        cases = ((ScanReport("allow", data_classes=("medical",)), {}, "result_withheld:scan_data_class_mismatch"),
                 (OSError("down"), {}, "result_withheld:scan_error:rec"),
                 (OSError("down"), {"on_timeout": "allow"}, "executed"))
        for report, settings, reason in cases:
            gw = self.inbound_gateway({"ok": 1}, [InboundOnly(report=report)], scan_settings=ScanSettings(**settings))
            d = self.token("public", args)
            self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, reason)
        self.assertEqual([(e["direction"], e["error_type"], e["action"])
                          for e in self.last("tool_executed")["result_scan_errors"]], [("inbound", "OSError", "allow")])

        class SlowInbound(Recorder):
            def scan(self, request, timeout):
                if request.direction == "inbound":
                    time.sleep(1.0)
                return ScanReport("allow")

        gw = self.inbound_gateway({"ok": 1}, [SlowInbound()], scan_settings=ScanSettings(timeout_seconds=0.1))
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason,
                         "result_withheld:scan_timeout:rec")

    def test_scan_inbound_for_content_outside_a_tool_call(self):
        av = PatternScanner("av", rules=PatternScanner.example_rules(), kind="av")
        dlp = PatternScanner("dlp", rules=[DX], kind="dlp")
        gw = self.tk.gateway(tools=self.tools, scanners=[av, dlp])
        r = gw.scan_inbound("hello", source="mail:inbox/1", files=[("a.bin", EICAR, "application/octet-stream")])
        self.assertEqual((r.allowed, r.reason), (False, "scan_blocked:av"))
        e = self.last("content_scan_inbound")
        self.assertEqual((e["source"], e["decision"], [p["name"] for p in e["content_scans"][0]["parts"]]),
                         ("mail:inbox/1", "scan_blocked:av", ["result", "file:a.bin"]))
        self.assertTrue(gw.scan_inbound("hello", source="mail:inbox/2").allowed)
        self.assertEqual(gw.scan_inbound("Diagnosis: x", source="s", data_class="public").reason,
                         "scan_data_class_mismatch")
        self.assertTrue(gw.scan_inbound("Diagnosis: x", source="s").allowed)       # no class given: not checked
        self.assertTrue(self.tk.ledger.verify(self.fx.key.public_key()).ok)


if __name__ == "__main__":
    unittest.main()
