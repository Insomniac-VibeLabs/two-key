"""Content scanning wired into the tool gateway: verdicts gate the call and are bound into the ledger."""
import base64
import threading
import unittest
from collections.abc import Mapping

from two_key.canonical import canonical_bytes, digest_hex
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
REDEEM_KEYS = {"jti", "token_sha256", "tool", "args_hash", "capability_entry_seq", "capability_entry_digest"}


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
                   self.tk.gateway(tools=self.tools, scanners=None, scan_settings=ScanSettings(on_error="allow"))):
            self.assertIsNone(gw.scan_engine)
            d = self.token("public", args)
            r = gw.invoke(d.capability, "email_send", args, fields("public"))
            self.assertEqual(r.reason, "executed")
            self.assertIsInstance(self.sent[-1]["cc"], tuple)           # args passed through, no snapshot copy
            self.assertEqual(set(self.last("capability_redeemed")), REDEEM_KEYS)
        self.assertFalse(any(e.kind == "content_scan_async" or "content_scans" in e.body
                             for e in self.tk.ledger.entries))
        self.assertTrue(self.tk.ledger.verify(self.fx.key.public_key()).ok)

    # -- (b) data-class override ---------------------------------------------------
    def test_override_off_records_dlp_class_but_keeps_the_self_label_check(self):
        gw = self.tk.gateway(tools=self.tools, scanners=[PatternScanner("dlp", rules=[DX], kind="dlp")])
        d = self.token("public", MED_ARGS)                # mislabeled: medical content declared public
        r = gw.invoke(d.capability, "email_send", MED_ARGS, fields("public"))
        self.assertEqual(r.reason, "executed")            # placeholder default: today's behavior
        body = self.last("capability_redeemed")
        self.assertEqual(body["content_scans"][0]["data_classes"], ["medical"])
        self.assertEqual(body["scan_policy"]["dlp_overrides_data_class"], False)

    def test_override_on_denies_a_mislabeled_call(self):
        gw = self.tk.gateway(tools=self.tools, scanners=[PatternScanner("dlp", rules=[DX], kind="dlp")],
                             scan_settings=ScanSettings(dlp_overrides_data_class=True))
        d = self.token("public", MED_ARGS)
        r = gw.invoke(d.capability, "email_send", MED_ARGS, fields("public"))
        self.assertEqual((r.allowed, r.reason), (False, "scan_data_class_mismatch"))
        self.assertEqual(self.sent, [])
        denied = self.last("gateway_denied")
        self.assertEqual((denied["scan_data_class"], denied["content_scans"][0]["outcome"]), ("medical", "allow"))

    def test_override_on_allows_when_the_dlp_class_matches_the_token(self):
        args = {"to": "clinic.example", "body": "my SSN is 123-45-6789"}
        gw = self.tk.gateway(tools=self.tools, scanners=[PatternScanner("dlp", rules=[SSN], kind="dlp")],
                             scan_settings=ScanSettings(dlp_overrides_data_class=True))
        d = self.token("personal", args)
        # The caller's own label no longer matters: the scan establishes the class.
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "executed")
        self.assertEqual(self.last("capability_redeemed")["scan_data_class"], "personal")

    def test_override_on_with_no_or_several_classes_uses_classified(self):
        gw = self.tk.gateway(tools=self.tools, scanners=[PatternScanner("dlp", rules=[SSN, DX], kind="dlp")],
                             scan_settings=ScanSettings(dlp_overrides_data_class=True))
        args = {"to": "clinic.example", "body": "plain text"}
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason,
                         "scan_data_class_mismatch")
        self.assertEqual(self.last("gateway_denied")["scan_data_class"], "classified")

    # -- digest binding --------------------------------------------------------------
    def test_verdict_is_bound_to_the_exact_hashed_bytes(self):
        rec = Recorder()
        gw = self.tk.gateway(tools=self.tools, scanners=[rec])
        args = {"to": "clinic.example", "body": "hello"}
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "executed")
        part = rec.requests[0].parts[0]
        self.assertEqual(part.data, canonical_bytes({"tool": "email_send", "args": args}))
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
        self.assertEqual(rec.requests[0].parts[0].data, canonical_bytes({"tool": "email_send", "args": honest}))

    # -- outcomes, (a) on_error, order -------------------------------------------------
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
                             scan_settings=ScanSettings(on_error="allow"))
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "executed")
        scan = self.last("capability_redeemed")["content_scans"][0]
        self.assertEqual((scan["outcome"], scan["detail"]), ("error", "OSError: scanner down"))

    def test_digest_only_payload_with_a_content_scanner_is_an_error(self):
        args = {"to": "clinic.example", "body": "x"}
        gw = self.tk.gateway(tools=self.tools, scanners=[PatternScanner(rules=[])],
                             scan_settings=ScanSettings(payload="digest_only"))
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "scan_error:pattern")

    def test_sequential_stops_at_first_deny_parallel_runs_all(self):
        args = {"to": "clinic.example", "body": "x"}
        for order, second_calls in (("sequential", 0), ("parallel", 1)):
            first, second = Recorder("first", ScanReport("block")), Recorder("second", kind="av")
            gw = self.tk.gateway(tools=self.tools, scanners=[first, second], scan_settings=ScanSettings(order=order))
            d = self.token("public", args)
            self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason,
                             "scan_blocked:first")
            self.assertEqual(len(second.requests), second_calls, order)

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
        sc = AsyncCallbackScanner("async", lambda req, sid: submitted.append(sid), on_flag=flags.append)
        gw = self.tk.gateway(tools=self.tools, scanners=[sc])
        args = {"to": "clinic.example", "body": "x"}
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "executed")
        pending = self.last("capability_redeemed")["content_scans"][0]
        self.assertEqual((pending["outcome"], pending["scan_id"]), ("pending", submitted[0]))
        self.assertTrue(sc.deliver(submitted[0], {"outcome": "block", "findings": ["late"]}))
        late = self.last("content_scan_async")
        self.assertEqual((late["jti"], late["scan"]["outcome"], late["scan"]["payload_digest"]),
                         (d.token_payload["jti"], "block", pending["payload_digest"]))
        self.assertEqual(flags[0]["context"]["jti"], d.token_payload["jti"])
        self.assertEqual(gw.async_scan_errors, [])
        self.assertTrue(self.tk.ledger.verify(self.fx.key.public_key()).ok)

    def test_async_hold_until_verdict_gates_the_call(self):
        def submit(req, sid):
            threading.Timer(0.05, lambda: sc.deliver(sid, {"outcome": "block"})).start()

        sc = AsyncCallbackScanner("async", submit, hold_until_verdict=True)
        gw = self.tk.gateway(tools=self.tools, scanners=[sc])
        args = {"to": "clinic.example", "body": "x"}
        d = self.token("public", args)
        self.assertEqual(gw.invoke(d.capability, "email_send", args, fields("public")).reason, "scan_blocked:async")
        self.assertEqual(self.sent, [])


if __name__ == "__main__":
    unittest.main()
