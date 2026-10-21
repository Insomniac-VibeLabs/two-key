# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Content scanning behind the MCP proxy, without the MCP SDK: the proxy.yaml scan block and per-tool files,
the drafter's file hints, the start-up warning for undeclared files, and one tools/call with an attached file
through the scanner, Path A, Path B, and the gateway (two_key.mcp_proxy)."""

import base64
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.mcp_proxy.config import ProxyConfigError, parse_proxy_config
from two_key.mcp_proxy.core import (ProxyCore, check_tools_signed, file_like_inputs, select_tools,
                                    undeclared_file_inputs)
from two_key.mcp_proxy.draft import draft_specs, draft_tool, render_proxy_tools, render_rules
from two_key.quorum import QuorumPolicy
from two_key.scan import ScanResult, Scanner
from two_key.strict import load_yaml
from two_key.testing import TEST_AGENT, FixedJudge

DIGEST = "sha256:" + "0" * 64
MARKER = b"FAKE-MALWARE-MARKER"
ATTACH_SCHEMA = {"type": "object", "properties": {
    "to": {"type": "string"}, "body": {"type": "string"},
    "attachments": {"type": "array", "items": {"type": "object", "properties": {
        "filename": {"type": "string"}, "content": {"type": "string", "contentEncoding": "base64"}}}}}}
UPSTREAM = [
    {"name": "send_email", "description": "Send an email.", "inputSchema": ATTACH_SCHEMA},
    {"name": "print_doc", "description": "Print a document.",
     "inputSchema": {"type": "object", "properties": {"file_path": {"type": "string"}}}},
    {"name": "lookup", "description": "Look a word up.",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
]
FIELDS = {"scan": {"type": "enum", "values": ["clean", "flagged", "unavailable"], "default": "clean",
                   "source": "caller"}}
RULES = [{"id": "tools", "allow_only_tools": ["send_email", "print_doc", "lookup"]},
         {"id": "scan", "deny_if_fields": {"scan": {"eq": "flagged"}}}]
SPECS = {
    "send_email": {"irreversible": True, "data_class_floor": "personal",
                   "counterparties": [{"json_path": "to", "allow": ["ops@example.org"]}],
                   "payload": [{"json_path": "body", "shape": "string"}, {"json_path": "attachments"}],
                   "fields": {"scan": {"source": "caller"}}},
    "print_doc": {"irreversible": False, "data_class_floor": "public",
                  "payload": [{"json_path": "file_path", "shape": "string"}],
                  "fields": {"scan": {"source": "caller"}}},
    "lookup": {"irreversible": False, "data_class_floor": "public",
               "payload": [{"json_path": "query", "shape": "string"}],
               "fields": {"scan": "not_applicable"}},
}


def config(base: Path, **over):
    data = {"constitution": "c.json", "keys": {"principal": "k.pem"}, "ledger": "ledger", "judges": "judges.yaml",
            "upstream": {"command": ["mail-mcp"], "schema_digest": DIGEST}}
    data.update(over)
    return parse_proxy_config(data, base / "proxy.yaml")


class Marker:
    """Flags a part that carries the fake malware marker, and keeps what it was sent."""
    label = "marker"

    def __init__(self):
        self.parts = []

    def inspect(self, request):
        self.parts.extend(request.parts)
        if any(MARKER in p.data for p in request.parts):
            return ScanResult.flagged("malware", scanner="marker")
        return ScanResult.clean("marker")


class Config(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        (self.base / "outbox").mkdir()

    def test_scan_block_and_files(self):
        c = config(self.base, scan={"type": "clamd", "address": "127.0.0.1:3310"},
                   tools={"send_email": {"files": [{"path": "attachments[].content", "kind": "base64", "max_bytes": 4096}]},
                          "print_doc": {"files": [{"path": "file_path", "kind": "path", "folder": "outbox", "max_bytes": 1024}]}})
        self.assertEqual(c.scan["type"], "clamd")
        self.assertEqual(c.tools["send_email"].files[0].path, "attachments[].content")
        # A relative folder is relative to the directory of proxy.yaml.
        self.assertEqual(Path(c.tools["print_doc"].files[0].folder), self.base / "outbox")

    def test_refusals(self):
        scan = {"type": "clamd", "address": "127.0.0.1:3310"}
        bad = {
            "declare files, which are for the content scanner":
                {"tools": {"send_email": {"files": [{"path": "attachments[].content", "max_bytes": 4096}]}}},
            r"scan.type: expected one of": {"scan": {"type": "antivirus"}},
            r"unknown key\(s\) \['url'\] for type clamd": {"scan": dict(scan, url="icap://x")},
            r"scan.address: required": {"scan": {"type": "clamd"}},
            r"kind: expected one of": {"scan": scan, "tools": {"send_email": {"files": [
                {"path": "attachments[].content", "kind": "zip"}]}}},
            r"a path file needs the folder": {"scan": scan, "tools": {"print_doc": {"files": [
                {"path": "file_path", "kind": "path", "max_bytes": 1024}]}}},
            r"is not a directory": {"scan": scan, "tools": {"print_doc": {"files": [
                {"path": "file_path", "kind": "path", "folder": "missing", "max_bytes": 1024}]}}},
            r"only a kind: path file has a folder": {"scan": scan, "tools": {"send_email": {"files": [
                {"path": "attachments[].content", "folder": "outbox", "max_bytes": 4096}]}}},
            r"a path is declared twice": {"scan": scan, "tools": {"send_email": {"files": [
                {"path": "attachments[].content", "max_bytes": 4096}, {"path": "attachments[].content", "max_bytes": 4096}]}}},
            r"max_bytes: required": {"scan": scan, "tools": {"send_email": {"files": [
                {"path": "attachments[].content"}]}}},
            r"so at most 196608 bytes": {"scan": scan, "tools": {"send_email": {"files": [
                {"path": "attachments[].content", "max_bytes": 1000000}]}}},
            r"replaced by max_bytes": {"scan": dict(scan, max_file_bytes=1000)},
            r"is not an argument path": {"scan": scan, "tools": {"send_email": {"files": [
                {"path": "attachments[0].content", "max_bytes": 4096}]}}},
        }
        for message, over in bad.items():
            with self.subTest(message), self.assertRaisesRegex(ProxyConfigError, message):
                config(self.base, **over)


class Hints(unittest.TestCase):
    def test_file_like_inputs(self):
        schema = {"type": "object", "properties": {
            "attachments": ATTACH_SCHEMA["properties"]["attachments"],
            "file_path": {"type": "string"},
            "image": {"type": "string", "format": "binary"},
            "doc": {"type": "string", "contentEncoding": "base64url"},
            "upload": {"type": "object", "properties": {"data": {"type": "string"}, "name": {"type": "string"}}},
            "files": {"type": "array", "items": {"type": "string"}},
            "subject": {"type": "string"}, "count": {"type": "integer"}, "profile": {"type": "string"}}}
        self.assertEqual(file_like_inputs(schema), [
            ("attachments[].content", "base64"), ("doc", "base64url"), ("file_path", "path"),
            ("files[]", "base64"), ("image", "base64"), ("upload.data", "base64")])
        self.assertEqual(file_like_inputs(None), [])
        self.assertEqual(file_like_inputs({"type": "object", "properties": {"x": "not a schema"}}), [])

    def test_undeclared_files_warn_at_start(self):
        selection = select_tools(UPSTREAM, SPECS, {})
        self.assertEqual(undeclared_file_inputs(selection, SPECS, None), [])
        bare = Scanner(Marker())
        lines = undeclared_file_inputs(selection, SPECS, bare)
        self.assertEqual(len(lines), 2, lines)
        self.assertIn("print_doc: file_path looks like a file", lines[0])
        self.assertIn("send_email: attachments[].content looks like a file", lines[1])
        self.assertIn("scanned as text, not as a file", lines[1])
        with tempfile.TemporaryDirectory() as folder:
            declared = Scanner(Marker(), files={"send_email": [{"path": "attachments[].content", "max_bytes": 4096}],
                                                "print_doc": [{"path": "file_path", "kind": "path",
                                                               "folder": folder, "max_bytes": 1024}]})
            self.assertEqual(undeclared_file_inputs(selection, SPECS, declared), [])

    def test_the_drafter_hints_files_and_never_declares_them(self):
        t = draft_tool({"name": "send_email", "description": "Send an email.", "inputSchema": ATTACH_SCHEMA})
        self.assertEqual(t.files, [("attachments[].content", "base64")])
        self.assertTrue(any("looks like a file" in n for n in t.notes), t.notes)
        draft = draft_specs(UPSTREAM)
        tools = render_proxy_tools(draft)
        self.assertIn('#   - {path: "attachments[].content", kind: base64, max_bytes: REPLACE_WITH_BYTES}', tools)
        self.assertIn('#   - {path: "file_path", kind: path, folder: REPLACE_WITH_FOLDER, max_bytes: REPLACE_WITH_BYTES}',
                      tools)
        self.assertIn("base64: at most 196608", tools)
        parsed = load_yaml(tools)                       # commented: the drafted proxy.yaml declares no file
        self.assertNotIn("files", parsed["tools"]["send_email"])
        rules = render_rules(draft, ["mail-mcp"])
        self.assertIn("# To scan calls with an antivirus or DLP product (docs/SCANNERS.md)", rules)
        self.assertNotIn("scan", str(load_yaml(rules)))  # a template only: no field or rule is drafted


class Calls(unittest.TestCase):
    """One tools/call with an attached file: the agent sends the arguments the tool's schema asks for, and
    nothing else. The proxy, not the agent, has it scanned."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.calls = []

    def upstream(self, name, arguments):
        self.calls.append((name, arguments))
        return {"sent": True}

    def core(self, judge="yes"):
        key = generate_private_key()
        env = sign_constitution("Email ops. Never send malware.", RULES, key, SPECS, fields=FIELDS)
        self.marker = Marker()
        scanner = Scanner(self.marker, files={"send_email": [{"path": "attachments[].content", "max_bytes": 4096}]})
        self.judge = FixedJudge("a", judge)
        with contextlib.redirect_stderr(io.StringIO()):
            tk = TwoKey(Ledger(self.dir / "ledger", key), key.public_key(), verify_signed(env, key.public_key()),
                        [self.judge], private_key=key, quorum=QuorumPolicy(required_yes=1),
                        allow_test_doubles=True, monitored_agent=TEST_AGENT, scanner=scanner)
        cfg = config(self.dir, scan={"type": "python", "hook": "scan_hook_fixture:inspect"},
                     tools={"send_email": {"claim": "floor", "files": [{"path": "attachments[].content", "max_bytes": 4096}]}})
        check_tools_signed(cfg, tk)
        return ProxyCore(tk, cfg, select_tools(UPSTREAM, SPECS, cfg.tools), self.upstream)

    @staticmethod
    def email(content: bytes) -> dict:
        return {"to": "ops@example.org", "body": "report attached",
                "attachments": [{"filename": "r.txt", "content": base64.b64encode(content).decode("ascii")}]}

    def test_a_clean_file_is_sent(self):
        core = self.core()
        out = core.call_tool("send_email", self.email(b"quarterly numbers"))
        self.assertTrue(out.allowed, out)
        self.assertEqual(len(self.calls), 1)
        names = [p.name for p in self.marker.parts]
        self.assertEqual(names, ["arguments", "proposal", "file:attachments[0].content"])
        file_part = self.marker.parts[2]
        self.assertEqual(file_part.data, b"quarterly numbers")     # the scanner gets the decoded bytes
        scan = [e for e in core.two_key.ledger.entries if e.kind == "scan"][-1].body
        self.assertEqual(scan["verdict"], "clean")
        self.assertNotIn("quarterly", str(scan))                   # the ledger keeps the digest, not the file

    def test_a_flagged_file_is_never_sent(self):
        core = self.core()
        out = core.call_tool("send_email", self.email(b"x " + MARKER))
        self.assertFalse(out.allowed)
        self.assertEqual(out.reason, "rule_denied:scan")
        self.assertEqual(self.calls, [])

    def test_an_oversized_or_unreadable_file_is_denied_before_the_scanner_and_never_sent(self):
        core = self.core()
        out = core.call_tool("send_email", self.email(b"x" * 4097))
        self.assertEqual((out.allowed, out.reason), (False, "file_too_large"))
        bad = dict(self.email(b""), attachments=[{"filename": "r.txt", "content": "not base64!"}])
        out = core.call_tool("send_email", bad)
        self.assertEqual((out.allowed, out.reason), (False, "file_unreadable"))
        self.assertEqual((self.calls, self.marker.parts), ([], []))
        denied = [e.body for e in core.two_key.ledger.entries if e.kind == "decision"][-2:]
        self.assertEqual([d["file_denied"].get("why") for d in denied], [None, "bad_base64"])

    def test_the_agent_cannot_supply_the_verdict(self):
        core = self.core()
        args = dict(self.email(b"x " + MARKER), scan="clean")
        out = core.call_tool("send_email", args)
        self.assertFalse(out.allowed)
        self.assertEqual(out.reason, "derive_failed:caller_field_in_arguments:scan")
        self.assertEqual(self.calls, [])

    def test_the_agent_never_sees_a_scan_input(self):
        core = self.core()
        listed = {t["name"]: t for t in core.list_tools()}
        self.assertNotIn("scan", listed["send_email"]["inputSchema"].get("properties", {}))


if __name__ == "__main__":
    unittest.main()
