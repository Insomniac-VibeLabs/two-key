# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The TypeScript tool-check helper (typescript/toolcheck/) against the Python side: canonical JSON byte for byte on
random values, a Python stamp passing the TypeScript checks, a TypeScript receipt passing the gateway's check, a
seen record shared by both helpers, and a TypeScript SDK server behind a real ``two-key mcp-proxy``.

Skipped unless Node 22.13 or later is on the path and the helper's tests are built (``npm ci && npm run build:test``
in typescript/toolcheck/); the CI job ``typescript-toolcheck`` builds them and runs this file."""

import dataclasses
import json
import math
import random
import shutil
import subprocess  # nosec B404 - runs node on the repository's own test fixtures
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from two_key.canonical import EncodingError, canonical_bytes  # noqa: E402
from two_key.capability import _b64u  # noqa: E402
from two_key.keys import save_public_key, sign  # noqa: E402
from two_key.toolcheck import (META_KEY, StampSigner, ToolCheckConfig, ToolChecker, ToolCheckError,  # noqa: E402
                               key_fingerprint, new_tool_key, result_hash, tool_args_hash, verify_receipt)

from test_toolcheck_vectors import IAT, seeded  # noqa: E402

PACKAGE = ROOT / "typescript" / "toolcheck"
BUILT = PACKAGE / "build" / "test" / "fixtures"
NODE = shutil.which("node")
RESULT = {"content": [{"type": "text", "text": "paid"}], "isError": False}


def node_ready() -> bool:
    if NODE is None or not (BUILT / "cross.js").exists():
        return False
    version = subprocess.run([NODE, "--version"], capture_output=True, text=True, check=False).stdout  # nosec B603
    major, minor = (int(x) for x in version.strip().lstrip("v").split(".")[:2])
    return (major, minor) >= (22, 13)


READY = node_ready()


def node(request: dict) -> list:
    done = subprocess.run([NODE, "--no-warnings", str(BUILT / "cross.js")], input=json.dumps(request),  # nosec B603
                          capture_output=True, text=True, check=True, timeout=120, cwd=PACKAGE)
    return json.loads(done.stdout)


def random_string(rng: random.Random) -> str:
    alphabet = ["a", "Z", "0", " ", '"', "\\", "\n", "\t", "\x00", "\x1f", "\x7f", "é", " ", "～",
                "\U0001f600", "\U00010000", "/", "<"]
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 6)))


def random_number(rng: random.Random):
    kind = rng.randint(0, 5)
    if kind == 0:
        return rng.randint(-2**53, 2**53)
    if kind == 1:
        return rng.randint(-1000, 1000)
    if kind == 2:
        return rng.uniform(-1e6, 1e6)
    if kind == 3:
        return math.ldexp(rng.uniform(-1, 1), rng.randint(-1074, 1023))
    if kind == 4:
        return float(rng.randint(-10**6, 10**6)) + rng.choice([0.5, 0.25, 0.1, 0.0])
    return rng.choice([1e-4, 1e-5, 1e15, 1e16, 1e21, 1e22, 5e-324, 1.7976931348623157e308, 0.1 + 0.2, -0.0])


def random_value(rng: random.Random, depth: int = 0):
    kind = rng.randint(0, 6 if depth < 4 else 3)
    if kind == 0:
        return rng.choice([None, True, False])
    if kind == 1:
        return random_string(rng)
    if kind in (2, 3):
        return random_number(rng)
    if kind == 4:
        return [random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {random_string(rng): random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))}


def keeps_its_form(value) -> bool:
    """Whether JavaScript parses this value from Python's JSON without changing what Python would write back: no
    whole-number float (12.0 arrives as 12) and no integer beyond 2^53."""
    if isinstance(value, float):
        return not value.is_integer()
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return True
    if isinstance(value, int):
        return abs(value) <= 2**53
    items = value.values() if isinstance(value, dict) else value
    return all(keeps_its_form(item) for item in items)


@unittest.skipUnless(READY, "needs node 22.13+ and the built TypeScript helper (typescript/toolcheck: npm run build:test)")
class CanonicalJson(unittest.TestCase):
    def test_random_values_encode_byte_for_byte_as_python_reads_them(self):
        rng = random.Random(28)      # fixed seed: a failure is reproducible
        values = [random_value(rng) for _ in range(3000)]
        answers = node({"op": "canonical", "values": values})
        same_form = 0
        for value, answer in zip(values, answers):
            self.assertNotIn("error", answer, value)
            # The JSON JavaScript writes (a result on the wire), read and written back by Python: always identical.
            self.assertEqual(canonical_bytes(json.loads(answer["wire"])).decode("ascii"), answer["canonical"], value)
            if keeps_its_form(value):
                same_form += 1
                # The value Python sent (arguments through the proxy): identical too, so the hash matches.
                self.assertEqual(canonical_bytes(value).decode("ascii"), answer["canonical"], value)
        self.assertGreater(same_form, 1000)

    def test_a_whole_number_float_or_a_big_integer_cannot_match_and_so_is_refused(self):
        values = [{"amount": 12.0}, {"n": 2**53 + 1}, {"n": 1e16}]
        for value, answer in zip(values, node({"op": "canonical", "values": values})):
            self.assertNotEqual(canonical_bytes(value).decode("ascii"), answer["canonical"])

    def test_values_json_cannot_hold_are_errors_on_both_sides(self):
        deep = _nested(65)
        self.assertRaises(EncodingError, canonical_bytes, deep)
        self.assertIn("error", node({"op": "canonical", "values": [deep]})[0])


def _nested(levels: int):
    value = 1
    for _ in range(levels):
        value = [value]
    return value


def _token(capability, arguments, jti="0123456789abcdef0123456789abcdef"):
    payload = {"v": 2, "alg": "ed25519+ml-dsa-65", "jti": jti, "tool": "pay_vendor", "iat": IAT, "exp": IAT + 120,
               "tool_args_hash": tool_args_hash(arguments)}
    body = _b64u(canonical_bytes(payload))
    return f"tk2.{body}.{sign(capability, body.encode('ascii'))}", payload


@unittest.skipUnless(READY, "needs node 22.13+ and the built TypeScript helper (typescript/toolcheck: npm run build:test)")
class CrossSigning(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.capability, self.stamp_key = seeded(1), seeded(2)
        self.tool_fp = new_tool_key(self.tmp / "tool.pem")
        save_public_key(self.tmp / "cap.pub.pem", self.capability.public_key())
        save_public_key(self.tmp / "stamp.pub.pem", self.stamp_key.public_key())
        self.config = self.tmp / "check.json"
        self.config.write_text(json.dumps({
            "tool": "pay_vendor", "capability_public_key": "cap.pub.pem",
            "capability_key_fingerprint": key_fingerprint(self.capability.public_key()),
            "stamp_public_key": "stamp.pub.pem", "stamp_key_fingerprint": key_fingerprint(self.stamp_key.public_key()),
            "tool_private_key": "tool.pem", "seen_record": "seen.sqlite"}))

    def call(self, arguments, sent=None, jti="0123456789abcdef0123456789abcdef"):
        token, payload = _token(self.capability, arguments, jti)
        stamp = StampSigner(self.stamp_key, clock=lambda: IAT + 1).stamp(token, payload, 8)
        return token, stamp, {"arguments": arguments if sent is None else sent,
                              "meta": {META_KEY: {"token": token, "stamp": stamp}}, "result": RESULT}

    def run_calls(self, *calls):
        return node({"op": "call", "config": str(self.config), "now": IAT + 2, "calls": [c[2] for c in calls]})

    def test_a_python_stamp_passes_and_the_typescript_receipt_passes_the_gateway(self):
        call = self.call({"vendor": "ada", "amount": 12.5, "memo": "café \U0001f600"})
        answer = self.run_calls(call)[0]
        self.assertNotIn("refused", answer)
        body = verify_receipt(answer["receipt"], pinned=self.tool_fp, jti="0123456789abcdef0123456789abcdef",
                              tool="pay_vendor", stamp=call[1], result=result_hash(RESULT))
        self.assertEqual(body["outcome"], "ran")

    def test_a_typescript_refusal_reaches_the_gateway_as_refused(self):
        call = self.call({"vendor": "ada", "amount": 12.5}, sent={"vendor": "ada", "amount": 13})
        answer = self.run_calls(call)[0]
        self.assertEqual(answer["refused"], "args_mismatch")
        with self.assertRaises(ToolCheckError) as caught:
            verify_receipt(answer["receipt"], pinned=self.tool_fp, jti="0123456789abcdef0123456789abcdef",
                           tool="pay_vendor", stamp=call[1], result=None)
        self.assertEqual(caught.exception.reason, "refused:args_mismatch")

    def test_a_whole_number_float_from_python_is_refused_not_passed(self):
        self.assertEqual(self.run_calls(self.call({"vendor": "ada", "amount": 12.0}))[0]["refused"], "args_mismatch")

    def test_python_and_typescript_copies_sharing_a_seen_record_refuse_each_others_replays(self):
        first = self.call({"vendor": "ada", "amount": 1.5}, jti="a" * 32)
        python = ToolChecker(ToolCheckConfig.load(self.config), clock=lambda: IAT + 2)
        python.check(first[2]["arguments"], first[2]["meta"])
        second = self.call({"vendor": "ada", "amount": 2.5}, jti="b" * 32)
        answers = self.run_calls(first, second)
        self.assertEqual(answers[0]["refused"], "replayed")
        self.assertNotIn("refused", answers[1])
        with self.assertRaises(ToolCheckError) as caught:
            python.check(second[2]["arguments"], second[2]["meta"])
        self.assertEqual(caught.exception.reason, "replayed")


import test_toolcheck_mcp  # noqa: E402  (the subclass below runs its tests against the TypeScript server)


@unittest.skipUnless(READY and (BUILT / "server.js").exists(), "needs node 22.13+ and the built TypeScript helper")
class TypeScriptServerBehindTheProxy(test_toolcheck_mcp.ThroughTheProxy):
    """docs/TOOL_CHECK.md end to end: the same tests as the Python server's, against a TypeScript SDK server
    (typescript/toolcheck/test/fixtures/server.ts) whose pay_vendor runs only through the helper, behind a real
    two-key mcp-proxy."""

    def config(self, digest="sha256:" + "0" * 64, variant=""):
        cfg = super().config(digest, variant)
        command = (NODE, "--no-warnings", str(BUILT / "server.js"))
        return dataclasses.replace(cfg, upstream=dataclasses.replace(cfg.upstream, command=command))


if __name__ == "__main__":
    unittest.main()
