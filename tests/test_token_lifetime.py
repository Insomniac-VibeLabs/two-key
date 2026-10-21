# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Fix 8: a token may not outlive the configured TTL, be issued in the future, or lack a time field."""

import tempfile
import unittest
from pathlib import Path

from two_key.canonical import canonical_bytes
from two_key.capability import CapabilityIssuer, CapabilityVerifier, TokenError, _b64u
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.gateway import ToolGateway
from two_key.keys import generate_private_key, sign
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def forge(issuer, payload):
    body = _b64u(canonical_bytes(payload))
    return f"tk1.{body}.{sign(issuer.private_key, body.encode('ascii'))}"


BASE = {"v": 1, "jti": "j", "tool": "search", "args_hash": "a", "ledger_root": "r", "ledger_size": 0,
        "bytecode_hash": "b", "nl_hash": "n", "spec_hash": ""}


class Lifetime(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.issuer = CapabilityIssuer(generate_private_key(), clock=self.clock, max_ttl_seconds=120)

    def verify(self, **fields):
        return self.issuer.verifier().verify(forge(self.issuer, dict(BASE, **fields)))

    def test_issuer_refuses_a_ttl_above_its_max(self):
        with self.assertRaisesRegex(ValueError, "exceeds this issuer's max_ttl_seconds"):
            self.issuer.issue(tool="search", arguments={}, ledger_root="r", ledger_size=0, bytecode_hash="b",
                              nl_hash="n", ttl_seconds=121)
        ok = self.issuer.issue(tool="search", arguments={}, ledger_root="r", ledger_size=0, bytecode_hash="b",
                               nl_hash="n", ttl_seconds=120)
        self.assertEqual(self.issuer.verifier().verify(ok.token)["jti"], ok.payload["jti"])

    def test_verifier_refuses_a_long_lived_signed_token(self):
        now = int(self.clock.t)
        with self.assertRaisesRegex(TokenError, "ttl_too_long"):
            self.verify(iat=now, exp=now + 10**9)
        self.assertEqual(self.verify(iat=now, exp=now + 120)["jti"], "j")

    def test_issued_in_the_future(self):
        now = int(self.clock.t)
        with self.assertRaisesRegex(TokenError, "issued_in_future"):
            self.verify(iat=now + 6, exp=now + 60)
        self.assertEqual(self.verify(iat=now + 5, exp=now + 60)["jti"], "j")  # within the 5 s skew

    def test_missing_or_bad_time_fields_are_malformed(self):
        now = int(self.clock.t)
        for fields in ({"iat": now}, {"exp": now + 10}, {"iat": "x", "exp": now + 10},
                       {"iat": now, "exp": now}, {"iat": now, "exp": now - 1}, {"iat": None, "exp": None}):
            with self.assertRaisesRegex(TokenError, "malformed_token"):
                self.issuer.verifier().verify(forge(self.issuer, dict(BASE, **fields)))

    def test_bad_max_ttl(self):
        for bad in (0, -1, True, 1.5):
            with self.assertRaisesRegex(ValueError, "max_ttl_seconds must be an integer from 1 to 300"):
                CapabilityVerifier(self.issuer.public_key, max_ttl_seconds=bad)


class GatewayAndTwoKey(unittest.TestCase):
    def test_gateway_returns_token_errors_not_exceptions(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            env = sign_constitution("c", [{"id": "t", "allow_only_tools": ["search"]}], key,
                                    {"search": {"irreversible": False, "data_class_floor": "public"}})
            tk = TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                        [FixedJudge("a", "yes")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                        allow_test_doubles=True, monitored_agent=TEST_AGENT, ttl_seconds=60)
            self.assertEqual(tk.issuer.max_ttl_seconds, 60)
            gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled, tools={"search": lambda a: a})
            self.assertEqual(gw.issuer.max_ttl_seconds, 60)
            no_exp = forge(tk.issuer, {"v": 1, "jti": "x", "tool": "search"})
            self.assertEqual(gw.invoke(no_exp, "search", {}).reason, "malformed_token")
            now = int(tk.issuer.clock())
            no_args_hash = forge(tk.issuer, {"v": 1, "jti": "x", "tool": "search", "iat": now, "exp": now + 30})
            self.assertEqual(gw.invoke(no_args_hash, "search", {}).reason, "malformed_token")
            for iat, exp in ((str(now), "1e400"), ("-1e400", str(now + 30))):   # JSON numbers that parse to inf
                text = canonical_bytes(BASE).decode()[:-1] + f',"exp":{exp},"iat":{iat}}}'
                body = _b64u(text.encode())
                huge = f"tk1.{body}.{sign(tk.issuer.private_key, body.encode('ascii'))}"
                self.assertEqual(gw.invoke(huge, "search", {}).reason, "malformed_token")
            long = forge(tk.issuer, dict(BASE, iat=now, exp=now + 61))
            self.assertEqual(gw.invoke(long, "search", {}).reason, "ttl_too_long")
            for bad in (0, -5, True, 2.5, float("nan"), float("inf"), float("-inf"), 301, 10**12, "60", None):
                with self.assertRaisesRegex(TwoKeyConfigError, "^ttl_out_of_range: ttl_seconds must be an "
                                                               "integer from 1 to 300", msg=repr(bad)):
                    TwoKey(tk.ledger, key.public_key(), tk.constitution, [FixedJudge("a", "yes")], private_key=key,
                           quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                           monitored_agent=TEST_AGENT, ttl_seconds=bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TtlBounds(unittest.TestCase):
    def test_issuer_and_verifier_bounds(self):
        from two_key.capability import MAX_TTL_SECONDS
        key = generate_private_key()
        self.assertEqual(CapabilityIssuer(key, max_ttl_seconds=MAX_TTL_SECONDS).max_ttl_seconds, 300)
        for bad in (float("nan"), float("inf"), 301, 0, True, 1.0):
            with self.assertRaisesRegex(ValueError, "max_ttl_seconds must be an integer from 1 to 300", msg=repr(bad)):
                CapabilityVerifier(key.public_key(), max_ttl_seconds=bad)
            with self.assertRaisesRegex(ValueError, "ttl_seconds must be an integer from 1 to 300", msg=repr(bad)):
                CapabilityIssuer(key).issue(tool="t", arguments={}, ledger_root="r", ledger_size=1,
                                            bytecode_hash="b", nl_hash="n", ttl_seconds=bad)
