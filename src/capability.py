"""
Compact Kernel — Capability tokens
==================================
Short-lived, scope-bound tokens. A tool gateway must refuse any call
that does not present a token whose scope covers that exact tool
invocation. Tokens are HMAC-signed in the prototype; production uses
a hardware-backed key in a TEE / Secure Enclave / HSM.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class Capability:
    principal: str
    tool: str
    scope: dict
    issued_at: float
    expires_at: float
    ledger_root: str
    token: str

    def expired(self) -> bool:
        return time.time() >= self.expires_at


class CapabilityIssuer:
    def __init__(self, secret: bytes | None = None):
        self.secret = secret or os.urandom(32)

    def issue(
        self,
        principal: str,
        tool: str,
        scope: dict,
        ledger_root: str,
        ttl_seconds: int = 30,
    ) -> Capability:
        now = time.time()
        payload = {
            "principal": principal,
            "tool": tool,
            "scope": scope,
            "issued_at": now,
            "expires_at": now + ttl_seconds,
            "ledger_root": ledger_root,
        }
        sig = hmac.new(self.secret, _canon(payload), hashlib.sha256).hexdigest()
        payload["token"] = sig
        return Capability(**payload)

    def verify(self, cap: Capability) -> bool:
        if cap.expired():
            return False
        payload = {
            "principal": cap.principal,
            "tool": cap.tool,
            "scope": cap.scope,
            "issued_at": cap.issued_at,
            "expires_at": cap.expires_at,
            "ledger_root": cap.ledger_root,
        }
        expected = hmac.new(self.secret, _canon(payload), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, cap.token)
