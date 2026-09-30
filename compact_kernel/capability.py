"""
Compact Kernel: capability tokens
=================================
Short-lived, scope-bound, single-use bearer tokens (spec 5.5).

Token = "ck1." + b64url(canonical payload) + "." + b64url(HMAC-SHA256(secret, "ck1." + b64payload))

Payload fields: v, jti (unique id for single-use), principal, tool,
scope{amount_usd, counterparty, data_class}, args_hash, issued_at,
expires_at, ledger_root, constitution_digest.

Reference option (per Stephan's instructions, 2026-09-30): the token is bound
to ``args_hash``, the SHA-256 of the canonical JSON of {tool, args} for the
literal tool-call arguments. Alternatives are listed in DESIGN_OPTIONS.md
section 3. The prototype uses HMAC with a secret shared between issuer and
gateway. Production is expected to use a hardware-backed key (spec 5.1 item 6).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .canonical import canonical_bytes, canonical_hash

PREFIX = "ck1"
MIN_SECRET_BYTES = 32


class TokenError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def args_hash(tool: str, args: Mapping[str, Any]) -> str:
    """Canonical hash of the literal tool-call arguments (reference binding option)."""
    if not isinstance(args, Mapping):
        raise TypeError("tool args must be a mapping")
    return canonical_hash({"tool": tool, "args": dict(args)})


def token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode("ascii", "replace")).hexdigest()


@dataclass(frozen=True)
class IssuedCapability:
    token: str
    payload: dict

    @property
    def token_hash(self) -> str:
        return token_sha256(self.token)


class CapabilityIssuer:
    def __init__(self, secret: bytes | None = None, clock: Callable[[], float] = time.time):
        secret = secret if secret is not None else os.urandom(MIN_SECRET_BYTES)
        if len(secret) < MIN_SECRET_BYTES:
            raise ValueError(f"capability secret must be at least {MIN_SECRET_BYTES} bytes")
        self._secret = secret
        self.clock = clock

    def __repr__(self) -> str:
        return "<CapabilityIssuer [secret redacted]>"

    def _mac(self, signing_input: str) -> str:
        return _b64u(hmac.new(self._secret, signing_input.encode("ascii"), hashlib.sha256).digest())

    def issue(self, *, principal: str, tool: str, scope: dict, args_digest: str, ledger_root: str,
              constitution_digest: str, ttl_seconds: int) -> IssuedCapability:
        if not isinstance(ttl_seconds, int) or ttl_seconds < 1:
            raise ValueError("ttl_seconds must be a positive integer")
        now = self.clock()
        payload = {
            "v": 1, "jti": secrets.token_hex(16), "principal": principal, "tool": tool, "scope": dict(scope),
            "args_hash": args_digest, "issued_at": now, "expires_at": now + ttl_seconds,
            "ledger_root": ledger_root, "constitution_digest": constitution_digest,
        }
        body = _b64u(canonical_bytes(payload))
        signing_input = f"{PREFIX}.{body}"
        return IssuedCapability(f"{signing_input}.{self._mac(signing_input)}", payload)

    def verify(self, token: Any) -> dict:
        """Check format, MAC, and expiry. Return the payload or raise TokenError."""
        if not isinstance(token, str) or token.count(".") != 2:
            raise TokenError("malformed_token")
        prefix, body, mac = token.split(".")
        if prefix != PREFIX:
            raise TokenError("unsupported_token_version")
        if not hmac.compare_digest(self._mac(f"{prefix}.{body}"), mac):
            raise TokenError("bad_signature")
        try:
            payload = json.loads(_b64u_dec(body))
        except ValueError:
            raise TokenError("malformed_token") from None
        if not isinstance(payload, dict) or payload.get("v") != 1:
            raise TokenError("malformed_token")
        if self.clock() >= float(payload["expires_at"]):
            raise TokenError("expired")
        return payload
