"""
Compact Kernel: capability tokens
=================================
Short-lived, scope-bound, single-use bearer tokens (spec 5.5).

Token = mode + "." + b64url(canonical payload) + "." + b64url(tag over mode + "." + b64payload)

Token modes (the issuer and the gateway must agree; a token of any other mode
is refused as ``unsupported_token_version``, so there is no downgrade):

  ck1        HMAC-SHA-256, >= 256-bit key (legacy default)
  ck1-hs384  HMAC-SHA-384, 384-bit key by default (default for PQ profiles)
  ck1-sig    signed with a separate token key set (PrivateKeySet), e.g. hybrid
             ML-DSA-65 + Ed25519. Optional: about 4.6 KB per token, and slower.

HMAC with a >= 256-bit key is already considered quantum-resistant (Grover's
algorithm at most halves the effective key strength), so the HMAC modes are
the recommended default; ck1-sig exists for deployments where the verifier
must not hold a secret that can also mint tokens.

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
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .canonical import canonical_bytes, canonical_hash
from .crypto.provider import CryptoProvider, PQUnavailableError, default_provider
from .crypto.signatures import as_private_keyset, as_public_keyset

PREFIX = "ck1"
MIN_SECRET_BYTES = 32
MAC_MODES = {"ck1": ("hmac-sha256", 32), "ck1-hs384": ("hmac-sha384", 48)}
TOKEN_MODES = tuple(MAC_MODES) + ("ck1-sig",)


class TokenError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def args_hash(tool: str, args: Mapping[str, Any], alg: str = "sha256",
              provider: CryptoProvider | None = None) -> str:
    """Canonical hash of the literal tool-call arguments (reference binding option).

    SHA-256 by default; SHA-384 in the post-quantum profiles."""
    if not isinstance(args, Mapping):
        raise TypeError("tool args must be a mapping")
    return canonical_hash({"tool": tool, "args": dict(args)}, alg, provider)


def token_sha256(token: str) -> str:
    """Identifier of a token for ledger records (SHA-256; an identifier, not a security binding)."""
    return default_provider().hash_hex("sha256", token.encode("ascii", "replace"))


@dataclass(frozen=True)
class IssuedCapability:
    token: str
    payload: dict

    @property
    def token_hash(self) -> str:
        return token_sha256(self.token)


class CapabilityIssuer:
    def __init__(self, secret: bytes | None = None, clock: Callable[[], float] = time.time, *,
                 mode: str = "ck1", signing_key: Any = None, verify_key: Any = None,
                 crypto: CryptoProvider | None = None):
        if mode not in TOKEN_MODES:
            raise ValueError(f"token mode must be one of {TOKEN_MODES}")
        self.crypto = crypto or default_provider()
        self.mode = mode
        self.clock = clock
        self._signer = self._verifier = None
        if mode in MAC_MODES:
            alg, default_len = MAC_MODES[mode]
            secret = secret if secret is not None else self.crypto.random_bytes(default_len)
            if len(secret) < MIN_SECRET_BYTES:
                raise ValueError(f"capability secret must be at least {MIN_SECRET_BYTES} bytes")
            self._mac_fn = self.crypto.hmac_factory(alg, secret)  # key schedule computed once
        else:
            if signing_key is None and verify_key is None:
                raise ValueError("ck1-sig mode needs a token signing key set (and/or a verify key)")
            if signing_key is not None:
                self._signer = as_private_keyset(signing_key, self.crypto)
            vk = verify_key if verify_key is not None else self._signer.public()
            self._verifier = as_public_keyset(vk, self.crypto)

    def __repr__(self) -> str:
        return f"<CapabilityIssuer mode={self.mode} [secret redacted]>"

    def _tag(self, signing_input: str) -> str:
        data = signing_input.encode("ascii")
        if self._signer is None and self.mode == "ck1-sig":
            raise ValueError("this issuer holds only a verify key")
        if self.mode in MAC_MODES:
            return _b64u(self._mac_fn(data))
        return _b64u(base64.b64decode(self._signer.sign(data)))

    def _check_tag(self, signing_input: str, tag: str) -> bool:
        if self.mode in MAC_MODES:
            return self.crypto.constant_time_eq(_b64u(self._mac_fn(signing_input.encode("ascii"))), tag)
        try:
            sig = base64.b64encode(_b64u_dec(tag)).decode("ascii")
        except ValueError:
            return False
        return self._verifier.verify(signing_input.encode("ascii"), sig)

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
        signing_input = f"{self.mode}.{body}"
        return IssuedCapability(f"{signing_input}.{self._tag(signing_input)}", payload)

    def verify(self, token: Any) -> dict:
        """Check format, MAC, and expiry. Return the payload or raise TokenError."""
        if not isinstance(token, str) or token.count(".") != 2:
            raise TokenError("malformed_token")
        prefix, body, tag = token.split(".")
        if prefix != self.mode:
            raise TokenError("unsupported_token_version")
        try:
            ok = self._check_tag(f"{prefix}.{body}", tag)
        except PQUnavailableError:
            raise TokenError("pq_unavailable") from None
        if not ok:
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
