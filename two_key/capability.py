"""Single-use capability tokens bound to the ledger root at issuance.

Tokens are signed by a capability key that lives outside the ledger
directory. ``CapabilityVerifier`` holds only the public half. The gateway
uses that. ``CapabilityIssuer`` holds the private half and is what
``TwoKey`` uses to mint. The principal key signs the constitution and the
ledger head. It is not the minting key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_bytes, canonical_hash
from .strict import loads_json
from cryptography.hazmat.primitives import serialization

from .keys import (generate_private_key, load_private_key_file, public_key, save_private_key, save_public_key, sign,
                   verify)


class TokenError(ValueError):
    pass


# verify() refuses a token whose lifetime (exp - iat) exceeds the verifier's max_ttl_seconds, or whose
# iat is more than MAX_CLOCK_SKEW_SECONDS in the future. TwoKey sets max_ttl_seconds to its own
# ttl_seconds, so a token can never be valid longer than the configured lifetime.
# MAX_TTL_SECONDS is the hard ceiling for any TTL: a token is a one-shot capability, not a session.
DEFAULT_MAX_TTL_SECONDS = 300
MAX_TTL_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 5.0


def valid_ttl(value: Any, name: str = "ttl_seconds") -> int:
    """An int in [1, MAX_TTL_SECONDS]. bool, float (NaN, inf, 2.5), str, and None are refused."""
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_TTL_SECONDS:
        raise ValueError(f"{name} must be an integer from 1 to {MAX_TTL_SECONDS}, got {value!r}"[:200])
    return value


def _max_ttl(value: Any) -> int:
    return valid_ttl(value, "max_ttl_seconds")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_dec(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def args_hash(arguments: dict) -> str:
    return canonical_hash(arguments)


class CapabilityKeyError(ValueError):
    """The capability key is missing, changed, or is the principal key. Two-Key refuses to start."""


def _raw(public) -> bytes:
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def capability_key_fingerprint(public) -> str:
    """Full SHA-256 of the raw public key. Recorded in ``constitution_loaded`` and pinned by the gateway."""
    return "sha256:" + hashlib.sha256(_raw(public)).hexdigest()


def _pinned(ledger) -> str | None:
    for entry in reversed(getattr(ledger, "entries", [])):
        if entry.kind == "constitution_loaded":
            return entry.body.get("capability_key_fingerprint")
    return None


def open_capability_key(ledger, principal_public=None):
    """Load or create the minting key outside the ledger directory.

    The key is created with O_EXCL, mode 0600, inside ``<ledger>.capability/``
    at mode 0700. Once the ledger holds a ``capability_issued`` entry, a missing
    key file, or a key whose fingerprint differs from the one pinned in the last
    ``constitution_loaded`` entry, is refused (``CapabilityKeyError``) rather than
    silently replaced. Issued tokens with no pinned fingerprint in the last
    ``constitution_loaded`` entry (a ledger from before pinning, or an edited
    one) are refused too (``capability_key_unpinned``), since then nothing
    ties the key on disk to the tokens already issued.
    A key whose public half is the principal key is refused.
    The gateway must not call this. It verifies with the public half only.
    """
    path = ledger.capability_key_path()
    issued = any(e.kind == "capability_issued" for e in getattr(ledger, "entries", []))
    if path.exists():
        # Owner only (0o700): the rule's suggested 0o644 would let others read this key directory.
        os.chmod(path.parent, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        try:   # the safe loader: no symlink, a regular file, no group or other access (#57)
            key = load_private_key_file(path)
        except ValueError as e:
            raise CapabilityKeyError(f"capability key: {e}") from None
    else:
        if issued:
            raise CapabilityKeyError(
                "capability_key_missing: the ledger has capability_issued entries; refusing to mint with a new key")
        key = generate_private_key()
        save_private_key(path, key, private_dir=True)
        save_public_key(path.with_name("capability.pub.pem"), public_key(key))
    pinned = _pinned(ledger)
    if issued and not (isinstance(pinned, str) and pinned):
        raise CapabilityKeyError(
            "capability_key_unpinned: the ledger has capability_issued entries but the last constitution_loaded "
            "pins no key fingerprint (a ledger from before pinning, an edited one, or a TwoKey started without "
            "private_key= before 0.2.3); refusing to mint with a key the ledger cannot vouch for")
    if issued and pinned != capability_key_fingerprint(key.public_key()):
        raise CapabilityKeyError("capability_key_changed: the key does not match the fingerprint pinned in the ledger")
    if principal_public is not None and _raw(key.public_key()) == _raw(principal_public):
        raise CapabilityKeyError("capability_key_is_principal_key: the token key must not be the principal key")
    return key


@dataclass(frozen=True)
class IssuedCapability:
    token: str
    payload: dict

    @property
    def token_hash(self) -> str:
        return canonical_hash(self.token)


class CapabilityVerifier:
    """Checks a token. It cannot mint."""

    def __init__(self, public_key, *, clock=None, max_ttl_seconds: int = DEFAULT_MAX_TTL_SECONDS):
        self.public_key = public_key
        self.private_key = None
        self.clock = clock or time.time
        self.max_ttl_seconds = _max_ttl(max_ttl_seconds)

    def verify(self, token: Any) -> dict:
        """Check format, signature, lifetime, issue time, and expiry. Return the payload or raise TokenError."""
        if not isinstance(token, str) or token.count(".") != 2 or not token.startswith("tk1."):
            raise TokenError("malformed_token")
        _, body, signature = token.split(".")
        if not verify(self.public_key, body.encode("ascii"), signature):
            raise TokenError("bad_signature")
        try:
            payload = loads_json(_b64u_dec(body))
        except ValueError:  # StrictParseError is a ValueError
            raise TokenError("malformed_token") from None
        if not isinstance(payload, dict) or payload.get("v") != 1:
            raise TokenError("malformed_token")
        try:
            issued_at, expires_at = float(payload["iat"]), float(payload["exp"])
        except (KeyError, TypeError, ValueError, OverflowError):  # a missing or non-numeric time field
            raise TokenError("malformed_token") from None
        if not (math.isfinite(issued_at) and math.isfinite(expires_at)) or expires_at <= issued_at:
            raise TokenError("malformed_token")  # NaN, inf (1e400), or a token that expires before it is issued
        if expires_at - issued_at > self.max_ttl_seconds + 1e-3:  # 1 ms tolerance for float rounding
            raise TokenError("ttl_too_long")
        now = self.clock()
        if issued_at > now + MAX_CLOCK_SKEW_SECONDS:
            raise TokenError("issued_in_future")
        if now >= expires_at:
            raise TokenError("expired")
        return payload

    def issue(self, **kwargs) -> IssuedCapability:
        raise TokenError("verifier_cannot_mint")


class CapabilityIssuer(CapabilityVerifier):
    def __init__(self, private_key, public_key=None, *, clock=None, max_ttl_seconds: int = DEFAULT_MAX_TTL_SECONDS):
        super().__init__(public_key or private_key.public_key(), clock=clock, max_ttl_seconds=max_ttl_seconds)
        self.private_key = private_key

    def verifier(self) -> CapabilityVerifier:
        """A redeeming object. The private key is not on it."""
        return CapabilityVerifier(self.public_key, clock=self.clock, max_ttl_seconds=self.max_ttl_seconds)

    def issue(self, *, tool: str, arguments: dict, ledger_root: str, ledger_size: int,
              bytecode_hash: str, nl_hash: str, ttl_seconds: int = 120,
              spec_hash: str = "", form: dict | None = None,
              claimed_data_class: str | None = None, args_digest: str | None = None) -> IssuedCapability:
        """Mint a token. ``args_digest`` is ``args_hash(arguments)`` when the caller already encoded them."""
        if self.private_key is None:
            raise TokenError("verifier_cannot_mint")
        valid_ttl(ttl_seconds)
        if ttl_seconds > self.max_ttl_seconds:
            raise ValueError(f"ttl_seconds exceeds this issuer's max_ttl_seconds ({self.max_ttl_seconds})")
        now = int(self.clock())
        payload = {
            "v": 1,
            "jti": secrets.token_hex(16),
            "tool": tool,
            "args_hash": args_digest if args_digest is not None else args_hash(arguments),
            "ledger_root": ledger_root,
            "ledger_size": ledger_size,
            "bytecode_hash": bytecode_hash,
            "nl_hash": nl_hash,
            "spec_hash": spec_hash,
            "iat": now,
            "exp": now + ttl_seconds,
        }
        if form is not None:
            payload["form"] = form
            payload["claimed_data_class"] = claimed_data_class
        body = _b64u(canonical_bytes(payload))
        signature = sign(self.private_key, body.encode("ascii"))
        return IssuedCapability(f"tk1.{body}.{signature}", payload)
