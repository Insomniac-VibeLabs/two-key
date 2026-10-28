# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The tool check (#28): a tool behind ``two-key mcp-proxy`` proves for itself that each call was authorized and
spent, and signs a receipt that Two-Key checks and ledgers. docs/TOOL_CHECK.md is the wire description, for a tool
written in any language; this module is both sides of it in Python.

Three signed objects, each canonical JSON (``canonical_bytes``) in base64url, signed with Ed25519 over a purpose
label, a zero byte and that text, so a signature made for one purpose fails for any other:

- the token field ``tool_args_hash``: the hash of the arguments as the tool receives them (after projection),
  inside the ``tk1`` token the issuer signs. Present only for a tool whose signed spec turns the check on.
- the redeem stamp ``tks1.<body>.<sig>``, label ``two-key-redeem-stamp/1``, signed by the gateway's stamp key once
  ``redemption_started`` is on the ledger: this token, for this tool and these arguments, was spent at ``seq``.
- the tool receipt ``tkr1.<body>.<sig>``, label ``two-key-tool-receipt/1``, signed by the tool's own key over the
  jti, the stamp's hash and the hash of the result, or the reason the tool refused.

The tool's checks run in a fixed order and stop at the first failure (:meth:`ToolChecker.check`); any failure,
including an error inside the helper, is a refusal, never a pass. The seen record that refuses a second use of a
jti is a small SQLite file (Python's standard library), pruned as tokens expire.
"""

from __future__ import annotations

import hashlib
import math
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from . import _platform
from .canonical import EncodingError, canonical_bytes, canonical_hash
from .capability import MAX_TTL_SECONDS, _b64u, _b64u_dec, capability_key_fingerprint
from .keys import (generate_private_key, load_private_key_file, load_public_key, public_from_raw, public_raw,
                   save_private_key, save_public_key, sign, verify)
from .strict import loads_json

STAMP_PREFIX = "tks1"
RECEIPT_PREFIX = "tkr1"
STAMP_LABEL = b"two-key-redeem-stamp/1"
RECEIPT_LABEL = b"two-key-tool-receipt/1"
# The key the proxy and the tool use in MCP ``_meta``, on the request and on the result.
META_KEY = "io.github.insomniac-vibelabs/two-key"
ALG = "ed25519"
# Fixed and not configurable (risk R9): how far the tool's clock may be behind or ahead of Two-Key's.
CLOCK_ALLOWANCE_SECONDS = 5
# A stamp or receipt is a few hundred characters; anything far longer is refused unread.
MAX_OBJECT_CHARS = 4096
EXEMPT = "exempt"
# What the tool refuses with, in check order (docs/TOOL_CHECK.md).
REFUSALS = ("check_missing", "stamp_invalid", "token_invalid", "stamp_mismatch", "tool_mismatch", "args_mismatch",
            "expired", "replayed", "check_failed")


class ToolCheckError(ValueError):
    """A check that failed. ``reason`` is a short code from :data:`REFUSALS` or a receipt reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def key_fingerprint(public) -> str:
    """``sha256:`` of the raw public key: the same form as the capability key's fingerprint."""
    return capability_key_fingerprint(public)


def text_hash(text: str) -> str:
    """``sha256:`` of a token, stamp or receipt as sent (its ASCII text)."""
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def tool_args_hash(arguments: Any) -> str:
    """``sha256:`` of the canonical JSON of the arguments as the tool receives them."""
    return "sha256:" + canonical_hash(arguments)


def result_hash(result: Mapping[str, Any]) -> str:
    """``sha256:`` of the canonical JSON of an MCP result in wire form, without its ``_meta``."""
    return "sha256:" + canonical_hash({k: v for k, v in result.items() if k != "_meta"})


def checked(spec: Mapping[str, Any] | None) -> str | None:
    """The pinned tool key fingerprint when the signed spec turns the check on, else None (absent or exempt)."""
    value = (spec or {}).get("tool_check")
    return value["key"] if isinstance(value, Mapping) else None


def _message(label: bytes, body: str) -> bytes:
    return label + b"\x00" + body.encode("ascii")


def seal(prefix: str, label: bytes, private_key, body: Mapping[str, Any]) -> str:
    """``<prefix>.<base64url canonical body>.<base64 signature over label, 0x00, body text>``."""
    text = _b64u(canonical_bytes(dict(body)))
    return f"{prefix}.{text}.{sign(private_key, _message(label, text))}"


def peek(prefix: str, text: Any, what: str) -> tuple[dict, str, str]:
    """The body of a stamp or receipt, its body text and signature, not yet verified. Raises ``<what>_invalid``."""
    if not isinstance(text, str) or len(text) > MAX_OBJECT_CHARS or text.count(".") != 2 \
            or not text.startswith(prefix + "."):
        raise ToolCheckError(f"{what}_invalid")
    _, body_text, signature = text.split(".")
    try:
        body = loads_json(_b64u_dec(body_text))
        text.encode("ascii")
    except (ValueError, UnicodeError):
        raise ToolCheckError(f"{what}_invalid") from None
    if not isinstance(body, dict) or body.get("v") != 1 or body.get("alg") != ALG:
        raise ToolCheckError(f"{what}_invalid")
    return body, body_text, signature


def open_sealed(prefix: str, label: bytes, public, text: Any, what: str) -> dict:
    """The body of a stamp or receipt whose signature verifies with ``public``. Raises ``<what>_invalid``."""
    body, body_text, signature = peek(prefix, text, what)
    if not verify(public, _message(label, body_text), signature):
        raise ToolCheckError(f"{what}_invalid")
    return body


# ---------------------------------------------------------------------------------------------- Two-Key's side

def stamp_key_path(ledger) -> Path:
    """The stamp key: beside the capability key, in the owner-only folder outside the ledger directory."""
    return ledger.capability_key_path().with_name("stamp.pem")


def open_stamp_key(ledger, pinned: str | None = None):
    """Load or create the gateway's stamp key (it signs stamps only). A key that is not the one ``pinned`` in the
    ledger is refused, as a changed capability key is: the tools pin it."""
    path = stamp_key_path(ledger)
    if path.exists():
        _platform.owner_only_dir(path.parent)
        try:
            key = load_private_key_file(path)
        except ValueError as e:
            raise ToolCheckError(f"stamp_key: {e}") from None
    else:
        if pinned:
            raise ToolCheckError("stamp_key_missing: the ledger pins a stamp key and the file is gone; the "
                                 "checking tools would refuse every stamp")
        key = generate_private_key()
        save_private_key(path, key, private_dir=True)
        save_public_key(path.with_name("stamp.pub.pem"), key.public_key())
    if pinned and pinned != key_fingerprint(key.public_key()):
        raise ToolCheckError("stamp_key_changed: the stamp key does not match the fingerprint pinned in the ledger")
    return key


class StampSigner:
    """Signs redeem stamps, and nothing else. The gateway holds one; it cannot sign a token."""

    def __init__(self, private_key, *, clock: Callable[[], float] | None = None):
        self._key = private_key
        self.public_key = private_key.public_key()
        self.fingerprint = key_fingerprint(self.public_key)
        self._clock = clock or time.time

    def stamp(self, token: str, payload: Mapping[str, Any], seq: int) -> str:
        return seal(STAMP_PREFIX, STAMP_LABEL, self._key, {
            "v": 1, "alg": ALG, "jti": payload["jti"], "tool": payload["tool"],
            "tool_args_hash": payload["tool_args_hash"], "token_hash": text_hash(token), "seq": seq,
            "iat": int(self._clock())})


def verify_receipt(receipt: Any, *, pinned: str, jti: str, tool: str, stamp: str, result: str | None) -> dict:
    """The receipt's body when it is signed by the pinned tool key, names this jti, tool and stamp, says the tool
    ran, and covers ``result`` (a :func:`result_hash`). Raises ``ToolCheckError`` with ``missing``,
    ``bad_signature``, ``mismatch`` or ``refused:<reason>``."""
    if receipt is None:
        raise ToolCheckError("missing")
    try:
        body, body_text, signature = peek(RECEIPT_PREFIX, receipt, "receipt")
        public = public_from_raw(body.get("key"))
    except (ToolCheckError, TypeError, ValueError):
        raise ToolCheckError("bad_signature") from None
    if key_fingerprint(public) != pinned or not verify(public, _message(RECEIPT_LABEL, body_text), signature):
        raise ToolCheckError("bad_signature")
    if body.get("jti") != jti or body.get("tool") != tool:
        raise ToolCheckError("mismatch")
    outcome = body.get("outcome")
    if isinstance(outcome, str) and outcome.startswith("refused:"):
        reason = outcome[len("refused:"):]
        raise ToolCheckError("refused:" + (reason if reason in REFUSALS else "other"))
    if outcome != "ran" or body.get("stamp_hash") != text_hash(stamp) or body.get("result_hash") != result:
        raise ToolCheckError("mismatch")
    return body


def mcp_receipt(output: Any) -> tuple[Any, str]:
    """The receipt in an MCP result's ``_meta`` (None when there is none) and the hash of the rest of the result,
    for the gateway's ``receipt_reader``."""
    wire = output.model_dump(mode="json", by_alias=True, exclude_none=True) if hasattr(output, "model_dump") \
        else output
    if not isinstance(wire, Mapping):
        raise ToolCheckError("missing")
    meta = wire.get("_meta")
    mine = meta.get(META_KEY) if isinstance(meta, Mapping) else None
    return (mine.get("receipt") if isinstance(mine, Mapping) else None), result_hash(wire)


# --------------------------------------------------------------------------------------------- the tool's side

def new_tool_key(path: Path | str) -> str:
    """Make a tool key, owner-only, never over an existing file; return the fingerprint for ``tool_check.key``."""
    key = generate_private_key()
    save_private_key(path, key)
    return key_fingerprint(key.public_key())


class SeenRecord:
    """The jtis this tool has accepted, in a SQLite file only its owner can read. Adding a jti is one atomic
    step; a jti already there is refused. Entries go once their token can no longer be valid."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        if not self.path.exists():
            try:
                os.close(_platform.create_new(self.path))
            except FileExistsError:      # another copy of the tool made it first
                pass
        fd = _platform.open_nofollow(self.path)
        try:
            problem = _platform.access_problem(fd)
        finally:
            os.close(fd)
        if problem:
            raise ToolCheckError(f"seen record {self.path}: {problem}")
        db = self._connect()
        try:
            db.execute("CREATE TABLE IF NOT EXISTS seen (jti TEXT PRIMARY KEY, until REAL NOT NULL)")
        finally:
            db.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10, isolation_level=None)

    def add(self, jti: str, until: float, now: float) -> bool:
        """Record ``jti`` until ``until``; False when it was already there. Prunes what has expired."""
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM seen WHERE until < ?", (now,))
            try:
                db.execute("INSERT INTO seen (jti, until) VALUES (?, ?)", (jti, until))
            except sqlite3.IntegrityError:
                db.execute("ROLLBACK")
                return False
            db.execute("COMMIT")
            return True
        finally:
            db.close()


@dataclass(frozen=True)
class ToolCheckConfig:
    """What a checking tool needs: its signed tool id, Two-Key's two public keys (pinned by fingerprint), its own
    private key, and where its seen record lives."""
    tool: str
    capability_key: Any
    stamp_key: Any
    tool_key: Any
    seen_record: Path

    @classmethod
    def load(cls, path: Path | str) -> "ToolCheckConfig":
        """Read a JSON config (docs/TOOL_CHECK.md). Each public key must have its pinned fingerprint."""
        path = Path(path)
        data = loads_json(path.read_bytes())
        keys = ("tool", "capability_public_key", "capability_key_fingerprint", "stamp_public_key",
                "stamp_key_fingerprint", "tool_private_key", "seen_record")
        if not isinstance(data, dict) or set(data) != set(keys) or not all(isinstance(data[k], str) for k in keys):
            raise ToolCheckError(f"{path}: expected exactly the string keys {list(keys)}")

        def where(name: str) -> Path:
            p = Path(data[name]).expanduser()
            return p if p.is_absolute() else path.parent / p
        pinned = []
        for name in ("capability", "stamp"):
            public = load_public_key(where(f"{name}_public_key"))
            if key_fingerprint(public) != data[f"{name}_key_fingerprint"]:
                raise ToolCheckError(f"{path}: {name}_public_key does not have the pinned fingerprint")
            pinned.append(public)
        return cls(data["tool"], pinned[0], pinned[1], load_private_key_file(where("tool_private_key")),
                   where("seen_record"))


@dataclass(frozen=True)
class CheckedCall:
    jti: str
    tool: str
    stamp_hash: str


def _mine(meta: Any) -> Mapping | None:
    """Two-Key's entry in a request's ``_meta``: a mapping, or an MCP SDK model of one."""
    if hasattr(meta, "model_dump"):
        meta = meta.model_dump(mode="json", by_alias=True, exclude_none=True)
    mine = meta.get(META_KEY) if isinstance(meta, Mapping) else None
    return mine if isinstance(mine, Mapping) else None


def _token_payload(public, token: str) -> dict:
    """The payload of a ``tk1`` token signed by ``public``; the times are checked by the caller."""
    if not isinstance(token, str) or len(token) > MAX_OBJECT_CHARS * 4 or token.count(".") != 2 or not token.startswith("tk1."):
        raise ToolCheckError("token_invalid")
    _, body, signature = token.split(".")
    if not verify(public, body.encode("ascii"), signature):
        raise ToolCheckError("token_invalid")
    try:
        payload = loads_json(_b64u_dec(body))
    except ValueError:
        raise ToolCheckError("token_invalid") from None
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise ToolCheckError("token_invalid")
    return payload


class ToolChecker:
    """The checks a tool runs before its own code, and the receipt it signs after (docs/TOOL_CHECK.md)."""

    def __init__(self, config: ToolCheckConfig, *, clock: Callable[[], float] | None = None):
        self.config = config
        self.public_raw = public_raw(config.tool_key.public_key())
        self._clock = clock or time.time
        self._seen = SeenRecord(config.seen_record)

    def check(self, arguments: Any, meta: Any) -> CheckedCall:
        """Checks 1 to 8, in order; raises ``ToolCheckError`` at the first that fails. Any other error inside
        the helper is ``check_failed``: never a pass."""
        try:
            return self._check(arguments, meta)
        except ToolCheckError:
            raise
        except Exception:
            raise ToolCheckError("check_failed") from None

    def _check(self, arguments: Any, meta: Any) -> CheckedCall:
        mine = _mine(meta) or {}
        token, stamp = mine.get("token"), mine.get("stamp")
        if not isinstance(token, str) or not isinstance(stamp, str):
            raise ToolCheckError("check_missing")                                        # 1
        stamped = open_sealed(STAMP_PREFIX, STAMP_LABEL, self.config.stamp_key, stamp, "stamp")    # 2
        payload = _token_payload(self.config.capability_key, token)                     # 3
        if stamped.get("token_hash") != text_hash(token) or stamped.get("jti") != payload.get("jti") \
                or stamped.get("tool") != payload.get("tool"):
            raise ToolCheckError("stamp_mismatch")                                       # 4
        if payload.get("tool") != self.config.tool:
            raise ToolCheckError("tool_mismatch")                                        # 5
        try:
            received = tool_args_hash(arguments)
        except (EncodingError, TypeError, ValueError):
            raise ToolCheckError("args_mismatch") from None
        if not received == payload.get("tool_args_hash") == stamped.get("tool_args_hash"):
            raise ToolCheckError("args_mismatch")                                        # 6
        now = self._clock()
        exp, iat = payload.get("exp"), payload.get("iat")
        if not all(isinstance(t, (int, float)) and not isinstance(t, bool) and math.isfinite(t) for t in (exp, iat)) \
                or exp - iat > MAX_TTL_SECONDS or now > exp + CLOCK_ALLOWANCE_SECONDS \
                or iat > now + CLOCK_ALLOWANCE_SECONDS:
            raise ToolCheckError("expired")                                              # 7
        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti or not self._seen.add(jti, exp + CLOCK_ALLOWANCE_SECONDS, now):
            raise ToolCheckError("replayed")                                             # 8
        return CheckedCall(jti, self.config.tool, text_hash(stamp))

    def receipt(self, call: CheckedCall, result: Mapping[str, Any]) -> str:
        """The receipt for a call that ran: over the jti, the stamp and the result (MCP wire form)."""
        return self._sign(call.jti, call.stamp_hash, result_hash(result), "ran")

    def refusal(self, reason: str, meta: Any) -> str:
        """The receipt for a refused call: the tool did not run. Names the jti when the token could be read."""
        mine = _mine(meta)
        jti, stamp_hash = None, None
        if mine is not None:
            try:
                jti = _token_payload(self.config.capability_key, mine.get("token")).get("jti")
            except Exception:
                jti = None
            if isinstance(mine.get("stamp"), str) and len(mine["stamp"]) <= MAX_OBJECT_CHARS:
                stamp_hash = text_hash(mine["stamp"]) if mine["stamp"].isascii() else None
        return self._sign(jti if isinstance(jti, str) else None, stamp_hash, None, f"refused:{reason}")

    def _sign(self, jti, stamp_hash, result, outcome: str) -> str:
        return seal(RECEIPT_PREFIX, RECEIPT_LABEL, self.config.tool_key, {
            "v": 1, "alg": ALG, "key": self.public_raw, "jti": jti, "tool": self.config.tool,
            "stamp_hash": stamp_hash, "result_hash": result, "outcome": outcome, "iat": int(self._clock())})

    async def mcp_call(self, arguments: Any, meta: Any, run: Callable[[Any], Awaitable[Any]]) -> Any:
        """For an MCP server on the Python SDK: check, then ``await run(arguments)`` (an MCP ``CallToolResult``),
        and return that result with the receipt in its ``_meta``. A refused call returns an error result with a
        refusal receipt, and ``run`` is never called."""
        import mcp_types as types      # the server already depends on the MCP SDK
        try:
            call = self.check(arguments, meta)
        except ToolCheckError as e:
            text = f"two-key tool check refused this call: {e.reason}"
            return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True,
                                        _meta={META_KEY: {"receipt": self.refusal(e.reason, meta)}})
        result = await run(arguments)
        wire = result.model_dump(mode="json", by_alias=True, exclude_none=True)
        meta_out = dict(wire.get("_meta") or {})
        meta_out[META_KEY] = {"receipt": self.receipt(call, wire)}
        return result.model_copy(update={"meta": meta_out})


__all__ = ["CLOCK_ALLOWANCE_SECONDS", "EXEMPT", "META_KEY", "CheckedCall", "SeenRecord", "StampSigner",
           "ToolCheckConfig", "ToolCheckError", "ToolChecker", "checked", "key_fingerprint", "mcp_receipt", "new_tool_key",
           "open_stamp_key", "result_hash", "stamp_key_path", "text_hash", "tool_args_hash", "verify_receipt"]
