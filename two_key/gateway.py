"""Redeem a capability token. It never scans: a scanned tool's token carries the verdict and each file's digest
(scan.py), and the gateway checks the files again just before the tool runs (``file_changed``).

The gateway keeps a ``CapabilityVerifier``. It does not keep the minting
key. It refuses a verifier whose key is the principal key, and it redeems a
token only if the verifier's key fingerprint is the one pinned in the
ledger's ``constitution_loaded`` entry (``capability_key_mismatch``). A redemption intent is checkpointed before the tool runs. A later
retry of that intent does not run the tool. A tool exception appends an
abort and leaves the token usable. A crash after a successful return
cannot run the token again, because the intent is already on the ledger.
The gateway runs in the ``TwoKey`` process, on the ledger object that ``TwoKey`` uses
(``TwoKey.gateway()``). A gateway in another process or on another host is not supported (#45): a
``Ledger`` opened elsewhere does not see tokens issued after it opened, and it holds the principal,
witness, and ledger keys anyway. Built on a ledger no ``TwoKey`` in this process opened, the gateway
emits ``TwoKeyDeploymentWarning`` once per process. The verifier holding only the capability public key
is an API property, not process isolation: the registered tools run in this process too.
A refusal of an authenticated token is ledgered as ``gateway_denied`` (reason,
jti, tool, argument size and digest) at most once per jti after a successful append:
the jti is recorded only after ``append_bounded`` + ``checkpoint`` succeed, so a
failed ledger write can be retried on a later deny. Concurrent same-jti denies are
single-flight under ``_denied_jtis_guard`` so only one ``gateway_denied`` append runs
at a time; waiters re-check and skip if already marked. Waiters use a timed
``Condition.wait`` (``_DENY_INFLIGHT_WAIT_SECONDS``, default 30s; configurable via
``deny_inflight_wait_seconds``, which must be finite and positive — ``inf``/``nan``
fall back to 30s): on timeout they still deny fail-closed without marking and
without fail-open, so a stuck ``append_bounded`` cannot hang waiters forever. The in-memory set is LRU-capped (``_MAX_DENIED_JTIS``, clamped to at least 1).
Further denies for a remembered jti still refuse but do not append. A token that does
not verify writes nothing.
"""

from __future__ import annotations

from collections import OrderedDict
import math
import os
import sys
import threading
import warnings
from dataclasses import dataclass
from typing import Any, Callable

from . import _platform
from .capability import (DEFAULT_MAX_TTL_SECONDS, CapabilityIssuer, CapabilityVerifier, TokenError, _raw,
                         capability_key_fingerprint)
from .agent_meta import cap_ledger_text, type_tag
from .action import MAX_TOOL_NAME_CHARS, TOOL_NAME
from .canonical import MAX_INPUT_DEPTH, EncodingError, OversizeError, canonical_bytes, digest_hex, to_plain
from .derive import (MAX_ARGS_BYTES, DeriveError, args_too_large, blocked_from_rules, caller_fields, canonical_too_large,
                     derive, dropped_keys, form_for, forms_match, project_arguments, size_record)
from .ledger import LedgerError
from .scan import VERDICTS


_MAX_REASON_CHARS = 200
_MAX_JTI_CHARS = 64
# Hard cap on remembered denied jtis (LRU via OrderedDict). Cyber #16.
_MAX_DENIED_JTIS = 4096
# Same-jti waiters: max seconds to wait for an in-flight deny append (#25).
_DENY_INFLIGHT_WAIT_SECONDS = 30.0


def _ledger_failed(e: Exception) -> str:
    """The deny reason for a ledger write that failed: the capped LedgerError text, or the type of anything else."""
    return f"ledger_failed:{cap_ledger_text(str(e)) if isinstance(e, LedgerError) else type_tag(e)}"


def _short(value) -> str | None:
    """A jti for the ledger: a short string, else nothing (the token is signed, but keep entries small)."""
    return value if isinstance(value, str) and len(value) <= _MAX_JTI_CHARS else None


class TwoKeyDeploymentWarning(UserWarning):
    """The gateway was given a ledger no ``TwoKey`` in this process opened. A split gateway is unsupported (#45)."""


# Set by TwoKey on the ledger object it uses. A gateway on another object is not the supported deployment.
_TWO_KEY_LEDGER_MARK = "_two_key_bound"
# Set once the warning has been emitted in this process. The lock makes check-and-set one step.
_deployment_warned = threading.Event()
_deployment_warned_guard = threading.Lock()


def mark_two_key_ledger(ledger) -> None:
    """Record that a ``TwoKey`` in this process uses ``ledger``. A double that refuses attributes stays unmarked."""
    try:
        setattr(ledger, _TWO_KEY_LEDGER_MARK, True)
    except (AttributeError, TypeError):
        pass


def _warn_unbound_ledger(ledger) -> None:
    """Warn, at most once per process, when ``ledger`` is not one a ``TwoKey`` here opened."""
    if getattr(ledger, _TWO_KEY_LEDGER_MARK, False) is True:
        return
    with _deployment_warned_guard:
        if _deployment_warned.is_set():
            return
        _deployment_warned.set()
    warnings.warn("ToolGateway was given a ledger that no TwoKey in this process opened. A gateway in "
                  "another process or on another host is not supported (#45); it refuses tokens issued "
                  "after its ledger opened. Build it with TwoKey.gateway().",
                  TwoKeyDeploymentWarning, stacklevel=3)


def reset_deployment_warning() -> None:
    """Let the next unbound ledger warn again. Tests use this to check the warning more than once per process."""
    with _deployment_warned_guard:
        _deployment_warned.clear()


_BOUND_FIELDS = ("jti", "tool", "args_hash", "bytecode_hash", "nl_hash", "ledger_root", "ledger_size")


@dataclass(frozen=True)
class GatewayResult:
    allowed: bool
    reason: str
    output: Any = None


def _as_verifier(issuer) -> CapabilityVerifier:
    """The redeeming object keeps the public key only."""
    if isinstance(issuer, CapabilityIssuer):
        return issuer.verifier()
    if isinstance(issuer, CapabilityVerifier):
        return CapabilityVerifier(issuer.public_key, clock=issuer.clock, max_ttl_seconds=issuer.max_ttl_seconds)
    public = getattr(issuer, "public_key", None)
    if public is None or not hasattr(issuer, "verify"):
        raise TokenError("gateway requires a token verifier")
    return CapabilityVerifier(public, clock=getattr(issuer, "clock", None),
                              max_ttl_seconds=getattr(issuer, "max_ttl_seconds", DEFAULT_MAX_TTL_SECONDS))


class ToolGateway:
    def __init__(self, ledger, issuer, compiled, *, tools: dict[str, Callable] | None = None,
                 max_denied_jtis: int | None = None,
                 deny_inflight_wait_seconds: float | None = None, scanner=None):
        self.ledger = ledger
        _warn_unbound_ledger(ledger)
        self.issuer = _as_verifier(issuer)
        principal = getattr(ledger, "public_key", None)
        if principal is not None and _raw(self.issuer.public_key) == _raw(principal):
            raise TokenError("capability_key_is_principal_key")
        self._fingerprint = capability_key_fingerprint(self.issuer.public_key)
        self.compiled = compiled
        self.tools = tools or {}
        # TwoKey's content scanner, for its configuration only (which tools are scanned, which arguments are
        # files): the gateway never calls it. None when no scanner is configured.
        self.scanner = scanner
        # One in-process lock per jti being redeemed. #42: _lock_refs counts the threads that hold or
        # wait on each lock, under _locks_guard; the entry is removed when the count reaches zero, so the
        # map holds only jtis in flight. No LRU cap: evicting a held lock would split one jti in two.
        self._locks: dict[str, threading.Lock] = {}
        self._lock_refs: dict[str, int] = {}
        self._locks_guard = threading.Lock()
        # After a successful gateway_denied append for a jti, further denies still refuse but
        # do not append. Marked only after append+checkpoint succeed (#16). LRU-capped.
        self._denied_jtis: OrderedDict[str, None] = OrderedDict()
        # Condition: lock + wait/notify for same-jti single-flight (#23).
        self._denied_jtis_guard = threading.Condition()
        self._deny_inflight: set[str] = set()
        # #22: zero/negative would make the LRU pop loop KeyError on an empty map.
        n = int(max_denied_jtis) if max_denied_jtis is not None else _MAX_DENIED_JTIS
        self._max_denied_jtis = max(1, n)
        # #25/#28: timed wait so a hung append cannot block same-jti waiters forever.
        # Require finite positive; inf/nan (and <=0) fall back to the 30s default.
        wait = (_DENY_INFLIGHT_WAIT_SECONDS if deny_inflight_wait_seconds is None
                else float(deny_inflight_wait_seconds))
        self._deny_inflight_wait_seconds = (
            wait if math.isfinite(wait) and wait > 0 else _DENY_INFLIGHT_WAIT_SECONDS
        )

    def invoke(self, token: str, tool: str, arguments: dict, *, facts: dict | None = None) -> GatewayResult:
        """Redeem ``token`` for ``tool(arguments)``.

        ``facts`` are the caller-supplied facts at redemption, for a tool that maps ``source: caller``
        fields. The form is recomputed with them: a fact whose value is not the one the token was issued for,
        or a missing fact, is ``fact_mismatch``. A fact with a ``json_path`` reaches the tool there.

        A token that does not verify (bad signature, expired, malformed) is refused without a
        ledger entry, so an unauthenticated caller cannot write to the ledger. Any later refusal of
        an authenticated token is ledgered as ``gateway_denied`` with the reason, the jti, the tool
        name (only if it is a short identifier), and the size and digest of the arguments, never
        their values.
        """
        try:
            payload = self.issuer.verify(token)
        except TokenError as e:
            return GatewayResult(False, str(e))
        result, encoded = self._invoke_verified(payload, tool, arguments, facts)
        if result.allowed or result.reason.startswith(("ledger_failed:", "tool_error:")):
            return result      # a tool error is already ledgered (redemption_aborted); a ledger failure cannot be
        return self._record_deny(result, payload, tool, encoded)

    def _record_deny(self, result: GatewayResult, payload: dict, tool, encoded: dict) -> GatewayResult:
        jti = _short(payload.get("jti"))
        if jti is not None:
            with self._denied_jtis_guard:
                # #23/#25: wait (timed) for an in-flight same-jti deny; then skip if marked.
                while jti in self._deny_inflight:
                    notified = self._denied_jtis_guard.wait(timeout=self._deny_inflight_wait_seconds)
                    if not notified and jti in self._deny_inflight:
                        # Append still stuck: fail-closed deny; do not mark; do not fail-open.
                        return result
                if jti in self._denied_jtis:
                    self._denied_jtis.move_to_end(jti)
                    return result      # still deny; do not append another gateway_denied for this jti
                self._deny_inflight.add(jti)
                # Do not mark yet — only after a successful append (#16).
        try:
            body = {"reason": result.reason[:_MAX_REASON_CHARS], "jti": jti}
            if isinstance(tool, str) and len(tool) <= MAX_TOOL_NAME_CHARS and TOOL_NAME.fullmatch(tool):
                body["tool"] = tool
            else:
                body.update({"tool": None, **size_record(tool, "tool")})
            frozen = encoded.get("frozen")
            if frozen is not None:
                body.update({"tool_args_size": len(frozen), "tool_args_digest": "sha256:" + digest_hex(frozen),
                             "tool_args_omitted": True})
            elif "plain" in encoded:     # copied, but not encodable (NaN, for example): measured from the copy
                body.update(size_record(encoded["plain"], "tool_args"))
            else:                        # not copied (too deep, too many items, an unsupported type): not measured
                body.update({"tool_args_size": -1, "tool_args_digest": None, "tool_args_omitted": True})
            try:
                self.ledger.append_bounded("gateway_denied", body)
                self.ledger.checkpoint()
            except Exception as e:  # still a deny; do not mark jti, so a later deny can retry ledgering
                print(f"two-key: could not record gateway deny {result.reason[:_MAX_REASON_CHARS]!r}: "
                      f"{type_tag(e)}"[:500], file=sys.stderr)
                return GatewayResult(False, _ledger_failed(e), result.output)
            if jti is not None:
                with self._denied_jtis_guard:
                    if jti in self._denied_jtis:
                        self._denied_jtis.move_to_end(jti)
                    else:
                        while len(self._denied_jtis) >= self._max_denied_jtis:
                            self._denied_jtis.popitem(last=False)  # drop oldest
                        self._denied_jtis[jti] = None
            return result
        finally:
            if jti is not None:
                with self._denied_jtis_guard:
                    self._deny_inflight.discard(jti)
                    self._denied_jtis_guard.notify_all()

    def _invoke_verified(self, payload: dict, tool: str, arguments: dict,
                         facts: dict | None = None) -> tuple[GatewayResult, dict]:
        """Run the checks and the tool; also return the plain copy and encoded bytes, as far as they got."""
        encoded: dict = {}
        result = self._redeem(payload, tool, arguments, encoded, facts)
        return result, encoded

    @staticmethod
    def _facts_changed(spec, signed_form, fresh_form) -> bool:
        """True when a caller-supplied field's value is not the one the token's form holds (type-exact)."""
        signed_fields, fresh_fields = signed_form.get("fields") or {}, fresh_form.get("fields") or {}
        try:
            return any(canonical_bytes(signed_fields.get(n)) != canonical_bytes(fresh_fields.get(n))
                       for n in caller_fields(spec))
        except (TypeError, ValueError, EncodingError):
            return True

    def _redeem(self, payload: dict, tool: str, arguments: dict, encoded: dict,
                facts: dict | None = None) -> GatewayResult:
        if any(name not in payload for name in _BOUND_FIELDS):
            return GatewayResult(False, "malformed_token")  # a signed token without a binding field
        # Copied once into built-in types (any Mapping becomes a dict); every check, the hash, and the
        # tool read the copy. Encoded before the size check, so nesting too deep is invalid_call on every
        # Python version. Encoded once: the same bytes give the hash and settle the size cap.
        try:
            arguments = to_plain(arguments, max_depth=MAX_INPUT_DEPTH, what="tool args are",
                                 max_items=MAX_ARGS_BYTES // 2)
        except OversizeError:
            return GatewayResult(False, "args_too_large")
        except EncodingError as e:
            return GatewayResult(False, f"invalid_call:{cap_ledger_text(str(e))}")
        encoded["plain"] = arguments
        try:
            frozen = canonical_bytes(arguments, max_depth=MAX_INPUT_DEPTH, what="tool args are")
        except EncodingError as e:   # nested too deeply, NaN, or a non-string key; the same reason as authorize
            return GatewayResult(False, f"invalid_call:{cap_ledger_text(str(e))}")
        encoded["frozen"] = frozen
        hashed = digest_hex(frozen)
        if canonical_too_large(frozen, arguments):
            return GatewayResult(False, "args_too_large")  # before deriving or ledgering
        if payload["tool"] != tool:
            return GatewayResult(False, "tool_mismatch")
        if payload["args_hash"] != hashed:
            return GatewayResult(False, "args_mismatch")
        if payload["bytecode_hash"] != self.compiled.bytecode_hash or payload["nl_hash"] != self.compiled.nl_hash:
            return GatewayResult(False, "constitution_mismatch")
        if payload.get("spec_hash", "") != self.compiled.spec_hash:
            return GatewayResult(False, "constitution_mismatch")
        if not self.compiled.specs_enforced:
            return GatewayResult(False, "tool_specs_required")
        spec = self.compiled.tool_specs.get(tool)
        if spec is None:
            return GatewayResult(False, "tool_specs_required")
        if "form" not in payload or "claimed_data_class" not in payload:
            return GatewayResult(False, "derived_mismatch")
        has_facts = bool(caller_fields(spec))
        if facts is not None:
            try:      # copied once, under the same caps as the arguments
                facts = to_plain(facts, max_depth=MAX_INPUT_DEPTH, what="facts are", max_items=MAX_ARGS_BYTES // 2)
            except (OversizeError, EncodingError):
                return GatewayResult(False, "fact_mismatch" if has_facts else "derived_mismatch")
            if args_too_large(facts):
                return GatewayResult(False, "fact_mismatch" if has_facts else "derived_mismatch")
        scan = None
        if self.scanner is not None and self.scanner.scans(spec):
            # No second scan: the verdict is the one the token binds. Supplied any other way, it is refused.
            scan = payload.get("scan")
            if (not isinstance(scan, dict) or scan.get("verdict") not in VERDICTS
                    or not isinstance(scan.get("files"), list)):
                return GatewayResult(False, "scan_mismatch")
            if facts is not None and (not isinstance(facts, dict) or self.scanner.field in facts):
                return GatewayResult(False, "fact_mismatch")
            facts = {**(facts or {}), self.scanner.field: scan["verdict"]}
        elif "scan" in payload:
            return GatewayResult(False, "scan_mismatch")
        try:
            derived = derive(spec, arguments, self.compiled.fields, facts)
            fresh = form_for(derived, payload["claimed_data_class"],
                             blocked_from_rules(self.compiled.rules))
        except DeriveError as e:
            fact_error = e.reason.startswith(("fact", "caller_field")) or any(
                e.reason.endswith(f":{n}") for n in caller_fields(spec))
            return GatewayResult(False, "fact_mismatch" if fact_error and has_facts else "derived_mismatch")
        if not forms_match(payload["form"], fresh):
            if has_facts and isinstance(payload["form"], dict) and self._facts_changed(spec, payload["form"], fresh):
                return GatewayResult(False, "fact_mismatch")
            return GatewayResult(False, "derived_mismatch")
        size = payload["ledger_size"]
        if not isinstance(size, int) or size < 0 or size > self.ledger.size():
            return GatewayResult(False, "ledger_size_invalid")
        if self.ledger.merkle_root(size) != payload["ledger_root"]:
            return GatewayResult(False, "ledger_root_mismatch")
        if self._pinned_at(size) != self._fingerprint:
            return GatewayResult(False, "capability_key_mismatch")
        if self.ledger.kinds_after(size, {"constitution_loaded", "revocation"}):
            return GatewayResult(False, "revoked_or_reloaded")
        fn = self.tools.get(tool)
        if fn is None:
            return GatewayResult(False, "tool_not_registered")
        with self._hold(payload["jti"]):
            if self.ledger.is_redeemed(payload["jti"]):
                return GatewayResult(False, "already_redeemed")
            if self.ledger.redemption_started(payload["jti"]):
                return GatewayResult(False, "already_attempted")
            # Last, just before the tool runs: each declared file is the one that was scanned.
            if scan is not None:
                try:
                    same = self.scanner.file_digests(tool, arguments) == scan["files"]
                except Exception:       # could not read them again: not the files that were scanned
                    same = False
                if not same:
                    return GatewayResult(False, "file_changed")
            try:
                self.ledger.append_bounded("redemption_started", {"jti": payload["jti"], "tool": tool,
                                                                  "dropped_keys": dropped_keys(spec, arguments)})
                self.ledger.checkpoint()
            except Exception as e:      # not only LedgerError: an OSError (disk full) must not escape invoke (#60)
                return GatewayResult(False, _ledger_failed(e))
            try:
                output = fn(project_arguments(spec, arguments, dict(derived.fields)))
            except Exception as e:
                try:
                    self.ledger.append_bounded("redemption_aborted", {"jti": payload["jti"], "tool": tool})
                    self.ledger.checkpoint()
                except Exception as le:
                    return GatewayResult(False, _ledger_failed(le))
                return GatewayResult(False, f"tool_error:{type_tag(e)}", None)
            try:
                self.ledger.append_bounded("redemption", {"jti": payload["jti"], "tool": tool})
                self.ledger.checkpoint()
            except Exception as e:
                return GatewayResult(False, _ledger_failed(e), output)
        return GatewayResult(True, "redeemed", output)

    def _pinned_at(self, size: int) -> str | None:
        """The capability key fingerprint in the last ``constitution_loaded`` entry before ``size``."""
        entry = self.ledger.last_before(size, "constitution_loaded")
        if entry is None:
            return None
        return entry.body.get("capability_key_fingerprint")

    def _unref(self, jti: str) -> None:
        """Drop one holder of ``jti``'s lock; remove the entry when none is left (#42)."""
        with self._locks_guard:
            n = self._lock_refs[jti] - 1
            if n:
                self._lock_refs[jti] = n
            else:
                del self._lock_refs[jti]
                del self._locks[jti]

    def _hold(self, jti: str):
        gateway = self
        class _Hold:
            def __enter__(self):
                with gateway._locks_guard:
                    self.lock = gateway._locks.setdefault(jti, threading.Lock())
                    gateway._lock_refs[jti] = gateway._lock_refs.get(jti, 0) + 1
                try:
                    self.lock.acquire()
                except BaseException:
                    gateway._unref(jti)
                    raise
                self.fd = None
                try:
                    path = gateway.ledger.redeem_lock_path(jti)
                    self.fd = _platform.open_lock_file(path)
                    _platform.lock(self.fd)
                    return self
                except BaseException:
                    if self.fd is not None:
                        os.close(self.fd)
                    self.lock.release()
                    gateway._unref(jti)
                    raise

            def __exit__(self, *exc):
                try:
                    if self.fd is not None:
                        try:
                            _platform.unlock(self.fd)
                        finally:
                            os.close(self.fd)
                finally:
                    self.lock.release()
                    gateway._unref(jti)
        return _Hold()
