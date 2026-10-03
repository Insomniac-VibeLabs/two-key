"""
Two-Key: tool gateway
============================
The only component allowed to cause side effects (spec 5.1 item 7). Before
any tool runs, it checks everything spec 5.5 lists, plus single-use:

  1. valid signature           -> bad_signature / malformed_token
  2. not expired               -> expired
  3. principal matches         -> wrong_principal
  4. tool matches the call     -> tool_mismatch
  5. literal args match        -> args_mismatch     (reference binding: args_hash)
     The call is serialized once (two-key-enc/2, canonical.freeze_call) into
     immutable bytes. Those bytes are hashed for this check, scanned, and
     decoded for execution, so the tool runs exactly what was checked
     (F_REVIEW finding 1). A token without ``args_enc`` is refused
     (unsupported_args_encoding).
  6. amount within scope       -> amount_exceeds_scope
  7. counterparty matches      -> counterparty_mismatch
  8. data class matches        -> data_class_mismatch
  9. ledger_root (chain digest) is a known entry -> unknown_ledger_root
     (checked after 10a)
 10. ledger-root binding, PRIOR_ART.md §4 (i), selected by the author on
     2026-09-30 (CONCEPTION_NOTES.md Entry 2):
     a. the gateway keeps its own last-known view (size, Merkle root) of the
        principal's ledger and checks on every call that the ledger still
        contains it (same root at that size)
                               -> ledger_fork_detected
        With ``view_refresh="every_call"`` it also advances the view to the
        current ledger on every call, by RFC 9162 consistency proof.
     b. the token's root R (ledger_size, ledger_merkle_root) equals the view
        or is proven an ancestor of it by a consistency proof. If R is newer
        than the view (the usual case: a token issued since the last call),
        a consistency proof must show that the view is an ancestor of R; R, which the
        issuer authenticated inside the token, then becomes the new view. One proof
        per call either way.
                               -> token_missing_ledger_binding / ledger_root_not_ancestor
     c. H(bytecode), H(NL constitution), and the constitution digest in the
        token equal those in the latest constitution_loaded entry
                               -> constitution_hash_mismatch
     d. no constitution reload or revocation entry after issuance
                               -> constitution_changed_since_issue / revoked
     e. the token's own capability_issued entry exists and matches
                               -> capability_not_recorded
 11. single use (jti)          -> replayed
     The used-token record lives in the ledger (``PersonalLedger.redeem``),
     not in the gateway, so every gateway on one TwoKey instance shares it:
     a token is accepted once no matter how many gateways or threads try.
     Checks 9-11 and the redemption run under the ledger's lock. Across
     processes on POSIX, every append and checkpoint holds an ``flock`` on
     ``<ledger-directory>.lock``, beside the ledger directory. A write that
     finds another writer has changed the ledger file is refused:
     ``replayed`` if that writer redeemed this token, otherwise
     ``already_attempted`` or ``ledger_concurrent_writer``. The refusal is
     not written to this (now stale) ledger instance, because appending
     would fork the chain.

Optional content scanning (scanning.py; CONCEPTION_NOTES.md Entries 5-7):
only when ``scanners`` are configured, after checks 1-8 pass the gateway
takes ONE snapshot of the arguments (their canonical encoding), hashes it for
check 5, sends it (plus any file parts from ``file_extractors``, and the
decoded strings) to the scanners, and executes the tool on that same
snapshot, so the scanned bytes, the hashed bytes, and the executed arguments
are the same. Any conviction denies (Entries 6 and 7): a scanner can only add
a deny. Deny reasons: scan_blocked:<id>, scan_quarantined:<id>,
scan_error:<id> / scan_timeout:<id> (errors are treated like timeouts;
both deny unless ScanSettings.on_timeout is "allow"), scan_data_class_mismatch
(a DLP data class other than the token's). Each verdict (scanner id/version,
digest of the scanned bytes, outcome) is recorded in the capability_redeemed
or gateway_denied entry, and each scanner error or timeout also in
``scan_errors`` with its type and the action taken.

Inbound (Entry 7: "before files are received or processed"): what the tool
returns is scanned with the same scanners and rules before the agent gets it
(part ``result``, any ``result_file_extractors`` files, and the decoded
strings). If the scan denies, the result is withheld: GatewayResult(False,
"result_withheld:<reason>"). The tool has already run; its tool_executed
entry records the result scans. ``scan_inbound()`` scans content that
arrives outside a tool call (content_scan_inbound entries). Post-send
verdicts (a non-default async mode) arrive later as content_scan_async
entries. With no scanners the gateway does not scan. The call is still
one snapshot: the same bytes are hashed and executed.

On success the gateway first checkpoints ``redemption_started``, then runs
the tool, then logs ``capability_redeemed``. A crash after the intent does
not run the tool again (``already_attempted``). A tool exception logs
``redemption_aborted`` and ``tool_error`` and leaves the token usable.
The tool error is not allowed. A tool with no registered executor does not
spend the token (``tool_not_registered``).
``tool_executed`` stores a hash of the result (the result itself is not stored)
and links to the token's capability_issued entry. Scanning, when configured,
still runs on the frozen argument bytes before the intent, and on the tool
result before the caller receives it.

Call fields (amount, counterparty, data class) come from ``call_fields``
supplied by the caller or from a per-tool extractor. Who derives these fields
is an OPEN DESIGN QUESTION (DESIGN_OPTIONS.md section 1). This gateway only
provides the hook and does not choose. For counterparty and data class it
requires exact equality with the token scope. That is stricter than spec
5.5's "matches if present"; see DESIGN_OPTIONS.md section 3.

Every outcome is written to the ledger. A token is marked redeemed before the
tool executes, so a failing tool cannot be retried with the same token.

Hot path: no network I/O, no key parsing (the issuer caches its MAC key
schedule / parsed verify key). By default one ledger checkpoint (signed head)
per call; ``checkpoint_every=N`` signs after every N calls, and 0 leaves
checkpointing to the caller (e.g. a timer calling ``ledger.checkpoint()``).
Entries not yet covered by a signed head show up as ``size_mismatch`` in
``ledger.verify`` until the next checkpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence

from . import merkle
from .action import ActionValidationError, normalize_action
from .scope import disagreement
from .canonical import (DOMAIN_TOOL_RESULT, ENCODING, canonical_hash, freeze_call, typed_bytes, typed_hash,
                        typed_loads)
from .capability import CapabilityIssuer, TokenError, token_digest
from .ledger import LedgerError, PersonalLedger
from .scanning import AsyncCallbackScanner, ContentScanner, ScanEngine, ScanSettings, ScanVerdict

Extractor = Callable[[Mapping[str, Any]], Mapping[str, Any]]
# File parts for content scanning: fn(args) -> iterable of (name, bytes, content_type).
FileExtractor = Callable[[Mapping[str, Any]], Iterable[tuple[str, bytes, str]]]
# Inbound file parts: fn(tool result) -> iterable of (name, bytes, content_type).
ResultFileExtractor = Callable[[Any], Iterable[tuple[str, bytes, str]]]
CALL_FIELDS = ("amount_usd", "counterparty", "data_class")


@dataclass(frozen=True)
class GatewayResult:
    allowed: bool
    reason: str
    result: Any = None


@dataclass(frozen=True)
class InboundScanResult:
    """``scan_inbound``: may the agent receive or process this content?"""
    allowed: bool
    reason: str
    verdicts: tuple = ()


class ToolGateway:
    def __init__(self, issuer: CapabilityIssuer, ledger: PersonalLedger, principal: str,
                 tools: Mapping[str, Callable[..., Any]] | None = None,
                 extractors: Mapping[str, Extractor] | None = None, *, digest_alg: str | None = None,
                 checkpoint_every: int = 1, view_refresh: str = "token",
                 scanners: Sequence[ContentScanner] | None = None, scan_settings: ScanSettings | None = None,
                 file_extractors: Mapping[str, FileExtractor] | None = None,
                 result_file_extractors: Mapping[str, ResultFileExtractor] | None = None):
        self.issuer, self.ledger, self.principal = issuer, ledger, principal
        self.digest_alg = digest_alg or ledger.digest_alg  # follow the ledger (SHA-384 by default)
        if not isinstance(checkpoint_every, int) or isinstance(checkpoint_every, bool) or checkpoint_every < 0:
            raise ValueError("checkpoint_every must be an integer >= 0")
        self.checkpoint_every = checkpoint_every
        self._calls_since_checkpoint = 0
        self.checkpoint_error: str | None = None
        self.tools = dict(tools or {})
        self.extractors = dict(extractors or {})
        # Single use is tracked by the ledger (ledger.redeem), shared by every gateway on it and rebuilt
        # from the ledger's capability_redeemed entries on load, so replay protection survives restarts.
        # Last-known ledger view (§4 (i)): (size, Merkle root). Taken from the ledger at construction;
        # Two-Key has verified the ledger against the principal's signed head by then. The view
        # only ever moves forward along a verified consistency proof.
        if view_refresh not in ("token", "every_call"):
            raise ValueError("view_refresh must be 'token' or 'every_call'")
        self.view_refresh = view_refresh
        self._view_size = ledger.size
        self._view_root = ledger.root_bytes(self._view_size)
        # Optional content scanning (scanning.py). None: no scanning, and _invoke takes the original path.
        self.scan_engine = ScanEngine(scanners, scan_settings) if scanners else None
        self.file_extractors = dict(file_extractors or {})
        self.result_file_extractors = dict(result_file_extractors or {})
        self.async_scan_errors: list[str] = []
        if self.scan_engine is not None:
            for sc in self.scan_engine.scanners:
                if isinstance(sc, AsyncCallbackScanner):
                    sc.subscribe(self._on_async_verdict)

    @property
    def view(self) -> tuple[int, str]:
        return self._view_size, self._view_root.hex()

    def _view_intact(self) -> bool:
        """The ledger still contains the view: same root at the view size (no rewrite or truncation)."""
        return self.ledger.size >= self._view_size and \
            self.ledger.root_bytes(self._view_size) == self._view_root  # memoized in the tree: O(1) typically

    def refresh_view(self) -> bool:
        """Advance the view to the current ledger, if and only if a consistency proof shows it extends it."""
        n = self.ledger.size
        if not self._view_intact():
            return False
        if n == self._view_size:
            return True
        new_root = self.ledger.root_bytes(n)
        if self._view_size and not merkle.verify_consistency(
                self._view_size, n, self._view_root, new_root,
                self.ledger.consistency_path(self._view_size, n), self.ledger.hash_fn()):
            return False
        self._view_size, self._view_root = n, new_root
        return True

    def _check_ledger_binding(self, p: dict) -> tuple[str | None, Any]:
        """PRIOR_ART.md §4 (i) checks b-e. Returns (deny reason or None, capability_issued entry)."""
        size, root_hex = p.get("ledger_size"), p.get("ledger_merkle_root")
        if isinstance(size, bool) or not isinstance(size, int) or not isinstance(root_hex, str) \
                or not p.get("bytecode_hash") or not p.get("nl_hash"):
            return "token_missing_ledger_binding", None
        try:
            token_root = bytes.fromhex(root_hex)
        except ValueError:
            return "token_missing_ledger_binding", None
        led, v_size, v_root = self.ledger, self._view_size, self._view_root
        if not 0 < size <= led.size:
            return "ledger_root_not_ancestor", None
        h = led.hash_fn()
        if size == v_size:        # R is the last-known root
            ok = token_root == v_root
        elif size < v_size:       # R must be an ancestor of the last-known root
            ok = merkle.verify_consistency(size, v_size, token_root, v_root, led.consistency_path(size, v_size), h)
        else:                     # R is newer: the view must be an ancestor of R, then R becomes the view
            ok = (merkle.verify_consistency(v_size, size, v_root, token_root, led.consistency_path(v_size, size), h)
                  if v_size else led.root_bytes(size) == token_root)
        # The chain digest in the token must be the last entry covered by R.
        if not ok or led.entries[size - 1].digest != p.get("ledger_root"):
            return ("ledger_root_not_ancestor" if self._view_intact() else "ledger_fork_detected"), None
        if size > v_size:
            led.root_bytes(size)  # warm the tree memo so the next _view_intact() is a lookup
            self._view_size, self._view_root = size, token_root
        loaded = led.latest_constitution()
        if loaded is None or loaded.body.get("bytecode_hash") != p.get("bytecode_hash") \
                or loaded.body.get("nl_hash") != p.get("nl_hash") \
                or loaded.body.get("constitution_digest") != p.get("constitution_digest"):
            return "constitution_hash_mismatch", None
        if loaded.seq >= size:
            return "constitution_changed_since_issue", None
        if led.revocation_for(p.get("jti", ""), size) is not None:
            return "revoked", None
        cap = led.capability_entry(p.get("jti", ""))
        if cap is None or cap.seq != size:
            return "capability_not_recorded", None
        return None, cap

    def _deny(self, reason: str, token: Any, tool: Any, **extra: Any) -> GatewayResult:
        th = token_digest(token, self.digest_alg, self.ledger.crypto) if isinstance(token, str) else None
        self.ledger.append("gateway_denied", {"reason": reason, "token_digest": th, "tool": str(tool), **extra})
        return GatewayResult(False, reason)

    # -- content scanning (scanning.py) -----------------------------------------
    def _scan(self, tool: str, snapshot: bytes, args: Mapping, jti: Any,
              scope_data_class: Any = None) -> list[ScanVerdict]:
        raw = [("call", "application/json", snapshot)]  # exactly the bytes args_hash covers (two-key-enc/2)
        fx = self.file_extractors.get(tool)
        if fx is not None:
            for name, data, ctype in fx(args):
                raw.append((f"file:{name}", ctype, data))
        # Decoded strings (Entry 6, c): every string in the arguments, unescaped (the call part is
        # ASCII-escaped, type-tagged JSON). File parts are already exact bytes. payload_digest covers the exact bytes.
        return self._run_scan("outbound", tool, raw, list(_strings_in(args, "args")), jti, scope_data_class)

    def _run_scan(self, direction: str, tool: str, raw: list, texts: list, jti: Any,
                  scope_data_class: Any) -> list[ScanVerdict]:
        eng = self.scan_engine
        parts = eng.build_parts(raw, self.digest_alg, self.ledger.crypto)
        seen: dict = {}
        for i, (name, text) in enumerate(texts):  # keys containing dots can repeat a path: keep names unique
            seen[name] = seen.get(name, 0) + 1
            if seen[name] > 1:
                texts[i] = (f"{name}#{seen[name]}", text)
        return eng.run(tool, parts, self.digest_alg, self.ledger.crypto,
                       {"gateway": id(self), "jti": jti, "tool": tool, "direction": direction},
                       texts=eng.build_texts(texts, self.digest_alg, self.ledger.crypto),
                       scope_data_class=scope_data_class if isinstance(scope_data_class, str) else None,
                       direction=direction)

    def _scan_record(self, prefix: str, verdicts: list[ScanVerdict], call_data_class: Any) -> dict:
        """Ledger fields: outbound/inbound-file prefix "" (content_scans, scan_policy, scan_data_classes,
        scan_errors); tool results prefix "result_" (result_scans, result_scan_errors, ...)."""
        eng = self.scan_engine
        return {f"{prefix or 'content_'}scans": [v.to_record() for v in verdicts],
                f"{prefix}scan_policy": eng.settings.to_record(),
                f"{prefix}scan_data_classes": eng.data_classes_seen(verdicts, call_data_class),
                f"{prefix}scan_errors": eng.error_records(verdicts)}

    def _inbound_parts(self, tool: str, content: Any, extractor: Any, files: Iterable = ()) -> tuple[list, list]:
        """Exact-byte parts and decoded strings for content coming back to the agent (Entry 7)."""
        if isinstance(content, (bytes, bytearray, memoryview)):
            raw, texts = [("result", "application/octet-stream", bytes(content))], []   # a file: exact bytes
        else:
            try:
                enc = typed_bytes(content, DOMAIN_TOOL_RESULT)   # the bytes H(result) in tool_executed covers
                raw = [("result", "application/json", enc)]
                texts = list(_strings_in(typed_loads(enc, DOMAIN_TOOL_RESULT), "result"))
            except (TypeError, ValueError):
                r = repr(content)
                raw, texts = [("result", "text/plain; charset=utf-8", r.encode("utf-8", "surrogatepass"))], [("result", r)]
        extra = list(files)
        if extractor is not None:
            extra += list(extractor(content))
        for name, data, ctype in extra:
            raw.append((f"file:{name}", ctype, data))
        return raw, texts

    def scan_inbound(self, content: Any, *, source: str, files: Iterable[tuple[str, bytes, str]] = (),
                     data_class: str | None = None) -> InboundScanResult:
        """Scan content before the agent receives or processes it (Entry 7), for content that does not come
        back through ``invoke`` (for example a file arriving by email). ``files`` are (name, bytes,
        content_type). With ``data_class``, every DLP class must be that class. Recorded as a
        content_scan_inbound entry. With no scanners configured: allowed, ``not_scanned``, nothing recorded.
        """
        eng = self.scan_engine
        if eng is None:
            return InboundScanResult(True, "not_scanned")
        src = str(source)[:200]
        try:
            raw, texts = self._inbound_parts("inbound", content, None, files)
            verdicts = self._run_scan("inbound", "inbound", raw, texts, None, data_class)
        except Exception as e:  # noqa: BLE001 - unusable input: refuse it
            why = f"invalid_inbound:{type(e).__name__}"
            self.ledger.append("content_scan_inbound", {"source": src, "decision": why})
            return InboundScanResult(False, why)
        why = eng.decide(verdicts, data_class)
        self.ledger.append("content_scan_inbound", {"source": src, "decision": why or "allowed",
                                                    **self._scan_record("", verdicts, data_class)})
        if self.checkpoint_every == 1:
            self.ledger.checkpoint()
        return InboundScanResult(why is None, why or "allowed", tuple(verdicts))

    def _on_async_verdict(self, context: Mapping[str, Any], verdict: ScanVerdict) -> None:
        """Record a post-send verdict (adapter 5) for a call this gateway scanned."""
        if context.get("gateway") != id(self):
            return
        try:
            self.ledger.append("content_scan_async", {"jti": context.get("jti"), "tool": context.get("tool"),
                                                      "direction": context.get("direction", "outbound"),
                                                      "scan": verdict.to_record()})
            if self.checkpoint_every == 1:
                self.ledger.checkpoint()
        except Exception as e:  # kept on the gateway: the ledger may be stale or closed
            self.async_scan_errors.append(f"{type(e).__name__}: {e}"[:300])

    def _call_fields(self, tool: str, args: Mapping, call_fields: Mapping | None) -> dict:
        extracted = None
        if tool in self.extractors:
            extracted = dict(self.extractors[tool](args))
        if extracted is None and call_fields is None:
            raise ActionValidationError("call_fields required (no extractor registered for this tool)")
        if extracted is not None and call_fields is not None:
            a = normalize_action({"tool": tool, **{k: extracted[k] for k in CALL_FIELDS if k in extracted}})
            b = normalize_action({"tool": tool, **{k: call_fields[k] for k in CALL_FIELDS if k in call_fields}})
            if (a.amount_usd, a.counterparty, a.data_class) != (b.amount_usd, b.counterparty, b.data_class):
                raise ActionValidationError("declared call fields disagree with extractor")
        src = extracted if extracted is not None else dict(call_fields or {})
        unknown = set(src) - set(CALL_FIELDS)
        if unknown:
            raise ActionValidationError(f"unknown call fields {sorted(unknown)}")
        # Missing fields take the conservative defaults (data_class=classified).
        record = normalize_action({"tool": tool, **src}).to_record()
        # Caller-supplied scope cannot be quieter than the frozen arguments.
        mismatch = disagreement(record, args)
        if mismatch:
            raise ActionValidationError(f"call fields disagree with frozen arguments: {mismatch}")
        return record

    def invoke(self, token: Any, tool: str, args: Mapping[str, Any],
               call_fields: Mapping[str, Any] | None = None) -> GatewayResult:
        try:
            return self._invoke(token, tool, args, call_fields)
        finally:
            # Signed head per checkpoint_every calls (no-op if the ledger already signs every append).
            self._calls_since_checkpoint += 1
            if self.checkpoint_every and self._calls_since_checkpoint >= self.checkpoint_every:
                try:
                    self.ledger.checkpoint()
                    self._calls_since_checkpoint = 0
                    self.checkpoint_error = None
                except Exception as e:  # recorded; the next checkpoint covers these entries
                    self.checkpoint_error = f"{type(e).__name__}: {e}"

    def _invoke(self, token: Any, tool: str, args: Mapping[str, Any],
                call_fields: Mapping[str, Any] | None) -> GatewayResult:
        try:
            p = self.issuer.verify(token)
        except TokenError as e:
            return self._deny(e.reason, token, tool)
        eng = self.scan_engine
        try:
            call_tool = normalize_action({"tool": tool}).tool
            # One snapshot on every path (F_REVIEW finding 1): the caller's args are read exactly once,
            # into immutable bytes. Those bytes are hashed (check 5), scanned, and decoded for the
            # extractor and the tool; each gets its own decoded copy, so nothing can change in between.
            frozen = freeze_call(call_tool, args)
            fields = self._call_fields(call_tool, frozen.args(), call_fields)
            call_args_hash = frozen.digest(self.digest_alg, self.ledger.crypto)
        except (ActionValidationError, TypeError, ValueError) as e:
            return self._deny(f"invalid_call:{e}", token, tool)
        if p.get("args_enc") != ENCODING:
            return self._deny("unsupported_args_encoding", token, tool)

        scope = p.get("scope") or {}
        if p.get("principal") != self.principal:
            return self._deny("wrong_principal", token, tool)
        if p.get("tool") != call_tool:
            return self._deny("tool_mismatch", token, tool)
        if p.get("args_hash") != call_args_hash:
            return self._deny("args_mismatch", token, tool)
        if fields["amount_usd"] > float(scope.get("amount_usd", 0.0)):
            return self._deny("amount_exceeds_scope", token, tool)
        if fields["counterparty"] != scope.get("counterparty", ""):
            return self._deny("counterparty_mismatch", token, tool)
        if fields["data_class"] != scope.get("data_class"):
            return self._deny("data_class_mismatch", token, tool)
        jti = p.get("jti")
        scan_rec: dict = {}
        if eng is not None:
            try:
                verdicts = self._scan(call_tool, frozen.data, frozen.args(), jti, scope.get("data_class"))
            except Exception as e:  # noqa: BLE001 - a file extractor failed or returned something unusable
                return self._deny(f"invalid_call:file_extractor:{type(e).__name__}", token, tool)
            scan_rec = self._scan_record("", verdicts, fields["data_class"])
            why = eng.decide(verdicts, scope.get("data_class"), fields["data_class"])
            if why is not None:
                return self._deny(why, token, tool, **scan_rec)
        with self.ledger.lock:  # checks 9-11 and the redemption are atomic w.r.t. other gateways/threads
            # §4 (i): the ledger must still contain the gateway's last-known view.
            intact = self.refresh_view() if self.view_refresh == "every_call" else self._view_intact()
            if not intact:
                return self._deny("ledger_fork_detected", token, tool)
            if self.ledger.index_of(p.get("ledger_root", "")) is None:
                return self._deny("unknown_ledger_root", token, tool)
            reason, cap = self._check_ledger_binding(p)
            if reason is not None:
                return self._deny(reason, token, tool)
            tok_hash = token_digest(token, self.digest_alg, self.ledger.crypto)
            if cap.body.get("token_digest") != tok_hash:
                return self._deny("capability_not_recorded", token, tool)
            if not jti or self.ledger.is_redeemed(jti):
                return self._deny("replayed", token, tool)

            link = {"capability_entry_seq": cap.seq, "capability_entry_digest": cap.digest}
            body = {"token_digest": tok_hash, "tool": call_tool,
                    "args_hash": call_args_hash, "args_enc": ENCODING, **link, **scan_rec}
            fn = self.tools.get(call_tool)
            if fn is None:
                return GatewayResult(False, "tool_not_registered")
            if self.ledger.redemption_started(jti):
                return self._deny("already_attempted", token, tool)
            started, why = self.ledger.begin_attempt(jti, body)
            if started is None:
                if self.ledger._stale:
                    return GatewayResult(False, why)
                if why in ("replayed", "already_attempted"):
                    return self._deny(why, token, tool)
                return GatewayResult(False, why)
        try:
            result = fn(**frozen.args())  # decoded from the same bytes that were hashed and scanned
        except Exception as e:
            try:
                self.ledger.abort_attempt(jti, {"tool": call_tool, "error": type(e).__name__, **link})
                self.ledger.append("tool_error", {"jti": jti, "error": type(e).__name__, **link})
            except LedgerError as le:
                return GatewayResult(False, f"ledger_failed:{le}")
            return GatewayResult(False, f"tool_error:{type(e).__name__}")
        redeemed, why = self.ledger.redeem(jti, body)
        if redeemed is None:
            return GatewayResult(False, why, result)
        executed = {"jti": jti, "tool": call_tool, **link,
                    "result_hash": _result_hash(result, self.digest_alg, self.ledger)}
        if eng is None:
            self.ledger.append("tool_executed", executed)
            return GatewayResult(True, "executed", result)
        # Inbound (Entry 7): scan what the tool returned before the agent receives it.
        try:
            raw, texts = self._inbound_parts(call_tool, result, self.result_file_extractors.get(call_tool))
            rverdicts = self._run_scan("inbound", call_tool, raw, texts, jti, scope.get("data_class"))
        except Exception as e:  # noqa: BLE001 - a result file extractor failed: withhold the result
            why = f"invalid_result:file_extractor:{type(e).__name__}"
            self.ledger.append("tool_executed", {**executed, "result_withheld": why})
            return GatewayResult(False, f"result_withheld:{why}")
        why = eng.decide(rverdicts, scope.get("data_class"))
        self.ledger.append("tool_executed", {**executed, **self._scan_record("result_", rverdicts, None),
                                             "result_withheld": why})
        if why is not None:
            return GatewayResult(False, f"result_withheld:{why}")
        return GatewayResult(True, "executed", result)


def _strings_in(obj: Any, path: str):
    """(path, string) for every string in decoded JSON arguments: values, and keys (path ``<path>.<key>#key``)."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            yield f"{path}.{k}#key", str(k)
            yield from _strings_in(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _strings_in(v, f"{path}[{i}]")


def _result_hash(result: Any, alg: str, ledger: PersonalLedger) -> str:
    """H(two-key-enc/2 of the result), or H(canonical JSON of its repr) for results it can't encode."""
    try:
        return typed_hash(result, DOMAIN_TOOL_RESULT, alg, ledger.crypto)
    except (TypeError, ValueError):
        return canonical_hash({"repr": repr(result)}, alg, ledger.crypto)
