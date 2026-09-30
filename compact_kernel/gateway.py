"""
Compact Kernel: tool gateway
============================
The only component allowed to cause side effects (spec 5.1 item 7). Before
any tool runs, it checks everything spec 5.5 lists, plus single-use:

  1. valid signature           -> bad_signature / malformed_token
  2. not expired               -> expired
  3. principal matches         -> wrong_principal
  4. tool matches the call     -> tool_mismatch
  5. literal args match        -> args_mismatch     (reference binding: args_hash)
  6. amount within scope       -> amount_exceeds_scope
  7. counterparty matches      -> counterparty_mismatch
  8. data class matches        -> data_class_mismatch
  9. ledger_root is the current head or an ancestor, and no constitution was
     loaded after it           -> unknown_ledger_root / constitution_changed_since_issue
 10. single use (jti)          -> replayed

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
from typing import Any, Callable, Mapping

from .action import ActionValidationError, normalize_action
from .capability import CapabilityIssuer, TokenError, args_hash, token_sha256
from .ledger import PersonalLedger

Extractor = Callable[[Mapping[str, Any]], Mapping[str, Any]]
CALL_FIELDS = ("amount_usd", "counterparty", "data_class")


@dataclass(frozen=True)
class GatewayResult:
    allowed: bool
    reason: str
    result: Any = None


class ToolGateway:
    def __init__(self, issuer: CapabilityIssuer, ledger: PersonalLedger, principal: str,
                 tools: Mapping[str, Callable[..., Any]] | None = None,
                 extractors: Mapping[str, Extractor] | None = None, *, digest_alg: str = "sha256",
                 checkpoint_every: int = 1):
        self.issuer, self.ledger, self.principal = issuer, ledger, principal
        self.digest_alg = digest_alg
        if not isinstance(checkpoint_every, int) or isinstance(checkpoint_every, bool) or checkpoint_every < 0:
            raise ValueError("checkpoint_every must be an integer >= 0")
        self.checkpoint_every = checkpoint_every
        self._calls_since_checkpoint = 0
        self.checkpoint_error: str | None = None
        self.tools = dict(tools or {})
        self.extractors = dict(extractors or {})
        # Rebuild the single-use set from the ledger so replay protection survives restarts.
        self._redeemed = {e.body.get("jti") for e in ledger.entries if e.kind == "capability_redeemed"}

    def _deny(self, reason: str, token: Any, tool: Any) -> GatewayResult:
        th = token_sha256(token) if isinstance(token, str) else None
        self.ledger.append("gateway_denied", {"reason": reason, "token_sha256": th, "tool": str(tool)})
        return GatewayResult(False, reason)

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
        return normalize_action({"tool": tool, **src}).to_record()

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
        try:
            call_tool = normalize_action({"tool": tool}).tool
            fields = self._call_fields(call_tool, args, call_fields)
            call_args_hash = args_hash(call_tool, args, self.digest_alg, self.ledger.crypto)
        except (ActionValidationError, TypeError, ValueError) as e:
            return self._deny(f"invalid_call:{e}", token, tool)

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
        idx = self.ledger.index_of(p.get("ledger_root", ""))
        if idx is None:
            return self._deny("unknown_ledger_root", token, tool)
        if "constitution_loaded" in self.ledger.kinds_after(idx):
            return self._deny("constitution_changed_since_issue", token, tool)
        jti = p.get("jti")
        if not jti or jti in self._redeemed:
            return self._deny("replayed", token, tool)

        self._redeemed.add(jti)
        self.ledger.append("capability_redeemed", {"jti": jti, "token_sha256": token_sha256(token),
                                                   "tool": call_tool, "args_hash": call_args_hash})
        fn = self.tools.get(call_tool)
        if fn is None:
            return GatewayResult(True, "authorized_no_executor")
        try:
            result = fn(**dict(args))
        except Exception as e:
            self.ledger.append("tool_error", {"jti": jti, "error": type(e).__name__})
            return GatewayResult(True, f"tool_error:{type(e).__name__}")
        self.ledger.append("tool_executed", {"jti": jti, "tool": call_tool})
        return GatewayResult(True, "executed", result)
