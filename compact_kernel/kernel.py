"""
Compact Kernel: dual-path constitutional enforcement
====================================================
1. Load the principal's signed constitution: plain-English text for Path B
   and hard rules compiled for Path A. The Ed25519 signature is verified
   first; unsigned or modified constitutions are refused.
2. Receive a proposed action plus the literal tool-call arguments.
   Normalize and validate the action.
3. Path A: deterministic Policy VM. Fail closed.
4. Path B: multi-model intent quorum over the judges the user chose. Fail closed.
   By default Path B is skipped when Path A denies (privacy); this is configurable.
5. Only if BOTH paths pass, issue a short-lived, single-use capability token
   bound to tool, scope, args hash, and the current ledger root.
6. Every step is appended to the principal's signed ledger. If the ledger
   cannot append, the result is deny.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import keys
from .action import Action, ActionValidationError, normalize_action
from .canonical import canonical_hash, sha256_hex
from .capability import CapabilityIssuer, args_hash
from .constitution import Constitution, verify_signed
from .gateway import Extractor, ToolGateway
from .judges.base import Judge
from .ledger import LedgerError, PersonalLedger
from .policy_vm import DEFAULT_MAX_STEPS, PolicyVM, compile_constitution
from .quorum import QuorumPolicy, convene


class KernelConfigError(ValueError):
    pass


@dataclass
class Decision:
    allowed: bool
    reason: str
    vm_allowed: bool | None = None
    vm_reason: str | None = None
    denied_by_rule: str | None = None
    quorum_passed: bool | None = None
    quorum: dict | None = None
    capability: str | None = None          # the full token (bearer secret), only if allowed
    token_payload: dict | None = None
    ledger_digest: str = ""
    action: dict | None = field(default=None, repr=False)


class CompactKernel:
    def __init__(
        self,
        signed_constitution: dict,
        trusted_public_key: Ed25519PublicKey,
        ledger_path: Path,
        judges: Sequence[Judge],
        *,
        ledger_signing_key: Ed25519PrivateKey | None = None,
        allow_unsigned_ledger: bool = False,
        quorum_policy: QuorumPolicy | None = None,
        ttl_seconds: int = 30,
        max_steps: int = DEFAULT_MAX_STEPS,
        capability_secret: bytes | None = None,
        clock: Callable[[], float] | None = None,
        allow_test_doubles: bool = False,
    ):
        if not judges:
            raise KernelConfigError("at least one Path B judge is required")
        if not allow_test_doubles and any(getattr(j, "is_test_double", False) for j in judges):
            raise KernelConfigError("test-double judges supplied; pass allow_test_doubles=True for demos/tests only")
        if ledger_signing_key is None and not allow_unsigned_ledger:
            raise KernelConfigError("ledger_signing_key required (or allow_unsigned_ledger=True for testing)")
        if ledger_signing_key is not None and \
                keys.public_key_raw(ledger_signing_key) != keys.public_key_raw(trusted_public_key):
            raise KernelConfigError("ledger_signing_key must be the principal's key")

        # Refuse unsigned, modified, or foreign-signed constitutions (spec 5.1 item 2).
        self.constitution: Constitution = verify_signed(signed_constitution, trusted_public_key)
        self.trusted_public_key = trusted_public_key
        self.principal = self.constitution.principal
        self.constitution_text = self.constitution.text
        self.bytecode = compile_constitution(self.constitution.hard_rules, max_steps=max_steps)
        self.vm = PolicyVM(self.bytecode, max_steps=max_steps)

        self.ledger = PersonalLedger(Path(ledger_path), signing_key=ledger_signing_key)
        if self.ledger.entries:
            if ledger_signing_key is not None:
                rep = self.ledger.verify(trusted_public_key)
                if not rep.ok:
                    raise LedgerError(f"existing ledger failed verification: {rep.reason}")
            elif not self.ledger.verify_chain():
                raise LedgerError("existing ledger hash chain is broken")

        issuer_kw = {"clock": clock} if clock else {}
        self.issuer = CapabilityIssuer(capability_secret, **issuer_kw)
        self.judges = list(judges)
        self.quorum_policy = quorum_policy or QuorumPolicy(required_yes=min(2, len(self.judges)))
        if self.quorum_policy.required_yes > len(self.judges):
            raise KernelConfigError("required_yes exceeds the number of judges")
        self.ttl_seconds = ttl_seconds

        self.ledger.append("constitution_loaded", {
            "principal": self.principal,
            "constitution_digest": self.constitution.digest,
            "signer": self.constitution.signer_fingerprint,
            "rules": self.constitution.hard_rules,
            "bytecode_len": len(self.bytecode),
            "judges": [{"id": j.judge_id, "provider": j.provider} for j in self.judges],
            "quorum": {"required_yes": self.quorum_policy.required_yes,
                       "min_responding": self.quorum_policy.effective_min_responding,
                       "min_distinct_providers": self.quorum_policy.min_distinct_providers},
        })

    # ------------------------------------------------------------------
    def gateway(self, tools: Mapping[str, Callable[..., Any]] | None = None,
                extractors: Mapping[str, Extractor] | None = None) -> ToolGateway:
        return ToolGateway(self.issuer, self.ledger, self.principal, tools, extractors)

    def _deny(self, reason: str, action_rec: dict | None = None, **kw) -> Decision:
        body = {"allowed": False, "reason": reason, "denied_by_rule": kw.get("denied_by_rule"),
                "action_digest": canonical_hash(action_rec) if action_rec else None}
        try:
            self.ledger.append("decision", body)
        except Exception:
            pass  # already denying; nothing more to do
        return Decision(False, reason, ledger_digest=self.ledger.root(), action=action_rec, **kw)

    def authorize(self, proposed: Action | Mapping[str, Any], proposal: str,
                  tool_args: Mapping[str, Any] | None = None) -> Decision:
        try:
            return self._authorize(proposed, proposal, {} if tool_args is None else tool_args)
        except Exception as e:  # spec 5.7: no best-effort allow; the ledger or any component failing means deny
            return Decision(False, f"internal_error:{type(e).__name__}", ledger_digest=self.ledger.root())

    def _authorize(self, proposed, proposal: str, tool_args: Mapping[str, Any]) -> Decision:
        if not isinstance(proposal, str):
            proposal = str(proposal)
        self.ledger.append("proposal", {"action_input": _safe_record(proposed), "proposal": proposal,
                                        "proposal_sha256": sha256_hex(proposal.encode("utf-8")),
                                        "tool_args": _safe_record(tool_args)})
        try:
            action = normalize_action(proposed)
            a_hash = args_hash(action.tool, tool_args)
        except (ActionValidationError, TypeError, ValueError) as e:
            return self._deny(f"invalid_action:{e}")
        rec = action.to_record()
        self.ledger.append("action_normalized", {"action": rec, "action_digest": canonical_hash(rec),
                                                 "args_hash": a_hash})

        vm_res = self.vm.eval(action)
        self.ledger.append("vm_result", {"allowed": vm_res.allowed, "reason": vm_res.reason,
                                         "steps": vm_res.steps, "denied_by": vm_res.denied_by})
        q = convene(self.judges, self.constitution_text, action, proposal, self.quorum_policy)
        self.ledger.append("quorum_result", q.to_record())
        qsum = {"yes": q.yes, "no": q.no, "abstain": q.abstain, "reason": q.reason}

        if not vm_res.allowed:
            return self._deny(f"path_a_denied:{vm_res.reason}", rec, vm_allowed=False, vm_reason=vm_res.reason,
                              denied_by_rule=vm_res.denied_by, quorum_passed=q.passed, quorum=qsum)
        if not q.passed:
            return self._deny(f"path_b_denied:{q.reason}", rec, vm_allowed=True, vm_reason=vm_res.reason,
                              quorum_passed=False, quorum=qsum)

        cap = self.issuer.issue(
            principal=self.principal, tool=action.tool,
            scope={"amount_usd": action.amount_usd, "counterparty": action.counterparty,
                   "data_class": action.data_class},
            args_digest=a_hash, ledger_root=self.ledger.root(),
            constitution_digest=self.constitution.digest, ttl_seconds=self.ttl_seconds)
        try:
            self.issuer.verify(cap.token)
        except Exception:
            return self._deny("issuer_self_check_failed", rec, vm_allowed=True, quorum_passed=True, quorum=qsum)
        # If this append fails, the exception propagates and authorize() returns a deny without the token.
        p = cap.payload
        self.ledger.append("capability_issued", {
            "jti": p["jti"], "token_sha256": cap.token_hash, "tool": p["tool"], "scope": p["scope"],
            "args_hash": p["args_hash"], "expires_at": p["expires_at"], "ledger_root": p["ledger_root"]})
        self.ledger.append("decision", {"allowed": True, "reason": "dual_path_pass", "denied_by_rule": None,
                                        "action_digest": canonical_hash(rec)})
        return Decision(True, "dual_path_pass", True, vm_res.reason, None, True, qsum, cap.token, cap.payload,
                        self.ledger.root(), rec)


def _safe_record(obj: Any) -> Any:
    """Make an arbitrary proposed input JSON-safe for logging."""
    if isinstance(obj, Action):
        return obj.to_record()
    if isinstance(obj, Mapping):
        return {str(k): _safe_record(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe_record(v) for v in obj]
    if isinstance(obj, float) and (obj != obj or obj in (float("inf"), float("-inf"))):
        return repr(obj)
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return repr(obj)
