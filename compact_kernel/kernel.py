"""
Compact Kernel: dual-path constitutional enforcement
====================================================
1. Load the principal's hard rules (Path A bytecode) and natural-language
   constitution (Path B).
2. Receive a proposed tool invocation, normalized and validated.
3. Path A: deterministic Policy VM. Fail closed.
4. Path B: multi-model intent quorum. Fail closed.
5. Issue a short-lived capability token only if BOTH paths pass.
6. Append the full decision record to the principal's ledger.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .action import Action, ActionValidationError, normalize_action
from .capability import CapabilityIssuer
from .judges.base import Judge
from .ledger import PersonalLedger
from .policy_vm import DEFAULT_MAX_STEPS, PolicyVM, compile_constitution
from .quorum import QuorumPolicy, QuorumResult, convene


class KernelConfigError(ValueError):
    pass


@dataclass
class Decision:
    allowed: bool
    reason: str
    vm_allowed: bool | None
    vm_reason: str | None
    denied_by_rule: str | None
    quorum_passed: bool | None
    quorum: dict | None
    capability: Any | None
    ledger_digest: str


class CompactKernel:
    def __init__(
        self,
        principal: str,
        constitution_text: str,
        hard_rules: list[dict],
        ledger_path: Path,
        judges: Sequence[Judge],
        quorum_policy: QuorumPolicy | None = None,
        ttl_seconds: int = 30,
        max_steps: int = DEFAULT_MAX_STEPS,
        allow_test_doubles: bool = False,
    ):
        if not judges:
            raise KernelConfigError("at least one Path B judge is required")
        if not allow_test_doubles and any(getattr(j, "is_test_double", False) for j in judges):
            raise KernelConfigError("test-double judges supplied; pass allow_test_doubles=True for demos/tests only")
        self.principal = principal
        self.constitution_text = constitution_text
        self.bytecode = compile_constitution(hard_rules, max_steps=max_steps)
        self.vm = PolicyVM(self.bytecode, max_steps=max_steps)
        self.ledger = PersonalLedger(ledger_path)
        self.issuer = CapabilityIssuer()
        self.judges = list(judges)
        self.quorum_policy = quorum_policy or QuorumPolicy()
        self.ttl_seconds = ttl_seconds
        self.ledger.append("constitution_loaded",
                           {"principal": principal, "rules": hard_rules, "bytecode_len": len(self.bytecode)})

    def _deny(self, reason: str, **kw) -> Decision:
        self.ledger.append("decision", {"allowed": False, "reason": reason,
                                        "denied_by_rule": kw.get("denied_by_rule")})
        return Decision(False, reason, kw.get("vm_allowed"), kw.get("vm_reason"), kw.get("denied_by_rule"),
                        kw.get("quorum_passed"), kw.get("quorum"), None, self.ledger.root())

    def authorize(self, proposed: Action | Mapping[str, Any], proposal: str) -> Decision:
        self.ledger.append("proposal", {"action_input": _safe_record(proposed), "proposal": proposal})
        try:
            action = normalize_action(proposed)
        except ActionValidationError as e:
            return self._deny(f"invalid_action:{e}")

        vm_res = self.vm.eval(action)
        self.ledger.append("vm_result", {"allowed": vm_res.allowed, "reason": vm_res.reason,
                                         "steps": vm_res.steps, "denied_by": vm_res.denied_by})
        q: QuorumResult = convene(self.judges, self.constitution_text, action, proposal, self.quorum_policy)
        self.ledger.append("quorum_result", q.to_record())
        qsum = {"yes": q.yes, "no": q.no, "abstain": q.abstain, "reason": q.reason}
        if not vm_res.allowed:
            return self._deny(f"path_a_denied:{vm_res.reason}", vm_allowed=False, vm_reason=vm_res.reason,
                              denied_by_rule=vm_res.denied_by, quorum_passed=q.passed, quorum=qsum)
        if not q.passed:
            return self._deny(f"path_b_denied:{q.reason}", vm_allowed=True, vm_reason=vm_res.reason,
                              quorum_passed=False, quorum=qsum)
        cap = self.issuer.issue(principal=self.principal, tool=action.tool,
                                scope={"amount_usd": action.amount_usd, "counterparty": action.counterparty,
                                       "data_class": action.data_class},
                                ledger_root=self.ledger.root(), ttl_seconds=self.ttl_seconds)
        if not self.issuer.verify(cap):
            return self._deny("issuer_self_check_failed", vm_allowed=True, quorum_passed=True, quorum=qsum)
        self.ledger.append("capability_issued", {"tool": cap.tool, "expires_at": cap.expires_at})
        self.ledger.append("decision", {"allowed": True, "reason": "dual_path_pass"})
        return Decision(True, "dual_path_pass", True, vm_res.reason, None, True, qsum, cap, self.ledger.root())


def _safe_record(proposed: Any) -> Any:
    if isinstance(proposed, Action):
        return proposed.to_record()
    if isinstance(proposed, Mapping):
        return {str(k): (v if isinstance(v, (str, int, float, bool, type(None), list, dict)) else repr(v))
                for k, v in proposed.items()}
    return repr(proposed)
