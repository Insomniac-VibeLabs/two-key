"""
Compact Kernel — Dual-Path Constitutional Enforcement
=====================================================
The invention's core method:

  1. Load the principal's compiled constitution (Path A bytecode)
     and natural-language constitution (Path B judges).
  2. Receive a proposed tool invocation from any language model.
  3. Evaluate Path A: deterministic Policy VM. Fail-closed.
  4. Evaluate Path B: multi-model intent quorum. Fail-closed.
  5. Only if BOTH paths pass, issue a short-lived capability token
     bound to the current personal-ledger root.
  6. Append the full decision record to the principal's ledger.

Neither a single model vendor nor a prompt injection can authorize
an action the constitution forbids, because Path A does not read
English at decision time.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from capability import Capability, CapabilityIssuer
from ledger import PersonalLedger
from policy_vm import Action, PolicyVM, compile_constitution
from quorum import HeuristicJudge, QuorumResult, convene


@dataclass
class Decision:
    allowed: bool
    reason: str
    vm_allowed: bool
    vm_reason: str
    quorum_passed: bool
    quorum: dict | None
    capability: dict | None
    ledger_digest: str


class CompactKernel:
    def __init__(
        self,
        principal: str,
        constitution_text: str,
        hard_rules: list[dict],
        ledger_path: Path,
        judges: list[HeuristicJudge] | None = None,
        quorum_threshold: float = 0.67,
        ttl_seconds: int = 30,
    ):
        self.principal = principal
        self.constitution_text = constitution_text
        self.bytecode = compile_constitution(hard_rules)
        self.vm = PolicyVM(self.bytecode)
        self.ledger = PersonalLedger(ledger_path)
        self.issuer = CapabilityIssuer()
        self.judges = judges or [
            HeuristicJudge("judge-alpha", strictness=0.3),
            HeuristicJudge("judge-bravo", strictness=0.6),
            HeuristicJudge("judge-charlie", strictness=0.9),
        ]
        self.quorum_threshold = quorum_threshold
        self.ttl_seconds = ttl_seconds

        self.ledger.append(
            "constitution_loaded",
            {"principal": principal, "rules": hard_rules, "bytecode_len": len(self.bytecode)},
        )

    def authorize(self, action: Action, proposal: str) -> Decision:
        self.ledger.append(
            "proposal",
            {"tool": action.tool, "amount_usd": action.amount_usd, "proposal": proposal[:500]},
        )

        vm_res = self.vm.eval(action)
        self.ledger.append(
            "vm_result",
            {"allowed": vm_res.allowed, "reason": vm_res.reason, "steps": vm_res.steps},
        )

        q: QuorumResult = convene(
            self.judges,
            self.constitution_text,
            action,
            proposal,
            threshold=self.quorum_threshold,
        )
        self.ledger.append(
            "quorum_result",
            {
                "passed": q.passed,
                "yes": q.yes,
                "no": q.no,
                "ballots": [asdict(b) for b in q.ballots],
            },
        )

        if not vm_res.allowed:
            d = Decision(
                allowed=False,
                reason=f"path_a_denied:{vm_res.reason}",
                vm_allowed=False,
                vm_reason=vm_res.reason,
                quorum_passed=q.passed,
                quorum={"yes": q.yes, "no": q.no},
                capability=None,
                ledger_digest=self.ledger.root(),
            )
            self.ledger.append("decision", {"allowed": False, "reason": d.reason})
            return d

        if not q.passed:
            d = Decision(
                allowed=False,
                reason="path_b_denied:quorum",
                vm_allowed=True,
                vm_reason=vm_res.reason,
                quorum_passed=False,
                quorum={"yes": q.yes, "no": q.no},
                capability=None,
                ledger_digest=self.ledger.root(),
            )
            self.ledger.append("decision", {"allowed": False, "reason": d.reason})
            return d

        cap = self.issuer.issue(
            principal=self.principal,
            tool=action.tool,
            scope={
                "amount_usd": action.amount_usd,
                "counterparty": action.counterparty,
                "data_class": action.data_class,
            },
            ledger_root=self.ledger.root(),
            ttl_seconds=self.ttl_seconds,
        )
        assert self.issuer.verify(cap)

        d = Decision(
            allowed=True,
            reason="dual_path_pass",
            vm_allowed=True,
            vm_reason=vm_res.reason,
            quorum_passed=True,
            quorum={"yes": q.yes, "no": q.no},
            capability={
                "tool": cap.tool,
                "expires_at": cap.expires_at,
                "token": cap.token[:16] + "…",
                "ledger_root": cap.ledger_root[:16] + "…",
            },
            ledger_digest=self.ledger.root(),
        )
        self.ledger.append("capability_issued", {"tool": cap.tool, "expires_at": cap.expires_at})
        self.ledger.append("decision", {"allowed": True, "reason": d.reason})
        return d
