"""
Compact Kernel: dual-path constitutional enforcement
====================================================
1. Load the principal's signed constitution: plain-English text for Path B
   and hard rules compiled for Path A. The principal's signature (Ed25519, ECDSA
   P-384, or hybrid ML-DSA-65) is verified first; unsigned or modified
   constitutions are refused.
2. Receive a proposed action plus the literal tool-call arguments.
   Normalize and validate the action.
3. Path A: deterministic Policy VM. Fail closed.
4. Path B: multi-model intent quorum over the judges the user chose. Fail closed.
   By default Path B is skipped when Path A denies (privacy); set
   short_circuit_path_b=False to run both paths on every proposal.
5. Only if BOTH paths pass, issue a short-lived, single-use capability token
   bound to tool, scope, args hash, and the current ledger root.
6. Every step is appended to the principal's signed ledger. If the ledger
   cannot append, the result is deny. The ledger head is signed once per
   decision (``head_signing="decision"``, default) or after every append
   (``head_signing="append"``); if the signed-head checkpoint fails, the
   decision is a deny.

Crypto (compact_kernel.crypto): a CryptoProvider runs its known-answer
self-test before the kernel starts; ``fips_mode`` refuses non-approved
algorithms. The principal key may be legacy Ed25519, ECDSA P-384, or a hybrid
ML-DSA-65 suite; ``require_pq=True`` refuses to start without a hybrid key and
a working ML-DSA backend. Non-legacy suites default to SHA-384 digests and
HMAC-SHA-384 tokens.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .action import Action, ActionValidationError, normalize_action
from .canonical import canonical_hash, sha256_hex
from .capability import CapabilityIssuer, args_hash
from .constitution import Constitution, verify_signed
from .crypto.provider import CryptoProvider, default_provider
from .crypto.signatures import LEGACY_SUITE, as_public_keyset
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
        trusted_public_key: Any,
        ledger_path: Path,
        judges: Sequence[Judge],
        *,
        ledger_signing_key: Any = None,
        allow_unsigned_ledger: bool = False,
        quorum_policy: QuorumPolicy | None = None,
        ttl_seconds: int = 30,
        max_steps: int = DEFAULT_MAX_STEPS,
        capability_secret: bytes | None = None,
        clock: Callable[[], float] | None = None,
        allow_test_doubles: bool = False,
        short_circuit_path_b: bool = True,
        crypto: CryptoProvider | None = None,
        require_pq: bool = False,
        digest_alg: str | None = None,
        token_mode: str | None = None,
        token_signing_key: Any = None,
        head_signing: str = "decision",
        ledger_fsync: bool = True,
    ):
        # Crypto first: the known-answer self-test must pass before anything else (raises SelfTestError).
        self.crypto = crypto or default_provider()
        self.selftest = self.crypto.ensure_selftest()
        trusted = as_public_keyset(trusted_public_key, self.crypto)  # PQUnavailableError if hybrid w/o backend
        if require_pq:
            if not trusted.is_pq:
                raise KernelConfigError(f"require_pq=True but the principal key suite {trusted.suite!r} "
                                        "is not a hybrid ML-DSA suite")
            self.crypto.require_pq()
        if head_signing not in ("decision", "append"):
            raise KernelConfigError("head_signing must be 'decision' or 'append'")
        if not judges:
            raise KernelConfigError("at least one Path B judge is required")
        if not allow_test_doubles and any(getattr(j, "is_test_double", False) for j in judges):
            raise KernelConfigError("test-double judges supplied; pass allow_test_doubles=True for demos/tests only")
        if ledger_signing_key is None and not allow_unsigned_ledger:
            raise KernelConfigError("ledger_signing_key required (or allow_unsigned_ledger=True for testing)")
        if ledger_signing_key is not None and \
                as_public_keyset(ledger_signing_key, self.crypto).encoded != trusted.encoded:
            raise KernelConfigError("ledger_signing_key must be the principal's key")
        legacy = trusted.suite == LEGACY_SUITE
        self.digest_alg = digest_alg or ("sha256" if legacy else "sha384")
        self.crypto.check("hash", self.digest_alg)
        self.token_mode = token_mode or ("ck1" if legacy else "ck1-hs384")

        # Refuse unsigned, modified, or foreign-signed constitutions (spec 5.1 item 2).
        self.constitution: Constitution = verify_signed(signed_constitution, trusted, self.crypto)
        self.trusted_public_key = trusted_public_key
        self.trusted_keyset = trusted
        self.principal = self.constitution.principal
        self.constitution_text = self.constitution.text
        self.bytecode = compile_constitution(self.constitution.hard_rules, max_steps=max_steps)
        self.vm = PolicyVM(self.bytecode, max_steps=max_steps)

        self.head_signing = head_signing
        self.ledger = PersonalLedger(Path(ledger_path), signing_key=ledger_signing_key, digest_alg=self.digest_alg,
                                     auto_sign_every=1 if head_signing == "append" else 0,
                                     fsync=ledger_fsync, crypto=self.crypto)
        if self.ledger.entries:
            if ledger_signing_key is not None:
                rep = self.ledger.verify(trusted)
                if not rep.ok:
                    raise LedgerError(f"existing ledger failed verification: {rep.reason}")
            elif not self.ledger.verify_chain():
                raise LedgerError("existing ledger hash chain is broken")

        issuer_kw = {"clock": clock} if clock else {}
        self.issuer = CapabilityIssuer(capability_secret, mode=self.token_mode, signing_key=token_signing_key,
                                       crypto=self.crypto, **issuer_kw)
        self.judges = list(judges)
        self.quorum_policy = quorum_policy or QuorumPolicy(required_yes=min(2, len(self.judges)))
        if self.quorum_policy.required_yes > len(self.judges):
            raise KernelConfigError("required_yes exceeds the number of judges")
        self.ttl_seconds = ttl_seconds
        # Ordering option (DESIGN_OPTIONS.md section 4). Default: skip Path B when Path A
        # denies, so forbidden proposals are never sent to external judges (privacy).
        self.short_circuit_path_b = short_circuit_path_b

        self.ledger.append("constitution_loaded", {
            "principal": self.principal,
            "constitution_digest": self.constitution.digest,
            "signer": self.constitution.signer_fingerprint,
            "rules": self.constitution.hard_rules,
            "bytecode_len": len(self.bytecode),
            "judges": [{"id": j.judge_id, "provider": j.provider} for j in self.judges],
            "short_circuit_path_b": self.short_circuit_path_b,
            "quorum": {"required_yes": self.quorum_policy.required_yes,
                       "min_responding": self.quorum_policy.effective_min_responding,
                       "min_distinct_providers": self.quorum_policy.min_distinct_providers,
                       "timeout_seconds": self.quorum_policy.timeout_seconds},
            "crypto": self.crypto_profile(),
        })
        self.ledger.checkpoint()

    def crypto_profile(self) -> dict:
        be = self.crypto.pq_backend()
        return {"signature_suite": self.trusted_keyset.suite, "digest_alg": self.digest_alg,
                "token_mode": self.token_mode, "fips_mode": self.crypto.fips_mode,
                "pq_backend": None if be is None else be.describe(), "head_signing": self.head_signing,
                "selftest": {"ok": self.selftest["ok"], "tests": len(self.selftest["passed"])}}

    # ------------------------------------------------------------------
    def gateway(self, tools: Mapping[str, Callable[..., Any]] | None = None,
                extractors: Mapping[str, Extractor] | None = None, *, checkpoint_every: int = 1) -> ToolGateway:
        return ToolGateway(self.issuer, self.ledger, self.principal, tools, extractors, digest_alg=self.digest_alg,
                           checkpoint_every=checkpoint_every)

    def _deny(self, reason: str, action_rec: dict | None = None, **kw) -> Decision:
        body = {"allowed": False, "reason": reason, "denied_by_rule": kw.get("denied_by_rule"),
                "action_digest": self._h(action_rec) if action_rec else None}
        try:
            self.ledger.append("decision", body)
        except Exception:
            pass  # already denying; nothing more to do
        return Decision(False, reason, ledger_digest=self.ledger.root(), action=action_rec, **kw)

    def authorize(self, proposed: Action | Mapping[str, Any], proposal: str,
                  tool_args: Mapping[str, Any] | None = None) -> Decision:
        try:
            d = self._authorize(proposed, proposal, {} if tool_args is None else tool_args)
        except Exception as e:  # spec 5.7: no best-effort allow; the ledger or any component failing means deny
            d = Decision(False, f"internal_error:{type(e).__name__}", ledger_digest=self.ledger.root())
        try:
            self.ledger.checkpoint()  # one signed head per decision
        except Exception as e:
            if d.allowed:  # never release a token whose decision is not covered by a signed head
                return Decision(False, f"internal_error:ledger_checkpoint:{type(e).__name__}",
                                ledger_digest=self.ledger.root())
        return d

    def _h(self, obj: Any) -> str:
        return canonical_hash(obj, self.digest_alg, self.crypto)

    def _authorize(self, proposed, proposal: str, tool_args: Mapping[str, Any]) -> Decision:
        if not isinstance(proposal, str):
            proposal = str(proposal)
        self.ledger.append("proposal", {"action_input": _safe_record(proposed), "proposal": proposal,
                                        "proposal_sha256": sha256_hex(proposal.encode("utf-8")),
                                        "tool_args": _safe_record(tool_args)})
        try:
            action = normalize_action(proposed)
            a_hash = args_hash(action.tool, tool_args, self.digest_alg, self.crypto)
        except (ActionValidationError, TypeError, ValueError) as e:
            return self._deny(f"invalid_action:{e}")
        rec = action.to_record()
        self.ledger.append("action_normalized", {"action": rec, "action_digest": self._h(rec),
                                                 "args_hash": a_hash})

        vm_res = self.vm.eval(action)
        self.ledger.append("vm_result", {"allowed": vm_res.allowed, "reason": vm_res.reason,
                                         "steps": vm_res.steps, "denied_by": vm_res.denied_by})
        if not vm_res.allowed and self.short_circuit_path_b:
            self.ledger.append("quorum_skipped", {"reason": "path_a_denied", "short_circuit_path_b": True})
            return self._deny(f"path_a_denied:{vm_res.reason}", rec, vm_allowed=False, vm_reason=vm_res.reason,
                              denied_by_rule=vm_res.denied_by, quorum_passed=None, quorum=None)
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
                                        "action_digest": self._h(rec)})
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
