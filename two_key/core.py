"""
Two-Key: dual-path constitutional enforcement
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

PRIOR_ART.md §4 directions selected by Stephan Busch on 2026-09-30
(CONCEPTION_NOTES.md Entry 2):
(i)   tokens bind the ledger Merkle root R and size at issuance plus
      H(bytecode) and H(NL constitution). The gateway checks ancestry by
      consistency proof, the hashes against the latest constitution_loaded
      entry, reload/revocation after issuance, and links results to the
      token's ledger entry (gateway.py). ``revoke()`` appends revocation entries.
(ii)  one principal-signed constitution document is compiled into both
      the Path A bytecode and the Path B prose (compiler.py). Both hashes are
      recorded at load and bound into ballots and tokens.
      ``reload_constitution()`` accepts only principal-signed documents.
(iii) judge-set heterogeneity, the availability floor K, bound ballots, and
      record-only judge inputs (quorum.py); Path B runs only after Path A passes.

Crypto (two_key.crypto): a CryptoProvider runs its known-answer
self-test before Two-Key starts; ``fips_mode`` refuses non-approved
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
from .compiler import CompiledConstitution, compile_both
from .constitution import Constitution, verify_signed
from .crypto.provider import CryptoProvider, default_provider
from .crypto.signatures import LEGACY_SUITE, as_public_keyset
from .gateway import Extractor, ToolGateway
from .judges.base import Judge
from .ledger import LedgerError, PersonalLedger
from .policy_vm import DEFAULT_MAX_STEPS, PolicyVM
from .quorum import QuorumConfigError, QuorumPolicy, check_judge_set, convene


class TwoKeyConfigError(ValueError):
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


class TwoKey:
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
                raise TwoKeyConfigError(f"require_pq=True but the principal key suite {trusted.suite!r} "
                                        "is not a hybrid ML-DSA suite")
            self.crypto.require_pq()
        if head_signing not in ("decision", "append"):
            raise TwoKeyConfigError("head_signing must be 'decision' or 'append'")
        if not judges:
            raise TwoKeyConfigError("at least one Path B judge is required")
        if not allow_test_doubles and any(getattr(j, "is_test_double", False) for j in judges):
            raise TwoKeyConfigError("test-double judges supplied; pass allow_test_doubles=True for demos/tests only")
        if ledger_signing_key is None and not allow_unsigned_ledger:
            raise TwoKeyConfigError("ledger_signing_key required (or allow_unsigned_ledger=True for testing)")
        if ledger_signing_key is not None and \
                as_public_keyset(ledger_signing_key, self.crypto).encoded != trusted.encoded:
            raise TwoKeyConfigError("ledger_signing_key must be the principal's key")
        legacy = trusted.suite == LEGACY_SUITE
        self.digest_alg = digest_alg or ("sha256" if legacy else "sha384")
        self.crypto.check("hash", self.digest_alg)
        self.token_mode = token_mode or ("tk1" if legacy else "tk1-hs384")

        # Refuse unsigned, modified, or foreign-signed constitutions (spec 5.1 item 2).
        self.trusted_public_key = trusted_public_key
        self.trusted_keyset = trusted
        self.max_steps = max_steps
        self._install(verify_signed(signed_constitution, trusted, self.crypto))
        self.principal = self.constitution.principal

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
            raise TwoKeyConfigError("required_yes exceeds the number of judges")
        try:  # §4 (iii): judge-set selection must meet the heterogeneity floor
            check_judge_set(self.judges, self.quorum_policy)
        except QuorumConfigError as e:
            raise TwoKeyConfigError(str(e)) from e
        self.ttl_seconds = ttl_seconds
        # Ordering option (DESIGN_OPTIONS.md section 4). Default: skip Path B when Path A
        # denies, so forbidden proposals are never sent to external judges (privacy).
        if self.quorum_policy.require_path_a_first and not short_circuit_path_b:
            raise TwoKeyConfigError("quorum policy requires Path B only after Path A passes "
                                    "(short_circuit_path_b must be True)")
        self.short_circuit_path_b = short_circuit_path_b

        self._append_loaded()
        self.ledger.checkpoint()

    # -- constitution (§4 (ii)) ------------------------------------------------
    def _install(self, constitution: Constitution) -> None:
        compiled = compile_both(constitution, max_steps=self.max_steps, digest_alg=self.digest_alg,
                                provider=self.crypto)
        self.constitution: Constitution = constitution
        self.compiled: CompiledConstitution = compiled
        self.constitution_text = compiled.judge_text
        self.bytecode = compiled.bytecode
        self.vm = PolicyVM(self.bytecode, max_steps=self.max_steps)

    def _append_loaded(self, **extra) -> None:
        self.ledger.append("constitution_loaded", {
            "principal": self.principal,
            "constitution_digest": self.constitution.digest,
            "signer": self.constitution.signer_fingerprint,
            "source_format": self.compiled.source_format,
            "compiler": self.compiled.compiler,
            "bytecode_hash": self.compiled.bytecode_hash,
            "nl_hash": self.compiled.nl_hash,
            "rules": self.constitution.hard_rules,
            "bytecode_len": len(self.bytecode),
            "judges": [_describe(j) for j in self.judges],
            "short_circuit_path_b": self.short_circuit_path_b,
            "quorum": self.quorum_policy.to_record(),
            "crypto": self.crypto_profile(),
            **extra,
        })

    def reload_constitution(self, signed_constitution: dict) -> None:
        """Load a new constitution. Only a document signed by the principal's trusted key is accepted.

        A refused reload is recorded as ``constitution_reload_refused`` and re-raised. On success a new
        constitution_loaded entry is appended; tokens issued before it are refused by the gateway.
        """
        try:
            c = verify_signed(signed_constitution, self.trusted_keyset, self.crypto)
            if c.principal != self.principal:
                raise TwoKeyConfigError("reloaded constitution names a different principal")
            prev = self.constitution, self.compiled
            self._install(c)
        except Exception as e:
            self.ledger.append("constitution_reload_refused", {"error": f"{type(e).__name__}: {e}"[:500]})
            self.ledger.checkpoint()
            raise
        try:
            self._append_loaded(previous_constitution_digest=prev[0].digest)
        except Exception:
            self.constitution, self.compiled = prev
            self._install(prev[0])
            raise
        self.ledger.checkpoint()

    def revoke(self, jti: str | None = None, reason: str = "") -> dict:
        """Append a revocation entry (§4 (i)): one token by jti, or all tokens issued so far (jti=None)."""
        if jti is not None and (not isinstance(jti, str) or not jti):
            raise ValueError("jti must be a non-empty string or None")
        e = self.ledger.append("revocation", {"jti": jti, "scope": "token" if jti else "all_issued",
                                              "reason": str(reason)[:500]})
        self.ledger.checkpoint()
        return {"seq": e.seq, "digest": e.digest}

    def ballot_binding(self, action_record: dict) -> dict:
        return {"action_hash": self._h(action_record), "constitution_hash": self.constitution.digest,
                "nl_hash": self.compiled.nl_hash, "bytecode_hash": self.compiled.bytecode_hash}

    def crypto_profile(self) -> dict:
        be = self.crypto.pq_backend()
        return {"signature_suite": self.trusted_keyset.suite, "digest_alg": self.digest_alg,
                "token_mode": self.token_mode, "fips_mode": self.crypto.fips_mode,
                "pq_backend": None if be is None else be.describe(), "head_signing": self.head_signing,
                "selftest": {"ok": self.selftest["ok"], "tests": len(self.selftest["passed"])}}

    # ------------------------------------------------------------------
    def gateway(self, tools: Mapping[str, Callable[..., Any]] | None = None,
                extractors: Mapping[str, Extractor] | None = None, *, checkpoint_every: int = 1,
                view_refresh: str = "token", scanners: Sequence[Any] | None = None,
                scan_settings: Any = None, file_extractors: Mapping[str, Callable] | None = None,
                result_file_extractors: Mapping[str, Callable] | None = None) -> ToolGateway:
        """A tool gateway on this instance's token key and ledger. ``scanners``, ``scan_settings``,
        ``file_extractors``, and ``result_file_extractors`` configure optional content scanning
        (scanning.py); there is none by default."""
        return ToolGateway(self.issuer, self.ledger, self.principal, tools, extractors, digest_alg=self.digest_alg,
                           checkpoint_every=checkpoint_every, view_refresh=view_refresh, scanners=scanners,
                           scan_settings=scan_settings, file_extractors=file_extractors,
                           result_file_extractors=result_file_extractors)

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
        binding = self.ballot_binding(rec)
        self.ledger.append("action_normalized", {"action": rec, "action_digest": binding["action_hash"],
                                                 "args_hash": a_hash})

        vm_res = self.vm.eval(action)
        self.ledger.append("vm_result", {"allowed": vm_res.allowed, "reason": vm_res.reason,
                                         "steps": vm_res.steps, "denied_by": vm_res.denied_by})
        if not vm_res.allowed and self.short_circuit_path_b:
            self.ledger.append("quorum_skipped", {"reason": "path_a_denied", "short_circuit_path_b": True})
            return self._deny(f"path_a_denied:{vm_res.reason}", rec, vm_allowed=False, vm_reason=vm_res.reason,
                              denied_by_rule=vm_res.denied_by, quorum_passed=None, quorum=None)
        q = convene(self.judges, self.constitution_text, action, proposal, self.quorum_policy, binding)
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
            constitution_digest=self.constitution.digest, ttl_seconds=self.ttl_seconds,
            ledger_size=self.ledger.size, ledger_merkle_root=self.ledger.merkle_root(),
            bytecode_hash=self.compiled.bytecode_hash, nl_hash=self.compiled.nl_hash)
        try:
            self.issuer.verify(cap.token)
        except Exception:
            return self._deny("issuer_self_check_failed", rec, vm_allowed=True, quorum_passed=True, quorum=qsum)
        # If this append fails, the exception propagates and authorize() returns a deny without the token.
        p = cap.payload
        self.ledger.append("capability_issued", {
            "jti": p["jti"], "token_sha256": cap.token_hash, "tool": p["tool"], "scope": p["scope"],
            "args_hash": p["args_hash"], "expires_at": p["expires_at"], "ledger_root": p["ledger_root"],
            "ledger_size": p["ledger_size"], "ledger_merkle_root": p["ledger_merkle_root"],
            "bytecode_hash": p["bytecode_hash"], "nl_hash": p["nl_hash"]})
        self.ledger.append("decision", {"allowed": True, "reason": "dual_path_pass", "denied_by_rule": None,
                                        "action_digest": binding["action_hash"]})
        return Decision(True, "dual_path_pass", True, vm_res.reason, None, True, qsum, cap.token, cap.payload,
                        self.ledger.root(), rec)


def _describe(j: Any) -> dict:
    d = getattr(j, "describe", None)
    if callable(d):
        return d()
    return {"id": getattr(j, "judge_id", "?"), "provider": getattr(j, "provider", "?"),
            "vendor": getattr(j, "vendor", None) or getattr(j, "provider", "?"),
            "local_weights": bool(getattr(j, "local_weights", False))}


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
