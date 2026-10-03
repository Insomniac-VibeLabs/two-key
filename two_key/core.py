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
   Both paths always answer. A deny or a missing answer from either path denies.
5. Only if BOTH paths pass, issue a short-lived, single-use capability token
   bound to tool, scope, args hash, and the current ledger root.
6. Every step is appended to the principal's signed ledger. If the ledger
   cannot append, the result is deny. The ledger head is signed once per
   decision (``head_signing="decision"``, default) or after every append
   (``head_signing="append"``); if the signed-head checkpoint fails, the
   decision is a deny.

PRIOR_ART.md §4 directions selected by the author on 2026-09-30
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

Deployment mode (deployment.py; CONCEPTION_NOTES.md Entry 9): ``personal``
(default, unchanged behavior) or ``enterprise`` (every signed ledger head is
also anchored to a permissioned chain; startup fails without one). Set once,
early, from the argument, TWOKEY_DEPLOYMENT_MODE, or a config file, and
recorded in the ledger.

PKI identities (pki.py; CONCEPTION_NOTES.md Entry 11): with ``pki=`` (required
in enterprise mode), the principal's X.509 certificate must chain to a trust
anchor, be unrevoked, map to the role ``principal``, and certify the trusted
key. Judge certificates (``judge_credentials=``) are checked at startup.
In enterprise mode each ``authorize`` call needs an agent assertion
(``pki.sign_agent_request``) unless ``require_agent_identity`` is off. Every
verified identity is recorded in the ledger.

Crypto (two_key.crypto): a CryptoProvider runs its known-answer
self-test before Two-Key starts; ``fips_mode`` refuses non-approved
algorithms. The principal key may be legacy Ed25519, ECDSA P-384, or a hybrid
ML-DSA-65 suite; ``require_pq=True`` refuses to start without a hybrid key and
a working ML-DSA backend. Every suite defaults to SHA-384 digests and
HMAC-SHA-384 tokens (since F_REVIEW, CONCEPTION_NOTES Entry 10; earlier,
Ed25519 defaulted to SHA-256 and HMAC-SHA-256). A ledger written with SHA-256
still verifies; appending to one needs an explicit ``digest_alg="sha256"``.
Tool arguments and action records are hashed in the typed, injective
two-key-enc/2 encoding (canonical.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import pki as _pki
from .action import Action, ActionValidationError, normalize_action
from .canonical import DOMAIN_ACTION_RECORD, ENCODING, digest_hex, freeze_call, typed_hash
from .capability import CapabilityIssuer, args_hash
from .compiler import CompiledConstitution, compile_both
from .constitution import Constitution, verify_signed
from .scope import disagreement
from .crypto.provider import CryptoProvider, default_provider
from .crypto.signatures import as_public_keyset
from . import deployment as _deployment
from .anchoring import NullAnchor
from .gateway import Extractor, ToolGateway
from .judges.base import Judge
from .ledger import LedgerError, PersonalLedger
from . import siem
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
        short_circuit_path_b: bool = False,
        crypto: CryptoProvider | None = None,
        require_pq: bool = False,
        digest_alg: str | None = None,
        token_mode: str | None = None,
        token_signing_key: Any = None,
        head_signing: str = "decision",
        ledger_fsync: bool = True,
        deployment_mode: str | None = None,
        deployment_config: Path | str | None = None,
        agent_session_env: str | None = None,
        agents: Sequence | None = None,
        anchor: Any = None,
        pki: Any = None,
        principal_credential: Any = None,
        judge_credentials: Mapping[str, Any] | None = None,
        siem_host: str | None = None,
        siem_port: int = 6514,
        siem_cafile: str | None = None,
    ):
        # Deployment mode first (Entry 9): an early, global setting other settings can depend on later.
        try:
            self.deployment = _deployment.resolve(deployment_mode, config_path=deployment_config)
            _deployment.check_anchor(self.deployment, anchor)
        except _deployment.DeploymentConfigError as e:
            raise TwoKeyConfigError(str(e)) from e
        self.siem_host = siem_host
        self.siem_port = int(siem_port)
        self.siem_cafile = siem_cafile
        if deployment_config and not self.siem_host:
            data = _deployment.load_config_file(deployment_config)
            block = data.get("siem") if isinstance(data, dict) else None
            if isinstance(block, dict) and block.get("host"):
                self.siem_host = str(block["host"])
                self.siem_port = int(block.get("port", self.siem_port))
        if self.deployment.is_enterprise and not self.siem_host:
            raise TwoKeyConfigError("deployment_mode 'enterprise' requires a SIEM syslog target "
                                    "(siem_host= or a siem.host in the deployment config); "
                                    "events are RFC 5424 over TLS, port 6514")
        self.anchor = anchor
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
        # SHA-384 / HMAC-SHA-384 for every suite (F_REVIEW; Entry 10). SHA-256 and tk1 only when chosen.
        self.digest_alg = digest_alg or "sha384"
        self.crypto.check("hash", self.digest_alg)
        self.token_mode = token_mode or "tk1-sig"
        self._setup_pki(pki, principal_credential, judge_credentials or {}, deployment_config, trusted, judges)

        # Refuse unsigned, modified, or foreign-signed constitutions (spec 5.1 item 2).
        self.trusted_public_key = trusted_public_key
        self.trusted_keyset = trusted
        self.max_steps = max_steps
        self._install(verify_signed(signed_constitution, trusted, self.crypto))
        self.principal = self.constitution.principal

        self.head_signing = head_signing
        try:
            self.ledger = PersonalLedger(Path(ledger_path), signing_key=ledger_signing_key,
                                         digest_alg=self.digest_alg,
                                         auto_sign_every=1 if head_signing == "append" else 0,
                                         fsync=ledger_fsync, crypto=self.crypto,
                                         head_anchor=None if isinstance(anchor, NullAnchor) else anchor)
        except LedgerError as e:
            if digest_alg is None and str(e).startswith("ledger uses "):
                raise TwoKeyConfigError(
                    f"{e}: this ledger was written with an earlier default. It still verifies "
                    "(PersonalLedger(path, signing_key=key).verify(public_key), or python -m two_key verify-ledger --key). To keep appending "
                    f"to it, pass digest_alg={str(e).split()[2].rstrip(',')!r} explicitly (legacy); or start a new ledger "
                    "(SHA-384 by default)") from e
            raise
        recorded = _deployment.recorded_mode(self.ledger)
        if recorded is not None and recorded != self.deployment.mode:
            raise TwoKeyConfigError(f"this ledger was set up in deployment_mode {recorded!r}; it is set once and "
                                    f"can't be reopened as {self.deployment.mode!r}")
        if self.ledger.entries:
            if ledger_signing_key is not None:
                rep = self.ledger.verify(trusted)
                if not rep.ok:
                    raise LedgerError(f"existing ledger failed verification: {rep.reason}")
            elif not self.ledger.verify_chain():
                raise LedgerError("existing ledger hash chain is broken")

        issuer_kw = {"clock": clock} if clock else {}
        # Signed tokens are the default. The gateway gets only the public key, so checking a token cannot mint one.
        if self.token_mode == "tk1-sig" and token_signing_key is None:
            token_signing_key = ledger_signing_key
        if self.token_mode == "tk1-sig" and token_signing_key is None:
            raise TwoKeyConfigError("tk1-sig requires ledger_signing_key or token_signing_key")
        self.issuer = CapabilityIssuer(capability_secret, mode=self.token_mode, signing_key=token_signing_key,
                                       crypto=self.crypto, **issuer_kw)
        self._gateway_issuer = self.issuer
        if self.token_mode == "tk1-sig":
            self._gateway_issuer = CapabilityIssuer(mode="tk1-sig", verify_key=self.issuer._verifier,
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
        # Both paths always answer. The old skip flag is accepted and ignored.
        self.short_circuit_path_b = False
        self.agents = {a.agent_id: a for a in (agents or [])}
        if len(self.agents) != len(agents or []):
            raise TwoKeyConfigError("agent ids must be unique")
        self._agent_session = self._freeze_agent_session(agent_session_env)

        self._append_loaded()
        self.ledger.checkpoint()

    # -- PKI identities (Entry 11) ---------------------------------------------
    def _setup_pki(self, pki, principal_credential, judge_credentials, deployment_config, trusted, judges) -> None:
        if pki is None and deployment_config is not None:
            data = _deployment.load_config_file(deployment_config)
            if "pki" in data:
                pki = data["pki"]
                base = Path(deployment_config).parent
            else:
                base = Path(".")
        else:
            base = Path(".")
        try:
            if isinstance(pki, Mapping):
                pki = _pki.PkiConfig.from_mapping(pki, base)
            if isinstance(pki, _pki.PkiConfig):
                pki = _pki.PkiVerifier(pki, self.crypto)
            if pki is not None and not isinstance(pki, _pki.PkiVerifier):
                raise TwoKeyConfigError("pki must be a PkiConfig, PkiVerifier, or a config mapping")
            _deployment.check_pki(self.deployment, pki)
        except (_deployment.DeploymentConfigError, _pki.PkiError, OSError) as e:
            raise TwoKeyConfigError(str(e)) from e
        self.pki = pki
        self.principal_identity = None
        self.judge_identities: dict = {}
        self._agent_nonces: set = set()
        if pki is None:
            if principal_credential is not None or judge_credentials:
                raise TwoKeyConfigError("certificates were given but no pki is configured")
            return
        if principal_credential is None:
            if self.deployment.is_enterprise:
                raise TwoKeyConfigError("deployment_mode 'enterprise' requires principal_credential= (the "
                                        "principal's certificate); placeholder pending a maintainer decision")
        else:
            try:
                ident = pki.verify(principal_credential, "principal")
            except _pki.PkiError as e:
                raise TwoKeyConfigError(f"principal certificate rejected: {e}") from e
            if ident.public_keyset.encoded != trusted.encoded:
                raise TwoKeyConfigError("the principal certificate does not certify the trusted principal key "
                                        f"(certificate key {ident.public_keyset.fingerprint}, trusted "
                                        f"{trusted.fingerprint})")
            self.principal_identity = ident
        ids = {getattr(j, "judge_id", None) for j in judges}
        unknown = set(judge_credentials) - ids
        if unknown:
            raise TwoKeyConfigError(f"judge_credentials for unknown judges: {sorted(unknown)}")
        if pki.config.require_judge_identities and set(judge_credentials) != ids:
            raise TwoKeyConfigError(f"require_judge_identities: missing certificates for "
                                    f"{sorted(i for i in ids - set(judge_credentials) if i)}")
        for jid, cred in judge_credentials.items():
            try:
                self.judge_identities[jid] = pki.verify(cred, "judge")
            except _pki.PkiError as e:
                raise TwoKeyConfigError(f"judge {jid!r} certificate rejected: {e}") from e

    def identity_record(self) -> dict | None:
        if self.pki is None:
            return None
        return {"pki": self.pki.describe(),
                "principal": None if self.principal_identity is None else self.principal_identity.to_record(),
                "judges": {k: v.to_record() for k, v in sorted(self.judge_identities.items())}}

    @property
    def agent_identity_required(self) -> bool:
        return self.pki is not None and self.deployment.is_enterprise and self.pki.config.require_agent_identity

    def _check_agent(self, rec: dict, proposal: str, args: dict, assertion: Any) -> str | None:
        """None if the agent check passes (or isn't required); otherwise the deny reason."""
        if assertion is None:
            if self.agent_identity_required:
                self.ledger.append("agent_identity", {"ok": False, "reason": "agent_identity_required"})
                return "agent_identity_required"
            return None
        if self.pki is None:
            self.ledger.append("agent_identity", {"ok": False, "reason": "no_pki_configured"})
            return "agent_identity_rejected:no_pki_configured"
        digest = _pki.request_digest(rec, proposal, args_hash(rec["tool"], args, "sha384", self.crypto), self.crypto)
        try:
            ident = _pki.verify_agent_assertion(self.pki, assertion, digest, self._agent_nonces)
        except _pki.PkiError as e:
            reason = getattr(e, "reason", type(e).__name__)
            self.ledger.append("agent_identity", {"ok": False, "reason": reason, "detail": str(e)[:300]})
            return f"agent_identity_rejected:{reason}"
        self.ledger.append("agent_identity", {"ok": True, "identity": ident.to_record(),
                                              "nonce": str(assertion.get("nonce")), "request_digest": digest})
        return None

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
            "deployment": {**self.deployment.to_record(),
                           "anchor": None if self.anchor is None else self.anchor.describe()},
            **({"identity": self.identity_record()} if self.pki is not None else {}),
            **extra,
        })

    def reload_constitution(self, signed_constitution: dict, *, acknowledge: bool = False) -> None:
        """Load a new constitution. Only a document signed by the principal's trusted key is accepted.

        A change to the text or the hard rules is refused unless ``acknowledge`` is true. That is a
        separate principal action from the agent's request. A refused reload is recorded as
        ``constitution_reload_refused`` and re-raised. On success a new constitution_loaded entry is
        appended; tokens issued before it are refused by the gateway.
        """
        try:
            c = verify_signed(signed_constitution, self.trusted_keyset, self.crypto)
            if c.principal != self.principal:
                raise TwoKeyConfigError("reloaded constitution names a different principal")
            changed = c.text != self.constitution.text or c.hard_rules != self.constitution.hard_rules
            if changed and not acknowledge:
                raise TwoKeyConfigError("constitution change requires a separate principal acknowledgement")
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
                "token_mode": self.token_mode, "encoding": ENCODING, "fips_mode": self.crypto.fips_mode,
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
        return ToolGateway(self._gateway_issuer, self.ledger, self.principal, tools, extractors, digest_alg=self.digest_alg,
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
        self._emit_siem(False, reason, action_rec)
        return Decision(False, reason, ledger_digest=self.ledger.root(), action=action_rec, **kw)

    def _emit_siem(self, allowed: bool, reason: str, action_rec: dict | None) -> None:
        """Enterprise only. A down SIEM is recorded and does not change the decision."""
        if not self.deployment.is_enterprise or not self.siem_host:
            return
        tool = None if not isinstance(action_rec, dict) else action_rec.get("tool")
        digest = self._h(action_rec) if action_rec else None
        event = {"kind": "decision", "allowed": bool(allowed), "reason": reason,
                 "tool": tool, "action_digest": digest, "ledger_root": self.ledger.root()}
        ok = siem.send(self.siem_host, self.siem_port, event, cafile=self.siem_cafile)
        try:
            self.ledger.append("siem_delivery", {"ok": ok, "host": self.siem_host, "port": self.siem_port})
        except Exception:
            pass


    def _freeze_agent_session(self, env_name: str | None):
        """Read monitored-agent credentials once. The caller cannot supply them.

        A cloud judge must not reuse any configured agent credential. Hosting
        is not trust: a vendor agent is still untrusted. The legacy env var
        remains for one external agent.
        """
        tokens = set()
        if env_name:
            value = os.environ.get(env_name)
            if not value:
                raise TwoKeyConfigError(f"agent_session_env {env_name} is not set")
            tokens.add(value)
        for agent in self.agents.values():
            if not agent.is_cloud():
                continue
            token = agent.credential_token()
            if not token:
                raise TwoKeyConfigError(f"cloud agent {agent.agent_id} has no credential")
            tokens.add(token)
        cloud = any(getattr(j, "is_cloud", lambda: False)() for j in self.judges)
        if cloud and not tokens:
            raise TwoKeyConfigError("a cloud judge requires agent_session_env, or a configured cloud agent credential")
        if len(tokens) == 1 and not self.agents:
            return next(iter(tokens))
        return frozenset(tokens) if tokens else None

    def _agent_failure(self, agent_id: str, error: str, instruction: str | None = None,
                       provider: str | None = None, hosting: str | None = None) -> Decision:
        body = {"agent_id": agent_id, "ok": False, "error": error}
        if provider:
            body["provider"] = provider
        if hosting:
            body["hosting"] = hosting
        if isinstance(instruction, str):
            body["instruction_len"] = len(instruction)
            body["instruction_digest"] = digest_hex(instruction.encode("utf-8", "surrogatepass"),
                                                    self.digest_alg, self.crypto)
        self.ledger.append("agent_proposal", body)
        try:
            self.ledger.checkpoint()
        except Exception:
            return Decision(False, "internal_error:ledger_checkpoint", ledger_digest=self.ledger.root())
        return Decision(False, error if error == "unknown_agent" else f"agent_proposal_rejected:{error}",
                        ledger_digest=self.ledger.root())

    def authorize_from_agent(self, agent_id: str, instruction: str, agent_assertion: Any = None) -> Decision:
        """Ask a configured agent for one proposal, then authorize it.

        The agent may be local or a vendor model. It sees the constitution and
        an escaped instruction. The proposal is untrusted and cannot execute a
        tool. A malformed reply is a deny. The instruction itself is not written
        to the ledger; only its digest is, on failure.
        """
        agent = self.agents.get(agent_id)
        if agent is None:
            return self._agent_failure(agent_id, "unknown_agent", instruction)
        try:
            proposed = agent.complete(instruction, self.constitution_text)
        except Exception as e:
            return self._agent_failure(agent_id, type(e).__name__, instruction, agent.provider, agent.hosting)
        return self.authorize(proposed.action, proposed.proposal, proposed.tool_args, agent_assertion,
                              agent_meta=proposed.to_record())

    def authorize(self, proposed: Action | Mapping[str, Any], proposal: str,
                  tool_args: Mapping[str, Any] | None = None, agent_assertion: Any = None,
                  *, agent_meta: Mapping[str, Any] | None = None) -> Decision:
        """``agent_assertion``: from ``pki.sign_agent_request`` (required in enterprise mode by default)."""
        try:
            d = self._authorize(proposed, proposal, {} if tool_args is None else tool_args, agent_assertion, agent_meta)
        except Exception as e:  # spec 5.7: no best-effort allow; the ledger or any component failing means deny
            d = Decision(False, f"internal_error:{type(e).__name__}", ledger_digest=self.ledger.root())
        try:
            self.ledger.checkpoint()  # one signed head per decision
        except Exception as e:
            if d.allowed:  # never release a token whose decision is not covered by a signed head
                return Decision(False, f"internal_error:ledger_checkpoint:{type(e).__name__}",
                                ledger_digest=self.ledger.root())
        return d

    def _h(self, action_record: Any) -> str:
        """H(action record) for ballots and decisions: two-key-enc/2 under the action-record label."""
        return typed_hash(action_record, DOMAIN_ACTION_RECORD, self.digest_alg, self.crypto)

    def _authorize(self, proposed, proposal: str, tool_args: Mapping[str, Any], agent_assertion: Any = None,
                   agent_meta: Mapping[str, Any] | None = None) -> Decision:
        if not isinstance(proposal, str):
            proposal = str(proposal)
        # Read the tool args once (F_REVIEW finding 1): the logged args and args_hash come from the same bytes.
        try:
            frozen, frozen_error = freeze_call("", tool_args), None
            logged_args = _safe_record(frozen.args())
        except (TypeError, ValueError) as e:
            frozen, frozen_error, logged_args = None, e, _safe_record(tool_args)
        proposal_entry = {"action_input": _safe_record(proposed), "proposal": proposal,
                          "proposal_digest": digest_hex(proposal.encode("utf-8", "surrogatepass"),
                                                        self.digest_alg, self.crypto),
                          "proposal_digest_alg": self.digest_alg,
                          "tool_args": logged_args}
        if agent_meta:
            proposal_entry["agent"] = {k: agent_meta.get(k) for k in ("agent_id", "provider", "hosting", "model")}
        self.ledger.append("proposal", proposal_entry)
        try:
            action = normalize_action(proposed)
            if frozen_error is not None:
                raise frozen_error
            a_hash = args_hash(action.tool, frozen.args(), self.digest_alg, self.crypto)
        except (ActionValidationError, TypeError, ValueError) as e:
            return self._deny(f"invalid_action:{e}")
        rec = action.to_record()
        mismatch = disagreement(rec, frozen.args())
        if mismatch:
            return self._deny(f"record_args_mismatch:{mismatch}", rec)
        binding = self.ballot_binding(rec)
        self.ledger.append("action_normalized", {"action": rec, "action_digest": binding["action_hash"],
                                                 "args_hash": a_hash})
        agent_denied = self._check_agent(rec, proposal, frozen.args(), agent_assertion)
        if agent_denied is not None:
            return self._deny(agent_denied, rec)

        path_a_responded = False
        try:
            vm_res = self.vm.eval(action)
            path_a_responded = True
            self.ledger.append("vm_result", {"allowed": vm_res.allowed, "reason": vm_res.reason,
                                             "steps": vm_res.steps, "denied_by": vm_res.denied_by})
        except Exception as e:
            vm_res = None
            self.ledger.append("vm_result", {"allowed": None, "reason": f"no_response:{type(e).__name__}"})
        q = convene(self.judges, self.constitution_text, action, proposal, self.quorum_policy, binding, frozen.args(), self._agent_session)
        self.ledger.append("quorum_result", q.to_record())
        qsum = {"yes": q.yes, "no": q.no, "abstain": q.abstain, "reason": q.reason}
        path_b_responded = bool(q.counted)
        if not path_a_responded:
            return self._deny("path_a_no_response", rec, vm_allowed=False, quorum_passed=q.passed, quorum=qsum)
        if not path_b_responded:
            return self._deny(f"path_b_no_response:{q.reason}", rec, vm_allowed=vm_res.allowed,
                              vm_reason=vm_res.reason, denied_by_rule=vm_res.denied_by,
                              quorum_passed=False, quorum=qsum)
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
            "jti": p["jti"], "token_digest": cap.token_digest(self.digest_alg, self.crypto), "tool": p["tool"],
            "scope": p["scope"], "args_hash": p["args_hash"], "args_enc": p["args_enc"], "expires_at": p["expires_at"], "ledger_root": p["ledger_root"],
            "ledger_size": p["ledger_size"], "ledger_merkle_root": p["ledger_merkle_root"],
            "bytecode_hash": p["bytecode_hash"], "nl_hash": p["nl_hash"]})
        self.ledger.append("decision", {"allowed": True, "reason": "dual_path_pass", "denied_by_rule": None,
                                        "action_digest": binding["action_hash"]})
        self._emit_siem(True, "dual_path_pass", rec)
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
