# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Two-Key: a tool call runs only if Path A and Path B both allow.

``authorize_from_agent`` runs both paths once the call is well-formed and within limits,
and does not execute tools. A malformed or oversized call is an early deny before either path.
Hosting (local or cloud) is recorded and never treated as trust.

``TwoKey`` refuses to start (``TwoKeyConfigError``) with no judge, with no
Path B deadline, with duplicate judge ids, without an operator declaration
of the monitored agent (``monitored_agent_required:``), or when a judge
holds the monitored agent's credential (the same API token, or the same
username and password) at any address, sent or not, or when neither side
sends a credential on one address (``judge_matches_agent:``; see identity.py).
"""

from __future__ import annotations

import os
import sys
import threading
from dataclasses import dataclass, asdict, replace
from typing import Any, Mapping

from .action import Action, ActionValidationError, normalize_action
from .audit import identities_digest, policy_digest
from .canonical import (MAX_INPUT_DEPTH, EncodingError, OversizeError, canonical_bytes, canonical_hash, digest_hex,
                        to_plain)
from .agents import MAX_PROPOSAL_TEXT_CHARS, AgentConfigError, AgentDeclined, parse_proposal, tool_vocabulary
from .agent_meta import (AgentMetadataError, REASON_LEDGER_BODY, cap_ledger_text, check_agent_meta_field,
                         ledger_agent_record, normalize_origin, type_tag)
from .capability import (CapabilityIssuer, CapabilityKeyError, capability_key_fingerprint, open_capability_key,
                         valid_ttl)
from .compiler import CompiledConstitution, compile_both
from .constitution import Constitution, ConstitutionError, verify_signed
from .identity import (AgentDeclaration, IdentityError, PASSWORD_FINGERPRINT_ALG, SeparationReport, check_separation,
                       configured_agent_identity, configured_agent_secrets, fingerprint_key_id, judge_identity)
from .derive import (MAX_ACTION_BYTES, MAX_ARGS_BYTES, DeriveError, args_size, args_too_large, blocked_from_rules, canonical_too_large,
                     derive, disagreement, disallowed_party, dropped_keys, form_for, size_record)
from .fields import defaults as field_defaults
from .gateway import ToolGateway, mark_two_key_ledger
from .ledger import LedgerError
from .policy_vm import PolicyVM
from .quorum import QuorumPolicy, check_judge_set, convene, lone_judge_warning, unmeetable_floor
from .scan import CLIENT_BUDGET_SECONDS, FileDeniedError, Outcome, ScanConfigError, Scanner
from .siem import RefusedTokens, SiemConfig, start_delivery as start_siem
from .writable import WritablePathsError, check as check_writable, report as report_writable, resolve_mode


class TwoKeyConfigError(ValueError):
    """Two-Key refuses to start with this configuration."""


# The start-up note that no content scanner is configured is said once per process, not once per TwoKey.
_no_scanner_noted = threading.Event()


def resolve_facts(resolver: Any, tool: Any, arguments: Any) -> Mapping[str, Any] | None:
    """``resolver(tool, copy of arguments)``. Any failure supplies no facts; the type goes to stderr only."""
    try:
        copy = to_plain(arguments, max_depth=MAX_INPUT_DEPTH, what="tool args are", max_items=MAX_ARGS_BYTES // 2)
        return resolver(tool, copy)
    except Exception as e:      # trusted code that failed: the call denies on the missing fact, never runs
        print(f"two-key: fact resolver failed: {type_tag(e)}", file=sys.stderr)
        return None


_DERIVE_DENIALS = {"amount_mismatch", "counterparty_mismatch", "irreversible_mismatch"}


def _unmeasured(name: str) -> dict:
    """The ledger record for an input that stopped copying past its cap: no size or digest was computed."""
    return {f"{name}_size": -1, f"{name}_digest": None, f"{name}_omitted": True}


def _derive_deny(reason: str | None) -> bool:
    return bool(reason) and (reason.startswith("derive_failed:") or reason in _DERIVE_DENIALS)


@dataclass
class Decision:
    allowed: bool
    reason: str
    token: str | None
    path_a: dict
    path_b: dict
    ledger_size: int
    agent: dict | None = None

    @property
    def token_jti(self) -> str | None:
        """The token id, read from the token body (not verified here; the gateway verifies)."""
        if not self.token:
            return None
        try:
            import base64
            from .strict import loads_json
            body = self.token.split(".")[1]
            return loads_json(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))["jti"]
        except Exception:
            return None

    @property
    def token_digest(self) -> str | None:
        """``capability_issued.token_hash`` in the ledger. Safe to print; it cannot be redeemed."""
        return canonical_hash(self.token) if self.token else None

    def to_record(self) -> dict:
        """A printable record. The bearer token is replaced by its jti and digest; use ``.token``."""
        rec = asdict(self)
        rec.pop("token")
        rec["token_jti"], rec["token_digest"] = self.token_jti, self.token_digest
        return rec


def _serial_history(ledger) -> tuple[str | None, int | None, set]:
    """From the ledger's ``constitution_loaded`` entries: the digest it last ran, the highest serial it has run
    (None if none had a serial), and every digest it ran under that serial."""
    last_digest, top, top_digests = None, None, set()
    for entry in getattr(ledger, "entries", ()):
        if entry.kind != "constitution_loaded":
            continue
        last_digest = entry.body.get("digest")
        serial = entry.body.get("serial")
        if not isinstance(serial, int) or isinstance(serial, bool):
            continue
        if top is None or serial > top:
            top, top_digests = serial, set()
        if serial == top:
            top_digests.add(entry.body.get("digest"))
    return last_digest, top, top_digests


def check_constitution_order(ledger, constitution: Constitution) -> str | None:
    """Refuse a constitution older than one this ledger has run; return the digest the ledger last ran, if any.

    The order is the principal's signed ``serial`` (live run 9x, C44: an older constitution signed with the same
    key, put back). Once a ledger has run a constitution with a serial, a lower serial is refused
    (``constitution_rollback``), the same serial with other bytes is refused (``constitution_serial_reused``),
    and a constitution with no serial is refused (``constitution_serial_missing``). A ledger that has never run
    one with a serial accepts any; there is no setting that turns the check off. To go back to older rules, sign
    them again with a higher serial.
    """
    last_digest, top, top_digests = _serial_history(ledger)
    if top is None:
        return last_digest
    serial = constitution.serial
    if serial is None:
        raise TwoKeyConfigError(f"constitution_serial_missing: this ledger has run serial {top}; a constitution "
                                "without a serial could be an older one. Sign it with a serial above "
                                f"{top} (docs/SETTINGS.md, serial)")
    if serial < top:
        raise TwoKeyConfigError(f"constitution_rollback: this constitution is serial {serial}, and this ledger has "
                                f"run serial {top}. To go back to older rules, sign them again with a serial above "
                                f"{top}")
    if serial == top and constitution.digest not in top_digests:
        raise TwoKeyConfigError(f"constitution_serial_reused: this ledger has run another constitution as serial "
                                f"{serial}; sign this one with a serial above {top}")
    return last_digest


class TwoKey:
    def __init__(self, ledger, public_key, constitution: Constitution, judges: list, *,
                 private_key=None, quorum: QuorumPolicy | None = None, ttl_seconds: int = 120,
                 allow_test_doubles: bool = False, clock=None, monitored_agent: Any = None,
                 scanner: Scanner | None = None, on_writable_paths: str | None = None, check_paths=(),
                 siem: Any = None):
        if not allow_test_doubles and any(getattr(j, "is_test_double", False) for j in judges):
            raise ValueError("test-double judges refused; pass allow_test_doubles=True only for offline tests")
        if not constitution.specs_enforced:
            raise ConstitutionError("tool_specs required")
        self.ledger = ledger
        self.public_key = public_key
        self.private_key = private_key
        self.constitution = constitution
        # Before anything is written: a constitution older than one this ledger has run is refused (run 9x, C44).
        self._previous_digest = check_constitution_order(ledger, constitution)
        self.compiled: CompiledConstitution = compile_both(
            constitution.prose, constitution.hard_rules, constitution.tool_specs,
            specs_enforced=True, fields=constitution.fields)
        self.vm = PolicyVM(self.compiled.bytecode)
        self.judges = list(judges)
        if not self.judges:
            # Fail closed: with no judge, Path B can never turn its key.
            raise TwoKeyConfigError("no_judges: configure at least one Path B judge")
        judge_ids = [getattr(j, "judge_id", None) for j in self.judges]
        if any(not isinstance(i, str) or not i for i in judge_ids) or len(set(judge_ids)) != len(judge_ids):
            # Ballots are matched to judges by id; a shared id lets one judge's ballot stand in for another's.
            raise TwoKeyConfigError("duplicate_judge_id: judge ids must be unique, non-empty strings")
        self.quorum = (quorum or QuorumPolicy()).resolved(len(self.judges))
        unmeetable = unmeetable_floor(self.judges, self.quorum)
        if unmeetable:
            # Never met: every authorize would deny, after sending the call to every judge (#54).
            raise TwoKeyConfigError(f"{unmeetable}: the quorum policy (required_yes={self.quorum.required_yes}, "
                                    f"min_responding={self.quorum.effective_min_responding}, min_distinct_providers="
                                    f"{self.quorum.min_distinct_providers}) cannot be met by these judges")
        if self.quorum.timeout_seconds is None:
            # Fail closed on a hung judge: every round ends by the deadline, and a late judge abstains.
            raise TwoKeyConfigError("Path B needs a hard deadline: quorum timeout_seconds must be a positive "
                                    "number, not None")
        check_judge_set(self.judges, self.quorum)
        self._check_writable(on_writable_paths, check_paths)
        self.scanner = self._check_scanner(scanner)
        self.siem = self._check_siem(siem)
        self.delivery = None
        self.refused_tokens = None
        lone = lone_judge_warning(self.judges, self.quorum)
        if lone:      # allowed, and recorded in quorum_policy; said once, so the operator sees it (run 6x, X03)
            print(f"two-key: WARNING: {lone}", file=sys.stderr)
        # Judge != monitored agent, from operator configuration only (identity.py): refused on the agent's
        # credential at any address, or keyless on the agent's keyless address; likely accidents are warned on
        # stderr and recorded below.
        self.separation = self._check_separation(monitored_agent, allow_test_doubles)
        # The resolved identities are written once, in constitution_loaded; every decision entry
        # carries the digest of the policy in effect (policy_digest) and of those identities (identities_digest).
        sep = self.separation.to_record()
        self._identities_digest = identities_digest(sep)      # recomputable: two_key.audit
        sep = {**sep, "identities_digest": self._identities_digest,
               "credential_fingerprint": {"alg": "hmac-sha256", "password_alg": PASSWORD_FINGERPRINT_ALG,
                                          "key_id": fingerprint_key_id(self._fp_key),
                                          "input": "every credential a side holds, sent or not, with surrounding "
                                                   "whitespace stripped; PBKDF2-HMAC-SHA256 for a secret that "
                                                   "contains ':' (a username and password as one username:password "
                                                   "pair, or a token holding one), HMAC-SHA256 otherwise"}}
        # The full policy is in constitution_loaded (quorum_policy); each decision carries its digest.
        self._policy_digest = policy_digest(self.quorum.to_record())
        self._decision_context = {"policy_digest": self._policy_digest,
                                  "identities_digest": self._identities_digest}
        try:
            valid_ttl(ttl_seconds)       # an int in 1..MAX_TTL_SECONDS (300); NaN, inf, floats refused
        except ValueError as e:
            raise TwoKeyConfigError(f"ttl_out_of_range: {e}") from None
        self.ttl_seconds = ttl_seconds
        # The minting key is not the principal key, and it is not given to the gateway.
        # max_ttl_seconds: verify() refuses any token that lives longer than this TwoKey's TTL.
        self.issuer = None
        if not private_key and self._has_capability_key(ledger):
            # Its constitution_loaded would pin no capability key. Once tokens exist (issued before it, or by a
            # keyed TwoKey still running), every later keyed start would refuse with capability_key_unpinned (#48).
            raise TwoKeyConfigError("keyless_start_refused: a TwoKey with private_key= has run on this ledger; a "
                                    "start without it would record no capability key and block later keyed "
                                    "starts. Pass private_key=")
        if private_key:
            try:
                cap_key = open_capability_key(ledger, public_key)
            except CapabilityKeyError as e:
                raise TwoKeyConfigError(str(e)) from e
            self.issuer = CapabilityIssuer(cap_key, clock=clock, max_ttl_seconds=ttl_seconds)
        self._clock = clock
        # The supported deployment: the gateway runs in this process on this ledger object (#45).
        mark_two_key_ledger(ledger)
        with self.ledger.exclusive():
            self._record_loaded(constitution, sep)
        self._start_siem()

    def _record_loaded(self, constitution: Constitution, sep: dict) -> None:
        """Write ``constitution_loaded`` and its checkpoint. The caller holds the ledger's write lock, which read
        what other processes appended first: the order check runs again on that, so two proxies started at once
        on one ledger cannot both record the same serial with different rules (run 9y, S6c)."""
        self._previous_digest = check_constitution_order(self.ledger, constitution)
        self.ledger.append("constitution_loaded", {
            "digest": constitution.digest,
            "bytecode_hash": self.compiled.bytecode_hash,
            "nl_hash": self.compiled.nl_hash,
            "spec_hash": self.compiled.spec_hash,
            "quorum_policy": self.quorum.to_record(),
            "policy_digest": self._policy_digest,
            # The gateway pins this: a token key that is not this one does not redeem.
            "capability_key_fingerprint": (None if self.issuer is None
                                           else capability_key_fingerprint(self.issuer.public_key)),
            "judge_agent_separation": sep,
            # The deprecated opt-in (QuorumPolicy.allow_same_model_distinct_tenant), recorded as set. It lifts
            # nothing now, so the pairs list is always empty; both keys stay so the entry keeps its shape.
            "same_model_tenant_optin": self.quorum.allow_same_model_distinct_tenant,
            "same_model_tenant_optin_pairs": list(self.separation.tenant_optin_pairs),
            # Present only with a content scanner, so a setup without one records exactly what it did before.
            **({"scanner": self.scanner.to_record()} if self.scanner is not None else {}),
            # Present only for a constitution with a serial, for the same reason (live run 9x, C44).
            **({"serial": constitution.serial, "previous_digest": self._previous_digest}
               if constitution.serial is not None else {}),
        })
        self.ledger.checkpoint()

    def agent_vocabulary(self, tools: list[str] | None = None) -> str:
        """Text for ``MonitoredAgent.complete(vocabulary=...)``: signed tool ids, argument paths, value
        syntax, floors, and data classes; never a value. ``tools`` limits it to one task's tools.
        Opt-in; it goes to the agent's host. It grants nothing and changes neither path."""
        return tool_vocabulary(self.constitution, tools)

    def gateway(self, tools: dict | None = None, **kw) -> ToolGateway:
        """The supported way to build the gateway: in this process, on this ledger object (#45).

        The gateway gets the capability public key only (a verifier), never ``self.issuer``. That is an
        API property, not isolation: this process also holds the minting key, the principal, witness,
        and ledger keys, and the registered tools run here. A gateway in another process or on another
        host is not supported.
        """
        if self.issuer is None:
            raise TwoKeyConfigError("no_issuer_key: a TwoKey started without private_key= issues no tokens, "
                                    "so it has no gateway")
        kw.setdefault("refused_tokens", self.refused_tokens)
        return ToolGateway(self.ledger, self.issuer.verifier(), self.compiled, tools=tools, scanner=self.scanner,
                           **kw)

    def _check_siem(self, siem: Any):
        """The SIEM export settings (``two_key/siem.py``), checked at start. Deployment, not policy.

        Plaintext syslog (UDP or TCP) and an ``http://`` webhook are refused under ``high_assurance`` and
        allowed elsewhere with a warning (maintainer's decision, 2026-10-16). A collector that cannot be
        reached is a warning too: the ledger keeps every entry, and the copy catches up from its cursor,
        so no decision waits on a SIEM.
        """
        if siem is None:
            return None
        if not isinstance(siem, SiemConfig):
            raise TwoKeyConfigError("siem_invalid: pass a two_key.siem.SiemConfig")
        plaintext = siem.plaintext_sinks
        if plaintext and self.quorum.is_high_assurance:
            raise TwoKeyConfigError(f"siem_plaintext_refused: high_assurance does not send the ledger copy "
                                    f"in the clear; {plaintext} use syslog over TLS (6514) or an https "
                                    "webhook")
        if plaintext:
            print(f"two-key: WARNING: the SIEM copy goes out in the clear to {plaintext}; anyone on the "
                  "path can read the tool names, outcomes, and reason codes, or forge entries. Use "
                  "transport: tls (port 6514) or an https:// webhook", file=sys.stderr)
        return siem

    def _start_siem(self) -> None:
        """Record where the copy goes, then start the sender. Both after ``constitution_loaded``, so the
        SIEM sees that entry too."""
        if self.siem is None:
            return
        self.ledger.record("siem_configured", self.siem.record())
        self.delivery = start_siem(self.siem, self.ledger)
        self.refused_tokens = RefusedTokens(
            interval_seconds=self.siem.refused_token_interval_seconds,
            report=lambda counts: self.delivery.report("gateway_token_refused", counts))

    def close(self) -> None:
        """Stop the SIEM sender, after a last pass. Idempotent; a ``TwoKey`` without one does nothing.

        Whatever has not gone out yet is still in the ledger, and the next start sends it from the cursor.
        """
        if self.refused_tokens is not None:
            self.refused_tokens.flush()
        if self.delivery is not None:
            self.delivery.close()

    def _check_writable(self, mode: str | None, paths) -> None:
        """Paths another account could change (two_key/writable.py): this interpreter's program, import path,
        and loaded modules, and ``check_paths`` (paths, or ``(path, "file" | "folder")`` pairs, such as the
        integration's own settings). Named on stderr; with ``on_writable_paths="refuse"``, or a
        high_assurance quorum, refused before anything is written to the ledger."""
        try:
            mode = resolve_mode(mode, self.quorum.is_high_assurance)
        except ValueError as e:
            raise TwoKeyConfigError(str(e)) from None
        targets = []
        for item in paths:
            path, rule = item if isinstance(item, tuple) else (item, None)
            path = os.fspath(path)
            rule = rule or ("folder" if os.path.isdir(path) else "file")
            if rule not in ("file", "folder"):
                raise TwoKeyConfigError(f"check_paths: {path}: expected file or folder, got {rule!r}")
            targets.append((path, rule))
        why = "high_assurance" if self.quorum.is_high_assurance else "on_writable_paths: refuse"
        try:
            report_writable(check_writable(targets), mode, why=why)
        except WritablePathsError as e:
            raise TwoKeyConfigError(str(e)) from None

    def _check_scanner(self, scanner: Any) -> Scanner | None:
        """Check the content scanner against the signed constitution, and say what it scans (scan.py)."""
        if scanner is None:
            if not _no_scanner_noted.is_set():
                _no_scanner_noted.set()
                print("two-key: note: no content scanner (antivirus or DLP) is configured; see docs/SCANNERS.md",
                      file=sys.stderr)
            return None
        if not isinstance(scanner, Scanner):
            raise TwoKeyConfigError("scanner_invalid: pass a two_key.scan.Scanner")
        try:
            notes = scanner.bind(self.compiled)
        except ScanConfigError as e:
            raise TwoKeyConfigError(str(e)) from None
        for note in notes:
            print(f"two-key: note: {note}", file=sys.stderr)
        budget = scanner.timeout_seconds + float(self.quorum.timeout_seconds or 0)
        if budget > CLIENT_BUDGET_SECONDS:
            print(f"two-key: WARNING: the scan limit ({scanner.timeout_seconds:g} s) plus the judges' deadline "
                  f"({self.quorum.timeout_seconds:g} s) is over {CLIENT_BUDGET_SECONDS:g} s; MCP clients often give "
                  "up on a tool call after 60 s", file=sys.stderr)
        if self.quorum.is_high_assurance and scanner.stance != "strict":
            print(f"two-key: WARNING: high_assurance with the {scanner.stance} scan stance: an unavailable scanner "
                  "lets calls through to the two keys; sign the strict rule (deny flagged and unavailable)",
                  file=sys.stderr)
        return scanner

    def _scan(self, tool: str, arguments: Any, proposal: Any,
              encrypted_pass: bool = False) -> tuple[Outcome, tuple[str, dict] | None]:
        """Scan one call (Two-Key starts it; the agent cannot). Also returns the ledger entry for the scanner
        going down or coming back, said once each on stderr, never once per call. Raises ``FileDeniedError``
        before the scanner is called when a declared file cannot be read or the call is over a file limit."""
        scanner = self.scanner
        outcome = scanner.run(tool, scanner.prepare(tool, arguments, proposal), encrypted_pass=encrypted_pass)
        change = scanner.transition(outcome.available)
        if change == "down":
            print(f"two-key: WARNING: the content scanner is unavailable ({outcome.error or 'no answer'}); calls "
                  f"go on under the {scanner.stance} stance until it answers again", file=sys.stderr)
            return outcome, ("scanner_unavailable", {"scanner": scanner.label, "error": outcome.error,
                                                     "stance": scanner.stance})
        if change == "up":
            print("two-key: the content scanner is answering again", file=sys.stderr)
            return outcome, ("scanner_recovered", {"scanner": scanner.label})
        return outcome, None

    @staticmethod
    def _has_capability_key(ledger) -> bool:
        if any(e.kind == "capability_issued" for e in getattr(ledger, "entries", ())):
            return True
        path_of = getattr(ledger, "capability_key_path", None)
        return callable(path_of) and os.path.lexists(path_of())

    def _check_separation(self, monitored_agent: Any, allow_test_doubles: bool) -> SeparationReport:
        """Refuse to start if any judge could be the monitored agent. See identity.py."""
        if monitored_agent is None:
            raise TwoKeyConfigError("monitored_agent_required: declare the monitored agent (monitored_agent= "
                                    "with model, provider, base_url, and credential_env, username_env with "
                                    "password_env, or credential: none) whenever judges are configured")
        decls = monitored_agent if isinstance(monitored_agent, (list, tuple)) else [monitored_agent]
        # A placeholder in-process agent proves nothing about a real judge, so it is accepted only
        # when every judge is a test double too (an offline test). With a real judge, declare the real agent.
        allow_in_process = allow_test_doubles and all(getattr(j, "is_test_double", False) for j in self.judges)
        try:
            self._fp_key = key = self.ledger.fingerprint_key()   # per-install HMAC key; fingerprints only
        except LedgerError as e:
            raise TwoKeyConfigError(str(e)) from e
        try:
            agents = []
            sources = []
            for d in decls:
                if isinstance(d, AgentDeclaration) or isinstance(d, Mapping):
                    if not isinstance(d, AgentDeclaration):
                        d = AgentDeclaration.from_mapping(d)
                    sources.append(d)
                    agents.append(d.resolve(allow_in_process=allow_in_process, fp_key=key))
                elif all(hasattr(d, k) for k in ("agent_id", "model", "base_url", "credential")):
                    sources.append(d)   # a MonitoredAgent; its credential is re-read at call time
                    agents.append(configured_agent_identity(d, key))
                else:
                    raise IdentityError("monitored_agent must be a mapping, an AgentDeclaration, or a MonitoredAgent")
            self._agent_sources = sources
            judges = [judge_identity(j, key) for j in self.judges]
            return check_separation(agents, judges, self.quorum.allow_same_provider_judge,
                                    allow_same_model_distinct_tenant=self.quorum.allow_same_model_distinct_tenant)
        except IdentityError as e:
            raise TwoKeyConfigError(str(e)) from e

    @classmethod
    def load(cls, ledger, public_key, envelope: dict, judges: list, **kw) -> "TwoKey":
        return cls(ledger, public_key, verify_signed(envelope, public_key), judges, **kw)

    def authorize(self, action: dict, arguments: dict, proposal: str, *,
                  agent_id: str | None = None, hosting: str | None = None,
                  agent_session: str | None = None, origin: str = "library",
                  facts: Mapping[str, Any] | None = None) -> Decision:
        """Run both paths once the call is well-formed and within limits. Any exception is a deny that is written to the ledger (``internal_error:``).

        ``origin`` is recorded on the decision entry (the CLI passes ``"cli"``).
        ``origin``, ``agent_id``, and ``hosting`` are operator/library metadata for the
        ledger (at most 256 characters after strip; non-str refused). They are not trust.

        ``facts`` holds the caller-supplied facts (``source: caller`` fields) the tool maps: trusted values
        from the integration, never from the agent. A fact the agent wrote, a missing fact, or an unknown one
        is a ``derive_failed:`` deny; both paths still run. Pass the same facts to ``gateway.invoke``.
        """
        try:
            origin = normalize_origin(origin)
        except AgentMetadataError as e:
            # Fail closed: never echo the bad origin onto the ledger.
            return self._deny(None, e.reason, None, None, None, e.detail)
        try:
            agent = ledger_agent_record(agent_id, hosting)
        except AgentMetadataError as e:
            return self._deny(origin, e.reason, None, None, None, e.detail)
        try:
            return self._authorize(action, arguments, proposal, agent=agent,
                                   agent_session=agent_session, origin=origin, facts=facts)
        except Exception as e:  # fail closed: no exception reaches the caller as anything but a deny
            return self._deny(origin, f"internal_error:{type_tag(e)}", agent, None, None)

    def _authorize(self, action: dict, arguments: dict, proposal: str, *,
                   agent: dict | None = None,
                   agent_session: str | None = None, origin: str = "library",
                   facts: Mapping[str, Any] | None = None) -> Decision:
        # agent was built by authorize()/authorize_from_agent via ledger_agent_record
        # (type and 256-char caps). Hosting is a deployment fact, not a trust decision.
        # The raw claim is measured before anything reads it: an oversized one keeps only size and digest.
        # Each input is copied once into built-in types (any Mapping becomes a dict), and everything below
        # reads only the copy: a custom Mapping cannot be sized by its str() and then read as 5 MB.
        # Depth first, so a claim nested too deeply is malformed_action on every Python version.
        # MAX_INPUT_DEPTH leaves room for the levels the claim gains inside a judge's record or the ledger.
        claim = action.to_record() if isinstance(action, Action) else action
        try:
            claim = to_plain(claim, max_depth=MAX_INPUT_DEPTH, what="action claim is",
                             max_items=MAX_ACTION_BYTES // 2)
        except OversizeError:
            return self._deny(origin, "action_too_large", agent, None, None, _unmeasured("action"))
        except EncodingError as e:
            why = cap_ledger_text(str(e))
            return self._deny(origin, f"malformed_action:{why}", agent, None, None,
                              {"action_omitted": True, "action_error": why})
        claim_size = args_size(claim)
        if claim_size < 0 or claim_size > MAX_ACTION_BYTES:
            return self._deny(origin, "action_too_large", agent, None, None, size_record(claim, "action"))
        try:
            normalized = normalize_action(claim)
        except ActionValidationError as e:   # the message names the field, never its value
            return self._deny(origin, f"malformed_action:{e}", agent, None, None)
        try:
            arguments = to_plain(arguments, max_depth=MAX_INPUT_DEPTH, what="tool args are",
                                 max_items=MAX_ARGS_BYTES // 2)
        except OversizeError:
            return self._deny(origin, "args_too_large", agent, None, None, _unmeasured("tool_args"))
        except EncodingError as e:     # invalid_call:<why>, the same as the gateway's
            why = cap_ledger_text(str(e))
            return self._deny(origin, f"invalid_call:{why}", agent, None, None,
                              {"tool_args_omitted": True, "tool_args_error": why})
        if isinstance(arguments, Mapping):
            # Freeze the arguments to the canonical bytes a token would bind, before the size check:
            # a value that cannot be encoded (nested too deeply, NaN, a non-string key) is
            # invalid_call on every Python version, not args_too_large where the sizer recursed out.
            try:
                frozen = canonical_bytes(arguments, max_depth=MAX_INPUT_DEPTH, what="tool args are")
            except EncodingError as e:     # invalid_call:<why>, the same as the gateway's
                why = cap_ledger_text(str(e))
                return self._deny(origin, f"invalid_call:{why}", agent, None, None,
                                  {"tool_args_omitted": True, "tool_args_error": why})
            # Encoded once: these bytes settle the size cap and give the digest the token binds.
            oversized = canonical_too_large(frozen, arguments)
            frozen_digest = digest_hex(frozen)
        else:
            oversized, frozen_digest = args_too_large(arguments), None
        # Before anything is derived, judged, or ledgered: only the size and digest are kept.
        if oversized:
            return self._deny(origin, "args_too_large", agent, None, None, size_record(arguments, "tool_args"))
        try:   # a structured proposal is held to the same depth and types, and copied like the args
            proposal = to_plain(proposal, max_depth=MAX_INPUT_DEPTH, what="proposal is",
                                max_items=MAX_ARGS_BYTES // 2)
        except OversizeError:
            return self._deny(origin, "proposal_too_large", agent, None, None, _unmeasured("proposal"))
        except EncodingError as e:
            return self._deny(origin, "malformed_proposal", agent, None, None,
                              {"proposal_omitted": True, "proposal_error": cap_ledger_text(str(e))})
        if args_too_large(proposal):
            return self._deny(origin, "proposal_too_large", agent, None, None, size_record(proposal, "proposal"))
        # Caller-supplied facts are copied once, under the same caps as the arguments. A copy that fails is a
        # derive deny below (both paths still run), never a fact read from the original object.
        facts_error = None
        if facts is not None:
            try:
                facts = to_plain(facts, max_depth=MAX_INPUT_DEPTH, what="facts are", max_items=MAX_ARGS_BYTES // 2)
                if args_too_large(facts):
                    facts_error = "facts_too_large"
            except OversizeError:
                facts_error = "facts_too_large"
            except EncodingError:
                facts_error = "facts_unreadable"
        spec = None
        if self.compiled.specs_enforced:
            spec = self.compiled.tool_specs.get(normalized.tool)
        form = None
        claimed_data_class = normalized.data_class
        deny_reason = None
        scanned: Outcome | None = None
        scanner_change: tuple[str, dict] | None = None
        if spec is not None:
            proposed: Mapping[str, Any] = claim if isinstance(claim, dict) else {}
            blocked = blocked_from_rules(self.compiled.rules)
            try:
                if not isinstance(arguments, Mapping):
                    raise DeriveError("arguments_not_object")
                if facts_error:
                    raise DeriveError(facts_error)
                if self.scanner is not None and self.scanner.scans(spec):
                    # Two-Key fills the verdict itself, after the call reads under its spec; nothing the agent
                    # or the integration supplies stands in for it.
                    if facts is not None and not isinstance(facts, Mapping):
                        raise DeriveError("facts_not_object")
                    if facts is not None and self.scanner.field in facts:
                        raise DeriveError("scan_fact_supplied")
                    derive(spec, arguments, self.compiled.fields, {**(facts or {}), self.scanner.field: "unavailable"})
                    scanned, scanner_change = self._scan(normalized.tool, arguments, proposal,
                                                         self.scanner.passes_encrypted(spec))
                    facts = {**(facts or {}), self.scanner.field: scanned.verdict}
                derived = derive(spec, arguments, self.compiled.fields, facts)
            except FileDeniedError as exc:
                # A declared file Two-Key cannot read, or over a file limit, is not a well-formed call within
                # limits: denied before the scanner and both paths, whatever the stance. The ledger gets the
                # file's argument path, why, and sizes; the agent gets the code.
                return self._deny(origin, exc.reason, agent, None, None,
                                  {"tool": normalized.tool, "file_denied": exc.record,
                                   "tool_args_digest": f"sha256:{frozen_digest}"})
            except DeriveError as exc:
                deny_reason = f"derive_failed:{cap_ledger_text(exc.reason)}"
                # No custom field values were derived, so a deny_if_fields rule reaches LOAD_FIELD with
                # nothing to load and Path A records a vm_fault: still a deny, and honest about why.
                normalized = replace(normalized, data_class="classified", irreversible=True)
            else:
                mismatch = disagreement(proposed, derived)
                if mismatch:
                    deny_reason = mismatch
                form = form_for(derived, claimed_data_class, blocked)
                party = form["counterparty"] if derived.counterparties else normalized.counterparty
                normalized = replace(
                    normalized,
                    amount_usd=float(form["amount_usd"]),
                    data_class=form["data_class"],
                    counterparty=party,
                    irreversible=bool(form["irreversible"]),
                    fields=dict(derived.fields),     # from the bytes or facts; Path A reads them with LOAD_FIELD
                    fact_fields=derived.fact_fields,
                )
                if (
                    deny_reason is None
                    and disallowed_party(spec, arguments)
                    and not (set(derived.counterparties) & blocked)
                ):
                    deny_reason = "counterparty_not_allowed"
        if spec is None and self.compiled.fields:
            # No spec means the tool is not allow-listed, so Path A denies; the defaults keep a custom-field
            # rule from faulting first, so the deny names the rule that caught it.
            normalized = replace(normalized, fields=field_defaults(self.compiled.fields))
        path_a = self.vm.eval(normalized)
        path_a_rec = {"allowed": path_a.allowed, "reason": path_a.reason, "denied_by": path_a.denied_by}
        binding = {
            "action_hash": canonical_hash(normalized.to_record()),
            "constitution_hash": self.constitution.digest,
            "nl_hash": self.compiled.nl_hash,
            "bytecode_hash": self.compiled.bytecode_hash,
        }
        # From here both paths answer. A Path A deny does not skip Path B.
        # After a derive deny, judges do not receive the argument bytes unless
        # the quorum policy opts in. The normalized record still goes to Path B.
        judge_args: Mapping | None = arguments
        judge_proposal = proposal
        judge_action = normalized
        if scanned is not None:
            # Files appear as their digest and size, never their content. Flagged: no arguments and no proposal
            # text for the judges, unless the policy opts in, so a detected secret is not sent to a judge vendor.
            judge_args = scanned.judge_args
            withheld = scanned.verdict == "flagged" and not self.quorum.tool_args_on_scan_flag
            if withheld:
                judge_args, judge_proposal = None, ""
            judge_action = replace(normalized, scan=scanned.judge_summary(withheld))
        elif self.scanner is not None and spec is None:
            judge_args = None      # not a signed tool: not scanned, so its arguments are not sent to the judges
        if _derive_deny(deny_reason) and not self.quorum.tool_args_on_derive_deny:
            judge_args = None
        if deny_reason and deny_reason.startswith("derive_failed:") and judge_args is None:
            # The call cannot be read under its spec, so it is denied already, and judges would get a form with
            # nothing derived in it and no arguments: there is nothing to judge. They are not asked; Path B is
            # ledgered as skipped. With tool_args_on_derive_deny they see the arguments, and are asked.
            quorum_passed, quorum_reason = False, "skipped:derive_failed"
            path_b_rec = {"passed": False, "reason": quorum_reason, "yes": 0, "no": 0, "abstain": 0,
                          "skipped": True}
        else:
            try:
                # Re-read the named agent credential. A placeholder session must not hide it.
                # Unreadable: deny before any judge sees the call. The value is not in the reason.
                configured = configured_agent_secrets(self._agent_sources)
            except IdentityError:
                return self._deny(origin, "agent_credential_unreadable", agent, path_a_rec, None)
            quorum = convene(self.judges, self.compiled.judge_text, judge_action, judge_proposal,
                             self.quorum, binding, judge_args, agent_session,
                             configured_secrets=configured)
            quorum_passed, quorum_reason = quorum.passed, quorum.reason
            path_b_rec = {"passed": quorum.passed, "reason": quorum.reason,
                          "yes": quorum.yes, "no": quorum.no, "abstain": quorum.abstain}
        allowed = bool(path_a.allowed and quorum_passed and deny_reason is None)
        if deny_reason:
            reason = deny_reason
        elif allowed:
            reason = "both_paths_allow"
        else:
            reason = path_a.reason if not path_a.allowed else quorum_reason
        token = None
        try:
            with self.ledger.exclusive():       # the entries and the checkpoint over them in one hold (run 9y, S6c)
                body_omitted = False

                def _bounded(kind: str, body: dict):
                    nonlocal body_omitted
                    entry = self.ledger.append_bounded(kind, body)
                    if entry.body.get("body_omitted"):
                        body_omitted = True
                    return entry

                _bounded("proposal", {"tool": normalized.tool, "proposal": proposal, "agent": agent})
                if spec is not None:
                    record = {
                        "tool": normalized.tool,
                        "form": form,
                        "claimed_data_class": claimed_data_class,
                        "deny_reason": deny_reason,
                        # Names of keys the tool will not receive. Never their values.
                        "dropped_keys": dropped_keys(spec, arguments),
                    }
                    if normalized.fact_fields:      # which form fields are caller-supplied facts; absent otherwise
                        record["fact_fields"] = list(normalized.fact_fields)
                    _bounded("action_normalized", record)
                if scanner_change is not None:
                    _bounded(*scanner_change)
                if scanned is not None:
                    _bounded("scan", scanned.ledger_record(self.scanner.stance))
                _bounded("path_a", path_a_rec)
                _bounded("path_b", path_b_rec)
                # body_omitted is only for an already-decided DENY audit entry. If it would
                # fire on a path about to issue a token, fail closed instead.
                if allowed and body_omitted:
                    allowed, reason = False, REASON_LEDGER_BODY
                if allowed:
                    if self.issuer is None:
                        allowed, reason = False, "no_issuer_key"
                    else:
                        issued = self.issuer.issue(
                            tool=normalized.tool, arguments=arguments, args_digest=frozen_digest,
                            ledger_root=self.ledger.merkle_root(), ledger_size=self.ledger.size(),
                            bytecode_hash=self.compiled.bytecode_hash, nl_hash=self.compiled.nl_hash,
                            spec_hash=self.compiled.spec_hash,
                            form=form, claimed_data_class=claimed_data_class if form is not None else None,
                            ttl_seconds=self.ttl_seconds,
                            scan=scanned.token_claim() if scanned is not None else None)
                        token = issued.token
                        _bounded("capability_issued", {"jti": issued.payload["jti"],
                                                       "token_hash": issued.token_hash,
                                                       "ledger_root": issued.payload["ledger_root"]})
                        if body_omitted:
                            allowed, reason, token = False, REASON_LEDGER_BODY, None
                _bounded("decision", {"allowed": allowed, "reason": reason, "agent": agent,
                                      "origin": origin, **self._decision_context})
                if allowed and body_omitted:
                    allowed, reason, token = False, REASON_LEDGER_BODY, None
                self.ledger.checkpoint()
        except LedgerError as e:
            return Decision(False, f"ledger_failed:{cap_ledger_text(str(e))}", None, path_a_rec, path_b_rec, self.ledger.size(), agent)
        return Decision(allowed, reason, token if allowed else None, path_a_rec, path_b_rec, self.ledger.size(), agent)

    def authorize_from_agent(self, agent, proposal_text: str, *, agent_session: str | None = None,
                             origin: str = "library", facts: Any = None) -> Decision:
        """Parse an untrusted agent proposal, run both paths, and do not execute the tool.

        ``facts`` is a resolver, ``facts(tool, arguments) -> mapping``, called after parsing with a copy of
        the proposed arguments, because a fact depends on the call. It is trusted operator code that receives
        agent-written arguments: it must look a fact up by an id in the system of record, never echo an
        argument. A resolver that raises supplies no facts (a ``field_missing`` deny for a tool that needs one).

        The text is measured before it is parsed. Text over ``MAX_PROPOSAL_TEXT_CHARS`` is a
        ``proposal_too_large`` deny, and text that is not a string or does not parse is a
        ``malformed_proposal`` deny. Either way the ledger keeps only its size and digest, and
        the reason carries no value or key name.

        ``origin``, ``agent.agent_id``, and ``agent.hosting`` are library metadata for the
        ledger (same type and 256-char caps as ``authorize`` kwargs).
        """
        try:
            origin = normalize_origin(origin)
        except AgentMetadataError as e:
            return self._deny(None, e.reason, None, None, None, e.detail)
        try:
            agent_id = check_agent_meta_field("agent_id", getattr(agent, "agent_id", None))
            hosting = check_agent_meta_field("hosting", getattr(agent, "hosting", None))
            record = ledger_agent_record(agent_id, hosting)
        except AgentMetadataError as e:
            return self._deny(origin, e.reason, None, None, None, e.detail)
        try:
            if isinstance(proposal_text, str) and len(proposal_text) > MAX_PROPOSAL_TEXT_CHARS:
                return self._deny(origin, "proposal_too_large", record, None, None,
                                  size_record(proposal_text, "proposal_text"))
            try:
                action, arguments, proposal = parse_proposal(proposal_text)
            except AgentDeclined as d:
                # Not a call: neither path runs and no token exists. The reason is agent text, kept like a
                # proposal string (at most MAX_DECLINE_CHARS) and never used as the decision reason.
                return self._deny(origin, "agent_declined", record, None, None,
                                  {"decline": d.reason, **size_record(proposal_text, "proposal_text")})
            except (AgentConfigError, RecursionError):   # the message may quote a key name: not in the reason
                return self._deny(origin, "malformed_proposal", record, None, None,
                                  {**size_record(proposal_text, "proposal_text"),
                                   "proposal_text_type": type_tag(proposal_text)})
        except Exception as e:  # fail closed, as in authorize()
            return self._deny(origin, f"internal_error:{type_tag(e)}", record, None, None)
        resolved = None
        if facts is not None:
            resolved = resolve_facts(facts, action.get("tool") if isinstance(action, Mapping) else None, arguments)
        return self.authorize(action, arguments, proposal, agent_id=agent_id,
                              hosting=hosting, agent_session=agent_session, origin=origin, facts=resolved)

    def revoke(self, reason: str) -> None:
        with self.ledger.exclusive():
            self.ledger.append("revocation", {"reason": reason})
            self.ledger.checkpoint()

    def _deny(self, origin: str | None, reason: str, agent, path_a, path_b, extra: dict | None = None) -> Decision:
        """Ledger a deny decision. ``origin`` is passed down by the caller, never stored on ``self``.

        ``origin`` may be ``None`` when the supplied origin itself failed validation
        (detail already carries ``field``/``size``/``digest`` or ``got``; do not echo it).
        """
        try:
            body = {"allowed": False, "reason": reason, "agent": agent,
                    **(extra or {}), **self._decision_context}
            if origin is not None:
                body["origin"] = origin
            self.ledger.record("decision", body)
        except Exception as e:  # still a deny; say so, because the ledger now lacks this decision
            # Cap pieces before format so a huge str(e) is not built into one f-string then sliced.
            reason_bit = reason if len(reason) <= 200 else reason[:200]
            exc_bit = str(e)
            if len(exc_bit) > 200:
                exc_bit = exc_bit[:200]
            print(f"two-key: could not record deny decision {reason_bit!r}: {type_tag(e)}: {exc_bit}"[:500],
                  file=sys.stderr)
            reason = (f"ledger_failed:{cap_ledger_text(str(e))}" if isinstance(e, LedgerError)
                      else f"ledger_failed:{type_tag(e)}")
        try:
            size = self.ledger.size()
        except Exception:
            size = 0
        return Decision(False, reason, None, path_a or {}, path_b or {}, size, agent)
