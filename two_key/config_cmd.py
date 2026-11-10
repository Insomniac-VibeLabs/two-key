# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""``two-key config show`` and ``two-key config check``: read-only views of a proxy's configuration.

Neither command writes a file, opens the ledger, starts the proxy, or contacts a judge, a scanner, a
collector or the upstream server. Neither prints a secret: a key file is named by path and a judge's key by
the name of its environment variable; an upstream literal value is shown only as ``<literal>``. ``check``
reads the principal key file to take its public half, as the proxy does, and nothing else from it.

``check`` runs what ``mcp-proxy`` runs at start that can run without side effects. It does not run the
agent-access check: that depends on which account starts the proxy, so only the proxy can answer it.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from typing import Any, Mapping

OK, WARN, FAIL = "ok", "WARN", "FAIL"


def _load(path: Path | str):
    """The proxy config, or a ``(FAIL, message)`` finding."""
    from .mcp_proxy.config import ProxyConfigError, load_proxy_config
    try:
        return load_proxy_config(path), None
    except ProxyConfigError as e:
        return None, (FAIL, f"config_invalid: {e}")


def _judges(config):
    from .judges.config import load_config_file
    try:
        return load_config_file(config.judges), None
    except (OSError, ValueError) as e:
        return None, (FAIL, f"judges_invalid: {type(e).__name__}: {e}")


def check(path: Path | str, environ: Mapping[str, str] | None = None) -> list[tuple[str, str]]:
    """``(level, text)`` findings for the proxy config at ``path``. Any ``FAIL`` means ``mcp-proxy`` would
    refuse to start (or, for the writable-path and SIEM findings, would under that setting)."""
    config, bad = _load(path)
    if bad:
        return [bad]
    return check_config(config, environ)


def check_config(config, environ: Mapping[str, str] | None = None) -> list[tuple[str, str]]:
    """``check`` for a config already read. ``config set`` runs it on the staged files before it writes."""
    environ = os.environ if environ is None else environ
    found: list[tuple[str, str]] = [(OK, f"config: {config.path} reads cleanly")]
    constitution_found, signed = _constitution(config)
    found += constitution_found
    found += _witness_pin(config)
    loaded, bad = _judges(config)
    high = False
    judges, agent = [], None
    if bad:
        found.append(bad)
    else:
        judges, policy = loaded
        high = bool(policy.is_high_assurance)
        found += _quorum(judges, policy)
        found += _cloud_session(config, judges)
        agent_found, agent = _agent(config)
        found += agent_found
        found += _identities(config, judges, agent)
    found += _environment(config, environ, judges, agent)
    found += _upstream(config, high)
    found += _writable(config, high)
    found += _siem(config, high)
    found += _agent_access(config, high)
    found += _unanswered_hold(config, high, judges_read=not bad)
    found.append(_rollover_line(config.ledger_rollover))
    if signed is not None:
        found += _tool_checks(signed, high)
        found += _roster(config, signed, high, agent)
    return found


def _roster_entry(entry, signed, lookup, declared: set, judges) -> list[tuple[str, str]]:
    """The config-check lines for one roster entry."""
    from .roster import tool_allows
    tools = sorted(t for t, spec in signed.tool_specs.items() if tool_allows(spec, entry.id))
    kind = "shared group" if entry.shared else "agent"
    uid = lookup(entry.account)
    if uid is None:
        return [(WARN, f"agents: {kind} {entry.id!r}: account {entry.account!r} does not exist on this machine, so "
                       f"a proxy for it cannot start here; tools: {tools or 'none'}")]
    level, note = OK, f"uid {uid}"
    if uid == 0 or (hasattr(os, "geteuid") and uid == os.geteuid()):
        level, note = FAIL, f"uid {uid}, which is root or two-key's own account (the proxy refuses it)"
    out = [(level, f"agents: {kind} {entry.id!r}: account {entry.account!r} ({note}); tools: {tools or 'none'}")]
    if declared and entry.id not in declared:
        out.append((WARN, f"agents: {entry.id!r} has no monitored_agent declaration with that id in {judges}, so "
                          "judges are checked against the declared agents only"))
    return out


def _roster(config, signed, high: bool, agent=None, *, lookup=None) -> list[tuple[str, str]]:
    """The signed agent roster (two_key/roster.py): one line per agent with its account, whether this machine has
    that account and whether it passes the agent-access checks, and its tools. It cannot read the sudoers file or
    ``authorized_keys``, so it does not say which account a wrapper or a forced command starts the proxy as."""
    from .identity import declarations
    from .roster import ANY, uid_of
    lookup = uid_of if lookup is None else lookup
    entries = signed.agents
    if not entries:
        if high:
            return [(FAIL, "agent_roster_required: high_assurance needs a signed agent roster (agents: in the rules "
                           "file); the proxy refuses to start without one (docs/CONNECTING.md)")]
        return [(OK, f"agents: no signed roster; the proxy serves agent_id {config.agent_id or 'unnamed'!r} from "
                     "proxy.yaml, unchecked, and records the account that started it")]
    declared = {d.id for d in declarations(agent)}
    out = []
    for entry in entries:
        out += _roster_entry(entry, signed, lookup, declared, config.judges)
    if config.agent_id is not None and config.agent_id not in {e.id for e in entries}:
        out.append((FAIL, f"agent_account_mismatch: proxy.yaml's agent_id {config.agent_id!r} is not on the signed "
                          "roster; remove it (the account that starts the proxy picks the agent)"))
    open_tools = sorted(t for t, spec in signed.tool_specs.items() if spec.get("agents", ANY) == ANY)
    if high and open_tools:
        out.append((FAIL, f"agent_list_required: high_assurance needs each tool to name its agents; {open_tools} "
                          "are open to any listed agent"))
    return out


def _unanswered_hold(config, high: bool, *, judges_read: bool = True) -> list[tuple[str, str]]:
    """``unanswered_hold`` (docs/TOOL_CHECK.md): a FAIL when ``high_assurance`` is told not to hold. When
    ``judges.yaml`` could not be read, the profile is unknown, so a value that is not set is not called off
    (run 13 G F6: the setup check printed ``off`` for a high_assurance deployment it had not written yet)."""
    from .mcp_proxy.config import unanswered_hold_problem
    problem = unanswered_hold_problem(config, high)
    if problem:
        return [(FAIL, problem)]
    if config.unanswered_hold or high:
        return [(OK, "unanswered_hold: on" + (" (high_assurance)" if high else ""))]
    if not judges_read:
        # Run 14 V4: the profile is in judges.yaml, so with it unread the answer is not known. Do not lead with off.
        return [(OK, "unanswered_hold: not known until judges.yaml reads: on if it sets high_assurance (which "
                     "always holds), otherwise off, as proxy.yaml does not set it")]
    return [(OK, "unanswered_hold: off")]


def _rollover_line(rollover) -> tuple[str, str]:
    """``ledger_rollover`` as the proxy will apply it (run 14 R13/J4: ``config show`` had it, ``config check`` did
    not). The loader already refused a value out of range, so this only reports."""
    if not rollover.enabled:
        return (OK, "ledger_rollover: off; the active ledger file grows without limit and is read in full at every "
                    "start (docs/SETTINGS.md)")
    view = _rollover_view(rollover)
    days = f" or after {view['segment_days']} days" if view["segment_days"] else ""
    return (OK, f"ledger_rollover: on; seals at {view['segment_mb']} MB{days}, no new token past "
                f"{view['hard_limit_mb']} MB until it has run; compression {view['compression']}; archives kept: "
                f"{view['keep_archives']}")


def _witness_pin(config) -> list[tuple[str, str]]:
    """``witness_public_key``, the witness pinned outside the ledger, against the ledger's ``witness.pem``. After
    ``rotate-witness`` or the key upgrade the operator copies the new public key there by hand; a stale copy passed
    ``config check`` and then the proxy refused ``witness_key_changed`` (0.9.0 regression report, item 2). This
    reads key files only, never the ledger. A witness key that cannot be read here is left to the proxy."""
    from .keys import classical_half, is_hybrid, load_private_key_file, load_public_key, public_raw
    if config.witness_public_key is None:
        return []
    try:
        pin = public_raw(load_public_key(config.witness_public_key))
    except (OSError, ValueError) as e:
        return [(FAIL, f"witness_public_key: {config.witness_public_key} cannot be read ({type(e).__name__})")]
    ledger = Path(config.ledger)
    witness_file = ledger.parent / f"{ledger.name}.witness" / "witness.pem"
    if not witness_file.exists():
        return []       # the first start makes it, and then checks the pin itself
    try:
        witness = load_private_key_file(witness_file)
    except (OSError, ValueError):
        return [(WARN, f"witness_public_key: {witness_file} could not be read here, so the pin was not compared; "
                       "run config check as Two-Key's own account")]
    if pin == public_raw(witness.public_key()):
        return [(OK, f"witness_public_key: matches {witness_file}")]
    why = ("it is the 0.8.0 key, and the key upgrade made a new hybrid witness key"
           if is_hybrid(witness) and pin == public_raw(classical_half(witness).public_key())
           else "rotate-witness or the key upgrade changed the witness key")
    return [(FAIL, f"witness_key_changed: witness_public_key {config.witness_public_key} does not match "
                   f"{witness_file}; {why}. Copy {witness_file.parent / 'witness.pub.pem'} over it (HOWTO \"Rotate the "
                   "witness key\", UPGRADING), or the proxy refuses to start")]


def _tool_checks(signed, high: bool) -> list[tuple[str, str]]:
    """Each signed tool's tool check (#28, docs/TOOL_CHECK.md). Under ``high_assurance`` a tool with neither a
    receipt key nor ``exempt`` is a FAIL, as the proxy refuses to start; otherwise one OK line lists them."""
    from .toolcheck import checked
    on = sorted(t for t, spec in signed.tool_specs.items() if checked(spec))
    exempt = sorted(t for t, spec in signed.tool_specs.items() if spec.get("tool_check") == "exempt")
    off = sorted(t for t, spec in signed.tool_specs.items() if "tool_check" not in spec)
    out = [(OK, f"tool_check: on for {on or 'no tool'}; exempt: {exempt or 'none'}; off: {off or 'none'}")]
    if high and off:
        out.append((FAIL, f"tool_check_required: high_assurance needs the tool check for {off}; give each a "
                          "receipt key (two-key tool-key new) or mark it exempt (docs/TOOL_CHECK.md)"))
    return out


def _upgrade_line(config) -> tuple[str, str]:
    """A 0.8.0 principal key: the proxy's first start upgrades the keys, unless the witness is pinned outside."""
    if config.witness_public_key is not None:
        return (FAIL, "principal_key: a 0.8.0 Ed25519 key, and witness_public_key pins the witness outside the "
                      "ledger, so the proxy will not upgrade the keys by itself; run two-key keys upgrade --config "
                      "FILE (docs/UPGRADING.md)")
    return (WARN, "principal_key: a 0.8.0 Ed25519 key; the proxy's first start upgrades every key to hybrid "
                  "Ed25519 + ML-DSA-65 and signs the constitution again (docs/UPGRADING.md)")


def _constitution(config) -> tuple[list[tuple[str, str]], Any]:
    from .constitution import load_envelope, verify_signed
    from .keys import is_hybrid, key_file_is_encrypted
    try:
        # As the proxy opens it: with keys.passphrase_file when it is encrypted, never a prompt.
        public = config.load_principal_key(prompt=False).public_key()
        encrypted = key_file_is_encrypted(config.principal_key)
    except (OSError, ValueError) as e:
        return [(FAIL, f"principal_key: {config.principal_key}: {e}")], None
    if encrypted:
        key_line = (OK, "principal_key: encrypted; keys.passphrase_file opens it")
    elif config.principal_passphrase_file is not None:
        key_line = (WARN, "principal_key: keys.passphrase_file is set, but the key is not encrypted; run "
                          "two-key config key-passphrase --new-from FILE, or remove the setting")
    else:
        key_line = (OK, "principal_key: not encrypted; whoever can read the file can sign "
                        "(two-key config key-passphrase, docs/SETUP.md)")
    try:
        signed = verify_signed(load_envelope(config.constitution), public)
    except (OSError, ValueError) as e:
        return [(FAIL, f"constitution: {config.constitution}: {e}")], None
    out = [key_line, (OK, f"constitution: signed by the principal key, digest {signed.digest}")]
    out += _constitution_access(config.constitution)
    if not is_hybrid(public):
        out.insert(1, _upgrade_line(config))
    unknown = sorted(set(config.tools) - set(signed.tool_specs))
    if unknown:
        out.append((FAIL, f"tools: {unknown} are not tools in the signed constitution"))
    out += _unset_claims(config, signed)
    return out, signed


def _constitution_access(path) -> list[tuple[str, str]]:
    """A WARN when the signed constitution is readable beyond its owner (run 13 #29, decision 2026-11-05). Its
    signature stops a change, not a read: a reader learns every rule and what each judge is told. Nothing is
    refused, because the proxy only reads the file; the key upgrade keeps the mode the file has."""
    from . import _platform
    try:
        with open(path, "rb") as fh:
            problem = _platform.access_problem(fh.fileno())
    except OSError:
        return []           # it was just read; a file that went away is the next start's error
    if problem is None:
        return []
    return [(WARN, f"constitution_readable: {path} is {problem}, so they can read every rule and what the judges "
                   f"are told; run {_platform.fix_hint(path)} (two-key setup writes it owner-only)")]


def _blanket_class_rules(rules) -> list[tuple[str, str | None]]:
    """``(rule id, tool or None)`` for each ``deny_if`` rule that tests only the data class (and perhaps the
    tool) and denies ``classified``: it denies every call to a tool whose claim is unset."""
    out = []
    for rule in rules:
        body = rule.get("deny_if")
        if isinstance(body, Mapping) and set(body) <= {"data_class_in", "tool"} \
                and "classified" in body.get("data_class_in", ()):
            out.append((rule["id"], body.get("tool")))
    return out


def _unset_claims(config, signed) -> list[tuple[str, str]]:
    """A tool with no ``claim`` is read as ``classified``. A rule that denies that class denies every call to
    it, which is rarely what the operator meant (live run 10, 2026-10-27)."""
    out = []
    for rule_id, only in _blanket_class_rules(signed.hard_rules):
        tools = sorted(t for t in signed.tool_specs
                       if (only is None or t == only) and config.tool_policy(t).claim == "none")
        if tools:
            out.append((WARN, f"tools: {tools} set no claim, so they read as classified, and rule {rule_id!r} "
                              "denies classified: every call to them is denied. Set tools.<id>.claim "
                              "(floor or a data class) if that is not meant"))
    return out


def _quorum(judges, policy) -> list[tuple[str, str]]:
    from .quorum import heterogeneity_shortfall, lenient_warnings
    out = [(OK, f"judges: {len(judges)} load; required_yes {policy.required_yes}, "
                f"min_responding {policy.effective_min_responding}"
                f"{', high_assurance floors' if policy.is_high_assurance else ''}")]
    for text in [*lenient_warnings(judges, policy), heterogeneity_shortfall(judges, policy)]:
        if text:
            out.append((WARN, text))
    return out


def _cloud_session(config, judges) -> list[tuple[str, str]]:
    """A cloud judge with no ``agent_session_env``: the proxy refuses to start (live setup run, 2026-10-27)."""
    from .mcp_proxy.core import cloud_session_missing
    missing = cloud_session_missing(config, judges)
    return [(FAIL, missing)] if missing else []


def _agent(config):
    """Findings for the ``monitored_agent`` block, and the declaration (None when there is none)."""
    from .identity import load_monitored_agent_file
    try:
        agent = load_monitored_agent_file(config.judges)
    except (OSError, ValueError) as e:
        return [(FAIL, f"monitored_agent: {e}")], None
    if agent is None:
        return [(WARN, "monitored_agent: none declared, so judges are not checked against the agent's "
                       "own model and credential")], None
    problem = agent_declaration_problem(agent)
    if problem:
        return [(FAIL, problem)], None
    return [(OK, "monitored_agent: declared")], agent


def agent_declaration_problem(agent) -> str | None:
    """Why the proxy and the library refuse this ``monitored_agent`` declaration (or each one of a roster's list) when
    they resolve it, or None. Loading checks only the keys; a missing ``base_url``, or ``credential: none`` for an
    agent that is not on this host or its network, passed setup and config check and then stopped the proxy at its
    start (cloud re-test of run 13, 2026-11-05)."""
    for one in agent if isinstance(agent, list) else [agent]:
        try:
            one.validate()
        except ValueError as e:     # IdentityError
            text = str(e)
            return text if text.startswith("monitored_agent") else f"monitored_agent: {text}"
    return None


def _unresolved(model: Any, base_url: Any, upstream: Any) -> bool:
    """Whether Two-Key cannot tell who serves this model at this address (identity.ResolvedIdentity.unresolved)."""
    from .identity import IdentityError, resolve_upstream_info, validate_upstream
    if not isinstance(model, str) or not model or not isinstance(base_url, str) or not base_url:
        return False        # the loaders refuse these on their own
    try:
        declared = validate_upstream(upstream, "upstream")
    except IdentityError:
        return False        # so does the proxy, with its own message
    return not (resolve_upstream_info(base_url, model)[0] or declared)


def _identities(config, judges, agent) -> list[tuple[str, str]]:
    """A judge or agent whose upstream Two-Key cannot resolve: the proxy refuses to start
    (``mcp_proxy.core.identity_refusal``) unless ``allow_unresolved_identity: true`` (live run 11, D1). A WARN,
    not a FAIL, so ``setup`` and ``config set`` still write a deployment that names its upstream later."""
    sides = [f"judge {j.judge_id!r}" for j in judges
             if _unresolved(getattr(j, "model", None), getattr(j, "base_url", None), getattr(j, "upstream", None))]
    from .identity import declarations
    for one in declarations(agent):
        if _unresolved(one.model, one.base_url, one.upstream):
            sides.append(f"agent {one.id!r}")
    if not sides:
        return []
    what = (f"Two-Key cannot resolve who serves {', '.join(sides)} (a local proxy or an unrecognized host, and a "
            "model that names no maker)")
    if config.allow_unresolved_identity:
        return [(WARN, f"unresolved_identity: {what}; allowed by allow_unresolved_identity: true")]
    return [(WARN, f"unresolved_identity: {what}, so the proxy refuses to start; declare upstream: (where that "
                   "address forwards, such as api.x.ai) for it in the judges file, or set "
                   "allow_unresolved_identity: true in the proxy config to accept the risk")]


def judge_variables(judge) -> list[tuple[str, str]]:
    """``(setting, variable)`` for each environment variable a judge reads: its key and its ballot key."""
    credential = getattr(judge, "credential", None)
    kind = getattr(credential, "kind", None)
    out = []
    if kind == "env":
        out.append(("auth.var", credential.var))
    elif kind == "basic":
        out += [("auth.username_env", credential.username_var), ("auth.password_env", credential.password_var)]
    if getattr(judge, "ballot_key_env", None):
        out.append(("ballot_key_env", judge.ballot_key_env))
    return out


def _agent_variables(agent) -> list[tuple[str, str]]:
    from .identity import declarations
    return [(name, getattr(one, name)) for one in declarations(agent)
            for name in ("credential_env", "username_env", "password_env")
            if isinstance(getattr(one, name, None), str)]


def _named_variables(config, judges, agent) -> list[tuple[str, str, str]]:
    """``(level, finding, variable)`` for each environment variable the proxy and its judges read; ``finding`` is the
    line printed when the variable is unset. An upstream or agent variable is a FAIL (the upstream would not get it,
    or the proxy refuses to start without it); a judge's is a WARN (the proxy starts, and that judge abstains)."""
    found = [(FAIL, f"upstream_env_missing: upstream.env.{name} reads {value.from_env}", value.from_env)
             for name, value in sorted(config.upstream.env.items()) if value.from_env is not None]
    if config.agent_session_env:
        found.append((FAIL, f"agent_session_missing: agent_session_env names {config.agent_session_env}",
                      config.agent_session_env))
    found += [(FAIL, f"agent_credential_missing: monitored_agent.{setting} names {var}", var)
              for setting, var in _agent_variables(agent)]
    found += [(WARN, f"judge_env_missing: judge {judge.judge_id} {setting} names {var}", var)
              for judge in judges for setting, var in judge_variables(judge)]
    return found


def _environment(config, environ: Mapping[str, str], judges=(), agent=None) -> list[tuple[str, str]]:
    """Variables the proxy and its judges read, by name; a value is never printed (live run 9, finding 1)."""
    named = _named_variables(config, judges, agent)
    here = "which is unset or empty here (the proxy's own environment may differ)"
    out = [(level, f"{finding}, {here}" + ("; the judge will abstain" if level == WARN else ""))
           for level, finding, var in named if not environ.get(var)]
    if out:
        return out
    if not named:
        return [(OK, "environment: the config names no variables")]
    return [(OK, f"environment: set here: {', '.join(sorted({var for _, _, var in named}))}")]


def _upstream(config, high: bool) -> list[tuple[str, str]]:
    """The upstream server's files (#13): a ``check_paths`` entry that does not exist, and a launcher with
    nothing named (``upstream_paths_unchecked``), which ``high_assurance`` refuses."""
    from .mcp_proxy.config import ProxyConfigError
    from .mcp_proxy.core import check_upstream_paths, upstream_paths
    try:
        upstream_paths(config.upstream)
        line = check_upstream_paths(config.upstream, high, stream=io.StringIO())
    except ProxyConfigError as e:
        return [(FAIL, str(e))]
    return [(WARN, line)] if line else []


def _writable(config, high: bool) -> list[tuple[str, str]]:
    from . import writable
    from .mcp_proxy.config import ProxyConfigError
    from .mcp_proxy.core import startup_paths
    try:
        mode = writable.resolve_mode(config.on_writable_paths, high)
    except ValueError as e:
        return [(FAIL, str(e))]
    try:
        paths = startup_paths(config)
    except ProxyConfigError:        # check_path_missing, already a failure from _upstream
        return []
    found = writable.check(paths)
    level = FAIL if mode == "refuse" else WARN
    out = [(level, f"writable_path: {p}: {problem}") for p, problem in found[:writable.MAX_LINES]]
    if len(found) > writable.MAX_LINES:
        out.append((level, f"writable_path: and {len(found) - writable.MAX_LINES} more"))
    return out or [(OK, f"writable_paths: nothing another account can change (on_writable_paths: {mode})")]


def _agent_access(config, high: bool) -> list[tuple[str, str]]:
    """The mode only: which account starts the proxy is something only the proxy can see."""
    from . import agent_access
    try:
        mode = agent_access.resolve_mode(config.on_agent_access, high)
    except ValueError as e:
        return [(FAIL, str(e))]
    return [(OK, f"agent_access: not checked here; the proxy checks the account that starts it "
                 f"(on_agent_access: {mode})")]


def _siem(config, high: bool) -> list[tuple[str, str]]:
    from .siem_sinks import siem_from_config
    if config.siem is None:
        return [(OK, "siem: not configured, no copy leaves the ledger")]
    try:
        siem = siem_from_config(config.siem, config.path.parent)
    except (OSError, ValueError) as e:
        return [(FAIL, f"siem_invalid: {e}")]
    plain = siem.plaintext_sinks
    if plain and high:
        return [(FAIL, f"siem_plaintext_refused: high_assurance does not send the ledger copy in the clear; "
                       f"{plain}")]
    if plain:
        return [(WARN, f"siem: the copy goes out in the clear to {plain}")]
    return [(OK, f"siem: {len(siem.sinks)} sink(s), none in the clear")]


def show(path: Path | str) -> dict[str, Any]:
    """The effective settings, with defaults filled in, as a JSON-ready dict. Raises ``ValueError``."""
    config, bad = _load(path)
    if bad:
        raise ValueError(bad[1])
    loaded, bad = _judges(config)
    if bad:
        raise ValueError(bad[1])
    judges, policy = loaded
    from . import agent_access, writable
    high = bool(policy.is_high_assurance)
    siem = None
    if config.siem is not None:
        from .siem_sinks import siem_from_config
        siem = siem_from_config(config.siem, config.path.parent).record()
    return {
        "config": str(config.path),
        "constitution": str(config.constitution),
        "keys": {"principal": str(config.principal_key),
                 "passphrase_file": str(config.principal_passphrase_file) if config.principal_passphrase_file
                 else None},
        "ledger": str(config.ledger),
        "judges_file": str(config.judges),
        "witness_public_key": str(config.witness_public_key) if config.witness_public_key else None,
        "head_anchor": str(config.head_anchor) if config.head_anchor else None,
        "ttl_seconds": config.ttl_seconds,
        "agent_id": config.agent_id,
        "hosting": config.hosting,
        "agent_session_env": config.agent_session_env,
        "allow_unresolved_identity": config.allow_unresolved_identity,
        "on_writable_paths": writable.resolve_mode(config.on_writable_paths, high),
        "on_agent_access": agent_access.resolve_mode(config.on_agent_access, high),
        "unanswered_hold": bool(config.unanswered_hold) or high,
        "ledger_rollover": _rollover_view(config.ledger_rollover),
        "high_assurance": high,
        "upstream": {
            "command": list(config.upstream.command),
            "env": {name: ({"env": v.from_env} if v.from_env else "<literal>")
                    for name, v in sorted(config.upstream.env.items())},
            "cwd": str(config.upstream.cwd) if config.upstream.cwd else None,
            "schema_digest": config.upstream.schema_digest,
            "on_schema_change": config.upstream.on_schema_change,
            "call_timeout_seconds": config.upstream.call_timeout_seconds,
            "check_paths": [str(p) for p in config.upstream.check_paths],
        },
        "tools": {tool: {"claim": p.claim, "upstream_name": p.upstream_name,
                         "proposal": p.proposal is not None, "facts": dict(p.facts),
                         "files": [f.path for f in p.files]}
                  for tool, p in sorted(config.tools.items())},
        "scan": _scan_view(config.scan),
        "siem": siem,
        "quorum": policy.to_record(),
        "judges": [_judge_view(j) for j in judges],
    }


def _judge_view(judge) -> dict[str, Any]:
    """One judge as configured: where it is and which variables it reads, never a value."""
    from .judges.config import ADAPTERS
    kind = next((name for name, cls in sorted(ADAPTERS.items()) if type(judge) is cls), type(judge).__name__)
    credential = getattr(judge, "credential", None)
    return {"id": judge.judge_id, "type": kind, "base_url": getattr(judge, "base_url", None), "model": judge.model,
            "maker": getattr(judge, "maker", None), "local": bool(judge.is_local()),
            "auth": getattr(credential, "kind", None),
            "variables": dict(judge_variables(judge)),
            "ballot_key_env": getattr(judge, "ballot_key_env", None)}


def _rollover_view(rollover) -> dict:
    """``ledger_rollover`` as it applies, the hard limit worked out."""
    return {"enabled": rollover.enabled, "segment_mb": rollover.segment_mb, "segment_days": rollover.segment_days,
            "hard_limit_mb": rollover.hard_limit_bytes // (1024 * 1024), "compression": rollover.compression,
            "keep_archives": rollover.keep_archives}


def _scan_view(scan):
    """The scanner block with each ``env`` value shown as ``<literal>``: a command scanner's variables can hold a
    secret."""
    if scan is None:
        return None
    view = dict(scan)
    if isinstance(view.get("env"), dict):
        view["env"] = dict.fromkeys(sorted(view["env"]), "<literal>")
    return view


def run_show(args) -> int:
    import sys
    try:
        print(json.dumps(show(args.config), indent=2, default=str))
    except ValueError as e:
        print(f"two-key: config show: {e}", file=sys.stderr)
        return 1
    return 0


def run_check(args) -> int:
    findings = check(args.config)
    for level, text in findings:
        print(f"{level:<4}  {text}")
    failed = sum(1 for level, _ in findings if level == FAIL)
    warned = sum(1 for level, _ in findings if level == WARN)
    print(f"\n{failed} failure(s), {warned} warning(s)")
    return 1 if failed else 0
