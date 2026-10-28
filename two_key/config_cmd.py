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
    if signed is not None:
        found += _tool_checks(signed, high)
    return found


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


def _constitution(config) -> tuple[list[tuple[str, str]], Any]:
    from .constitution import load_envelope, verify_signed
    from .keys import key_file_is_encrypted
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
    unknown = sorted(set(config.tools) - set(signed.tool_specs))
    if unknown:
        out.append((FAIL, f"tools: {unknown} are not tools in the signed constitution"))
    out += _unset_claims(config, signed)
    return out, signed


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
    return [(OK, "monitored_agent: declared")], agent


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
    if agent is not None and _unresolved(agent.model, agent.base_url, agent.upstream):
        sides.append(f"agent {agent.id!r}")
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
    if agent is None:
        return []
    return [(name, getattr(agent, name)) for name in ("credential_env", "username_env", "password_env")
            if isinstance(getattr(agent, name, None), str)]


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
