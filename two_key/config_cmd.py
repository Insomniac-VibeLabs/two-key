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
    from .judges.config import JudgeConfigError, load_config_file
    try:
        return load_config_file(config.judges), None
    except (OSError, ValueError, JudgeConfigError) as e:
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
    found += _constitution(config)
    loaded, bad = _judges(config)
    high = False
    if bad:
        found.append(bad)
    else:
        judges, policy = loaded
        high = bool(policy.is_high_assurance)
        found += _quorum(judges, policy)
        found += _agent(config)
    found += _environment(config, environ)
    found += _upstream(config, high)
    found += _writable(config, high)
    found += _siem(config, high)
    found += _agent_access(config, high)
    return found


def _constitution(config) -> list[tuple[str, str]]:
    from .constitution import ConstitutionError, ConstitutionSignatureError, load_envelope, verify_signed
    from .keys import key_file_is_encrypted
    try:
        # As the proxy opens it: with keys.passphrase_file when it is encrypted, never a prompt.
        public = config.load_principal_key(prompt=False).public_key()
        encrypted = key_file_is_encrypted(config.principal_key)
    except (OSError, ValueError) as e:
        return [(FAIL, f"principal_key: {config.principal_key}: {e}")]
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
    except (OSError, ValueError, ConstitutionError, ConstitutionSignatureError) as e:
        return [(FAIL, f"constitution: {config.constitution}: {e}")]
    out = [key_line, (OK, f"constitution: signed by the principal key, digest {signed.digest}")]
    unknown = sorted(set(config.tools) - set(signed.tool_specs))
    if unknown:
        out.append((FAIL, f"tools: {unknown} are not tools in the signed constitution"))
    return out


def _quorum(judges, policy) -> list[tuple[str, str]]:
    from .quorum import heterogeneity_shortfall, lone_judge_warning
    out = [(OK, f"judges: {len(judges)} load; required_yes {policy.required_yes}, "
                f"min_responding {policy.effective_min_responding}"
                f"{', high_assurance floors' if policy.is_high_assurance else ''}")]
    for text in (lone_judge_warning(judges, policy), heterogeneity_shortfall(judges, policy)):
        if text:
            out.append((WARN, text))
    return out


def _agent(config) -> list[tuple[str, str]]:
    from .identity import IdentityError, load_monitored_agent_file
    try:
        agent = load_monitored_agent_file(config.judges)
    except (OSError, ValueError, IdentityError) as e:
        return [(FAIL, f"monitored_agent: {e}")]
    if agent is None:
        return [(WARN, "monitored_agent: none declared, so judges are not checked against the agent's "
                       "own model and credential")]
    return [(OK, "monitored_agent: declared")]


def _environment(config, environ: Mapping[str, str]) -> list[tuple[str, str]]:
    """Variables the proxy reads at start, by name; a value is never printed."""
    out = []
    for name, value in sorted(config.upstream.env.items()):
        if value.from_env is not None and not environ.get(value.from_env):
            out.append((FAIL, f"upstream_env_missing: upstream.env.{name} reads {value.from_env}, which is "
                              "unset or empty here (the proxy's own environment may differ)"))
    if config.agent_session_env and not environ.get(config.agent_session_env):
        out.append((FAIL, f"agent_session_missing: agent_session_env names {config.agent_session_env}, "
                          "which is unset or empty here (the proxy's own environment may differ)"))
    return out or [(OK, "environment: every variable the config names is set")]


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
    from .siem import SiemConfigError
    from .siem_sinks import siem_from_config
    if config.siem is None:
        return [(OK, "siem: not configured, no copy leaves the ledger")]
    try:
        siem = siem_from_config(config.siem, config.path.parent)
    except (OSError, ValueError, SiemConfigError) as e:
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
        "judges": [{"id": j.judge_id, "model": j.model, "maker": getattr(j, "maker", None),
                    "local": bool(j.is_local()),
                    "ballot_key_env": getattr(j, "ballot_key_env", None)} for j in judges],
    }


def _scan_view(scan):
    """The scanner block with each ``env`` value shown as ``<literal>``: a command scanner's variables can hold a
    secret."""
    if scan is None:
        return None
    view = dict(scan)
    if isinstance(view.get("env"), dict):
        view["env"] = {name: "<literal>" for name in sorted(view["env"])}
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
