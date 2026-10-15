"""The MCP proxy's configuration file (``two-key mcp-proxy --config proxy.yaml``).

Read strictly (``two_key.strict``): a repeated key, a YAML merge key, and an unknown key are refused, so a
typo never drops a setting. Relative paths are relative to the config file's directory. Nothing here
imports the MCP SDK.

Secrets are never values in this file. An upstream environment variable is either a literal (for
settings such as a log level) or ``{env: NAME}``, read from the proxy's own environment at start. The
upstream child gets only the variables listed here, plus the SDK's minimal set (``HOME``, ``LOGNAME``,
``PATH``, ``SHELL``, ``TERM``, ``USER``); the proxy's other variables, such as judge keys, are not passed.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from ..action import MAX_TOOL_NAME_CHARS, TOOL_NAME
from ..fields import FIELD_NAME
from ..guard import GuardConfigError
from ..guard import valid_claim as _guard_claim
from ..strict import StrictParseError, load_file_strict

ON_SCHEMA_CHANGE = ("refuse", "warn")
HOOK = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*")
DEFAULT_CALL_TIMEOUT_SECONDS = 60.0
MAX_CALL_TIMEOUT_SECONDS = 3600.0
MAX_PROPOSAL_CHARS = 1000
SCHEMA_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
# Upstream tool names are MCP names (case-sensitive, a little wider than a signed tool id).
UPSTREAM_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,127}")

_TOP_KEYS = {"constitution", "keys", "ledger", "judges", "witness_public_key", "head_anchor", "ttl_seconds",
             "agent_session_env", "agent_id", "hosting", "allow_unresolved_identity", "upstream", "tools"}
_REQUIRED_TOP = ("constitution", "keys", "ledger", "judges", "upstream")
_KEY_KEYS = {"principal"}
_UPSTREAM_KEYS = {"command", "env", "cwd", "schema_digest", "on_schema_change", "call_timeout_seconds"}
_TOOL_KEYS = {"claim", "proposal", "upstream_name", "facts"}


class ProxyConfigError(ValueError):
    """The proxy refuses to start with this configuration."""


@dataclass(frozen=True)
class ToolPolicy:
    """Per-tool settings. ``claim`` is ``floor``, ``none`` (omitted, so ``classified``), or a data class.
    ``facts`` maps each caller-supplied field the tool maps to its hook, ``module:function``."""
    claim: str = "none"
    proposal: str | None = None
    upstream_name: str | None = None
    facts: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class EnvValue:
    """An upstream environment value: a literal, or the name of a variable in the proxy's environment."""
    literal: str | None = None
    from_env: str | None = None


@dataclass(frozen=True)
class UpstreamConfig:
    command: tuple[str, ...]
    env: Mapping[str, EnvValue]
    cwd: Path | None
    schema_digest: str
    on_schema_change: str = "refuse"
    call_timeout_seconds: float = DEFAULT_CALL_TIMEOUT_SECONDS

    def resolved_env(self, environ: Mapping[str, str] | None = None) -> dict[str, str]:
        """The child's extra variables. A ``{env: NAME}`` that is unset or empty refuses to start."""
        environ = os.environ if environ is None else environ
        out: dict[str, str] = {}
        for name, value in sorted(self.env.items()):
            if value.from_env is not None:
                got = environ.get(value.from_env)
                if not got:
                    raise ProxyConfigError(f"upstream_env_missing: upstream.env.{name} reads the environment "
                                           f"variable {value.from_env}, which is unset or empty")
                out[name] = got
            else:
                out[name] = value.literal or ""
        return out


@dataclass(frozen=True)
class ProxyConfig:
    path: Path
    constitution: Path
    principal_key: Path
    ledger: Path
    judges: Path
    upstream: UpstreamConfig
    tools: Mapping[str, ToolPolicy] = field(default_factory=dict)
    witness_public_key: Path | None = None
    head_anchor: Path | None = None
    ttl_seconds: int = 120
    agent_session_env: str | None = None
    agent_id: str | None = None
    hosting: str | None = None
    allow_unresolved_identity: bool = False

    def tool_policy(self, tool: str) -> ToolPolicy:
        return self.tools.get(tool) or ToolPolicy()


def _mapping(value: Any, where: str, allowed: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProxyConfigError(f"{where}: expected a mapping")
    extra = sorted(str(k) for k in set(value) - allowed)
    if extra:
        raise ProxyConfigError(f"{where}: unknown key(s) {extra}; allowed: {sorted(allowed)}")
    return value


def _text(value: Any, where: str, max_chars: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or value.startswith("REPLACE_"):
        raise ProxyConfigError(f"{where}: expected a non-empty string")
    if len(value) > max_chars:
        raise ProxyConfigError(f"{where}: longer than {max_chars} characters")
    return value


def _path(base: Path, value: Any, where: str) -> Path:
    path = Path(_text(value, where)).expanduser()
    return path if path.is_absolute() else (base / path)


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ProxyConfigError(f"{where}: expected true or false")
    return value


def _env_name(value: Any, where: str) -> str:
    if not isinstance(value, str) or not ENV_NAME.fullmatch(value):
        raise ProxyConfigError(f"{where}: expected an environment variable name")
    return value


def _command(value: Any) -> tuple[str, ...]:
    """A program and its arguments as a list. There is no shell: a string is refused."""
    if not isinstance(value, list) or not value:
        raise ProxyConfigError("upstream.command: expected a non-empty list (program, then arguments); "
                               "it is run without a shell")
    out = []
    for i, part in enumerate(value):
        if not isinstance(part, str) or not part or "\x00" in part:
            raise ProxyConfigError(f"upstream.command[{i}]: expected a non-empty string")
        out.append(part)
    return tuple(out)


def _env(value: Any) -> dict[str, EnvValue]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ProxyConfigError("upstream.env: expected a mapping of variable name to value or {env: NAME}")
    out: dict[str, EnvValue] = {}
    for name, item in value.items():
        where = f"upstream.env.{name}"
        _env_name(name, "upstream.env")
        if isinstance(item, str):
            if "\x00" in item:
                raise ProxyConfigError(f"{where}: contains a NUL character")
            out[name] = EnvValue(literal=item)
        elif isinstance(item, Mapping) and set(item) == {"env"}:
            out[name] = EnvValue(from_env=_env_name(item["env"], f"{where}.env"))
        else:
            raise ProxyConfigError(f"{where}: expected a string or {{env: NAME}}")
    return out


def _timeout(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= MAX_CALL_TIMEOUT_SECONDS:
        raise ProxyConfigError(f"upstream.call_timeout_seconds: expected a number in (0, {MAX_CALL_TIMEOUT_SECONDS:g}]")
    return float(value)


def _upstream(base: Path, value: Any) -> UpstreamConfig:
    up = _mapping(value, "upstream", _UPSTREAM_KEYS)
    for key in ("command", "schema_digest"):
        if key not in up:
            hint = " (run two-key mcp-draft-specs to get it)" if key == "schema_digest" else ""
            raise ProxyConfigError(f"upstream.{key}: required{hint}")
    digest = up["schema_digest"]
    if not isinstance(digest, str) or not SCHEMA_DIGEST.fullmatch(digest):
        raise ProxyConfigError("upstream.schema_digest: expected sha256:<64 lower-case hex digits> "
                               "(from two-key mcp-draft-specs)")
    on_change = up.get("on_schema_change", "refuse")
    if on_change not in ON_SCHEMA_CHANGE:
        raise ProxyConfigError(f"upstream.on_schema_change: expected one of {list(ON_SCHEMA_CHANGE)}")
    return UpstreamConfig(
        command=_command(up["command"]),
        env=_env(up.get("env")),
        cwd=_path(base, up["cwd"], "upstream.cwd") if "cwd" in up else None,
        schema_digest=digest,
        on_schema_change=on_change,
        call_timeout_seconds=_timeout(up["call_timeout_seconds"]) if "call_timeout_seconds" in up
        else DEFAULT_CALL_TIMEOUT_SECONDS,
    )


def valid_claim(value: Any, where: str) -> str:
    """``floor``, ``none``, or a data class (``financial+medical`` too), in canonical form."""
    try:
        return _guard_claim(value)
    except GuardConfigError as e:
        raise ProxyConfigError(f"{where}: {str(e).removeprefix('claim: ')}") from None


def _facts(value: Any, where: str) -> dict[str, str]:
    """``{field: {hook: "module:function"}}``. The hook is trusted operator code, imported at start."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ProxyConfigError(f"{where}: expected a mapping of caller-supplied field to {{hook: module:function}}")
    out = {}
    for name, entry in value.items():
        if not isinstance(name, str) or not FIELD_NAME.fullmatch(name):
            raise ProxyConfigError(f"{where}: {str(name)[:80]!r} is not a field name")
        if not isinstance(entry, Mapping) or set(entry) != {"hook"}:
            raise ProxyConfigError(f"{where}.{name}: expected {{hook: module:function}}")
        hook = entry["hook"]
        if not isinstance(hook, str) or not HOOK.fullmatch(hook):
            raise ProxyConfigError(f"{where}.{name}.hook: expected module:function")
        out[name] = hook
    return out


def _tools(value: Any) -> dict[str, ToolPolicy]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ProxyConfigError("tools: expected a mapping of signed tool id to settings")
    out: dict[str, ToolPolicy] = {}
    upstream_names: dict[str, str] = {}
    for tool, settings in value.items():
        if not isinstance(tool, str) or len(tool) > MAX_TOOL_NAME_CHARS or not TOOL_NAME.fullmatch(tool):
            raise ProxyConfigError(f"tools: {str(tool)[:80]!r} is not a signed tool id (lower case a-z, 0-9, _ . : / -)")
        where = f"tools.{tool}"
        settings = _mapping(settings if settings is not None else {}, where, _TOOL_KEYS)
        name = settings.get("upstream_name")
        if name is not None:
            if not isinstance(name, str) or not UPSTREAM_NAME.fullmatch(name):
                raise ProxyConfigError(f"{where}.upstream_name: expected an MCP tool name")
            if name in upstream_names:
                raise ProxyConfigError(f"{where}.upstream_name: {name!r} is also the upstream name of "
                                       f"{upstream_names[name]!r}")
            upstream_names[name] = tool
        proposal = settings.get("proposal")
        if proposal is not None:
            proposal = _text(proposal, f"{where}.proposal", MAX_PROPOSAL_CHARS)
        out[tool] = ToolPolicy(claim=valid_claim(settings.get("claim", "none"), f"{where}.claim"),
                               proposal=proposal, upstream_name=name,
                               facts=_facts(settings.get("facts"), f"{where}.facts"))
    return out


def _ttl(value: Any) -> int:
    from ..capability import MAX_TTL_SECONDS
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_TTL_SECONDS:
        raise ProxyConfigError(f"ttl_seconds: expected an integer from 1 to {MAX_TTL_SECONDS}")
    return value


def parse_proxy_config(data: Any, path: Path) -> ProxyConfig:
    """A validated ``ProxyConfig`` from a parsed document. ``path`` is the file it came from."""
    base = path.parent
    top = _mapping(data, "proxy config", _TOP_KEYS)
    for key in _REQUIRED_TOP:
        if key not in top:
            raise ProxyConfigError(f"{key}: required")
    keys = _mapping(top["keys"], "keys", _KEY_KEYS)
    if "principal" not in keys:
        raise ProxyConfigError("keys.principal: required (the principal private key)")
    meta = {}
    for key in ("agent_id", "hosting"):
        if key in top:
            meta[key] = _text(top[key], key, 256)
    return ProxyConfig(
        path=path,
        constitution=_path(base, top["constitution"], "constitution"),
        principal_key=_path(base, keys["principal"], "keys.principal"),
        ledger=_path(base, top["ledger"], "ledger"),
        judges=_path(base, top["judges"], "judges"),
        upstream=_upstream(base, top["upstream"]),
        tools=_tools(top.get("tools")),
        witness_public_key=(_path(base, top["witness_public_key"], "witness_public_key")
                            if "witness_public_key" in top else None),
        head_anchor=_path(base, top["head_anchor"], "head_anchor") if "head_anchor" in top else None,
        ttl_seconds=_ttl(top["ttl_seconds"]) if "ttl_seconds" in top else 120,
        agent_session_env=(_env_name(top["agent_session_env"], "agent_session_env")
                           if "agent_session_env" in top else None),
        allow_unresolved_identity=(_bool(top["allow_unresolved_identity"], "allow_unresolved_identity")
                                   if "allow_unresolved_identity" in top else False),
        **meta,
    )


def load_proxy_config(path: Path | str) -> ProxyConfig:
    path = Path(path)
    try:
        data = load_file_strict(path)
    except (OSError, StrictParseError) as e:
        raise ProxyConfigError(f"{path}: {e}") from None
    except ImportError:
        raise ProxyConfigError(f"{path}: reading YAML needs PyYAML (pip install \"two-key[mcp]\")") from None
    return parse_proxy_config(data, path)
