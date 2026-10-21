# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
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
from ..judges.config import HOOK
from ..scan import FileArg, ScanConfigError, file_arg
from ..scanners import check_scan_block
from ..siem import SiemConfigError
from ..siem_sinks import check_siem_block
from ..strict import StrictParseError, load_file_strict

ON_SCHEMA_CHANGE = ("refuse", "warn")
DEFAULT_CALL_TIMEOUT_SECONDS = 60.0
MAX_CALL_TIMEOUT_SECONDS = 3600.0
MAX_PROPOSAL_CHARS = 1000
SCHEMA_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
# Upstream tool names are MCP names (case-sensitive, a little wider than a signed tool id).
UPSTREAM_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,127}")

_TOP_KEYS = {"constitution", "keys", "ledger", "judges", "witness_public_key", "head_anchor", "ttl_seconds",
             "agent_session_env", "agent_id", "hosting", "allow_unresolved_identity", "upstream", "tools", "scan",
             "on_writable_paths", "on_agent_access", "siem"}
_REQUIRED_TOP = ("constitution", "keys", "ledger", "judges", "upstream")
_KEY_KEYS = {"principal", "passphrase_file"}
_UPSTREAM_KEYS = {"command", "env", "cwd", "schema_digest", "on_schema_change", "call_timeout_seconds",
                  "check_paths"}
MAX_CHECK_PATHS = 64
_TOOL_KEYS = {"claim", "proposal", "upstream_name", "facts", "files"}


class ProxyConfigError(ValueError):
    """The proxy refuses to start with this configuration."""


@dataclass(frozen=True)
class ToolPolicy:
    """Per-tool settings. ``claim`` is ``floor``, ``none`` (omitted, so ``classified``), or a data class.
    ``facts`` maps each caller-supplied field the tool maps to its hook, ``module:function``. ``files`` lists
    the arguments that hold a file, for the content scanner (``scan:``)."""
    claim: str = "none"
    proposal: str | None = None
    upstream_name: str | None = None
    facts: Mapping[str, str] = field(default_factory=dict)
    files: tuple[FileArg, ...] = ()


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
    # The upstream's own files and folders, for the start-up checks (#13): absolute, and each must exist
    # when the proxy starts.
    check_paths: tuple[Path, ...] = ()

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
    # The content scanner block (two_key.scanners), checked for shape; built when the proxy starts.
    scan: Mapping[str, Any] | None = None
    # warn (None: the default) or refuse when another account can change a path the proxy runs or reads
    # (two_key/writable.py); high_assurance refuses either way.
    on_writable_paths: str | None = None
    # refuse (None: the default) or warn when the account that started the proxy (the agent host's) is
    # Two-Key's own, is root, cannot be told, or can change a path the proxy runs or reads
    # (two_key/agent_access.py); high_assurance refuses either way.
    on_agent_access: str | None = None
    # The SIEM export block (two_key.siem_sinks), checked for shape; the sinks are built when the proxy
    # starts. None: no copy leaves the ledger.
    siem: Mapping[str, Any] | None = None
    # The file holding the principal key's passphrase, when the key is encrypted (two_key/keys.py). The
    # proxy reads it at start; its stdin is the agent's channel, so it never prompts.
    principal_passphrase_file: Path | None = None

    def tool_policy(self, tool: str) -> ToolPolicy:
        return self.tools.get(tool) or ToolPolicy()

    def load_principal_key(self, *, prompt: bool = False):
        """The principal private key, opened with ``keys.passphrase_file`` when the key is encrypted. The
        proxy passes ``prompt=False``: there is no terminal on its stdin. A command run by hand may ask."""
        from ..keys import load_private_key_file, passphrase_source
        return load_private_key_file(self.principal_key,
                                     passphrase_source(self.principal_passphrase_file, prompt=prompt))


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


def _check_paths(value: Any) -> tuple[Path, ...]:
    """``upstream.check_paths``: absolute paths only. A relative one would be read against the proxy's
    folder, not the folder the upstream starts in, and ``~`` against the proxy's account, not the upstream's.
    On Windows a path needs its drive (or a UNC share): ``\\opt`` means a different folder on each drive."""
    if not isinstance(value, list) or not value:
        raise ProxyConfigError("upstream.check_paths: expected a non-empty list of absolute paths")
    if len(value) > MAX_CHECK_PATHS:
        raise ProxyConfigError(f"upstream.check_paths: at most {MAX_CHECK_PATHS} entries")
    out = []
    for i, item in enumerate(value):
        where = f"upstream.check_paths[{i}]"
        if not isinstance(item, str) or not item or "\x00" in item or not os.path.isabs(item) \
                or (os.name == "nt" and not os.path.splitdrive(item)[0]):
            raise ProxyConfigError(f"{where}: expected an absolute path")
        out.append(Path(item))
    return tuple(out)


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
        check_paths=_check_paths(up["check_paths"]) if "check_paths" in up else (),
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


def _files(base: Path, value: Any, where: str) -> tuple[FileArg, ...]:
    """``[{path: attachments[].content, kind: base64|base64url|path, folder: dir}]``; a relative folder is
    relative to the config file's directory."""
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ProxyConfigError(f"{where}: expected a list of {{path, kind, folder}}")
    out = []
    for i, item in enumerate(value):
        if isinstance(item, Mapping) and isinstance(item.get("folder"), str) and item["folder"]:
            item = dict(item, folder=str(_path(base, item["folder"], f"{where}[{i}].folder")))
        try:
            out.append(file_arg(item, f"{where}[{i}]"))
        except ScanConfigError as e:
            raise ProxyConfigError(str(e)) from None
    if len({f.path for f in out}) != len(out):
        raise ProxyConfigError(f"{where}: a path is declared twice")
    return tuple(out)


def _tools(value: Any, base: Path | None = None) -> dict[str, ToolPolicy]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ProxyConfigError("tools: expected a mapping of signed tool id to settings")
    out: dict[str, ToolPolicy] = {}
    upstream_names: dict[str, str] = {}
    for tool, settings in value.items():
        out[tool] = _tool_policy(tool, settings, base or Path("."), upstream_names)
    return out


def _tool_policy(tool: Any, settings: Any, base: Path, upstream_names: dict[str, str]) -> ToolPolicy:
    """One ``tools:`` entry. ``upstream_names`` (upstream name to tool id) spans the entries, so one upstream
    tool is not offered under two ids."""
    if not isinstance(tool, str) or len(tool) > MAX_TOOL_NAME_CHARS or not TOOL_NAME.fullmatch(tool):
        raise ProxyConfigError(f"tools: {str(tool)[:80]!r} is not a signed tool id (lower case a-z, 0-9, _ . : / -)")
    where = f"tools.{tool}"
    settings = _mapping(settings if settings is not None else {}, where, _TOOL_KEYS)
    name = _upstream_name(settings.get("upstream_name"), where, tool, upstream_names)
    proposal = settings.get("proposal")
    if proposal is not None:
        proposal = _text(proposal, f"{where}.proposal", MAX_PROPOSAL_CHARS)
    return ToolPolicy(claim=valid_claim(settings.get("claim", "none"), f"{where}.claim"),
                      proposal=proposal, upstream_name=name,
                      facts=_facts(settings.get("facts"), f"{where}.facts"),
                      files=_files(base, settings.get("files"), f"{where}.files"))


def _upstream_name(name: Any, where: str, tool: str, upstream_names: dict[str, str]) -> str | None:
    if name is None:
        return None
    if not isinstance(name, str) or not UPSTREAM_NAME.fullmatch(name):
        raise ProxyConfigError(f"{where}.upstream_name: expected an MCP tool name")
    if name in upstream_names:
        raise ProxyConfigError(f"{where}.upstream_name: {name!r} is also the upstream name of "
                               f"{upstream_names[name]!r}")
    upstream_names[name] = tool
    return name


def _ttl(value: Any) -> int:
    from ..capability import MAX_TTL_SECONDS
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_TTL_SECONDS:
        raise ProxyConfigError(f"ttl_seconds: expected an integer from 1 to {MAX_TTL_SECONDS}")
    return value


def _agent_access_mode(value: Any) -> str:
    if value not in ("warn", "refuse"):
        raise ProxyConfigError("on_agent_access: expected warn or refuse")
    return value


def _writable_mode(value: Any) -> str:
    if value not in ("warn", "refuse"):
        raise ProxyConfigError("on_writable_paths: expected warn or refuse")
    return value


def _scan_block(top: Mapping, tools: Mapping[str, ToolPolicy]) -> dict | None:
    """The checked ``scan:`` block, or None. A tool that declares files needs one."""
    scan = None
    if "scan" in top:
        try:
            scan = check_scan_block(top["scan"])
        except ScanConfigError as e:
            raise ProxyConfigError(str(e)) from None
    with_files = sorted(tool for tool, policy in tools.items() if policy.files)
    if with_files and scan is None:
        raise ProxyConfigError(f"tools: {with_files} declare files, which are for the content scanner; add a "
                               "scan: block")
    return scan


def _siem_block(top: Mapping) -> dict | None:
    """The checked ``siem:`` block, or None. The sinks are built when the proxy starts."""
    if "siem" not in top:
        return None
    try:
        return check_siem_block(top["siem"])
    except SiemConfigError as e:
        raise ProxyConfigError(str(e)) from None


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
    tools = _tools(top.get("tools"), base)
    scan = _scan_block(top, tools)
    return ProxyConfig(
        path=path,
        constitution=_path(base, top["constitution"], "constitution"),
        principal_key=_path(base, keys["principal"], "keys.principal"),
        ledger=_path(base, top["ledger"], "ledger"),
        judges=_path(base, top["judges"], "judges"),
        upstream=_upstream(base, top["upstream"]),
        tools=tools,
        scan=scan,
        siem=_siem_block(top),
        witness_public_key=(_path(base, top["witness_public_key"], "witness_public_key")
                            if "witness_public_key" in top else None),
        head_anchor=_path(base, top["head_anchor"], "head_anchor") if "head_anchor" in top else None,
        principal_passphrase_file=(_path(base, keys["passphrase_file"], "keys.passphrase_file")
                                   if "passphrase_file" in keys else None),
        ttl_seconds=_ttl(top["ttl_seconds"]) if "ttl_seconds" in top else 120,
        agent_session_env=(_env_name(top["agent_session_env"], "agent_session_env")
                           if "agent_session_env" in top else None),
        allow_unresolved_identity=(_bool(top["allow_unresolved_identity"], "allow_unresolved_identity")
                                   if "allow_unresolved_identity" in top else False),
        on_writable_paths=_writable_mode(top["on_writable_paths"]) if "on_writable_paths" in top else None,
        on_agent_access=_agent_access_mode(top["on_agent_access"]) if "on_agent_access" in top else None,
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
