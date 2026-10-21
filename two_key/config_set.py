"""``two-key config set``, ``config get`` and ``config undo``: change one setting of a proxy deployment.

The files stay separate (docs/SETTINGS.md says why); this module edits the right one for you. A setting is
named by its path in the file that holds it, the same path docs/SETTINGS.md lists, with list items numbered
(``siem.sinks[0].port``, ``judges[1].timeout``, ``hard_rules[2].deny_if.amount_usd_gt``) and a key that has a
dot in it in brackets (``tools[fs.read].claim``). The first part says which file: a ``proxy.yaml`` key,
``judges``/``quorum``/``monitored_agent`` for ``judges.yaml``, and ``hard_rules``/``tool_specs``/``fields`` for
the signed rules.

A change is refused, and nothing is written, unless all of this holds (docs/SETUP.md):

- **Two-Key's own account.** Not root, and every file it writes, and the folder that holds it, can be
  changed by no other account (``_platform.write_problem``). Run from the agent's account, Two-Key's files
  belong to someone else, so the change is refused. Nothing here can tell an agent that runs as Two-Key's
  own account from the operator; that setup is refused by the proxy itself (``agent_same_account``).
- **The whole new configuration passes** ``config check`` (two_key/config_cmd.py), staged beside the real
  files: what the profile forbids stays forbidden, because the check fails. Only the two findings about
  this shell's environment variables do not block, since the proxy's own environment may differ.
- **A weaker setting needs** ``--confirm-weaker`` **and a typed** ``yes`` on a terminal. What counts as
  weaker is :func:`weaker`, read from the loaded configuration, not from the key that changed.
- **A signed setting needs the principal key** (``--key``) and the rules file the constitution was signed
  from (``--rules``), which must say exactly what is signed. The change is shown, confirmed with a typed
  ``yes``, signed, and the new envelope is verified before it replaces the old one. An encrypted principal
  key is opened with ``--key-passphrase-file``, else ``keys.passphrase_file``, else a prompt on the terminal.
- **No secret on the command line.** A value for ``upstream.env.*`` or ``scan.env.*`` that is a literal
  comes from ``--value-file`` or ``--prompt``, never from the arguments, where shell history and ``ps``
  keep it.

Then it records a ``config_changed`` ledger entry (setting names, file names and digests; never a value),
writes each file owner-only beside the old one and renames it into place, and keeps the previous version
as ``<file>.prev`` with ``<proxy config>.undo.json``, so ``config undo`` can put it back (and ``undo`` again
puts the change back). A running proxy keeps the settings it started with; a change takes effect at the
next start.

``config key-passphrase`` encrypts the principal key with a passphrase from a file, changes it, or (weaker)
removes it, and sets ``keys.passphrase_file`` to match, in one recorded change. It keeps no ``.prev``: a copy
of the key as it was would undo what the passphrase is for, so ``config undo`` does not reverse it.
"""

from __future__ import annotations

import copy
import getpass
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Mapping

from . import _platform, settings, writable

LEDGER_KIND = "config_changed"
UNDO_FORMAT = "two-key-config-undo-v1"
MAX_NAME_CHARS = 200
MAX_SETTINGS_RECORDED = 64

PROXY, JUDGES, RULES, CONSTITUTION, KEY = "proxy", "judges", "rules", "constitution", "key"
SETTINGS_FILE = {PROXY: settings.PROXY_YAML, JUDGES: settings.JUDGES_YAML, RULES: settings.RULES_YAML}
_JUDGES_TOP = ("judges", "quorum", "monitored_agent")
_RULES_TOP = ("hard_rules", "tool_specs", "fields")
# Which files Two-Key trusts, and which keys and ledger it uses (settings.NOT_SETTABLE). `setup` writes them; a
# change is a move to another deployment, made by hand and then checked, not one setting among others.
NOT_SETTABLE = tuple(sorted(key for file, key in settings.NOT_SETTABLE
                            if file == settings.PROXY_YAML and "." not in key))
# A literal here can be a secret (an upstream token, a scanner's password).
SECRET_LITERALS = (("upstream", "env"), ("scan", "env"))
# The findings of `config check` about this shell's variables: the proxy's own environment may differ.
ENVIRONMENT_ONLY = ("upstream_env_missing:", "agent_session_missing:")

_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")
_BRACKET = re.compile(r"\[([^\[\]]+)\]")


class ConfigChangeError(ValueError):
    """The change is refused. Nothing was written."""


# -- names ---------------------------------------------------------------------------------------------------


def parse_name(name: str) -> list[str | int]:
    """``siem.sinks[0].port`` -> ``["siem", "sinks", 0, "port"]``; ``tools[fs.read].claim`` keeps the dot."""
    if not isinstance(name, str) or not name or len(name) > MAX_NAME_CHARS or not name.isascii() \
            or not name.isprintable():
        raise ConfigChangeError(f"setting: expected a name of at most {MAX_NAME_CHARS} printable ASCII characters")
    tokens: list[str | int] = []
    i = 0
    while i < len(name):
        if name[i] == "[":
            token, i = _bracketed(name, i)
        else:
            token, i = _segment(name, i, first=not tokens)
        tokens.append(token)
    return tokens


def _bracketed(name: str, i: int) -> tuple[str | int, int]:
    """``[3]`` or ``[fs.read]`` at ``i``: the index or key, and where the next token starts."""
    m = _BRACKET.match(name, i)
    if not m:
        raise ConfigChangeError(f"setting {name!r}: an unclosed [ at {i}")
    inner = m.group(1)
    return (int(inner) if inner.isdigit() else inner), m.end()


def _segment(name: str, i: int, *, first: bool) -> tuple[str, int]:
    """A dotted key at ``i`` (after its ``.`` unless it is the first token), and where the next one starts."""
    if not first:
        if name[i] != ".":
            raise ConfigChangeError(f"setting {name!r}: expected . or [ at {i}")
        i += 1
    m = _SEGMENT.match(name, i)
    if not m:
        raise ConfigChangeError(f"setting {name!r}: expected a key at {i}")
    return m.group(0), m.end()


def format_name(tokens: list[str | int]) -> str:
    out = ""
    for t in tokens:
        if isinstance(t, int):
            out += f"[{t}]"
        elif _SEGMENT.fullmatch(t):
            out += f".{t}" if out else t
        else:
            out += f"[{t}]"
    return out


def role_for(tokens: list[str | int]) -> str:
    """Which file holds the setting. Raises ``ConfigChangeError`` for one this command does not change."""
    head = tokens[0]
    if head in _RULES_TOP:
        return RULES
    if head in ("quorum", "monitored_agent") or (head == "judges" and len(tokens) > 1):
        return JUDGES
    if head in NOT_SETTABLE:
        raise ConfigChangeError(f"not_settable: {head} names a file, key or ledger Two-Key trusts; change it by "
                                f"hand in proxy.yaml, then run two-key config check (docs/SETUP.md)")
    if head in ("prose", "constitution.md"):
        raise ConfigChangeError("not_settable: the prose is constitution.md; edit it and sign it again with "
                                "two-key sign-constitution")
    return PROXY


# Mappings whose keys the operator names, and what the catalogue calls such a key.
_FREE_KEYS = {
    (settings.PROXY_YAML, "tools"): "<id>",
    (settings.RULES_YAML, "tool_specs"): "<tool>",
    (settings.RULES_YAML, "tool_specs.<tool>.fields"): "<name>",
    (settings.RULES_YAML, "fields"): "<name>",
}


def pattern(role: str, tokens: list[str | int], doc: Any) -> str:
    """The catalogue key (two_key/settings.py) for a concrete setting name: ``siem.sinks[0].port`` is
    ``siem.sinks[syslog].port`` when that sink is a syslog sink, ``tools[fs.read].claim`` is
    ``tools.<id>.claim``."""
    file = SETTINGS_FILE[role]
    out: list[str] = []
    node = doc
    for t in tokens:
        here = ".".join(out)
        if isinstance(t, int):
            kind = ""
            if here == "siem.sinks" and isinstance(node, list) and t < len(node) and isinstance(node[t], Mapping):
                kind = str(node[t].get("type", ""))
            out[-1] += f"[{kind}]"
        else:
            out.append(_FREE_KEYS.get((file, here), t))
        node = _child(node, t)
    return ".".join(out)


def _child(node: Any, t: str | int) -> Any:
    if isinstance(t, int):
        return node[t] if isinstance(node, list) and 0 <= t < len(node) else None
    return node.get(t) if isinstance(node, Mapping) else None


def catalogue_row(role: str, tokens: list[str | int], doc: Any) -> settings.Setting | None:
    """The catalogue row for the setting, or for the nearest setting that holds it (a map such as
    ``upstream.env``)."""
    key = pattern(role, tokens, doc)
    file = SETTINGS_FILE[role]
    parts = key.split(".")
    while parts:
        row = settings.lookup(file, ".".join(parts))
        if row is not None:
            return row
        if parts[-1].endswith("]"):     # a whole list item: the list's own row
            parts[-1] = parts[-1][:parts[-1].rindex("[")]
        else:
            parts.pop()
    return None


def _secret_literal_path(tokens: list[str | int]) -> bool:
    return any(tuple(tokens[:2]) == p for p in SECRET_LITERALS)


def _has_literal(value: Any) -> bool:
    """Whether an env value holds a literal string anywhere (``{env: NAME}`` is a name, not a value)."""
    if isinstance(value, Mapping):
        if set(value) == {"env"}:
            return False
        return any(_has_literal(v) for v in value.values())
    return value is not None


def masked(tokens: list[str | int], value: Any) -> Any:
    """A value fit to print: each env literal (``upstream.env.NAME``, ``scan.env.NAME``) is ``<literal>``;
    ``{env: NAME}`` names a variable and is shown."""
    if isinstance(value, Mapping):
        return {k: masked(tokens + [k], v) for k, v in value.items()}
    if isinstance(value, list):
        return [masked(tokens + [i], v) for i, v in enumerate(value)]
    if len(tokens) == 3 and _secret_literal_path(tokens) and value is not None:
        return "<literal>"
    return value


# -- documents -----------------------------------------------------------------------------------------------


_MISSING = object()


def get_at(doc: Any, tokens: list[str | int]) -> Any:
    node = doc
    for t in tokens:
        if isinstance(t, int):
            if not isinstance(node, list) or not 0 <= t < len(node):
                return _MISSING
            node = node[t]
        else:
            if not isinstance(node, Mapping) or t not in node:
                return _MISSING
            node = node[t]
    return node


def set_at(doc: Any, tokens: list[str | int], value: Any, *, unset: bool = False) -> Any:
    """A copy of ``doc`` with the setting changed (or removed). Mappings on the way are created; a list item
    must exist, or be the next one (to add it)."""
    out = copy.deepcopy(doc) if doc is not None else {}
    if not isinstance(out, dict):
        raise ConfigChangeError("the file is not a mapping")
    name = format_name(tokens)
    node = _parent(out, tokens, unset, name)
    last = tokens[-1]
    if isinstance(last, int):
        _set_item(node, tokens, value, unset, name)
        return out
    if not isinstance(node, dict):
        raise ConfigChangeError(f"{name}: {format_name(tokens[:-1])} is not a mapping")
    if unset:
        if last not in node:
            raise ConfigChangeError(f"{name}: is not set")
        del node[last]
    else:
        node[last] = value
    return out


def _parent(out: dict, tokens: list[str | int], unset: bool, name: str) -> Any:
    """The node that holds the last token, creating the mappings on the way (not when unsetting)."""
    node: Any = out
    for i, t in enumerate(tokens[:-1]):
        if isinstance(t, int):
            if not isinstance(node, list) or not 0 <= t < len(node):
                raise ConfigChangeError(f"{name}: {format_name(tokens[:i + 1])} does not exist")
            node = node[t]
            continue
        if not isinstance(node, dict):
            raise ConfigChangeError(f"{name}: {format_name(tokens[:i])} is not a mapping")
        if t not in node or node[t] is None:
            if unset:
                raise ConfigChangeError(f"{name}: is not set")
            if isinstance(tokens[i + 1], int):
                raise ConfigChangeError(f"{name}: {format_name(tokens[:i + 1])} does not exist")
            node[t] = {}
        node = node[t]
    return node


def _set_item(node: Any, tokens: list[str | int], value: Any, unset: bool, name: str) -> None:
    """Set, add (at the next index) or remove a list item."""
    last = tokens[-1]
    if not isinstance(node, list):
        raise ConfigChangeError(f"{name}: {format_name(tokens[:-1])} is not a list")
    if unset:
        if not 0 <= last < len(node):
            raise ConfigChangeError(f"{name}: is not set")
        del node[last]
    elif last == len(node):
        node.append(value)
    elif 0 <= last < len(node):
        node[last] = value
    else:
        raise ConfigChangeError(f"{name}: the list has {len(node)} item(s); add one at [{len(node)}]")


def parse_value(text: str) -> Any:
    """JSON when it reads as JSON (``true``, ``120``, ``["a", "b"]``, ``{"env": "NAME"}``, ``"120"``); any
    other text is that string."""
    from .strict import StrictParseError, loads_json
    try:
        return loads_json(text)
    except StrictParseError:
        return text


def read_value_file(path: str) -> str:
    """A value from a file only its owner can read (a secret goes here, not on the command line). The text,
    without one final newline."""
    import stat
    try:
        fd = _platform.open_nofollow(path)
    except OSError as e:
        raise ConfigChangeError(f"--value-file: {path}: {e.strerror}") from None
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ConfigChangeError(f"--value-file: {path} is not a regular file")
        problem = _platform.access_problem(fh.fileno(), st)
        if problem:
            raise ConfigChangeError(f"value_file_insecure: {_platform.insecure(path, problem)}")
        data = fh.read(65537)
    if len(data) > 65536:
        raise ConfigChangeError(f"--value-file: {path} is longer than 64 KiB")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigChangeError(f"--value-file: {path} is not UTF-8 text") from None
    return text[:-1] if text.endswith("\n") else text


def dump(doc: Any, path: Path, by: str = "config set") -> bytes:
    """The file's new text: JSON for a ``.json`` file, YAML otherwise. Comments are not kept; the previous
    version is ``<file>.prev``. Read back strictly, it must be the same document."""
    from .strict import load_yaml, loads_json
    if path.suffix.lower() == ".json":
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        back = loads_json(text)
    else:
        import yaml
        kept = (f"Comments are not kept: the previous version is {path.name}.prev." if by == "config set"
                else "Change a setting with two-key config set (docs/SETUP.md).")
        text = (f"# Written by two-key {by}. {kept}\n# Every setting: docs/SETTINGS.md.\n"
                + yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, allow_unicode=True, width=100))
        back = load_yaml(text)
    if back != doc:
        raise ConfigChangeError(f"{path.name}: the new text does not read back as the same settings")
    return text.encode("utf-8")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# -- what counts as weaker -----------------------------------------------------------------------------------


_CLASS_RANK = {"public": 0, "personal": 1, "financial": 2, "medical": 2, "classified": 4}
_NEUTRAL_JUDGE_KEYS = {"timeout", "json_mode", "max_tokens", "response_format", "reasoning_effort"}


def _class_rank(claim: str, floor: str | None) -> int:
    if claim in ("none", None):
        return 4
    if claim == "floor":
        claim = floor or "classified"
    parts = claim.split("+")
    if len(parts) > 1:
        return 3 if "classified" not in parts else 4
    return _CLASS_RANK.get(claim, 4)


def _sinks(block: Mapping | None) -> dict[str, bool]:
    """Each SIEM sink by where it sends, and whether that is in the clear."""
    out: dict[str, bool] = {}
    for sink in (block or {}).get("sinks") or []:
        if not isinstance(sink, Mapping):
            continue
        if sink.get("type") == "webhook":
            url = str(sink.get("url", ""))
            out[f"webhook {url}"] = url.lower().startswith("http://")
        else:
            transport = sink.get("transport", "tls")
            out[f"syslog {sink.get('host')}:{sink.get('port', 'default')}/{transport}"] = transport in ("tcp", "udp")
    return out


@dataclass
class Posture:
    """What a configuration enforces, read through the loaders, for :func:`weaker`."""
    config: Any
    policy: Any
    judges_doc: Mapping
    signed: Mapping | None
    floors: Mapping[str, str] = field(default_factory=dict)
    key_encrypted: bool = False


def posture(config, judges_path: Path | None = None, envelope_path: Path | None = None) -> Posture:
    from .constitution import load_envelope
    from .judges.config import load_config_file
    from .keys import key_file_is_encrypted
    from .strict import load_file_strict
    judges_path = judges_path or config.judges
    _, policy = load_config_file(judges_path)
    judges_doc = load_file_strict(judges_path)
    try:
        signed = load_envelope(envelope_path or config.constitution).get("signed")
    except (OSError, ValueError):
        signed = None
    floors = {t: s.get("data_class_floor") for t, s in ((signed or {}).get("tool_specs") or {}).items()
              if isinstance(s, Mapping)}
    return Posture(config, policy, judges_doc if isinstance(judges_doc, Mapping) else {}, signed, floors,
                   key_file_is_encrypted(config.principal_key))


def _mode(value, high, resolve) -> str:
    try:
        return resolve(value, high)
    except ValueError:
        return "refuse"


def weaker(old: Posture, new: Posture) -> list[str]:
    """Why the new configuration enforces less than the old one, one line each (setting names, never a value
    that could be a secret). Empty when it does not."""
    from . import agent_access
    out: list[str] = []
    a, b = old.config, new.config
    pa, pb = old.policy, new.policy
    ha, hb = bool(pa.is_high_assurance), bool(pb.is_high_assurance)
    if ha and not hb:
        out.append("quorum: high_assurance turned off")
    if old.key_encrypted and not new.key_encrypted:
        out.append("keys.principal: the key is no longer encrypted")
    for name, resolve in (("on_writable_paths", writable.resolve_mode), ("on_agent_access", agent_access.resolve_mode)):
        if _mode(getattr(a, name), ha, resolve) == "refuse" and _mode(getattr(b, name), hb, resolve) == "warn":
            out.append(f"{name}: refuse to warn")
    if a.upstream.on_schema_change == "refuse" and b.upstream.on_schema_change == "warn":
        out.append("upstream.on_schema_change: refuse to warn")
    if set(a.upstream.check_paths) - set(b.upstream.check_paths):
        out.append("upstream.check_paths: a path is no longer checked")
    if not a.allow_unresolved_identity and b.allow_unresolved_identity:
        out.append("allow_unresolved_identity: turned on")
    if b.ttl_seconds > a.ttl_seconds:
        out.append("ttl_seconds: tokens live longer")
    if a.agent_session_env and not b.agent_session_env:
        out.append("agent_session_env: removed")
    old_sinks, new_sinks = _sinks(a.siem), _sinks(b.siem)
    if a.siem is not None and b.siem is None:
        out.append("siem: the copy to the SIEM is turned off")
    else:
        for label in sorted(set(old_sinks) - set(new_sinks)):
            out.append(f"siem: a sink no longer gets the copy ({label.split(' ')[0]})")
        for label, plain in sorted(new_sinks.items()):
            if plain and not old_sinks.get(label, False):
                out.append(f"siem: a sink sends in the clear ({label.split(' ')[0]})")
    if a.scan is not None and b.scan is None:
        out.append("scan: the content scanner is removed")
    for tool in sorted(set(a.tools) | set(b.tools)):
        pa_t, pb_t = a.tool_policy(tool), b.tool_policy(tool)
        floor = new.floors.get(tool) or old.floors.get(tool)
        if _class_rank(pb_t.claim, floor) < _class_rank(pa_t.claim, floor):
            out.append(f"tools.{tool}.claim: a lower data class")
        if {f.path for f in pa_t.files} - {f.path for f in pb_t.files}:
            out.append(f"tools.{tool}.files: a file is no longer declared for the scanner")
    out += _weaker_quorum(pa, pb)
    out += _weaker_judges(old.judges_doc, new.judges_doc)
    out += _weaker_signed(old.signed, new.signed)
    return out


def _weaker_quorum(pa, pb) -> list[str]:
    out = []
    for name in ("required_yes", "effective_min_responding", "min_distinct_providers", "min_makers",
                 "min_local_judges"):
        x, y = getattr(pa, name), getattr(pb, name)
        if x is not None and y is not None and y < x:
            out.append(f"quorum.{name.removeprefix('effective_')}: lowered")
    for name in ("require_local_yes",):
        if getattr(pa, name) and not getattr(pb, name):
            out.append(f"quorum.{name}: turned off")
    for name in ("tool_args_on_derive_deny", "tool_args_on_scan_flag"):
        if not getattr(pa, name) and getattr(pb, name):
            out.append(f"quorum.{name}: judges see more")
    if pa.judge_inputs == "record_only" and pb.judge_inputs != "record_only":
        out.append("quorum.judge_inputs: judges see the proposal")
    if pa.ballot_binding == "echo" and pb.ballot_binding != "echo":
        out.append("quorum.ballot_binding: echo to stamp")
    if pa.heterogeneity_scope == "responding" and pb.heterogeneity_scope != "responding":
        out.append("quorum.heterogeneity_scope: responding to selection")
    return out


def _judge_map(doc: Mapping) -> dict[str, Mapping]:
    return {str(j.get("id")): j for j in doc.get("judges") or [] if isinstance(j, Mapping)}


def _weaker_judges(old: Mapping, new: Mapping) -> list[str]:
    out = []
    a, b = _judge_map(old), _judge_map(new)
    if set(a) != set(b):
        out.append("judges: the judge set changed")
    for jid in sorted(set(a) & set(b)):
        changed = sorted(k for k in set(a[jid]) | set(b[jid])
                         if k not in _NEUTRAL_JUDGE_KEYS and a[jid].get(k) != b[jid].get(k))
        if changed:
            out.append(f"judges[{jid}]: {', '.join(changed)} changed")
    if old.get("monitored_agent") != new.get("monitored_agent"):
        out.append("monitored_agent: " + ("removed" if not new.get("monitored_agent") else "changed"))
    return out


_FLOOR_RANK = {"public": 0, "personal": 1, "medical": 2, "financial": 2, "classified": 4}


def _weaker_signed(old: Mapping | None, new: Mapping | None) -> list[str]:
    """Signed changes are weaker unless they only add a rule or tighten a tool spec (irreversible on, a higher
    floor, deny_unmapped on). Anything else is treated as weaker: the direction of an edit to a rule cannot
    be told in general."""
    if old is None or new is None or old == new:
        return []
    out = []
    old_rules, new_rules = old.get("hard_rules") or [], new.get("hard_rules") or []
    if old_rules != new_rules[:len(old_rules)]:
        out.append("hard_rules: a rule was changed or removed")
    if (old.get("fields") or {}) != (new.get("fields") or {}):
        out.append("fields: a custom field changed")
    a, b = old.get("tool_specs") or {}, new.get("tool_specs") or {}
    for tool in sorted(set(a) | set(b)):
        if tool not in a or tool not in b:
            out.append(f"tool_specs.{tool}: " + ("added" if tool not in a else "removed"))
            continue
        for key in sorted(set(a[tool]) | set(b[tool])):
            x, y = a[tool].get(key), b[tool].get(key)
            if x == y:
                continue
            if key == "irreversible" and x is False and y is True:
                continue
            if key == "deny_unmapped" and not x and y is True:
                continue
            if key == "data_class_floor" and _FLOOR_RANK.get(y, 4) > _FLOOR_RANK.get(x, 4):
                continue
            out.append(f"tool_specs.{tool}.{key}: changed")
    return out


# -- account and files ---------------------------------------------------------------------------------------


def _euid() -> int | None:
    return None if _platform.WINDOWS else os.geteuid()


def account_label() -> str:
    uid = _euid()
    if uid is None:  # pragma: no cover
        return os.environ.get("USERNAME", "unknown")
    return _platform.posix_account(uid)


def refuse_root() -> None:
    if _euid() == 0:
        raise ConfigChangeError("config_as_root: run this as Two-Key's own account, not as root; a file root "
                                "writes here belongs to root, and the proxy's account cannot then change it")


def check_target(path: Path) -> None:
    """A file this writes, and the folder it is in, can be changed by no other account; and it is a file."""
    if _platform.is_link(path):
        raise ConfigChangeError(f"config_target_link: {path} is a link; give the file it points to")
    if not path.is_file():
        raise ConfigChangeError(f"config_target_missing: {path} is not a file")
    found = writable.findings_for(path, "file") + writable.findings_for(path.parent, "folder")
    if found:
        where, problem = found[0]
        raise ConfigChangeError(f"config_target_unsafe: {where}: {problem}; only Two-Key's own account may change "
                                f"Two-Key's files, so run this as that account, and make them its own "
                                f"(docs/CONNECTING.md)")


def _staged_name(target: Path, what: str) -> Path:
    return target.parent / f".{target.stem}.{os.getpid()}.{os.urandom(4).hex()}.{what}{target.suffix}"


def _write_new(path: Path, data: bytes) -> None:
    fd = _platform.create_new(path, owner_only=True)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _read(path: Path) -> bytes:
    fd = _platform.open_nofollow(path)
    with os.fdopen(fd, "rb") as fh:
        return fh.read()


def undo_path(config_path: Path) -> Path:
    return config_path.parent / f"{config_path.name}.undo.json"


def prev_path(target: Path) -> Path:
    return target.parent / f"{target.name}.prev"


# -- applying a change ---------------------------------------------------------------------------------------


@dataclass
class FileChange:
    role: str
    path: Path
    new: bytes
    old: bytes = b""


@dataclass
class Change:
    command: str
    settings: list[str]
    files: list[FileChange]
    key: Any = None                 # the principal private key: signs the ledger entry (and the constitution)
    signed_before: Mapping | None = None
    signed_after: Mapping | None = None
    shown: list[str] = field(default_factory=list)


Confirm = Callable[[str], bool]


def terminal_confirm(prompt: str) -> bool:
    """A typed ``yes`` on a terminal. Without one (a pipe, a script, an agent), the answer is no."""
    if not sys.stdin.isatty():
        print("two-key: config: this change needs a typed yes on a terminal; there is none", file=sys.stderr)
        return False
    try:
        answer = input(prompt)
    except EOFError:
        return False
    return answer.strip() == "yes"


def _blocking(findings) -> list[str]:
    from .config_cmd import FAIL
    return [text for level, text in findings if level == FAIL and not text.startswith(ENVIRONMENT_ONLY)]


def apply(config_path: Path, config, change: Change, *, confirm_weaker: bool, confirm: Confirm,
          environ: Mapping[str, str] | None, out=None) -> dict:
    """Check, confirm, record, and write ``change``. Raises ``ConfigChangeError`` (nothing written) or returns
    what was done. ``change.key`` signs the ledger entry: the caller opens it before anything is staged, so a
    key that does not open refuses."""
    out = sys.stdout if out is None else out
    for fc in change.files:
        check_target(fc.path)
        fc.old = _read(fc.path)
    if os.path.lexists(undo_path(config_path)):
        check_target(undo_path(config_path))
    keep_prev = KEY not in {fc.role for fc in change.files}
    created: list[Path] = []
    recorded = False
    try:
        staged = _stage(change.files, "staged", created)
        reasons = _weaker_change(config, _checked(config, staged, environ))
        for line in change.shown:
            print(line, file=out)
        if reasons and not confirm_weaker:
            raise ConfigChangeError("weaker: " + "; ".join(reasons) + ". Run it again with --confirm-weaker to "
                                    "go ahead; nothing was written")
        signed = CONSTITUTION in staged
        for line in reasons:
            print(f"weaker: {line}", file=out)
        confirmed = _confirmed(change.command, reasons, signed, keep_prev, confirm, out)
        prevs = _stage(change.files, "prev", created, old=True) if keep_prev else {}
        record(config, ledger_body(change, reasons, confirmed=confirmed), change.key)
        recorded = True
        for fc in change.files:
            if keep_prev:
                _platform.replace(prevs[fc.role], prev_path(fc.path))
            _platform.replace(staged[fc.role], fc.path)
            _platform.fsync_dir(fc.path.parent)
        _write_undo(config_path, change, undoable=keep_prev)
    except OSError as e:
        if recorded:    # rare: a rename in a folder only this account can change failed
            raise ConfigChangeError(f"config_write_failed: {e}; the ledger records this change, but not every file "
                                    "was renamed into place: compare each file with its .prev") from None
        raise ConfigChangeError(f"config_write_failed: {e}; nothing was written") from None
    finally:
        for tmp in created:
            if os.path.lexists(tmp):
                os.unlink(tmp)
    return {"ok": True, "command": change.command, "settings": change.settings,
            "files": [str(fc.path) for fc in change.files], "weaker": reasons, "signed": signed,
            "next": "restart the proxy: a running proxy keeps the settings it started with"}


def _stage(files: list[FileChange], label: str, created: list[Path], *, old: bool = False) -> dict[str, Path]:
    """Each file's new (or, with ``old``, current) bytes in a new file beside it, by role."""
    staged: dict[str, Path] = {}
    for fc in files:
        tmp = _staged_name(fc.path, label)
        _write_new(tmp, fc.old if old else fc.new)
        created.append(tmp)
        staged[fc.role] = tmp
    return staged


def _checked(config, staged: Mapping[str, Path], environ: Mapping[str, str] | None):
    """The configuration as it would be with the staged files, after ``config check`` passed on it."""
    from . import config_cmd
    from .mcp_proxy.config import parse_proxy_config
    from .strict import load_file_strict
    new_config = config
    if PROXY in staged:
        try:
            new_config = parse_proxy_config(load_file_strict(staged[PROXY]), config.path)
        except (OSError, ValueError) as e:
            raise ConfigChangeError(f"config_invalid: {e}") from None
    check_config = replace(new_config, judges=staged.get(JUDGES, new_config.judges),
                           constitution=staged.get(CONSTITUTION, new_config.constitution),
                           principal_key=staged.get(KEY, new_config.principal_key))
    findings = config_cmd.check_config(check_config, environ)
    blocking = _blocking(findings)
    if blocking:
        for level, text in findings:
            print(f"{level:<4}  {text}", file=sys.stderr)
        raise ConfigChangeError(f"config_check_failed: {blocking[0]}" +
                                (f" (and {len(blocking) - 1} more)" if len(blocking) > 1 else "") +
                                "; nothing was written")
    return check_config


def _weaker_change(config, check_config) -> list[str]:
    """:func:`weaker` from the files as they are to the checked ones; either failing to load refuses."""
    try:
        before = posture(config)
    except Exception as e:      # every loader's own error: fail closed
        raise ConfigChangeError(f"config_current_invalid: the files as they are now do not load "
                                f"({type(e).__name__}: {e}), so whether this change weakens them cannot be "
                                "told; fix them by hand or with config undo, then run config check") from None
    try:
        after = posture(check_config)
    except Exception as e:      # the check passed, so this is not expected; fail closed
        raise ConfigChangeError(f"config_check_failed: {type(e).__name__}: {e}") from None
    return weaker(before, after)


def _confirmed(command: str, reasons: list[str], signed: bool, keep_prev: bool, confirm: Confirm, out) -> bool:
    """Asks for a typed yes when the change weakens, signs, or rewrites the key; refuses without one. Returns
    whether it asked."""
    if not (reasons or signed or not keep_prev):
        return False
    if signed:
        what = ("This puts back the previous signed constitution" if command == "undo" else
                "This signs a new constitution")
    elif not keep_prev:
        what = "This rewrites the principal key file, and config undo cannot reverse it"
    else:
        what = "This weakens what Two-Key enforces"
    if reasons and (signed or not keep_prev):
        what += ", and weakens what Two-Key enforces"
    out.flush()
    if not confirm(f"{what}. Type yes to go ahead: "):
        raise ConfigChangeError("not_confirmed: nothing was written")
    return True


def ledger_body(change: Change, reasons: list[str], *, confirmed: bool) -> dict:
    """The ``config_changed`` entry: setting names, file names and digests, never a value. The principal
    key file is named without digests."""
    constitution = next((fc for fc in change.files if fc.role == CONSTITUTION), None)
    signed_hash = None
    if constitution is not None:
        from .canonical import canonical_hash
        signed_hash = canonical_hash(json.loads(constitution.new.decode("utf-8"))["signed"])
    return {
        "command": change.command,
        "settings": change.settings[:MAX_SETTINGS_RECORDED],
        "files": [{"role": fc.role, "file": fc.path.name,
                   "old_sha256": None if fc.role == KEY else sha256(fc.old),
                   "new_sha256": None if fc.role == KEY else sha256(fc.new)} for fc in change.files],
        "signed": constitution is not None,
        "weaker": reasons[:MAX_SETTINGS_RECORDED],
        "confirmed": confirmed,
        "constitution_hash": signed_hash,
        "account": account_label(),
    }


def open_principal(config, passphrase=None):
    """The principal key this proxy uses (``keys.principal``), which signs the ledger. Encrypted, it opens
    with ``passphrase``, else ``keys.passphrase_file``, else a prompt on the terminal."""
    from .keys import load_private_key_file, passphrase_source
    if not (Path(config.ledger) / "entries.jsonl").is_file():
        raise ConfigChangeError(f"ledger_missing: no ledger at {config.ledger}; every change is recorded there, "
                                f"so start the proxy once (or run two-key setup) first")
    if passphrase is None:
        passphrase = passphrase_source(config.principal_passphrase_file)
    try:
        return load_private_key_file(config.principal_key, passphrase)
    except ValueError as e:
        raise ConfigChangeError(f"principal_key: {e}") from None


def record(config, body: dict, key) -> None:
    """Append ``config_changed`` to the deployment's ledger, signed with ``key``. A ledger that does not open
    refuses the change."""
    from .keys import load_public_key
    from .ledger import Ledger, LedgerError
    if not (Path(config.ledger) / "entries.jsonl").is_file():
        raise ConfigChangeError(f"ledger_missing: no ledger at {config.ledger}; every change is recorded there, "
                                f"so start the proxy once (or run two-key setup) first")
    try:
        witness = load_public_key(config.witness_public_key) if config.witness_public_key else None
        ledger = Ledger(config.ledger, key, witness_public_key=witness, anchor_path=config.head_anchor)
        ledger.append(LEDGER_KIND, body)
        ledger.checkpoint()
    except (OSError, ValueError, LedgerError) as e:
        raise ConfigChangeError(f"ledger_refused: {type(e).__name__}: {e}; nothing was written") from None


def _write_undo(config_path: Path, change: Change, *, undoable: bool = True) -> None:
    manifest = {"format": UNDO_FORMAT, "command": change.command, "settings": change.settings,
                "files": [{"role": fc.role, "path": str(fc.path), "before": sha256(fc.old),
                           "after": sha256(fc.new)} for fc in change.files] if undoable else [],
                "undoable": undoable}
    target = undo_path(config_path)
    tmp = _staged_name(target, "staged")
    try:
        _write_new(tmp, (json.dumps(manifest, indent=2) + "\n").encode("utf-8"))
        _platform.replace(tmp, target)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


# -- the commands --------------------------------------------------------------------------------------------


class _Lock:
    """One change at a time per proxy config."""

    def __init__(self, config_path: Path):
        self.path = config_path.parent / f".{config_path.name}.config.lock"

    def __enter__(self):
        self.fd = _platform.open_lock_file(self.path)
        _platform.lock(self.fd)
        return self

    def __exit__(self, *exc):
        try:
            _platform.unlock(self.fd)
        finally:
            os.close(self.fd)


def _load(config_path: Path):
    from .mcp_proxy.config import ProxyConfigError, load_proxy_config
    try:
        return load_proxy_config(config_path)
    except ProxyConfigError as e:
        raise ConfigChangeError(f"config_invalid: {e}; fix it by hand or run two-key config undo") from None


def _role_path(config, role: str) -> Path:
    return {PROXY: Path(config.path), JUDGES: Path(config.judges)}[role]


def _document(path: Path) -> Any:
    from .strict import StrictParseError, load_file_strict
    try:
        return load_file_strict(path)
    except (OSError, StrictParseError) as e:
        raise ConfigChangeError(f"{path}: {e}") from None


def get(config_path: Path | str, name: str) -> dict:
    """One setting: its value in the file (``None`` when the file does not set it), the file, the tier, and the
    catalogue's default and ``high_assurance`` note. An env literal is ``<literal>``."""
    config_path = Path(config_path).resolve()
    config = _load(config_path)
    tokens = parse_name(name)
    role = role_for(tokens)
    if role == RULES:
        from .constitution import load_envelope
        doc = load_envelope(config.constitution).get("signed") or {}
        where = str(config.constitution)
    else:
        path = _role_path(config, role)
        doc, where = _document(path), str(path)
    row = catalogue_row(role, tokens, doc)
    value = get_at(doc, tokens)
    return {"setting": format_name(tokens), "file": where, "tier": settings.SIGNED if role == RULES else
            settings.OPERATOR, "set": value is not _MISSING,
            "value": masked(tokens, None if value is _MISSING else value),
            "default": row.default if row else None, "high_assurance": (row.high_assurance or None) if row else None,
            "about": row.summary if row else None}


def set_setting(config_path: Path | str, name: str, value: Any = None, *, unset: bool = False,
                value_from: str = "argv", key_path: str | None = None, rules_path: str | None = None,
                confirm_weaker: bool = False, confirm: Confirm = terminal_confirm,
                environ: Mapping[str, str] | None = None, out=None,
                key_passphrase_file: str | None = None) -> dict:
    """``config set``: change one setting. ``value_from`` is ``argv``, ``file`` or ``prompt``."""
    refuse_root()
    config_path = Path(config_path).resolve()
    tokens = parse_name(name)
    role = role_for(tokens)
    if not unset and value_from == "argv" and _secret_literal_path(tokens) and _has_literal(value):
        raise ConfigChangeError(f"secret_on_command_line: a literal for {format_name(tokens)} can be a secret, and "
                                "the command line is kept in shell history and shown by ps; use --value-file FILE "
                                "or --prompt, or give {\"env\": \"NAME\"}")
    with _Lock(config_path):
        config = _load(config_path)
        passphrase = _passphrase(config, key_passphrase_file)
        if role == RULES:
            change = _signed_change(config, tokens, value, unset, key_path, rules_path, passphrase)
        else:
            path = _role_path(config, role)
            doc = _document(path)
            if catalogue_row(role, tokens, doc) is None:
                raise ConfigChangeError(f"unknown_setting: {format_name(tokens)} is not a setting of "
                                        f"{SETTINGS_FILE[role]}; docs/SETTINGS.md lists them")
            new_doc = set_at(doc, tokens, value, unset=unset)
            before = get_at(doc, tokens)
            change = Change("set", [format_name(tokens)], [FileChange(role, path, dump(new_doc, path))],
                            shown=[f"{format_name(tokens)} in {path.name}: "
                                   f"{_show(tokens, before)} -> {'(unset)' if unset else _show(tokens, value)}"],
                            key=open_principal(config, passphrase))
        return apply(config_path, config, change, confirm_weaker=confirm_weaker, confirm=confirm,
                     environ=environ, out=out)


def _show(tokens, value) -> str:
    if value is _MISSING:
        return "(not set)"
    return json.dumps(masked(tokens, value), ensure_ascii=False, default=str)


def _passphrase(config, passphrase_file: str | None):
    """Opens an encrypted principal key: ``--key-passphrase-file``, else ``keys.passphrase_file``, else a prompt;
    each key file is asked for once."""
    from .keys import passphrase_source, remember
    return remember(passphrase_source(passphrase_file or config.principal_passphrase_file))


def _principal(config, key_path: str | None, passphrase=None):
    """The principal key given with ``--key``; it must be the key the constitution and the proxy use."""
    from cryptography.hazmat.primitives import serialization
    from .keys import load_private_key_file
    if not key_path:
        raise ConfigChangeError("principal_key_needed: a signed setting is signed again; give the principal "
                                "private key with --key FILE")
    proxy_key = open_principal(config, passphrase)
    if Path(key_path).resolve() == Path(config.principal_key).resolve():
        return proxy_key
    try:
        key = load_private_key_file(key_path, passphrase)
    except ValueError as e:
        raise ConfigChangeError(str(e)) from None
    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    if key.public_key().public_bytes(*raw) != proxy_key.public_key().public_bytes(*raw):
        raise ConfigChangeError("principal_key_mismatch: --key is not the principal key this proxy uses "
                                "(keys.principal)")
    return key


def _envelope_rank(fmt: str) -> int:
    from .constitution import FORMAT_V1, FORMAT_V2, FORMAT_V3
    return {FORMAT_V1: 1, FORMAT_V2: 2, FORMAT_V3: 3}.get(fmt, 0)


def resign(signed: Mapping, rules_doc: Mapping, key, current_format: str) -> dict:
    """A new envelope for the rules document, with the signed prose, in at least the current format; verified
    with the key's public half before it is returned."""
    from .constitution import sign_constitution, verify_signed
    try:
        envelope = sign_constitution(signed["prose"], rules_doc.get("hard_rules"), key, rules_doc.get("tool_specs"),
                                     fields=rules_doc.get("fields"))
        if _envelope_rank(envelope["format"]) < _envelope_rank(current_format):
            envelope = sign_constitution(signed["prose"], rules_doc.get("hard_rules"), key,
                                         rules_doc.get("tool_specs"), fields=rules_doc.get("fields"),
                                         envelope_format="v3" if _envelope_rank(current_format) == 3 else "v2")
        verify_signed(json.loads(json.dumps(envelope)), key.public_key())
    except (ValueError, TypeError) as e:
        raise ConfigChangeError(f"constitution_refused: {e}") from None
    return envelope


def _plain(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def _signed_of(rules_doc: Mapping, prose: str, key) -> dict:
    """What signing ``rules_doc`` would put in the envelope (validated, canonical)."""
    from .constitution import sign_constitution
    try:
        return sign_constitution(prose, rules_doc.get("hard_rules"), key, rules_doc.get("tool_specs"),
                                 fields=rules_doc.get("fields"))["signed"]
    except (ValueError, TypeError) as e:
        raise ConfigChangeError(f"rules_invalid: {e}") from None


def _signed_change(config, tokens, value, unset, key_path, rules_path, passphrase) -> Change:
    from .constitution import load_envelope, verify_signed
    key = _principal(config, key_path, passphrase)
    if not rules_path:
        raise ConfigChangeError("rules_file_needed: a signed setting is changed in the rules file the constitution "
                                "was signed from; give it with --rules FILE")
    try:
        envelope = load_envelope(config.constitution)
        current = verify_signed(envelope, key.public_key())
    except (OSError, ValueError) as e:
        raise ConfigChangeError(f"constitution: {config.constitution}: {e}") from None
    rules_file = Path(rules_path).resolve()
    rules_doc = _document(rules_file)
    if not isinstance(rules_doc, Mapping):
        raise ConfigChangeError(f"{rules_file}: expected a mapping with hard_rules and tool_specs")
    signed_before = envelope["signed"]
    if _plain(_signed_of(rules_doc, current.prose, key)) != _plain(signed_before):
        raise ConfigChangeError(f"rules_source_differs: {rules_file} does not say what the constitution signs; "
                                "sign it with two-key sign-constitution (or put back what was signed) first, so "
                                "this change signs only itself")
    if catalogue_row(RULES, tokens, rules_doc) is None:
        raise ConfigChangeError(f"unknown_setting: {format_name(tokens)} is not a setting of hard_rules.yaml; "
                                "docs/SETTINGS.md lists them")
    new_doc = set_at(rules_doc, tokens, value, unset=unset)
    new_envelope = resign(signed_before, new_doc, key, envelope.get("format", ""))
    if _plain(new_envelope["signed"]) == _plain(signed_before):
        raise ConfigChangeError(f"unchanged: {format_name(tokens)} already signs as that")
    name = format_name(tokens)
    shown = [f"{name} (signed): {_show(tokens, get_at(rules_doc, tokens))} -> "
             f"{'(unset)' if unset else _show(tokens, value)}"]
    shown += signed_diff(signed_before, new_envelope["signed"])
    envelope_bytes = (json.dumps(new_envelope, indent=2) + "\n").encode("utf-8")
    return Change("set", [name], [FileChange(RULES, rules_file, dump(new_doc, rules_file)),
                                  FileChange(CONSTITUTION, Path(config.constitution), envelope_bytes)],
                  key=key, signed_before=signed_before, signed_after=new_envelope["signed"], shown=shown)


def signed_diff(before: Mapping, after: Mapping) -> list[str]:
    """What the new constitution signs differently, as ``- old`` / ``+ new`` lines per top-level part."""
    out = []
    for part in ("hard_rules", "tool_specs", "fields"):
        a, b = before.get(part), after.get(part)
        if a == b:
            continue
        a_lines = json.dumps(a, indent=1, sort_keys=True).splitlines() if a is not None else []
        b_lines = json.dumps(b, indent=1, sort_keys=True).splitlines() if b is not None else []
        import difflib
        out.append(f"signed {part}:")
        out += [f"  {line}" for line in difflib.unified_diff(a_lines, b_lines, lineterm="", n=1)][2:]
    return out


def undo(config_path: Path | str, *, key_path: str | None = None, confirm_weaker: bool = False,
         confirm: Confirm = terminal_confirm, environ: Mapping[str, str] | None = None, out=None,
         key_passphrase_file: str | None = None) -> dict:
    """``config undo``: put back the files of the last change. Running it again puts the change back."""
    from .constitution import verify_signed
    from .strict import StrictParseError, loads_json
    refuse_root()
    config_path = Path(config_path).resolve()
    manifest_path = undo_path(config_path)
    with _Lock(config_path):
        if not manifest_path.is_file():
            raise ConfigChangeError(f"nothing_to_undo: {manifest_path} does not exist")
        check_target(manifest_path)
        try:
            manifest = loads_json(_read(manifest_path))
        except (OSError, StrictParseError) as e:
            raise ConfigChangeError(f"undo_invalid: {manifest_path}: {e}") from None
        if not isinstance(manifest, dict) or manifest.get("format") != UNDO_FORMAT or not isinstance(
                manifest.get("files"), list):
            raise ConfigChangeError(f"undo_invalid: {manifest_path} is not a {UNDO_FORMAT} file")
        if manifest.get("undoable") is False:
            raise ConfigChangeError(f"nothing_to_undo: the last change was config {manifest.get('command')}, which "
                                    "keeps no copy of the key as it was; run config key-passphrase again to change "
                                    "the passphrase")
        config = _load(config_path)
        passphrase = _passphrase(config, key_passphrase_file)
        files: list[FileChange] = []
        for item in manifest["files"]:
            if not isinstance(item, dict) or item.get("role") not in (PROXY, JUDGES, RULES, CONSTITUTION):
                raise ConfigChangeError(f"undo_invalid: {manifest_path}: a file entry is not one this writes")
            path = Path(str(item.get("path")))
            expected = {PROXY: config_path, JUDGES: Path(config.judges).resolve(),
                        CONSTITUTION: Path(config.constitution).resolve()}.get(item["role"])
            if expected is not None and path.resolve() != expected:
                raise ConfigChangeError(f"undo_stale: {path} is no longer this proxy's {item['role']} file")
            prev = prev_path(path)
            check_target(path)
            check_target(prev)
            now, then = _read(path), _read(prev)
            if sha256(now) != item.get("after"):
                raise ConfigChangeError(f"undo_stale: {path} changed after the last config {manifest.get('command')}; "
                                        "put it back by hand from the .prev file if that is what you want")
            if sha256(then) != item.get("before"):
                raise ConfigChangeError(f"undo_stale: {prev} is not the version the last change replaced")
            files.append(FileChange(item["role"], path, then))
        by_role = {fc.role: fc for fc in files}
        if CONSTITUTION not in by_role:
            key = open_principal(config, passphrase)
        else:
            key = _principal(config, key_path, passphrase)
            restored = by_role[CONSTITUTION]
            try:
                verify_signed(loads_json(restored.new), key.public_key())
            except ValueError as e:
                raise ConfigChangeError(f"constitution_refused: the previous constitution does not verify: {e}") \
                    from None
        names = [str(s) for s in manifest.get("settings") or []][:MAX_SETTINGS_RECORDED]
        change = Change("undo", names, files, key=key,
                        shown=[f"undo: {', '.join(names) or '(no setting named)'} in "
                               f"{', '.join(fc.path.name for fc in files)}"])
        return apply(config_path, config, change, confirm_weaker=confirm_weaker, confirm=confirm,
                     environ=environ, out=out)


def change_key_encryption(config_path: Path | str, *, new_from: str | None = None, remove: bool = False,
                          confirm_weaker: bool = False, confirm: Confirm = terminal_confirm,
                          environ: Mapping[str, str] | None = None, out=None,
                          key_passphrase_file: str | None = None) -> dict:
    """``config key-passphrase``: encrypt the principal key with the passphrase in ``new_from`` (or change it),
    or, with ``remove``, store it unencrypted again; ``keys.passphrase_file`` follows, in the same change.

    The passphrase is read from a file because the proxy reads it from one at start: its stdin is the agent's
    channel. The file must be one only this account can read (``keys.read_passphrase_file``)."""
    from .keys import check_new_passphrase, private_key_bytes, read_passphrase_file
    refuse_root()
    if (new_from is None) == (not remove):
        raise ConfigChangeError("give exactly one of --new-from FILE or --remove")
    config_path = Path(config_path).resolve()
    with _Lock(config_path):
        config = _load(config_path)
        passphrase = _passphrase(config, key_passphrase_file)
        key = open_principal(config, passphrase)
        key_path = Path(config.principal_key)
        doc = _document(config_path)
        if not isinstance(doc, Mapping) or not isinstance(doc.get("keys"), Mapping):
            raise ConfigChangeError(f"config_invalid: {config_path} has no keys mapping")
        if remove:
            if not posture_key_encrypted(key_path):
                raise ConfigChangeError("unchanged: the principal key is not encrypted")
            new_key, setting = private_key_bytes(key), None
        else:
            source = Path(new_from).expanduser()
            if not source.is_absolute():
                raise ConfigChangeError("passphrase_file_relative: give the passphrase file as an absolute path; "
                                        "the proxy reads it from wherever it starts")
            try:
                new_key = private_key_bytes(key, check_new_passphrase(read_passphrase_file(source)))
            except ValueError as e:
                raise ConfigChangeError(str(e)) from None
            setting = str(source)
        keys_doc = dict(doc["keys"])
        if setting is None:
            keys_doc.pop("passphrase_file", None)
        else:
            keys_doc["passphrase_file"] = setting
        new_doc = dict(doc)
        new_doc["keys"] = keys_doc
        files = [FileChange(KEY, key_path, new_key), FileChange(PROXY, config_path, dump(new_doc, config_path))]
        if not remove:
            files.reverse()     # the proxy file first: a stop between the two leaves a key it can still open
        change = Change("key-passphrase", ["keys.principal", "keys.passphrase_file"], files, key=key,
                        shown=[f"keys.principal in {config_path.name}: "
                               + ("encrypted -> not encrypted" if remove else
                                  f"encrypted with the passphrase in {setting}")])
        return apply(config_path, config, change, confirm_weaker=confirm_weaker, confirm=confirm,
                     environ=environ, out=out)


def posture_key_encrypted(path: Path) -> bool:
    from .keys import key_file_is_encrypted
    try:
        return key_file_is_encrypted(path)
    except ValueError as e:
        raise ConfigChangeError(f"principal_key: {e}") from None


# -- the command line ----------------------------------------------------------------------------------------


def _report(result: dict) -> int:
    print(json.dumps(result, indent=2))
    return 0


def run_get(args) -> int:
    try:
        print(json.dumps(get(args.config, args.setting), indent=2, default=str))
    except (OSError, ValueError) as e:
        print(f"two-key: config get: {e}", file=sys.stderr)
        return 1
    return 0


def run_set(args) -> int:
    given = [args.value is not None, args.value_file is not None, bool(args.prompt), bool(args.unset)]
    if sum(given) != 1:
        print("two-key: config set: give exactly one of VALUE, --value-file FILE, --prompt, or --unset",
              file=sys.stderr)
        return 1
    try:
        if args.value_file is not None:
            value, source = read_value_file(args.value_file), "file"
        elif args.prompt:
            if not sys.stdin.isatty():
                raise ConfigChangeError("--prompt needs a terminal")
            value, source = getpass.getpass(f"value for {args.setting}: "), "prompt"
        else:
            value, source = (None if args.unset else parse_value(args.value)), "argv"
        result = set_setting(args.config, args.setting, value, unset=bool(args.unset), value_from=source,
                             key_path=args.key, rules_path=args.rules, confirm_weaker=args.confirm_weaker,
                             key_passphrase_file=args.key_passphrase_file)
    except ConfigChangeError as e:
        print(f"two-key: config set: refused: {e}", file=sys.stderr)
        return 1
    return _report(result)


def run_undo(args) -> int:
    try:
        result = undo(args.config, key_path=args.key, confirm_weaker=args.confirm_weaker,
                      key_passphrase_file=args.key_passphrase_file)
    except ConfigChangeError as e:
        print(f"two-key: config undo: refused: {e}", file=sys.stderr)
        return 1
    return _report(result)


def run_key_passphrase(args) -> int:
    try:
        result = change_key_encryption(args.config, new_from=args.new_from, remove=bool(args.remove),
                                confirm_weaker=args.confirm_weaker, key_passphrase_file=args.key_passphrase_file)
    except ConfigChangeError as e:
        print(f"two-key: config key-passphrase: refused: {e}", file=sys.stderr)
        return 1
    return _report(result)


__all__ = ["ConfigChangeError", "LEDGER_KIND", "apply", "change_key_encryption", "get", "parse_name", "set_setting",
           "undo", "weaker"]
