# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""``two-key setup``: write a new deployment's files in one go, then check them (docs/SETUP.md).

It asks for the route (``proxy``, ``guard`` or ``library``), the profile (``default`` or ``high_assurance``), the
judges, the monitored agent, the rules to sign, and for the proxy the upstream server; or it reads the same
answers from ``--answers FILE``. It never asks for a secret: a judge's key, the agent's credential and the
agent session are named by environment variable, and their values stay out of every file. To encrypt the
principal key, it takes the path of a passphrase file (``key_passphrase_file``), never the passphrase.

It writes into a new folder beside the target, owner-only from the first byte, and renames that folder into
place only when the whole set passes ``config check`` (the proxy route) or loads and verifies (the others),
so a refused setup leaves nothing behind. Then it creates the ledger and records a ``config_changed`` entry
with each file's digest. It refuses to run as root and refuses a target that exists or a folder above it
that another account could change.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

from . import _platform, writable
from .config_set import (CONSTITUTION, JUDGES, PROXY, RULES, ConfigChangeError, LEDGER_KIND, account_label,
                         dump, refuse_root, sha256)

ROUTES = ("proxy", "guard", "library")
PROFILES = ("default", "high_assurance")
JUDGE_TYPES = ("openai_compatible", "anthropic", "gemini", "ollama")
DATA_CLASSES = ("public", "personal", "medical", "financial", "classified")
ANSWER_KEYS = {"route", "profile", "judges", "monitored_agent", "rules_file", "prose_file", "tools", "upstream",
               "agent_session_env", "key_passphrase_file"}

# Use-case agnostic on purpose: what a call may do is the rules' business, and the principal writes the rest.
STARTER_PROSE = """\
Vote yes only when the call is something the operator asked the agent to do, its arguments fit that
request, and nothing in it is a surprise. Vote no when the call goes beyond the request, when its
arguments look wrong for it, or when you are not sure.
"""

FILES = {"key": "principal.pem", "public": "principal.pub.pem", "prose": "constitution.md",
         "rules": "hard_rules.yaml", "constitution": "constitution.signed.json", "judges": "judges.yaml",
         "proxy": "proxy.yaml", "ledger": "ledger"}


class SetupError(ValueError):
    """Setup refused. Nothing was left behind."""


# -- answers -------------------------------------------------------------------------------------------------


Ask = Callable[[str], str]


def _ask(ask: Ask, question: str, default: str | None = None, choices: tuple[str, ...] | None = None) -> str:
    hint = f" ({'/'.join(choices)})" if choices else ""
    shown = f" [{default}]" if default else ""
    while True:
        answer = ask(f"{question}{hint}{shown}: ").strip()
        answer = answer or (default or "")
        if not answer:
            print("  an answer is needed", file=sys.stderr)
            continue
        if choices and answer not in choices:
            print(f"  one of {', '.join(choices)}", file=sys.stderr)
            continue
        return answer


def _yes(ask: Ask, question: str, default: bool) -> bool:
    return _ask(ask, question, "yes" if default else "no", ("yes", "no")) == "yes"


def interview(ask: Ask = input) -> dict:
    """The answers, asked one by one on the terminal. Nothing asked is a secret."""
    out: dict[str, Any] = {}
    print("Two-Key setup. Every answer can be changed later with two-key config set (docs/SETUP.md).\n"
          "Secrets are never asked for: give the NAME of the environment variable that will hold each one.")
    out["route"] = _ask(ask, "Route: proxy (two-key mcp-proxy in front of an MCP server), guard, or library",
                        "proxy", ROUTES)
    out["profile"] = _ask(ask, "Profile", "default", PROFILES)
    judges = [_ask_judge(ask, 1)]
    while _yes(ask, "Add another judge?", out["profile"] == "high_assurance" and len(judges) < 2):
        judges.append(_ask_judge(ask, len(judges) + 1))
    out["judges"] = judges
    out["monitored_agent"] = _ask_agent(ask)
    _optional(out, "key_passphrase_file", ask,
              "Principal key: absolute path of a file only this account can read, holding a passphrase to "
              "encrypt the key with (blank: not encrypted): ")
    if not _optional(out, "rules_file", ask, "Rules to sign: a reviewed rules file (for the proxy, rules.draft.yaml "
                     "from two-key mcp-draft-specs), or blank for a starter: "):
        out["tools"] = _ask_tools(ask)
    _optional(out, "prose_file", ask, "The prose the judges read: a file, or blank for a starter you edit later: ")
    if out["route"] == "proxy":
        command = shlex.split(_ask(ask, "Upstream MCP server: the command that starts it"))
        digest = ask("Upstream schema digest (sha256:...), or blank to read it from the server now "
                     "(starts it; needs the mcp extra): ").strip()
        out["upstream"] = {"command": command, "schema_digest": digest}
        _optional(out, "agent_session_env", ask,
                  "Name of the environment variable that holds the agent's session (blank: none): ")
    return out


def _optional(out: dict, key: str, ask: Ask, question: str) -> bool:
    """Asks a question that may be left blank; a non-blank answer is stored under ``key``."""
    answer = ask(question).strip()
    if answer:
        out[key] = answer
    return bool(answer)


def _ask_judge(ask: Ask, n: int) -> dict:
    kind = _ask(ask, f"Judge {n}: type", "openai_compatible", JUDGE_TYPES)
    judge: dict[str, Any] = {"id": _ask(ask, f"Judge {n}: id", f"judge{n}"), "type": kind,
                             "model": _ask(ask, f"Judge {n}: model")}
    if kind in ("openai_compatible", "ollama"):
        judge["base_url"] = _ask(ask, f"Judge {n}: base URL",
                                 "http://127.0.0.1:11434" if kind == "ollama" else None)
    _optional(judge, "maker", ask, f"Judge {n}: who made the model (blank: the provider): ")
    _optional(judge, "auth_env", ask,
              f"Judge {n}: name of the environment variable holding its API key (blank: none): ")
    return judge


def _ask_agent(ask: Ask) -> dict:
    agent: dict[str, Any] = {"id": _ask(ask, "Monitored agent: id", "monitored-agent"),
                             "model": _ask(ask, "Monitored agent: model"),
                             "provider": _ask(ask, "Monitored agent: provider (a label)"),
                             "base_url": _ask(ask, "Monitored agent: base URL")}
    env = ask("Monitored agent: name of the environment variable holding its credential (blank: none): ").strip()
    agent["credential_env" if env else "credential"] = env or "none"
    return agent


def _ask_tools(ask: Ask) -> list[dict]:
    """The starter rules' tools: each id, whether a call can be undone, and its lowest data class."""
    return [{"id": tool,
             "irreversible": _yes(ask, f"Tool {tool}: can a call not be undone?", True),
             "data_class_floor": _ask(ask, f"Tool {tool}: lowest data class", "classified", DATA_CLASSES)}
            for tool in shlex.split(_ask(ask, "Starter: the tool ids to allow, separated by spaces"))]


def load_answers(path: str) -> dict:
    from .strict import StrictParseError, load_file_strict
    try:
        data = load_file_strict(path)
    except (OSError, StrictParseError) as e:
        raise SetupError(f"--answers: {path}: {e}") from None
    if not isinstance(data, dict):
        raise SetupError(f"--answers: {path}: expected a mapping")
    unknown = sorted(set(data) - ANSWER_KEYS)
    if unknown:
        raise SetupError(f"--answers: unknown key(s) {unknown}; allowed: {sorted(ANSWER_KEYS)}")
    return data


# -- the files -----------------------------------------------------------------------------------------------


def _judge(spec: Mapping) -> dict:
    if not isinstance(spec, Mapping):
        raise SetupError("judges: each judge is a mapping")
    judge = {k: v for k, v in spec.items() if k != "auth_env"}
    if spec.get("auth_env"):
        judge["auth"] = {"type": "env", "var": spec["auth_env"]}
    return judge


def judges_doc(answers: Mapping) -> dict:
    judges = answers.get("judges")
    if not isinstance(judges, list) or not judges:
        raise SetupError("judges: at least one judge is needed")
    return {"monitored_agent": dict(answers.get("monitored_agent") or {}),
            "judges": [_judge(j) for j in judges],
            "quorum": {"profile": answers.get("profile", "default")}}


def starter_rules(tools: Any) -> dict:
    if not isinstance(tools, list) or not tools:
        raise SetupError("tools: name at least one tool, or give rules_file")
    specs = {}
    for tool in tools:
        if not isinstance(tool, Mapping) or not isinstance(tool.get("id"), str):
            raise SetupError("tools: each tool is a mapping with an id")
        specs[tool["id"]] = {"irreversible": tool.get("irreversible", True),
                             "data_class_floor": tool.get("data_class_floor", "classified")}
    return {"hard_rules": [{"id": "tools", "allow_only_tools": list(specs)}], "tool_specs": specs}


def proxy_doc(answers: Mapping, digest: str) -> dict:
    high = answers.get("profile") == "high_assurance"
    upstream = answers.get("upstream")
    if not isinstance(upstream, Mapping) or not upstream.get("command"):
        raise SetupError("upstream.command: the proxy route needs the upstream server's command")
    keys: dict[str, Any] = {"principal": FILES["key"]}
    if answers.get("key_passphrase_file"):
        keys["passphrase_file"] = str(answers["key_passphrase_file"])
    doc: dict[str, Any] = {
        "constitution": FILES["constitution"], "keys": keys, "ledger": FILES["ledger"],
        "judges": FILES["judges"],
        "upstream": {"command": list(upstream["command"]), "schema_digest": digest, "on_schema_change": "refuse",
                     "call_timeout_seconds": 60},
        "ttl_seconds": 120, "allow_unresolved_identity": False,
        "on_writable_paths": "refuse" if high else "warn", "on_agent_access": "refuse",
    }
    if answers.get("agent_session_env"):
        doc["agent_session_env"] = answers["agent_session_env"]
    return doc


def _write(path: Path, data: bytes) -> None:
    fd = _platform.create_new(path, owner_only=True)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _read_source(path: str, what: str) -> bytes:
    # The path is the operator's own answer (the interview, or the answers file they pass to setup), never an
    # agent's or the network's: setup reads the rules and prose the operator names so it can sign them, and it
    # refuses to run as root. SonarCloud reads the answers file as untrusted content; a check here would prove
    # nothing, so the finding is suppressed rather than worked around.
    try:
        return Path(path).read_bytes()  # NOSONAR
    except OSError as e:
        raise SetupError(f"{what}: {path}: {e.strerror}") from None


def _schema_digest(command: list[str], envelope: Mapping) -> str:
    """Read the upstream's tools and digest the signed ones, as ``mcp-draft-specs --constitution`` does."""
    try:
        from .mcp_proxy import sdk
        from .mcp_proxy.draft import signed_check
    except ImportError as e:
        raise SetupError(f"upstream.schema_digest: reading it from the server needs the mcp extra ({e}); give it "
                         "instead (two-key mcp-draft-specs --constitution prints it)") from None
    try:
        digest, missing, _ = signed_check(sdk.draft_tools(command, {}), envelope)
    except ValueError as e:
        raise SetupError(f"upstream.schema_digest: {e}") from None
    if missing:
        raise SetupError(f"upstream: the server does not list the signed tool(s) {list(missing)}")
    return digest


def build(answers: Mapping, target: Path | str, *, environ: Mapping[str, str] | None = None, out=None) -> dict:
    """Write and check every file in a new folder, rename it to ``target``, then create the ledger."""
    from .keys import generate_private_key, save_private_key, save_public_key
    out = sys.stdout if out is None else out
    try:
        refuse_root()
    except ConfigChangeError as e:
        raise SetupError(str(e)) from None
    route = answers.get("route", "proxy")
    if route not in ROUTES:
        raise SetupError(f"route: expected one of {list(ROUTES)}")
    if answers.get("profile", "default") not in PROFILES:
        raise SetupError(f"profile: expected one of {list(PROFILES)}")
    passphrase = _new_passphrase(answers.get("key_passphrase_file"))
    target = Path(os.path.abspath(target))
    staging = _staging(target)
    try:
        key = generate_private_key()
        save_private_key(staging / FILES["key"], key, passphrase=passphrase)
        save_public_key(staging / FILES["public"], key.public_key())
        envelope, signed = _write_constitution(staging, answers, key)
        _write(staging / FILES["judges"], dump(judges_doc(answers), staging / FILES["judges"], "setup"))
        written = ["key", "public", "prose", "rules", "constitution", "judges"]
        if route == "proxy":
            written.append("proxy")
        _write_proxy_and_check(staging, target, answers, envelope, key, environ, out)
        if os.path.lexists(target):
            raise SetupError(f"setup_target_exists: {target} appeared while setup ran")
        os.rename(staging, target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    _platform.fsync_dir(target.parent)
    record = _record_setup(target, key, written, signed.digest)
    return {"ok": True, "route": route, "dir": str(target),
            "files": [str(target / FILES[w]) for w in written], "ledger": str(target / FILES["ledger"]),
            "ledger_entry": record, "next": _next_steps(route, target, answers)}


def _new_passphrase(file: Any):
    """The passphrase that encrypts the new principal key, from the answer's file; None when none is given."""
    from .keys import check_new_passphrase, read_passphrase_file
    if not file:
        return None
    source = Path(str(file)).expanduser()
    if not source.is_absolute():
        raise SetupError("key_passphrase_file: give an absolute path; the proxy reads it from wherever it starts")
    try:
        return check_new_passphrase(read_passphrase_file(source))
    except ValueError as e:
        raise SetupError(str(e)) from None


def _staging(target: Path) -> Path:
    """A new owner-only folder beside ``target``, which must not exist and must sit in a folder only this
    account can change."""
    if os.path.lexists(target):
        raise SetupError(f"setup_target_exists: {target} exists; setup writes a new folder and never over one")
    parent = target.parent
    if not parent.is_dir():
        raise SetupError(f"setup_target_parent: {parent} is not a folder")
    found = writable.findings_for(parent, "folder")
    if found:
        raise SetupError(f"setup_target_unsafe: {found[0][0]}: {found[0][1]}; only Two-Key's own account may "
                         "change the folders above Two-Key's files (docs/CONNECTING.md)")
    staging = parent / f".{target.name}.setup-{os.urandom(4).hex()}"
    os.mkdir(staging, 0o700)
    _platform.owner_only_dir(staging)
    return staging


def _write_constitution(staging: Path, answers: Mapping, key):
    """The prose, the rules, and the constitution signed from them. Returns the envelope and what verified."""
    from .constitution import load_unsigned_with_fields, sign_constitution, verify_signed
    prose = _read_source(answers["prose_file"], "prose_file") if answers.get("prose_file") else \
        STARTER_PROSE.encode("utf-8")
    _write(staging / FILES["prose"], prose)
    if answers.get("rules_file"):
        rules_bytes = _read_source(answers["rules_file"], "rules_file")
    else:
        rules_bytes = dump(starter_rules(answers.get("tools")), staging / FILES["rules"], "setup")
    _write(staging / FILES["rules"], rules_bytes)
    try:
        text, rules, specs, fields = load_unsigned_with_fields(staging / FILES["prose"], staging / FILES["rules"])
        envelope = sign_constitution(text, rules, key, specs, fields=fields)
        signed = verify_signed(json.loads(json.dumps(envelope)), key.public_key())
    except (ValueError, TypeError) as e:
        raise SetupError(f"rules: {e}") from None
    _write(staging / FILES["constitution"], (json.dumps(envelope, indent=2) + "\n").encode("utf-8"))
    return envelope, signed


def _write_proxy_and_check(staging: Path, target: Path, answers: Mapping, envelope, key,
                           environ: Mapping[str, str] | None, out) -> None:
    """For the proxy route, proxy.yaml; then ``config check`` on the staged folder. A failure refuses."""
    from .config_cmd import FAIL, check
    from .config_set import ENVIRONMENT_ONLY
    if answers.get("route", "proxy") == "proxy":
        upstream = answers.get("upstream") if isinstance(answers.get("upstream"), Mapping) else {}
        digest = upstream.get("schema_digest") or _schema_digest(list(upstream.get("command") or []), envelope)
        _write(staging / FILES["proxy"], dump(proxy_doc(answers, digest), staging / FILES["proxy"], "setup"))
        findings = check(staging / FILES["proxy"], environ)
    else:
        findings = _check_library(staging, key)
    for level, line in findings:
        print(f"{level:<4}  {line.replace(str(staging), str(target))}", file=out)
    blocking = [t for level, t in findings if level == FAIL and not t.startswith(ENVIRONMENT_ONLY)]
    if blocking:
        raise SetupError(f"config_check_failed: {blocking[0].replace(str(staging), str(target))}; nothing was "
                         "written")


def _check_library(staging: Path, key) -> list[tuple[str, str]]:
    """The guard and library routes have no proxy.yaml: load the judges and verify the constitution."""
    from .config_cmd import FAIL, OK
    from .constitution import load_envelope, verify_signed
    from .identity import load_monitored_agent_file
    from .judges.config import load_config_file
    found = []
    try:
        signed = verify_signed(load_envelope(staging / FILES["constitution"]), key.public_key())
        found.append((OK, f"constitution: signed by the principal key, digest {signed.digest}"))
        judges, policy = load_config_file(staging / FILES["judges"])
        found.append((OK, f"judges: {len(judges)} load; required_yes {policy.required_yes}"))
        load_monitored_agent_file(staging / FILES["judges"])
        found.append((OK, "monitored_agent: declared"))
    except Exception as e:      # every loader's own error, reported as a refusal
        found.append((FAIL, f"{type(e).__name__}: {e}"))
    return found


def _record_setup(target: Path, key, written: list[str], constitution_hash: str) -> int:
    from .ledger import Ledger
    ledger = Ledger(target / FILES["ledger"], key)
    roles = {"proxy": PROXY, "judges": JUDGES, "rules": RULES, "constitution": CONSTITUTION}
    files = [{"role": roles.get(w, w), "file": FILES[w], "old_sha256": None,
              "new_sha256": sha256((target / FILES[w]).read_bytes())} for w in written if w != "key"]
    entry = ledger.append(LEDGER_KIND, {"command": "setup", "settings": [], "files": files, "signed": True,
                                        "weaker": [], "confirmed": False, "constitution_hash": constitution_hash,
                                        "account": account_label()})
    ledger.checkpoint()
    return entry.seq


def _next_steps(route: str, target: Path, answers: Mapping) -> list[str]:
    names = sorted({j.get("auth_env") for j in answers.get("judges") or [] if isinstance(j, Mapping)
                    and j.get("auth_env")} | {(answers.get("monitored_agent") or {}).get("credential_env")} -
                   {None, ""})
    steps = []
    if names:
        steps.append(f"set {', '.join(names)} in the proxy's own environment (values never go in a file)")
    if route == "proxy":
        steps += [f"two-key config check --config {target / FILES['proxy']}",
                  "start the proxy from the agent's host as another account (docs/CONNECTING.md)",
                  f"edit {target / FILES['prose']} if you used the starter, then sign it again"]
    else:
        steps += ["load these files from Python as docs/HOWTO.md 'Authorize from Python' shows"
                  + ("; the key is encrypted, so open it with load_private_key_file(path, "
                     "passphrase_source(PASSPHRASE_FILE))" if answers.get("key_passphrase_file") else ""),
                  "config set, get and undo work on a proxy config; on this route, edit the files and sign "
                  "again with two-key sign-constitution"]
    steps.append(f"keep a copy of {target / FILES['ledger']}.witness/witness.pub.pem where the ledger's account "
                 "cannot change it, and pin it (docs/HOWTO.md 'Pin the witness key')")
    return steps


def run(args) -> int:
    try:
        if args.answers:
            answers = load_answers(args.answers)
        else:
            if not sys.stdin.isatty():
                raise SetupError("setup asks its questions on a terminal; without one, give --answers FILE")
            answers = interview()
        result = build(answers, args.dir)
    except (SetupError, ConfigChangeError) as e:
        print(f"two-key: setup: refused: {e}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


__all__ = ["SetupError", "build", "interview", "load_answers"]
