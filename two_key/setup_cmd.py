# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""``two-key setup``: write a new deployment's files in one go, then check them (docs/SETUP.md).

It asks for the route (``proxy``, ``guard`` or ``library``), the profile (``default`` or ``high_assurance``), the
judges, the quorum's numbers (offered at the profile's own), the monitored agent, the judge history settings,
the rules to sign, and for the proxy the upstream server and whether one proxy at a time may serve the agent;
or it reads the same
answers from ``--answers FILE``. It never asks for a secret: a judge's key, the agent's credential and the
agent session are named by environment variable, and their values stay out of every file. To encrypt the
principal key, it takes the path of a passphrase file (``key_passphrase_file``), never the passphrase.

A quorum number below the profile's own is weaker, as it is for ``config set``: the interview shows why and
keeps it only after a typed ``yes``; from ``--answers`` it needs ``--confirm-weaker`` and a typed ``yes`` on a
terminal. The ``config_changed`` entry setup records lists what was weaker. A proxy with a cloud judge needs
``agent_session_env``: without it every call that judge sees is denied (``cloud_judge_session_required``), so
the interview asks until it is named, ``config check`` fails, and ``mcp-proxy`` refuses to start without it.

It writes into a new folder beside the target, owner-only from the first byte, and renames that folder into
place only when the whole set passes ``config check`` (the proxy route) or loads and verifies (the others),
so a refused setup leaves nothing behind. Then it creates the ledger and records a ``config_changed`` entry
with each file's digest. It refuses to run as root and refuses a target that exists or a folder above it
that another account could change.
"""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

from . import _platform, writable
from .constitution import TOOL_CHECK_KEY
from .toolcheck import EXEMPT
from .config_set import (CONSTITUTION, JUDGES, PROXY, RULES, Confirm, ConfigChangeError, LEDGER_KIND,
                         account_label, dump, refuse_root, sha256, terminal_confirm, weaker_quorum)

ROUTES = ("proxy", "guard", "library")
PROFILES = ("default", "high_assurance")
JUDGE_TYPES = ("openai_compatible", "anthropic", "gemini", "ollama")
DATA_CLASSES = ("public", "personal", "medical", "financial", "classified")
ANSWER_KEYS = {"route", "profile", "judges", "quorum", "monitored_agent", "rules_file", "prose_file", "tools",
               "upstream", "agent_session_env", "key_passphrase_file", "judge_history", "one_proxy_per_agent"}
# The quorum numbers setup asks for; the other quorum settings keep their defaults until `config set`.
QUORUM_COUNTS = ("required_yes", "min_responding", "min_distinct_providers", "min_makers", "min_local_judges")
QUORUM_QUESTIONS = {
    "required_yes": "yes votes a call needs",
    "min_responding": "judges that must answer, or the call is denied uncounted",
    "min_distinct_providers": "different providers among those judges",
    "min_makers": "different makers of the judges' models",
    "min_local_judges": "judges that run on this host or its network",
}

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
    out["quorum"] = _ask_quorum(ask, out["profile"], judges)
    out["monitored_agent"] = _ask_agent(ask)
    out["judge_history"] = _ask_history(ask)
    _optional(out, "key_passphrase_file", ask,
              "Principal key: absolute path of a file only this account can read, holding a passphrase to "
              "encrypt the key with (blank: not encrypted): ")
    if not _optional(out, "rules_file", ask, "Rules to sign: a reviewed rules file (for the proxy, rules.draft.yaml "
                     "from two-key mcp-draft-specs), or blank for a starter: "):
        out["tools"] = _ask_tools(ask, out["profile"] if out["route"] == "proxy" else None)
    _optional(out, "prose_file", ask, "The prose the judges read: a file, or blank for a starter you edit later: ")
    if out["route"] == "proxy":
        command = shlex.split(_ask(ask, "Upstream MCP server: the command that starts it"))
        digest = ask("Upstream schema digest (sha256:...), or blank to read it from the server now "
                     "(starts it; needs the mcp extra): ").strip()
        out["upstream"] = {"command": command, "schema_digest": digest}
        _ask_session(out, ask, cloud_judges(judges))
        out["one_proxy_per_agent"] = _yes(ask, "Let only one proxy at a time serve this agent on this ledger? "
                                          "(no is weaker)", True)
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
    _ask_upstream(judge, ask, f"Judge {n}")
    _optional(judge, "auth_env", ask,
              f"Judge {n}: name of the environment variable holding its API key (blank: none): ")
    return judge


def needs_upstream(spec: Mapping) -> bool:
    """True when a judge's or the agent's address and model do not say who serves it (a local proxy, an
    unrecognized host): without ``upstream`` the proxy refuses to start with ``unresolved_identity``."""
    from .identity import resolve_upstream_info
    return bool(spec.get("base_url")) and not resolve_upstream_info(spec["base_url"], spec.get("model", ""))[0]


def _ask_upstream(spec: dict, ask: Ask, who: str) -> None:
    """``upstream`` for a judge or the agent that :func:`needs_upstream` (live run 11, D1)."""
    if not needs_upstream(spec):
        return
    _optional(spec, "upstream", ask, f"{who}: Two-Key cannot tell who serves {spec.get('model')} at "
                                     f"{spec['base_url']}; where does that address forward the calls (a host "
                                     "such as api.x.ai; stated by you, not checked; blank: none): ")


def _ask_quorum(ask: Ask, profile: str, judges: list[dict]) -> dict:
    """The five quorum numbers, each offered at the profile's own. A lower one is weaker: it is kept only after a
    typed yes, which is what ``config set --confirm-weaker`` asks for too."""
    defaults = profile_quorum(profile, len(judges))
    print(f"Quorum: the {profile} profile's numbers for {len(judges)} judge(s) are offered; a lower one is weaker.")
    while True:
        counts = {name: _ask_count(ask, f"Quorum: {name}, {QUORUM_QUESTIONS[name]}", defaults[name])
                  for name in QUORUM_COUNTS}
        problem, lenient = quorum_findings(profile, judges, counts)
        for line in lenient:
            print(f"  WARN  {line}", file=sys.stderr)
        if problem:
            print(f"  {problem}", file=sys.stderr)
            if _yes(ask, "Give the quorum numbers again? (no: keep them, and setup refuses at the end)", True):
                continue
            return counts
        reasons = weaker_reasons({"profile": profile, "judges": judges, "quorum": counts})
        if not reasons or _typed_yes(ask, reasons):
            return counts


def _ask_count(ask: Ask, question: str, default: int) -> int:
    while True:
        try:
            return int(_ask(ask, question, str(default)))
        except ValueError:
            print("  a whole number", file=sys.stderr)


def _typed_yes(ask: Ask, reasons: list[str]) -> bool:
    for line in reasons:
        print(f"weaker: {line}", file=sys.stderr)
    return ask("This weakens what the profile enforces. Type yes to keep these numbers, anything else to give "
               "them again: ").strip() == "yes"


def quorum_findings(profile: str, judges: list[dict], counts: Mapping) -> tuple[str | None, list[str]]:
    """Why the judges' loader would refuse these numbers for these judges (None when it would not, or when a
    judge itself does not load: ``build`` reports that one), and the warnings ``config check`` would print about
    a quorum that could be too lenient."""
    from .judges.config import JudgeConfigError, load_config
    from .quorum import lenient_warnings
    specs = [_judge(j) for j in judges]
    try:
        load_config({"judges": specs})
    except JudgeConfigError:
        return None, []
    try:
        loaded, policy = load_config({"judges": specs, "quorum": {"profile": profile, **counts}})
    except JudgeConfigError as e:
        return f"quorum: {e}", []
    return None, lenient_warnings(loaded, policy)


def _ask_session(out: dict, ask: Ask, cloud: list[str]) -> None:
    """``agent_session_env``. A cloud judge abstains on a call that comes without the agent's session, so with
    one the answer cannot be blank (live setup run, 2026-10-27)."""
    question = "Name of the environment variable that holds the agent's session"
    if not cloud:
        _optional(out, "agent_session_env", ask, f"{question} (blank: none): ")
        return
    print(f"Judge(s) {', '.join(cloud)} are not on this machine: each refuses a call that comes without the agent's "
          "session, so the proxy needs it.")
    out["agent_session_env"] = _ask(ask, question)


def _ask_agent(ask: Ask) -> dict:
    agent: dict[str, Any] = {"id": _ask(ask, "Monitored agent: id", "monitored-agent"),
                             "model": _ask(ask, "Monitored agent: model"),
                             "provider": _ask(ask, "Monitored agent: provider (a label)"),
                             "base_url": _ask(ask, "Monitored agent: base URL")}
    _ask_upstream(agent, ask, "Monitored agent")
    env = ask("Monitored agent: name of the environment variable holding its credential (blank: none): ").strip()
    agent["credential_env" if env else "credential"] = env or "none"
    return agent


def _ask_history(ask: Ask) -> dict:
    """``quorum.judge_history`` (0.8.0): the defaults unless the operator changes them; every "less" is weaker."""
    if not _yes(ask, "Show the judges a summary of recent decisions with each call? (no is weaker)", True):
        return {"enabled": False}
    on_failure = _ask(ask, "If that summary cannot be built: deny the call, or judge it without the summary "
                      "(weaker)", "deny", ("deny", "judge_without_history"))
    denies = _ask(ask, "Attempt episode: how many denied calls from the agent", "5")
    minutes = _ask(ask, "Attempt episode: within how many minutes", "10")
    try:
        return {"enabled": True, "on_failure": on_failure, "burst_denies": int(denies), "burst_minutes": int(minutes)}
    except ValueError:
        raise SetupError("judge_history: the episode counts are whole numbers") from None


def _ask_tools(ask: Ask, profile: str | None) -> list[dict]:
    """The starter rules' tools: each id, whether a call can be undone, and its lowest data class; behind the
    proxy (``profile`` given), also its tool check (#28)."""
    tools = []
    for tool in shlex.split(_ask(ask, "Starter: the tool ids to allow, separated by spaces")):
        entry = {"id": tool,
                 "irreversible": _yes(ask, f"Tool {tool}: can a call not be undone?", True),
                 "data_class_floor": _ask(ask, f"Tool {tool}: lowest data class", "classified", DATA_CLASSES)}
        if profile is not None:
            _ask_tool_check(entry, ask, profile)
        tools.append(entry)
    return tools


def _ask_tool_check(entry: dict, ask: Ask, profile: str) -> None:
    """The tool check: the fingerprint of the tool's receipt key, ``exempt``, or (not under high_assurance) off."""
    needed = profile == "high_assurance"
    question = (f"Tool {entry['id']}: tool check (docs/TOOL_CHECK.md): the receipt key's fingerprint "
                "(sha256:..., from two-key tool-key new), or exempt" + ("" if needed else ", or blank for off"))
    while True:
        answer = ask(question + ": ").strip()
        if not answer and not needed:
            return
        value = answer if answer == EXEMPT else {"key": answer}
        if not tool_check_problems({"route": "proxy", "profile": profile, "tools": [dict(entry, tool_check=value)]}):
            entry["tool_check"] = value
            return
        print("  give sha256: and 64 hex digits, or exempt" + ("" if needed else ", or leave it blank"))


def cloud_judges(judges: Any) -> list[str]:
    """The ids of the judges that run in the cloud (``LLMJudge.is_cloud``). A judge that does not load is left
    out: ``build`` reports it."""
    from .judges.config import JudgeConfigError, build_judge
    out = []
    for spec in judges if isinstance(judges, list) else []:
        try:
            judge = build_judge(_judge(spec))
        except (JudgeConfigError, SetupError):
            continue
        if getattr(judge, "is_cloud", lambda: False)():
            out.append(str(judge.judge_id))
    return out


def _policy(profile: str, counts: Mapping, n_judges: int):
    """The quorum policy the judges' loader builds from the profile and these numbers."""
    from .quorum import QuorumConfigError, QuorumPolicy
    make = QuorumPolicy.high_assurance if profile == "high_assurance" else QuorumPolicy
    try:
        return make(**counts).resolved(n_judges)
    except (QuorumConfigError, TypeError) as e:
        raise SetupError(f"quorum: {e}") from None


def profile_quorum(profile: str, n_judges: int) -> dict[str, int]:
    """The profile's own quorum numbers for this many judges: what setup offers, and what lower is weaker than."""
    policy = _policy(profile, {}, n_judges)
    return {"required_yes": policy.required_yes, "min_responding": policy.effective_min_responding,
            "min_distinct_providers": policy.min_distinct_providers, "min_makers": policy.min_makers,
            "min_local_judges": policy.min_local_judges}


def _quorum_answer(answers: Mapping) -> dict:
    """The ``quorum`` answer: some of the five numbers, or none."""
    counts = answers.get("quorum")
    if counts is None:
        return {}
    if not isinstance(counts, Mapping) or set(counts) - set(QUORUM_COUNTS):
        raise SetupError(f"quorum: expected a mapping of {list(QUORUM_COUNTS)}; set the other quorum settings "
                         "afterwards with two-key config set")
    return dict(counts)


def weaker_reasons(answers: Mapping) -> list[str]:
    """Why the answers enforce less than the profile's own, one line each (as ``config set`` words it): a lower
    quorum number, or under ``high_assurance`` a tool exempt from the tool check."""
    profile = answers.get("profile", "default")
    exempt = [f"tool_specs.{t['id']}.tool_check: exempt" for t in _tools(answers)
              if profile == "high_assurance" and t.get("tool_check") == EXEMPT]
    counts = _quorum_answer(answers)
    if not counts:
        return exempt
    judges = answers.get("judges")
    n_judges = len(judges) if isinstance(judges, list) else 0
    return weaker_quorum(_policy(profile, {}, n_judges), _policy(profile, counts, n_judges)) + exempt


def _tools(answers: Mapping) -> list[Mapping]:
    tools = answers.get("tools")
    return [t for t in tools if isinstance(t, Mapping) and isinstance(t.get("id"), str)] \
        if isinstance(tools, list) else []


def tool_check_problems(answers: Mapping) -> list[str]:
    """What is wrong with the starter tools' tool checks (#28): only behind the proxy, a fingerprint or
    ``exempt``, and under ``high_assurance`` one or the other for every tool (the proxy refuses to start). A
    reviewed rules file is checked by ``config check`` instead."""
    if answers.get("rules_file"):
        return []
    out = []
    proxy = answers.get("route", "proxy") == "proxy"
    for tool in _tools(answers):
        value = tool.get("tool_check")
        if value is None:
            if proxy and answers.get("profile") == "high_assurance":
                out.append(f"tool {tool['id']}: high_assurance needs the tool check: a receipt key's fingerprint "
                           "(two-key tool-key new) or exempt")
        elif not proxy:
            out.append(f"tool {tool['id']}: the tool check is only for tools behind two-key mcp-proxy")
        elif value != EXEMPT and not (isinstance(value, Mapping) and set(value) == {"key"}
                                      and isinstance(value["key"], str) and TOOL_CHECK_KEY.fullmatch(value["key"])):
            out.append(f"tool {tool['id']}: tool_check is exempt or {{key: sha256:<64 hex digits>}}")
    return out


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
    quorum: dict[str, Any] = {"profile": answers.get("profile", "default"), **_quorum_answer(answers)}
    history = answers.get("judge_history")
    if history is not None:
        if not isinstance(history, Mapping):
            raise SetupError("judge_history: expected a mapping (enabled, on_failure, burst_denies, ...)")
        quorum["judge_history"] = dict(history)
    return {"monitored_agent": dict(answers.get("monitored_agent") or {}),
            "judges": [_judge(j) for j in judges],
            "quorum": quorum}


NO_SERIAL = ("until a constitution with a serial runs, this ledger accepts any constitution signed with this key, "
             "an older one too (docs/HOWTO.md, The serial)")


def starter_rules(tools: Any) -> dict:
    if not isinstance(tools, list) or not tools:
        raise SetupError("tools: name at least one tool, or give rules_file")
    specs = {}
    for tool in tools:
        if not isinstance(tool, Mapping) or not isinstance(tool.get("id"), str):
            raise SetupError("tools: each tool is a mapping with an id")
        specs[tool["id"]] = {"irreversible": tool.get("irreversible", True),
                             "data_class_floor": tool.get("data_class_floor", "classified")}
        if tool.get("tool_check") is not None:
            specs[tool["id"]]["tool_check"] = tool["tool_check"]
    # serial 1: every later change signs a higher one, and the ledger refuses to go back (live run 9x, C44)
    return {"serial": 1, "hard_rules": [{"id": "tools", "allow_only_tools": list(specs)}], "tool_specs": specs}


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
    agent = answers.get("monitored_agent")
    if isinstance(agent, Mapping) and agent.get("id"):
        # The ledger names the agent by the proxy's agent_id; without it every decision records no agent and
        # the judges' history calls it "unnamed" (live walkthrough, 2026-10-27).
        doc["agent_id"] = str(agent["id"])
    if "one_proxy_per_agent" in answers:
        if not isinstance(answers["one_proxy_per_agent"], bool):
            raise SetupError("one_proxy_per_agent: expected true or false")
        doc["one_proxy_per_agent"] = answers["one_proxy_per_agent"]
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


@contextlib.contextmanager
def _owner_only_umask():
    """Close what setup creates without an explicit mode (the ledger, its key and witness folders, the public
    keys) to the group and others, whatever the shell's umask. Under Ubuntu's 002 the ledger was left
    group-writable and ``config check`` warned ``writable_path`` (live walkthrough, 2026-10-27)."""
    old = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(old)


def build(answers: Mapping, target: Path | str, *, environ: Mapping[str, str] | None = None, out=None,
          confirm_weaker: bool = False, confirm: Confirm = terminal_confirm) -> dict:
    """Write and check every file in a new folder, rename it to ``target``, then create the ledger. Weaker
    answers need ``confirm_weaker`` and a yes from ``confirm``, as ``config set`` does. Nothing it creates is
    writable by the group or others."""
    with _owner_only_umask():
        return _build(answers, target, environ=environ, out=out, confirm_weaker=confirm_weaker, confirm=confirm)


def _build(answers: Mapping, target: Path | str, *, environ: Mapping[str, str] | None, out, confirm_weaker: bool,
           confirm: Confirm) -> dict:
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
    problems = tool_check_problems(answers)
    if problems:
        raise SetupError("tools: " + "; ".join(problems))
    weaker = _confirmed_weaker(answers, confirm_weaker, confirm, out)
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
    record = _record_setup(target, key, written, signed.digest, weaker)
    return {"ok": True, "route": route, "dir": str(target),
            "files": [str(target / FILES[w]) for w in written], "ledger": str(target / FILES["ledger"]),
            "ledger_entry": record, "weaker": weaker, "next": _next_steps(route, target, answers)}


def _confirmed_weaker(answers: Mapping, confirm_weaker: bool, confirm: Confirm, out) -> list[str]:
    """What in the answers is weaker than the profile's own; refuses it without the flag and a typed yes."""
    reasons = weaker_reasons(answers)
    if not reasons:
        return []
    if not confirm_weaker:
        raise SetupError("weaker: " + "; ".join(reasons) + ". Run it again with --confirm-weaker to go ahead; "
                         "nothing was written")
    for line in reasons:
        print(f"weaker: {line}", file=out)
    out.flush()
    if not confirm("This weakens what the profile enforces. Type yes to go ahead: "):
        raise SetupError("not_confirmed: nothing was written")
    return reasons


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
    from .constitution import load_serial, load_unsigned_with_fields, sign_constitution, verify_signed
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
        serial = load_serial(staging / FILES["rules"])
        envelope = sign_constitution(text, rules, key, specs, fields=fields, serial=serial)
        signed = verify_signed(json.loads(json.dumps(envelope)), key.public_key())
    except (ValueError, TypeError) as e:
        raise SetupError(f"rules: {e}") from None
    _write(staging / FILES["constitution"], (json.dumps(envelope, indent=2) + "\n").encode("utf-8"))
    if serial is None:      # an operator's rules file; the starter has serial 1 (run 9y, S8)
        print(f"two-key: setup: WARNING: rules_file has no serial: {NO_SERIAL}", file=sys.stderr)
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


def _record_setup(target: Path, key, written: list[str], constitution_hash: str, weaker: list[str]) -> int:
    from .ledger import Ledger
    ledger = Ledger(target / FILES["ledger"], key)
    roles = {"proxy": PROXY, "judges": JUDGES, "rules": RULES, "constitution": CONSTITUTION}
    files = [{"role": roles.get(w, w), "file": FILES[w], "old_sha256": None,
              "new_sha256": sha256((target / FILES[w]).read_bytes())} for w in written if w != "key"]
    entry = ledger.append(LEDGER_KIND, {"command": "setup", "settings": [], "files": files, "signed": True,
                                        "weaker": weaker, "confirmed": bool(weaker),
                                        "constitution_hash": constitution_hash, "account": account_label()})
    ledger.checkpoint()
    return entry.seq


def _env_names(route: str, answers: Mapping) -> list[str]:
    """The variables the answers name: each judge's API key, the agent's credential, and (proxy) its session."""
    names = {j.get("auth_env") for j in answers.get("judges") or [] if isinstance(j, Mapping)}
    names.add((answers.get("monitored_agent") or {}).get("credential_env"))
    if route == "proxy":
        names.add(answers.get("agent_session_env"))
    return sorted(names - {None, ""})


def _next_steps(route: str, target: Path, answers: Mapping) -> list[str]:
    from .constitution import load_serial
    names = _env_names(route, answers)
    steps = []
    if names:
        steps.append(f"set {', '.join(names)} in the proxy's own environment (values never go in a file)")
    if answers.get("rules_file") and load_serial(target / FILES["rules"]) is None:
        steps.append(f"add serial: 1 to {target / FILES['rules']} and sign it again with two-key sign-constitution: "
                     f"{NO_SERIAL}")
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
            result = build(answers, args.dir, confirm_weaker=args.confirm_weaker)
        else:
            if not sys.stdin.isatty():
                raise SetupError("setup asks its questions on a terminal; without one, give --answers FILE")
            answers = interview()
            # The interview asked for the typed yes when the weaker numbers were given.
            result = build(answers, args.dir, confirm_weaker=True, confirm=lambda _prompt: True)
    except (SetupError, ConfigChangeError) as e:
        print(f"two-key: setup: refused: {e}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


__all__ = ["SetupError", "build", "interview", "load_answers"]
