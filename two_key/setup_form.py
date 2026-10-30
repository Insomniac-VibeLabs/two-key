# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""What the ``two-key setup --window`` window checks and does, without the window (two_key/setup_gui.py).

The window collects the same answers the terminal interview asks for (two_key/setup_cmd.py) and hands them to
the same ``build``, so the files, the refusals and the ledger entry are the same. This module holds what the
window needs between the questions:

- :func:`review`: everything that would stop setup, what ``config check`` would warn about, and what is weaker
  than the profile's own, read from the answers as they stand.
- :func:`quorum_minimums`: the lowest number each quorum box accepts. Under ``high_assurance`` that is the
  profile's own number, so the window can only raise it (raising is stronger, never weaker).
- :data:`HIGH_ASSURANCE_SETTINGS`: what the ``high_assurance`` profile sets, which the window shows grayed out.
- :func:`save_answers`: the answers as a file for ``two-key setup --answers`` on a machine with no screen. It
  holds no secret: only the names of environment variables and the paths of files.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from . import _platform
from .setup_cmd import (ANSWER_KEYS, PROFILES, QUORUM_COUNTS, ROUTES, SetupError, build, cloud_judges,
                        load_answers, needs_upstream, profile_quorum, quorum_findings, tool_check_problems,
                        weaker_reasons)

HIGH_ASSURANCE = "high_assurance"
# What the high_assurance profile sets beyond the quorum numbers (docs/SETTINGS.md, "high_assurance"). The window
# shows each one grayed out while the switch is on.
HIGH_ASSURANCE_SETTINGS = (
    ("tool_specs.<tool>.tool_check", "required behind the proxy: a receipt key, or exempt (weaker, typed yes)"),
    ("quorum.require_local_yes", "true: a judge on this machine must vote yes"),
    ("on_writable_paths", "refuse: the proxy does not start when another account can change a file it runs or reads"),
    ("on_agent_access", "refuse: the proxy does not start when the agent's account could reach Two-Key's files"),
    ("siem plaintext sinks", "refused: no ledger copy is sent in the clear"),
    ("upstream.check_paths", "required: the upstream server's files are checked, or the proxy does not start"),
)
# The lowest each quorum box accepts under the default profile (two_key/quorum.py refuses less).
_DEFAULT_MINIMUMS = {"required_yes": 1, "min_responding": 1, "min_distinct_providers": 1, "min_makers": 1,
                     "min_local_judges": 0}


@dataclass
class Review:
    """The answers as they stand: ``problems`` stop setup, ``warnings`` are what ``config check`` would print,
    and ``weaker`` needs the typed yes."""
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    weaker: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return not self.problems


def quorum_minimums(profile: str, n_judges: int) -> dict[str, int]:
    """The lowest number each quorum box accepts: the profile's own under ``high_assurance``, else the least the
    quorum loader takes."""
    if profile != HIGH_ASSURANCE:
        return dict(_DEFAULT_MINIMUMS)
    try:
        return profile_quorum(HIGH_ASSURANCE, max(1, n_judges))
    except SetupError:
        return dict(_DEFAULT_MINIMUMS)


def clean(answers: Mapping) -> dict:
    """The answers without blank optional values, so a box left empty means "not given", as in the interview."""
    out = {}
    for key, value in answers.items():
        if key not in ANSWER_KEYS or value in (None, "", [], {}):
            continue
        out[key] = value
    return out


def review(answers: Mapping) -> Review:
    """Every problem, warning and weaker setting in ``answers``, in the order the window shows its pages."""
    found = Review()
    route, profile = answers.get("route", "proxy"), answers.get("profile", "default")
    if route not in ROUTES:
        found.problems.append(f"route: one of {', '.join(ROUTES)}")
    if profile not in PROFILES:
        found.problems.append(f"profile: one of {', '.join(PROFILES)}")
    judges = [j for j in answers.get("judges") or [] if isinstance(j, Mapping)]
    found.problems += _judge_problems(judges)
    found.problems += _agent_problems(answers.get("monitored_agent"))
    found.problems += _source_problems(answers)
    if route == "proxy":
        found.problems += _proxy_problems(answers, judges)
    found.warnings += _identity_warnings(judges, answers.get("monitored_agent"))
    if judges and not found.problems:
        _quorum_review(found, profile, judges, answers)
    return found


def _judge_problems(judges: list[Mapping]) -> list[str]:
    if not judges:
        return ["judges: at least one judge is needed"]
    out = []
    ids = [str(j.get("id") or "") for j in judges]
    if len(set(ids)) != len(ids):
        out.append("judges: each judge needs its own id")
    for n, judge in enumerate(judges, 1):
        for key in ("id", "type", "model"):
            if not judge.get(key):
                out.append(f"judge {n}: {key} is needed")
        if judge.get("type") in ("openai_compatible", "ollama") and not judge.get("base_url"):
            out.append(f"judge {n}: base URL is needed")
    return out


def _identity_warnings(judges: list[Mapping], agent: Any) -> list[str]:
    """``config check`` warns, and the proxy refuses to start, for a judge or agent nobody can tell the server of
    (``unresolved_identity``); setup itself goes ahead, as the terminal interview does (live run 11 decision)."""
    named = [(f"judge {n}", j) for n, j in enumerate(judges, 1)]
    if isinstance(agent, Mapping):
        named.append(("monitored agent", agent))
    return [f"{who}: Two-Key cannot tell who serves {spec.get('model')} at {spec.get('base_url')}; say where that "
            "address forwards the calls (upstream), or the proxy refuses to start (unresolved_identity)"
            for who, spec in named if needs_upstream(spec) and not spec.get("upstream")]


def _agent_problems(agent: Any) -> list[str]:
    if not isinstance(agent, Mapping):
        return ["monitored agent: id, model, provider and base URL are needed"]
    return [f"monitored agent: {key.replace('_', ' ')} is needed" for key in ("id", "model", "provider", "base_url")
            if not agent.get(key)]


def _source_problems(answers: Mapping) -> list[str]:
    out = []
    if not answers.get("rules_file") and not answers.get("tools"):
        out.append("rules: give a reviewed rules file, or name at least one tool for the starter rules")
    out += tool_check_problems(answers)
    passphrase = answers.get("key_passphrase_file")
    if passphrase and not os.path.isabs(str(passphrase)):
        out.append("principal key: the passphrase file needs an absolute path")
    for key, what in (("rules_file", "rules file"), ("prose_file", "prose file")):
        if answers.get(key) and not Path(str(answers[key])).is_file():
            out.append(f"{what}: {answers[key]} is not a file")
    return out


def _proxy_problems(answers: Mapping, judges: list[Mapping]) -> list[str]:
    out = []
    upstream = answers.get("upstream") if isinstance(answers.get("upstream"), Mapping) else {}
    if not upstream.get("command"):
        out.append("upstream: the command that starts the MCP server is needed")
    digest = upstream.get("schema_digest") or ""
    if digest and not str(digest).startswith("sha256:"):
        out.append("upstream: the schema digest starts with sha256:, or leave it blank to read it from the server")
    cloud = cloud_judges(list(judges))
    if cloud and not answers.get("agent_session_env"):
        out.append(f"agent session: judge(s) {', '.join(cloud)} are not on this machine and refuse a call without "
                   "the agent's session; name the environment variable that holds it")
    return out


def _quorum_review(found: Review, profile: str, judges: list[Mapping], answers: Mapping) -> None:
    counts = answers.get("quorum") or {}
    if counts:
        lowest = quorum_minimums(profile, len(judges))
        found.problems += [f"quorum: {name} is at least {lowest[name]} under {profile}" for name in QUORUM_COUNTS
                           if name in counts and counts[name] < lowest[name]]
    problem, lenient = quorum_findings(profile, list(judges), counts or {})
    if problem:
        found.problems.append(problem)
    found.warnings += lenient
    found.weaker += weaker_reasons(answers)


def save_answers(answers: Mapping, path: Path | str, *, overwrite: bool = False) -> Path:
    """Write the answers as JSON, owner-only, for ``two-key setup --answers``. Refuses an existing file unless
    ``overwrite``; then it is replaced, never written in place."""
    path = Path(path)
    data = (json.dumps(clean(answers), indent=2, sort_keys=True) + "\n").encode("utf-8")
    if path.exists() and not overwrite:
        raise SetupError(f"answers: {path} exists")
    staged = path.with_name(path.name + ".new")
    if staged.exists():
        staged.unlink()
    fd = _platform.create_new(staged, owner_only=True)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(staged, path)
    return path


def open_answers(path: Path | str) -> dict:
    """The answers in a file ``save_answers`` (or a person) wrote, checked as ``--answers`` checks them."""
    return load_answers(str(path))


def run_setup(answers: Mapping, target: Path | str, *, typed_yes: str, out=None,
              environ: Mapping[str, str] | None = None) -> dict:
    """Run ``build`` with these answers. Weaker answers go ahead only when ``typed_yes`` is exactly ``yes``, which
    the window's Review page asks for, as the interview and ``--confirm-weaker`` do."""
    def agreed(_prompt: str) -> bool:
        return typed_yes.strip() == "yes"
    return build(clean(answers), target, confirm_weaker=True, confirm=agreed, out=out, environ=environ)


__all__ = ["HIGH_ASSURANCE", "HIGH_ASSURANCE_SETTINGS", "Review", "clean", "open_answers", "quorum_minimums",
           "review", "run_setup", "save_answers"]
