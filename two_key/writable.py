"""Paths another account could change, checked when Two-Key starts (0.6.0).

Two-Key's process holds the minting, principal, witness, and ledger keys, and runs the code it imports:
Two-Key itself, the libraries under it, judge callbacks, fact hooks, and scanner hooks. Whoever can change
one of those files, or a folder on Python's import path, or a file Two-Key reads its settings from, does not
have to get past Path A or the judges: they change what Two-Key does. So when a ``TwoKey`` starts, it looks
at those paths, and the folders above them, and names each one an account other than its own could change
(``_platform.write_problem``).

This finds a setup mistake (a virtualenv, a checkout, or a config file the agent's user can write). It is
not a defence against code that has already been changed, and it cannot see everything: the wrapper that
started the process, the upstream server's own files behind ``sudo``, or a group whose members are only
trusted accounts. A clean start is not proof; docs/CONNECTING.md is the checklist.

``on_writable_paths``: ``warn`` (the default) names each path on stderr and starts; ``refuse`` does not
start. ``high_assurance`` refuses, and does not accept ``warn``. There is no setting that turns it off.
"""

from __future__ import annotations

import os
import sys
from typing import Iterable

from . import _platform

MODES = ("warn", "refuse")
MAX_LINES = 10
GUIDE = "docs/CONNECTING.md"

# Results for paths of the running interpreter (its program, import path, and loaded modules), which do
# not change while it runs; a TwoKey built again in the same process does not look at them again.
_runtime_cache: dict[tuple[str, str], list[tuple[str, str]]] = {}
_runtime_memo: dict[tuple[str, str], str | None] = {}


class WritablePathsError(ValueError):
    """Two-Key refuses to start: a path it runs or reads could be changed by another account."""


def _key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _parents(path: str) -> list[str]:
    out = []
    parent = os.path.dirname(path)
    while parent and parent != path:
        out.append(parent)
        path, parent = parent, os.path.dirname(parent)
    return out


def _problem(path: str, rule: str, memo: dict) -> str | None:
    k = (_key(path), rule)
    if k not in memo:
        try:
            memo[k] = _platform.write_problem(path, rule)
        except OSError as e:
            # Fail closed: a path Two-Key cannot inspect is named, not passed.
            memo[k] = f"cannot be checked ({e.strerror or type(e).__name__})"
    return memo[k]


def findings_for(path, rule: str = "file", memo: dict | None = None) -> list[tuple[str, str]]:
    """``(path, problem)`` for ``path`` and every folder above it, named by their real paths.

    ``rule`` is ``file`` or ``folder`` (see ``_platform.write_problem``). A path that does not exist is
    checked through the nearest folder that does, as a folder: whoever can add entries there can create it.
    The folders above, both as written and with links resolved, are checked as parents, where only renaming
    or removing an entry counts. A link itself is not checked; the folder that holds it is.
    """
    memo = {} if memo is None else memo
    written = os.path.abspath(os.fspath(path))
    real = os.path.realpath(written)
    target = real
    while not os.path.lexists(target):
        parent = os.path.dirname(target)
        if not parent or parent == target:
            break
        target, rule = parent, "folder"
    checks: dict[str, tuple[str, str]] = {_key(target): (target, rule)}
    parents = _parents(real) + [os.path.realpath(p) for p in _parents(written) if not _platform.is_link(p)]
    for parent in parents:
        k = _key(parent)
        if k not in checks and os.path.isdir(parent):
            checks[k] = (parent, "parent")
    out = []
    for p, r in checks.values():
        problem = _problem(p, r, memo)
        if problem:
            out.append((p, problem))
    return out


def runtime_targets() -> list[tuple[str, str]]:
    """``(path, rule)`` for what this interpreter runs: its program, each entry on ``sys.path`` (the working
    directory for an empty one) with the ``.pth`` files in it, and each loaded module's file, compiled file,
    and folder."""
    targets: list[tuple[str, str]] = []
    if sys.executable:
        targets.append((sys.executable, "file"))
    for entry in list(sys.path):
        targets.extend(_import_path_targets(entry))
    for module in list(sys.modules.values()):
        targets.extend(_module_targets(module))
    return targets


def _import_path_targets(entry: object) -> list[tuple[str, str]]:
    """One ``sys.path`` entry: a file, or a folder and the ``.pth`` files in it."""
    if not isinstance(entry, str):
        return []
    try:
        entry = entry or os.getcwd()
    except OSError:         # the working directory was removed
        return []
    if os.path.isfile(entry):
        return [(entry, "file")]
    targets = [(entry, "folder")]
    try:
        names = sorted(os.listdir(entry))
    except OSError:
        return targets
    targets.extend((os.path.join(entry, n), "file") for n in names if n.endswith(".pth"))
    return targets


def _module_paths(module: object) -> list[object]:
    """A loaded module's file and compiled file, as ``__file__`` and ``__cached__`` and as its spec names
    them. Python 3.15 no longer sets ``__cached__``, so the compiled file is named only by
    ``__spec__.cached`` there; reading both keeps a ``__pycache__`` folder from going unchecked."""
    values = [getattr(module, "__file__", None), getattr(module, "__cached__", None)]
    spec = getattr(module, "__spec__", None)
    if spec is not None:
        if getattr(spec, "has_location", False):
            values.append(getattr(spec, "origin", None))
        try:
            values.append(spec.cached)
        except (AttributeError, NotImplementedError):    # a spec that is not a ModuleSpec, or no cache tag
            pass
    return values


def _module_targets(module: object) -> list[tuple[str, str]]:
    """A loaded module's file and compiled file, each with its folder."""
    targets: list[tuple[str, str]] = []
    for value in _module_paths(module):
        if isinstance(value, str) and value:
            for target in ((value, "file"), (os.path.dirname(os.path.abspath(value)), "folder")):
                if target not in targets:
                    targets.append(target)
    return targets


def _collapse(found: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    """One entry per path, and none under a folder already named: whoever can change the folder can
    change everything in it."""
    unique: dict[str, tuple[str, str]] = {}
    for path, problem in found:
        unique.setdefault(_key(path), (path, problem))
    folders = [k for k, (p, _) in unique.items() if os.path.isdir(p)]
    kept = []
    for k, item in sorted(unique.items()):
        if any(k != f and k.startswith(f.rstrip("\\/") + os.sep) for f in folders):
            continue
        kept.append(item)
    return kept


def check(paths: Iterable[tuple[str, str]] = (), *, runtime: bool = True) -> list[tuple[str, str]]:
    """Every ``(path, problem)`` for ``paths`` (``(path, rule)`` pairs) and, with ``runtime``, the
    interpreter's own paths; one per path, none under a folder already named."""
    found: list[tuple[str, str]] = []
    if runtime:
        for path, rule in runtime_targets():
            k = (_key(path), rule)
            if k not in _runtime_cache:
                _runtime_cache[k] = findings_for(path, rule, _runtime_memo)
            found.extend(_runtime_cache[k])
    memo: dict = {}
    for path, rule in paths:
        found.extend(findings_for(path, rule, memo))
    return _collapse(found)


def resolve_mode(mode: str | None, high_assurance: bool) -> str:
    """``warn`` or ``refuse`` from ``on_writable_paths`` and the quorum profile. Raises ``ValueError``."""
    if mode is not None and mode not in MODES:
        raise ValueError(f"on_writable_paths: expected one of {list(MODES)}")
    if high_assurance:
        if mode == "warn":
            raise ValueError("on_writable_paths: high_assurance refuses to start when another account can change "
                             "a path Two-Key runs or reads; remove on_writable_paths: warn")
        return "refuse"
    return mode or "warn"


def report(found: list[tuple[str, str]], mode: str, *, why: str, stream=None) -> None:
    """Name each path on stderr (at most ``MAX_LINES``); under ``refuse``, then raise ``WritablePathsError``."""
    if not found:
        return
    stream = sys.stderr if stream is None else stream
    for path, problem in found[:MAX_LINES]:
        print(f"two-key: WARNING: writable_path: {path}: {problem}; whoever can change it can change what "
              f"Two-Key runs or reads ({GUIDE})", file=stream)
    if len(found) > MAX_LINES:
        print(f"two-key: WARNING: writable_path: and {len(found) - MAX_LINES} more", file=stream)
    if mode == "refuse":
        path, problem = found[0]
        more = f" (and {len(found) - 1} more)" if len(found) > 1 else ""
        raise WritablePathsError(f"writable_path: {path}: {problem}{more}; {why} refuses to start until only "
                                 f"Two-Key's own account (or root or Administrators) can change these ({GUIDE})")


__all__ = ["MODES", "WritablePathsError", "check", "findings_for", "report", "resolve_mode", "runtime_targets"]
