# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Run 9: known weakenings of Two-Key, for `harness.py --sabotage NAME`.

A PASS in a live run says Two-Key denied what it should. It does not say the harness would have noticed if Two-Key
had not. Each patch here weakens one check in a COPY of the package (under tests/live/selftest/sabotage_<name>/pkg/),
and the self-test is run against that copy. A patch the harness turns into at least one FAIL is `caught`. One it does
not is `missed`: either a hole in the harness, or (`blind_spot`) a check the harness has no way to reach, which this
file states and the pass prints instead of leaving a PASS to imply coverage.

Nothing here touches `two_key/` in the repository: the copy is made by `apply`, the patch text must match the source
exactly once (a patch that stops matching after a refactor fails loudly, rather than silently weakening nothing), and
the harness grades with the real package. Runs with the stub bots, so it costs no GrokBot usage.
"""
from __future__ import annotations

import shutil
from pathlib import Path

# name -> {"file": path under two_key/, "edits": [(old, new), ...], "what": plain words, "blind_spot": reason or None}
PATCHES = {
    # The same machinery with nothing weakened: it must produce no FAIL, or a CAUGHT elsewhere proves nothing.
    "control": {"file": "core.py", "edits": [], "what": "nothing: the copy is the package as it is"},
    "path_a_ignored": {
        "file": "core.py",
        "edits": [("allowed = bool(path_a.allowed and quorum_passed and deny_reason is None)",
                   "allowed = bool(quorum_passed and deny_reason is None)")],
        "what": "Path A's verdict is computed and ledgered but no longer decides: only the judges do",
    },
    "missing_ballot_is_yes": {
        "file": "quorum.py",
        "edits": [("    if len(responding) < k_floor:\n", "    if False:\n"),
                  ("    yes = sum(1 for b in responding if b.vote == \"yes\")\n    if yes < policy.required_yes:",
                   "    yes = sum(1 for b in responding if b.vote == \"yes\") + abstain\n"
                   "    if yes < policy.required_yes:")],
        "what": "a judge that is down or returns a malformed ballot counts as a yes",
    },
    "scan_flag_ignored": {
        "file": "scan.py",
        "edits": [("        return cls(\"flagged\", tuple(categories) or (\"policy\",), scanner, version)",
                   "        return cls(\"clean\", (), scanner, version)")],
        "what": "a scanner's flagged answer is read as clean",
    },
    "siem_passes_arguments": {
        "file": "siem.py",
        "edits": [("    out = _pick(body, spec.sent)\n    for key in spec.hashed:",
                   "    out = dict(body)\n    for key in spec.hashed:")],
        "what": "the SIEM copy sends every field of a ledger entry, not only the allowlisted ones",
    },
    "upstream_paths_ignored": {
        "file": "mcp_proxy/core.py",
        "edits": [("    for path in named:\n        rule = _rule(path)", "    for path in []:\n        rule = _rule(path)")],
        "what": "the start-up checks no longer look at the upstream server's own files (issue #13)",
    },
    "config_confirmation_skipped": {
        "file": "config_set.py",
        "edits": [("    if not sys.stdin.isatty():\n        print(\"two-key: config: this change needs a typed yes on a "
                   "terminal; there is none\", file=sys.stderr)\n        return False",
                   "    return True\n    if not sys.stdin.isatty():\n        return False")],
        "what": "a weaker or signed `config set` no longer needs a typed yes on a terminal",
        "needs_non_root": True,      # the commands refuse to run as root, so a pass run as root cannot exercise them
    },
    "one_proxy_lock_skipped": {
        "file": "mcp_proxy/core.py",
        "edits": [("    if _platform.try_lock(fd):\n", "    if True:\n")],
        "what": "a second proxy for an agent already connected to the ledger starts anyway (0.8.0, D10)",
    },
    "ballot_rationale_kept": {
        "file": "quorum.py",
        "edits": [("        rec = {\"judge_id\": b.judge_id, \"vote\": b.vote,",
                   "        rec = {\"rationale\": b.rationale, \"judge_id\": b.judge_id, \"vote\": b.vote,")],
        "what": "each ballot record in the ledger keeps the judge's rationale text, not only its digest (0.8.0, D8)",
    },
    "history_digest_unbound": {
        "file": "core.py",
        "edits": [("                    history_digest = judge_history.digest(summary)",
                   "                    history_digest = judge_history.digest({**summary, \"planted\": True})")],
        "what": "the ledgered history digest no longer matches the summary the judges were sent (0.8.0, #1)",
    },
    "gateway_skips_argument_hash": {
        "file": "gateway.py",
        "edits": [("        if payload[\"args_hash\"] != hashed:", "        if False:")],
        "what": "the gateway no longer checks that the arguments it redeems are the ones the token was issued for",
        # The proxy authorizes and redeems in one process with the same bytes, and the harness can only hand it a
        # call, never a token. Nothing it can send reaches this comparison. Covered by tests/test_gateway_boundary.py
        # and tests/test_cli_tokens.py, which present a token for other arguments.
        "blind_spot": "the proxy mints and redeems in one process, so a live call never carries a token for other "
                      "arguments (unit tests present one)",
    },
}


def verdict(name: str, counts: dict, incidents: int = 0) -> str:
    """`caught`, `missed`, `blind_spot` (missed, as stated above), or `control_ok` / `control_failed`. A referee
    incident (a leaked argument value, say) is noticing too, though no case fails on it."""
    failed = counts.get("FAIL", 0) + counts.get("ERROR", 0) + incidents
    if name == "control":
        return "control_failed" if failed else "control_ok"
    if failed:
        return "caught"
    return "blind_spot" if PATCHES[name].get("blind_spot") else "missed"


def apply(name: str, repo: Path, dest: Path) -> Path:
    """Copy `repo/two_key` to `dest/two_key` and apply the patch there. Returns `dest`."""
    patch = PATCHES[name]
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(repo / "two_key", dest / "two_key", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    target = dest / "two_key" / patch["file"]
    text = target.read_text(encoding="utf-8")
    for old, new in patch["edits"]:
        if text.count(old) != 1:
            raise SystemExit(f"sabotage {name}: the text to weaken is not in two_key/{patch['file']} exactly once "
                             f"({text.count(old)} times); update tests/live/sabotage.py\n--- looked for ---\n{old}")
        text = text.replace(old, new)
    target.write_text(text, encoding="utf-8")
    return dest
