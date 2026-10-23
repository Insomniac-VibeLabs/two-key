# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The environment for a child process a test starts: only what the test names, plus what the OS needs.

Windows cannot start networking (asyncio fails with WinError 10106) or find programs without a few system
variables, so on Windows the child keeps SYSTEMROOT, COMSPEC, PATHEXT, TEMP, TMP and USERPROFILE. Elsewhere it
gets PATH and what the test passes, nothing else.
"""

import os

WINDOWS_KEEP = ("SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP", "USERPROFILE")


def child_env(**extra: str) -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", "")}
    if os.name == "nt":
        env.update({name: os.environ[name] for name in WINDOWS_KEEP if name in os.environ})
    env.update(extra)
    return env
