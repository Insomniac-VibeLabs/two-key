"""File-access helpers for tests on Linux, macOS, and Windows (0.6.0).

POSIX tests set and read mode bits. Windows has no mode bits (Python reports 0o666 for every file), so
there ``chmod`` grants or removes an Everyone entry in the access list and ``private`` reads the access
list the way Two-Key does (``two_key._platform``).
"""

import os
import stat
import subprocess  # nosec B404 - runs icacls on Windows

from two_key import _platform

EVERYONE = "*S-1-1-0"


def chmod(path, mode: int) -> None:
    """``os.chmod`` on POSIX. On Windows: group or other bits grant Everyone read (or modify, for write
    bits); none removes that grant."""
    if not _platform.WINDOWS:
        os.chmod(path, mode)  # skipcq: BAN-B103 -- tests loosen and tighten modes on purpose
        return
    if mode & 0o077:  # pragma: no cover - Windows only
        rights = "M" if mode & 0o022 else ("RX" if os.path.isdir(path) else "R")
        args = ["/grant", f"{EVERYONE}:({rights})"]
    else:  # pragma: no cover
        args = ["/remove:g", EVERYONE]
    subprocess.run(["icacls", os.fspath(path), *args], check=True, capture_output=True)  # nosec B603 B607


def private(path) -> bool:
    """Whether only the owner can reach ``path``: mode 0600 (file) or 0700 (directory) on POSIX, an access
    list Two-Key accepts on Windows."""
    if os.path.isdir(path):
        return _platform.is_owner_only_dir(path)
    if not _platform.WINDOWS:
        return stat.S_IMODE(os.stat(path).st_mode) == 0o600
    fd = _platform.open_nofollow(path)  # pragma: no cover
    try:  # pragma: no cover
        return _platform.access_problem(fd) is None
    finally:  # pragma: no cover
        os.close(fd)
