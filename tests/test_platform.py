# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""two_key._platform: owner-only files and directories, no-follow opens, and locks (0.6.0).

The POSIX branches run on Linux and macOS, the Windows branches on the Windows runner.
"""

import os
import subprocess  # nosec B404 - starts this interpreter in a test
import sys
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from child_env import child_env
from perm import EVERYONE, chmod
from two_key import _platform
from two_key.keys import load_private_key_file, save_private_key
from two_key.ledger import Ledger, LedgerError

ROOT = Path(__file__).resolve().parent.parent


def loosen(path: Path) -> None:
    """Let other accounts read ``path`` (and write, if it is a directory)."""
    chmod(path, 0o644 if path.is_file() else 0o775)


def symlink_or_skip(test: unittest.TestCase, target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as e:  # Windows without the symlink privilege
        test.skipTest(f"cannot create a symlink here: {e}")


class Files(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def write_new(self, name="f", data=b"\x00\r\n\x1a\nend", **kw) -> Path:
        path = self.dir / name
        fd = _platform.create_new(path, **kw)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return path

    def test_a_new_file_is_owner_only_and_binary(self):
        path = self.write_new()
        self.assertEqual(path.read_bytes(), b"\x00\r\n\x1a\nend")   # no newline or Ctrl-Z translation
        fd = _platform.open_nofollow(path)
        try:
            self.assertIsNone(_platform.access_problem(fd))
            self.assertEqual(os.read(fd, 100), b"\x00\r\n\x1a\nend")
        finally:
            os.close(fd)

    def test_create_new_never_overwrites(self):
        path = self.write_new()
        with self.assertRaises(FileExistsError):
            _platform.create_new(path)

    def test_create_new_refuses_a_planted_symlink(self):
        target = self.write_new("target")
        symlink_or_skip(self, target, self.dir / "link")
        with self.assertRaises(FileExistsError):
            _platform.create_new(self.dir / "link")
        self.assertEqual(target.read_bytes(), b"\x00\r\n\x1a\nend")

    def test_open_nofollow_refuses_a_symlink(self):
        target = self.write_new("target")
        symlink_or_skip(self, target, self.dir / "link")
        with self.assertRaises(OSError):
            os.close(_platform.open_nofollow(self.dir / "link"))
        self.assertTrue(_platform.is_link(self.dir / "link"))
        self.assertFalse(_platform.is_link(target))

    @unittest.skipUnless(_platform.WINDOWS, "junctions are Windows only")
    def test_open_nofollow_refuses_a_junction(self):  # pragma: no cover
        import _winapi
        real = self.dir / "real"
        real.mkdir()
        _winapi.CreateJunction(str(real), str(self.dir / "junction"))
        self.assertTrue(_platform.is_link(self.dir / "junction"))
        with self.assertRaises(OSError):
            os.close(_platform.open_nofollow(self.dir / "junction"))

    def test_a_file_others_can_read_is_refused(self):
        path = self.write_new()
        loosen(path)
        fd = _platform.open_nofollow(path)
        try:
            problem = _platform.access_problem(fd)
        finally:
            os.close(fd)
        self.assertTrue(problem)
        if _platform.WINDOWS:
            self.assertIn(EVERYONE.lstrip("*"), problem)
        else:
            self.assertEqual(problem, "readable by group or others")

    def test_not_owner_only_file(self):
        path = self.write_new(owner_only=False)
        if not _platform.WINDOWS:
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_the_error_names_each_platform_fix(self):
        message = _platform.insecure("k.pem", "readable by group or others")
        if _platform.WINDOWS:
            self.assertIn('icacls "k.pem" /inheritance:r /grant:r "%USERNAME%":F', message)
        else:
            self.assertEqual(message, "k.pem is readable by group or others; chmod 600 it")

    def test_owner_only_dir(self):
        sub = self.dir / "keys"
        sub.mkdir()
        loosen(sub)
        self.assertTrue(_platform.dir_write_problem(sub) or not _platform.is_owner_only_dir(sub))
        _platform.owner_only_dir(sub)
        self.assertTrue(_platform.is_owner_only_dir(sub))
        self.assertIsNone(_platform.dir_write_problem(sub))

    def test_inside(self):
        sub = self.dir / "Ledger"
        sub.mkdir()
        self.assertTrue(_platform.inside(sub / "x", sub))
        self.assertTrue(_platform.inside(sub, sub))
        self.assertFalse(_platform.inside(self.dir / "Ledger.witness", sub))
        if _platform.WINDOWS:
            self.assertTrue(_platform.inside(str(sub).upper() + "\\x", sub))

    def test_replace(self):
        a, b = self.write_new("a", b"new"), self.write_new("b", b"old")
        _platform.replace(a, b)
        self.assertEqual(b.read_bytes(), b"new")
        self.assertFalse(a.exists())

    def test_resolve_program(self):
        if _platform.WINDOWS:
            self.assertTrue(_platform.resolve_program("cmd").lower().endswith("cmd.exe"))
        else:
            self.assertEqual(_platform.resolve_program("npx"), "npx")


class Lock(unittest.TestCase):
    CHILD = ("import sys, time; from two_key import _platform; fd = _platform.open_lock_file(sys.argv[1]); "
             "_platform.lock(fd); print(time.time(), flush=True); _platform.unlock(fd)")

    def test_another_process_waits_for_the_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "x.lock")
            fd = _platform.open_lock_file(path)
            try:
                _platform.lock(fd)
                child = subprocess.Popen([sys.executable, "-c", self.CHILD, str(path)],  # nosec B603
                                         stdout=subprocess.PIPE, text=True, env=child_env(PYTHONPATH=str(ROOT)))
                time.sleep(1.0)
                self.assertIsNone(child.poll())          # still waiting
                released = time.time()
                _platform.unlock(fd)
                out, _ = child.communicate(timeout=60)
            finally:
                os.close(fd)
            self.assertEqual(child.returncode, 0)
            self.assertGreaterEqual(float(out.strip()), released - 0.05)


class Callers(unittest.TestCase):
    def test_a_ledger_key_others_can_read_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = Ed25519PrivateKey.generate()
            led = Ledger(Path(tmp, "ledger"), key)
            led.append("note", {"ok": True})
            loosen(led.ledger_key_path)
            with self.assertRaisesRegex(LedgerError, "ledger_key_insecure"):
                Ledger(Path(tmp, "ledger"), key)

    def test_a_key_file_others_can_read_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "principal.pem")
            save_private_key(path, Ed25519PrivateKey.generate())
            load_private_key_file(path)
            loosen(path)
            with self.assertRaisesRegex(ValueError, "key_file_insecure"):
                load_private_key_file(path)

    def test_key_directories_are_owner_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            led = Ledger(Path(tmp, "ledger"), Ed25519PrivateKey.generate())
            led.append("note", {"ok": True})
            led.checkpoint()
            for directory in (led.ledger_key_path.parent, led.witness_path.parent):
                self.assertTrue(_platform.is_owner_only_dir(directory), directory)


if __name__ == "__main__":
    unittest.main(verbosity=2)
