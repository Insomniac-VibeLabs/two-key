"""The upstream server's own files in the proxy's start-up checks (#13, two_key/mcp_proxy/core.py).

With ``upstream.command: [sudo, -n, -u, mcp-billing, <interpreter>, <server script>]``, ``command[0]`` is the
launcher; the server is in the arguments. Each absolute argument that exists is checked (a file with its
folder), ``upstream.check_paths`` names more, and a launcher with nothing named warns
(``upstream_paths_unchecked``), or refuses under ``high_assurance``.
"""

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from perm import chmod
from two_key import writable
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.mcp_proxy import core
from two_key.mcp_proxy.config import MAX_CHECK_PATHS, ProxyConfigError, parse_proxy_config
from two_key.mcp_proxy.core import check_upstream_paths, launcher, startup_paths, upstream_paths
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

DIGEST = "sha256:" + "0" * 64
RULES = [{"id": "tools", "allow_only_tools": ["lookup"]}]
SPECS = {"lookup": {"irreversible": False, "data_class_floor": "public"}}
NO_RUNTIME = mock.patch("two_key.writable.runtime_targets", return_value=[])


def key(path) -> str:
    return os.path.normcase(os.path.abspath(path))


class Tree(unittest.TestCase):
    """A server installed in a temporary tree: <dir>/opt/upstream/server.py and an interpreter beside it."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        # The real path: findings name real paths (macOS keeps temporary files under /var -> /private/var).
        self.dir = Path(os.path.realpath(tmp.name))
        self.addCleanup(self._open_up)
        self.upstream = self.dir / "opt" / "upstream"
        self.upstream.mkdir(parents=True)
        self.server = self.upstream / "server.py"
        self.server.write_text("pass\n", encoding="utf-8", newline="\n")
        self.python = self.dir / "opt" / "python"
        self.python.write_text("", encoding="utf-8", newline="\n")
        self._private()
        # A launcher by name only, so the test does not depend on where this machine keeps sudo.
        self.sudo = str(self.dir / "sudo")

    def _private(self):
        """Owner-only, whatever the umask (002 under a user-private group)."""
        for root, dirs, files in os.walk(self.dir):
            for name in dirs:
                chmod(Path(root, name), 0o700)
            for name in files:
                chmod(Path(root, name), 0o600)

    def _open_up(self):
        for root, dirs, files in os.walk(self.dir):
            for name in dirs + files:
                chmod(Path(root, name), 0o700)

    def config(self, command=None, **upstream):
        data = {"constitution": "c.json", "keys": {"principal": "k.pem"}, "ledger": "ledger",
                "judges": "judges.yaml",
                "upstream": {"command": command or [self.sudo, "-n", "-u", "mcp-billing", str(self.python),
                                                    str(self.server)],
                             "schema_digest": DIGEST, "cwd": str(self.dir), **upstream}}
        return parse_proxy_config(data, self.dir / "proxy.yaml")


class Setting(Tree):
    def test_check_paths_takes_absolute_paths_only(self):
        self.assertEqual(self.config().upstream.check_paths, ())
        cfg = self.config(check_paths=[str(self.upstream), str(self.server)])
        self.assertEqual(cfg.upstream.check_paths, (self.upstream, self.server))
        for bad in ("relative/server.py", "~/server.py", "", 5, None):
            with self.subTest(bad=bad), self.assertRaisesRegex(ProxyConfigError,
                                                               r"upstream.check_paths\[0\]: expected an absolute"):
                self.config(check_paths=[bad])
        for bad in ([], str(self.upstream), {"a": str(self.upstream)}):
            with self.subTest(bad=bad), self.assertRaisesRegex(ProxyConfigError, "expected a non-empty list"):
                self.config(check_paths=bad)
        with self.assertRaisesRegex(ProxyConfigError, f"at most {MAX_CHECK_PATHS} entries"):
            self.config(check_paths=[str(self.server)] * (MAX_CHECK_PATHS + 1))

    def test_launcher_names(self):
        for program in ("sudo", "/usr/bin/sudo", "doas", "env", "/usr/bin/env", "npx", "NPX.CMD", "npx.cmd",
                        "uvx", "uvx.exe", "pipx", "cmd", "cmd.exe", "powershell.exe", "pwsh", "Pwsh.EXE"):
            with self.subTest(program=program):
                self.assertIsNotNone(launcher(program))
        for program in ("python", "/usr/bin/python3", "node", "server", "sudoku", "npx-server", "my.sudo"):
            with self.subTest(program=program):
                self.assertIsNone(launcher(program))


class WhatIsChecked(Tree):
    def targets(self, cfg):
        return {(key(p), rule) for p, rule in startup_paths(cfg)}

    def test_absolute_arguments_that_exist_are_checked_with_their_folders(self):
        got = self.targets(self.config())
        for path, rule in ((self.python, "file"), (self.server, "file"), (self.upstream, "folder"),
                           (self.python.parent, "folder")):
            self.assertIn((key(path), rule), got)

    def test_a_folder_argument_is_checked_as_a_folder(self):
        cfg = self.config(command=[self.sudo, "-u", "x", str(self.python), "--root", str(self.upstream)])
        self.assertIn((key(self.upstream), "folder"), self.targets(cfg))

    def test_options_relative_and_missing_arguments_are_not_paths(self):
        cfg = self.config(command=["sudo", "-n", "-u", "mcp-billing", "--preserve-env=TOKEN", "--",
                                   "server.py", str(self.dir / "missing.py"), f"--config={self.server}"])
        self.assertEqual(upstream_paths(cfg.upstream), [])

    def test_check_paths_entries_are_checked(self):
        package = self.dir / "opt" / "package"
        package.mkdir(mode=0o700)
        cfg = self.config(command=["npx", "-y", "@example/server"], check_paths=[str(package), str(self.server)])
        self.assertEqual(upstream_paths(cfg.upstream),
                         [(package, "folder"), (self.server, "file"), (str(self.upstream), "folder")])

    def test_a_missing_check_paths_entry_refuses(self):
        cfg = self.config(check_paths=[str(self.server), str(self.dir / "gone")])
        with self.assertRaisesRegex(ProxyConfigError, r"^check_path_missing: upstream.check_paths\[1\]: .*gone "
                                                      r"does not exist"):
            startup_paths(cfg)

    def test_the_issue_repro_another_account_can_write_the_servers_folder(self):
        cfg = self.config()
        self.assertEqual(writable.check(startup_paths(cfg), runtime=False), [])
        chmod(self.upstream, 0o777)                           # chmod o+w on the server's folder
        found = [os.path.normcase(p) for p, _ in writable.check(startup_paths(cfg), runtime=False)]
        self.assertIn(os.path.normcase(str(self.upstream)), found)

    def test_a_check_paths_folder_another_account_can_write_is_named(self):
        package = self.dir / "opt" / "package"
        package.mkdir(mode=0o700)
        chmod(package, 0o777)
        cfg = self.config(command=["npx", "-y", "@example/server"], check_paths=[str(package)])
        found = [os.path.normcase(p) for p, _ in writable.check(startup_paths(cfg), runtime=False)]
        self.assertIn(os.path.normcase(str(package)), found)


class Unchecked(Tree):
    def test_a_launcher_with_nothing_named_warns(self):
        cfg = self.config(command=["npx", "-y", "@example/server@1.2.3"])
        err = io.StringIO()
        line = check_upstream_paths(cfg.upstream, False, stream=err)
        self.assertTrue(line.startswith("upstream_paths_unchecked: upstream.command starts with npx, "), line)
        self.assertEqual(err.getvalue(), f"two-key: WARNING: {line}\n")
        self.assertIn("upstream.check_paths", line)

    def test_high_assurance_refuses(self):
        cfg = self.config(command=["sudo", "-n", "-u", "mcp-billing", "--", "npx", "-y", "@example/server"])
        with self.assertRaisesRegex(ProxyConfigError, r"^upstream_paths_unchecked: upstream.command starts with "
                                                      r"sudo, .*; high_assurance refuses to start$"):
            check_upstream_paths(cfg.upstream, True, stream=io.StringIO())

    def test_quiet_when_something_is_named_or_there_is_no_launcher(self):
        cases = [self.config(),
                 self.config(command=["npx", "-y", "@example/server"], check_paths=[str(self.upstream)]),
                 self.config(command=[str(self.python), str(self.server)]),
                 self.config(command=["server"])]
        for cfg in cases:
            for high in (False, True):
                with self.subTest(command=cfg.upstream.command, high=high):
                    err = io.StringIO()
                    self.assertIsNone(check_upstream_paths(cfg.upstream, high, stream=err))
                    self.assertEqual(err.getvalue(), "")


class AtStart(Tree):
    """The new targets reach ``TwoKey``'s writable-path check, which refuses before the ledger is written."""

    def setUp(self):
        super().setUp()
        self.key = generate_private_key()
        self.con = verify_signed(sign_constitution("p", RULES, self.key, SPECS), self.key.public_key())

    @NO_RUNTIME
    def test_refuse_does_not_start_when_the_servers_folder_is_open(self, _):
        paths = startup_paths(self.config())
        start = lambda name: TwoKey(Ledger(self.dir / name, self.key), self.key.public_key(), self.con,  # noqa: E731
                                    [FixedJudge("a", "yes")], private_key=self.key,
                                    quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True,
                                    monitored_agent=TEST_AGENT, on_writable_paths="refuse", check_paths=paths)
        with contextlib.redirect_stderr(io.StringIO()):
            start("ledger1")
            chmod(self.upstream, 0o777)
            with self.assertRaisesRegex(TwoKeyConfigError, "on_writable_paths: refuse refuses to start") as raised:
                start("ledger2")
        self.assertIn(f"writable_path: {self.upstream}: ", str(raised.exception))

    def build(self, cfg, high):
        """``build_two_key`` up to the start-up checks, with the key and judges loaded by stand-ins."""
        policy = SimpleNamespace(is_high_assurance=high)
        with mock.patch("two_key.keys.load_private_key_file", return_value=self.key), \
             mock.patch("two_key.judges.config.load_config_file", return_value=([], policy)), \
             mock.patch("two_key.agent_access.check", side_effect=RuntimeError("past the upstream checks")), \
             contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                core.build_two_key(cfg)
            finally:
                self.err = err.getvalue()

    def test_the_proxy_refuses_under_high_assurance_before_the_ledger_is_opened(self):
        cfg = self.config(command=["npx", "-y", "@example/server"])
        with self.assertRaisesRegex(ProxyConfigError, "^upstream_paths_unchecked: .*high_assurance refuses"):
            self.build(cfg, True)
        self.assertFalse((self.dir / "ledger").exists())
        with self.assertRaisesRegex(RuntimeError, "past the upstream checks"):
            self.build(cfg, False)
        self.assertIn("two-key: WARNING: upstream_paths_unchecked: upstream.command starts with npx", self.err)

    def test_a_missing_check_paths_entry_refuses_before_the_ledger_is_opened(self):
        cfg = self.config(check_paths=[str(self.dir / "gone")])
        for high in (False, True):
            with self.subTest(high=high), self.assertRaisesRegex(ProxyConfigError, "^check_path_missing: "):
                self.build(cfg, high)
        self.assertFalse((self.dir / "ledger").exists())


if __name__ == "__main__":
    unittest.main()
