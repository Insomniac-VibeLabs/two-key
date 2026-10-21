# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Paths another account could change, checked when Two-Key starts (0.6.0, two_key/writable.py).

Code and settings in such a path run with Two-Key's keys, so Two-Key names them on stderr, refuses to start
with on_writable_paths="refuse", and always refuses under high_assurance (which does not accept "warn").
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from perm import chmod
from two_key import _platform, writable
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.mcp_proxy.config import ProxyConfigError, parse_proxy_config
from two_key.mcp_proxy.core import startup_paths
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["lookup"]}]
SPECS = {"lookup": {"irreversible": False, "data_class_floor": "public"}}
ONE = [FixedJudge("a", "yes")]
# Two makers and a local judge: what high_assurance asks for.
HIGH = [FixedJudge("a", "yes", provider="p0", maker="m0", local_weights=True),
        FixedJudge("b", "yes", provider="p1", maker="m1")]
POSIX = not _platform.WINDOWS
ROOT = POSIX and os.geteuid() == 0
NO_RUNTIME = mock.patch("two_key.writable.runtime_targets", return_value=[])


def real(path) -> str:
    """Findings name real paths (macOS keeps temporary files under a link, Windows under a short name)."""
    return os.path.realpath(path)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for root, dirs, files in os.walk(self.dir):
            for name in dirs + files:
                chmod(Path(root, name), 0o700)
        self.tmp.cleanup()

    def file(self, name="settings.yaml", mode=None, parent=None):
        path = Path(parent or self.dir, name)
        path.write_text("x: 1\n", encoding="utf-8", newline="\n")
        if mode is not None:
            chmod(path, mode)
        return path

    def folder(self, name, mode=None):
        path = self.dir / name
        path.mkdir()
        if mode is not None:
            chmod(path, mode)
        return path


class WhatCounts(Fixture):
    def test_a_private_file_passes_and_one_others_can_write_is_named(self):
        path = self.file(mode=0o600)
        self.assertIsNone(_platform.write_problem(path))
        self.assertEqual(writable.findings_for(path), [])
        chmod(path, 0o666)
        problem = _platform.write_problem(path)
        self.assertTrue(problem)
        self.assertIn("everyone" if POSIX else "Everyone", problem)
        self.assertEqual(writable.findings_for(path), [(real(path), problem)])

    @unittest.skipUnless(POSIX, "mode bits")
    def test_group_write_counts_except_for_group_0(self):
        path = self.file(mode=0o620)
        gid = os.stat(path).st_gid
        if gid == 0:
            if not ROOT:
                self.skipTest("the test user's group is 0")
            self.assertIsNone(_platform.write_problem(path))      # root's group: only root is in it
            os.chown(path, -1, 65534)
        self.assertIn("writable by group", _platform.write_problem(path))

    @unittest.skipUnless(ROOT, "changing a file's owner needs root")
    def test_an_owner_other_than_this_user_or_root_counts(self):
        path = self.file(mode=0o600)
        os.chown(path, 65534, -1)
        self.assertIn("owned by", _platform.write_problem(path))

    @unittest.skipUnless(POSIX, "the sticky bit")
    def test_a_sticky_folder_above_is_fine_and_a_plain_writable_one_is_not(self):
        shared = self.folder("shared", 0o1777)
        own = Path(shared, "own")
        own.mkdir(mode=0o700)
        path = self.file(parent=own, mode=0o600)
        self.assertEqual(writable.findings_for(path), [])
        chmod(shared, 0o777)
        self.assertEqual(writable.findings_for(path), [(real(shared), "writable by everyone")])

    def test_a_missing_path_is_checked_through_the_folder_that_would_hold_it(self):
        open_folder = self.folder("open", 0o777)
        found = writable.findings_for(open_folder / "python312.zip", "folder")
        self.assertEqual([p for p, _ in found], [real(open_folder)])
        if POSIX:   # a sticky bit does not stop anyone creating a new entry
            chmod(open_folder, 0o1777)
            self.assertEqual([p for p, _ in writable.findings_for(open_folder / "x.py")], [real(open_folder)])

    def test_nothing_under_a_folder_already_named_is_named_again(self):
        open_folder = self.folder("open", 0o777)
        inner = self.file(parent=open_folder, mode=0o666)
        found = writable.check([(inner, "file"), (open_folder, "folder")], runtime=False)
        self.assertEqual([p for p, _ in found], [real(open_folder)])

    def test_a_writable_folder_on_the_import_path_is_named(self):
        open_folder = self.folder("site", 0o777)
        sys.path.append(str(open_folder))
        self.addCleanup(sys.path.remove, str(open_folder))
        self.assertIn((str(open_folder), "folder"), writable.runtime_targets())
        self.assertIn(os.path.normcase(real(open_folder)), [os.path.normcase(p) for p, _ in writable.check()])

    def test_loaded_modules_and_their_compiled_files_are_looked_at(self):
        targets = {os.path.normcase(os.path.abspath(p)) for p, _ in writable.runtime_targets()}
        self.assertIn(os.path.normcase(os.path.abspath(writable.__file__)), targets)
        self.assertIn(os.path.normcase(os.path.abspath(sys.executable)), targets)
        if writable.__spec__.cached:
            self.assertIn(os.path.normcase(os.path.abspath(writable.__spec__.cached)), targets)

    def test_a_compiled_file_named_only_by_the_spec_is_looked_at(self):
        # Python 3.15 sets no __cached__ on a module; its compiled file is named only by __spec__.cached.
        open_cache = self.folder("__pycache__", 0o777)
        compiled = open_cache / "mod.cpython-315.pyc"
        module = types.ModuleType("mod")
        module.__file__ = str(self.file("mod.py", mode=0o600))
        module.__spec__ = importlib.util.spec_from_file_location("mod", module.__file__)
        module.__spec__.cached = str(compiled)
        self.assertFalse(hasattr(module, "__cached__"))
        targets = writable._module_targets(module)
        self.assertIn((str(compiled), "file"), targets)
        self.assertIn((str(open_cache), "folder"), targets)
        with mock.patch.dict(sys.modules, {"mod": module}):
            found = [os.path.normcase(p) for p, _ in writable.check()]
        self.assertIn(os.path.normcase(real(open_cache)), found)

    def test_a_module_without_a_location_adds_nothing(self):
        for spec in (None, importlib.machinery.ModuleSpec("built", None, origin="built-in"), object()):
            module = types.ModuleType("built")
            module.__spec__ = spec
            with self.subTest(spec=spec):
                self.assertEqual(writable._module_targets(module), [])


class Modes(unittest.TestCase):
    def test_resolve_mode(self):
        self.assertEqual(writable.resolve_mode(None, False), "warn")
        self.assertEqual(writable.resolve_mode("refuse", False), "refuse")
        self.assertEqual(writable.resolve_mode(None, True), "refuse")
        self.assertEqual(writable.resolve_mode("refuse", True), "refuse")
        with self.assertRaisesRegex(ValueError, "high_assurance refuses"):
            writable.resolve_mode("warn", True)
        for bad in ("off", "ignore", "", False):
            with self.assertRaisesRegex(ValueError, "expected one of"):
                writable.resolve_mode(bad, False)

    def test_report_caps_the_lines(self):
        found = [(f"/p{i}", "writable by everyone") for i in range(writable.MAX_LINES + 3)]
        out = io.StringIO()
        writable.report(found, "warn", why="x", stream=out)
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), writable.MAX_LINES + 1)
        self.assertIn("and 3 more", lines[-1])
        with self.assertRaisesRegex(writable.WritablePathsError, r"/p0: writable by everyone \(and 12 more\); x "):
            writable.report(found, "refuse", why="x", stream=io.StringIO())


class AtStart(Fixture):
    def setUp(self):
        super().setUp()
        self.key = generate_private_key()
        self.con = verify_signed(sign_constitution("p", RULES, self.key, SPECS), self.key.public_key())
        self.n = 0

    def start(self, judges=ONE, quorum=None, **kw):
        self.n += 1
        self.ledger = Ledger(self.dir / f"ledger{self.n}", self.key)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            try:
                tk = TwoKey(self.ledger, self.key.public_key(), self.con, judges, private_key=self.key,
                            quorum=quorum or QuorumPolicy(required_yes=1), allow_test_doubles=True,
                            monitored_agent=TEST_AGENT, **kw)
            finally:
                self.err = err.getvalue()
        return tk

    def high(self):
        return QuorumPolicy.high_assurance(required_yes=2, timeout_seconds=10)

    @NO_RUNTIME
    def test_clean_paths_start_quietly(self, _):
        self.start(check_paths=[self.file(mode=0o600), self.dir])
        self.assertNotIn("writable_path", self.err)
        self.start(judges=HIGH, quorum=self.high(), check_paths=[self.file("b.yaml", mode=0o600)])
        self.assertNotIn("writable_path", self.err)

    @NO_RUNTIME
    def test_warn_names_the_path_and_starts(self, _):
        path = self.file(mode=0o666)
        tk = self.start(check_paths=[path])
        self.assertIn(f"two-key: WARNING: writable_path: {real(path)}: ", self.err)
        self.assertIn("docs/CONNECTING.md", self.err)
        d = tk.authorize({"tool": "lookup", "data_class": "public"}, {}, "look up")
        self.assertTrue(d.allowed, d.reason)

    @NO_RUNTIME
    def test_refuse_and_high_assurance_do_not_start_and_write_nothing(self, _):
        path = self.file(mode=0o666)
        for kw in ({"on_writable_paths": "refuse"}, {"judges": HIGH, "quorum": self.high()},
                   {"judges": HIGH, "quorum": self.high(), "on_writable_paths": "refuse"}):
            with self.subTest(kw=sorted(kw)):
                with self.assertRaises(TwoKeyConfigError) as raised:
                    self.start(check_paths=[path], **kw)
                why = "high_assurance" if "quorum" in kw else "on_writable_paths: refuse"
                self.assertIn(f"writable_path: {real(path)}: ", str(raised.exception))
                self.assertIn(f"{why} refuses to start", str(raised.exception))
                self.assertIn(f"writable_path: {real(path)}: ", self.err)
                self.assertNotIn("constitution_loaded", [e.kind for e in self.ledger.entries])

    @NO_RUNTIME
    def test_high_assurance_does_not_take_warn(self, _):
        with self.assertRaisesRegex(TwoKeyConfigError, "high_assurance refuses .* remove on_writable_paths: warn"):
            self.start(judges=HIGH, quorum=self.high(), on_writable_paths="warn")

    @NO_RUNTIME
    def test_bad_settings(self, _):
        with self.assertRaisesRegex(TwoKeyConfigError, "on_writable_paths: expected one of"):
            self.start(on_writable_paths="off")
        with self.assertRaisesRegex(TwoKeyConfigError, "check_paths: .* expected file or folder"):
            self.start(check_paths=[(self.dir, "parent")])

    def test_the_interpreter_is_checked_without_being_asked(self):
        open_folder = self.folder("site", 0o777)
        with mock.patch("two_key.writable.runtime_targets", return_value=[(str(open_folder), "folder")]):
            self.start()
        self.assertIn(f"writable_path: {real(open_folder)}: ", self.err)


class Proxy(Fixture):
    def config(self, **over):
        data = {"constitution": "c.json", "keys": {"principal": "k.pem"}, "ledger": "ledger",
                "judges": "judges.yaml",
                "upstream": {"command": [sys.executable, "-m", "server"], "schema_digest": "sha256:" + "0" * 64}}
        data.update(over)
        return parse_proxy_config(data, self.dir / "proxy.yaml")

    def test_the_setting(self):
        self.assertIsNone(self.config().on_writable_paths)
        for value in ("warn", "refuse"):
            self.assertEqual(self.config(on_writable_paths=value).on_writable_paths, value)
        for bad in ("off", True, None, "Refuse"):
            with self.assertRaisesRegex(ProxyConfigError, "on_writable_paths: expected warn or refuse"):
                self.config(on_writable_paths=bad)

    def test_what_the_proxy_checks(self):
        cfg = self.config(tools={"lookup": {"claim": "floor",
                                            "facts": {"po_matched": {"hook": "scan_hook_fixture:inspect"}},
                                            "files": [{"path": "file", "kind": "path", "folder": str(self.dir),
                                                       "max_bytes": 10}]}},
                          scan={"type": "command", "command": [sys.executable, "-c", "pass"]})
        got = {(os.path.normcase(os.path.abspath(p)), rule) for p, rule in startup_paths(cfg)}
        want = [(self.dir / "proxy.yaml", "file"), (self.dir / "c.json", "file"), (self.dir / "k.pem", "file"),
                (self.dir / "judges.yaml", "file"), (self.dir / "ledger", "folder"), (Path.cwd(), "folder"),
                (Path(sys.executable), "file"), (self.dir, "folder"),
                (Path(__file__).with_name("scan_hook_fixture.py"), "file")]
        for path, rule in want:
            self.assertIn((os.path.normcase(os.path.abspath(path)), rule), got)

    def test_upstream_cwd_replaces_the_callers_folder(self):
        cfg = self.config(upstream={"command": [sys.executable], "schema_digest": "sha256:" + "0" * 64,
                                    "cwd": str(self.dir)})
        folders = [os.path.normcase(os.path.abspath(p)) for p, rule in startup_paths(cfg) if rule == "folder"]
        self.assertIn(os.path.normcase(str(self.dir)), folders)
        self.assertNotIn(os.path.normcase(os.getcwd()), folders)


if __name__ == "__main__":
    unittest.main()
