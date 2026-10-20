"""The account that started the MCP proxy (two_key/agent_access.py, ``on_agent_access``): refused by default
when it is Two-Key's own, root, unknown, or can change a path the proxy runs or reads."""

import io
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from two_key import _platform, agent_access
from two_key.agent_access import AgentAccessError
from two_key.mcp_proxy.config import ProxyConfigError, parse_proxy_config
from two_key.mcp_proxy.core import startup_paths

DIGEST = "sha256:" + "0" * 64
OTHER = 4_000_123            # an account no test machine has
# Windows has no POSIX account id, and the decorators below are read when the class is defined, before its
# skip can take effect. The Accounts tests skip there, so the id is only read on POSIX.
EUID = None if _platform.WINDOWS else os.geteuid()


def config(**over):
    data = {"constitution": "c.json", "keys": {"principal": "k.pem"}, "ledger": "ledger", "judges": "judges.yaml",
            "upstream": {"command": ["server"], "schema_digest": DIGEST}, **over}
    return parse_proxy_config(data, Path("/etc/two-key/proxy.yaml"))


class Modes(unittest.TestCase):
    def test_refuse_is_the_default(self):
        self.assertIsNone(config().on_agent_access)
        self.assertEqual(agent_access.resolve_mode(None, False), "refuse")
        self.assertEqual(agent_access.resolve_mode("warn", False), "warn")
        self.assertEqual(config(on_agent_access="warn").on_agent_access, "warn")

    def test_high_assurance_refuses_and_does_not_accept_warn(self):
        self.assertEqual(agent_access.resolve_mode(None, True), "refuse")
        with self.assertRaisesRegex(ValueError, "remove on_agent_access: warn"):
            agent_access.resolve_mode("warn", True)

    def test_a_bad_value(self):
        with self.assertRaisesRegex(ProxyConfigError, "on_agent_access: expected warn or refuse"):
            config(on_agent_access="off")


@unittest.skipIf(_platform.WINDOWS, "POSIX accounts")
class Accounts(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        # The real path: the writable-path check names what it checked, and on macOS /var is a link to
        # /private/var, so an expectation built from the name tempfile returns would not match.
        self.dir = Path(tmp.name).resolve()
        os.chmod(self.dir, 0o700)
        self.file = self.dir / "proxy.yaml"
        self.file.write_text("x", encoding="utf-8")
        os.chmod(self.file, 0o600)
        # The interpreter's own paths depend on the machine (a runner's tool cache is group-writable).
        runtime = patch("two_key.writable.runtime_targets", return_value=[])
        runtime.start()
        self.addCleanup(runtime.stop)

    def found(self, uid, label="agent (uid 4000123)"):
        return agent_access.problems([(self.file, "file")], parent=(uid, label), own_uid=EUID)

    def test_another_account_that_cannot_write_starts(self):
        self.assertEqual(self.found(OTHER), [])

    def test_the_same_account_is_refused(self):
        (line,) = self.found(EUID, "two-key (uid 996)")
        self.assertTrue(line.startswith("agent_same_account: the proxy was started by two-key (uid 996), "
                                        "Two-Key's own account"), line)

    @unittest.skipIf(EUID == 0, "root is Two-Key's own account here")
    def test_root_is_refused(self):
        (line,) = self.found(0, "root (uid 0)")
        self.assertTrue(line.startswith("agent_account_root: "), line)

    def test_an_unknown_account_is_refused(self):
        (line,) = self.found(None, "the process that started Two-Key has exited (parent pid 1)")
        self.assertEqual(line, "agent_account_unknown: cannot tell which account started the proxy: the process "
                               "that started Two-Key has exited (parent pid 1)")

    def test_a_file_everyone_can_write(self):
        os.chmod(self.file, 0o666)
        (line,) = self.found(OTHER)
        self.assertEqual(line, f"agent_can_write: {self.file}: the account that started the proxy, agent (uid "
                               "4000123), could change it (everyone can write it)")

    def test_a_group_the_agent_may_be_in(self):
        os.chmod(self.file, 0o620)
        if os.stat(self.file).st_gid == 0:
            self.skipTest("group 0 is not counted by the writable-path check")
        (line,) = self.found(OTHER)                 # its groups cannot be listed: fail closed
        self.assertIn("its groups cannot be listed", line)

    def test_a_group_the_agent_is_not_in(self):
        os.chmod(self.file, 0o620)
        st = os.stat(self.file)
        with patch("pwd.getpwuid") as getpwuid, patch("os.getgrouplist", return_value=[st.st_gid + 1]):
            getpwuid.return_value.pw_name, getpwuid.return_value.pw_gid = "agent", st.st_gid + 1
            self.assertEqual(self.found(OTHER), [])

    def test_a_folder_above_the_agent_owns(self):
        with patch.object(_platform, "account_can_write",
                          side_effect=lambda p, uid: "it owns it" if Path(p) == self.dir else None), \
             patch.object(_platform, "write_problem",
                          side_effect=lambda p, rule="file": "owned by agent" if Path(p) == self.dir else None):
            found = self.found(OTHER)
        self.assertEqual(found, [f"agent_can_write: {self.dir}: the account that started the proxy, agent (uid "
                                 "4000123), could change it (it owns it)"])

    def test_the_upstream_servers_files_behind_a_launcher(self):
        # #13: the server script is an argument of sudo, not command[0], and is still checked.
        server = self.dir / "server.py"
        server.write_text("pass\n", encoding="utf-8")
        os.chmod(server, 0o600)
        data = {"constitution": "c.json", "keys": {"principal": "k.pem"}, "ledger": "ledger",
                "judges": "judges.yaml",
                "upstream": {"command": [str(self.dir / "sudo"), "-n", "-u", "mcp-billing", str(server)],
                             "schema_digest": DIGEST, "cwd": str(self.dir)}}
        paths = startup_paths(parse_proxy_config(data, self.file))
        self.assertEqual(agent_access.problems(paths, parent=(OTHER, "agent (uid 4000123)"), own_uid=EUID), [])
        os.chmod(server, 0o666)
        self.assertEqual(agent_access.problems(paths, parent=(OTHER, "agent (uid 4000123)"), own_uid=EUID),
                         [f"agent_can_write: {server}: the account that started the proxy, agent (uid 4000123), "
                          "could change it (everyone can write it)"])

    def test_refuse_raises_with_the_first_and_names_the_rest(self):
        os.chmod(self.file, 0o666)
        err = io.StringIO()
        with self.assertRaises(AgentAccessError) as raised:
            agent_access.check([(self.file, "file")], "refuse", why="on_agent_access: refuse (the default)",
                               stream=err, parent=(EUID, "two-key (uid 996)"), own_uid=EUID)
        self.assertEqual(str(raised.exception),
                         "agent_same_account: the proxy was started by two-key (uid 996), Two-Key's own account, "
                         "so the agent could read Two-Key's keys and change its settings; run the agent as another "
                         "account; on_agent_access: refuse (the default) refuses to start (docs/CONNECTING.md)")

    def test_warn_names_it_and_starts(self):
        err = io.StringIO()
        found = agent_access.check([(self.file, "file")], "warn", why="", stream=err,
                                   parent=(EUID, "two-key (uid 996)"), own_uid=EUID)
        self.assertEqual(len(found), 1)
        self.assertIn("two-key: WARNING: agent_same_account: ", err.getvalue())
        self.assertIn("on_agent_access: warn starts anyway", err.getvalue())

    def test_this_process_parent_is_read(self):
        uid, label = _platform.parent_account()
        self.assertEqual(uid, os.getuid(), label)   # the test runner started it as the same account

    def test_account_can_write_reads_the_mode(self):
        self.assertEqual(_platform.account_can_write(self.file, os.geteuid()), "it owns it")
        self.assertIsNone(_platform.account_can_write(self.file, OTHER))
        os.chmod(self.file, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWOTH)
        self.assertEqual(_platform.account_can_write(self.file, OTHER), "everyone can write it")


if __name__ == "__main__":
    unittest.main()
