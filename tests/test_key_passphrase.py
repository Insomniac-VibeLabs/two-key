# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""A principal key encrypted with a passphrase (two_key/keys.py), and everything that opens it: the proxy at
start, ``config check``, every ``--key`` command, ``config set``/``undo``, ``config key-passphrase``, ``setup``
and the key backup.

The passphrase comes from a file only its owner can read, or a prompt on a terminal; never the command line
or the environment. A key that cannot be opened refuses, and nothing is written.
"""

import base64
import contextlib
import io
import json
import os
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization

from perm import chmod, private
from test_config_set import ANSWERS, Deployment, quiet
from test_key_backup import PHRASES, BackupFixture
from two_key import _platform, cli, config_cmd, config_set, keys, setup_cmd
from two_key.backup import BackupError, restore_backup, verify_backup
from two_key.config_set import ConfigChangeError
from two_key.keys import (decrypt_private_key, encrypt_private_key, generate_private_key, load_private_key_file,
                          passphrase_source, public_raw, read_passphrase_file, remember, save_private_key)
from two_key.mcp_proxy.config import load_proxy_config
from two_key.mcp_proxy.core import startup_paths

POSIX = not _platform.WINDOWS
# Made at run time: a test passphrase is no credential, and none is written into the source.
PASSPHRASE = secrets.token_hex(16).encode("ascii")
OTHER = secrets.token_hex(16).encode("ascii")


def write_secret(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    chmod(path, 0o600)
    return path


class Format(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(os.path.realpath(tmp.name))
        chmod(self.dir, 0o700)
        self.key = generate_private_key()
        self.path = self.dir / "principal.pem"

    def same(self, a, b):
        self.assertEqual(public_raw(a.public_key()), public_raw(b.public_key()))

    def test_round_trip_and_the_file_holds_no_plain_key(self):
        save_private_key(self.path, self.key, passphrase=PASSPHRASE)
        data = self.path.read_bytes()
        self.assertTrue(data.startswith(b"-----BEGIN TWO-KEY ENCRYPTED PRIVATE KEY-----\n"))
        self.assertTrue(private(self.path))
        plain = self.key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                       serialization.NoEncryption())
        self.assertNotIn(plain, data)
        self.assertNotIn(base64.b64encode(plain), data)
        self.same(load_private_key_file(self.path, PASSPHRASE), self.key)
        header = keys.encrypted_header(data)
        self.assertEqual((header["kdf"]["name"], header["kdf"]["iterations"], header["enc"]["name"]),
                         ("pbkdf2-sha256", 600_000, "aes-256-gcm"))

    def test_no_passphrase_or_a_wrong_one_is_refused(self):
        save_private_key(self.path, self.key, passphrase=PASSPHRASE)
        with self.assertRaisesRegex(ValueError, "^key_passphrase_needed: .* is encrypted"):
            load_private_key_file(self.path)
        with self.assertRaisesRegex(ValueError, "^key_passphrase_wrong: "):
            load_private_key_file(self.path, OTHER)
        with self.assertRaisesRegex(ValueError, "^key_passphrase_wrong: "):
            load_private_key_file(self.path, b"")

    def test_a_changed_header_or_ciphertext_does_not_open(self):
        data = encrypt_private_key(self.key, PASSPHRASE)
        body = b"".join(data.strip().splitlines()[1:-1])
        header = json.loads(base64.b64decode(body))

        def armour(h):
            text = json.dumps(h, sort_keys=True, separators=(",", ":")).encode("ascii")
            return (b"-----BEGIN TWO-KEY ENCRYPTED PRIVATE KEY-----\n" + base64.encodebytes(text)
                    + b"-----END TWO-KEY ENCRYPTED PRIVATE KEY-----\n")
        nonce = bytearray(base64.b64decode(header["enc"]["nonce"]))
        nonce[0] ^= 1
        moved = dict(header, enc=dict(header["enc"], nonce=base64.b64encode(bytes(nonce)).decode()))
        with self.assertRaisesRegex(ValueError, "^key_passphrase_wrong: "):
            decrypt_private_key(armour(moved), PASSPHRASE)
        cipher = bytearray(base64.b64decode(header["ciphertext"]))
        cipher[-1] ^= 1
        flipped = dict(header, ciphertext=base64.b64encode(bytes(cipher)).decode())
        with self.assertRaisesRegex(ValueError, "^key_passphrase_wrong: "):
            decrypt_private_key(armour(flipped), PASSPHRASE)
        # Fewer iterations than Two-Key writes is refused before the KDF runs: a file cannot weaken itself.
        cheap = dict(header, kdf=dict(header["kdf"], iterations=1000))
        with self.assertRaisesRegex(ValueError, "^key_file_invalid: "):
            decrypt_private_key(armour(cheap), PASSPHRASE)
        extra = dict(header, note="x")
        with self.assertRaisesRegex(ValueError, "^key_file_invalid: "):
            decrypt_private_key(armour(extra), PASSPHRASE)

    def test_a_new_passphrase_needs_twelve_bytes(self):
        with self.assertRaisesRegex(ValueError, "^key_passphrase_short: "):
            encrypt_private_key(self.key, b"short")
        with self.assertRaisesRegex(ValueError, "^key_passphrase_invalid: "):
            encrypt_private_key(self.key, b"            ")

    def test_a_key_encrypted_by_another_tool_is_named(self):
        self.path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.BestAvailableEncryption(PASSPHRASE)))
        chmod(self.path, 0o600)
        with self.assertRaisesRegex(ValueError, "^key_file_invalid: .*encrypted by another tool"):
            load_private_key_file(self.path, PASSPHRASE)

    def test_an_unencrypted_key_never_asks(self):
        save_private_key(self.path, self.key)
        asked = []
        self.same(load_private_key_file(self.path, lambda p: asked.append(p) or PASSPHRASE), self.key)
        self.assertEqual(asked, [])

    def test_the_passphrase_file(self):
        good = write_secret(self.dir / "pass", PASSPHRASE + b"\n")
        self.assertEqual(read_passphrase_file(good), PASSPHRASE)
        write_secret(good, PASSPHRASE + b"\r\n")
        self.assertEqual(read_passphrase_file(good), PASSPHRASE)
        write_secret(good, b"one\ntwo\n")
        with self.assertRaisesRegex(ValueError, "^passphrase_file_invalid: "):
            read_passphrase_file(good)
        write_secret(good, b"\n")
        with self.assertRaisesRegex(ValueError, "^passphrase_file_invalid: "):
            read_passphrase_file(good)
        write_secret(good, b"x" * 2000)
        with self.assertRaisesRegex(ValueError, "^passphrase_file_invalid: "):
            read_passphrase_file(good)
        write_secret(good, PASSPHRASE)
        if POSIX:
            chmod(good, 0o640)
            with self.assertRaisesRegex(ValueError, "^passphrase_file_insecure: .*chmod 600"):
                read_passphrase_file(good)
            chmod(good, 0o600)
            link = self.dir / "link"
            os.symlink(good, link)
            with self.assertRaisesRegex(ValueError, "^passphrase_file_unreadable: "):
                read_passphrase_file(link)

    def test_no_terminal_means_no_prompt(self):
        save_private_key(self.path, self.key, passphrase=PASSPHRASE)
        with mock.patch("sys.stdin", io.StringIO(PASSPHRASE.decode() + "\n")):
            with self.assertRaisesRegex(ValueError, "^key_passphrase_needed: .*no terminal"):
                load_private_key_file(self.path, passphrase_source(None))

    def test_remember_asks_once_per_file(self):
        asked = []
        source = remember(lambda p: asked.append(p) or PASSPHRASE)
        self.assertEqual((source("a"), source("a"), source("b")), (PASSPHRASE, PASSPHRASE, PASSPHRASE))
        self.assertEqual(asked, ["a", "b"])


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CommandLine(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(os.path.realpath(tmp.name))
        chmod(self.dir, 0o700)
        self.pass_file = write_secret(self.dir / "pass", PASSPHRASE + b"\n")
        (self.dir / "c.md").write_text("Approve small, routine requests.", encoding="utf-8")
        (self.dir / "r.yaml").write_text(json.dumps(
            {"hard_rules": [{"id": "tools", "allow_only_tools": ["tool_a"]}],
             "tool_specs": {"tool_a": {"irreversible": False, "data_class_floor": "public"}}}), encoding="utf-8")

    def test_init_key_encrypts_and_sign_constitution_opens_it(self):
        code, _, err = run("init-key", str(self.dir / "k"), "--passphrase-file", str(self.pass_file))
        self.assertEqual(code, 0, err)
        key = self.dir / "k" / "principal.pem"
        self.assertTrue(keys.key_file_is_encrypted(key))
        sign = ("sign-constitution", "--key", str(key), "--prose", str(self.dir / "c.md"),
                "--rules", str(self.dir / "r.yaml"), "--out", str(self.dir / "c.json"))
        with mock.patch("sys.stdin", io.StringIO("")):
            with self.assertRaisesRegex(SystemExit, "key_passphrase_needed"):
                run(*sign)
        self.assertFalse((self.dir / "c.json").exists())
        code, _, err = run(*sign, "--key-passphrase-file", str(self.pass_file))
        self.assertEqual(code, 0, err)
        self.assertTrue((self.dir / "c.json").exists())

    def test_init_key_refuses_a_short_passphrase_and_writes_no_key(self):
        write_secret(self.pass_file, b"short\n")
        code, _, err = run("init-key", str(self.dir / "k"), "--passphrase-file", str(self.pass_file))
        self.assertEqual(code, 1)
        self.assertIn("key_passphrase_short", err)
        self.assertFalse((self.dir / "k" / "principal.pem").exists())

    def test_the_passphrase_is_never_an_argument(self):
        with self.assertRaises(SystemExit):
            run("init-key", str(self.dir / "k"), "--passphrase", PASSPHRASE.decode())


class Encrypted(Deployment):
    """A deployment whose key `config key-passphrase` encrypted."""

    def setUp(self):
        super().setUp()
        self.pass_file = write_secret(self.base / "principal.pass", PASSPHRASE + b"\n")
        self.encrypt()

    def encrypt(self, source=None, **kw):
        kw.setdefault("confirm", self.confirm())
        kw.setdefault("environ", {})
        return quiet(config_set.change_key_encryption, self.proxy, new_from=str(source or self.pass_file), **kw)

    def ledger(self):
        from two_key.ledger import Ledger
        return Ledger(self.dir / "ledger", load_private_key_file(self.key, PASSPHRASE))

    def test_the_key_is_encrypted_and_the_proxy_names_the_file(self):
        self.assertTrue(keys.key_file_is_encrypted(self.key))
        self.assertTrue(private(self.key))
        config = load_proxy_config(self.proxy)
        self.assertEqual(config.principal_passphrase_file, self.pass_file)
        self.assertIn((self.pass_file, "file"), startup_paths(config))
        public = config.load_principal_key().public_key()
        self.assertEqual(public_raw(public), public_raw(load_private_key_file(self.key, PASSPHRASE).public_key()))
        found = config_cmd.check(str(self.proxy), {})
        self.assertIn((config_cmd.OK, "principal_key: encrypted; keys.passphrase_file opens it"), found)
        self.assertFalse([t for level, t in found if level == config_cmd.FAIL and "principal" in t], found)

    def test_no_copy_of_the_old_key_is_kept_and_undo_does_not_reverse_it(self):
        self.assertFalse((self.dir / "principal.pem.prev").exists())
        self.assertFalse(any("principal" in p.name and p.name != "principal.pem" and p.name != "principal.pub.pem"
                             for p in self.dir.iterdir()), sorted(p.name for p in self.dir.iterdir()))
        with self.assertRaisesRegex(ConfigChangeError, "^nothing_to_undo: .*key-passphrase"):
            quiet(config_set.undo, self.proxy, confirm=self.confirm(), environ={})

    def test_it_is_recorded_with_names_and_no_key_digest(self):
        entry = self.changes()[-1]
        self.assertEqual(entry.body["command"], "key-passphrase")
        self.assertEqual(entry.body["settings"], ["keys.principal", "keys.passphrase_file"])
        self.assertTrue(entry.body["confirmed"])
        files = {f["role"]: f for f in entry.body["files"]}
        self.assertEqual((files["key"]["old_sha256"], files["key"]["new_sha256"]), (None, None))
        self.assertTrue(files["proxy"]["new_sha256"].startswith("sha256:"))
        self.assertNotIn(PASSPHRASE.decode(), json.dumps(entry.body))
        self.assertTrue(self.answered and "principal key file" in self.answered[-1])

    def test_a_setting_changes_with_the_passphrase_from_the_file(self):
        self.set("ttl_seconds", 60)
        self.assertEqual(self.changes()[-1].body["settings"], ["ttl_seconds"])

    def test_a_signed_change_with_the_encrypted_key(self):
        self.set("tool_specs.tool_a.irreversible", True, key_path=str(self.key), rules_path=str(self.rules))
        entry = self.changes()[-1]
        self.assertTrue(entry.body["signed"])
        self.assertTrue(keys.key_file_is_encrypted(self.key))

    def test_removing_it_is_weaker(self):
        before = self.snapshot()
        with self.assertRaisesRegex(ConfigChangeError, "^weaker: keys.principal: the key is no longer encrypted"):
            quiet(config_set.change_key_encryption, self.proxy, remove=True, confirm=self.confirm(), environ={})
        self.assertEqual(self.snapshot(), before)
        quiet(config_set.change_key_encryption, self.proxy, remove=True, confirm_weaker=True, confirm=self.confirm(),
              environ={})
        self.assertFalse(keys.key_file_is_encrypted(self.key))
        self.assertIsNone(load_proxy_config(self.proxy).principal_passphrase_file)
        self.assertEqual(self.changes()[-1].body["weaker"], ["keys.principal: the key is no longer encrypted"])
        with self.assertRaisesRegex(ConfigChangeError, "^unchanged: "):
            quiet(config_set.change_key_encryption, self.proxy, remove=True, confirm_weaker=True,
                  confirm=self.confirm(), environ={})

    def test_changing_it_needs_the_current_one_and_writes_nothing_on_a_refusal(self):
        new = write_secret(self.base / "new.pass", OTHER + b"\n")
        before = self.snapshot()
        for source, pattern in ((Path("new.pass"), "passphrase_file_relative"),
                                (write_secret(self.base / "short.pass", b"short"), "key_passphrase_short")):
            with self.assertRaisesRegex(ConfigChangeError, pattern):
                self.encrypt(source)
            self.assertEqual(self.snapshot(), before)
        if POSIX:
            chmod(new, 0o644)
            with self.assertRaisesRegex(ConfigChangeError, "passphrase_file_insecure"):
                self.encrypt(new)
            chmod(new, 0o600)
        with self.assertRaisesRegex(ConfigChangeError, "not_confirmed"):
            self.encrypt(new, confirm=self.confirm(False))
        self.assertEqual(self.snapshot(), before)
        self.encrypt(new)
        self.assertEqual(load_proxy_config(self.proxy).principal_passphrase_file, new)
        load_private_key_file(self.key, OTHER)
        with self.assertRaisesRegex(ValueError, "key_passphrase_wrong"):
            load_private_key_file(self.key, PASSPHRASE)

    def test_a_wrong_passphrase_file_refuses_every_change(self):
        write_secret(self.pass_file, OTHER + b"\n")
        before = self.snapshot()
        with self.assertRaisesRegex(ConfigChangeError, "^principal_key: key_passphrase_wrong"):
            self.set("ttl_seconds", 60)
        self.assertEqual(self.snapshot(), before)
        found = config_cmd.check(str(self.proxy), {})
        self.assertTrue(any(level == config_cmd.FAIL and "key_passphrase_wrong" in t for level, t in found), found)

    def test_the_proxy_without_the_file_refuses_to_start(self):
        from two_key.mcp_proxy.config import ProxyConfigError
        from two_key.mcp_proxy.core import build_two_key
        text = self.proxy.read_text(encoding="utf-8")
        lines = [l for l in text.splitlines() if "passphrase_file" in l]
        self.assertEqual(len(lines), 1, lines)
        line = lines[0]
        chmod(self.proxy, 0o600)
        self.proxy.write_text(text.replace(line + "\n", ""), encoding="utf-8")
        with self.assertRaisesRegex(ProxyConfigError, "key_passphrase_needed"):
            build_two_key(load_proxy_config(self.proxy))


class SetupWithPassphrase(Deployment):
    answers = dict(ANSWERS)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pass_dir = Path(os.path.realpath(tmp.name))
        self.pass_file = write_secret(pass_dir / "principal.pass", PASSPHRASE + b"\n")
        self.answers = dict(ANSWERS, key_passphrase_file=str(self.pass_file))
        super().setUp()

    def ledger(self):
        from two_key.ledger import Ledger
        return Ledger(self.dir / "ledger", load_private_key_file(self.key, PASSPHRASE))

    def test_setup_encrypts_the_key_and_writes_the_setting(self):
        self.assertTrue(keys.key_file_is_encrypted(self.key))
        self.assertEqual(load_proxy_config(self.proxy).principal_passphrase_file, self.pass_file)
        self.assertNotIn(PASSPHRASE.decode(), self.proxy.read_text(encoding="utf-8"))
        self.assertEqual(self.changes()[0].body["command"], "setup")
        self.assertFalse([t for level, t in config_cmd.check(str(self.proxy), {}) if level == config_cmd.FAIL])

    def test_setup_refuses_a_relative_or_short_passphrase_file(self):
        for value, pattern in (("principal.pass", "absolute path"),
                               (str(write_secret(self.base / "s", b"short")), "key_passphrase_short")):
            with self.assertRaisesRegex(setup_cmd.SetupError, pattern):
                quiet(setup_cmd.build, dict(ANSWERS, key_passphrase_file=value), self.base / "other", environ={})
            self.assertFalse((self.base / "other").exists())


class Backup(BackupFixture):
    def setUp(self):
        super().setUp()
        self.key_path.unlink()
        save_private_key(self.key_path, self.key, passphrase=PASSPHRASE)

    def test_the_key_stays_encrypted_through_export_and_restore(self):
        with self.assertRaisesRegex(BackupError, "key_passphrase_needed"):
            self.export()
        self.export(key_passphrase=PASSPHRASE)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(BackupError, "key_passphrase_needed"):
                verify_backup(self.out, PHRASES)
            with self.assertRaisesRegex(BackupError, "key_passphrase_wrong"):
                verify_backup(self.out, PHRASES, key_passphrase=OTHER)
            self.assertTrue(verify_backup(self.out, PHRASES, key_passphrase=PASSPHRASE)["ok"])
        saved = self.key_path.read_bytes()
        self.key_path.unlink()
        with contextlib.redirect_stderr(io.StringIO()):
            result = restore_backup(self.ledger, self.key_path, self.out, PHRASES, key_passphrase=PASSPHRASE)
        self.assertEqual(result["actions"]["principal.pem"], "created")
        self.assertEqual(self.key_path.read_bytes(), saved)
        self.assertTrue(keys.key_file_is_encrypted(self.key_path))


if __name__ == "__main__":
    unittest.main()
