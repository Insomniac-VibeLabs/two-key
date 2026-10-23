# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""No key material is left in the system temp directory.

A ledger's key, witness, capability, lock, and redemption-lock directories are
siblings of the ledger directory. A ledger opened at the root of a temporary
directory therefore puts them in /tmp, where they outlive the cleanup.
"""

import io
import os
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from two_key.cli import main

TESTS = Path(__file__).resolve().parent
# Ledger(tmp, ...), Ledger(Path(tmp), ...), Ledger(self.tmp.name, ...), Ledger(Path(self.tmp.name), ...)
_ROOT = r"(?:tmp|self\.tmp\.name|self\.dir)"
AT_TEMP_ROOT = re.compile(r"Ledger\(\s*(?:Path\(\s*" + _ROOT + r"\s*\)|" + _ROOT + r")\s*,")


class TempHygiene(unittest.TestCase):
    def test_no_test_opens_a_ledger_at_a_temp_root(self):
        offenders = []
        for path in sorted(TESTS.glob("test_*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if AT_TEMP_ROOT.search(line) and path.name != Path(__file__).name:
                    offenders.append(f"{path.name}:{number}")
        self.assertEqual(offenders, [], "open the ledger at Path(tmp, 'ledger') so its side directories stay inside")

    def test_no_test_uses_mkdtemp_without_cleanup(self):
        offenders = [p.name for p in sorted(TESTS.glob("test_*.py"))
                     if "mkdtemp(" in p.read_text(encoding="utf-8") and p.name != Path(__file__).name]
        self.assertEqual(offenders, [])

    def test_demo_leaves_nothing_in_the_temp_directory(self):
        with tempfile.TemporaryDirectory() as outer:
            saved = tempfile.tempdir
            tempfile.tempdir = outer
            try:
                with redirect_stdout(io.StringIO()):
                    main(["demo"])
            finally:
                tempfile.tempdir = saved
            self.assertEqual(os.listdir(outer), [])


if __name__ == "__main__":
    unittest.main()
