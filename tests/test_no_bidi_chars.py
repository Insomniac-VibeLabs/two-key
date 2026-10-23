# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""No raw bidirectional control characters in the repository's text files (Trojan Source, CVE-2021-42574).

A test that needs one writes it as an escape (``"\\u202e"``), so the source reads the same in every editor and
review tool (SonarCloud flagged two raw ones in PR #11).
"""

import unicodedata
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "build", "dist", "state", "selftest", ".mypy_cache"}
SUFFIXES = {".py", ".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini"}
BIDI = {"LRE", "RLE", "LRO", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI"}
MARKS = {0x200E, 0x200F, 0x061C}


def _files():
    for path in ROOT.rglob("*"):
        if path.suffix in SUFFIXES and path.is_file() and not SKIP_DIRS & set(path.relative_to(ROOT).parts):
            yield path


class NoBidiCharacters(unittest.TestCase):
    def test_none_in_text_files(self):
        found = []
        for path in _files():
            text = path.read_text(encoding="utf-8", errors="replace")
            for n, line in enumerate(text.splitlines(), 1):
                if any(unicodedata.bidirectional(c) in BIDI or ord(c) in MARKS for c in line):
                    found.append(f"{path.relative_to(ROOT)}:{n}")
        self.assertEqual(found, [], "write bidirectional controls as escapes, e.g. \\u202e")


if __name__ == "__main__":
    unittest.main()
