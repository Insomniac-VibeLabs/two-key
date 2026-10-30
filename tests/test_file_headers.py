# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Every tracked file that can hold a comment opens with the copyright, author, and SPDX licence header.

Python, YAML, TOML, shell, ``MANIFEST.in`` and ``.gitignore`` use ``#`` lines (after a shebang); Markdown uses an
HTML comment so the page renders unchanged; ``llms.txt`` keeps its title first and carries the comment at the end.
``docs/SETTINGS.md`` gets its header from ``two_key/settings.py``. Files that cannot hold a comment, or whose bytes
are data, are listed in ``EXEMPT`` with the reason.
"""

import shutil
import subprocess  # nosec B404 - runs git with a fixed argument list
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINES = ("Copyright 2026 Insomniac-VibeLabs", "Author: Stephan Busch", "SPDX-License-Identifier: Apache-2.0")
SUFFIXES = {".py", ".md", ".txt", ".yml", ".yaml", ".toml", ".sh", ".in", ".gitignore"}
EXEMPT = {
    "LICENSE": "the licence text itself",
    "examples/constitution.md": "constitution prose is signed and sent to the judges as written",
    "examples/demo/constitution.md": "constitution prose is signed and sent to the judges as written",
    "tests/fixtures/v1_constitution.md": "an old-format constitution the tests load as written",
}


def _tracked():
    git = shutil.which("git")
    if git is None or not (ROOT / ".git").exists():
        return None
    out = subprocess.run([git, "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout  # nosec B603
    return [p for p in out.splitlines() if p not in EXEMPT and (Path(p).suffix or Path(p).name) in SUFFIXES]


class FileHeaders(unittest.TestCase):
    def test_every_file_has_the_header(self):
        files = _tracked()
        if files is None:
            self.skipTest("not a git checkout")
        missing = []
        for rel in files:
            text = (ROOT / rel).read_text(encoding="utf-8")
            head = text if rel == "llms.txt" else "\n".join(text.splitlines()[:6])
            if not all(line in head for line in LINES):
                missing.append(rel)
        self.assertEqual(missing, [], "add the copyright header (see CONTRIBUTING.md)")


if __name__ == "__main__":
    unittest.main()
