# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""``server.json`` lists the package on the official MCP Registry; it must agree with the package it points at.

The registry takes the version from ``server.json`` and checks ownership by finding ``mcp-name: <name>`` in the
README that PyPI shows, so a release that bumps ``pyproject.toml`` without ``server.json``, or a README without the
line, fails to publish (docs/PYPI.md "List on the MCP Registry").
"""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _pyproject(field):
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    return re.search(rf'^{field} = "([^"]+)"$', text, re.MULTILINE).group(1)


class McpRegistry(unittest.TestCase):
    def setUp(self):
        self.server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
        self.package = self.server["packages"][0]

    def test_versions_match_pyproject(self):
        version = _pyproject("version")
        self.assertEqual(self.server["version"], version)
        self.assertEqual(self.package["version"], version)

    def test_package_is_this_project_on_pypi_over_stdio(self):
        self.assertEqual(len(self.server["packages"]), 1)
        self.assertEqual(self.package["registryType"], "pypi")
        self.assertEqual(self.package["identifier"], _pyproject("name"))
        self.assertEqual(self.package["transport"], {"type": "stdio"})
        self.assertEqual(self.package["packageArguments"][0]["value"], "mcp-proxy")

    def test_readme_carries_the_ownership_line(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        # The registry needs a boundary after the name, so a trailing period or letter would not count.
        line = re.compile(rf"mcp-name: {re.escape(self.server['name'])}(?=\s|-->|<)")
        self.assertRegex(readme, line)

    def test_name_and_description_fit_the_registry(self):
        self.assertTrue(self.server["name"].startswith("io.github.Insomniac-VibeLabs/"))
        self.assertLessEqual(len(self.server["description"]), 100)
        self.assertLessEqual(len(self.server["title"]), 100)


if __name__ == "__main__":
    unittest.main()
