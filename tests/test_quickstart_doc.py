# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""docs/QUICKSTART.md is run by tests/quickstart_run.py in CI. These check that the page still has the blocks
and markers that run expects, and that a block's result is judged by its marker."""

import subprocess
import unittest

from quickstart_run import DOC, Block, blocks, problem


def result(code, out=""):
    return subprocess.CompletedProcess(["bash"], code, out, "")


class QuickstartPage(unittest.TestCase):
    def test_the_page_has_its_steps_and_each_marker_is_read(self):
        found = blocks(DOC.read_text(encoding="utf-8"))
        run = [b for b in found if not b.skip]
        self.assertEqual(len(found), 7)
        self.assertIn("two-key setup --dir quickstart", run[0].code)
        self.assertEqual([b.exit for b in run], [0, 0, 2, 0])
        self.assertEqual([b.expect for b in run], [None, "both_paths_allow", "rule_denied:tools",
                                                   "rule_denied:tools"])

    def test_a_marker_sets_the_exit_code_and_the_text_to_expect(self):
        block = Block("true\n", "exit=2 expect=denied")
        self.assertIsNone(problem(block, result(2, "x denied y")))
        self.assertEqual(problem(block, result(0, "denied")), "exit 0, expected 2")
        self.assertEqual(problem(block, result(2, "allowed")), "'denied' not in the output")

    def test_a_block_with_no_marker_must_exit_zero(self):
        found = blocks("text\n```bash\necho hi\n```\n")
        self.assertEqual(len(found), 1)
        self.assertFalse(found[0].skip)
        self.assertEqual(found[0].code, "echo hi\n")
        self.assertEqual(problem(found[0], result(1)), "exit 1, expected 0")


if __name__ == "__main__":
    unittest.main()
