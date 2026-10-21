# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Empty tenant {} is invalid; omit tenant instead (#8)."""
from __future__ import annotations

import unittest

from two_key.identity import IdentityError, validate_tenant


class EmptyTenant(unittest.TestCase):
    def test_none_means_omit(self):
        self.assertEqual(validate_tenant(None, "agent"), {})

    def test_empty_mapping_refused(self):
        with self.assertRaises(IdentityError) as cm:
            validate_tenant({}, "agent")
        self.assertIn("must not be empty", str(cm.exception))

    def test_nonempty_ok(self):
        self.assertEqual(validate_tenant({"project": "p1"}, "agent"), {"project": "p1"})


if __name__ == "__main__":
    unittest.main()
