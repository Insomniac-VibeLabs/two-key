# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Declared upstream labels are folded; bare openai maps to api.openai.com (#9)."""
from __future__ import annotations

import unittest

from two_key.identity import normalize_upstream


class UpstreamFold(unittest.TestCase):
    def test_bare_openai_maps_to_api_host(self):
        self.assertEqual(normalize_upstream("openai"), "api.openai.com")
        self.assertEqual(normalize_upstream(" OpenAI "), "api.openai.com")

    def test_fullwidth_and_zero_width_fold(self):
        self.assertEqual(normalize_upstream("\uff4f\uff50\uff45\uff4e\uff41\uff49"), "api.openai.com")
        self.assertEqual(normalize_upstream("api.\u200bopenai.com"), "api.openai.com")
        self.assertEqual(normalize_upstream("\ufeffopenai"), "api.openai.com")

    def test_url_still_normalizes(self):
        self.assertEqual(normalize_upstream("https://API.OpenAI.com:443/v1"), "api.openai.com")


if __name__ == "__main__":
    unittest.main()
