"""Runs the end-to-end demo (two_key/e2e_demo.py) as a user would: every capability, offline."""

import subprocess
import sys
import unittest
from pathlib import Path

from two_key.crypto.signatures import pq_available

ROOT = Path(__file__).resolve().parents[1]


class EndToEndDemo(unittest.TestCase):
    def test_every_check_passes(self):
        r = subprocess.run([sys.executable, "-m", "two_key", "e2e-demo"], cwd=ROOT, capture_output=True, text=True,
                           timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        self.assertNotIn("[FAIL]", r.stdout)
        self.assertIn(", 0 failed, ", r.stdout)
        for section in ("1. Seed-phrase backup", "2. Constitution upload and signing", "3. Hybrid post-quantum",
                        "4. Path A + Path B", "5. Capability tokens and gateway", "6. Scanning hooks",
                        "7. Ledger", "8. Enterprise: PKI identities"):
            self.assertIn(section, r.stdout)
        if pq_available():
            self.assertIn(", 0 skipped", r.stdout)
        passed = int(r.stdout.rsplit("e2e summary: ", 1)[1].split()[0])
        self.assertGreaterEqual(passed, 39)

    def test_seed_words_are_not_printed(self):
        from two_key import seedphrase
        r = subprocess.run([sys.executable, "-m", "two_key.e2e_demo"], cwd=ROOT, capture_output=True, text=True,
                           timeout=300)
        printed = set(r.stdout.lower().replace("(", " ").replace(")", " ").split())
        # The demo's phrase is random, so check that no run of 24 wordlist words appears, only the redacted form.
        words = set(seedphrase.wordlist())
        tokens = r.stdout.split()
        run = longest = 0
        for t in tokens:
            run = run + 1 if t in words else 0
            longest = max(longest, run)
        self.assertLess(longest, 6)
        self.assertIn("[redacted]", r.stdout)
        self.assertTrue(printed)


if __name__ == "__main__":
    unittest.main()
