# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""origin is passed down per call, not stored on the TwoKey, so one call cannot label another's decision."""

import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


class Origin(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, key, SPECS)
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), key), key.public_key(),
                         verify_signed(env, key.public_key()), [FixedJudge("a", "yes")], private_key=key,
                         quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)

    def origins(self):
        return [e.body["origin"] for e in self.tk.ledger.entries if e.kind == "decision"]

    def test_no_origin_state_on_the_instance(self):
        self.tk.authorize(SEARCH, {"q": "x"}, "look", origin="cli")
        self.assertFalse(hasattr(self.tk, "_origin"))

    def test_each_call_records_its_own_origin(self):
        self.tk.authorize(SEARCH, {"q": "x"}, "look", origin="cli")
        self.tk.authorize(SEARCH, {"q": "x"}, "look")
        self.tk.authorize({"tool": "Bad Name!"}, {}, "x", origin="cli")      # early deny path
        self.tk.authorize_from_agent(None, None)                               # early deny via agent path
        self.assertEqual(self.origins(), ["cli", "library", "cli", "library"])

    def test_interleaved_calls_keep_their_origin(self):
        # A slow call that started as "cli" still records "cli" after a "library" call ran meanwhile.
        started, release = threading.Event(), threading.Event()
        real = self.tk._authorize

        def slow(*a, **kw):
            if kw.get("origin") == "cli":
                started.set()
                release.wait(5)
            return real(*a, **kw)
        with mock.patch.object(self.tk, "_authorize", side_effect=slow):
            t = threading.Thread(target=self.tk.authorize, args=(SEARCH, {"q": "x"}, "look"), kwargs={"origin": "cli"})
            t.start()
            started.wait(5)
            self.tk.authorize(SEARCH, {"q": "y"}, "look")
            release.set()
            t.join(5)
        self.assertEqual(sorted(self.origins()), ["cli", "library"])
        self.assertEqual(self.origins()[-1], "cli")


if __name__ == "__main__":
    unittest.main()


class OriginMetadataCap(unittest.TestCase):
    """origin is B1-capped: str, strip, max 256; non-str / oversize deny fail-closed."""

    MARK = "ZQXORIGIN"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, key, SPECS)
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), key), key.public_key(),
                         verify_signed(env, key.public_key()), [FixedJudge("a", "yes")], private_key=key,
                         quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)

    def _blob(self) -> bytes:
        return self.tk.ledger.entries_path.read_bytes()

    def test_oversize_origin_denies_no_mark_no_token(self):
        from two_key.agent_meta import REASON_TOO_LARGE
        huge = self.MARK + "o" * (5 << 20)
        d = self.tk.authorize(SEARCH, {"q": "x"}, "look", origin=huge)
        self.assertEqual((d.allowed, d.token, d.reason), (False, None, REASON_TOO_LARGE))
        self.assertNotIn(self.MARK.encode(), self._blob())
        self.assertLess(len(self._blob()), 64 * 1024)
        bodies = [e.body for e in self.tk.ledger.entries if e.kind == "decision"]
        self.assertTrue(bodies)
        self.assertEqual(bodies[-1].get("reason"), REASON_TOO_LARGE)
        self.assertEqual(bodies[-1].get("field"), "origin")
        self.assertIn("digest", bodies[-1])
        self.assertNotIn("origin", bodies[-1])  # never echo the bad value

    def test_non_str_origin_denies(self):
        from two_key.agent_meta import REASON_INVALID
        for bad in (b"cli", object(), 123, ["cli"]):
            d = self.tk.authorize(SEARCH, {"q": "x"}, "look", origin=bad)
            self.assertEqual((d.allowed, d.token, d.reason), (False, None, REASON_INVALID), bad)
            bodies = [e.body for e in self.tk.ledger.entries if e.kind == "decision"]
            self.assertEqual(bodies[-1].get("got"), "non_str")
            self.assertNotIn("origin", bodies[-1])

    def test_exactly_256_ok_257_deny(self):
        from two_key.agent_meta import REASON_TOO_LARGE
        ok = self.tk.authorize(SEARCH, {"q": "x"}, "look", origin="c" * 256)
        self.assertTrue(ok.allowed and ok.token)
        allow_bodies = [e.body for e in self.tk.ledger.entries
                        if e.kind == "decision" and e.body.get("allowed")]
        self.assertEqual(allow_bodies[-1]["origin"], "c" * 256)
        bad = self.tk.authorize(SEARCH, {"q": "x"}, "look", origin="c" * 257)
        self.assertEqual((bad.allowed, bad.token, bad.reason), (False, None, REASON_TOO_LARGE))
        deny = [e.body for e in self.tk.ledger.entries
                if e.kind == "decision" and e.body.get("reason") == REASON_TOO_LARGE][-1]
        self.assertNotIn("origin", deny)
        self.assertEqual(deny.get("field"), "origin")

    def test_blank_and_none_default_to_library(self):
        d1 = self.tk.authorize(SEARCH, {"q": "x"}, "look", origin=None)
        d2 = self.tk.authorize(SEARCH, {"q": "x"}, "look", origin="   ")
        self.assertTrue(d1.allowed and d2.allowed)
        origins = [e.body["origin"] for e in self.tk.ledger.entries if e.kind == "decision"]
        self.assertEqual(origins, ["library", "library"])

    def test_authorize_from_agent_oversize_origin(self):
        from two_key.agent_meta import REASON_TOO_LARGE
        import json
        raw = json.dumps({"tool": "search", "arguments": {"q": "x"}, "proposal": "look",
                          "amount_usd": 0, "data_class": "public", "irreversible": False})
        d = self.tk.authorize_from_agent(None, raw, origin=self.MARK + "z" * 300)
        self.assertEqual((d.allowed, d.token, d.reason), (False, None, REASON_TOO_LARGE))
        self.assertNotIn(self.MARK.encode(), self._blob())

