# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""B1: agent_id / hosting library metadata is typed and length-capped (fail closed)."""

import json
import tempfile
import unittest
from pathlib import Path

from two_key.agent_meta import (MAX_AGENT_METADATA_CHARS, REASON_INVALID, REASON_TOO_LARGE,
                                check_agent_meta_field, check_agent_meta_mapping)
from two_key.agents import MonitoredAgent
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge


RULES = [
    {"id": "tools", "allow_only_tools": ["search", "email_draft"]},
    {"id": "no-wires", "deny_if": {"tool": "wire_transfer"}},
    {"id": "cap", "deny_if": {"amount_usd_gt": 200}},
    {"id": "sensitive", "deny_if": {"data_class_in": ["medical", "classified"]}},
]
SPECS = {
    "search": {"irreversible": False, "data_class_floor": "public"},
    "email_draft": {
        "irreversible": False,
        "data_class_floor": "public",
        "counterparties": [{"json_path": "to", "allow": ["ada", "ada@example"]}],
    },
}
PROSE = "Never wire money. Cap spend at 200. No medical or classified data."
SEARCH = {"tool": "search", "amount_usd": 0, "data_class": "public", "irreversible": False}
MARK = "ZQXMARK"


def _engine(tmp, votes=("yes", "yes")):
    key = generate_private_key()
    env = sign_constitution(PROSE, RULES, key, SPECS)
    ledger = Ledger(Path(tmp, "ledger"), key)
    judges = [FixedJudge(f"j{i}", vote, provider=f"p{i}", maker=f"v{i}", local_weights=(i == 0))
              for i, vote in enumerate(votes)]
    tk = TwoKey(ledger, key.public_key(), verify_signed(env, key.public_key()), judges,
                private_key=key, quorum=QuorumPolicy(required_yes=len(votes)),
                allow_test_doubles=True, monitored_agent=TEST_AGENT)
    return tk


def _ledger_blob(tk) -> bytes:
    """Approximate ledger footprint for assertions (ciphertext lines on disk)."""
    return tk.ledger.entries_path.read_bytes()


class AgentMetadataTests(unittest.TestCase):
    def test_helper_exact_boundary(self):
        self.assertEqual(check_agent_meta_field("agent_id", "a" * MAX_AGENT_METADATA_CHARS),
                         "a" * MAX_AGENT_METADATA_CHARS)
        with self.assertRaises(Exception) as ctx:
            check_agent_meta_field("agent_id", "a" * (MAX_AGENT_METADATA_CHARS + 1))
        self.assertEqual(ctx.exception.reason, REASON_TOO_LARGE)

    def test_oversize_agent_id_denies_no_mark_in_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp)
            huge = MARK + "a" * (5 << 20)
            d = tk.authorize(SEARCH, {"q": "x"}, "look", agent_id=huge)
            self.assertEqual((d.allowed, d.token, d.reason), (False, None, REASON_TOO_LARGE))
            blob = _ledger_blob(tk)
            self.assertNotIn(MARK.encode(), blob)
            self.assertLess(len(blob), 64 * 1024)  # sealed ledger + deny; not ~10 MB
            bodies = [e.body for e in tk.ledger.entries if e.kind == "decision"]
            self.assertTrue(bodies)
            self.assertEqual(bodies[-1].get("reason"), REASON_TOO_LARGE)
            self.assertEqual(bodies[-1].get("field"), "agent_id")
            self.assertIn("digest", bodies[-1])
            self.assertTrue(bodies[-1].get("agent") in (None, {}) or "agent" not in bodies[-1])

    def test_oversize_hosting_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp)
            d = tk.authorize(SEARCH, {"q": "x"}, "look", hosting=MARK + "h" * 300)
            self.assertEqual((d.allowed, d.token, d.reason), (False, None, REASON_TOO_LARGE))
            self.assertNotIn(MARK.encode(), _ledger_blob(tk))

    def test_non_str_agent_id_denies_no_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp)
            for bad in (b"bytes-id", object(), float("nan"), 123):
                d = tk.authorize(SEARCH, {"q": "x"}, "look", agent_id=bad)
                self.assertEqual((d.allowed, d.token, d.reason), (False, None, REASON_INVALID), bad)

    def test_non_str_hosting_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp)
            d = tk.authorize(SEARCH, {"q": "x"}, "look", hosting=b"cloud")
            self.assertEqual((d.allowed, d.token, d.reason), (False, None, REASON_INVALID))

    def test_none_and_omitted_still_allow(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp)
            d1 = tk.authorize(SEARCH, {"q": "x"}, "look")
            d2 = tk.authorize(SEARCH, {"q": "x"}, "look", agent_id=None, hosting=None)
            self.assertTrue(d1.allowed and d1.token)
            self.assertTrue(d2.allowed and d2.token)
            self.assertIsNone(d1.agent)
            self.assertIsNone(d2.agent)

    def test_short_str_still_allows(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp)
            d = tk.authorize(SEARCH, {"q": "x"}, "look", agent_id="agent-1", hosting="cloud")
            self.assertTrue(d.allowed and d.token)
            self.assertEqual(d.agent, {"id": "agent-1", "hosting": "cloud", "trusted": False})

    def test_exactly_256_ok_257_deny(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp)
            ok = tk.authorize(SEARCH, {"q": "x"}, "look", agent_id="a" * 256)
            bad = tk.authorize(SEARCH, {"q": "x"}, "look", agent_id="a" * 257)
            self.assertTrue(ok.allowed and ok.token)
            self.assertEqual((bad.allowed, bad.token, bad.reason), (False, None, REASON_TOO_LARGE))

    def test_authorize_from_agent_oversize_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp)
            agent = MonitoredAgent(MARK + "x" * 300, "xai", "grok", "https://api.x.ai/v1", "cloud",
                                   kind="openai_compatible")
            raw = json.dumps({"tool": "email_draft", "arguments": {"to": "ada"}, "proposal": "draft",
                              "amount_usd": 0, "data_class": "public", "irreversible": False})
            d = tk.authorize_from_agent(agent, raw)
            self.assertEqual((d.allowed, d.token, d.reason), (False, None, REASON_TOO_LARGE))
            self.assertNotIn(MARK.encode(), _ledger_blob(tk))

    def test_strip_counted_for_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp)
            # 256 letters with surrounding spaces → still OK after strip
            d = tk.authorize(SEARCH, {"q": "x"}, "look", agent_id="  " + ("b" * 256) + "  ")
            self.assertTrue(d.allowed)
            self.assertEqual(d.agent["id"], "b" * 256)


    def test_invalid_detail_uses_non_str_not_raw_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp)
            d = tk.authorize(SEARCH, {"q": "x"}, "look", agent_id=b"bytes")
            self.assertEqual(d.reason, REASON_INVALID)
            bodies = [e.body for e in tk.ledger.entries if e.kind == "decision"]
            self.assertEqual(bodies[-1].get("got"), "non_str")
            self.assertEqual(bodies[-1].get("field"), "agent_id")

    def test_huge_type_name_cannot_balloon_deny(self):
        """A caller-defined type with a multi-MB __name__ must not inflate the ledger."""
        from two_key.agent_meta import type_tag, MAX_TYPE_TAG_CHARS
        huge = "H" * (2 << 20)
        cls = type(huge, (), {})
        tag = type_tag(cls())
        self.assertLessEqual(len(tag), MAX_TYPE_TAG_CHARS)
        self.assertNotIn(huge, tag)
        with tempfile.TemporaryDirectory() as tmp:
            tk = _engine(tmp)
            d = tk.authorize(SEARCH, {"q": "x"}, "look", agent_id=cls())
            self.assertEqual((d.allowed, d.token, d.reason), (False, None, REASON_INVALID))
            blob = _ledger_blob(tk)
            self.assertNotIn(b"H" * 100, blob)
            self.assertLess(len(blob), 64 * 1024)
            bodies = [e.body for e in tk.ledger.entries if e.kind == "decision"]
            self.assertEqual(bodies[-1].get("got"), "non_str")


    def test_mapping_helper_rejects_non_mapping(self):
        for bad in (["agent_id", "x"], 123, "not-a-map"):
            with self.assertRaises(Exception) as ctx:
                check_agent_meta_mapping(bad)
            self.assertEqual(ctx.exception.reason, REASON_INVALID)
            self.assertEqual(ctx.exception.detail.get("got"), "non_mapping")
            self.assertEqual(ctx.exception.detail.get("field"), "agent_meta")




if __name__ == "__main__":
    unittest.main()
