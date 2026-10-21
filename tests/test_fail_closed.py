# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Every Path B failure is a deny: abstain, error, timeout, unparseable output, no judges, no deadline."""

import tempfile
import threading
import time
import unittest
from pathlib import Path

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.judges.base import Ballot, Judge
from two_key.judges.config import JudgeConfigError, load_config
from two_key.judges.ollama import OllamaJudge
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge, RaisingJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


class Hung(Judge):
    is_test_double = True

    def __init__(self, jid="hung"):
        self.judge_id, self.provider, self.release = jid, "test-double", threading.Event()

    def score(self, text, action, proposal):
        self.release.wait(5)
        return Ballot(self.judge_id, self.provider, "yes", 0.9, "too late")


class NotABallot(Judge):
    is_test_double = True

    def __init__(self):
        self.judge_id, self.provider = "odd", "test-double"

    def score(self, text, action, proposal):
        return {"vote": "yes"}


def ollama(text=None, exc=None):
    def transport(url, headers, body, timeout):
        if exc:
            raise exc
        return {"message": {"content": text}}
    return OllamaJudge("local", "ollama", "qwen2.5:7b", transport=transport)


# The in-process TEST_AGENT is accepted only when every judge is a test double; with a real
# (Ollama) judge, declare a real agent: another model on another local daemon. (Two keyless sides on one
# address are refused: nothing tells them apart.)
LOCAL_AGENT = {"id": "local-agent", "model": "llama3.1:8b", "provider": "ollama",
               "base_url": "http://localhost:11435", "credential": "none"}


def engine(tmp, judges, quorum=None, **kw):
    key = generate_private_key()
    env = sign_constitution("Searching is fine.", RULES, key, SPECS)
    agent = TEST_AGENT if all(getattr(j, "is_test_double", False) for j in judges) else LOCAL_AGENT
    return TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()), judges,
                  private_key=key, quorum=quorum, allow_test_doubles=True, monitored_agent=agent, **kw)


class OneJudgeFailureIsADeny(unittest.TestCase):
    def deny(self, judge, policy=None):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(tmp, [judge], policy)
            started = time.monotonic()
            d = tk.authorize(SEARCH, {}, "look it up")
            elapsed = time.monotonic() - started
            self.assertFalse(d.allowed)
            self.assertIsNone(d.token)
            self.assertFalse(d.path_b["passed"])
            self.assertEqual([e.kind for e in tk.ledger.entries][-1], "decision")
            return d, elapsed

    def test_abstain(self):
        d, _ = self.deny(FixedJudge("a", "abstain"))
        self.assertEqual(d.reason, "insufficient_responses:0<1")

    def test_error(self):
        self.deny(RaisingJudge())

    def test_invalid_ballot_object(self):
        self.deny(NotABallot())

    def test_unparseable_and_transport_failure(self):
        for j in (ollama("sure, looks fine to me"), ollama('{"consistent": "yes"}'),
                  ollama('{"consistent": true, "confidence": 0.9, "rationale": "x", "extra": 1}'),
                  ollama(exc=OSError("connection refused"))):
            self.deny(j)

    def test_timeout_parallel_and_sequential(self):
        for parallel in (True, False):
            j = Hung()
            _, elapsed = self.deny(j, QuorumPolicy(required_yes=1, timeout_seconds=0.2, parallel=parallel))
            j.release.set()
            self.assertLess(elapsed, 2.0)

    def test_judge_says_no(self):
        d, _ = self.deny(FixedJudge("a", "no"))
        self.assertEqual(d.reason, "insufficient_yes:0<1")


class AbstentionsNeverCountAsYes(unittest.TestCase):
    def test_two_of_two_with_one_failure(self):
        for bad in (FixedJudge("b", "abstain"), RaisingJudge("b"), ollama("not json")):
            with tempfile.TemporaryDirectory() as tmp:
                tk = engine(tmp, [FixedJudge("a", "yes"), bad], QuorumPolicy(required_yes=2))
                d = tk.authorize(SEARCH, {}, "look it up")
                self.assertFalse(d.allowed)
                self.assertIn(d.path_b["yes"], (None, 1))


class StartupRefusals(unittest.TestCase):
    def test_zero_judges(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(TwoKeyConfigError) as raised:
                engine(tmp, [])
            self.assertTrue(str(raised.exception).startswith("no_judges"))
        with self.assertRaisesRegex(JudgeConfigError, "non-empty 'judges' list"):
            load_config({"judges": []})

    def test_no_hard_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(TwoKeyConfigError, "^Path B needs a hard deadline"):
                engine(tmp, [FixedJudge("a", "yes")], QuorumPolicy(required_yes=1, timeout_seconds=None))
        with self.assertRaisesRegex(JudgeConfigError, "timeout_seconds must be a positive number \(a hard deadline\)"):  # skipcq: PY-W0073 - test only
            load_config({"judges": [{"id": "l", "type": "ollama", "model": "m"}],
                         "quorum": {"required_yes": 1, "timeout_seconds": None}})


if __name__ == "__main__":
    unittest.main(verbosity=2)
