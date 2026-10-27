# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The judge history summary (#1) and per-judge ballot records (0.8.0).

The acceptance cases of the design note (section 7), and the decisions D1, D4, D6, D7 and D10. Network-free: the
judges are test doubles that keep the prompt an LLM judge would have been sent.
"""

import contextlib
import io
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from two_key import history
from two_key.audit import check_history_digests
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.judges.base import Ballot, Judge
from two_key.judges.llm import HISTORY_INSTRUCTION, SYSTEM_PROMPT, build_user_prompt
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy, error_class
from two_key.siem import project
from two_key.testing import TEST_AGENT, FixedJudge

DAY = 86400.0
T0 = 1_800_000_000.0          # a fixed start for the fake clock
RULES = [{"id": "tools", "allow_only_tools": ["pay_invoice", "send_note"]},
         {"id": "blocked", "deny_counterparties": ["evil-corp"]}]
SPECS = {
    "pay_invoice": {"irreversible": True, "data_class_floor": "financial",
                    "amount": {"json_path": "amount", "unit": "usd"},
                    "counterparties": [{"json_path": "to",
                                        "allow": ["acme-supplies", "beta-corp", "evil-corp", "@example.com"]}],
                    "payload": [{"json_path": "memo"}]},
    "send_note": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "text"}]},
}
PROSE = "We pay acme-supplies once a month, about $1,200. Never pay the same invoice twice."
INJECT = "zzinj"   # every planted string contains this


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


class Recording(Judge):
    """Votes as told and keeps the user prompt an LLM judge would send, and the action it was given."""

    is_test_double = True

    def __init__(self, judge_id="rec", vote="yes", rationale="consistent", provider="test-double", hook=None):
        self.judge_id, self.provider, self.vote, self.rationale = judge_id, provider, vote, rationale
        self.prompts, self.actions, self.hook = [], [], hook

    def score(self, constitution_text, action, proposal):
        if self.hook is not None:
            self.hook()
        self.actions.append(action)
        self.prompts.append(build_user_prompt(constitution_text, action, proposal))
        return Ballot(self.judge_id, self.provider, self.vote, 0.8, self.rationale)

    @property
    def last(self):
        return self.actions[-1].history


def pay(to="acme-supplies", amount=1200.0, memo="invoice 7"):
    return ({"tool": "pay_invoice", "data_class": "financial", "amount_usd": amount, "counterparty": to},
            {"amount": amount, "to": to, "memo": memo})


def quiet(fn, *a, **kw):
    with contextlib.redirect_stderr(io.StringIO()) as err:
        result = fn(*a, **kw)
    return result, err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.key = generate_private_key()
        self.envelope = sign_constitution(PROSE, RULES, self.key, SPECS)
        self.con = verify_signed(self.envelope, self.key.public_key())
        self.clock = Clock()

    def ledger(self, name="ledger"):
        return quiet(Ledger, self.dir / name, self.key)[0]

    def start(self, judges=None, *, ledger=None, quorum=None, **kw):
        self.judge = Recording()
        tk, self.err = quiet(TwoKey, ledger or self.ledger(), self.key.public_key(), self.con,
                             judges or [self.judge], private_key=self.key,
                             quorum=quorum or QuorumPolicy(required_yes=1), allow_test_doubles=True,
                             monitored_agent=TEST_AGENT, clock=self.clock, **kw)
        self.addCleanup(tk.close)
        return tk

    def run_call(self, tk, call, *, redeem=True, agent_id=None):
        d = tk.authorize(*call, "pay it", agent_id=agent_id)
        if d.allowed and redeem:
            gw = tk.gateway(tools={"pay_invoice": lambda a: "paid", "send_note": lambda a: "sent"})
            self.assertTrue(gw.invoke(d.token, call[0]["tool"], call[1]).allowed)
        return d

    @staticmethod
    def entries(tk, kind):
        return [e.body for e in tk.ledger.entries if e.kind == kind]


class AcceptanceCases(Base):
    def test_1_a_duplicate_bill_shows_the_first_payment(self):
        tk = self.start()
        self.assertTrue(self.run_call(tk, pay()).allowed)
        self.clock.now += 3600
        self.run_call(tk, pay())
        this = self.judge.last["this_tool"]
        self.assertEqual(this["tool"], "pay_invoice")
        self.assertEqual(this["counterparty"], "acme-supplies")
        self.assertEqual(this["last_decisions"][0],
                         {"age_hours": 1.0, "outcome": "allowed", "run": True, "amount_usd": 1200.0})
        self.assertEqual(this["days_since_last_allowed"], 0.04)
        self.assertEqual(this["allowed_totals"]["7d"], {"count": 1, "amount_usd": 1200.0})
        self.assertIn("<decision_history>", self.judge.prompts[-1])

    def test_2_a_monthly_repeat_shows_thirty_day_spacing(self):
        tk = self.start()
        for _ in range(2):
            self.run_call(tk, pay())
            self.clock.now += 30 * DAY
        self.run_call(tk, pay())
        this = self.judge.last["this_tool"]
        self.assertEqual([d["age_hours"] for d in this["last_decisions"]], [720.0, 1440.0])
        self.assertEqual(this["days_since_last_allowed"], 30.0)
        self.assertEqual(this["allowed_totals"]["30d"]["count"], 1)
        self.assertEqual(this["allowed_totals"]["90d"], {"count": 2, "amount_usd": 2400.0})

    def test_3_each_party_sees_only_its_own_history(self):
        tk = self.start()
        self.run_call(tk, pay("acme-supplies", 100.0))
        self.run_call(tk, pay("beta-corp", 200.0))
        self.run_call(tk, pay("acme-supplies", 300.0))
        this = self.judge.last["this_tool"]
        self.assertEqual([d["amount_usd"] for d in this["last_decisions"]], [100.0])
        self.assertEqual(this["allowed_totals"]["90d"], {"count": 1, "amount_usd": 100.0})

    def test_4_a_slow_ninety_day_drip_shows_the_sum(self):
        tk = self.start()
        for _ in range(89):
            self.run_call(tk, pay(amount=10.0))
            self.clock.now += DAY
        self.run_call(tk, pay(amount=10.0))
        totals = self.judge.last["this_tool"]["allowed_totals"]
        self.assertEqual(totals["90d"], {"count": 89, "amount_usd": 890.0})
        self.assertEqual(totals["7d"]["count"], 7)
        self.assertEqual(len(self.judge.last["this_tool"]["last_decisions"]), 10)

    def test_5_a_burst_of_denies_shows_by_reason_code(self):
        tk = self.start()
        for i in range(10):
            tk.authorize({"tool": "wire_money"}, {}, "x")      # no signed spec: a Path A deny
            self.clock.now += 5
        self.run_call(tk, pay())
        counts = self.judge.last["all_tools"]["1h"]
        self.assertEqual(counts["denied"], {"rule_denied:tools": 10})
        self.assertEqual(counts["allowed"], 0)
        self.assertEqual(self.judge.last["all_tools"]["24h"]["denied"], {"rule_denied:tools": 10})

    def test_6_attacker_text_never_reaches_a_judge(self):
        judge = Recording(rationale=f"{INJECT}-rationale")
        tk = self.start([judge])
        planted = [
            ({"tool": f"{INJECT}_tool"}, {}, "x"),                                   # a tool with no spec
            (*pay(f"{INJECT}-party"), "x"),                                          # a party on no allow list
            (*pay(f"{INJECT}-local@example.com"), f"{INJECT} proposal"),              # an @domain address
            (*pay(f"{INJECT}@evil.example"), "x"),
            ({"tool": "pay_invoice", "amount_usd": 5.0}, {"to": "acme-supplies"}, "x"),   # derive_failed
            ({"tool": "pay_invoice", "data_class": f"{INJECT}"}, {}, "x"),           # malformed_action:<msg>
        ]
        for action, args, proposal in planted:
            tk.authorize(action, args, proposal)
            self.clock.now += 60
        from two_key.agents import MonitoredAgent
        agent = MonitoredAgent("a", "test-double", "m", "http://127.0.0.1:1/v1", "local", kind="openai_compatible")
        tk.authorize_from_agent(agent, json.dumps({"decline": f"{INJECT} decline"}))
        self.run_call(tk, pay("acme-supplies"))
        self.run_call(tk, pay(f"other-{INJECT}@example.com"))
        self.assertTrue(judge.prompts)
        for prompt in judge.prompts:
            history_part = prompt.split("<decision_history>")[1].split("</decision_history>")[0] \
                if "<decision_history>" in prompt else ""
            self.assertNotIn(INJECT, history_part)
        self.assertEqual(judge.last["this_tool"]["counterparty"], "@example.com")
        seen = json.dumps([a.history for a in judge.actions])
        self.assertNotIn(INJECT, seen)
        # What the ledger keeps as the decision's subject is the same filtered text.
        self.assertNotIn(INJECT, json.dumps([b.get("subject") for b in self.entries(tk, "decision")]))

    def test_7_turned_off_judges_get_0_7_3_prompts(self):
        quorum = QuorumPolicy(required_yes=1, judge_history={"enabled": False})
        tk = self.start(quorum=quorum)
        self.assertIn("quorum.judge_history enabled: false", self.err)
        self.run_call(tk, pay())
        self.run_call(tk, pay())
        self.assertIsNone(self.judge.actions[-1].history)
        self.assertNotIn("decision_history", self.judge.prompts[-1])
        loaded = self.entries(tk, "constitution_loaded")[-1]
        self.assertFalse(loaded["quorum_policy"]["judge_history"]["enabled"])
        decision = self.entries(tk, "decision")[-1]
        self.assertIsNone(decision["history_digest"])
        self.assertNotIn("history_hash", json.dumps(self.entries(tk, "path_b")))
        # Without a summary the judges' prompt is what build_user_prompt wrote in 0.7.3: no new section.
        self.assertEqual(self.judge.prompts[-1],
                         build_user_prompt(self.con.prose, self.judge.actions[-1], ""))

    def test_8_a_tool_without_an_amount_gets_counts_only(self):
        tk = self.start()
        note = ({"tool": "send_note", "data_class": "public", "irreversible": False}, {"text": "hi"})
        self.run_call(tk, note)
        self.run_call(tk, note)
        this = self.judge.last["this_tool"]
        self.assertIsNone(this["counterparty"])
        self.assertNotIn("amount_usd", json.dumps(this))
        self.assertEqual(this["allowed_totals"]["7d"], {"count": 1})

    def test_9_a_ledger_from_before_0_8_0_opens_with_undated_history(self):
        ledger = self.ledger()
        with ledger.exclusive():      # what 0.7.3 wrote for one allowed payment: no at, no subject
            ledger.append("proposal", {"tool": "pay_invoice", "proposal": "p", "agent": None})
            ledger.append("action_normalized", {"tool": "pay_invoice", "form": {
                "amount_usd": 1200.0, "data_class": "financial", "counterparty": "acme-supplies",
                "irreversible": True, "counterparties": ["acme-supplies"]}, "claimed_data_class": "financial",
                "deny_reason": None, "dropped_keys": []})
            ledger.append("path_b", {"passed": True, "reason": "quorum_pass", "yes": 1, "no": 0, "abstain": 0})
            ledger.append("decision", {"allowed": True, "reason": "both_paths_allow", "agent": None,
                                       "origin": "library", "policy_digest": "x", "identities_digest": "y"})
            ledger.checkpoint()
        tk = self.start(ledger=ledger)
        self.run_call(tk, pay())
        summary = self.judge.last
        self.assertIsNone(summary["history_starts"])
        this = summary["this_tool"]
        self.assertEqual(this["last_decisions"], [{"age": "before_upgrade", "outcome": "allowed", "run": False,
                                                   "amount_usd": 1200.0}])
        self.assertEqual(this["allowed_totals"]["90d"], {"count": 0, "amount_usd": 0.0})

    def test_10_two_threads_with_one_duplicate_each_see_the_other(self):
        tk = self.start()
        registered = threading.Barrier(2, timeout=10)

        appended = threading.local()

        class Flights(list):
            def append(self, item):
                super().append(item)
                appended.now = True

        class Gate:
            """The in-flight lock, except that a call that has just registered waits, after letting go of it,
            until the other call has registered too; then both build their summary."""
            lock = threading.Lock()

            def __enter__(self):
                self.lock.acquire()

            def __exit__(self, *exc):
                self.lock.release()
                if getattr(appended, "now", False):
                    appended.now = False
                    registered.wait()
        tk._in_flight, tk._in_flight_lock = Flights(), Gate()
        calls = []
        threads = [threading.Thread(target=lambda: calls.append(tk.authorize(*pay(), "pay it"))) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(20)
        self.assertEqual([a.history["this_tool"]["in_flight"] for a in self.judge.actions], [1, 1])
        # And the re-check at mint: the second to mint sees the first's approval and gets no token.
        self.assertEqual(sorted(d.reason for d in calls), ["both_paths_allow", "history_changed"])

    def test_11_ballot_records_show_which_judge_was_down(self):
        class Slow(Recording):
            def score(self, *a):
                time.sleep(1.0)
                return super().score(*a)
        judges = [Recording("a", rationale=f"{INJECT} one"), Recording("b", rationale=f"{INJECT} two"),
                  Slow("cloud-b")]
        tk = self.start(judges, quorum=QuorumPolicy(required_yes=2, min_responding=2, timeout_seconds=0.3))
        d = tk.authorize(*pay(), "pay it")
        self.assertTrue(d.allowed, d.reason)
        path_b = self.entries(tk, "path_b")[-1]
        self.assertEqual((path_b["yes"], path_b["abstain"]), (2, 1))
        self.assertEqual([(b["judge_id"], b["vote"], b["error_class"]) for b in path_b["ballots"]],
                         [("a", "yes", None), ("b", "yes", None), ("cloud-b", "abstain", "timeout")])
        self.assertTrue(path_b["ballots"][0]["rationale_digest"].startswith("hmac-sha256:"))
        self.assertNotEqual(path_b["ballots"][0]["rationale_digest"], path_b["ballots"][1]["rationale_digest"])
        self.assertIsNone(path_b["ballots"][2]["rationale_digest"])
        ledger_text = json.dumps([e.body for e in tk.ledger.entries])
        self.assertNotIn(INJECT, ledger_text)
        self.assertNotIn("timeout: no ballot", ledger_text)
        event = project("path_b", path_b)
        self.assertEqual([b["error_class"] for b in event["ballots"]], [None, None, "timeout"])
        self.assertNotIn(INJECT, json.dumps(event))

    def test_12_the_audit_rebuilds_every_history_digest(self):
        tk = self.start()
        self.run_call(tk, pay())
        tk.authorize({"tool": "wire_money"}, {}, "x")
        self.clock.now += 3600
        self.run_call(tk, pay("beta-corp", 50.0))
        self.run_call(tk, pay())
        self.assertEqual(check_history_digests(tk.ledger, self.con), [])
        entries = list(tk.ledger.entries)
        i = max(n for n, e in enumerate(entries) if e.kind == "decision" and e.body.get("history_digest"))
        forged = dict(entries[i].body, history_digest="sha256:" + "0" * 64)
        entries[i] = entries[i].__class__(entries[i].seq, entries[i].prev, "decision", forged, entries[i].entry_hash)
        problems = check_history_digests(SimpleNamespace(entries=entries), self.con)
        self.assertEqual(len(problems), 1)
        self.assertIn("does not match", problems[0])

    def test_13_the_audit_checks_two_processes_on_one_ledger(self):
        # Two proxies on one ledger, each for its own agent, load with different agent ids; a decision does not say
        # which process made it. Live run (2026-10-27): a third load after both made the audit pick the wrong one.
        first = self.start(known_agent_ids=["agent-1"])
        second = self.start(ledger=Ledger(self.dir / "ledger", self.key), known_agent_ids=["agent-1", "agent-2"])
        self.start(ledger=Ledger(self.dir / "ledger", self.key), known_agent_ids=["agent-1"]).close()
        for tk, agent in ((first, "agent-1"), (second, "agent-2"), (first, "agent-1"), (second, "agent-2")):
            self.clock.now += 60
            self.assertTrue(self.run_call(tk, pay(), agent_id=agent).allowed)
        self.assertEqual(check_history_digests(Ledger(self.dir / "ledger", self.key), self.con), [])


class Decisions(Base):
    def test_every_decision_is_dated_and_carries_its_subject(self):
        tk = self.start()
        self.run_call(tk, pay())
        tk.authorize({"tool": "wire_money"}, {}, "x")
        for d in self.entries(tk, "decision"):
            self.assertEqual(d["at"], history.format_time(T0))
            self.assertIn("subject", d)
        allowed, denied = self.entries(tk, "decision")
        self.assertEqual(allowed["subject"], {"tool": "pay_invoice", "counterparties": ["acme-supplies"],
                                              "amount_usd": 1200.0})
        self.assertTrue(allowed["history_digest"].startswith("sha256:"))
        self.assertEqual(denied["subject"], {"tool": None, "counterparties": [], "amount_usd": None})
        event = project("decision", allowed)
        self.assertEqual(event["at"], "2027-01-15T08:00:00Z")
        self.assertNotIn("acme-supplies", json.dumps(event))
        self.assertNotIn("1200", json.dumps(event))

    def test_the_summary_is_bound_to_the_round(self):
        tk = self.start()
        seen = []

        class Bound(Recording):
            def score_bound(self, constitution_text, action, proposal, binding):
                seen.append(dict(binding))
                return self.score(constitution_text, action, proposal)
        tk.judges[0].__class__ = Bound
        self.run_call(tk, pay())
        digest = self.entries(tk, "decision")[-1]["history_digest"]
        self.assertEqual(seen[-1]["history_hash"], digest)
        self.assertEqual(history.digest(self.judge.last), digest)

    def test_a_deny_counterparty_is_never_shown(self):
        tk = self.start()
        tk.authorize(*pay("evil-corp"), "x")
        self.run_call(tk, pay())
        self.assertNotIn("evil-corp", json.dumps(self.judge.actions[-1].history))
        self.assertEqual(self.entries(tk, "decision")[0]["subject"]["counterparties"], [])

    def test_d6_an_approved_call_not_yet_run_is_shown_apart(self):
        tk = self.start()
        self.run_call(tk, pay(), redeem=False)
        self.clock.now += 10
        self.run_call(tk, pay())
        this = self.judge.last["this_tool"]
        self.assertEqual(this["approved_not_run"], {"count": 1, "amount_usd": 1200.0})
        self.assertEqual(this["allowed_totals"]["7d"]["count"], 0)
        self.assertIsNone(this["days_since_last_allowed"])
        self.assertIs(this["last_decisions"][0]["run"], False)
        self.clock.now += 400       # past the longest token lifetime: no longer waiting to run
        self.run_call(tk, pay())
        self.assertEqual(self.judge.last["this_tool"]["approved_not_run"]["count"], 0)

    def test_a_clock_that_went_back_shows_more_not_less(self):
        tk = self.start()
        self.run_call(tk, pay())
        self.clock.now -= 3600
        self.run_call(tk, pay())
        summary = self.judge.last
        self.assertTrue(summary["clock_went_back"])
        self.assertEqual(summary["this_tool"]["allowed_totals"]["7d"]["count"], 1)

    def test_reason_codes_lose_their_detail(self):
        self.assertEqual(history.reason_code("derive_failed:amount_missing"), "derive_failed")
        self.assertEqual(history.reason_code("malformed_action:tool: not an identifier"), "malformed_action")
        self.assertEqual(history.reason_code("rule_denied:spend-cap"), "rule_denied:spend-cap")
        self.assertEqual(history.reason_code(f"rule_denied:{INJECT} <x>"), "rule_denied")
        self.assertEqual(history.reason_code(f"{INJECT}:x"), "other")

    def test_ballot_error_classes_are_a_fixed_set(self):
        self.assertEqual(error_class("http 429"), ("http", 429))
        self.assertEqual(error_class("transport: OSError"), ("transport", None))
        self.assertEqual(error_class(f"RuntimeError: {INJECT}"), ("other", None))
        self.assertEqual(error_class(None), (None, None))

    def test_the_system_prompt_gains_one_sentence_only_with_history(self):
        from two_key.judges.openai_compat import OpenAICompatibleJudge
        sent = []

        def transport(url, headers, body, timeout):
            sent.append(body["messages"][0]["content"])
            return {"choices": [{"message": {"content": json.dumps(
                {"consistent": True, "confidence": 0.9, "rationale": "ok"})}}]}
        agent = {"id": "agent", "model": "grok-4", "provider": "xai", "base_url": "https://api.x.ai/v1",
                 "credential_env": "HISTORY_TEST_AGENT_KEY"}
        os.environ["HISTORY_TEST_AGENT_KEY"] = "agent-secret"
        self.addCleanup(os.environ.pop, "HISTORY_TEST_AGENT_KEY", None)
        for enabled, name in ((True, "on"), (False, "off")):
            judge = OpenAICompatibleJudge("local", "ollama", "llama3", "http://127.0.0.1:11434/v1",
                                          transport=transport)
            tk, _ = quiet(TwoKey, self.ledger(name), self.key.public_key(), self.con, [judge],
                          private_key=self.key, quorum=QuorumPolicy(required_yes=1,
                                                                    judge_history={"enabled": enabled}),
                          monitored_agent=agent, clock=self.clock)
            self.addCleanup(tk.close)
            tk.authorize(*pay(), "pay it")
        self.assertEqual(sent, [SYSTEM_PROMPT + HISTORY_INSTRUCTION, SYSTEM_PROMPT])


class FailureAndEpisodes(Base):
    def test_d1_a_summary_that_cannot_be_built_denies_without_asking_the_judges(self):
        tk = self.start()
        with mock.patch.object(tk._history, "summary", side_effect=KeyError("boom")):
            d = tk.authorize(*pay(), "pay it")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "internal_error:history")
        self.assertEqual(self.judge.actions, [])
        failed = self.entries(tk, "judge_history_failed")
        self.assertEqual(failed, [{"error_class": "build_error", "on_failure": "deny", "tool": "pay_invoice"}])
        self.assertEqual(self.entries(tk, "path_b")[-1]["reason"], "skipped:history_failed")
        self.assertEqual(project("judge_history_failed", failed[0])["error_class"], "build_error")

    def test_d1_judge_without_history_is_judged_and_recorded(self):
        tk = self.start(quorum=QuorumPolicy(required_yes=1, judge_history={"on_failure": "judge_without_history"}))
        self.assertIn("judge_without_history", self.err)
        with mock.patch.object(tk._history, "summary", side_effect=RecursionError()):
            d = tk.authorize(*pay(), "pay it")
        self.assertTrue(d.allowed, d.reason)
        self.assertIsNone(self.judge.actions[-1].history)
        self.assertIsNone(self.entries(tk, "decision")[-1]["history_digest"])
        self.assertEqual(self.entries(tk, "judge_history_failed")[-1]["error_class"], "too_deep")

    def test_d4_a_burst_of_denies_is_an_attempt_episode(self):
        tk = self.start(known_agent_ids=["grok"])
        for i in range(6):
            tk.authorize(*pay(f"{INJECT}-{i}"), "x", agent_id="grok")      # not on the allow list
            self.clock.now += 30
        episodes = self.entries(tk, "attempt_episode")
        self.assertEqual(len(episodes), 1)      # found once, at the fifth deny; the sixth extends it
        self.assertEqual(episodes[0], {"agent_id": "grok", "started": history.format_time(T0), "denies": 5,
                                       "reasons": {"counterparty_not_allowed": 5}})
        self.assertEqual(project("attempt_episode", episodes[0])["denies"], 5)
        self.run_call(tk, pay(), agent_id="grok")
        agent = self.judge.last["agent"]
        self.assertEqual(agent["agent"], "grok")
        self.assertEqual(agent["episodes_90d"], 1)
        self.assertEqual(agent["episodes"][0]["denies"], 6)
        self.assertEqual(agent["episodes"][0]["tools"], ["pay_invoice"])
        self.assertNotIn(INJECT, json.dumps(agent))
        # An agent id the operator did not configure is never shown; its episodes are "unnamed".
        self.run_call(tk, pay(), agent_id=f"{INJECT}-agent")
        self.assertEqual(self.judge.last["agent"], {"agent": "unnamed", "episodes": [], "episodes_90d": 0})

    def test_d4_a_restart_does_not_ledger_an_episode_again(self):
        ledger = self.ledger()
        tk = self.start(ledger=ledger)
        for i in range(5):
            tk.authorize({"tool": "wire_money"}, {}, "x")
        self.assertEqual(len(self.entries(tk, "attempt_episode")), 1)
        tk.close()
        again = self.start(ledger=ledger)
        again.authorize({"tool": "wire_money"}, {}, "x")
        self.assertEqual(len(self.entries(again, "attempt_episode")), 1)

    def test_d7_an_approval_from_another_process_after_the_summary_is_caught_at_mint(self):
        other = self.start(ledger=self.ledger())
        mine_ledger = Ledger(self.dir / "ledger", self.key)
        state = {}

        def meanwhile():
            if "done" not in state:     # while this round's judges deliberate, another process approves
                state["done"] = other.authorize(*pay(), "pay it")
        judge = Recording(hook=meanwhile)
        mine = self.start([judge], ledger=mine_ledger)
        d = mine.authorize(*pay(), "pay it")
        self.assertTrue(state["done"].allowed)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "history_changed")
        self.assertIsNone(d.token)
        self.assertIs(self.entries(mine, "path_b")[-1]["passed"], True)
        # The retry is judged with the new history, and allowed by it.
        retry = mine.authorize(*pay(), "pay it")
        self.assertTrue(retry.allowed, retry.reason)
        self.assertEqual([d.get("reason", d["outcome"]) for d in judge.last["this_tool"]["last_decisions"]],
                         ["history_changed", "allowed"])

    def test_d7_another_party_is_not_a_change(self):
        other = self.start(ledger=self.ledger())
        mine_ledger = Ledger(self.dir / "ledger", self.key)
        mine = self.start([Recording(hook=lambda: other.authorize(*pay("beta-corp"), "x"))], ledger=mine_ledger)
        self.assertTrue(mine.authorize(*pay(), "pay it").allowed)


class OneProxyPerAgent(Base):
    @staticmethod
    def config(agent_id="grok", on=True):
        return SimpleNamespace(agent_id=agent_id, one_proxy_per_agent=on)

    def test_d10_a_second_proxy_for_the_same_agent_refuses(self):
        from two_key.mcp_proxy.config import ProxyConfigError
        from two_key.mcp_proxy.core import hold_agent_lock
        first = self.start(ledger=self.ledger())
        hold_agent_lock(first, self.config())
        second = self.start(ledger=Ledger(self.dir / "ledger", self.key))
        config = self.config()
        with self.assertRaisesRegex(ProxyConfigError, "agent_already_connected"):
            quiet(hold_agent_lock, second, config)
        refused = [e.body for e in Ledger(self.dir / "ledger", self.key).entries
                   if e.kind == "agent_already_connected"]
        self.assertEqual(refused, [{"agent_id": "grok", "origin": "mcp-proxy"}])
        third = self.start(ledger=Ledger(self.dir / "ledger", self.key))
        hold_agent_lock(third, self.config("other-agent"))      # another agent is fine
        first.close()                                           # the lock goes with the first proxy
        fourth = self.start(ledger=Ledger(self.dir / "ledger", self.key))
        hold_agent_lock(fourth, self.config())

    def test_d10_off_warns_and_takes_nothing(self):
        from two_key.mcp_proxy.core import hold_agent_lock
        tk = self.start()
        _, err = quiet(hold_agent_lock, tk, self.config(on=False))
        self.assertIn("one_proxy_per_agent: false", err)
        self.assertIsNone(getattr(tk, "agent_lock_fd", None))

    def test_d10_the_setting_loads_and_weaker_is_named(self):
        from two_key.config_set import _weaker_history
        from two_key.history import JudgeHistoryPolicy
        on, off = JudgeHistoryPolicy(), JudgeHistoryPolicy(enabled=False)
        self.assertEqual(_weaker_history(on, off), ["quorum.judge_history.enabled: judges see no decision history"])
        self.assertEqual(_weaker_history(off, on), [])
        self.assertIn("quorum.judge_history.on_failure: deny to judge_without_history",
                      _weaker_history(on, JudgeHistoryPolicy(on_failure="judge_without_history")))
        self.assertIn("quorum.judge_history.window_days: lowered", _weaker_history(on, JudgeHistoryPolicy(window_days=7)))


class Settings(unittest.TestCase):
    def test_bad_values_are_refused(self):
        from two_key.quorum import QuorumConfigError
        for bad in ({"window_days": 14}, {"max_items": 0}, {"max_items": 51}, {"on_failure": "allow"},
                    {"enabled": "yes"}, {"burst_denies": 1}, {"surprise": 1}):
            with self.subTest(bad=bad), self.assertRaises(QuorumConfigError):
                QuorumPolicy(judge_history=bad)

    def test_the_policy_record_always_names_the_settings(self):
        self.assertEqual(QuorumPolicy().to_record()["judge_history"],
                         {"enabled": True, "window_days": 90, "max_items": 10, "on_failure": "deny",
                          "burst_denies": 5, "burst_minutes": 10})

    def test_judges_yaml_reads_the_block(self):
        from two_key.judges.config import load_config
        judges, policy = load_config({"judges": [{"id": "o", "type": "ollama", "model": "llama3"}],
                                      "quorum": {"judge_history": {"window_days": 30, "max_items": 5}}})
        self.assertEqual((policy.judge_history.window_days, policy.judge_history.max_items), (30, 5))

    def test_times_are_rfc3339_to_the_second(self):
        self.assertEqual(history.format_time(0), "1970-01-01T00:00:00Z")
        self.assertEqual(history.parse_time("2026-10-25T01:03:15Z"), 1792890195.0)
        self.assertIsNone(history.parse_time("2026-10-25 01:03:15"))


if __name__ == "__main__":
    unittest.main()
